//! `shodan-cvedb` — Shodan's public CVE database. Keyless. Owns `cvss`, `cvssVersion`,
//! `severity`, `publishedAt`, `summary` on [`crate::types::CvePayload`].
//!
//! `GET https://cvedb.shodan.io/cve/{CVE}` — verified live 2026-08-21. A known CVE answers
//! `200` with (among other fields) `cvss: float`, `cvss_version: float`, `cvss_v2: float`,
//! `cvss_v3: float`, `cvss_v4: null`, `epss: float`, `kev: bool`, `summary: str`,
//! `published_time: str` (e.g. `"2021-07-02T22:15:08"` — no timezone suffix). An unknown CVE
//! answers **`404`** with `{"detail":"No information available"}`.
//!
//! ## Deliberately does not write `epss` or `kev`
//!
//! The response carries both. This tool does not write either to the payload, even though it
//! could: [`crate::sources::cve::epss`] and [`crate::sources::cve::kev`] read those same
//! numbers from their own authoritative upstreams (FIRST, CISA), and Shodan CVEDB's own copy
//! is itself derived from those upstreams — writing it here would be double-counting a
//! derived source next to its source of record. Worse, `runtime::merge_patch` is documented
//! as shallow last-writer-wins, so depending on tool ordering the derived copy could silently
//! overwrite the authoritative one with a possibly-stale value. [`shodan_to_yield`]'s own test
//! asserts the produced patch never contains `epss` or `kev`.
//!
//! ## Judgment call: no bare `cvss` field
//!
//! The response also carries a bare `cvss` (no revision attached). It is not used here —
//! [`select_cvss`] only reads `cvss_v4`/`cvss_v3`/`cvss_v2`, each of which travels with a
//! known scale. A bare `cvss` with no revision tag is exactly the ambiguity
//! [`crate::types::CvePayload::cvss_version`]'s own doc comment warns against (NVD can carry
//! a v3.1 `8.8` and a v2 `9.0` for the same CVE on different scales) — using it would mean
//! guessing which scale it's on.
//!
//! ## `publishedAt` is a UTC interpretation, not a guess
//!
//! `published_time` carries no timezone. NVD publishes these instants in UTC, so
//! [`parse_published_time`] parses the naive local time and stamps it `Utc` — an
//! interpretation of an under-specified field, not a guess about the underlying value.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

use crate::fetch::{self, OzBody, OzOutcome};
use crate::layer_plan::FLAG_AGGREGATE_ANSWERED;
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;

const SHODAN_CVEDB_BASE: &str = "https://cvedb.shodan.io/cve/";

/// `summary` is truncated to this many characters — the measured Print Spooler CVE's summary
/// runs to several paragraphs, and this payload renders in a detail panel, not an archive. 500
/// chars covers a couple of sentences of real context without one CVE's summary dominating
/// every future `payload_patch` merge.
const MAX_SUMMARY_CHARS: usize = 500;

/// This tool's contribution, before it's turned into a [`ToolYield`]. Every field independent
/// — Shodan CVEDB can answer with only some of them populated.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ShodanCveInfo {
    pub cvss: Option<f64>,
    pub cvss_version: Option<String>,
    pub severity: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub summary: Option<String>,
}

/// Formats a numeric CVSS revision (`3.1`, `4.0`, …) for display, trimming a spurious decimal
/// artefact on a whole number (`4` → `"4.0"`) while leaving a real minor version (`3.1`) alone.
fn format_cvss_version(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{v:.1}")
    } else {
        format!("{v}")
    }
}

/// Picks the highest CVSS revision actually present (`cvss_v4` → `cvss_v3` → `cvss_v2`) and
/// returns its score, a version label, and the major revision number (2/3/4) the score is on
/// — the major number is what [`derive_severity`] needs to choose the right qualitative-band
/// table, so it travels alongside the label rather than being re-derived from it later.
///
/// The label prefers the response's own `cvss_version` when it actually agrees with the
/// revision family just selected (its floor matches: a `cvss_version` of `3.1` agrees with
/// `cvss_v3`, not `cvss_v2`) — using the response's own more specific value when it's
/// trustworthy, falling back to a generic label otherwise. This never lets a v2 score carry a
/// v3-shaped label or vice versa: the label is chosen from the *same* field that was actually
/// read for the score.
fn select_cvss(json: &serde_json::Value) -> (Option<f64>, Option<String>, Option<u8>) {
    let response_version = json.get("cvss_version").and_then(|v| v.as_f64());

    let pick = |field: &str, major: u8, generic: &str| {
        json.get(field).and_then(|v| v.as_f64()).map(|score| {
            let label = match response_version {
                Some(rv) if rv.floor() as u8 == major => format_cvss_version(rv),
                _ => generic.to_string(),
            };
            (score, label, major)
        })
    };

    pick("cvss_v4", 4, "4.0")
        .or_else(|| pick("cvss_v3", 3, "3.x"))
        .or_else(|| pick("cvss_v2", 2, "2.0"))
        .map(|(score, label, major)| (Some(score), Some(label), Some(major)))
        .unwrap_or((None, None, None))
}

/// CVSS v3.x/v4 qualitative bands, per the published table: 0.0 NONE, 0.1-3.9 LOW,
/// 4.0-6.9 MEDIUM, 7.0-8.9 HIGH, 9.0-10.0 CRITICAL.
fn severity_v3(score: f64) -> &'static str {
    if score <= 0.0 {
        "NONE"
    } else if score <= 3.9 {
        "LOW"
    } else if score <= 6.9 {
        "MEDIUM"
    } else if score <= 8.9 {
        "HIGH"
    } else {
        "CRITICAL"
    }
}

/// CVSS v2's own, different qualitative bands: 0.0-3.9 LOW, 4.0-6.9 MEDIUM, 7.0-10.0 HIGH — no
/// NONE/CRITICAL bands exist in v2 at all. Chosen over "leave severity unset for v2" so a v2
/// -only CVE still gets a `severity` chip; the risk the brief calls out — mislabelling a v2
/// score with the v3 table — is avoided by keeping this a genuinely separate function that the
/// major-version branch in [`derive_severity`] is the only caller of.
fn severity_v2(score: f64) -> &'static str {
    if score <= 3.9 {
        "LOW"
    } else if score <= 6.9 {
        "MEDIUM"
    } else {
        "HIGH"
    }
}

/// Derives `severity` from `score`, using the band table that matches `major` (2, 3, or 4).
/// `None` for any other major number — a revision this module doesn't know a table for should
/// not guess.
fn derive_severity(score: f64, major: u8) -> Option<String> {
    match major {
        3 | 4 => Some(severity_v3(score).to_string()),
        2 => Some(severity_v2(score).to_string()),
        _ => None,
    }
}

/// Truncates `raw` to [`MAX_SUMMARY_CHARS`], appending an ellipsis when it was cut. Operates
/// on `char`s, not bytes, so it never splits inside a multi-byte character.
fn truncate_summary(raw: &str) -> String {
    if raw.chars().count() <= MAX_SUMMARY_CHARS {
        raw.to_string()
    } else {
        let truncated: String = raw.chars().take(MAX_SUMMARY_CHARS).collect();
        format!("{truncated}\u{2026}")
    }
}

/// Parses `published_time` (`"2021-07-02T22:15:08"`, no timezone, sometimes with fractional
/// seconds) as UTC. See the module doc for why UTC is an interpretation, not a guess.
fn parse_published_time(raw: &str) -> Option<DateTime<Utc>> {
    let naive = NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f"))
        .ok()?;
    Some(Utc.from_utc_datetime(&naive))
}

/// Parses a Shodan CVEDB `200` body into a [`ShodanCveInfo`]. Infallible — every field is
/// independently optional, so there is no shape this can reject outright, unlike this
/// category's other tools. Pure and tested against inline fixtures.
pub fn parse_shodan_cve(json: &serde_json::Value) -> ShodanCveInfo {
    let (cvss, cvss_version, major) = select_cvss(json);
    let severity = match (cvss, major) {
        (Some(score), Some(major)) => derive_severity(score, major),
        _ => None,
    };
    let published_at = json
        .get("published_time")
        .and_then(|v| v.as_str())
        .and_then(parse_published_time);
    let summary = json
        .get("summary")
        .and_then(|v| v.as_str())
        .map(truncate_summary);

    ShodanCveInfo {
        cvss,
        cvss_version,
        severity,
        published_at,
        summary,
    }
}

/// Turns a [`ShodanCveInfo`] into a [`ToolYield`], writing only the fields that were actually
/// present. Deliberately never writes `epss`/`kev` — see the module doc.
///
/// Posts [`FLAG_AGGREGATE_ANSWERED`] when any field was actually populated — the input
/// `cve-mitre`'s own fallback phase gates on (`layer_plan::no_authoritative_or_aggregate_answer`),
/// so the two keyless fallbacks stay strictly ordered instead of both firing on a silent NVD.
pub fn shodan_to_yield(info: &ShodanCveInfo) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if let Some(cvss) = info.cvss {
        patch.insert("cvss".to_string(), serde_json::json!(cvss));
    }
    if let Some(version) = &info.cvss_version {
        patch.insert("cvssVersion".to_string(), serde_json::json!(version));
    }
    if let Some(severity) = &info.severity {
        patch.insert("severity".to_string(), serde_json::json!(severity));
    }
    if let Some(published_at) = info.published_at {
        patch.insert(
            "publishedAt".to_string(),
            serde_json::json!(published_at.to_rfc3339()),
        );
    }
    if let Some(summary) = &info.summary {
        patch.insert("summary".to_string(), serde_json::json!(summary));
    }

    let answered = info.cvss.is_some()
        || info.severity.is_some()
        || info.published_at.is_some()
        || info.summary.is_some();

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        flags: if answered {
            vec![(FLAG_AGGREGATE_ANSWERED, true)]
        } else {
            Vec::new()
        },
        ..Default::default()
    }
}

/// Queries Shodan's CVEDB for `cve`. Untested beyond its pure helpers, same convention as the
/// rest of this crate.
pub async fn run_shodan(cve: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{SHODAN_CVEDB_BASE}{}", urlencoding::encode(cve));
    // The CVE id being looked up — CVEDB's whole record is keyed on it.
    let outcome = ctx
        .fetch("cve-shodan", cve, &url, fetch::OzFetchOptions::default())
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // Same reasoning as poc_github.rs: verified live 2026-08-21, a 404 here means "CVEDB has
    // no record of this CVE" (body `{"detail":"No information available"}`), not "the source
    // is down" — it must not fold into HttpError and drag a clean layer down to Degraded.
    if let OzOutcome::HttpError { status: 404, .. } = &outcome {
        return DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        );
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled, non-404 OzOutcome was handled above");
    };
    let OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "Shodan CVEDB response was not JSON".to_string(),
            },
            None,
        );
    };

    let info = parse_shodan_cve(json);
    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults { count: 1 },
        Some(shodan_to_yield(&info)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── select_cvss / revision preference ───────────────────────────────

    #[test]
    fn prefers_v4_over_v3_and_v2_when_all_present() {
        let json = serde_json::json!({
            "cvss_v2": 9.0, "cvss_v3": 8.8, "cvss_v4": 7.5, "cvss_version": 4.0
        });
        let (score, version, major) = select_cvss(&json);
        assert_eq!(score, Some(7.5));
        assert_eq!(version.as_deref(), Some("4.0"));
        assert_eq!(major, Some(4));
    }

    #[test]
    fn falls_back_to_v3_when_v4_is_absent() {
        let json = serde_json::json!({
            "cvss_v2": 9.0, "cvss_v3": 8.8, "cvss_v4": null, "cvss_version": 3.1
        });
        let (score, version, major) = select_cvss(&json);
        assert_eq!(score, Some(8.8));
        assert_eq!(
            version.as_deref(),
            Some("3.1"),
            "must use the response's own 3.1, not a generic 3.x"
        );
        assert_eq!(major, Some(3));
    }

    #[test]
    fn falls_back_to_v2_when_only_v2_is_present() {
        let json = serde_json::json!({ "cvss_v2": 9.0, "cvss_version": 2.0 });
        let (score, version, major) = select_cvss(&json);
        assert_eq!(score, Some(9.0));
        assert_eq!(version.as_deref(), Some("2.0"));
        assert_eq!(major, Some(2));
    }

    #[test]
    fn never_labels_a_v2_score_with_a_v3_or_v4_version() {
        // The response's `cvss_version` claims 3.1, but only cvss_v2 is populated (a
        // malformed/inconsistent upstream response). The label must still come from the
        // revision that was actually selected (v2), never from the mismatched claim.
        let json = serde_json::json!({ "cvss_v2": 9.0, "cvss_version": 3.1 });
        let (score, version, major) = select_cvss(&json);
        assert_eq!(score, Some(9.0));
        assert_eq!(
            version.as_deref(),
            Some("2.0"),
            "must not mix a v2 score with a v3 label"
        );
        assert_eq!(major, Some(2));
    }

    #[test]
    fn generic_label_used_when_response_has_no_cvss_version() {
        let json = serde_json::json!({ "cvss_v3": 8.8 });
        let (_, version, _) = select_cvss(&json);
        assert_eq!(version.as_deref(), Some("3.x"));
    }

    #[test]
    fn no_score_present_at_all_yields_nothing() {
        let json = serde_json::json!({ "cvss": 8.8 });
        assert_eq!(select_cvss(&json), (None, None, None));
    }

    // ── severity ─────────────────────────────────────────────────────────

    #[test]
    fn v3_severity_bands_match_the_published_table() {
        assert_eq!(severity_v3(0.0), "NONE");
        assert_eq!(severity_v3(3.9), "LOW");
        assert_eq!(severity_v3(4.0), "MEDIUM");
        assert_eq!(severity_v3(6.9), "MEDIUM");
        assert_eq!(severity_v3(7.0), "HIGH");
        assert_eq!(severity_v3(8.9), "HIGH");
        assert_eq!(severity_v3(9.0), "CRITICAL");
        assert_eq!(severity_v3(10.0), "CRITICAL");
    }

    #[test]
    fn v2_severity_bands_are_a_different_table_than_v3() {
        assert_eq!(severity_v2(3.9), "LOW");
        assert_eq!(severity_v2(4.0), "MEDIUM");
        assert_eq!(severity_v2(6.9), "MEDIUM");
        assert_eq!(severity_v2(7.0), "HIGH", "v2 has no CRITICAL band at all");
        assert_eq!(severity_v2(10.0), "HIGH");
    }

    #[test]
    fn derive_severity_applies_the_v3_table_to_v3_and_v4() {
        assert_eq!(derive_severity(9.0, 3).as_deref(), Some("CRITICAL"));
        assert_eq!(derive_severity(9.0, 4).as_deref(), Some("CRITICAL"));
    }

    #[test]
    fn derive_severity_applies_the_v2_table_to_v2_never_the_v3_table() {
        // A score of 9.0 is CRITICAL under the v3 table but HIGH under v2 (v2's ceiling
        // band). Applying v3's table here would be a real mislabel, exactly what the brief
        // calls out.
        assert_eq!(derive_severity(9.0, 2).as_deref(), Some("HIGH"));
    }

    // ── published_time parsing ───────────────────────────────────────────

    #[test]
    fn parses_the_measured_no_timezone_format() {
        let parsed = parse_published_time("2021-07-02T22:15:08").expect("parses");
        assert_eq!(parsed.to_rfc3339(), "2021-07-02T22:15:08+00:00");
    }

    #[test]
    fn tolerates_fractional_seconds() {
        let parsed = parse_published_time("2021-07-02T22:15:08.123").expect("parses");
        assert_eq!(parsed.date_naive().to_string(), "2021-07-02");
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_published_time("not a date"), None);
    }

    // ── summary truncation ───────────────────────────────────────────────

    #[test]
    fn short_summary_is_untouched() {
        assert_eq!(truncate_summary("short"), "short");
    }

    #[test]
    fn long_summary_is_truncated_with_an_ellipsis() {
        let long = "a".repeat(600);
        let truncated = truncate_summary(&long);
        assert_eq!(
            truncated.chars().count(),
            MAX_SUMMARY_CHARS + 1,
            "content + one ellipsis char"
        );
        assert!(truncated.ends_with('\u{2026}'));
    }

    // ── parse_shodan_cve / shodan_to_yield ───────────────────────────────

    #[test]
    fn parses_a_full_response() {
        let json = serde_json::json!({
            "cve_id": "CVE-2021-34527",
            "summary": "PrintNightmare.",
            "cvss": 8.8,
            "cvss_version": 3.1,
            "cvss_v2": 9.0,
            "cvss_v3": 8.8,
            "cvss_v4": null,
            "epss": 0.9979,
            "kev": true,
            "published_time": "2021-07-02T22:15:08",
        });
        let info = parse_shodan_cve(&json);
        assert_eq!(info.cvss, Some(8.8));
        assert_eq!(info.cvss_version.as_deref(), Some("3.1"));
        assert_eq!(info.severity.as_deref(), Some("HIGH"));
        assert!(info.published_at.is_some());
        assert_eq!(info.summary.as_deref(), Some("PrintNightmare."));
    }

    #[test]
    fn yield_never_contains_epss_or_kev_even_though_the_source_has_them() {
        // The whole point of the module doc's "deliberately does not write" section: those
        // fields belong to epss.rs/kev.rs's authoritative upstreams, and merge_patch is
        // last-writer-wins, so this tool must never touch either key.
        let info = ShodanCveInfo {
            cvss: Some(8.8),
            cvss_version: Some("3.1".to_string()),
            severity: Some("HIGH".to_string()),
            published_at: Some(Utc::now()),
            summary: Some("test".to_string()),
        };
        let produced = shodan_to_yield(&info);
        let obj = produced.payload_patch.as_object().expect("object patch");
        assert!(!obj.contains_key("epss"));
        assert!(!obj.contains_key("kev"));
    }

    #[test]
    fn yield_omits_absent_fields_entirely() {
        let info = ShodanCveInfo::default();
        let produced = shodan_to_yield(&info);
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }
}
