//! `cve-nvd` — the NVD 2.0 REST API, the source of record for a CVE's score and description.
//!
//! Keyless. This unit is graded "yes-with-free-key" because `NVD_API_KEY` lifts the rate
//! limit from 5 requests per 30 seconds to 50; it does **not** gate access, so
//! `registry::ToolDef::env_vars` is empty here for the same reason it is empty for
//! `github-user` — the key upgrades throughput, it does not decide whether the tool can run.
//! Verified keyless against `CVE-2021-34527` on 2026-08-21: HTTP 200, full record.
//!
//! ## Absence is a 200, not a 404
//!
//! An unknown CVE id returns **HTTP 200** with `{"totalResults":0,"vulnerabilities":[]}`
//! (measured). So this tool needs no special status mapping: an empty `vulnerabilities` array
//! is `OkEmpty`, and any non-2xx really is a failure.
//!
//! ## Picking one score out of several, which is the whole difficulty here
//!
//! `metrics` is not one score. For `CVE-2021-34527` NVD returns, in one response:
//!
//! - `cvssMetricV31`, **Secondary**, `secure@microsoft.com`, v3.1, **8.8**, `HIGH`
//! - `cvssMetricV31`, **Secondary**, `nvd@nist.gov`, v3.1, **8.8**, `HIGH`
//! - `cvssMetricV2`, **Primary**, `nvd@nist.gov`, v2.0, **9.0**, `HIGH`
//! - `ssvcV203` — a decision-point record with **no `cvssData` object at all**
//!
//! Three ways to get this wrong, all of which produce a plausible number and no error:
//!
//! 1. **Take the first entry of the first metric key.** That is whichever score a third party
//!    submitted — here Microsoft's, not NVD's.
//! 2. **Prefer `type == "Primary"` across the whole `metrics` object.** For this CVE the only
//!    Primary is the **CVSS v2** one, so the node would show `9.0` while every other tool in
//!    the layer, and every other CVE in the tree, is on the v3.1 scale. A v2 9.0 and a v3.1
//!    8.8 are not comparable numbers.
//! 3. **Assume every metric entry has a `cvssData`.** `ssvcV203` does not, and it sits in the
//!    same map.
//!
//! [`select_metric`] resolves it in that order of precedence: **newest CVSS revision first**
//! (v4.0 → v3.1 → v3.0 → v2.0), then within that one revision prefer `Primary`, then prefer
//! the NVD-sourced entry, then take the first. The revision that was actually chosen travels
//! with the score in [`CvePayload::cvss_version`], so a v2 fallback can never be read as a v3
//! score.
//!
//! One more shape difference worth naming, because it is invisible until it bites: on a
//! `cvssMetricV31` entry the qualitative rating lives at `cvssData.baseSeverity`, and on a
//! `cvssMetricV2` entry it lives on the **entry itself**, one level up. Both are read.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

use crate::fetch::{self, OzBody, OzOutcome};
use crate::layer_plan::FLAG_AUTHORITATIVE_ANSWERED;
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::CpeMatch;

const NVD_API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=";

/// Longest description kept. NVD's `descriptions[].value` is a full advisory paragraph — the
/// Print Spooler one runs to several hundred words including a dated update notice. The panel
/// renders this inline next to a chip, so it is truncated to roughly a screenful. The number
/// is this file's own choice, picked rather than specified.
const MAX_SUMMARY_CHARS: usize = 600;

/// The CVSS revisions NVD publishes, newest first. Iteration order **is** the precedence rule
/// — see the module doc for what goes wrong without it.
const METRIC_KEYS_NEWEST_FIRST: &[&str] = &[
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2",
];

/// One CVSS score selected out of an NVD record, with the revision it is on.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectedMetric {
    pub score: f64,
    /// The revision string as NVD itself reports it (`"3.1"`, `"2.0"`).
    pub version: String,
    pub severity: Option<String>,
}

/// The subset of an NVD CVE record this tool reads.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NvdRecord {
    pub metric: Option<SelectedMetric>,
    pub published_at: Option<DateTime<Utc>>,
    pub summary: Option<String>,
    /// `configurations[].nodes[].cpeMatch[]`, flattened. Only entries where `vulnerable` is
    /// not explicitly `false` are kept — NVD's own schema uses that flag to list a *fixed*
    /// version's CPE alongside the vulnerable ones, and keeping both would tell an investigator
    /// a patched build is affected.
    pub configurations: Vec<CpeMatch>,
    /// `weaknesses[].description[].value` — usually a CWE id string (`"CWE-79"`), occasionally
    /// a placeholder like `"NVD-CWE-noinfo"`. Kept as NVD reports it; no filtering.
    pub weaknesses: Vec<String>,
}

/// Parses NVD's `published`/`lastModified` instants.
///
/// Measured format: `2021-07-02T22:15:08.757` — **no timezone suffix**, with fractional
/// seconds. NVD documents these as UTC, so reading them as UTC is an interpretation of an
/// under-specified serialisation rather than a guess about the value. The no-fraction form is
/// accepted too, since nothing in the API contract promises the milliseconds are always there.
pub fn parse_nvd_instant(raw: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .and_then(|naive| Utc.from_local_datetime(&naive).single())
}

/// Picks the one score to display out of NVD's `metrics` object. See the module doc for the
/// three ways this goes wrong and why the precedence is revision-first.
pub fn select_metric(metrics: &serde_json::Value) -> Option<SelectedMetric> {
    for key in METRIC_KEYS_NEWEST_FIRST {
        let entries = match metrics.get(key).and_then(|v| v.as_array()) {
            // A revision NVD did not publish for this CVE, or — as with `ssvcV203` — a key
            // that is not a CVSS metric at all. Both mean "look at the next revision", never
            // "give up".
            None => continue,
            Some(entries) if entries.is_empty() => continue,
            Some(entries) => entries,
        };

        // Within one revision only. Crossing revisions to find a `Primary` is exactly the
        // mistake that returns a v2 9.0 for a CVE whose v3.1 score is 8.8.
        let chosen = entries
            .iter()
            .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("Primary"))
            .or_else(|| {
                entries
                    .iter()
                    .find(|e| e.get("source").and_then(|s| s.as_str()) == Some("nvd@nist.gov"))
            })
            .or_else(|| entries.first())?;

        let data = chosen.get("cvssData")?;
        let score = data.get("baseScore").and_then(|v| v.as_f64())?;
        let version = data
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            // NVD has always sent `version`; if it ever stops, the map key still names the
            // revision, and shipping the score unlabelled is the one outcome to avoid.
            .unwrap_or_else(|| key.trim_start_matches("cvssMetricV").to_string());
        let severity = data
            .get("baseSeverity")
            .and_then(|v| v.as_str())
            // v2 entries carry the rating on the entry, not inside `cvssData`.
            .or_else(|| chosen.get("baseSeverity").and_then(|v| v.as_str()))
            .map(str::to_string);

        return Some(SelectedMetric {
            score,
            version,
            severity,
        });
    }
    None
}

/// Flattens `configurations[].nodes[].cpeMatch[]` into a plain list. Pure and tested.
pub fn parse_configurations(cve: &serde_json::Value) -> Vec<CpeMatch> {
    let mut out = Vec::new();
    let Some(configs) = cve.get("configurations").and_then(|v| v.as_array()) else {
        return out;
    };
    for config in configs {
        let Some(nodes) = config.get("nodes").and_then(|v| v.as_array()) else {
            continue;
        };
        for node in nodes {
            let Some(matches) = node.get("cpeMatch").and_then(|v| v.as_array()) else {
                continue;
            };
            for m in matches {
                // A fixed version's own CPE, explicitly marked non-vulnerable — listing it
                // alongside the vulnerable ones would tell an investigator a patched build is
                // affected. Absent `vulnerable` is treated as vulnerable, same as NVD's own UI.
                if m.get("vulnerable").and_then(|v| v.as_bool()) == Some(false) {
                    continue;
                }
                let Some(criteria) = m.get("criteria").and_then(|v| v.as_str()) else {
                    continue;
                };
                out.push(CpeMatch {
                    criteria: criteria.to_string(),
                    version_start_including: m
                        .get("versionStartIncluding")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    version_start_excluding: m
                        .get("versionStartExcluding")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    version_end_including: m
                        .get("versionEndIncluding")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    version_end_excluding: m
                        .get("versionEndExcluding")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                });
            }
        }
    }
    out
}

/// Flattens `weaknesses[].description[].value` into a de-duplicated list of CWE ids. Pure and
/// tested.
pub fn parse_weaknesses(cve: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(weaknesses) = cve.get("weaknesses").and_then(|v| v.as_array()) else {
        return out;
    };
    for w in weaknesses {
        let Some(descriptions) = w.get("description").and_then(|v| v.as_array()) else {
            continue;
        };
        for d in descriptions {
            if let Some(value) = d.get("value").and_then(|v| v.as_str())
                && !out.iter().any(|existing| existing == value)
            {
                out.push(value.to_string());
            }
        }
    }
    out
}

/// Parses a `GET /rest/json/cves/2.0?cveId=…` body.
///
/// `Ok(None)` is the "NVD has no such CVE" case — a 200 with an empty `vulnerabilities`
/// array, which is a real finding and not a parse failure. `Err` is reserved for a body whose
/// shape this tool cannot read at all, which must stay loud: NVD changing its envelope should
/// never degrade into "this CVE has no score".
pub fn parse_nvd_response(json: &serde_json::Value) -> Result<Option<NvdRecord>, String> {
    let vulns = json
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "NVD response has no `vulnerabilities` array".to_string())?;

    let Some(first) = vulns.first() else {
        return Ok(None);
    };
    let cve = first
        .get("cve")
        .ok_or_else(|| "NVD `vulnerabilities[0]` has no `cve` object".to_string())?;

    let metric = cve.get("metrics").and_then(select_metric);
    let published_at = cve
        .get("published")
        .and_then(|v| v.as_str())
        .and_then(parse_nvd_instant);
    let summary = cve
        .get("descriptions")
        .and_then(|v| v.as_array())
        .and_then(|list| {
            list.iter()
                .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
                .or_else(|| list.first())
        })
        .and_then(|d| d.get("value").and_then(|v| v.as_str()))
        .map(truncate_summary);
    let configurations = parse_configurations(cve);
    let weaknesses = parse_weaknesses(cve);

    Ok(Some(NvdRecord {
        metric,
        published_at,
        summary,
        configurations,
        weaknesses,
    }))
}

/// Truncates on a character boundary, never a byte one — an advisory can contain non-ASCII
/// and slicing a UTF-8 string by byte index panics.
fn truncate_summary(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.chars().count() <= MAX_SUMMARY_CHARS {
        return trimmed.to_string();
    }
    let kept: String = trimmed.chars().take(MAX_SUMMARY_CHARS).collect();
    format!("{}…", kept.trim_end())
}

/// Turns a parsed record into the payload patch.
///
/// **Field ownership.** This tool owns `cvss`, `cvssVersion`, `severity`, `publishedAt`,
/// `summary`, `configurations` and `weaknesses`, and writes nothing else. `epss` and `kev`
/// belong to `cve-epss` and `cve-kev`,
/// which read them from FIRST and CISA directly. `runtime::merge_patch` is a shallow
/// last-writer-wins merge, so two tools writing one key is a silent overwrite, not a conflict
/// anyone would see — the fan-out is designed so no key has two writers in the same phase.
///
/// It also posts [`FLAG_AUTHORITATIVE_ANSWERED`], which is what holds the `cve-shodan`
/// fallback phase closed. That flag is set **only when NVD actually returned a record**, so a
/// timeout, a rate-limit or an empty result all open the fallback, and a successful NVD
/// lookup keeps it shut.
pub fn nvd_record_to_yield(record: &NvdRecord) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if let Some(metric) = &record.metric {
        patch.insert("cvss".into(), serde_json::json!(metric.score));
        patch.insert("cvssVersion".into(), serde_json::json!(metric.version));
        if let Some(severity) = &metric.severity {
            patch.insert("severity".into(), serde_json::json!(severity));
        }
    }
    if let Some(published) = record.published_at {
        patch.insert("publishedAt".into(), serde_json::json!(published));
    }
    if let Some(summary) = &record.summary {
        patch.insert("summary".into(), serde_json::json!(summary));
    }
    if !record.configurations.is_empty() {
        patch.insert(
            "configurations".into(),
            serde_json::json!(record.configurations),
        );
    }
    if !record.weaknesses.is_empty() {
        patch.insert("weaknesses".into(), serde_json::json!(record.weaknesses));
    }

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        flags: vec![(FLAG_AUTHORITATIVE_ANSWERED, true)],
        ..Default::default()
    }
}

pub async fn run_nvd(cve: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{NVD_API_BASE}{}", urlencoding::encode(cve));
    // `apiKey` is NVD's own header name, not an `Authorization` bearer. Absent, the request
    // still succeeds at the 5-per-30s tier.
    let headers = match ozint_core::config::optional("NVD_API_KEY") {
        Some(key) => vec![("apiKey".to_string(), key)],
        None => Vec::new(),
    };

    // The CVE id being looked up — this endpoint's whole response is a function of it.
    let outcome = ctx
        .fetch(
            "cve-nvd",
            cve,
            &url,
            fetch::OzFetchOptions {
                headers,
                ..Default::default()
            },
        )
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled OzOutcome was handled above");
    };
    let OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "NVD response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_nvd_response(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        // NVD knows no such CVE. A finding, not a failure — and deliberately *without* the
        // authoritative-answered flag, so the aggregator fallback still gets its turn.
        Ok(None) => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(Some(record)) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(nvd_record_to_yield(&record)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real `CVE-2021-34527` metrics block, trimmed to the fields this tool reads. Every
    /// value is as returned by NVD on 2026-08-21 — including the fact that neither v3.1 entry
    /// is `Primary` and the only `Primary` is on the v2 scale.
    fn print_spooler_metrics() -> serde_json::Value {
        serde_json::json!({
            "cvssMetricV31": [
                {
                    "source": "secure@microsoft.com",
                    "type": "Secondary",
                    "cvssData": { "version": "3.1", "baseScore": 8.8, "baseSeverity": "HIGH" }
                },
                {
                    "source": "nvd@nist.gov",
                    "type": "Secondary",
                    "cvssData": { "version": "3.1", "baseScore": 8.8, "baseSeverity": "HIGH" }
                }
            ],
            "cvssMetricV2": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "baseSeverity": "HIGH",
                    "cvssData": { "version": "2.0", "baseScore": 9.0 }
                }
            ],
            "ssvcV203": [
                { "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0", "options": [] }
            ]
        })
    }

    // ── metric selection: the three traps ────────────────────────────────

    #[test]
    fn the_newest_revision_wins_over_a_primary_on_an_older_one() {
        // The trap that produces a plausible wrong answer: the only `Primary` for this CVE is
        // the CVSS **v2** 9.0. Preferring Primary across the whole metrics object would put a
        // v2 score on a node the rest of the tree reads as v3.
        let selected = select_metric(&print_spooler_metrics()).expect("a metric");
        assert_eq!(selected.score, 8.8);
        assert_eq!(selected.version, "3.1");
        assert_eq!(selected.severity.as_deref(), Some("HIGH"));
    }

    #[test]
    fn a_metrics_entry_with_no_cvss_data_is_stepped_over_not_tripped_on() {
        // `ssvcV203` sits in the same map and has no `cvssData`. It must not shadow a real
        // revision, and it must not abort the search.
        let metrics = serde_json::json!({
            "ssvcV203": [{ "source": "x", "options": [] }],
            "cvssMetricV31": [
                { "source": "nvd@nist.gov", "type": "Primary",
                  "cvssData": { "version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL" } }
            ]
        });
        let selected = select_metric(&metrics).expect("a metric");
        assert_eq!(selected.score, 10.0);
        assert_eq!(selected.version, "3.1");
    }

    #[test]
    fn primary_wins_within_one_revision() {
        // Log4Shell's real shape: two v3.1 entries, one Primary from NVD and one Secondary
        // from a CNA. Same score here, but the precedence must still be deterministic.
        let metrics = serde_json::json!({
            "cvssMetricV31": [
                { "source": "cna@example.org", "type": "Secondary",
                  "cvssData": { "version": "3.1", "baseScore": 9.1, "baseSeverity": "CRITICAL" } },
                { "source": "nvd@nist.gov", "type": "Primary",
                  "cvssData": { "version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL" } }
            ]
        });
        let selected = select_metric(&metrics).expect("a metric");
        assert_eq!(
            selected.score, 10.0,
            "the Primary entry of the chosen revision wins"
        );
    }

    #[test]
    fn nvd_is_preferred_over_a_third_party_when_neither_is_primary() {
        let metrics = serde_json::json!({
            "cvssMetricV31": [
                { "source": "vendor@example.com", "type": "Secondary",
                  "cvssData": { "version": "3.1", "baseScore": 5.0, "baseSeverity": "MEDIUM" } },
                { "source": "nvd@nist.gov", "type": "Secondary",
                  "cvssData": { "version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH" } }
            ]
        });
        assert_eq!(select_metric(&metrics).expect("a metric").score, 7.5);
    }

    #[test]
    fn a_v4_score_outranks_a_v31_score() {
        let metrics = serde_json::json!({
            "cvssMetricV31": [
                { "source": "nvd@nist.gov", "type": "Primary",
                  "cvssData": { "version": "3.1", "baseScore": 8.8, "baseSeverity": "HIGH" } }
            ],
            "cvssMetricV40": [
                { "source": "nvd@nist.gov", "type": "Primary",
                  "cvssData": { "version": "4.0", "baseScore": 9.3, "baseSeverity": "CRITICAL" } }
            ]
        });
        let selected = select_metric(&metrics).expect("a metric");
        assert_eq!(selected.version, "4.0");
        assert_eq!(selected.score, 9.3);
    }

    #[test]
    fn a_v2_only_cve_is_labelled_v2_and_reads_its_severity_off_the_entry() {
        // The shape difference that is invisible until it bites: v2 puts `baseSeverity` on the
        // entry, v3 puts it inside `cvssData`.
        let metrics = serde_json::json!({
            "cvssMetricV2": [
                { "source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "MEDIUM",
                  "cvssData": { "version": "2.0", "baseScore": 5.0 } }
            ]
        });
        let selected = select_metric(&metrics).expect("a metric");
        assert_eq!(
            selected.version, "2.0",
            "a v2 score must never be labelled v3"
        );
        assert_eq!(selected.severity.as_deref(), Some("MEDIUM"));
    }

    #[test]
    fn no_cvss_metric_at_all_selects_nothing_rather_than_zero() {
        // A score of 0.0 is a real CVSS value (`NONE`). Substituting it for "unscored" would
        // paint an unscored CVE as harmless.
        assert_eq!(select_metric(&serde_json::json!({})), None);
        assert_eq!(
            select_metric(&serde_json::json!({ "ssvcV203": [{}] })),
            None
        );
        assert_eq!(
            select_metric(&serde_json::json!({ "cvssMetricV31": [] })),
            None
        );
    }

    // ── instants ─────────────────────────────────────────────────────────

    #[test]
    fn nvd_instants_parse_with_and_without_fractional_seconds() {
        let with = parse_nvd_instant("2021-07-02T22:15:08.757").expect("fractional");
        let without = parse_nvd_instant("2021-07-02T22:15:08").expect("whole seconds");
        assert_eq!(with.to_rfc3339(), "2021-07-02T22:15:08.757+00:00");
        assert_eq!(without.to_rfc3339(), "2021-07-02T22:15:08+00:00");
        assert_eq!(parse_nvd_instant("not a date"), None);
        // A timezone suffix is not the measured format, and must not silently shift the value.
        assert_eq!(parse_nvd_instant("2021-07-02T22:15:08+02:00"), None);
    }

    // ── configurations / weaknesses ─────────────────────────────────────

    #[test]
    fn configurations_are_flattened_across_configs_nodes_and_cpe_matches() {
        let cve = serde_json::json!({
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "cpeMatch": [
                        {
                            "vulnerable": true,
                            "criteria": "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "10.0.17763",
                            "versionEndExcluding": "10.0.17763.1935"
                        },
                        {
                            "vulnerable": false,
                            "criteria": "cpe:2.3:o:microsoft:windows_server_2019:10.0.17763.1935:*:*:*:*:*:*:*"
                        }
                    ]
                }]
            }]
        });
        let configs = parse_configurations(&cve);
        assert_eq!(
            configs.len(),
            1,
            "the non-vulnerable (fixed) CPE must be dropped"
        );
        assert_eq!(
            configs[0].criteria,
            "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*"
        );
        assert_eq!(
            configs[0].version_start_including.as_deref(),
            Some("10.0.17763")
        );
        assert_eq!(
            configs[0].version_end_excluding.as_deref(),
            Some("10.0.17763.1935")
        );
        assert_eq!(configs[0].version_start_excluding, None);
        assert_eq!(configs[0].version_end_including, None);
    }

    #[test]
    fn a_cpe_match_with_no_vulnerable_flag_is_kept() {
        // Absent `vulnerable` means vulnerable, same as NVD's own UI — only an explicit
        // `false` marks a fixed-version CPE to drop.
        let cve = serde_json::json!({
            "configurations": [{
                "nodes": [{ "cpeMatch": [{ "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" }] }]
            }]
        });
        assert_eq!(parse_configurations(&cve).len(), 1);
    }

    #[test]
    fn no_configurations_at_all_is_an_empty_list_not_an_error() {
        assert_eq!(parse_configurations(&serde_json::json!({})), Vec::new());
    }

    #[test]
    fn weaknesses_are_flattened_and_deduplicated() {
        let cve = serde_json::json!({
            "weaknesses": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "description": [{ "lang": "en", "value": "CWE-79" }]
                },
                {
                    "source": "cna@example.org",
                    "type": "Secondary",
                    "description": [{ "lang": "en", "value": "CWE-79" }, { "lang": "en", "value": "CWE-89" }]
                }
            ]
        });
        assert_eq!(
            parse_weaknesses(&cve),
            vec!["CWE-79".to_string(), "CWE-89".to_string()]
        );
    }

    #[test]
    fn no_weaknesses_at_all_is_an_empty_list_not_an_error() {
        assert!(parse_weaknesses(&serde_json::json!({})).is_empty());
    }

    // ── response envelope ────────────────────────────────────────────────

    #[test]
    fn an_empty_result_set_is_absence_not_a_parse_failure() {
        // Measured: NVD answers an unknown CVE id with 200 and an empty array.
        let json = serde_json::json!({ "totalResults": 0, "vulnerabilities": [] });
        assert_eq!(parse_nvd_response(&json), Ok(None));
    }

    #[test]
    fn a_missing_vulnerabilities_array_is_loud() {
        // If NVD changes its envelope, this tool must fail visibly rather than report every
        // CVE as unknown — a silent downgrade would look exactly like a quiet database.
        let err = parse_nvd_response(&serde_json::json!({ "message": "service unavailable" }))
            .expect_err("a shape change must not parse");
        assert!(err.contains("vulnerabilities"));
    }

    #[test]
    fn the_full_record_parses_into_the_fields_this_tool_owns() {
        let json = serde_json::json!({
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-34527",
                    "published": "2021-07-02T22:15:08.757",
                    "descriptions": [
                        { "lang": "es", "value": "descripción" },
                        { "lang": "en", "value": "A remote code execution vulnerability." }
                    ],
                    "metrics": print_spooler_metrics(),
                    "configurations": [{
                        "nodes": [{
                            "cpeMatch": [{
                                "vulnerable": true,
                                "criteria": "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "10.0.17763.1935"
                            }]
                        }]
                    }],
                    "weaknesses": [{
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [{ "lang": "en", "value": "CWE-269" }]
                    }]
                }
            }]
        });
        let record = parse_nvd_response(&json)
            .expect("parses")
            .expect("a record");
        assert_eq!(record.metric.as_ref().expect("metric").score, 8.8);
        assert_eq!(
            record.summary.as_deref(),
            Some("A remote code execution vulnerability.")
        );
        assert_eq!(
            record.published_at.expect("published").to_rfc3339(),
            "2021-07-02T22:15:08.757+00:00"
        );
        assert_eq!(record.configurations.len(), 1);
        assert_eq!(
            record.configurations[0].criteria,
            "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*"
        );
        assert_eq!(record.weaknesses, vec!["CWE-269".to_string()]);
    }

    #[test]
    fn the_english_description_is_preferred_over_whichever_came_first() {
        let json = serde_json::json!({
            "vulnerabilities": [{ "cve": { "descriptions": [
                { "lang": "es", "value": "primero" },
                { "lang": "en", "value": "second" }
            ]}}]
        });
        let record = parse_nvd_response(&json)
            .expect("parses")
            .expect("a record");
        assert_eq!(record.summary.as_deref(), Some("second"));
    }

    #[test]
    fn a_long_summary_is_truncated_on_a_character_boundary() {
        // An advisory can contain non-ASCII; slicing by byte index would panic.
        let long = "é".repeat(MAX_SUMMARY_CHARS + 50);
        let out = truncate_summary(&long);
        assert!(
            out.chars().count() <= MAX_SUMMARY_CHARS + 1,
            "kept {} chars",
            out.chars().count()
        );
        assert!(out.ends_with('…'));
        assert_eq!(truncate_summary("  short  "), "short");
    }

    // ── yield ────────────────────────────────────────────────────────────

    #[test]
    fn the_yield_writes_only_the_fields_this_tool_owns() {
        // `epss` and `kev` come from FIRST and CISA. Writing them here would let a merge
        // silently overwrite the authoritative value with a second-hand one.
        let record = NvdRecord {
            metric: Some(SelectedMetric {
                score: 8.8,
                version: "3.1".into(),
                severity: Some("HIGH".into()),
            }),
            published_at: parse_nvd_instant("2021-07-02T22:15:08.757"),
            summary: Some("boom".into()),
            configurations: vec![CpeMatch {
                criteria: "cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*".into(),
                version_end_excluding: Some("10.0.17763.1935".into()),
                ..Default::default()
            }],
            weaknesses: vec!["CWE-269".into()],
        };
        let patch = nvd_record_to_yield(&record).payload_patch;
        let obj = patch.as_object().expect("an object patch");

        assert_eq!(obj["cvss"], 8.8);
        assert_eq!(obj["cvssVersion"], "3.1");
        assert_eq!(obj["severity"], "HIGH");
        assert!(obj.contains_key("publishedAt"));
        assert_eq!(obj["summary"], "boom");
        assert!(obj.contains_key("configurations"));
        assert_eq!(obj["weaknesses"], serde_json::json!(["CWE-269"]));
        assert!(!obj.contains_key("epss"), "epss is cve-epss's field");
        assert!(!obj.contains_key("kev"), "kev is cve-kev's field");
        assert!(
            !obj.contains_key("pocUrls"),
            "pocUrls is cve-poc-github's field"
        );
    }

    #[test]
    fn the_patch_round_trips_into_a_cve_payload() {
        // The contract `persist_parent_payload` relies on: serialise, shallow-merge, re-type.
        // A key that does not exist on `CvePayload` would make that `from_value` fail and the
        // layer's findings would vanish with no error anywhere.
        let record = NvdRecord {
            metric: Some(SelectedMetric {
                score: 9.8,
                version: "3.1".into(),
                severity: Some("CRITICAL".into()),
            }),
            published_at: parse_nvd_instant("2021-12-10T10:15:09.143"),
            summary: Some("Log4Shell".into()),
            configurations: vec![CpeMatch {
                criteria: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*".into(),
                ..Default::default()
            }],
            weaknesses: vec!["CWE-502".into()],
        };
        let mut payload = serde_json::to_value(crate::types::OzPayload::Cve(
            crate::types::CvePayload::default(),
        ))
        .expect("serialise");
        let (serde_json::Value::Object(dst), serde_json::Value::Object(src)) =
            (&mut payload, &nvd_record_to_yield(&record).payload_patch)
        else {
            panic!("both sides must be objects")
        };
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }

        let merged: crate::types::OzPayload = serde_json::from_value(payload).expect("re-typed");
        match merged {
            crate::types::OzPayload::Cve(p) => {
                assert_eq!(p.cvss, Some(9.8));
                assert_eq!(p.cvss_version.as_deref(), Some("3.1"));
                assert_eq!(p.severity.as_deref(), Some("CRITICAL"));
                assert!(!p.kev, "an untouched field keeps its default");
                assert_eq!(p.epss, None);
                assert_eq!(p.configurations.len(), 1);
                assert_eq!(
                    p.configurations[0].criteria,
                    "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
                );
                assert_eq!(p.weaknesses, vec!["CWE-502".to_string()]);
            }
            other => panic!("the merge changed the payload type: {other:?}"),
        }
    }

    #[test]
    fn the_authoritative_flag_is_posted_only_when_a_record_came_back() {
        // This flag is the only thing holding the `cve-shodan` fallback phase closed. If it
        // were posted unconditionally, the fallback would never run and a CVE that NVD does
        // not know would silently stay unscored.
        let yielded = nvd_record_to_yield(&NvdRecord::default());
        assert_eq!(yielded.flags, vec![(FLAG_AUTHORITATIVE_ANSWERED, true)]);
        assert_eq!(
            yielded.payload_patch,
            serde_json::json!({}),
            "a record with nothing readable in it still patches nothing"
        );
    }

    #[test]
    fn an_unscored_record_still_reports_what_it_does_know() {
        let record = NvdRecord {
            metric: None,
            published_at: parse_nvd_instant("2024-01-01T00:00:00"),
            summary: Some("reserved".into()),
            ..Default::default()
        };
        let obj = nvd_record_to_yield(&record).payload_patch;
        let obj = obj.as_object().expect("object");
        assert!(
            !obj.contains_key("cvss"),
            "an unscored CVE must not be given a score"
        );
        assert!(!obj.contains_key("cvssVersion"));
        assert!(obj.contains_key("publishedAt"));
        assert_eq!(obj["summary"], "reserved");
        assert!(
            !obj.contains_key("configurations"),
            "no configurations were parsed"
        );
        assert!(!obj.contains_key("weaknesses"), "no weaknesses were parsed");
    }
}
