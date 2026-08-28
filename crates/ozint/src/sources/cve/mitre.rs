//! `cve-mitre` — CVE.org's own CVE Record API, the last-resort fallback behind both NVD and
//! Shodan CVEDB. Keyless.
//!
//! `GET https://cveawg.mitre.org/api/cve/{CVE-ID}` — verified live 2026-08-25 against both an
//! old CVE (`CVE-2021-44228`, Log4Shell) and a very recent one: **HTTP 200**, a full CVE
//! Record JSON envelope (`cveMetadata` + `containers.cna`). An id CVE.org holds nothing on
//! answers **`404`**.
//!
//! ## Why this is safe to write `cvss`/`severity`/`summary` directly, unlike `cve-shodan`
//!
//! `cve-shodan`'s module doc explains why it must never write those fields when NVD already
//! did: Shodan's copy is *derived* from NVD/FIRST, so writing it next to the source of record
//! risks a silent last-writer-wins collision between two copies of the same claim. MITRE's
//! `containers.cna.metrics` is different in kind — it is the **CNA's own first-party
//! assessment** (the organisation MITRE delegated the CVE to, usually the vendor or a
//! coordinating body), not a copy of anyone else's number. There is nothing to double-count.
//!
//! ## Why it is still gated behind both NVD *and* Shodan, not NVD alone
//!
//! See `layer_plan::no_authoritative_or_aggregate_answer`'s own doc for the mechanism. In
//! short: if this fired whenever NVD merely stayed silent, it would run in the same layer as
//! `cve-shodan` (gated on the same, weaker condition) and the two would be free to write
//! `cvss`/`severity`/`summary` in the same pass — reintroducing exactly the last-writer-wins
//! collision this category's whole two-phase shape exists to avoid, one level down. Ordering
//! the two fallbacks strictly (Shodan first, MITRE only once Shodan *also* answered nothing)
//! keeps every write attributable to exactly one source.
//!
//! ## Field ownership
//!
//! `cvss`/`cvssVersion`/`severity`/`publishedAt`/`summary` — the same five `cve-shodan` would
//! own had it answered. Never both write in the same investigation, by construction of the
//! gate above. It also writes `configurations`/`weaknesses`, reshaped from
//! `containers.cna.affected[].versions[]` and `containers.cna.problemTypes[]` respectively —
//! CVE Record v5 has no `cpeMatch`/`weaknesses` array of its own, so these are derived rather
//! than a direct read the way NVD's are.

use chrono::{DateTime, Utc};

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::CpeMatch;

const MITRE_CVE_BASE: &str = "https://cveawg.mitre.org/api/cve/";

/// `summary` truncation, same figure and same reason as `cve-shodan`'s.
const MAX_SUMMARY_CHARS: usize = 500;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MitreCveInfo {
    pub cvss: Option<f64>,
    pub cvss_version: Option<String>,
    pub severity: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub summary: Option<String>,
    /// Derived from `containers.cna.affected[].versions[]` — CVE Record v5 has no `cpeMatch`
    /// array at all, so this is a reshaping, not a direct read. `criteria` is a CPE URI when
    /// `affected[].cpes[]` supplies one, otherwise a `vendor:product` fallback identifier.
    pub configurations: Vec<CpeMatch>,
    /// `containers.cna.problemTypes[].descriptions[].cweId` — CVE Record v5's name for the
    /// same concept NVD calls `weaknesses`.
    pub weaknesses: Vec<String>,
}

fn truncate_summary(raw: &str) -> String {
    if raw.chars().count() <= MAX_SUMMARY_CHARS {
        raw.to_string()
    } else {
        let truncated: String = raw.chars().take(MAX_SUMMARY_CHARS).collect();
        format!("{truncated}\u{2026}")
    }
}

/// Reads the first CVSS metric out of `containers.cna.metrics[]` — an array because a CNA may
/// publish more than one scale; the first entry is taken as the CNA's leading assessment
/// rather than picking a "highest revision" the way `cve-shodan` does, since MITRE's schema
/// does not guarantee more than one is ever present.
fn select_cvss(cna: &serde_json::Value) -> (Option<f64>, Option<String>) {
    let metrics = cna.get("metrics").and_then(|v| v.as_array());
    let Some(metrics) = metrics else {
        return (None, None);
    };

    for metric in metrics {
        for (key, version) in [
            ("cvssV4_0", "4.0"),
            ("cvssV3_1", "3.1"),
            ("cvssV3_0", "3.0"),
            ("cvssV2_0", "2.0"),
        ] {
            if let Some(block) = metric.get(key) {
                let score = block.get("baseScore").and_then(|v| v.as_f64());
                let severity_label = block
                    .get("baseSeverity")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                if score.is_some() {
                    return (score, severity_label.or_else(|| Some(version.to_string())));
                }
            }
        }
    }
    (None, None)
}

/// Derives vulnerable product/version ranges from `containers.cna.affected[].versions[]`.
///
/// CVE Record v5 has no `cpeMatch` array — a CNA reports affected products as
/// `{vendor, product, versions: [{version, lessThan|lessThanOrEqual, status}]}`. Mapped onto
/// the same [`CpeMatch`] shape NVD uses: `version` becomes the inclusive start, `lessThan`/
/// `lessThanOrEqual` become the end bound. A version entry explicitly marked `"unaffected"` is
/// dropped, same reasoning as NVD's `vulnerable: false` entries. Pure and tested.
pub fn parse_configurations(cna: &serde_json::Value) -> Vec<CpeMatch> {
    let mut out = Vec::new();
    let Some(affected) = cna.get("affected").and_then(|v| v.as_array()) else {
        return out;
    };

    for entry in affected {
        let criteria = entry
            .get("cpes")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                let vendor = entry
                    .get("vendor")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let product = entry
                    .get("product")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                format!("{vendor}:{product}")
            });

        let Some(versions) = entry.get("versions").and_then(|v| v.as_array()) else {
            continue;
        };
        for version in versions {
            if version.get("status").and_then(|v| v.as_str()) == Some("unaffected") {
                continue;
            }
            let version_start_including = version
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let version_end_excluding = version
                .get("lessThan")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let version_end_including = version
                .get("lessThanOrEqual")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            if version_start_including.is_none()
                && version_end_excluding.is_none()
                && version_end_including.is_none()
            {
                continue;
            }
            out.push(CpeMatch {
                criteria: criteria.clone(),
                version_start_including,
                version_start_excluding: None,
                version_end_including,
                version_end_excluding,
            });
        }
    }
    out
}

/// Reads CWE ids out of `containers.cna.problemTypes[].descriptions[].cweId`, de-duplicated.
/// Pure and tested.
pub fn parse_weaknesses(cna: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(problem_types) = cna.get("problemTypes").and_then(|v| v.as_array()) else {
        return out;
    };
    for problem_type in problem_types {
        let Some(descriptions) = problem_type.get("descriptions").and_then(|v| v.as_array()) else {
            continue;
        };
        for d in descriptions {
            if let Some(cwe_id) = d.get("cweId").and_then(|v| v.as_str())
                && !out.iter().any(|existing| existing == cwe_id)
            {
                out.push(cwe_id.to_string());
            }
        }
    }
    out
}

/// Parses one CVE Record JSON body. `Err` only when the CNA container itself is missing —
/// every field inside it is independently optional, same convention as `cve-shodan`'s parser.
pub fn parse_mitre_cve(json: &serde_json::Value) -> Result<MitreCveInfo, String> {
    let cna = json
        .get("containers")
        .and_then(|c| c.get("cna"))
        .ok_or_else(|| "MITRE CVE record has no `containers.cna`".to_string())?;

    let (cvss, severity) = select_cvss(cna);
    let cvss_version = if cvss.is_some() {
        cna.get("metrics")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|m| {
                    ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
                        .iter()
                        .find(|k| m.get(**k).is_some())
                        .map(|k| k.trim_start_matches("cvssV").replace('_', ".").to_string())
                })
            })
    } else {
        None
    };

    let summary = cna
        .get("descriptions")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
                .or_else(|| arr.first())
        })
        .and_then(|d| d.get("value"))
        .and_then(|v| v.as_str())
        .map(truncate_summary);

    let published_at = json
        .get("cveMetadata")
        .and_then(|m| m.get("datePublished"))
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));
    let configurations = parse_configurations(cna);
    let weaknesses = parse_weaknesses(cna);

    Ok(MitreCveInfo {
        cvss,
        cvss_version,
        severity,
        published_at,
        summary,
        configurations,
        weaknesses,
    })
}

pub fn mitre_to_yield(info: &MitreCveInfo) -> ToolYield {
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
    if !info.configurations.is_empty() {
        patch.insert(
            "configurations".to_string(),
            serde_json::json!(info.configurations),
        );
    }
    if !info.weaknesses.is_empty() {
        patch.insert("weaknesses".to_string(), serde_json::json!(info.weaknesses));
    }
    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        ..Default::default()
    }
}

pub async fn run_mitre(cve: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{MITRE_CVE_BASE}{}", urlencoding::encode(cve));
    let outcome = ctx
        .fetch("cve-mitre", cve, &url, fetch::OzFetchOptions::default())
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // Verified live 2026-08-25: an id CVE.org holds nothing on answers 404 — absence, not
    // failure, same reasoning as this category's other keyless fallbacks.
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
                message: "MITRE CVE response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_mitre_cve(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(info) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(mitre_to_yield(&info)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed real Log4Shell CNA container, transcribed from a live 2026-08-25 call.
    fn log4shell_record() -> serde_json::Value {
        serde_json::json!({
            "cveMetadata": {
                "cveId": "CVE-2021-44228",
                "datePublished": "2021-12-10T00:00:00.000Z"
            },
            "containers": {
                "cna": {
                    "descriptions": [
                        { "lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP." }
                    ],
                    "metrics": [
                        { "cvssV3_1": { "baseScore": 10.0, "baseSeverity": "CRITICAL" } }
                    ],
                    "affected": [{
                        "vendor": "Apache",
                        "product": "Log4j2",
                        "versions": [
                            { "version": "2.0-beta9", "lessThan": "2.15.0", "status": "affected" },
                            { "version": "2.16.0", "status": "unaffected" }
                        ]
                    }],
                    "problemTypes": [{
                        "descriptions": [
                            { "lang": "en", "description": "Improper Restriction of XML External Entity Reference", "cweId": "CWE-611" }
                        ]
                    }]
                }
            }
        })
    }

    #[test]
    fn parses_a_real_cna_record() {
        let info = parse_mitre_cve(&log4shell_record()).expect("parses");
        assert_eq!(info.cvss, Some(10.0));
        assert_eq!(info.severity.as_deref(), Some("CRITICAL"));
        assert_eq!(info.cvss_version.as_deref(), Some("3.1"));
        assert!(info.summary.as_deref().unwrap().contains("Log4j2"));
        assert!(info.published_at.is_some());
        assert_eq!(
            info.configurations.len(),
            1,
            "the unaffected version entry must be dropped"
        );
        assert_eq!(info.configurations[0].criteria, "Apache:Log4j2");
        assert_eq!(
            info.configurations[0].version_start_including.as_deref(),
            Some("2.0-beta9")
        );
        assert_eq!(
            info.configurations[0].version_end_excluding.as_deref(),
            Some("2.15.0")
        );
        assert_eq!(info.weaknesses, vec!["CWE-611".to_string()]);
    }

    #[test]
    fn a_cpe_supplied_by_affected_is_preferred_over_the_vendor_product_fallback() {
        let json = serde_json::json!({
            "cveMetadata": {},
            "containers": { "cna": {
                "affected": [{
                    "vendor": "Apache",
                    "product": "Log4j2",
                    "cpes": ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
                    "versions": [{ "version": "2.14.1", "status": "affected" }]
                }]
            }}
        });
        let info = parse_mitre_cve(&json).expect("parses");
        assert_eq!(
            info.configurations[0].criteria,
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        );
    }

    #[test]
    fn no_affected_or_problem_types_is_an_empty_list_not_an_error() {
        let json = serde_json::json!({
            "cveMetadata": {},
            "containers": { "cna": { "descriptions": [] } }
        });
        let info = parse_mitre_cve(&json).expect("parses");
        assert!(info.configurations.is_empty());
        assert!(info.weaknesses.is_empty());
    }

    #[test]
    fn rejects_a_response_with_no_cna_container() {
        assert!(parse_mitre_cve(&serde_json::json!({ "cveMetadata": {} })).is_err());
    }

    #[test]
    fn a_record_with_no_metrics_at_all_yields_no_score_but_still_parses() {
        let json = serde_json::json!({
            "cveMetadata": {},
            "containers": { "cna": { "descriptions": [] } }
        });
        let info = parse_mitre_cve(&json).expect("parses");
        assert_eq!(info.cvss, None);
        assert_eq!(info.summary, None);
    }

    #[test]
    fn yield_owns_the_same_five_fields_cve_shodan_would_have_plus_configurations_and_weaknesses() {
        let info = parse_mitre_cve(&log4shell_record()).expect("parses");
        let produced = mitre_to_yield(&info);
        let obj = produced.payload_patch.as_object().unwrap();
        for key in [
            "cvss",
            "cvssVersion",
            "severity",
            "publishedAt",
            "summary",
            "configurations",
            "weaknesses",
        ] {
            assert!(obj.contains_key(key), "missing `{key}`");
        }
    }

    #[test]
    fn yield_omits_absent_fields_entirely() {
        let produced = mitre_to_yield(&MitreCveInfo::default());
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }

    #[tokio::test]
    #[ignore = "hits a live third-party endpoint"]
    async fn the_live_endpoint_still_answers_the_shape_we_parse() {
        let outcome = run_mitre("CVE-2021-44228", &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { .. }, Some(produced)) => {
                assert!(produced.payload_patch.get("cvss").is_some());
            }
            other => panic!("expected results against a well-known CVE, got {other:?}"),
        }
    }
}
