//! `hash-hybrid-analysis` — Falcon Sandbox's hash search, tier 2 of this category.
//!
//! `GET /api/v2/search/hash?hash={hash}`, headers `api-key` and `User-Agent: Falcon Sandbox`
//! (the second is not optional — CrowdStrike's own docs require it and this crate takes that
//! at face value rather than testing its absence against a paid key). Verified 2026-08-25
//! against the EICAR SHA-256: **the `www.` host 301-redirects to the bare
//! `hybrid-analysis.com`**, so this tool calls the bare host directly rather than spending an
//! extra hop on every request. A hash nobody has submitted answers **HTTP 404** with
//! `{"message":"Requested hash not found"}`.
//!
//! For the EICAR hash the endpoint returned **665 sandbox reports** — every submitter's every
//! run, most `state: "ERROR"` (`FILE_TYPE_BAD_ERROR`, since EICAR is not a real executable in
//! most sandboxed environments) but a real minority `state: "SUCCESS"` with `verdict:
//! "malicious"`. The shape carries nothing beyond `id`/`environment_description`/`state`/
//! `error_type`/`verdict` per report — no threat score, no family, no IOC list. A deeper
//! report needs a second call to `/api/v2/report/{id}/summary` per report id, which this
//! tool does not make: fanning out 665 follow-up requests for one hash is the kind of spend
//! this category's whole tier-2 gate (`layer_plan::has_detections`) exists to bound, and 665
//! is itself already a signal worth surfacing without it.
//!
//! ## Field ownership
//!
//! Owns `sandboxVerdict` and `sandboxReports` on [`crate::types::HashPayload`]. `sandboxVerdict`
//! is `"malicious"` when at least one report says so, `"no-detections"` when every report
//! completed with some other verdict, and omitted entirely when every report is an `ERROR` —
//! that last case means the sandbox never actually ran the sample, which is a different fact
//! from "ran it and it looked clean" and this tool does not blur the two.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const HA_API_BASE: &str = "https://hybrid-analysis.com/api/v2/search/hash";
const ENV_VAR: &str = "HYBRID_ANALYSIS_KEY";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct HaRecord {
    pub total_reports: u32,
    pub malicious_reports: u32,
    /// Reports that completed (`state == "SUCCESS"`) with some verdict other than malicious.
    pub other_verdict_reports: u32,
}

/// Parses a `GET /search/hash` body. An empty `reports` array on a 200 (rather than the
/// measured 404) has not been observed but is handled the same way as zero — `Ok(None)`.
pub fn parse_ha_response(json: &serde_json::Value) -> Result<Option<HaRecord>, String> {
    let reports = json
        .get("reports")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Hybrid Analysis response has no `reports` array".to_string())?;
    if reports.is_empty() {
        return Ok(None);
    }

    let mut malicious_reports = 0u32;
    let mut other_verdict_reports = 0u32;
    for report in reports {
        match report.get("verdict").and_then(|v| v.as_str()) {
            Some("malicious") => malicious_reports += 1,
            Some(_) => other_verdict_reports += 1,
            None => {}
        }
    }

    Ok(Some(HaRecord {
        total_reports: reports.len() as u32,
        malicious_reports,
        other_verdict_reports,
    }))
}

/// Owns `sandboxVerdict`/`sandboxReports` and nothing else — see the module doc for the
/// three-way verdict rule.
pub fn ha_record_to_yield(record: &HaRecord) -> ToolYield {
    let mut patch = serde_json::Map::new();
    patch.insert(
        "sandbox_reports".into(),
        serde_json::json!(record.total_reports),
    );
    let verdict = if record.malicious_reports > 0 {
        Some("malicious")
    } else if record.other_verdict_reports > 0 {
        Some("no-detections")
    } else {
        None
    };
    if let Some(verdict) = verdict {
        patch.insert("sandbox_verdict".into(), serde_json::json!(verdict));
    }

    let rows = vec![OzRow {
        label: "Sandbox runs".to_string(),
        value: format!(
            "{} malicious / {} total",
            record.malicious_reports, record.total_reports
        ),
        ..Default::default()
    }];

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows,
        ..Default::default()
    }
}

pub async fn run_hybrid_analysis(hash: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!("{HA_API_BASE}?hash={}", urlencoding::encode(hash));
    let headers = vec![
        ("api-key".to_string(), key),
        ("User-Agent".to_string(), "Falcon Sandbox".to_string()),
    ];
    let outcome = ctx
        .fetch(
            "hash-hybrid-analysis",
            hash,
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
    // Measured 2026-08-25: a hash with no sandbox history answers 404 with a plain message
    // body, not an empty `reports` array on a 200.
    if let OzOutcome::HttpError { status: 404, .. } = &outcome {
        return DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default()));
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
                message: "Hybrid Analysis response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_ha_response(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(None) => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(Some(record)) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults {
                count: record.total_reports,
            },
            Some(ha_record_to_yield(&record)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mixed_reports() -> serde_json::Value {
        serde_json::json!({
            "sha256s": ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"],
            "reports": [
                { "id": "a", "state": "ERROR", "error_type": "FILE_TYPE_BAD_ERROR", "verdict": null },
                { "id": "b", "state": "SUCCESS", "verdict": "malicious" },
                { "id": "c", "state": "SUCCESS", "verdict": "malicious" },
                { "id": "d", "state": "SUCCESS", "verdict": "no specific threat" }
            ]
        })
    }

    #[test]
    fn parses_a_real_mixed_report_set() {
        let record = parse_ha_response(&mixed_reports())
            .expect("parses")
            .expect("found");
        assert_eq!(record.total_reports, 4);
        assert_eq!(record.malicious_reports, 2);
        assert_eq!(
            record.other_verdict_reports, 1,
            "the ERROR report with no verdict is not counted"
        );
    }

    #[test]
    fn empty_reports_reads_as_none() {
        let json = serde_json::json!({ "reports": [] });
        assert_eq!(parse_ha_response(&json), Ok(None));
    }

    #[test]
    fn rejects_a_response_missing_reports() {
        assert!(parse_ha_response(&serde_json::json!({})).is_err());
    }

    #[test]
    fn yield_reports_malicious_when_any_report_says_so() {
        let record = HaRecord {
            total_reports: 4,
            malicious_reports: 2,
            other_verdict_reports: 1,
        };
        let produced = ha_record_to_yield(&record);
        assert_eq!(
            produced.payload_patch["sandbox_verdict"],
            serde_json::json!("malicious")
        );
        assert_eq!(
            produced.payload_patch["sandbox_reports"],
            serde_json::json!(4)
        );
    }

    #[test]
    fn yield_reports_no_detections_when_nothing_was_malicious() {
        let record = HaRecord {
            total_reports: 3,
            malicious_reports: 0,
            other_verdict_reports: 2,
        };
        let produced = ha_record_to_yield(&record);
        assert_eq!(
            produced.payload_patch["sandbox_verdict"],
            serde_json::json!("no-detections")
        );
    }

    #[test]
    fn yield_omits_verdict_when_every_report_only_errored() {
        let record = HaRecord {
            total_reports: 5,
            malicious_reports: 0,
            other_verdict_reports: 0,
        };
        let produced = ha_record_to_yield(&record);
        assert!(
            produced.payload_patch.get("sandbox_verdict").is_none(),
            "an all-ERROR sample means the sandbox never ran it, not that it looked clean"
        );
        assert_eq!(
            produced.payload_patch["sandbox_reports"],
            serde_json::json!(5)
        );
    }

    // ── arming ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome =
            run_hybrid_analysis(&"a".repeat(64), &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNoKey { env_var }, produced) => {
                assert_eq!(env_var, ENV_VAR);
                assert!(produced.is_none());
            }
            other => panic!("expected SkippedNoKey without a key, got {other:?}"),
        }

        if let Some(v) = prev {
            unsafe { std::env::set_var(ENV_VAR, v) };
        }
    }
}
