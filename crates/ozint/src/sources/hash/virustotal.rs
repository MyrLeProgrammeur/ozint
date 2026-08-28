//! `hash-virustotal` — VirusTotal v3's file report, the multi-engine AV consensus this
//! category's tier-2 escalation is keyed on.
//!
//! `GET /api/v3/files/{hash}`, header `x-apikey`. Verified 2026-08-25 against the EICAR test
//! file's SHA-256: **HTTP 200**, `data.attributes.last_analysis_stats` =
//! `{"malicious":43,"suspicious":0,"undetected":4,"harmless":0,"timeout":21,
//! "confirmed-timeout":0,"failure":2,"type-unsupported":5}`. A hash nobody has ever submitted
//! answers **HTTP 404** with `{"error":{"code":"NotFoundError", ...}}` — unlike `cve-nvd`,
//! absence here is a real non-2xx, not a 200 with an empty body, so `fold_fetch_failure`'s
//! ordinary 404-as-not-necessarily-failure handling below is load-bearing.
//!
//! ## What counts as a "detection", since VT's own stats object has eight buckets
//!
//! [`HashPayload::detections`] is `malicious` alone — a file's plain positive count, the
//! number the tier-2 escalation threshold (`layer_plan::HASH_TIER2_MIN_DETECTIONS`) is meant
//! to read. [`HashPayload::engines_total`] is the sum of every bucket VT reports, so the ratio
//! rendered as a bar (`12 / 68 engines`) reflects the whole engine roster that was actually
//! queried for this file, not a curated subset. `suspicious`, `timeout`, `failure` and
//! `type-unsupported` engines are real engines that ran and did not return a clean
//! malicious/harmless verdict; folding them out of the denominator would inflate the ratio the
//! chip shows.
//!
//! Free-tier quota is 4 requests/minute, 500/day — the tightest of this category's five
//! sources by a wide margin, which is why `registry::ToolDef::ttl_secs` caches this one
//! hardest (24h, same as `cve-nvd`'s NVD entry).

use crate::fetch::{self, OzBody, OzOutcome};
use crate::layer_plan::FACT_DETECTIONS;
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const VT_API_BASE: &str = "https://www.virustotal.com/api/v3/files/";
const ENV_VAR: &str = "VIRUSTOTAL_API_KEY";

/// The subset of a VT file report this tool reads.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VtRecord {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub malicious: u32,
    pub engines_total: u32,
    pub meaningful_name: Option<String>,
    pub suggested_threat_label: Option<String>,
}

fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parses `data.attributes` of a `GET /files/{hash}` response.
pub fn parse_vt_response(json: &serde_json::Value) -> Result<VtRecord, String> {
    let attrs = json
        .get("data")
        .and_then(|d| d.get("attributes"))
        .ok_or_else(|| "VirusTotal response has no `data.attributes`".to_string())?;

    let stats = attrs
        .get("last_analysis_stats")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "VirusTotal response has no `last_analysis_stats`".to_string())?;
    let stat = |key: &str| stats.get(key).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let malicious = stat("malicious");
    let engines_total: u32 = stats.values().filter_map(|v| v.as_u64()).sum::<u64>() as u32;

    let suggested_threat_label = attrs
        .get("popular_threat_classification")
        .and_then(|c| c.get("suggested_threat_label"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    Ok(VtRecord {
        md5: nonempty(attrs.get("md5").and_then(|v| v.as_str())),
        sha1: nonempty(attrs.get("sha1").and_then(|v| v.as_str())),
        sha256: nonempty(attrs.get("sha256").and_then(|v| v.as_str())),
        malicious,
        engines_total,
        meaningful_name: nonempty(attrs.get("meaningful_name").and_then(|v| v.as_str())),
        suggested_threat_label,
    })
}

/// Turns a parsed record into a [`ToolYield`]. Owns `md5`/`sha1`/`sha256`/`detections`/
/// `engines_total` on [`crate::types::HashPayload`] and posts [`FACT_DETECTIONS`] — the fact
/// `layer_plan::has_detections` reads to open this category's tier-2 phase.
pub fn vt_record_to_yield(record: &VtRecord) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if let Some(md5) = &record.md5 {
        patch.insert("md5".into(), serde_json::json!(md5));
    }
    if let Some(sha1) = &record.sha1 {
        patch.insert("sha1".into(), serde_json::json!(sha1));
    }
    if let Some(sha256) = &record.sha256 {
        patch.insert("sha256".into(), serde_json::json!(sha256));
    }
    patch.insert("detections".into(), serde_json::json!(record.malicious));
    patch.insert(
        "engines_total".into(),
        serde_json::json!(record.engines_total),
    );

    let mut rows = Vec::new();
    if let Some(name) = &record.meaningful_name {
        rows.push(OzRow {
            label: "File name".to_string(),
            value: name.clone(),
            ..Default::default()
        });
    }
    if let Some(label) = &record.suggested_threat_label {
        rows.push(OzRow {
            label: "VT threat label".to_string(),
            value: label.clone(),
            ..Default::default()
        });
    }

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows,
        facts: vec![(FACT_DETECTIONS, record.malicious as f64)],
        ..Default::default()
    }
}

pub async fn run_virustotal(hash: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!("{VT_API_BASE}{hash}");
    let headers = vec![("x-apikey".to_string(), key)];
    let outcome = ctx
        .fetch(
            "hash-virustotal",
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
    // A hash VirusTotal has never seen submitted answers 404 — a clean, positive "unknown",
    // not a probe failure. Measured 2026-08-25.
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
                message: "VirusTotal response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_vt_response(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(record) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(vt_record_to_yield(&record)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real EICAR SHA-256 record's `attributes`, trimmed to the fields this tool reads.
    /// Transcribed from a live 2026-08-25 call.
    fn eicar_attributes() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "attributes": {
                    "md5": "44d88612fea8a8f36de82e1278abb02f",
                    "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
                    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    "meaningful_name": "eicar.com",
                    "last_analysis_stats": {
                        "malicious": 43, "suspicious": 0, "undetected": 4, "harmless": 0,
                        "timeout": 21, "confirmed-timeout": 0, "failure": 2, "type-unsupported": 5
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "virus.eicar/test"
                    }
                }
            }
        })
    }

    #[test]
    fn parses_a_real_detected_record() {
        let record = parse_vt_response(&eicar_attributes()).expect("record parses");
        assert_eq!(record.malicious, 43);
        assert_eq!(record.engines_total, 43 + 4 + 21 + 2 + 5);
        assert_eq!(
            record.md5.as_deref(),
            Some("44d88612fea8a8f36de82e1278abb02f")
        );
        assert_eq!(
            record.suggested_threat_label.as_deref(),
            Some("virus.eicar/test")
        );
    }

    #[test]
    fn rejects_a_response_missing_last_analysis_stats() {
        let json = serde_json::json!({ "data": { "attributes": {} } });
        assert!(parse_vt_response(&json).is_err());
    }

    #[test]
    fn rejects_a_response_missing_data() {
        let json = serde_json::json!({});
        assert!(parse_vt_response(&json).is_err());
    }

    #[test]
    fn yield_owns_exactly_the_documented_fields_and_posts_the_detections_fact() {
        let record = parse_vt_response(&eicar_attributes()).expect("record parses");
        let produced = vt_record_to_yield(&record);
        let patch = produced.payload_patch.as_object().expect("object patch");
        for key in ["md5", "sha1", "sha256", "detections", "engines_total"] {
            assert!(patch.contains_key(key), "missing `{key}`");
        }
        assert_eq!(
            patch.len(),
            5,
            "must write no field beyond the documented five"
        );
        assert_eq!(produced.facts, vec![(FACT_DETECTIONS, 43.0)]);
    }

    #[test]
    fn a_clean_record_posts_zero_detections_not_an_absent_fact() {
        let clean = VtRecord {
            malicious: 0,
            engines_total: 70,
            ..Default::default()
        };
        let produced = vt_record_to_yield(&clean);
        assert_eq!(produced.facts, vec![(FACT_DETECTIONS, 0.0)]);
        assert_eq!(produced.payload_patch["detections"], serde_json::json!(0));
    }

    // ── arming ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_virustotal(&"a".repeat(64), &crate::sources::ToolCtx::default()).await;
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
