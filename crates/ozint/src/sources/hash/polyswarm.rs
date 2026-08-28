//! `hash-polyswarm` — PolySwarm's marketplace hash search, tier 2 of this category.
//!
//! ## Resolving the endpoint ambiguity
//!
//! `/v3/search/hash/{sha256}` vs `/v3/search/hash` looked like an open question. Neither is it,
//! measured 2026-08-25 with a real key:
//!
//! - `GET /v3/search/hash/{hash}` → **400** `{"result":"Hash type not supported"}`, for every
//!   hash type tried (md5, sha1, sha256) — the path segment after `hash/` is not the hash at
//!   all.
//! - `GET /v3/search/hash/{hash}?type=sha256` → the same 400, so `type` is not read from the
//!   query string either.
//! - `GET /v3/search/hash/{type}?hash={hash}` → **200**, real results. The path segment is the
//!   hash *type* (`md5`/`sha1`/`sha256`), and the hash itself is a query parameter — the
//!   reverse of what both candidate shapes assumed.
//!
//! `Authorization: {key}` (a raw key, no `Bearer` prefix — verified working as-is). A hash
//! with no marketplace history answers **HTTP 204 with an empty body**, not a 404 or a 200
//! with an empty array — [`fetch::dispatch_content_type`] already reads a 2xx empty body as
//! [`crate::fetch::OzBody::Empty`], so this tool folds that into `OkEmpty` alongside a genuine
//! `result: []`.
//!
//! ## Field ownership
//!
//! Owns `polyswarmScore` alone (`result[0].polyscore`, 0.0-1.0) on
//! [`crate::types::HashPayload`] — deliberately not `detections`/`engines_total`, which
//! `hash-virustotal` owns: PolySwarm's `assertions` are a paid-engine marketplace vote, a
//! different signal from VirusTotal's free-engine AV consensus, and blending the two ratios
//! into one field would silently pick a source `merge_patch` never surfaces the disagreement
//! on. Per-engine malware-family names (`assertions[].metadata.malware_family`) become rows,
//! the same non-conflicting channel `hash-otx` uses for its own family list.

use super::hash_kind;
use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const POLYSWARM_API_BASE: &str = "https://api.polyswarm.network/v3/search/hash/";
const ENV_VAR: &str = "POLYSWARM_API_KEY";
const MAX_FAMILY_ROWS: usize = 5;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct PolyswarmRecord {
    pub polyscore: Option<f64>,
    pub detections: u32,
    pub total_assertions: u32,
    pub malware_families: Vec<String>,
}

/// Parses a `GET /search/hash/{type}?hash=…` body. `Ok(None)` covers both the measured
/// negative shapes (`result: []`, or the caller already folded a 204 to an empty JSON body) —
/// PolySwarm genuinely has no artifact record for the hash. `Err` is reserved for a `result[0]`
/// this tool cannot read at all.
pub fn parse_polyswarm_response(
    json: &serde_json::Value,
) -> Result<Option<PolyswarmRecord>, String> {
    let Some(results) = json.get("result").and_then(|v| v.as_array()) else {
        return Err("PolySwarm response has no `result` array".to_string());
    };
    let Some(artifact) = results.first() else {
        return Ok(None);
    };

    let polyscore = artifact.get("polyscore").and_then(|v| v.as_f64());
    let assertions = artifact
        .get("assertions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let detections = assertions
        .iter()
        .filter(|a| a.get("verdict").and_then(|v| v.as_bool()) == Some(true))
        .count() as u32;
    let malware_families = assertions
        .iter()
        .filter_map(|a| a.get("metadata")?.get("malware_family")?.as_str())
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    Ok(Some(PolyswarmRecord {
        polyscore,
        detections,
        total_assertions: assertions.len() as u32,
        malware_families,
    }))
}

/// Owns `polyswarmScore` and nothing else on the payload — see the module doc for why
/// PolySwarm's own detection count stays out of `detections`/`engines_total`.
pub fn polyswarm_record_to_yield(record: &PolyswarmRecord) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if let Some(score) = record.polyscore {
        patch.insert("polyswarm_score".into(), serde_json::json!(score));
    }

    let mut rows = vec![OzRow {
        label: "PolySwarm engines".to_string(),
        value: format!(
            "{} / {} flagged malicious",
            record.detections, record.total_assertions
        ),
        ..Default::default()
    }];
    if !record.malware_families.is_empty() {
        let mut names = record.malware_families.clone();
        names.truncate(MAX_FAMILY_ROWS);
        rows.push(OzRow {
            label: "PolySwarm families".to_string(),
            value: names.join(", "),
            ..Default::default()
        });
    }

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows,
        ..Default::default()
    }
}

pub async fn run_polyswarm(hash: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };
    let Some(kind) = hash_kind(hash) else {
        // `normalize::normalize_hash` only ever hands this tool a 32/40/64-char hex string, so
        // this should be unreachable in the normal path — the same belt-and-braces posture
        // `youtube-channel`'s key check documents.
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("`{hash}` is not an MD5/SHA-1/SHA-256 length"),
            },
            None,
        );
    };

    let url = format!(
        "{POLYSWARM_API_BASE}{kind}?hash={}",
        urlencoding::encode(hash)
    );
    let headers = vec![("Authorization".to_string(), key)];
    let outcome = ctx
        .fetch(
            "hash-polyswarm",
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
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled OzOutcome was handled above");
    };
    // A 204 (measured negative case) folds to `OzBody::Empty` before this tool ever sees it.
    if matches!(resp.body, OzBody::Empty) {
        return DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        );
    }
    let OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "PolySwarm response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_polyswarm_response(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(None) => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(Some(record)) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(polyswarm_record_to_yield(&record)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_result() -> serde_json::Value {
        // Trimmed from the live EICAR SHA-256 response, 2026-08-25.
        serde_json::json!({
            "has_more": false,
            "limit": 50,
            "result": [{
                "artifact_id": "41363621986537527",
                "polyscore": 0.94,
                "assertions": [
                    { "author_name": "Qihoo 360", "verdict": true,
                      "metadata": { "malware_family": "qex.eicar.gen.gen" } },
                    { "author_name": "Filseclab", "verdict": true,
                      "metadata": { "malware_family": "EICAR.Test.File.zewa" } },
                    { "author_name": "SomeEngine", "verdict": false, "metadata": {} }
                ]
            }]
        })
    }

    #[test]
    fn parses_a_real_detected_artifact() {
        let record = parse_polyswarm_response(&real_result())
            .expect("parses")
            .expect("found");
        assert_eq!(record.polyscore, Some(0.94));
        assert_eq!(record.detections, 2);
        assert_eq!(record.total_assertions, 3);
        assert_eq!(record.malware_families.len(), 2);
    }

    #[test]
    fn an_empty_result_array_reads_as_none() {
        let json = serde_json::json!({ "result": [] });
        assert_eq!(parse_polyswarm_response(&json), Ok(None));
    }

    #[test]
    fn rejects_a_response_missing_result() {
        assert!(parse_polyswarm_response(&serde_json::json!({})).is_err());
    }

    #[test]
    fn yield_owns_only_polyswarm_score_on_the_payload() {
        let record = parse_polyswarm_response(&real_result())
            .expect("parses")
            .expect("found");
        let produced = polyswarm_record_to_yield(&record);
        let patch = produced.payload_patch.as_object().expect("object patch");
        assert_eq!(patch.len(), 1);
        assert_eq!(patch["polyswarm_score"], serde_json::json!(0.94));
    }

    #[test]
    fn family_row_deduplicates_and_caps() {
        let record = PolyswarmRecord {
            polyscore: Some(0.5),
            detections: 6,
            total_assertions: 6,
            malware_families: (0..10).map(|i| format!("family-{}", i % 3)).collect(),
        };
        let produced = polyswarm_record_to_yield(&record);
        let families_row = &produced.rows[1];
        assert!(
            families_row.value.split(", ").count() <= MAX_FAMILY_ROWS,
            "must cap even after dedup"
        );
    }

    // ── hash-type routing ───────────────────────────────────────────────

    #[test]
    fn hash_kind_selects_the_right_path_segment() {
        assert_eq!(hash_kind(&"a".repeat(64)), Some("sha256"));
        assert_eq!(hash_kind(&"a".repeat(40)), Some("sha1"));
        assert_eq!(hash_kind(&"a".repeat(32)), Some("md5"));
    }

    // ── arming ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_polyswarm(&"a".repeat(64), &crate::sources::ToolCtx::default()).await;
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
