//! `hash-otx` — AlienVault OTX's file-indicator general section.
//!
//! `GET /api/v1/indicators/file/{hash}/general`, header `X-OTX-API-KEY`. Verified 2026-08-25
//! against the EICAR SHA-256 (50 pulses) and a random unseen hash: **HTTP 200 in both cases**
//! — OTX never answers a non-2xx for an unknown indicator, it just returns
//! `pulse_info.count: 0` and an empty `base_indicator: {}`. That makes this the third source
//! in this crate (after `cve-nvd` and `cve-epss`) where absence is a 200, not a 404, and this
//! tool needs no special status mapping as a result.
//!
//! ## Field ownership
//!
//! Owns `pulseCount` alone on [`crate::types::HashPayload`]. `pulse_info.related.other
//! .malware_families` — an aggregate list across every pulse referencing the hash — is real
//! and verified (24 distinct entries for the EICAR sample, from `"Emotet"` to `"Mirai"` to
//! `"Eicar"` itself), but it names no field this tool owns; it becomes rows instead, which
//! `ToolYield::rows` can safely accumulate alongside every other tool's rows without the
//! last-writer-wins collision a payload field would risk.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const OTX_API_BASE: &str = "https://otx.alienvault.com/api/v1/indicators/file/";
const ENV_VAR: &str = "ALIENVAULT_OTX_KEY";

/// Max malware-family names rendered as a row — the EICAR sample's `related.other
/// .malware_families` ran to 24 entries, most of them noise from unrelated pulses reusing the
/// indicator; a handful is a summary, the full list is not.
const MAX_FAMILY_ROWS: usize = 8;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct OtxRecord {
    pub pulse_count: u32,
    pub malware_families: Vec<String>,
}

/// Parses a `GET /indicators/file/{hash}/general` body. Never `Err` for a well-formed OTX
/// response — `pulse_info.count` absent is read as zero rather than rejected, since a
/// genuinely malformed body from this endpoint has not been observed and this tool would
/// rather under-report than fail loudly over a field OTX is free to omit.
pub fn parse_otx_response(json: &serde_json::Value) -> OtxRecord {
    let pulse_info = json.get("pulse_info");
    let pulse_count = pulse_info
        .and_then(|p| p.get("count"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    let malware_families = pulse_info
        .and_then(|p| p.get("related"))
        .and_then(|r| r.get("other"))
        .and_then(|o| o.get("malware_families"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|f| f.as_str())
                .map(str::trim)
                .filter(|f| !f.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    OtxRecord {
        pulse_count,
        malware_families,
    }
}

/// Owns `pulseCount` and nothing else on the payload; malware-family names become rows, not a
/// payload field — see the module doc for why.
pub fn otx_record_to_yield(record: &OtxRecord) -> ToolYield {
    let mut rows = Vec::new();
    if !record.malware_families.is_empty() {
        let mut names = record.malware_families.clone();
        names.truncate(MAX_FAMILY_ROWS);
        rows.push(OzRow {
            label: "OTX malware families".to_string(),
            value: names.join(", "),
            ..Default::default()
        });
    }

    ToolYield {
        payload_patch: serde_json::json!({ "pulse_count": record.pulse_count }),
        rows,
        ..Default::default()
    }
}

pub async fn run_otx(hash: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!("{OTX_API_BASE}{hash}/general");
    let headers = vec![("X-OTX-API-KEY".to_string(), key)];
    let outcome = ctx
        .fetch(
            "hash-otx",
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
    let OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "OTX response was not JSON".to_string(),
            },
            None,
        );
    };

    let record = parse_otx_response(json);
    if record.pulse_count == 0 {
        return DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        );
    }
    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults {
            count: record.pulse_count,
        },
        Some(otx_record_to_yield(&record)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_pulse_backed_hash() {
        // Trimmed from the live EICAR SHA-256 response, 2026-08-25.
        let json = serde_json::json!({
            "pulse_info": {
                "count": 50,
                "related": { "other": { "malware_families": ["", "Emotet", "Mirai", "Eicar"] } }
            }
        });
        let record = parse_otx_response(&json);
        assert_eq!(record.pulse_count, 50);
        assert_eq!(
            record.malware_families,
            vec!["Emotet", "Mirai", "Eicar"],
            "blank entries dropped"
        );
    }

    #[test]
    fn a_never_seen_hash_reads_as_zero_pulses_not_an_error() {
        // The real negative-case shape: `base_indicator: {}`, `pulse_info.count: 0`.
        let json = serde_json::json!({
            "base_indicator": {},
            "pulse_info": { "count": 0, "pulses": [] }
        });
        let record = parse_otx_response(&json);
        assert_eq!(record.pulse_count, 0);
        assert!(record.malware_families.is_empty());
    }

    #[test]
    fn missing_pulse_info_entirely_reads_as_zero_rather_than_failing() {
        let record = parse_otx_response(&serde_json::json!({}));
        assert_eq!(record.pulse_count, 0);
    }

    #[test]
    fn yield_owns_only_pulse_count_on_the_payload() {
        let record = OtxRecord {
            pulse_count: 12,
            malware_families: vec!["Emotet".to_string()],
        };
        let produced = otx_record_to_yield(&record);
        let patch = produced.payload_patch.as_object().expect("object patch");
        assert_eq!(patch.len(), 1);
        assert_eq!(patch["pulse_count"], serde_json::json!(12));
        assert_eq!(
            produced.rows.len(),
            1,
            "families become a row, not a payload field"
        );
    }

    #[test]
    fn family_row_is_capped_rather_than_dumping_every_pulse() {
        let record = OtxRecord {
            pulse_count: 1,
            malware_families: (0..20).map(|i| format!("family-{i}")).collect(),
        };
        let produced = otx_record_to_yield(&record);
        let listed = produced.rows[0].value.split(", ").count();
        assert_eq!(listed, MAX_FAMILY_ROWS);
    }

    // ── arming ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_otx(&"a".repeat(64), &crate::sources::ToolCtx::default()).await;
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
