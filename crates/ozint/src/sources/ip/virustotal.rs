//! `ip-virustotal` — VirusTotal v3's IP-address report. Owns `vtMalicious`/`vtReputation` on
//! [`crate::types::IpPayload`].
//!
//! `GET /api/v3/ip_addresses/{ip}`, header `x-apikey`. Verified live 2026-08-25 against
//! `8.8.8.8`: **HTTP 200**, `data.attributes.last_analysis_stats` (the same eight-bucket shape
//! `hash-virustotal` reads), `data.attributes.reputation` (signed), `data.attributes.as_owner`,
//! `data.attributes.country`, `data.attributes.tags`.
//!
//! Shares the API key and the account quota with `hash-virustotal` and `dom-virustotal` — see
//! `registry::rate_limits_for`'s `"virustotal"` bucket, registered once for all three so the
//! 4/min · 500/day free-tier budget is a crate-wide fact, not a per-tool one nobody enforces.
//! Cached for 24h, same as `hash-virustotal`, for the same reason: the tightest quota in this
//! crate deserves the hardest cache.
//!
//! ## `detections` is `malicious` alone, same convention as `hash-virustotal`
//!
//! [`IpVtRecord::malicious`] reads `last_analysis_stats.malicious` — the plain positive count,
//! not a blend with `suspicious`/`harmless`/etc. Kept as its own field on `IpPayload`
//! (`vtMalicious`) rather than reusing `abuseScore`: a VT engine-consensus count and an
//! AbuseIPDB community-report confidence are different metrics from different providers, and
//! collapsing them into one number would hide which source said what.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const VT_IP_BASE: &str = "https://www.virustotal.com/api/v3/ip_addresses/";
const ENV_VAR: &str = "VIRUSTOTAL_API_KEY";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct IpVtRecord {
    pub malicious: u32,
    pub reputation: i64,
    pub as_owner: Option<String>,
    pub country: Option<String>,
}

fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub fn parse_ip_vt_response(json: &serde_json::Value) -> Result<IpVtRecord, String> {
    let attrs = json
        .get("data")
        .and_then(|d| d.get("attributes"))
        .ok_or_else(|| "VirusTotal response has no `data.attributes`".to_string())?;

    let malicious = attrs
        .get("last_analysis_stats")
        .and_then(|v| v.get("malicious"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let reputation = attrs
        .get("reputation")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    Ok(IpVtRecord {
        malicious,
        reputation,
        as_owner: nonempty(attrs.get("as_owner").and_then(|v| v.as_str())),
        country: nonempty(attrs.get("country").and_then(|v| v.as_str())),
    })
}

/// Owns `vtMalicious`/`vtReputation` alone. Deliberately does not touch `country` — `ip-ipinfo`
/// owns that field, and VT's own country attribute is a coarser, less-current signal (it moves
/// on VT's re-scan cadence, not on address-block delegation) that would only ever agree or
/// silently lose to whichever tool wrote second.
pub fn ip_vt_record_to_yield(record: &IpVtRecord) -> ToolYield {
    let mut rows = Vec::new();
    if let Some(owner) = &record.as_owner {
        rows.push(OzRow {
            label: "VT AS owner".to_string(),
            value: owner.clone(),
            ..Default::default()
        });
    }

    ToolYield {
        payload_patch: serde_json::json!({
            "vtMalicious": record.malicious,
            "vtReputation": record.reputation,
        }),
        rows,
        ..Default::default()
    }
}

pub async fn run_ip_virustotal(ip: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!("{VT_IP_BASE}{}", urlencoding::encode(ip));
    let headers = vec![("x-apikey".to_string(), key)];
    let outcome = ctx
        .fetch(
            "ip-virustotal",
            ip,
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
                message: "VirusTotal response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_ip_vt_response(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(record) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(ip_vt_record_to_yield(&record)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from a live 2026-08-25 call against `8.8.8.8`.
    fn google_dns() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "id": "8.8.8.8",
                "attributes": {
                    "as_owner": "Google LLC",
                    "country": "US",
                    "reputation": 557,
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0, "undetected": 20, "harmless": 68, "timeout": 0
                    }
                }
            }
        })
    }

    #[test]
    fn parses_a_real_record() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        assert_eq!(record.malicious, 0);
        assert_eq!(record.reputation, 557);
        assert_eq!(record.as_owner.as_deref(), Some("Google LLC"));
    }

    #[test]
    fn yield_owns_only_the_two_documented_keys() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        let produced = ip_vt_record_to_yield(&record);
        let obj = produced.payload_patch.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["vtMalicious", "vtReputation"]);
    }

    #[test]
    fn rejects_a_response_missing_attributes() {
        assert!(parse_ip_vt_response(&serde_json::json!({})).is_err());
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_ip_virustotal("8.8.8.8", &crate::sources::ToolCtx::default()).await;
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
