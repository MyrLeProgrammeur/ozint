//! `dom-virustotal` — VirusTotal v3's domain report. Owns `vtMalicious`/`vtReputation` on
//! [`crate::types::DomainPayload`].
//!
//! `GET /api/v3/domains/{domain}`, header `x-apikey`. Verified live 2026-08-25 against
//! `google.com`: **HTTP 200**, `data.attributes.last_analysis_stats` (91 AV engines),
//! `data.attributes.reputation`, `data.attributes.categories`, `data.attributes.whois`.
//!
//! ## Deliberately does not write `subdomains`
//!
//! VT's domain report carries `data.attributes.subdomains_count`-adjacent hints in some cases,
//! but no reliable enumeration the way certificate transparency gives `dom-certspotter`. VT
//! also is not the source of record for that field — `dom-certspotter`'s module doc already
//! names it the authoritative writer of `subdomains`/`subdomainsTruncated`, and this tool must
//! not compete with it.
//!
//! ## Shares the crate-wide VirusTotal quota
//!
//! Same `"virustotal"` rate-key bucket as `hash-virustotal`, `hash-*`'s tier-2 escalation and
//! `ip-virustotal` — see `registry::rate_limits_for`. Cached 24h, the crate's hardest TTL,
//! for the same reason `cve-nvd`/`hash-virustotal` are: this account's daily budget is shared
//! across every VT-calling tool now, and a shorter TTL here would spend it fastest of all four.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const VT_DOMAIN_BASE: &str = "https://www.virustotal.com/api/v3/domains/";
const ENV_VAR: &str = "VIRUSTOTAL_API_KEY";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DomainVtRecord {
    pub malicious: u32,
    pub reputation: i64,
    pub categories: Vec<String>,
}

pub fn parse_domain_vt_response(json: &serde_json::Value) -> Result<DomainVtRecord, String> {
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
    let categories = attrs
        .get("categories")
        .and_then(|v| v.as_object())
        .map(|obj| {
            let mut values: Vec<String> = obj
                .values()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect();
            values.sort_unstable();
            values.dedup();
            values
        })
        .unwrap_or_default();

    Ok(DomainVtRecord {
        malicious,
        reputation,
        categories,
    })
}

/// Owns `vtMalicious`/`vtReputation` alone — never `subdomains`, see the module doc.
pub fn domain_vt_record_to_yield(record: &DomainVtRecord) -> ToolYield {
    let mut rows = Vec::new();
    if !record.categories.is_empty() {
        rows.push(OzRow {
            label: "VT categories".to_string(),
            value: record.categories.join(", "),
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

pub async fn run_domain_virustotal(domain: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!("{VT_DOMAIN_BASE}{}", urlencoding::encode(domain));
    let headers = vec![("x-apikey".to_string(), key)];
    let outcome = ctx
        .fetch(
            "dom-virustotal",
            domain,
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
    // A domain VT has never seen submitted answers 404, the same shape `hash-virustotal`
    // documents for a never-submitted hash.
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

    match parse_domain_vt_response(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(record) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(domain_vt_record_to_yield(&record)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from a live 2026-08-25 call against `google.com`.
    fn google_com() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "id": "google.com",
                "attributes": {
                    "reputation": 557,
                    "categories": {
                        "BitDefender": "business",
                        "Sophos": "information technology"
                    },
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0, "undetected": 20, "harmless": 71, "timeout": 0
                    }
                }
            }
        })
    }

    #[test]
    fn parses_a_real_record() {
        let record = parse_domain_vt_response(&google_com()).unwrap();
        assert_eq!(record.malicious, 0);
        assert_eq!(record.reputation, 557);
        assert_eq!(record.categories.len(), 2);
    }

    #[test]
    fn yield_owns_only_the_two_documented_keys() {
        let record = parse_domain_vt_response(&google_com()).unwrap();
        let produced = domain_vt_record_to_yield(&record);
        let obj = produced.payload_patch.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["vtMalicious", "vtReputation"]);
        assert!(
            !obj.contains_key("subdomains"),
            "dom-certspotter owns subdomains, never this tool"
        );
    }

    #[test]
    fn rejects_a_response_missing_attributes() {
        assert!(parse_domain_vt_response(&serde_json::json!({})).is_err());
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome =
            run_domain_virustotal("google.com", &crate::sources::ToolCtx::default()).await;
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
