//! `ip-abuseipdb` — AbuseIPDB's `check` endpoint, the source `layer_plan::FACT_ABUSE_SCORE` was
//! named for and, until this tool, had no writer. Owns `abuseScore` on
//! [`crate::types::IpPayload`].
//!
//! `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`, header
//! `Key: {ABUSEIPDB_API_KEY}`, `Accept: application/json`. Verified live 2026-08-25 against
//! `8.8.8.8`: **HTTP 200**, `data.abuseConfidenceScore` (0-100), `data.isTor`,
//! `data.totalReports`, `data.isWhitelisted`. Free tier: 1000 checks/day.
//!
//! ## `reputation_flagged()` finally has an input
//!
//! `layer_plan::ABUSE_ESCALATION_THRESHOLD` (25) is the boundary `layer_plan::reputation_flagged`
//! reads from [`crate::layer_plan::FACT_ABUSE_SCORE`] — a fully-built, tested predicate that,
//! before this tool, had nothing posting that fact. Every call posts it, clean or not: a `0`
//! confidence is a real, positive finding ("nobody has reported this address"), not an absent
//! measurement, so `set_fact` runs unconditionally rather than only above some threshold.
//!
//! `isTor` also feeds [`crate::layer_plan::FLAG_ANONYMIZER`] — the same flag
//! `ip-internetdb` sets from Shodan's own tags. Only ever posted `true`: an address AbuseIPDB
//! has not tagged Tor is not thereby cleared, the same "silence is not a clearance" rule
//! `ip-internetdb`'s module doc states for its own tags.
//!
//! ## Field ownership
//!
//! Owns `abuseScore` alone. `isTor` becomes a flag, never a payload field — `anonymizer` is
//! `ip-internetdb`'s payload key, and this tool corroborates it through the flag channel
//! instead of writing the same JSON key from two sources in one phase.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::layer_plan::{FACT_ABUSE_SCORE, FLAG_ANONYMIZER};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const ABUSEIPDB_BASE: &str = "https://api.abuseipdb.com/api/v2/check";
const ENV_VAR: &str = "ABUSEIPDB_API_KEY";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AbuseResult {
    pub confidence: u8,
    pub is_tor: bool,
    pub total_reports: u32,
    pub is_whitelisted: bool,
}

/// Parses one `check` response. `Err` only when `data.abuseConfidenceScore` itself is missing
/// or not a plausible 0-100 integer — every other field is read best-effort.
pub fn parse_abuse_response(json: &serde_json::Value) -> Result<AbuseResult, String> {
    let data = json
        .get("data")
        .ok_or_else(|| "AbuseIPDB response has no `data`".to_string())?;
    let confidence = data
        .get("abuseConfidenceScore")
        .and_then(|v| v.as_u64())
        .filter(|v| *v <= 100)
        .ok_or_else(|| "AbuseIPDB `abuseConfidenceScore` is missing or out of range".to_string())?
        as u8;

    Ok(AbuseResult {
        confidence,
        is_tor: data.get("isTor").and_then(|v| v.as_bool()).unwrap_or(false),
        total_reports: data
            .get("totalReports")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        is_whitelisted: data
            .get("isWhitelisted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}

pub fn abuse_result_to_yield(result: &AbuseResult) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "AbuseIPDB confidence".to_string(),
        value: format!("{}%", result.confidence),
        ..Default::default()
    }];
    if result.total_reports > 0 {
        rows.push(OzRow {
            label: "Reports".to_string(),
            value: result.total_reports.to_string(),
            ..Default::default()
        });
    }
    if result.is_whitelisted {
        rows.push(OzRow {
            label: "Whitelisted".to_string(),
            value: "AbuseIPDB's own community whitelist".to_string(),
            ..Default::default()
        });
    }

    ToolYield {
        payload_patch: serde_json::json!({ "abuseScore": result.confidence }),
        rows,
        facts: vec![(FACT_ABUSE_SCORE, result.confidence as f64)],
        flags: if result.is_tor {
            vec![(FLAG_ANONYMIZER, true)]
        } else {
            Vec::new()
        },
        ..Default::default()
    }
}

pub async fn run_abuseipdb(ip: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!(
        "{ABUSEIPDB_BASE}?ipAddress={}&maxAgeInDays=90",
        urlencoding::encode(ip)
    );
    let headers = vec![
        ("Key".to_string(), key),
        ("Accept".to_string(), "application/json".to_string()),
    ];
    let outcome = ctx
        .fetch(
            "ip-abuseipdb",
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
                message: "AbuseIPDB response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_abuse_response(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(result) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(abuse_result_to_yield(&result)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transcribed from a live 2026-08-25 call against `8.8.8.8`.
    fn google_dns() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "ipAddress": "8.8.8.8",
                "isPublic": true,
                "ipVersion": 4,
                "isWhitelisted": true,
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "isp": "Google LLC",
                "isTor": false,
                "totalReports": 193,
                "numDistinctUsers": 87
            }
        })
    }

    #[test]
    fn parses_a_clean_address() {
        let result = parse_abuse_response(&google_dns()).unwrap();
        assert_eq!(result.confidence, 0);
        assert!(!result.is_tor);
        assert_eq!(result.total_reports, 193);
        assert!(result.is_whitelisted);
    }

    #[test]
    fn a_zero_confidence_still_posts_the_fact_as_a_real_finding() {
        let result = parse_abuse_response(&google_dns()).unwrap();
        let produced = abuse_result_to_yield(&result);
        assert_eq!(produced.facts, vec![(FACT_ABUSE_SCORE, 0.0)]);
        assert_eq!(produced.payload_patch["abuseScore"], serde_json::json!(0));
    }

    #[test]
    fn a_tor_flag_sets_anonymizer_but_never_a_payload_key() {
        let mut result = parse_abuse_response(&google_dns()).unwrap();
        result.is_tor = true;
        let produced = abuse_result_to_yield(&result);
        assert_eq!(produced.flags, vec![(FLAG_ANONYMIZER, true)]);
        assert!(
            produced
                .payload_patch
                .as_object()
                .unwrap()
                .get("anonymizer")
                .is_none(),
            "anonymizer is ip-internetdb's payload key, not this tool's"
        );
    }

    #[test]
    fn a_clean_address_sets_no_anonymizer_flag() {
        let result = parse_abuse_response(&google_dns()).unwrap();
        assert!(abuse_result_to_yield(&result).flags.is_empty());
    }

    #[test]
    fn missing_confidence_is_a_parse_error() {
        assert!(parse_abuse_response(&serde_json::json!({ "data": {} })).is_err());
    }

    #[test]
    fn missing_data_is_a_parse_error() {
        assert!(parse_abuse_response(&serde_json::json!({})).is_err());
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_abuseipdb("8.8.8.8", &crate::sources::ToolCtx::default()).await;
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
