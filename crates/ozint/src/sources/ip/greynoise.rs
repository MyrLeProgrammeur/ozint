//! `ip-greynoise` — GreyNoise's free Community API. Owns `classification` on
//! [`crate::types::IpPayload`] — the field IPinfo/InternetDB's module docs already reserved
//! for it and left unwritten.
//!
//! `GET https://api.greynoise.io/v3/community/{ip}`, header `key`. Verified live 2026-08-25
//! against `8.8.8.8`: the response is `{"ip":"8.8.8.8","noise":false,"riot":false,
//! "message":"IP not observed scanning the internet."}` — carried on **HTTP 404**.
//!
//! ## `404` with a body is GreyNoise's documented shape, not a failure
//!
//! This is the crate's second endpoint (after `bluesky-actor`) whose absent-case is a non-2xx
//! status with a genuinely informative body, and it needs the same discipline
//! `bluesky-actor`'s module doc lays out: the status code alone is not enough to decide
//! "empty" versus "failed". Here the tell is structural rather than a message string —
//! [`run_greynoise`] parses `body_snippet` as JSON and only treats the `404` as
//! [`ToolOutcome::OkEmpty`] when it decodes into an object carrying a `noise` boolean (the one
//! key present on every documented shape, noisy or not). A `404` with an unparseable body, or
//! one missing `noise` entirely, falls through to [`crate::sources::fold_fetch_failure`] and is
//! reported as the real failure it is.
//!
//! ## `noise: true` alone is not enough to classify malicious
//!
//! `noise` means "this address is known to be mass-scanning the internet" — common, and not by
//! itself a verdict; a research crawler and an exploit scanner are both "noisy". Only when the
//! response's own `classification` field is present is one written here, and it is passed
//! through verbatim (`"benign"`/`"malicious"`/`"unknown"`) rather than derived from `noise`.
//! `riot: true` (a known benign business service — cloud providers, CDNs) becomes a row, not a
//! classification, for the same reason: RIOT is a different GreyNoise programme with its own
//! semantics, not a third value on the classification enum.

use crate::layer_plan::FLAG_MALICIOUS;
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const GREYNOISE_BASE: &str = "https://api.greynoise.io/v3/community/";
const ENV_VAR: &str = "GREYNOISE_API_KEY";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GreynoiseResult {
    pub noise: bool,
    pub riot: bool,
    pub classification: Option<String>,
    pub message: Option<String>,
}

fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parses a GreyNoise community body. `Err` only when `noise` itself is absent or not a
/// boolean — the structural tell [`run_greynoise`] uses to decide a `404` was this endpoint's
/// documented shape rather than a genuine failure.
pub fn parse_greynoise(json: &serde_json::Value) -> Result<GreynoiseResult, String> {
    let noise = json
        .get("noise")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| "GreyNoise response has no `noise` boolean".to_string())?;

    Ok(GreynoiseResult {
        noise,
        riot: json.get("riot").and_then(|v| v.as_bool()).unwrap_or(false),
        classification: nonempty(json.get("classification").and_then(|v| v.as_str())),
        message: nonempty(json.get("message").and_then(|v| v.as_str())),
    })
}

pub fn greynoise_to_yield(result: &GreynoiseResult) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if let Some(classification) = &result.classification {
        patch.insert(
            "classification".to_string(),
            serde_json::json!(classification),
        );
    }

    let mut rows = Vec::new();
    if result.noise {
        rows.push(OzRow {
            label: "GreyNoise".to_string(),
            value: "observed mass-scanning the internet".to_string(),
            ..Default::default()
        });
    }
    if result.riot {
        rows.push(OzRow {
            label: "GreyNoise RIOT".to_string(),
            value: "known benign business service (RIOT)".to_string(),
            ..Default::default()
        });
    }
    if let Some(message) = &result.message {
        rows.push(OzRow {
            label: "GreyNoise".to_string(),
            value: message.clone(),
            ..Default::default()
        });
    }

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows,
        flags: if result.classification.as_deref() == Some("malicious") {
            vec![(FLAG_MALICIOUS, true)]
        } else {
            Vec::new()
        },
        ..Default::default()
    }
}

pub async fn run_greynoise(ip: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    use crate::fetch::{self, OzOutcome};

    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!("{GREYNOISE_BASE}{}", urlencoding::encode(ip));
    let headers = vec![("key".to_string(), key)];
    let outcome = ctx
        .fetch(
            "ip-greynoise",
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

    // GreyNoise's documented shape for a quiet address: HTTP 404 with a genuinely informative
    // body. See the module doc — this must not be mistaken for a bare failure the way
    // `bluesky-actor` guards against its own 400-shaped absence.
    if let OzOutcome::HttpError {
        status: 404,
        body_snippet: Some(snippet),
    } = &outcome
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(snippet)
        && let Ok(result) = parse_greynoise(&json)
    {
        let outcome = if result.classification.is_some() || result.noise || result.riot {
            ToolOutcome::OkWithResults { count: 1 }
        } else {
            ToolOutcome::OkEmpty
        };
        return DispatchOutcome::Ran(outcome, Some(greynoise_to_yield(&result)));
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled, non-documented-404 OzOutcome was handled above");
    };
    let fetch::OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "GreyNoise response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_greynoise(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(result) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(greynoise_to_yield(&result)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transcribed verbatim from a live 2026-08-25 call — this is the `404` body itself.
    fn quiet_address() -> serde_json::Value {
        serde_json::json!({
            "ip": "8.8.8.8",
            "noise": false,
            "riot": false,
            "message": "IP not observed scanning the internet."
        })
    }

    #[test]
    fn parses_the_quiet_shape() {
        let result = parse_greynoise(&quiet_address()).unwrap();
        assert!(!result.noise);
        assert!(!result.riot);
        assert_eq!(result.classification, None);
        assert!(result.message.is_some());
    }

    #[test]
    fn a_classification_is_passed_through_verbatim() {
        let json =
            serde_json::json!({ "ip": "1.2.3.4", "noise": true, "classification": "malicious" });
        let result = parse_greynoise(&json).unwrap();
        assert_eq!(result.classification.as_deref(), Some("malicious"));
        let produced = greynoise_to_yield(&result);
        assert_eq!(produced.payload_patch["classification"], "malicious");
        assert_eq!(produced.flags, vec![(FLAG_MALICIOUS, true)]);
    }

    #[test]
    fn no_classification_writes_no_payload_key_and_no_flag() {
        let result = parse_greynoise(&quiet_address()).unwrap();
        let produced = greynoise_to_yield(&result);
        assert_eq!(produced.payload_patch, serde_json::json!({}));
        assert!(produced.flags.is_empty());
    }

    #[test]
    fn missing_noise_is_a_parse_error() {
        assert!(parse_greynoise(&serde_json::json!({ "riot": false })).is_err());
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_greynoise("8.8.8.8", &crate::sources::ToolCtx::default()).await;
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
