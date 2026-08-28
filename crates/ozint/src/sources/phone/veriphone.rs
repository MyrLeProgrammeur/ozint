//! `phone-veriphone` — Veriphone's free-tier phone verification API. `entity-phone`'s first
//! tool that reaches the network: `phone-local-normalize`'s own module doc names `carrier` as
//! exactly the field local metadata cannot answer, and this is that gap closed.
//!
//! Endpoint: `GET https://api.veriphone.io/v2/verify?phone={e164}&key={VERIPHONE_API_KEY}`.
//! Free tier: 1000 requests/month, no card required at signup, and — verified by direct call
//! 2026-08-26 — the full payload (carrier, line type, region, timezone) is not paid-gated;
//! only the monthly volume is metered.
//!
//! ## The response shape, verified by direct call 2026-08-26
//!
//! A valid mobile number (`+33612345678`) answers `200` with `status: "success"`,
//! `phone_valid: true`, `phone_type: "mobile"`, `carrier: "SFR"`. A valid but non-mobile number
//! (`+33199999999`, a French fixed line) answers the same shape with `carrier: ""` — landlines
//! genuinely have no carrier in Veriphone's data, so an empty string is treated as absent, not
//! an error. A syntactically invalid input (`notaphonenumber`) still answers **`200`**, with
//! `status: "error"`, `phone_valid: false`, `reason: "not_a_number"` — never a non-200, so
//! [`parse_veriphone_response`] discriminates on `status`/`phone_valid`, not on HTTP status.
//!
//! ## Why this never writes `lineType`, `country` or `valid`
//!
//! `phone-local-normalize` already owns those three `PhonePayload` fields, populated from
//! `phonenumber`'s bundled metadata — a static classification, not a live network query.
//! Veriphone's own `phone_type`/`country`/`phone_valid` answer the same questions from a
//! different (live, carrier-aware) source, and both tools fire in the same unconditional
//! `breadth` phase (`plans::phone_plan`), so nothing here can assume it runs after the other —
//! `runtime::merge_patch`'s shallow last-writer-wins merge would silently let whichever
//! finished second win a shared key. This tool therefore owns exactly the one `PhonePayload`
//! field `phone-local-normalize` never sets — `carrier` — and reports its own `phone_type`/
//! `region`/`timezone` read as rows only, visible to the analyst as Veriphone's own verdict
//! without contesting the payload's field of record. If the two sources ever disagree on line
//! type, that disagreement is visible by comparing the payload's `lineType` against this
//! tool's own "Type (Veriphone)" row — the same "two blocks, never merged" convention
//! `coordinate_plan`'s raw-vs-reverse-geocoded split already uses for exactly this reason.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const VERIPHONE_ENDPOINT: &str = "https://api.veriphone.io/v2/verify";

pub const VERIPHONE_API_KEY_VAR: &str = "VERIPHONE_API_KEY";

/// A Veriphone verification result, narrowed to the fields this tool reports.
#[derive(Debug, Clone, PartialEq)]
pub struct VeriphoneResult {
    pub phone_valid: bool,
    /// `None` for an invalid number, or a landline with no carrier data (both verified live —
    /// see the module doc), never an invented default.
    pub carrier: Option<String>,
    pub phone_type: Option<String>,
    pub phone_region: Option<String>,
    pub timezone: Option<String>,
}

fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parses Veriphone's response body. Always `200` per the module doc — this never returns
/// `Err` for an invalid *phone number*, only for a body that doesn't fit the documented shape
/// at all (missing `status`). An invalid number is a real, valid parse: `phone_valid: false`.
/// Pure and tested.
pub fn parse_veriphone_response(json: &serde_json::Value) -> Result<VeriphoneResult, String> {
    let _status = json
        .get("status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Veriphone response is missing `status`".to_string())?;

    let phone_valid = json
        .get("phone_valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(VeriphoneResult {
        phone_valid,
        carrier: nonempty(json.get("carrier").and_then(|v| v.as_str())),
        phone_type: nonempty(json.get("phone_type").and_then(|v| v.as_str())),
        phone_region: nonempty(json.get("phone_region").and_then(|v| v.as_str())),
        timezone: json
            .get("timezone")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

fn veriphone_to_yield(result: &VeriphoneResult) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "Veriphone".to_string(),
        value: if result.phone_valid {
            "valid number".to_string()
        } else {
            "invalid number".to_string()
        },
        ..Default::default()
    }];
    if let Some(phone_type) = &result.phone_type {
        rows.push(OzRow {
            label: "Type (Veriphone)".to_string(),
            value: phone_type.clone(),
            ..Default::default()
        });
    }
    if let Some(region) = &result.phone_region {
        rows.push(OzRow {
            label: "Region".to_string(),
            value: region.clone(),
            ..Default::default()
        });
    }
    if let Some(timezone) = &result.timezone {
        rows.push(OzRow {
            label: "Timezone".to_string(),
            value: timezone.clone(),
            ..Default::default()
        });
    }
    if let Some(carrier) = &result.carrier {
        rows.push(OzRow {
            label: "Carrier".to_string(),
            value: carrier.clone(),
            ..Default::default()
        });
    }

    // Only `carrier` is written to the payload — see the module doc's field-ownership section.
    let mut patch = serde_json::Map::new();
    if let Some(carrier) = &result.carrier {
        patch.insert("carrier".to_string(), serde_json::json!(carrier));
    }

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows,
        facts: Vec::new(),
        flags: Vec::new(),
        values: Vec::new(),
        children: Vec::new(),
    }
}

/// Verifies `value` (an E.164 phone number) against Veriphone. `SkippedNoKey` when
/// `VERIPHONE_API_KEY` is absent.
pub async fn run_veriphone(value: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(VERIPHONE_API_KEY_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: VERIPHONE_API_KEY_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!(
        "{VERIPHONE_ENDPOINT}?phone={}&key={}",
        urlencoding::encode(value),
        urlencoding::encode(&key),
    );

    let outcome = ctx
        .fetch(
            "phone-veriphone",
            value,
            &url,
            fetch::OzFetchOptions::default(),
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
                message: "Veriphone response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_veriphone_response(json) {
        Ok(result) if !result.phone_valid => {
            DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(veriphone_to_yield(&result)))
        }
        Ok(result) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(veriphone_to_yield(&result)),
        ),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mobile_response() -> serde_json::Value {
        serde_json::json!({
            "status": "success",
            "phone": "+33612345678",
            "phone_valid": true,
            "phone_type": "mobile",
            "phone_region": "France",
            "country": "France",
            "carrier": "SFR",
            "timezone": ["Europe/Paris"]
        })
    }

    #[test]
    fn parses_a_valid_mobile_result() {
        let result = parse_veriphone_response(&mobile_response()).expect("parses");
        assert!(result.phone_valid);
        assert_eq!(result.carrier.as_deref(), Some("SFR"));
        assert_eq!(result.phone_type.as_deref(), Some("mobile"));
        assert_eq!(result.timezone.as_deref(), Some("Europe/Paris"));
    }

    #[test]
    fn a_landline_with_no_carrier_string_is_treated_as_absent() {
        let json = serde_json::json!({
            "status": "success",
            "phone_valid": true,
            "phone_type": "fixed_line",
            "carrier": "",
            "timezone": ["Europe/Paris"]
        });
        let result = parse_veriphone_response(&json).unwrap();
        assert_eq!(result.carrier, None);
    }

    #[test]
    fn an_invalid_number_still_parses_as_a_real_result_not_an_error() {
        let json = serde_json::json!({
            "status": "error",
            "phone_valid": false,
            "reason": "not_a_number"
        });
        let result = parse_veriphone_response(&json).expect("still parses");
        assert!(!result.phone_valid);
    }

    #[test]
    fn rejects_a_body_missing_status() {
        assert!(parse_veriphone_response(&serde_json::json!({"phone_valid": true})).is_err());
    }

    #[test]
    fn yield_writes_only_carrier_to_the_payload() {
        let result = parse_veriphone_response(&mobile_response()).unwrap();
        let produced = veriphone_to_yield(&result);
        assert_eq!(
            produced.payload_patch,
            serde_json::json!({"carrier": "SFR"})
        );
    }

    #[test]
    fn yield_writes_no_payload_key_when_carrier_is_absent() {
        let result = VeriphoneResult {
            phone_valid: true,
            carrier: None,
            phone_type: Some("fixed_line".to_string()),
            phone_region: None,
            timezone: None,
        };
        let produced = veriphone_to_yield(&result);
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(VERIPHONE_API_KEY_VAR).ok();
        unsafe { std::env::remove_var(VERIPHONE_API_KEY_VAR) };

        let outcome = run_veriphone("+33612345678", &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNoKey { env_var }, produced) => {
                assert_eq!(env_var, VERIPHONE_API_KEY_VAR);
                assert!(produced.is_none());
            }
            other => panic!("expected SkippedNoKey without a key, got {other:?}"),
        }

        if let Some(v) = prev {
            unsafe { std::env::set_var(VERIPHONE_API_KEY_VAR, v) };
        }
    }
}

#[cfg(test)]
mod live_smoke {
    use super::*;

    #[tokio::test]
    #[ignore = "needs a real VERIPHONE_API_KEY in the environment"]
    async fn live_veriphone_lookup_against_a_real_french_mobile() {
        let outcome = run_veriphone("+33612345678", &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(y)) => {
                println!("LIVE VERIPHONE: {count} result, rows: {:?}", y.rows);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
