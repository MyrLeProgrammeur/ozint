//! `epss` — FIRST's Exploit Prediction Scoring System. Keyless. Owns only the `epss` field of
//! [`crate::types::CvePayload`].
//!
//! `GET https://api.first.org/data/v1/epss?cve={CVE}` — verified live 2026-08-21. A known CVE
//! answers `200` with `"data":[{"cve":"CVE-2021-34527","epss":"0.997920000", …}]`; an unknown
//! one answers `200` too, with `"total":0,"data":[]` — a clean, positive absence, not an error.
//!
//! ## The trap this module exists to avoid
//!
//! **`epss` is a JSON *string*, not a number.** `raw.as_f64()` on `"0.997920000"` returns
//! `None` — it does not error loudly, it just silently produces nothing, which would make the
//! `signal.rs` chip's "EPSS>0.7 AND KEV" critical escalation quietly never fire for every CVE
//! that has a score. [`parse_epss_value`] parses the string form with `str::parse::<f64>()`
//! and also accepts a bare JSON number, in case a future API version stops stringifying it —
//! the string path is the one verified live today, the number path is defensive.
//!
//! A parsed value outside `0.0..=1.0` is rejected rather than clamped or stored: EPSS is a
//! probability, and a value outside that range means the response is malformed in some way
//! this module doesn't understand — silently clamping it would hide that and let a corrupted
//! number drive the chip's ratio bar as if it were a real score.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;

const EPSS_API_BASE: &str = "https://api.first.org/data/v1/epss?cve=";

/// Pulls the numeric value out of the `epss` field regardless of whether the API sent it as
/// the string it sends today or a bare number a future version might send. Pure and tested —
/// this is the function that stands between "EPSS score" and "silently nothing", see the
/// module doc.
fn parse_epss_value(raw: &serde_json::Value) -> Result<f64, String> {
    match raw {
        serde_json::Value::String(s) => s
            .parse::<f64>()
            .map_err(|e| format!("EPSS `epss` string `{s}` did not parse as a float: {e}")),
        serde_json::Value::Number(n) => n
            .as_f64()
            .ok_or_else(|| format!("EPSS `epss` number {n} was not representable as f64")),
        other => Err(format!(
            "EPSS `epss` field had an unexpected JSON type: {other}"
        )),
    }
}

/// Rejects a parsed score outside the valid probability range instead of storing or clamping
/// it — see the module doc for why silence here is the wrong failure mode.
fn validate_score(score: f64) -> Result<f64, String> {
    if (0.0..=1.0).contains(&score) {
        Ok(score)
    } else {
        Err(format!(
            "EPSS score {score} is outside the valid 0.0..=1.0 probability range"
        ))
    }
}

/// Parses `GET /data/v1/epss?cve={CVE}` into `Some(score)`, or `None` for the documented
/// `"data":[]` absence (which is not an error — see the module doc). Pure and tested against
/// inline fixtures.
pub fn parse_epss_response(json: &serde_json::Value) -> Result<Option<f64>, String> {
    let data = json
        .get("data")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "EPSS response is missing `data`".to_string())?;

    let Some(entry) = data.first() else {
        return Ok(None);
    };

    let raw = entry
        .get("epss")
        .ok_or_else(|| "EPSS entry is missing `epss`".to_string())?;
    let score = parse_epss_value(raw)?;
    validate_score(score).map(Some)
}

/// Turns a validated score into a [`ToolYield`] carrying only the `epss` field. Pure.
pub fn epss_to_yield(score: f64) -> ToolYield {
    ToolYield {
        payload_patch: serde_json::json!({ "epss": score }),
        ..Default::default()
    }
}

/// Queries FIRST's EPSS API for `cve`. Untested beyond its pure helpers, same convention as
/// the rest of this crate.
pub async fn run_epss(cve: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{EPSS_API_BASE}{}", urlencoding::encode(cve));
    // The CVE id being looked up — FIRST's answer is keyed on it alone.
    let outcome = ctx
        .fetch("cve-epss", cve, &url, fetch::OzFetchOptions::default())
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
                message: "EPSS response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_epss_response(json) {
        // A genuine absence: EPSS has no score for this CVE. A real finding, not an error —
        // an empty *object* patch, not the null a bare `ToolYield::default()` would carry
        // (see `registry::ToolYield::payload_patch`'s own doc on why null vs `{}` matters).
        Ok(None) => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(Some(score)) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(epss_to_yield(score)),
        ),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_epss_value / parse_epss_response ──────────────────────────

    #[test]
    fn parses_the_real_stringified_epss_field() {
        // This is the trap fixture. `raw.as_f64()` on a JSON string returns `None`, so a
        // naive "simplification" to that call would make `parse_epss_response` return
        // `Err("EPSS entry is missing `epss`"... )`-shaped or a type error here instead of
        // `Ok(Some(0.99792))`. If this test ever starts failing, someone reintroduced the
        // `.as_f64()` bug this module exists to prevent.
        let json = serde_json::json!({
            "status": "OK",
            "total": 1,
            "data": [{"cve": "CVE-2021-34527", "epss": "0.997920000", "percentile": "0.999570000"}]
        });
        assert_eq!(parse_epss_response(&json), Ok(Some(0.99792)));
    }

    #[test]
    fn accepts_a_bare_number_for_a_future_api_version() {
        let json = serde_json::json!({
            "data": [{"cve": "CVE-2021-34527", "epss": 0.5}]
        });
        assert_eq!(parse_epss_response(&json), Ok(Some(0.5)));
    }

    #[test]
    fn empty_data_array_is_a_clean_absence_not_an_error() {
        let json = serde_json::json!({
            "status": "OK",
            "total": 0,
            "data": []
        });
        assert_eq!(parse_epss_response(&json), Ok(None));
    }

    #[test]
    fn missing_data_field_is_an_error() {
        let json = serde_json::json!({ "status": "OK" });
        assert!(parse_epss_response(&json).is_err());
    }

    #[test]
    fn missing_epss_field_on_an_entry_is_an_error() {
        let json = serde_json::json!({ "data": [{"cve": "CVE-2021-34527"}] });
        assert!(parse_epss_response(&json).is_err());
    }

    #[test]
    fn unparseable_epss_string_is_an_error() {
        let json = serde_json::json!({ "data": [{"epss": "not-a-number"}] });
        assert!(parse_epss_response(&json).is_err());
    }

    // ── range validation ─────────────────────────────────────────────────

    #[test]
    fn boundary_scores_are_accepted() {
        assert_eq!(validate_score(0.0), Ok(0.0));
        assert_eq!(validate_score(1.0), Ok(1.0));
    }

    #[test]
    fn an_out_of_range_score_is_rejected_not_clamped() {
        let json = serde_json::json!({ "data": [{"epss": "1.5"}] });
        assert!(
            parse_epss_response(&json).is_err(),
            "an EPSS value above 1.0 must be rejected, never silently clamped into range"
        );

        let json = serde_json::json!({ "data": [{"epss": "-0.1"}] });
        assert!(parse_epss_response(&json).is_err());
    }

    // ── epss_to_yield ────────────────────────────────────────────────────

    #[test]
    fn yield_carries_only_the_epss_field() {
        let produced = epss_to_yield(0.99792);
        assert_eq!(
            produced.payload_patch,
            serde_json::json!({ "epss": 0.99792 })
        );
        assert!(produced.rows.is_empty());
        assert!(produced.children.is_empty());
    }
}
