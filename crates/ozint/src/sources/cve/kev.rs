//! `kev` — CISA's Known Exploited Vulnerabilities catalogue. Keyless. Owns only the `kev`
//! field of [`crate::types::CvePayload`].
//!
//! `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
//! — verified live 2026-08-21: `200`, 1,596,534 bytes,
//! `{"title":…, "catalogVersion":…, "dateReleased":…, "count":1673, "vulnerabilities":[…]}`.
//! There is no per-CVE endpoint; every call fetches the whole catalogue and searches it
//! locally. 1.6MB is well under [`crate::fetch::MAX_BODY_BYTES`] (8MB), but that margin is
//! finite and the catalogue only grows — if CISA's KEV list ever roughly quintuples, this
//! tool starts failing on [`crate::outcome::ToolOutcome::ParseError`]-shaped
//! [`crate::fetch::OzOutcome::TooLarge`] rather than silently truncating.
//!
//! ## Absence is a finding, and the payload must say so explicitly
//!
//! A CVE absent from the catalogue is genuinely meaningful — "not known to be exploited in
//! the wild" — so it settles [`crate::outcome::ToolOutcome::OkEmpty`], same as every other
//! honest-absence case in this crate. But unlike those cases, the payload here still writes
//! `{"kev": false}` explicitly rather than an empty `{}` patch. `kev` on
//! [`crate::types::CvePayload`] is `#[serde(skip_serializing_if = "std::ops::Not::not")]`, so
//! an explicit `false` and a `false` produced by never having checked serialise identically —
//! the payload field alone cannot carry the difference between "we checked and it is not
//! listed" and "nobody checked". That distinction lives one layer up, in the
//! [`crate::outcome::ToolOutcome`] this tool reports (`OkEmpty` vs. e.g. `SkippedNoKey`), not
//! in the JSON. Writing `false` here is deliberate and harmless, not a no-op filler value.
//!
//! A body that parses as JSON but carries no `vulnerabilities` array at all is a different
//! thing entirely: the catalogue's shape changed. That must be loud —
//! [`crate::outcome::ToolOutcome::ParseError`] — never silently reported as "not exploited".

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Searches the KEV catalogue's `vulnerabilities[].cveID` for a case-insensitive match
/// against `cve`. `Err` only when the catalogue has no `vulnerabilities` array at all — a
/// shape change, not an absence. Pure and tested against inline fixtures.
pub fn parse_kev_catalogue(json: &serde_json::Value, cve: &str) -> Result<bool, String> {
    let vulnerabilities = json
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "KEV catalogue response is missing `vulnerabilities`".to_string())?;

    let found = vulnerabilities.iter().any(|entry| {
        entry
            .get("cveID")
            .and_then(|v| v.as_str())
            .is_some_and(|id| id.eq_ignore_ascii_case(cve))
    });
    Ok(found)
}

/// Turns a catalogue-membership result into a [`ToolYield`] — always writes `kev` explicitly,
/// including `false`. See the module doc for why an explicit `false` is not a no-op here.
pub fn kev_to_yield(present: bool) -> ToolYield {
    ToolYield {
        payload_patch: serde_json::json!({ "kev": present }),
        ..Default::default()
    }
}

/// Fetches the whole KEV catalogue and checks it for `cve`. Untested beyond its pure helpers,
/// same convention as the rest of this crate.
pub async fn run_kev(cve: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    // The catalogue's URL never varies with the seed value — a constant key so every CVE
    // lookup shares the same cached download instead of each one re-fetching the same 1.6 MB
    // file. This is the headline fix `ToolCtx` exists for.
    let outcome = ctx
        .fetch(
            "cve-kev",
            "catalogue",
            KEV_URL,
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
                message: "KEV catalogue response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_kev_catalogue(json, cve) {
        Ok(true) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(kev_to_yield(true)),
        ),
        // A genuine, checked absence — see the module doc for why the payload still writes
        // an explicit `kev: false` rather than an empty patch.
        Ok(false) => DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(kev_to_yield(false))),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalogue_with(cve_ids: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "title": "test",
            "catalogVersion": "2026.08.21",
            "dateReleased": "2026-08-21T00:00:00.000Z",
            "count": cve_ids.len(),
            "vulnerabilities": cve_ids.iter().map(|id| serde_json::json!({
                "cveID": id,
                "vendorProject": "Test",
                "product": "Widget",
                "vulnerabilityName": "Test vuln",
                "dateAdded": "2026-08-20",
                "shortDescription": "test",
            })).collect::<Vec<_>>()
        })
    }

    #[test]
    fn finds_an_exact_match() {
        let json = catalogue_with(&["CVE-2026-72530", "CVE-2021-34527"]);
        assert_eq!(parse_kev_catalogue(&json, "CVE-2021-34527"), Ok(true));
    }

    #[test]
    fn match_is_case_insensitive() {
        let json = catalogue_with(&["CVE-2021-34527"]);
        assert_eq!(parse_kev_catalogue(&json, "cve-2021-34527"), Ok(true));
        assert_eq!(parse_kev_catalogue(&json, "Cve-2021-34527"), Ok(true));
    }

    #[test]
    fn absent_cve_is_a_clean_false_not_an_error() {
        let json = catalogue_with(&["CVE-2026-72530"]);
        assert_eq!(parse_kev_catalogue(&json, "CVE-2021-34527"), Ok(false));
    }

    #[test]
    fn a_catalogue_with_no_vulnerabilities_array_is_an_error() {
        // A shape change must be loud, not silently reported as "not exploited".
        let json = serde_json::json!({ "title": "test", "count": 0 });
        assert!(parse_kev_catalogue(&json, "CVE-2021-34527").is_err());
    }

    #[test]
    fn yield_writes_an_explicit_false_for_absence() {
        let produced = kev_to_yield(false);
        assert_eq!(produced.payload_patch, serde_json::json!({ "kev": false }));
    }

    #[test]
    fn yield_writes_true_for_presence() {
        let produced = kev_to_yield(true);
        assert_eq!(produced.payload_patch, serde_json::json!({ "kev": true }));
    }
}
