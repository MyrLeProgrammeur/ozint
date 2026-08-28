//! `email-microsoft-credential-type` — a keyless Microsoft 365 / Azure AD tenant fingerprint,
//! landed 2026-08-26 as this crate's first GAFAM-specific unit. Calls the unofficial but real
//! `POST https://login.microsoftonline.com/common/GetCredentialType` endpoint
//! (`{"Username":"<email>"}`), confirmed live and reachable with no key, header, or session.
//!
//! ## What this tool can and cannot claim — read before touching the parsing below
//!
//! A live test against this crate's own real, working Outlook-adjacent Gmail account **and** a
//! deliberately nonexistent `@outlook.com` address both answered `IfExistsResult: 1` — proof
//! that `IfExistsResult` is **not** a reliable existence signal for consumer/personal Microsoft
//! accounts. A follow-up research pass confirmed this against real documentation, not
//! guesswork: [War Room's GetCredentialType writeup](https://warroom.rsmus.com/enumerating-emails-via-office-com/)
//! states existence-checking "works reliably on managed domains only," and
//! [msxfaq.de](https://www.msxfaq.de/cloud/authentifizierung/getcredentialtype.htm) documents
//! that `IfExistsResult` returns `1` for "invalid domains, Microsoft accounts, and invalid
//! outlook.de accounts" alike — real personal accounts and nonexistent addresses collapse into
//! the same bucket.
//!
//! `DomainType` is the field that is reliable regardless of what kind of address was queried —
//! it fingerprints how the domain authenticates, not whether one address on it exists:
//!
//! | `DomainType` | meaning |
//! |---|---|
//! | 2 | Consumer (outlook.com/hotmail.com/live.com) |
//! | 3 | Managed — cloud-only Microsoft 365 / Azure AD tenant |
//! | 4 | Federated, on-premises (ADFS) |
//! | 5 | Federated, cloud-hosted identity provider |
//! | other | Unknown |
//!
//! `IfExistsResult` (`0` exists / `1` does-not-exist-or-consumer / `2` throttled / `4` server
//! error / `5` exists via an alternate IdP / `6` exists via both) is therefore only surfaced as
//! an existence claim when `DomainType` is `3`, `4`, or `5` — a business tenant, where Microsoft
//! itself participates in authentication and the field is diagnostic. For `DomainType == 2`
//! (consumer) this crate reports the domain type alone and explicitly declines to claim
//! existence, rather than shipping a coin-flip as a finding.
//!
//! ## `ThrottleStatus`
//!
//! `0` not throttled, `1` Azure AD-side throttling, `2` Microsoft-account-side throttling —
//! surfaced as a row only when non-zero, since a throttled response makes any `IfExistsResult`
//! read on that call untrustworthy regardless of domain type.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const ENDPOINT: &str = "https://login.microsoftonline.com/common/GetCredentialType";

#[derive(Debug, Clone, Copy, PartialEq)]
struct CredentialType {
    if_exists_result: i64,
    domain_type: i64,
    throttle_status: i64,
}

/// Parses `GetCredentialType`'s response body. `DomainType` lives under `EstsProperties`, per
/// the real response shape observed live — not a guess. Pure and tested.
fn parse_credential_type(json: &serde_json::Value) -> Result<CredentialType, String> {
    let if_exists_result = json
        .get("IfExistsResult")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "GetCredentialType response is missing `IfExistsResult`".to_string())?;
    let domain_type = json
        .get("EstsProperties")
        .and_then(|v| v.get("DomainType"))
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            "GetCredentialType response is missing `EstsProperties.DomainType`".to_string()
        })?;
    let throttle_status = json
        .get("ThrottleStatus")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    Ok(CredentialType {
        if_exists_result,
        domain_type,
        throttle_status,
    })
}

fn domain_type_label(domain_type: i64) -> &'static str {
    match domain_type {
        2 => "Consumer (Outlook/Hotmail/Live)",
        3 => "Managed (cloud-only Microsoft 365 tenant)",
        4 => "Federated (on-premises ADFS)",
        5 => "Federated (cloud-hosted identity provider)",
        _ => "Unknown",
    }
}

/// `None` when `IfExistsResult` is not diagnostic for this domain type — see the module doc.
/// Never returns a claim for `domain_type == 2`.
fn existence_label(if_exists_result: i64, domain_type: i64) -> Option<&'static str> {
    if domain_type == 2 {
        return None;
    }
    match if_exists_result {
        0 => Some("exists"),
        1 => Some("does not exist"),
        5 => Some("exists (alternate identity provider)"),
        6 => Some("exists (domain and alternate identity provider)"),
        _ => None,
    }
}

fn credential_type_to_yield(result: &CredentialType) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "Domain type".to_string(),
        value: domain_type_label(result.domain_type).to_string(),
        ..Default::default()
    }];
    if let Some(existence) = existence_label(result.if_exists_result, result.domain_type) {
        rows.push(OzRow {
            label: "Account".to_string(),
            value: existence.to_string(),
            ..Default::default()
        });
    }
    if result.throttle_status != 0 {
        rows.push(OzRow {
            label: "Throttled".to_string(),
            value: "this call was throttled — the existence read above (if any) is unreliable"
                .to_string(),
            ..Default::default()
        });
    }
    ToolYield {
        rows,
        ..Default::default()
    }
}

/// Looks `email` up against Microsoft's `GetCredentialType`. Keyless.
pub async fn run_microsoft_credential_type(
    email: &str,
    ctx: &crate::sources::ToolCtx,
) -> DispatchOutcome {
    let body = serde_json::json!({ "Username": email }).to_string();
    let opts = fetch::OzFetchOptions {
        method: reqwest::Method::POST,
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body: Some(body.into_bytes()),
        ..Default::default()
    };

    let outcome = ctx
        .fetch("email-microsoft-credential-type", email, ENDPOINT, opts)
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
                message: "GetCredentialType response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_credential_type(json) {
        Ok(result) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(credential_type_to_yield(&result)),
        ),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed_exists_response() -> serde_json::Value {
        serde_json::json!({
            "IfExistsResult": 0,
            "ThrottleStatus": 0,
            "EstsProperties": { "DomainType": 3 }
        })
    }

    fn consumer_response() -> serde_json::Value {
        serde_json::json!({
            "IfExistsResult": 1,
            "ThrottleStatus": 0,
            "EstsProperties": { "DomainType": 2 }
        })
    }

    #[test]
    fn parses_a_managed_tenant_response() {
        let result = parse_credential_type(&managed_exists_response()).unwrap();
        assert_eq!(result.domain_type, 3);
        assert_eq!(result.if_exists_result, 0);
    }

    #[test]
    fn a_response_missing_domain_type_is_rejected() {
        let json = serde_json::json!({ "IfExistsResult": 0 });
        assert!(parse_credential_type(&json).is_err());
    }

    #[test]
    fn existence_is_never_claimed_for_a_consumer_domain() {
        assert_eq!(existence_label(0, 2), None);
        assert_eq!(existence_label(1, 2), None);
    }

    #[test]
    fn existence_is_claimed_for_a_managed_or_federated_domain() {
        assert_eq!(existence_label(0, 3), Some("exists"));
        assert_eq!(existence_label(1, 4), Some("does not exist"));
        assert_eq!(
            existence_label(5, 5),
            Some("exists (alternate identity provider)")
        );
    }

    #[test]
    fn yield_never_adds_an_account_row_for_a_consumer_domain() {
        let result = parse_credential_type(&consumer_response()).unwrap();
        let produced = credential_type_to_yield(&result);
        assert!(!produced.rows.iter().any(|r| r.label == "Account"));
        assert_eq!(produced.rows[0].value, "Consumer (Outlook/Hotmail/Live)");
    }

    #[test]
    fn yield_adds_an_account_row_for_a_managed_domain() {
        let result = parse_credential_type(&managed_exists_response()).unwrap();
        let produced = credential_type_to_yield(&result);
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Account" && r.value == "exists")
        );
    }

    #[test]
    fn yield_flags_a_throttled_call() {
        let mut json = managed_exists_response();
        json["ThrottleStatus"] = serde_json::json!(1);
        let result = parse_credential_type(&json).unwrap();
        let produced = credential_type_to_yield(&result);
        assert!(produced.rows.iter().any(|r| r.label == "Throttled"));
    }

    #[test]
    fn yield_never_touches_the_payload() {
        let result = parse_credential_type(&managed_exists_response()).unwrap();
        let produced = credential_type_to_yield(&result);
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }
}
