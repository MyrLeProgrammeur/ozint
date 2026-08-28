//! `devto-user` — dev.to (Forem)'s public, keyless user-lookup API.
//!
//! Endpoint: `GET https://dev.to/api/users/by_username?url={handle}`. No auth. Verified by
//! direct call 2026-08-25: a real handle (`ben`) answers `200` with a full profile including
//! `twitter_username`/`github_username`/`website_url`; an unknown handle answers a clean `404`
//! `{"error":"not found","status":404}` — folded to [`crate::outcome::ToolOutcome::OkEmpty`]
//! via [`crate::sources::fold_fetch_failure`]'s ordinary `HttpError` path is wrong here (a 404
//! is this endpoint's documented absence signal, not a failure) — [`run_devto_user`]
//! special-cases it before falling through, the same shape `bluesky.rs` uses for its own
//! absence-via-status-code case.
//!
//! ## Children
//!
//! `twitter_username`/`github_username` become [`OzType::Username`] children when present and
//! different from the queried handle (same self-reference guard every tool in this category
//! applies). `website_url` becomes an [`OzType::Domain`] child via [`super::extract_domain`].

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

use super::{extract_domain, nonempty};

const DEVTO_USERS_ENDPOINT: &str = "https://dev.to/api/users/by_username?url=";

/// A dev.to user, narrowed to the fields this tool reports.
#[derive(Debug, Clone, PartialEq)]
pub struct DevtoUser {
    pub username: String,
    pub name: Option<String>,
    pub twitter_username: Option<String>,
    pub github_username: Option<String>,
    pub summary: Option<String>,
    pub location: Option<String>,
    pub website_url: Option<String>,
}

/// Parses `by_username`'s response body. Rejects a body with no `username` — every other field
/// is optional. Pure and tested.
pub fn parse_devto_user(json: &serde_json::Value) -> Result<DevtoUser, String> {
    let username = json
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "dev.to response is missing `username`".to_string())?
        .to_string();

    Ok(DevtoUser {
        username,
        name: nonempty(json.get("name").and_then(|v| v.as_str())),
        twitter_username: nonempty(json.get("twitter_username").and_then(|v| v.as_str())),
        github_username: nonempty(json.get("github_username").and_then(|v| v.as_str())),
        summary: nonempty(json.get("summary").and_then(|v| v.as_str())),
        location: nonempty(json.get("location").and_then(|v| v.as_str())),
        website_url: nonempty(json.get("website_url").and_then(|v| v.as_str())),
    })
}

/// Turns a parsed [`DevtoUser`] into a [`ToolYield`]. Pure and tested.
pub fn devto_user_to_yield(user: &DevtoUser, queried_handle: &str) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "dev.to".to_string(),
        value: user.name.clone().unwrap_or_else(|| user.username.clone()),
        href: Some(format!("https://dev.to/{}", user.username)),
        ..Default::default()
    }];
    if let Some(location) = &user.location {
        rows.push(OzRow {
            label: "Location".to_string(),
            value: location.clone(),
            ..Default::default()
        });
    }
    if let Some(summary) = &user.summary {
        rows.push(OzRow {
            label: "Summary".to_string(),
            value: summary.clone(),
            ..Default::default()
        });
    }
    if let Some(website) = &user.website_url {
        rows.push(OzRow {
            label: "Website".to_string(),
            value: website.clone(),
            href: Some(website.clone()),
            ..Default::default()
        });
    }

    let queried_lower = queried_handle.to_ascii_lowercase();
    let mut children = Vec::new();
    if let Some(twitter) = &user.twitter_username
        && twitter.to_ascii_lowercase() != queried_lower
    {
        children.push(ChildSeed {
            oz_type: OzType::Username,
            value: twitter.clone(),
            note: Some("dev.to profile's linked Twitter handle".to_string()),
        });
    }
    if let Some(github) = &user.github_username
        && github.to_ascii_lowercase() != queried_lower
    {
        children.push(ChildSeed {
            oz_type: OzType::Username,
            value: github.clone(),
            note: Some("dev.to profile's linked GitHub handle".to_string()),
        });
    }
    if let Some(website) = &user.website_url
        && let Some(domain) = extract_domain(website)
    {
        children.push(ChildSeed {
            oz_type: OzType::Domain,
            value: domain,
            note: Some("dev.to profile website".to_string()),
        });
    }

    ToolYield {
        payload_patch: serde_json::json!({}),
        rows,
        facts: Vec::new(),
        flags: Vec::new(),
        values: Vec::new(),
        children,
    }
}

/// Looks `handle` up on dev.to. Keyless.
pub async fn run_devto_user(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{DEVTO_USERS_ENDPOINT}{}", urlencoding::encode(handle));

    let outcome = ctx
        .fetch("devto-user", handle, &url, fetch::OzFetchOptions::default())
        .await;
    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // A 404 is this endpoint's documented absence signal — verified by direct call, see the
    // module doc — so it settles the honest empty finding rather than falling through to
    // `fold_fetch_failure`'s generic `HttpError`.
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
                message: "dev.to response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_devto_user(json) {
        Ok(user) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(devto_user_to_yield(&user, handle)),
        ),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_response() -> serde_json::Value {
        serde_json::json!({
            "type_of": "user",
            "id": 1,
            "username": "ben",
            "name": "Ben Halpern",
            "twitter_username": "bendhalpern",
            "github_username": "benhalpern",
            "summary": "A Canadian software developer.",
            "location": "NY",
            "website_url": "http://benhalpern.com"
        })
    }

    #[test]
    fn parses_a_full_profile() {
        let user = parse_devto_user(&full_response()).expect("parses");
        assert_eq!(user.username, "ben");
        assert_eq!(user.name.as_deref(), Some("Ben Halpern"));
        assert_eq!(user.twitter_username.as_deref(), Some("bendhalpern"));
    }

    #[test]
    fn rejects_a_response_missing_username() {
        let json = serde_json::json!({ "name": "No Username" });
        assert!(parse_devto_user(&json).is_err());
    }

    #[test]
    fn a_bare_profile_still_parses() {
        let json = serde_json::json!({ "username": "bare" });
        let user = parse_devto_user(&json).unwrap();
        assert_eq!(user.username, "bare");
        assert_eq!(user.name, None);
    }

    #[test]
    fn yield_emits_twitter_github_and_domain_children() {
        let user = parse_devto_user(&full_response()).unwrap();
        let produced = devto_user_to_yield(&user, "ben");
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Username && c.value == "bendhalpern")
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Username && c.value == "benhalpern")
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Domain && c.value == "benhalpern.com")
        );
    }

    #[test]
    fn yield_suppresses_a_child_matching_the_queried_handle() {
        let user = parse_devto_user(&full_response()).unwrap();
        let produced = devto_user_to_yield(&user, "bendhalpern");
        assert!(
            !produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Username && c.value == "bendhalpern")
        );
    }
}
