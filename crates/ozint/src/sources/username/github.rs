//! `github-user` — GitHub's public profile REST endpoint.
//!
//! Keyless at 60 req/hr. `GITHUB_TOKEN`, if already set in the environment for another
//! purpose, is sent as a bearer token when present to lift that to 5000/hr, but its absence
//! never blocks the tool — which is why `registry::ToolDef::env_vars` is empty for it.
//!
//! ## Children
//!
//! `twitter_username` becomes an [`OzType::Username`] child when present and different from the
//! queried login — same self-reference guard `devto.rs`'s `devto_user_to_yield` applies to its
//! own linked-handle fields.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

use super::{extract_domain, nonempty};

const GITHUB_API_BASE: &str = "https://api.github.com/users/";

/// A GitHub user profile, narrowed to the fields this tool cares about. Pure struct — parsed
/// by [`parse_github_profile`], turned into a [`ToolYield`] by [`github_profile_to_yield`].
#[derive(Debug, Clone, PartialEq)]
pub struct GithubProfile {
    pub login: String,
    pub html_url: String,
    pub name: Option<String>,
    pub bio: Option<String>,
    pub location: Option<String>,
    pub company: Option<String>,
    pub blog: Option<String>,
    pub email: Option<String>,
    pub twitter_username: Option<String>,
}

/// Parses a `GET /users/{login}` response body into a [`GithubProfile`]. Pure and tested
/// against an inline fixture.
pub fn parse_github_profile(json: &serde_json::Value) -> Result<GithubProfile, String> {
    let login = json
        .get("login")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "GitHub response is missing `login`".to_string())?
        .to_string();
    let html_url = json
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    Ok(GithubProfile {
        login,
        html_url,
        name: nonempty(json.get("name").and_then(|v| v.as_str())),
        bio: nonempty(json.get("bio").and_then(|v| v.as_str())),
        location: nonempty(json.get("location").and_then(|v| v.as_str())),
        company: nonempty(json.get("company").and_then(|v| v.as_str())),
        blog: nonempty(json.get("blog").and_then(|v| v.as_str())),
        email: nonempty(json.get("email").and_then(|v| v.as_str())),
        twitter_username: nonempty(json.get("twitter_username").and_then(|v| v.as_str())),
    })
}

/// Turns a parsed [`GithubProfile`] into a [`ToolYield`]: profile facts as rows, and only the
/// children the response actually contained (never invented) — an `Email` child when the
/// profile exposes one, a `Domain` child parsed from `blog`, a `Name` child from the real
/// name. Pure and tested.
pub fn github_profile_to_yield(profile: &GithubProfile) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "GitHub".to_string(),
        value: profile.login.clone(),
        href: (!profile.html_url.is_empty()).then(|| profile.html_url.clone()),
        ..Default::default()
    }];
    if let Some(name) = &profile.name {
        rows.push(OzRow {
            label: "Name".to_string(),
            value: name.clone(),
            ..Default::default()
        });
    }
    if let Some(bio) = &profile.bio {
        rows.push(OzRow {
            label: "Bio".to_string(),
            value: bio.clone(),
            ..Default::default()
        });
    }
    if let Some(location) = &profile.location {
        rows.push(OzRow {
            label: "Location".to_string(),
            value: location.clone(),
            ..Default::default()
        });
    }
    if let Some(company) = &profile.company {
        rows.push(OzRow {
            label: "Company".to_string(),
            value: company.clone(),
            ..Default::default()
        });
    }
    if let Some(blog) = &profile.blog {
        rows.push(OzRow {
            label: "Blog".to_string(),
            value: blog.clone(),
            ..Default::default()
        });
    }
    if let Some(email) = &profile.email {
        rows.push(OzRow {
            label: "Email".to_string(),
            value: email.clone(),
            ..Default::default()
        });
    }
    if let Some(twitter) = &profile.twitter_username {
        rows.push(OzRow {
            label: "Twitter".to_string(),
            value: twitter.clone(),
            ..Default::default()
        });
    }

    let queried_lower = profile.login.to_ascii_lowercase();
    let mut children = Vec::new();
    if let Some(email) = &profile.email {
        children.push(ChildSeed {
            oz_type: OzType::Email,
            value: email.clone(),
            note: Some("public GitHub profile email".to_string()),
        });
    }
    if let Some(domain) = profile.blog.as_deref().and_then(extract_domain) {
        children.push(ChildSeed {
            oz_type: OzType::Domain,
            value: domain,
            note: Some("GitHub profile blog/website link".to_string()),
        });
    }
    if let Some(name) = &profile.name {
        children.push(ChildSeed {
            oz_type: OzType::Name,
            value: name.clone(),
            note: Some("GitHub profile display name".to_string()),
        });
    }
    if let Some(twitter) = &profile.twitter_username
        && twitter.to_ascii_lowercase() != queried_lower
    {
        children.push(ChildSeed {
            oz_type: OzType::Username,
            value: twitter.clone(),
            note: Some("GitHub profile's linked Twitter handle".to_string()),
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

/// Queries GitHub's public profile API for `handle`. Untested beyond its pure helpers, same
/// convention as the rest of this category.
pub async fn run_github_user(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{GITHUB_API_BASE}{}", urlencoding::encode(handle));
    let mut headers = vec![(
        "Accept".to_string(),
        "application/vnd.github+json".to_string(),
    )];
    if let Some(token) = ozint_core::config::optional("GITHUB_TOKEN") {
        headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    }

    // The username being looked up — GitHub's profile is keyed on it.
    let outcome = ctx
        .fetch(
            "github-user",
            handle,
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
    // GitHub answers 404 for an unknown login — a clean, positive "not found", not a probe
    // failure.
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
                message: "GitHub response was not JSON".to_string(),
            },
            None,
        );
    };
    let profile = match parse_github_profile(json) {
        Ok(profile) => profile,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults { count: 1 },
        Some(github_profile_to_yield(&profile)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_github_profile() {
        let json = serde_json::json!({
            "login": "mtrebosc",
            "html_url": "https://github.com/mtrebosc",
            "name": "Matheo Trebosc",
            "bio": "  building things  ",
            "location": "France",
            "company": null,
            "blog": "matheo.dev",
            "email": "m@example.com",
            "twitter_username": "mtrebosc_x"
        });
        let profile = parse_github_profile(&json).expect("profile parses");
        assert_eq!(profile.login, "mtrebosc");
        assert_eq!(profile.name.as_deref(), Some("Matheo Trebosc"));
        assert_eq!(
            profile.bio.as_deref(),
            Some("building things"),
            "bio must be trimmed"
        );
        assert_eq!(
            profile.company, None,
            "an explicit JSON null must not become Some(\"\")"
        );
        assert_eq!(profile.blog.as_deref(), Some("matheo.dev"));
        assert_eq!(profile.email.as_deref(), Some("m@example.com"));
        assert_eq!(profile.twitter_username.as_deref(), Some("mtrebosc_x"));
    }

    #[test]
    fn empty_string_fields_are_treated_as_absent() {
        let json = serde_json::json!({
            "login": "someone",
            "name": "",
            "bio": "   "
        });
        let profile = parse_github_profile(&json).expect("profile parses");
        assert_eq!(profile.name, None);
        assert_eq!(profile.bio, None);
    }

    #[test]
    fn rejects_a_response_missing_login() {
        let json = serde_json::json!({ "name": "No Login Field" });
        assert!(parse_github_profile(&json).is_err());
    }

    // ── profile → yield (children only from what the response contained) ──

    #[test]
    fn yield_emits_no_children_when_the_profile_has_none() {
        let profile = GithubProfile {
            login: "bare".to_string(),
            html_url: "https://github.com/bare".to_string(),
            name: None,
            bio: None,
            location: None,
            company: None,
            blog: None,
            email: None,
            twitter_username: None,
        };
        let produced = github_profile_to_yield(&profile);
        assert!(produced.children.is_empty());
        assert_eq!(produced.rows.len(), 1, "only the GitHub row itself");
    }

    #[test]
    fn yield_emits_exactly_the_children_the_profile_contains() {
        let profile = GithubProfile {
            login: "full".to_string(),
            html_url: "https://github.com/full".to_string(),
            name: Some("Full Name".to_string()),
            bio: Some("bio text".to_string()),
            location: Some("Nowhere".to_string()),
            company: None,
            blog: Some("https://full.example.com".to_string()),
            email: Some("full@example.com".to_string()),
            twitter_username: Some("full_twitter".to_string()),
        };
        let produced = github_profile_to_yield(&profile);
        assert_eq!(produced.children.len(), 4);
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Email && c.value == "full@example.com")
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Domain && c.value == "full.example.com")
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Name && c.value == "Full Name")
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Username && c.value == "full_twitter")
        );
    }

    #[test]
    fn yield_suppresses_a_twitter_child_matching_the_queried_login() {
        let profile = GithubProfile {
            login: "sameuser".to_string(),
            html_url: "https://github.com/sameuser".to_string(),
            name: None,
            bio: None,
            location: None,
            company: None,
            blog: None,
            email: None,
            twitter_username: Some("SameUser".to_string()),
        };
        let produced = github_profile_to_yield(&profile);
        assert!(
            !produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Username)
        );
    }

    #[test]
    fn yield_skips_a_domain_child_when_blog_does_not_look_like_a_domain() {
        let profile = GithubProfile {
            login: "weird".to_string(),
            html_url: "https://github.com/weird".to_string(),
            name: None,
            bio: None,
            location: None,
            company: None,
            blog: Some("not a url".to_string()),
            email: None,
            twitter_username: None,
        };
        let produced = github_profile_to_yield(&profile);
        assert!(produced.children.is_empty());
    }
}
