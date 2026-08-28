//! `lobsters-user` — Lobsters' public, keyless per-user JSON endpoint.
//!
//! Endpoint: `GET https://lobste.rs/~{handle}.json`. No auth. Verified by direct call
//! 2026-08-25: a real handle (`pushcx`) answers `200` with a real JSON profile (this is a
//! structured API, not the HTML page — the `.json` suffix on the same path Lobsters' own web
//! UI uses); an unknown handle answers `404`, folded to
//! [`crate::outcome::ToolOutcome::OkEmpty`] the same way [`super::devto::run_devto_user`]
//! folds its own 404.
//!
//! ## Children
//!
//! `about` is free-text HTML, the same shape `hn.rs`'s Hacker News `about` field is — mined
//! for `mailto`-shaped emails and `http(s)://` links with the exact same conservative helper
//! ([`super::hn::mine`] does not exist as a shared export; this module keeps its own copy of
//! the same regexes rather than reaching into `hn`'s private helpers, since both categories'
//! module docs already treat "one module per tool" as this crate's convention).

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

use super::{extract_domain, nonempty};

const LOBSTERS_BASE: &str = "https://lobste.rs/~";

/// A Lobsters user, narrowed to the fields this tool reports.
#[derive(Debug, Clone, PartialEq)]
pub struct LobstersUser {
    pub username: String,
    pub created_at: Option<String>,
    pub is_admin: bool,
    pub is_moderator: bool,
    /// Raw HTML, as Lobsters returns it — [`strip_lobsters_html`] is applied before display.
    pub about: Option<String>,
}

/// Parses `~{handle}.json`'s response body. Rejects a body with no `username`. Pure and tested.
pub fn parse_lobsters_user(json: &serde_json::Value) -> Result<LobstersUser, String> {
    let username = json
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Lobsters response is missing `username`".to_string())?
        .to_string();

    Ok(LobstersUser {
        username,
        created_at: nonempty(json.get("created_at").and_then(|v| v.as_str())),
        is_admin: json
            .get("is_admin")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        is_moderator: json
            .get("is_moderator")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        about: nonempty(json.get("about").and_then(|v| v.as_str())),
    })
}

/// Strips HTML tags from Lobsters' `about` field. Simpler than `hn::strip_html` — Lobsters'
/// about text is server-rendered HTML with no numeric entities observed in the wild, so no
/// entity table is carried here; a future divergence would show up as literal `&amp;`-style
/// text in a row rather than silently mis-rendering.
fn strip_lobsters_html(input: &str) -> String {
    static TAG_RE: OnceLock<Regex> = OnceLock::new();
    let tag_re = TAG_RE.get_or_init(|| Regex::new(r"<[^>]*>").expect("valid tag regex"));
    tag_re
        .replace_all(input, " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Mines conservative `Email`/`Domain` children out of a non-empty `about` field.
fn mine_about_children(about: &str) -> Vec<ChildSeed> {
    static EMAIL_RE: OnceLock<Regex> = OnceLock::new();
    let email_re = EMAIL_RE.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").expect("valid email regex")
    });
    static URL_RE: OnceLock<Regex> = OnceLock::new();
    let url_re =
        URL_RE.get_or_init(|| Regex::new(r#"https?://[^\s<>"']+"#).expect("valid url regex"));

    let mut children = Vec::new();

    let mut seen_emails = HashSet::new();
    for m in email_re.find_iter(about) {
        let email = m.as_str().to_string();
        if seen_emails.insert(email.clone()) {
            children.push(ChildSeed {
                oz_type: OzType::Email,
                value: email,
                note: Some("Lobsters profile about text".to_string()),
            });
        }
    }

    let mut seen_domains = HashSet::new();
    for m in url_re.find_iter(about) {
        if let Some(domain) = extract_domain(m.as_str())
            && domain != "lobste.rs"
            && seen_domains.insert(domain.clone())
        {
            children.push(ChildSeed {
                oz_type: OzType::Domain,
                value: domain,
                note: Some("Lobsters profile about link".to_string()),
            });
        }
    }

    children
}

/// Turns a parsed [`LobstersUser`] into a [`ToolYield`]. Pure and tested.
pub fn lobsters_user_to_yield(user: &LobstersUser) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "Lobsters".to_string(),
        value: user.username.clone(),
        href: Some(format!("https://lobste.rs/~{}", user.username)),
        ..Default::default()
    }];
    if user.is_admin {
        rows.push(OzRow {
            label: "Role".to_string(),
            value: "Administrator".to_string(),
            ..Default::default()
        });
    } else if user.is_moderator {
        rows.push(OzRow {
            label: "Role".to_string(),
            value: "Moderator".to_string(),
            ..Default::default()
        });
    }
    if let Some(created_at) = &user.created_at {
        rows.push(OzRow {
            label: "Joined".to_string(),
            value: created_at.clone(),
            ..Default::default()
        });
    }
    let about_text = user.about.as_deref().map(strip_lobsters_html);
    if let Some(about) = &about_text
        && !about.is_empty()
    {
        rows.push(OzRow {
            label: "About".to_string(),
            value: about.clone(),
            ..Default::default()
        });
    }

    let children = user
        .about
        .as_deref()
        .map(mine_about_children)
        .unwrap_or_default();

    ToolYield {
        payload_patch: serde_json::json!({}),
        rows,
        facts: Vec::new(),
        flags: Vec::new(),
        values: Vec::new(),
        children,
    }
}

/// Looks `handle` up on Lobsters. Keyless.
pub async fn run_lobsters_user(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{LOBSTERS_BASE}{}.json", urlencoding::encode(handle));

    let outcome = ctx
        .fetch(
            "lobsters-user",
            handle,
            &url,
            fetch::OzFetchOptions::default(),
        )
        .await;
    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
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
                message: "Lobsters response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_lobsters_user(json) {
        Ok(user) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(lobsters_user_to_yield(&user)),
        ),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_response() -> serde_json::Value {
        serde_json::json!({
            "username": "pushcx",
            "created_at": "2012-08-14T20:25:08.000-05:00",
            "is_admin": true,
            "is_moderator": true,
            "about": "<p>Hi, I'm <a href=\"https://push.cx\">Peter</a>.</p>"
        })
    }

    #[test]
    fn parses_a_full_profile() {
        let user = parse_lobsters_user(&full_response()).expect("parses");
        assert_eq!(user.username, "pushcx");
        assert!(user.is_admin);
        assert!(user.about.is_some());
    }

    #[test]
    fn rejects_a_response_missing_username() {
        assert!(parse_lobsters_user(&serde_json::json!({})).is_err());
    }

    #[test]
    fn admin_and_moderator_default_false_when_absent() {
        let json = serde_json::json!({ "username": "bare" });
        let user = parse_lobsters_user(&json).unwrap();
        assert!(!user.is_admin);
        assert!(!user.is_moderator);
    }

    #[test]
    fn strip_lobsters_html_removes_tags() {
        assert_eq!(strip_lobsters_html("<p>Hi <b>there</b></p>"), "Hi there");
    }

    #[test]
    fn yield_mines_a_domain_child_but_never_the_sites_own_host() {
        let user = parse_lobsters_user(&full_response()).unwrap();
        let produced = lobsters_user_to_yield(&user);
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Domain && c.value == "push.cx")
        );
        assert!(!produced.children.iter().any(|c| c.value == "lobste.rs"));
    }

    #[test]
    fn yield_shows_administrator_role() {
        let user = parse_lobsters_user(&full_response()).unwrap();
        let produced = lobsters_user_to_yield(&user);
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Role" && r.value == "Administrator")
        );
    }
}
