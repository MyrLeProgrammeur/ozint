//! `bluesky-actor` — Bluesky's public AT Proto AppView, `app.bsky.actor.getProfile`.
//!
//! Keyless at `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={handle}` —
//! no token, no registration, nothing in `registry::ToolDef::env_vars`.
//!
//! **The absent-case subtlety, verified by direct call 2026-08-21:** an unknown handle does
//! **not** answer a clean `404`. It answers `400` with body
//! `{"error":"InvalidRequest","message":"Profile not found"}`. A bare "any 400/404 is empty"
//! rule would therefore also swallow a genuinely malformed request or a transient upstream
//! validation error under the same status code, so [`run_bluesky_actor`] special-cases this
//! *before* falling back to [`crate::sources::fold_fetch_failure`]: it only treats a
//! `400`/`404` as [`ToolOutcome::OkEmpty`] when the response body itself, case-insensitively,
//! says `"profile not found"`. Any other message on a `400`/`404` — or a `400`/`404` with no
//! body at all — falls through to `fold_fetch_failure` and is reported as the real failure it
//! is, per this crate's "empty is a finding, never a disguised failure" doctrine.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

use super::{extract_domain, nonempty};

const BLUESKY_API_BASE: &str = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=";

/// The namespace an unqualified handle is assumed to live in.
const BLUESKY_DEFAULT_NAMESPACE: &str = ".bsky.social";

/// Turn a seed value into something `getProfile` will accept, or `None` if it already is one.
///
/// **Why this exists.** `actor` takes an *AT identifier*: a DID, or a handle that is a domain
/// name — and therefore contains a dot. A bare username does not qualify, and the AppView
/// rejects it with `400 {"error":"InvalidRequest","message":"Invalid AT identifier"}` before it
/// ever looks anything up. Since this tool is registered against `entity-username`, whose seeds
/// are bare usernames by definition, it answered 400 for essentially every value it was given —
/// a tool that could never succeed at its own declared job. Caught by firing the README's own
/// suggested seed, not by the suite, whose tests all fed it already-qualified handles.
///
/// The qualification is a guess, and a good one: `.bsky.social` is where handles live unless
/// their owner has attached a domain. It is applied only when the value cannot be an AT
/// identifier already, and [`run_bluesky_actor`] records what it actually queried so the guess
/// is visible rather than silent.
pub fn qualify_handle(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() || v.contains('.') || v.starts_with("did:") {
        return None;
    }
    Some(format!("{v}{BLUESKY_DEFAULT_NAMESPACE}"))
}

/// A Bluesky actor profile, narrowed to the fields this tool cares about. Pure struct —
/// parsed by [`parse_bluesky_profile`], turned into a [`ToolYield`] by
/// [`bluesky_profile_to_yield`].
#[derive(Debug, Clone, PartialEq)]
pub struct BlueskyProfile {
    pub handle: String,
    pub did: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub followers_count: Option<u64>,
    pub follows_count: Option<u64>,
    pub posts_count: Option<u64>,
    pub created_at: Option<String>,
}

/// Parses a `getProfile` response body into a [`BlueskyProfile`]. Pure and tested against an
/// inline fixture. Rejects a response with no `handle` — every other field is optional, same
/// convention as `github::parse_github_profile`.
pub fn parse_bluesky_profile(json: &serde_json::Value) -> Result<BlueskyProfile, String> {
    let handle = json
        .get("handle")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Bluesky response is missing `handle`".to_string())?
        .to_string();

    Ok(BlueskyProfile {
        handle,
        did: nonempty(json.get("did").and_then(|v| v.as_str())),
        display_name: nonempty(json.get("displayName").and_then(|v| v.as_str())),
        description: nonempty(json.get("description").and_then(|v| v.as_str())),
        // `as_u64` already returns `None` for a JSON `null` or a missing key, so no extra
        // absence handling is needed here the way string fields need `nonempty`.
        followers_count: json.get("followersCount").and_then(|v| v.as_u64()),
        follows_count: json.get("followsCount").and_then(|v| v.as_u64()),
        posts_count: json.get("postsCount").and_then(|v| v.as_u64()),
        created_at: nonempty(json.get("createdAt").and_then(|v| v.as_str())),
    })
}

/// Whether `handle` is a custom domain the subject proved control of, as opposed to the
/// default `*.bsky.social` namespace. A Bluesky handle is itself a domain-verified identity —
/// a custom one is a genuinely strong OSINT link, while a `*.bsky.social` handle just proves
/// the subject signed up and proves nothing about them. Pure and tested directly.
fn is_custom_domain_handle(handle: &str) -> bool {
    !handle.to_ascii_lowercase().ends_with(".bsky.social")
}

/// Turns a parsed [`BlueskyProfile`] into a [`ToolYield`]: profile facts as rows, and only the
/// children the response actually contained (never invented) — a `Name` child from the
/// display name, and a `Domain` child from the handle only when it is a custom domain.
/// Pure and tested.
pub fn bluesky_profile_to_yield(profile: &BlueskyProfile) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "Bluesky".to_string(),
        value: profile.handle.clone(),
        href: (!profile.handle.is_empty())
            .then(|| format!("https://bsky.app/profile/{}", profile.handle)),
        ..Default::default()
    }];
    if let Some(name) = &profile.display_name {
        rows.push(OzRow {
            label: "Name".to_string(),
            value: name.clone(),
            ..Default::default()
        });
    }
    if let Some(bio) = &profile.description {
        rows.push(OzRow {
            label: "Bio".to_string(),
            value: bio.clone(),
            ..Default::default()
        });
    }
    if let Some(did) = &profile.did {
        rows.push(OzRow {
            label: "DID".to_string(),
            value: did.clone(),
            ..Default::default()
        });
    }
    if let Some(followers) = profile.followers_count {
        rows.push(OzRow {
            label: "Followers".to_string(),
            value: followers.to_string(),
            ..Default::default()
        });
    }
    if let Some(follows) = profile.follows_count {
        rows.push(OzRow {
            label: "Following".to_string(),
            value: follows.to_string(),
            ..Default::default()
        });
    }
    if let Some(posts) = profile.posts_count {
        rows.push(OzRow {
            label: "Posts".to_string(),
            value: posts.to_string(),
            ..Default::default()
        });
    }
    if let Some(created) = &profile.created_at {
        rows.push(OzRow {
            label: "Created".to_string(),
            value: created.clone(),
            ..Default::default()
        });
    }

    let mut children = Vec::new();
    if let Some(name) = &profile.display_name {
        children.push(ChildSeed {
            oz_type: OzType::Name,
            value: name.clone(),
            note: Some("Bluesky profile display name".to_string()),
        });
    }
    if is_custom_domain_handle(&profile.handle)
        && let Some(domain) = extract_domain(&profile.handle)
    {
        children.push(ChildSeed {
            oz_type: OzType::Domain,
            value: domain,
            note: Some(
                "Bluesky handle is a custom domain the subject proved control of".to_string(),
            ),
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

/// Queries Bluesky's public AppView for `handle`. Untested beyond its pure helpers, same
/// convention as the rest of this category.
pub async fn run_bluesky_actor(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    // A bare username is not an AT identifier and would be refused unread — see
    // [`qualify_handle`].
    let qualified = qualify_handle(handle);
    let actor = qualified.as_deref().unwrap_or(handle);
    let url = format!("{BLUESKY_API_BASE}{}", urlencoding::encode(actor));

    // Keyed on what was actually queried, not on what was typed: the cache and the provenance
    // must agree with the request, or a later reader cannot reproduce it.
    let outcome = ctx
        .fetch(
            "bluesky-actor",
            actor,
            &url,
            fetch::OzFetchOptions::default(),
        )
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // An unknown handle answers 400 (occasionally documented as 404 elsewhere in the AT Proto
    // ecosystem), not a clean 404 — see the module doc. Only treat it as a positive "not
    // found" when the body itself says so; any other 400/404 (or one with no readable body)
    // is a real failure and must fall through to `fold_fetch_failure` below.
    if let OzOutcome::HttpError {
        status: 400 | 404,
        body_snippet: Some(snippet),
    } = &outcome
        && snippet.to_ascii_lowercase().contains("profile not found")
    {
        return DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default()));
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!(
            "every non-Ok, non-Cancelled, non-\"profile not found\" OzOutcome was handled above"
        );
    };
    let OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "Bluesky response was not JSON".to_string(),
            },
            None,
        );
    };
    let profile = match parse_bluesky_profile(json) {
        Ok(profile) => profile,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults { count: 1 },
        Some(bluesky_profile_to_yield(&profile)),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_bare_username_is_qualified_into_an_at_identifier() {
        // The bug this pins shut: `torvalds` was sent verbatim and refused with
        // `400 Invalid AT identifier`, so the tool could never succeed on the one kind of
        // value its own entity type produces.
        assert_eq!(
            qualify_handle("torvalds").as_deref(),
            Some("torvalds.bsky.social")
        );
        assert_eq!(
            qualify_handle("  torvalds  ").as_deref(),
            Some("torvalds.bsky.social")
        );
    }

    #[test]
    fn an_identifier_that_is_already_valid_is_left_alone() {
        // Anything with a dot is already a handle, and a `did:` is already an identifier.
        // Appending to either would break a lookup that would otherwise have worked.
        assert_eq!(qualify_handle("torvalds.bsky.social"), None);
        assert_eq!(qualify_handle("jay.bsky.team"), None);
        assert_eq!(qualify_handle("did:plc:abc123"), None);
        assert_eq!(qualify_handle(""), None);
        assert_eq!(qualify_handle("   "), None);
    }

    use super::*;

    #[test]
    fn parses_a_full_bluesky_profile() {
        let json = serde_json::json!({
            "did": "did:plc:z72i7hdynmk6r22z27h6tvur",
            "handle": "bsky.app",
            "displayName": "Bluesky",
            "description": "  official Bluesky account  ",
            "avatar": "https://cdn.bsky.app/img/avatar/plain/...",
            "banner": "https://cdn.bsky.app/img/banner/plain/...",
            "createdAt": "2023-04-12T04:53:57.057Z",
            "indexedAt": "2025-10-27T21:05:26.152Z",
            "followersCount": 34604238,
            "followsCount": 11,
            "postsCount": 808
        });
        let profile = parse_bluesky_profile(&json).expect("profile parses");
        assert_eq!(profile.handle, "bsky.app");
        assert_eq!(
            profile.did.as_deref(),
            Some("did:plc:z72i7hdynmk6r22z27h6tvur")
        );
        assert_eq!(profile.display_name.as_deref(), Some("Bluesky"));
        assert_eq!(
            profile.description.as_deref(),
            Some("official Bluesky account"),
            "description must be trimmed"
        );
        assert_eq!(profile.followers_count, Some(34604238));
        assert_eq!(profile.follows_count, Some(11));
        assert_eq!(profile.posts_count, Some(808));
        assert_eq!(
            profile.created_at.as_deref(),
            Some("2023-04-12T04:53:57.057Z")
        );
    }

    #[test]
    fn null_and_empty_optional_fields_are_treated_as_absent() {
        let json = serde_json::json!({
            "handle": "someone.bsky.social",
            "did": null,
            "displayName": "",
            "description": "   ",
            "followersCount": null
        });
        let profile = parse_bluesky_profile(&json).expect("profile parses");
        assert_eq!(profile.did, None);
        assert_eq!(profile.display_name, None);
        assert_eq!(profile.description, None);
        assert_eq!(profile.followers_count, None);
        assert_eq!(
            profile.follows_count, None,
            "missing key must also be absent"
        );
        assert_eq!(profile.posts_count, None);
        assert_eq!(profile.created_at, None);
    }

    #[test]
    fn rejects_a_response_missing_handle() {
        let json = serde_json::json!({ "did": "did:plc:abc", "displayName": "No Handle" });
        assert!(parse_bluesky_profile(&json).is_err());
    }

    // ── custom-domain handle decision ───────────────────────────────────

    #[test]
    fn bsky_social_handle_is_not_a_custom_domain() {
        assert!(!is_custom_domain_handle("someone.bsky.social"));
        assert!(
            !is_custom_domain_handle("Someone.BSKY.SOCIAL"),
            "must be case-insensitive"
        );
    }

    #[test]
    fn a_bare_domain_handle_is_a_custom_domain() {
        assert!(is_custom_domain_handle("matheo.dev"));
        assert!(is_custom_domain_handle("bsky.app"));
    }

    // ── profile → yield (children only from what the response contained) ──

    fn bare_profile(handle: &str) -> BlueskyProfile {
        BlueskyProfile {
            handle: handle.to_string(),
            did: None,
            display_name: None,
            description: None,
            followers_count: None,
            follows_count: None,
            posts_count: None,
            created_at: None,
        }
    }

    #[test]
    fn yield_emits_no_children_when_the_profile_has_none() {
        let profile = bare_profile("bare.bsky.social");
        let produced = bluesky_profile_to_yield(&profile);
        assert!(produced.children.is_empty());
        assert_eq!(produced.rows.len(), 1, "only the Bluesky row itself");
        assert_eq!(
            produced.rows[0].href.as_deref(),
            Some("https://bsky.app/profile/bare.bsky.social")
        );
    }

    #[test]
    fn yield_emits_exactly_the_children_the_profile_contains() {
        let mut profile = bare_profile("matheo.dev");
        profile.display_name = Some("Matheo".to_string());
        profile.did = Some("did:plc:xyz".to_string());
        profile.followers_count = Some(10);

        let produced = bluesky_profile_to_yield(&profile);
        assert_eq!(produced.children.len(), 2);
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Name && c.value == "Matheo")
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Domain && c.value == "matheo.dev")
        );

        // Rows: Bluesky, Name, DID, Followers.
        assert_eq!(produced.rows.len(), 4);
    }

    #[test]
    fn yield_skips_a_domain_child_for_a_default_bsky_social_handle() {
        let mut profile = bare_profile("someone.bsky.social");
        profile.display_name = Some("Someone".to_string());

        let produced = bluesky_profile_to_yield(&profile);
        assert_eq!(
            produced.children.len(),
            1,
            "only the Name child — no Domain child"
        );
        assert!(
            produced
                .children
                .iter()
                .all(|c| c.oz_type != OzType::Domain)
        );
        assert!(produced.children.iter().any(|c| c.oz_type == OzType::Name));
    }
}
