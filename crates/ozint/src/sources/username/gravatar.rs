//! `gravatar-profile` — Gravatar's v3 public profile API, looked up by **profile username
//! slug**. Keyless.
//!
//! A previous session left Gravatar unbuilt, reasoning that Gravatar's lookup key is an MD5
//! (or SHA-256) hash of an email address, that this crate has no hashing dependency, and that
//! hashing an email makes it an `entity-email` tool anyway rather than an `entity-username`
//! one. That reasoning was right about the *hash* endpoint and wrong about the tool being
//! unbuildable: Gravatar's v3 profile API also accepts a **profile username slug** directly,
//! which needs no hash at all and is exactly an `entity-username` lookup. Verified live
//! 2026-08-21:
//!
//! - `GET https://api.gravatar.com/v3/profiles/beau` → `200` with the profile JSON.
//! - `GET https://api.gravatar.com/v3/profiles/zzznotarealuser999x` → clean `404`
//!   `{"error":"Profile not found"}`.
//!
//! Both keyless. The email-hash path (`/v3/profiles/{md5-or-sha256-of-email}`) remains a
//! separate, still-unbuilt `entity-email` concern and is deliberately not implemented here —
//! it would need a hashing dependency this crate does not have, and this module does not add one.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

use super::{extract_domain, nonempty};

const GRAVATAR_API_BASE: &str = "https://api.gravatar.com/v3/profiles/";

/// One `verified_accounts` entry on a Gravatar profile. Pure struct, parsed alongside
/// [`GravatarProfile`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedAccount {
    /// The raw `service_type` (`twitter`, `github`, …), when the response includes one.
    pub service_type: Option<String>,
    /// Human label as Gravatar renders it (`X`, not `twitter`). Falls back to a generic label
    /// when absent, since a row/child still needs something to say.
    pub service_label: String,
    pub url: String,
    /// Hidden by the profile owner — hidden entries are skipped entirely by
    /// [`gravatar_profile_to_yield`], never turned into a row or a child.
    pub is_hidden: bool,
}

/// One `payments.links` entry on a Gravatar profile — a published crypto wallet address.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentLink {
    /// The wallet's currency/network (`btc`, `eth`, …), when the response includes one.
    pub link_type: Option<String>,
    pub address: String,
}

/// A Gravatar profile, narrowed to the fields this tool cares about. Pure struct — parsed by
/// [`parse_gravatar_profile`], turned into a [`ToolYield`] by [`gravatar_profile_to_yield`].
#[derive(Debug, Clone, PartialEq)]
pub struct GravatarProfile {
    /// Always present on a real response — the only field [`parse_gravatar_profile`] requires.
    pub hash: String,
    pub display_name: Option<String>,
    pub profile_url: Option<String>,
    pub avatar_url: Option<String>,
    pub location: Option<String>,
    pub job_title: Option<String>,
    pub company: Option<String>,
    pub description: Option<String>,
    pub pronouns: Option<String>,
    pub verified_accounts: Vec<VerifiedAccount>,
    /// Published crypto wallet addresses (`payments.links[]`). Previously dropped entirely.
    pub payments: Vec<PaymentLink>,
}

/// Parses one entry of the `verified_accounts` array. Returns `None` for an entry with no
/// usable `url` — nothing else about it is worth carrying.
fn parse_verified_account(json: &serde_json::Value) -> Option<VerifiedAccount> {
    let url = nonempty(json.get("url").and_then(|v| v.as_str()))?;
    let service_label = nonempty(json.get("service_label").and_then(|v| v.as_str()))
        .unwrap_or_else(|| "Verified account".to_string());
    let service_type = nonempty(json.get("service_type").and_then(|v| v.as_str()));
    let is_hidden = json
        .get("is_hidden")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some(VerifiedAccount {
        service_type,
        service_label,
        url,
        is_hidden,
    })
}

/// Parses one entry of the `payments.links` array. Returns `None` for an entry with no usable
/// `address` — nothing else about it is worth carrying.
fn parse_payment_link(json: &serde_json::Value) -> Option<PaymentLink> {
    let address = nonempty(json.get("address").and_then(|v| v.as_str()))?;
    let link_type = nonempty(json.get("type").and_then(|v| v.as_str()));
    Some(PaymentLink { link_type, address })
}

/// Parses a `GET /v3/profiles/{slug}` response body into a [`GravatarProfile`]. Pure and
/// tested against inline fixtures.
pub fn parse_gravatar_profile(json: &serde_json::Value) -> Result<GravatarProfile, String> {
    let hash = nonempty(json.get("hash").and_then(|v| v.as_str()))
        .ok_or_else(|| "Gravatar response is missing `hash`".to_string())?;

    let verified_accounts = json
        .get("verified_accounts")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_verified_account).collect())
        .unwrap_or_default();

    let payments = json
        .get("payments")
        .and_then(|v| v.get("links"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_payment_link).collect())
        .unwrap_or_default();

    Ok(GravatarProfile {
        hash,
        display_name: nonempty(json.get("display_name").and_then(|v| v.as_str())),
        profile_url: nonempty(json.get("profile_url").and_then(|v| v.as_str())),
        avatar_url: nonempty(json.get("avatar_url").and_then(|v| v.as_str())),
        location: nonempty(json.get("location").and_then(|v| v.as_str())),
        job_title: nonempty(json.get("job_title").and_then(|v| v.as_str())),
        company: nonempty(json.get("company").and_then(|v| v.as_str())),
        description: nonempty(json.get("description").and_then(|v| v.as_str())),
        pronouns: nonempty(json.get("pronouns").and_then(|v| v.as_str())),
        verified_accounts,
        payments,
    })
}

/// Extracts the last non-empty path segment from a URL — the handle a verified-account link
/// implies (`https://x.com/beaulebens` → `beaulebens`). Returns `None` when the URL doesn't
/// parse or has no usable trailing segment (a bare domain, or a path of only empty segments).
pub fn handle_from_url(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    parsed
        .path_segments()?
        .rev()
        .find(|segment| !segment.is_empty())
        .map(str::to_string)
}

/// Turns a parsed [`GravatarProfile`] into a [`ToolYield`]: profile facts as rows, and only
/// the children the response actually contained (never invented). `queried_handle` is the
/// slug this tool was called with — used as the row's display fallback when `display_name` is
/// absent, and to suppress a self-referential `Username` child. Pure and tested.
pub fn gravatar_profile_to_yield(profile: &GravatarProfile, queried_handle: &str) -> ToolYield {
    let display_value = profile
        .display_name
        .clone()
        .unwrap_or_else(|| queried_handle.to_string());
    let mut rows = vec![OzRow {
        label: "Gravatar".to_string(),
        value: display_value,
        href: profile.profile_url.clone(),
        ..Default::default()
    }];
    if let Some(location) = &profile.location {
        rows.push(OzRow {
            label: "Location".to_string(),
            value: location.clone(),
            ..Default::default()
        });
    }
    if let Some(job_title) = &profile.job_title {
        rows.push(OzRow {
            label: "Job title".to_string(),
            value: job_title.clone(),
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
    if let Some(description) = &profile.description {
        rows.push(OzRow {
            label: "Bio".to_string(),
            value: description.clone(),
            ..Default::default()
        });
    }
    if let Some(pronouns) = &profile.pronouns {
        rows.push(OzRow {
            label: "Pronouns".to_string(),
            value: pronouns.clone(),
            ..Default::default()
        });
    }
    if let Some(avatar_url) = &profile.avatar_url {
        rows.push(OzRow {
            label: "Avatar".to_string(),
            value: avatar_url.clone(),
            ..Default::default()
        });
    }
    for payment in &profile.payments {
        let label = payment
            .link_type
            .clone()
            .unwrap_or_else(|| "Payment".to_string());
        rows.push(OzRow {
            label,
            value: payment.address.clone(),
            ..Default::default()
        });
    }

    let queried_lower = queried_handle.to_ascii_lowercase();
    let mut children = Vec::new();
    let mut seen_children: std::collections::HashSet<(OzType, String)> =
        std::collections::HashSet::new();

    for account in &profile.verified_accounts {
        if account.is_hidden {
            // Hidden by the profile owner — not our data to surface, no row and no child.
            continue;
        }

        rows.push(OzRow {
            label: account.service_label.clone(),
            value: account.url.clone(),
            href: Some(account.url.clone()),
            ..Default::default()
        });

        if let Some(handle) = handle_from_url(&account.url)
            && handle.to_ascii_lowercase() != queried_lower
            && seen_children.insert((OzType::Username, handle.clone()))
        {
            children.push(ChildSeed {
                oz_type: OzType::Username,
                value: handle,
                note: Some(format!("verified {} account", account.service_label)),
            });
        }

        if let Some(domain) = extract_domain(&account.url)
            && seen_children.insert((OzType::Domain, domain.clone()))
        {
            children.push(ChildSeed {
                oz_type: OzType::Domain,
                value: domain,
                note: Some("Gravatar verified account link".to_string()),
            });
        }
    }

    if let Some(name) = &profile.display_name {
        children.push(ChildSeed {
            oz_type: OzType::Name,
            value: name.clone(),
            note: Some("Gravatar profile display name".to_string()),
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

/// Queries Gravatar's v3 public profile API for `handle` (a profile username slug, not an
/// email hash). Untested beyond its pure helpers, same convention as the rest of this category.
pub async fn run_gravatar_profile(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{GRAVATAR_API_BASE}{}", urlencoding::encode(handle));

    // The profile username slug being looked up — Gravatar's v3 profile is keyed on it.
    let outcome = ctx
        .fetch(
            "gravatar-profile",
            handle,
            &url,
            fetch::OzFetchOptions::default(),
        )
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // Gravatar answers 404 for an unknown profile slug — a clean, positive "not found", not a
    // probe failure.
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
                message: "Gravatar response was not JSON".to_string(),
            },
            None,
        );
    };
    let profile = match parse_gravatar_profile(json) {
        Ok(profile) => profile,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults { count: 1 },
        Some(gravatar_profile_to_yield(&profile, handle)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_json() -> serde_json::Value {
        serde_json::json!({
            "hash": "27205e5c51cb03f862138b22bcb5dc20f94a342e744ff6df1b8dc8af3c865109",
            "display_name": "Beau Lebens",
            "profile_url": "https://gravatar.com/beau",
            "avatar_url": "https://0.gravatar.com/avatar/27205e...",
            "avatar_alt_text": "",
            "location": "Golden, CO",
            "description": "Lead of WooCommerce, at Automattic.",
            "job_title": "Lead, WooCommerce",
            "company": "Automattic",
            "pronouns": "he/him",
            "pronunciation": "",
            "verified_accounts": [
                {
                    "service_type": "twitter",
                    "service_label": "X",
                    "service_icon": "https://gravatar.com/icons/x.svg",
                    "url": "https://x.com/beaulebens",
                    "is_hidden": false
                }
            ],
            "payments": {
                "links": [
                    { "type": "btc", "address": "bc1qxyz0000000000000000000000000000000000" }
                ]
            }
        })
    }

    #[test]
    fn parses_a_full_gravatar_profile() {
        let profile = parse_gravatar_profile(&full_json()).expect("profile parses");
        assert_eq!(
            profile.hash,
            "27205e5c51cb03f862138b22bcb5dc20f94a342e744ff6df1b8dc8af3c865109"
        );
        assert_eq!(profile.display_name.as_deref(), Some("Beau Lebens"));
        assert_eq!(
            profile.profile_url.as_deref(),
            Some("https://gravatar.com/beau")
        );
        assert_eq!(profile.location.as_deref(), Some("Golden, CO"));
        assert_eq!(profile.job_title.as_deref(), Some("Lead, WooCommerce"));
        assert_eq!(profile.company.as_deref(), Some("Automattic"));
        assert_eq!(profile.pronouns.as_deref(), Some("he/him"));
        assert_eq!(profile.verified_accounts.len(), 1);
        let account = &profile.verified_accounts[0];
        assert_eq!(account.service_type.as_deref(), Some("twitter"));
        assert_eq!(account.service_label, "X");
        assert_eq!(account.url, "https://x.com/beaulebens");
        assert!(!account.is_hidden);
        assert_eq!(profile.payments.len(), 1);
        assert_eq!(profile.payments[0].link_type.as_deref(), Some("btc"));
        assert_eq!(
            profile.payments[0].address,
            "bc1qxyz0000000000000000000000000000000000"
        );
    }

    #[test]
    fn parses_payment_links_missing_a_type() {
        let json = serde_json::json!({
            "hash": "abc123",
            "payments": { "links": [ { "address": "0xdeadbeef" } ] }
        });
        let profile = parse_gravatar_profile(&json).expect("profile parses");
        assert_eq!(profile.payments.len(), 1);
        assert_eq!(profile.payments[0].link_type, None);
        assert_eq!(profile.payments[0].address, "0xdeadbeef");
    }

    #[test]
    fn payment_links_surface_as_rows_in_the_yield() {
        let profile = parse_gravatar_profile(&full_json()).expect("profile parses");
        let produced = gravatar_profile_to_yield(&profile, "someone");
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "btc" && r.value == "bc1qxyz0000000000000000000000000000000000"),
            "the published wallet address must reach the rendered rows, not be dropped"
        );
    }

    #[test]
    fn rejects_a_response_missing_hash() {
        let json = serde_json::json!({ "display_name": "No Hash" });
        assert!(parse_gravatar_profile(&json).is_err());
    }

    #[test]
    fn empty_string_fields_are_treated_as_absent() {
        let json = serde_json::json!({
            "hash": "abc123",
            "display_name": "",
            "location": "   "
        });
        let profile = parse_gravatar_profile(&json).expect("profile parses");
        assert_eq!(profile.display_name, None);
        assert_eq!(profile.location, None);
    }

    #[test]
    fn hidden_verified_accounts_produce_neither_a_row_nor_a_child() {
        let json = serde_json::json!({
            "hash": "abc123",
            "verified_accounts": [
                {
                    "service_type": "github",
                    "service_label": "GitHub",
                    "url": "https://github.com/hidden-handle",
                    "is_hidden": true
                }
            ]
        });
        let profile = parse_gravatar_profile(&json).expect("profile parses");
        assert_eq!(
            profile.verified_accounts.len(),
            1,
            "still parsed, just marked hidden"
        );
        let produced = gravatar_profile_to_yield(&profile, "someone");
        assert_eq!(
            produced.rows.len(),
            1,
            "only the Gravatar row itself, no row for the hidden account"
        );
        assert!(produced.children.is_empty());
    }

    // ── handle_from_url ──────────────────────────────────────────────────

    #[test]
    fn handle_from_url_strips_a_trailing_slash() {
        assert_eq!(
            handle_from_url("https://x.com/beaulebens/").as_deref(),
            Some("beaulebens")
        );
    }

    #[test]
    fn handle_from_url_is_none_for_a_bare_domain_with_no_path() {
        assert_eq!(handle_from_url("https://x.com"), None);
        assert_eq!(handle_from_url("https://x.com/"), None);
    }

    #[test]
    fn handle_from_url_reads_a_normal_profile_url() {
        assert_eq!(
            handle_from_url("https://x.com/beaulebens").as_deref(),
            Some("beaulebens")
        );
    }

    // ── profile → yield ──────────────────────────────────────────────────

    #[test]
    fn yield_emits_the_expected_rows_and_children_for_a_full_profile() {
        let profile = parse_gravatar_profile(&full_json()).expect("profile parses");
        let produced = gravatar_profile_to_yield(&profile, "someone-else");

        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Gravatar" && r.value == "Beau Lebens")
        );
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "X" && r.value == "https://x.com/beaulebens")
        );

        assert_eq!(
            produced.children.len(),
            3,
            "one Username, one Domain, one Name"
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Username && c.value == "beaulebens")
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Domain && c.value == "x.com")
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Name && c.value == "Beau Lebens")
        );
    }

    #[test]
    fn yield_suppresses_the_self_referential_username_child() {
        let profile = parse_gravatar_profile(&full_json()).expect("profile parses");
        // Queried with the same handle the verified account resolves to (case-insensitive).
        let produced = gravatar_profile_to_yield(&profile, "BeauLebens");
        assert!(
            !produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Username),
            "the queried handle itself must not come back as a discovered child"
        );
        // The Domain and Name children are unrelated to the queried handle and still appear.
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Domain)
        );
        assert!(produced.children.iter().any(|c| c.oz_type == OzType::Name));
    }

    #[test]
    fn yield_dedups_the_same_handle_seen_via_two_services() {
        let json = serde_json::json!({
            "hash": "abc123",
            "verified_accounts": [
                {
                    "service_type": "github",
                    "service_label": "GitHub",
                    "url": "https://github.com/duplicate",
                    "is_hidden": false
                },
                {
                    "service_type": "mastodon",
                    "service_label": "Mastodon",
                    "url": "https://mastodon.social/duplicate",
                    "is_hidden": false
                }
            ]
        });
        let profile = parse_gravatar_profile(&json).expect("profile parses");
        let produced = gravatar_profile_to_yield(&profile, "someone");
        let username_children: Vec<_> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Username)
            .collect();
        assert_eq!(
            username_children.len(),
            1,
            "the same handle value must appear once"
        );
        assert_eq!(username_children[0].value, "duplicate");
    }

    #[test]
    fn yield_emits_no_children_when_the_profile_has_none() {
        let json = serde_json::json!({ "hash": "abc123" });
        let profile = parse_gravatar_profile(&json).expect("profile parses");
        let produced = gravatar_profile_to_yield(&profile, "someone");
        assert!(produced.children.is_empty());
        assert_eq!(produced.rows.len(), 1, "only the Gravatar row itself");
        assert_eq!(
            produced.rows[0].value, "someone",
            "falls back to the queried handle"
        );
    }
}
