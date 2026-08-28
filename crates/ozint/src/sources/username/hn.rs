//! `hn-algolia` — Hacker News user lookup via Algolia's public HN search index. Keyless.
//!
//! ## Why this tool makes two calls
//!
//! The obvious single call is `GET https://hn.algolia.com/api/v1/users/{username}`. It works
//! for a real user — verified live 2026-08-21: `pg` → `200
//! {"about":"Bug fixer.","karma":157316,"username":"pg"}`. But for an **unknown** username it
//! answers **`500 Internal Server Error`** with an HTML error body, also verified live
//! 2026-08-21, same date. A 500 is a genuine failure signal, not a "this account does not
//! exist" signal — folding it into [`crate::outcome::ToolOutcome::OkEmpty`] would violate this
//! crate's "empty is a finding" doctrine (see `outcome.rs`'s module doc): it would let a broken
//! upstream masquerade as a verified absence.
//!
//! So existence is established by a *different* endpoint first:
//!
//! 1. **Existence probe** — `GET https://hn.algolia.com/api/v1/search?tags=author_{username}&hitsPerPage=1`.
//!    Verified live 2026-08-21: this endpoint answers **`200` in both cases** (known and
//!    unknown author) and discriminates purely on `nbHits` — `0` for an unknown author,
//!    `> 0` for a real one. That makes it the honest existence probe: any status other than
//!    200 here is folded as a genuine tool failure via [`crate::sources::fold_fetch_failure`],
//!    never swallowed into `OkEmpty`. `nbHits == 0` is the one case that legitimately becomes
//!    `OkEmpty`, and the second call is never made when it fires.
//! 2. **Profile enrichment**, only once the probe confirms `nbHits > 0` —
//!    `GET https://hn.algolia.com/api/v1/users/{username}` for `karma` and `about`. If this
//!    second call fails for any reason (network failure, non-2xx, unparsable body), the tool
//!    **degrades gracefully**: it keeps the confirmed existence plus the item count from step 1
//!    and still reports [`crate::outcome::ToolOutcome::OkWithResults`] with a minimal profile
//!    (no karma, no about). A missing enrichment must never erase a confirmed finding.
//!
//! Both calls URL-encode the username.
//!
//! ## Children
//!
//! HN's `about` field is a free-text, HTML-ish blurb that conventionally carries contact
//! details. It is mined — conservatively — for `mailto`-shaped email addresses and
//! `http(s)://` links (the latter run through [`extract_domain`]), deduplicated, and only ever
//! produced from a genuinely present, non-empty `about`. Nothing is invented beyond what the
//! response actually contained.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

use super::{extract_domain, nonempty};

const HN_SEARCH_URL: &str = "https://hn.algolia.com/api/v1/search";
const HN_USER_BASE: &str = "https://hn.algolia.com/api/v1/users/";

/// A Hacker News user, narrowed to the fields this tool cares about. `items` comes from the
/// existence-probe search call (always known once this struct is built); `karma`/`about` come
/// from the profile-enrichment call and are `None` either when the API omitted them or when
/// that second call failed outright (the degrade path — see the module doc).
#[derive(Debug, Clone, PartialEq)]
pub struct HnProfile {
    pub username: String,
    /// `nbHits` from the search probe — how many HN items (stories/comments) this author has.
    pub items: u64,
    pub karma: Option<i64>,
    /// HTML-stripped, trimmed, non-empty `about` text.
    pub about: Option<String>,
}

/// Parses `GET /search?tags=author_{username}&hitsPerPage=1` for its `nbHits` field. Pure and
/// tested. Rejects a body with no `nbHits` — that shape means the response isn't what this
/// endpoint promises, not that the count is zero.
pub fn parse_hn_search(json: &serde_json::Value) -> Result<u64, String> {
    json.get("nbHits")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "HN search response is missing `nbHits`".to_string())
}

/// Parses `GET /users/{username}` into an [`HnProfile`]. `items` is left at `0` here — it is
/// not this endpoint's field, the caller fills it in from [`parse_hn_search`]'s result. Pure
/// and tested against an inline fixture.
pub fn parse_hn_user(json: &serde_json::Value) -> Result<HnProfile, String> {
    let username = json
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "HN user response is missing `username`".to_string())?
        .to_string();
    let karma = json.get("karma").and_then(|v| v.as_i64());
    let about_stripped = json.get("about").and_then(|v| v.as_str()).map(strip_html);
    let about = nonempty(about_stripped.as_deref());

    Ok(HnProfile {
        username,
        items: 0,
        karma,
        about,
    })
}

/// Strips HTML tags from `input` and decodes the small set of entities HN's `about` field
/// actually uses, collapsing whitespace left behind by tag removal. Pure and tested.
pub fn strip_html(input: &str) -> String {
    static TAG_RE: OnceLock<Regex> = OnceLock::new();
    let tag_re = TAG_RE.get_or_init(|| Regex::new(r"<[^>]*>").expect("valid tag regex"));

    let without_tags = tag_re.replace_all(input, " ");
    // `&amp;` is decoded last so an already-escaped entity (e.g. a literal "&lt;" typed by
    // the user, encoded upstream as "&amp;lt;") does not get double-unescaped into "<".
    let decoded = without_tags
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x2F;", "/")
        .replace("&#39;", "'")
        .replace("&amp;", "&");

    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Mines conservative `Email`/`Domain` children out of a non-empty, already-stripped `about`
/// text. Deduplicated; never called on an absent/empty `about` by [`hn_profile_to_yield`]. Pure
/// and tested.
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
                note: Some("Hacker News profile about text".to_string()),
            });
        }
    }

    let mut seen_domains = HashSet::new();
    for m in url_re.find_iter(about) {
        if let Some(domain) = extract_domain(m.as_str())
            && seen_domains.insert(domain.clone())
        {
            children.push(ChildSeed {
                oz_type: OzType::Domain,
                value: domain,
                note: Some("Hacker News profile about link".to_string()),
            });
        }
    }

    children
}

/// Turns a parsed [`HnProfile`] into a [`ToolYield`]: the `Hacker News` and `Items` rows are
/// always present (both are known by the time this is called — `items` from the search probe,
/// `username` from the handle that was queried); `Karma`/`About` rows, and any children mined
/// from `about`, appear only when the enrichment call actually supplied them. Pure and tested.
pub fn hn_profile_to_yield(profile: &HnProfile) -> ToolYield {
    let mut rows = vec![
        OzRow {
            label: "Hacker News".to_string(),
            value: profile.username.clone(),
            href: Some(format!(
                "https://news.ycombinator.com/user?id={}",
                profile.username
            )),
            ..Default::default()
        },
        OzRow {
            label: "Items".to_string(),
            value: profile.items.to_string(),
            ..Default::default()
        },
    ];
    if let Some(karma) = profile.karma {
        rows.push(OzRow {
            label: "Karma".to_string(),
            value: karma.to_string(),
            ..Default::default()
        });
    }
    if let Some(about) = &profile.about {
        rows.push(OzRow {
            label: "About".to_string(),
            value: about.clone(),
            ..Default::default()
        });
    }

    let children = profile
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

/// Queries Algolia's HN index for `handle`: an existence probe, then (only if it confirms a
/// real author) a profile-enrichment call that degrades gracefully on any failure. Untested
/// beyond its pure helpers, same convention as the rest of this category.
pub async fn run_hn_algolia(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let search_url = format!(
        "{HN_SEARCH_URL}?tags=author_{}&hitsPerPage=1",
        urlencoding::encode(handle)
    );

    // The existence-probe search call for this user — namespaced apart from the profile call
    // below, since they hit different endpoints and must not share an answer.
    let search_outcome = ctx
        .fetch(
            "hn-algolia",
            &format!("search:{handle}"),
            &search_url,
            fetch::OzFetchOptions::default(),
        )
        .await;
    if matches!(search_outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&search_outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(search_resp) = search_outcome else {
        unreachable!("every non-Ok, non-Cancelled OzOutcome was handled above");
    };
    let OzBody::Json(search_json) = &search_resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "HN search response was not JSON".to_string(),
            },
            None,
        );
    };
    let items = match parse_hn_search(search_json) {
        Ok(n) => n,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    // A verified absence: the existence probe answered 200 and cleanly reported zero hits for
    // this author. No enrichment call is made — there is nothing to enrich.
    if items == 0 {
        return DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default()));
    }

    // Existence is confirmed. The enrichment call degrades gracefully on any failure — see the
    // module doc — rather than turning a confirmed finding into a tool-level error.
    let user_url = format!("{HN_USER_BASE}{}", urlencoding::encode(handle));
    // The profile-enrichment call for this user — see the search call above for why the two
    // must not collide.
    let user_outcome = ctx
        .fetch(
            "hn-algolia",
            &format!("user:{handle}"),
            &user_url,
            fetch::OzFetchOptions::default(),
        )
        .await;
    if matches!(user_outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }

    let profile = match user_outcome {
        OzOutcome::Ok(resp) => match &resp.body {
            OzBody::Json(json) => match parse_hn_user(json) {
                Ok(mut profile) => {
                    profile.items = items;
                    Some(profile)
                }
                Err(_) => None,
            },
            _ => None,
        },
        _ => None,
    };
    let profile = profile.unwrap_or_else(|| HnProfile {
        username: handle.to_string(),
        items,
        karma: None,
        about: None,
    });

    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults { count: 1 },
        Some(hn_profile_to_yield(&profile)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_hn_search ──────────────────────────────────────────────────

    #[test]
    fn parses_nb_hits_from_a_search_response() {
        let json = serde_json::json!({
            "hits": [{"author": "pg", "objectID": "1"}],
            "nbHits": 12345,
            "hitsPerPage": 1,
            "page": 0
        });
        assert_eq!(parse_hn_search(&json), Ok(12345));
    }

    #[test]
    fn rejects_a_search_response_missing_nb_hits() {
        let json = serde_json::json!({ "hits": [] });
        assert!(parse_hn_search(&json).is_err());
    }

    #[test]
    fn zero_nb_hits_parses_fine_it_is_not_the_same_as_missing() {
        let json = serde_json::json!({ "nbHits": 0 });
        assert_eq!(parse_hn_search(&json), Ok(0));
    }

    // ── parse_hn_user ────────────────────────────────────────────────────

    #[test]
    fn parses_a_full_hn_user_profile() {
        let json = serde_json::json!({
            "about": "Bug fixer.",
            "karma": 157316,
            "username": "pg"
        });
        let profile = parse_hn_user(&json).expect("profile parses");
        assert_eq!(profile.username, "pg");
        assert_eq!(profile.karma, Some(157316));
        assert_eq!(profile.about.as_deref(), Some("Bug fixer."));
        assert_eq!(
            profile.items, 0,
            "items is not this endpoint's field, caller fills it in"
        );
    }

    #[test]
    fn rejects_a_user_response_missing_username() {
        let json = serde_json::json!({ "karma": 1 });
        assert!(parse_hn_user(&json).is_err());
    }

    #[test]
    fn absent_or_blank_about_becomes_none() {
        let json = serde_json::json!({ "username": "someone", "about": null });
        assert_eq!(parse_hn_user(&json).unwrap().about, None);

        let json = serde_json::json!({ "username": "someone", "about": "   " });
        assert_eq!(parse_hn_user(&json).unwrap().about, None);

        let json = serde_json::json!({ "username": "someone" });
        assert_eq!(parse_hn_user(&json).unwrap().about, None);
    }

    // ── strip_html ───────────────────────────────────────────────────────

    #[test]
    fn strip_html_removes_tags_and_collapses_whitespace() {
        assert_eq!(strip_html("<p>Hello   <b>world</b></p>"), "Hello world");
    }

    #[test]
    fn strip_html_decodes_the_known_entities() {
        assert_eq!(
            strip_html("Tom &amp; Jerry &lt;3 &quot;cats&quot; &#39;n&#39; &#x2F;dogs"),
            "Tom & Jerry <3 \"cats\" 'n' /dogs"
        );
    }

    #[test]
    fn strip_html_leaves_plain_text_untouched() {
        assert_eq!(strip_html("just plain text"), "just plain text");
    }

    // ── hn_profile_to_yield: rows ────────────────────────────────────────

    #[test]
    fn yield_always_has_the_hn_and_items_rows() {
        let profile = HnProfile {
            username: "pg".to_string(),
            items: 12345,
            karma: None,
            about: None,
        };
        let produced = hn_profile_to_yield(&profile);
        assert_eq!(
            produced.rows.len(),
            2,
            "only HN + Items when karma/about are absent"
        );
        assert_eq!(produced.rows[0].label, "Hacker News");
        assert_eq!(produced.rows[0].value, "pg");
        assert_eq!(
            produced.rows[0].href.as_deref(),
            Some("https://news.ycombinator.com/user?id=pg")
        );
        assert_eq!(produced.rows[1].label, "Items");
        assert_eq!(produced.rows[1].value, "12345");
    }

    #[test]
    fn yield_adds_karma_and_about_rows_when_present() {
        let profile = HnProfile {
            username: "pg".to_string(),
            items: 5,
            karma: Some(157316),
            about: Some("Bug fixer.".to_string()),
        };
        let produced = hn_profile_to_yield(&profile);
        assert_eq!(produced.rows.len(), 4);
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Karma" && r.value == "157316")
        );
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "About" && r.value == "Bug fixer.")
        );
    }

    // ── hn_profile_to_yield: children ────────────────────────────────────

    #[test]
    fn yield_emits_no_children_when_about_is_absent() {
        let profile = HnProfile {
            username: "bare".to_string(),
            items: 1,
            karma: None,
            about: None,
        };
        let produced = hn_profile_to_yield(&profile);
        assert!(produced.children.is_empty());
    }

    #[test]
    fn yield_mines_an_email_and_a_domain_from_about() {
        let profile = HnProfile {
            username: "full".to_string(),
            items: 1,
            karma: None,
            about: Some(
                "Reach me at pg@example.com or see https://www.paulgraham.com/essays.html"
                    .to_string(),
            ),
        };
        let produced = hn_profile_to_yield(&profile);
        assert_eq!(produced.children.len(), 2);
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Email && c.value == "pg@example.com")
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Domain && c.value == "paulgraham.com")
        );
    }

    #[test]
    fn yield_dedups_a_repeated_email_address() {
        let profile = HnProfile {
            username: "repeat".to_string(),
            items: 1,
            karma: None,
            about: Some("Email pg@example.com or just pg@example.com again.".to_string()),
        };
        let produced = hn_profile_to_yield(&profile);
        let email_children: Vec<_> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Email)
            .collect();
        assert_eq!(
            email_children.len(),
            1,
            "the same address must not be emitted twice"
        );
    }

    #[test]
    fn yield_does_not_treat_a_plausible_but_incomplete_string_as_an_email() {
        // "user@work" has no dotted TLD after the @ — a deliberately conservative regex must
        // not treat this as an address.
        let profile = HnProfile {
            username: "plausible".to_string(),
            items: 1,
            karma: None,
            about: Some("Find me on IRC as user@work, not by email.".to_string()),
        };
        let produced = hn_profile_to_yield(&profile);
        assert!(
            produced.children.iter().all(|c| c.oz_type != OzType::Email),
            "user@work must not become an Email child"
        );
    }
}
