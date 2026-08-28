//! `entity-username (USR)` — one of twelve entity-type categories under `sources/`. This was
//! the first category built, specifically because its whole primary tool chain is keyless or
//! already-keyed — no new account setup needed to demo it end to end.
//!
//! One module per tool, each holding its own pure parse/shape helpers plus the thin untested
//! `async fn` that makes the real network call — the split this crate uses everywhere (see
//! `fetch.rs`'s module doc).
//!
//! | module | tool id | reached |
//! |---|---|---|
//! | [`wmn`] | `wmn-probe` | keyless — the ~730-site WhatsMyName fan-out |
//! | [`github`] | `github-user` | keyless (`GITHUB_TOKEN` only lifts the rate limit) |
//! | [`bluesky`] | `bluesky-actor` | keyless — AT Proto public AppView |
//! | [`mastodon`] | `mastodon-lookup` | keyless — fan-out across a fixed instance list |
//! | [`hn`] | `hn-algolia` | keyless — Algolia's Hacker News index |
//! | [`gravatar`] | `gravatar-profile` | keyless — profile-by-username slug |
//! | [`youtube`] | `youtube-channel` | needs `YOUTUBE_API_KEY` (absent → honest skip) |
//! | [`keybase`] | `keybase-lookup` | keyless — cryptographically-proved cross-account links |
//! | [`devto`] | `devto-user` | keyless — dev.to (Forem) public profile API |
//! | [`lobsters`] | `lobsters-user` | keyless — Lobsters' per-user JSON endpoint |
//! | [`steam`] | `steam-profile` | keyless — Steam Community's public XML profile feed |
//!
//! ## Sources deliberately absent from this slice
//!
//! **PullPush (Reddit)** — listed as keyless. It is
//! not, any more: `GET https://api.pullpush.io/reddit/search/{submission,comment}/?author=…`
//! answers **`429`** with `"This website does not provide free scraping resources for agents.
//! Please contact the administrator on Discord if you're interested in a paid scraping
//! service."` — verified by direct call **2026-08-21** on both endpoints. That is a
//! deliberate policy wall, not a rate limit we can wait out, so no `pullpush` module exists
//! and nothing is catalogued for it. Reddit-by-username needs a different supplier before it
//! can be built; do not re-add PullPush without re-verifying it first.
//!
//! **Telegram (`t.me/s/{handle}` scrape)** — deferred, not blocked. The public preview page
//! is reachable keylessly, but `t.me/s/{absent}` answers `302` into `t.me/{absent}`, which
//! itself answers `200` — so the redirect the shared HTTP pool follows erases the only status
//! signal, and the surviving discriminators are CSS class markers (`tgme_channel_info`) that
//! [`crate::fetch::OzBody::Html`] strips before a caller ever sees them. Shipping that would
//! mean guessing from stripped prose. This scrape pairs naturally with the Bot API `getChat`
//! path anyway, whose token is absent from the env table — so both halves wait together.
//! Verified 2026-08-21.
//!
//! **Maigret / Naminter / Sherlock / Aliens Eye / Snoop** — sidecar-only by design;
//! they wait on the sidecar bridge (Phase 5).

pub mod bluesky;
pub mod devto;
pub mod github;
pub mod gravatar;
pub mod hn;
pub mod keybase;
pub mod lobsters;
pub mod mastodon;
pub mod reddit;
pub mod steam;
pub mod wmn;
pub mod youtube;

use crate::fetch::OzBody;

/// Renders an [`OzBody`] to plain text for a caller to substring-search, regardless of how
/// `oz_fetch` dispatched the content-type. Shared by every tool in this category that needs
/// to look at a body it did not get as structured JSON.
pub(crate) fn body_text(body: &OzBody) -> String {
    match body {
        OzBody::Json(v) => v.to_string(),
        OzBody::Html { title, text } => format!("{title}\n{text}"),
        OzBody::Xml(s) => s.clone(),
        OzBody::Text(s) => s.clone(),
        OzBody::Empty => String::new(),
    }
}

/// Trims a `&str` field and drops it if nothing is left — the shape almost every profile API
/// in this category needs, since they variously return `null`, `""` or `"   "` for an unset
/// field and all three mean "absent", never `Some("")`.
pub(crate) fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Best-effort domain extraction from a free-text profile field (GitHub's `blog`, a Mastodon
/// profile field, a Gravatar verified-account URL), which is sometimes a bare hostname,
/// sometimes a full URL, and sometimes something else entirely. Returns `None` rather than
/// guessing when it doesn't look like a real domain.
pub(crate) fn extract_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let host = url::Url::parse(&with_scheme).ok()?.host_str()?.to_string();
    if host.contains('.') {
        Some(host.strip_prefix("www.").unwrap_or(&host).to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_text_renders_every_body_shape() {
        assert_eq!(body_text(&OzBody::Empty), "");
        assert_eq!(body_text(&OzBody::Text("plain".into())), "plain");
        assert_eq!(body_text(&OzBody::Xml("<a/>".into())), "<a/>");
        assert_eq!(
            body_text(&OzBody::Html {
                title: "T".into(),
                text: "B".into()
            }),
            "T\nB"
        );
        assert_eq!(
            body_text(&OzBody::Json(serde_json::json!({ "a": 1 }))),
            r#"{"a":1}"#
        );
    }

    #[test]
    fn nonempty_drops_blank_and_whitespace_only_fields() {
        assert_eq!(nonempty(None), None);
        assert_eq!(nonempty(Some("")), None);
        assert_eq!(nonempty(Some("   ")), None);
        assert_eq!(nonempty(Some("  kept  ")).as_deref(), Some("kept"));
    }

    #[test]
    fn extracts_a_domain_from_a_bare_hostname() {
        assert_eq!(extract_domain("matheo.dev").as_deref(), Some("matheo.dev"));
    }

    #[test]
    fn extracts_a_domain_from_a_full_url_and_strips_www() {
        assert_eq!(
            extract_domain("https://www.example.com/path").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn does_not_invent_a_domain_from_a_non_domain_field() {
        assert_eq!(extract_domain(""), None);
        assert_eq!(extract_domain("   "), None);
        assert_eq!(
            extract_domain("just some text"),
            None,
            "no dot, not a real host"
        );
    }
}
