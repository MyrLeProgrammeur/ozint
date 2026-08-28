//! `video-telegram-resolve` — the crate's first Telegram tool. `registry.rs`'s module doc used
//! to list Telegram as "deferred"; this is that deferral resolved, scoped to exactly one
//! capability: identifying a video already posted to a **public** Telegram channel, from that
//! post's own URL.
//!
//! ## The endpoint, verified by direct call
//!
//! `https://t.me/s/{channel}/{postId}` — Telegram's login-free web preview, a known keyless
//! `t.me/s/` pattern. Fetched with a real channel before this parser was
//! written: `t.me/s/durov/531` returns `200` with the full HTML page, and the message with
//! `data-post="durov/531"` contains `<video src="https://cdn4.telesco.pe/file/…">` — a direct,
//! playable CDN URL, no auth. A channel with no public preview (checked against `t.me/s/bbcnews`
//! — that channel does not expose one) instead 302-redirects to `t.me/{channel}` and serves a
//! bare "Contact @channel" landing page with no `data-post` markers at all; that is handled as
//! a real, positive `OkEmpty` rather than an error, the same posture `username::bluesky`'s
//! "profile not found" case takes.
//!
//! ## Why this bypasses `ToolCtx::fetch` and calls [`crate::fetch::oz_fetch_bytes`] directly
//!
//! Every other HTML-fetching path in this crate goes through [`crate::fetch::oz_fetch`], whose
//! `OzBody::Html` variant is **already stripped to plain text** by
//! `ozint_core::net::html_to_text` — tags, and every attribute on them, are gone before this
//! tool would ever see them. That is exactly the information this tool exists to read: the
//! `<video src>` URL and the `data-post` markers are attributes, not visible text, and no
//! amount of parsing the stripped-text output could recover them. `oz_fetch_bytes` is `oz_fetch`
//! **before** that content-type dispatch — the same SSRF screen, shared pool, size cap and
//! retry policy, only the parsing step is skipped — which is precisely what a raw-HTML scraper
//! needs and no existing tool in this crate has needed before it.
//!
//! One consequence: this tool does not go through [`crate::sources::ToolCtx::fetch`]'s cache
//! (built around `OzResponse`/`OzBody`, which has no raw-bytes variant to store — see
//! [`crate::fetch::OzBytes`]'s own doc). `ToolDef::ttl_secs` is `0` for this reason, not as an
//! oversight: a Telegram preview page is a live, editable/deletable thing, so a short-lived
//! cache would buy little even if the plumbing existed.
//!
//! ## What this deliberately does not do
//!
//! No video bytes are downloaded — only the CDN URL is reported, the same "links, not content"
//! posture `geo-map-links` takes. No handling for a private channel, a bot, or a channel that
//! requires membership: the public `/s/` preview is the whole surface this tool reaches, and a
//! channel outside it reports the same honest `OkEmpty` as one with no messages at all, since
//! neither this tool nor Telegram's own response distinguishes the two from the outside.

use std::sync::LazyLock;

use regex::Regex;

use crate::fetch::{self, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

/// A Telegram channel/post pair parsed from a `t.me` post URL. `None` for anything else — a
/// bare channel link, a `media_id`, a non-Telegram URL — since this tool needs a specific post,
/// not a channel.
pub fn parse_telegram_post_url(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let url = url::Url::parse(&with_scheme).ok()?;
    let host = url.host_str()?.trim_start_matches("www.");
    if host != "t.me" {
        return None;
    }

    let mut segs: Vec<&str> = url.path_segments()?.filter(|s| !s.is_empty()).collect();
    // Accept the `/s/` preview form too (`t.me/s/durov/531`), so a URL copied straight out of
    // a browser tab already on the preview still resolves.
    if segs.first() == Some(&"s") {
        segs.remove(0);
    }
    if segs.len() != 2 {
        return None;
    }
    let (channel, post_id) = (segs[0], segs[1]);
    if channel.is_empty() || post_id.is_empty() || !post_id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((channel.to_string(), post_id.to_string()))
}

struct TelegramVideoPost {
    video_url: String,
    poster_url: Option<String>,
    caption: Option<String>,
    author: Option<String>,
    posted_at: Option<String>,
}

/// Isolates the HTML block for `data-post="{channel}/{post_id}"` inside a `t.me/s/{channel}`
/// (or `/{postId}`) page — from that marker up to the next message wrapper, or the end of the
/// page. `None` means the page genuinely does not contain this post (wrong id, or a channel
/// with no public preview at all), which the caller reports as `OkEmpty`, not an error.
fn isolate_message_block<'a>(html: &'a str, channel: &str, post_id: &str) -> Option<&'a str> {
    static NEXT_WRAP_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"class="tgme_widget_message_wrap"#).expect("static pattern"));

    let marker = format!(r#"data-post="{channel}/{post_id}""#);
    let start = html.find(&marker)?;
    let after = &html[start..];
    let end = NEXT_WRAP_RE
        .find(after)
        .map(|m| m.start())
        .unwrap_or(after.len());
    Some(&after[..end])
}

fn parse_telegram_message_block(block: &str) -> Option<TelegramVideoPost> {
    static VIDEO_SRC_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"<video[^>]*\ssrc="([^"]+)""#).expect("static pattern"));
    static POSTER_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"tgme_widget_message_video_thumb"[^>]*style="background-image:url\('([^']+)'\)"#,
        )
        .expect("static pattern")
    });
    static TEXT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?s)tgme_widget_message_text[^>]*>(.*?)</div>"#).expect("static pattern")
    });
    static TIME_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"<time datetime="([^"]+)""#).expect("static pattern"));
    static AUTHOR_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"tgme_widget_message_owner_name"[^>]*><span[^>]*>([^<]+)</span>"#)
            .expect("static pattern")
    });

    let video_url = VIDEO_SRC_RE.captures(block)?.get(1)?.as_str().to_string();

    let caption = TEXT_RE.captures(block).and_then(|c| {
        let (_, text) = ozint_core::net::html_to_text(&c[1]);
        (!text.is_empty()).then_some(text)
    });

    Some(TelegramVideoPost {
        video_url,
        poster_url: POSTER_RE.captures(block).map(|c| c[1].to_string()),
        caption,
        author: AUTHOR_RE.captures(block).map(|c| c[1].trim().to_string()),
        posted_at: TIME_RE.captures(block).map(|c| c[1].to_string()),
    })
}

fn telegram_post_to_yield(post: &TelegramVideoPost, canonical_url: &str) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "Video".to_string(),
        value: post.video_url.clone(),
        href: Some(post.video_url.clone()),
        ..Default::default()
    }];
    if let Some(author) = &post.author {
        rows.push(OzRow {
            label: "Channel".to_string(),
            value: author.clone(),
            ..Default::default()
        });
    }
    if let Some(caption) = &post.caption {
        rows.push(OzRow {
            label: "Caption".to_string(),
            value: caption.clone(),
            ..Default::default()
        });
    }
    if let Some(posted_at) = &post.posted_at {
        rows.push(OzRow {
            label: "Posted".to_string(),
            value: posted_at.clone(),
            ..Default::default()
        });
    }
    if let Some(poster) = &post.poster_url {
        rows.push(OzRow {
            label: "Thumbnail".to_string(),
            value: poster.clone(),
            href: Some(poster.clone()),
            ..Default::default()
        });
    }

    let mut metadata = rows.clone();
    metadata.retain(|r| r.label != "Video");

    ToolYield {
        payload_patch: serde_json::json!({
            "sourceUrl": canonical_url,
            "platform": "telegram",
            "metadata": metadata,
        }),
        rows,
        facts: Vec::new(),
        flags: Vec::new(),
        values: Vec::new(),
        children: Vec::new(),
    }
}

pub async fn run_video_telegram_resolve(
    value: &str,
    ctx: &crate::sources::ToolCtx,
) -> DispatchOutcome {
    let Some((channel, post_id)) = parse_telegram_post_url(value) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNotApplicable {
                reason: "the value is not a Telegram post URL (`t.me/{channel}/{postId}`)"
                    .to_string(),
            },
            None,
        );
    };

    let fetch_url = format!("https://t.me/s/{channel}/{post_id}");
    let opts = fetch::OzFetchOptions {
        cancel: ctx.cancel.clone(),
        ..Default::default()
    };

    let raw = match fetch::oz_fetch_bytes(&fetch_url, opts).await {
        Ok(raw) => raw,
        Err(OzOutcome::Cancelled) => return DispatchOutcome::Cancelled,
        Err(other) => {
            return match crate::sources::fold_fetch_failure(&other) {
                Some(failure) => DispatchOutcome::Ran(failure, None),
                None => DispatchOutcome::Ran(
                    ToolOutcome::ParseError {
                        message: "unexpected fetch outcome".to_string(),
                    },
                    None,
                ),
            };
        }
    };

    let html = String::from_utf8_lossy(&raw.bytes);
    let Some(block) = isolate_message_block(&html, &channel, &post_id) else {
        // Either this post is not (or no longer) in the preview window, or the channel has no
        // public preview at all (a 302 to a bare "Contact @channel" page) — both are a real,
        // positive "found nothing" per this crate's doctrine, not a parse failure.
        return DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default()));
    };

    match parse_telegram_message_block(block) {
        Some(post) => {
            let canonical_url = format!("https://t.me/{channel}/{post_id}");
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count: 1 },
                Some(telegram_post_to_yield(&post, &canonical_url)),
            )
        }
        // The post exists but carries no `<video>` — a real post, genuinely not a video.
        None => DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── URL parsing ──────────────────────────────────────────────────────

    #[test]
    fn parses_a_canonical_post_url() {
        assert_eq!(
            parse_telegram_post_url("https://t.me/durov/531"),
            Some(("durov".to_string(), "531".to_string()))
        );
    }

    #[test]
    fn parses_the_preview_form_too() {
        assert_eq!(
            parse_telegram_post_url("https://t.me/s/durov/531"),
            Some(("durov".to_string(), "531".to_string()))
        );
    }

    #[test]
    fn rejects_a_bare_channel_link_with_no_post_id() {
        assert_eq!(parse_telegram_post_url("https://t.me/durov"), None);
    }

    #[test]
    fn rejects_a_non_telegram_value() {
        assert_eq!(parse_telegram_post_url(&"a".repeat(64)), None);
        assert_eq!(
            parse_telegram_post_url("https://youtu.be/dQw4w9WgXcQ"),
            None
        );
        assert_eq!(
            parse_telegram_post_url("https://bsky.app/profile/bsky.app/post/abc"),
            None
        );
    }

    // ── message-block isolation and parsing, against a fixture shaped exactly like the
    // ── real `t.me/s/durov/531` page fetched and inspected before this module was written ──

    fn fixture_page() -> String {
        r#"<div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="durov/530">
                <div class="tgme_widget_message_text js-message_text">an earlier post</div>
            </div></div>
            <div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="durov/531">
                <div class="tgme_widget_message_author"><a class="tgme_widget_message_owner_name" href="https://t.me/durov"><span dir="auto">Pavel Durov</span></a></div>
                <div class="media_supported_cont"><a class="tgme_widget_message_video_player" href="https://t.me/durov/531"><i class="tgme_widget_message_video_thumb" style="background-image:url('https://cdn4.telesco.pe/file/poster.jpg')"></i></a></div>
                <video src="https://cdn4.telesco.pe/file/c4225d3b52.mp4?token=abc" class="tgme_widget_message_video"></video>
                <div class="tgme_widget_message_text js-message_text" dir="auto">Dubai is full of traffic</div>
                <time datetime="2026-05-16T13:57:49+00:00"></time>
            </div></div>
            <div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="durov/532">
                <div class="tgme_widget_message_text js-message_text">a later post</div>
            </div></div>"#
            .to_string()
    }

    #[test]
    fn isolates_exactly_the_requested_message() {
        let page = fixture_page();
        let block = isolate_message_block(&page, "durov", "531").expect("block found");
        assert!(block.contains("cdn4.telesco.pe/file/c4225d3b52.mp4"));
        assert!(!block.contains("an earlier post"));
        assert!(!block.contains("a later post"));
    }

    #[test]
    fn a_post_not_in_the_page_is_absent() {
        let page = fixture_page();
        assert!(isolate_message_block(&page, "durov", "999").is_none());
    }

    #[test]
    fn parses_video_poster_caption_author_and_time_from_the_block() {
        let page = fixture_page();
        let block = isolate_message_block(&page, "durov", "531").unwrap();
        let post = parse_telegram_message_block(block).expect("a video post");
        assert_eq!(
            post.video_url,
            "https://cdn4.telesco.pe/file/c4225d3b52.mp4?token=abc"
        );
        assert_eq!(
            post.poster_url.as_deref(),
            Some("https://cdn4.telesco.pe/file/poster.jpg")
        );
        assert_eq!(post.caption.as_deref(), Some("Dubai is full of traffic"));
        assert_eq!(post.author.as_deref(), Some("Pavel Durov"));
        assert_eq!(post.posted_at.as_deref(), Some("2026-05-16T13:57:49+00:00"));
    }

    #[test]
    fn a_block_with_no_video_tag_parses_to_none() {
        let page = fixture_page();
        let block = isolate_message_block(&page, "durov", "530").unwrap();
        assert!(parse_telegram_message_block(block).is_none());
    }

    // ── arming ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_non_telegram_value_is_not_applicable() {
        let outcome =
            run_video_telegram_resolve(&"a".repeat(64), &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNotApplicable { .. }, None) => {}
            other => panic!("expected SkippedNotApplicable, got {other:?}"),
        }
    }
}
