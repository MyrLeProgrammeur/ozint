//! `video-bluesky-resolve` — resolves a Bluesky post URL to its embedded video, via the same
//! public AT Proto AppView `username::bluesky` already calls, keyless.
//!
//! ## The chain, verified by direct call before this module was written
//!
//! A `bsky.app/profile/{handle-or-did}/post/{rkey}` URL names an actor and a record key, not
//! an `at://` URI `app.bsky.feed.getPostThread` needs directly. Two calls:
//!
//! 1. **Handle → DID**, only when the URL's actor segment is a handle rather than a DID
//!    already: `GET com.atproto.identity.resolveHandle?handle={handle}`, keyless, public.
//!    Verified against `bsky.app` itself (`did:plc:z72i7hdynmk6r22z27h6tvur`) and against a
//!    handle constructed not to exist, which answers `400`
//!    `{"error":"InvalidRequest","message":"Unable to resolve handle"}` — the same
//!    status-plus-body-text shape `username::bluesky`'s "profile not found" case already
//!    established for this API family, handled the same way here.
//! 2. **`getPostThread`**, `uri=at://{did}/app.bsky.feed.post/{rkey}`, keyless, public. Found a
//!    real post with a video embed via `getAuthorFeed`'s `filter=posts_with_video`
//!    (`bsky.app`'s own `3mk4lzkrnk22d`), then called `getPostThread` on its `at://` URI
//!    directly and confirmed the shape: `thread.post.embed` on a video post carries
//!    `"$type":"app.bsky.embed.video#view"`, a `playlist` (HLS `.m3u8`, not an `.mp4`) and a
//!    `thumbnail`, both direct CDN URLs. A non-existent post answers `400`
//!    `{"error":"NotFound","message":"Post not found: …"}` — handled the same way as step 1's
//!    absent-handle case, and a post that exists but carries no video embed (most posts) is a
//!    genuine, positive `OkEmpty`: the lookup ran, the post is real, it just isn't a video.
//!
//! ## Why this is `.m3u8`, not a downloadable file, and why that is fine
//!
//! Bluesky serves video as an HLS playlist, never a single file URL — there is no "the mp4"
//! to hand back. This tool reports the playlist URL as-is, same "links, not content" posture
//! `video-telegram-resolve` and `geo-map-links` both take: identifying where the video lives is
//! this tool's job, fetching and storing its bytes is a different unit's.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const RESOLVE_HANDLE_ENDPOINT: &str =
    "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle=";
const GET_POST_THREAD_ENDPOINT: &str =
    "https://public.api.bsky.app/xrpc/app.bsky.feed.getPostThread?uri=";

/// A `(actor, rkey)` pair parsed from a `bsky.app/profile/{actor}/post/{rkey}` URL. `actor` is
/// either a handle or a `did:...` string, both of which `bsky.app` accepts in that position.
pub fn parse_bluesky_post_url(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let url = url::Url::parse(&with_scheme).ok()?;
    let host = url.host_str()?.trim_start_matches("www.");
    if host != "bsky.app" {
        return None;
    }
    let segs: Vec<&str> = url.path_segments()?.filter(|s| !s.is_empty()).collect();
    if segs.len() != 4 || segs[0] != "profile" || segs[2] != "post" {
        return None;
    }
    if segs[1].is_empty() || segs[3].is_empty() {
        return None;
    }
    Some((segs[1].to_string(), segs[3].to_string()))
}

#[derive(Debug, PartialEq)]
struct BlueskyVideoPost {
    playlist: String,
    thumbnail: Option<String>,
    caption: Option<String>,
    author_handle: Option<String>,
    author_display_name: Option<String>,
    posted_at: Option<String>,
}

/// `Ok(None)` covers both "the thread response has no recognizable video embed" and "the
/// thread is a `notFound`/`blocked` view" — both are the empty finding, distinct only from a
/// response that is not a `getPostThread` shape at all (`Err`).
fn parse_bluesky_video_thread(
    json: &serde_json::Value,
) -> Result<Option<BlueskyVideoPost>, String> {
    let thread = json
        .get("thread")
        .ok_or_else(|| "Bluesky response is missing `thread`".to_string())?;
    let Some(post) = thread.get("post") else {
        // `notFoundPost`/`blockedPost` view types carry no `post` key at all — a real,
        // structurally valid answer that just isn't a resolvable post.
        return Ok(None);
    };

    let embed = post.get("embed");
    let is_video = embed.and_then(|e| e.get("$type")).and_then(|v| v.as_str())
        == Some("app.bsky.embed.video#view");
    if !is_video {
        return Ok(None);
    }
    let embed = embed.expect("checked above");

    let playlist = embed
        .get("playlist")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Bluesky video embed is missing `playlist`".to_string())?
        .to_string();

    let author = post.get("author");
    let record = post.get("record");

    Ok(Some(BlueskyVideoPost {
        playlist,
        thumbnail: crate::sources::username::nonempty(
            embed.get("thumbnail").and_then(|v| v.as_str()),
        ),
        caption: crate::sources::username::nonempty(
            record.and_then(|r| r.get("text")).and_then(|v| v.as_str()),
        ),
        author_handle: crate::sources::username::nonempty(
            author
                .and_then(|a| a.get("handle"))
                .and_then(|v| v.as_str()),
        ),
        author_display_name: crate::sources::username::nonempty(
            author
                .and_then(|a| a.get("displayName"))
                .and_then(|v| v.as_str()),
        ),
        posted_at: crate::sources::username::nonempty(
            record
                .and_then(|r| r.get("createdAt"))
                .and_then(|v| v.as_str()),
        ),
    }))
}

fn bluesky_video_to_yield(post: &BlueskyVideoPost, canonical_url: &str) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "Video".to_string(),
        value: post.playlist.clone(),
        href: Some(post.playlist.clone()),
        ..Default::default()
    }];
    let author_label = post
        .author_display_name
        .clone()
        .or_else(|| post.author_handle.clone());
    if let Some(author) = &author_label {
        rows.push(OzRow {
            label: "Author".to_string(),
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
    if let Some(thumbnail) = &post.thumbnail {
        rows.push(OzRow {
            label: "Thumbnail".to_string(),
            value: thumbnail.clone(),
            href: Some(thumbnail.clone()),
            ..Default::default()
        });
    }

    let mut metadata = rows.clone();
    metadata.retain(|r| r.label != "Video");

    ToolYield {
        payload_patch: serde_json::json!({
            "sourceUrl": canonical_url,
            "platform": "bluesky",
            "metadata": metadata,
        }),
        rows,
        facts: Vec::new(),
        flags: Vec::new(),
        values: Vec::new(),
        children: Vec::new(),
    }
}

/// Treats a `400`/`404` as the empty finding only when the body itself says so — the same
/// discipline `username::bluesky::run_bluesky_actor` documents and applies to `getProfile`.
fn is_not_found_body(outcome: &OzOutcome, needle: &str) -> bool {
    matches!(outcome, OzOutcome::HttpError { status: 400 | 404, body_snippet: Some(snippet) }
        if snippet.to_ascii_lowercase().contains(needle))
}

pub async fn run_video_bluesky_resolve(
    value: &str,
    ctx: &crate::sources::ToolCtx,
) -> DispatchOutcome {
    let Some((actor, rkey)) = parse_bluesky_post_url(value) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNotApplicable {
                reason: "the value is not a Bluesky post URL \
                          (`bsky.app/profile/{actor}/post/{rkey}`)"
                    .to_string(),
            },
            None,
        );
    };

    let did = if actor.starts_with("did:") {
        actor.clone()
    } else {
        let url = format!("{RESOLVE_HANDLE_ENDPOINT}{}", urlencoding::encode(&actor));
        let outcome = ctx
            .fetch(
                "video-bluesky-resolve",
                &format!("handle:{actor}"),
                &url,
                fetch::OzFetchOptions::default(),
            )
            .await;
        if matches!(outcome, OzOutcome::Cancelled) {
            return DispatchOutcome::Cancelled;
        }
        if is_not_found_body(&outcome, "unable to resolve handle") {
            return DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default()));
        }
        if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
            return DispatchOutcome::Ran(failure, None);
        }
        let OzOutcome::Ok(resp) = outcome else {
            unreachable!(
                "every non-Ok, non-Cancelled, non-\"unable to resolve\" outcome handled above"
            );
        };
        let OzBody::Json(json) = &resp.body else {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: "Bluesky handle-resolve response was not JSON".to_string(),
                },
                None,
            );
        };
        match json.get("did").and_then(|v| v.as_str()) {
            Some(did) => did.to_string(),
            None => {
                return DispatchOutcome::Ran(
                    ToolOutcome::ParseError {
                        message: "Bluesky handle-resolve response is missing `did`".to_string(),
                    },
                    None,
                );
            }
        }
    };

    let uri = format!("at://{did}/app.bsky.feed.post/{rkey}");
    let url = format!("{GET_POST_THREAD_ENDPOINT}{}", urlencoding::encode(&uri));
    let outcome = ctx
        .fetch(
            "video-bluesky-resolve",
            &uri,
            &url,
            fetch::OzFetchOptions::default(),
        )
        .await;
    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if is_not_found_body(&outcome, "post not found") {
        return DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default()));
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled, non-\"post not found\" outcome handled above");
    };
    let OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "Bluesky getPostThread response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_bluesky_video_thread(json) {
        Ok(Some(post)) => {
            let canonical_url = format!("https://bsky.app/profile/{actor}/post/{rkey}");
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count: 1 },
                Some(bluesky_video_to_yield(&post, &canonical_url)),
            )
        }
        Ok(None) => DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default())),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── URL parsing ──────────────────────────────────────────────────────

    #[test]
    fn parses_a_handle_form_post_url() {
        assert_eq!(
            parse_bluesky_post_url("https://bsky.app/profile/bsky.app/post/3mk4lzkrnk22d"),
            Some(("bsky.app".to_string(), "3mk4lzkrnk22d".to_string()))
        );
    }

    #[test]
    fn parses_a_did_form_post_url() {
        assert_eq!(
            parse_bluesky_post_url(
                "https://bsky.app/profile/did:plc:z72i7hdynmk6r22z27h6tvur/post/3mk4lzkrnk22d"
            ),
            Some((
                "did:plc:z72i7hdynmk6r22z27h6tvur".to_string(),
                "3mk4lzkrnk22d".to_string()
            ))
        );
    }

    #[test]
    fn rejects_a_profile_url_with_no_post() {
        assert_eq!(
            parse_bluesky_post_url("https://bsky.app/profile/bsky.app"),
            None
        );
    }

    #[test]
    fn rejects_a_non_bluesky_value() {
        assert_eq!(parse_bluesky_post_url(&"a".repeat(64)), None);
        assert_eq!(parse_bluesky_post_url("https://youtu.be/dQw4w9WgXcQ"), None);
        assert_eq!(parse_bluesky_post_url("https://t.me/durov/531"), None);
    }

    // ── thread parsing, against the real shape confirmed by direct call ────

    fn real_video_thread() -> serde_json::Value {
        serde_json::json!({
            "thread": {
                "post": {
                    "author": { "did": "did:plc:z72i7hdynmk6r22z27h6tvur", "handle": "bsky.app", "displayName": "Bluesky" },
                    "record": {
                        "createdAt": "2026-04-22T23:00:21.312Z",
                        "text": "v1.121 is live!"
                    },
                    "embed": {
                        "$type": "app.bsky.embed.video#view",
                        "playlist": "https://video.bsky.app/watch/.../playlist.m3u8",
                        "thumbnail": "https://video.bsky.app/watch/.../thumbnail.jpg"
                    }
                }
            }
        })
    }

    #[test]
    fn parses_a_real_video_post_thread() {
        let post = parse_bluesky_video_thread(&real_video_thread())
            .unwrap()
            .unwrap();
        assert_eq!(
            post.playlist,
            "https://video.bsky.app/watch/.../playlist.m3u8"
        );
        assert_eq!(
            post.thumbnail.as_deref(),
            Some("https://video.bsky.app/watch/.../thumbnail.jpg")
        );
        assert_eq!(post.caption.as_deref(), Some("v1.121 is live!"));
        assert_eq!(post.author_display_name.as_deref(), Some("Bluesky"));
    }

    #[test]
    fn a_post_with_a_non_video_embed_is_the_empty_finding() {
        let json = serde_json::json!({
            "thread": { "post": { "embed": { "$type": "app.bsky.embed.record#view" } } }
        });
        assert_eq!(parse_bluesky_video_thread(&json), Ok(None));
    }

    #[test]
    fn a_post_with_no_embed_at_all_is_the_empty_finding() {
        let json = serde_json::json!({ "thread": { "post": { "record": { "text": "hello" } } } });
        assert_eq!(parse_bluesky_video_thread(&json), Ok(None));
    }

    #[test]
    fn a_not_found_thread_view_is_the_empty_finding() {
        let json = serde_json::json!({ "thread": { "$type": "app.bsky.feed.defs#notFoundPost" } });
        assert_eq!(parse_bluesky_video_thread(&json), Ok(None));
    }

    #[test]
    fn a_response_missing_thread_entirely_is_rejected() {
        let json = serde_json::json!({ "unexpected": true });
        assert!(parse_bluesky_video_thread(&json).is_err());
    }

    // ── arming ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_non_bluesky_value_is_not_applicable() {
        let outcome =
            run_video_bluesky_resolve(&"a".repeat(64), &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNotApplicable { .. }, None) => {}
            other => panic!("expected SkippedNotApplicable, got {other:?}"),
        }
    }
}
