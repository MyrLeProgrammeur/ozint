//! `video-youtube-lookup` — YouTube Data API v3, video-by-id (`videos.list`). Needs
//! `YOUTUBE_API_KEY`, the same credential `username::youtube`'s `youtube-channel` uses.
//!
//! ## ⚠️ The request shape is UNVERIFIED, same caveat as `youtube-channel`
//!
//! `YOUTUBE_API_KEY` is absent from this repo's env table (checked directly: not present in
//! this repo's dev env file, and not in the process env this crate reads via
//! `ozint_core::config`), and Google validates the API key before it validates parameters —
//! `username::youtube`'s module doc already establishes that a bogus key cannot distinguish a
//! well-formed request from a malformed one. The endpoint, the `id` parameter and the response
//! shape below are taken from Google's published API reference, not from an observed response.
//! Parsing is defensive for the same reason `youtube-channel`'s is: it tolerates missing
//! sections rather than assuming the documented shape. **Smoke-test against a known video id
//! when `YOUTUBE_API_KEY` is first configured**, and correct this module if the real response
//! disagrees.
//!
//! Endpoint: `GET https://www.googleapis.com/youtube/v3/videos` with
//! `part=snippet,contentDetails,statistics`, `id={videoId}`, `key={YOUTUBE_API_KEY}`.
//!
//! An unknown id is documented to answer `200` with an empty/absent `items` array (not a
//! `404`) — handled as `OkEmpty`, the same convention `channels.list`'s parser uses.
//!
//! ## Value shape: a video id or URL, never a `media_id`
//!
//! `entity-video`'s three network tools and its one local tool share one `OzType::Video` node
//! shape but not one value shape — see `outcome::ToolOutcome::SkippedNotApplicable`'s doc.
//! [`extract_video_id`] accepts a bare 11-character id or a `watch?v=`/`youtu.be/`/`/shorts/`
//! URL; anything else (a `media_id`, a Telegram or Bluesky URL) is declined with that outcome
//! rather than attempted.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::sources::username::nonempty;
use crate::types::{OzRow, OzType};

const YOUTUBE_VIDEOS_ENDPOINT: &str = "https://www.googleapis.com/youtube/v3/videos";

pub const YOUTUBE_API_KEY_VAR: &str = "YOUTUBE_API_KEY";

/// A YouTube video, narrowed to the fields this tool reports.
#[derive(Debug, Clone, PartialEq)]
pub struct YoutubeVideo {
    pub video_id: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub channel_id: Option<String>,
    pub channel_title: Option<String>,
    pub published_at: Option<String>,
    /// Parsed from `contentDetails.duration`'s ISO-8601 form (`PT1M30S`) by
    /// [`parse_iso8601_duration`].
    pub duration_s: Option<f64>,
    pub view_count: Option<u64>,
    pub like_count: Option<u64>,
    pub comment_count: Option<u64>,
    /// `snippet.tags` — the video's keyword tags, if the uploader set any.
    pub tags: Vec<String>,
}

fn count_field(parent: Option<&serde_json::Value>, key: &str) -> Option<u64> {
    let raw = parent?.get(key)?;
    match raw {
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        serde_json::Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

/// Parses `PT#H#M#S` (any component optional, seconds may carry a fraction) into whole
/// seconds. Returns `None` for anything that does not start `PT` — never guesses at a
/// malformed duration.
pub fn parse_iso8601_duration(raw: &str) -> Option<f64> {
    let rest = raw.strip_prefix("PT")?;
    if rest.is_empty() {
        return None;
    }
    let mut total = 0.0;
    let mut number = String::new();
    for ch in rest.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            number.push(ch);
            continue;
        }
        let value: f64 = number.parse().ok()?;
        number.clear();
        total += match ch {
            'H' => value * 3600.0,
            'M' => value * 60.0,
            'S' => value,
            _ => return None,
        };
    }
    if !number.is_empty() {
        // Trailing digits with no unit letter — the string was cut short or malformed.
        return None;
    }
    Some(total)
}

/// Extracts an 11-character YouTube video id from a bare id, a `watch?v=` URL, a `youtu.be/`
/// short link, or a `/shorts/` link. `None` for anything else — this tool declines rather than
/// guesses, per the module doc's value-shape boundary.
pub fn extract_video_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();

    let is_video_id = |s: &str| {
        s.len() == 11
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };

    if is_video_id(trimmed) {
        return Some(trimmed.to_string());
    }

    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let url = url::Url::parse(&with_scheme).ok()?;
    let host = url
        .host_str()?
        .trim_start_matches("www.")
        .trim_start_matches("m.");

    let candidate = match host {
        "youtube.com" | "youtube-nocookie.com" => {
            if let Some((_, v)) = url.query_pairs().find(|(k, _)| k == "v") {
                Some(v.into_owned())
            } else {
                let mut segs = url.path_segments()?;
                match segs.next() {
                    Some("shorts") | Some("embed") => segs.next().map(str::to_string),
                    _ => None,
                }
            }
        }
        "youtu.be" => url
            .path_segments()?
            .find(|seg| !seg.is_empty())
            .map(str::to_string),
        _ => None,
    }?;

    is_video_id(&candidate).then_some(candidate)
}

pub fn parse_youtube_videos(json: &serde_json::Value) -> Result<Option<YoutubeVideo>, String> {
    let items = match json.get("items") {
        None => {
            return if json.get("kind").is_some() {
                Ok(None)
            } else {
                Err("YouTube response has neither `items` nor `kind`".to_string())
            };
        }
        Some(serde_json::Value::Array(items)) => items,
        Some(_) => return Err("YouTube response `items` is not an array".to_string()),
    };

    let Some(first) = items.first() else {
        return Ok(None);
    };

    let video_id = first
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "YouTube video item is missing `id`".to_string())?
        .to_string();

    let snippet = first.get("snippet");
    let content_details = first.get("contentDetails");
    let statistics = first.get("statistics");

    Ok(Some(YoutubeVideo {
        video_id,
        title: nonempty(
            snippet
                .and_then(|s| s.get("title"))
                .and_then(|v| v.as_str()),
        ),
        description: nonempty(
            snippet
                .and_then(|s| s.get("description"))
                .and_then(|v| v.as_str()),
        ),
        channel_id: nonempty(
            snippet
                .and_then(|s| s.get("channelId"))
                .and_then(|v| v.as_str()),
        ),
        channel_title: nonempty(
            snippet
                .and_then(|s| s.get("channelTitle"))
                .and_then(|v| v.as_str()),
        ),
        published_at: nonempty(
            snippet
                .and_then(|s| s.get("publishedAt"))
                .and_then(|v| v.as_str()),
        ),
        duration_s: content_details
            .and_then(|c| c.get("duration"))
            .and_then(|v| v.as_str())
            .and_then(parse_iso8601_duration),
        view_count: count_field(statistics, "viewCount"),
        like_count: count_field(statistics, "likeCount"),
        comment_count: count_field(statistics, "commentCount"),
        tags: snippet
            .and_then(|s| s.get("tags"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    }))
}

pub fn youtube_video_to_yield(video: &YoutubeVideo) -> ToolYield {
    let watch_url = format!("https://www.youtube.com/watch?v={}", video.video_id);

    let mut rows = vec![OzRow {
        label: "YouTube".to_string(),
        value: video
            .title
            .clone()
            .unwrap_or_else(|| video.video_id.clone()),
        href: Some(watch_url.clone()),
        ..Default::default()
    }];
    if let Some(channel_title) = &video.channel_title {
        rows.push(OzRow {
            label: "Channel".to_string(),
            value: channel_title.clone(),
            href: video
                .channel_id
                .as_ref()
                .map(|id| format!("https://www.youtube.com/channel/{id}")),
            ..Default::default()
        });
    }
    if let Some(description) = &video.description {
        rows.push(OzRow {
            label: "Description".to_string(),
            value: description.clone(),
            ..Default::default()
        });
    }
    if let Some(duration_s) = video.duration_s {
        let mins = (duration_s / 60.0).floor() as u64;
        let secs = (duration_s % 60.0).round() as u64;
        rows.push(OzRow {
            label: "Duration".to_string(),
            value: format!("{mins}:{secs:02}"),
            ..Default::default()
        });
    }
    for (label, count) in [
        ("Views", video.view_count),
        ("Likes", video.like_count),
        ("Comments", video.comment_count),
    ] {
        if let Some(count) = count {
            rows.push(OzRow {
                label: label.to_string(),
                value: count.to_string(),
                ..Default::default()
            });
        }
    }
    if let Some(published_at) = &video.published_at {
        rows.push(OzRow {
            label: "Published".to_string(),
            value: published_at.clone(),
            ..Default::default()
        });
    }
    if !video.tags.is_empty() {
        rows.push(OzRow {
            label: "Tags".to_string(),
            value: video.tags.join(", "),
            ..Default::default()
        });
    }

    let mut children = Vec::new();
    if let Some(channel_title) = &video.channel_title {
        children.push(ChildSeed {
            oz_type: OzType::Name,
            value: channel_title.clone(),
            note: Some("YouTube video's channel name".to_string()),
        });
    }

    let mut metadata = rows.clone();
    metadata.retain(|r| r.label != "YouTube");

    let mut patch = serde_json::json!({
        "sourceUrl": watch_url,
        "platform": "youtube",
    });
    if let Some(d) = video.duration_s {
        patch["durationS"] = serde_json::json!(d);
    }
    patch["metadata"] = serde_json::to_value(&metadata).unwrap_or_else(|_| serde_json::json!([]));

    ToolYield {
        payload_patch: patch,
        rows,
        facts: Vec::new(),
        flags: Vec::new(),
        values: Vec::new(),
        children,
    }
}

pub async fn run_video_youtube_lookup(
    value: &str,
    ctx: &crate::sources::ToolCtx,
) -> DispatchOutcome {
    let Some(video_id) = extract_video_id(value) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNotApplicable {
                reason: "the value is not a YouTube video id or URL".to_string(),
            },
            None,
        );
    };

    let Some(key) = ozint_core::config::optional(YOUTUBE_API_KEY_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: YOUTUBE_API_KEY_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!(
        "{YOUTUBE_VIDEOS_ENDPOINT}?part=snippet%2CcontentDetails%2Cstatistics&id={}&key={}",
        urlencoding::encode(&video_id),
        urlencoding::encode(&key),
    );

    let outcome = ctx
        .fetch(
            "video-youtube-lookup",
            &video_id,
            &url,
            fetch::OzFetchOptions::default(),
        )
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
                message: "YouTube response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_youtube_videos(json) {
        Ok(Some(video)) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(youtube_video_to_yield(&video)),
        ),
        Ok(None) => DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default())),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_response() -> serde_json::Value {
        serde_json::json!({
            "kind": "youtube#videoListResponse",
            "items": [{
                "kind": "youtube#video",
                "id": "dQw4w9WgXcQ",
                "snippet": {
                    "title": "Never Gonna Give You Up",
                    "description": "  the original  ",
                    "channelId": "UCuAXFkgsw1L7xaCfnd5JJOw",
                    "channelTitle": "Rick Astley",
                    "publishedAt": "2009-10-25T06:57:33Z",
                    "tags": ["rick astley", "official"]
                },
                "contentDetails": { "duration": "PT3M33S" },
                "statistics": { "viewCount": "1500000000", "likeCount": "17000000", "commentCount": "2200000" }
            }]
        })
    }

    // ── duration parsing ────────────────────────────────────────────────

    #[test]
    fn parses_minutes_and_seconds() {
        assert_eq!(parse_iso8601_duration("PT3M33S"), Some(213.0));
    }

    #[test]
    fn parses_hours_minutes_seconds() {
        assert_eq!(parse_iso8601_duration("PT1H2M3S"), Some(3723.0));
    }

    #[test]
    fn parses_seconds_only_and_a_bare_pt_zero() {
        assert_eq!(parse_iso8601_duration("PT45S"), Some(45.0));
        assert_eq!(parse_iso8601_duration("PT0S"), Some(0.0));
    }

    #[test]
    fn rejects_a_non_duration_string() {
        assert_eq!(parse_iso8601_duration("3:33"), None);
        assert_eq!(parse_iso8601_duration(""), None);
        assert_eq!(parse_iso8601_duration("PT"), None);
    }

    // ── video id extraction ─────────────────────────────────────────────

    #[test]
    fn accepts_a_bare_video_id() {
        assert_eq!(
            extract_video_id("dQw4w9WgXcQ"),
            Some("dQw4w9WgXcQ".to_string())
        );
    }

    #[test]
    fn extracts_from_watch_url() {
        assert_eq!(
            extract_video_id("https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10s"),
            Some("dQw4w9WgXcQ".to_string())
        );
    }

    #[test]
    fn extracts_from_short_link() {
        assert_eq!(
            extract_video_id("https://youtu.be/dQw4w9WgXcQ"),
            Some("dQw4w9WgXcQ".to_string())
        );
        assert_eq!(
            extract_video_id("youtu.be/dQw4w9WgXcQ"),
            Some("dQw4w9WgXcQ".to_string())
        );
    }

    #[test]
    fn extracts_from_shorts_link() {
        assert_eq!(
            extract_video_id("https://www.youtube.com/shorts/dQw4w9WgXcQ"),
            Some("dQw4w9WgXcQ".to_string())
        );
    }

    #[test]
    fn rejects_a_non_youtube_value() {
        assert_eq!(
            extract_video_id(&"a".repeat(64)),
            None,
            "a media_id must not parse as a video id"
        );
        assert_eq!(extract_video_id("https://t.me/durov/531"), None);
        assert_eq!(
            extract_video_id("https://bsky.app/profile/bsky.app/post/abc"),
            None
        );
        assert_eq!(extract_video_id("not a url at all"), None);
    }

    // ── parsing ──────────────────────────────────────────────────────────

    #[test]
    fn parses_a_full_video_response() {
        let video = parse_youtube_videos(&full_response())
            .expect("parses")
            .expect("a video");
        assert_eq!(video.video_id, "dQw4w9WgXcQ");
        assert_eq!(video.title.as_deref(), Some("Never Gonna Give You Up"));
        assert_eq!(video.description.as_deref(), Some("the original"));
        assert_eq!(video.duration_s, Some(213.0));
        assert_eq!(video.view_count, Some(1_500_000_000));
        assert_eq!(
            video.tags,
            vec!["rick astley".to_string(), "official".to_string()]
        );
    }

    #[test]
    fn an_empty_items_array_is_the_empty_finding_not_an_error() {
        let json = serde_json::json!({ "kind": "youtube#videoListResponse", "items": [] });
        assert_eq!(parse_youtube_videos(&json), Ok(None));
    }

    #[test]
    fn a_body_that_is_not_a_video_list_response_is_rejected() {
        let json = serde_json::json!({ "error": { "code": 400, "message": "API key not valid." } });
        assert!(parse_youtube_videos(&json).is_err());
    }

    // ── yield ────────────────────────────────────────────────────────────

    #[test]
    fn yield_writes_source_url_platform_and_metadata() {
        let video = parse_youtube_videos(&full_response()).unwrap().unwrap();
        let produced = youtube_video_to_yield(&video);
        assert_eq!(produced.payload_patch["platform"], "youtube");
        assert_eq!(
            produced.payload_patch["sourceUrl"],
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        );
        assert_eq!(produced.payload_patch["durationS"], 213.0);
        assert!(produced.payload_patch["metadata"].as_array().unwrap().len() > 1);
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Name && c.value == "Rick Astley")
        );
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Tags" && r.value == "rick astley, official")
        );
    }

    // ── arming ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn reports_not_applicable_before_even_checking_the_key() {
        let outcome =
            run_video_youtube_lookup(&"a".repeat(64), &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNotApplicable { .. }, None) => {}
            other => panic!("expected SkippedNotApplicable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(YOUTUBE_API_KEY_VAR).ok();
        unsafe { std::env::remove_var(YOUTUBE_API_KEY_VAR) };

        let outcome =
            run_video_youtube_lookup("dQw4w9WgXcQ", &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNoKey { env_var }, produced) => {
                assert_eq!(env_var, YOUTUBE_API_KEY_VAR);
                assert!(produced.is_none());
            }
            other => panic!("expected SkippedNoKey without a key, got {other:?}"),
        }

        if let Some(v) = prev {
            unsafe { std::env::set_var(YOUTUBE_API_KEY_VAR, v) };
        }
    }
}
