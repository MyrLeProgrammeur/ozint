//! `video-ytdlp-probe` — TikTok (and any other `yt-dlp`-supported platform not already
//! covered) video metadata, via the `yt-dlp` binary's `--dump-json` mode. Found by the
//! 2026-08-25 category audit as the single highest-leverage addition to `entity-video`: one
//! external binary legitimately subsumes what would otherwise be a bespoke Rust parser per
//! platform, the same "shell out to a real tool" shape `video-local-probe` already uses for
//! `ffmpeg`/`ffprobe`.
//!
//! ## Scope: TikTok only, deliberately
//!
//! `yt-dlp` supports hundreds of sites, but this tool's value shape has to stay disjoint from
//! `video-youtube-lookup`/`-telegram-resolve`/`-bluesky-resolve` — see [`is_tiktok_url`] and
//! `plans::video_plan`'s mutual-exclusivity test. Widening this to "any URL `yt-dlp`
//! recognises" would risk two tools both claiming a YouTube URL (this one *could* handle it
//! too) and colliding on `VideoPayload`'s fields under the shallow last-writer-wins merge.
//! TikTok is claimed here specifically because nothing else in this plan covers it, and the
//! audit verified TikTok's own oEmbed is a strictly weaker source (no direct media URL) than
//! what `yt-dlp --dump-json` returns.
//!
//! ## Verified by direct run, 2026-08-25
//!
//! `yt-dlp --dump-json --no-warnings <url>`: a real TikTok video answers exit `0`, one line of
//! JSON on stdout (`id`, `title`, `uploader`, `duration`, `extractor`, `webpage_url`, plus a
//! signed `url`/`formats[]` this tool does not keep — see "Why no direct media URL" below). An
//! unreachable/dead URL answers exit `1`, empty stdout, the error on stderr — never a
//! malformed-but-present JSON body, so [`run_video_ytdlp_probe`] treats a non-zero exit or
//! empty stdout as a genuine tool failure, not an empty finding to fake.
//!
//! ## Why no direct media URL is kept in the payload
//!
//! `yt-dlp`'s `url`/`formats[].url` fields are short-lived, signed CDN links (the same shape
//! `video-telegram-resolve` keeps, deliberately, for Telegram) — but TikTok's signed URLs are
//! typically single-use/short-TTL in practice, more so than Telegram's, so persisting one into
//! a node's payload would go stale faster than the record itself. This tool reports identity
//! and metadata only, matching the "links, not content" posture the whole `entity-video`
//! category already committed to for its network tools.

use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;
use url::Url;

use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const YTDLP_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether `value` is a TikTok URL — `tiktok.com` (`www.`/`m.` stripped), or one of TikTok's
/// own short-link hosts (`vm.tiktok.com`, `vt.tiktok.com`). Deliberately does not accept a bare
/// video id: TikTok ids are not visually distinguishable from any other platform's numeric id,
/// so requiring a full URL is what keeps this tool's value shape unambiguous.
pub fn is_tiktok_url(value: &str) -> bool {
    let with_scheme = if value.contains("://") {
        value.to_string()
    } else {
        format!("https://{value}")
    };
    let Ok(url) = Url::parse(&with_scheme) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches("www.").trim_start_matches("m.");
    host == "tiktok.com" || host == "vm.tiktok.com" || host == "vt.tiktok.com"
}

/// A `yt-dlp --dump-json` result, narrowed to the fields this tool reports.
#[derive(Debug, Clone, PartialEq)]
pub struct YtdlpVideo {
    pub id: Option<String>,
    pub title: Option<String>,
    pub uploader: Option<String>,
    pub duration_s: Option<f64>,
    pub webpage_url: Option<String>,
    /// `upload_date` — `yt-dlp`'s `YYYYMMDD` string, kept as-is.
    pub upload_date: Option<String>,
    pub view_count: Option<u64>,
    pub like_count: Option<u64>,
    pub comment_count: Option<u64>,
}

fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Parses one `yt-dlp --dump-json` line. Rejects a body with no `id` — every field beyond that
/// is optional. Pure and tested.
pub fn parse_ytdlp_json(json: &serde_json::Value) -> Result<YtdlpVideo, String> {
    let id = json
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "yt-dlp output is missing `id`".to_string())?
        .to_string();

    Ok(YtdlpVideo {
        id: Some(id),
        title: nonempty(json.get("title").and_then(|v| v.as_str())),
        uploader: nonempty(json.get("uploader").and_then(|v| v.as_str())),
        duration_s: json.get("duration").and_then(|v| v.as_f64()),
        webpage_url: nonempty(json.get("webpage_url").and_then(|v| v.as_str())),
        upload_date: nonempty(json.get("upload_date").and_then(|v| v.as_str())),
        view_count: json.get("view_count").and_then(|v| v.as_u64()),
        like_count: json.get("like_count").and_then(|v| v.as_u64()),
        comment_count: json.get("comment_count").and_then(|v| v.as_u64()),
    })
}

fn ytdlp_to_yield(video: &YtdlpVideo, queried_url: &str) -> ToolYield {
    let source_url = video
        .webpage_url
        .clone()
        .unwrap_or_else(|| queried_url.to_string());

    let mut rows = vec![OzRow {
        label: "TikTok".to_string(),
        value: video.title.clone().unwrap_or_else(|| source_url.clone()),
        href: Some(source_url.clone()),
        ..Default::default()
    }];
    if let Some(uploader) = &video.uploader {
        rows.push(OzRow {
            label: "Uploader".to_string(),
            value: uploader.clone(),
            ..Default::default()
        });
    }
    if let Some(duration_s) = video.duration_s {
        rows.push(OzRow {
            label: "Duration".to_string(),
            value: format!("{duration_s:.0}s"),
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
    if let Some(upload_date) = &video.upload_date {
        rows.push(OzRow {
            label: "Uploaded".to_string(),
            value: upload_date.clone(),
            ..Default::default()
        });
    }

    let mut patch = serde_json::json!({ "sourceUrl": source_url, "platform": "tiktok" });
    if let Some(d) = video.duration_s {
        patch["durationS"] = serde_json::json!(d);
    }
    patch["metadata"] = serde_json::to_value(&rows[1..]).unwrap_or_else(|_| serde_json::json!([]));

    ToolYield {
        payload_patch: patch,
        rows,
        facts: Vec::new(),
        flags: Vec::new(),
        values: Vec::new(),
        children: Vec::new(),
    }
}

/// Runs `video-ytdlp-probe` against `value` (a TikTok URL). Shells out to the `yt-dlp` binary —
/// see the module doc for the exit-code/stdout contract this relies on, verified by direct run.
pub async fn run_video_ytdlp_probe(value: &str) -> DispatchOutcome {
    if !is_tiktok_url(value) {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNotApplicable {
                reason: "the value is not a TikTok URL".to_string(),
            },
            None,
        );
    }

    let output = timeout(
        YTDLP_TIMEOUT,
        Command::new("yt-dlp")
            .args(["--dump-json", "--no-warnings"])
            .arg(value)
            .stdin(Stdio::null())
            .output(),
    )
    .await;

    let out = match output {
        Ok(Ok(out)) => out,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return DispatchOutcome::Ran(
                ToolOutcome::SkippedNotApplicable {
                    reason: "no `yt-dlp` binary found on PATH".to_string(),
                },
                None,
            );
        }
        Ok(Err(e)) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("could not run yt-dlp: {e}"),
                },
                None,
            );
        }
        Err(_) => {
            return DispatchOutcome::Ran(
                ToolOutcome::Timeout {
                    after_ms: YTDLP_TIMEOUT.as_millis() as u64,
                },
                None,
            );
        }
    };

    if !out.status.success() || out.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("yt-dlp exited with {}: {}", out.status, stderr.trim()),
            },
            None,
        );
    }

    let json: serde_json::Value = match serde_json::from_slice(&out.stdout) {
        Ok(json) => json,
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("yt-dlp output was not JSON: {e}"),
                },
                None,
            );
        }
    };

    match parse_ytdlp_json(&json) {
        Ok(video) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(ytdlp_to_yield(&video, value)),
        ),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_tiktok_urls() {
        assert!(is_tiktok_url(
            "https://www.tiktok.com/@scout2015/video/6718335390845095173"
        ));
        assert!(is_tiktok_url("https://vm.tiktok.com/ZMabc123/"));
        assert!(is_tiktok_url("tiktok.com/@user/video/123"));
    }

    #[test]
    fn rejects_non_tiktok_values() {
        assert!(!is_tiktok_url(
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
        ));
        assert!(!is_tiktok_url("https://t.me/durov/531"));
        assert!(!is_tiktok_url(&"a".repeat(64)));
        assert!(!is_tiktok_url("not a url at all"));
    }

    fn sample_json() -> serde_json::Value {
        serde_json::json!({
            "id": "6718335390845095173",
            "title": "Scramble up ur name",
            "uploader": "scout2015",
            "duration": 10,
            "extractor": "TikTok",
            "webpage_url": "https://www.tiktok.com/@scout2015/video/6718335390845095173",
            "upload_date": "20190617",
            "view_count": 123456,
            "like_count": 7890,
            "comment_count": 42
        })
    }

    #[test]
    fn parses_a_real_ytdlp_output() {
        let video = parse_ytdlp_json(&sample_json()).expect("parses");
        assert_eq!(video.uploader.as_deref(), Some("scout2015"));
        assert_eq!(video.duration_s, Some(10.0));
        assert_eq!(video.upload_date.as_deref(), Some("20190617"));
        assert_eq!(video.view_count, Some(123456));
        assert_eq!(video.like_count, Some(7890));
        assert_eq!(video.comment_count, Some(42));
    }

    #[test]
    fn rejects_output_missing_id() {
        assert!(parse_ytdlp_json(&serde_json::json!({"title": "no id"})).is_err());
    }

    #[test]
    fn yield_writes_source_url_and_platform() {
        let video = parse_ytdlp_json(&sample_json()).unwrap();
        let produced = ytdlp_to_yield(
            &video,
            "https://www.tiktok.com/@scout2015/video/6718335390845095173",
        );
        assert_eq!(produced.payload_patch["platform"], "tiktok");
        assert_eq!(produced.payload_patch["durationS"], 10.0);
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Views" && r.value == "123456")
        );
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Uploaded" && r.value == "20190617")
        );
    }

    #[tokio::test]
    async fn a_non_tiktok_value_is_not_applicable() {
        let outcome = run_video_ytdlp_probe("https://www.youtube.com/watch?v=dQw4w9WgXcQ").await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNotApplicable { .. }, None) => {}
            other => panic!("expected SkippedNotApplicable, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod live_smoke {
    use super::*;

    #[tokio::test]
    #[ignore = "shells out to the real yt-dlp binary against a live TikTok URL"]
    async fn live_ytdlp_probe_against_a_real_tiktok_video() {
        let outcome =
            run_video_ytdlp_probe("https://www.tiktok.com/@scout2015/video/6718335390845095173")
                .await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(y)) => {
                println!("LIVE YTDLP: {count} result, rows: {:?}", y.rows);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
