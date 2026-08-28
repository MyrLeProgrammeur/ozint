//! `video-local-probe` — `entity-video`'s local tool: `ffprobe` for duration/codec, `ffmpeg`
//! for scene-change keyframes, on bytes already sitting in `crate::media`'s store.
//!
//! ## `LocalOnly`, and the shape check it needs that `img-exif` didn't
//!
//! No request leaves this process — same reasoning as `img-exif`, `geo-map-links` and every
//! other `AccessTier::LocalOnly` tool. What is new for `entity-video` is that a `VID` node's
//! own value is not one shape: it can be a `media_id` in the local store (this tool's whole
//! job) *or* a platform URL (`video-youtube-lookup`/`-telegram-resolve`/`-bluesky-resolve`'s).
//! All four fire together in `plans::video_plan`'s one breadth phase, so this tool has to
//! decline cleanly — [`crate::outcome::ToolOutcome::SkippedNotApplicable`] — when handed a
//! value that is not a `media_id`, rather than either lying that it searched (`OkEmpty`) or
//! that a response came back malformed (`ParseError`) for a request it never made.
//!
//! The same outcome covers the other way this tool can decline: no `ffprobe`/`ffmpeg` binary
//! on `PATH`. Verified present on this development machine at `/usr/bin/ffmpeg` and
//! `/usr/bin/ffprobe`, but nothing in this crate assumes a deployment target ships them, and
//! `SkippedNoKey`'s own doc is explicit that it means an env-var/API-key gap, not a missing
//! local binary — see `ToolOutcome::SkippedNotApplicable`'s doc for why one variant honestly
//! covers both this tool's declines.
//!
//! ## Keyframes: scene-change, bounded, verified against a real encode
//!
//! `ffmpeg -vf "select='gt(scene,0.3)'" -vsync vfr -frames:v N` — the standard scene-change
//! selection filter, capped at [`crate::types::MAX_VIDEO_KEYFRAMES`]. Verified by direct run
//! against a synthetic clip (a `testsrc` pattern cut to a flat colour, encoded with `ffmpeg
//! -f lavfi`) before this module was written: the filter found exactly the one frame at the
//! cut, not the sixty input frames. When the scene filter finds nothing (a static or very
//! short clip), a single fallback frame at `t=0` becomes the poster instead — every video this
//! tool successfully probes gets *some* representative image, even one with no scene changes
//! at all. That fallback frame is never itself added to `keyframe_media_ids`/emitted as a
//! child: it is not a scene-detected pivot, just a thumbnail, and this tool's children are
//! only frames the scene filter actually flagged as changed.
//!
//! ## Why each keyframe becomes an `Image` child, not just a payload field
//!
//! Same reasoning as `img-exif`'s GPS-fix child: a keyframe sitting in `keyframeMediaIds` is a
//! string an analyst has to notice and act on manually. A real `Image` node re-enters
//! `entity-image`'s own chain — EXIF, and eventually reverse-image lookup — for free, which is
//! the Bellingcat verification-chain idea the product brief names: a video's individual frames
//! can each carry their own GPS fix or matched-elsewhere history that the video container
//! itself never would.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use tokio::process::Command;
use tokio::time::timeout;

use crate::media;
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{MAX_VIDEO_KEYFRAMES, OzRow, OzType};

/// ISO 6709 signed-degrees pair, e.g. `+37.3382-122.0413/` (QuickTime's
/// `com.apple.quicktime.location.ISO6709`) or `+27.5916+086.5640+8850/` (with altitude). Two
/// signed decimal numbers back to back with no separator between them — the sign of the second
/// is what marks where the first ends, hence the explicit `[+-]` anchors rather than splitting
/// on whitespace/comma.
static ISO6709_LATLON: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([+-]\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)").expect("static ISO 6709 pattern")
});

/// Parses the leading lat/lon pair out of an ISO 6709-style location string. Returns `None`
/// (rather than a partial fix) when the string doesn't start with two signed decimal numbers —
/// callers keep the raw string either way, this only feeds the typed `lat`/`lon` fields and the
/// `Coordinate` child.
fn parse_iso6709(raw: &str) -> Option<(f64, f64)> {
    let caps = ISO6709_LATLON.captures(raw.trim())?;
    let lat: f64 = caps.get(1)?.as_str().parse().ok()?;
    let lon: f64 = caps.get(2)?.as_str().parse().ok()?;
    Some((lat, lon))
}

/// How long one `ffprobe`/`ffmpeg` invocation may run before this tool gives up on it. Local
/// and bounded (the keyframe cap already limits the expensive call's output), so this exists
/// only to stop a pathological input file from hanging a layer indefinitely.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(45);

/// Unlike `img-exif`/`geo-map-links`, this tool is `async` even though it makes no network
/// request: `ffprobe`/`ffmpeg` run as child processes, and awaiting them the ordinary way (via
/// `tokio::process::Command`) is the correct way to not block the runtime's worker thread —
/// spawning a blocking wait here would be the wrong kind of "no request to await".
pub async fn run_video_local_probe(value: &str) -> DispatchOutcome {
    run_video_local_probe_in(&media::media_dir(), value).await
}

/// [`run_video_local_probe`] against an explicit media-store root — the form the tests use.
pub async fn run_video_local_probe_in(root: &Path, value: &str) -> DispatchOutcome {
    if !media::is_media_id(value) {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNotApplicable {
                reason: "the node's value is not a media_id in the local store — \
                          video-local-probe only runs against an uploaded/fetched video already \
                          in the media store"
                    .to_string(),
            },
            None,
        );
    }

    let loaded = match media::load_in(root, value) {
        Ok(loaded) => loaded,
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("could not read the stored media object: {e}"),
                },
                None,
            );
        }
    };
    let Some((meta, bytes)) = loaded else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!(
                    "`{value}` names no object in the media store — upload or fetch it before probing can run"
                ),
            },
            None,
        );
    };
    if !meta.is_video() {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("`{}` is not a decodable video type", meta.mime),
            },
            None,
        );
    }

    let workdir = std::env::temp_dir()
        .join("ozint-video-probe")
        .join(uuid::Uuid::new_v4().to_string());
    if let Err(e) = std::fs::create_dir_all(&workdir) {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("could not create a working directory: {e}"),
            },
            None,
        );
    }
    // Cleaned up on every exit path below, best-effort — a leftover temp dir is a disk-space
    // annoyance, never a correctness problem, so its removal error is swallowed rather than
    // turned into a tool failure over bytes that already did their job.
    let cleanup = || {
        let _ = std::fs::remove_dir_all(&workdir);
    };

    let video_path = workdir.join("input");
    if let Err(e) = std::fs::write(&video_path, &bytes) {
        cleanup();
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("could not stage the video for probing: {e}"),
            },
            None,
        );
    }

    // ── ffprobe: duration, codec, whether there is a video stream at all ──
    let probe_out = match timeout(
        PROBE_TIMEOUT,
        Command::new("ffprobe")
            .args([
                "-v",
                "quiet",
                "-print_format",
                "json",
                "-show_format",
                "-show_streams",
            ])
            .arg(&video_path)
            .output(),
    )
    .await
    {
        Ok(Ok(out)) => out,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            cleanup();
            return DispatchOutcome::Ran(
                ToolOutcome::SkippedNotApplicable {
                    reason: "no `ffprobe` binary found on PATH — video-local-probe needs \
                              ffmpeg's tools installed on this machine"
                        .to_string(),
                },
                None,
            );
        }
        Ok(Err(e)) => {
            cleanup();
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("could not run ffprobe: {e}"),
                },
                None,
            );
        }
        Err(_) => {
            cleanup();
            return DispatchOutcome::Ran(
                ToolOutcome::Timeout {
                    after_ms: PROBE_TIMEOUT.as_millis() as u64,
                },
                None,
            );
        }
    };
    if !probe_out.status.success() {
        cleanup();
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!(
                    "ffprobe exited with {}: {}",
                    probe_out.status,
                    String::from_utf8_lossy(&probe_out.stderr).trim()
                ),
            },
            None,
        );
    }
    let probe_json: serde_json::Value = match serde_json::from_slice(&probe_out.stdout) {
        Ok(v) => v,
        Err(e) => {
            cleanup();
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("ffprobe output was not JSON: {e}"),
                },
                None,
            );
        }
    };

    let duration_s = probe_json
        .get("format")
        .and_then(|f| f.get("duration"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok());

    let video_stream = probe_json
        .get("streams")
        .and_then(|s| s.as_array())
        .and_then(|streams| {
            streams
                .iter()
                .find(|s| s.get("codec_type").and_then(|v| v.as_str()) == Some("video"))
        });
    let codec = video_stream
        .and_then(|s| s.get("codec_name"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    // `format.tags` — container-level metadata a phone/camera embeds alongside the media
    // itself. `creation_time` is a plain ISO 8601 string most encoders write as-is; the
    // location tag's key varies by encoder (`location`, or QuickTime's
    // `com.apple.quicktime.location.ISO6709`), so both are checked. See the module-level
    // `parse_iso6709` doc for the string format.
    let format_tags = probe_json.get("format").and_then(|f| f.get("tags"));
    let creation_time = format_tags
        .and_then(|t| t.get("creation_time"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let location_raw = format_tags
        .and_then(|t| {
            t.get("location")
                .or_else(|| t.get("com.apple.quicktime.location.ISO6709"))
        })
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let location_latlon = location_raw.as_deref().and_then(parse_iso6709);

    // ── ffmpeg: scene-change keyframes, only when there is a video stream to read them from ──
    let mut keyframe_media_ids: Vec<String> = Vec::new();
    let mut poster_media_id: Option<String> = None;

    if video_stream.is_some() {
        let pattern = workdir.join("kf_%03d.jpg");
        match run_ffmpeg_frames(
            &video_path,
            &[
                "-vf",
                "select='gt(scene,0.3)'",
                "-vsync",
                "vfr",
                "-frames:v",
            ],
            &MAX_VIDEO_KEYFRAMES.to_string(),
            &pattern,
        )
        .await
        {
            Ok(_) => {
                let mut frames = collect_frames(&workdir, "kf_");
                frames.truncate(MAX_VIDEO_KEYFRAMES);
                for frame_path in &frames {
                    match std::fs::read(frame_path)
                        .map_err(|e| e.to_string())
                        .and_then(|bytes| {
                            media::store_bytes_in(root, &bytes, None).map_err(|e| e.to_string())
                        }) {
                        Ok(stored) => keyframe_media_ids.push(stored.media_id),
                        Err(_) => continue,
                    }
                }
            }
            Err(NotApplicableOr::NotApplicable(reason)) => {
                cleanup();
                return DispatchOutcome::Ran(ToolOutcome::SkippedNotApplicable { reason }, None);
            }
            Err(NotApplicableOr::Timeout) => {
                cleanup();
                return DispatchOutcome::Ran(
                    ToolOutcome::Timeout {
                        after_ms: EXTRACT_TIMEOUT.as_millis() as u64,
                    },
                    None,
                );
            }
            // A scene-select run that fails to *execute* falls back to the poster-only path
            // below rather than failing the whole tool — the common failure here is a codec
            // ffmpeg's scene filter cannot read, and duration/codec from ffprobe are still a
            // real result worth keeping. Logged, not surfaced as a `ToolOutcome`: a run that
            // executes and simply selects nothing (the ordinary case for a static clip) takes
            // the exact same path, so this is not reliably distinguishable from "nothing to
            // report" without parsing ffmpeg's own stderr grammar.
            Err(NotApplicableOr::Other(stderr)) => {
                tracing::debug!(
                    stderr,
                    "video-local-probe: scene-select ffmpeg run did not succeed"
                );
            }
        }

        if !keyframe_media_ids.is_empty() {
            poster_media_id = keyframe_media_ids.first().cloned();
        } else {
            let poster_path = workdir.join("poster.jpg");
            if run_ffmpeg_frames(&video_path, &[], "1", &poster_path)
                .await
                .is_ok()
                && let Ok(bytes) = std::fs::read(&poster_path)
                && let Ok(stored) = media::store_bytes_in(root, &bytes, None)
            {
                poster_media_id = Some(stored.media_id);
            }
        }
    }

    cleanup();

    let mut patch = serde_json::Map::new();
    patch.insert("mediaId".into(), serde_json::json!(meta.media_id));
    if let Some(d) = duration_s {
        patch.insert("durationS".into(), serde_json::json!(d));
    }
    if let Some(c) = &codec {
        patch.insert("codec".into(), serde_json::json!(c));
    }
    if let Some(p) = &poster_media_id {
        patch.insert("posterMediaId".into(), serde_json::json!(p));
    }
    if !keyframe_media_ids.is_empty() {
        patch.insert(
            "keyframeMediaIds".into(),
            serde_json::json!(keyframe_media_ids),
        );
    }
    if let Some(ct) = &creation_time {
        patch.insert("creationTime".into(), serde_json::json!(ct));
    }
    if let Some(raw) = &location_raw {
        patch.insert("locationRaw".into(), serde_json::json!(raw));
    }
    if let Some((lat, lon)) = location_latlon {
        patch.insert("lat".into(), serde_json::json!(lat));
        patch.insert("lon".into(), serde_json::json!(lon));
    }

    let mut rows = Vec::new();
    if let Some(d) = duration_s {
        let mins = (d / 60.0).floor() as u64;
        let secs = (d % 60.0).round() as u64;
        rows.push(OzRow {
            label: "Duration".into(),
            value: format!("{mins}:{secs:02}"),
            ..Default::default()
        });
    }
    if let Some(c) = &codec {
        rows.push(OzRow {
            label: "Codec".into(),
            value: c.clone(),
            ..Default::default()
        });
    }
    if let Some(ct) = &creation_time {
        rows.push(OzRow {
            label: "Created".into(),
            value: ct.clone(),
            ..Default::default()
        });
    }
    if let Some(raw) = &location_raw {
        rows.push(OzRow {
            label: "Location".into(),
            value: raw.clone(),
            ..Default::default()
        });
    }
    rows.push(OzRow {
        label: "Keyframes".into(),
        value: keyframe_media_ids.len().to_string(),
        ..Default::default()
    });

    let mut children: Vec<ChildSeed> = keyframe_media_ids
        .iter()
        .map(|id| ChildSeed {
            oz_type: OzType::Image,
            value: id.clone(),
            note: Some("video keyframe (scene change)".to_string()),
        })
        .collect();
    if let Some((lat, lon)) = location_latlon {
        children.push(ChildSeed {
            oz_type: OzType::Coordinate,
            value: format!("{lat:.5},{lon:.5}"),
            note: Some("video container GPS tag".to_string()),
        });
    }

    let count = keyframe_media_ids
        .len()
        .max(poster_media_id.is_some() as usize)
        .max(location_latlon.is_some() as usize);
    let outcome = if count == 0 {
        ToolOutcome::OkEmpty
    } else {
        ToolOutcome::OkWithResults {
            count: count as u32,
        }
    };

    DispatchOutcome::Ran(
        outcome,
        Some(ToolYield {
            payload_patch: serde_json::Value::Object(patch),
            rows,
            children,
            ..Default::default()
        }),
    )
}

enum NotApplicableOr {
    NotApplicable(String),
    Timeout,
    Other(String),
}

/// Runs `ffmpeg -v quiet -y -i <input> <extra_args...> <out>`, where `extra_args` is empty for
/// a plain "grab one frame" call and the scene-select flags otherwise. Shared by the keyframe
/// pass and the single-frame poster fallback so both go through the same NotFound/timeout
/// handling.
async fn run_ffmpeg_frames(
    input: &Path,
    extra_args: &[&str],
    frame_count_arg: &str,
    out_pattern: &Path,
) -> Result<(), NotApplicableOr> {
    let mut cmd = Command::new("ffmpeg");
    cmd.args(["-v", "quiet", "-y", "-i"]).arg(input);
    if extra_args.is_empty() {
        cmd.args(["-frames:v", frame_count_arg]);
    } else {
        cmd.args(extra_args).arg(frame_count_arg);
    }
    cmd.arg(out_pattern);

    match timeout(EXTRACT_TIMEOUT, cmd.output()).await {
        Ok(Ok(out)) if out.status.success() => Ok(()),
        Ok(Ok(out)) => Err(NotApplicableOr::Other(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        )),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(NotApplicableOr::NotApplicable(
                "no `ffmpeg` binary found on PATH — video-local-probe needs ffmpeg's tools \
             installed on this machine"
                    .to_string(),
            ))
        }
        Ok(Err(e)) => Err(NotApplicableOr::Other(e.to_string())),
        Err(_) => Err(NotApplicableOr::Timeout),
    }
}

/// Every file in `dir` whose name starts with `prefix`, sorted — `ffmpeg`'s `%03d` pattern
/// already zero-pads, so lexical order is frame order.
fn collect_frames(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut frames: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix))
        })
        .collect();
    frames.sort();
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> PathBuf {
        let dir = std::env::temp_dir()
            .join("ozint-video-local-probe-tests")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parse_iso6709_reads_the_leading_signed_lat_lon_pair() {
        // QuickTime's own tag shape, no altitude.
        assert_eq!(
            parse_iso6709("+37.3382-122.0413/"),
            Some((37.3382, -122.0413))
        );
        // With an altitude term after the pair — still just the first two.
        assert_eq!(
            parse_iso6709("+27.5916+086.5640+8850/"),
            Some((27.5916, 86.5640))
        );
        // Both negative.
        assert_eq!(
            parse_iso6709("-33.8688-151.2093/"),
            Some((-33.8688, -151.2093))
        );
    }

    #[test]
    fn parse_iso6709_rejects_a_string_with_no_leading_signed_pair() {
        assert_eq!(parse_iso6709("not a coordinate"), None);
        assert_eq!(parse_iso6709(""), None);
    }

    #[tokio::test]
    async fn a_value_that_is_not_a_media_id_is_not_applicable_not_an_error() {
        let root = temp_root();
        match run_video_local_probe_in(&root, "https://youtu.be/dQw4w9WgXcQ").await {
            DispatchOutcome::Ran(ToolOutcome::SkippedNotApplicable { reason }, None) => {
                assert!(reason.contains("media_id"));
            }
            other => panic!("expected SkippedNotApplicable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_media_id_absent_from_the_store_is_a_parse_error() {
        let root = temp_root();
        match run_video_local_probe_in(&root, &"0".repeat(64)).await {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None) => {
                assert!(message.contains("names no object"));
            }
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_non_video_object_is_a_parse_error() {
        let root = temp_root();
        const PNG: &[u8] = &[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        let stored = media::store_bytes_in(&root, PNG, None).unwrap();
        match run_video_local_probe_in(&root, &stored.media_id).await {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None) => {
                assert!(message.contains("not a decodable video type"));
            }
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }
    /// Is `ffmpeg` on this machine?
    ///
    /// The two tests below encode a clip and then probe it, so they cannot run without it.
    /// `ffmpeg` is an **optional** dependency of this project — only `video-local-probe` shells
    /// out to it — and a contributor working on, say, the CVE sources should not have a red
    /// suite because of a binary they were never asked to install.
    ///
    /// So these skip rather than fail, and say so loudly on stderr rather than passing in
    /// silence. The coverage is not lost: CI installs `ffmpeg`, so these always execute there
    /// and a real regression still fails the build. A skip that nothing guarantees will ever
    /// run is just a deleted test with extra steps.
    fn ffmpeg_available() -> bool {
        std::process::Command::new("ffmpeg")
            .arg("-version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// A real short clip that changes scene once (encoded with `testsrc` cut to a flat colour)
    /// — the exact shape verified by direct `ffmpeg`/`ffprobe` runs before this module was
    /// written. Regenerated at test time rather than checked in as a fixture: encoding a
    /// five-second clip is fast and keeps this test from depending on a binary asset.
    fn synthesize_scene_change_clip(dir: &Path) -> PathBuf {
        let out = dir.join("scene.mp4");
        let status = std::process::Command::new("ffmpeg")
            .args([
                "-v",
                "quiet",
                "-y",
                "-f",
                "lavfi",
                "-i",
                "testsrc=duration=2:size=64x64:rate=5",
                "-f",
                "lavfi",
                "-i",
                "color=c=red:duration=1:size=64x64:rate=5",
                "-filter_complex",
                "[0:v][1:v]concat=n=2:v=1:a=0[v]",
                "-map",
                "[v]",
                "-pix_fmt",
                "yuv420p",
            ])
            .arg(&out)
            .status();
        assert!(
            matches!(status, Ok(s) if s.success()),
            "test fixture encode must succeed on this machine"
        );
        out
    }

    #[tokio::test]
    async fn a_real_clip_yields_duration_codec_and_at_least_one_keyframe_child() {
        if !ffmpeg_available() {
            eprintln!(
                "SKIPPED a_real_clip_yields_duration_codec_and_at_least_one_keyframe_child: ffmpeg is not on PATH"
            );
            return;
        }
        let root = temp_root();
        let clip_dir = temp_root();
        let clip_path = synthesize_scene_change_clip(&clip_dir);
        let bytes = std::fs::read(&clip_path).unwrap();
        let stored = media::store_bytes_in(&root, &bytes, None).unwrap();

        let produced = match run_video_local_probe_in(&root, &stored.media_id).await {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { .. }, Some(produced)) => produced,
            other => panic!("expected results, got {other:?}"),
        };

        assert_eq!(produced.payload_patch["mediaId"], stored.media_id);
        assert!(produced.payload_patch["durationS"].as_f64().unwrap() > 2.0);
        assert!(produced.payload_patch["codec"].as_str().is_some());
        assert!(produced.payload_patch["posterMediaId"].as_str().is_some());
        assert!(
            !produced.children.is_empty(),
            "the scene cut must produce at least one keyframe child"
        );
        for child in &produced.children {
            assert_eq!(child.oz_type, OzType::Image);
        }
    }

    /// A one-frame clip whose container carries `creation_time` and a QuickTime-style
    /// `location` tag — the shape a phone-recorded video embeds, per ffmpeg's own
    /// `-metadata` write path (mirrors what a real device's muxer writes into `format.tags`).
    fn synthesize_clip_with_location_metadata(dir: &Path) -> PathBuf {
        let out = dir.join("located.mp4");
        let status = std::process::Command::new("ffmpeg")
            .args([
                "-v",
                "quiet",
                "-y",
                "-f",
                "lavfi",
                "-i",
                "color=c=blue:duration=1:size=64x64:rate=5",
                "-metadata",
                "creation_time=2024-05-01T12:00:00.000000Z",
                "-metadata",
                "location=+37.3382-122.0413/",
                "-pix_fmt",
                "yuv420p",
            ])
            .arg(&out)
            .status();
        assert!(
            matches!(status, Ok(s) if s.success()),
            "test fixture encode must succeed on this machine"
        );
        out
    }

    #[tokio::test]
    async fn a_clip_with_location_metadata_yields_creation_time_lat_lon_and_a_coordinate_child() {
        if !ffmpeg_available() {
            eprintln!(
                "SKIPPED a_clip_with_location_metadata_yields_creation_time_lat_lon_and_a_coordinate_child: ffmpeg is not on PATH"
            );
            return;
        }
        let root = temp_root();
        let clip_dir = temp_root();
        let clip_path = synthesize_clip_with_location_metadata(&clip_dir);
        let bytes = std::fs::read(&clip_path).unwrap();
        let stored = media::store_bytes_in(&root, &bytes, None).unwrap();

        let produced = match run_video_local_probe_in(&root, &stored.media_id).await {
            DispatchOutcome::Ran(_, Some(produced)) => produced,
            other => panic!("expected a yield, got {other:?}"),
        };

        assert!(
            produced.payload_patch["creationTime"]
                .as_str()
                .unwrap()
                .starts_with("2024-05-01"),
            "unexpected creationTime: {:?}",
            produced.payload_patch["creationTime"]
        );
        assert_eq!(produced.payload_patch["locationRaw"], "+37.3382-122.0413/");
        assert!((produced.payload_patch["lat"].as_f64().unwrap() - 37.3382).abs() < 1e-3);
        assert!((produced.payload_patch["lon"].as_f64().unwrap() - -122.0413).abs() < 1e-3);

        let coord_child = produced
            .children
            .iter()
            .find(|c| c.oz_type == OzType::Coordinate)
            .expect("a GPS-tagged clip must spawn a Coordinate child");
        assert_eq!(coord_child.value, "37.33820,-122.04130");
    }
}
