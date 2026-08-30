//! `sidecar-maigret` — `entity-username`'s deep-sweep tier, named but left unwired in
//! `plans::username_plan`'s own doc comment until this unit landed. Runs against a local
//! `soxoj/maigret:web` container (MIT, `docker pull soxoj/maigret:web`) — see
//! `crates/ozint/docker/docker-compose.yml`.
//!
//! ## The API, verified by starting the real container and calling it (2026-08-25)
//!
//! `soxoj/maigret` publishes two Docker tags: `latest` (CLI-only, no server) and `web` (auto-
//! launches a Flask app on port 5000). The `web` variant's HTTP surface is read straight out
//! of its own `maigret/web/app.py` and then exercised for real:
//!
//! - `POST /api/scan` (form body `usernames=<value>`) → `{"job_id": "<hex>"}`. Confirmed live:
//!   `curl -d "usernames=torvalds" http://localhost:5000/api/scan`.
//! - `GET /api/scan/{job_id}/stream` → a genuine `text/event-stream`. Confirmed live against
//!   the job above; observed event shapes:
//!   - `{"type":"start","username":..,"total":509}` — Maigret's default run checks the top
//!     509 sites by traffic (not the full ~3000+ database; `-a`/`all_sites` would need a
//!     scan option this tool does not set).
//!   - `{"type":"found","username":..,"site":..,"url":..,"ids":{...}}` — one per confirmed
//!     hit. `ids` is a bag of extractor-derived profile fields (varies per site; observed
//!     `uid`/`username`/`fullname`/`image`/`follower_count`/… on real sites during the probe).
//!   - `{"type":"progress",...}` — one per site checked, ignorable for this tool's purposes.
//!   - `{"type":"done","redirect":"/results/search_<job_id>"}` — terminal.
//!   - `{"type":"stopped",...}` / `{"type":"error",...}` — also terminal, seen only in source,
//!     not reproduced live (would need an actual mid-scan failure or `/stop` call).
//! - `POST /api/scan/{job_id}/stop` — confirmed live to answer `{"error":"unknown job"}` once
//!   the job has already finished/been dropped (matches `sfwebui.py`'s in-memory
//!   `live_jobs` dict, which the stream generator's `finally` clears when the SSE connection
//!   ends). Used here on cancellation so an aborted layer doesn't leave an orphaned scan
//!   running inside the container.
//!
//! ## Why this writes `rows`, never `payload_patch["hits"]`
//!
//! `wmn.rs` is the sole owner of `UsernamePayload.hits` — it writes the *entire* array in one
//! patch, and `runtime::merge_patch`'s shallow last-writer-wins semantics mean a second tool
//! writing that same key would silently replace WhatsMyName's ~730-site sweep with whatever
//! subset Maigret happened to check, discarding real evidence rather than adding to it. This
//! tool's own deep-sweep phase only fires *after* `wmn-probe`'s phase already ran (gated on
//! `layer_plan::enough_confirmed_hits()`), so the collision is not hypothetical — it is the
//! very next phase in the plan. Every confirmed site instead becomes an `OzRow` (label = site
//! name, value = the profile URL, `href` set), landing in the node's detail rows alongside
//! `phone-local-normalize`'s and `img-exif`'s row-only pattern, not in the structured payload.
//!
//! ## Why this does not wait for `done` unconditionally
//!
//! A default Maigret run checks 509 sites with a 10s per-site timeout and its own internal
//! concurrency; the live probe above needed several minutes to reach `done` on real network
//! conditions. `wmn-probe`'s own module doc already accepts a multi-minute worst case for its
//! ~730-site sweep, synchronously, inside `fire_layer`'s loop — so blocking is not new here.
//! What is bounded is the *ceiling*: [`STREAM_BUDGET`] caps how long this tool waits before it
//! settles with whatever `found` events already arrived, rather than blocking indefinitely on
//! a slow or stalled container. A capped partial sweep is still a genuine, honest finding —
//! unlike SpiderFoot (`spiderfoot.rs`), which has no equivalent "stream what's ready so far"
//! shape and needs the refresh-later pattern instead; see that module's doc for why the two
//! sidecars end up handled differently despite sharing a time budget.
//!
//! ## Why a confirmed hit does NOT become a child — read this before "fixing" it
//!
//! A confirmed hit was briefly turned into an `OzType::Username` `ChildSeed` carrying the
//! queried handle itself — read `wmn.rs`'s module doc for the full reasoning shared by all
//! three site-list sweeps in this crate (`wmn.rs`, `blackbird.rs`, this file). In short:
//! Maigret confirms one identity across many sites, not many identities, so a same-value child
//! always dedups against the node the layer is already running on
//! (`runtime::emit_child`'s dedup-before-persist step, `runtime.rs:444-458`) and can only ever
//! add a corroboration record there, never a new node — and no `OzType` in this crate carries a
//! per-platform profile URL as its identity, so there is no sound value a child could carry
//! instead. The children were removed once this was confirmed; the row list above is where a
//! confirmed hit's information actually belongs.

use std::time::Duration;

use futures::StreamExt;

use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const DEFAULT_BASE_URL: &str = "http://localhost:5000";

/// How long this tool waits for Maigret's SSE stream to reach `done` before settling with
/// whatever `found` events already arrived. Same order of magnitude as `spiderfoot.rs`'s poll
/// budget, for the same reason: a layer is one deliberate human click, not a background job,
/// so there is a ceiling on how long one tool may hold it open.
const STREAM_BUDGET: Duration = Duration::from_secs(90);

/// One `{"type":"found",...}` event, the only event shape this tool keeps. `ids` is Maigret's
/// own extractor output — a bag of site-specific profile fields (confirmed by reading
/// `soxoj/socid-extractor`, the library Maigret calls on a positive hit: ~100-130 of its
/// ~175 documented site schemes actually extract real fields — full name, bio, join date,
/// follower count, linked socials — rather than only confirming presence). Every field name is
/// site-defined, so this is kept as a raw JSON map rather than a typed struct; `null`/empty maps
/// (the ~2900 sites `socid-extractor` has no scheme for) are dropped before reaching
/// [`maigret_to_yield`].
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
struct FoundEvent {
    site: String,
    url: String,
    #[serde(default)]
    ids: serde_json::Map<String, serde_json::Value>,
}

/// Parses one `data: {...}` SSE line into its `type` field and the raw JSON, or `None` for a
/// blank keep-alive line / malformed frame — both are silently skippable, not tool failures.
fn parse_sse_event(line: &str) -> Option<serde_json::Value> {
    let payload = line.strip_prefix("data:")?.trim();
    serde_json::from_str(payload).ok()
}

/// Turns collected `found` events into a [`ToolYield`]. `truncated` is true when the stream
/// budget ran out before a `done` event — the row list is then a genuine but incomplete sample,
/// and the yield says so via a synthetic row rather than presenting it as exhaustive.
/// `Value::Array`/`Value::Object` render as their plain JSON text (rare in practice — extractors
/// mostly return scalars); a bare string renders unquoted.
fn id_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn maigret_to_yield(hits: &[FoundEvent], truncated: bool) -> ToolYield {
    let mut rows: Vec<OzRow> = Vec::new();
    for h in hits {
        rows.push(OzRow {
            label: h.site.clone(),
            value: h.url.clone(),
            href: Some(h.url.clone()),
            ..Default::default()
        });
        for (key, value) in &h.ids {
            rows.push(OzRow {
                label: format!("{} · {}", h.site, key),
                value: id_value_to_string(value),
                ..Default::default()
            });
        }
    }
    if truncated {
        rows.push(OzRow {
            label: "Maigret sweep".to_string(),
            value: format!(
                "stopped after {}s — {} confirmed site{} found so far, more may exist",
                STREAM_BUDGET.as_secs(),
                hits.len(),
                if hits.len() == 1 { "" } else { "s" }
            ),
            ..Default::default()
        });
    }
    ToolYield {
        rows,
        ..Default::default()
    }
}

/// Runs `sidecar-maigret` against `value` (a username). Reaches
/// `MAIGRET_SIDECAR_URL` (default [`DEFAULT_BASE_URL`]) directly via
/// `ozint_core::http::client()` — see `sidecar::mod`'s doc for why that bypasses
/// `safe_fetch_url` deliberately.
pub async fn run_maigret(value: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let base = super::sidecar_base_url("MAIGRET_SIDECAR_URL", DEFAULT_BASE_URL);

    let start = super::sidecar_request(
        reqwest::Method::POST,
        &format!("{base}/api/scan"),
        Some(&[("usernames", value)]),
        Duration::from_secs(15),
    )
    .await;

    let job = match start {
        Ok(json) => json,
        Err(outcome) => return DispatchOutcome::Ran(outcome, None),
    };
    let Some(job_id) = job.get("job_id").and_then(|v| v.as_str()) else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "Maigret's /api/scan response had no job_id".to_string(),
            },
            None,
        );
    };

    let stream_url = format!("{base}/api/scan/{job_id}/stream");
    let client = ozint_core::http::client();
    let resp = match client.get(&stream_url).timeout(STREAM_BUDGET).send().await {
        Ok(r) => r,
        Err(e) if e.is_timeout() => {
            return DispatchOutcome::Ran(
                ToolOutcome::Timeout {
                    after_ms: STREAM_BUDGET.as_millis() as u64,
                },
                None,
            );
        }
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::HttpError {
                    status: 0,
                    message: Some(format!("could not open Maigret's stream: {e}")),
                },
                None,
            );
        }
    };

    let deadline = tokio::time::Instant::now() + STREAM_BUDGET;
    let mut byte_stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut hits: Vec<FoundEvent> = Vec::new();
    let mut truncated = true;

    loop {
        if let Some(cancel) = &ctx.cancel
            && cancel.is_cancelled()
        {
            let _ = client
                .post(format!("{base}/api/scan/{job_id}/stop"))
                .timeout(Duration::from_secs(5))
                .send()
                .await;
            return DispatchOutcome::Cancelled;
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            // Best-effort: ask the container to stop the scan since we're no longer reading
            // it, rather than leaving it to burn through the rest of the site list unread.
            let _ = client
                .post(format!("{base}/api/scan/{job_id}/stop"))
                .timeout(Duration::from_secs(5))
                .send()
                .await;
            break;
        }

        let chunk = match tokio::time::timeout(remaining, byte_stream.next()).await {
            Ok(Some(Ok(bytes))) => bytes,
            Ok(Some(Err(e))) => {
                return DispatchOutcome::Ran(
                    ToolOutcome::HttpError {
                        status: 0,
                        message: Some(format!("Maigret's stream broke: {e}")),
                    },
                    None,
                );
            }
            // Stream ended on its own — the container closed the connection.
            Ok(None) => {
                truncated = false;
                break;
            }
            Err(_) => break, // budget exhausted mid-wait
        };

        buf.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(pos) = buf.find("\n\n") {
            let frame = buf[..pos].to_string();
            buf.drain(..pos + 2);
            for line in frame.lines() {
                let Some(json) = parse_sse_event(line) else {
                    continue;
                };
                match json.get("type").and_then(|v| v.as_str()) {
                    Some("found") => {
                        if let Ok(hit) = serde_json::from_value::<FoundEvent>(json.clone()) {
                            hits.push(hit);
                        }
                    }
                    Some("done") | Some("stopped") => {
                        truncated = false;
                    }
                    _ => {}
                }
            }
            if !truncated {
                break;
            }
        }
        if !truncated {
            break;
        }
    }

    let count = hits.len() as u32;
    let produced = maigret_to_yield(&hits, truncated);
    if count == 0 {
        DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(produced))
    } else {
        DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(produced))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_found_event() {
        let line = r#"data: {"type": "found", "username": "torvalds", "site": "SoundCloud", "url": "https://soundcloud.com/torvalds", "ids": {}}"#;
        let json = parse_sse_event(line).expect("parses");
        let hit: FoundEvent = serde_json::from_value(json).expect("shape matches");
        assert_eq!(hit.site, "SoundCloud");
        assert_eq!(hit.url, "https://soundcloud.com/torvalds");
    }

    #[test]
    fn ignores_a_progress_event_shape_mismatch() {
        let line = r#"data: {"type": "progress", "checked": 3, "total": 509, "site": "X"}"#;
        let json = parse_sse_event(line).expect("still valid JSON");
        assert!(
            serde_json::from_value::<FoundEvent>(json).is_err(),
            "a progress event has no url field"
        );
    }

    #[test]
    fn a_blank_keepalive_line_is_skipped_not_an_error() {
        assert!(parse_sse_event("").is_none());
        assert!(parse_sse_event("data:").is_none());
    }

    #[test]
    fn yield_marks_truncation_with_a_synthetic_row_and_keeps_every_hit() {
        let hits = vec![
            FoundEvent {
                site: "GitHub".to_string(),
                url: "https://github.com/x".to_string(),
                ids: Default::default(),
            },
            FoundEvent {
                site: "GitLab".to_string(),
                url: "https://gitlab.com/x".to_string(),
                ids: Default::default(),
            },
        ];
        let full = maigret_to_yield(&hits, false);
        assert_eq!(full.rows.len(), 2);

        let partial = maigret_to_yield(&hits, true);
        assert_eq!(
            partial.rows.len(),
            3,
            "a truncation note is appended, not silently dropped"
        );
        assert!(partial.rows.last().unwrap().label.contains("Maigret sweep"));
    }

    #[test]
    fn yield_never_touches_the_hits_payload_field() {
        // The whole point of the module doc's field-collision section: this tool must never
        // write `payload_patch`, which is where `UsernamePayload.hits` lives, or it would
        // shallow-overwrite WhatsMyName's own sweep.
        let hits = vec![FoundEvent {
            site: "X".to_string(),
            url: "https://x.example/u".to_string(),
            ids: Default::default(),
        }];
        let produced = maigret_to_yield(&hits, false);
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }

    #[test]
    fn parses_ids_off_a_found_event() {
        let line = r#"data: {"type": "found", "username": "torvalds", "site": "Instagram", "url": "https://instagram.com/torvalds", "ids": {"username": "torvalds", "fullname": "Linus Torvalds"}}"#;
        let json = parse_sse_event(line).expect("parses");
        let hit: FoundEvent = serde_json::from_value(json).expect("shape matches");
        assert_eq!(
            hit.ids.get("fullname").and_then(|v| v.as_str()),
            Some("Linus Torvalds")
        );
    }

    #[test]
    fn yield_adds_a_row_per_extracted_id() {
        let mut ids = serde_json::Map::new();
        ids.insert("fullname".to_string(), serde_json::json!("Linus Torvalds"));
        let hits = vec![FoundEvent {
            site: "Instagram".to_string(),
            url: "https://instagram.com/torvalds".to_string(),
            ids,
        }];
        let produced = maigret_to_yield(&hits, false);
        assert_eq!(
            produced.rows.len(),
            2,
            "one existence row plus one per extracted id"
        );
        assert_eq!(produced.rows[1].label, "Instagram · fullname");
        assert_eq!(produced.rows[1].value, "Linus Torvalds");
    }

    #[test]
    fn a_hit_with_no_ids_produces_only_the_existence_row() {
        let hits = vec![FoundEvent {
            site: "SoundCloud".to_string(),
            url: "https://soundcloud.com/x".to_string(),
            ids: Default::default(),
        }];
        let produced = maigret_to_yield(&hits, false);
        assert_eq!(produced.rows.len(), 1);
    }

    #[tokio::test]
    async fn a_sidecar_that_is_not_running_reports_an_honest_connection_failure() {
        unsafe { std::env::set_var("MAIGRET_SIDECAR_URL", "http://127.0.0.1:1") };
        let outcome = run_maigret("someone", &crate::sources::ToolCtx::default()).await;
        unsafe { std::env::remove_var("MAIGRET_SIDECAR_URL") };
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::HttpError { status: 0, .. }, None) => {}
            other => panic!("expected a status-0 HttpError with no yield, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod live_smoke {
    use super::*;

    #[tokio::test]
    #[ignore = "needs the real maigret sidecar running (docker compose up -d)"]
    async fn live_maigret_sweep_against_torvalds() {
        let ctx = crate::sources::ToolCtx::default();
        let outcome = run_maigret("torvalds", &ctx).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(y)) => {
                println!(
                    "LIVE MAIGRET: {count} rows, first 3: {:?}",
                    &y.rows[..y.rows.len().min(3)]
                );
                assert!(count > 0);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
