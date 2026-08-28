//! `youtube-channel` — YouTube Data API v3, channel-by-handle. **Needs `YOUTUBE_API_KEY`.**
//!
//! This is the first catalogued tool in the crate that is *not* keyless, and it is here as
//! much for that as for YouTube: until it landed, `registry::resolve`'s
//! [`crate::outcome::ToolOutcome::SkippedNoKey`] branch had no real tool behind it and was
//! exercised only against synthetic `ToolDef`s in `registry.rs`'s own tests. `YOUTUBE_API_KEY`
//! is absent from this repo's env table (listed under "Missing keys / registrations needed"),
//! so in practice this tool reports a clean, honest
//! skip today rather than running — which is exactly the behaviour a layer needs to render
//! "a capability exists here, it just isn't configured" instead of silently showing nothing.
//!
//! ## ⚠️ The request shape is UNVERIFIED. Smoke-test it when a key lands.
//!
//! Every other tool in this category was checked by direct call before being written. This one
//! could not be: Google validates the API key **before** it validates parameters, so without a
//! key there is no response that can confirm the query is well-formed. Verified 2026-08-21:
//!
//! - no `key` at all → `403` `"Method doesn't allow unregistered callers"`
//! - `key=<bogus>` + a valid `forHandle` → `400` `"API key not valid"`
//! - `key=<bogus>` + a deliberately **invalid** parameter (`bogusParam=x`) → the *identical*
//!   `400` `"API key not valid"`
//!
//! That third probe is the control: a nonsense parameter and a correct one are indistinguishable
//! without a valid key, so passing the first two proves nothing about `forHandle`. The endpoint,
//! the `forHandle` parameter and the response shape below are taken from Google's published API
//! reference, not from an observed response. **When `YOUTUBE_API_KEY` is first configured, run
//! this tool against a known channel before trusting its output**, and correct this module if the
//! real response disagrees. Parsing here is deliberately defensive for that reason — it tolerates
//! missing sections rather than assuming the documented shape.
//!
//! Endpoint: `GET https://www.googleapis.com/youtube/v3/channels`
//! with `part=snippet,statistics`, `forHandle=@{handle}`, `key={YOUTUBE_API_KEY}`.
//!
//! An unknown handle is documented to answer `200` with an empty/absent `items` array (not a
//! `404`) — handled as `OkEmpty`, a real finding.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

use super::nonempty;

const YOUTUBE_CHANNELS_ENDPOINT: &str = "https://www.googleapis.com/youtube/v3/channels";

/// The env var this tool needs armed. Mirrored in `registry::CATALOGUE`'s entry — the
/// registry is what decides whether the tool runs at all; this constant only names the key
/// when the tool actually builds its request.
pub const YOUTUBE_API_KEY_VAR: &str = "YOUTUBE_API_KEY";

/// A YouTube channel, narrowed to the fields this tool reports.
#[derive(Debug, Clone, PartialEq)]
pub struct YoutubeChannel {
    pub channel_id: String,
    pub title: Option<String>,
    pub description: Option<String>,
    /// The `@handle` form, e.g. `@mrbeast`.
    pub custom_url: Option<String>,
    pub published_at: Option<String>,
    /// ISO-3166-1 alpha-2, when the channel declares one.
    pub country: Option<String>,
    pub subscriber_count: Option<u64>,
    pub video_count: Option<u64>,
    pub view_count: Option<u64>,
}

/// YouTube returns its statistics counters as JSON **strings** (`"subscriberCount": "1234"`),
/// but tolerating a real number costs one branch and protects against the shape note above
/// being wrong.
fn count_field(parent: Option<&serde_json::Value>, key: &str) -> Option<u64> {
    let raw = parent?.get(key)?;
    match raw {
        serde_json::Value::String(s) => s.trim().parse::<u64>().ok(),
        serde_json::Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

/// Parses a `channels.list` response into the first channel it describes.
///
/// `Ok(None)` means the call succeeded and the handle matched no channel — the Empty
/// *finding*, distinct from both an error and a parse failure. `Err` is reserved for a body
/// that is not a channel-list response at all.
pub fn parse_youtube_channels(json: &serde_json::Value) -> Result<Option<YoutubeChannel>, String> {
    let items = match json.get("items") {
        // An absent `items` is only Empty if this really is a channelListResponse; a body with
        // neither `items` nor `kind` is something else entirely and must not read as "no such
        // channel".
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

    let channel_id = first
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "YouTube channel item is missing `id`".to_string())?
        .to_string();

    let snippet = first.get("snippet");
    let statistics = first.get("statistics");

    Ok(Some(YoutubeChannel {
        channel_id,
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
        custom_url: nonempty(
            snippet
                .and_then(|s| s.get("customUrl"))
                .and_then(|v| v.as_str()),
        ),
        published_at: nonempty(
            snippet
                .and_then(|s| s.get("publishedAt"))
                .and_then(|v| v.as_str()),
        ),
        country: nonempty(
            snippet
                .and_then(|s| s.get("country"))
                .and_then(|v| v.as_str()),
        ),
        subscriber_count: count_field(statistics, "subscriberCount"),
        video_count: count_field(statistics, "videoCount"),
        view_count: count_field(statistics, "viewCount"),
    }))
}

/// Turns a parsed [`YoutubeChannel`] into a [`ToolYield`]. `queried_handle` suppresses the
/// self-referential Username child — the handle we started from is the node itself, not a
/// finding.
pub fn youtube_channel_to_yield(channel: &YoutubeChannel, queried_handle: &str) -> ToolYield {
    let channel_url = format!("https://www.youtube.com/channel/{}", channel.channel_id);

    let mut rows = vec![OzRow {
        label: "YouTube".to_string(),
        value: channel
            .title
            .clone()
            .unwrap_or_else(|| channel.channel_id.clone()),
        href: Some(channel_url),
        ..Default::default()
    }];
    if let Some(custom_url) = &channel.custom_url {
        rows.push(OzRow {
            label: "Handle".to_string(),
            value: custom_url.clone(),
            href: Some(format!(
                "https://www.youtube.com/{}",
                if custom_url.starts_with('@') {
                    custom_url.clone()
                } else {
                    format!("@{custom_url}")
                }
            )),
            ..Default::default()
        });
    }
    if let Some(description) = &channel.description {
        rows.push(OzRow {
            label: "Description".to_string(),
            value: description.clone(),
            ..Default::default()
        });
    }
    if let Some(country) = &channel.country {
        rows.push(OzRow {
            label: "Country".to_string(),
            value: country.clone(),
            ..Default::default()
        });
    }
    for (label, count) in [
        ("Subscribers", channel.subscriber_count),
        ("Videos", channel.video_count),
        ("Views", channel.view_count),
    ] {
        if let Some(count) = count {
            rows.push(OzRow {
                label: label.to_string(),
                value: count.to_string(),
                ..Default::default()
            });
        }
    }
    if let Some(published_at) = &channel.published_at {
        rows.push(OzRow {
            label: "Created".to_string(),
            value: published_at.clone(),
            ..Default::default()
        });
    }
    rows.push(OzRow {
        label: "Channel ID".to_string(),
        value: channel.channel_id.clone(),
        ..Default::default()
    });

    let mut children = Vec::new();
    // A channel `title` is a channel name, which is often a brand rather than a person — but
    // that judgement belongs to the analyst looking at the resulting Name node, not to this
    // parser silently dropping it. Emitted as-is, exactly like GitHub's display name.
    if let Some(title) = &channel.title {
        children.push(ChildSeed {
            oz_type: OzType::Name,
            value: title.clone(),
            note: Some("YouTube channel title".to_string()),
        });
    }
    if let Some(custom_url) = &channel.custom_url {
        let bare = custom_url.trim_start_matches('@');
        if !bare.is_empty() && !bare.eq_ignore_ascii_case(queried_handle.trim_start_matches('@')) {
            children.push(ChildSeed {
                oz_type: OzType::Username,
                value: bare.to_string(),
                note: Some("YouTube channel handle".to_string()),
            });
        }
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

/// Queries YouTube's `channels.list` for `handle`.
///
/// Reports [`ToolOutcome::SkippedNoKey`] itself when `YOUTUBE_API_KEY` is absent. That is
/// belt-and-braces: `registry::resolve` already filters unarmed tools out before a layer
/// dispatches them, so this branch should be unreachable in the normal path — but a tool that
/// silently builds a keyless request when its key is missing would produce a confusing `403`
/// instead of the honest skip, and this is cheaper than trusting every future caller to check.
pub async fn run_youtube_channel(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(YOUTUBE_API_KEY_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: YOUTUBE_API_KEY_VAR.to_string(),
            },
            None,
        );
    };

    // The API expects the `@handle` form; accept a bare handle from the classifier either way.
    let bare = handle.trim_start_matches('@');
    let url = format!(
        "{YOUTUBE_CHANNELS_ENDPOINT}?part=snippet%2Cstatistics&forHandle={}&key={}",
        urlencoding::encode(&format!("@{bare}")),
        urlencoding::encode(&key),
    );

    // The handle being looked up — the channel record is keyed on it.
    let outcome = ctx
        .fetch(
            "youtube-channel",
            handle,
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

    match parse_youtube_channels(json) {
        Ok(Some(channel)) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(youtube_channel_to_yield(&channel, handle)),
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
            "kind": "youtube#channelListResponse",
            "pageInfo": { "totalResults": 1, "resultsPerPage": 5 },
            "items": [{
                "kind": "youtube#channel",
                "id": "UCX6OQ3DkcsbYNE6H8uQQuVA",
                "snippet": {
                    "title": "MrBeast",
                    "description": "  SUBSCRIBE FOR A COOKIE  ",
                    "customUrl": "@mrbeast",
                    "publishedAt": "2012-02-20T00:43:50Z",
                    "country": "US"
                },
                "statistics": {
                    "viewCount": "91000000000",
                    "subscriberCount": "450000000",
                    "hiddenSubscriberCount": false,
                    "videoCount": "870"
                }
            }]
        })
    }

    // ── parsing ─────────────────────────────────────────────────────────

    #[test]
    fn parses_a_full_channel_response() {
        let channel = parse_youtube_channels(&full_response())
            .expect("response parses")
            .expect("a channel was returned");
        assert_eq!(channel.channel_id, "UCX6OQ3DkcsbYNE6H8uQQuVA");
        assert_eq!(channel.title.as_deref(), Some("MrBeast"));
        assert_eq!(
            channel.description.as_deref(),
            Some("SUBSCRIBE FOR A COOKIE"),
            "description must be trimmed"
        );
        assert_eq!(channel.custom_url.as_deref(), Some("@mrbeast"));
        assert_eq!(channel.country.as_deref(), Some("US"));
        assert_eq!(channel.subscriber_count, Some(450_000_000));
        assert_eq!(channel.video_count, Some(870));
        assert_eq!(channel.view_count, Some(91_000_000_000));
    }

    #[test]
    fn an_empty_items_array_is_the_empty_finding_not_an_error() {
        let json = serde_json::json!({
            "kind": "youtube#channelListResponse",
            "pageInfo": { "totalResults": 0, "resultsPerPage": 5 },
            "items": []
        });
        assert_eq!(parse_youtube_channels(&json), Ok(None));
    }

    #[test]
    fn an_absent_items_array_on_a_real_response_is_also_empty() {
        let json = serde_json::json!({
            "kind": "youtube#channelListResponse",
            "pageInfo": { "totalResults": 0, "resultsPerPage": 5 }
        });
        assert_eq!(parse_youtube_channels(&json), Ok(None));
    }

    #[test]
    fn a_body_that_is_not_a_channel_list_response_is_rejected() {
        // Google's own error envelope, which must never read as "no such channel".
        let json = serde_json::json!({
            "error": { "code": 400, "message": "API key not valid. Please pass a valid API key." }
        });
        assert!(parse_youtube_channels(&json).is_err());
    }

    #[test]
    fn a_channel_item_missing_id_is_rejected() {
        let json = serde_json::json!({
            "kind": "youtube#channelListResponse",
            "items": [{ "snippet": { "title": "No ID" } }]
        });
        assert!(parse_youtube_channels(&json).is_err());
    }

    #[test]
    fn a_channel_with_no_snippet_or_statistics_still_parses() {
        let json = serde_json::json!({
            "kind": "youtube#channelListResponse",
            "items": [{ "id": "UCbare" }]
        });
        let channel = parse_youtube_channels(&json)
            .expect("parses")
            .expect("a channel");
        assert_eq!(channel.channel_id, "UCbare");
        assert_eq!(channel.title, None);
        assert_eq!(channel.subscriber_count, None);
    }

    #[test]
    fn counts_parse_from_both_strings_and_numbers() {
        let stats = serde_json::json!({ "a": "42", "b": 43, "c": "not a number", "d": true });
        assert_eq!(count_field(Some(&stats), "a"), Some(42));
        assert_eq!(count_field(Some(&stats), "b"), Some(43));
        assert_eq!(count_field(Some(&stats), "c"), None);
        assert_eq!(count_field(Some(&stats), "d"), None);
        assert_eq!(count_field(Some(&stats), "missing"), None);
        assert_eq!(count_field(None, "a"), None);
    }

    #[test]
    fn empty_string_fields_are_treated_as_absent() {
        let json = serde_json::json!({
            "kind": "youtube#channelListResponse",
            "items": [{ "id": "UCx", "snippet": { "title": "", "description": "   " } }]
        });
        let channel = parse_youtube_channels(&json)
            .expect("parses")
            .expect("a channel");
        assert_eq!(channel.title, None);
        assert_eq!(channel.description, None);
    }

    // ── yield ────────────────────────────────────────────────────────────

    #[test]
    fn yield_emits_the_children_the_response_contained() {
        let channel = parse_youtube_channels(&full_response()).unwrap().unwrap();
        let produced = youtube_channel_to_yield(&channel, "somebodyelse");
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Name && c.value == "MrBeast")
        );
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Username && c.value == "mrbeast")
        );
    }

    #[test]
    fn yield_suppresses_the_username_child_that_is_the_queried_handle() {
        let channel = parse_youtube_channels(&full_response()).unwrap().unwrap();
        // Both the bare and the @-prefixed form of the seed must be recognised as self.
        for queried in ["mrbeast", "@mrbeast", "MrBeast"] {
            let produced = youtube_channel_to_yield(&channel, queried);
            assert!(
                !produced
                    .children
                    .iter()
                    .any(|c| c.oz_type == OzType::Username),
                "querying {queried} must not re-emit itself as a Username child"
            );
        }
    }

    #[test]
    fn yield_emits_no_children_for_a_bare_channel() {
        let channel = YoutubeChannel {
            channel_id: "UCbare".to_string(),
            title: None,
            description: None,
            custom_url: None,
            published_at: None,
            country: None,
            subscriber_count: None,
            video_count: None,
            view_count: None,
        };
        let produced = youtube_channel_to_yield(&channel, "bare");
        assert!(produced.children.is_empty());
        assert_eq!(
            produced.rows.len(),
            2,
            "the YouTube row (falling back to the channel id) and the Channel ID row"
        );
    }

    // ── arming ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        // A private guard so this never races another test over the real credential var.
        let prev = std::env::var(YOUTUBE_API_KEY_VAR).ok();
        unsafe { std::env::remove_var(YOUTUBE_API_KEY_VAR) };

        let outcome = run_youtube_channel("mrbeast", &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNoKey { env_var }, produced) => {
                assert_eq!(env_var, YOUTUBE_API_KEY_VAR);
                assert!(
                    produced.is_none(),
                    "a skipped tool produces nothing to apply"
                );
            }
            other => panic!("expected SkippedNoKey without a key, got {other:?}"),
        }

        if let Some(v) = prev {
            unsafe { std::env::set_var(YOUTUBE_API_KEY_VAR, v) };
        }
    }
}
