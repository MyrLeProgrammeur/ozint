//! `img-saucenao` — SauceNAO reverse-image search. Owns `reverseMatches` on
//! [`crate::types::ImagePayload`], the field the type already reserved for a gated tool to
//! fill.
//!
//! `GET https://saucenao.com/search.php?api_key={key}&output_type=2&numres={n}`, **file bytes
//! attached as `multipart/form-data`** (field name `file`) rather than SauceNAO's alternate
//! `url=` mode — this crate's stored images are content-addressed bytes with no public URL
//! SauceNAO could fetch, the same reason `entity-image`'s value is a `media_id` and not a
//! link. Verified live 2026-08-25 by a real multipart `POST` of this repo's own EXIF test
//! fixture: **HTTP 200**, `header.status: 0`, `header.short_remaining`/`long_remaining` (the
//! 4-per-30s / 100-per-day free-tier quota), `results[]` each carrying `header.similarity`
//! (a percentage string), `header.thumbnail`, `header.index_id`/`index_name`, and a
//! site-specific `data` object (`ext_urls[]` on many indexes, but not all — the same live call
//! returned a result with no `ext_urls` at all, only a `getchu_id`, so [`extract_source_url`]
//! must not assume the field exists).
//!
//! ## SauceNAO is weak on general photography, and this tool says so out loud
//!
//! Confirmed by the same live call: a synthetic real-world test photo (not anime/art) returned
//! a **99.09% similarity** match against an unrelated visual-novel CG asset — a confident-
//! looking number with no actual relationship to the query image. SauceNAO's index is
//! anime/art/Pixiv/deviantArt-oriented, and a generic photo landing near a high-similarity
//! index entry is exactly the false-positive shape that measurement demonstrates, not an edge
//! case. So [`saucenao_to_yield`] applies [`SIMILARITY_FLOOR`] (85%, SauceNAO's own published
//! convention for "meaningful") before emitting anything, and every row it does emit states the
//! similarity number next to the match — never presented as a bare confirmed link.

use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;
use crate::{fetch, media};

const SAUCENAO_BASE: &str = "https://saucenao.com/search.php";
const ENV_VAR: &str = "SAUCENAO_API_KEY";

/// SauceNAO's own published convention: below this, a "match" is noise. See the module doc's
/// measured false-positive example.
const SIMILARITY_FLOOR: f64 = 85.0;

const MAX_RESULTS: u32 = 5;

#[derive(Debug, Clone, PartialEq)]
pub struct SauceMatch {
    pub similarity: f64,
    pub index_name: Option<String>,
    pub title: Option<String>,
    pub source_url: Option<String>,
}

fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The first usable link out of a result's `data` object: `ext_urls[0]` when present (most
/// booru/art indexes), else the record's own `getchu_id`/`title` gives nothing clickable, so
/// `None` — never a guessed URL.
fn extract_source_url(data: &serde_json::Value) -> Option<String> {
    data.get("ext_urls")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .and_then(|s| nonempty(Some(s)))
}

fn extract_title(data: &serde_json::Value) -> Option<String> {
    for key in ["title", "material", "source"] {
        if let Some(v) = data.get(key).and_then(|v| v.as_str())
            && let Some(v) = nonempty(Some(v))
        {
            return Some(v);
        }
    }
    None
}

/// Parses one SauceNAO `output_type=2` response. `Err` only when `header.status` itself is
/// missing — a non-zero status is SauceNAO's own error signal (bad key, quota exhausted) and
/// is folded into the same error rather than a silent empty result.
pub fn parse_saucenao(json: &serde_json::Value) -> Result<Vec<SauceMatch>, String> {
    let status = json
        .get("header")
        .and_then(|h| h.get("status"))
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "SauceNAO response has no `header.status`".to_string())?;
    if status != 0 {
        return Err(format!("SauceNAO returned a non-zero status: {status}"));
    }

    let results = json
        .get("results")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut matches = Vec::new();
    for result in &results {
        let header = result.get("header");
        let similarity = header
            .and_then(|h| h.get("similarity"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<f64>().ok());
        let Some(similarity) = similarity else {
            continue;
        };
        let data = result.get("data").cloned().unwrap_or(serde_json::json!({}));
        matches.push(SauceMatch {
            similarity,
            index_name: header
                .and_then(|h| h.get("index_name"))
                .and_then(|v| v.as_str())
                .and_then(|s| nonempty(Some(s))),
            title: extract_title(&data),
            source_url: extract_source_url(&data),
        });
    }
    Ok(matches)
}

/// Turns matches at or above [`SIMILARITY_FLOOR`] into rows. Below-floor matches are dropped
/// entirely, not shown dimmed — see the module doc's measured false-positive.
pub fn saucenao_to_yield(matches: &[SauceMatch]) -> ToolYield {
    let rows: Vec<OzRow> = matches
        .iter()
        .filter(|m| m.similarity >= SIMILARITY_FLOOR)
        .map(|m| {
            let label = m
                .index_name
                .clone()
                .unwrap_or_else(|| "SauceNAO match".to_string());
            let value = match &m.title {
                Some(title) => format!("{title} ({:.1}% similarity)", m.similarity),
                None => format!("{:.1}% similarity", m.similarity),
            };
            // `gated` mirrors the registry's *ethical*-gate concept (face-match, credential
            // dumps) — `img-saucenao` is not one of those, it is an ordinary `FreeKey` tool
            // whose low-confidence risk is conveyed by stating the similarity number itself,
            // not by the gated flag. Left `false`.
            OzRow {
                label,
                value,
                href: m.source_url.clone(),
                ..Default::default()
            }
        })
        .collect();

    ToolYield {
        payload_patch: if rows.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::json!({ "reverseMatches": rows })
        },
        ..Default::default()
    }
}

/// Builds a `multipart/form-data` body with one `file` field — SauceNAO's alternate upload
/// mode, verified live 2026-08-25 against this repo's own stored bytes rather than assumed
/// from the `url=` mode's shape. Returns `(content_type, body)`.
fn build_multipart(filename: &str, mime: &str, bytes: &[u8]) -> (String, Vec<u8>) {
    let boundary = format!("ozint-{}", uuid::Uuid::new_v4());
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {mime}\r\n\r\n").as_bytes());
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

pub async fn run_saucenao(value: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let loaded = match media::load(value) {
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
                message: format!("`{value}` names no object in the media store"),
            },
            None,
        );
    };
    if !meta.is_image() {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("`{}` is not a decodable image type", meta.mime),
            },
            None,
        );
    }

    let (content_type, body) = build_multipart(&meta.media_id, &meta.mime, &bytes);
    let url = format!("{SAUCENAO_BASE}?api_key={key}&output_type=2&numres={MAX_RESULTS}");
    let opts = fetch::OzFetchOptions {
        method: reqwest::Method::POST,
        headers: vec![("Content-Type".to_string(), content_type)],
        body: Some(body),
        ..Default::default()
    };
    let outcome = ctx.fetch("img-saucenao", value, &url, opts).await;

    if matches!(outcome, fetch::OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let fetch::OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled OzOutcome was handled above");
    };
    let fetch::OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "SauceNAO response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_saucenao(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(matches) => {
            let kept = matches
                .iter()
                .filter(|m| m.similarity >= SIMILARITY_FLOOR)
                .count() as u32;
            let outcome = if kept == 0 {
                ToolOutcome::OkEmpty
            } else {
                ToolOutcome::OkWithResults { count: kept }
            };
            DispatchOutcome::Ran(outcome, Some(saucenao_to_yield(&matches)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real, measured false-positive from the module doc's live 2026-08-25 call: a
    /// generic photo scored 99.09% against an unrelated visual-novel CG, with no `ext_urls`.
    fn measured_noisy_match() -> serde_json::Value {
        serde_json::json!({
            "header": { "status": 0 },
            "results": [{
                "header": {
                    "similarity": "99.09",
                    "index_id": 2,
                    "index_name": "Index #2: H-Game CG - diss00.jpg"
                },
                "data": { "title": "Wiz Anniversary Complete", "company": "Crossnet", "getchu_id": "664010" }
            }]
        })
    }

    #[test]
    fn parses_the_measured_response_shape() {
        let matches = parse_saucenao(&measured_noisy_match()).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].similarity, 99.09);
        assert_eq!(
            matches[0].title.as_deref(),
            Some("Wiz Anniversary Complete")
        );
        assert_eq!(
            matches[0].source_url, None,
            "this measured result has no ext_urls at all"
        );
    }

    #[test]
    fn a_below_floor_match_is_dropped_entirely_not_shown_dimmed() {
        let matches = vec![SauceMatch {
            similarity: 60.0,
            index_name: None,
            title: Some("noise".to_string()),
            source_url: None,
        }];
        let produced = saucenao_to_yield(&matches);
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }

    #[test]
    fn an_above_floor_match_becomes_a_gated_row_with_the_similarity_stated() {
        let matches = vec![SauceMatch {
            similarity: 92.5,
            index_name: Some("Danbooru".to_string()),
            title: Some("some artwork".to_string()),
            source_url: Some("https://danbooru.donmai.us/posts/1".to_string()),
        }];
        let produced = saucenao_to_yield(&matches);
        let rows = produced.payload_patch["reverseMatches"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert!(row["value"].as_str().unwrap().contains("92.5%"));
    }

    #[test]
    fn the_measured_false_positive_is_kept_since_it_crosses_the_floor_but_states_the_number() {
        // The module doc's whole point: this tool does not silently drop a high-confidence
        // number just because it is measured to sometimes be wrong — it states the number so
        // the analyst can judge it, which is what the floor and the stated percentage are for.
        let matches = parse_saucenao(&measured_noisy_match()).unwrap();
        let produced = saucenao_to_yield(&matches);
        let rows = produced.payload_patch["reverseMatches"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0]["value"].as_str().unwrap().contains("99.1%")
                || rows[0]["value"].as_str().unwrap().contains("99.09%")
        );
    }

    #[test]
    fn a_nonzero_status_is_an_error() {
        let json = serde_json::json!({ "header": { "status": -1 } });
        assert!(parse_saucenao(&json).is_err());
    }

    #[test]
    fn missing_status_is_an_error() {
        assert!(parse_saucenao(&serde_json::json!({})).is_err());
    }

    #[test]
    fn multipart_body_carries_the_field_name_saucenao_expects() {
        let (content_type, body) = build_multipart("abc.jpg", "image/jpeg", b"fake-bytes");
        assert!(content_type.starts_with("multipart/form-data; boundary="));
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("name=\"file\""));
        assert!(text.contains("fake-bytes"));
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_saucenao(&"0".repeat(64), &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNoKey { env_var }, produced) => {
                assert_eq!(env_var, ENV_VAR);
                assert!(produced.is_none());
            }
            other => panic!("expected SkippedNoKey without a key, got {other:?}"),
        }

        if let Some(v) = prev {
            unsafe { std::env::set_var(ENV_VAR, v) };
        }
    }
}
