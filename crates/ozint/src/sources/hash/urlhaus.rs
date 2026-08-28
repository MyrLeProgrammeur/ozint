//! `hash-urlhaus` — abuse.ch URLhaus's payload lookup by hash. Owns `distributionUrls` on
//! [`crate::types::HashPayload`] — a pivot to hosting infrastructure no other tier-1 hash tool
//! in this category provides.
//!
//! `POST https://urlhaus-api.abuse.ch/v1/payload/`, form-encoded `sha256_hash={hash}` (or
//! `md5_hash={hash}` for an MD5-only lookup), header `Auth-Key` — the same abuse.ch account
//! `hash-malwarebazaar` already uses. Verified live 2026-08-25 against a sample pulled off
//! URLhaus's own `payloads/recent/` feed: **HTTP 200**, body-level `query_status: "ok"` with
//! `file_type`, `signature`, `firstseen`/`lastseen`, `imphash`, `ssdeep`/`tlsh`, and **`urls[]`**
//! — the distribution URLs the file was served from, each carrying `url`,
//! `urlhaus_reference` and `url_status`. A hash URLhaus has never indexed answers
//! `query_status: "no_results"`, same envelope-with-a-status-field shape
//! `hash-malwarebazaar`'s `hash_not_found` uses.
//!
//! ## Correcting a stale claim
//!
//! An earlier note in this category described URLhaus as URL-only. That was wrong, and stayed
//! wrong until checked directly: the `payload/` endpoint above looks a file up by its own
//! hash and was live-verified here 2026-08-25. See `sources::hash`'s module doc, updated to
//! match.
//!
//! ## Field ownership
//!
//! Owns `distributionUrls` alone — deliberately not `fileType`/`firstSeen`, even though the
//! response carries both: `hash-malwarebazaar` already owns those two, and abuse.ch's own two
//! services routinely disagree on file-type sniffing (a `signature`/`file_type` mismatch is not
//! rare across their corpora), so writing a second, unattributed copy next to MalwareBazaar's
//! would risk a silent last-writer-wins collision for no new information.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const URLHAUS_API_URL: &str = "https://urlhaus-api.abuse.ch/v1/payload/";
const ENV_VAR: &str = "ABUSECH_API_KEY";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct UrlhausRecord {
    pub file_type: Option<String>,
    pub signature: Option<String>,
    pub firstseen: Option<DateTime<Utc>>,
    pub urls: Vec<String>,
}

fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// URLhaus's `firstseen`/`lastseen` are `"2026-08-25 21:40:47"`, the same space-separated,
/// no-timezone, documented-UTC shape `hash-malwarebazaar`'s own instants use.
fn parse_urlhaus_instant(raw: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S")
        .ok()
        .and_then(|naive| Utc.from_local_datetime(&naive).single())
}

/// Parses one `POST /v1/payload/` response. `Ok(None)` is URLhaus's genuine "never indexed
/// this hash" (`query_status: "no_results"`), same convention as
/// `hash::malwarebazaar::parse_mb_response`'s `hash_not_found`.
pub fn parse_urlhaus_response(json: &serde_json::Value) -> Result<Option<UrlhausRecord>, String> {
    let status = json
        .get("query_status")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "URLhaus response has no `query_status`".to_string())?;

    if status == "no_results" {
        return Ok(None);
    }
    if status != "ok" {
        return Err(format!(
            "URLhaus returned an unrecognized query_status: {status}"
        ));
    }

    let urls = json
        .get("urls")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|u| u.get("url").and_then(|v| v.as_str()))
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(Some(UrlhausRecord {
        file_type: nonempty(json.get("file_type").and_then(|v| v.as_str())),
        signature: nonempty(json.get("signature").and_then(|v| v.as_str())),
        firstseen: json
            .get("firstseen")
            .and_then(|v| v.as_str())
            .and_then(parse_urlhaus_instant),
        urls,
    }))
}

/// Owns `distributionUrls` alone — see the module doc for why `fileType`/`firstSeen` are
/// deliberately left to `hash-malwarebazaar` despite being present in this same response.
pub fn urlhaus_record_to_yield(record: &UrlhausRecord) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if !record.urls.is_empty() {
        patch.insert("distribution_urls".into(), serde_json::json!(record.urls));
    }

    let mut rows = Vec::new();
    if let Some(signature) = &record.signature {
        rows.push(OzRow {
            label: "URLhaus signature".to_string(),
            value: signature.clone(),
            ..Default::default()
        });
    }
    for url in &record.urls {
        rows.push(OzRow {
            label: "Distribution URL".to_string(),
            value: url.clone(),
            href: Some(url.clone()),
            ..Default::default()
        });
    }

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows,
        ..Default::default()
    }
}

pub async fn run_urlhaus(hash: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    // sha256 is 64 hex chars; anything shorter is treated as an md5 lookup, the other shape
    // this endpoint accepts.
    let field = if hash.len() == 64 {
        "sha256_hash"
    } else {
        "md5_hash"
    };
    let opts = fetch::OzFetchOptions {
        method: reqwest::Method::POST,
        headers: vec![
            ("Auth-Key".to_string(), key),
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
        ],
        body: Some(format!("{field}={}", urlencoding::encode(hash)).into_bytes()),
        ..Default::default()
    };
    let outcome = ctx.fetch("hash-urlhaus", hash, URLHAUS_API_URL, opts).await;

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
                message: "URLhaus response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_urlhaus_response(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(None) => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(Some(record)) if record.urls.is_empty() => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(Some(record)) => {
            let count = record.urls.len() as u32;
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count },
                Some(urlhaus_record_to_yield(&record)),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transcribed from a live 2026-08-25 `get_info`-equivalent `payload/` call.
    fn real_entry() -> serde_json::Value {
        serde_json::json!({
            "query_status": "ok",
            "md5_hash": "434e6046b2d080d7975cbeac60ce32c1",
            "sha256_hash": "ac923f614cfe623c673dd794baa15524a7ba7626a11404ca68008bc4b3dd5cf2",
            "file_type": "html",
            "signature": null,
            "firstseen": "2026-08-25 21:40:47",
            "urls": [
                {
                    "url_id": "1773603",
                    "url": "http://muledo.com/donkey.php",
                    "url_status": "online",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/1773603/"
                }
            ]
        })
    }

    #[test]
    fn parses_a_real_indexed_sample() {
        let record = parse_urlhaus_response(&real_entry())
            .expect("parses")
            .expect("found");
        assert_eq!(record.file_type.as_deref(), Some("html"));
        assert_eq!(
            record.signature, None,
            "an explicit JSON null must not become Some(\"\")"
        );
        assert_eq!(
            record.urls,
            vec!["http://muledo.com/donkey.php".to_string()]
        );
        assert!(record.firstseen.is_some());
    }

    #[test]
    fn no_results_reads_as_none_not_an_error() {
        let json = serde_json::json!({ "query_status": "no_results" });
        assert_eq!(parse_urlhaus_response(&json), Ok(None));
    }

    #[test]
    fn an_unrecognized_status_is_an_error() {
        let json = serde_json::json!({ "query_status": "illegal_hash" });
        assert!(parse_urlhaus_response(&json).is_err());
    }

    #[test]
    fn yield_owns_only_distribution_urls() {
        let record = parse_urlhaus_response(&real_entry())
            .expect("parses")
            .expect("found");
        let produced = urlhaus_record_to_yield(&record);
        let patch = produced.payload_patch.as_object().unwrap();
        assert_eq!(patch.len(), 1);
        assert!(patch.contains_key("distribution_urls"));
        assert!(
            !patch.contains_key("file_type"),
            "hash-malwarebazaar owns fileType"
        );
    }

    #[test]
    fn missing_query_status_is_a_parse_error() {
        assert!(parse_urlhaus_response(&serde_json::json!({})).is_err());
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_urlhaus(&"a".repeat(64), &crate::sources::ToolCtx::default()).await;
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
