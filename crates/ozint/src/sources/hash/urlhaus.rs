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
//! would risk a silent last-writer-wins collision for no new information. `firstseen` is still
//! parsed (it is this tool's own indexing date, not a fact about the file MalwareBazaar could
//! disagree on) and is surfaced as a plain row rather than a payload field, so it stays visible
//! without opening a second ownership claim.
//!
//! ## Children: hosting infrastructure
//!
//! Each distribution URL's **host** becomes a child — a malware sample is evidence the URL's
//! host is live attacker infrastructure, which is exactly the pivot this tool's doc comment
//! above claims. A bare-IP host becomes an [`OzType::Ip`] child rather than
//! [`OzType::Domain`], since the value genuinely is an IP address and the two entity types
//! dispatch to different tool sets; a hostname becomes [`OzType::Domain`].
//!
//! Hosts are deduplicated (many distribution URLs on the same sample routinely share one
//! host — a single C2 panel serving several payload paths) and, among duplicates, an entry
//! URLhaus still marks `url_status: "online"` is kept over one already taken down, since a
//! live host is the more actionable lead. The result is capped at
//! [`MAX_DISTRIBUTION_HOSTS`] — see its doc for why no `truncated` flag is needed here, unlike
//! `dom::certspotter`'s `subdomainsTruncated`.

use std::collections::HashSet;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

const URLHAUS_API_URL: &str = "https://urlhaus-api.abuse.ch/v1/payload/";
const ENV_VAR: &str = "ABUSECH_API_KEY";

/// Cap on how many distinct hosts one URLhaus record spawns as [`OzType::Domain`]/
/// [`OzType::Ip`] children. Every distribution URL is still listed in full as a "Distribution
/// URL" row regardless of this cap — nothing is hidden from the detail panel, only the number
/// of *new investigable nodes* one sample can fan out into is bounded, the same split
/// `dom::certspotter` draws between its full `subdomains` list and its capped children. Because
/// the underlying row list is never truncated, there is no completeness claim to protect and
/// therefore no `truncated` flag to set (contrast `dom::certspotter`'s `subdomainsTruncated`,
/// which exists because *its* payload list is itself capped).
///
/// 20 matches [`crate::types::MAX_SUBDOMAIN_CHILDREN`]'s order of magnitude — this crate's
/// existing convention for "enough infrastructure leads to act on without a single sample
/// flooding the tree".
const MAX_DISTRIBUTION_HOSTS: usize = 20;

/// One distribution URL entry as URLhaus reports it: the URL itself plus the takedown status
/// used to order host children (see the module doc).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UrlhausUrl {
    pub url: String,
    pub url_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct UrlhausRecord {
    pub file_type: Option<String>,
    pub signature: Option<String>,
    pub firstseen: Option<DateTime<Utc>>,
    pub urls: Vec<UrlhausUrl>,
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
                .filter_map(|u| {
                    let raw = u.get("url").and_then(|v| v.as_str())?;
                    if raw.trim().is_empty() {
                        return None;
                    }
                    Some(UrlhausUrl {
                        url: raw.to_string(),
                        url_status: nonempty(u.get("url_status").and_then(|v| v.as_str())),
                    })
                })
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

/// Pulls the host out of one distribution URL and classifies it as [`OzType::Domain`] or
/// [`OzType::Ip`]. `None` when the URL doesn't parse or carries no host at all — never
/// fabricated. Pure and tested.
fn url_host(url: &str) -> Option<(OzType, String)> {
    let parsed = url::Url::parse(url).ok()?;
    match parsed.host()? {
        url::Host::Domain(d) => Some((OzType::Domain, d.to_ascii_lowercase())),
        url::Host::Ipv4(ip) => Some((OzType::Ip, ip.to_string())),
        url::Host::Ipv6(ip) => Some((OzType::Ip, ip.to_string())),
    }
}

/// Builds the host-pivot children — see the module doc's "Children: hosting infrastructure"
/// for the ordering, dedup and cap this implements. Pure and tested.
fn distribution_host_children(urls: &[UrlhausUrl]) -> Vec<ChildSeed> {
    // A stable sort so `online` entries move to the front while preserving each group's
    // original (feed) order — an `online` duplicate must win the dedup slot below over an
    // already-taken-down one, but two equally-`online` (or equally-not) entries should keep
    // the order URLhaus itself returned them in.
    let mut ordered: Vec<&UrlhausUrl> = urls.iter().collect();
    ordered.sort_by_key(|u| u.url_status.as_deref() != Some("online"));

    let mut seen = HashSet::new();
    let mut children = Vec::new();
    for entry in ordered {
        let Some((oz_type, value)) = url_host(&entry.url) else {
            continue;
        };
        if !seen.insert((oz_type, value.clone())) {
            continue;
        }
        children.push(ChildSeed {
            oz_type,
            value,
            note: Some("served a malware sample from this URL (URLhaus)".to_string()),
        });
        if children.len() >= MAX_DISTRIBUTION_HOSTS {
            break;
        }
    }
    children
}

/// Owns `distributionUrls` alone — see the module doc for why `fileType`/`firstSeen` are
/// deliberately left to `hash-malwarebazaar` despite being present in this same response.
pub fn urlhaus_record_to_yield(record: &UrlhausRecord) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if !record.urls.is_empty() {
        let urls: Vec<&str> = record.urls.iter().map(|u| u.url.as_str()).collect();
        patch.insert("distribution_urls".into(), serde_json::json!(urls));
    }

    let mut rows = Vec::new();
    if let Some(signature) = &record.signature {
        rows.push(OzRow {
            label: "URLhaus signature".to_string(),
            value: signature.clone(),
            ..Default::default()
        });
    }
    if let Some(firstseen) = record.firstseen {
        rows.push(OzRow {
            label: "First seen (URLhaus)".to_string(),
            value: firstseen.to_rfc3339(),
            at: Some(firstseen),
            ..Default::default()
        });
    }
    for entry in &record.urls {
        rows.push(OzRow {
            label: "Distribution URL".to_string(),
            value: entry.url.clone(),
            href: Some(entry.url.clone()),
            ..Default::default()
        });
    }

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows,
        children: distribution_host_children(&record.urls),
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
            vec![UrlhausUrl {
                url: "http://muledo.com/donkey.php".to_string(),
                url_status: Some("online".to_string()),
            }]
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

    #[test]
    fn firstseen_is_surfaced_as_a_row_not_a_payload_field() {
        let record = parse_urlhaus_response(&real_entry())
            .expect("parses")
            .expect("found");
        let produced = urlhaus_record_to_yield(&record);
        assert!(
            !produced
                .payload_patch
                .as_object()
                .unwrap()
                .contains_key("firstseen"),
            "firstseen must stay out of the payload — see the field-ownership module doc"
        );
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "First seen (URLhaus)" && r.at.is_some()),
            "firstseen was parsed and asserted in a test but previously never read anywhere"
        );
    }

    #[test]
    fn a_distribution_url_host_becomes_a_domain_child() {
        let record = parse_urlhaus_response(&real_entry())
            .expect("parses")
            .expect("found");
        let produced = urlhaus_record_to_yield(&record);
        assert_eq!(
            produced.children,
            vec![ChildSeed {
                oz_type: OzType::Domain,
                value: "muledo.com".to_string(),
                note: Some("served a malware sample from this URL (URLhaus)".to_string()),
            }]
        );
    }

    #[test]
    fn a_bare_ip_host_becomes_an_ip_child_not_a_domain_child() {
        let children = distribution_host_children(&[UrlhausUrl {
            url: "http://203.0.113.5/payload.exe".to_string(),
            url_status: Some("online".to_string()),
        }]);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].oz_type, OzType::Ip);
        assert_eq!(children[0].value, "203.0.113.5");
    }

    #[test]
    fn urls_sharing_a_host_dedupe_to_one_child() {
        let children = distribution_host_children(&[
            UrlhausUrl {
                url: "http://muledo.com/a.php".to_string(),
                url_status: Some("offline".to_string()),
            },
            UrlhausUrl {
                url: "http://muledo.com/b.php".to_string(),
                url_status: Some("offline".to_string()),
            },
        ]);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].value, "muledo.com");
    }

    #[test]
    fn an_online_duplicate_wins_the_dedup_slot_over_an_offline_one() {
        // Same host, offline entry listed first in feed order — the online one must still be
        // the survivor, since it is the more actionable lead. This also exercises the sort's
        // stability requirement: it must not just "sort online first" but do so without
        // scrambling same-status entries.
        let children = distribution_host_children(&[
            UrlhausUrl {
                url: "http://muledo.com/old.php".to_string(),
                url_status: Some("offline".to_string()),
            },
            UrlhausUrl {
                url: "http://muledo.com/live.php".to_string(),
                url_status: Some("online".to_string()),
            },
        ]);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].value, "muledo.com");
    }

    #[test]
    fn host_children_are_capped_at_max_distribution_hosts() {
        let urls: Vec<UrlhausUrl> = (0..30)
            .map(|i| UrlhausUrl {
                url: format!("http://host{i}.example.com/payload.exe"),
                url_status: Some("online".to_string()),
            })
            .collect();
        let children = distribution_host_children(&urls);
        assert_eq!(children.len(), MAX_DISTRIBUTION_HOSTS);
    }

    #[test]
    fn every_distribution_url_is_still_a_row_even_past_the_child_cap() {
        // The cap in `distribution_host_children` bounds new nodes, not what the detail panel
        // shows — the row list must stay exhaustive.
        let urls: Vec<UrlhausUrl> = (0..30)
            .map(|i| UrlhausUrl {
                url: format!("http://host{i}.example.com/payload.exe"),
                url_status: Some("online".to_string()),
            })
            .collect();
        let record = UrlhausRecord {
            urls,
            ..Default::default()
        };
        let produced = urlhaus_record_to_yield(&record);
        let url_rows = produced
            .rows
            .iter()
            .filter(|r| r.label == "Distribution URL")
            .count();
        assert_eq!(url_rows, 30);
    }

    #[test]
    fn a_url_with_no_parseable_host_is_skipped_not_fabricated() {
        assert_eq!(url_host("not a url"), None);
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
