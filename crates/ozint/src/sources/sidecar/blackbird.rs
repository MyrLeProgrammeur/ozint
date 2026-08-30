//! `sidecar-blackbird-username`/`sidecar-blackbird-email` — a second, broader existence sweep
//! for `entity-username` (alongside `maigret-probe`) and `entity-email` (alongside
//! `sidecar-holehe`). Runs against a local Blackbird sidecar
//! (`crates/ozint/docker/blackbird/`), built from `p1ngul1n0/blackbird` (GPLv3, verified
//! by reading `docs/LICENSE` directly — GitHub's own license detector reports none, because the
//! file lives at `docs/LICENSE` rather than the repo root).
//!
//! ## Why this tool exists alongside Maigret and holehe, not instead of them
//!
//! Blackbird's username mode wraps the WhatsMyName project's own 700+-site list (CC-BY-SA
//! 4.0, attribution: WebBreacher/WhatsMyName) — wider than Maigret's default ~509-site scan and
//! `wmn-probe`'s own ~730-site sweep, but the *same* existence-only technique underneath, so it
//! is genuinely additional breadth, not a replacement. Blackbird's email mode is a small,
//! separately curated 16-site list (`data/email-data.json`) distinct from holehe's ~120
//! password-reset/signup probes — different sites, same shape.
//!
//! ## The one thing Blackbird has that neither Maigret nor holehe do: declarative metadata
//!
//! A minority of Blackbird's sites (`data/wmn-metadata.json`: Duolingo, Gravatar, Instagram,
//! StreamElements, TikTok, Twitter, as of the 2026-08-26 audit that wired this tool) carry a
//! per-site extraction spec — a JSON-path or HTML-regex rule the tool runs against the same
//! response it already fetched to confirm existence, pulling out real fields (Duolingo's
//! subscription tier, a display name, a follower count) rather than a bare true/false. Neither
//! GAFAM platform is in that list yet — Google, Facebook, Amazon, Apple and Microsoft all
//! require an authenticated or bespoke per-platform client (the GHunt approach for Google is
//! the model), which is out of scope for this tool and left as a documented follow-up.
//!
//! ## Verified by reading the source, not assumed
//!
//! `src/modules/core/email.py`/`username.py` build one `{name, url, category, status,
//! metadata}` record per site checked (`status` one of `FOUND`/`NOT-FOUND`/`ERROR`/`NONE`);
//! `metadata` is `null` for the ~700 sites with no extraction spec, and a list of `{name,
//! value, ...}` fields for the handful that have one — confirmed by reading
//! `src/modules/utils/parse.py::extractMetadata`, which only appends a field when its own
//! extraction actually returned a value. `saveToJson` — and therefore any JSON file to read —
//! is only written `if config.json and <found accounts>`; a genuinely empty result produces no
//! file at all, which `docker/blackbird/app.py`'s shim already treats as `{"results": []}`
//! rather than an error, per this crate's "empty is a finding, never a disguised failure"
//! doctrine.
//!
//! ## Why this writes only `rows`, never a payload field or a child
//!
//! Same reasoning as `sidecar-maigret`'s module doc: `UsernamePayload.hits` belongs to
//! `wmn-probe` alone, and `EmailPayload` has no "accounts" field to begin with. Every confirmed
//! site becomes an [`OzRow`]; a site with metadata gets one extra row per extracted field,
//! labelled `<site> · <field name>`, landing in the node's detail rows alongside every other
//! row-only tool in this crate.
//!
//! Confirmed hits were briefly also turned into `OzType::Username` `ChildSeed`s carrying the
//! queried handle itself — read `wmn.rs`'s module doc for the full reasoning shared by all
//! three site-list sweeps in this crate (`wmn.rs`, this file, `maigret.rs`). In short: Blackbird
//! confirms one identity across many sites, not many identities, so a same-value child always
//! dedups against the node the layer is already running on (`runtime::emit_child`'s
//! dedup-before-persist step, `runtime.rs:444-458`) and can only ever add a corroboration
//! record there, never a new node — and no `OzType` in this crate carries a per-platform
//! profile URL as its identity, so there is no sound value a child could carry instead. The
//! children were removed once this was confirmed; the row list above is where a confirmed
//! hit's information actually belongs.

use std::time::Duration;

use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const DEFAULT_BASE_URL: &str = "http://localhost:5200";

/// Above the shim's own 150s subprocess budget (`app.py`), for the same reason
/// `holehe.rs`/`maigret.rs` set theirs above their sidecar's internal timeout — let the shim's
/// own timeout answer first with a specific `504` rather than this side giving up and reporting
/// a less specific transport failure.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(160);

/// One extracted field from a site with a declarative metadata spec. `value` is absent from the
/// wire shape entirely when extraction found nothing for that field — see the module doc.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
struct MetadataField {
    name: String,
    #[serde(default)]
    value: Option<serde_json::Value>,
}

/// One `results[]` entry, narrowed to what this tool keeps. `category` is read by Blackbird's
/// own PDF export and has no analogue in this crate's row model, so it is dropped here rather
/// than carried through unused. `downloaded` — the local filesystem path of an image Blackbird's
/// own metadata system already fetched and saved (present on image-type metadata) — is kept: it
/// is provenance for an artifact already retrieved, not a re-derivable label.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
struct BlackbirdHit {
    name: String,
    url: String,
    status: String,
    #[serde(default)]
    metadata: Option<Vec<MetadataField>>,
    #[serde(default)]
    downloaded: Option<String>,
}

/// Parses the shim's `{"results": [...]}` body into confirmed hits — `status == "FOUND"` rows
/// only. `NOT-FOUND`/`ERROR`/`NONE` are dropped: this tool reports what it confirmed, not every
/// site it checked. Pure and tested.
fn parse_blackbird_results(json: &serde_json::Value) -> Result<Vec<BlackbirdHit>, String> {
    let results = json
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "blackbird shim response is missing `results`".to_string())?;

    Ok(results
        .iter()
        .filter_map(|r| serde_json::from_value::<BlackbirdHit>(r.clone()).ok())
        .filter(|hit| hit.status == "FOUND")
        .collect())
}

/// `Value::Array` metadata (Blackbird's own `type: "Array"` fields, e.g. a list of linked
/// emails) is joined with commas rather than dropped; anything else renders as its plain JSON
/// text minus the surrounding quotes on a bare string.
fn metadata_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(metadata_value_to_string)
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

fn blackbird_to_yield(hits: &[BlackbirdHit]) -> ToolYield {
    let mut rows = Vec::new();
    for hit in hits {
        rows.push(OzRow {
            label: hit.name.clone(),
            value: "account registered".to_string(),
            href: Some(hit.url.clone()),
            ..Default::default()
        });
        for field in hit.metadata.iter().flatten() {
            let Some(value) = &field.value else { continue };
            rows.push(OzRow {
                label: format!("{} · {}", hit.name, field.name),
                value: metadata_value_to_string(value),
                ..Default::default()
            });
        }
        if let Some(downloaded) = &hit.downloaded {
            rows.push(OzRow {
                label: format!("{} · downloaded", hit.name),
                value: downloaded.clone(),
                ..Default::default()
            });
        }
    }
    ToolYield {
        rows,
        ..Default::default()
    }
}

/// Shared by both entity types — `mode` is `"username"` or `"email"`, matching the shim's own
/// `--username`/`--email` branch.
async fn run_blackbird(mode: &str, value: &str) -> DispatchOutcome {
    let base = super::sidecar_base_url("BLACKBIRD_SIDECAR_URL", DEFAULT_BASE_URL);
    let url = format!(
        "{base}/check?mode={mode}&value={}",
        urlencoding::encode(value)
    );

    let json = match super::sidecar_request(reqwest::Method::GET, &url, None, REQUEST_TIMEOUT).await
    {
        Ok(json) => json,
        Err(outcome) => return DispatchOutcome::Ran(outcome, None),
    };

    let hits = match parse_blackbird_results(&json) {
        Ok(hits) => hits,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    let count = hits.len() as u32;
    let produced = blackbird_to_yield(&hits);
    if count == 0 {
        DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(produced))
    } else {
        DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(produced))
    }
}

/// Runs `sidecar-blackbird-username` against `value` (a handle).
pub async fn run_blackbird_username(
    value: &str,
    _ctx: &crate::sources::ToolCtx,
) -> DispatchOutcome {
    run_blackbird("username", value).await
}

/// Runs `sidecar-blackbird-email` against `value` (an email address).
pub async fn run_blackbird_email(value: &str, _ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    run_blackbird("email", value).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_response() -> serde_json::Value {
        serde_json::json!({
            "username": "torvalds",
            "results": [
                {"name": "GitHub", "url": "https://github.com/torvalds", "category": "tech", "status": "FOUND", "metadata": null},
                {"name": "Reddit", "url": "https://reddit.com/user/torvalds", "category": "social", "status": "NOT-FOUND", "metadata": null},
                {"name": "Duolingo", "url": "https://duolingo.com/x", "category": "misc", "status": "FOUND", "metadata": [
                    {"schema": "JSON", "type": "String", "name": "Streak", "path": ["streak"], "value": "42"}
                ], "downloaded": "/data/blackbird/torvalds_duolingo.jpg"},
                {"name": "Broken", "url": "https://broken.example", "category": "misc", "status": "ERROR", "metadata": null}
            ]
        })
    }

    #[test]
    fn keeps_only_found_hits() {
        let hits = parse_blackbird_results(&sample_response()).expect("parses");
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().any(|h| h.name == "GitHub"));
        assert!(hits.iter().any(|h| h.name == "Duolingo"));
    }

    #[test]
    fn a_response_missing_results_is_rejected() {
        assert!(parse_blackbird_results(&serde_json::json!({})).is_err());
    }

    #[test]
    fn no_found_hits_is_a_valid_empty_parse() {
        let json = serde_json::json!({
            "results": [
                {"name": "X", "url": "https://x.example", "category": "misc", "status": "NOT-FOUND", "metadata": null}
            ]
        });
        assert_eq!(parse_blackbird_results(&json), Ok(Vec::new()));
    }

    #[test]
    fn yield_builds_one_row_per_hit_plus_one_per_metadata_field() {
        let hits = parse_blackbird_results(&sample_response()).unwrap();
        let produced = blackbird_to_yield(&hits);
        // GitHub: 1 row. Duolingo: 1 existence row + 1 metadata row + 1 downloaded row.
        assert_eq!(produced.rows.len(), 4);
        assert!(produced.rows.iter().any(
            |r| r.label == "GitHub" && r.href.as_deref() == Some("https://github.com/torvalds")
        ));
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Duolingo · Streak" && r.value == "42")
        );
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Duolingo · downloaded"
                    && r.value == "/data/blackbird/torvalds_duolingo.jpg")
        );
    }

    #[test]
    fn yield_never_touches_the_payload() {
        let hits = parse_blackbird_results(&sample_response()).unwrap();
        let produced = blackbird_to_yield(&hits);
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }

    #[test]
    fn metadata_array_values_join_with_commas() {
        let value = serde_json::json!(["a@example.com", "b@example.com"]);
        assert_eq!(
            metadata_value_to_string(&value),
            "a@example.com, b@example.com"
        );
    }

    #[tokio::test]
    async fn a_sidecar_that_is_not_running_reports_an_honest_connection_failure() {
        unsafe { std::env::set_var("BLACKBIRD_SIDECAR_URL", "http://127.0.0.1:1") };
        let outcome = run_blackbird_username("someone", &crate::sources::ToolCtx::default()).await;
        unsafe { std::env::remove_var("BLACKBIRD_SIDECAR_URL") };
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
    #[ignore = "needs the real blackbird sidecar running (docker compose up -d)"]
    async fn live_blackbird_username_sweep() {
        let ctx = crate::sources::ToolCtx::default();
        let outcome = run_blackbird_username("torvalds", &ctx).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(y)) => {
                println!(
                    "LIVE BLACKBIRD USERNAME: {count} rows: {:?}",
                    &y.rows[..y.rows.len().min(5)]
                );
                assert!(count > 0);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore = "needs the real blackbird sidecar running (docker compose up -d)"]
    async fn live_blackbird_email_sweep() {
        let ctx = crate::sources::ToolCtx::default();
        let outcome = run_blackbird_email("analyst@example.com", &ctx).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(y)) => {
                println!("LIVE BLACKBIRD EMAIL: {count} rows: {:?}", y.rows);
                assert!(count > 0);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
