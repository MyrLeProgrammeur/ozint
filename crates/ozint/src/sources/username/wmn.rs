//! `wmn-probe` — the WhatsMyName ~730-site fan-out.
//!
//! The site list is `WebBreacher/WhatsMyName`'s `wmn-data.json`, **CC BY-SA 4.0**: the
//! attribution carried on this tool's `registry::ToolDef` is a licence obligation, not a
//! nicety, and must reach the UI.
//!
//! Everything here except [`run_wmn_probe`] and `probe_one_site` is pure and tested against
//! inline fixtures; those two make real network calls and are deliberately kept thin, per
//! this crate's convention (see `fetch.rs`'s module doc).
//!
//! ## Rows, added alongside the payload
//!
//! Until this pass, a confirmed hit only ever reached `payload_patch["hits"]` — invisible in
//! the detail panel, reachable only by an analyst who thinks to inspect the raw payload. Every
//! confirmed [`SiteHit`] now also becomes an [`OzRow`] (uncapped — there is no reason to hide
//! any of a ~730-site sweep's real findings from the one view that actually renders per-hit
//! detail).
//!
//! ## Why a confirmed hit does NOT become a child — read this before "fixing" it
//!
//! A confirmed hit was briefly turned into an `OzType::Username` `ChildSeed` carrying the
//! queried handle itself (the site being confirmed doesn't change *which* identity was found —
//! WhatsMyName confirms one identity across many sites, not many identities). That value is
//! always already the node this tool's own layer is running against, so
//! `runtime::emit_child`'s dedup-before-persist step (`runtime.rs:444-458`: it computes the
//! seed's dedup key and checks the visited set *before* ever building a node) can never treat
//! it as new — it only ever produces a corroboration record on the very node already under
//! investigation. No `OzType` in this crate carries a per-platform profile URL as its identity
//! (all twelve are identities, not locations), so there is no sound child value a site-list
//! sweep like this one could seed instead. The children were removed once this was confirmed;
//! the row list above is where a confirmed hit's information actually belongs.

use tokio::sync::Semaphore;

use crate::fetch::{self, CancelSignal, OzBody, OzOutcome};
use crate::layer_plan::FACT_CONFIRMED_SITES;
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, SiteHit, SiteHitStatus, UsernamePayload};

const WMN_DATASET_URL: &str =
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json";

/// Bounded concurrency for the ~730-site fan-out, via a [`tokio::sync::Semaphore`] (no new
/// dependency — `tokio` `full` already covers this).
///
/// **32** is chosen as a balance, not a measurement: with `fetch::oz_fetch`'s 12s default
/// per-attempt timeout, a worst case where every one of ~730 probes times out would still
/// finish in `730 / 32 * 12s ≈ 274s` (~4.5 minutes) — versus roughly 2.4 hours run serially —
/// while keeping this one tool invocation's in-flight connection/file-descriptor footprint low
/// enough that it doesn't starve whatever else a layer runs alongside it. In practice almost
/// every site answers in well under a second, so real runs finish far faster than the
/// timeout-worst-case above. Tune once the source scheduler can measure this for real.
const WMN_CONCURRENCY: usize = 32;

/// One site descriptor parsed out of `wmn-data.json`.
#[derive(Debug, Clone, PartialEq)]
pub struct WmnSite {
    pub name: String,
    pub uri_check: String,
    pub e_code: Option<u16>,
    pub e_string: Option<String>,
    pub m_code: Option<u16>,
    pub m_string: Option<String>,
    pub category: Option<String>,
}

/// Parses the `sites` array out of the WhatsMyName dataset JSON. Pure and tested against
/// inline fixtures — no network here.
///
/// Sites that declare a `post_body` (a POST-shaped probe) are skipped: this implementation
/// only supports the GET-via-`uri_check` probe shape the vast majority of the dataset uses.
/// A site missing `name` or `uri_check` entirely is also skipped rather than failing the
/// whole parse — one malformed entry in a ~730-entry dataset shouldn't sink the rest.
pub fn parse_wmn_dataset(json: &serde_json::Value) -> Result<Vec<WmnSite>, String> {
    let sites = json
        .get("sites")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "wmn dataset is missing its `sites` array".to_string())?;

    let mut out = Vec::with_capacity(sites.len());
    for entry in sites {
        if entry.get("post_body").is_some() {
            continue;
        }
        let (Some(name), Some(uri_check)) = (
            entry.get("name").and_then(|v| v.as_str()),
            entry.get("uri_check").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        out.push(WmnSite {
            name: name.to_string(),
            uri_check: uri_check.to_string(),
            e_code: entry
                .get("e_code")
                .and_then(|v| v.as_u64())
                .map(|n| n as u16),
            e_string: entry
                .get("e_string")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            m_code: entry
                .get("m_code")
                .and_then(|v| v.as_u64())
                .map(|n| n as u16),
            m_string: entry
                .get("m_string")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            category: entry
                .get("cat")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        });
    }

    if out.is_empty() {
        return Err("wmn dataset parsed but yielded zero GET-probeable sites".to_string());
    }
    Ok(out)
}

/// Substitutes the `{account}` placeholder in a WhatsMyName `uri_check` template with the
/// (URL-encoded) handle. Pure and tested.
pub fn substitute_account(uri_template: &str, handle: &str) -> String {
    uri_template.replace("{account}", &urlencoding::encode(handle))
}

/// What a classification decision needs to see, kept as a struct so
/// [`classify_wmn_response`] stays a plain, easily-fixtured pure function.
pub struct WmnClassifyInput<'a> {
    pub status: u16,
    pub body: &'a str,
    pub e_code: Option<u16>,
    pub e_string: Option<&'a str>,
    pub m_code: Option<u16>,
    pub m_string: Option<&'a str>,
}

/// Classifies one probe response into a [`SiteHitStatus`], given the site's declared
/// exists/missing signals. A criterion that the site doesn't declare is treated as trivially
/// satisfied (so a code-only or string-only site still classifies), but at least one of
/// `e_code`/`e_string` (or `m_code`/`m_string`) must be declared for that side to count at
/// all — a site with no criteria whatsoever cannot be classified and comes back `Possible`.
/// Pure and tested.
pub fn classify_wmn_response(input: &WmnClassifyInput) -> SiteHitStatus {
    let has_e_criteria = input.e_code.is_some() || input.e_string.is_some();
    let e_code_ok = input.e_code.is_none_or(|c| c == input.status);
    let e_string_ok = input.e_string.is_none_or(|s| input.body.contains(s));

    let has_m_criteria = input.m_code.is_some() || input.m_string.is_some();
    let m_code_ok = input.m_code.is_none_or(|c| c == input.status);
    let m_string_ok = input.m_string.is_none_or(|s| input.body.contains(s));

    if has_e_criteria && e_code_ok && e_string_ok {
        SiteHitStatus::Confirmed
    } else if has_m_criteria && m_code_ok && m_string_ok {
        SiteHitStatus::Absent
    } else {
        SiteHitStatus::Possible
    }
}

/// Probes one site for `handle`. Untested (network) — see the module-level convention note.
///
/// **Deliberately not cached**, unlike every other tool in this crate. `oz_tool_cache` has no
/// eviction policy, so caching all ~730 per-site probe responses for every handle ever queried
/// would grow the table without bound. The unit's own spec (`cache.rs`'s module doc) names "the
/// WhatsMyName site list" — the dataset, singular — as the daily-TTL target, not the probes
/// themselves, so this function keeps taking a plain `Option<CancelSignal>` and calling
/// [`fetch::oz_fetch`] directly rather than a [`crate::sources::ToolCtx`].
async fn probe_one_site(site: &WmnSite, handle: &str, cancel: Option<CancelSignal>) -> SiteHit {
    let url = substitute_account(&site.uri_check, handle);
    let outcome = fetch::oz_fetch(
        &url,
        fetch::OzFetchOptions {
            cancel,
            ..Default::default()
        },
    )
    .await;

    let status = match outcome {
        OzOutcome::Ok(resp) => {
            let text = super::body_text(&resp.body);
            classify_wmn_response(&WmnClassifyInput {
                status: resp.status,
                body: &text,
                e_code: site.e_code,
                e_string: site.e_string.as_deref(),
                m_code: site.m_code,
                m_string: site.m_string.as_deref(),
            })
        }
        // A non-retryable 4xx (most commonly the site's own declared m_code, e.g. 404) is a
        // legitimate classification input, not a probe failure.
        OzOutcome::HttpError {
            status,
            body_snippet,
        } => {
            let text = body_snippet.unwrap_or_default();
            classify_wmn_response(&WmnClassifyInput {
                status,
                body: &text,
                e_code: site.e_code,
                e_string: site.e_string.as_deref(),
                m_code: site.m_code,
                m_string: site.m_string.as_deref(),
            })
        }
        _ => SiteHitStatus::Error,
    };

    SiteHit {
        site: site.name.clone(),
        category: site.category.clone(),
        url,
        status,
    }
}

/// Turns every confirmed hit in `hits` into a row. Uncapped — see the module doc for why this
/// is the only thing a confirmed hit becomes (no children). Pure and tested.
fn confirmed_hits_to_rows(hits: &[SiteHit]) -> Vec<OzRow> {
    hits.iter()
        .filter(|h| h.status == SiteHitStatus::Confirmed)
        .map(|hit| OzRow {
            label: hit.site.clone(),
            value: "account registered".to_string(),
            href: Some(hit.url.clone()),
            ..Default::default()
        })
        .collect()
}

/// Fans a handle out across the WhatsMyName site list. **Counts as ONE lookup**, not ~730 —
/// the lookup meter treats this fan-out as a single logical tool
/// invocation, and this function's single [`DispatchOutcome`] return reflects that: the
/// per-site detail lives inside the one [`UsernamePayload`] this produces, not as ~730
/// separate tool reports.
pub async fn run_wmn_probe(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    // The ~730-site list itself, not a per-handle request — a constant key so every handle
    // queried shares the same cached dataset download instead of each one re-fetching it.
    let dataset_outcome = ctx
        .fetch(
            "wmn-probe",
            "dataset",
            WMN_DATASET_URL,
            fetch::OzFetchOptions {
                cancel: ctx.cancel.clone(),
                ..Default::default()
            },
        )
        .await;

    if matches!(dataset_outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&dataset_outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = dataset_outcome else {
        unreachable!("every non-Ok, non-Cancelled OzOutcome was handled above");
    };
    // ⚠️ **`raw.githubusercontent.com` serves JSON as `text/plain`.**
    //
    // `fetch::dispatch_content_type` buckets by the declared content type
    // (`kind.contains("json")`), so this 258 KB JSON document arrives as
    // `OzBody::Text`, not `OzBody::Json`. Matching `Json` alone meant every
    // real run of this tool returned `ParseError { "wmn dataset response was
    // not JSON" }` — i.e. **the crate's largest username sweep (~730 sites)
    // never once ran against the live web.** Caught 2026-08-26 by reading a
    // real investigation's stored tool reports, not by the suite: every unit
    // test here builds `OzBody::Json(...)` by hand and so skips the exact
    // layer that breaks. Verified against the live URL: HTTP 200,
    // `text/plain; charset=utf-8`, valid JSON.
    //
    // Accept either shape, parsing Text on its merits. Kept local rather than
    // loosening `dispatch_content_type` for all 64 tools — several parsers
    // deliberately branch on `Text`, and widening that seam blind would trade
    // one silent breakage for another.
    let owned_json;
    let dataset_json = match &resp.body {
        OzBody::Json(v) => v,
        OzBody::Text(raw) => match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(v) => {
                owned_json = v;
                &owned_json
            }
            Err(e) => {
                return DispatchOutcome::Ran(
                    ToolOutcome::ParseError {
                        message: format!(
                            "wmn dataset was served as text and did not parse as JSON: {e}"
                        ),
                    },
                    None,
                );
            }
        },
        _ => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: "wmn dataset response was not JSON".to_string(),
                },
                None,
            );
        }
    };
    let sites = match parse_wmn_dataset(dataset_json) {
        Ok(sites) => sites,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    let semaphore = Semaphore::new(WMN_CONCURRENCY);
    let hits: Vec<SiteHit> = futures::future::join_all(sites.iter().map(|site| {
        let semaphore = &semaphore;
        let cancel = ctx.cancel.clone();
        async move {
            let _permit = semaphore
                .acquire()
                .await
                .expect("semaphore is never closed");
            probe_one_site(site, handle, cancel).await
        }
    }))
    .await;

    let sites_checked = hits.len() as u32;
    let sites_confirmed = hits
        .iter()
        .filter(|h| h.status == SiteHitStatus::Confirmed)
        .count() as u32;
    let rows = confirmed_hits_to_rows(&hits);

    let payload = UsernamePayload {
        hits,
        sites_checked,
        sites_confirmed,
        profile: Vec::new(),
    };
    let payload_patch = serde_json::to_value(&payload).unwrap_or(serde_json::json!({}));

    let tool_outcome = if sites_confirmed > 0 {
        ToolOutcome::OkWithResults {
            count: sites_confirmed,
        }
    } else {
        ToolOutcome::OkEmpty
    };

    let produced = ToolYield {
        payload_patch,
        rows,
        facts: vec![(FACT_CONFIRMED_SITES, sites_confirmed as f64)],
        flags: Vec::new(),
        values: Vec::new(),
        children: Vec::new(),
    };

    DispatchOutcome::Ran(tool_outcome, Some(produced))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── the content-type trap ───────────────────────────────────────────

    /// Pins the bug that made this whole tool dead on the live web:
    /// `raw.githubusercontent.com` serves the dataset as `text/plain`, so
    /// `fetch::dispatch_content_type` hands back `OzBody::Text` and the old
    /// `let OzBody::Json(..) = ..` match fell through to `ParseError`.
    ///
    /// The rest of this module's tests all build `OzBody::Json` by hand,
    /// which is exactly why none of them caught it — they skip the layer
    /// that breaks. This one asserts on the real declared content type.
    #[test]
    fn json_served_as_text_plain_still_parses() {
        let raw = r#"{"sites":[{"name":"GitHub","uri_check":"https://github.com/{account}","e_code":200,"e_string":"followers","m_code":404,"m_string":"Not Found"}]}"#;
        // What `dispatch_content_type` produces for GitHub raw's headers.
        let body = crate::fetch::OzBody::Text(raw.to_string());
        let crate::fetch::OzBody::Text(text) = &body else {
            panic!("fixture is Text")
        };
        let value: serde_json::Value =
            serde_json::from_str(text).expect("a text/plain body that is valid JSON must parse");
        let sites = parse_wmn_dataset(&value).expect("dataset parses");
        assert_eq!(
            sites.len(),
            1,
            "the site survives the text/plain round trip"
        );
        assert_eq!(sites[0].name, "GitHub");
    }

    // ── dataset parsing ─────────────────────────────────────────────────

    #[test]
    fn parses_a_minimal_wmn_dataset() {
        let json = serde_json::json!({
            "sites": [
                {
                    "name": "GitHub",
                    "uri_check": "https://github.com/{account}",
                    "e_code": 200,
                    "e_string": "Repositories",
                    "m_code": 404,
                    "m_string": "Not Found",
                    "cat": "coding"
                },
                {
                    "name": "SomePostSite",
                    "uri_check": "https://example.com/check",
                    "post_body": "account={account}"
                }
            ]
        });
        let sites = parse_wmn_dataset(&json).expect("dataset parses");
        assert_eq!(sites.len(), 1, "the POST-shaped site must be skipped");
        assert_eq!(sites[0].name, "GitHub");
        assert_eq!(sites[0].e_code, Some(200));
        assert_eq!(sites[0].category.as_deref(), Some("coding"));
    }

    #[test]
    fn skips_malformed_entries_without_failing_the_whole_parse() {
        let json = serde_json::json!({
            "sites": [
                { "e_code": 200 },
                { "name": "OK Site", "uri_check": "https://example.com/{account}" }
            ]
        });
        let sites = parse_wmn_dataset(&json).expect("dataset parses despite one bad entry");
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].name, "OK Site");
    }

    #[test]
    fn rejects_a_dataset_with_no_sites_array() {
        let json = serde_json::json!({ "license": "CC BY-SA 4.0" });
        assert!(parse_wmn_dataset(&json).is_err());
    }

    #[test]
    fn rejects_a_dataset_that_yields_zero_usable_sites() {
        let json = serde_json::json!({ "sites": [{ "e_code": 200 }] });
        assert!(parse_wmn_dataset(&json).is_err());
    }

    // ── account substitution ────────────────────────────────────────────

    #[test]
    fn substitutes_and_url_encodes_the_handle() {
        assert_eq!(
            substitute_account("https://github.com/{account}", "mtrebosc"),
            "https://github.com/mtrebosc"
        );
        assert_eq!(
            substitute_account("https://example.com/u/{account}/profile", "a b"),
            "https://example.com/u/a%20b/profile"
        );
    }

    // ── classification ───────────────────────────────────────────────────

    #[test]
    fn classifies_confirmed_when_both_e_code_and_e_string_match() {
        let status = classify_wmn_response(&WmnClassifyInput {
            status: 200,
            body: "Welcome, here are the Repositories",
            e_code: Some(200),
            e_string: Some("Repositories"),
            m_code: Some(404),
            m_string: Some("Not Found"),
        });
        assert_eq!(status, SiteHitStatus::Confirmed);
    }

    #[test]
    fn classifies_absent_when_m_code_and_m_string_match() {
        let status = classify_wmn_response(&WmnClassifyInput {
            status: 404,
            body: "404 Not Found",
            e_code: Some(200),
            e_string: Some("Repositories"),
            m_code: Some(404),
            m_string: Some("Not Found"),
        });
        assert_eq!(status, SiteHitStatus::Absent);
    }

    #[test]
    fn classifies_possible_when_neither_side_matches() {
        let status = classify_wmn_response(&WmnClassifyInput {
            status: 302,
            body: "redirecting…",
            e_code: Some(200),
            e_string: Some("Repositories"),
            m_code: Some(404),
            m_string: Some("Not Found"),
        });
        assert_eq!(status, SiteHitStatus::Possible);
    }

    #[test]
    fn a_code_only_site_classifies_on_status_alone() {
        let status = classify_wmn_response(&WmnClassifyInput {
            status: 200,
            body: "",
            e_code: Some(200),
            e_string: None,
            m_code: Some(404),
            m_string: None,
        });
        assert_eq!(status, SiteHitStatus::Confirmed);
    }

    #[test]
    fn a_string_only_site_classifies_on_body_alone() {
        let status = classify_wmn_response(&WmnClassifyInput {
            status: 200,
            body: "user@handle exists",
            e_code: None,
            e_string: Some("exists"),
            m_code: None,
            m_string: Some("does not exist"),
        });
        assert_eq!(status, SiteHitStatus::Confirmed);
    }

    #[test]
    fn a_site_with_no_criteria_at_all_is_possible() {
        let status = classify_wmn_response(&WmnClassifyInput {
            status: 200,
            body: "anything",
            e_code: None,
            e_string: None,
            m_code: None,
            m_string: None,
        });
        assert_eq!(status, SiteHitStatus::Possible);
    }

    // ── rows ─────────────────────────────────────────────────────────────

    fn hit(site: &str, status: SiteHitStatus) -> SiteHit {
        SiteHit {
            site: site.to_string(),
            category: None,
            url: format!("https://{}.example/handle", site.to_ascii_lowercase()),
            status,
        }
    }

    #[test]
    fn a_confirmed_hit_becomes_a_row() {
        let hits = vec![
            hit("GitHub", SiteHitStatus::Confirmed),
            hit("Reddit", SiteHitStatus::Absent),
        ];
        let rows = confirmed_hits_to_rows(&hits);
        assert_eq!(rows.len(), 1, "only the confirmed hit produces a row");
        assert_eq!(rows[0].label, "GitHub");
        assert_eq!(
            rows[0].href.as_deref(),
            Some("https://github.example/handle")
        );
    }

    #[test]
    fn possible_and_absent_and_error_hits_produce_no_row() {
        let hits = vec![
            hit("A", SiteHitStatus::Possible),
            hit("B", SiteHitStatus::Absent),
            hit("C", SiteHitStatus::Error),
        ];
        assert!(confirmed_hits_to_rows(&hits).is_empty());
    }

    #[test]
    fn every_confirmed_hit_gets_a_row_uncapped() {
        let hits: Vec<SiteHit> = (0..50)
            .map(|i| hit(&format!("site{i:03}"), SiteHitStatus::Confirmed))
            .collect();
        let rows = confirmed_hits_to_rows(&hits);
        assert_eq!(
            rows.len(),
            hits.len(),
            "rows are never capped, unlike the children this tool briefly emitted"
        );
    }
}
