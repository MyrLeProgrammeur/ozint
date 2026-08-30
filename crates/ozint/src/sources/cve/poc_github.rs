//! `poc-github` — nomi-sec/PoC-in-GitHub, a community-maintained mirror of GitHub repos that
//! claim to be proof-of-concept exploits for a given CVE. Keyless. Owns the `pocUrls`
//! field of [`crate::types::CvePayload`], and also emits rows and [`OzType::Username`]
//! children — see "Rows" and "Children" below.
//!
//! `GET https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{YEAR}/{CVE}.json`,
//! where `{YEAR}` is the 4-digit year parsed out of the CVE id. Verified live 2026-08-21: a
//! CVE with indexed PoCs answers `200` with a JSON array of GitHub repo objects
//! (`html_url`/`full_name`/`description`/`stargazers_count`/`created_at`/`updated_at`); a CVE
//! with none answers **`404`**.
//!
//! Each `pocUrls` entry keeps `stargazers_count` and `updated_at` alongside the URL — without
//! them there is no way to tell a maintained PoC from an abandoned fork-of-a-fork, and this
//! index routinely lists several repos for one CVE.
//!
//! ## Rows
//!
//! Previously this tool wrote no rows at all, which left `stargazersCount`/`updatedAt` reachable
//! only through `pocUrls`'s payload patch — invisible in the detail panel itself. Each kept repo
//! now also gets a "PoC repo" row (link, stars, last update), so the same information the
//! payload carries is visible without reading raw JSON.
//!
//! ## Children
//!
//! Each entry's GitHub owner (`owner` in `full_name`'s `owner/repo`) becomes an
//! [`OzType::Username`] child — someone publishing a public exploit for the CVE under
//! investigation is a lead worth following in its own right, independent of whether their
//! particular repo is still maintained. See [`poc_owner_children`] for the extraction,
//! ordering, dedup and cap.
//!
//! ## The trap this module exists to avoid
//!
//! A 404 here means "no public PoC repo is indexed for this CVE" — the overwhelmingly common
//! case, since most CVEs never get a public exploit repo — **not** "the source is down". If
//! this were routed through [`crate::sources::fold_fetch_failure`] like every other non-2xx
//! status, it would become [`crate::outcome::ToolOutcome::HttpError`], and
//! `outcome::settle_kind` would then count a clean "no PoC found" as a tool failure — capable
//! of dragging an otherwise-clean CVE layer down to `Degraded` for the common case, not the
//! exceptional one. [`run_poc_github`] pins 404 to
//! [`crate::outcome::ToolOutcome::OkEmpty`] before `fold_fetch_failure` ever sees it. Every
//! other non-2xx status still goes through the normal fold — a 404 is special because *this
//! specific source* uses it to mean "not indexed", not because 404s are safe to ignore in
//! general.
//!
//! ## Cap
//!
//! `pocUrls` is capped at 25 entries. Nothing upstream enforces a cap; this file picks one because the
//! payload is rendered in a detail panel, not archived — an investigator does not need the
//! full list of every fork-of-a-fork PoC repo GitHub search can surface, and an unbounded
//! list would bloat every future `payload_patch` merge for CVEs with dozens of copycat repos.

use std::collections::HashSet;

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType, PocRepo};

const POC_GITHUB_BASE: &str = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/";

/// Cap on how many PoC repo URLs are kept in `pocUrls`. See the module doc.
const MAX_POC_URLS: usize = 25;

/// Cap on how many distinct repo owners one CVE's PoC list spawns as [`OzType::Username`]
/// children. `MAX_POC_URLS` already bounds the underlying repo list, so this is rarely the
/// binding constraint — it would take that many *different* people each publishing exactly one
/// PoC for the same CVE. Kept anyway rather than relying on the repo cap to bound it indirectly,
/// matching `dom::certspotter`'s convention of always capping what can become a new node.
const MAX_POC_OWNERS: usize = 20;

/// Extracts the 4-digit year segment out of a normalized `CVE-YYYY-NNNN` id (`CVE-2021-34527`
/// → `"2021"`). `None` for anything that doesn't have that shape — the caller must not make a
/// request in that case. Pure and tested.
pub fn parse_cve_year(cve: &str) -> Option<&str> {
    let mut parts = cve.split('-');
    let prefix = parts.next()?;
    if !prefix.eq_ignore_ascii_case("CVE") {
        return None;
    }
    let year = parts.next()?;
    if year.len() == 4 && year.chars().all(|c| c.is_ascii_digit()) {
        Some(year)
    } else {
        None
    }
}

/// Reads the response body as JSON, accepting the `text/plain` this host actually serves.
///
/// **`raw.githubusercontent.com` serves every file — `.json` included — as
/// `text/plain; charset=utf-8`** with `x-content-type-options: nosniff` (measured 2026-08-21).
/// `fetch::dispatch_content_type` keys on the declared type, so the body arrives as
/// [`OzBody::Text`], and matching only on [`OzBody::Json`] made this tool report a
/// `ParseError` for **every CVE that actually has PoC repos**.
///
/// That bug was invisible in the unit tests and would have been near-invisible in use: the
/// common case is a CVE with no public exploit, which 404s and settles cleanly `OkEmpty`, so
/// the tool looked healthy and only ever broke on the findings worth having. It was caught by
/// `sources::cve`'s `#[ignore]`d live test, which is the entire reason that test exists.
///
/// Handled here rather than in `dispatch_content_type`, which must not start JSON-parsing
/// every `text/plain` body in the crate on one host's behalf.
fn body_to_json(body: &OzBody) -> Result<serde_json::Value, String> {
    match body {
        OzBody::Json(json) => Ok(json.clone()),
        OzBody::Text(text) => serde_json::from_str(text)
            .map_err(|e| format!("PoC-in-GitHub body was not parseable JSON: {e}")),
        other => Err(format!(
            "PoC-in-GitHub response was neither JSON nor text: {other:?}"
        )),
    }
}

/// Parses a PoC-in-GitHub `200` body — a JSON array of GitHub repo-search objects — into
/// [`PocRepo`]s, capped at [`MAX_POC_URLS`]. `Err` only when the body isn't a JSON array at
/// all, which means the source's response shape changed. Pure and tested.
///
/// Besides `html_url`, this also keeps `stargazers_count` and `updated_at` — without them
/// there is no way to tell a maintained PoC from an abandoned fork-of-a-fork, and this index
/// routinely lists both for the same CVE. An entry with no `html_url` is dropped entirely
/// (nothing to link to); a missing `stargazers_count`/`updated_at` is kept as `None` rather
/// than dropping the whole entry, since the URL alone is still useful.
pub fn parse_poc_repos(json: &serde_json::Value) -> Result<Vec<PocRepo>, String> {
    let entries = json
        .as_array()
        .ok_or_else(|| "PoC-in-GitHub response was not a JSON array".to_string())?;

    Ok(entries
        .iter()
        .filter_map(|entry| {
            let html_url = entry.get("html_url").and_then(|v| v.as_str())?.to_string();
            let stargazers_count = entry.get("stargazers_count").and_then(|v| v.as_i64());
            let updated_at = entry
                .get("updated_at")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            Some(PocRepo {
                html_url,
                stargazers_count,
                updated_at,
            })
        })
        .take(MAX_POC_URLS)
        .collect())
}

/// Extracts one raw PoC-in-GitHub entry's GitHub owner. Prefers splitting `full_name`
/// (`owner/repo`); falls back to parsing the first path segment out of `html_url` when
/// `full_name` is absent or malformed, since `html_url` is the one field every entry that
/// reaches this point is guaranteed to have — `poc_owner_children` only calls this on entries
/// that already passed that check. `None` when neither source yields a non-empty owner.
/// Pure and tested.
fn repo_owner(entry: &serde_json::Value, html_url: &str) -> Option<String> {
    if let Some(full_name) = entry.get("full_name").and_then(|v| v.as_str())
        && let Some((owner, _repo)) = full_name.split_once('/')
        && !owner.trim().is_empty()
    {
        return Some(owner.trim().to_string());
    }
    let parsed = url::Url::parse(html_url).ok()?;
    let owner = parsed.path_segments()?.next()?;
    if owner.is_empty() {
        None
    } else {
        Some(owner.to_string())
    }
}

/// Extracts the repo owners behind `json`'s PoC entries as [`ChildSeed`]s — see the module
/// doc's "Children" section for why an owner is worth surfacing on its own.
///
/// Runs over the same [`MAX_POC_URLS`]-capped, `html_url`-present subset [`parse_poc_repos`]
/// keeps, so an owner is never produced for a repo that itself got dropped from `pocUrls`.
/// Candidates are sorted by `stargazers_count` (absent counted as 0, stable sort so entries
/// with equal stars keep the API's own order) before dedup and the [`MAX_POC_OWNERS`] cap —
/// this makes the owners behind the most-starred, most-credible repos the ones that survive if
/// the cap is ever actually hit, rather than an arbitrary array-order cut. Owners are deduped
/// case-insensitively, since GitHub usernames are case-insensitive and the same person can
/// publish more than one copycat PoC for a widely-exploited CVE. `Err` only when the body isn't
/// a JSON array, mirroring [`parse_poc_repos`].
fn poc_owner_children(json: &serde_json::Value) -> Result<Vec<ChildSeed>, String> {
    let entries = json
        .as_array()
        .ok_or_else(|| "PoC-in-GitHub response was not a JSON array".to_string())?;

    let mut candidates: Vec<(i64, String)> = entries
        .iter()
        .filter_map(|entry| {
            let html_url = entry.get("html_url").and_then(|v| v.as_str())?;
            let owner = repo_owner(entry, html_url)?;
            let stars = entry
                .get("stargazers_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            Some((stars, owner))
        })
        .take(MAX_POC_URLS)
        .collect();

    candidates.sort_by_key(|(stars, _)| std::cmp::Reverse(*stars));

    let mut seen = HashSet::new();
    Ok(candidates
        .into_iter()
        .filter(|(_, owner)| seen.insert(owner.to_ascii_lowercase()))
        .take(MAX_POC_OWNERS)
        .map(|(_, owner)| ChildSeed {
            oz_type: OzType::Username,
            value: owner,
            note: Some("published a PoC repo for this CVE on GitHub".to_string()),
        })
        .collect())
}

/// One "PoC repo" row per kept repo — see the module doc's "Rows" section for why this exists.
/// Pure.
fn poc_repo_rows(repos: &[PocRepo]) -> Vec<OzRow> {
    repos
        .iter()
        .map(|repo| {
            let mut value = repo.html_url.clone();
            if let Some(stars) = repo.stargazers_count {
                value.push_str(&format!(" — {stars}\u{2605}"));
            }
            if let Some(updated) = &repo.updated_at {
                value.push_str(&format!(", updated {updated}"));
            }
            OzRow {
                label: "PoC repo".to_string(),
                value,
                href: Some(repo.html_url.clone()),
                ..Default::default()
            }
        })
        .collect()
}

/// Turns a list of PoC repos into a [`ToolYield`] carrying `pocUrls` plus a "PoC repo" row per
/// entry. Owner children are attached separately by the caller (`run_poc_github`), since
/// deriving them needs the raw JSON entries (`full_name`), which [`PocRepo`] does not carry.
/// Pure.
pub fn poc_urls_to_yield(repos: &[PocRepo]) -> ToolYield {
    ToolYield {
        payload_patch: serde_json::json!({ "pocUrls": repos }),
        rows: poc_repo_rows(repos),
        ..Default::default()
    }
}

/// Fetches the PoC-in-GitHub index page for `cve`. Untested beyond its pure helpers, same
/// convention as the rest of this crate.
pub async fn run_poc_github(cve: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(year) = parse_cve_year(cve) else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("could not parse a 4-digit year out of `{cve}`"),
            },
            None,
        );
    };

    let url = format!("{POC_GITHUB_BASE}{year}/{}.json", urlencoding::encode(cve));
    // The CVE id being looked up — each CVE has its own indexed JSON file.
    let outcome = ctx
        .fetch(
            "cve-poc-github",
            cve,
            &url,
            fetch::OzFetchOptions::default(),
        )
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // TRAP pinned here — see the module doc. Must run before `fold_fetch_failure`.
    if let OzOutcome::HttpError { status: 404, .. } = &outcome {
        return DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        );
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled, non-404 OzOutcome was handled above");
    };
    // Not `OzBody::Json` — this host declares `.json` as `text/plain`. See `body_to_json`.
    let json = match body_to_json(&resp.body) {
        Ok(json) => json,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    match parse_poc_repos(&json) {
        Ok(urls) if urls.is_empty() => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(urls) => {
            let count = urls.len() as u32;
            let mut yielded = poc_urls_to_yield(&urls);
            // `json` was already confirmed to be an array by the `parse_poc_repos` call above,
            // so the only `Err` `poc_owner_children` can return is unreachable here; fall back
            // to no owner children rather than propagate, since a partial result (repos, no
            // owners) beats losing an already-successful lookup to an owner-extraction quirk.
            yielded.children = poc_owner_children(&json).unwrap_or_default();
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(yielded))
        }
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── the content-type trap ────────────────────────────────────────────

    #[test]
    fn a_text_plain_body_is_still_read_as_json() {
        // The regression this pins: `raw.githubusercontent.com` declares `.json` files as
        // `text/plain`, so the body never reaches `OzBody::Json`. Matching only on that
        // variant made the tool ParseError on every CVE that HAS PoC repos — while the
        // common no-PoC case kept 404ing cleanly, so nothing looked wrong.
        let raw = r#"[{"html_url":"https://github.com/DenizSe/CVE-2021-34527"}]"#;
        let json = body_to_json(&OzBody::Text(raw.to_string())).expect("text/plain must parse");
        assert_eq!(
            parse_poc_repos(&json).expect("an array"),
            vec![PocRepo {
                html_url: "https://github.com/DenizSe/CVE-2021-34527".to_string(),
                stargazers_count: None,
                updated_at: None,
            }]
        );
    }

    #[test]
    fn a_json_body_still_works_and_a_non_text_body_is_loud() {
        let value = serde_json::json!([{ "html_url": "https://github.com/a/b" }]);
        assert_eq!(
            body_to_json(&OzBody::Json(value.clone())).expect("json"),
            value
        );
        assert!(body_to_json(&OzBody::Empty).is_err());
        assert!(body_to_json(&OzBody::Text("not json".into())).is_err());
    }

    // ── parse_cve_year ───────────────────────────────────────────────────

    #[test]
    fn extracts_the_year_from_a_normalized_cve_id() {
        assert_eq!(parse_cve_year("CVE-2021-34527"), Some("2021"));
        assert_eq!(parse_cve_year("CVE-2026-72530"), Some("2026"));
    }

    #[test]
    fn rejects_an_id_with_no_cve_prefix() {
        assert_eq!(parse_cve_year("2021-34527"), None);
    }

    #[test]
    fn rejects_a_non_four_digit_year() {
        assert_eq!(parse_cve_year("CVE-21-34527"), None);
        assert_eq!(parse_cve_year("CVE-20211-34527"), None);
    }

    #[test]
    fn rejects_a_bare_or_malformed_string() {
        assert_eq!(parse_cve_year("not-a-cve"), None);
        assert_eq!(parse_cve_year("CVE"), None);
        assert_eq!(parse_cve_year(""), None);
    }

    // ── parse_poc_repos ──────────────────────────────────────────────────

    #[test]
    fn collects_html_urls_from_repo_entries() {
        let json = serde_json::json!([
            {"html_url": "https://github.com/a/poc1", "full_name": "a/poc1", "stargazers_count": 5},
            {"html_url": "https://github.com/b/poc2", "full_name": "b/poc2", "stargazers_count": 1},
        ]);
        let urls = parse_poc_repos(&json).expect("parses");
        assert_eq!(
            urls,
            vec![
                PocRepo {
                    html_url: "https://github.com/a/poc1".to_string(),
                    stargazers_count: Some(5),
                    updated_at: None,
                },
                PocRepo {
                    html_url: "https://github.com/b/poc2".to_string(),
                    stargazers_count: Some(1),
                    updated_at: None,
                },
            ]
        );
    }

    #[test]
    fn stars_and_updated_at_are_kept_so_a_maintained_poc_can_be_told_from_a_dead_fork() {
        let json = serde_json::json!([{
            "html_url": "https://github.com/a/poc1",
            "full_name": "a/poc1",
            "stargazers_count": 42,
            "updated_at": "2024-03-15T10:00:00Z"
        }]);
        let urls = parse_poc_repos(&json).expect("parses");
        assert_eq!(urls[0].stargazers_count, Some(42));
        assert_eq!(urls[0].updated_at.as_deref(), Some("2024-03-15T10:00:00Z"));
    }

    #[test]
    fn a_missing_star_count_or_update_timestamp_does_not_drop_the_entry() {
        let json = serde_json::json!([{"html_url": "https://github.com/a/poc1"}]);
        let urls = parse_poc_repos(&json).expect("parses");
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].stargazers_count, None);
        assert_eq!(urls[0].updated_at, None);
    }

    #[test]
    fn caps_the_result_at_max_poc_urls() {
        let entries: Vec<serde_json::Value> = (0..30)
            .map(|i| serde_json::json!({"html_url": format!("https://github.com/x/poc{i}")}))
            .collect();
        let json = serde_json::Value::Array(entries);
        let urls = parse_poc_repos(&json).expect("parses");
        assert_eq!(urls.len(), MAX_POC_URLS);
    }

    #[test]
    fn a_non_array_body_is_an_error() {
        let json = serde_json::json!({"not": "an array"});
        assert!(parse_poc_repos(&json).is_err());
    }

    #[test]
    fn an_empty_array_parses_to_an_empty_list_not_an_error() {
        let json = serde_json::json!([]);
        assert_eq!(parse_poc_repos(&json), Ok(Vec::new()));
    }

    // ── poc_urls_to_yield ────────────────────────────────────────────────

    #[test]
    fn yield_carries_poc_urls_and_a_row_per_repo_with_star_count_and_last_update() {
        // Updated 2026-08-30: this tool used to write no rows at all, so `stargazersCount`/
        // `updatedAt` were reachable only through the payload patch this test still checks.
        let repos = vec![PocRepo {
            html_url: "https://github.com/a/poc1".to_string(),
            stargazers_count: Some(7),
            updated_at: Some("2024-03-15T10:00:00Z".to_string()),
        }];
        let produced = poc_urls_to_yield(&repos);
        assert_eq!(
            produced.payload_patch,
            serde_json::json!({ "pocUrls": [{
                "htmlUrl": "https://github.com/a/poc1",
                "stargazersCount": 7,
                "updatedAt": "2024-03-15T10:00:00Z"
            }] })
        );
        assert_eq!(produced.rows.len(), 1);
        assert_eq!(produced.rows[0].label, "PoC repo");
        assert_eq!(
            produced.rows[0].href.as_deref(),
            Some("https://github.com/a/poc1")
        );
        assert!(produced.rows[0].value.contains("7"));
        assert!(produced.rows[0].value.contains("2024-03-15T10:00:00Z"));
    }

    // ── repo_owner / poc_owner_children ─────────────────────────────────

    #[test]
    fn repo_owner_splits_full_name_into_the_owner_segment() {
        let entry = serde_json::json!({
            "html_url": "https://github.com/DenizSe/CVE-2021-34527",
            "full_name": "DenizSe/CVE-2021-34527"
        });
        assert_eq!(
            repo_owner(&entry, "https://github.com/DenizSe/CVE-2021-34527"),
            Some("DenizSe".to_string())
        );
    }

    #[test]
    fn repo_owner_falls_back_to_the_html_url_path_when_full_name_is_absent() {
        let entry = serde_json::json!({ "html_url": "https://github.com/someone/exploit" });
        assert_eq!(
            repo_owner(&entry, "https://github.com/someone/exploit"),
            Some("someone".to_string())
        );
    }

    #[test]
    fn poc_owner_children_emits_a_username_child_per_owner() {
        let json = serde_json::json!([
            {"html_url": "https://github.com/a/poc1", "full_name": "a/poc1"},
        ]);
        let children = poc_owner_children(&json).expect("parses");
        assert_eq!(
            children,
            vec![ChildSeed {
                oz_type: OzType::Username,
                value: "a".to_string(),
                note: Some("published a PoC repo for this CVE on GitHub".to_string()),
            }]
        );
    }

    #[test]
    fn the_same_owner_publishing_two_pocs_dedupes_to_one_child() {
        let json = serde_json::json!([
            {"html_url": "https://github.com/a/poc1", "full_name": "a/poc1", "stargazers_count": 3},
            {"html_url": "https://github.com/a/poc2", "full_name": "a/poc2", "stargazers_count": 9},
            {"html_url": "https://github.com/a/poc1", "full_name": "A/poc1", "stargazers_count": 1},
        ]);
        let children = poc_owner_children(&json).expect("parses");
        assert_eq!(
            children.len(),
            1,
            "dedup must be case-insensitive — GitHub usernames are"
        );
        assert_eq!(children[0].value, "a");
    }

    #[test]
    fn owners_are_ordered_by_stargazers_count_descending_before_the_cap() {
        let json = serde_json::json!([
            {"html_url": "https://github.com/low/poc", "full_name": "low/poc", "stargazers_count": 1},
            {"html_url": "https://github.com/high/poc", "full_name": "high/poc", "stargazers_count": 50},
        ]);
        let children = poc_owner_children(&json).expect("parses");
        assert_eq!(
            children
                .iter()
                .map(|c| c.value.as_str())
                .collect::<Vec<_>>(),
            vec!["high", "low"],
            "the most-starred repo's owner must survive first if the cap is ever hit"
        );
    }

    #[test]
    fn owner_children_are_capped_at_max_poc_owners() {
        let entries: Vec<serde_json::Value> = (0..30)
            .map(|i| {
                serde_json::json!({
                    "html_url": format!("https://github.com/owner{i}/poc"),
                    "full_name": format!("owner{i}/poc"),
                })
            })
            .collect();
        let json = serde_json::Value::Array(entries);
        let children = poc_owner_children(&json).expect("parses");
        assert_eq!(children.len(), MAX_POC_OWNERS);
    }

    #[test]
    fn an_entry_with_no_owner_information_is_skipped_not_fabricated() {
        let json = serde_json::json!([{ "html_url": "not a url", "stargazers_count": 5 }]);
        let children = poc_owner_children(&json).expect("parses");
        assert!(children.is_empty());
    }
}
