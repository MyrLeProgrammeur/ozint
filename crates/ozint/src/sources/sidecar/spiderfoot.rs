//! `sidecar-spiderfoot` — a broad, passive OSINT sweep for `entity-domain` and `entity-ip`,
//! offered as `dom-spiderfoot`/`ip-spiderfoot`. Runs against a local SpiderFoot container
//! (`smicallef/spiderfoot`, MIT) — see `crates/ozint/docker/docker-compose.yml`, which
//! builds it straight from the upstream Dockerfile (no pre-built Docker Hub image exists under
//! the project's own name — verified 2026-08-25, see the compose file's own comment).
//!
//! ## The API, read from `sfwebui.py`/`spiderfoot/db.py` and confirmed against `db.py`'s own
//! status-string literals
//!
//! SpiderFoot's real HTTP surface is a set of CherryPy endpoints under `/`, not a
//! `/api?...`-shaped JSON-RPC surface — describing it as "REST :5001" undersells the shape a
//! little, but the port and the fire-and-poll model are exactly right:
//!
//! - `POST /startscan` (form body `scanname`, `scantarget`, `modulelist`, `typelist`,
//!   `usecase`, `Accept: application/json`) → `["SUCCESS", "<scanId>"]` or
//!   `["ERROR", "<message>"]`. **All five fields are required** — `sfwebui.py`'s
//!   `startscan(self, scanname, scantarget, modulelist, typelist, usecase)` has no
//!   defaults, and CherryPy's dispatcher answers a bare `404` (not a `400`/error body) when
//!   any is missing from the form, which cost real time to diagnose against the running
//!   container before the actual required-field shape was found. `modulelist`/`typelist` are
//!   sent empty so `usecase` alone selects the module set.
//!   `usecase=Passive` is used deliberately — SpiderFoot's own module grouping distinguishes
//!   `Passive` (no data ever sent to or through the target) from `Footprint`/`Investigate`/
//!   `all`, and nothing in this crate's product decisions asks for an active-probe default.
//!   See "Why `Passive`"
//!   below — **and note the capital P**: `startscan` matches `usecase` against each module's
//!   own `group` list (`["Investigate", "Passive"]`, read straight off a loaded module in the
//!   running container), which is title-cased. A lowercase `passive` — the value this crate's
//!   own first draft used — silently resolves to *zero*
//!   modules and a `["ERROR", "Incorrect usage: no modules specified for scan."]` response,
//!   not a 4xx; verified by direct call against the real container 2026-08-25 before this was
//!   caught. `all` is not case-sensitive (checked with `==`, not membership) and was the value
//!   that first revealed the container was reachable — precisely the kind of thing this
//!   crate's own "measured, not assumed" convention exists to catch.
//! - `GET /scanstatus?id=<id>` → `[name, target, created, started, ended, status, riskmatrix]`.
//!   `status` (index 5) is one of `STARTING`/`RUNNING`/`FINISHED`/`ABORTED`/`ERROR-FAILED`,
//!   per `sf.py`'s own terminal-state check (`["ERROR-FAILED", "ABORT-REQUESTED", "ABORTED",
//!   "FINISHED"]`) — the three this tool treats as terminal.
//! - `GET /scaneventresultsunique?id=<id>&eventType=ALL` → `[[data, type, count], ...]`, read
//!   straight from the results table (`scanResultEventUnique`) regardless of whether the scan
//!   has finished — this is what makes the poll-budget below safe to cut short, see next.
//!
//! ## The poll-shape mismatch, and how it's resolved here
//!
//! SpiderFoot's poll shape (start-scan/poll) doesn't fit the fire-and-settle layer model —
//! resolved by bounding the wait (~90s) and falling back to a refreshable/re-pollable node.
//! This tool bounds the wait at [`POLL_BUDGET`], polling `/scanstatus` every
//! [`POLL_INTERVAL`]. What it does **not** need is a new "pending" [`ToolOutcome`] variant for
//! the case where the budget runs out before the scan reaches a terminal state:
//! `scaneventresultsunique` reads whatever SpiderFoot has already written to its own database,
//! live, independent of scan status — so a still-`RUNNING` scan at the 90s mark already has
//! real, partial results to report, the same "truncated but genuine" shape
//! `sidecar::maigret` settles on for its own stream budget. The **"refreshable, re-pollable
//! node"** half of this resolution is just this crate's existing refresh path:
//! hitting refresh re-dispatches this tool, which starts a *fresh*
//! SpiderFoot scan rather than resuming the truncated one — SpiderFoot's API has no "resume",
//! and this crate's `ToolCtx::bypass` contract has never meant anything other than "run it
//! again," which is the honest thing to do here too.
//!
//! **On cancellation**, this tool best-effort `POST /stopscan?id=<id>`s the running scan
//! rather than just walking away from it — SpiderFoot keeps running server-side otherwise, and
//! this is a fire-and-poll job, not a request this crate can abort by
//! closing a connection. `stopscan` needs a request body at all (even empty) or CherryPy
//! answers `411 Length Required` before the handler ever runs — verified live; a bare
//! zero-byte `POST` with no body triggers it.
//!
//! ## Why `Passive`
//!
//! The "do not build" list explicitly keeps Maigret,
//! SpiderFoot and friends out of the Autofire blanket-consent gate that DeHashed/FaceCheck/etc.
//! sit behind — this tool is not treated as more sensitive than any other keyless-adjacent
//! source in the catalogue. But it *is* the first tool in this crate whose underlying engine
//! can, if configured differently, actively touch the target (port scans, brute-force
//! subdomain resolution) rather than only reading third-party indexes — so this dispatcher
//! pins `usecase=Passive` rather than exposing SpiderFoot's own broader defaults, matching this
//! crate's posture everywhere else (`geo-overpass`/`dom-certspotter`/… all read, none probe).
//!
//! ## Why one dispatcher serves two `OzType`s
//!
//! Same pattern `directory::run_dir_tiles` already uses for `dir-tiles-person`/
//! `dir-tiles-entity`: SpiderFoot's `targetTypeFromString` already tells a domain from an IP
//! from the string alone, so there is nothing type-specific for this crate to special-case —
//! [`run_spiderfoot`] takes the value as-is and lets the sidecar classify it.

use std::time::Duration;

use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const DEFAULT_BASE_URL: &str = "http://localhost:5001";

/// Total time this tool will wait for `/startscan` to reach a terminal `scanstatus`, polling
/// at [`POLL_INTERVAL`]. See the module doc for why running out of budget is not treated as a
/// failure — whatever `scaneventresultsunique` already holds at that point is reported as a
/// genuine, if partial, finding.
const POLL_BUDGET: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_secs(3);

const TERMINAL_STATUSES: &[&str] = &["FINISHED", "ABORTED", "ERROR-FAILED"];

/// One `[data, type, count]` row from `scaneventresultsunique`.
fn parse_unique_row(row: &serde_json::Value) -> Option<OzRow> {
    let arr = row.as_array()?;
    let data = arr.first()?.as_str()?;
    let event_type = arr.get(1)?.as_str()?;
    let count = arr.get(2).and_then(|v| v.as_u64()).unwrap_or(1);
    Some(OzRow {
        label: event_type.to_string(),
        value: if count > 1 {
            format!("{data} (\u{d7}{count})")
        } else {
            data.to_string()
        },
        ..Default::default()
    })
}

fn results_to_yield(rows: Vec<OzRow>, truncated: bool) -> ToolYield {
    let mut rows = rows;
    if truncated {
        rows.push(OzRow {
            label: "SpiderFoot sweep".to_string(),
            value: format!(
                "still running after {}s — {} finding{} so far; refresh this node to poll again",
                POLL_BUDGET.as_secs(),
                rows.len(),
                if rows.len() == 1 { "" } else { "s" }
            ),
            ..Default::default()
        });
    }
    ToolYield {
        rows,
        ..Default::default()
    }
}

/// Best-effort `POST /stopscan?id=<id>`, ignoring the outcome — called when this tool is
/// giving up on a scan (cancelled, or the poll budget ran out) so the container doesn't keep
/// grinding through an unread scan. A `stopscan` needs a request body at all (even empty) or
/// CherryPy answers `411 Length Required` before the handler runs — verified live; the empty
/// form below exists specifically to supply one.
async fn stop_scan(base: &str, scan_id: &str) {
    let _ = super::sidecar_request(
        reqwest::Method::POST,
        &format!("{base}/stopscan?id={}", urlencoding::encode(scan_id)),
        Some(&[]),
        Duration::from_secs(5),
    )
    .await;
}

async fn fetch_unique_results(base: &str, scan_id: &str) -> Result<Vec<OzRow>, ToolOutcome> {
    let url = format!(
        "{base}/scaneventresultsunique?id={}&eventType=ALL",
        urlencoding::encode(scan_id)
    );
    let json =
        super::sidecar_request(reqwest::Method::GET, &url, None, Duration::from_secs(15)).await?;
    let Some(rows) = json.as_array() else {
        return Err(ToolOutcome::ParseError {
            message: "SpiderFoot's scaneventresultsunique did not return a JSON array".to_string(),
        });
    };
    Ok(rows.iter().filter_map(parse_unique_row).collect())
}

/// Runs `sidecar-spiderfoot` against `value` (a domain or an IP — SpiderFoot classifies it).
/// Reaches `SPIDERFOOT_SIDECAR_URL` (default [`DEFAULT_BASE_URL`]) directly via
/// `ozint_core::http::client()` — see `sidecar::mod`'s doc for why that bypasses
/// `safe_fetch_url` deliberately.
pub async fn run_spiderfoot(value: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let base = super::sidecar_base_url("SPIDERFOOT_SIDECAR_URL", DEFAULT_BASE_URL);

    let start = super::sidecar_request(
        reqwest::Method::POST,
        &format!("{base}/startscan"),
        // `modulelist`/`typelist` must be present (even empty) or CherryPy 404s the whole
        // call before `startscan`'s own body runs — see the module doc. `usecase` is
        // capital-`Passive`, matching the module `group` list it's checked against.
        Some(&[
            ("scanname", value),
            ("scantarget", value),
            ("modulelist", ""),
            ("typelist", ""),
            ("usecase", "Passive"),
        ]),
        Duration::from_secs(15),
    )
    .await;

    let start_json = match start {
        Ok(json) => json,
        Err(outcome) => return DispatchOutcome::Ran(outcome, None),
    };
    let Some(arr) = start_json.as_array() else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "SpiderFoot's /startscan did not return a JSON array".to_string(),
            },
            None,
        );
    };
    if arr.first().and_then(|v| v.as_str()) != Some("SUCCESS") {
        let message = arr
            .get(1)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown /startscan error")
            .to_string();
        return DispatchOutcome::Ran(
            ToolOutcome::HttpError {
                status: 0,
                message: Some(message),
            },
            None,
        );
    }
    let Some(scan_id) = arr.get(1).and_then(|v| v.as_str()) else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "SpiderFoot's /startscan reported SUCCESS with no scan id".to_string(),
            },
            None,
        );
    };
    let scan_id = scan_id.to_string();

    let deadline = tokio::time::Instant::now() + POLL_BUDGET;
    let mut terminal = false;

    loop {
        if let Some(cancel) = &ctx.cancel
            && cancel.is_cancelled()
        {
            stop_scan(&base, &scan_id).await;
            return DispatchOutcome::Cancelled;
        }
        if tokio::time::Instant::now() >= deadline {
            stop_scan(&base, &scan_id).await;
            break;
        }

        let status_url = format!("{base}/scanstatus?id={}", urlencoding::encode(&scan_id));
        // A transient status-poll failure does not end the sweep — the scan itself is still
        // running server-side regardless of whether this one poll answered. `Err` is dropped
        // deliberately: keep trying within the remaining budget rather than giving up on the
        // first hiccup.
        if let Ok(json) = super::sidecar_request(
            reqwest::Method::GET,
            &status_url,
            None,
            Duration::from_secs(10),
        )
        .await
        {
            let status = json
                .as_array()
                .and_then(|a| a.get(5))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if TERMINAL_STATUSES.contains(&status) {
                terminal = true;
                break;
            }
        }

        tokio::time::sleep(
            POLL_INTERVAL.min(deadline.saturating_duration_since(tokio::time::Instant::now())),
        )
        .await;
    }

    let rows = match fetch_unique_results(&base, &scan_id).await {
        Ok(rows) => rows,
        Err(outcome) => return DispatchOutcome::Ran(outcome, None),
    };

    let count = rows.len() as u32;
    let produced = results_to_yield(rows, !terminal);
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
    fn parses_a_unique_result_row_with_a_count_above_one() {
        let row = serde_json::json!(["mail@example.com", "EMAILADDR", 3]);
        let parsed = parse_unique_row(&row).expect("parses");
        assert_eq!(parsed.label, "EMAILADDR");
        assert_eq!(parsed.value, "mail@example.com (\u{d7}3)");
    }

    #[test]
    fn a_count_of_one_is_not_annotated() {
        let row = serde_json::json!(["1.2.3.4", "IP_ADDRESS", 1]);
        let parsed = parse_unique_row(&row).expect("parses");
        assert_eq!(parsed.value, "1.2.3.4");
    }

    #[test]
    fn a_malformed_row_is_skipped_not_a_parse_error() {
        assert!(parse_unique_row(&serde_json::json!(["only one field"])).is_none());
        assert!(parse_unique_row(&serde_json::json!("not even an array")).is_none());
    }

    #[test]
    fn truncated_results_get_an_appended_note_terminal_ones_dont() {
        let rows = vec![OzRow {
            label: "IP_ADDRESS".to_string(),
            value: "1.2.3.4".to_string(),
            ..Default::default()
        }];
        let terminal = results_to_yield(rows.clone(), false);
        assert_eq!(terminal.rows.len(), 1);

        let truncated = results_to_yield(rows, true);
        assert_eq!(truncated.rows.len(), 2);
        assert!(
            truncated
                .rows
                .last()
                .unwrap()
                .label
                .contains("SpiderFoot sweep")
        );
    }

    #[test]
    fn yield_never_writes_a_payload_patch() {
        // Same reasoning as `sidecar::maigret`: this tool's findings are heterogeneous
        // (any SpiderFoot event type), so there is no single `DomainPayload`/`IpPayload`
        // field they could honestly own — they surface as rows only.
        let produced = results_to_yield(vec![], false);
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }

    #[tokio::test]
    async fn a_sidecar_that_is_not_running_reports_an_honest_connection_failure() {
        unsafe { std::env::set_var("SPIDERFOOT_SIDECAR_URL", "http://127.0.0.1:1") };
        let outcome = run_spiderfoot("example.com", &crate::sources::ToolCtx::default()).await;
        unsafe { std::env::remove_var("SPIDERFOOT_SIDECAR_URL") };
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
    #[ignore = "needs the real spiderfoot sidecar running (docker compose up -d)"]
    async fn live_spiderfoot_sweep_against_example_com() {
        let ctx = crate::sources::ToolCtx::default();
        let outcome = run_spiderfoot("example.com", &ctx).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(y)) => {
                println!(
                    "LIVE SPIDERFOOT: {count} rows, first 3: {:?}",
                    &y.rows[..y.rows.len().min(3)]
                );
                assert!(count > 0);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
