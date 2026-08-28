//! `sidecar-holehe` — `entity-email`'s account-existence sweep, the single highest-value gap
//! the 2026-08-25 category audit found: this crate's whole `entity-email` category was one
//! Gravatar lookup, while a commercial competitor (EmailOSINT.org) returned 12 confirmed
//! account registrations for the same seed email by probing password-reset/signup side
//! channels. `holehe` (`github.com/megadose/holehe`, GPLv3, actively maintained) is the
//! open-source tool that does exactly that, keylessly, across ~120 sites.
//!
//! ## Why this is a sidecar, not a Rust port
//!
//! Reimplementing holehe's ~120 site-specific probes in Rust would mean porting and then
//! keeping in sync ~120 bespoke request/response fingerprints as sites change their auth
//! flows — a maintenance burden with no upside over calling the upstream project directly.
//! `crates/ozint/docker/holehe/` builds a small Docker image (no official server image
//! exists — holehe ships a CLI only) wrapping holehe's CLI behind a one-endpoint Flask shim,
//! the same "own the missing server, not the tool's logic" shape `soxoj/maigret:web` already
//! provides pre-built for `maigret.rs`. GPLv3 is called out-of-process here (a sidecar over
//! HTTP), never linked, the same posture already accepted for Maigret's MIT image.
//!
//! ## The shim's shape, and why CSV
//!
//! `holehe --help` has no `--json` flag — only `-C`/`--csv`. The shim
//! (`crates/ozint/docker/holehe/app.py`) runs `holehe <email> --only-used --no-color -C`
//! in a fresh temp directory per request and reads the CSV it writes, exposed as
//! `GET /check?email=`. Verified by starting the real container and calling it 2026-08-25
//! against a real, consenting test address: 121 sites checked in ~11s, 4 genuine `exists:true`
//! hits (independently corroborating account registrations the address's owner confirmed).
//!
//! ## `rateLimit`, and why a flagged row is dropped, not trusted as `false`
//!
//! Each CSV row carries its own `rateLimit` boolean — holehe's own signal that a site refused
//! to answer cleanly for this attempt, distinct from `exists`. A rate-limited site's `exists`
//! value is not a genuine finding (some sites default `false` under rate-limiting, not "we
//! checked and it's unused"), so [`parse_holehe_results`] excludes rate-limited rows from the
//! confirmed-hit list entirely rather than reporting a maybe-false negative as though it were
//! verified — the same "empty is a finding, never a disguised failure" doctrine `outcome.rs`
//! states for the whole crate, applied one level down inside a single tool's own row set.
//!
//! ## Why this writes only `rows`, never a payload field
//!
//! `EmailPayload` has no "accounts" field, and inventing one collision-free is unnecessary
//! when the row-only pattern `sidecar-maigret`/`phone-local-normalize` already use fits: each
//! confirmed site becomes an [`OzRow`], landing in the node's detail rows.

use std::time::Duration;

use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const DEFAULT_BASE_URL: &str = "http://localhost:5100";

/// This crate's own sidecar timeout ceiling, one layer above the shim's internal 90s budget
/// (`app.py`'s `subprocess.run(..., timeout=90)`) — long enough to let the shim's own timeout
/// fire and return a clean `504` first, rather than this side giving up first and reporting a
/// less specific transport failure for what is really a holehe-side timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(100);

/// One row from holehe's CSV output, narrowed to what this tool keeps. `email_recovery`/
/// `phone_number` are populated by a minority of holehe's ~150 modules (confirmed by reading
/// the source: `software/adobe.py` — unmasked, `products/samsung.py`,
/// `social_media/odnoklassniki.py`, `mails/mail_ru.py` — masked or list-shaped) from a
/// password-recovery-challenge response the module already fetches to answer `exists`; every
/// other module hardcodes both to `None`. The shim already threads these through
/// (`docker/holehe/app.py`'s `row.get("emailrecovery") or None`); this struct used to drop them
/// on the floor after that.
///
/// `others` is holehe's per-module free-form extra bag (e.g. account creation date), kept as
/// whatever nested object the shim parsed off its CSV — never flattened/normalized on this
/// side either. `frequent_rate_limit` is a module-level flag (holehe's own static hint that a
/// given site is known to rate-limit often) distinct from the per-request `rateLimit` flag
/// already used to filter hits above.
#[derive(Debug, Clone, Default, PartialEq)]
struct HoleheHit {
    name: String,
    domain: String,
    method: String,
    email_recovery: Option<String>,
    phone_number: Option<String>,
    frequent_rate_limit: bool,
    others: Option<serde_json::Value>,
}

/// Parses the shim's `{"email": ..., "results": [...]}` body into the confirmed hits —
/// `exists: true` rows whose own `rateLimit` flag is `false`, per the module doc. Pure and
/// tested.
fn parse_holehe_results(json: &serde_json::Value) -> Result<Vec<HoleheHit>, String> {
    let results = json
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "holehe shim response is missing `results`".to_string())?;

    let hits = results
        .iter()
        .filter(|r| {
            r.get("exists").and_then(|v| v.as_bool()) == Some(true)
                && r.get("rateLimit").and_then(|v| v.as_bool()) != Some(true)
        })
        .filter_map(|r| {
            Some(HoleheHit {
                name: r.get("name").and_then(|v| v.as_str())?.to_string(),
                domain: r.get("domain").and_then(|v| v.as_str())?.to_string(),
                method: r
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                email_recovery: r
                    .get("emailrecovery")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                phone_number: r
                    .get("phoneNumber")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                frequent_rate_limit: r
                    .get("frequentRateLimit")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                others: r.get("others").cloned().filter(|v| !v.is_null()),
            })
        })
        .collect();

    Ok(hits)
}

fn holehe_to_yield(hits: &[HoleheHit]) -> ToolYield {
    let mut rows = Vec::new();
    for h in hits {
        rows.push(OzRow {
            label: h.name.clone(),
            value: format!("account registered ({})", h.method),
            href: Some(format!("https://{}", h.domain)),
            ..Default::default()
        });
        if let Some(recovery) = &h.email_recovery {
            rows.push(OzRow {
                label: format!("{} · Recovery email", h.name),
                value: recovery.clone(),
                ..Default::default()
            });
        }
        if let Some(phone) = &h.phone_number {
            rows.push(OzRow {
                label: format!("{} · Phone", h.name),
                value: phone.clone(),
                ..Default::default()
            });
        }
        if h.frequent_rate_limit {
            rows.push(OzRow {
                label: format!("{} · Frequently rate-limited", h.name),
                value: "true".to_string(),
                ..Default::default()
            });
        }
        if let Some(others) = h.others.as_ref().and_then(|v| v.as_object()) {
            for (key, value) in others {
                rows.push(OzRow {
                    label: format!("{} · {key}", h.name),
                    value: match value {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    },
                    ..Default::default()
                });
            }
        }
    }
    ToolYield {
        rows,
        ..Default::default()
    }
}

/// Runs `sidecar-holehe` against `value` (an email address). Reaches `HOLEHE_SIDECAR_URL`
/// (default [`DEFAULT_BASE_URL`]) directly via [`super::sidecar_request`] — see `sidecar::mod`'s
/// doc for why that bypasses `safe_fetch_url` deliberately.
pub async fn run_holehe(value: &str, _ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let base = super::sidecar_base_url("HOLEHE_SIDECAR_URL", DEFAULT_BASE_URL);
    let url = format!("{base}/check?email={}", urlencoding::encode(value));

    let json = match super::sidecar_request(reqwest::Method::GET, &url, None, REQUEST_TIMEOUT).await
    {
        Ok(json) => json,
        Err(outcome) => return DispatchOutcome::Ran(outcome, None),
    };

    let hits = match parse_holehe_results(&json) {
        Ok(hits) => hits,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    let count = hits.len() as u32;
    let produced = holehe_to_yield(&hits);
    if count == 0 {
        DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(produced))
    } else {
        DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(produced))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_response() -> serde_json::Value {
        serde_json::json!({
            "email": "test@example.com",
            "results": [
                {"name": "spotify", "domain": "spotify.com", "method": "login", "exists": true, "rateLimit": false},
                {"name": "twitter", "domain": "twitter.com", "method": "login", "exists": true, "rateLimit": false},
                {"name": "adobe", "domain": "adobe.com", "method": "password recovery", "exists": false, "rateLimit": true},
                {"name": "amazon", "domain": "amazon.com", "method": "login", "exists": false, "rateLimit": false}
            ]
        })
    }

    #[test]
    fn keeps_only_confirmed_non_rate_limited_hits() {
        let hits = parse_holehe_results(&sample_response()).expect("parses");
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().any(|h| h.name == "spotify"));
        assert!(hits.iter().any(|h| h.name == "twitter"));
    }

    #[test]
    fn a_rate_limited_exists_true_row_is_excluded_not_trusted() {
        // A pathological case not in the sample above: exists:true but rateLimit:true must
        // still be dropped — the flag governs trust regardless of which way `exists` leans.
        let json = serde_json::json!({
            "results": [
                {"name": "flaky", "domain": "flaky.example", "method": "login", "exists": true, "rateLimit": true}
            ]
        });
        let hits = parse_holehe_results(&json).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn a_response_missing_results_is_rejected() {
        assert!(parse_holehe_results(&serde_json::json!({})).is_err());
    }

    #[test]
    fn no_confirmed_hits_is_a_valid_empty_parse() {
        let json = serde_json::json!({
            "results": [
                {"name": "x", "domain": "x.example", "method": "login", "exists": false, "rateLimit": false}
            ]
        });
        assert_eq!(parse_holehe_results(&json), Ok(Vec::new()));
    }

    #[test]
    fn yield_builds_one_row_per_hit_with_a_working_link() {
        let hits = vec![HoleheHit {
            name: "spotify".to_string(),
            domain: "spotify.com".to_string(),
            method: "login".to_string(),
            email_recovery: None,
            phone_number: None,
            ..Default::default()
        }];
        let produced = holehe_to_yield(&hits);
        assert_eq!(produced.rows.len(), 1);
        assert_eq!(produced.rows[0].label, "spotify");
        assert_eq!(
            produced.rows[0].href.as_deref(),
            Some("https://spotify.com")
        );
    }

    #[test]
    fn yield_adds_a_row_per_recovery_field_when_present() {
        let hits = vec![HoleheHit {
            name: "adobe".to_string(),
            domain: "adobe.com".to_string(),
            method: "password recovery".to_string(),
            email_recovery: Some("j***@example.com".to_string()),
            phone_number: Some("+336******67".to_string()),
            ..Default::default()
        }];
        let produced = holehe_to_yield(&hits);
        assert_eq!(
            produced.rows.len(),
            3,
            "one existence row plus one per recovery field"
        );
        assert_eq!(produced.rows[1].label, "adobe · Recovery email");
        assert_eq!(produced.rows[1].value, "j***@example.com");
        assert_eq!(produced.rows[2].label, "adobe · Phone");
        assert_eq!(produced.rows[2].value, "+336******67");
    }

    #[test]
    fn parse_reads_recovery_fields_off_the_shim_response() {
        let json = serde_json::json!({
            "results": [
                {"name": "adobe", "domain": "adobe.com", "method": "password recovery", "exists": true, "rateLimit": false,
                 "emailrecovery": "j***@example.com", "phoneNumber": "+336******67"}
            ]
        });
        let hits = parse_holehe_results(&json).unwrap();
        assert_eq!(hits[0].email_recovery.as_deref(), Some("j***@example.com"));
        assert_eq!(hits[0].phone_number.as_deref(), Some("+336******67"));
    }

    #[test]
    fn parse_reads_others_and_frequent_rate_limit_off_the_shim_response() {
        let json = serde_json::json!({
            "results": [
                {"name": "adobe", "domain": "adobe.com", "method": "password recovery", "exists": true, "rateLimit": false,
                 "frequentRateLimit": true, "others": {"Date, time of the creation": "2020-01-01"}}
            ]
        });
        let hits = parse_holehe_results(&json).unwrap();
        assert!(hits[0].frequent_rate_limit);
        assert_eq!(
            hits[0]
                .others
                .as_ref()
                .and_then(|v| v.get("Date, time of the creation"))
                .and_then(|v| v.as_str()),
            Some("2020-01-01")
        );
    }

    #[tokio::test]
    async fn a_sidecar_that_is_not_running_reports_an_honest_connection_failure() {
        unsafe { std::env::set_var("HOLEHE_SIDECAR_URL", "http://127.0.0.1:1") };
        let outcome = run_holehe("someone@example.com", &crate::sources::ToolCtx::default()).await;
        unsafe { std::env::remove_var("HOLEHE_SIDECAR_URL") };
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
    #[ignore = "needs the real holehe sidecar running (docker compose up -d)"]
    async fn live_holehe_sweep_against_a_real_email() {
        let ctx = crate::sources::ToolCtx::default();
        let outcome = run_holehe("analyst@example.com", &ctx).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(y)) => {
                println!("LIVE HOLEHE: {count} rows: {:?}", y.rows);
                assert!(count > 0);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
