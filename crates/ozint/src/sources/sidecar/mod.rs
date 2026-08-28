//! The uniform contract for the three optional local Docker sidecars
//! this crate can escalate to: [`maigret`] (`entity-username`'s deep-sweep tier),
//! [`spiderfoot`] (a broad, expensive sweep offered to `entity-domain` and `entity-ip`), and
//! [`holehe`] (`entity-email`'s account-existence sweep).
//!
//! `crates/ozint/docker/docker-compose.yml` runs both — `docker compose -f
//! crates/ozint/docker/docker-compose.yml up -d`. Neither tool in this module requires
//! it: with no container listening, the connection attempt below fails honestly (see "What
//! not-deployed looks like" further down) and the rest of the crate is unaffected, per this
//! crate's standing convention for `AccessTier::Sidecar`/`LocalOnly` tools that a missing
//! capability shows as configured-but-off, not vanished (`img-exif`, `phone-local-normalize`).
//!
//! ## Why these two calls bypass `ToolCtx::fetch` / `fetch::oz_fetch` entirely
//!
//! Every other tool in this crate reaches the network through `fetch::oz_fetch`, whose entire
//! point is `ozint_core::net::safe_fetch_url` — screen out localhost/private/link-local
//! targets before a request goes out, because the URL being fetched is built from analyst
//! input or a third party's response, and could otherwise be steered at an internal service. A
//! sidecar is the opposite case: the target is `MAIGRET_SIDECAR_URL` / `SPIDERFOOT_SIDECAR_URL`
//! — an **operator-set config value**, never derived from investigation data — and it is
//! *supposed* to resolve to `localhost`. That is the entire meaning of `AccessTier::Sidecar`:
//! "reached over the network, but a network this installation itself stood up." Routing it
//! through `safe_fetch_url` would make every call answer `Forbidden` unconditionally, which is
//! a worse lie than the one this module is built to avoid — it would read as "blocked by
//! policy" when the true state is "nothing is listening here, or it is, and it just answered."
//! Both tools therefore call [`ozint_core::http::client()`] directly: the same shared
//! connection pool `oz_fetch` itself is built on, just without the public-target screen that
//! does not apply to a config-controlled local address.
//!
//! ## What "not deployed" looks like, and why no new `ToolOutcome` variant exists for it
//!
//! With no container running, a connect attempt to `localhost:PORT` fails at the TCP layer —
//! `reqwest` reports a connection-refused error. [`sidecar_request`] folds that into
//! `ToolOutcome::HttpError { status: 0, .. }`, the exact status-zero convention
//! `sources::fold_fetch_failure` already uses for `OzOutcome::TransportError` (a DNS failure, a
//! reset connection): a sidecar that isn't running and a public host that's unreachable are the
//! same *kind* of fact to this crate's taxonomy — an attempt was made, nothing answered.
//!
//! Considered and rejected: a dedicated `SkippedSidecarAbsent` variant. `SkippedNoKey` is a
//! **pre-dispatch** refusal — the tool never attempts a call because `registry::resolve`
//! already knows the env var is unset. A sidecar has no such gate: `MAIGRET_SIDECAR_URL`
//! always resolves to *something* (a default when unset), so the tool always genuinely
//! attempts the connection, and the outcome is always a real attempt's result — never a skip.
//! `HttpError{status:0}` already says exactly that, honestly, without inventing a 15th variant
//! for a fact the taxonomy already has a name for. This mirrors `outcome.rs`'s own restraint:
//! a new variant earns its place only for a genuinely new *kind* of fact, and "the network call
//! failed" is not new.
//!
//! ## Why no `SkippedNoKey`-style pre-check either
//!
//! `registry::ToolDef::env_vars` gates on a **credential** — its absence is a fact about
//! configuration, known before any request is attempted, and `resolve()` reports it without
//! ever dispatching. A sidecar base URL is not a credential: there is nothing to "arm", only
//! somewhere to try. So both tools here declare `env_vars: &[]` (like every other
//! keyless/local tool in the catalogue) and let the connection attempt itself be the source of
//! truth — `is_armed`/`resolve` treat them as always-runnable, and reaching for the actual
//! container is what tells the analyst whether it is really there.

use std::time::Duration;

use crate::outcome::ToolOutcome;

pub mod blackbird;
pub mod holehe;
pub mod maigret;
pub mod spiderfoot;

/// Reads `env_var`, falling back to `default` when unset or empty. The sidecar-tier analogue
/// of `registry::ToolDef::env_vars`, except — per the module doc — a missing override is never
/// a reason to skip: every deployment has *some* address to try.
pub fn sidecar_base_url(env_var: &str, default: &str) -> String {
    ozint_core::config::or_default(env_var, default)
}

/// One request to a local sidecar, deliberately bypassing `ozint_core::net::safe_fetch_url` —
/// see the module doc for why that is correct here rather than a hole. `body_form` is sent as
/// `application/x-www-form-urlencoded` when present — both Maigret's and SpiderFoot's real
/// APIs take form-encoded POST bodies, not JSON, per `sfwebui.py`/`maigret/web/app.py` read
/// directly off each project's source (see `maigret.rs`/`spiderfoot.rs` module docs for the
/// verification).
pub async fn sidecar_request(
    method: reqwest::Method,
    url: &str,
    body_form: Option<&[(&str, &str)]>,
    timeout: Duration,
) -> Result<serde_json::Value, ToolOutcome> {
    let client = ozint_core::http::client();
    let mut req = client
        .request(method, url)
        .timeout(timeout)
        .header("Accept", "application/json");
    if let Some(form) = body_form {
        req = req.form(form);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) if e.is_timeout() => {
            return Err(ToolOutcome::Timeout {
                after_ms: timeout.as_millis() as u64,
            });
        }
        Err(e) => {
            return Err(ToolOutcome::HttpError {
                status: 0,
                message: Some(format!("sidecar unreachable at {url}: {e}")),
            });
        }
    };

    let status = resp.status();
    if !status.is_success() {
        return Err(ToolOutcome::HttpError {
            status: status.as_u16(),
            message: None,
        });
    }

    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return Err(ToolOutcome::ParseError {
                message: format!("could not read sidecar response body: {e}"),
            });
        }
    };
    serde_json::from_slice(&bytes).map_err(|e| ToolOutcome::ParseError {
        message: format!("sidecar response was not JSON: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_base_url_falls_back_when_unset() {
        const VAR: &str = "OZINT_TEST_SIDECAR_UNSET_VAR";
        unsafe { std::env::remove_var(VAR) };
        assert_eq!(
            sidecar_base_url(VAR, "http://localhost:9999"),
            "http://localhost:9999"
        );
    }

    #[test]
    fn sidecar_base_url_reads_the_override_when_set() {
        const VAR: &str = "OZINT_TEST_SIDECAR_SET_VAR";
        unsafe { std::env::set_var(VAR, "http://example.internal:1234") };
        assert_eq!(
            sidecar_base_url(VAR, "http://localhost:9999"),
            "http://example.internal:1234"
        );
        unsafe { std::env::remove_var(VAR) };
    }

    #[tokio::test]
    async fn a_request_to_nothing_listening_is_an_honest_transport_failure() {
        // Port 1 is a reserved, never-listening TCP port — the same "guaranteed unreachable"
        // trick `sources::mod`'s own cache tests use for `UNREACHABLE`, chosen so this test
        // never depends on whether a real sidecar happens to be running on this machine.
        let outcome = sidecar_request(
            reqwest::Method::GET,
            "http://127.0.0.1:1/",
            None,
            Duration::from_secs(2),
        )
        .await;
        match outcome {
            Err(ToolOutcome::HttpError {
                status: 0,
                message: Some(msg),
            }) => {
                assert!(msg.contains("sidecar unreachable"));
            }
            other => {
                panic!("expected a status-0 HttpError for an unreachable sidecar, got {other:?}")
            }
        }
    }
}
