//! `oz_fetch(url, opts)`, the one HTTP client every OZINT tool call goes through.
//!
//! Every URL is screened by [`ozint_core::net::safe_fetch_url`] before anything is sent —
//! no exceptions, no bypass flag (the SSRF guard itself lives in `ozint-core` now; it used
//! to be a private `ozint-server` module, moved out as part of this same unit so this crate
//! could reach it — see `ozint_core::net`). HTML bodies are converted to plain text with
//! [`ozint_core::net::html_to_text`], reused verbatim rather than re-implemented.
//!
//! **Never throws.** [`oz_fetch`] always returns an [`OzOutcome`] — there is no `Result`
//! an OZINT tool could accidentally propagate into a 500. `OzOutcome` is a **minimal, local**
//! stand-in for the canonical 11-variant outcome union that [`crate::outcome::ToolOutcome`]
//! defines for a whole tool invocation — this module sits one layer below that: it reports what
//! happened to *one HTTP request* (including retries), and a tool wrapper folds that into a
//! `ToolOutcome`. See the doc comment on [`OzOutcome`] for the intended mapping.
//!
//! Retry policy: bounded exponential backoff, and **only** on the transient status classes
//! (429, 5xx) or a request timeout — a non-429 4xx is never retried. Response bodies are
//! streamed and the read is aborted past [`MAX_BODY_BYTES`] rather than buffered unbounded.

use std::time::{Duration, Instant};

use futures::StreamExt;
use ozint_core::net::{html_to_text, safe_fetch_url};
use reqwest::Method;
use url::Url;

// ─── Tunables ──────────────────────────────────────────────────────────────

/// Cap on a response body we will buffer in memory. OZINT tool responses are documents
/// (JSON API payloads, scraped HTML pages), not media — 8 MiB comfortably covers the largest
/// expected payload (a bloated HTML page, a large breach/JSON dump) while bounding memory use
/// per in-flight fetch: with dozens of tools fanning out per layer, an unbounded response
/// body from one adversarial or misbehaving upstream could otherwise exhaust process memory.
pub const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// Attempts beyond the first. Total attempts made for a request = `1 + MAX_RETRIES` (unless a
/// non-retryable outcome or cancellation ends it sooner).
pub const MAX_RETRIES: u32 = 3;

/// Base delay before the first retry. Doubles per subsequent retry (attempt 1 → 250ms,
/// attempt 2 → 500ms, attempt 3 → 1000ms, …), capped at [`MAX_BACKOFF_MS`].
const BASE_BACKOFF_MS: u64 = 250;

/// Ceiling on the exponential backoff so a source with many retries in flight doesn't push a
/// single tool call's total latency past what an analyst will wait for a layer to settle.
const MAX_BACKOFF_MS: u64 = 4_000;

/// Default per-attempt timeout. Deliberately shorter than the shared pool's blanket 30s
/// (`ozint_core::http::client`) so a slow OSINT source fails one attempt fast and retries,
/// rather than eating the whole budget on a single hang.
const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(12);

// ─── Cancellation ──────────────────────────────────────────────────────────

/// A cheap, cloneable cancellation signal for [`oz_fetch`], built on `tokio::sync::watch`.
///
/// The common idiom for this is `tokio_util::sync::CancellationToken`, but
/// `tokio-util` is not a direct dependency of `ozint` and this unit was told not to
/// add one. `watch` gives the same two operations `CancellationToken` is actually used for
/// here — flip a flag from one side, `await` it resolving on the other, with the state
/// staying resolved afterwards — without a new crate.
#[derive(Clone)]
pub struct CancelSignal(tokio::sync::watch::Receiver<bool>);

impl CancelSignal {
    /// Resolves once [`CancelHandle::cancel`] has been called (including if it already was).
    pub async fn cancelled(&mut self) {
        let _ = self.0.wait_for(|cancelled| *cancelled).await;
    }

    /// Non-blocking check, for a call site that only wants to poll rather than await.
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }
}

/// The producer half of a [`CancelSignal`] pair.
#[derive(Clone)]
pub struct CancelHandle(tokio::sync::watch::Sender<bool>);

impl CancelHandle {
    /// Builds a fresh, not-yet-cancelled handle/signal pair.
    pub fn new() -> (CancelHandle, CancelSignal) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (CancelHandle(tx), CancelSignal(rx))
    }

    /// Signals cancellation. Idempotent; every clone of the paired [`CancelSignal`] observes it.
    pub fn cancel(&self) {
        let _ = self.0.send(true);
    }
}

// ─── Request options ───────────────────────────────────────────────────────

/// Options for one [`oz_fetch`] call.
#[derive(Clone)]
pub struct OzFetchOptions {
    pub method: Method,
    /// Extra headers, applied after the shared pool's defaults.
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    /// Per-attempt timeout (not a total-call timeout — each retry gets a fresh one).
    pub timeout: Duration,
    /// Retries beyond the first attempt. `0` disables retrying entirely.
    pub max_retries: u32,
    /// Explicit User-Agent override. The shared pool (`ozint_core::http::client`) already
    /// sets `OZINT/<version>` on every request; leave this `None` unless a specific tool's
    /// upstream demands a different one — the override is deliberately opt-in and explicit
    /// per call rather than a blanket default, so such cases stay visible at the call site.
    pub user_agent_override: Option<String>,
    pub cancel: Option<CancelSignal>,
}

impl Default for OzFetchOptions {
    fn default() -> Self {
        Self {
            method: Method::GET,
            headers: Vec::new(),
            body: None,
            timeout: DEFAULT_ATTEMPT_TIMEOUT,
            max_retries: MAX_RETRIES,
            user_agent_override: None,
            cancel: None,
        }
    }
}

// ─── Response body ─────────────────────────────────────────────────────────

/// A successful response body, dispatched on its declared `Content-Type`.
///
/// `Serialize`/`Deserialize` exist for exactly one caller: the fetch cache stores a settled
/// response as a `serde_json::Value` (see [`crate::sources::ToolCtx::fetch`]). Nothing else
/// should serialize a body — it is not a wire type.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum OzBody {
    Json(serde_json::Value),
    /// `html_to_text`'s two outputs — the page title (140-char cap) and stripped body text.
    Html {
        title: String,
        text: String,
    },
    /// XML is not structurally parsed: `quick-xml` is not a dependency of this crate, so an
    /// XML body is carried as raw text for the caller to parse itself. Reported, not added.
    Xml(String),
    Text(String),
    /// A 2xx response with an empty body.
    Empty,
}

/// A settled (2xx, fully read, body dispatched) response.
///
/// See [`OzBody`] on why this is serializable: the tool cache round-trips it, nothing else.
/// `elapsed_ms`/`attempts` describe the call that *originally* filled the cache; a cache hit
/// replays them verbatim. No caller reads them for timing — a `ToolReport`'s `elapsed_ms` is
/// measured by the layer runtime around the whole dispatch, not taken from here.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OzResponse {
    pub status: u16,
    /// The screened URL actually requested (after `safe_fetch_url` parsing).
    pub url: String,
    pub body: OzBody,
    pub elapsed_ms: u128,
    /// Total attempts made, including the first (always ≥ 1).
    pub attempts: u32,
}

/// The outcome of one [`oz_fetch`] call. Never an `Err` — every branch a caller needs is a
/// variant here, including "the request itself was rejected before any network I/O happened".
///
/// Intended mapping onto `outcome.rs`'s `ToolOutcome` (owned by a different, concurrent
/// unit — not applied here): `Ok` becomes `OkWithResults`/`OkEmpty` depending on what the tool
/// found in the body; `Blocked`/`Forbidden`-shaped denials become `ToolOutcome::Forbidden`;
/// `Timeout` maps directly; `HttpError` maps directly (`body_snippet` → `message`);
/// `TransportError`/`TooLarge` have no exact match in the 11-variant union today and likely
/// fold into `ToolOutcome::HttpError`/`ParseError` with a synthesized message; `ParseError`
/// maps directly; `Cancelled` has no equivalent in the union (it is not a tool failure at
/// all, it is the caller stopping the investigation) and should short-circuit before a
/// `ToolOutcome` is even constructed.
///
/// Serializable for the tool cache only — see [`OzBody`]. Note that only the `Ok` variant is
/// ever *stored*: [`crate::sources::ToolCtx::fetch`] round-trips a failure through the cache's
/// error channel precisely so it is handed to concurrent followers without being persisted.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum OzOutcome {
    /// 2xx response, body parsed for its declared content-type.
    Ok(OzResponse),
    /// `safe_fetch_url` rejected the target before any network call was made.
    Blocked { url: String },
    /// Cancelled via `CancelSignal` before a response was obtained.
    Cancelled,
    /// Every attempt (first try + retries) timed out.
    Timeout { attempts: u32, elapsed_ms: u128 },
    /// The response body exceeded `MAX_BODY_BYTES`; the stream was aborted mid-read.
    TooLarge { cap_bytes: u64 },
    /// A non-retryable (or retry-exhausted) HTTP status.
    HttpError {
        status: u16,
        body_snippet: Option<String>,
    },
    /// A transport-level failure (DNS, connect, TLS, stream I/O) after retries exhausted.
    TransportError { message: String },
    /// A 2xx response whose body did not parse as its declared content-type.
    ParseError {
        content_type: String,
        message: String,
    },
}

// ─── Pure helpers (tested) ─────────────────────────────────────────────────

/// Whether an HTTP status belongs to the transient class this module retries: `429` or any
/// `5xx`. Every other status (including every other `4xx`) is never retried.
const fn is_transient_status(status: u16) -> bool {
    status == 429 || (status >= 500 && status <= 599)
}

/// Exponential backoff for the Nth retry (`attempt` is 1-based: the first retry is `1`),
/// doubling from [`BASE_BACKOFF_MS`] and capped at [`MAX_BACKOFF_MS`]. Pure and deterministic
/// (no jitter) so it stays cheaply testable; a jitter term can be layered on by the caller.
fn backoff_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(16); // 16 is already far past the cap
    let ms = BASE_BACKOFF_MS.saturating_mul(1u64 << shift);
    Duration::from_millis(ms.min(MAX_BACKOFF_MS))
}

/// Whether reading `incoming` more bytes on top of `accumulated` would cross `cap`.
const fn would_exceed_cap(accumulated: u64, incoming: usize, cap: u64) -> bool {
    accumulated.saturating_add(incoming as u64) > cap
}

/// Parses `bytes` per the (lowercased, parameter-stripped) `content_type`. Falls back to
/// [`OzBody::Text`] for anything unrecognized — matching the "content-type parsing" bullet's
/// four buckets (json/xml/html/text) without ever failing on an unknown or missing header.
fn dispatch_content_type(content_type: &str, bytes: &[u8]) -> Result<OzBody, String> {
    if bytes.is_empty() {
        return Ok(OzBody::Empty);
    }

    let kind = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if kind.contains("json") {
        let text = String::from_utf8_lossy(bytes);
        serde_json::from_str::<serde_json::Value>(&text)
            .map(OzBody::Json)
            .map_err(|e| e.to_string())
    } else if kind.contains("html") {
        let text = String::from_utf8_lossy(bytes);
        let (title, body_text) = html_to_text(&text);
        Ok(OzBody::Html {
            title,
            text: body_text,
        })
    } else if kind.contains("xml") {
        Ok(OzBody::Xml(String::from_utf8_lossy(bytes).into_owned()))
    } else {
        Ok(OzBody::Text(String::from_utf8_lossy(bytes).into_owned()))
    }
}

/// Screens `raw` through the shared SSRF guard, translating a rejection straight into the
/// [`OzOutcome`] variant the caller returns — no exceptions, no bypass flag.
fn screen_url(raw: &str) -> Result<Url, OzOutcome> {
    safe_fetch_url(raw).ok_or_else(|| OzOutcome::Blocked {
        url: raw.to_string(),
    })
}

// ─── The fetch itself (untested — see module docs) ─────────────────────────

/// What one body-read attempt produced, before it's folded into an [`OzOutcome`].
enum CapReadError {
    TooLarge,
    Cancelled,
    Transport(String),
}

async fn read_capped_body(
    resp: reqwest::Response,
    cap: u64,
    mut cancel: Option<&mut CancelSignal>,
) -> Result<Vec<u8>, CapReadError> {
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let next = if let Some(signal) = cancel.as_deref_mut() {
            tokio::select! {
                biased;
                _ = signal.cancelled() => return Err(CapReadError::Cancelled),
                chunk = stream.next() => chunk,
            }
        } else {
            stream.next().await
        };

        match next {
            None => return Ok(buf),
            Some(Ok(chunk)) => {
                if would_exceed_cap(buf.len() as u64, chunk.len(), cap) {
                    return Err(CapReadError::TooLarge);
                }
                buf.extend_from_slice(&chunk);
            }
            Some(Err(e)) => return Err(CapReadError::Transport(e.to_string())),
        }
    }
}

/// What the last failing attempt in the retry loop looked like, so the loop can report a
/// specific [`OzOutcome`] once retries are exhausted instead of an aggregate guess.
enum LastFailure {
    Timeout,
    Status(u16, Option<String>),
    Transport(String),
}

/// Fetches `url` through the shared HTTP pool, screened by the SSRF guard, with bounded
/// exponential-backoff retry on transient failures. Never returns an `Err` — see the module
/// docs and [`OzOutcome`] for why, and for how this is meant to be folded into a per-tool
/// `ToolOutcome` by the caller.
///
/// This `async fn` itself is intentionally left untested (repo convention for network code:
/// split a thin untested wrapper from pure, heavily-tested helpers) — `screen_url`,
/// `dispatch_content_type`, `is_transient_status`/backoff and the cap arithmetic above are
/// what carry the test coverage for this module's behaviour.
pub async fn oz_fetch(url: &str, opts: OzFetchOptions) -> OzOutcome {
    match fetch_raw(url, opts).await {
        Err(settled) => settled,
        Ok(raw) => match dispatch_content_type(&raw.content_type, &raw.bytes) {
            Ok(body) => OzOutcome::Ok(OzResponse {
                status: raw.status,
                url: raw.url,
                body,
                elapsed_ms: raw.elapsed_ms,
                attempts: raw.attempts,
            }),
            Err(message) => OzOutcome::ParseError {
                content_type: raw.content_type,
                message,
            },
        },
    }
}

/// A 2xx response, read to completion under the cap, with **nothing parsed**.
///
/// `content_type` is carried verbatim as the server declared it, and is deliberately not
/// authoritative about anything: what these bytes actually are is decided by sniffing them
/// (`crate::media::sniff_mime`). It is here so a caller can report the disagreement, not so a
/// caller can trust it.
#[derive(Debug, Clone)]
pub struct OzBytes {
    pub status: u16,
    /// The screened URL actually requested.
    pub url: String,
    /// The server's claim about the content type.
    pub content_type: String,
    pub bytes: Vec<u8>,
    pub elapsed_ms: u128,
    pub attempts: u32,
}

/// [`oz_fetch`] without the content-type dispatch: the raw bytes of a 2xx response.
///
/// This exists because [`OzBody`] has no binary variant and must not grow one — it is what
/// the fetch cache round-trips through `serde_json`, where a `Vec<u8>` becomes a JSON array
/// of integers. Byte ingress (proxying media bytes) is a different job with a different lifetime:
/// bytes go to the content-addressed store, not to the response cache.
///
/// What it explicitly does **not** do is open a second HTTP path. It is the same
/// `safe_fetch_url` screen, the same shared pool, the same [`MAX_BODY_BYTES`] cap and the same
/// retry policy as every other OZINT call — a second, separately-guarded egress path is
/// precisely how an SSRF screen ends up applied in three places and enforced in two.
///
/// The `Err` arm is a **settled outcome, not an error to propagate**: every failure mode is
/// already an [`OzOutcome`] variant, exactly as [`oz_fetch`]'s contract requires.
pub async fn oz_fetch_bytes(url: &str, opts: OzFetchOptions) -> Result<OzBytes, OzOutcome> {
    fetch_raw(url, opts).await
}

async fn fetch_raw(url: &str, mut opts: OzFetchOptions) -> Result<OzBytes, OzOutcome> {
    let started = Instant::now();

    let parsed = screen_url(url)?;

    let client = ozint_core::http::client();
    let mut attempt: u32 = 0;
    let mut timed_out_attempts: u32 = 0;
    let mut last_failure: Option<LastFailure>;

    loop {
        attempt += 1;

        if let Some(cancel) = opts.cancel.as_ref()
            && cancel.is_cancelled()
        {
            return Err(OzOutcome::Cancelled);
        }

        let mut req = client
            .request(opts.method.clone(), parsed.clone())
            .timeout(opts.timeout);
        for (k, v) in &opts.headers {
            req = req.header(k, v);
        }
        if let Some(ua) = &opts.user_agent_override {
            req = req.header(reqwest::header::USER_AGENT, ua);
        }
        if let Some(body) = &opts.body {
            req = req.body(body.clone());
        }

        let send_result = if let Some(cancel) = opts.cancel.as_mut() {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(OzOutcome::Cancelled),
                r = req.send() => r,
            }
        } else {
            req.send().await
        };

        match send_result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if (200..300).contains(&status) {
                    let content_type = resp
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();

                    match read_capped_body(resp, MAX_BODY_BYTES, opts.cancel.as_mut()).await {
                        Ok(bytes) => {
                            return Ok(OzBytes {
                                status,
                                url: parsed.to_string(),
                                content_type,
                                bytes,
                                elapsed_ms: started.elapsed().as_millis(),
                                attempts: attempt,
                            });
                        }
                        Err(CapReadError::TooLarge) => {
                            return Err(OzOutcome::TooLarge {
                                cap_bytes: MAX_BODY_BYTES,
                            });
                        }
                        Err(CapReadError::Cancelled) => return Err(OzOutcome::Cancelled),
                        Err(CapReadError::Transport(message)) => {
                            last_failure = Some(LastFailure::Transport(message));
                        }
                    }
                } else {
                    let snippet = resp
                        .text()
                        .await
                        .ok()
                        .map(|s| s.chars().take(300).collect::<String>());
                    if is_transient_status(status) {
                        last_failure = Some(LastFailure::Status(status, snippet));
                    } else {
                        return Err(OzOutcome::HttpError {
                            status,
                            body_snippet: snippet,
                        });
                    }
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    timed_out_attempts += 1;
                    last_failure = Some(LastFailure::Timeout);
                } else {
                    last_failure = Some(LastFailure::Transport(e.to_string()));
                }
            }
        }

        if attempt > opts.max_retries {
            break;
        }
        tokio::time::sleep(backoff_delay(attempt)).await;
    }

    Err(match last_failure {
        Some(LastFailure::Timeout) => OzOutcome::Timeout {
            attempts: attempt,
            elapsed_ms: started.elapsed().as_millis(),
        },
        Some(LastFailure::Status(status, body_snippet)) => OzOutcome::HttpError {
            status,
            body_snippet,
        },
        Some(LastFailure::Transport(message)) => OzOutcome::TransportError { message },
        None => OzOutcome::Timeout {
            attempts: attempt.max(timed_out_attempts).max(1),
            elapsed_ms: started.elapsed().as_millis(),
        },
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SSRF screening ──────────────────────────────────────────────────

    #[test]
    fn screen_url_blocks_private_targets() {
        assert!(matches!(
            screen_url("http://127.0.0.1/x"),
            Err(OzOutcome::Blocked { .. })
        ));
        assert!(matches!(
            screen_url("http://localhost/x"),
            Err(OzOutcome::Blocked { .. })
        ));
        assert!(matches!(
            screen_url("ftp://example.com/x"),
            Err(OzOutcome::Blocked { .. })
        ));
    }

    #[test]
    fn screen_url_allows_a_public_https_target() {
        assert!(screen_url("https://example.com/report").is_ok());
    }

    // ── Retry classification ────────────────────────────────────────────

    #[test]
    fn retryable_statuses_are_429_and_5xx_only() {
        assert!(is_transient_status(429));
        assert!(is_transient_status(500));
        assert!(is_transient_status(503));
        assert!(is_transient_status(599));
    }

    #[test]
    fn non_retryable_4xx_statuses_are_never_retried() {
        assert!(!is_transient_status(400));
        assert!(!is_transient_status(401));
        assert!(!is_transient_status(403));
        assert!(!is_transient_status(404));
        assert!(!is_transient_status(410));
    }

    #[test]
    fn success_and_redirect_statuses_are_not_transient() {
        assert!(!is_transient_status(200));
        assert!(!is_transient_status(204));
        assert!(!is_transient_status(301));
    }

    // ── Backoff ──────────────────────────────────────────────────────────

    #[test]
    fn backoff_doubles_per_attempt() {
        assert_eq!(backoff_delay(1), Duration::from_millis(250));
        assert_eq!(backoff_delay(2), Duration::from_millis(500));
        assert_eq!(backoff_delay(3), Duration::from_millis(1_000));
        assert_eq!(backoff_delay(4), Duration::from_millis(2_000));
    }

    #[test]
    fn backoff_is_capped() {
        assert_eq!(backoff_delay(5), Duration::from_millis(4_000));
        assert_eq!(backoff_delay(20), Duration::from_millis(4_000));
    }

    // ── Size cap arithmetic ──────────────────────────────────────────────

    #[test]
    fn cap_arithmetic_flags_only_once_the_cap_is_crossed() {
        assert!(!would_exceed_cap(0, 100, 100));
        assert!(!would_exceed_cap(50, 50, 100));
        assert!(would_exceed_cap(50, 51, 100));
        assert!(would_exceed_cap(100, 1, 100));
    }

    #[test]
    fn cap_arithmetic_never_overflows_at_u64_edges() {
        assert!(would_exceed_cap(u64::MAX, 1, MAX_BODY_BYTES));
    }

    // ── Content-type dispatch ────────────────────────────────────────────

    #[test]
    fn dispatch_parses_json() {
        let body = dispatch_content_type("application/json; charset=utf-8", br#"{"a":1}"#).unwrap();
        assert_eq!(body, OzBody::Json(serde_json::json!({"a": 1})));
    }

    #[test]
    fn dispatch_reports_invalid_json_as_a_parse_error() {
        let err = dispatch_content_type("application/json", b"{not json").unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn dispatch_extracts_html_title_and_text() {
        let html = b"<html><head><title>Hi</title></head><body><p>Body</p></body></html>";
        let body = dispatch_content_type("text/html; charset=utf-8", html).unwrap();
        match body {
            OzBody::Html { title, text } => {
                assert_eq!(title, "Hi");
                assert!(text.contains("Body"));
            }
            other => panic!("expected Html, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_carries_xml_as_raw_text() {
        let body = dispatch_content_type("application/xml", b"<root/>").unwrap();
        assert_eq!(body, OzBody::Xml("<root/>".to_string()));
    }

    #[test]
    fn dispatch_falls_back_to_text_for_unknown_content_types() {
        let body = dispatch_content_type("application/octet-stream", b"raw").unwrap();
        assert_eq!(body, OzBody::Text("raw".to_string()));
    }

    #[test]
    fn dispatch_reports_empty_body_regardless_of_content_type() {
        let body = dispatch_content_type("application/json", b"").unwrap();
        assert_eq!(body, OzBody::Empty);
    }

    // ── Cancellation signal ─────────────────────────────────────────────

    #[test]
    fn cancel_signal_starts_uncancelled_and_flips_once_handled() {
        let (handle, signal) = CancelHandle::new();
        assert!(!signal.is_cancelled());
        handle.cancel();
        assert!(signal.is_cancelled());
    }

    #[test]
    fn cancel_signal_clones_all_observe_one_cancel() {
        let (handle, signal) = CancelHandle::new();
        let cloned = signal.clone();
        handle.cancel();
        assert!(signal.is_cancelled());
        assert!(cloned.is_cancelled());
    }
}
