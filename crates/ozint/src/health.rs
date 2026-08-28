//! A per-`tool_id` circuit breaker (closed → open → half-open, with exponential backoff).
//!
//! **Why this exists**: a permanently-dead source (for example a source returning 403, or an
//! endpoint that has been retired) must be skipped **instantly** once the pattern is established, instead of
//! paying a full request timeout on every layer that happens to touch it. With a wide fan-out
//! — many layers over a session, sometimes a 730-site-style probe — that wasted timeout is
//! multiplied by every call, which is exactly the cost this breaker exists to cut.
//!
//! **Persistence — read this before assuming otherwise.** Breaker state lives in an in-process
//! `HashMap` only. **A server restart resets every circuit back to `Closed`, forgetting that a
//! source was dead.** This unit was explicitly told it may not `CREATE TABLE` anything —
//! `store.rs` already owns the `oz_*` schema and is committed — so persisting this is
//! deliberately left to a later unit (e.g. a new column added to an existing `oz_*` row, once
//! whichever unit needs it decides where that column belongs). In-memory is an accepted answer
//! for this unit, called out here on purpose rather than glossed over.
//!
//! **Which outcomes count as circuit faults, and why** (see [`is_fault`]): a 404 for a handle
//! that genuinely does not exist is a *result*, not a tool fault; a 500, a timeout or a
//! transport error *is* a fault.
//! - [`ToolOutcome::Timeout`] and [`ToolOutcome::ParseError`] are faults: the source is
//!   unreachable or returning garbage, not answering our query.
//! - A 5xx [`ToolOutcome::HttpError`] is a fault (the source is broken); a non-5xx one (404,
//!   400, 422, …) is **not** — the server answered correctly and definitively about this
//!   specific query, which is exactly the "404 = result" case described above.
//! - [`ToolOutcome::Forbidden`] **is** a fault: GeoConfirmed's blanket 403 on a default
//!   User-Agent is the motivating example — a source refusing every request outright is
//!   precisely what this breaker exists to stop hammering.
//! - [`ToolOutcome::RateLimitedDropped`] is **not** a fault: the request was never even sent,
//!   dropped by our own scheduler's throttle — that says nothing about the source's health.
//! - `OkWithResults`/`OkEmpty` are successes; every `Skipped*` variant was never attempted at
//!   all and should never reach [`ToolHealth::record`] in the first place — `check` is what
//!   produces those without an attempt ever happening.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration as ChronoDuration, Utc};

use crate::outcome::ToolOutcome;

/// A fault means the *source itself* misbehaved (broke, hung, or refused us outright) — see
/// the module doc for the full per-variant reasoning behind this split.
pub fn is_fault(outcome: &ToolOutcome) -> bool {
    match outcome {
        ToolOutcome::Timeout { .. } => true,
        ToolOutcome::ParseError { .. } => true,
        ToolOutcome::Forbidden { .. } => true,
        ToolOutcome::HttpError { status, .. } => *status >= 500,
        _ => false,
    }
}

/// Consecutive faults (while closed) before the breaker trips open. Three survives a single
/// blip (a request lost to transient network noise) while still catching a genuinely dead
/// source within the first handful of calls a layer makes to it.
const FAILURE_THRESHOLD: u32 = 3;
/// First backoff window once a circuit trips.
const INITIAL_BACKOFF_SECS: i64 = 30;
/// Backoff doubles on every failed half-open probe, capped here so a source that's been dead
/// for a long time still gets re-checked at least once an hour rather than never again.
const MAX_BACKOFF_SECS: i64 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone)]
struct Breaker {
    state: State,
    consecutive_failures: u32,
    backoff_secs: i64,
    /// Set whenever `state == Open`; also left in place (stale) during `HalfOpen` purely so a
    /// second concurrent `check()` has *something* to report as `retry_after` while the probe
    /// is in flight — see `check`'s `HalfOpen` arm.
    opens_until: Option<DateTime<Utc>>,
    /// `HalfOpen` allows exactly one caller through at a time; this is that gate.
    probe_in_flight: bool,
}

impl Default for Breaker {
    fn default() -> Self {
        Self {
            state: State::Closed,
            consecutive_failures: 0,
            backoff_secs: INITIAL_BACKOFF_SECS,
            opens_until: None,
            probe_in_flight: false,
        }
    }
}

type ClockFn = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

pub struct ToolHealth {
    breakers: Mutex<HashMap<String, Breaker>>,
    now: ClockFn,
}

impl Default for ToolHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolHealth {
    pub fn new() -> Self {
        Self {
            breakers: Mutex::new(HashMap::new()),
            now: Arc::new(Utc::now),
        }
    }

    /// Test/host hook: inject a clock so open/backoff windows can be driven deterministically,
    /// without a real sleep.
    pub fn with_clock(now: impl Fn() -> DateTime<Utc> + Send + Sync + 'static) -> Self {
        Self {
            breakers: Mutex::new(HashMap::new()),
            now: Arc::new(now),
        }
    }

    /// Call before invoking `tool_id`. `None` means proceed — the caller must feed the
    /// resulting outcome back through [`record`](Self::record). `Some(outcome)` means skip
    /// instantly: the circuit is open (still inside its backoff window), or already half-open
    /// with its one allowed probe already in flight.
    pub fn check(&self, tool_id: &str) -> Option<ToolOutcome> {
        let now = (self.now)();
        let mut breakers = self.breakers.lock().unwrap();
        let breaker = breakers.entry(tool_id.to_string()).or_default();

        match breaker.state {
            State::Closed => None,
            State::Open => {
                let until = breaker
                    .opens_until
                    .expect("Open state always carries opens_until");
                if now < until {
                    return Some(ToolOutcome::SkippedCircuitOpen {
                        retry_after: Some(until),
                    });
                }
                // Backoff window elapsed: let exactly one probe through.
                breaker.state = State::HalfOpen;
                breaker.probe_in_flight = true;
                None
            }
            State::HalfOpen => {
                if breaker.probe_in_flight {
                    Some(ToolOutcome::SkippedCircuitOpen {
                        retry_after: breaker.opens_until,
                    })
                } else {
                    // Defensive: reaching half-open with no probe in flight means a previous
                    // probe's outcome was never recorded (a caller that called `check` but
                    // never followed up with `record`). Treat this call as the new probe
                    // rather than leaving the breaker wedged half-open forever.
                    breaker.probe_in_flight = true;
                    None
                }
            }
        }
    }

    /// Feed the outcome of an attempted call back into the breaker. Only [`is_fault`] outcomes
    /// move it toward/deeper into `Open`; every other outcome (a success, or a "result-shaped"
    /// failure like a clean 404) is evidence the source is healthy.
    pub fn record(&self, tool_id: &str, outcome: &ToolOutcome) {
        let now = (self.now)();
        let fault = is_fault(outcome);
        let mut breakers = self.breakers.lock().unwrap();
        let breaker = breakers.entry(tool_id.to_string()).or_default();

        match breaker.state {
            State::Closed => {
                if fault {
                    breaker.consecutive_failures += 1;
                    if breaker.consecutive_failures >= FAILURE_THRESHOLD {
                        breaker.state = State::Open;
                        breaker.opens_until =
                            Some(now + ChronoDuration::seconds(breaker.backoff_secs));
                    }
                } else {
                    breaker.consecutive_failures = 0;
                }
            }
            State::HalfOpen => {
                breaker.probe_in_flight = false;
                if fault {
                    // The probe failed: stay dead, and wait longer before trying again.
                    breaker.backoff_secs = (breaker.backoff_secs * 2).min(MAX_BACKOFF_SECS);
                    breaker.state = State::Open;
                    breaker.opens_until = Some(now + ChronoDuration::seconds(breaker.backoff_secs));
                } else {
                    // The probe succeeded: the source is back. Reset entirely, including the
                    // backoff, so a future outage starts its own backoff from the beginning
                    // rather than inheriting this one's escalation.
                    *breaker = Breaker::default();
                }
            }
            State::Open => {
                // `check()` gates every real attempt, so a `record()` call should never arrive
                // while Open. If one does anyway (a caller that ignored the skip), don't let a
                // stray result perturb the window — the backoff timer alone still governs.
            }
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};

    fn clocked() -> (ToolHealth, Arc<AtomicI64>) {
        let millis = Arc::new(AtomicI64::new(0));
        let read = millis.clone();
        let health = ToolHealth::with_clock(move || {
            DateTime::<Utc>::from_timestamp_millis(read.load(Ordering::SeqCst)).unwrap()
        });
        (health, millis)
    }

    fn fault() -> ToolOutcome {
        ToolOutcome::HttpError {
            status: 500,
            message: None,
        }
    }

    fn not_found() -> ToolOutcome {
        ToolOutcome::HttpError {
            status: 404,
            message: None,
        }
    }

    #[test]
    fn is_fault_matches_the_documented_split() {
        assert!(is_fault(&ToolOutcome::Timeout { after_ms: 1 }));
        assert!(is_fault(&ToolOutcome::ParseError {
            message: "x".into()
        }));
        assert!(is_fault(&ToolOutcome::Forbidden { message: None }));
        assert!(is_fault(&ToolOutcome::HttpError {
            status: 500,
            message: None
        }));
        assert!(is_fault(&ToolOutcome::HttpError {
            status: 503,
            message: None
        }));
        assert!(
            !is_fault(&ToolOutcome::HttpError {
                status: 404,
                message: None
            }),
            "a clean 404 is a result, not a fault"
        );
        assert!(!is_fault(&ToolOutcome::HttpError {
            status: 400,
            message: None
        }));
        assert!(!is_fault(&ToolOutcome::RateLimitedDropped));
        assert!(!is_fault(&ToolOutcome::OkEmpty));
        assert!(!is_fault(&ToolOutcome::OkWithResults { count: 3 }));
        assert!(!is_fault(&ToolOutcome::SkippedNoKey {
            env_var: "X".into()
        }));
    }

    #[test]
    fn result_shaped_failures_never_trip_the_breaker() {
        let (health, _clock) = clocked();
        for _ in 0..20 {
            assert!(health.check("geo-lookup").is_none());
            health.record("geo-lookup", &not_found());
        }
        assert!(
            health.check("geo-lookup").is_none(),
            "20 clean 404s in a row must never open the circuit"
        );
    }

    #[test]
    fn faults_below_threshold_stay_closed() {
        let (health, _clock) = clocked();
        health.record("wmn-probe", &fault());
        health.record("wmn-probe", &fault());
        assert!(
            health.check("wmn-probe").is_none(),
            "two faults, threshold is three: still closed"
        );
    }

    #[test]
    fn full_lifecycle_closed_open_half_open_closed_and_open_again() {
        let (health, clock) = clocked();
        let tool = "geoconfirmed"; // the motivating example (blanket 403)

        // Closed -> Open: FAILURE_THRESHOLD consecutive faults.
        for _ in 0..FAILURE_THRESHOLD {
            assert!(health.check(tool).is_none());
            health.record(tool, &fault());
        }
        match health.check(tool) {
            Some(ToolOutcome::SkippedCircuitOpen { retry_after }) => assert!(retry_after.is_some()),
            other => panic!("expected SkippedCircuitOpen, got {other:?}"),
        }

        // Still inside the 30s backoff window: still skipped.
        clock.store(5_000, Ordering::SeqCst);
        assert!(matches!(
            health.check(tool),
            Some(ToolOutcome::SkippedCircuitOpen { .. })
        ));

        // Window elapses (30s): exactly one probe gets through.
        clock.store(31_000, Ordering::SeqCst);
        assert!(
            health.check(tool).is_none(),
            "the single allowed half-open probe must be let through"
        );
        // A second, concurrent caller must be skipped while that probe is in flight.
        assert!(
            matches!(
                health.check(tool),
                Some(ToolOutcome::SkippedCircuitOpen { .. })
            ),
            "only ONE probe may be in flight at a time"
        );

        // The probe fails: re-open with a bigger backoff (30s -> 60s).
        health.record(tool, &fault());
        assert!(matches!(
            health.check(tool),
            Some(ToolOutcome::SkippedCircuitOpen { .. })
        ));

        // New window is 31_000 + 60_000 = 91_000ms: 62_000 is still inside it.
        clock.store(62_000, Ordering::SeqCst);
        assert!(
            matches!(
                health.check(tool),
                Some(ToolOutcome::SkippedCircuitOpen { .. })
            ),
            "backoff must have grown, not reset"
        );

        clock.store(92_000, Ordering::SeqCst); // past the 91_000 mark
        assert!(
            health.check(tool).is_none(),
            "second probe window must have elapsed by now"
        );

        // This probe succeeds: circuit closes and resets.
        health.record(tool, &ToolOutcome::OkWithResults { count: 1 });
        assert!(health.check(tool).is_none());

        // Closed means faults have to build back up from zero again (not inherit the old count).
        health.record(tool, &fault());
        health.record(tool, &fault());
        assert!(
            health.check(tool).is_none(),
            "only two faults after a fresh close: still under threshold"
        );
    }

    #[test]
    fn each_tool_id_gets_its_own_independent_breaker() {
        let (health, _clock) = clocked();
        for _ in 0..FAILURE_THRESHOLD {
            health.record("dead-source", &fault());
        }
        assert!(matches!(
            health.check("dead-source"),
            Some(ToolOutcome::SkippedCircuitOpen { .. })
        ));
        assert!(
            health.check("healthy-source").is_none(),
            "a fault storm on one tool must not affect another"
        );
    }
}
