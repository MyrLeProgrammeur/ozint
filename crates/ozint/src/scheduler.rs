//! Two independent throttling mechanisms an orchestrator needs
//! before it fans a layer out to external OSINT sources.
//!
//! **(a) Per-`rate_key` token buckets.** Every external source
//! ships its own quota (VirusTotal 4/min *and* 500/day, NVD 5/30s keyless, HIBP 10/min, Nominatim
//! 1/s, CourtListener 5/min *and* 125/day, GreyNoise 50/week, GitHub 60/hr — 5000/hr with a
//! PAT, WhatsMyName.ink 10/15min, PolySwarm 60/hr, Netlas 50/day, tgkit 20/hr, ThreatMiner
//! 10/min, SEC EDGAR 10/s). A `rate_key` can carry several [`RateLimit`] windows at once
//! (e.g. VirusTotal's minute burst *and* its daily cap); [`Scheduler::try_reserve_at`] admits
//! a call only when **every** registered window has room, and commits none of them if even
//! one is full — a request that clears the burst window but not the daily cap must not
//! silently spend burst quota it can never use.
//!
//! **(b) A concurrency lane** ([`Scheduler::lane`]) is a different problem: the WhatsMyName
//! ~730-site sweep is *one* logical lookup that must not open 730 sockets at once. That is a
//! semaphore bound, not a rate limit — no window, no quota, just "at most N in flight".
//! `tokio::sync::Semaphore` provides it here.
//!
//! **Where the persistence line is drawn.** Only day- and week-scoped windows are written to
//! `oz_quota` (via `store::get_quota_usage`/`put_quota_usage`); second/minute/hour windows
//! live in memory only. The reason to persist anything at all is that a dev reload
//! must not re-burn quota — but that risk is proportional to how expensive the quota is and
//! how long it takes to refill. A burned minute or hour window is whole again within the same
//! order of time a restart itself takes to notice; losing it to a reload costs nothing anyone
//! would feel. A burned **daily** quota (VirusTotal's 500, CourtListener's 125) or **weekly**
//! quota (GreyNoise's 50) is scarce and takes a day or a week to come back — exactly the
//! "silently re-grant hundreds of calls" risk persistence exists to guard against. Persisting
//! sub-hour windows would only add an SQLite round-trip to the hottest part of this module for
//! a problem that doesn't exist at that granularity.
//!
//! **Testability.** [`Scheduler::try_reserve_at`] takes `now` as an explicit parameter rather
//! than reading a clock internally, so the whole admit/refuse/rollover state machine is
//! exercised deterministically by picking timestamps — no test ever sleeps, real or virtual.
//! [`Scheduler::acquire`] is the async, production-facing wrapper: it reads the real wall
//! clock, retries `try_reserve_at` until either it is admitted or `max_wait` elapses, and
//! returns [`ToolOutcome::RateLimitedDropped`] rather than blocking a caller indefinitely on
//! (say) a weekly quota.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use ozint_db::Db;
use tokio::sync::Semaphore;

use crate::fetch::CancelSignal;
use crate::outcome::ToolOutcome;
use crate::store;

// ─── Rate limits ────────────────────────────────────────────────────────────

/// One throttling window. The four named, real-calendar variants cover most sources; a small
/// number of real quotas (NVD's 5/30s, WhatsMyName.ink's 10/15min) don't land on a calendar
/// boundary at all, hence `Custom` — adding a sixth bucket for "arbitrary duration" was less
/// surprising than forcing those two into the nearest named variant and quietly under- or
/// over-throttling them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimit {
    PerSecond(u32),
    PerMinute(u32),
    PerHour(u32),
    PerDay(u32),
    PerWeek(u32),
    Custom { window: Duration, cap: u32 },
}

impl RateLimit {
    fn cap(&self) -> u32 {
        match self {
            RateLimit::PerSecond(n)
            | RateLimit::PerMinute(n)
            | RateLimit::PerHour(n)
            | RateLimit::PerDay(n)
            | RateLimit::PerWeek(n) => *n,
            RateLimit::Custom { cap, .. } => *cap,
        }
    }

    fn window_millis(&self) -> i64 {
        match self {
            RateLimit::PerSecond(_) => 1_000,
            RateLimit::PerMinute(_) => 60_000,
            RateLimit::PerHour(_) => 3_600_000,
            RateLimit::PerDay(_) => 86_400_000,
            RateLimit::PerWeek(_) => 604_800_000,
            RateLimit::Custom { window, .. } => window.as_millis() as i64,
        }
    }

    /// Storage/cache key for this window's bucket. Stable and distinct per variant so two
    /// windows on the same `rate_key` (e.g. VirusTotal's minute + day) never collide.
    fn window_kind(&self) -> String {
        match self {
            RateLimit::PerSecond(_) => "second".to_string(),
            RateLimit::PerMinute(_) => "minute".to_string(),
            RateLimit::PerHour(_) => "hour".to_string(),
            RateLimit::PerDay(_) => "day".to_string(),
            RateLimit::PerWeek(_) => "week".to_string(),
            RateLimit::Custom { window, .. } => format!("custom-{}ms", window.as_millis()),
        }
    }

    /// See the module doc's "Where the persistence line is drawn" section: only day/week
    /// windows survive a restart.
    fn persists(&self) -> bool {
        matches!(self, RateLimit::PerDay(_) | RateLimit::PerWeek(_))
    }
}

// ─── Where the quota numbers live ──────────────────────────────────────────
//
// **Not here.** `registry::rate_limits_for` is the single source of truth, keyed on the same
// `ToolDef::rate_key` the runtime admits against, and it is guarded by a test
// (`only_citable_quotas_are_registered`) enforcing one restraint: a source with no entry means
// *we have not established a figure*, never *unlimited by decision*.
//
// This module used to carry a second catalogue — fourteen `pub const` slices named for
// third-party APIs, transcribed from each provider's published limits. **Nothing in
// production ever read a single one of them**; `runtime::fire_layer` goes only through
// `rate_limits_for`, and the one reference anywhere was a unit test in this file.
//
// Two disconnected quota tables is bad on its own, and these two disagreed: the deleted `NVD`
// const said 50 requests per 30 seconds where the live `nvd-rest` entry says 5. Stated
// precisely, because the difference is instructive rather than a simple error — **50/30s is
// NVD's rate with an API key and 5/30s is its keyless rate**, and `cve-nvd` runs keyless. The
// constant was not a typo; it was a figure for a tier this build does not use, sitting in the
// table that *looked* authoritative because its entries were named after the services. A
// reader reaching for it would have registered a quota ten times too permissive for the tier
// actually in force — which is exactly the failure mode an unkeyed, unread catalogue invites.
//
// So they are gone rather than kept "for when a tool needs them". A number nobody measured and
// nobody reads is not an asset; when a tool lands, its quota is measured against the live
// endpoint and registered in `rate_limits_for` with the measurement written down, which is
// what every entry there already does.

// ─── Scheduler ──────────────────────────────────────────────────────────────

/// Proof that one call was admitted under a rate key. Token-bucket admission has nothing to
/// release on drop (unlike a semaphore permit) — this exists only so callers can require one
/// at the type level rather than trusting themselves to check a `bool`.
#[derive(Debug)]
pub struct Permit;

#[derive(Debug, Clone, Copy)]
struct WindowState {
    window_start_ms: i64,
    used: u32,
}

pub struct Scheduler {
    db: Db,
    limits: Mutex<HashMap<String, Vec<RateLimit>>>,
    /// In-memory cache of every window's current bucket, for both persisted and
    /// memory-only windows — persisted ones are write-through (see `commit`), memory-only
    /// ones live here exclusively.
    windows: Mutex<HashMap<(String, String), WindowState>>,
    lanes: Mutex<HashMap<String, Arc<Semaphore>>>,
}

impl Scheduler {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            limits: Mutex::new(HashMap::new()),
            windows: Mutex::new(HashMap::new()),
            lanes: Mutex::new(HashMap::new()),
        }
    }

    /// Registers (or replaces) the windows enforced for `rate_key`. Replacing is deliberate —
    /// it lets a caller re-register e.g. `"github"` with [`GITHUB_WITH_PAT`] once a token gets
    /// armed, without needing a separate "update" method.
    pub fn register(&self, rate_key: &str, limits: &[RateLimit]) {
        self.limits
            .lock()
            .unwrap()
            .insert(rate_key.to_string(), limits.to_vec());
    }

    /// Returns (or creates) the named concurrency lane. Callers that ask for the same `name`
    /// share one semaphore — the lane is keyed by name, not re-created per call — so e.g. two
    /// concurrently-running layers that both fan out to WhatsMyName still share the one
    /// ~730-site concurrency cap rather than each getting their own.
    pub fn lane(&self, name: &str, max_concurrent: usize) -> Arc<Semaphore> {
        self.lanes
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(max_concurrent)))
            .clone()
    }

    /// The deterministic core: may `rate_key` be called at instant `now`? A `rate_key` with no
    /// registered limits is unmetered by design — `register` is opt-in, so a tool nobody has
    /// bothered to throttle should not silently jam on an implicit default.
    ///
    /// On success, every registered window's usage is incremented and the persisted ones
    /// (day/week) are written through to `oz_quota` before returning. On failure, **nothing**
    /// is committed — see the module doc on all-or-nothing admission — and the `Err` carries
    /// how long until the earliest binding window would have room, so a caller can decide
    /// whether that's worth waiting for.
    pub fn try_reserve_at(&self, rate_key: &str, now: DateTime<Utc>) -> Result<Permit, Duration> {
        let limits = {
            self.limits
                .lock()
                .unwrap()
                .get(rate_key)
                .cloned()
                .unwrap_or_default()
        };
        if limits.is_empty() {
            return Ok(Permit);
        }

        let now_ms = now.timestamp_millis();
        let mut planned: Vec<((String, String), WindowState)> = Vec::with_capacity(limits.len());
        let mut wait: Option<Duration> = None;

        {
            let mut windows = self.windows.lock().unwrap();
            for limit in &limits {
                let key = (rate_key.to_string(), limit.window_kind());
                let window_millis = limit.window_millis();
                let window_start_ms = (now_ms / window_millis) * window_millis;

                let cached = match windows.get(&key) {
                    Some(s) => *s,
                    None => {
                        let loaded = if limit.persists() {
                            store::get_quota_usage(&self.db, &key.0, &key.1)
                                .ok()
                                .flatten()
                                .map(|(window_start, used)| WindowState {
                                    window_start_ms: window_start,
                                    used: used as u32,
                                })
                        } else {
                            None
                        };
                        let s = loaded.unwrap_or(WindowState {
                            window_start_ms,
                            used: 0,
                        });
                        windows.insert(key.clone(), s);
                        s
                    }
                };

                // The cached bucket may belong to a window that has since rolled over — this
                // is a read-only projection of that; it is only committed to `windows` (and to
                // SQLite) once every window on this rate_key is known to admit.
                let effective = if cached.window_start_ms == window_start_ms {
                    cached
                } else {
                    WindowState {
                        window_start_ms,
                        used: 0,
                    }
                };

                if effective.used >= limit.cap() {
                    let reset_at_ms = effective.window_start_ms + window_millis;
                    let remaining_ms = (reset_at_ms - now_ms).max(0) as u64;
                    let candidate = Duration::from_millis(remaining_ms);
                    wait = Some(match wait {
                        Some(w) if w <= candidate => w,
                        _ => candidate,
                    });
                } else {
                    planned.push((
                        key,
                        WindowState {
                            window_start_ms: effective.window_start_ms,
                            used: effective.used + 1,
                        },
                    ));
                }
            }
        }

        if let Some(w) = wait {
            return Err(w);
        }

        // All windows admitted: commit every one, write-through the persisted kinds.
        {
            let mut windows = self.windows.lock().unwrap();
            for (key, new_state) in &planned {
                windows.insert(key.clone(), *new_state);
            }
        }
        for (limit, (key, new_state)) in limits.iter().zip(planned.iter()) {
            if limit.persists()
                && let Err(e) = store::put_quota_usage(
                    &self.db,
                    &key.0,
                    &key.1,
                    new_state.window_start_ms,
                    new_state.used as i64,
                )
            {
                tracing::warn!(
                    rate_key = %key.0, window_kind = %key.1, error = %e,
                    "failed to persist quota usage — this window will re-check against SQLite next process start and may under-count"
                );
            }
        }
        Ok(Permit)
    }

    /// Production entry point. Reads the real wall clock and retries admission until either it
    /// succeeds or `max_wait` has elapsed, sleeping only as long as the binding window says is
    /// necessary (capped by the remaining budget) between attempts — never longer, and never
    /// unboundedly, so a caller can never be hung on (say) a weekly quota with no key.
    pub async fn acquire(&self, rate_key: &str, max_wait: Duration) -> Result<Permit, ToolOutcome> {
        self.acquire_cancellable(rate_key, max_wait, None).await
    }

    /// [`Scheduler::acquire`], interruptible by the layer's [`CancelSignal`].
    ///
    /// **Why this exists before it has a caller.** Waiting for a rate-limit window is the
    /// longest sleep in the whole engine — a `PerHour` limit can park a tool for minutes. The
    /// kill switch's whole promise is that a stop stops things *now*; a tool asleep in here
    /// would keep the layer alive for the full `max_wait` after the analyst killed it, and
    /// then quietly proceed to make the very third-party call the kill was meant to prevent.
    /// No source calls the scheduler yet, which is exactly why this is cheap to fix today and
    /// would be an invisible trap for whoever wires the first one.
    ///
    /// Returns [`ToolOutcome::Cancelled`] — not `RateLimitedDropped`, which would blame the
    /// rate limit for a decision the analyst made.
    pub async fn acquire_cancellable(
        &self,
        rate_key: &str,
        max_wait: Duration,
        cancel: Option<CancelSignal>,
    ) -> Result<Permit, ToolOutcome> {
        let deadline = tokio::time::Instant::now() + max_wait;
        let mut cancel = cancel;
        loop {
            if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
                return Err(ToolOutcome::Cancelled);
            }
            match self.try_reserve_at(rate_key, Utc::now()) {
                Ok(permit) => return Ok(permit),
                Err(wait) => {
                    let now_instant = tokio::time::Instant::now();
                    if now_instant >= deadline {
                        return Err(ToolOutcome::RateLimitedDropped);
                    }
                    let remaining = deadline - now_instant;
                    let nap = wait.min(remaining);
                    match cancel.as_mut() {
                        Some(signal) => {
                            tokio::select! {
                                _ = tokio::time::sleep(nap) => {}
                                _ = signal.cancelled() => return Err(ToolOutcome::Cancelled),
                            }
                        }
                        None => tokio::time::sleep(nap).await,
                    }
                }
            }
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::fetch::CancelHandle;

    use super::*;

    fn at_ms(ms: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(ms).unwrap()
    }

    #[test]
    fn unregistered_rate_key_is_unmetered() {
        let db = ozint_db::open_memory().unwrap();
        let scheduler = Scheduler::new(db);
        // Nothing was registered for "unknown-tool" — admit unconditionally rather than
        // silently jamming on an implicit default limit.
        for _ in 0..50 {
            assert!(scheduler.try_reserve_at("unknown-tool", at_ms(0)).is_ok());
        }
    }

    #[test]
    fn burst_window_admits_then_refuses() {
        let db = ozint_db::open_memory().unwrap();
        let scheduler = Scheduler::new(db);
        scheduler.register("hibp", &[RateLimit::PerMinute(2)]);

        let t0 = at_ms(0);
        assert!(scheduler.try_reserve_at("hibp", t0).is_ok());
        assert!(scheduler.try_reserve_at("hibp", t0).is_ok());
        let err = scheduler.try_reserve_at("hibp", t0).unwrap_err();
        assert!(
            err > Duration::ZERO,
            "must report a positive wait, not a bare refusal"
        );
        assert!(err <= Duration::from_secs(60));
    }

    #[test]
    fn two_windows_the_daily_cap_binds_before_the_burst_window_would() {
        let db = ozint_db::open_memory().unwrap();
        let scheduler = Scheduler::new(db);
        // Minute window has room for 4; day window only for 2 — the day cap must be what
        // stops the third call, not the (still-open) minute window.
        scheduler.register(
            "virustotal",
            &[RateLimit::PerMinute(4), RateLimit::PerDay(2)],
        );

        let t0 = at_ms(0);
        assert!(scheduler.try_reserve_at("virustotal", t0).is_ok());
        assert!(scheduler.try_reserve_at("virustotal", t0).is_ok());
        let err = scheduler.try_reserve_at("virustotal", t0).unwrap_err();
        // Minute window would free up within 60s; only the day window's ~24h reset explains
        // a wait this long, which is proof it — not the minute window — is what bound this.
        assert!(
            err > Duration::from_secs(60),
            "the binding window must be the day cap, not the minute one"
        );
    }

    #[test]
    fn every_window_must_admit_or_none_of_them_are_spent() {
        let db = ozint_db::open_memory().unwrap();
        let scheduler = Scheduler::new(db);
        scheduler.register(
            "courtlistener",
            &[RateLimit::PerMinute(5), RateLimit::PerDay(1)],
        );

        let t0 = at_ms(0);
        assert!(scheduler.try_reserve_at("courtlistener", t0).is_ok()); // spends the single daily slot
        assert!(scheduler.try_reserve_at("courtlistener", t0).is_err()); // day cap now blocks

        // Advance one minute (rolls the burst window) but stay on the same calendar day: the
        // burst window is fresh again, but the request must still be refused because the day
        // cap was never touched by that rollover.
        let t1 = at_ms(60_000);
        assert!(
            scheduler.try_reserve_at("courtlistener", t1).is_err(),
            "the still-exhausted day window must keep refusing"
        );
    }

    #[test]
    fn window_rollover_resets_usage() {
        let db = ozint_db::open_memory().unwrap();
        let scheduler = Scheduler::new(db);
        scheduler.register("threatminer", &[RateLimit::PerMinute(10)]);

        let t0 = at_ms(0);
        for _ in 0..10 {
            assert!(scheduler.try_reserve_at("threatminer", t0).is_ok());
        }
        assert!(scheduler.try_reserve_at("threatminer", t0).is_err());

        // One minute later: a brand new window, capacity is back.
        let t1 = at_ms(60_000);
        assert!(scheduler.try_reserve_at("threatminer", t1).is_ok());
    }

    #[test]
    fn daily_quota_persists_across_a_simulated_restart() {
        let db = ozint_db::open_memory().unwrap();
        let t0 = at_ms(0);

        {
            let scheduler = Scheduler::new(db.clone());
            scheduler.register("netlas", &[RateLimit::PerDay(50)]); // PerDay(50)
            for _ in 0..50 {
                assert!(scheduler.try_reserve_at("netlas", t0).is_ok());
            }
            assert!(
                scheduler.try_reserve_at("netlas", t0).is_err(),
                "day cap exhausted before the 'restart'"
            );
        }

        // A fresh Scheduler over the SAME Db — the stand-in for a dev reload. This is the
        // entire reason `oz_quota` exists: the daily cap must still read as exhausted.
        let scheduler2 = Scheduler::new(db);
        scheduler2.register("netlas", &[RateLimit::PerDay(50)]);
        let err = scheduler2.try_reserve_at("netlas", t0).unwrap_err();
        assert!(
            err > Duration::ZERO,
            "a new Scheduler instance must not have re-granted the burned daily quota"
        );
    }

    #[test]
    fn sub_day_windows_do_not_persist_across_a_simulated_restart() {
        // The deliberate other half of the persistence line: a minute window is cheap enough
        // to refill that losing it on reload is fine, and it must NOT be found in SQLite.
        let db = ozint_db::open_memory().unwrap();
        let t0 = at_ms(0);

        {
            let scheduler = Scheduler::new(db.clone());
            scheduler.register("tgkit-burst", &[RateLimit::PerMinute(1)]);
            assert!(scheduler.try_reserve_at("tgkit-burst", t0).is_ok());
            assert!(scheduler.try_reserve_at("tgkit-burst", t0).is_err());
        }

        let scheduler2 = Scheduler::new(db);
        scheduler2.register("tgkit-burst", &[RateLimit::PerMinute(1)]);
        assert!(
            scheduler2.try_reserve_at("tgkit-burst", t0).is_ok(),
            "a minute window must reset on restart — it was never written to oz_quota"
        );
    }

    #[test]
    fn custom_window_covers_non_calendar_durations() {
        // NVD's 5/30s and WhatsMyName.ink's 10/15min don't land on any of the named
        // variants; Custom must still enforce them correctly.
        let db = ozint_db::open_memory().unwrap();
        let scheduler = Scheduler::new(db);
        scheduler.register(
            "whatsmyname-ink",
            &[RateLimit::Custom {
                window: Duration::from_secs(15 * 60),
                cap: 10,
            }],
        );

        let t0 = at_ms(0);
        for _ in 0..10 {
            assert!(scheduler.try_reserve_at("whatsmyname-ink", t0).is_ok());
        }
        assert!(scheduler.try_reserve_at("whatsmyname-ink", t0).is_err());

        // Just before the 15-minute window rolls: still refused.
        let almost = at_ms(15 * 60_000 - 1);
        assert!(scheduler.try_reserve_at("whatsmyname-ink", almost).is_err());
        // At the boundary: fresh window.
        let rolled = at_ms(15 * 60_000);
        assert!(scheduler.try_reserve_at("whatsmyname-ink", rolled).is_ok());
    }

    // ── acquire(): the bounded-wait async wrapper ──────────────────────────
    //
    // These don't sleep for real: `max_wait: Duration::ZERO` means `acquire` must fail on its
    // very first check without ever reaching `tokio::time::sleep`, so a Tokio test runtime
    // resolves the `.await` immediately with no time advancement needed.

    #[tokio::test]
    async fn acquire_admits_immediately_when_capacity_is_free() {
        let db = ozint_db::open_memory().unwrap();
        let scheduler = Scheduler::new(db);
        // An inline limit, not a shared constant: see "Where the quota numbers live" above.
        // This test needs *a* quota with free capacity, not a particular service's.
        scheduler.register("sec-edgar", &[RateLimit::PerSecond(10)]);
        assert!(
            scheduler
                .acquire("sec-edgar", Duration::from_secs(1))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn acquire_drops_immediately_when_max_wait_is_zero_and_capacity_is_gone() {
        let db = ozint_db::open_memory().unwrap();
        let scheduler = Scheduler::new(db);
        scheduler.register("nominatim", &[RateLimit::PerSecond(1)]);
        assert!(
            scheduler
                .acquire("nominatim", Duration::from_secs(1))
                .await
                .is_ok()
        );
        let outcome = scheduler
            .acquire("nominatim", Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(outcome, ToolOutcome::RateLimitedDropped);
    }

    // ── lane(): the concurrency semaphore, distinct from rate limiting ─────

    #[test]
    fn lane_bounds_concurrency_and_is_shared_by_name() {
        let db = ozint_db::open_memory().unwrap();
        let scheduler = Scheduler::new(db);
        let sem = scheduler.lane("whatsmyname-sweep", 2);
        assert_eq!(sem.available_permits(), 2);

        let p1 = sem.clone().try_acquire_owned().unwrap();
        let p2 = sem.clone().try_acquire_owned().unwrap();
        assert!(
            sem.clone().try_acquire_owned().is_err(),
            "a third concurrent slot must be refused"
        );

        drop(p1);
        assert!(
            sem.clone().try_acquire_owned().is_ok(),
            "releasing one slot must free capacity for the next"
        );
        drop(p2);

        // Asking for the same lane name again must return the SAME semaphore, not a fresh one
        // with its own independent counter — two callers throttling the same physical sweep
        // (e.g. two layers both fanning out to WhatsMyName) must share one cap.
        let sem_again = scheduler.lane("whatsmyname-sweep", 2);
        assert!(Arc::ptr_eq(&sem, &sem_again));
    }

    #[test]
    fn distinct_lane_names_are_independent() {
        let db = ozint_db::open_memory().unwrap();
        let scheduler = Scheduler::new(db);
        let a = scheduler.lane("lane-a", 1);
        let b = scheduler.lane("lane-b", 1);
        assert!(!Arc::ptr_eq(&a, &b));
        let _hold_a = a.try_acquire_owned().unwrap();
        // lane-a being fully held must not affect lane-b's independent capacity.
        assert!(b.try_acquire_owned().is_ok());
    }

    // ── Cancellation while waiting on a window ─────────────────────────────────────

    #[tokio::test]
    async fn an_already_cancelled_caller_never_takes_a_slot() {
        let sched = Scheduler::new(ozint_db::open_memory().unwrap());
        sched.register("k", &[RateLimit::PerHour(1)]);
        let (handle, signal) = CancelHandle::new();
        handle.cancel();

        let outcome = sched
            .acquire_cancellable("k", Duration::from_secs(60), Some(signal))
            .await
            .unwrap_err();

        assert_eq!(outcome, ToolOutcome::Cancelled);
        // The slot must still be there: a cancelled caller that burned quota on its way out
        // would make a kill cost the analyst their remaining calls.
        assert!(sched.try_reserve_at("k", Utc::now()).is_ok());
    }

    #[tokio::test]
    async fn a_kill_interrupts_a_wait_instead_of_sleeping_it_out() {
        let sched = Scheduler::new(ozint_db::open_memory().unwrap());
        // One call per hour, already spent: the next caller would wait ~an hour.
        sched.register("k", &[RateLimit::PerHour(1)]);
        let _first = sched.try_reserve_at("k", Utc::now()).unwrap();

        let (handle, signal) = CancelHandle::new();
        let waiter = tokio::spawn(async move {
            let sched = Scheduler::new(ozint_db::open_memory().unwrap());
            sched.register("k", &[RateLimit::PerHour(1)]);
            let _spent = sched.try_reserve_at("k", Utc::now()).unwrap();
            sched
                .acquire_cancellable("k", Duration::from_secs(3600), Some(signal))
                .await
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.cancel();

        let outcome = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("a killed wait must return promptly, not sleep out its max_wait")
            .unwrap()
            .unwrap_err();
        assert_eq!(outcome, ToolOutcome::Cancelled);
    }

    #[tokio::test]
    async fn a_rate_limit_timeout_still_blames_the_rate_limit_not_the_analyst() {
        let sched = Scheduler::new(ozint_db::open_memory().unwrap());
        sched.register("k", &[RateLimit::PerHour(1)]);
        let _spent = sched.try_reserve_at("k", Utc::now()).unwrap();
        let (_handle, signal) = CancelHandle::new();

        let outcome = sched
            .acquire_cancellable("k", Duration::from_millis(20), Some(signal))
            .await
            .unwrap_err();

        assert_eq!(outcome, ToolOutcome::RateLimitedDropped);
    }
}
