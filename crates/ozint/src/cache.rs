//! Persistent per-`(tool_id, key)` cache with per-tool TTL, single-flight
//! de-duplication and a bypass flag.
//!
//! **Schema ownership**: `store.rs` owns `oz_tool_cache` (see its module doc). This module never
//! `CREATE TABLE`s anything; it only calls [`store::get_cache_entry`]/[`store::put_cache_entry`]
//! and layers policy on top: TTL, single-flight, bypass. The caller (the tool registry) is the
//! source of truth for what TTL to pass — this module has no built-in table of TTLs. Typical
//! values: 24h for reputation lookups, 7d for geo lookups, daily
//! for slow-changing datasets (KEV, SDN, the WhatsMyName site list), weekly for ATT&CK/MaxMind.
//!
//! **This is a persistence layer an earlier in-memory single-flight cache never had**: `ToolCache`
//! adds single-flight *and* durability across restarts, not just in-process de-duplication.
//!
//! **Single-flight mechanism**: an in-process `HashMap<(tool_id, key), Arc<OnceCell<Value>>>`
//! guarded by a plain `std::sync::Mutex` (the guard is only ever held for a synchronous
//! check-or-insert, never across an `.await`). `tokio::sync::OnceCell::get_or_try_init` does
//! the actual de-duplication: when N callers race to initialize the same cell, exactly one of
//! their closures is ever invoked — every other caller simply awaits that same in-progress
//! future and receives its result once it resolves. This matters because a wide fan-out (a
//! WhatsMyName-style 730-site probe, or several layers asking about the same value at once)
//! would otherwise re-request the same dataset once per caller, which is exactly what this
//! unit exists to prevent.
//!
//! On success the cell's entry is removed from the map once the fetch settles (whoever led it
//! removes it); any caller still holding a clone of the `Arc` keeps working regardless — Arc
//! reference counting doesn't care whether the map still points at it. Removing it is what lets
//! a *later*, non-concurrent call (TTL expiry, or a bypassed refresh) start a genuinely new
//! fetch instead of replaying the same resolved cell forever.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use ozint_db::Db;
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::store;

fn system_clock_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

type ClockFn = Arc<dyn Fn() -> i64 + Send + Sync>;

/// One in-flight fetch, shared by every concurrent caller asking for the same
/// `(tool_id, key)` — see the module doc's "Single-flight mechanism" section.
type InFlight = Arc<OnceCell<Value>>;

pub struct ToolCache {
    db: Db,
    inflight: StdMutex<HashMap<String, InFlight>>,
    now_ms: ClockFn,
}

impl ToolCache {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            inflight: StdMutex::new(HashMap::new()),
            now_ms: Arc::new(system_clock_ms),
        }
    }

    /// Test/host hook: inject a clock instead of `Utc::now()`, so TTL expiry can be driven
    /// deterministically without a real sleep.
    pub fn with_clock(db: Db, now_ms: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        Self {
            db,
            inflight: StdMutex::new(HashMap::new()),
            now_ms: Arc::new(now_ms),
        }
    }

    /// `\u{1}` can't appear in a tool id or a cache key (both are ASCII identifiers built by
    /// this crate's own registry/normalizer), so this is a safe, allocation-cheap composite key.
    fn map_key(tool_id: &str, key: &str) -> String {
        format!("{tool_id}\u{1}{key}")
    }

    /// Synchronous cache read — never triggers a fetch. Returns `None` on a cold cache, a row
    /// older than `ttl`, or an unparseable stored payload (degrade like a miss rather than
    /// error out — same philosophy as `store.rs`'s row hydration).
    pub fn peek(&self, tool_id: &str, key: &str, ttl: Duration) -> Option<Value> {
        let (payload_json, retrieved_at) = store::get_cache_entry(&self.db, tool_id, key)
            .ok()
            .flatten()?;
        let age_ms = (self.now_ms)() - retrieved_at;
        if age_ms < 0 || age_ms as u128 > ttl.as_millis() {
            return None;
        }
        match serde_json::from_str(&payload_json) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(tool_id, key, error = %e, "tool cache: dropping unparseable cached payload");
                None
            }
        }
    }

    /// Returns the cached value if fresh (unless `bypass`), otherwise runs `fetch` — exactly
    /// once no matter how many callers ask for the same `(tool_id, key)` concurrently.
    ///
    /// `bypass = true` is the manual-refresh hook: it skips the TTL check entirely and
    /// always performs a fresh fetch. A refresh that could still silently serve a stale cached
    /// value would make the whole refresh feature a lie, so this flag is the explicit, honest
    /// way to force a miss rather than something refresh has to fake by other means.
    ///
    /// A successful fetch is persisted before being handed back. A failed fetch is never
    /// cached: `OnceCell::get_or_try_init` leaves the cell uninitialized on `Err`, so the very
    /// next call (even for the exact same key) retries instead of replaying the failure.
    pub async fn get_or_fetch<F, Fut>(
        &self,
        tool_id: &str,
        key: &str,
        ttl: Duration,
        bypass: bool,
        fetch: F,
    ) -> Result<Value, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Value, String>>,
    {
        if !bypass && let Some(v) = self.peek(tool_id, key, ttl) {
            return Ok(v);
        }

        let map_key = Self::map_key(tool_id, key);
        let cell: InFlight = {
            let mut guard = self.inflight.lock().unwrap();
            guard
                .entry(map_key.clone())
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone()
        };

        let tool_id_owned = tool_id.to_string();
        let key_owned = key.to_string();
        let db = self.db.clone();
        let retrieved_at = (self.now_ms)();

        let result = cell
            .get_or_try_init(|| async move {
                let value = fetch().await?;
                // Persistence is best-effort, and deliberately so: the fetch already succeeded,
                // so a failed *write* must not be reported as a failed lookup. Propagating it
                // would mean a full disk or a locked database silently turned every working
                // tool into a broken one — a cache is an optimisation, and an optimisation that
                // can fail the thing it optimises is a liability. It is warned about loudly
                // instead, and the next call simply misses and refetches.
                match serde_json::to_string(&value) {
                    Ok(payload) => {
                        if let Err(e) = store::put_cache_entry(
                            &db,
                            &tool_id_owned,
                            &key_owned,
                            &payload,
                            retrieved_at,
                            None,
                        ) {
                            tracing::warn!(
                                tool_id = %tool_id_owned, key = %key_owned, error = %e,
                                "tool cache: fetch succeeded but the cache write failed; serving uncached"
                            );
                        }
                    }
                    Err(e) => tracing::warn!(
                        tool_id = %tool_id_owned, key = %key_owned, error = %e,
                        "tool cache: fetched value is not serializable; serving uncached"
                    ),
                }
                Ok::<Value, String>(value)
            })
            .await
            .cloned();

        // See the module doc: safe to drop from the map now regardless of who led the fetch —
        // any concurrent follower already holds its own clone of `cell`.
        self.inflight.lock().unwrap().remove(&map_key);

        result
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

    fn cache_with_clock() -> (ToolCache, Arc<AtomicI64>) {
        let db = ozint_db::open_memory().unwrap();
        let clock = Arc::new(AtomicI64::new(0));
        let clock_read = clock.clone();
        let cache = ToolCache::with_clock(db, move || clock_read.load(Ordering::SeqCst));
        (cache, clock)
    }

    #[tokio::test]
    async fn ttl_hit_serves_cached_value_without_refetching() {
        let (cache, clock) = cache_with_clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let ttl = Duration::from_secs(60);

        for _ in 0..3 {
            let calls = calls.clone();
            let v = cache
                .get_or_fetch("wmn-probe", "mtrebosc", ttl, false, || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({"v": 1}))
                })
                .await
                .unwrap();
            assert_eq!(v, json!({"v": 1}));
            clock.fetch_add(1_000, Ordering::SeqCst); // still well within the 60s TTL
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a TTL hit must not re-invoke fetch"
        );
    }

    #[tokio::test]
    async fn ttl_expiry_triggers_a_fresh_fetch() {
        let (cache, clock) = cache_with_clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let ttl = Duration::from_secs(10);

        cache
            .get_or_fetch("wmn-probe", "mtrebosc", ttl, false, {
                let calls = calls.clone();
                || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({"v": 1}))
                }
            })
            .await
            .unwrap();

        clock.fetch_add(11_000, Ordering::SeqCst); // past the 10s TTL

        let v = cache
            .get_or_fetch("wmn-probe", "mtrebosc", ttl, false, {
                let calls = calls.clone();
                || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({"v": 2}))
                }
            })
            .await
            .unwrap();

        assert_eq!(v, json!({"v": 2}));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "an expired entry must trigger a refetch"
        );
    }

    #[tokio::test]
    async fn bypass_forces_a_miss_even_well_within_ttl() {
        let (cache, _clock) = cache_with_clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let ttl = Duration::from_secs(3600);

        cache
            .get_or_fetch("wmn-probe", "mtrebosc", ttl, false, {
                let calls = calls.clone();
                || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({"v": 1}))
                }
            })
            .await
            .unwrap();

        // Well within TTL, but a manual refresh must force a genuine re-fetch.
        let v = cache
            .get_or_fetch("wmn-probe", "mtrebosc", ttl, true, {
                let calls = calls.clone();
                || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({"v": 2}))
                }
            })
            .await
            .unwrap();

        assert_eq!(v, json!({"v": 2}));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "bypass must not be served from cache"
        );
    }

    #[tokio::test]
    async fn concurrent_callers_for_the_same_key_produce_exactly_one_fetch() {
        let db = ozint_db::open_memory().unwrap();
        let cache = Arc::new(ToolCache::new(db));
        let calls = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(tokio::sync::Notify::new());
        let ttl = Duration::from_secs(60);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let calls = calls.clone();
            let notify = notify.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_fetch("wmn-probe", "mtrebosc", ttl, false, || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        // Park here so the other 7 callers have a chance to arrive while this
                        // one is still "in flight" — proving the race, not just a warm cache.
                        notify.notified().await;
                        Ok(json!({"hits": 14}))
                    })
                    .await
            }));
        }

        // Let every spawned task reach a pending await: the leader parked on `notify`, every
        // follower parked inside `OnceCell`'s own internal wait.
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        notify.notify_waiters();

        for h in handles {
            assert_eq!(h.await.unwrap().unwrap(), json!({"hits": 14}));
        }

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "single-flight must collapse N concurrent callers into exactly one fetch"
        );
    }

    #[tokio::test]
    async fn peek_does_not_trigger_a_fetch_and_reflects_ttl() {
        let (cache, clock) = cache_with_clock();
        assert_eq!(
            cache.peek("wmn-probe", "mtrebosc", Duration::from_secs(60)),
            None
        );

        cache
            .get_or_fetch(
                "wmn-probe",
                "mtrebosc",
                Duration::from_secs(60),
                false,
                || async { Ok(json!({"v": 1})) },
            )
            .await
            .unwrap();

        assert_eq!(
            cache.peek("wmn-probe", "mtrebosc", Duration::from_secs(60)),
            Some(json!({"v": 1}))
        );

        clock.fetch_add(61_000, Ordering::SeqCst);
        assert_eq!(
            cache.peek("wmn-probe", "mtrebosc", Duration::from_secs(60)),
            None,
            "stale row must not be served"
        );
    }

    #[tokio::test]
    async fn a_failed_fetch_is_never_cached_and_the_next_call_retries() {
        let (cache, _clock) = cache_with_clock();
        let calls = Arc::new(AtomicUsize::new(0));

        let first = cache
            .get_or_fetch("wmn-probe", "mtrebosc", Duration::from_secs(60), false, {
                let calls = calls.clone();
                || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err("boom".to_string())
                }
            })
            .await;
        assert_eq!(first, Err("boom".to_string()));

        let second = cache
            .get_or_fetch("wmn-probe", "mtrebosc", Duration::from_secs(60), false, {
                let calls = calls.clone();
                || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(json!({"v": 1}))
                }
            })
            .await;
        assert_eq!(second, Ok(json!({"v": 1})));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a failure must not be cached — the next call must retry"
        );
    }
}
