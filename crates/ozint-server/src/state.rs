use std::sync::Arc;

use crate::routes::ozint::OzintState;

/// Shared state handed to every axum handler.
///
/// Cheap to clone: it only holds handles.
#[derive(Clone)]
pub struct AppState {
    /// One shared connection pool, so 60 tools firing in a layer reuse connections
    /// instead of opening 60.
    pub http: ozint_core::http::Client,
    pub db: ozint_db::Db,
    /// Live `CancelHandle`s plus the per-investigation `VisitedSet`/`ToolHealth` pair —
    /// see `routes::ozint::state`.
    pub ozint: Arc<OzintState>,
    /// Per-`rate_key` quota enforcement.
    ///
    /// Process-wide and built once, which is the whole point: a quota is a property of the
    /// upstream source, so two investigations running at once must contend for the same
    /// windows. One scheduler per investigation would let N concurrent branches each spend a
    /// full budget against a source that only has one.
    pub ozint_scheduler: Arc<ozint::scheduler::Scheduler>,
    /// Per-`(tool_id, cache_key)` response cache.
    ///
    /// Process-wide for the same reason the scheduler is, and it is the same reason twice: a
    /// cached upstream response is a property of the upstream, not of one investigation. The
    /// fetches most worth collapsing are precisely the ones every investigation makes
    /// identically — CISA's 1.6 MB KEV catalogue, WhatsMyName's ~730-entry site list — and a
    /// per-investigation cache would re-download each of them per investigation.
    pub ozint_cache: Arc<ozint::cache::ToolCache>,
    /// The kill switch — see `routes::safety` and `ozint_core::safety::freeze`. Enforced by
    /// the `freeze_gate` middleware in `app::router`, not by anything handlers have to
    /// remember to call.
    pub freeze: Arc<ozint_core::safety::FreezeState>,
}

/// Builds the scheduler with every catalogued `rate_key` registered.
///
/// Registration happens up front rather than lazily at first use, and the difference matters:
/// a key with **no** registered window admits instantly, so a source whose registration was
/// forgotten would be silently unthrottled — the failure mode being a rate-limit ban from an
/// upstream, noticed days later and nowhere near the cause.
/// `registry::rate_limits_for` deliberately answers an empty slice for sources whose quota this
/// project cannot cite. That is a stated absence, not a missed registration, and this loop
/// still walks past it so the key exists in the table either way.
///
/// Shared by `AppState::new` and the test-support constructor so the two cannot drift into
/// disagreeing about what is throttled.
pub fn build_ozint_scheduler(db: ozint_db::Db) -> Arc<ozint::scheduler::Scheduler> {
    let scheduler = ozint::scheduler::Scheduler::new(db);
    for rate_key in ozint::registry::rate_keys() {
        scheduler.register(rate_key, ozint::registry::rate_limits_for(rate_key));
    }
    Arc::new(scheduler)
}

impl AppState {
    pub fn new() -> anyhow::Result<Self> {
        let db = ozint_db::open_default()?;

        Ok(Self {
            http: ozint_core::http::client(),
            ozint_scheduler: build_ozint_scheduler(db.clone()),
            ozint_cache: Arc::new(ozint::cache::ToolCache::new(db.clone())),
            db,
            ozint: Default::default(),
            // Explicitly the file-backed variant: `FreezeState::default()` is in-memory, so a
            // freeze that did not survive a restart would be the silent failure mode.
            freeze: Arc::new(ozint_core::safety::FreezeState::from_data_dir()),
        })
    }
}
