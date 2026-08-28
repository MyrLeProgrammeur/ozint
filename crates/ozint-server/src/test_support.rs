//! Shared `#[cfg(test)]` helpers for route unit tests.

use crate::state::AppState;

pub fn test_state() -> AppState {
    let db = ozint_db::open_memory().unwrap();
    AppState {
        http: ozint_core::http::client(),
        ozint: Default::default(),
        ozint_scheduler: crate::state::build_ozint_scheduler(db.clone()),
        ozint_cache: std::sync::Arc::new(ozint::cache::ToolCache::new(db.clone())),
        db,
        // In-memory: a test must never read or write the machine's real freeze file.
        freeze: Default::default(),
    }
}
