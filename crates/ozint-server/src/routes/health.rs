use axum::Json;
use serde_json::{Value, json};

/// `GET /api/health` — liveness probe for the Rust server itself.
pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "runtime": "rust",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
