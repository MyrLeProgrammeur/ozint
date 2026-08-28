//! `GET|POST /api/safety/freeze` — the server half of the kill switch, plus the middleware
//! that actually enforces it.
//!
//! The state lives in [`ozint_core::safety::freeze`]; this module is only the surface and
//! the gate. Three things worth knowing before changing anything here:
//!
//! **1. The freeze route itself is never gated.** Whatever else a freeze refuses, lifting it
//! has to keep working — a kill switch you cannot un-flip is a brick, not a safety feature.
//!
//! **2. Engaging a freeze kills what is already running.** Refusing *new* requests while an
//! OZINT layer keeps firing tools at third-party services would satisfy the letter of "frozen"
//! and none of its point. `POST {"frozen":true}` therefore cancels every live layer on its way
//! in, and reports how many it hit.
//!
//! **3. What is gated, and what deliberately is not.** The gate covers every route that makes
//! an outbound call or takes an action; it does **not** cover local reads. A frozen OZINT
//! should be inspectable — the analyst can still read an investigation tree, browse code, list
//! memory — it just cannot reach out or act. The exact list is in [`super::super::app`], one
//! `.route()` per line, because an implicit rule here would be one nobody can audit.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::state::AppState;

/// `GET /api/safety/freeze` — the current record, including an `unreadable` reason when the
/// state was forced closed because the stored file could not be parsed.
pub async fn get(State(state): State<AppState>) -> Response {
    Json(state.freeze.snapshot()).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FreezeBody {
    frozen: bool,
    /// Who flipped it, for display only. Defaults to `"api"`.
    #[serde(default)]
    source: Option<String>,
}

/// `POST /api/safety/freeze` — sets the state, and on engage cancels every live OZINT layer.
///
/// Returns **500** with the full record when the state could not be persisted. The value *is*
/// in force in this process either way; the 500 says "it will not survive a restart", which is
/// exactly the thing an analyst must not learn by accident later.
pub async fn set(State(state): State<AppState>, Json(body): Json<FreezeBody>) -> Response {
    let source = body
        .source
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("api");
    let update = state.freeze.set(body.frozen, source);

    let layers_cancelled = if body.frozen {
        state.ozint.cancel_all()
    } else {
        0
    };

    let mut payload = json!({
        "record": update.record,
        "persisted": update.persist_error.is_none(),
        "layersCancelled": layers_cancelled,
    });
    if let Some(reason) = &update.persist_error {
        payload["persistError"] = json!(reason);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(payload)).into_response();
    }
    Json(payload).into_response()
}

/// The gate. Applied with `route_layer` to the acting/outbound half of the router, so it runs
/// only for those paths and never for a 404.
///
/// **423 Locked**, not 403: the condition is temporary and self-inflicted, and the client can
/// clear it by calling this very namespace. The body carries the record so a surface can say
/// *when* it was frozen rather than just that it is.
pub async fn freeze_gate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if state.freeze.is_frozen() {
        let record = state.freeze.snapshot();
        let path = request.uri().path().to_string();
        tracing::info!(target: "ozint::safety::freeze", %path, "refused: OZINT is frozen");
        return (
            StatusCode::LOCKED,
            Json(json!({ "error": "OZINT is frozen", "record": record })),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use ozint::fetch::CancelHandle;
    use tower::ServiceExt;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn a_fresh_server_is_not_frozen() {
        let state = crate::test_support::test_state();
        let json = body_json(get(State(state)).await).await;
        assert_eq!(json["frozen"], false);
    }

    #[tokio::test]
    async fn setting_the_freeze_is_visible_to_the_next_read() {
        let state = crate::test_support::test_state();
        let response = set(
            State(state.clone()),
            Json(FreezeBody {
                frozen: true,
                source: Some("voice".into()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let json = body_json(get(State(state)).await).await;
        assert_eq!(json["frozen"], true);
        assert_eq!(json["source"], "voice");
    }

    #[tokio::test]
    async fn engaging_a_freeze_kills_every_live_layer() {
        let state = crate::test_support::test_state();
        let (handle_a, signal_a) = CancelHandle::new();
        let (handle_b, signal_b) = CancelHandle::new();
        state.ozint.register_cancel("inv-1", "layer-a", handle_a);
        state.ozint.register_cancel("inv-2", "layer-b", handle_b);

        let json = body_json(
            set(
                State(state),
                Json(FreezeBody {
                    frozen: true,
                    source: None,
                }),
            )
            .await,
        )
        .await;

        assert_eq!(
            json["layersCancelled"], 2,
            "a freeze that lets running tools finish is not a freeze"
        );
        assert!(signal_a.is_cancelled());
        assert!(signal_b.is_cancelled());
    }

    #[tokio::test]
    async fn lifting_a_freeze_cancels_nothing() {
        let state = crate::test_support::test_state();
        let (handle, signal) = CancelHandle::new();
        state.ozint.register_cancel("inv-1", "layer-a", handle);

        let json = body_json(
            set(
                State(state),
                Json(FreezeBody {
                    frozen: false,
                    source: None,
                }),
            )
            .await,
        )
        .await;

        assert_eq!(json["layersCancelled"], 0);
        assert!(!signal.is_cancelled(), "unfreezing must not kill anything");
    }

    // ── The gate, exercised through the real router ─────────────────────────────────────

    async fn call(state: AppState, method: &str, path: &str) -> Response {
        let request = HttpRequest::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        crate::app::router(state).oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn a_frozen_server_refuses_an_outbound_route_with_423() {
        let state = crate::test_support::test_state();
        let _ = state.freeze.set(true, "test");

        let response = call(state, "POST", "/api/ozint/fire").await;
        assert_eq!(response.status(), StatusCode::LOCKED);
        let json = body_json(response).await;
        assert_eq!(json["record"]["frozen"], true);
    }

    #[tokio::test]
    async fn a_frozen_server_refuses_a_node_refresh_too() {
        // A refresh fans out to the same third parties a layer does. Under-gating it would be
        // an egress leak while the UI says "frozen" — the exact failure this gate exists for.
        let state = crate::test_support::test_state();
        let _ = state.freeze.set(true, "test");

        let response = call(state, "POST", "/api/ozint/refresh").await;
        assert_eq!(response.status(), StatusCode::LOCKED);
    }

    #[tokio::test]
    async fn a_frozen_server_still_serves_local_reads() {
        let state = crate::test_support::test_state();
        let _ = state.freeze.set(true, "test");

        let response = call(state, "GET", "/api/ozint/investigations").await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a frozen OZINT must still be inspectable — freeze cuts actions, not reading"
        );
    }

    #[tokio::test]
    async fn the_freeze_route_itself_is_never_gated() {
        let state = crate::test_support::test_state();
        let _ = state.freeze.set(true, "test");

        let response = call(state.clone(), "GET", "/api/safety/freeze").await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a kill switch you cannot read is a brick"
        );

        let request = HttpRequest::builder()
            .method("POST")
            .uri("/api/safety/freeze")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"frozen":false}"#))
            .unwrap();
        let response = crate::app::router(state.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a kill switch you cannot un-flip is a brick"
        );
        assert!(!state.freeze.is_frozen());
    }

    #[tokio::test]
    async fn an_unfrozen_server_lets_a_gated_route_through_to_its_own_handler() {
        let state = crate::test_support::test_state();
        // `/api/ozint/fire` with an empty body is a 400 from its own handler — the point is
        // that it is *not* a 423, i.e. the gate is transparent when nothing is frozen.
        let response = call(state, "POST", "/api/ozint/fire").await;
        assert_ne!(response.status(), StatusCode::LOCKED);
    }
}
