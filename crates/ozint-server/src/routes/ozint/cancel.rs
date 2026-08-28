//! `POST /api/ozint/cancel {investigationId}` or `{layerId}` — flips the matching
//! `CancelHandle`. A real, separate endpoint, never inferred from the SSE response future
//! being dropped: see `runtime.rs`'s module doc for why (a closed tab does not propagate
//! promptly, and queued tool calls keep spending real, sometimes rate-limited, quota).

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelBody {
    investigation_id: Option<String>,
    layer_id: Option<String>,
}

/// What one [`CancelBody`] resolves to. Pulled out as a pure function so the precedence rule
/// (a specific `layerId` wins over a broader `investigationId` when a caller sends both) is
/// testable without a live `AppState`.
enum CancelTarget<'a> {
    Layer(&'a str),
    Investigation(&'a str),
    Invalid,
}

fn select_target(body: &CancelBody) -> CancelTarget<'_> {
    if let Some(layer_id) = body
        .layer_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return CancelTarget::Layer(layer_id);
    }
    if let Some(investigation_id) = body
        .investigation_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return CancelTarget::Investigation(investigation_id);
    }
    CancelTarget::Invalid
}

/// `POST /api/ozint/cancel` — see the module doc.
pub async fn cancel(State(state): State<AppState>, Json(body): Json<CancelBody>) -> Response {
    match select_target(&body) {
        CancelTarget::Layer(layer_id) => {
            let cancelled = state.ozint.cancel_layer(layer_id);
            Json(json!({ "cancelled": cancelled })).into_response()
        }
        CancelTarget::Investigation(investigation_id) => {
            let hit = state.ozint.cancel_investigation(investigation_id);
            Json(json!({ "cancelled": hit > 0, "layersCancelled": hit })).into_response()
        }
        CancelTarget::Invalid => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "provide `investigationId` or `layerId`" })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozint::fetch::CancelHandle;

    #[test]
    fn cancel_body_deserializes_camel_case() {
        let body: CancelBody = serde_json::from_str(r#"{"investigationId":"inv-1"}"#).unwrap();
        assert_eq!(body.investigation_id.as_deref(), Some("inv-1"));
        assert!(body.layer_id.is_none());

        let body: CancelBody = serde_json::from_str(r#"{"layerId":"layer-1"}"#).unwrap();
        assert_eq!(body.layer_id.as_deref(), Some("layer-1"));
    }

    #[test]
    fn a_layer_id_takes_precedence_over_an_investigation_id() {
        let body = CancelBody {
            investigation_id: Some("inv-1".into()),
            layer_id: Some("layer-1".into()),
        };
        assert!(matches!(
            select_target(&body),
            CancelTarget::Layer("layer-1")
        ));
    }

    #[test]
    fn falls_back_to_investigation_when_no_layer_id_given() {
        let body = CancelBody {
            investigation_id: Some("inv-1".into()),
            layer_id: None,
        };
        assert!(matches!(
            select_target(&body),
            CancelTarget::Investigation("inv-1")
        ));
    }

    #[test]
    fn blank_strings_are_treated_as_absent() {
        let body = CancelBody {
            investigation_id: Some("   ".into()),
            layer_id: Some("".into()),
        };
        assert!(matches!(select_target(&body), CancelTarget::Invalid));
    }

    #[test]
    fn neither_field_is_invalid() {
        assert!(matches!(
            select_target(&CancelBody::default()),
            CancelTarget::Invalid
        ));
    }

    // ── Handler-level: registry lifecycle end to end through the real function ──────────

    #[tokio::test]
    async fn cancel_by_layer_id_flips_a_registered_handle() {
        let state = crate::test_support::test_state();
        let (handle, signal) = CancelHandle::new();
        state.ozint.register_cancel("inv-1", "layer-1", handle);

        let response = cancel(
            State(state),
            Json(CancelBody {
                investigation_id: None,
                layer_id: Some("layer-1".into()),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(signal.is_cancelled());
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["cancelled"], true);
    }

    #[tokio::test]
    async fn cancel_by_investigation_id_reports_how_many_branches_it_hit() {
        let state = crate::test_support::test_state();
        let (handle_a, signal_a) = CancelHandle::new();
        let (handle_b, signal_b) = CancelHandle::new();
        state.ozint.register_cancel("inv-1", "layer-a", handle_a);
        state.ozint.register_cancel("inv-1", "layer-b", handle_b);

        let response = cancel(
            State(state),
            Json(CancelBody {
                investigation_id: Some("inv-1".into()),
                layer_id: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(signal_a.is_cancelled());
        assert!(signal_b.is_cancelled());
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["cancelled"], true);
        assert_eq!(json["layersCancelled"], 2);
    }

    #[tokio::test]
    async fn cancel_with_neither_field_is_a_bad_request() {
        let state = crate::test_support::test_state();
        let response = cancel(State(state), Json(CancelBody::default())).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cancelling_an_unknown_layer_reports_false_not_an_error() {
        let state = crate::test_support::test_state();
        let response = cancel(
            State(state),
            Json(CancelBody {
                investigation_id: None,
                layer_id: Some("ghost-layer".into()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["cancelled"], false);
    }
}
