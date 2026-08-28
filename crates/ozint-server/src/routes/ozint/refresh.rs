//! `POST /api/ozint/refresh {nodeId}` — the wire half of node refresh.
//!
//! Plain JSON, not SSE, and that is the honest shape: a refresh re-runs one node's own tool
//! chain and returns one verdict about one node. It opens no layer, creates no layer row,
//! emits no `LayerEvent` and produces no children — so there is no multiplexed stream for it
//! to belong to. See `ozint::refresh`'s module doc for every rule the engine enforces.
//!
//! Two things this handler owns that the engine cannot:
//!
//! 1. **Registering a cancel handle.** A refresh can fan out across a whole directory's tiles
//!    or a multi-tool chain, so it must be reachable by `POST /api/ozint/cancel` and, more
//!    importantly, by the kill switch's `cancel_all`. Without this a freeze would stop new
//!    requests while every in-flight refresh kept hitting third parties — a freeze in name
//!    only, which is exactly the gap the kill switch closed for layers. The handle is
//!    registered under a synthetic `refresh-<uuid>` layer id: no client can name it (none is
//!    ever sent one), but `cancel_investigation` and `cancel_all` both sweep by registration,
//!    so both reach it.
//! 2. **Distinguishing "cannot be re-run" from "nothing changed."** A node with no replayable
//!    tool chain answers `422`, never `200 {changed: false}`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use ozint::fetch::CancelHandle;
use ozint::outcome::ToolReport;
use ozint::refresh::{RefreshError, RefreshResult, refresh_node};
use ozint::{OzNode, store};

use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshBody {
    node_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RefreshResponse {
    node: OzNode,
    changed: bool,
    changed_fields: Vec<String>,
    reports: Vec<ToolReport>,
    /// Child seeds the replayed tools offered and this refresh did not act on — a refresh
    /// never touches children, and saying how many it declined is what keeps that rule from
    /// looking like a source that went quiet.
    children_ignored: usize,
    lookups: i64,
    cost_cents: i64,
    aborted: bool,
}

impl From<RefreshResult> for RefreshResponse {
    fn from(r: RefreshResult) -> Self {
        Self {
            node: r.node,
            changed: r.changed,
            changed_fields: r.changed_fields,
            reports: r.reports,
            children_ignored: r.children_ignored,
            lookups: r.lookups,
            cost_cents: r.cost_cents,
            aborted: r.aborted,
        }
    }
}

pub async fn refresh(State(state): State<AppState>, Json(body): Json<RefreshBody>) -> Response {
    let Some(node_id) = body
        .node_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "nodeId is required" })),
        )
            .into_response();
    };

    // The investigation id is needed before the refresh runs, so the cancel handle can be
    // registered where an investigation-wide cancel will find it.
    let investigation_id = match store::get_node(&state.db, node_id) {
        Ok(Some(node)) => node.investigation_id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "node not found" })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let (handle, signal) = CancelHandle::new();
    let pseudo_layer_id = format!("refresh-{}", uuid::Uuid::new_v4());
    state
        .ozint
        .register_cancel(&investigation_id, &pseudo_layer_id, handle);

    let outcome = refresh_node(
        &state.db,
        node_id,
        Some(signal),
        Some(state.ozint_cache.clone()),
    )
    .await;

    state
        .ozint
        .remove_cancel(&investigation_id, &pseudo_layer_id);

    match outcome {
        Ok(result) => Json(RefreshResponse::from(result)).into_response(),
        Err(RefreshError::NodeNotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "node not found" })),
        )
            .into_response(),
        // 422, not 400: the request was perfectly well-formed, the node simply carries nothing
        // this build can re-invoke. The chain travels with the error so the cockpit can name
        // the tools instead of showing a shrug.
        Err(RefreshError::NothingToReplay { chain, reason }) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": reason, "toolChain": chain })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ozint::{Investigation, NodeStatus, OzPayload, OzType, Provenance};

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn seed(state: &AppState, chain: &[&str]) {
        let now = Utc::now();
        store::create_investigation(
            &state.db,
            &Investigation {
                id: "inv-1".into(),
                seed_input: "mtrebosc".into(),
                seed_type: OzType::Username,
                root_node_id: "node-1".into(),
                created_at: now,
                updated_at: now,
                lookups: 0,
                cost_cents: 0,
                spawned_from_investigation_id: None,
                spawned_from_relation: None,
            },
        )
        .unwrap();

        let mut provenance = Provenance::new("seed", "typed by the analyst");
        provenance.tool_chain = chain.iter().map(|s| s.to_string()).collect();

        store::insert_node(
            &state.db,
            &OzNode {
                id: "node-1".into(),
                investigation_id: "inv-1".into(),
                parent_id: None,
                layer_id: None,
                ordinal: 0,
                depth: 0,
                oz_type: OzType::Username,
                value: "mtrebosc".into(),
                display: "mtrebosc".into(),
                dedup_key: "username:mtrebosc".into(),
                payload: OzPayload::empty_for(OzType::Username),
                preview_signal: None,
                full_signal: None,
                sections: Vec::new(),
                gated: false,
                status: NodeStatus::Settled,
                provenance,
                already_in_tree: None,
                corroborations: Vec::new(),
                edited_value: None,
                created_at: now,
            },
        )
        .unwrap();
    }

    #[tokio::test]
    async fn a_missing_node_id_is_a_400() {
        let state = crate::test_support::test_state();
        let response = refresh(State(state), Json(RefreshBody::default())).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_unknown_node_is_a_404() {
        let state = crate::test_support::test_state();
        let response = refresh(
            State(state),
            Json(RefreshBody {
                node_id: Some("nope".into()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_node_that_cannot_be_re_run_is_a_422_naming_its_chain() {
        // The distinction this route exists to keep: "we re-checked and nothing moved" (200)
        // and "there was nothing here to re-check" (422) must never render identically.
        let state = crate::test_support::test_state();
        seed(&state, &["seed"]);

        let response = refresh(
            State(state),
            Json(RefreshBody {
                node_id: Some("node-1".into()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let json = body_json(response).await;
        assert_eq!(json["toolChain"], serde_json::json!(["seed"]));
        assert!(json["error"].as_str().unwrap().contains("registry"));
    }

    #[tokio::test]
    async fn the_cancel_handle_is_removed_once_the_refresh_returns() {
        // A handle outliving its refresh would leak, and would let a later cancel "succeed"
        // against something that finished long ago.
        let state = crate::test_support::test_state();
        seed(&state, &["seed"]);

        let _ = refresh(
            State(state.clone()),
            Json(RefreshBody {
                node_id: Some("node-1".into()),
            }),
        )
        .await;
        assert_eq!(state.ozint.cancel_investigation("inv-1"), 0);
    }

    #[test]
    fn the_body_parses_camel_case() {
        let body: RefreshBody = serde_json::from_str(r#"{"nodeId":"node-1"}"#).unwrap();
        assert_eq!(body.node_id.as_deref(), Some("node-1"));
    }
}
