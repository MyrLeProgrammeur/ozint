//! `POST /api/ozint/spawn {investigationId, relationId}` — spawn a new investigation from a
//! relation.
//!
//! Searching a relation opens a **brand-new, independent investigation**: its own root, its
//! own visited set, its own lookup meter, its own subject file. It is never grafted onto the
//! tree that surfaced it. The product rule is *one person, one tree*, and the engine has a
//! second, mechanical reason of its own: the visited/dedup set is a property of
//! a tree, so grafting a second person into it would make their overlapping findings
//! ("already in tree") silently suppress each other.
//!
//! The link back is **one-way**: the new investigation records
//! `spawned_from_investigation_id` + `spawned_from_relation`. The source tree records nothing.
//!
//! ## This route creates; it does not fire
//!
//! It returns the new investigation and its root node, and stops. Firing stays entirely in
//! `POST /api/ozint/fire {investigationId, parentNodeId}` — one place that opens an SSE
//! stream, one place that owns cancellation. That also makes spawn cheap and safe to call: it
//! reaches no third party at all, which is why it lives in the un-gated router.
//!
//! ## Spawning re-derives the relation first
//!
//! The request names a relation *id*, never a raw value. The relation is then re-derived from
//! the source tree and must still be there. So a relation whose evidence the analyst has since
//! rejected cannot be spawned from a stale panel — it answers `409`, which is the honest
//! outcome: that relation no longer exists.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use ozint::relations;
use ozint::{Investigation, NodeStatus, OzNode, OzPayload, Provenance, classify, normalize, store};

use super::classifier_llm::LlmClassifier;
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpawnBody {
    investigation_id: Option<String>,
    relation_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SpawnResponse {
    investigation: Investigation,
    root_node: OzNode,
    /// False when this relation had already been spawned and the existing investigation is
    /// being handed back instead of a second identical one.
    created: bool,
}

pub async fn spawn(State(state): State<AppState>, Json(body): Json<SpawnBody>) -> Response {
    let (Some(investigation_id), Some(relation_id)) = (
        body.investigation_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        body.relation_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    ) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "investigationId and relationId are both required" })),
        )
            .into_response();
    };

    let source = match store::get_investigation(&state.db, investigation_id) {
        Ok(Some(inv)) => inv,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "investigation not found" })),
            )
                .into_response();
        }
        Err(e) => return server_error(e),
    };

    // Re-derive rather than trust the client's copy of the card. See the module doc.
    let nodes = match store::list_nodes(&state.db, &source.id) {
        Ok(nodes) => nodes,
        Err(e) => return server_error(e),
    };
    let report = relations::infer(&nodes);
    let Some(relation) = report.relations.into_iter().find(|r| r.id == relation_id) else {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "that relation is no longer derived from this investigation — it may rest on a node that has since been rejected or edited",
                "relationId": relation_id,
            })),
        )
            .into_response();
    };

    // Idempotent: the same card clicked twice hands back the same tree.
    match store::find_spawned(&state.db, &source.id, &relation.id) {
        Ok(Some(existing)) => {
            return match store::get_node(&state.db, &existing.root_node_id) {
                Ok(Some(root_node)) => {
                    Json(SpawnResponse { investigation: existing, root_node, created: false })
                        .into_response()
                }
                // The row exists but its root does not: a genuinely broken record, reported
                // rather than silently replaced by a fresh spawn that would orphan it.
                Ok(None) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "an investigation was already spawned from this relation but its root node is missing",
                        "investigationId": existing.id,
                    })),
                )
                    .into_response(),
                Err(e) => server_error(e),
            };
        }
        Ok(None) => {}
        Err(e) => return server_error(e),
    }

    // The seed goes through the classifier like any other, rather than trusting the relation's
    // own `subject_type`: classification is the one place that decides what a value *is*, and a
    // second opinion embedded in a relation card would be a second source of truth.
    //
    // It escalates to the LLM tier on the same terms as Autofire does. A relation subject is
    // machine-derived, but that does not make it unambiguous: "Jane Doe" lifted off a profile
    // card is exactly the Name-vs-Directory coin flip the deterministic tier cannot settle.
    // The locked rule this must respect bans *per-keystroke* classification; a spawn is a
    // single button click, so it qualifies the same way Autofire does.
    let seed = relation.subject.trim();
    let classification =
        classify::classify_with_llm(seed, &LlmClassifier::new(state.freeze.is_frozen())).await;
    let oz_type = classification.oz_type;
    let normalized = normalize::normalize(oz_type, seed);

    let investigation_id = uuid::Uuid::new_v4().to_string();
    let root_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    let investigation = Investigation {
        id: investigation_id.clone(),
        seed_input: seed.to_string(),
        seed_type: oz_type,
        root_node_id: root_id.clone(),
        created_at: now,
        updated_at: now,
        // Fresh meter. A spawned investigation inherits nothing it did not spend.
        lookups: 0,
        cost_cents: 0,
        spawned_from_investigation_id: Some(source.id.clone()),
        spawned_from_relation: Some(relation.id.clone()),
    };
    if let Err(e) = store::create_investigation(&state.db, &investigation) {
        return server_error(e);
    }

    let mut provenance = Provenance::new(
        "relation-spawn",
        format!(
            "spawned from a {} relation in a separate investigation",
            relation.kind.label()
        ),
    );
    // Gating follows the relation across the tree boundary. A subject reached only because a
    // gated tool matched a face does not become ungated by being looked at in a new window.
    provenance.gated = relation.gated;

    let root_node = OzNode {
        id: root_id,
        investigation_id,
        parent_id: None,
        layer_id: None,
        ordinal: 0,
        depth: 0,
        oz_type,
        value: normalized.key.clone(),
        display: normalized.display,
        dedup_key: normalize::dedup_key(oz_type, seed),
        payload: OzPayload::empty_for(oz_type),
        preview_signal: None,
        full_signal: None,
        sections: Vec::new(),
        gated: relation.gated,
        status: NodeStatus::Idle,
        provenance,
        already_in_tree: None,
        corroborations: Vec::new(),
        edited_value: None,
        created_at: now,
    };
    if let Err(e) = store::insert_node(&state.db, &root_node) {
        return server_error(e);
    }

    (
        StatusCode::CREATED,
        Json(SpawnResponse {
            investigation,
            root_node,
            created: true,
        }),
    )
        .into_response()
}

fn server_error(err: impl std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": err.to_string() })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozint::types::UsernamePayload;
    use ozint::{OzRow, OzType, RecordStatus};

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn node_with_name(id: &str, handle: &str, name: &str) -> OzNode {
        OzNode {
            id: id.into(),
            investigation_id: "inv-1".into(),
            parent_id: None,
            layer_id: None,
            ordinal: 0,
            depth: 0,
            oz_type: OzType::Username,
            value: handle.into(),
            display: handle.into(),
            dedup_key: normalize::dedup_key(OzType::Username, handle),
            payload: OzPayload::Username(UsernamePayload {
                profile: vec![OzRow {
                    label: "Name".into(),
                    value: name.into(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            preview_signal: None,
            full_signal: None,
            sections: Vec::new(),
            gated: false,
            status: NodeStatus::Settled,
            provenance: Provenance::new("github-user", "queried the GitHub user API"),
            already_in_tree: None,
            corroborations: Vec::new(),
            edited_value: None,
            created_at: Utc::now(),
        }
    }

    /// A source investigation whose tree yields exactly one relation: Grace Lovelace, by
    /// shared surname with Ada Lovelace.
    fn seed_source(state: &AppState) -> String {
        let now = Utc::now();
        store::create_investigation(
            &state.db,
            &Investigation {
                id: "inv-1".into(),
                seed_input: "ada".into(),
                seed_type: OzType::Username,
                root_node_id: "n1".into(),
                created_at: now,
                updated_at: now,
                lookups: 7,
                cost_cents: 42,
                spawned_from_investigation_id: None,
                spawned_from_relation: None,
            },
        )
        .unwrap();
        store::insert_node(&state.db, &node_with_name("n1", "ada", "Ada Lovelace")).unwrap();
        let mut second = node_with_name("n2", "grace", "Grace Lovelace");
        second.ordinal = 1;
        store::insert_node(&state.db, &second).unwrap();

        let nodes = store::list_nodes(&state.db, "inv-1").unwrap();
        relations::infer(&nodes)
            .relations
            .first()
            .expect("one relation")
            .id
            .clone()
    }

    #[tokio::test]
    async fn spawning_creates_a_separate_tree_linked_one_way() {
        let state = crate::test_support::test_state();
        let relation_id = seed_source(&state);

        let response = spawn(
            State(state.clone()),
            Json(SpawnBody {
                investigation_id: Some("inv-1".into()),
                relation_id: Some(relation_id.clone()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let json = body_json(response).await;

        assert_eq!(json["created"], true);
        assert_ne!(
            json["investigation"]["id"], "inv-1",
            "a relation never joins the source tree"
        );
        assert_eq!(json["investigation"]["spawnedFromInvestigationId"], "inv-1");
        assert_eq!(json["investigation"]["spawnedFromRelation"], relation_id);
        assert_eq!(
            json["investigation"]["lookups"], 0,
            "a fresh meter, inheriting nothing"
        );
        assert_eq!(json["investigation"]["costCents"], 0);
        assert_eq!(json["rootNode"]["display"], "Grace Lovelace");
        assert_eq!(
            json["rootNode"]["depth"], 0,
            "the spawned node is a root, not a child"
        );
        assert!(json["rootNode"]["parentId"].is_null());

        // And the source tree is untouched — the link really is one-way.
        let source = store::get_investigation(&state.db, "inv-1")
            .unwrap()
            .unwrap();
        assert!(source.spawned_from_investigation_id.is_none());
        assert_eq!(store::list_nodes(&state.db, "inv-1").unwrap().len(), 2);
    }

    #[tokio::test]
    async fn the_seed_goes_through_the_classifier() {
        let state = crate::test_support::test_state();
        let relation_id = seed_source(&state);
        let json = body_json(
            spawn(
                State(state),
                Json(SpawnBody {
                    investigation_id: Some("inv-1".into()),
                    relation_id: Some(relation_id),
                }),
            )
            .await,
        )
        .await;
        // A two-word personal name classifies as NAM, which dispatches to the directory
        // orchestrator — not as a username.
        assert_eq!(json["investigation"]["seedType"], "name");
        assert_eq!(json["rootNode"]["type"], "name");
    }

    #[tokio::test]
    async fn spawning_the_same_relation_twice_hands_back_the_same_tree() {
        let state = crate::test_support::test_state();
        let relation_id = seed_source(&state);
        let body = || SpawnBody {
            investigation_id: Some("inv-1".into()),
            relation_id: Some(relation_id.clone()),
        };

        let first = body_json(spawn(State(state.clone()), Json(body())).await).await;
        let second_response = spawn(State(state.clone()), Json(body())).await;
        assert_eq!(second_response.status(), StatusCode::OK);
        let second = body_json(second_response).await;

        assert_eq!(second["created"], false);
        assert_eq!(first["investigation"]["id"], second["investigation"]["id"]);
        assert_eq!(
            store::list_investigations(&state.db, 50).unwrap().len(),
            2,
            "a double click must not leave the analyst two identical trees to reconcile"
        );
    }

    #[tokio::test]
    async fn a_relation_whose_evidence_was_rejected_can_no_longer_be_spawned() {
        // The stale-panel case. The card is still on the analyst's screen; the relation behind
        // it is gone. Answering 409 says so instead of opening an investigation into something
        // this tree no longer claims.
        let state = crate::test_support::test_state();
        let relation_id = seed_source(&state);

        let mut second = store::get_node(&state.db, "n2").unwrap().unwrap();
        second.provenance.record_status = RecordStatus::Rejected {
            rejected_at: Utc::now(),
        };
        store::insert_node(&state.db, &second).unwrap();

        let response = spawn(
            State(state),
            Json(SpawnBody {
                investigation_id: Some("inv-1".into()),
                relation_id: Some(relation_id),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn an_unknown_relation_id_is_a_conflict_not_a_silent_spawn() {
        let state = crate::test_support::test_state();
        seed_source(&state);
        let response = spawn(
            State(state),
            Json(SpawnBody {
                investigation_id: Some("inv-1".into()),
                relation_id: Some("shared-surname:nobody at all".into()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn an_unknown_investigation_is_a_404() {
        let state = crate::test_support::test_state();
        let response = spawn(
            State(state),
            Json(SpawnBody {
                investigation_id: Some("nope".into()),
                relation_id: Some("x".into()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_missing_field_is_a_400() {
        let state = crate::test_support::test_state();
        let response = spawn(State(state), Json(SpawnBody::default())).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn the_body_parses_camel_case() {
        let body: SpawnBody =
            serde_json::from_str(r#"{"investigationId":"inv-1","relationId":"r-1"}"#).unwrap();
        assert_eq!(body.investigation_id.as_deref(), Some("inv-1"));
        assert_eq!(body.relation_id.as_deref(), Some("r-1"));
    }
}
