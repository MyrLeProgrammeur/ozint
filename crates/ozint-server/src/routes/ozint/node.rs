//! `POST /api/ozint/node/{id}/edit|reject|restore` — the wire half of node editing.
//!
//! The analyst's three verdicts on a finding. **Nothing is ever deleted**: SAVE keeps the
//! tool's original value and chip verbatim inside `provenance.record_status`, MARK WRONG
//! excludes a node from the subject file and from relation inference while leaving it
//! rendered (struck through), and RESTORE undoes *only* the rejection — a node that was
//! corrected before being rejected comes back corrected, not as-returned.
//!
//! All three are **local writes that reach nothing**, so they stay live while the kill switch
//! is frozen: a frozen OZINT must still let its owner annotate what it already collected.
//!
//! The storage rules (dedup-key re-derivation on a correction, the first original surviving a
//! second edit, the pre-rejection status stash) live in `ozint::store` and are
//! documented there. This module owns the HTTP contract and one guard the store cannot
//! express — see below.
//!
//! ## Why editing a rejected node is refused
//!
//! `RecordStatus` is one enum with one slot: a node is `AsReturned`, `Corrected` **or**
//! `Rejected`. So writing a correction onto a rejected node would overwrite the rejection and
//! silently un-reject it — the node would quietly rejoin the subject file and relation
//! inference, with no event anywhere saying the analyst's "this is wrong" had been discarded.
//! Rather than model a fourth state nobody asked for, this route answers `409` and says to
//! restore first. The opposite order (correct, then reject) is fine and already supported: the
//! correction is stashed and comes back on restore.
//!
//! ## Why editing the **root** re-classifies
//!
//! A found node's type was decided by the tool that produced it. A **root**'s type was decided
//! by the classifier reading the analyst's own seed — so correcting a root's value is
//! correcting the classifier's input, and leaving the type behind produced an investigation
//! whose `seed_type` said `Username` while its seed said `8.8.8.8`. Nothing surfaced that; the
//! tree just planned the wrong tools forever. A root edit therefore goes back through
//! `classify_with_llm`, on the same terms as `spawn` (a single button click, not a keystroke,
//! so the no-per-keystroke-classification rule is respected). Settled 2026-08-23 — type is an
//! explicit, correctable thing.
//!
//! **A retype is refused once the root carries findings** (`409`). `OzPayload` is a tagged
//! union keyed on `oz_type`, so a `Username` payload under a node now claiming to be an `Ip`
//! does not read as stale — it reads as a different entity's findings. The two ways out are
//! to destroy them (which this unit's nothing-is-deleted rule forbids) or to refuse, and a
//! tree of username results is not a tree about an IP address anyway: that is a new
//! investigation, not a corrected one. Correcting the *spelling* of a root without changing
//! its type stays allowed at any time.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use ozint::types::OzPayload;
use ozint::{classify, store};

use crate::routes::ozint::classifier_llm::LlmClassifier;
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditBody {
    value: Option<String>,
}

fn server_error(err: impl std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": err.to_string() })),
    )
        .into_response()
}

/// Re-reads the node after a write so the client renders the server's truth rather than its
/// own optimistic guess at what the write did — the dedup key, the record status and the
/// preserved original are all derived server-side.
fn reread(state: &AppState, id: &str) -> Response {
    match store::get_node(&state.db, id) {
        Ok(Some(node)) => Json(node).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "node not found" })),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

/// `POST /api/ozint/node/{id}/edit {value}` — SAVE.
pub async fn edit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<EditBody>,
) -> Response {
    let Some(value) = body
        .value
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "value must not be empty" })),
        )
            .into_response();
    };

    let node = match store::get_node(&state.db, &id) {
        Ok(Some(node)) => node,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "node not found" })),
            )
                .into_response();
        }
        Err(e) => return server_error(e),
    };

    // See the module doc: a correction written over a rejection would erase it silently.
    if node.provenance.record_status.is_rejected() {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "this node is marked wrong — restore it before correcting it, or the rejection would be silently discarded",
            })),
        )
            .into_response();
    }

    if value == node.effective_value() {
        // Not an error, but not a correction either: recording one would push a no-op into the
        // provenance record that is this project's only audit trail.
        return Json(node).into_response();
    }

    // Is this the investigation's root? Only a root carries the classifier's verdict.
    let investigation = match store::get_investigation(&state.db, &node.investigation_id) {
        Ok(Some(inv)) => inv,
        // A node whose investigation row is gone is still editable as a plain value; there is
        // simply no seed to keep in step with it.
        Ok(None) => {
            return match store::edit_node(&state.db, &id, value) {
                Ok(true) => reread(&state, &id),
                Ok(false) => (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "node not found" })),
                )
                    .into_response(),
                Err(e) => server_error(e),
            };
        }
        Err(e) => return server_error(e),
    };

    let mut retype_to = None;
    if investigation.root_node_id == id {
        let classification =
            classify::classify_with_llm(value, &LlmClassifier::new(state.freeze.is_frozen())).await;
        if classification.oz_type != node.oz_type {
            // See the module doc: retyping a root that already holds findings would present
            // one entity's results as another's, and clearing them is a deletion this unit
            // forbids.
            // Findings live in three places and all three must be checked: the payload (a
            // tool's structured result, folded in by `merge_patch`), the sections (its rows),
            // and the children it spawned. Checking only sections missed the payload, which is
            // exactly what `retype_root` resets.
            let has_findings = !node.sections.is_empty()
                || node.payload != OzPayload::empty_for(node.oz_type)
                || match store::list_nodes(&state.db, &node.investigation_id) {
                    Ok(nodes) => nodes
                        .iter()
                        .any(|n| n.parent_id.as_deref() == Some(id.as_str())),
                    Err(e) => return server_error(e),
                };
            if has_findings {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "this root already carries findings, and the correction changes its type — start a new investigation rather than presenting one entity's results as another's",
                        "currentType": node.oz_type,
                        "classifiedAs": classification.oz_type,
                    })),
                )
                    .into_response();
            }
            retype_to = Some(classification.oz_type);
        }
    }

    match store::edit_node(&state.db, &id, value) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "node not found" })),
            )
                .into_response();
        }
        Err(e) => return server_error(e),
    }
    if let Some(new_type) = retype_to
        && let Err(e) = store::retype_root(&state.db, &id, &node.investigation_id, new_type, value)
    {
        return server_error(e);
    }
    reread(&state, &id)
}

/// `POST /api/ozint/node/{id}/reject` — MARK WRONG. Idempotent.
pub async fn reject(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match store::reject_node(&state.db, &id) {
        Ok(true) => reread(&state, &id),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "node not found" })),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

/// `POST /api/ozint/node/{id}/restore` — undo a rejection, and only that. Idempotent.
pub async fn restore(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match store::restore_node(&state.db, &id) {
        Ok(true) => reread(&state, &id),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "node not found" })),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ozint::types::UsernamePayload;
    use ozint::{
        Investigation, NodeStatus, OzNode, OzRow, OzType, Provenance, SignalChip, SignalTone,
        normalize,
    };

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn seed(state: &AppState) {
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
                dedup_key: normalize::dedup_key(OzType::Username, "mtrebosc"),
                payload: OzPayload::Username(UsernamePayload {
                    profile: vec![OzRow {
                        label: "Name".into(),
                        value: "Mathéo Trebosc".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                preview_signal: Some(SignalChip::new("14 / 312 sites", SignalTone::Neutral)),
                full_signal: None,
                sections: Vec::new(),
                gated: false,
                status: NodeStatus::Settled,
                provenance: Provenance::new("wmn-probe", "queried WhatsMyName"),
                already_in_tree: None,
                corroborations: Vec::new(),
                edited_value: None,
                created_at: now,
            },
        )
        .unwrap();
    }

    #[tokio::test]
    async fn saving_a_correction_preserves_the_original_and_moves_the_dedup_key() {
        let state = crate::test_support::test_state();
        seed(&state);

        let json = body_json(
            edit(
                State(state.clone()),
                Path("node-1".into()),
                Json(EditBody {
                    value: Some("mtrebosc2".into()),
                }),
            )
            .await,
        )
        .await;

        assert_eq!(json["editedValue"], "mtrebosc2");
        assert_eq!(
            json["value"], "mtrebosc",
            "the tool's own value is never overwritten"
        );
        assert_eq!(json["provenance"]["recordStatus"]["kind"], "corrected");
        assert_eq!(
            json["provenance"]["recordStatus"]["originalValue"],
            "mtrebosc"
        );
        assert_eq!(
            json["provenance"]["recordStatus"]["originalChip"]["text"],
            "14 / 312 sites"
        );
        assert_eq!(
            json["dedupKey"],
            normalize::dedup_key(OzType::Username, "mtrebosc2"),
            "the key follows the analyst, or dedup starts matching the wrong value"
        );
    }

    /// An investigation whose root has not been fired yet: no payload, no sections, no
    /// children. The state a root is actually in when an analyst notices they pasted the
    /// wrong thing.
    fn seed_unfired_root(state: &AppState) {
        seed(state);
        let mut root = store::get_node(&state.db, "node-1").unwrap().unwrap();
        root.payload = OzPayload::empty_for(OzType::Username);
        root.preview_signal = None;
        store::insert_node(&state.db, &root).unwrap();
    }

    #[tokio::test]
    async fn correcting_an_unfired_root_re_classifies_it_and_moves_the_seed() {
        // The bug this closes produced no symptom: the seed said `Username` while the value
        // said `8.8.8.8`, and the tree simply planned username tools forever.
        let state = crate::test_support::test_state();
        seed_unfired_root(&state);

        let json = body_json(
            edit(
                State(state.clone()),
                Path("node-1".into()),
                Json(EditBody {
                    value: Some("8.8.8.8".into()),
                }),
            )
            .await,
        )
        .await;

        assert_eq!(
            json["type"], "ip",
            "the node's own type follows the classifier"
        );
        assert_eq!(
            json["dedupKey"],
            normalize::dedup_key(OzType::Ip, "8.8.8.8")
        );

        let inv = store::get_investigation(&state.db, "inv-1")
            .unwrap()
            .unwrap();
        assert_eq!(
            inv.seed_type,
            OzType::Ip,
            "the investigation's seed moves with the root"
        );
        assert_eq!(inv.seed_input, "8.8.8.8");
    }

    #[tokio::test]
    async fn re_typing_a_root_that_already_carries_findings_is_refused() {
        // `OzPayload` is keyed on `oz_type`: a username payload under a node claiming to be an
        // IP reads as a different entity's findings, and clearing it is a deletion this unit
        // forbids. The seeded root carries a WhatsMyName result.
        let state = crate::test_support::test_state();
        seed(&state);

        let response = edit(
            State(state.clone()),
            Path("node-1".into()),
            Json(EditBody {
                value: Some("8.8.8.8".into()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let inv = store::get_investigation(&state.db, "inv-1")
            .unwrap()
            .unwrap();
        assert_eq!(inv.seed_type, OzType::Username, "nothing moved");
        let root = store::get_node(&state.db, "node-1").unwrap().unwrap();
        assert!(
            root.edited_value.is_none(),
            "the correction is refused whole, not half-applied"
        );
    }

    #[tokio::test]
    async fn correcting_the_spelling_of_a_root_without_changing_its_type_is_always_allowed() {
        // The common case, and it must not be caught by the findings guard.
        let state = crate::test_support::test_state();
        seed(&state);

        let json = body_json(
            edit(
                State(state.clone()),
                Path("node-1".into()),
                Json(EditBody {
                    value: Some("mtrebosc2".into()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(json["editedValue"], "mtrebosc2");
        assert_eq!(json["type"], "username");
    }

    #[tokio::test]
    async fn re_saving_the_same_value_records_nothing() {
        // The provenance row is this project's only audit trail. A no-op "correction" in it is
        // noise that makes a real one harder to find.
        let state = crate::test_support::test_state();
        seed(&state);

        let json = body_json(
            edit(
                State(state),
                Path("node-1".into()),
                Json(EditBody {
                    value: Some("  mtrebosc  ".into()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(json["provenance"]["recordStatus"]["kind"], "as-returned");
        assert!(json.get("editedValue").is_none());
    }

    #[tokio::test]
    async fn correcting_a_rejected_node_is_refused_instead_of_silently_un_rejecting_it() {
        // RecordStatus has one slot. Writing Corrected over Rejected would put the node back
        // into the subject file and relation inference with nothing anywhere saying so.
        let state = crate::test_support::test_state();
        seed(&state);
        let _ = reject(State(state.clone()), Path("node-1".into())).await;

        let response = edit(
            State(state.clone()),
            Path("node-1".into()),
            Json(EditBody {
                value: Some("m.trebosc".into()),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let node = store::get_node(&state.db, "node-1").unwrap().unwrap();
        assert!(
            node.provenance.record_status.is_rejected(),
            "the verdict must survive the refusal"
        );
    }

    #[tokio::test]
    async fn rejecting_hides_a_node_from_relations_without_deleting_it() {
        let state = crate::test_support::test_state();
        seed(&state);

        let json = body_json(reject(State(state.clone()), Path("node-1".into())).await).await;
        assert_eq!(json["provenance"]["recordStatus"]["kind"], "rejected");
        // Still there, still rendered — nothing is ever deleted.
        assert!(store::get_node(&state.db, "node-1").unwrap().is_some());
        assert_eq!(json["payload"]["profile"][0]["value"], "Mathéo Trebosc");
    }

    #[tokio::test]
    async fn restore_undoes_only_the_rejection() {
        let state = crate::test_support::test_state();
        seed(&state);

        let _ = edit(
            State(state.clone()),
            Path("node-1".into()),
            Json(EditBody {
                value: Some("mtrebosc2".into()),
            }),
        )
        .await;
        let _ = reject(State(state.clone()), Path("node-1".into())).await;
        let json = body_json(restore(State(state), Path("node-1".into())).await).await;

        assert_eq!(json["provenance"]["recordStatus"]["kind"], "corrected");
        assert_eq!(
            json["editedValue"], "mtrebosc2",
            "restoring a rejection must not drop the correction"
        );
    }

    #[tokio::test]
    async fn reject_and_restore_are_idempotent() {
        let state = crate::test_support::test_state();
        seed(&state);

        for _ in 0..2 {
            let r = reject(State(state.clone()), Path("node-1".into())).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        for _ in 0..2 {
            let r = restore(State(state.clone()), Path("node-1".into())).await;
            assert_eq!(r.status(), StatusCode::OK);
        }
        let node = store::get_node(&state.db, "node-1").unwrap().unwrap();
        assert!(!node.provenance.record_status.is_rejected());
    }

    #[tokio::test]
    async fn an_unknown_node_is_a_404_on_all_three() {
        let state = crate::test_support::test_state();
        assert_eq!(
            edit(
                State(state.clone()),
                Path("nope".into()),
                Json(EditBody {
                    value: Some("x".into())
                })
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            reject(State(state.clone()), Path("nope".into()))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            restore(State(state), Path("nope".into())).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn an_empty_value_is_a_400() {
        let state = crate::test_support::test_state();
        seed(&state);
        assert_eq!(
            edit(
                State(state),
                Path("node-1".into()),
                Json(EditBody {
                    value: Some("   ".into())
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
}
