//! `GET /api/ozint/investigations` (list) and `GET /api/ozint/investigations/{id}` (full
//! rehydrate) — the read half of history-resume. Plain JSON, no streaming; the
//! resumable-*continue* half is `POST /api/ozint/fire {investigationId, parentNodeId}`
//! (`fire.rs`), which is what actually needs the rebuilt `VisitedSet`.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;

use chrono::Utc;

use ozint::dossier;
use ozint::outcome::ToolReport;
use ozint::relations::{self, RelationReport};
use ozint::subject_file::{self, SubjectFileView};
use ozint::{Investigation, OzNode, OzType, store};

use crate::state::AppState;

/// Same default as most "recent items" lists in this codebase's memory routes — generous
/// enough to cover a working session's worth of investigations without the caller having to
/// think about pagination for the common case.
const DEFAULT_LIST_LIMIT: i64 = 50;

/// GET /api/ozint/investigations?limit=N → newest-first `Investigation[]`.
pub async fn list(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_LIST_LIMIT);
    match store::list_investigations(&state.db, limit) {
        Ok(items) => Json(items).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// One fired layer, as the rehydrate serves it.
///
/// `store::OzLayerRow` keeps `tool_reports_json` as an opaque string (it deliberately does not
/// depend on `outcome.rs`); this view parses it, so the cockpit reads one shape whether a layer
/// is arriving live on the SSE stream or being replayed from history.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LayerView {
    id: String,
    parent_node_id: String,
    oz_type: OzType,
    value: String,
    status: String,
    started_at: chrono::DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    settled_at: Option<chrono::DateTime<Utc>>,
    new_children: i64,
    reports: Vec<ToolReport>,
    /// True when a stored report blob exists but no longer parses — a `ToolOutcome` renamed
    /// between the write and this read, say. Without this flag such a layer would rehydrate
    /// with `reports: []`, which is indistinguishable from a layer that genuinely ran no
    /// tools; the analyst would be shown "nothing ran" where the truth is "we can no longer
    /// read what ran".
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    reports_unreadable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
}

impl From<store::OzLayerRow> for LayerView {
    fn from(row: store::OzLayerRow) -> Self {
        let (reports, reports_unreadable) = match row.tool_reports_json.as_deref() {
            None => (Vec::new(), false),
            Some(json) => match serde_json::from_str::<Vec<ToolReport>>(json) {
                Ok(reports) => (reports, false),
                Err(e) => {
                    tracing::warn!(layer_id = %row.id, error = %e, "stored ozint tool reports no longer parse");
                    (Vec::new(), true)
                }
            },
        };
        Self {
            id: row.id,
            parent_node_id: row.parent_node_id,
            oz_type: row.oz_type,
            value: row.value,
            status: row.status,
            started_at: row.started_at,
            settled_at: row.settled_at,
            new_children: row.new_children,
            reports,
            reports_unreadable,
            summary: row.summary,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InvestigationDetail {
    investigation: Investigation,
    /// Ordered `(depth, ordinal)` — `store::list_nodes`' own contract — so a rehydrated tree
    /// renders identically to the one the live SSE stream built.
    nodes: Vec<OzNode>,
    /// Oldest first, i.e. the order they were fired in. Carries each layer's settle verdict,
    /// its tool reports and its persisted LLM summary — the summary is read back, never
    /// regenerated, so reopening a history costs nothing.
    layers: Vec<LayerView>,
    /// Re-derived on every read, never stored. See `ozint::relations`.
    relations: RelationReport,
    /// The 12-field deliverable, folded live from `nodes` on the same argument as `relations`:
    /// a rejection has to drop out of it and a correction has to appear in it the instant the
    /// analyst acts, and a stored copy could only manage that with invalidation bookkeeping.
    /// Served here rather than from a `/subject-file` endpoint of its own because it is a fold
    /// over the very `nodes` this response already carries — a second route would re-read the
    /// tree to recompute something the client was just handed.
    ///
    /// **Person-shaped roots only**. A CVE, hash, IP, domain or coordinate
    /// investigation is handed `{"kind":"notApplicable","rootType":…}` — an explicit absence,
    /// never an empty dossier that would read as a fruitless search for a person.
    subject_file: SubjectFileView,
}

/// GET /api/ozint/investigations/{id} → the full rehydrate: `{investigation, nodes, layers,
/// relations, subjectFile}`, or 404 when unknown.
///
/// This is history-resume's read half, and everything it returns is served **from
/// storage**, with two deliberate exceptions that are cheap and must never go stale:
/// relations and the subject file (both re-derived, so a rejection removes a finding from them
/// immediately) and a layer's parsed reports.
///
/// **Registry-version tolerance**: nothing here consults the tool registry. A node produced by
/// a tool this build no longer catalogues renders in full from its stored payload — it simply
/// cannot be *re-run* (`POST /api/ozint/refresh` answers 422 and names the tool). Rendering and
/// re-running are separate capabilities and only the second one depends on the registry.
///
/// The *resumable* half is `POST /api/ozint/fire {investigationId, parentNodeId}`, which
/// rebuilds the `VisitedSet` from the stored tree before firing — see `fire.rs`.
pub async fn get(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let investigation = match store::get_investigation(&state.db, &id) {
        Ok(Some(inv)) => inv,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "investigation not found" })),
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
    let nodes = match store::list_nodes(&state.db, &id) {
        Ok(nodes) => nodes,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let layers = match store::list_layers(&state.db, &id) {
        Ok(rows) => rows.into_iter().map(LayerView::from).collect(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let relations = relations::infer(&nodes);
    let subject_file = subject_file::build_for(investigation.seed_type, &nodes);
    Json(InvestigationDetail {
        investigation,
        nodes,
        layers,
        relations,
        subject_file,
    })
    .into_response()
}

/// GET /api/ozint/investigations/{id}/meter → `{lookups, costCents, inFlight}`.
///
/// The lookup meter's read surface. The two cumulative numbers come off the investigation
/// row, where the engine writes them — **one tick per tool invocation**, so WhatsMyName's
/// ~730-site sweep is one lookup, not 730 (that property lives in the dispatcher: it returns a
/// single outcome, and `fire_layer` increments once per dispatch).
///
/// `inFlight` is process-local by nature — it is only ever true right now — and is folded from
/// the event stream by `OzintState::observe`. After a restart it is zero, which is correct:
/// nothing is in flight after a restart.
pub async fn meter(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match store::get_investigation(&state.db, &id) {
        Ok(Some(inv)) => Json(json!({
            "lookups": inv.lookups,
            "costCents": inv.cost_cents,
            "inFlight": state.ozint.in_flight(&id),
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "investigation not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /api/ozint/investigations/{id}/relations → `{relations, rulesWithoutInput}`.
///
/// ⚠️ `rulesWithoutInput` is **not** the cockpit's analyst-facing `NOT SEARCHED` block, which
/// says a *person* has not been investigated. This says an inference *rule* had no input. The
/// two shared a name until 2026-08-23.
///
/// Derived live from the stored tree on every call, never persisted — that is what makes
/// relation inference's first hard rule (a relation resting on a rejected node
/// disappears) hold without any invalidation bookkeeping. See `ozint::relations`.
///
/// **Deliberately in the un-gated router**: this is a pure local fold over rows already in
/// SQLite and reaches nothing outside the process, so a frozen OZINT still shows its
/// relations. An *optional* LLM phrasing pass is not wired here for exactly that
/// reason — it would put cloud egress behind a route that must stay readable while frozen.
pub async fn relations_for(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match store::get_investigation(&state.db, &id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "investigation not found" })),
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
    }
    match store::list_nodes(&state.db, &id) {
        Ok(nodes) => {
            let report: RelationReport = relations::infer(&nodes);
            Json(report).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// GET /api/ozint/investigations/{id}/export?format=json|markdown → the dossier exporter.
///
/// Defaults to `json` (the lossless shape — every stored [`OzNode`] verbatim, including
/// rejected ones and full provenance). `format=markdown` renders the same assembly as a
/// document. Reads the same four things `get` does (investigation, nodes, layers, relations,
/// subject file) — nothing is served from a cache, so an export always reflects the tree as it
/// stands right now, including any correction or rejection the analyst just made.
///
/// **Deliberately in the un-gated router**, same reasoning as `relations_for`: this is a pure
/// local fold over rows already in SQLite and reaches nothing outside the process, so an
/// analyst can still export while frozen.
pub async fn export(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let investigation = match store::get_investigation(&state.db, &id) {
        Ok(Some(inv)) => inv,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "investigation not found" })),
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
    let nodes = match store::list_nodes(&state.db, &id) {
        Ok(nodes) => nodes,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let layers = match store::list_layers(&state.db, &id) {
        Ok(rows) => rows,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let relations = relations::infer(&nodes);
    let subject_file = subject_file::build_for(investigation.seed_type, &nodes);
    let seed = investigation.seed_input.clone();
    let dossier = dossier::build(investigation, nodes, &layers, relations, subject_file);

    match params.get("format").map(String::as_str) {
        Some("markdown") | Some("md") => {
            let body = dossier::to_markdown(&dossier);
            let filename = format!("ozint-{}.md", slugify(&seed));
            (
                [
                    (
                        header::CONTENT_TYPE,
                        "text/markdown; charset=utf-8".to_string(),
                    ),
                    (
                        header::CONTENT_DISPOSITION,
                        format!("attachment; filename=\"{filename}\""),
                    ),
                ],
                body,
            )
                .into_response()
        }
        _ => Json(dossier).into_response(),
    }
}

/// Lowercases and replaces every non-alphanumeric run with `-`, for a filesystem-safe export
/// filename. Not a general slugifier — just enough to turn a seed value into a usable name.
fn slugify(raw: &str) -> String {
    let mut out = String::new();
    let mut last_was_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "investigation".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ozint::{NodeStatus, OzPayload, OzType, Provenance};

    fn sample_investigation(id: &str, created_at: chrono::DateTime<Utc>) -> Investigation {
        Investigation {
            id: id.to_string(),
            seed_input: "mtrebosc".to_string(),
            seed_type: OzType::Username,
            root_node_id: format!("{id}-root"),
            created_at,
            updated_at: created_at,
            lookups: 0,
            cost_cents: 0,
            spawned_from_investigation_id: None,
            spawned_from_relation: None,
        }
    }

    fn sample_root(id: &str, investigation_id: &str) -> OzNode {
        OzNode {
            id: id.to_string(),
            investigation_id: investigation_id.to_string(),
            parent_id: None,
            layer_id: None,
            ordinal: 0,
            depth: 0,
            oz_type: OzType::Username,
            value: "mtrebosc".to_string(),
            display: "mtrebosc".to_string(),
            dedup_key: "username:mtrebosc".to_string(),
            payload: OzPayload::empty_for(OzType::Username),
            preview_signal: None,
            full_signal: None,
            sections: Vec::new(),
            gated: false,
            status: NodeStatus::Idle,
            provenance: Provenance::new("seed", "typed by the analyst"),
            already_in_tree: None,
            corroborations: Vec::new(),
            edited_value: None,
            created_at: Utc::now(),
        }
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn list_returns_newest_first() {
        let state = crate::test_support::test_state();
        let older = sample_investigation(
            "a",
            chrono::DateTime::<Utc>::from_timestamp_millis(1_000).unwrap(),
        );
        let newer = sample_investigation(
            "b",
            chrono::DateTime::<Utc>::from_timestamp_millis(2_000).unwrap(),
        );
        store::create_investigation(&state.db, &older).unwrap();
        store::create_investigation(&state.db, &newer).unwrap();

        let response = list(State(state), Query(HashMap::new())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let ids: Vec<&str> = json
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["b", "a"]);
    }

    #[tokio::test]
    async fn list_respects_a_limit_query_param() {
        let state = crate::test_support::test_state();
        for i in 0..3 {
            let inv = sample_investigation(
                &format!("inv-{i}"),
                chrono::DateTime::<Utc>::from_timestamp_millis(i * 1_000).unwrap(),
            );
            store::create_investigation(&state.db, &inv).unwrap();
        }

        let mut params = HashMap::new();
        params.insert("limit".to_string(), "2".to_string());
        let response = list(State(state), Query(params)).await;
        let json = body_json(response).await;
        assert_eq!(json.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn get_rehydrates_the_investigation_and_its_ordered_nodes() {
        let state = crate::test_support::test_state();
        let inv = sample_investigation("inv-1", Utc::now());
        store::create_investigation(&state.db, &inv).unwrap();
        let root = sample_root("root", "inv-1");
        store::insert_node(&state.db, &root).unwrap();

        let response = get(State(state), Path("inv-1".to_string())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["investigation"]["id"], "inv-1");
        assert_eq!(json["nodes"].as_array().unwrap().len(), 1);
        assert_eq!(json["nodes"][0]["id"], "root");
    }

    #[tokio::test]
    async fn get_unknown_investigation_is_a_404() {
        let state = crate::test_support::test_state();
        let response = get(State(state), Path("does-not-exist".to_string())).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── History-resume: what a reopened investigation must still know ──────────────

    #[tokio::test]
    async fn a_rehydrate_carries_layers_their_reports_and_their_persisted_summary() {
        // The summary in particular is *read back*, never regenerated — reopening a history
        // must not re-bill an LLM call the analyst already paid for.
        let state = crate::test_support::test_state();
        store::create_investigation(&state.db, &sample_investigation("inv-1", Utc::now())).unwrap();
        store::insert_node(&state.db, &sample_root("root", "inv-1")).unwrap();

        let started = Utc::now();
        store::insert_layer(
            &state.db,
            "layer-1",
            "inv-1",
            "root",
            OzType::Username,
            "mtrebosc",
            "running",
            started,
        )
        .unwrap();
        let reports = vec![ozint::outcome::ToolReport::new(
            "wmn-probe",
            "WhatsMyName",
            ozint::outcome::ToolOutcome::OkWithResults { count: 14 },
            1200,
            false,
            "queried the WhatsMyName site list",
        )];
        store::settle_layer(
            &state.db,
            "layer-1",
            "settled",
            Utc::now(),
            3,
            Some(&serde_json::to_string(&reports).unwrap()),
        )
        .unwrap();
        store::attach_layer_summary(&state.db, "layer-1", "Fourteen accounts, mostly dormant.")
            .unwrap();

        let json = body_json(get(State(state), Path("inv-1".to_string())).await).await;
        let layer = &json["layers"][0];
        assert_eq!(layer["id"], "layer-1");
        assert_eq!(layer["status"], "settled");
        assert_eq!(layer["newChildren"], 3);
        assert_eq!(layer["summary"], "Fourteen accounts, mostly dormant.");
        assert_eq!(layer["reports"][0]["toolId"], "wmn-probe");
        assert_eq!(layer["reports"][0]["results"], 14);
        assert!(layer.get("reportsUnreadable").is_none());
    }

    #[tokio::test]
    async fn a_report_blob_that_no_longer_parses_says_so_instead_of_looking_empty() {
        // `reports: []` and "we can no longer read what ran" must not render identically —
        // the first claims the layer fired nothing.
        let state = crate::test_support::test_state();
        store::create_investigation(&state.db, &sample_investigation("inv-1", Utc::now())).unwrap();
        store::insert_layer(
            &state.db,
            "layer-1",
            "inv-1",
            "root",
            OzType::Username,
            "x",
            "running",
            Utc::now(),
        )
        .unwrap();
        store::settle_layer(
            &state.db,
            "layer-1",
            "settled",
            Utc::now(),
            0,
            Some("{ not a report list }"),
        )
        .unwrap();

        let json = body_json(get(State(state), Path("inv-1".to_string())).await).await;
        assert_eq!(json["layers"][0]["reportsUnreadable"], true);
        assert_eq!(json["layers"][0]["reports"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn a_node_whose_tool_left_the_registry_still_rehydrates_in_full() {
        // Registry-version tolerance. Rendering and re-running are separate capabilities: this
        // node renders from its stored payload; only `POST /api/ozint/refresh` needs the tool
        // to still exist, and it answers 422 there rather than pretending nothing changed.
        let state = crate::test_support::test_state();
        store::create_investigation(&state.db, &sample_investigation("inv-1", Utc::now())).unwrap();
        let mut node = sample_root("root", "inv-1");
        node.provenance =
            ozint::Provenance::new("a-tool-this-build-dropped", "queried something long gone");
        node.payload = OzPayload::Username(ozint::types::UsernamePayload {
            sites_checked: 312,
            sites_confirmed: 14,
            ..Default::default()
        });
        node.preview_signal = Some(ozint::SignalChip::new(
            "14 / 312 sites",
            ozint::SignalTone::Neutral,
        ));
        store::insert_node(&state.db, &node).unwrap();

        let json = body_json(get(State(state), Path("inv-1".to_string())).await).await;
        assert_eq!(
            json["nodes"][0]["provenance"]["sourceToolId"],
            "a-tool-this-build-dropped"
        );
        assert_eq!(json["nodes"][0]["payload"]["sitesConfirmed"], 14);
        assert_eq!(json["nodes"][0]["previewSignal"]["text"], "14 / 312 sites");
    }

    #[tokio::test]
    async fn a_rehydrate_carries_the_analysts_edits_and_rejections() {
        let state = crate::test_support::test_state();
        store::create_investigation(&state.db, &sample_investigation("inv-1", Utc::now())).unwrap();
        store::insert_node(&state.db, &sample_root("root", "inv-1")).unwrap();
        let mut second = sample_root("n2", "inv-1");
        second.ordinal = 1;
        second.dedup_key = "username:other".into();
        store::insert_node(&state.db, &second).unwrap();

        store::edit_node(&state.db, "root", "m.trebosc").unwrap();
        store::reject_node(&state.db, "n2").unwrap();

        let json = body_json(get(State(state), Path("inv-1".to_string())).await).await;
        let root = json["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == "root")
            .unwrap();
        assert_eq!(root["editedValue"], "m.trebosc");
        assert_eq!(root["provenance"]["recordStatus"]["kind"], "corrected");
        let rejected = json["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == "n2")
            .unwrap();
        assert_eq!(
            rejected["provenance"]["recordStatus"]["kind"], "rejected",
            "nothing is ever deleted"
        );
    }

    #[tokio::test]
    async fn a_rehydrate_restores_the_lookup_and_cost_meters() {
        let state = crate::test_support::test_state();
        store::create_investigation(&state.db, &sample_investigation("inv-1", Utc::now())).unwrap();
        store::bump_investigation_usage(&state.db, "inv-1", 7, 42, Utc::now()).unwrap();

        let json = body_json(get(State(state), Path("inv-1".to_string())).await).await;
        assert_eq!(json["investigation"]["lookups"], 7);
        assert_eq!(json["investigation"]["costCents"], 42);
    }

    #[tokio::test]
    async fn the_meter_reports_the_persisted_totals_and_a_live_in_flight_count() {
        let state = crate::test_support::test_state();
        store::create_investigation(&state.db, &sample_investigation("inv-1", Utc::now())).unwrap();
        store::bump_investigation_usage(&state.db, "inv-1", 7, 42, Utc::now()).unwrap();

        let json = body_json(meter(State(state.clone()), Path("inv-1".to_string())).await).await;
        assert_eq!(json["lookups"], 7);
        assert_eq!(json["costCents"], 42);
        assert_eq!(json["inFlight"], 0, "nothing is running");

        state.ozint.observe(
            "inv-1",
            &ozint::runtime::LayerEvent::ToolStart {
                layer_id: "layer-a".into(),
                tool_id: "wmn-probe".into(),
                label: "WhatsMyName".into(),
                gated: false,
            },
        );
        let json = body_json(meter(State(state), Path("inv-1".to_string())).await).await;
        assert_eq!(json["inFlight"], 1);
    }

    #[tokio::test]
    async fn the_meter_of_an_unknown_investigation_is_a_404() {
        let state = crate::test_support::test_state();
        assert_eq!(
            meter(State(state), Path("nope".to_string())).await.status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn the_rehydrate_carries_the_subject_file_derived_from_the_tree() {
        // The subject file is served on the rehydrate rather than from a route of its own,
        // so this is the only place its arrival on the wire is asserted.
        let state = crate::test_support::test_state();
        store::create_investigation(&state.db, &sample_investigation("inv-1", Utc::now())).unwrap();

        let mut node = sample_root("n1", "inv-1");
        node.payload = OzPayload::Username(ozint::types::UsernamePayload {
            profile: vec![ozint::OzRow {
                label: "Name".into(),
                value: "Ada Lovelace".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        store::insert_node(&state.db, &node).unwrap();

        let json = body_json(get(State(state), Path("inv-1".to_string())).await).await;
        let file = &json["subjectFile"];
        assert_eq!(file["kind"], "file", "a username root is person-shaped");
        assert_eq!(file["total"], 13, "twelve fields plus the photo slot");
        assert_eq!(
            file["fields"].as_array().expect("the fields array").len(),
            12,
            "every field ships, including the empty ones — an absent field and an unsearched \
             one must not render identically"
        );
        // One FULL NAME, carried exactly as the source spelled it.
        assert_eq!(file["fields"][0]["label"], "FULL NAME");
        assert_eq!(
            file["fields"][0]["items"][0]["values"][0]["value"],
            "Ada Lovelace"
        );
        // The one field the earlier design mock demonstrated and nothing here can produce.
        assert!(
            file["fields"][1]["items"]
                .as_array()
                .expect("age items")
                .is_empty(),
            "AGE has no producer and must stay empty rather than be inferred"
        );
    }

    #[tokio::test]
    async fn a_non_person_root_is_handed_an_explicit_absence_not_an_empty_dossier() {
        // `COMPLETENESS 0 / 13` over EMPLOYER and POSTAL ADDRESS on a CVE
        // investigation is not a measurement — the fields were never applicable.
        let state = crate::test_support::test_state();
        let mut inv = sample_investigation("inv-1", Utc::now());
        inv.seed_type = OzType::Cve;
        inv.seed_input = "CVE-2024-38063".into();
        store::create_investigation(&state.db, &inv).unwrap();

        let json = body_json(get(State(state), Path("inv-1".to_string())).await).await;
        assert_eq!(json["subjectFile"]["kind"], "notApplicable");
        assert_eq!(json["subjectFile"]["rootType"], "cve");
        assert!(
            json["subjectFile"]["fields"].is_null(),
            "no dossier is folded at all"
        );
    }

    #[tokio::test]
    async fn a_rejected_node_leaves_the_subject_file_on_the_next_read() {
        // Derived-never-stored, asserted through the route: no invalidation pass runs between
        // the rejection and this read.
        let state = crate::test_support::test_state();
        store::create_investigation(&state.db, &sample_investigation("inv-1", Utc::now())).unwrap();
        let mut node = sample_root("n1", "inv-1");
        node.oz_type = ozint::types::OzType::Email;
        node.value = "a@example.com".into();
        node.display = "a@example.com".into();
        node.payload = OzPayload::empty_for(ozint::types::OzType::Email);
        store::insert_node(&state.db, &node).unwrap();

        let emails = |json: &serde_json::Value| -> usize {
            json["subjectFile"]["fields"]
                .as_array()
                .expect("fields")
                .iter()
                .find(|f| f["label"] == "EMAIL ADDRESSES")
                .expect("the emails field")["items"]
                .as_array()
                .expect("items")
                .len()
        };

        let before = body_json(get(State(state.clone()), Path("inv-1".to_string())).await).await;
        assert_eq!(emails(&before), 1);

        store::reject_node(&state.db, "n1").unwrap();
        let after = body_json(get(State(state), Path("inv-1".to_string())).await).await;
        assert_eq!(
            emails(&after),
            0,
            "a rejected finding must vanish from the deliverable"
        );
    }

    #[tokio::test]
    async fn relations_for_an_unknown_investigation_is_a_404() {
        // Not an empty relation list: "this investigation does not exist" and "this
        // investigation has no relations" are different answers.
        let state = crate::test_support::test_state();
        let response = relations_for(State(state), Path("does-not-exist".to_string())).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn relations_are_derived_from_the_stored_tree() {
        let state = crate::test_support::test_state();
        store::create_investigation(&state.db, &sample_investigation("inv-1", Utc::now())).unwrap();

        let mut a = sample_root("n1", "inv-1");
        a.payload = OzPayload::Username(ozint::types::UsernamePayload {
            profile: vec![ozint::OzRow {
                label: "Name".into(),
                value: "Ada Lovelace".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        let mut b = sample_root("n2", "inv-1");
        b.ordinal = 1;
        b.dedup_key = "username:other".into();
        b.payload = OzPayload::Username(ozint::types::UsernamePayload {
            profile: vec![ozint::OzRow {
                label: "Name".into(),
                value: "Grace Lovelace".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        store::insert_node(&state.db, &a).unwrap();
        store::insert_node(&state.db, &b).unwrap();

        let json = body_json(relations_for(State(state), Path("inv-1".to_string())).await).await;
        assert_eq!(json["relations"][0]["subject"], "Grace Lovelace");
        assert!(
            !json["rulesWithoutInput"].as_array().unwrap().is_empty(),
            "the panel must always close with what it did not search"
        );
    }
}
