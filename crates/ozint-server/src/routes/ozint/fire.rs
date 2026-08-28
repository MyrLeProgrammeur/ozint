//! `POST /api/ozint/fire {seed}` (start) or `{investigationId, parentNodeId}` (continue) →
//! one multiplexed SSE stream of `LayerEvent`s for the fired layer. See `runtime.rs`'s module
//! doc for why this is one stream per *investigation call*, not one per layer, and why the
//! engine keeps running to settlement even if this response's stream stops being read.

use std::convert::Infallible;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::{Json, http};
use chrono::Utc;
use futures::{Stream, StreamExt};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;

use ozint::fetch::CancelHandle;
use ozint::layer_plan::LayerPlan;
use ozint::runtime::{LayerContext, LayerEvent, fire_layer};
use ozint::visited::VisitedSet;
use ozint::{
    Investigation, NodeStatus, OzNode, OzPayload, OzType, Provenance, classify, normalize, plans,
    store,
};

use super::classifier_llm::LlmClassifier;
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FireBody {
    seed: Option<String>,
    investigation_id: Option<String>,
    parent_node_id: Option<String>,
    /// The server-side skip for the LLM summary. Absent/`null` means "on" — the summary is a
    /// default-on convenience note, not an opt-in feature, so a client that has never heard of
    /// this field must not silently lose it.
    show_summary: Option<bool>,
    /// The search bar's type selector. Absent/`null` is the selector's default
    /// *auto*, and behaves exactly as before: the classifier decides. Set, it **replaces** the
    /// classifier for this seed rather than biasing it, and the root node's provenance says so.
    ///
    /// Only meaningful on the `{seed}` branch. A `continue` call already has a typed parent
    /// node, so there is nothing here to override.
    oz_type: Option<OzType>,
}

/// The root node's provenance sentence, naming which tier actually decided its type.
///
/// All four cases were previously flattened into one string, `typed by the analyst`, which was
/// true of the *value* and said nothing about the type — so a type the analyst forced and a
/// type an LLM guessed rendered identically.
fn seed_method(method: classify::ClassifyMethod) -> &'static str {
    use classify::ClassifyMethod::*;
    match method {
        AnalystForced => "typed by the analyst, type chosen by the analyst",
        Deterministic => "typed by the analyst, type resolved by shape",
        Llm => "typed by the analyst, type resolved by the classifier's LLM tier",
        DeterministicFallback => {
            "typed by the analyst, type resolved by shape — the LLM tier was unreachable"
        }
    }
}

fn bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": message.into() })),
    )
        .into_response()
}

fn not_found(message: impl Into<String>) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": message.into() })),
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

/// `{seed}` branch: classify the raw seed, create a fresh investigation and root node, then
/// hand back a `LayerContext` ready to fire layer 1 on that root.
async fn setup_seed(
    state: &AppState,
    raw_seed: &str,
    show_summary: bool,
    forced_type: Option<OzType>,
) -> Result<LayerContext, Response> {
    let seed = raw_seed.trim();
    if seed.is_empty() {
        return Err(bad_request("seed must not be empty"));
    }

    // The search bar's type selector, set to anything but *auto*, replaces the
    // classifier outright — an analyst who pastes `Acme Industries`, watches it come back as a
    // person's name and meant a company had no way to say so, since `EDIT` changes a node's
    // value and never its type. The LLM tier is not consulted either: there is nothing left to
    // be ambiguous about once the analyst has asserted the answer.
    //
    // Left alone (the selector's *auto* default), everything below is unchanged:
    //
    // This route is the Autofire button handler the classifier's locked rule requires
    // (never called per-keystroke), which is what makes it the one place allowed to escalate to
    // the LLM tier. It does so for a vanishingly small share of seeds: `classify_with_llm`
    // returns the deterministic answer immediately unless the shape pass came back genuinely
    // ambiguous, which in practice means free text that is neither a person's name nor a
    // company by any available signal. Everything else never reaches the network.
    //
    // Until this call existed, nothing implemented `ClassifierLlm` outside test code and the
    // whole escalation tier was unreachable — see `classifier_llm.rs`.
    let classification = match forced_type {
        Some(forced) => classify::classify_forced(seed, forced),
        None => {
            classify::classify_with_llm(seed, &LlmClassifier::new(state.freeze.is_frozen())).await
        }
    };
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
        lookups: 0,
        cost_cents: 0,
        spawned_from_investigation_id: None,
        spawned_from_relation: None,
    };
    store::create_investigation(&state.db, &investigation).map_err(server_error)?;

    let root_node = OzNode {
        id: root_id.clone(),
        investigation_id: investigation_id.clone(),
        parent_id: None,
        layer_id: None,
        ordinal: 0,
        depth: 0,
        oz_type,
        value: normalized.key.clone(),
        display: normalized.display.clone(),
        dedup_key: normalize::dedup_key(oz_type, seed),
        payload: OzPayload::empty_for(oz_type),
        preview_signal: None,
        full_signal: None,
        sections: Vec::new(),
        gated: false,
        status: NodeStatus::Idle,
        // `Provenance::method` is rendered verbatim, so this is where the bypass becomes
        // visible to the analyst rather than a field only the wire knows about. A forced type
        // and a classifier verdict must never read identically: the whole point of the
        // selector is that the analyst can tell which one produced the node they are looking
        // at — and, on reopening an old investigation, which one produced it back then.
        provenance: Provenance::new("seed", seed_method(classification.method)),
        already_in_tree: None,
        corroborations: Vec::new(),
        edited_value: None,
        created_at: now,
    };
    store::insert_node(&state.db, &root_node).map_err(server_error)?;

    let (visited, health) = state.ozint.investigation_runtime(&investigation_id);
    // A fresh investigation has exactly one node: seed the visited set with it so a layer
    // that (oddly) rediscovers the seed's own value annotates rather than duplicates.
    *visited.lock().unwrap() = VisitedSet::from_nodes(&[root_node]);

    Ok(LayerContext {
        db: state.db.clone(),
        investigation_id,
        parent_node_id: root_id,
        parent_depth: 0,
        oz_type,
        value: normalized.key,
        visited,
        health,
        scheduler: Some(state.ozint_scheduler.clone()),
        cache: Some(state.ozint_cache.clone()),
        cancel: None,
        show_summary,
        freeze: state.freeze.clone(),
    })
}

/// `{investigationId, parentNodeId}` branch: "continue search on this". Rebuilds the visited
/// set from the stored tree **before** firing — a rule restated in
/// `visited.rs`'s own doc on `VisitedSet::from_nodes`: skipping this on a resumed or
/// continued tree duplicates everything it already contains.
async fn setup_continue(
    state: &AppState,
    investigation_id: &str,
    parent_node_id: &str,
    show_summary: bool,
) -> Result<LayerContext, Response> {
    let parent = store::get_node(&state.db, parent_node_id).map_err(server_error)?;
    let Some(parent) = parent else {
        return Err(not_found("parent node not found"));
    };
    if parent.investigation_id != investigation_id {
        return Err(bad_request(
            "parentNodeId does not belong to investigationId",
        ));
    }

    let (visited, health) = state.ozint.investigation_runtime(investigation_id);
    let nodes = store::list_nodes(&state.db, investigation_id).map_err(server_error)?;
    *visited.lock().unwrap() = VisitedSet::from_nodes(&nodes);

    Ok(LayerContext {
        db: state.db.clone(),
        investigation_id: investigation_id.to_string(),
        parent_node_id: parent.id,
        parent_depth: parent.depth,
        oz_type: parent.oz_type,
        // The analyst's correction when there is one (`effective_value`), not the stale
        // as-returned value — continuing a search should chase what the analyst believes is
        // correct, not what a tool happened to originally return.
        value: parent.edited_value.unwrap_or(parent.value),
        visited,
        health,
        scheduler: Some(state.ozint_scheduler.clone()),
        cache: Some(state.ozint_cache.clone()),
        cancel: None,
        show_summary,
        freeze: state.freeze.clone(),
    })
}

/// `POST /api/ozint/fire` — see the module doc.
pub async fn fire(State(state): State<AppState>, Json(body): Json<FireBody>) -> Response {
    let show_summary = body.show_summary.unwrap_or(true);
    let setup = match body.seed.as_deref().map(str::trim) {
        Some(seed) if !seed.is_empty() => {
            setup_seed(&state, seed, show_summary, body.oz_type).await
        }
        _ => match (
            body.investigation_id.as_deref(),
            body.parent_node_id.as_deref(),
        ) {
            (Some(investigation_id), Some(parent_node_id)) => {
                setup_continue(&state, investigation_id, parent_node_id, show_summary).await
            }
            _ => Err(bad_request(
                "provide either `seed`, or `investigationId` + `parentNodeId`",
            )),
        },
    };

    let ctx = match setup {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };

    stream_layer(state, ctx)
}

/// The per-entity plan, from `ozint::plans` — the single owner of "which tools fire
/// for this type".
///
/// This route used to build the plan itself, flattening `registry::resolve(oz_type).runnable`
/// into one phase, as a placeholder until orchestrators existed. That placeholder had a bug
/// worth naming, because it is the kind that shows up as *nothing*: filtering on `runnable`
/// dropped every unarmed tool before the engine ever saw it, so a tool whose key is missing
/// vanished from the fan-out instead of being reported as `SkippedNoKey`. The analyst would
/// have been shown a smaller denominator with no indication a capability existed at all —
/// exactly the silent-shrink failure `runtime.rs` reports unknown tool ids to avoid.
///
/// A plan names capabilities; `registry::resolve` decides what is armed; the runtime reports
/// the difference. Those are three separate jobs and this route does none of them.
fn build_plan(oz_type: OzType) -> Option<LayerPlan> {
    plans::plan_for(oz_type)
}

/// Fires `ctx` and streams every `LayerEvent` back as `data: <json>\n\n` SSE frames.
///
/// Two background tasks, not one, and this is deliberate:
/// - one drives `fire_layer` itself, writing into `engine_tx`;
/// - the other drains `engine_rx` and relays into `out_tx` (which the SSE body reads),
///   *also* owning the cancel handle's registration/removal.
///
/// The relay task keeps draining `engine_rx` to completion even once `out_tx.send` starts
/// failing (the SSE response was dropped) — the engine must run to settlement regardless of
/// whether anyone is still reading the stream, exactly as `runtime.rs`'s module doc requires:
/// cancellation is `POST /api/ozint/cancel`, never an inferred disconnect.
fn stream_layer(state: AppState, mut ctx: LayerContext) -> Response {
    // No orchestrator for this type yet. Answered as a plain HTTP error rather than by
    // opening a stream and firing an empty plan: the engine settles an empty plan as
    // `Failed`, which would tell the analyst we looked and lost, when the truth is that this
    // entity type has not been built. See `ozint::plans` for why `plan_for` is an
    // `Option` in the first place.
    let Some(plan) = build_plan(ctx.oz_type) else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": format!(
                    "no orchestrator is built for {} nodes yet",
                    ctx.oz_type.code()
                ),
                "ozType": ctx.oz_type,
            })),
        )
            .into_response();
    };

    let (handle, signal) = CancelHandle::new();
    ctx.cancel = Some(signal);
    let investigation_id = ctx.investigation_id.clone();

    let (engine_tx, mut engine_rx) = mpsc::channel::<LayerEvent>(64);
    let (out_tx, out_rx) = mpsc::channel::<LayerEvent>(64);

    tokio::spawn(async move {
        fire_layer(&ctx, &plan, engine_tx).await;
    });

    let ozint = state.ozint.clone();
    tokio::spawn(async move {
        let mut handle = Some(handle);
        let mut seen_layer_id: Option<String> = None;

        while let Some(event) = engine_rx.recv().await {
            if let LayerEvent::LayerStart { layer_id, .. } = &event
                && let Some(h) = handle.take()
            {
                ozint.register_cancel(&investigation_id, layer_id, h);
                seen_layer_id = Some(layer_id.clone());
            }
            // Feeds the in-flight gauge. Fed here rather than inside the engine
            // because this task already sees every frame of every branch, and it must run on
            // the relay side of the channel so a dropped SSE body still keeps the count honest.
            ozint.observe(&investigation_id, &event);
            // Ignore a send failure: it only means the SSE body was dropped, and this loop
            // must keep draining engine_rx regardless (see the function doc).
            let _ = out_tx.send(event).await;
        }

        if let Some(layer_id) = seen_layer_id {
            ozint.remove_cancel(&investigation_id, &layer_id);
        }
    });

    let sse_stream = async_stream::stream! {
        let mut rx = out_rx;
        while let Some(event) = rx.recv().await {
            let payload = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
            yield Ok::<Event, Infallible>(Event::default().data(payload));
        }
    };

    // `Sse::into_response`'s default `Cache-Control` and lack of keep-alive pings is close but
    // not exact — `.keep_alive()` would inject `:`-comment lines the client's hand-rolled
    // parser (`web/src/lib/ozint/stream-parser.ts`) does not expect, so it is never called; the
    // headers are overridden explicitly to match the captured contract exactly.
    let mut response = Sse::new(box_stream(sse_stream)).into_response();
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("keep-alive"),
    );
    response
}

fn box_stream(
    s: impl Stream<Item = Result<Event, Infallible>> + Send + 'static,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    s.boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fire_body_deserializes_camel_case_seed_form() {
        let body: FireBody = serde_json::from_str(r#"{"seed":"mtrebosc"}"#).unwrap();
        assert_eq!(body.seed.as_deref(), Some("mtrebosc"));
        assert!(body.investigation_id.is_none());
        assert!(body.parent_node_id.is_none());
    }

    #[test]
    fn fire_body_deserializes_camel_case_continue_form() {
        let body: FireBody =
            serde_json::from_str(r#"{"investigationId":"inv-1","parentNodeId":"node-1"}"#).unwrap();
        assert_eq!(body.investigation_id.as_deref(), Some("inv-1"));
        assert_eq!(body.parent_node_id.as_deref(), Some("node-1"));
        assert!(body.seed.is_none());
    }

    #[test]
    fn fire_body_show_summary_is_absent_by_default_not_false() {
        // Absent must read as "unspecified", not "off" — `fire()` is the one that turns an
        // absent flag into the default-on `true`, via `unwrap_or(true)`. If this ever became
        // `Option<bool>` with a serde default of `false`, that default would silently flip.
        let body: FireBody = serde_json::from_str(r#"{"seed":"mtrebosc"}"#).unwrap();
        assert_eq!(body.show_summary, None);
    }

    #[test]
    fn fire_body_show_summary_deserializes_camel_case() {
        let body: FireBody =
            serde_json::from_str(r#"{"seed":"mtrebosc","showSummary":false}"#).unwrap();
        assert_eq!(body.show_summary, Some(false));
    }

    // ── The search-bar type selector ────────────────────────────────────
    //
    // The field had to exist on `FireBody` before the front-end could ship the selector at
    // all: serde ignores unknown keys, so a client sending `ozType` against the previous
    // struct would have had its override dropped in silence and got a classifier verdict
    // back — precisely the kind of control that silently does nothing this field exists to
    // avoid.
    #[test]
    fn fire_body_carries_the_analysts_forced_type() {
        let body: FireBody =
            serde_json::from_str(r#"{"seed":"Acme Industries","ozType":"directory"}"#).unwrap();
        assert_eq!(body.oz_type, Some(OzType::Directory));
    }

    #[test]
    fn fire_body_without_a_type_means_auto_not_a_default_type() {
        let body: FireBody = serde_json::from_str(r#"{"seed":"Acme Industries"}"#).unwrap();
        assert_eq!(
            body.oz_type, None,
            "absent must reach the classifier, never a silent default"
        );
    }

    #[test]
    fn a_forced_type_is_never_reported_as_a_classifier_verdict() {
        // `Acme Industries` is the canonical example: the shape pass has no regex
        // that beats a coin flip here and guesses `Name`. Forcing `Directory` must both change
        // the answer and change what the node claims about where the answer came from.
        let auto = classify::classify("Acme Industries");
        assert_eq!(auto.oz_type, OzType::Name);
        assert_eq!(auto.method, classify::ClassifyMethod::Deterministic);

        let forced = classify::classify_forced("Acme Industries", OzType::Directory);
        assert_eq!(forced.oz_type, OzType::Directory);
        assert_eq!(forced.method, classify::ClassifyMethod::AnalystForced);
        assert!(
            forced.alternates.is_empty(),
            "the analyst asserted it; there is no runner-up"
        );

        assert_ne!(
            seed_method(forced.method),
            seed_method(auto.method),
            "provenance is the only place the analyst sees which tier decided the type"
        );
    }

    #[test]
    fn forcing_a_type_the_value_does_not_parse_as_says_so_rather_than_pretending() {
        // Forcing is an override of the classifier, not of the normalizer. The analyst gets
        // their type — and an honest note that the value does not parse as one.
        let forced = classify::classify_forced("definitely not an address", OzType::Ip);
        assert_eq!(forced.oz_type, OzType::Ip);
        assert!(!forced.valid);
        assert!(forced.note.is_some());
    }

    #[test]
    fn fire_body_missing_everything_still_deserializes() {
        // Validation (which branch, if any) is the handler's job, not serde's — an empty
        // object must parse so the handler can produce a clean 400 rather than a raw
        // deserialization error.
        let body: FireBody = serde_json::from_str("{}").unwrap();
        assert!(
            body.seed.is_none() && body.investigation_id.is_none() && body.parent_node_id.is_none()
        );
    }

    // ── Branch selection (the logic in `fire`, exercised directly) ──────────────────────

    #[derive(Debug, PartialEq)]
    enum Branch {
        Seed(String),
        Continue(String, String),
        Invalid,
    }

    /// Mirrors `fire`'s branch selection without needing a live `AppState`/DB — this is the
    /// one piece of that handler that is pure decision logic, so it is pulled out and tested
    /// here rather than left implicit inside an untestable async DB-touching function.
    fn select_branch(body: &FireBody) -> Branch {
        match body.seed.as_deref().map(str::trim) {
            Some(seed) if !seed.is_empty() => Branch::Seed(seed.to_string()),
            _ => match (
                body.investigation_id.as_deref(),
                body.parent_node_id.as_deref(),
            ) {
                (Some(i), Some(p)) => Branch::Continue(i.to_string(), p.to_string()),
                _ => Branch::Invalid,
            },
        }
    }

    #[test]
    fn a_non_empty_seed_wins_the_seed_branch() {
        let body = FireBody {
            seed: Some("mtrebosc".into()),
            ..Default::default()
        };
        assert_eq!(select_branch(&body), Branch::Seed("mtrebosc".into()));
    }

    #[test]
    fn a_blank_seed_falls_through_to_continue() {
        let body = FireBody {
            seed: Some("   ".into()),
            investigation_id: Some("inv-1".into()),
            parent_node_id: Some("node-1".into()),
            ..Default::default()
        };
        assert_eq!(
            select_branch(&body),
            Branch::Continue("inv-1".into(), "node-1".into())
        );
    }

    #[test]
    fn missing_seed_with_both_continue_fields_selects_continue() {
        let body = FireBody {
            seed: None,
            investigation_id: Some("inv-1".into()),
            parent_node_id: Some("node-1".into()),
            ..Default::default()
        };
        assert_eq!(
            select_branch(&body),
            Branch::Continue("inv-1".into(), "node-1".into())
        );
    }

    #[test]
    fn neither_seed_nor_a_complete_continue_pair_is_invalid() {
        assert_eq!(select_branch(&FireBody::default()), Branch::Invalid);
        assert_eq!(
            select_branch(&FireBody {
                investigation_id: Some("inv-1".into()),
                ..Default::default()
            }),
            Branch::Invalid,
            "investigationId alone, with no parentNodeId, must not be treated as continue"
        );
        assert_eq!(
            select_branch(&FireBody {
                parent_node_id: Some("node-1".into()),
                ..Default::default()
            }),
            Branch::Invalid,
            "parentNodeId alone, with no investigationId, must not be treated as continue"
        );
    }

    // ── SSE framing (given a LayerEvent, the exact bytes the client parser expects) ──────
    //
    // Axum's `Event` has no public way to render itself to text (the encoder it uses,
    // `Event::finalize`, is crate-private) — so this drives the real, public path instead:
    // build an actual `Sse` response around one event and read its body bytes back with
    // `axum::body::to_bytes`. That is the exact wire format a browser (and
    // `web/src/lib/ozint/stream-parser.ts`) would receive, not an approximation of it.

    async fn render_one_event(event: &LayerEvent) -> String {
        let payload = serde_json::to_string(event).unwrap();
        let sse_event = Event::default().data(&payload);
        let stream = futures::stream::once(async { Ok::<Event, Infallible>(sse_event) });
        let response = Sse::new(stream).into_response();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn a_layer_event_frames_as_a_bare_data_line_with_no_event_or_id() {
        let event = LayerEvent::LayerStart {
            layer_id: "l1".into(),
            investigation_id: "inv-1".into(),
            parent_node_id: "n1".into(),
            firing: 2,
            max_possible: 4,
            gated: 0,
        };
        let frame = render_one_event(&event).await;

        // `web/src/lib/ozint/stream-parser.ts` requires: a `data:` line, no `event:`/`id:`/`retry:` line,
        // and the block ends on the `\n\n` boundary its incremental reader splits on.
        assert!(frame.starts_with("data:"), "frame: {frame:?}");
        assert!(!frame.contains("event:"), "frame: {frame:?}");
        assert!(!frame.contains("id:"), "frame: {frame:?}");
        assert!(!frame.contains("retry:"), "frame: {frame:?}");
        assert!(frame.ends_with("\n\n"), "frame: {frame:?}");

        // And the payload embedded in that line must itself be the exact camelCase JSON the
        // client's LayerEvent union expects.
        let data_line = frame
            .lines()
            .find(|l| l.starts_with("data:"))
            .expect("a data line");
        let json: serde_json::Value =
            serde_json::from_str(data_line.trim_start_matches("data:").trim()).unwrap();
        assert_eq!(json["type"], "layerStart");
        assert_eq!(json["layerId"], "l1");
        assert_eq!(json["maxPossible"], 4);
    }

    #[tokio::test]
    async fn a_node_event_frames_the_same_way() {
        // A second variant, to catch a framing bug that only shows up on a payload shaped
        // differently from LayerStart (e.g. one containing nested objects/newline-sensitive
        // content in its JSON).
        let event = LayerEvent::LayerEmpty {
            layer_id: "l2".into(),
            reports: vec![],
        };
        let frame = render_one_event(&event).await;
        assert!(frame.starts_with("data:"));
        assert!(frame.ends_with("\n\n"));
        let data_line = frame
            .lines()
            .find(|l| l.starts_with("data:"))
            .expect("a data line");
        let json: serde_json::Value =
            serde_json::from_str(data_line.trim_start_matches("data:").trim()).unwrap();
        assert_eq!(json["type"], "layerEmpty");
    }
}
