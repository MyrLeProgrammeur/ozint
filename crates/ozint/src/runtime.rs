//! The engine, and the event union a firing layer emits.
//!
//! [`fire_layer`] is where every other unit meets: it resolves tools through the registry,
//! skips the ones the circuit breaker has given up on, admits the rest through the
//! scheduler's quotas, dispatches them, folds their yields into the triggering node's
//! payload and into typed children, dedups those children against the tree, persists as it
//! goes, and settles.
//!
//! ## The rule this engine exists to enforce
//!
//! **It never recurses.** A child node is created `Idle` and is never fired. "No
//! auto-recursion — the user drives every branch by hand" is a locked rule, and that is not a
//! preference about pacing: an engine that followed its own children would fan a single
//! handle into an unbounded, unbudgeted sweep of paid and rate-limited sources within
//! seconds. Every expansion is one deliberate human click.
//!
//! ## Why one multiplexed stream, not one per layer
//!
//! `POST /api/ozint/fire` opens **one** SSE stream per
//! *investigation*, and every event is stamped with its `layerId`. The reason is not
//! elegance — HTTP/1.1 caps a browser at ~6 connections per origin, and the cockpit's whole
//! interaction model is "continue on this node", repeatedly, with **multiple branches
//! running at once**. A stream per layer would deadlock the sixth branch, and the analyst
//! would experience that as the cockpit silently freezing.
//!
//! ## Why cancel is a POST, not a disconnect
//!
//! Also not a style preference: `POST /api/ozint/cancel` is a
//! separate request, and the runtime must **never** rely on the client disconnecting
//! (axum would surface that as a dropped response future). A browser tab closing does not
//! reliably or promptly propagate, and in the meantime every queued tool call keeps
//! spending real quota — some of it paid, some of it rate-limited to 50 calls *per week*.
//! An abort has to be something the client says, not something we infer.
//!
//! ## Ordering contract
//!
//! Per layer: an optional `Node` frame for the node being fired on, then exactly one
//! `LayerStart`, then a `Node` frame for each node already stored beneath it, then any
//! interleaving of `ToolStart`/`ToolDone`/
//! `Node`/`ParentPayload`, then exactly one terminal event (`LayerSettled`, `LayerEmpty`,
//! `LayerFailed` or `LayerAborted`). `Summary` is the one event permitted **after** a
//! terminal event: the LLM summary pass is fire-and-attach and must never block a layer
//! from settling, so its sentence arrives late by design. `fire_layer` spawns it (see the
//! comment at that call site for why there and not in the route layer) right after the
//! terminal frame is sent, and only when `LayerContext::show_summary` is set — when it is
//! not, no `Summary` frame is emitted at all, on any layer.

use std::sync::{Arc, Mutex};

use chrono::Utc;
use ozint_core::safety::FreezeState;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::fetch::CancelSignal;
use crate::health::ToolHealth;
use crate::layer_plan::{LayerPlan, PhaseAcc};
use crate::outcome::{SettleKind, ToolOutcome, ToolReport};
use crate::registry::{self, ChildSeed, ToolDef, ToolYield};
use crate::sources::{self, DispatchOutcome};
use crate::types::{
    Corroboration, NodeStatus, OzNode, OzRow, OzSection, OzType, Provenance, SectionKind,
};
use crate::visited::{VisitedEntry, VisitedSet};
use crate::{normalize, signal, store, summary};

use ozint_db::Db;

/// One frame on the investigation's SSE stream.
///
/// Every variant carries `layer_id` because the stream is multiplexed across concurrently
/// running branches — a frame that could not say which layer it belongs to would be
/// unroutable on the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum LayerEvent {
    /// A layer began. Carries the full fan-out plan up front so the UI can render
    /// "0 / 14" immediately rather than growing a denominator as tools trickle in.
    #[serde(rename_all = "camelCase")]
    LayerStart {
        layer_id: String,
        investigation_id: String,
        parent_node_id: String,
        /// Tools that will actually fire now.
        firing: usize,
        /// Every tool the plan could reach, conditional phases included. Reporting only
        /// `firing` would hide the conditional cascade from the analyst.
        max_possible: usize,
        /// How many of `max_possible` are ethically gated.
        gated: usize,
    },

    /// A single tool was dispatched.
    #[serde(rename_all = "camelCase")]
    ToolStart {
        layer_id: String,
        tool_id: String,
        label: String,
        gated: bool,
    },

    /// A single tool finished — including the ways it can finish without running at all
    /// (no key, gated-unarmed, circuit open, predicate false). Every dispatched tool
    /// produces exactly one of these, so the UI's in-flight count can never leak.
    #[serde(rename_all = "camelCase")]
    ToolDone {
        layer_id: String,
        report: ToolReport,
    },

    /// A patch to the **triggering** node's own payload, as opposed to a child.
    ///
    /// **Emitted per contributing tool, as the tool returns** — the card of the node you
    /// continued enriches live while its own layer runs, rather than snapping into its
    /// finished shape once. Each
    /// frame carries only *that tool's* patch and section, never the layer's accumulated view,
    /// so a client applies them in arrival order and lands where the stored node already is.
    /// That equivalence is only true because [`merge_patch`] is shallow and last-writer-wins:
    /// folding patches one at a time into the node gives the same keys as folding them into
    /// each other first. A deep merge would make the two orders diverge.
    ///
    /// This distinction is the one `entity-username`'s research surfaced and it is easy to
    /// lose: a root USR node's own `14 / 312 sites` chip is not a child of anything — it is
    /// the node describing itself with what its own layer learned. Without this event the
    /// only way to express it would be a self-child, which would then pollute the tree and
    /// the dedup set.
    #[serde(rename_all = "camelCase")]
    ParentPayload {
        layer_id: String,
        node_id: String,
        /// A JSON merge patch over the node's existing payload.
        patch: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        preview_signal: Option<crate::types::SignalChip>,
        /// The detail sections this layer's tools produced, already merged into the stored
        /// node. Carried on the frame rather than left to a re-fetch so the live panel and
        /// the persisted node agree without a round trip.
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        sections: Vec<OzSection>,
    },

    /// **A node, as it now stands** — not necessarily a new one.
    ///
    /// A newly discovered child is emitted **as it is produced**, not batched at settle: the
    /// store persists nodes as they stream for the same reason, so a browser refresh
    /// mid-layer does not lose what was already found.
    ///
    /// The same frame also opens every layer, restating the node being fired on and the
    /// subtree already stored under it (see `fire_layer`). One frame type covers both because
    /// a client's only correct reduction of this frame is an **upsert keyed on `node.id`**,
    /// which makes a restatement a no-op and a rediscovery-after-a-drop a repair. A client
    /// that instead appends would double every node the moment it re-continued a branch — so
    /// the idempotency is part of the contract, not an implementation detail of the emitter.
    #[serde(rename_all = "camelCase")]
    Node { layer_id: String, node: Box<OzNode> },

    /// A value that was found again rather than found anew. It is deliberately **not** a
    /// `Node`: it annotates the existing node instead of duplicating it, which is precisely
    /// what makes a subsequent `0 NEW ENTITIES` honest rather than an artefact of
    /// re-counting things already in the tree.
    #[serde(rename_all = "camelCase")]
    AlreadyInTree {
        layer_id: String,
        /// The node already holding this value.
        existing_node_id: String,
        /// Rendered annotation, e.g. `already in tree · L1`.
        annotation: String,
        /// **The route that found it this time.** Without it the client could say "found
        /// twice" but never "via github-user and via gravatar-profile", which is the part that
        /// makes a second path evidence rather than trivia. It is also persisted onto the node
        /// (`OzNode::corroborations`), so reopening the investigation does not erase it.
        found_again_by: Corroboration,
        /// How many independent routes now reach this value, the first included. `2` on the
        /// first rediscovery. `None` when the count could not be read back from storage —
        /// stated rather than defaulted to a number that would be a guess.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        paths: Option<usize>,
    },

    /// The layer completed and produced children.
    #[serde(rename_all = "camelCase")]
    LayerSettled {
        layer_id: String,
        new_children: usize,
        reports: Vec<ToolReport>,
    },

    /// The layer completed and produced nothing new. **A real finding**, stated explicitly —
    /// dead ends must be spoken aloud, never left silent.
    #[serde(rename_all = "camelCase")]
    LayerEmpty {
        layer_id: String,
        reports: Vec<ToolReport>,
    },

    /// The layer completed but lost some tools on the way. Distinct from `LayerEmpty`
    /// because information was lost, and from `LayerFailed` because some was not.
    #[serde(rename_all = "camelCase")]
    LayerDegraded {
        layer_id: String,
        new_children: usize,
        reports: Vec<ToolReport>,
    },

    /// The layer taught us nothing because every tool broke or nothing was armed.
    /// **Never** rendered as `0 NEW ENTITIES` — that block means "we looked and there is
    /// nothing", which is exactly what this layer cannot claim.
    #[serde(rename_all = "camelCase")]
    LayerFailed {
        layer_id: String,
        reports: Vec<ToolReport>,
    },

    /// The layer was killed mid-flight. Retryable, and marked as such rather than being
    /// dressed up as a completed layer.
    #[serde(rename_all = "camelCase")]
    LayerAborted {
        layer_id: String,
        reports: Vec<ToolReport>,
    },

    /// The LLM sentence for a settled layer. Arrives after the terminal event by
    /// design; when the LLM is unreachable this still fires, carrying the honest fallback
    /// sentence rather than nothing at all.
    #[serde(rename_all = "camelCase")]
    Summary {
        layer_id: String,
        text: String,
        fallback: bool,
    },

    /// A stream-level failure that is not attributable to one tool.
    #[serde(rename_all = "camelCase")]
    Error {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        layer_id: Option<String>,
        message: String,
    },
}

impl LayerEvent {
    /// The layer this frame belongs to, for client-side routing across branches.
    pub fn layer_id(&self) -> Option<&str> {
        match self {
            LayerEvent::LayerStart { layer_id, .. }
            | LayerEvent::ToolStart { layer_id, .. }
            | LayerEvent::ToolDone { layer_id, .. }
            | LayerEvent::ParentPayload { layer_id, .. }
            | LayerEvent::Node { layer_id, .. }
            | LayerEvent::AlreadyInTree { layer_id, .. }
            | LayerEvent::LayerSettled { layer_id, .. }
            | LayerEvent::LayerEmpty { layer_id, .. }
            | LayerEvent::LayerDegraded { layer_id, .. }
            | LayerEvent::LayerFailed { layer_id, .. }
            | LayerEvent::LayerAborted { layer_id, .. }
            | LayerEvent::Summary { layer_id, .. } => Some(layer_id),
            LayerEvent::Error { layer_id, .. } => layer_id.as_deref(),
        }
    }

    /// Whether this frame closes its layer. `Summary` deliberately does not: it is allowed
    /// to arrive afterwards.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            LayerEvent::LayerSettled { .. }
                | LayerEvent::LayerEmpty { .. }
                | LayerEvent::LayerDegraded { .. }
                | LayerEvent::LayerFailed { .. }
                | LayerEvent::LayerAborted { .. }
        )
    }

    /// Build the terminal frame for a settle decision. Routing this through one function
    /// rather than letting each call site pick a variant is what keeps `SettleKind` and the
    /// wire from ever disagreeing about whether a layer was empty or failed.
    pub fn terminal_for(
        kind: SettleKind,
        layer_id: impl Into<String>,
        new_children: usize,
        reports: Vec<ToolReport>,
    ) -> LayerEvent {
        let layer_id = layer_id.into();
        match kind {
            SettleKind::Settled => LayerEvent::LayerSettled {
                layer_id,
                new_children,
                reports,
            },
            SettleKind::Empty => LayerEvent::LayerEmpty { layer_id, reports },
            SettleKind::Degraded => LayerEvent::LayerDegraded {
                layer_id,
                new_children,
                reports,
            },
            SettleKind::Failed => LayerEvent::LayerFailed { layer_id, reports },
            SettleKind::Aborted => LayerEvent::LayerAborted { layer_id, reports },
        }
    }
}

/// The sentence attached to a layer when a configured model was asked and did not answer.
///
/// It says what actually happened instead of pretending a summary was written: an empty string
/// or a cheerful "analysis complete" would both misrepresent a layer nobody summarised.
///
/// Distinct from [`SUMMARY_NOT_CONFIGURED`], and the distinction is the point — "we asked and
/// it failed" is a fault worth investigating, "no model is configured" is a supported way to
/// run this tool. Reporting the second as the first told every default installation that
/// something had broken.
pub const SUMMARY_UNAVAILABLE: &str = "No summary: the model did not answer when this layer settled. The tool reports below are complete and unaffected.";

/// The sentence attached to a layer when no model is configured at all.
///
/// Running without one is a first-class mode, not a degraded install: every finding in the
/// tree is produced by a deterministic tool, and the summary is a convenience on top. So this
/// reads as a statement of configuration rather than as a failure, and names the variable that
/// would turn it on.
pub const SUMMARY_NOT_CONFIGURED: &str = "No summary: no language model is configured, so none was asked. Set `OZINT_LLM_API_KEY` to enable the one-paragraph narration. The tool reports below are complete and unaffected.";

// ─── The engine ────────────────────────────────────────────────────────────

/// Everything a layer needs that outlives it. Passed by reference so several branches can
/// fire concurrently against one investigation without cloning its state.
pub struct LayerContext {
    pub db: Db,
    pub investigation_id: String,
    /// The node the analyst clicked "continue" on — or the root, on the first Autofire.
    pub parent_node_id: String,
    pub parent_depth: i64,
    pub oz_type: OzType,
    pub value: String,
    /// Shared across every branch of one investigation. Dedup is a property of the *tree*,
    /// so two branches running at once must contend for the same set — otherwise both can
    /// independently "discover" the same value and the tree grows a duplicate.
    pub visited: Arc<Mutex<VisitedSet>>,
    pub health: Arc<ToolHealth>,
    /// Per-`rate_key` quota enforcement, shared process-wide.
    ///
    /// `Option` rather than a bare `Arc`, and it is worth saying why rather than reading it as
    /// laxity: a scheduler with no registered window for a key admits instantly, so `None` and
    /// "a scheduler that knows no quotas" behave identically. Making it optional keeps the
    /// several dozen existing `LayerContext` literals in tests from each having to build one
    /// to express "not the thing under test", without inventing a second no-op implementation.
    /// The server always supplies one — see `AppState`.
    pub scheduler: Option<Arc<crate::scheduler::Scheduler>>,
    /// The fetch cache, shared process-wide for the same reason the scheduler is: a cached
    /// upstream response belongs to the upstream, not to one investigation, and the fetches
    /// most worth collapsing (the KEV catalogue, the WhatsMyName site list) are exactly the
    /// ones every investigation asks for identically.
    ///
    /// `Option` on the same grounds as [`LayerContext::scheduler`] — `None` is indistinguish-
    /// able from a cache whose every TTL is zero, so a test can say "not the thing under test"
    /// without building one. The server always supplies one; see `AppState`.
    pub cache: Option<Arc<crate::cache::ToolCache>>,
    pub cancel: Option<CancelSignal>,
    /// The LLM summary pass's server-side skip (`showSummary` in the fire body, default
    /// `true`). When `false`, `fire_layer` never spawns the summary task at all — no LLM call,
    /// no cost, no `Summary` frame. See `summary::run`'s doc for the split of responsibility.
    pub show_summary: bool,
    /// The server-side kill switch, sampled once right before the summary is spawned (see
    /// `fire_layer`). `egress::oz_guard`'s module doc names this unit as the first caller
    /// expected to feed the freeze gate — a request-time freeze already blocks `/api/ozint/fire`
    /// at the route middleware and never reaches here, so what this actually covers is a layer
    /// that was already in flight when the freeze landed: the kill switch cancels it (settling
    /// it `Aborted`), and this snapshot keeps the *summary* from turning around and making the
    /// exact outbound call the freeze was just used to stop.
    pub freeze: Arc<FreezeState>,
}

/// What a settled layer leaves behind, for the caller that owns the HTTP response.
#[derive(Debug, Clone)]
pub struct LayerResult {
    pub layer_id: String,
    pub kind: SettleKind,
    pub new_children: usize,
    pub reports: Vec<ToolReport>,
    /// Tool invocations to bill to the lookup meter. A 730-site fan-out is **one**.
    pub lookups: i64,
    pub cost_cents: i64,
}

/// How long a tool will wait for its quota window before the layer gives up on it and reports
/// [`ToolOutcome::RateLimitedDropped`].
///
/// Chosen against the quotas actually registered (`registry::rate_limits_for`): Nominatim's
/// 1/second and NVD's 5-per-30s both refill well inside this, so a realistic burst waits and
/// then runs rather than being dropped. GitHub's 60/hour does not — a layer that has genuinely
/// exhausted an hourly budget should tell the analyst so within a few seconds, not hold the
/// stream open for the rest of the hour. That asymmetry is the point: waiting is for windows
/// that reopen on a human timescale.
const SCHEDULER_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(45);

fn settle_status_str(kind: SettleKind) -> &'static str {
    match kind {
        SettleKind::Settled => "settled",
        SettleKind::Empty => "empty",
        SettleKind::Degraded => "degraded",
        SettleKind::Failed => "failed",
        SettleKind::Aborted => "aborted",
    }
}

fn node_status_for(kind: SettleKind) -> NodeStatus {
    match kind {
        SettleKind::Settled => NodeStatus::Settled,
        SettleKind::Empty => NodeStatus::Empty,
        SettleKind::Degraded => NodeStatus::Degraded,
        SettleKind::Failed => NodeStatus::Failed,
        SettleKind::Aborted => NodeStatus::Aborted,
    }
}

/// Shallow JSON merge of a tool's `payload_patch` into an accumulating patch.
///
/// Deliberately shallow, and deliberately last-writer-wins per key. A deep merge would
/// silently interleave two tools' views of the same nested object, which is precisely the
/// multi-source *conflict* case this codebase refuses to auto-resolve — conflicts belong in
/// the subject file as two visible values, not blended invisibly inside one payload.
fn merge_patch(acc: &mut serde_json::Value, patch: &serde_json::Value) {
    let (serde_json::Value::Object(dst), serde_json::Value::Object(src)) = (&mut *acc, patch)
    else {
        return;
    };
    for (k, v) in src {
        dst.insert(k.clone(), v.clone());
    }
}

/// Turns one accepted [`ChildSeed`] into a persisted, emitted child node — or, when the
/// value is already somewhere in this tree, into an annotation instead.
///
/// Returns `true` when a genuinely new node was added, which is what feeds `new_children`
/// and therefore the `Empty`-vs-`Settled` verdict.
#[allow(clippy::too_many_arguments)]
async fn emit_child(
    ctx: &LayerContext,
    layer_id: &str,
    tool: &ToolDef,
    seed: &ChildSeed,
    tx: &mpsc::Sender<LayerEvent>,
) -> bool {
    let normalized = normalize::normalize(seed.oz_type, &seed.value);
    let dedup_key = normalize::dedup_key(seed.oz_type, &seed.value);

    // Dedup before persisting, not after: a value already in the tree must never reach the
    // node table, or a later rehydrate would resurrect the duplicate we just suppressed.
    // Copy what the annotation needs and release the lock *before* awaiting the send.
    // Holding it across an await would let one branch pin the shared visited set while it
    // waits on a full channel that only drains when the consumer is polled — and every
    // other branch of this investigation contends for that same lock.
    let already = {
        let visited = ctx.visited.lock().unwrap();
        visited
            .check(seed.oz_type, &dedup_key)
            .map(|existing| (existing.node_id.clone(), existing.annotation()))
    };
    if let Some((existing_node_id, annotation)) = already {
        // This is corroboration, and the route that produced it was sitting in
        // scope here being thrown away. Persist it first — a marker that lived only on the
        // frame vanished on the next rehydrate.
        let found_again_by = Corroboration {
            tool_id: tool.id.to_string(),
            method: tool.method.to_string(),
            parent_node_id: ctx.parent_node_id.clone(),
            layer_id: layer_id.to_string(),
            found_at: Utc::now(),
            gated: tool.gated,
        };
        let paths = match store::record_corroboration(
            &ctx.db,
            &existing_node_id,
            &found_again_by,
            &annotation,
        ) {
            Ok(paths) => paths,
            Err(e) => {
                tracing::warn!(node_id = %existing_node_id, error = %e, "could not record corroboration");
                None
            }
        };
        let _ = tx
            .send(LayerEvent::AlreadyInTree {
                layer_id: layer_id.to_string(),
                existing_node_id,
                annotation,
                found_again_by,
                paths,
            })
            .await;
        return false;
    }

    let node_id = uuid::Uuid::new_v4().to_string();
    let depth = ctx.parent_depth + 1;
    let ordinal =
        store::next_ordinal(&ctx.db, &ctx.investigation_id, Some(&ctx.parent_node_id)).unwrap_or(0);

    let mut provenance = Provenance::new(tool.id, tool.method);
    provenance.found_via_parent_id = Some(ctx.parent_node_id.clone());
    // Gating propagates onto the node AND its provenance, and is never cleared downstream —
    // a finding a gated tool touched stays marked, everywhere.
    provenance.gated = tool.gated;

    let node = OzNode {
        id: node_id.clone(),
        investigation_id: ctx.investigation_id.clone(),
        parent_id: Some(ctx.parent_node_id.clone()),
        layer_id: Some(layer_id.to_string()),
        ordinal,
        depth,
        oz_type: seed.oz_type,
        value: normalized.key.clone(),
        display: normalized.display.clone(),
        dedup_key: dedup_key.clone(),
        payload: crate::types::OzPayload::empty_for(seed.oz_type),
        // A freshly discovered child has an empty payload, so it has no verdict to show
        // yet. It earns a chip only once the analyst continues on it and its own layer
        // runs — inventing one here would assert a finding nothing produced.
        preview_signal: None,
        full_signal: None,
        sections: Vec::new(),
        gated: tool.gated,
        // Idle, always. This is the no-auto-recursion rule in one field.
        status: NodeStatus::Idle,
        provenance,
        already_in_tree: None,
        corroborations: Vec::new(),
        edited_value: None,
        created_at: Utc::now(),
    };

    if let Err(e) = store::insert_node(&ctx.db, &node) {
        tracing::warn!(node_id = %node_id, error = %e, "failed to persist an ozint child node");
        let _ = tx
            .send(LayerEvent::Error {
                layer_id: Some(layer_id.to_string()),
                message: format!("could not persist a discovered node: {e}"),
            })
            .await;
        return false;
    }

    {
        let mut visited = ctx.visited.lock().unwrap();
        visited.insert(
            seed.oz_type,
            &dedup_key,
            VisitedEntry::new(node_id.clone(), depth, Some(layer_id.to_string())),
        );
    }

    let _ = tx
        .send(LayerEvent::Node {
            layer_id: layer_id.to_string(),
            node: Box::new(node),
        })
        .await;
    true
}

/// Runs one layer to settlement, streaming events as it goes.
///
/// The caller owns the receiving half of `tx` and is responsible for framing it onto the
/// investigation's SSE stream. Events are sent as work completes — nodes in particular are
/// persisted and emitted the moment they are found, not batched at settle, so a browser
/// refresh mid-layer does not lose what was already discovered.
/// Accounts for every tool a kill stopped from producing anything: `rest` is the slice of the
/// current phase from the tool the cancel landed on, inclusive, so both "aborted mid-request"
/// and "never started" are covered by one call.
///
/// **Only the current phase.** Later phases were never admitted by `firing_now` — their
/// `when(acc)` predicate was never evaluated, and it may well have been false — so claiming
/// they were cancelled would invent a capability the layer never had. That boundary is the
/// same one `SkippedPhasePredicate` draws in the normal path.
///
/// Tools already carrying a report (registry-skipped, circuit-open) keep theirs: a tool that
/// was never going to run was not cancelled.
fn report_cancelled_rest(reports: &mut Vec<ToolReport>, rest: &[String]) {
    for tool_id in rest {
        if reports.iter().any(|r| &r.tool_id == tool_id) {
            continue;
        }
        let (label, gated, method) = match registry::find(tool_id) {
            Some(tool) => (tool.label.to_string(), tool.gated, tool.method.to_string()),
            None => (tool_id.clone(), false, "not dispatched".to_string()),
        };
        reports.push(ToolReport::new(
            tool_id.clone(),
            label,
            ToolOutcome::Cancelled,
            0,
            gated,
            method,
        ));
    }
}

/// Reports every tool of a phase the cascade never opened, so a held-back phase is visible
/// instead of absent.
///
/// Without this, a conditional phase simply vanishes: `LayerStart` has already told the UI
/// that `max_possible` counts every tool the plan could reach, so a phase whose predicate was
/// false leaves the analyst looking at `4 / 5` with no fifth tool and no reason. That is the
/// silent shrink `ToolOutcome::SkippedPhasePredicate` and `LayerPlan::skipped_from` were
/// written to prevent — and, until `entity-cve` became the first plan with a conditional
/// phase, neither had a caller to prevent it with.
///
/// Tools already carrying a report (registry-skipped, circuit-open) keep theirs, for the same
/// reason `report_cancelled_rest` leaves them alone.
fn report_phase_skipped(reports: &mut Vec<ToolReport>, phase: &crate::layer_plan::LayerPhase) {
    let name = phase.when.name();
    for tool_id in &phase.tools {
        if reports.iter().any(|r| &r.tool_id == tool_id) {
            continue;
        }
        let (label, gated, method) = match registry::find(tool_id) {
            Some(tool) => (tool.label.to_string(), tool.gated, tool.method.to_string()),
            None => (tool_id.clone(), false, "not dispatched".to_string()),
        };
        reports.push(ToolReport::new(
            tool_id.clone(),
            label,
            ToolOutcome::SkippedPhasePredicate {
                reason: format!("phase `{}` did not open: {name}", phase.id),
            },
            0,
            gated,
            method,
        ));
    }
}

/// The [`ToolOutcome::SkippedMissingInput`] this tool should be refused with, or `None` when
/// every `needs_input` key it declares is readable.
///
/// The reason distinguishes the two failures, because they call for different actions from the
/// analyst: an *absent* key means the upstream tool errored and the layer is worth re-firing;
/// a *disputed* key means two sources disagreed and the disagreement is itself the finding.
fn missing_input_for(
    tool: &ToolDef,
    handoff: &crate::layer_plan::Handoff,
    acc: &PhaseAcc,
) -> Option<ToolOutcome> {
    use crate::layer_plan::ValueStatus;

    for key in tool.needs_input {
        if handoff.contains_key(*key) {
            continue;
        }
        let reason = match acc.value_status(key) {
            ValueStatus::Disputed { first, second } => format!(
                "`{key}` is disputed — {} reported `{}`, {} reported `{}`; this layer will not pick one",
                first.0, first.1, second.0, second.1
            ),
            // `Ready` is unreachable: a readable value is in the snapshot by construction, and
            // the snapshot was taken from this same accumulator. Phrased as the absent case
            // rather than asserted, because being wrong here should cost a slightly odd
            // sentence, not a panic mid-layer.
            ValueStatus::Absent | ValueStatus::Ready { .. } => format!(
                "no earlier tool in this layer published `{key}`, so there was nothing to look up"
            ),
        };
        return Some(ToolOutcome::SkippedMissingInput {
            input: (*key).to_string(),
            reason,
        });
    }
    None
}

/// Merges a layer's accumulated patch into the node it fired on, **stores it**, and returns
/// the chip that patch produces.
///
/// See the call site for why the store write matters. Returns `None` whenever the node cannot
/// be loaded, the merge cannot be re-typed, or the merged payload yields no verdict — a
/// missing chip is not an error, it is a node with nothing to claim yet.
/// Folds one tool's loose [`ToolYield::rows`] into a single detail section owned by that tool.
///
/// **One section per tool, never one merged block.** It is the same rule the payload fan-out
/// follows for a different reason: two tools reporting a `Location` are reporting two
/// observations, and a merged key/value block would show one of them with no indication that
/// the other existed or disagreed. The section id is the tool id, so a re-fire or a refresh
/// replaces that tool's block rather than appending a second copy.
///
/// [`SectionKind::KeyValue`] for everything: a row carrying an `href` renders its own `SRC ↗`
/// regardless of the section's kind (see [`OzRow::href`]), so `Links` would only be a claim
/// that *every* row in the block is a link — which no tool here guarantees.
pub(crate) fn section_from_rows(tool: &ToolDef, rows: Vec<OzRow>) -> Option<OzSection> {
    if rows.is_empty() {
        return None;
    }
    let rows = rows
        .into_iter()
        .map(|mut row| {
            // Stamped, not assumed: the section id already names the tool, but a row can be
            // lifted out of its section (relations mines them individually) and must not lose
            // where it came from on the way.
            row.source_tool_id
                .get_or_insert_with(|| tool.id.to_string());
            row
        })
        .collect();
    Some(OzSection {
        id: tool.id.to_string(),
        label: tool.label.to_string(),
        kind: SectionKind::KeyValue,
        rows,
    })
}

/// Replaces same-id sections in place and appends genuinely new ones.
///
/// Replace rather than append: firing a layer twice on one node, or refreshing it, re-runs the
/// same tools, and appending would grow a second `GitHub` block on every run. Replace rather
/// than merge-rows: the tool just re-answered, so its new rows are its current answer in full.
pub(crate) fn merge_sections(existing: &mut Vec<OzSection>, incoming: &[OzSection]) {
    for section in incoming {
        match existing.iter_mut().find(|s| s.id == section.id) {
            Some(slot) => *slot = section.clone(),
            None => existing.push(section.clone()),
        }
    }
}

fn persist_parent_payload(
    db: &Db,
    node_id: &str,
    patch: &serde_json::Value,
    gated_verdict: bool,
    contributing: &[&'static str],
    sections: &[OzSection],
) -> Option<crate::types::SignalChip> {
    let mut node = match store::get_node(db, node_id) {
        Ok(Some(node)) => node,
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!(%node_id, error = %e, "failed to load the ozint parent node");
            return None;
        }
    };

    let mut payload_json = serde_json::to_value(&node.payload).ok()?;
    merge_patch(&mut payload_json, patch);
    let merged: crate::types::OzPayload = serde_json::from_value(payload_json).ok()?;

    let chip = signal::signal_for(&merged, signal::SignalMode::Native)
        // A gated tool anywhere in this layer marks the verdict it helped produce.
        .map(|chip| {
            if gated_verdict {
                signal::apply_gated(chip)
            } else {
                chip
            }
        });

    node.payload = merged;
    node.preview_signal = chip.clone();
    merge_sections(&mut node.sections, sections);
    // Every tool that actually patched this node's payload contributed to what it now claims,
    // so it belongs in the chain — and it is what a node refresh re-invokes when the
    // analyst re-runs this lookup.
    for tool_id in contributing {
        if !node.provenance.tool_chain.iter().any(|t| t == tool_id) {
            node.provenance.tool_chain.push((*tool_id).to_string());
        }
    }
    node.provenance.retrieved_at = Utc::now();
    if gated_verdict {
        node.provenance.gated = true;
        node.gated = true;
    }
    if let Err(e) = store::insert_node(db, &node) {
        tracing::warn!(%node_id, error = %e, "failed to persist the ozint parent payload");
    }
    chip
}

/// Reads the stored tree and returns the node this layer fires on, plus every node stored
/// beneath it in breadth-first order.
///
/// Reads through `store::list_nodes` — the same call `GET /api/ozint/investigations/{id}`
/// serves its `nodes` from — so the replay and the rehydrate can never disagree about what
/// the tree contains, rejected nodes included.
///
/// Degrades to `(None, [])` rather than failing the layer: a stream that cannot restate the
/// tree is a poorer stream, never a reason to refuse to search.
fn replay_subtree(ctx: &LayerContext) -> (Option<OzNode>, Vec<OzNode>) {
    let nodes = match store::list_nodes(&ctx.db, &ctx.investigation_id) {
        Ok(nodes) => nodes,
        Err(e) => {
            tracing::warn!(
                investigation_id = %ctx.investigation_id,
                error = %e,
                "could not read the stored tree to replay it onto the stream"
            );
            return (None, Vec::new());
        }
    };
    match split_subtree(nodes, &ctx.parent_node_id) {
        Some((root, descendants)) => (Some(root), descendants),
        None => {
            // Not fatal, but never normal: every caller fires on a node it just read or just
            // wrote. Silence here would have been the third way this contract could be
            // broken without a symptom.
            tracing::warn!(
                node_id = %ctx.parent_node_id,
                investigation_id = %ctx.investigation_id,
                "the node this layer fires on is absent from its investigation's stored tree"
            );
            (None, Vec::new())
        }
    }
}

/// Splits a flat node list into `(the node with `root_id`, its descendants breadth-first)`.
///
/// Breadth-first, and each sibling group in `ordinal` order, so the replay arrives in the
/// same order the tree was built in — a client that appends children in arrival order lands
/// on the identical layout whether it built the tree live or received it here.
///
/// `None` when `root_id` is not in the list. Nodes unreachable from `root_id` (siblings,
/// ancestors, other branches) are dropped: this layer speaks for its own subtree only.
fn split_subtree(nodes: Vec<OzNode>, root_id: &str) -> Option<(OzNode, Vec<OzNode>)> {
    use std::collections::{HashMap, VecDeque};

    let mut root: Option<OzNode> = None;
    let mut by_parent: HashMap<String, Vec<OzNode>> = HashMap::new();
    for node in nodes {
        if node.id == root_id {
            root = Some(node);
            continue;
        }
        if let Some(parent_id) = node.parent_id.clone() {
            by_parent.entry(parent_id).or_default().push(node);
        }
    }
    let root = root?;
    for siblings in by_parent.values_mut() {
        siblings.sort_by_key(|n| n.ordinal);
    }

    let mut out = Vec::new();
    let mut queue = VecDeque::from([root.id.clone()]);
    // `remove`, not `get`: a parent is expanded at most once, so a cycle in the stored
    // `parent_id` graph cannot turn this into an infinite walk.
    while let Some(id) = queue.pop_front() {
        let Some(children) = by_parent.remove(&id) else {
            continue;
        };
        for child in children {
            queue.push_back(child.id.clone());
            out.push(child);
        }
    }
    Some((root, out))
}

pub async fn fire_layer(
    ctx: &LayerContext,
    plan: &LayerPlan,
    tx: mpsc::Sender<LayerEvent>,
) -> LayerResult {
    let layer_id = uuid::Uuid::new_v4().to_string();
    let started_at = Utc::now();

    let resolution = registry::resolve(ctx.oz_type);
    let gated_in_plan = plan.gated_count(registry::is_gated);

    // ── The stored subtree, replayed onto the stream (see `replay_subtree`'s doc) ────────
    //
    // Split around `LayerStart` on purpose, and the split is the whole point:
    //
    // - **the fired node goes first**, because a client marks it *running* when the layer
    //   opens and can only do that for a node it already knows. On a fresh seed the root is
    //   created by the route before the stream even exists, so a frames-only client had
    //   nothing at all to mark — an empty canvas for the entire run of a layer it could see
    //   firing.
    // - **its descendants go after**, because opening a layer on a node is what tells a
    //   client that node's children are about to be re-established, so anything it was
    //   holding under it is dropped at that instant. Sent before `LayerStart` they would be
    //   swallowed by that drop; sent after, they restore exactly what the store still holds
    //   — which matters because a re-continue does *not* re-emit them as new children. They
    //   are in the rebuilt `VisitedSet`, so they come back as `AlreadyInTree` frames
    //   pointing at node ids the client has just discarded.
    let (fired_node, existing_descendants) = replay_subtree(ctx);

    if let Some(node) = fired_node {
        let _ = tx
            .send(LayerEvent::Node {
                layer_id: layer_id.clone(),
                node: Box::new(node),
            })
            .await;
    }

    let _ = tx
        .send(LayerEvent::LayerStart {
            layer_id: layer_id.clone(),
            investigation_id: ctx.investigation_id.clone(),
            parent_node_id: ctx.parent_node_id.clone(),
            firing: resolution.runnable.len(),
            max_possible: plan.max_possible(),
            gated: gated_in_plan,
        })
        .await;

    for node in existing_descendants {
        let _ = tx
            .send(LayerEvent::Node {
                layer_id: layer_id.clone(),
                node: Box::new(node),
            })
            .await;
    }

    if let Err(e) = store::insert_layer(
        &ctx.db,
        &layer_id,
        &ctx.investigation_id,
        &ctx.parent_node_id,
        ctx.oz_type,
        &ctx.value,
        "running",
        started_at,
    ) {
        tracing::warn!(layer_id = %layer_id, error = %e, "failed to persist the ozint layer row");
    }

    let mut reports: Vec<ToolReport> = Vec::new();
    let mut acc = PhaseAcc::default();
    let mut new_children = 0usize;
    let mut lookups = 0i64;
    let mut cost_cents = 0i64;
    let mut aborted = false;
    // Whether any tool has already enriched the parent node this layer, and whether one of
    // those frames already carried the gated verdict. Both exist only to keep the *end state*
    // of the incremental emission identical to the single end-of-layer emission it replaced —
    // see the reconciliation after the phase loop.
    let mut emitted_parent = false;
    let mut gated_marked = false;

    // Tools the registry could not run at all (unarmed, gated-unarmed) are reported before
    // anything fires. They are part of the layer's honest account of itself: the analyst
    // must be able to see that a capability existed and why it stayed silent.
    for (tool, outcome) in &resolution.skipped {
        reports.push(ToolReport::new(
            tool.id,
            tool.label,
            outcome.clone(),
            0,
            tool.gated,
            tool.method,
        ));
    }

    let mut phase_index = 0usize;
    while let Some((idx, phase)) = plan.firing_now(phase_index, &acc) {
        // `firing_now` jumps over any phase whose predicate was false to reach this one. Those
        // jumped-over phases are reported here and nowhere else: the tail sweep after the loop
        // only looks forward from the last phase that ran, so a phase skipped *between* two
        // that ran would otherwise disappear entirely.
        for passed in &plan.phases[phase_index..idx] {
            report_phase_skipped(&mut reports, passed);
        }
        phase_index = idx + 1;

        // The sibling hand-off, frozen once per phase.
        //
        // Taken here rather than inside the tool loop on purpose, and the difference is not
        // cosmetic: read per-tool, a tool would see whatever its *same-phase* predecessors had
        // just published, which works only because this loop happens to be sequential. Nothing
        // promises that — `LayerPhase`'s own doc says order within a phase is irrelevant
        // because a phase fans out in parallel — so a hand-off that depended on it would be
        // correct by accident today and silently wrong the day the fan-out becomes concurrent.
        // A phase-start snapshot gives every tool in the phase the same view, and that view is
        // exactly the guarantee the plan already makes: earlier phases ran first.
        let handoff = acc.handoff();

        for (position, tool_id) in phase.tools.iter().enumerate() {
            if ctx.cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
                aborted = true;
                report_cancelled_rest(&mut reports, &phase.tools[position..]);
                break;
            }

            let Some(tool) = registry::find(tool_id) else {
                // The plan named a tool the catalogue does not have. Surface it as a visible
                // failure rather than skipping quietly — a plan/catalogue drift that hides
                // itself is how a layer silently stops doing half its job.
                reports.push(ToolReport::new(
                    tool_id.clone(),
                    tool_id.clone(),
                    ToolOutcome::ParseError {
                        message: format!("layer plan names `{tool_id}`, absent from the registry"),
                    },
                    0,
                    false,
                    "not dispatched",
                ));
                continue;
            };

            // Already accounted for by the registry resolution above.
            if resolution.skipped.iter().any(|(t, _)| t.id == tool.id) {
                continue;
            }

            // A tool that runs on a sibling's output, whose sibling did not deliver.
            //
            // Refused here — before the breaker, the quota and `ToolStart` — because none of
            // those apply to a request that will not be made: it must not sample the circuit
            // breaker (the source did not fail), must not consume a quota permit (nothing was
            // sent), and must not move the UI's in-flight count. The report still reaches the
            // analyst in the terminal frame, naming the key and which of the two ways it was
            // unreadable.
            if let Some(missing) = missing_input_for(tool, &handoff, &acc) {
                reports.push(ToolReport::new(
                    tool.id,
                    tool.label,
                    missing,
                    0,
                    tool.gated,
                    tool.method,
                ));
                continue;
            }

            // A source the breaker has given up on costs nothing to skip and a full timeout
            // to attempt — multiplied by every layer the analyst fires.
            if let Some(open) = ctx.health.check(tool.id) {
                reports.push(ToolReport::new(
                    tool.id,
                    tool.label,
                    open,
                    0,
                    tool.gated,
                    tool.method,
                ));
                continue;
            }

            // Quota, before the request and before `ToolStart`. The source scheduler was
            // built as part of this crate's first wave and then had **no caller at all** —
            // this module's own doc claimed it "admits the rest through the scheduler's
            // quotas", which was simply not happening, and `ToolOutcome::RateLimitedDropped`
            // was an unreachable variant of the taxonomy. Every registered quota
            // (`registry::rate_limits_for`) was decorative until here.
            //
            // Reported *without* a `ToolStart`/`ToolDone` pair, matching how the registry's own
            // skips are handled: nothing was dispatched, so the UI's in-flight count must not
            // move. The report still reaches the analyst in the terminal frame.
            if let Some(scheduler) = &ctx.scheduler {
                match scheduler
                    .acquire_cancellable(tool.rate_key, SCHEDULER_MAX_WAIT, ctx.cancel.clone())
                    .await
                {
                    Ok(_permit) => {}
                    Err(ToolOutcome::Cancelled) => {
                        aborted = true;
                        report_cancelled_rest(&mut reports, &phase.tools[position..]);
                        break;
                    }
                    Err(dropped) => {
                        reports.push(ToolReport::new(
                            tool.id,
                            tool.label,
                            dropped,
                            0,
                            tool.gated,
                            tool.method,
                        ));
                        continue;
                    }
                }
            }

            let _ = tx
                .send(LayerEvent::ToolStart {
                    layer_id: layer_id.clone(),
                    tool_id: tool.id.to_string(),
                    label: tool.label.to_string(),
                    gated: tool.gated,
                })
                .await;

            let began = std::time::Instant::now();
            // The TTL comes off the tool's own registry entry: the caller is the source of
            // truth for what TTL to pass (see `cache.rs`), which has no built-in TTL table.
            // A layer never bypasses: forcing a fresh fetch is a node refresh's job and
            // only its job, otherwise the cache would only ever be written and never read.
            let tool_ctx = sources::ToolCtx {
                cancel: ctx.cancel.clone(),
                cache: ctx.cache.clone(),
                ttl: std::time::Duration::from_secs(tool.ttl_secs),
                bypass: false,
                handoff: handoff.clone(),
            };
            let dispatched = sources::dispatch(tool.id, &ctx.value, &tool_ctx).await;
            let elapsed_ms = began.elapsed().as_millis() as u64;

            let (outcome, produced) = match dispatched {
                DispatchOutcome::Cancelled => {
                    aborted = true;
                    // This tool *did* start; it just never got to a result. It belongs in the
                    // cancelled account exactly like the ones that never started.
                    report_cancelled_rest(&mut reports, &phase.tools[position..]);
                    break;
                }
                DispatchOutcome::Ran(outcome, produced) => (outcome, produced),
            };

            // One tick per tool invocation, whatever the fan-out underneath it.
            lookups += 1;
            cost_cents += tool.cost_cents as i64;

            ctx.health.record(tool.id, &outcome);
            let report = ToolReport::new(
                tool.id,
                tool.label,
                outcome,
                elapsed_ms,
                tool.gated,
                tool.method,
            );
            let _ = tx
                .send(LayerEvent::ToolDone {
                    layer_id: layer_id.clone(),
                    report: report.clone(),
                })
                .await;
            reports.push(report);

            let Some(ToolYield {
                payload_patch: patch,
                rows,
                facts,
                flags,
                values,
                children,
            }) = produced
            else {
                continue;
            };

            // Until this line, `rows` was destructured away with `..` here and in
            // `refresh.rs`, so every row every tool built was dropped on the floor between
            // the tool and the node. It produced no symptom anywhere: `OzNode::sections` is
            // created empty and round-trips through the store fine, so the detail panel was
            // simply always empty, and `relations::infer` — which mines `node.sections` for
            // evidence rows — was reading a vector nothing ever wrote to.
            // The parent node is enriched here, per tool, rather than once after
            // the whole loop. The layer used to accumulate every patch and every section and
            // fire a single frame just before the terminal event, so the card of the node the
            // analyst continued sat empty for the length of the layer and then snapped into
            // its finished shape — while the engine's whole model is that the node you act on
            // gets richer as tools return.
            //
            // Persisting per tool is safe for the same reason emitting per tool is: the merge
            // is shallow and last-writer-wins, so folding patches into the node one at a time
            // leaves exactly the keys that folding them into each other first would have.
            // Nothing here may come to depend on seeing the layer's accumulated patch.
            let tool_sections: Vec<OzSection> = section_from_rows(tool, rows).into_iter().collect();
            let patched = patch.as_object().is_some_and(|o| !o.is_empty());
            if patched || !tool_sections.is_empty() {
                // A gated tool anywhere in this layer marks the verdict it helped produce.
                // Read off `reports`, which already holds this tool's own report, so the
                // running value is the final one as soon as the gated tool has run.
                let gated_verdict = reports.iter().any(|r| r.gated && r.outcome.is_success());
                // Only a tool that actually patched the payload joins the node's tool chain —
                // a tool that ran and contributed nothing belongs to the layer's reports, not
                // to this node's provenance.
                let contributing = [tool.id];
                let chip = persist_parent_payload(
                    &ctx.db,
                    &ctx.parent_node_id,
                    &patch,
                    gated_verdict,
                    if patched { &contributing } else { &[] },
                    &tool_sections,
                );
                let _ = tx
                    .send(LayerEvent::ParentPayload {
                        layer_id: layer_id.clone(),
                        node_id: ctx.parent_node_id.clone(),
                        patch: patch.clone(),
                        preview_signal: chip,
                        sections: tool_sections,
                    })
                    .await;
                emitted_parent = true;
                gated_marked |= gated_verdict;
            }

            for (k, v) in facts {
                acc.set_fact(k, v);
            }
            for (k, v) in flags {
                acc.set_flag(k, v);
            }
            // Published for the *next* phase, never for this one — the snapshot above was
            // already handed to every tool in this phase, so nothing here can see it yet.
            for (k, v) in values {
                acc.set_value(k, v, tool.id);
            }
            acc.tools_run.push(tool.id.to_string());

            for seed in &children {
                if emit_child(ctx, &layer_id, tool, seed, &tx).await {
                    new_children += 1;
                }
            }
            acc.children = new_children;
        }

        if aborted {
            break;
        }
    }

    // The tail: phases after the last one that ran, none of whose predicates hold.
    //
    // Deliberately not reached when `aborted`. A cancel stops the cascade before those
    // predicates were ever evaluated, so reporting them as "skipped because the predicate was
    // false" would state a test result nobody computed — the same boundary
    // `report_cancelled_rest` draws for exactly the same reason.
    if !aborted {
        for (phase, _) in plan.skipped_from(phase_index, &acc) {
            report_phase_skipped(&mut reports, phase);
        }
    }

    // The parent node was already enriched and persisted tool by tool above. One case does not
    // reach it: a **gated** tool that succeeded *after* the last tool to contribute a patch or
    // a section. The end-of-layer emission this replaced read the gated verdict off the whole
    // report set, so it caught that tool; the incremental frames each read it as of their own
    // moment, and no frame follows to carry it. Without this the node would silently lose its
    // gated marking depending on tool order alone.
    //
    // Deliberately conditional on a frame having been emitted at all: under the old code the
    // guard was `patch OR sections`, so a layer that produced neither never persisted anything
    // and never marked the node gated either. That stays true.
    if emitted_parent && !gated_marked && reports.iter().any(|r| r.gated && r.outcome.is_success())
    {
        let chip = persist_parent_payload(
            &ctx.db,
            &ctx.parent_node_id,
            &serde_json::json!({}),
            true,
            &[],
            &[],
        );
        let _ = tx
            .send(LayerEvent::ParentPayload {
                layer_id: layer_id.clone(),
                node_id: ctx.parent_node_id.clone(),
                patch: serde_json::json!({}),
                preview_signal: chip,
                sections: Vec::new(),
            })
            .await;
    }

    let kind = crate::outcome::settle_kind(&reports, new_children, aborted);
    let status = settle_status_str(kind);

    let reports_json = serde_json::to_string(&reports).ok();
    if let Err(e) = store::settle_layer(
        &ctx.db,
        &layer_id,
        status,
        Utc::now(),
        new_children as i64,
        reports_json.as_deref(),
    ) {
        tracing::warn!(layer_id = %layer_id, error = %e, "failed to settle the ozint layer row");
    }
    if let Err(e) = store::set_node_status(&ctx.db, &ctx.parent_node_id, node_status_for(kind)) {
        tracing::warn!(node_id = %ctx.parent_node_id, error = %e, "failed to update the ozint parent node status");
    }
    if let Err(e) = store::bump_investigation_usage(
        &ctx.db,
        &ctx.investigation_id,
        lookups,
        cost_cents,
        Utc::now(),
    ) {
        tracing::warn!(error = %e, "failed to bill the ozint lookup meter");
    }

    let _ = tx
        .send(LayerEvent::terminal_for(
            kind,
            layer_id.clone(),
            new_children,
            reports.clone(),
        ))
        .await;

    // Spawned, not awaited, and only *after* the terminal frame is already on the wire: this is
    // what makes the summary genuinely fire-and-attach rather than fire-and-block. Doing it here
    // rather than in the route's relay task (`ozint-server/src/routes/ozint/fire.rs`) buys two
    // things that matter more than keeping this crate free of an LLM call: (1) `fire_layer` is
    // the one place that already holds every fact the summary needs (`reports`, `kind`,
    // `new_children`, the gated verdict) without re-deriving them from a cloned `LayerEvent`
    // stream on the other side of a channel; (2) it makes the fire-and-attach guarantee a
    // property of the *engine*, matching this module's existing rule that fire_layer runs to
    // settlement "regardless of whether anyone is still reading the stream" — the summary now
    // inherits that same independence for free, instead of depending on the relay task's own
    // drain-to-completion behaviour staying correct forever.
    if ctx.show_summary {
        let gated_verdict = reports.iter().any(|r| r.gated && r.outcome.is_success());
        let frozen = ctx.freeze.is_frozen();
        let db = ctx.db.clone();
        let oz_type = ctx.oz_type;
        let value = ctx.value.clone();
        let summary_layer_id = layer_id.clone();
        let summary_reports = reports.clone();
        let summary_tx = tx.clone();
        tokio::spawn(async move {
            if let Some((text, fallback)) = summary::run(
                &db,
                &summary_layer_id,
                oz_type,
                &value,
                kind,
                new_children,
                gated_verdict,
                &summary_reports,
                frozen,
            )
            .await
            {
                let _ = summary_tx
                    .send(LayerEvent::Summary {
                        layer_id: summary_layer_id,
                        text,
                        fallback,
                    })
                    .await;
            }
        });
    }

    LayerResult {
        layer_id,
        kind,
        new_children,
        reports,
        lookups,
        cost_cents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outcome::{SettleKind, ToolOutcome, ToolReport};

    fn report(tool_id: &str, outcome: ToolOutcome) -> ToolReport {
        ToolReport::new(tool_id, tool_id, outcome, 12, false, "queried the thing")
    }

    #[test]
    fn every_frame_can_name_its_layer() {
        let frames = vec![
            LayerEvent::LayerStart {
                layer_id: "l1".into(),
                investigation_id: "inv".into(),
                parent_node_id: "n1".into(),
                firing: 2,
                max_possible: 4,
                gated: 1,
            },
            LayerEvent::ToolStart {
                layer_id: "l1".into(),
                tool_id: "wmn-probe".into(),
                label: "WhatsMyName".into(),
                gated: false,
            },
            LayerEvent::ToolDone {
                layer_id: "l1".into(),
                report: report("wmn-probe", ToolOutcome::OkWithResults { count: 14 }),
            },
            LayerEvent::AlreadyInTree {
                layer_id: "l1".into(),
                existing_node_id: "n0".into(),
                annotation: "already in tree · L1".into(),
                found_again_by: Corroboration {
                    tool_id: "gravatar-profile".into(),
                    method: "queried Gravatar".into(),
                    parent_node_id: "n1".into(),
                    layer_id: "l1".into(),
                    found_at: Utc::now(),
                    gated: false,
                },
                paths: Some(2),
            },
            LayerEvent::Summary {
                layer_id: "l1".into(),
                text: "x".into(),
                fallback: true,
            },
        ];
        for frame in &frames {
            assert_eq!(frame.layer_id(), Some("l1"), "unroutable frame: {frame:?}");
        }
    }

    #[test]
    fn a_stream_level_error_may_have_no_layer() {
        let e = LayerEvent::Error {
            layer_id: None,
            message: "boom".into(),
        };
        assert_eq!(e.layer_id(), None);
        assert!(!e.is_terminal());
    }

    #[test]
    fn summary_is_not_terminal_so_it_can_arrive_late() {
        let s = LayerEvent::Summary {
            layer_id: "l1".into(),
            text: "x".into(),
            fallback: false,
        };
        assert!(!s.is_terminal(), "a late summary must not close its layer");
    }

    #[test]
    fn terminal_for_never_turns_a_failure_into_an_empty() {
        let reports = vec![report(
            "a",
            ToolOutcome::HttpError {
                status: 500,
                message: None,
            },
        )];
        let failed = LayerEvent::terminal_for(SettleKind::Failed, "l1", 0, reports.clone());
        assert!(matches!(failed, LayerEvent::LayerFailed { .. }));
        assert!(failed.is_terminal());

        // The distinction the whole feature rests on, asserted on the wire and not only in
        // settle_kind: zero children plus a failure is Failed, zero children with clean
        // tools is Empty, and the two serialise to different frames.
        let empty = LayerEvent::terminal_for(SettleKind::Empty, "l1", 0, vec![]);
        assert!(matches!(empty, LayerEvent::LayerEmpty { .. }));

        let a = serde_json::to_value(&failed).unwrap();
        let b = serde_json::to_value(&empty).unwrap();
        assert_ne!(a["type"], b["type"]);
    }

    #[test]
    fn frames_serialise_camel_case_with_a_type_tag() {
        let start = LayerEvent::LayerStart {
            layer_id: "l1".into(),
            investigation_id: "inv".into(),
            parent_node_id: "n1".into(),
            firing: 2,
            max_possible: 4,
            gated: 1,
        };
        let json = serde_json::to_value(&start).unwrap();
        assert_eq!(json["type"], "layerStart");
        assert_eq!(json["layerId"], "l1");
        assert_eq!(json["maxPossible"], 4);
    }

    #[test]
    fn frames_round_trip() {
        let frame = LayerEvent::ToolDone {
            layer_id: "l1".into(),
            report: report("github-user", ToolOutcome::OkEmpty),
        };
        let s = serde_json::to_string(&frame).unwrap();
        let back: LayerEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(frame, back);
    }

    // ─── Engine ────────────────────────────────────────────────────────────
    //
    // These drive the real `fire_layer` against a real in-memory database, and reach no
    // network — by construction, not by luck. Every case below fires either an empty plan, a
    // plan naming a deliberately unknown tool id, or a pre-cancelled signal, so no dispatcher
    // ever opens a socket. Keep it that way: the catalogue's real tools point at live third
    // parties (WhatsMyName alone sweeps ~730 sites), and a test suite that quietly reached
    // them would be slow, flaky, and rude to those services.
    //
    // What they assert is the behaviour the whole feature's honesty rests on: a layer that
    // ran nothing must settle `Failed`, never `Empty`.

    use crate::layer_plan::LayerPlan;
    use crate::types::{Investigation, OzPayload, OzType};

    fn seed_investigation(db: &ozint_db::Db, oz_type: OzType, value: &str) -> (String, String) {
        let inv_id = "inv-test".to_string();
        let root_id = "node-root".to_string();
        let now = Utc::now();

        store::create_investigation(
            db,
            &Investigation {
                id: inv_id.clone(),
                seed_input: value.to_string(),
                seed_type: oz_type,
                root_node_id: root_id.clone(),
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
            db,
            &OzNode {
                id: root_id.clone(),
                investigation_id: inv_id.clone(),
                parent_id: None,
                layer_id: None,
                ordinal: 0,
                depth: 0,
                oz_type,
                value: value.to_string(),
                display: value.to_string(),
                dedup_key: crate::normalize::dedup_key(oz_type, value),
                payload: OzPayload::empty_for(oz_type),
                preview_signal: None,
                full_signal: None,
                sections: Vec::new(),
                gated: false,
                status: NodeStatus::Idle,
                provenance: Provenance::new("seed", "typed by the analyst"),
                already_in_tree: None,
                corroborations: Vec::new(),
                edited_value: None,
                created_at: now,
            },
        )
        .unwrap();

        (inv_id, root_id)
    }

    /// `show_summary: false` here is deliberate, not an oversight: every test in this module
    /// predates the LLM summary pass and asserts exact things about the frames `fire_layer`
    /// emits and about `_rx`-ignoring call sites that never drain to completion. Defaulting this
    /// helper to `true` would spawn a background summary task under every one of them — mostly
    /// harmless (a missing `OZINT_LLM_API_KEY` fails fast, no network reached) but still a
    /// non-deterministic extra write racing a test's own assertions in the tests that never
    /// drain their receiver. The summary-specific tests below build their own context instead.
    fn context(db: &ozint_db::Db, inv_id: &str, root_id: &str, value: &str) -> LayerContext {
        LayerContext {
            db: db.clone(),
            investigation_id: inv_id.to_string(),
            parent_node_id: root_id.to_string(),
            parent_depth: 0,
            oz_type: OzType::Username,
            value: value.to_string(),
            visited: Arc::new(Mutex::new(VisitedSet::new())),
            health: Arc::new(ToolHealth::new()),
            // Not the thing under test here, and a scheduler with no registered window admits
            // instantly anyway — see `LayerContext::scheduler`. The scheduler's own admit/
            // refuse state machine is exercised deterministically in `scheduler.rs`, and its
            // effect on a layer's reports is exercised below.
            scheduler: None,
            // Same reasoning: `None` and a cache with a zero TTL are indistinguishable, and
            // these tests dispatch tools that make no network call. `cache.rs` owns the TTL /
            // single-flight / bypass behaviour's own tests.
            cache: None,
            cancel: None,
            show_summary: false,
            freeze: Arc::new(FreezeState::in_memory()),
        }
    }

    async fn drain(rx: &mut mpsc::Receiver<LayerEvent>) -> Vec<LayerEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        // Anything still queued after the sender dropped.
        while let Some(ev) = rx.recv().await {
            out.push(ev);
        }
        out
    }

    // ─── The sibling hand-off ──────────────────────────────────────────────

    #[tokio::test]
    async fn a_tool_whose_sibling_did_not_deliver_is_refused_before_it_costs_anything() {
        // `ip-peeringdb` alone, with no wave before it to publish an ASN. It must be refused
        // without a request, and it must be refused *distinguishably* — the same layer run
        // against a network PeeringDB genuinely holds nothing on would report `OkEmpty`, and
        // those are opposite findings.
        //
        // Hermetic by construction: the refusal happens before `dispatch`, so no socket opens.
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Ip, "8.8.8.8");
        let mut ctx = context(&db, &inv, &root, "8.8.8.8");
        ctx.oz_type = OzType::Ip;

        let plan = LayerPlan::new(vec![crate::layer_plan::LayerPhase::new(
            "asn-derived",
            ["ip-peeringdb"],
        )]);
        let (tx, _rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;

        let report = result
            .reports
            .iter()
            .find(|r| r.tool_id == "ip-peeringdb")
            .expect("the refused tool must still appear in the layer's account of itself");
        match &report.outcome {
            ToolOutcome::SkippedMissingInput { input, reason } => {
                assert_eq!(input, crate::layer_plan::INPUT_ASN);
                assert!(reason.contains("published"), "unexpected reason: {reason}");
            }
            other => panic!("expected SkippedMissingInput, got {other:?}"),
        }
        assert_eq!(
            result.lookups, 0,
            "a tool that was never dispatched must not bill a lookup"
        );
        assert_eq!(
            result.kind,
            SettleKind::Failed,
            "a layer where the only tool was refused taught us nothing — never Empty"
        );
    }

    #[test]
    fn a_disputed_input_is_refused_by_naming_the_disagreement() {
        // The other half of the refusal, and the one that matters most: two tools disagreeing
        // about an ASN must not be resolved by whichever ran last. The report has to say so.
        let tool = registry::find("ip-peeringdb").expect("ip-peeringdb is catalogued");
        let mut acc = PhaseAcc::default();
        acc.set_value(crate::layer_plan::INPUT_ASN, "AS15169", "ip-ipinfo");
        acc.set_value(crate::layer_plan::INPUT_ASN, "AS36040", "ip-other");

        let handoff = acc.handoff();
        assert!(
            handoff.is_empty(),
            "a disputed key must not reach a tool at all"
        );

        match missing_input_for(tool, &handoff, &acc) {
            Some(ToolOutcome::SkippedMissingInput { reason, .. }) => {
                assert!(reason.contains("disputed"), "unexpected reason: {reason}");
                assert!(reason.contains("ip-ipinfo") && reason.contains("AS15169"));
                assert!(reason.contains("ip-other") && reason.contains("AS36040"));
            }
            other => panic!("expected a disputed SkippedMissingInput, got {other:?}"),
        }
    }

    #[test]
    fn a_readable_input_lets_the_tool_through() {
        let tool = registry::find("ip-peeringdb").expect("ip-peeringdb is catalogued");
        let mut acc = PhaseAcc::default();
        acc.set_value(crate::layer_plan::INPUT_ASN, "AS15169", "ip-ipinfo");
        assert!(missing_input_for(tool, &acc.handoff(), &acc).is_none());
    }

    #[test]
    fn a_tool_that_needs_nothing_is_never_refused() {
        let tool = registry::find("ip-ipinfo").expect("ip-ipinfo is catalogued");
        assert!(
            missing_input_for(
                tool,
                &crate::layer_plan::Handoff::new(),
                &PhaseAcc::default()
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn an_empty_plan_settles_failed_not_empty() {
        // The single most important assertion in this crate. A layer with nothing to run
        // learned nothing, and must never render as the "0 NEW ENTITIES" block, which
        // claims we looked and there was genuinely nothing there.
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let ctx = context(&db, &inv, &root, "mtrebosc");

        let plan = LayerPlan::new(vec![]);
        let (tx, mut rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;
        let events = drain(&mut rx).await;

        assert_eq!(result.kind, SettleKind::Failed);
        assert_eq!(result.new_children, 0);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, LayerEvent::LayerFailed { .. })),
            "expected a LayerFailed frame, got {events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, LayerEvent::LayerEmpty { .. })),
            "a layer that ran nothing must never emit LayerEmpty"
        );
    }

    #[tokio::test]
    async fn the_layer_row_and_node_status_persist_the_same_verdict() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let ctx = context(&db, &inv, &root, "mtrebosc");

        let plan = LayerPlan::new(vec![]);
        let (tx, _rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;

        // A reopened investigation must show what the live stream showed — this is what
        // makes history resumable rather than a lossy replay.
        let layer = store::get_layer(&db, &result.layer_id)
            .unwrap()
            .expect("layer row");
        assert_eq!(layer.status, "failed");
        let node = store::get_node(&db, &root).unwrap().expect("root node");
        assert_eq!(node.status, NodeStatus::Failed);
    }

    // ── What a layer learned about the node it fired on must outlive the stream ────────

    #[tokio::test]
    async fn the_parent_payload_and_chip_survive_a_reload() {
        let db = ozint_db::open_memory().unwrap();
        let (_inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");

        let patch = serde_json::json!({ "sitesChecked": 312, "sitesConfirmed": 14 });
        let chip = persist_parent_payload(&db, &root, &patch, false, &["wmn-probe"], &[]);

        let stored = store::get_node(&db, &root).unwrap().expect("root node");
        match &stored.payload {
            OzPayload::Username(p) => {
                assert_eq!(
                    p.sites_checked, 312,
                    "the node must remember what its layer measured"
                );
                assert_eq!(p.sites_confirmed, 14);
            }
            other => panic!("expected a username payload, got {other:?}"),
        }
        assert_eq!(
            stored.preview_signal, chip,
            "the stored chip must be the one the stream showed"
        );
        assert!(
            stored
                .provenance
                .tool_chain
                .iter()
                .any(|t| t == "wmn-probe"),
            "a tool that patched this payload belongs in the chain node-refresh re-invokes"
        );
    }

    #[tokio::test]
    async fn a_second_layer_merges_into_the_stored_payload_instead_of_replacing_it() {
        let db = ozint_db::open_memory().unwrap();
        let (_inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");

        persist_parent_payload(
            &db,
            &root,
            &serde_json::json!({ "sitesChecked": 312 }),
            false,
            &["wmn-probe"],
            &[],
        );
        persist_parent_payload(
            &db,
            &root,
            &serde_json::json!({ "sitesConfirmed": 14 }),
            false,
            &["github-user"],
            &[],
        );

        let stored = store::get_node(&db, &root).unwrap().expect("root node");
        match &stored.payload {
            OzPayload::Username(p) => {
                assert_eq!(
                    p.sites_checked, 312,
                    "an earlier layer's finding must not be erased"
                );
                assert_eq!(p.sites_confirmed, 14);
            }
            other => panic!("expected a username payload, got {other:?}"),
        }
        assert_eq!(
            stored
                .provenance
                .tool_chain
                .iter()
                .filter(|t| *t == "wmn-probe")
                .count(),
            1
        );
        assert!(
            stored
                .provenance
                .tool_chain
                .iter()
                .any(|t| t == "github-user")
        );
    }

    #[tokio::test]
    async fn a_gated_contribution_marks_the_stored_node_not_just_the_frame() {
        let db = ozint_db::open_memory().unwrap();
        let (_inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");

        persist_parent_payload(
            &db,
            &root,
            &serde_json::json!({ "sitesChecked": 1 }),
            true,
            &[],
            &[],
        );

        let stored = store::get_node(&db, &root).unwrap().expect("root node");
        assert!(
            stored.gated,
            "gating must survive a reload — it never gets cleared downstream"
        );
        assert!(stored.provenance.gated);
    }

    // ── Detail sections: rows used to be discarded between the tool and the node ──────

    fn tool(id: &'static str, label: &'static str) -> ToolDef {
        let mut def = *registry::find("github-user").expect("a catalogued tool to clone");
        def.id = id;
        def.label = label;
        def
    }

    fn row(label: &str, value: &str) -> OzRow {
        OzRow {
            label: label.to_string(),
            value: value.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn a_tool_with_no_rows_contributes_no_section() {
        // An empty section would render as a titled block with nothing in it — a tool
        // claiming it had something to say.
        assert!(section_from_rows(&tool("t", "T"), Vec::new()).is_none());
    }

    #[test]
    fn a_section_carries_its_tool_identity_down_to_each_row() {
        let section =
            section_from_rows(&tool("github-user", "GitHub"), vec![row("Bio", "hi")]).unwrap();
        assert_eq!(
            section.id, "github-user",
            "the id must be the tool's, so a re-fire replaces"
        );
        assert_eq!(section.label, "GitHub");
        assert_eq!(
            section.rows[0].source_tool_id.as_deref(),
            Some("github-user")
        );
    }

    #[test]
    fn a_row_that_already_names_its_tool_keeps_that_name() {
        // A fan-out tool may attribute a row to the specific site it came from; the enclosing
        // section must not overwrite the finer attribution with its own id.
        let mut r = row("Bio", "hi");
        r.source_tool_id = Some("inner-probe".to_string());
        let section = section_from_rows(&tool("github-user", "GitHub"), vec![r]).unwrap();
        assert_eq!(
            section.rows[0].source_tool_id.as_deref(),
            Some("inner-probe")
        );
    }

    #[test]
    fn re_running_a_tool_replaces_its_section_instead_of_appending_a_second_one() {
        let mut existing = vec![
            section_from_rows(&tool("a", "A"), vec![row("Bio", "old")]).unwrap(),
            section_from_rows(&tool("b", "B"), vec![row("Name", "kept")]).unwrap(),
        ];
        let incoming = vec![section_from_rows(&tool("a", "A"), vec![row("Bio", "new")]).unwrap()];

        merge_sections(&mut existing, &incoming);

        assert_eq!(
            existing.len(),
            2,
            "a re-run must not grow a second block for the same tool"
        );
        assert_eq!(existing[0].rows[0].value, "new");
        assert_eq!(
            existing[1].rows[0].value, "kept",
            "another tool's block is untouched"
        );
    }

    #[tokio::test]
    async fn a_tools_rows_reach_the_stored_node_and_not_only_the_stream() {
        // The regression this pins: `fire_layer` destructured `ToolYield`'s `rows` away with
        // `..`, so every row every tool built was dropped. Nothing failed — `OzNode::sections`
        // starts empty and stays valid — the detail panel was just permanently blank and
        // `relations::infer` mined an always-empty vector for evidence.
        let db = ozint_db::open_memory().unwrap();
        let (_inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");

        let section = section_from_rows(&tool("github-user", "GitHub"), vec![row("Bio", "hi")]);
        persist_parent_payload(
            &db,
            &root,
            &serde_json::json!({ "sitesChecked": 1 }),
            false,
            &["github-user"],
            &section.into_iter().collect::<Vec<_>>(),
        );

        let stored = store::get_node(&db, &root).unwrap().expect("root node");
        assert_eq!(
            stored.sections.len(),
            1,
            "the section must survive the round trip"
        );
        assert_eq!(stored.sections[0].id, "github-user");
        assert_eq!(stored.sections[0].rows[0].value, "hi");
    }

    #[tokio::test]
    async fn a_layer_always_opens_with_exactly_one_start_frame() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let ctx = context(&db, &inv, &root, "mtrebosc");

        let plan = LayerPlan::new(vec![]);
        let (tx, mut rx) = mpsc::channel(64);
        fire_layer(&ctx, &plan, tx).await;
        let events = drain(&mut rx).await;

        let starts = events
            .iter()
            .filter(|e| matches!(e, LayerEvent::LayerStart { .. }))
            .count();
        assert_eq!(starts, 1);
        // The stream now opens by restating the node it fires on; `LayerStart` is second.
        assert!(matches!(events.first(), Some(LayerEvent::Node { .. })));
        assert!(matches!(events.get(1), Some(LayerEvent::LayerStart { .. })));

        let terminals = events.iter().filter(|e| e.is_terminal()).count();
        assert_eq!(terminals, 1, "exactly one terminal frame per layer");
        assert!(events.last().is_some_and(|e| e.is_terminal()));
    }

    // ── The stream restates the tree it is firing into ───────────────────────────────
    //
    // The gap this closes was found by running the cockpit, not by a test: a seed's root node
    // is created by the route *before* the SSE stream opens, so a client that only reduces
    // frames had never been told the node existed. It rendered an empty canvas for the whole
    // run of a layer it could watch firing. Hydrating from
    // `GET /api/ozint/investigations/{id}` covers that one case and no other — in particular
    // it cannot help a re-continue, where the fired node *is* known and it is the subtree
    // underneath that goes missing.

    fn insert_child(
        db: &ozint_db::Db,
        inv_id: &str,
        id: &str,
        parent_id: &str,
        ordinal: i64,
        depth: i64,
        value: &str,
    ) {
        store::insert_node(
            db,
            &OzNode {
                id: id.to_string(),
                investigation_id: inv_id.to_string(),
                parent_id: Some(parent_id.to_string()),
                layer_id: Some("layer-old".to_string()),
                ordinal,
                depth,
                oz_type: OzType::Username,
                value: value.to_string(),
                display: value.to_string(),
                dedup_key: crate::normalize::dedup_key(OzType::Username, value),
                payload: OzPayload::empty_for(OzType::Username),
                preview_signal: None,
                full_signal: None,
                sections: Vec::new(),
                gated: false,
                status: NodeStatus::Idle,
                provenance: Provenance::new("github-user", "found earlier"),
                already_in_tree: None,
                corroborations: Vec::new(),
                edited_value: None,
                created_at: Utc::now(),
            },
        )
        .unwrap();
    }

    #[tokio::test]
    async fn the_stream_opens_by_restating_the_node_it_fires_on() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let ctx = context(&db, &inv, &root, "mtrebosc");

        let (tx, mut rx) = mpsc::channel(64);
        fire_layer(&ctx, &LayerPlan::new(vec![]), tx).await;
        let events = drain(&mut rx).await;

        let LayerEvent::Node { node, .. } = &events[0] else {
            panic!("the first frame must be the node being fired on: {events:?}")
        };
        assert_eq!(node.id, root);
        assert_eq!(node.value, "mtrebosc");
        // Before `LayerStart`, not after: a client marks the fired node *running* when the
        // layer opens, and can only do that for a node it already holds.
        assert!(
            matches!(events[1], LayerEvent::LayerStart { .. }),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn a_re_continue_replays_the_subtree_the_layer_is_about_to_re_enter() {
        // The failure mode without this: opening a layer on a node tells the client that
        // node's children are about to be re-established, so it drops what it holds under it.
        // But a re-continue does not re-emit them — they are in the rebuilt `VisitedSet`, so
        // they come back as `AlreadyInTree` frames pointing at ids the client just discarded,
        // and the analyst watches an expanded branch disappear with no error anywhere.
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        insert_child(&db, &inv, "child-b", &root, 1, 1, "second");
        insert_child(&db, &inv, "child-a", &root, 0, 1, "first");
        insert_child(&db, &inv, "grandchild", "child-a", 0, 2, "deeper");
        // A branch that is not under the fired node: this layer does not speak for it.
        insert_child(
            &db,
            &inv,
            "elsewhere",
            "child-b-not-in-tree",
            0,
            1,
            "unrelated",
        );

        let ctx = context(&db, &inv, &root, "mtrebosc");
        let (tx, mut rx) = mpsc::channel(64);
        fire_layer(&ctx, &LayerPlan::new(vec![]), tx).await;
        let events = drain(&mut rx).await;

        let ids: Vec<&str> = events
            .iter()
            .filter_map(|e| match e {
                LayerEvent::Node { node, .. } => Some(node.id.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            ids,
            vec![root.as_str(), "child-a", "child-b", "grandchild"],
            "the fired node, then its subtree breadth-first in ordinal order: {events:?}"
        );

        let start_at = events
            .iter()
            .position(|e| matches!(e, LayerEvent::LayerStart { .. }))
            .unwrap();
        let descendants_at = events
            .iter()
            .position(|e| matches!(e, LayerEvent::Node { node, .. } if node.id == "child-a"))
            .unwrap();
        assert!(
            descendants_at > start_at,
            "descendants must land after the layer opens, or the drop swallows them"
        );
    }

    #[test]
    fn splitting_a_tree_around_a_node_that_is_not_in_it_yields_nothing() {
        // Never normal — every caller fires on a node it just read or just wrote — so the
        // engine logs it. It must not panic or invent a root.
        assert!(split_subtree(Vec::new(), "node-root").is_none());
    }

    #[test]
    fn splitting_keeps_only_what_hangs_off_the_fired_node() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        insert_child(&db, &inv, "kept", &root, 0, 1, "kept");
        insert_child(
            &db,
            &inv,
            "sibling-branch",
            "some-other-node",
            0,
            1,
            "other",
        );

        let nodes = store::list_nodes(&db, &inv).unwrap();
        let (found_root, descendants) = split_subtree(nodes, &root).unwrap();
        assert_eq!(found_root.id, root);
        assert_eq!(
            descendants
                .iter()
                .map(|n| n.id.as_str())
                .collect::<Vec<_>>(),
            vec!["kept"]
        );
    }

    #[tokio::test]
    async fn a_plan_naming_an_unknown_tool_reports_it_instead_of_going_quiet() {
        // Registry/plan drift must be visible. A layer that silently drops half its tools
        // looks identical to a layer that genuinely found nothing.
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let ctx = context(&db, &inv, &root, "mtrebosc");

        let plan = LayerPlan::flat(["definitely-not-a-real-tool"]);
        let (tx, _rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;

        let report = result
            .reports
            .iter()
            .find(|r| r.tool_id == "definitely-not-a-real-tool")
            .expect("the missing tool must still be reported");
        assert!(matches!(report.outcome, ToolOutcome::ParseError { .. }));
    }

    #[tokio::test]
    async fn a_cancelled_layer_aborts_rather_than_settling() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let mut ctx = context(&db, &inv, &root, "mtrebosc");

        let (handle, signal) = crate::fetch::CancelHandle::new();
        handle.cancel();
        ctx.cancel = Some(signal);

        let plan = LayerPlan::flat(["wmn-probe"]);
        let (tx, mut rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;
        let events = drain(&mut rx).await;

        assert_eq!(result.kind, SettleKind::Aborted);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, LayerEvent::LayerAborted { .. }))
        );
        // An abort is retryable and must not be dressed up as a completed layer.
        assert!(!events.iter().any(|e| matches!(
            e,
            LayerEvent::LayerSettled { .. } | LayerEvent::LayerEmpty { .. }
        )));
        assert_eq!(
            result.lookups, 0,
            "a pre-cancelled layer must not bill a lookup"
        );
    }

    #[tokio::test]
    async fn a_killed_layer_accounts_for_every_tool_it_never_ran() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let mut ctx = context(&db, &inv, &root, "mtrebosc");

        let (handle, signal) = crate::fetch::CancelHandle::new();
        handle.cancel();
        ctx.cancel = Some(signal);

        // Three real tools in one phase, killed before any of them starts.
        let plan = LayerPlan::flat(["wmn-probe", "github-user", "hn-algolia"]);
        let (tx, mut rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;
        let _ = drain(&mut rx).await;

        assert_eq!(result.kind, SettleKind::Aborted);
        for tool_id in ["wmn-probe", "github-user", "hn-algolia"] {
            let report = result
                .reports
                .iter()
                .find(|r| r.tool_id == tool_id)
                .unwrap_or_else(|| panic!("a killed layer must still account for `{tool_id}`"));
            assert_eq!(
                report.outcome,
                ToolOutcome::Cancelled,
                "`{tool_id}` never ran because of the kill and must say so"
            );
            assert!(
                report.outcome.is_retryable(),
                "a cancelled tool is retryable by re-firing"
            );
        }
    }

    #[tokio::test]
    async fn a_later_phase_is_not_claimed_as_cancelled() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let mut ctx = context(&db, &inv, &root, "mtrebosc");

        let (handle, signal) = crate::fetch::CancelHandle::new();
        handle.cancel();
        ctx.cancel = Some(signal);

        // Phase B's `when` predicate was never evaluated — the layer died in phase A. Saying
        // "cancelled" about it would invent a capability the layer never admitted.
        let plan = LayerPlan::new(vec![
            crate::layer_plan::LayerPhase::new("A", ["wmn-probe"]),
            crate::layer_plan::LayerPhase::new("B", ["github-user"])
                .gated_on(crate::layer_plan::enough_confirmed_hits()),
        ]);
        let (tx, mut rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;
        let _ = drain(&mut rx).await;

        assert!(result.reports.iter().any(|r| r.tool_id == "wmn-probe"));
        assert!(
            !result.reports.iter().any(|r| r.tool_id == "github-user"),
            "a phase the plan never admitted must not be reported at all"
        );
    }

    #[tokio::test]
    async fn a_tool_that_never_ran_is_never_billed() {
        // The meter counts tool *invocations*. A tool the plan named but the registry could
        // not dispatch never left the ground, so billing it would overstate what the
        // analyst spent — and the cost display is one of the few numbers they are asked to
        // trust. (The complementary property, that WhatsMyName's ~730-site sweep bills ONE
        // lookup rather than 730, lives in that tool's own dispatcher: it returns a single
        // DispatchOutcome, and this loop increments once per dispatch. Asserting it here
        // would require reaching the network, which this repo's tests never do.)
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let ctx = context(&db, &inv, &root, "mtrebosc");

        let plan = LayerPlan::flat(["definitely-not-a-real-tool"]);
        let (tx, _rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;

        assert_eq!(result.lookups, 0);
        assert_eq!(result.cost_cents, 0);
        let stored = store::get_investigation(&db, &inv).unwrap().unwrap();
        assert_eq!(
            stored.lookups, 0,
            "the meter must agree with the layer result"
        );
    }

    #[test]
    fn merge_patch_is_shallow_and_last_writer_wins() {
        // Deep-merging two tools' views of one nested object would blend a genuine
        // multi-source conflict invisibly — this codebase refuses to auto-resolve those.
        let mut acc = serde_json::json!({"sitesChecked": 312, "nested": {"a": 1}});
        merge_patch(
            &mut acc,
            &serde_json::json!({"nested": {"b": 2}, "sitesConfirmed": 14}),
        );
        assert_eq!(acc["sitesConfirmed"], 14);
        assert_eq!(
            acc["nested"],
            serde_json::json!({"b": 2}),
            "shallow, not deep"
        );
        assert_eq!(acc["sitesChecked"], 312, "untouched keys survive");
    }

    #[test]
    fn a_non_object_patch_is_ignored_rather_than_clobbering() {
        let mut acc = serde_json::json!({"a": 1});
        merge_patch(&mut acc, &serde_json::Value::Null);
        assert_eq!(acc, serde_json::json!({"a": 1}));
    }

    // ── LLM summary: wiring only (case/fallback logic is `summary`'s own tests) ──

    #[tokio::test]
    async fn show_summary_true_eventually_emits_a_summary_frame() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let mut ctx = context(&db, &inv, &root, "mtrebosc");
        ctx.show_summary = true;

        let plan = LayerPlan::new(vec![]);
        let (tx, mut rx) = mpsc::channel(64);
        fire_layer(&ctx, &plan, tx).await;
        // `drain` awaits until every sender (including the spawned summary task's clone) is
        // dropped, so this only returns once the background task has actually finished.
        let events = drain(&mut rx).await;

        let summary = events
            .iter()
            .find(|e| matches!(e, LayerEvent::Summary { .. }));
        assert!(
            summary.is_some(),
            "show_summary: true must eventually produce a Summary frame: {events:?}"
        );
        if let Some(LayerEvent::Summary { fallback, text, .. }) = summary {
            assert!(
                *fallback,
                "no OZINT_LLM_API_KEY in this test env — must be the honest fallback"
            );
            assert!(!text.is_empty());
        }
    }

    #[tokio::test]
    async fn show_summary_false_never_emits_a_summary_frame_or_persists_one() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Username, "mtrebosc");
        let ctx = context(&db, &inv, &root, "mtrebosc"); // show_summary: false by default

        let plan = LayerPlan::new(vec![]);
        let (tx, mut rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;
        let events = drain(&mut rx).await;

        assert!(
            !events
                .iter()
                .any(|e| matches!(e, LayerEvent::Summary { .. })),
            "show_summary: false must skip the Summary frame entirely: {events:?}"
        );
        let layer = store::get_layer(&db, &result.layer_id).unwrap().unwrap();
        assert!(
            layer.summary.is_none(),
            "skipping must mean no LLM call was ever attempted, not just no frame"
        );
    }

    // ── a phase the cascade never opened must be reported, not vanish ─────────────────
    //
    // `LayerStart` tells the UI that `max_possible` counts every tool the plan could reach,
    // conditional phases included. Until `entity-cve` there was no plan with a conditional
    // phase, so `LayerPlan::skipped_from` had no caller and a held-back phase would simply
    // have gone missing — the analyst reading `4 / 5` with no fifth tool and no reason.

    fn never() -> crate::layer_plan::Predicate {
        crate::layer_plan::Predicate::when("never-in-this-test", |_| false)
    }

    #[tokio::test]
    async fn a_phase_held_back_at_the_end_reports_its_predicate_by_name() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Name, "John Doe");
        let ctx = LayerContext {
            oz_type: OzType::Name,
            ..context(&db, &inv, &root, "John Doe")
        };

        let plan = LayerPlan::new(vec![
            crate::layer_plan::LayerPhase::new("tiles", ["dir-tiles-person"]),
            crate::layer_plan::LayerPhase::new("deep", ["github-user"]).gated_on(never()),
        ]);
        let (tx, _rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;

        let held = result
            .reports
            .iter()
            .find(|r| r.tool_id == "github-user")
            .expect("the held-back tool must appear in the layer's account of itself");
        match &held.outcome {
            ToolOutcome::SkippedPhasePredicate { reason } => {
                assert!(
                    reason.contains("deep"),
                    "the reason must name the phase: {reason}"
                );
                assert!(
                    reason.contains("never-in-this-test"),
                    "the reason must name the predicate: {reason}"
                );
            }
            other => panic!("expected SkippedPhasePredicate, got {other:?}"),
        }
        // A skip is not a failure and must not move the verdict — the tile resolver ran fine.
        assert_eq!(result.kind, SettleKind::Empty);
    }

    #[tokio::test]
    async fn a_phase_jumped_over_in_the_middle_is_reported_too() {
        // The case the end-of-loop sweep alone cannot catch: `firing_now` skips straight past
        // a false predicate to reach a later phase, so by the time the loop ends the
        // jumped-over phase is already behind `phase_index` and invisible to `skipped_from`.
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Name, "John Doe");
        let ctx = LayerContext {
            oz_type: OzType::Name,
            ..context(&db, &inv, &root, "John Doe")
        };

        let plan = LayerPlan::new(vec![
            crate::layer_plan::LayerPhase::new("tiles", ["dir-tiles-person"]),
            crate::layer_plan::LayerPhase::new("middle", ["github-user"]).gated_on(never()),
            crate::layer_plan::LayerPhase::new("last", ["dir-tiles-entity"]),
        ]);
        let (tx, _rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;

        let held = result
            .reports
            .iter()
            .find(|r| r.tool_id == "github-user")
            .expect("a phase jumped over in the middle must still be reported");
        assert!(matches!(
            held.outcome,
            ToolOutcome::SkippedPhasePredicate { .. }
        ));
        assert_eq!(
            result.reports.len(),
            3,
            "every tool the plan named is accounted for exactly once: {:?}",
            result
                .reports
                .iter()
                .map(|r| &r.tool_id)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn a_cancelled_layer_does_not_claim_later_phases_failed_their_predicate() {
        // Their predicates were never evaluated. Reporting them as "the predicate was false"
        // would state a test result nobody computed — the same boundary `report_cancelled_rest`
        // draws for the tools it does not touch.
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Name, "John Doe");
        let (handle, signal) = crate::fetch::CancelHandle::new();
        handle.cancel();
        let ctx = LayerContext {
            oz_type: OzType::Name,
            cancel: Some(signal),
            ..context(&db, &inv, &root, "John Doe")
        };

        let plan = LayerPlan::new(vec![
            crate::layer_plan::LayerPhase::new("tiles", ["dir-tiles-person"]),
            crate::layer_plan::LayerPhase::new("deep", ["github-user"]).gated_on(never()),
        ]);
        let (tx, _rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;

        assert_eq!(result.kind, SettleKind::Aborted);
        assert!(
            !result
                .reports
                .iter()
                .any(|r| matches!(r.outcome, ToolOutcome::SkippedPhasePredicate { .. })),
            "a cancelled layer must not report a predicate verdict it never computed"
        );
    }

    // ── the scheduler, which until now had no caller at all ───────────────────────────
    //
    // The source scheduler shipped with this crate's first wave and nothing ever called it.
    // This module's own doc claimed it "admits the rest through the scheduler's quotas", which
    // was not happening, every `rate_key` in the registry was decorative, and
    // `ToolOutcome::RateLimitedDropped` was an unreachable variant of the eleven.

    #[tokio::test(start_paused = true)]
    async fn an_exhausted_quota_drops_the_tool_and_says_so() {
        // `start_paused` matters more than it looks. `SCHEDULER_MAX_WAIT` is 45 real seconds,
        // and a tool facing a window that can never open waits out every one of them before
        // being dropped — which is correct behaviour and an intolerable unit test. Paused,
        // tokio auto-advances its timer whenever the runtime goes idle, so the *decision* is
        // exercised at full speed while the wall clock `try_reserve_at` reads stays put.
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Name, "John Doe");

        // A quota of zero per hour: the window can never open, so the tool is dropped rather
        // than waited on. `dir-tiles-person` makes no network call, so this test asserts the
        // *admission* decision and nothing else.
        let scheduler = crate::scheduler::Scheduler::new(db.clone());
        scheduler.register("directory-none", &[crate::scheduler::RateLimit::PerHour(0)]);

        let ctx = LayerContext {
            oz_type: OzType::Name,
            scheduler: Some(Arc::new(scheduler)),
            ..context(&db, &inv, &root, "John Doe")
        };
        let plan = crate::plans::plan_for(OzType::Name).expect("NAM plan");
        let (tx, mut rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;
        let events = drain(&mut rx).await;

        assert_eq!(
            result
                .reports
                .iter()
                .map(|r| r.outcome.clone())
                .collect::<Vec<_>>(),
            vec![ToolOutcome::RateLimitedDropped]
        );
        // Not dispatched, so the in-flight count must not move — same handling as a
        // registry-level skip. A `ToolStart` with no matching `ToolDone` would leak the UI's
        // spinner forever.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, LayerEvent::ToolStart { .. })),
            "a dropped tool must not open an in-flight slot: {events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, LayerEvent::ToolDone { .. }))
        );
        // Every tool refused before running is `Failed`, never the `Empty` that claims we
        // looked and found nothing.
        assert_eq!(result.kind, SettleKind::Failed);
        assert_eq!(result.lookups, 0, "a dropped tool is not billed");
    }

    #[tokio::test]
    async fn a_registered_quota_with_room_admits_normally() {
        // The other half: the wiring must not break the ordinary path. Without this, a
        // scheduler that refused everything would still pass the test above.
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Name, "John Doe");

        let scheduler = crate::scheduler::Scheduler::new(db.clone());
        scheduler.register(
            "directory-none",
            &[crate::scheduler::RateLimit::PerHour(10)],
        );

        let ctx = LayerContext {
            oz_type: OzType::Name,
            scheduler: Some(Arc::new(scheduler)),
            ..context(&db, &inv, &root, "John Doe")
        };
        let plan = crate::plans::plan_for(OzType::Name).expect("NAM plan");
        let (tx, _rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;

        assert_eq!(
            result.kind,
            SettleKind::Empty,
            "the tile resolver still ran"
        );
        assert_eq!(result.lookups, 1);
    }

    #[tokio::test]
    async fn an_unregistered_rate_key_admits_instead_of_blocking_forever() {
        // The property that makes `registry::rate_limits_for` safe to leave empty for a source
        // whose quota we cannot cite: no registered window means admit, not deny. If this
        // inverted, every keyless source in the catalogue would stop firing at once.
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Name, "John Doe");

        let ctx = LayerContext {
            oz_type: OzType::Name,
            // Deliberately registers nothing at all.
            scheduler: Some(Arc::new(crate::scheduler::Scheduler::new(db.clone()))),
            ..context(&db, &inv, &root, "John Doe")
        };
        let plan = crate::plans::plan_for(OzType::Name).expect("NAM plan");
        let (tx, _rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;

        assert_eq!(result.kind, SettleKind::Empty);
        assert_eq!(result.lookups, 1);
    }

    // ── entity-directory, end to end through the real engine ──────────────────────────
    //
    // `plans::plan_for(Name)` returning `None` used to block three separate things at once:
    // a spawned `NAM` root could not be fired at all, `summary`'s `DirectoryOnlyDeadEnd` case
    // was unreachable from `fire_layer`, and `refresh`'s tile-liveness sweep had no tiles to
    // probe. These two tests run the real plan through the real engine against a real store so
    // that "unblocked" is demonstrated rather than asserted from the unit tests of each piece.

    #[tokio::test]
    async fn a_name_layer_persists_its_tiles_onto_the_node_it_fired_on() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Name, "John Doe");
        let ctx = LayerContext {
            oz_type: OzType::Name,
            ..context(&db, &inv, &root, "John Doe")
        };

        let plan = crate::plans::plan_for(OzType::Name).expect("NAM has an orchestrator");
        let (tx, mut rx) = mpsc::channel(64);
        let result = fire_layer(&ctx, &plan, tx).await;
        let events = drain(&mut rx).await;

        // Zero children, by design — a directory layer creates no entities. That is exactly
        // `Empty`, and `summary::classify_case` is what turns it into an honest sentence.
        assert_eq!(result.new_children, 0);
        assert_eq!(result.kind, SettleKind::Empty);
        assert_eq!(
            result.lookups, 1,
            "one operation the analyst asked for = one lookup"
        );
        assert_eq!(result.cost_cents, 0);
        assert_eq!(
            crate::summary::classify_case(OzType::Name, result.kind, false, false),
            crate::summary::SummaryCase::DirectoryOnlyDeadEnd,
            "the case this unit makes reachable"
        );

        // And the tiles are on the *stored* node, not merely on the wire — this is what
        // resuming a reopened investigation re-renders from and what refresh probes.
        let node = store::get_node(&db, &root).unwrap().expect("root node");
        assert_eq!(node.status, NodeStatus::Empty);
        match &node.payload {
            crate::types::OzPayload::Name(p) => {
                assert_eq!(p.tiles.len(), 7);
                assert!(
                    p.tiles.iter().all(|t| t.live.is_none()),
                    "resolution claims no liveness"
                );
            }
            other => panic!("the layer changed the node's payload type: {other:?}"),
        }
        assert!(
            node.preview_signal.is_some(),
            "a resolved tile set is a verdict worth showing"
        );
        assert!(
            node.provenance
                .tool_chain
                .contains(&"dir-tiles-person".to_string()),
            "the resolver must join the chain refresh re-invokes, got {:?}",
            node.provenance.tool_chain
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, LayerEvent::ParentPayload { .. })),
            "the tiles must reach the stream as a parent patch, never as children: {events:?}"
        );
        // The opening restatement of the node being fired on is not a child; nothing else
        // may be a `Node` frame here.
        let node_frames: Vec<&str> = events
            .iter()
            .filter_map(|e| match e {
                LayerEvent::Node { node, .. } => Some(node.id.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            node_frames,
            vec![root.as_str()],
            "the tiles must not become children"
        );
    }

    // ── The parent card enriches live, mid-layer ─────────────────────────
    //
    // The engine's model is that the node you continued gets richer as tools return, not that
    // it is created and then finished. Until this test the layer accumulated every patch and
    // fired one `ParentPayload` after the whole tool loop, so the card sat empty for the length
    // of the layer and then snapped into shape. Both properties are asserted, because the weak
    // half passes on the old code too: one frame *per contributing tool*, and each frame
    // carrying **that tool's own patch**, never the layer's running total.
    #[tokio::test]
    async fn the_parent_node_is_enriched_once_per_tool_not_once_per_layer() {
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Name, "John Doe");
        let ctx = LayerContext {
            oz_type: OzType::Name,
            ..context(&db, &inv, &root, "John Doe")
        };

        // Two phases, one keyless offline resolver each. Not a plan that ships — `plans.rs`
        // deliberately runs *one* directory tool because both write the same `tiles` key and
        // the shallow merge would clobber. That clobbering is the point here: it is precisely
        // the case where "one frame per tool" and "one frame per layer" differ observably.
        let plan = crate::layer_plan::LayerPlan::new(vec![
            crate::layer_plan::LayerPhase::new("a", ["dir-tiles-person"]),
            crate::layer_plan::LayerPhase::new("b", ["dir-tiles-entity"]),
        ]);
        let (tx, mut rx) = mpsc::channel(64);
        fire_layer(&ctx, &plan, tx).await;
        let events = drain(&mut rx).await;

        let patches: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e, LayerEvent::ParentPayload { .. }))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            patches.len(),
            2,
            "one frame per contributing tool, not one for the layer: {events:?}"
        );

        // Live means *interleaved*: the first frame lands before the second tool has even
        // started. Under the old accumulate-then-emit both frames (there was only one) sat
        // after every `ToolDone`, so this is the assertion that actually fails on it.
        let second_tool_start = events
            .iter()
            .position(|e| matches!(e, LayerEvent::ToolStart { tool_id, .. } if tool_id == "dir-tiles-entity"))
            .expect("the second tool must start");
        assert!(
            patches[0] < second_tool_start,
            "the card must enrich while the layer still runs: {events:?}"
        );

        // And each frame carries one tool's own tiles rather than an accumulation — a client
        // applies them in arrival order and lands where the stored node already is.
        // 7 person tiles then 2 company dorks — each resolver's own set, and never 9, which is
        // what an accumulated patch would have to carry.
        for (idx, expected) in patches.iter().zip([7, 2]) {
            let LayerEvent::ParentPayload { patch, .. } = &events[*idx] else {
                unreachable!()
            };
            let tiles = patch["tiles"]
                .as_array()
                .expect("a directory patch carries tiles");
            assert_eq!(
                tiles.len(),
                expected,
                "frame at {idx} is not one tool's own set: {patch}"
            );
        }
    }

    #[tokio::test]
    async fn a_directory_layer_never_offers_a_person_a_company_s_tiles_or_the_reverse() {
        // The two plans are separate tools precisely so a `DIR` node (a company, per
        // `classify.rs`) is not sent to five people-search aggregators.
        let db = ozint_db::open_memory().unwrap();
        let (inv, root) = seed_investigation(&db, OzType::Directory, "Acme Corporation");
        let ctx = LayerContext {
            oz_type: OzType::Directory,
            ..context(&db, &inv, &root, "Acme Corporation")
        };

        let plan = crate::plans::plan_for(OzType::Directory).expect("DIR has an orchestrator");
        let (tx, _rx) = mpsc::channel(64);
        fire_layer(&ctx, &plan, tx).await;

        let node = store::get_node(&db, &root).unwrap().expect("root node");
        match &node.payload {
            crate::types::OzPayload::Directory(p) => {
                assert_eq!(p.tiles.len(), 2, "dork builders only");
                assert!(p.tiles.iter().all(|t| t.tool_id.contains("dork")));
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn settle_status_and_node_status_agree_on_every_kind() {
        // These two mappings are written separately and must not drift: the persisted layer
        // string and the persisted node status have to describe the same settle.
        for kind in [
            SettleKind::Settled,
            SettleKind::Empty,
            SettleKind::Degraded,
            SettleKind::Failed,
            SettleKind::Aborted,
        ] {
            let s = settle_status_str(kind);
            let n = node_status_for(kind);
            let n_str = serde_json::to_value(n).unwrap();
            assert_eq!(
                n_str,
                serde_json::Value::String(s.to_string()),
                "drift on {kind:?}"
            );
        }
    }
}
