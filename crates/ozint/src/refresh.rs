//! "Re-run this lookup", per node, distinct from Continue.
//!
//! Continue (`fire_layer`) asks *what else can this value lead to* and grows the tree.
//! Refresh asks *is what we already recorded about this node still true* and touches nothing
//! but that node. This module's rules:
//!
//! - It re-invokes **exactly `provenance.tool_chain`** — the tools that actually patched this
//!   node's payload — not the type's layer plan. A node whose chain is empty or names nothing
//!   the registry still has is a [`RefreshError::NothingToReplay`], never a quiet "unchanged".
//! - **Unchanged → `retrieved_at` only.** Changed → payload + chip updated, and the previous
//!   observation is pushed into `provenance.prior_observations`. That is deliberately *not*
//!   `RecordStatus::Corrected`, which is reserved for analyst edits.
//! - **It never touches children.** Any `ChildSeed` a replayed tool returns is counted into
//!   [`RefreshResult::children_ignored`] and dropped — counted rather than silently discarded,
//!   so "the source now reports 3 more accounts" is visible instead of invisible.
//! - Available on **every** node type, including directory-only ones (`DIR`/`NAM`), where it
//!   degrades to a per-tile URL-liveness probe.
//!
//! ## Judgment calls this module makes
//!
//! **Diff granularity:** arrays are compared as *multisets*,
//! not as sequences. WhatsMyName's ~730 probes run concurrently and their hit list comes back
//! in a different order essentially every run; an order-sensitive diff would therefore record
//! a "change" on every single refresh, filling `prior_observations` with noise and making the
//! one signal this feature exists to give — *this actually moved* — worthless. Reordering is
//! not a finding; a different set of members is.
//!
//! **A cancelled refresh applies nothing.** A half-replayed chain cannot be diffed honestly:
//! merging the patch from the two tools that answered before the kill would record the third
//! tool's *absence* as a change in the world. So an aborted refresh persists nothing at all,
//! not even `retrieved_at`, and says so.
//!
//! **Node status is left alone.** `NodeStatus` describes the layer fired *from* this node
//! (did continuing produce children?). A refresh fires no layer, so writing `Settled`/`Empty`
//! here would claim something about children that no layer went looking for.
//!
//! **A rejected or corrected node still refreshes**, and its `record_status` survives intact.
//! Refresh only ever writes `payload`, `preview_signal`, `retrieved_at` and
//! `prior_observations`; an analyst's verdict on the finding is theirs, not a tool's to
//! overwrite.
//!
//! **Directory liveness**: a tile is `live` when its host answered at all — 2xx/3xx, and also
//! 401/403, because a login wall or a Cloudflare challenge means the site is up and the tile
//! still worth opening by hand (which is the entire point of a directory tile). 404/410, 5xx,
//! timeouts and transport failures mark it not-live. The whole sweep bills **one** lookup, on
//! the same rule that makes WhatsMyName's 730-site fan-out one lookup: it is one operation the
//! analyst asked for.
//!
//! ## The cache-bypass flag
//!
//! This unit depends on the fetch cache's bypass flag. For a while that
//! dependency was inert: the flag existed and was tested, but no tool in `sources/` consulted
//! `ToolCache` at all, so there was nothing to bypass and none was threaded through
//! [`crate::sources::dispatch`]. That is no longer true — every dispatcher now fetches through
//! [`crate::sources::ToolCtx::fetch`] — and so [`refresh_via_chain`] sets `bypass: true` on the
//! context it builds. This is the flag's only caller, deliberately: a *layer* that bypassed
//! the cache would only ever write to it and never read it.
//!
//! The one place a refresh still cannot bypass anything is [`refresh_directory`], whose tile
//! probes call [`crate::fetch::oz_fetch`] directly and are not cached by anyone. Those replays
//! are genuine round-trips by construction.

use std::sync::Arc;

use chrono::Utc;
use serde_json::Value;

use ozint_db::Db;

use crate::fetch::{self, CancelSignal, OzFetchOptions, OzOutcome};
use crate::outcome::{ToolOutcome, ToolReport};
use crate::registry::{self, ToolDef, ToolYield};
use crate::sources::{self, DispatchOutcome};
use crate::types::{DirectoryPayload, OzNode, OzPayload, PriorObservation};
use crate::{signal, store};

/// Why a refresh could not even be attempted. Both variants are loud on purpose: the failure
/// mode this unit is most exposed to is a refresh that quietly reports "nothing changed"
/// because it never ran anything.
#[derive(Debug, Clone, PartialEq)]
pub enum RefreshError {
    NodeNotFound,
    /// The node's `tool_chain` contains nothing this build can re-invoke. Carries the chain
    /// verbatim so the caller can say *why* — a root node typed by the analyst (`seed`), or a
    /// node produced by a tool that has since left the registry (registry-version tolerance:
    /// such a node must still **render**, it just cannot re-run).
    NothingToReplay {
        chain: Vec<String>,
        reason: String,
    },
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefreshError::NodeNotFound => write!(f, "node not found"),
            RefreshError::NothingToReplay { reason, .. } => write!(f, "{reason}"),
        }
    }
}

/// What one refresh did.
#[derive(Debug, Clone)]
pub struct RefreshResult {
    /// The node as it now stands — persisted unless `aborted`.
    pub node: OzNode,
    pub changed: bool,
    /// Top-level payload keys whose value differs (multiset-compared for arrays). Empty
    /// whenever `changed` is false.
    pub changed_fields: Vec<String>,
    /// One per tool actually accounted for, replayed or skipped.
    pub reports: Vec<ToolReport>,
    /// Child seeds a replayed tool offered and this refresh deliberately did not act on.
    /// Reported so a growing source is visible rather than silently dropped.
    pub children_ignored: usize,
    pub lookups: i64,
    pub cost_cents: i64,
    /// The refresh was killed mid-chain. Nothing was persisted — see the module doc.
    pub aborted: bool,
}

// ─── Diff ──────────────────────────────────────────────────────────────────

/// Canonicalizes a JSON value so two payloads can be compared for *meaningful* difference:
/// object keys are already order-independent in `serde_json::Map`'s ordering, and arrays are
/// sorted by their canonical rendering so a reordered fan-out result is not a change. See the
/// module doc for why reordering must not count.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Array(items) => {
            let mut normalized: Vec<Value> = items.iter().map(canonical).collect();
            normalized.sort_by_cached_key(|v| v.to_string());
            Value::Array(normalized)
        }
        Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), canonical(v))).collect())
        }
        other => other.clone(),
    }
}

/// Top-level keys that differ between two payload renderings, canonicalized first. A key
/// present on one side and absent on the other counts as a difference.
fn changed_fields(before: &Value, after: &Value) -> Vec<String> {
    let (Value::Object(a), Value::Object(b)) = (canonical(before), canonical(after)) else {
        return if canonical(before) == canonical(after) {
            Vec::new()
        } else {
            vec!["*".into()]
        };
    };
    let mut keys: Vec<String> = Vec::new();
    for (k, v) in &a {
        if b.get(k) != Some(v) {
            keys.push(k.clone());
        }
    }
    for k in b.keys() {
        if !a.contains_key(k) {
            keys.push(k.clone());
        }
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// Same shallow, last-writer-wins merge `runtime.rs` applies to a layer's patches, for the
/// same reason: a deep merge would blend two sources' views of one nested object, which is
/// precisely the conflict case this codebase forbids resolving invisibly.
/// The hand-off a refresh replays with, read out of the node's own stored payload.
///
/// One arm per `layer_plan` `INPUT_*` key, matched against the payload field the publishing
/// tool wrote. Kept as an explicit mapping rather than a generic "copy same-named JSON keys"
/// because the two namespaces are not the same thing and must be allowed to diverge: a payload
/// field is what the node *shows*, a hand-off key is what a tool *runs on*.
fn handoff_from_payload(payload: &OzPayload) -> crate::layer_plan::Handoff {
    let mut handoff = crate::layer_plan::Handoff::new();
    if let OzPayload::Ip(ip) = payload
        && let Some(asn) = ip.asn.as_deref().map(str::trim).filter(|s| !s.is_empty())
    {
        handoff.insert(crate::layer_plan::INPUT_ASN.to_string(), asn.to_string());
    }
    handoff
}

fn merge_patch(acc: &mut Value, patch: &Value) {
    let (Value::Object(dst), Value::Object(src)) = (&mut *acc, patch) else {
        return;
    };
    for (k, v) in src {
        dst.insert(k.clone(), v.clone());
    }
}

// ─── Chain resolution ──────────────────────────────────────────────────────

/// One entry of a resolved replay chain.
enum ChainEntry {
    /// Armed and dispatchable.
    Run(&'static ToolDef),
    /// Catalogued but not armed — reported without being attempted, exactly as
    /// `registry::resolve` would have.
    Skip(&'static ToolDef, ToolOutcome),
    /// Not in the registry at all (the analyst's own `seed`, or a tool this build dropped).
    /// Not a `ToolDef`, so it is carried as a bare id and reported as a `ParseError` — the
    /// same visible-drift treatment `runtime.rs` gives a plan naming an unknown tool.
    Unknown(String),
}

fn resolve_chain(chain: &[String]) -> Vec<ChainEntry> {
    chain
        .iter()
        .map(|id| match registry::find(id) {
            Some(tool) if registry::is_armed(tool) => ChainEntry::Run(tool),
            Some(tool) => {
                let env_var = tool
                    .env_vars
                    .iter()
                    .copied()
                    .find(|v| ozint_core::config::optional(v).is_none())
                    .unwrap_or("")
                    .to_string();
                let outcome = if tool.gated {
                    ToolOutcome::SkippedGatedUnarmed { env_var }
                } else {
                    ToolOutcome::SkippedNoKey { env_var }
                };
                ChainEntry::Skip(tool, outcome)
            }
            None => ChainEntry::Unknown(id.clone()),
        })
        .collect()
}

// ─── Directory liveness ────────────────────────────────────────────────────

/// Whether a probe result means "this tile is worth opening by hand". See the module doc:
/// a login wall or a bot challenge is a live site, a 404 is a dead tile.
fn tile_is_live(outcome: &OzOutcome) -> bool {
    match outcome {
        OzOutcome::Ok(_) => true,
        OzOutcome::HttpError { status, .. } => matches!(status, 401 | 403 | 405 | 429),
        _ => false,
    }
}

/// Probes every tile of a directory-only node. Returns the refreshed payload and one report
/// per tile.
async fn probe_tiles(
    payload: &DirectoryPayload,
    cancel: Option<CancelSignal>,
) -> (DirectoryPayload, Vec<ToolReport>, bool) {
    let mut refreshed = payload.clone();
    let mut reports = Vec::new();

    for tile in &mut refreshed.tiles {
        if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
            return (refreshed, reports, true);
        }

        let began = std::time::Instant::now();
        let outcome = fetch::oz_fetch(
            &tile.url,
            OzFetchOptions {
                method: reqwest::Method::HEAD,
                // One attempt: a liveness probe that retries turns a slow sweep into a very
                // slow one, and "it did not answer promptly" is itself the answer here.
                max_retries: 0,
                cancel: cancel.clone(),
                ..Default::default()
            },
        )
        .await;
        let elapsed_ms = began.elapsed().as_millis() as u64;

        if matches!(outcome, OzOutcome::Cancelled) {
            return (refreshed, reports, true);
        }

        let live = tile_is_live(&outcome);
        tile.live = Some(live);

        let tool_outcome = if live {
            ToolOutcome::OkWithResults { count: 1 }
        } else {
            sources::fold_fetch_failure(&outcome).unwrap_or(ToolOutcome::ParseError {
                message: "unreadable probe".into(),
            })
        };
        reports.push(ToolReport::new(
            tile.tool_id.clone(),
            tile.label.clone(),
            tool_outcome,
            elapsed_ms,
            false,
            "HEAD liveness probe of the tile's launch URL",
        ));
    }

    (refreshed, reports, false)
}

// ─── The entry point ───────────────────────────────────────────────────────

/// Re-runs the lookup behind one node.
///
/// See the module doc for every rule this enforces. The caller owns billing decisions only in
/// the sense of reading [`RefreshResult::lookups`] back — this function has already written
/// them to the investigation's meter, in the same place `fire_layer` does.
pub async fn refresh_node(
    db: &Db,
    node_id: &str,
    cancel: Option<CancelSignal>,
    cache: Option<Arc<crate::cache::ToolCache>>,
) -> Result<RefreshResult, RefreshError> {
    let node = store::get_node(db, node_id)
        .map_err(|_| RefreshError::NodeNotFound)?
        .ok_or(RefreshError::NodeNotFound)?;

    if node.oz_type.is_directory_only() {
        // Directory tiles are probed directly and are not cached by any tool, so there is
        // nothing here for a bypass flag to bypass — see `probe_tiles`.
        return refresh_directory(db, node, cancel).await;
    }
    refresh_via_chain(db, node, cancel, cache).await
}

async fn refresh_directory(
    db: &Db,
    mut node: OzNode,
    cancel: Option<CancelSignal>,
) -> Result<RefreshResult, RefreshError> {
    let tiles = match &node.payload {
        OzPayload::Directory(p) | OzPayload::Name(p) => p.clone(),
        // A directory-typed node whose payload is not a directory payload is a contract
        // violation upstream, not something to paper over with an empty sweep.
        other => {
            return Err(RefreshError::NothingToReplay {
                chain: node.provenance.tool_chain.clone(),
                reason: format!(
                    "node is {} but carries a {:?} payload — nothing to probe",
                    node.oz_type.code(),
                    other.oz_type()
                ),
            });
        }
    };

    if tiles.tiles.is_empty() {
        return Err(RefreshError::NothingToReplay {
            chain: node.provenance.tool_chain.clone(),
            reason: "this directory node carries no tiles, so there is no URL to re-check"
                .to_string(),
        });
    }

    let before = serde_json::to_value(&node.payload).unwrap_or(Value::Null);
    let (refreshed, reports, aborted) = probe_tiles(&tiles, cancel).await;

    if aborted {
        return Ok(RefreshResult {
            node,
            changed: false,
            changed_fields: Vec::new(),
            reports,
            children_ignored: 0,
            lookups: 0,
            cost_cents: 0,
            aborted: true,
        });
    }

    let merged = match node.oz_type {
        crate::types::OzType::Name => OzPayload::Name(refreshed),
        _ => OzPayload::Directory(refreshed),
    };
    let after = serde_json::to_value(&merged).unwrap_or(Value::Null);
    let fields = changed_fields(&before, &after);
    let changed = !fields.is_empty();

    if changed {
        push_prior_observation(&mut node);
        node.payload = merged;
    }
    node.provenance.retrieved_at = Utc::now();
    persist(db, &node);

    // One operation the analyst asked for = one lookup, whatever the tile count. Same rule as
    // WhatsMyName's 730-site fan-out billing one.
    let lookups = 1;
    bill(db, &node.investigation_id, lookups, 0);

    Ok(RefreshResult {
        node,
        changed,
        changed_fields: fields,
        reports,
        children_ignored: 0,
        lookups,
        cost_cents: 0,
        aborted: false,
    })
}

async fn refresh_via_chain(
    db: &Db,
    mut node: OzNode,
    cancel: Option<CancelSignal>,
    cache: Option<Arc<crate::cache::ToolCache>>,
) -> Result<RefreshResult, RefreshError> {
    let chain = node.provenance.tool_chain.clone();
    let entries = resolve_chain(&chain);

    // The guard this unit exists to have. A node with no re-invokable tool must say so — a
    // "nothing changed" answer here would be indistinguishable from a real re-check that
    // found the world unmoved, which is exactly the silent failure this module exists to avoid.
    if !entries.iter().any(|e| matches!(e, ChainEntry::Run(_))) {
        let reason = if chain.is_empty() {
            "this node has no recorded tool chain, so there is no lookup to re-run".to_string()
        } else if entries.iter().all(|e| matches!(e, ChainEntry::Unknown(_))) {
            format!(
                "no tool in this node's chain ({}) exists in this build's registry — the node still renders from its stored payload, but it cannot be re-run",
                chain.join(", ")
            )
        } else {
            format!(
                "every tool in this node's chain ({}) is unarmed — arm its key and refresh again",
                chain.join(", ")
            )
        };
        return Err(RefreshError::NothingToReplay { chain, reason });
    }

    let value = node.effective_value().to_string();
    let before = serde_json::to_value(&node.payload).unwrap_or(Value::Null);
    // The sibling hand-off, for a replay that has no waves to hand anything over.
    //
    // A refresh re-runs a chain, not a plan: there is no earlier phase to publish an ASN for
    // `ip-peeringdb` to look up. But the node itself already holds one — a chain only contains
    // `ip-peeringdb` because it ran once and patched this node, which means the tool that
    // published the ASN ran too and its value was persisted. Seeding from the stored payload is
    // therefore the honest source, and it is a *fact about this node* rather than a by-product
    // of replay ordering, so it holds whatever order `resolve_chain` returns.
    //
    // A node whose payload lost the input (an analyst edit, an older schema) yields an empty
    // hand-off, and the replayed tool reports `SkippedMissingInput` rather than an empty result.
    let handoff = handoff_from_payload(&node.payload);

    let mut reports: Vec<ToolReport> = Vec::new();
    let mut patch = serde_json::json!({});
    let mut children_ignored = 0usize;
    let mut sections: Vec<crate::types::OzSection> = Vec::new();
    let mut lookups = 0i64;
    let mut cost_cents = 0i64;
    let mut gated_verdict = false;

    for (idx, entry) in entries.iter().enumerate() {
        match entry {
            ChainEntry::Skip(tool, outcome) => {
                reports.push(ToolReport::new(
                    tool.id,
                    tool.label,
                    outcome.clone(),
                    0,
                    tool.gated,
                    tool.method,
                ));
            }
            ChainEntry::Unknown(id) => {
                reports.push(ToolReport::new(
                    id.clone(),
                    id.clone(),
                    ToolOutcome::ParseError {
                        message: format!(
                            "`{id}` produced this node but is absent from this build's registry — it cannot be re-run"
                        ),
                    },
                    0,
                    false,
                    "not dispatched",
                ));
            }
            ChainEntry::Run(tool) => {
                if cancel.as_ref().is_some_and(|c| c.is_cancelled()) {
                    report_cancelled_rest(&mut reports, &entries[idx..]);
                    return Ok(aborted_result(node, reports, lookups, cost_cents));
                }

                let began = std::time::Instant::now();
                // `bypass: true` — this is the flag's one caller, and the reason it exists.
                // A refresh served from cache would answer "nothing changed" without having
                // asked anyone, which is the precise silent failure this whole unit is built
                // to prevent. The TTL is still the tool's own, because a bypassed call still
                // *writes*: the refresh repopulates the cache for everyone after it.
                let tool_ctx = sources::ToolCtx {
                    cancel: cancel.clone(),
                    cache: cache.clone(),
                    ttl: std::time::Duration::from_secs(tool.ttl_secs),
                    bypass: true,
                    handoff: handoff.clone(),
                };
                let dispatched = sources::dispatch(tool.id, &value, &tool_ctx).await;
                let elapsed_ms = began.elapsed().as_millis() as u64;

                let (outcome, produced) = match dispatched {
                    DispatchOutcome::Cancelled => {
                        report_cancelled_rest(&mut reports, &entries[idx..]);
                        return Ok(aborted_result(node, reports, lookups, cost_cents));
                    }
                    DispatchOutcome::Ran(outcome, produced) => (outcome, produced),
                };

                lookups += 1;
                cost_cents += tool.cost_cents as i64;
                if tool.gated && outcome.is_success() {
                    gated_verdict = true;
                }
                reports.push(ToolReport::new(
                    tool.id,
                    tool.label,
                    outcome,
                    elapsed_ms,
                    tool.gated,
                    tool.method,
                ));

                if let Some(ToolYield {
                    payload_patch,
                    rows,
                    children,
                    ..
                }) = produced
                {
                    merge_patch(&mut patch, &payload_patch);
                    children_ignored += children.len();
                    // `rows` used to be discarded here exactly as it was in `runtime.rs`. A
                    // refresh that re-ran a tool and then threw away everything it said about
                    // the node except its payload keys was quietly serving a stale detail
                    // panel next to a freshly-updated chip.
                    if let Some(section) = crate::runtime::section_from_rows(tool, rows) {
                        sections.push(section);
                    }
                }
            }
        }
    }

    // Merge onto the node's *current* payload rather than replacing it: a chain of several
    // tools each patches its own keys, and a tool that has gone quiet since should not erase
    // what a still-working sibling contributes.
    let mut merged_json = before.clone();
    merge_patch(&mut merged_json, &patch);
    let merged: OzPayload = match serde_json::from_value(merged_json.clone()) {
        Ok(p) => p,
        Err(e) => {
            // The replay produced something that no longer fits this node's payload type.
            // Reported as a tool-level parse failure and applied to nothing — never silently
            // half-applied.
            reports.push(ToolReport::new(
                "refresh",
                "refresh",
                ToolOutcome::ParseError {
                    message: format!(
                        "the replayed chain did not re-type into this node's payload: {e}"
                    ),
                },
                0,
                false,
                "merged the replayed chain into the stored payload",
            ));
            bill(db, &node.investigation_id, lookups, cost_cents);
            return Ok(RefreshResult {
                node,
                changed: false,
                changed_fields: Vec::new(),
                reports,
                children_ignored,
                lookups,
                cost_cents,
                aborted: false,
            });
        }
    };

    // Applied even when the payload did not move: the tools just re-answered, and their
    // current answer is what the panel must show. Placed after the re-type check on purpose —
    // the early return above states that a chain that no longer fits this node's payload is
    // applied to *nothing*, and half-applying its sections would make that sentence false.
    crate::runtime::merge_sections(&mut node.sections, &sections);

    let after = serde_json::to_value(&merged).unwrap_or(Value::Null);
    let fields = changed_fields(&before, &after);
    let changed = !fields.is_empty();

    if changed {
        push_prior_observation(&mut node);
        node.payload = merged;
        node.preview_signal =
            signal::signal_for(&node.payload, signal::SignalMode::Native).map(|chip| {
                if gated_verdict || node.gated {
                    signal::apply_gated(chip)
                } else {
                    chip
                }
            });
    }
    if gated_verdict {
        // Gating never gets cleared downstream.
        node.gated = true;
        node.provenance.gated = true;
    }
    node.provenance.retrieved_at = Utc::now();
    persist(db, &node);
    bill(db, &node.investigation_id, lookups, cost_cents);

    Ok(RefreshResult {
        node,
        changed,
        changed_fields: fields,
        reports,
        children_ignored,
        lookups,
        cost_cents,
        aborted: false,
    })
}

/// The previous observation of this node, kept before its payload is overwritten. `value` is
/// what the node claimed and `chip` the verdict it showed; `observed_at` is when that
/// observation was actually made, not now.
fn push_prior_observation(node: &mut OzNode) {
    node.provenance.prior_observations.push(PriorObservation {
        value: node.value.clone(),
        chip: node.preview_signal.clone(),
        observed_at: node.provenance.retrieved_at,
    });
}

fn report_cancelled_rest(reports: &mut Vec<ToolReport>, rest: &[ChainEntry]) {
    for entry in rest {
        let (id, label, gated, method) = match entry {
            ChainEntry::Run(tool) | ChainEntry::Skip(tool, _) => (
                tool.id.to_string(),
                tool.label.to_string(),
                tool.gated,
                tool.method.to_string(),
            ),
            ChainEntry::Unknown(id) => {
                (id.clone(), id.clone(), false, "not dispatched".to_string())
            }
        };
        if reports.iter().any(|r| r.tool_id == id) {
            continue;
        }
        reports.push(ToolReport::new(
            id,
            label,
            ToolOutcome::Cancelled,
            0,
            gated,
            method,
        ));
    }
}

fn aborted_result(
    node: OzNode,
    reports: Vec<ToolReport>,
    lookups: i64,
    cost_cents: i64,
) -> RefreshResult {
    RefreshResult {
        node,
        changed: false,
        changed_fields: Vec::new(),
        reports,
        children_ignored: 0,
        lookups,
        cost_cents,
        aborted: true,
    }
}

fn persist(db: &Db, node: &OzNode) {
    if let Err(e) = store::insert_node(db, node) {
        tracing::warn!(node_id = %node.id, error = %e, "failed to persist a refreshed ozint node");
    }
}

fn bill(db: &Db, investigation_id: &str, lookups: i64, cost_cents: i64) {
    if lookups == 0 && cost_cents == 0 {
        return;
    }
    if let Err(e) =
        store::bump_investigation_usage(db, investigation_id, lookups, cost_cents, Utc::now())
    {
        tracing::warn!(error = %e, "failed to bill an ozint refresh to the lookup meter");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        DirectoryTile, Investigation, NodeStatus, OzType, Provenance, RecordStatus, SignalChip,
        SignalTone, UsernamePayload,
    };
    use serde_json::json;

    // ── Diff semantics ─────────────────────────────────────────────────────

    #[test]
    fn a_reordered_array_is_not_a_change() {
        // Reordering is deliberately not a change. WhatsMyName's ~730 concurrent probes come
        // back in a different order every run; counting that as a change would push a junk
        // prior observation on every single refresh.
        let a = json!({"hits": [{"site": "github"}, {"site": "reddit"}]});
        let b = json!({"hits": [{"site": "reddit"}, {"site": "github"}]});
        assert_eq!(changed_fields(&a, &b), Vec::<String>::new());
    }

    #[test]
    fn a_different_array_member_is_a_change() {
        let a = json!({"hits": [{"site": "github"}]});
        let b = json!({"hits": [{"site": "github"}, {"site": "reddit"}]});
        assert_eq!(changed_fields(&a, &b), vec!["hits".to_string()]);
    }

    #[test]
    fn a_scalar_move_names_exactly_its_field() {
        let a = json!({"sitesChecked": 312, "sitesConfirmed": 14});
        let b = json!({"sitesChecked": 312, "sitesConfirmed": 15});
        assert_eq!(changed_fields(&a, &b), vec!["sitesConfirmed".to_string()]);
    }

    #[test]
    fn an_appearing_key_counts_as_a_change() {
        let a = json!({"sitesChecked": 312});
        let b = json!({"sitesChecked": 312, "reputation": "low"});
        assert_eq!(changed_fields(&a, &b), vec!["reputation".to_string()]);
    }

    #[test]
    fn nested_arrays_are_canonicalized_too() {
        let a = json!({"p": {"tags": ["b", "a"]}});
        let b = json!({"p": {"tags": ["a", "b"]}});
        assert!(changed_fields(&a, &b).is_empty());
    }

    // ── Tile liveness ──────────────────────────────────────────────────────

    #[test]
    fn a_login_wall_is_a_live_tile_and_a_404_is_not() {
        // A directory tile exists precisely because the site cannot be queried automatically;
        // "it refused my robot" is not "it is gone".
        assert!(tile_is_live(&OzOutcome::HttpError {
            status: 403,
            body_snippet: None
        }));
        assert!(tile_is_live(&OzOutcome::HttpError {
            status: 429,
            body_snippet: None
        }));
        assert!(!tile_is_live(&OzOutcome::HttpError {
            status: 404,
            body_snippet: None
        }));
        assert!(!tile_is_live(&OzOutcome::HttpError {
            status: 500,
            body_snippet: None
        }));
        assert!(!tile_is_live(&OzOutcome::Timeout {
            attempts: 1,
            elapsed_ms: 8_000
        }));
        assert!(!tile_is_live(&OzOutcome::Blocked {
            url: "http://127.0.0.1".into()
        }));
    }

    // ── Chain resolution ───────────────────────────────────────────────────

    #[test]
    fn the_analysts_own_seed_is_not_a_replayable_tool() {
        let entries = resolve_chain(&["seed".to_string()]);
        assert!(matches!(entries.as_slice(), [ChainEntry::Unknown(id)] if id == "seed"));
    }

    #[test]
    fn a_catalogued_keyless_tool_resolves_as_runnable() {
        let entries = resolve_chain(&["wmn-probe".to_string()]);
        assert!(matches!(entries.as_slice(), [ChainEntry::Run(t)] if t.id == "wmn-probe"));
    }

    // ── The engine, against a real in-memory DB and no network ─────────────
    //
    // Every case below either refuses before dispatch or pre-cancels, so no dispatcher ever
    // opens a socket — the same rule `runtime.rs`'s engine tests hold to.

    fn seed_node(db: &Db, oz_type: OzType, chain: &[&str], payload: OzPayload) -> OzNode {
        let now = Utc::now();
        store::create_investigation(
            db,
            &Investigation {
                id: "inv-1".into(),
                seed_input: "mtrebosc".into(),
                seed_type: oz_type,
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

        let mut provenance = Provenance::new("wmn-probe", "queried WhatsMyName");
        provenance.tool_chain = chain.iter().map(|s| s.to_string()).collect();
        provenance.retrieved_at = now - chrono::Duration::hours(3);

        let node = OzNode {
            id: "node-1".into(),
            investigation_id: "inv-1".into(),
            parent_id: None,
            layer_id: None,
            ordinal: 0,
            depth: 0,
            oz_type,
            value: "mtrebosc".into(),
            display: "mtrebosc".into(),
            dedup_key: crate::normalize::dedup_key(oz_type, "mtrebosc"),
            payload,
            preview_signal: Some(SignalChip::new("14 / 312 sites", SignalTone::Neutral)),
            full_signal: None,
            sections: Vec::new(),
            gated: false,
            status: NodeStatus::Settled,
            provenance,
            already_in_tree: None,
            corroborations: Vec::new(),
            edited_value: None,
            created_at: now,
        };
        store::insert_node(db, &node).unwrap();
        node
    }

    fn username_payload(confirmed: u32) -> OzPayload {
        OzPayload::Username(UsernamePayload {
            hits: Vec::new(),
            sites_checked: 312,
            sites_confirmed: confirmed,
            profile: Vec::new(),
        })
    }

    #[tokio::test]
    async fn refreshing_an_unknown_node_is_not_found() {
        let db = ozint_db::open_memory().unwrap();
        assert_eq!(
            refresh_node(&db, "nope", None, None).await.unwrap_err(),
            RefreshError::NodeNotFound
        );
    }

    #[tokio::test]
    async fn a_node_with_no_replayable_chain_refuses_loudly() {
        // The whole point of this unit's error taxonomy: a root node the analyst typed has
        // nothing to re-run, and must never be answered with a reassuring "unchanged".
        let db = ozint_db::open_memory().unwrap();
        seed_node(&db, OzType::Username, &["seed"], username_payload(14));

        let err = refresh_node(&db, "node-1", None, None).await.unwrap_err();
        match err {
            RefreshError::NothingToReplay { chain, reason } => {
                assert_eq!(chain, vec!["seed".to_string()]);
                assert!(reason.contains("registry"), "reason: {reason}");
            }
            other => panic!("expected NothingToReplay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_empty_chain_refuses_too() {
        let db = ozint_db::open_memory().unwrap();
        seed_node(&db, OzType::Username, &[], username_payload(14));
        assert!(matches!(
            refresh_node(&db, "node-1", None, None).await.unwrap_err(),
            RefreshError::NothingToReplay { .. }
        ));
    }

    #[tokio::test]
    async fn a_directory_node_with_no_tiles_refuses_rather_than_reporting_unchanged() {
        let db = ozint_db::open_memory().unwrap();
        seed_node(
            &db,
            OzType::Directory,
            &["seed"],
            OzPayload::Directory(DirectoryPayload::default()),
        );
        assert!(matches!(
            refresh_node(&db, "node-1", None, None).await.unwrap_err(),
            RefreshError::NothingToReplay { .. }
        ));
    }

    #[tokio::test]
    async fn a_cancelled_refresh_persists_nothing_and_bills_nothing() {
        let db = ozint_db::open_memory().unwrap();
        let before = seed_node(&db, OzType::Username, &["wmn-probe"], username_payload(14));

        let (handle, signal) = fetch::CancelHandle::new();
        handle.cancel();
        let result = refresh_node(&db, "node-1", Some(signal), None)
            .await
            .unwrap();

        assert!(result.aborted);
        assert!(!result.changed);
        assert_eq!(
            result.lookups, 0,
            "a pre-cancelled refresh must not bill a lookup"
        );
        assert!(
            result
                .reports
                .iter()
                .all(|r| r.outcome == ToolOutcome::Cancelled),
            "every tool the kill stopped must say so"
        );

        let stored = store::get_node(&db, "node-1").unwrap().unwrap();
        // Millisecond precision: the store round-trips timestamps through SQLite.
        assert_eq!(
            stored.provenance.retrieved_at.timestamp_millis(),
            before.provenance.retrieved_at.timestamp_millis(),
            "an aborted refresh must not even claim a fresh retrieval time"
        );
        let inv = store::get_investigation(&db, "inv-1").unwrap().unwrap();
        assert_eq!(inv.lookups, 0);
    }

    #[tokio::test]
    async fn a_cancelled_directory_sweep_persists_nothing() {
        let db = ozint_db::open_memory().unwrap();
        let tiles = DirectoryPayload {
            tiles: vec![DirectoryTile {
                tool_id: "pipl".into(),
                label: "Pipl".into(),
                url: "https://pipl.com/".into(),
                reason: "login wall".into(),
                live: None,
            }],
        };
        let before = seed_node(
            &db,
            OzType::Directory,
            &["seed"],
            OzPayload::Directory(tiles),
        );

        let (handle, signal) = fetch::CancelHandle::new();
        handle.cancel();
        let result = refresh_node(&db, "node-1", Some(signal), None)
            .await
            .unwrap();

        assert!(result.aborted);
        assert_eq!(result.lookups, 0);
        let stored = store::get_node(&db, "node-1").unwrap().unwrap();
        assert_eq!(
            stored.provenance.retrieved_at.timestamp_millis(),
            before.provenance.retrieved_at.timestamp_millis()
        );
    }

    // ── What a change does to the record ───────────────────────────────────
    //
    // Driven through the persistence helpers directly rather than a live dispatch, for the
    // no-network reason above.

    #[test]
    fn a_change_pushes_the_old_observation_instead_of_a_correction() {
        let mut node = OzNode {
            preview_signal: Some(SignalChip::new("14 / 312 sites", SignalTone::Neutral)),
            ..sample()
        };
        let was_at = node.provenance.retrieved_at;

        push_prior_observation(&mut node);

        let prior = node
            .provenance
            .prior_observations
            .first()
            .expect("a prior observation");
        assert_eq!(prior.value, "mtrebosc");
        assert_eq!(prior.chip.as_ref().unwrap().text, "14 / 312 sites");
        assert_eq!(
            prior.observed_at, was_at,
            "the prior observation is dated when it was made"
        );
        assert_eq!(
            node.provenance.record_status,
            RecordStatus::AsReturned,
            "a refresh is not an analyst correction — record_status must not move"
        );
    }

    #[test]
    fn an_analysts_verdict_survives_a_refresh_diff() {
        let mut node = sample();
        node.provenance.record_status = RecordStatus::Rejected {
            rejected_at: Utc::now(),
        };
        node.edited_value = Some("m.trebosc".into());

        push_prior_observation(&mut node);

        assert!(
            node.provenance.record_status.is_rejected(),
            "rejection is the analyst's, not a tool's to clear"
        );
        assert_eq!(node.edited_value.as_deref(), Some("m.trebosc"));
    }

    fn sample() -> OzNode {
        let mut provenance = Provenance::new("wmn-probe", "queried WhatsMyName");
        provenance.retrieved_at = Utc::now() - chrono::Duration::hours(2);
        OzNode {
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
            payload: username_payload(14),
            preview_signal: None,
            full_signal: None,
            sections: Vec::new(),
            gated: false,
            status: NodeStatus::Settled,
            provenance,
            already_in_tree: None,
            corroborations: Vec::new(),
            edited_value: None,
            created_at: Utc::now(),
        }
    }
}
