//! SQLite persistence for the OZINT engine. Every other Phase-1+ unit's state (layers, tool
//! cache, quota, provenance, node edits) is persisted through this module.
//!
//! This crate does **not** open its own SQLite file: it adds its `oz_*` tables to whatever
//! connection `ozint-db` already owns (`.data/memory.db`), via [`ensure_tables`]. There is no
//! migration framework — the idempotent `CREATE TABLE IF NOT EXISTS` + swallowed-duplicate-
//! column `ALTER TABLE` in `ensure_tables` *is* the migration system. Every public function
//! starts by locking the connection and calling `ensure_tables`.
//!
//! **Schema ownership**: this module owns every `oz_*` table, including `oz_tool_cache`
//! and `oz_quota` — those two are shared with the fetch cache and the source scheduler.
//! `store.rs` defines them once here; `cache.rs` and
//! `scheduler.rs` call [`ensure_tables`] and this module's row helpers rather than
//! `CREATE TABLE`-ing the same names themselves.
//!
//! **`oz_nodes.gated` is the single source of truth for two logical fields**:
//! `OzNode::gated` and `Provenance::gated`. Both are set from the same column on
//! hydration and written from the same value on insert — see [`hydrate`] and
//! [`insert_node`]. They are conceptually the same fact (this node was touched by an
//! ethically-gated tool) and must never drift apart, so storing them twice server-side
//! would only invite a bug where one gets updated and the other doesn't.

use chrono::{DateTime, Utc};
use ozint_db::Db;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::types::{
    Corroboration, Investigation, NodeStatus, OzNode, OzPayload, OzSection, OzType,
    PriorObservation, Provenance, RecordStatus, SignalChip,
};

// ─── Table creation ─────────────────────────────────────────────────────────

/// Idempotently create every `oz_*` table on this connection. Cheap enough to call
/// unconditionally at the top of every public function in this module (and in `cache.rs`/
/// `scheduler.rs`).
pub fn ensure_tables(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS oz_investigations (
          id                             TEXT PRIMARY KEY,
          seed_input                     TEXT NOT NULL,
          seed_type                      TEXT NOT NULL,
          root_node_id                   TEXT NOT NULL,
          created_at                     INTEGER NOT NULL,
          updated_at                     INTEGER NOT NULL,
          lookups                        INTEGER NOT NULL DEFAULT 0,
          cost_cents                     INTEGER NOT NULL DEFAULT 0,
          spawned_from_investigation_id  TEXT,
          spawned_from_relation          TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_oz_investigations_created ON oz_investigations(created_at);

        CREATE TABLE IF NOT EXISTS oz_nodes (
          id                        TEXT PRIMARY KEY,
          investigation_id          TEXT NOT NULL,
          parent_id                 TEXT,
          layer_id                  TEXT,
          ordinal                   INTEGER NOT NULL,
          depth                     INTEGER NOT NULL,
          oz_type                   TEXT NOT NULL,
          value                     TEXT NOT NULL,
          display                   TEXT NOT NULL,
          dedup_key                 TEXT NOT NULL,
          payload_json              TEXT NOT NULL,
          preview_signal_json       TEXT,
          full_signal_json          TEXT,
          sections_json             TEXT,
          status                    TEXT NOT NULL,
          already_in_tree           TEXT,
          edited_value              TEXT,
          created_at                INTEGER NOT NULL,
          found_via_parent_id       TEXT,
          source_tool_id            TEXT NOT NULL,
          method                    TEXT NOT NULL,
          retrieved_at              INTEGER NOT NULL,
          record_status_json        TEXT NOT NULL,
          tool_chain_json           TEXT NOT NULL,
          gated                     INTEGER NOT NULL DEFAULT 0,
          prior_observations_json   TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_oz_nodes_investigation ON oz_nodes(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_oz_nodes_parent ON oz_nodes(parent_id);
        CREATE INDEX IF NOT EXISTS idx_oz_nodes_dedup ON oz_nodes(investigation_id, dedup_key);
        CREATE INDEX IF NOT EXISTS idx_oz_nodes_gated ON oz_nodes(gated);

        CREATE TABLE IF NOT EXISTS oz_layers (
          id                 TEXT PRIMARY KEY,
          investigation_id   TEXT NOT NULL,
          parent_node_id     TEXT NOT NULL,
          oz_type            TEXT NOT NULL,
          value              TEXT NOT NULL,
          status             TEXT NOT NULL,
          started_at         INTEGER NOT NULL,
          settled_at         INTEGER,
          new_children       INTEGER NOT NULL DEFAULT 0,
          tool_reports_json  TEXT,
          summary            TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_oz_layers_investigation ON oz_layers(investigation_id);

        CREATE TABLE IF NOT EXISTS oz_tool_cache (
          tool_id           TEXT NOT NULL,
          cache_key         TEXT NOT NULL,
          payload_json      TEXT NOT NULL,
          retrieved_at      INTEGER NOT NULL,
          investigation_id  TEXT,
          PRIMARY KEY (tool_id, cache_key)
        );

        CREATE TABLE IF NOT EXISTS oz_quota (
          rate_key      TEXT NOT NULL,
          window_kind   TEXT NOT NULL,
          window_start  INTEGER NOT NULL,
          used          INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (rate_key, window_kind)
        );
        "#,
    )?;
    // `pre_reject_status_json` is not part of the base schema above — it is an
    // internal-only stash added here so RESTORE can undo *only* a rejection (see
    // `reject_node`/`restore_node`). Migrated with the same idempotent-ALTER style used
    // above: swallow "duplicate column" once it exists.
    // Same idempotent-ALTER migration for `corroborations_json`, added 2026-08-23 so a value
    // found by two independent routes keeps both across a reopen. It had lived only on the
    // `AlreadyInTree` SSE frame, so every corroboration in a tree vanished on rehydrate — with
    // no symptom, since the value itself was still there.
    for stmt in [
        "ALTER TABLE oz_nodes ADD COLUMN pre_reject_status_json TEXT",
        "ALTER TABLE oz_nodes ADD COLUMN corroborations_json TEXT",
        // And for `evidence_json` (2026-08-23): the archive captures
        // an analyst asked about, kept on the node's provenance rather than in a table of
        // their own — see `Provenance::evidence`.
        "ALTER TABLE oz_nodes ADD COLUMN evidence_json TEXT",
    ] {
        if let Err(e) = conn.execute_batch(stmt) {
            let msg = e.to_string().to_lowercase();
            if !msg.contains("duplicate column") && !msg.contains("already exists") {
                return Err(e);
            }
        }
    }
    Ok(())
}

// ─── Small shared helpers ───────────────────────────────────────────────────

/// Serialises a fieldless, kebab-case enum (`OzType`, `NodeStatus`) to its bare string
/// form (`"username"`, not `"\"username\""`) for storage in a plain TEXT column.
fn ser_enum<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        other => unreachable!("fieldless enum must serialise to a JSON string, got {other:?}"),
    }
}

/// Inverse of [`ser_enum`]. Returns `Err` on any string that isn't a valid variant —
/// callers decide how to degrade (see the registry-tolerance note on [`hydrate`]).
fn de_enum<T: DeserializeOwned>(raw: &str) -> Result<T, serde_json::Error> {
    serde_json::from_value(serde_json::Value::String(raw.to_string()))
}

fn to_millis(dt: DateTime<Utc>) -> i64 {
    dt.timestamp_millis()
}

fn from_millis(ms: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp_millis(ms).unwrap_or_else(Utc::now)
}

// ─── Investigations ──────────────────────────────────────────────────────────

const INVESTIGATION_COLUMNS: &str = "id, seed_input, seed_type, root_node_id, created_at, \
    updated_at, lookups, cost_cents, spawned_from_investigation_id, spawned_from_relation";

struct InvestigationRaw {
    id: String,
    seed_input: String,
    seed_type: String,
    root_node_id: String,
    created_at: i64,
    updated_at: i64,
    lookups: i64,
    cost_cents: i64,
    spawned_from_investigation_id: Option<String>,
    spawned_from_relation: Option<String>,
}

fn row_to_investigation_raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<InvestigationRaw> {
    Ok(InvestigationRaw {
        id: row.get(0)?,
        seed_input: row.get(1)?,
        seed_type: row.get(2)?,
        root_node_id: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        lookups: row.get(6)?,
        cost_cents: row.get(7)?,
        spawned_from_investigation_id: row.get(8)?,
        spawned_from_relation: row.get(9)?,
    })
}

/// Degrades (skips, with a warning) rather than fails on an unparseable `seed_type` — same
/// registry-version-tolerance policy as node hydration, see [`hydrate`].
fn hydrate_investigation(raw: InvestigationRaw) -> Option<Investigation> {
    let seed_type = match de_enum::<OzType>(&raw.seed_type) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(
                investigation_id = %raw.id,
                seed_type = %raw.seed_type,
                error = %e,
                "skipping investigation: unparseable seed_type"
            );
            return None;
        }
    };
    Some(Investigation {
        id: raw.id,
        seed_input: raw.seed_input,
        seed_type,
        root_node_id: raw.root_node_id,
        created_at: from_millis(raw.created_at),
        updated_at: from_millis(raw.updated_at),
        lookups: raw.lookups,
        cost_cents: raw.cost_cents,
        spawned_from_investigation_id: raw.spawned_from_investigation_id,
        spawned_from_relation: raw.spawned_from_relation,
    })
}

pub fn create_investigation(db: &Db, inv: &Investigation) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    conn.execute(
        "INSERT INTO oz_investigations
           (id, seed_input, seed_type, root_node_id, created_at, updated_at, lookups, cost_cents,
            spawned_from_investigation_id, spawned_from_relation)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            inv.id,
            inv.seed_input,
            ser_enum(&inv.seed_type),
            inv.root_node_id,
            to_millis(inv.created_at),
            to_millis(inv.updated_at),
            inv.lookups,
            inv.cost_cents,
            inv.spawned_from_investigation_id,
            inv.spawned_from_relation,
        ],
    )?;
    Ok(())
}

pub fn get_investigation(db: &Db, id: &str) -> rusqlite::Result<Option<Investigation>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {INVESTIGATION_COLUMNS} FROM oz_investigations WHERE id = ?1"
    ))?;
    let raw = stmt.query_row([id], row_to_investigation_raw).optional()?;
    Ok(raw.and_then(hydrate_investigation))
}

/// Newest first, capped at `limit` — the history list.
pub fn list_investigations(db: &Db, limit: i64) -> rusqlite::Result<Vec<Investigation>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {INVESTIGATION_COLUMNS} FROM oz_investigations ORDER BY created_at DESC LIMIT ?1"
    ))?;
    let raws = stmt
        .query_map([limit], row_to_investigation_raw)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(raws.into_iter().filter_map(hydrate_investigation).collect())
}

/// The investigation already spawned from one relation of one source investigation, if any.
///
/// The idempotency key for spawning an investigation from a relation. Spawning is a create, and a create reached from a
/// clickable card needs to survive a double-click and a re-opened history without quietly
/// growing a second identical tree the analyst then has to reconcile by hand.
pub fn find_spawned(
    db: &Db,
    from_investigation_id: &str,
    relation: &str,
) -> rusqlite::Result<Option<Investigation>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {INVESTIGATION_COLUMNS} FROM oz_investigations
         WHERE spawned_from_investigation_id = ?1 AND spawned_from_relation = ?2
         ORDER BY created_at ASC LIMIT 1"
    ))?;
    let raw = stmt
        .query_row(
            params![from_investigation_id, relation],
            row_to_investigation_raw,
        )
        .optional()?;
    Ok(raw.and_then(hydrate_investigation))
}

pub fn touch_investigation(db: &Db, id: &str, updated_at: DateTime<Utc>) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let changed = conn.execute(
        "UPDATE oz_investigations SET updated_at = ?1 WHERE id = ?2",
        params![to_millis(updated_at), id],
    )?;
    Ok(changed > 0)
}

/// Adds to (never overwrites) `lookups`/`cost_cents` and bumps `updated_at` in the same
/// write — a lookup happening is itself activity on the investigation.
pub fn bump_investigation_usage(
    db: &Db,
    id: &str,
    lookups_delta: i64,
    cost_cents_delta: i64,
    updated_at: DateTime<Utc>,
) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let changed = conn.execute(
        "UPDATE oz_investigations
         SET lookups = lookups + ?1, cost_cents = cost_cents + ?2, updated_at = ?3
         WHERE id = ?4",
        params![lookups_delta, cost_cents_delta, to_millis(updated_at), id],
    )?;
    Ok(changed > 0)
}

// ─── Nodes ───────────────────────────────────────────────────────────────────

const NODE_COLUMNS: &str = "id, investigation_id, parent_id, layer_id, ordinal, depth, oz_type, \
    value, display, dedup_key, payload_json, preview_signal_json, full_signal_json, sections_json, \
    status, already_in_tree, edited_value, created_at, found_via_parent_id, source_tool_id, method, \
    retrieved_at, record_status_json, tool_chain_json, gated, prior_observations_json, \
    corroborations_json, evidence_json";

struct NodeRaw {
    id: String,
    investigation_id: String,
    parent_id: Option<String>,
    layer_id: Option<String>,
    ordinal: i64,
    depth: i64,
    oz_type: String,
    value: String,
    display: String,
    dedup_key: String,
    payload_json: String,
    preview_signal_json: Option<String>,
    full_signal_json: Option<String>,
    sections_json: Option<String>,
    status: String,
    already_in_tree: Option<String>,
    corroborations_json: Option<String>,
    edited_value: Option<String>,
    created_at: i64,
    found_via_parent_id: Option<String>,
    source_tool_id: String,
    method: String,
    retrieved_at: i64,
    record_status_json: String,
    tool_chain_json: String,
    gated: i64,
    prior_observations_json: Option<String>,
    evidence_json: Option<String>,
}

fn row_to_node_raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRaw> {
    Ok(NodeRaw {
        id: row.get(0)?,
        investigation_id: row.get(1)?,
        parent_id: row.get(2)?,
        layer_id: row.get(3)?,
        ordinal: row.get(4)?,
        depth: row.get(5)?,
        oz_type: row.get(6)?,
        value: row.get(7)?,
        display: row.get(8)?,
        dedup_key: row.get(9)?,
        payload_json: row.get(10)?,
        preview_signal_json: row.get(11)?,
        full_signal_json: row.get(12)?,
        sections_json: row.get(13)?,
        status: row.get(14)?,
        already_in_tree: row.get(15)?,
        edited_value: row.get(16)?,
        created_at: row.get(17)?,
        found_via_parent_id: row.get(18)?,
        source_tool_id: row.get(19)?,
        method: row.get(20)?,
        retrieved_at: row.get(21)?,
        record_status_json: row.get(22)?,
        corroborations_json: row.get(26)?,
        tool_chain_json: row.get(23)?,
        gated: row.get(24)?,
        prior_observations_json: row.get(25)?,
        evidence_json: row.get(27)?,
    })
}

/// Turns a raw row into an `OzNode`, degrading rather than failing the whole load on a
/// corrupt row.
///
/// **Registry-version tolerance**, needed for resuming a reopened investigation: `source_tool_id`, `method` and
/// `tool_chain` are stored and returned as plain, unvalidated strings — this module never
/// joins against the live tool registry, so a node produced by a tool since removed from
/// the registry hydrates exactly as it always did. The only fields with no safe "unknown"
/// fallback are `oz_type` and `status` (both closed Rust enums with no catch-all variant),
/// so a row whose stored value doesn't parse as either is skipped with a `tracing::warn!`
/// rather than failing `list_nodes`/`get_node` for the whole investigation. Same policy for
/// `payload_json` and `record_status_json`, which must deserialise into their tagged enums.
/// `preview_signal_json`/`full_signal_json`/`sections_json`/`prior_observations_json` are
/// optional/best-effort: a parse failure there degrades to `None`/empty rather than
/// dropping the row, since none of them are load-bearing for the node's identity.
fn hydrate(raw: NodeRaw) -> Option<OzNode> {
    let oz_type = match de_enum::<OzType>(&raw.oz_type) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(node_id = %raw.id, oz_type = %raw.oz_type, error = %e, "skipping node: unparseable oz_type");
            return None;
        }
    };
    let status = match de_enum::<NodeStatus>(&raw.status) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(node_id = %raw.id, status = %raw.status, error = %e, "skipping node: unparseable status");
            return None;
        }
    };
    let payload: OzPayload = match serde_json::from_str(&raw.payload_json) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(node_id = %raw.id, error = %e, "skipping node: unparseable payload_json");
            return None;
        }
    };
    let record_status: RecordStatus = match serde_json::from_str(&raw.record_status_json) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(node_id = %raw.id, error = %e, "skipping node: unparseable record_status_json");
            return None;
        }
    };
    let preview_signal: Option<SignalChip> = raw
        .preview_signal_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let full_signal: Option<SignalChip> = raw
        .full_signal_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok());
    let sections: Vec<OzSection> = raw
        .sections_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let tool_chain: Vec<String> = serde_json::from_str(&raw.tool_chain_json).unwrap_or_default();
    let prior_observations: Vec<PriorObservation> = raw
        .prior_observations_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    let gated = raw.gated != 0;

    Some(OzNode {
        id: raw.id,
        investigation_id: raw.investigation_id,
        parent_id: raw.parent_id,
        layer_id: raw.layer_id,
        ordinal: raw.ordinal,
        depth: raw.depth,
        oz_type,
        value: raw.value,
        display: raw.display,
        dedup_key: raw.dedup_key,
        payload,
        preview_signal,
        full_signal,
        sections,
        gated, // same column as provenance.gated below — see module docs
        status,
        provenance: Provenance {
            found_via_parent_id: raw.found_via_parent_id,
            source_tool_id: raw.source_tool_id,
            method: raw.method,
            retrieved_at: from_millis(raw.retrieved_at),
            record_status,
            tool_chain,
            gated,
            prior_observations,
            // Same degrade-rather-than-drop rule as the two blobs above: an unreadable
            // evidence blob costs the archive links, not the finding.
            evidence: raw
                .evidence_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default(),
        },
        already_in_tree: raw.already_in_tree,
        // An unreadable blob degrades to "no extra routes recorded" rather than dropping the
        // node: losing a corroboration marker is a smaller harm than losing the finding.
        corroborations: raw
            .corroborations_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default(),
        edited_value: raw.edited_value,
        created_at: from_millis(raw.created_at),
    })
}

/// Upsert — callable as nodes stream in, not only at settle. On conflict, everything is
/// re-written **except** `investigation_id` and `created_at`: a node's owning investigation
/// and its original creation instant are identity, not mutable state, so a later stream
/// event (or a correction/rejection touching this same row) must never shift them.
pub fn insert_node(db: &Db, node: &OzNode) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;

    let payload_json = serde_json::to_string(&node.payload).expect("OzPayload always serialises");
    let preview_signal_json = node
        .preview_signal
        .as_ref()
        .map(|s| serde_json::to_string(s).expect("SignalChip always serialises"));
    let full_signal_json = node
        .full_signal
        .as_ref()
        .map(|s| serde_json::to_string(s).expect("SignalChip always serialises"));
    let sections_json = serde_json::to_string(&node.sections).expect("sections always serialise");
    let record_status_json = serde_json::to_string(&node.provenance.record_status)
        .expect("RecordStatus always serialises");
    let tool_chain_json =
        serde_json::to_string(&node.provenance.tool_chain).expect("tool_chain always serialises");
    let prior_observations_json = serde_json::to_string(&node.provenance.prior_observations)
        .expect("prior_observations always serialise");

    conn.execute(
        "INSERT INTO oz_nodes (
            id, investigation_id, parent_id, layer_id, ordinal, depth, oz_type, value, display,
            dedup_key, payload_json, preview_signal_json, full_signal_json, sections_json, status,
            already_in_tree, edited_value, created_at, found_via_parent_id, source_tool_id, method,
            retrieved_at, record_status_json, tool_chain_json, gated, prior_observations_json,
            corroborations_json, evidence_json
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28)
         ON CONFLICT(id) DO UPDATE SET
           parent_id = excluded.parent_id,
           layer_id = excluded.layer_id,
           ordinal = excluded.ordinal,
           depth = excluded.depth,
           oz_type = excluded.oz_type,
           value = excluded.value,
           display = excluded.display,
           dedup_key = excluded.dedup_key,
           payload_json = excluded.payload_json,
           preview_signal_json = excluded.preview_signal_json,
           full_signal_json = excluded.full_signal_json,
           sections_json = excluded.sections_json,
           status = excluded.status,
           already_in_tree = excluded.already_in_tree,
           edited_value = excluded.edited_value,
           found_via_parent_id = excluded.found_via_parent_id,
           source_tool_id = excluded.source_tool_id,
           method = excluded.method,
           retrieved_at = excluded.retrieved_at,
           record_status_json = excluded.record_status_json,
           tool_chain_json = excluded.tool_chain_json,
           gated = excluded.gated,
           prior_observations_json = excluded.prior_observations_json,
           corroborations_json = excluded.corroborations_json,
           evidence_json = excluded.evidence_json",
        params![
            node.id,
            node.investigation_id,
            node.parent_id,
            node.layer_id,
            node.ordinal,
            node.depth,
            ser_enum(&node.oz_type),
            node.value,
            node.display,
            node.dedup_key,
            payload_json,
            preview_signal_json,
            full_signal_json,
            sections_json,
            ser_enum(&node.status),
            node.already_in_tree,
            node.edited_value,
            to_millis(node.created_at),
            node.provenance.found_via_parent_id,
            node.provenance.source_tool_id,
            node.provenance.method,
            to_millis(node.provenance.retrieved_at),
            record_status_json,
            tool_chain_json,
            node.gated as i64,
            prior_observations_json,
            serde_json::to_string(&node.corroborations).expect("corroborations always serialise"),
            serde_json::to_string(&node.provenance.evidence).expect("evidence always serialises"),
        ],
    )?;
    Ok(())
}

pub fn get_node(db: &Db, id: &str) -> rusqlite::Result<Option<OzNode>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {NODE_COLUMNS} FROM oz_nodes WHERE id = ?1"
    ))?;
    let raw = stmt.query_row([id], row_to_node_raw).optional()?;
    Ok(raw.and_then(hydrate))
}

/// All nodes of one investigation, ordered `(depth, ordinal)` so a rehydrated tree renders
/// identically to the live one, for resuming a reopened investigation.
pub fn list_nodes(db: &Db, investigation_id: &str) -> rusqlite::Result<Vec<OzNode>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {NODE_COLUMNS} FROM oz_nodes WHERE investigation_id = ?1 ORDER BY depth ASC, ordinal ASC"
    ))?;
    let raws = stmt
        .query_map([investigation_id], row_to_node_raw)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(raws.into_iter().filter_map(hydrate).collect())
}

/// Next stable sibling ordinal under `(investigation_id, parent_id)` — `parent_id = NULL`
/// for the root. Callers should call this once per node right before `insert_node` while
/// streaming, so ordinals stay gap-free and stream order == render order.
pub fn next_ordinal(
    db: &Db,
    investigation_id: &str,
    parent_id: Option<&str>,
) -> rusqlite::Result<i64> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let next: i64 = conn.query_row(
        "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM oz_nodes WHERE investigation_id = ?1 AND parent_id IS ?2",
        params![investigation_id, parent_id],
        |r| r.get(0),
    )?;
    Ok(next)
}

/// `(value, preview_signal_json, record_status_json, pre_reject_status_json, oz_type)`.
type EditFields = (String, Option<String>, String, Option<String>, String);

/// Reads the handful of columns `edit_node`/`reject_node`/`restore_node` need, without
/// paying for a full [`hydrate`].
fn fetch_edit_fields(conn: &Connection, id: &str) -> rusqlite::Result<Option<EditFields>> {
    conn.query_row(
        "SELECT value, preview_signal_json, record_status_json, pre_reject_status_json, oz_type
         FROM oz_nodes WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )
    .optional()
}

/// Records a **second (or later) route** to a value already in the tree, and returns how many
/// independent routes now reach it (the first path included, so the first rediscovery returns
/// `2`). `None` means the node does not exist.
///
/// A rediscovered value is
/// corroboration, not a duplicate to suppress. Before this existed, the fact was announced on
/// the `AlreadyInTree` SSE frame and stored nowhere, so every corroboration in an investigation
/// disappeared the moment it was reopened — invisibly, since the value itself was still there.
///
/// The same tool reached from the same parent is the same probe running twice and is **not**
/// counted again; a different tool, or the same tool from a different parent, is a genuinely
/// different route. The node's own [`crate::types::Provenance`] is the first route and is
/// never duplicated into the list.
pub fn record_corroboration(
    db: &Db,
    node_id: &str,
    corroboration: &Corroboration,
    annotation: &str,
) -> rusqlite::Result<Option<usize>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let Some((existing_json, source_tool_id, found_via_parent_id)) = conn
        .query_row(
            "SELECT corroborations_json, source_tool_id, found_via_parent_id FROM oz_nodes WHERE id = ?1",
            [node_id],
            |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };

    let mut list: Vec<Corroboration> = existing_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let is_first_route = source_tool_id == corroboration.tool_id
        && found_via_parent_id.as_deref() == Some(corroboration.parent_node_id.as_str());
    let already_listed = list
        .iter()
        .any(|c| c.same_route_as(&corroboration.tool_id, &corroboration.parent_node_id));
    if !is_first_route && !already_listed {
        list.push(corroboration.clone());
    }

    conn.execute(
        "UPDATE oz_nodes SET corroborations_json = ?1, already_in_tree = ?2 WHERE id = ?3",
        params![
            serde_json::to_string(&list).expect("corroborations always serialise"),
            annotation,
            node_id
        ],
    )?;
    Ok(Some(1 + list.len()))
}

/// Stores one completed evidence check on a node, replacing any earlier record for the same
/// URL. Returns the node's full record list, or `None` when the node does not exist.
///
/// Writes through the connection lock in one pass, like [`record_corroboration`], rather than
/// reading the node and writing it back: an evidence check takes tens of seconds, and a
/// read-modify-write spanning that window would silently drop whatever an edit or a refresh
/// wrote to the node in the meantime.
pub fn record_evidence(
    db: &Db,
    node_id: &str,
    record: crate::evidence::EvidenceRecord,
) -> rusqlite::Result<Option<Vec<crate::evidence::EvidenceRecord>>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let Some(existing_json) = conn
        .query_row(
            "SELECT evidence_json FROM oz_nodes WHERE id = ?1",
            [node_id],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
    else {
        return Ok(None);
    };

    let mut list: Vec<crate::evidence::EvidenceRecord> = existing_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    crate::evidence::merge_records(&mut list, record);

    conn.execute(
        "UPDATE oz_nodes SET evidence_json = ?1 WHERE id = ?2",
        params![
            serde_json::to_string(&list).expect("evidence always serialises"),
            node_id
        ],
    )?;
    Ok(Some(list))
}

/// Re-types a **root** node after the analyst corrected its value, and moves the
/// investigation's seed with it.
///
/// `edit_node` re-derives `dedup_key` but leaves `oz_type` alone, which is right for a *found*
/// node — the tool that produced it already decided what it was. It is wrong for a root: the
/// root's type came from the classifier reading the analyst's own seed, so editing
/// `kilnwright` into `8.8.8.8` left an investigation whose `seed_type` still said `Username`
/// and a root node still shaped like one. Nothing surfaced that; the whole tree simply planned
/// the wrong tools. Settled 2026-08-23.
///
/// The payload is reset to [`OzPayload::empty_for`] the new type because an `OzPayload` is a
/// tagged union keyed on exactly this: a `Username` payload under a node now claiming to be an
/// `Ip` does not render stale, it renders as a different entity's findings. **The caller must
/// therefore refuse this on a root that already carries findings** — see
/// `routes::ozint::node::edit`, which answers `409` rather than destroy them.
///
/// `seed_input` follows the analyst's corrected value, because that is what the seed now *is*;
/// the node's own `value` column stays as first entered, per this unit's nothing-is-deleted
/// rule, with the original preserved in `record_status`.
pub fn retype_root(
    db: &Db,
    node_id: &str,
    investigation_id: &str,
    new_type: OzType,
    new_value: &str,
) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let payload_json = serde_json::to_string(&OzPayload::empty_for(new_type))
        .expect("OzPayload always serialises");
    let changed = conn.execute(
        "UPDATE oz_nodes SET oz_type = ?1, dedup_key = ?2, payload_json = ?3 WHERE id = ?4",
        params![
            ser_enum(&new_type),
            crate::normalize::dedup_key(new_type, new_value),
            payload_json,
            node_id
        ],
    )?;
    if changed == 0 {
        return Ok(false);
    }
    conn.execute(
        "UPDATE oz_investigations SET seed_input = ?1, seed_type = ?2, updated_at = ?3 WHERE id = ?4",
        params![new_value, ser_enum(&new_type), Utc::now().timestamp(), investigation_id],
    )?;
    Ok(true)
}

/// Analyst SAVE. The `value` column — what the tool actually returned —
/// is **never** written here; only `edited_value` and `provenance.record_status` change.
/// Moves a node's lifecycle status — the status of the layer fired **from** it, not a
/// judgment on its value. Written when that layer settles, so a rehydrated tree shows the
/// same `Empty`/`Failed` distinction the live stream did.
pub fn set_node_status(db: &Db, id: &str, status: NodeStatus) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let changed = conn.execute(
        "UPDATE oz_nodes SET status = ?1 WHERE id = ?2",
        params![ser_enum(&status), id],
    )?;
    Ok(changed > 0)
}

/// Re-editing an already-corrected node keeps the *first* correction's
/// `original_value`/`original_chip` (the original is what the tool returned, not what a
/// previous edit set it to) — only `edited_value`/`edited_at` move on a second SAVE.
/// Returns `false` if the node doesn't exist.
///
/// **The dedup key moves with the correction.** An analyst SAVE re-derives the dedup key,
/// and the reason is worth stating: the key is what
/// the visited-set dedup matches a newly-found value against. Left on the old, wrong value, a
/// correction produces two silent errors at once — a later layer finding the *corrected*
/// value creates a duplicate node for an entity already in the tree, while one finding the
/// *original, wrong* value is suppressed as "already in tree" and annotated onto a node that
/// no longer claims it. Neither surfaces as an error; both corrupt the tree quietly.
///
/// `value`, `display` and the original chip stay exactly as the tool returned them — the
/// correction lives in `edited_value` + `record_status`, per the unit's "nothing is deleted"
/// rule. Only the key derived *from* the value follows the analyst.
///
/// ⚠️ **Callers must refuse this on a rejected node.** `RecordStatus` has one slot, so writing
/// `Corrected` over `Rejected` here silently discards the analyst's "this is wrong" and puts
/// the node back into the subject file and relation inference with no trace. The single caller
/// (`routes::ozint::node::edit`) answers `409` and asks for a RESTORE first; this function does
/// not enforce it itself only because its `Result<bool>` has no room for a third outcome.
pub fn edit_node(db: &Db, id: &str, new_value: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let Some((value, preview_signal_json, record_status_json, _, oz_type_raw)) =
        fetch_edit_fields(&conn, id)?
    else {
        return Ok(false);
    };
    let existing: RecordStatus = serde_json::from_str(&record_status_json).unwrap_or_default();
    let (original_value, original_chip) = match existing {
        RecordStatus::Corrected {
            original_value,
            original_chip,
            ..
        } => (original_value, original_chip),
        _ => {
            let chip: Option<SignalChip> = preview_signal_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());
            (value, chip)
        }
    };
    let new_status = RecordStatus::Corrected {
        original_value,
        original_chip,
        edited_at: Utc::now(),
    };
    let new_status_json =
        serde_json::to_string(&new_status).expect("RecordStatus always serialises");

    // An `oz_type` this build no longer parses leaves the key alone rather than guessing:
    // a stale key is a known, bounded wrongness; a key derived under the wrong type is a new
    // one. `hydrate` already skips such rows loudly (see `unparseable_oz_type_skips_the_row`).
    let new_dedup_key = de_enum::<OzType>(&oz_type_raw)
        .ok()
        .map(|t| crate::normalize::dedup_key(t, new_value));

    let changed = match &new_dedup_key {
        Some(key) => conn.execute(
            "UPDATE oz_nodes SET record_status_json = ?1, edited_value = ?2, dedup_key = ?3 WHERE id = ?4",
            params![new_status_json, new_value, key, id],
        )?,
        None => conn.execute(
            "UPDATE oz_nodes SET record_status_json = ?1, edited_value = ?2 WHERE id = ?3",
            params![new_status_json, new_value, id],
        )?,
    };
    Ok(changed > 0)
}

/// Analyst MARK WRONG. Nothing is ever deleted: the pre-rejection
/// `record_status_json` is stashed in `pre_reject_status_json` (see the doc on
/// `ensure_tables`) precisely so [`restore_node`] can undo *only* the rejection — if the
/// node was `Corrected` before being rejected, restoring must bring the correction back,
/// not drop to `AsReturned`. Idempotent: rejecting an already-rejected node is a no-op that
/// still returns `true`. Returns `false` only if the node doesn't exist.
pub fn reject_node(db: &Db, id: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let Some((_, _, record_status_json, _, _)) = fetch_edit_fields(&conn, id)? else {
        return Ok(false);
    };
    let existing: RecordStatus = serde_json::from_str(&record_status_json).unwrap_or_default();
    if existing.is_rejected() {
        return Ok(true);
    }
    let rejected_json = serde_json::to_string(&RecordStatus::Rejected {
        rejected_at: Utc::now(),
    })
    .expect("RecordStatus always serialises");
    let changed = conn.execute(
        "UPDATE oz_nodes SET record_status_json = ?1, pre_reject_status_json = ?2 WHERE id = ?3",
        params![rejected_json, record_status_json, id],
    )?;
    Ok(changed > 0)
}

/// Undoes a rejection only, restoring whichever `record_status` (`AsReturned` or
/// `Corrected`) preceded it and clearing the stash. A correction is never touched by this
/// call. No-op (returns `true`) if the node isn't currently rejected; `false` if it doesn't
/// exist.
pub fn restore_node(db: &Db, id: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let Some((_, _, record_status_json, pre_reject_status_json, _)) = fetch_edit_fields(&conn, id)?
    else {
        return Ok(false);
    };
    let existing: RecordStatus = serde_json::from_str(&record_status_json).unwrap_or_default();
    if !existing.is_rejected() {
        return Ok(true);
    }
    let restored = pre_reject_status_json.unwrap_or_else(|| {
        serde_json::to_string(&RecordStatus::AsReturned).expect("RecordStatus always serialises")
    });
    let changed = conn.execute(
        "UPDATE oz_nodes SET record_status_json = ?1, pre_reject_status_json = NULL WHERE id = ?2",
        params![restored, id],
    )?;
    Ok(changed > 0)
}

// ─── Layers ──────────────────────────────────────────────────────────────────

/// A layer row. `status` is stored/returned as an opaque string rather than a typed enum:
/// that type belongs to `outcome.rs` (written by another unit in parallel), and this module
/// deliberately does not depend on it — see the crate-level task note on staying decoupled
/// from `ToolReport`. `tool_reports_json` is likewise opaque JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct OzLayerRow {
    pub id: String,
    pub investigation_id: String,
    pub parent_node_id: String,
    pub oz_type: OzType,
    pub value: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub settled_at: Option<DateTime<Utc>>,
    pub new_children: i64,
    pub tool_reports_json: Option<String>,
    pub summary: Option<String>,
}

const LAYER_COLUMNS: &str = "id, investigation_id, parent_node_id, oz_type, value, status, started_at, settled_at, new_children, tool_reports_json, summary";

struct LayerRaw {
    id: String,
    investigation_id: String,
    parent_node_id: String,
    oz_type: String,
    value: String,
    status: String,
    started_at: i64,
    settled_at: Option<i64>,
    new_children: i64,
    tool_reports_json: Option<String>,
    summary: Option<String>,
}

fn row_to_layer_raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<LayerRaw> {
    Ok(LayerRaw {
        id: row.get(0)?,
        investigation_id: row.get(1)?,
        parent_node_id: row.get(2)?,
        oz_type: row.get(3)?,
        value: row.get(4)?,
        status: row.get(5)?,
        started_at: row.get(6)?,
        settled_at: row.get(7)?,
        new_children: row.get(8)?,
        tool_reports_json: row.get(9)?,
        summary: row.get(10)?,
    })
}

/// Same registry-tolerance policy as node hydration: an unparseable `oz_type` skips the
/// row with a warning rather than failing the whole listing.
fn hydrate_layer(raw: LayerRaw) -> Option<OzLayerRow> {
    let oz_type = match de_enum::<OzType>(&raw.oz_type) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(layer_id = %raw.id, oz_type = %raw.oz_type, error = %e, "skipping layer: unparseable oz_type");
            return None;
        }
    };
    Some(OzLayerRow {
        id: raw.id,
        investigation_id: raw.investigation_id,
        parent_node_id: raw.parent_node_id,
        oz_type,
        value: raw.value,
        status: raw.status,
        started_at: from_millis(raw.started_at),
        settled_at: raw.settled_at.map(from_millis),
        new_children: raw.new_children,
        tool_reports_json: raw.tool_reports_json,
        summary: raw.summary,
    })
}

/// Insert-at-start: a layer begins with no `settled_at`, no children yet and no summary.
/// Eight arguments is one over clippy's default threshold — every one is a distinct,
/// independently-required column with no natural sub-grouping (unlike e.g. lat/lon), so a
/// wrapper struct would just move the same fields one level out without adding clarity.
#[allow(clippy::too_many_arguments)]
pub fn insert_layer(
    db: &Db,
    id: &str,
    investigation_id: &str,
    parent_node_id: &str,
    oz_type: OzType,
    value: &str,
    status: &str,
    started_at: DateTime<Utc>,
) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    conn.execute(
        "INSERT INTO oz_layers (id, investigation_id, parent_node_id, oz_type, value, status, started_at, new_children)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
        params![id, investigation_id, parent_node_id, ser_enum(&oz_type), value, status, to_millis(started_at)],
    )?;
    Ok(())
}

/// Update-at-settle: status/settled_at/new_children/tool_reports move together when a
/// layer finishes (settled/empty/degraded/failed/aborted).
pub fn settle_layer(
    db: &Db,
    layer_id: &str,
    status: &str,
    settled_at: DateTime<Utc>,
    new_children: i64,
    tool_reports_json: Option<&str>,
) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let changed = conn.execute(
        "UPDATE oz_layers SET status = ?1, settled_at = ?2, new_children = ?3, tool_reports_json = ?4 WHERE id = ?5",
        params![status, to_millis(settled_at), new_children, tool_reports_json, layer_id],
    )?;
    Ok(changed > 0)
}

/// Attaches the LLM summary independently of `settle_layer` — the summary pass
/// is fire-and-attach and must never block or re-run the settle write.
pub fn attach_layer_summary(db: &Db, layer_id: &str, summary: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let changed = conn.execute(
        "UPDATE oz_layers SET summary = ?1 WHERE id = ?2",
        params![summary, layer_id],
    )?;
    Ok(changed > 0)
}

pub fn get_layer(db: &Db, id: &str) -> rusqlite::Result<Option<OzLayerRow>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {LAYER_COLUMNS} FROM oz_layers WHERE id = ?1"
    ))?;
    let raw = stmt.query_row([id], row_to_layer_raw).optional()?;
    Ok(raw.and_then(hydrate_layer))
}

/// All layers of an investigation, oldest first (fire order) — used to rehydrate layer
/// summaries/tool reports on history resume.
pub fn list_layers(db: &Db, investigation_id: &str) -> rusqlite::Result<Vec<OzLayerRow>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT {LAYER_COLUMNS} FROM oz_layers WHERE investigation_id = ?1 ORDER BY started_at ASC"
    ))?;
    let raws = stmt
        .query_map([investigation_id], row_to_layer_raw)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(raws.into_iter().filter_map(hydrate_layer).collect())
}

// ─── Tool cache (storage only — TTL policy belongs to `cache.rs`) ─────────────

pub fn get_cache_entry(
    db: &Db,
    tool_id: &str,
    cache_key: &str,
) -> rusqlite::Result<Option<(String, i64)>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    conn.query_row(
        "SELECT payload_json, retrieved_at FROM oz_tool_cache WHERE tool_id = ?1 AND cache_key = ?2",
        params![tool_id, cache_key],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

pub fn put_cache_entry(
    db: &Db,
    tool_id: &str,
    cache_key: &str,
    payload_json: &str,
    retrieved_at: i64,
    investigation_id: Option<&str>,
) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    conn.execute(
        "INSERT INTO oz_tool_cache (tool_id, cache_key, payload_json, retrieved_at, investigation_id)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(tool_id, cache_key) DO UPDATE SET
           payload_json = excluded.payload_json,
           retrieved_at = excluded.retrieved_at,
           investigation_id = excluded.investigation_id",
        params![tool_id, cache_key, payload_json, retrieved_at, investigation_id],
    )?;
    Ok(())
}

// ─── Quota (storage only — token-bucket/window logic belongs to `scheduler.rs`) ───────────

pub fn get_quota_usage(
    db: &Db,
    rate_key: &str,
    window_kind: &str,
) -> rusqlite::Result<Option<(i64, i64)>> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    conn.query_row(
        "SELECT window_start, used FROM oz_quota WHERE rate_key = ?1 AND window_kind = ?2",
        params![rate_key, window_kind],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

pub fn put_quota_usage(
    db: &Db,
    rate_key: &str,
    window_kind: &str,
    window_start: i64,
    used: i64,
) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    ensure_tables(&conn)?;
    conn.execute(
        "INSERT INTO oz_quota (rate_key, window_kind, window_start, used)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(rate_key, window_kind) DO UPDATE SET
           window_start = excluded.window_start,
           used = excluded.used",
        params![rate_key, window_kind, window_start, used],
    )?;
    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OzPayload, SignalTone, UsernamePayload};

    fn sample_investigation(id: &str) -> Investigation {
        Investigation {
            id: id.to_string(),
            seed_input: "mtrebosc".to_string(),
            seed_type: OzType::Username,
            root_node_id: format!("{id}-root"),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            lookups: 0,
            cost_cents: 0,
            spawned_from_investigation_id: None,
            spawned_from_relation: None,
        }
    }

    /// A node with every optional field populated: full payload, both signal chips, a
    /// section, a multi-tool provenance chain and a prior observation. This is the shape
    /// the round-trip test exercises, since a node with everything `None`/empty would not
    /// catch a JSON-column mapping bug.
    /// Truncated to millisecond precision, matching the `INTEGER` (epoch-ms) storage —
    /// `chrono::Utc::now()`'s sub-ms precision would otherwise make every round-trip
    /// comparison spuriously fail.
    fn now_ms() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap()
    }

    #[test]
    fn an_evidence_check_survives_a_reopen_and_a_re_check_replaces_it() {
        use crate::evidence::{CaptureOutcome, EvidenceRecord, Snapshot};

        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        insert_node(&db, &full_node("node-1", "inv-1", 0)).unwrap();

        // The empty-archive answer is the one worth pinning: it has no snapshots, so a
        // storage layer that only persisted snapshot lists would round-trip it as "never
        // checked" with nothing anywhere saying otherwise.
        let list = record_evidence(
            &db,
            "node-1",
            EvidenceRecord::new("https://x.test/a", CaptureOutcome::NeverArchived),
        )
        .unwrap()
        .expect("the node exists");
        assert_eq!(list.len(), 2, "the fixture already carries one record");

        let reopened = get_node(&db, "node-1").unwrap().unwrap();
        let stored = reopened
            .provenance
            .evidence
            .iter()
            .find(|r| r.url == "https://x.test/a")
            .expect("the check must survive the round trip");
        assert!(stored.answered(), "the archive answered; it holds nothing");
        assert!(stored.snapshots.is_empty());

        // Re-checking the same URL is that URL's current answer in full, not a second row.
        let snapshot = Snapshot {
            captured_at: now_ms(),
            url: "https://web.archive.org/web/20240101000000id_/https://x.test/a".into(),
            original: "https://x.test/a".into(),
            status: "200".into(),
            sha1_base32: "AAAA".into(),
            mime: None,
        };
        let list = record_evidence(
            &db,
            "node-1",
            EvidenceRecord::new("https://x.test/a", CaptureOutcome::Found(vec![snapshot])),
        )
        .unwrap()
        .unwrap();
        assert_eq!(list.len(), 2, "a re-check updates in place");
        let reopened = get_node(&db, "node-1").unwrap().unwrap();
        let stored = reopened
            .provenance
            .evidence
            .iter()
            .find(|r| r.url == "https://x.test/a")
            .unwrap();
        assert_eq!(stored.snapshots.len(), 1);
    }

    #[test]
    fn recording_evidence_on_a_node_that_does_not_exist_says_so_rather_than_inventing_a_row() {
        let db = ozint_db::open_memory().unwrap();
        let out = record_evidence(
            &db,
            "no-such-node",
            crate::evidence::EvidenceRecord::new(
                "https://x.test/",
                crate::evidence::CaptureOutcome::NeverArchived,
            ),
        )
        .unwrap();
        assert!(out.is_none());
    }

    fn full_node(id: &str, investigation_id: &str, ordinal: i64) -> OzNode {
        let payload = UsernamePayload {
            sites_checked: 312,
            sites_confirmed: 14,
            profile: vec![crate::types::OzRow {
                label: "Bio".to_string(),
                value: "OSINT enjoyer".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };

        OzNode {
            id: id.to_string(),
            investigation_id: investigation_id.to_string(),
            parent_id: None,
            layer_id: Some("layer-1".to_string()),
            ordinal,
            depth: 0,
            oz_type: OzType::Username,
            value: "mtrebosc".to_string(),
            display: "mtrebosc".to_string(),
            dedup_key: "username:mtrebosc".to_string(),
            payload: OzPayload::Username(payload),
            preview_signal: Some(
                SignalChip::new("14 / 312 sites", SignalTone::Warn).with_ratio(0.045),
            ),
            full_signal: Some(SignalChip::new("14 confirmed", SignalTone::Warn)),
            sections: vec![OzSection::new(
                "profile",
                "Profile",
                crate::types::SectionKind::KeyValue,
            )],
            gated: true,
            status: NodeStatus::Settled,
            provenance: Provenance {
                found_via_parent_id: None,
                source_tool_id: "wmn-probe".to_string(),
                method: "queried WhatsMyName's site list for the handle".to_string(),
                retrieved_at: now_ms(),
                record_status: RecordStatus::AsReturned,
                tool_chain: vec!["wmn-probe".to_string(), "gravatar".to_string()],
                gated: true,
                prior_observations: vec![PriorObservation {
                    value: "mtrebosc-old".to_string(),
                    chip: None,
                    observed_at: now_ms(),
                }],
                evidence: vec![crate::evidence::EvidenceRecord::new(
                    "https://github.com/mtrebosc",
                    crate::evidence::CaptureOutcome::NeverArchived,
                )],
            },
            already_in_tree: None,
            corroborations: Vec::new(),
            edited_value: None,
            created_at: now_ms(),
        }
    }

    #[test]
    fn ensure_tables_is_safely_callable_twice() {
        let db = ozint_db::open_memory().unwrap();
        let conn = db.lock().unwrap();
        ensure_tables(&conn).unwrap();
        ensure_tables(&conn).unwrap();
    }

    #[test]
    fn node_with_full_payload_and_provenance_round_trips() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        let node = full_node("node-1", "inv-1", 0);
        insert_node(&db, &node).unwrap();

        let back = get_node(&db, "node-1").unwrap().expect("node exists");
        assert_eq!(back, node);
    }

    #[test]
    fn streaming_inserts_keep_stable_sibling_ordering() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();

        // Simulate three children streaming in under the same parent, each asking for the
        // next ordinal right before insert — this must produce 0, 1, 2 in arrival order.
        for (i, id) in ["child-a", "child-b", "child-c"].iter().enumerate() {
            let ordinal = next_ordinal(&db, "inv-1", Some("root")).unwrap();
            assert_eq!(ordinal, i as i64);
            let mut n = full_node(id, "inv-1", ordinal);
            n.parent_id = Some("root".to_string());
            n.depth = 1;
            insert_node(&db, &n).unwrap();
        }

        let nodes = list_nodes(&db, "inv-1").unwrap();
        assert_eq!(
            nodes.iter().map(|n| n.id.clone()).collect::<Vec<_>>(),
            vec!["child-a", "child-b", "child-c"]
        );
    }

    #[test]
    fn next_ordinal_is_scoped_per_parent() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        assert_eq!(next_ordinal(&db, "inv-1", Some("parent-a")).unwrap(), 0);
        assert_eq!(next_ordinal(&db, "inv-1", None).unwrap(), 0); // root scope is independent
        let mut n = full_node("child-1", "inv-1", 0);
        n.parent_id = Some("parent-a".to_string());
        insert_node(&db, &n).unwrap();
        assert_eq!(next_ordinal(&db, "inv-1", Some("parent-a")).unwrap(), 1);
        assert_eq!(next_ordinal(&db, "inv-1", Some("parent-b")).unwrap(), 0);
    }

    #[test]
    fn edit_preserves_the_original_value_verbatim() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        let node = full_node("node-1", "inv-1", 0);
        insert_node(&db, &node).unwrap();

        assert!(edit_node(&db, "node-1", "m.trebosc").unwrap());
        let edited = get_node(&db, "node-1").unwrap().unwrap();
        assert_eq!(
            edited.value, "mtrebosc",
            "the raw `value` column must never be overwritten"
        );
        assert_eq!(edited.edited_value.as_deref(), Some("m.trebosc"));
        match edited.provenance.record_status {
            RecordStatus::Corrected { original_value, .. } => {
                assert_eq!(original_value, "mtrebosc")
            }
            other => panic!("expected Corrected, got {other:?}"),
        }

        // A second SAVE must keep the FIRST original_value, not the intermediate edit.
        assert!(edit_node(&db, "node-1", "m.trebosc.2").unwrap());
        let edited_again = get_node(&db, "node-1").unwrap().unwrap();
        assert_eq!(edited_again.edited_value.as_deref(), Some("m.trebosc.2"));
        match edited_again.provenance.record_status {
            RecordStatus::Corrected { original_value, .. } => {
                assert_eq!(original_value, "mtrebosc")
            }
            other => panic!("expected Corrected, got {other:?}"),
        }
    }

    #[test]
    fn edit_missing_node_returns_false() {
        let db = ozint_db::open_memory().unwrap();
        assert!(!edit_node(&db, "nope", "x").unwrap());
    }

    #[test]
    fn reject_then_restore_round_trips_to_as_returned() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        let node = full_node("node-1", "inv-1", 0);
        insert_node(&db, &node).unwrap();

        assert!(reject_node(&db, "node-1").unwrap());
        let rejected = get_node(&db, "node-1").unwrap().unwrap();
        assert!(rejected.provenance.record_status.is_rejected());
        assert!(!rejected.contributes());

        assert!(restore_node(&db, "node-1").unwrap());
        let restored = get_node(&db, "node-1").unwrap().unwrap();
        assert_eq!(restored.provenance.record_status, RecordStatus::AsReturned);
        assert!(restored.contributes());
    }

    #[test]
    fn a_correction_moves_the_dedup_key_onto_the_corrected_value() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        let node = full_node("node-1", "inv-1", 0);
        let original_key = node.dedup_key.clone();
        insert_node(&db, &node).unwrap();

        assert!(edit_node(&db, "node-1", "m.trebosc").unwrap());
        let edited = get_node(&db, "node-1").unwrap().unwrap();

        // The key is what the visited set matches a newly-found value against. Left on the
        // wrong value it both duplicates the corrected entity and suppresses the wrong one —
        // neither of which surfaces as an error.
        assert_eq!(
            edited.dedup_key,
            crate::normalize::dedup_key(edited.oz_type, "m.trebosc")
        );
        assert_ne!(edited.dedup_key, original_key);
        // ...while everything the tool returned stays verbatim.
        assert_eq!(edited.value, node.value);
        assert_eq!(edited.display, node.display);
    }

    #[test]
    fn a_rejection_leaves_the_dedup_key_alone() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        let node = full_node("node-1", "inv-1", 0);
        insert_node(&db, &node).unwrap();

        assert!(reject_node(&db, "node-1").unwrap());
        let rejected = get_node(&db, "node-1").unwrap().unwrap();
        assert_eq!(
            rejected.dedup_key, node.dedup_key,
            "a rejected node still occupies its value"
        );
    }

    #[test]
    fn restore_brings_back_a_correction_not_as_returned() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        let node = full_node("node-1", "inv-1", 0);
        insert_node(&db, &node).unwrap();

        assert!(edit_node(&db, "node-1", "m.trebosc").unwrap());
        assert!(reject_node(&db, "node-1").unwrap());
        let rejected = get_node(&db, "node-1").unwrap().unwrap();
        assert!(rejected.provenance.record_status.is_rejected());
        // Nothing is deleted: the correction data must still be sitting in edited_value.
        assert_eq!(rejected.edited_value.as_deref(), Some("m.trebosc"));

        assert!(restore_node(&db, "node-1").unwrap());
        let restored = get_node(&db, "node-1").unwrap().unwrap();
        match restored.provenance.record_status {
            RecordStatus::Corrected { original_value, .. } => {
                assert_eq!(original_value, "mtrebosc")
            }
            other => {
                panic!("restore must bring back the pre-rejection Corrected status, got {other:?}")
            }
        }
        assert_eq!(restored.edited_value.as_deref(), Some("m.trebosc"));
    }

    #[test]
    fn reject_is_idempotent_and_restore_noop_when_not_rejected() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        insert_node(&db, &full_node("node-1", "inv-1", 0)).unwrap();

        assert!(reject_node(&db, "node-1").unwrap());
        assert!(reject_node(&db, "node-1").unwrap()); // second reject: no-op, still true
        assert!(
            get_node(&db, "node-1")
                .unwrap()
                .unwrap()
                .provenance
                .record_status
                .is_rejected()
        );

        insert_node(&db, &full_node("node-2", "inv-1", 1)).unwrap();
        assert!(restore_node(&db, "node-2").unwrap()); // never rejected: no-op, still true
        assert_eq!(
            get_node(&db, "node-2")
                .unwrap()
                .unwrap()
                .provenance
                .record_status,
            RecordStatus::AsReturned
        );
    }

    #[test]
    fn unknown_source_tool_id_still_hydrates() {
        // Registry-version tolerance: source_tool_id is never validated against a live
        // registry by this module, so a tool that has since been removed from the registry
        // must not prevent the node from loading.
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        let mut node = full_node("node-1", "inv-1", 0);
        node.provenance.source_tool_id = "ghost-tool-removed-from-registry-v0".to_string();
        node.provenance.tool_chain = vec!["ghost-tool-removed-from-registry-v0".to_string()];
        insert_node(&db, &node).unwrap();

        let back = get_node(&db, "node-1")
            .unwrap()
            .expect("node still hydrates");
        assert_eq!(
            back.provenance.source_tool_id,
            "ghost-tool-removed-from-registry-v0"
        );
    }

    #[test]
    fn unparseable_oz_type_skips_the_row_instead_of_failing_the_load() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        insert_node(&db, &full_node("good", "inv-1", 0)).unwrap();
        {
            let conn = db.lock().unwrap();
            ensure_tables(&conn).unwrap();
            // Hand-craft a corrupt row: an oz_type string that no longer exists in the enum
            // (simulating a schema/enum drift the registry-tolerance contract must survive).
            conn.execute(
                "INSERT INTO oz_nodes (id, investigation_id, parent_id, layer_id, ordinal, depth, oz_type, value,
                    display, dedup_key, payload_json, status, created_at, source_tool_id, method, retrieved_at,
                    record_status_json, tool_chain_json, gated)
                 VALUES ('bad', 'inv-1', NULL, NULL, 1, 0, 'no-longer-a-type', 'x', 'x', 'x', '{}', 'idle', 0,
                    'ghost', 'm', 0, '{\"kind\":\"as-returned\"}', '[]', 0)",
                [],
            )
            .unwrap();
        }

        let nodes = list_nodes(&db, "inv-1").unwrap();
        assert_eq!(
            nodes.len(),
            1,
            "the corrupt row must be skipped, not crash the whole load"
        );
        assert_eq!(nodes[0].id, "good");
        assert!(get_node(&db, "bad").unwrap().is_none());
    }

    #[test]
    fn investigation_create_get_and_list_newest_first() {
        let db = ozint_db::open_memory().unwrap();
        let mut a = sample_investigation("a");
        a.created_at = DateTime::<Utc>::from_timestamp_millis(1_000).unwrap();
        a.updated_at = a.created_at;
        let mut b = sample_investigation("b");
        b.created_at = DateTime::<Utc>::from_timestamp_millis(2_000).unwrap();
        b.updated_at = b.created_at;
        create_investigation(&db, &a).unwrap();
        create_investigation(&db, &b).unwrap();

        assert_eq!(
            get_investigation(&db, "a").unwrap().unwrap().seed_input,
            "mtrebosc"
        );
        let listed = list_investigations(&db, 10).unwrap();
        assert_eq!(
            listed.iter().map(|i| i.id.clone()).collect::<Vec<_>>(),
            vec!["b", "a"]
        );
    }

    #[test]
    fn bump_usage_accumulates_and_touch_updates_timestamp() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();

        bump_investigation_usage(&db, "inv-1", 5, 120, Utc::now()).unwrap();
        bump_investigation_usage(&db, "inv-1", 3, 30, Utc::now()).unwrap();
        let inv = get_investigation(&db, "inv-1").unwrap().unwrap();
        assert_eq!(inv.lookups, 8);
        assert_eq!(inv.cost_cents, 150);

        let later = DateTime::<Utc>::from_timestamp_millis(9_999_999).unwrap();
        touch_investigation(&db, "inv-1", later).unwrap();
        assert_eq!(
            get_investigation(&db, "inv-1").unwrap().unwrap().updated_at,
            later
        );
    }

    #[test]
    fn layer_lifecycle_insert_settle_and_attach_summary() {
        let db = ozint_db::open_memory().unwrap();
        create_investigation(&db, &sample_investigation("inv-1")).unwrap();
        let started = Utc::now();
        insert_layer(
            &db,
            "layer-1",
            "inv-1",
            "root",
            OzType::Username,
            "mtrebosc",
            "running",
            started,
        )
        .unwrap();

        let mid = get_layer(&db, "layer-1").unwrap().unwrap();
        assert_eq!(mid.status, "running");
        assert!(mid.settled_at.is_none());

        let settled_at = Utc::now();
        assert!(
            settle_layer(
                &db,
                "layer-1",
                "settled",
                settled_at,
                3,
                Some(r#"[{"toolId":"wmn-probe"}]"#)
            )
            .unwrap()
        );
        assert!(attach_layer_summary(&db, "layer-1", "Found 3 confirmed accounts.").unwrap());

        let done = get_layer(&db, "layer-1").unwrap().unwrap();
        assert_eq!(done.status, "settled");
        assert_eq!(done.new_children, 3);
        assert!(done.settled_at.is_some());
        assert_eq!(done.summary.as_deref(), Some("Found 3 confirmed accounts."));
        assert_eq!(
            done.tool_reports_json.as_deref(),
            Some(r#"[{"toolId":"wmn-probe"}]"#)
        );

        let listed = list_layers(&db, "inv-1").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "layer-1");
    }

    #[test]
    fn cache_and_quota_are_bare_get_put_storage() {
        let db = ozint_db::open_memory().unwrap();
        assert_eq!(get_cache_entry(&db, "wmn-probe", "mtrebosc").unwrap(), None);
        put_cache_entry(
            &db,
            "wmn-probe",
            "mtrebosc",
            r#"{"hits":14}"#,
            1_000,
            Some("inv-1"),
        )
        .unwrap();
        assert_eq!(
            get_cache_entry(&db, "wmn-probe", "mtrebosc").unwrap(),
            Some((r#"{"hits":14}"#.to_string(), 1_000))
        );
        // put again overwrites in place (bare storage, no TTL policy here)
        put_cache_entry(&db, "wmn-probe", "mtrebosc", r#"{"hits":15}"#, 2_000, None).unwrap();
        assert_eq!(
            get_cache_entry(&db, "wmn-probe", "mtrebosc").unwrap(),
            Some((r#"{"hits":15}"#.to_string(), 2_000))
        );

        assert_eq!(get_quota_usage(&db, "wmn-probe", "minute").unwrap(), None);
        put_quota_usage(&db, "wmn-probe", "minute", 60_000, 40).unwrap();
        assert_eq!(
            get_quota_usage(&db, "wmn-probe", "minute").unwrap(),
            Some((60_000, 40))
        );
        put_quota_usage(&db, "wmn-probe", "minute", 120_000, 1).unwrap();
        assert_eq!(
            get_quota_usage(&db, "wmn-probe", "minute").unwrap(),
            Some((120_000, 1))
        );
    }
}
