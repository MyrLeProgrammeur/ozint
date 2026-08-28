/**
 * OZINT investigation SSE stream — client half.
 *
 * The server half is `crates/ozint/src/runtime.rs` (`LayerEvent`, the wire union)
 * plus `outcome.rs` (`ToolReport`/`ToolOutcome`) and `types.rs` (`OzNode` and friends). This
 * file mirrors those types and adds the two things a browser needs that Rust doesn't:
 * an incremental frame reader (a `fetch` body arrives in arbitrary byte chunks, not frames)
 * and a demultiplexer (`POST /api/ozint/fire` opens one SSE stream per *investigation*, and
 * several layers can be running at once inside it — see `runtime.rs`'s module doc).
 *
 * Split precedent: `claude-stream-parser.ts` next to this file plays the same client-half
 * role for a code-agent stream.
 *
 * Field-casing note, because it is easy to get wrong by extrapolating from convention
 * instead of reading the actual `#[serde(...)]` attributes: every struct in this contract
 * renames to `camelCase`, and every enum tag renames to `kebab-case` — **except**
 * `ToolOutcome`'s struct-variant fields (`env_var`, `after_ms`, `retry_after`), which stay
 * raw snake_case. `#[serde(rename_all = "kebab-case")]` on an enum renames variant tags; it
 * only reaches into a struct variant's own fields when that variant carries its own
 * `#[serde(rename_all = ...)]`, and `ToolOutcome`'s variants don't. Verified empirically
 * (a throwaway `serde_json::to_value` probe test, run and reverted) rather than assumed from
 * the module doc's "structs camelCase" summary, which glosses over this exact case.
 */

// ── OzNode and its supporting types (types.rs) ──────────────────────────────

/** The twelve `OzType`/`OzPayload` tags (`types.rs`), verbatim as they hit the wire. */
export type OzType =
  | "username"
  | "email"
  | "phone"
  | "ip"
  | "domain"
  | "hash"
  | "image"
  | "video"
  | "coordinate"
  | "cve"
  | "directory"
  | "name";

export type SignalTone = "neutral" | "ok" | "warn" | "risk" | "critical" | "gated";

export interface SignalChip {
  text: string;
  tone: SignalTone;
  meta?: string;
  /** 0.0–1.0, present only when the chip renders as a bar. */
  ratio?: number;
}

export type SectionKind = "key-value" | "tags" | "timeline" | "links" | "media";

export interface OzRow {
  label: string;
  value: string;
  href?: string;
  /** ISO-8601, present only on `Timeline` rows. */
  at?: string;
  tone?: SignalTone;
  sourceToolId?: string;
  mediaId?: string;
  /** Omitted on the wire when `false` (`skip_serializing_if` on the Rust side) — treat an
   * absent value as `false`, not as unknown. */
  gated?: boolean;
}

export interface OzSection {
  id: string;
  label: string;
  kind: SectionKind;
  rows: OzRow[];
}

/**
 * `OzPayload` mirrors only the `type` discriminant from `types.rs`'s 11-variant union
 * (`UsernamePayload`, `EmailPayload`, … `DirectoryPayload`). This parser never branches on a
 * payload's per-type fields — it only routes and stores whole frames by `layerId` — so the
 * field bag stays a structural `Record<string, unknown>` here instead of duplicating all
 * eleven per-type payload structs. A future node-detail UI that needs field-level typing
 * should narrow this at that call site (e.g. `payload as UsernamePayloadFields`), not here.
 */
export interface OzPayload {
  type: OzType;
  [key: string]: unknown;
}

export type RecordStatus =
  | { kind: "as-returned" }
  | { kind: "corrected"; originalValue: string; originalChip?: SignalChip; editedAt: string }
  | { kind: "rejected"; rejectedAt: string };

export interface PriorObservation {
  value: string;
  chip?: SignalChip;
  /** ISO-8601. */
  observedAt: string;
}

export interface Provenance {
  foundViaParentId?: string;
  sourceToolId: string;
  method: string;
  /** ISO-8601. */
  retrievedAt: string;
  recordStatus: RecordStatus;
  toolChain?: string[];
  gated?: boolean;
  priorObservations?: PriorObservation[];
}

/**
 * One route by which a value was found — the second and later ones, since the first is the
 * node's own `provenance`. `Corroboration` in `types.rs`, plain camelCase.
 *
 * Corroboration needs the *name* of the tool that re-found a value, and this is where it comes
 * from: the annotation string alone (`already in tree · L2`) never carried it.
 */
export interface Corroboration {
  toolId: string;
  method: string;
  parentNodeId: string;
  layerId: string;
  /** ISO-8601. */
  foundAt: string;
  /** Omitted on the wire when `false` — absent means `false`, not unknown. */
  gated?: boolean;
}

export type NodeStatus = "idle" | "running" | "settled" | "empty" | "degraded" | "failed" | "aborted";

export interface OzNode {
  id: string;
  investigationId: string;
  parentId?: string;
  layerId?: string;
  ordinal: number;
  depth: number;
  /** `oz_type` on the Rust side, explicitly renamed to `type` on the wire. */
  type: OzType;
  value: string;
  display: string;
  dedupKey: string;
  payload: OzPayload;
  previewSignal?: SignalChip;
  fullSignal?: SignalChip;
  sections?: OzSection[];
  gated?: boolean;
  status: NodeStatus;
  provenance: Provenance;
  /** The node this one was found to already be. */
  alreadyInTree?: string;
  /**
   * Every route to this value after the first. Persisted on the node, so a reopened
   * investigation keeps its corroboration — the total path count is `1 + corroborations.length`.
   * Omitted on the wire when empty (`skip_serializing_if = "Vec::is_empty"`).
   */
  corroborations?: Corroboration[];
  editedValue?: string;
  /** ISO-8601. */
  createdAt: string;
}

// ── ToolOutcome / ToolReport (outcome.rs) ────────────────────────────────────

/**
 * The 11-variant tool outcome, tag `kind` (kebab-case). See the file-level note: these
 * struct-variant fields are the one place in the contract that stays snake_case.
 */
export type ToolOutcome =
  | { kind: "ok-with-results"; count: number }
  | { kind: "ok-empty" }
  | { kind: "skipped-no-key"; env_var: string }
  | { kind: "skipped-gated-unarmed"; env_var: string }
  | { kind: "skipped-phase-predicate"; reason: string }
  /**
   * The 13th variant: an upstream tool never published the `INPUT_*` key this one reads,
   * or two tools disputed it. Distinct from `ok-empty` (we asked and got nothing) and from
   * `skipped-no-key` (a configuration problem the analyst could fix).
   */
  | { kind: "skipped-missing-input"; input: string; reason: string }
  | { kind: "skipped-circuit-open"; retry_after?: string }
  | { kind: "rate-limited-dropped" }
  | { kind: "timeout"; after_ms: number }
  | { kind: "http-error"; status: number; message?: string }
  | { kind: "parse-error"; message: string }
  | { kind: "forbidden"; message?: string }
  /**
   * The kill switch reached this tool before the tool ran. Without it a cancelled layer's
   * report list simply omitted every tool it never got to, making "killed after 2 of 7" and
   * "the plan only had 2 tools" render identically.
   */
  | { kind: "cancelled" };

/** One tool's contribution to a layer. `ToolReport` itself is a plain camelCase struct. */
export interface ToolReport {
  toolId: string;
  label: string;
  outcome: ToolOutcome;
  elapsedMs: number;
  results: number;
  gated: boolean;
  method: string;
}

// ── LayerEvent (runtime.rs) — the frame union ────────────────────────────────

/**
 * One frame on the investigation's SSE stream, tag `type` (camelCase variant names, per
 * `LayerEvent`'s per-variant `#[serde(rename_all = "camelCase")]`). Every variant carries
 * `layerId` (optional only on `error`, matching `Option<String>` on the Rust side) so a
 * frame can always be routed — see `LayerEventRouter` below.
 */
export type LayerEvent =
  | {
      type: "layerStart";
      layerId: string;
      investigationId: string;
      parentNodeId: string;
      firing: number;
      maxPossible: number;
      /** Count of `maxPossible` that are ethically gated — a number, not a boolean. */
      gated: number;
    }
  | { type: "toolStart"; layerId: string; toolId: string; label: string; gated: boolean }
  | { type: "toolDone"; layerId: string; report: ToolReport }
  | {
      type: "parentPayload";
      layerId: string;
      nodeId: string;
      /** A JSON merge patch — shape depends on the node's `OzType`, never narrowed here. */
      patch: unknown;
      previewSignal?: SignalChip;
      /** Omitted by the server when empty (`skip_serializing_if = "Vec::is_empty"`). */
      sections?: OzSection[];
    }
  | { type: "node"; layerId: string; node: OzNode }
  | {
      type: "alreadyInTree";
      layerId: string;
      existingNodeId: string;
      annotation: string;
      /** The route that re-found the value: which tool, from which parent, when. */
      foundAgainBy: Corroboration;
      /** Total routes known to this value, the new one included. Omitted when the server
       * could not count them (`Option<usize>`), never defaulted to 1 here. */
      paths?: number;
    }
  | { type: "layerSettled"; layerId: string; newChildren: number; reports: ToolReport[] }
  | { type: "layerEmpty"; layerId: string; reports: ToolReport[] }
  | { type: "layerDegraded"; layerId: string; newChildren: number; reports: ToolReport[] }
  | { type: "layerFailed"; layerId: string; reports: ToolReport[] }
  | { type: "layerAborted"; layerId: string; reports: ToolReport[] }
  | { type: "summary"; layerId: string; text: string; fallback: boolean }
  | { type: "error"; layerId?: string; message: string };

/** Every valid `type` tag, used to reject a frame whose JSON parsed fine but isn't one of
 * these — the one shape check this parser does, since there is no schema-validation
 * dependency available to do more (see the "no new npm dependency" constraint). */
const LAYER_EVENT_TAGS: ReadonlySet<LayerEvent["type"]> = new Set([
  "layerStart",
  "toolStart",
  "toolDone",
  "parentPayload",
  "node",
  "alreadyInTree",
  "layerSettled",
  "layerEmpty",
  "layerDegraded",
  "layerFailed",
  "layerAborted",
  "summary",
  "error",
]);

const TERMINAL_TYPES: ReadonlySet<LayerEvent["type"]> = new Set([
  "layerSettled",
  "layerEmpty",
  "layerDegraded",
  "layerFailed",
  "layerAborted",
]);

/** Mirrors `LayerEvent::is_terminal()` in `runtime.rs`: whether this frame closes its layer.
 * `summary` is deliberately not terminal — it is allowed to arrive after the terminal frame. */
export function isTerminalLayerEvent(event: LayerEvent): boolean {
  return TERMINAL_TYPES.has(event.type);
}

function isLayerEventShape(value: unknown): value is LayerEvent {
  if (typeof value !== "object" || value === null || !("type" in value)) return false;
  const tag = (value as { type: unknown }).type;
  return typeof tag === "string" && LAYER_EVENT_TAGS.has(tag as LayerEvent["type"]);
}

// ── Frame parsing ─────────────────────────────────────────────────────────

/** A frame that could not be turned into a `LayerEvent` — bad JSON, no `data:` line, or an
 * unrecognised `type` tag. Carries enough to surface in the UI/logs; never thrown. */
export interface MalformedFrame {
  /** The raw text of the offending frame (post `data:` stripping when that succeeded). */
  raw: string;
  reason: string;
}

export type ParsedFrame = { ok: true; event: LayerEvent } | { ok: false; malformed: MalformedFrame };

/**
 * Parse one `\n\n`-delimited SSE block. The server (`runtime.rs`'s module doc) frames as
 * `data: <json>\n\n` with no `event:`/`id:`/`retry:` lines and no keep-alive comment pings —
 * so, unlike a general SSE client, this does not need to track a running event name or skip
 * `:`-prefixed comments. A block that doesn't fit that shape is reported, not swallowed: a
 * dropped frame nobody notices is how a layer appears to hang forever.
 */
function parseBlock(block: string): ParsedFrame | null {
  const trimmed = block.trim();
  if (trimmed.length === 0) return null;

  const dataLines = trimmed
    .split("\n")
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice("data:".length).trimStart());

  if (dataLines.length === 0) {
    return { ok: false, malformed: { raw: block, reason: "frame has no data: line" } };
  }

  // The server never sends multi-line data, but joining is the honest general SSE behaviour
  // if it ever did.
  const raw = dataLines.join("\n");

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { ok: false, malformed: { raw, reason: err instanceof Error ? err.message : "JSON.parse failed" } };
  }

  if (!isLayerEventShape(parsed)) {
    return { ok: false, malformed: { raw, reason: "parsed JSON has no recognised LayerEvent `type` tag" } };
  }

  return { ok: true, event: parsed };
}

/**
 * Incremental reader for the investigation SSE stream. `fetch`'s `ReadableStream` delivers
 * bytes in arbitrary chunks that have no relationship to frame boundaries — a chunk can end
 * mid-JSON — so this buffers across `push()` calls instead of parsing each chunk alone. This
 * is the entire reason an incremental parser exists rather than `JSON.parse` per chunk.
 */
export class OzintStreamReader {
  private buffer = "";

  /** Feed one decoded text chunk. Returns every frame completed by it, in order. A frame
   * still split across the chunk boundary stays buffered for the next `push()`. */
  push(chunk: string): ParsedFrame[] {
    this.buffer += chunk;
    const blocks = this.buffer.split("\n\n");
    // The last element is either "" (the buffer ended exactly on a `\n\n`) or a partial
    // block still waiting for its closing delimiter — either way, keep it buffered.
    this.buffer = blocks.pop() ?? "";

    const results: ParsedFrame[] = [];
    for (const block of blocks) {
      const frame = parseBlock(block);
      if (frame) results.push(frame);
    }
    return results;
  }

  /** Call once the underlying stream has ended. A well-behaved server always closes on a
   * `\n\n` boundary, so this normally returns nothing; it exists so a connection that drops
   * mid-frame still surfaces that partial frame as malformed instead of discarding it. */
  flush(): ParsedFrame[] {
    const leftover = this.buffer;
    this.buffer = "";
    const frame = parseBlock(leftover);
    return frame ? [frame] : [];
  }
}

// ── Demultiplexing by layer ──────────────────────────────────────────────────

/**
 * Groups a multiplexed investigation stream's events by `layerId`. Necessary because
 * `POST /api/ozint/fire` opens one SSE connection for the whole investigation and several
 * branches can be firing at once (`runtime.rs`'s module doc: "the cockpit's whole
 * interaction model is 'continue on this node', repeatedly, with multiple branches running
 * at once") — a UI driving one tree needs to know which node's layer a given frame updates.
 */
export class LayerEventRouter {
  private readonly byLayer = new Map<string, LayerEvent[]>();
  /** Stream-level `error` frames with no `layerId` — not attributable to one layer. */
  private readonly unrouted: LayerEvent[] = [];

  /** Route one event into its layer's history (or the unrouted bucket). */
  route(event: LayerEvent): void {
    const layerId = event.layerId;
    if (layerId === undefined) {
      this.unrouted.push(event);
      return;
    }
    const existing = this.byLayer.get(layerId);
    if (existing) {
      existing.push(event);
    } else {
      this.byLayer.set(layerId, [event]);
    }
  }

  /** Every event seen so far for one layer, in arrival order. */
  eventsFor(layerId: string): readonly LayerEvent[] {
    return this.byLayer.get(layerId) ?? [];
  }

  /** Stream-level events with no `layerId`. */
  unroutedEvents(): readonly LayerEvent[] {
    return this.unrouted;
  }

  /** Ids of every layer seen so far, in first-seen order. */
  layerIds(): readonly string[] {
    return [...this.byLayer.keys()];
  }

  /** Whether this layer's terminal event has arrived. A late `summary` may still follow. */
  isSettled(layerId: string): boolean {
    return this.eventsFor(layerId).some(isTerminalLayerEvent);
  }
}
