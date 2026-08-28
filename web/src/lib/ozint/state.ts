/**
 * The cockpit's tree state, and the pure reduction of one SSE frame onto it.
 *
 * Kept free of `fetch`, timers and React so the whole event contract can be
 * exercised without a network — `store.ts` is the thin shell that owns the
 * stream and the subscriptions.
 *
 * The frames arrive multiplexed: `POST /api/ozint/fire` opens one stream per
 * investigation and several layers can be in flight inside it at once, so every
 * frame is routed by `layerId` and nothing may assume a single active layer.
 */

import type {
  Corroboration,
  LayerEvent,
  OzNode,
  OzSection,
  SignalChip,
  ToolReport,
} from "@/lib/ozint/stream-parser";

import type { SettleKind } from "./outcomes";

/**
 * `firing` and the five `SettleKind`s are the live vocabulary. `interrupted` is
 * the sixth, and it only ever comes out of storage: `oz_layers.status` is
 * written `running` when a layer starts and only overwritten when it settles,
 * so a layer whose process died mid-flight is still `running` on disk forever.
 *
 * Rendering that as `firing` would draw a spinner for a layer nobody is running
 * — the cockpit's own version of a silent failure. It gets its own word instead.
 */
export type LayerStatus = "firing" | "interrupted" | SettleKind;

export interface LayerState {
  id: string;
  investigationId: string;
  parentNodeId: string;
  status: LayerStatus;
  /** Tools the plan intends to fire. */
  firing: number;
  /** Tools the plan could have fired if every key were armed and every circuit closed. */
  maxPossible: number;
  /** How many of them are ethically gated. */
  gated: number;
  /** Tool ids currently running, in start order. */
  running: string[];
  /** One report per tool, authoritative once the layer settles. */
  reports: ToolReport[];
  newChildren: number;
  summary?: { text: string; fallback: boolean };
  startedAt: number;
  /**
   * The stored tool reports exist but no longer parse — the server's own
   * `reportsUnreadable` flag. Without it a layer whose record was written by a
   * build that named its outcomes differently comes back with `reports: []`,
   * which is indistinguishable from a layer that ran no tools at all.
   */
  reportsUnreadable?: boolean;
  /**
   * This layer was read back from storage rather than watched. `firing`,
   * `maxPossible` and `gated` are the *plan*'s counts and the plan is not
   * persisted — only its reports are — so they are 0 here and mean "not
   * recorded", never "nothing was held back". Everything drawn from them is
   * suppressed rather than shown as a zero.
   */
  fromStorage?: boolean;
}

/**
 * Decision 9. A value found twice is annotated, never duplicated — and two
 * independent routes to the same entity is evidential reinforcement, so the
 * node carries a visible marker rather than a hidden provenance row.
 *
 * The wire names the re-finding tool: `LayerEvent::AlreadyInTree` carries a
 * `foundAgainBy: Corroboration` (tool, method, parent, layer, timestamp) and,
 * when the server could count them, a `paths` total. The first route is the
 * node's own `provenance`; these are every route after it. So the marker's
 * `└ via github-user` lines are read off the wire, never inferred.
 *
 * `paths` is left `undefined` when the server omits it rather than being
 * defaulted — a path count we did not receive is not a path count of one.
 */
export interface NodeCorroboration {
  /** Verbatim annotations, one per re-discovery. */
  annotations: string[];
  /** Layer ids the re-discoveries came from. */
  layerIds: string[];
  /** The routes themselves, in arrival order — this is what the card lists. */
  foundAgainBy: Corroboration[];
  /** The server's own total, when it sent one. */
  paths?: number;
}

export interface StreamError {
  layerId?: string;
  message: string;
}

export interface OzintTreeState {
  investigationId: string | null;
  rootNodeId: string | null;
  nodes: Record<string, OzNode>;
  /** Parent node id → child node ids, in arrival order. */
  children: Record<string, string[]>;
  layers: Record<string, LayerState>;
  /** Parent node id → its most recent layer id. */
  layerByParent: Record<string, string>;
  corroborations: Record<string, NodeCorroboration>;
  errors: StreamError[];
}

export function emptyTreeState(): OzintTreeState {
  return {
    investigationId: null,
    rootNodeId: null,
    nodes: {},
    children: {},
    layers: {},
    layerByParent: {},
    corroborations: {},
    errors: [],
  };
}

const TERMINAL: Record<string, SettleKind> = {
  layerSettled: "settled",
  layerEmpty: "empty",
  layerDegraded: "degraded",
  layerFailed: "failed",
  layerAborted: "aborted",
};

/** Shallow JSON merge patch, which is the shape `parentPayload.patch` arrives in. */
function mergePatch(base: unknown, patch: unknown): unknown {
  if (
    typeof base !== "object" ||
    base === null ||
    Array.isArray(base) ||
    typeof patch !== "object" ||
    patch === null ||
    Array.isArray(patch)
  ) {
    return patch ?? base;
  }
  return { ...(base as object), ...(patch as object) };
}

/** Every node in the subtree rooted at `id`, `id` excluded. */
function descendants(state: OzintTreeState, id: string): string[] {
  const out: string[] = [];
  const stack = [...(state.children[id] ?? [])];
  const seen = new Set<string>();
  while (stack.length > 0) {
    const next = stack.pop()!;
    if (seen.has(next)) continue;
    seen.add(next);
    out.push(next);
    stack.push(...(state.children[next] ?? []));
  }
  return out;
}

/**
 * Apply one frame. Returns a new state object; the caller compares by identity,
 * so an event that changes nothing must return the state it was given.
 */
export function applyEvent(
  state: OzintTreeState,
  event: LayerEvent,
): OzintTreeState {
  switch (event.type) {
    case "layerStart": {
      // Re-continuing a node re-fires it and replaces its children, so the old
      // subtree goes with it — otherwise the previous run's findings would sit
      // under a layer that no longer claims them.
      const stale = descendants(state, event.parentNodeId);
      const nodes = { ...state.nodes };
      const children = { ...state.children };
      const corroborations = { ...state.corroborations };
      const layers = { ...state.layers };
      const layerByParent = { ...state.layerByParent };
      for (const id of stale) {
        delete nodes[id];
        delete children[id];
        delete corroborations[id];
        // A discarded descendant's own layer goes with it: left behind, it
        // would keep answering `layerFor` for a node that no longer exists,
        // and count as in flight forever if it never settled.
        const staleLayerId = layerByParent[id];
        if (staleLayerId) {
          delete layers[staleLayerId];
          delete layerByParent[id];
        }
      }
      children[event.parentNodeId] = [];

      // The parent's own previous layer goes too. It is unreachable the moment
      // `layerByParent` points at the new one, and if it never settled — a
      // re-continue during a run — it would otherwise read as in flight forever.
      const previousLayerId = layerByParent[event.parentNodeId];
      if (previousLayerId && previousLayerId !== event.layerId) {
        delete layers[previousLayerId];
      }

      const parent = nodes[event.parentNodeId];
      if (parent) {
        nodes[event.parentNodeId] = { ...parent, status: "running" };
      }

      return {
        ...state,
        investigationId: event.investigationId,
        nodes,
        children,
        corroborations,
        layers: {
          ...layers,
          [event.layerId]: {
            id: event.layerId,
            investigationId: event.investigationId,
            parentNodeId: event.parentNodeId,
            status: "firing",
            firing: event.firing,
            maxPossible: event.maxPossible,
            gated: event.gated,
            running: [],
            reports: [],
            newChildren: 0,
            startedAt: Date.now(),
          },
        },
        layerByParent: {
          ...layerByParent,
          [event.parentNodeId]: event.layerId,
        },
      };
    }

    case "toolStart": {
      const layer = state.layers[event.layerId];
      if (!layer) return state;
      return {
        ...state,
        layers: {
          ...state.layers,
          [event.layerId]: { ...layer, running: [...layer.running, event.toolId] },
        },
      };
    }

    case "toolDone": {
      const layer = state.layers[event.layerId];
      if (!layer) return state;
      return {
        ...state,
        layers: {
          ...state.layers,
          [event.layerId]: {
            ...layer,
            running: layer.running.filter((id) => id !== event.report.toolId),
            reports: [...layer.reports, event.report],
          },
        },
      };
    }

    case "node": {
      const node = event.node;
      const parentId = node.parentId;
      const children = { ...state.children };
      if (parentId) {
        const siblings = children[parentId] ?? [];
        children[parentId] = siblings.includes(node.id)
          ? siblings
          : [...siblings, node.id];
      }
      return {
        ...state,
        investigationId: state.investigationId ?? node.investigationId,
        rootNodeId: parentId ? state.rootNodeId : (state.rootNodeId ?? node.id),
        nodes: { ...state.nodes, [node.id]: node },
        children,
      };
    }

    case "parentPayload": {
      // Decision 7: the node you continued gets richer while its own layer
      // runs. The card is not frozen the instant it is drawn.
      const node = state.nodes[event.nodeId];
      if (!node) return state;
      const patched: OzNode = {
        ...node,
        payload: mergePatch(node.payload, event.patch) as OzNode["payload"],
      };
      if (event.previewSignal) {
        patched.previewSignal = event.previewSignal as SignalChip;
      }
      if (event.sections && event.sections.length > 0) {
        patched.sections = event.sections as OzSection[];
      }
      return { ...state, nodes: { ...state.nodes, [event.nodeId]: patched } };
    }

    case "alreadyInTree": {
      const existing = state.corroborations[event.existingNodeId] ?? {
        annotations: [],
        layerIds: [],
        foundAgainBy: [],
      };
      return {
        ...state,
        corroborations: {
          ...state.corroborations,
          [event.existingNodeId]: {
            annotations: [...existing.annotations, event.annotation],
            layerIds: [...existing.layerIds, event.layerId],
            foundAgainBy: [...existing.foundAgainBy, event.foundAgainBy],
            paths: event.paths ?? existing.paths,
          },
        },
      };
    }

    case "layerSettled":
    case "layerEmpty":
    case "layerDegraded":
    case "layerFailed":
    case "layerAborted": {
      const layer = state.layers[event.layerId];
      if (!layer) return state;
      const kind = TERMINAL[event.type];
      const newChildren =
        "newChildren" in event ? (event.newChildren as number) : 0;
      const nodes = { ...state.nodes };
      const parent = nodes[layer.parentNodeId];
      if (parent) nodes[layer.parentNodeId] = { ...parent, status: kind };
      return {
        ...state,
        nodes,
        layers: {
          ...state.layers,
          [event.layerId]: {
            ...layer,
            status: kind,
            running: [],
            // The terminal frame carries the authoritative report list, which
            // includes tools that never emitted a `toolDone` of their own —
            // the ones a kill switch reached first.
            reports: event.reports,
            newChildren,
          },
        },
      };
    }

    case "summary": {
      const layer = state.layers[event.layerId];
      if (!layer) return state;
      return {
        ...state,
        layers: {
          ...state.layers,
          [event.layerId]: {
            ...layer,
            summary: { text: event.text, fallback: event.fallback },
          },
        },
      };
    }

    case "error":
      return {
        ...state,
        errors: [...state.errors, { layerId: event.layerId, message: event.message }],
      };
  }
}

// ── Rehydration ─────────────────────────────────────────────────────────────

/**
 * One layer as `GET /api/ozint/investigations/{id}` serves it — the persisted
 * row, not a frame. `status` is deliberately a bare string on the wire (the
 * store keeps it opaque), so it is a bare string here and gets validated below.
 */
export interface StoredLayer {
  id: string;
  parentNodeId: string;
  status: string;
  startedAt: string;
  settledAt?: string;
  newChildren: number;
  reports: ToolReport[];
  reportsUnreadable?: boolean;
  summary?: string;
}

const STORED_SETTLE: Record<string, SettleKind> = {
  settled: "settled",
  empty: "empty",
  degraded: "degraded",
  failed: "failed",
  aborted: "aborted",
};

/**
 * Fold an investigation's stored layers into the tree, so a reopened
 * investigation shows the same bands — and the same per-tool lists — as one
 * watched live.
 *
 * Three things are deliberately *not* reconstructed, because storage does not
 * hold them and inventing them is the failure mode this cockpit exists to
 * avoid: the plan's counts (see `LayerState.fromStorage`), the live `running`
 * list, and a `running` status (see `LayerStatus`).
 *
 * A layer whose stored status is neither `running` nor a settle kind is a
 * record this build cannot read. It becomes `interrupted` *and* raises an
 * error, rather than being quietly dropped.
 *
 * Idempotent: re-adopting the same rows replaces them by id. A layer already
 * known from the live stream is left alone — what we watched is better evidence
 * than what was written down, and it is the only copy that still has its plan.
 */
export function adoptStoredLayers(
  state: OzintTreeState,
  investigationId: string,
  stored: readonly StoredLayer[],
): OzintTreeState {
  if (stored.length === 0) return state;

  const layers = { ...state.layers };
  const layerByParent = { ...state.layerByParent };
  const errors = [...state.errors];

  // Oldest first, so the newest layer on a parent is the one `layerByParent`
  // ends up pointing at — the same rule the live stream follows.
  const ordered = [...stored].sort(
    (a, b) => Date.parse(a.startedAt) - Date.parse(b.startedAt),
  );

  for (const row of ordered) {
    if (state.layers[row.id] && !state.layers[row.id].fromStorage) continue;

    let status: LayerStatus;
    if (row.status === "running") {
      status = "interrupted";
    } else if (STORED_SETTLE[row.status]) {
      status = STORED_SETTLE[row.status];
    } else {
      status = "interrupted";
      errors.push({
        layerId: row.id,
        message: `stored layer status "${row.status}" is not one this build knows — its verdict cannot be read`,
      });
    }

    if (row.reportsUnreadable) {
      errors.push({
        layerId: row.id,
        message:
          "the stored tool reports for this layer no longer parse — what ran cannot be recovered",
      });
    }

    const startedAt = Date.parse(row.startedAt);
    layers[row.id] = {
      id: row.id,
      investigationId,
      parentNodeId: row.parentNodeId,
      status,
      firing: 0,
      maxPossible: 0,
      gated: 0,
      running: [],
      reports: row.reports ?? [],
      newChildren: row.newChildren,
      summary: row.summary
        ? // `fallback` marks a canned note, and storage keeps only the text.
          // Read back it is simply a note; claiming it came from a model would
          // be a claim the row cannot support, so it is styled as the quieter
          // of the two.
          { text: row.summary, fallback: true }
        : undefined,
      startedAt: Number.isNaN(startedAt) ? 0 : startedAt,
      reportsUnreadable: row.reportsUnreadable === true,
      fromStorage: true,
    };
    layerByParent[row.parentNodeId] = row.id;
  }

  return { ...state, layers, layerByParent, errors };
}

// ── Derived views ───────────────────────────────────────────────────────────

/** Layers still running. Drives the status bar's in-flight dot and the kill switch. */
export function inFlightLayers(state: OzintTreeState): LayerState[] {
  return Object.values(state.layers).filter((l) => l.status === "firing");
}

export function layerFor(
  state: OzintTreeState,
  nodeId: string,
): LayerState | undefined {
  const id = state.layerByParent[nodeId];
  return id ? state.layers[id] : undefined;
}

/**
 * Decision 9's block, for one node: every route to this value after the first,
 * and how many routes there are in total.
 *
 * Two sources have to agree here. A re-discovery that happens while we watch
 * arrives as an `alreadyInTree` frame; one that happened in an earlier session
 * comes back on the node itself (`OzNode.corroborations`, persisted). A
 * reopened-then-re-fired investigation has both, so routes are de-duplicated on
 * the triple that identifies one — same tool, same layer, same instant.
 *
 * `paths` counts the node's own provenance plus the distinct routes, and is
 * preferred from the server when it sent a number.
 */
export function corroborationFor(
  state: OzintTreeState,
  nodeId: string,
): { routes: Corroboration[]; paths: number } | undefined {
  const persisted = state.nodes[nodeId]?.corroborations ?? [];
  const live = state.corroborations[nodeId];
  const routes: Corroboration[] = [];
  const seen = new Set<string>();
  for (const route of [...persisted, ...(live?.foundAgainBy ?? [])]) {
    const key = `${route.toolId} ${route.layerId} ${route.foundAt}`;
    if (seen.has(key)) continue;
    seen.add(key);
    routes.push(route);
  }
  if (routes.length === 0) return undefined;
  return { routes, paths: live?.paths ?? routes.length + 1 };
}

/**
 * The value to show: the analyst's correction when there is one, otherwise what
 * the tool returned. Mirrors `OzNode::effective_value` on the Rust side, which
 * is what the subject file and relation inference already read.
 *
 * `display` is **not** rewritten by a correction — `store::edit_node` writes
 * `edited_value` and re-derives the dedup key, and nothing else — so rendering
 * `display` after an edit would show the analyst the very value they corrected.
 */
export function effectiveValue(node: OzNode): string {
  return node.editedValue ?? node.display;
}

/** Deepest depth in the tree, root = 0. */
export function treeDepth(state: OzintTreeState): number {
  let max = 0;
  for (const node of Object.values(state.nodes)) {
    if (node.depth > max) max = node.depth;
  }
  return max;
}

export function nodeCount(state: OzintTreeState): number {
  return Object.keys(state.nodes).length;
}

/**
 * A node is *inert* when it was never continued while a sibling was — the
 * prototype's rule, kept because nothing disappears: an un-continued node stays
 * visible and dimmed rather than being cleaned away.
 */
export function isInert(state: OzintTreeState, nodeId: string): boolean {
  const node = state.nodes[nodeId];
  if (!node?.parentId) return false;
  if (state.layerByParent[nodeId]) return false;
  const siblings = state.children[node.parentId] ?? [];
  return siblings.some((id) => id !== nodeId && Boolean(state.layerByParent[id]));
}
