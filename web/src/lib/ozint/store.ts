"use client";

import { useSyncExternalStore } from "react";

import {
  OzintStreamReader,
  type MalformedFrame,
  type OzNode,
  type ToolReport,
} from "@/lib/ozint/stream-parser";

import {
  adoptStoredLayers,
  applyEvent,
  emptyTreeState,
  type OzintTreeState,
  type StoredLayer,
} from "./state";
import type { Investigation } from "./history";
import type { RelationReport } from "./relations";
import type { SubjectFileView } from "./subject-file";
import type { OzTypeName } from "./tokens";

/**
 * The cockpit's single live investigation, and the stream that feeds it.
 *
 * `state.ts` owns the reduction and knows nothing about the network; this is the
 * thin shell around it — one `fetch` against `POST /api/ozint/fire`, the
 * incremental frame reader, and the `useSyncExternalStore` subscription the
 *
 * One connection at a time. `POST /api/ozint/fire` multiplexes every layer of
 * an investigation onto a single SSE stream, so continuing a second node while
 * the first is still running is *not* a second connection — it is a second
 * `fire` call whose frames arrive interleaved on their own stream. Both are
 * reduced into the same tree, routed by `layerId`, which is why the reducer
 * never assumes a single active layer.
 */

/** What the connection is doing. Distinct from any individual layer's status. */
export type ConnectionStatus = "idle" | "streaming" | "closed" | "error";

export interface Meter {
  lookups: number;
  costCents: number;
  /**
   * How many layers the *server* believes are in flight.
   *
   * A number, not a boolean — verified against `routes/ozint/investigations.rs`,
   * which folds it live from the SSE events. Read as a boolean it was always
   * false, which is exactly the kind of silent nothing this cockpit is not
   * allowed to render. It is process-local and resets to 0 on a restart, so it
   * is the server's belief, never the ground truth about a past investigation.
   */
  inFlight: number;
}

export interface OzintStoreState {
  tree: OzintTreeState;
  status: ConnectionStatus;
  /** How many `fire` streams are open right now. */
  openStreams: number;
  /**
   * Frames that arrived but could not be understood. Surfaced, never swallowed:
   * a dropped frame nobody notices is how a layer appears to hang forever.
   */
  malformed: MalformedFrame[];
  /** Transport-level failure — the request itself, not an `error` frame. */
  transportError: string | null;
  /** Real lookups and real cost, from the server's own meter. */
  meter: Meter | null;
  /**
   * The subject-file rail, exactly as the server built it — including its
   * `notApplicable` answer, which is what makes the rail *absent* rather than
   * empty for a CVE or hash root. Null means we have not read it yet, which is
   * a third thing again and must not render as either of the other two.
   */
  subjectFile: SubjectFileView | null;
  /**
   * POTENTIAL RELATIONS — the subject file's neighbour. Re-derived server-side on
   * every read of `GET /api/ozint/investigations/{id}` and folded in here
   * exactly like the subject file: never accumulated from frames, always
   * whatever the last read said. `null` means never read yet — a CVE/hash
   * root can still legitimately answer an *empty* report, which is not the
   * same statement.
   */
  relations: RelationReport | null;
  /** Why `POST /api/ozint/spawn` failed, if it did. Never a silent no-op. */
  spawnError: string | null;
  /** True while a spawn request is in flight, so a card can disable itself. */
  spawning: boolean;
  /**
   * PAST INVESTIGATIONS. `null` means never asked — a third thing again, and
   * distinct from an empty list, which is the real answer "you have run none".
   */
  history: Investigation[] | null;
  historyLoading: boolean;
  /** Why the list could not be read. Never rendered as an empty history. */
  historyError: string | null;
  /** Why a reopen failed, if one did. */
  reopenError: string | null;
}

export interface FireRequest {
  /** A new investigation's seed value. Mutually exclusive with continuing. */
  seed?: string;
  /** Continuing an existing tree: both of these, together. */
  investigationId?: string;
  parentNodeId?: string;
  /** The LLM summary's opt-out. Absent means on, server-side. */
  showSummary?: boolean;
  /**
   * The type selector. Absent is the selector's *auto*, which behaves
   * exactly as before — the classifier decides. Set, it **replaces** the
   * classifier rather than biasing it, and the root node's provenance says so
   * (`ClassifyMethod::AnalystForced` → "typed by the analyst, type chosen by
   * the analyst").
   *
   * Only meaningful on the `seed` branch: continuing already has a typed parent
   * node, so there is nothing there to override.
   */
  ozType?: OzTypeName;
}

const EMPTY: OzintStoreState = {
  tree: emptyTreeState(),
  status: "idle",
  openStreams: 0,
  malformed: [],
  transportError: null,
  meter: null,
  subjectFile: null,
  relations: null,
  spawnError: null,
  spawning: false,
  history: null,
  historyLoading: false,
  historyError: null,
  reopenError: null,
};

let state: OzintStoreState = EMPTY;
const listeners = new Set<() => void>();
/** One controller per open stream, so a kill switch can drop them all. */
const controllers = new Set<AbortController>();

function notify(): void {
  for (const listener of listeners) listener();
}

function set(next: Partial<OzintStoreState>): void {
  state = { ...state, ...next };
  notify();
}

/** The five frames after which an investigation's persisted state can differ. */
const TERMINAL_FRAMES: ReadonlySet<string> = new Set([
  "layerSettled",
  "layerEmpty",
  "layerDegraded",
  "layerFailed",
  "layerAborted",
]);

/** The URL join used by every call here, kept in one place. */
function api(path: string): string {
  return `/api/ozint${path}`;
}

async function readMeter(investigationId: string): Promise<void> {
  try {
    const res = await fetch(api(`/investigations/${investigationId}/meter`), {
      cache: "no-store",
    });
    if (!res.ok) return;
    const body = (await res.json()) as Partial<Meter>;
    if (typeof body.lookups !== "number" || typeof body.costCents !== "number") {
      return;
    }
    set({
      meter: {
        lookups: body.lookups,
        costCents: body.costCents,
        inFlight: typeof body.inFlight === "number" ? body.inFlight : 0,
      },
    });
  } catch {
    // The meter is an ornament on the status bar; failing to read it must never
    // disturb a running investigation.
  }
}

/**
 * Pull an investigation's nodes from `GET /api/ozint/investigations/{id}` and
 * fold them in as if they had been streamed.
 *
 * **No longer load-bearing, and kept anyway.** This existed because the engine
 * never streamed a `node` frame for the node you fired on, so a client that
 * only reduced frames showed an empty canvas while a layer was visibly running.
 * `e52fd11` closed that at the source: a fire stream now opens with the fired
 * node itself, before `layerStart`, and a continue replays one `node` frame per
 * stored descendant after it.
 *
 * It stays because it is still the path that fills the canvas for an
 * investigation reopened in a new session, and because it is how the subject
 * file is read at all. Reducing a node twice is a no-op — the reducer upserts
 * on `node.id`, which the engine now documents as a contract rather than a
 * property of its emitter.
 *
 * Nodes are applied shallowest first so a child never arrives before the parent
 * it hangs from.
 */
async function hydrate(investigationId: string): Promise<void> {
  try {
    const res = await fetch(api(`/investigations/${investigationId}`), {
      cache: "no-store",
    });
    if (!res.ok) return;
    const body = (await res.json()) as {
      nodes?: OzNode[];
      layers?: StoredLayer[];
      subjectFile?: SubjectFileView;
      relations?: RelationReport;
    };

    // The subject file is rebuilt server-side from the whole tree on every read,
    // so this is also how the rail stays current: it is re-read each time a
    // layer settles, never accumulated client-side from frames. Kept outside
    // the `nodes` guard — a `notApplicable` file is an answer worth having even
    // when there is nothing else to fold in.
    if (body.subjectFile && typeof body.subjectFile.kind === "string") {
      set({ subjectFile: body.subjectFile });
    }
    // Same reasoning for relations: derived fresh on every read, so a
    // rejection drops a relation out for free the moment this next fires.
    if (body.relations && Array.isArray(body.relations.relations)) {
      set({ relations: body.relations });
    }

    const nodes = body.nodes;
    if (!Array.isArray(nodes) || nodes.length === 0) return;

    const ordered = [...nodes].sort(
      (a, b) => a.depth - b.depth || a.ordinal - b.ordinal,
    );
    let tree = state.tree;
    for (const node of ordered) {
      // A node the stream already delivered is re-applied harmlessly: the
      // reducer replaces it by id and never duplicates the child edge.
      tree = applyEvent(tree, {
        type: "node",
        layerId: node.layerId ?? "",
        node,
      });
    }
    // The bands, from the stored layer rows. A layer this session watched keeps
    // the live copy — it is the only one that still knows its plan — so this
    // only fills in the layers of an investigation reopened from history.
    if (Array.isArray(body.layers)) {
      tree = adoptStoredLayers(tree, investigationId, body.layers);
    }
    set({ tree });
  } catch {
    // A cockpit that cannot hydrate still reduces its stream; it must not lose
    // the layer it is watching because a second request failed.
  }
}

/** The server's own explanation of a refusal, falling back to the status code. */
async function describeFailure(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: unknown };
    if (typeof body.error === "string" && body.error.length > 0) {
      return body.error;
    }
  } catch {
    // A non-JSON body is not a second failure to report; the status still is.
  }
  return `HTTP ${res.status}`;
}

/**
 * Open one stream and reduce it. Resolves when the stream ends — the caller is
 * free to ignore the promise, since every result lands in the store.
 */
async function fire(request: FireRequest): Promise<void> {
  const controller = new AbortController();
  controllers.add(controller);
  set({
    status: "streaming",
    openStreams: state.openStreams + 1,
    transportError: null,
  });

  const reader = new OzintStreamReader();
  let investigationId = request.investigationId ?? null;
  /** Nodes we were told to fire on but have never seen. */
  let needsHydration: string | null = null;

  /** Reduce a batch of frames, then notify once — not once per frame. */
  const consume = (frames: ReturnType<OzintStreamReader["push"]>): void => {
    if (frames.length === 0) return;
    let tree = state.tree;
    let malformed = state.malformed;
    for (const frame of frames) {
      if (frame.ok) {
        if (
          frame.event.type === "layerStart" &&
          !tree.nodes[frame.event.parentNodeId]
        ) {
          // Unknown to us — a fresh seed, or an investigation reopened in a new
          // session. Either way the node itself will never come down the wire.
          needsHydration = frame.event.investigationId;
        }
        tree = applyEvent(tree, frame.event);
        if (frame.event.type === "layerStart") {
          investigationId = frame.event.investigationId;
        }
        // A settled layer is the moment the subject file can have changed, so
        // it is re-read then. The engine rebuilds it from the whole tree on
        // every read, which is why the rail is never accumulated from frames.
        if (TERMINAL_FRAMES.has(frame.event.type) && investigationId) {
          needsHydration = investigationId;
        }
      } else {
        malformed = [...malformed, frame.malformed];
      }
    }
    set({ tree, malformed });
    if (needsHydration) {
      const id = needsHydration;
      needsHydration = null;
      // Deliberately not awaited: the canvas fills in as soon as the fetch
      // lands, and the stream keeps being read meanwhile.
      void hydrate(id);
    }
  };

  try {
    const res = await fetch(api("/fire"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
      signal: controller.signal,
      cache: "no-store",
    });

    if (!res.ok || !res.body) {
      // The server's own sentence, not our paraphrase of a status code. Firing
      // an entity type with no orchestrator answers 501 with `no orchestrator is
      // built for EML nodes yet`, which tells the analyst the capability was
      // never built — where a bare `HTTP 501` reads as a transient failure of
      // something that exists. It is also why the type selector offers every
      // type with no client-side capability list: the server knows which types
      // have a plan, and a list mirrored here would drift out of date silently.
      const detail = res.ok
        ? "the response carried no body"
        : await describeFailure(res);
      set({ status: "error", transportError: `fire failed — ${detail}` });
      return;
    }

    const decoder = new TextDecoder();
    const body = res.body.getReader();
    for (;;) {
      const { done, value } = await body.read();
      if (done) break;
      consume(reader.push(decoder.decode(value, { stream: true })));
    }
    consume(reader.flush());
    set({ status: "closed" });
  } catch (err) {
    // An abort is the kill switch working, not a failure to report as one.
    if (controller.signal.aborted) {
      set({ status: "closed" });
    } else {
      set({
        status: "error",
        transportError: err instanceof Error ? err.message : String(err),
      });
    }
  } finally {
    controllers.delete(controller);
    set({ openStreams: Math.max(0, state.openStreams - 1) });
    if (investigationId) await readMeter(investigationId);
  }
}

/**
 * Ask the server to stop a layer, or the whole investigation. The stream stays
 * open: the engine answers a cancellation with `layerAborted` frames carrying
 * the authoritative report list, and dropping the connection here would throw
 * away exactly the record of what the kill switch reached.
 */
async function cancel(target: {
  investigationId?: string;
  layerId?: string;
}): Promise<boolean> {
  try {
    const res = await fetch(api("/cancel"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(target),
      cache: "no-store",
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { cancelled?: boolean };
    return body.cancelled === true;
  } catch {
    return false;
  }
}

/**
 * The answer to `POST /api/ozint/refresh` — one node re-checked against its own
 * tools, nothing else touched.
 */
export interface RefreshResult {
  changed: boolean;
  changedFields: string[];
  reports: ToolReport[];
  /**
   * Child seeds the replayed tools offered and the refresh declined to act on.
   * A refresh never touches children, and saying how many it declined is what
   * stops that rule from looking like a source that went quiet.
   */
  childrenIgnored: number;
  aborted: boolean;
  checkedAt: number;
}

/**
 * Re-run one node's own tools and fold the re-read node back into the tree.
 *
 * Returns `null` when the server refused, which it does with a reason: a 422
 * means the node's tools have left the registry and it *cannot* be re-run. That
 * is not the same as "nothing changed", and the caller must not render it as
 * one — so a refusal comes back as an error string, never as an unchanged
 * result.
 */
async function refresh(
  nodeId: string,
): Promise<{ result?: RefreshResult; error?: string }> {
  try {
    const res = await fetch(api("/refresh"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nodeId }),
      cache: "no-store",
    });
    if (!res.ok) return { error: await describeFailure(res) };

    const body = (await res.json()) as {
      node?: OzNode;
      changed?: boolean;
      changedFields?: string[];
      reports?: ToolReport[];
      childrenIgnored?: number;
      aborted?: boolean;
    };
    if (!body.node) return { error: "the refresh returned no node" };

    set({
      tree: applyEvent(state.tree, {
        type: "node",
        layerId: body.node.layerId ?? "",
        node: body.node,
      }),
    });

    const investigationId = body.node.investigationId;
    if (investigationId) {
      // A refreshed value can change the subject file, and the meter moved:
      // a refresh spends real lookups.
      void hydrate(investigationId);
      void readMeter(investigationId);
    }

    return {
      result: {
        changed: body.changed === true,
        changedFields: body.changedFields ?? [],
        reports: body.reports ?? [],
        childrenIgnored: body.childrenIgnored ?? 0,
        aborted: body.aborted === true,
        checkedAt: Date.now(),
      },
    };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * The analyst's three verdicts on a finding —
 * `POST /api/ozint/node/{id}/edit|reject|restore`.
 *
 * All three are **local writes that reach nothing**, so they stay available
 * while the kill switch is frozen, and none of them spends a lookup. Each
 * answers with the node as the server re-read it, which is the copy folded back
 * into the tree: the dedup key, the record status and the preserved original are
 * all derived server-side and a client guess at them would be fiction.
 *
 * A refusal comes back as the server's own sentence. Two of them are real
 * product rules rather than transport failures — correcting a rejected node
 * (`409`, restore it first, or the rejection would be silently discarded) and
 * retyping a root that already carries findings (`409`, start a new
 * investigation) — and both must reach the analyst in those words.
 *
 * `edit` sends `{value}` and nothing else. There is deliberately no chip input:
 * `edited_chip` has no producer in the engine, so a control for it would post a
 * field the server ignores.
 */
async function verdict(
  nodeId: string,
  action: "edit" | "reject" | "restore",
  value?: string,
): Promise<{ node?: OzNode; error?: string }> {
  try {
    const res = await fetch(api(`/node/${nodeId}/${action}`), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(action === "edit" ? { value } : {}),
      cache: "no-store",
    });
    if (!res.ok) return { error: await describeFailure(res) };
    const node = (await res.json()) as OzNode;
    if (!node?.id) return { error: "the write returned no node" };

    set({
      tree: applyEvent(state.tree, {
        type: "node",
        layerId: node.layerId ?? "",
        node,
      }),
    });
    // The subject file and the relations are re-derived server-side on every
    // read, and all three verdicts change them — a rejection drops out of the
    // file, a correction appears in it. Re-reading is what makes that immediate.
    if (node.investigationId) void hydrate(node.investigationId);
    return { node };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Read PAST INVESTIGATIONS. A failure is recorded as a failure — an empty
 * history and an unreadable one are not the same statement.
 */
async function listInvestigations(limit?: number): Promise<void> {
  set({ historyLoading: true, historyError: null });
  try {
    const query = limit ? `?limit=${limit}` : "";
    const res = await fetch(api(`/investigations${query}`), { cache: "no-store" });
    if (!res.ok) {
      set({ historyLoading: false, historyError: await describeFailure(res) });
      return;
    }
    const body = (await res.json()) as unknown;
    if (!Array.isArray(body)) {
      set({
        historyLoading: false,
        historyError: "the history route answered something that is not a list",
      });
      return;
    }
    set({ history: body as Investigation[], historyLoading: false });
  } catch (err) {
    set({
      historyLoading: false,
      historyError: err instanceof Error ? err.message : String(err),
    });
  }
}

/**
 * Reopen a past investigation — **resumable**, not an archive.
 *
 * Everything comes from `GET /api/ozint/investigations/{id}`: the tree, the
 * layer rows behind the bands, the subject file, and then the meter. Nothing is
 * fired, so this costs no lookups; continuing a node afterwards is an ordinary
 * `fire {investigationId, parentNodeId}` and the engine rebuilds its visited set
 * from the very rows just read.
 *
 * `rootNodeId` is taken from the investigation row rather than inferred from a
 * parentless node, so a tree that arrives incomplete still knows where it starts.
 */
async function open(investigationId: string): Promise<boolean> {
  abortAll();
  state = {
    ...state,
    tree: emptyTreeState(),
    status: "idle",
    openStreams: 0,
    malformed: [],
    transportError: null,
    meter: null,
    subjectFile: null,
    relations: null,
    spawnError: null,
    reopenError: null,
  };
  notify();
  try {
    const res = await fetch(api(`/investigations/${investigationId}`), {
      cache: "no-store",
    });
    if (!res.ok) {
      set({ reopenError: await describeFailure(res) });
      return false;
    }
    const body = (await res.json()) as {
      investigation?: Investigation;
      nodes?: OzNode[];
      layers?: StoredLayer[];
      subjectFile?: SubjectFileView;
      relations?: RelationReport;
    };
    if (!body.investigation) {
      set({ reopenError: "the investigation came back without its own record" });
      return false;
    }

    let tree: OzintTreeState = {
      ...emptyTreeState(),
      investigationId: body.investigation.id,
      rootNodeId: body.investigation.rootNodeId,
    };
    const nodes = [...(body.nodes ?? [])].sort(
      (a, b) => a.depth - b.depth || a.ordinal - b.ordinal,
    );
    for (const node of nodes) {
      tree = applyEvent(tree, { type: "node", layerId: node.layerId ?? "", node });
    }
    tree = adoptStoredLayers(tree, body.investigation.id, body.layers ?? []);

    if (nodes.length === 0) {
      // Stored but empty. Said out loud rather than shown as a blank canvas
      // that reads like a cockpit that failed to load.
      tree = {
        ...tree,
        errors: [
          ...tree.errors,
          { message: "this investigation was stored with no nodes — there is nothing to resume from" },
        ],
      };
    }

    set({
      tree,
      subjectFile:
        body.subjectFile && typeof body.subjectFile.kind === "string"
          ? body.subjectFile
          : null,
      relations:
        body.relations && Array.isArray(body.relations.relations)
          ? body.relations
          : null,
    });
    await readMeter(body.investigation.id);
    return true;
  } catch (err) {
    set({ reopenError: err instanceof Error ? err.message : String(err) });
    return false;
  }
}

/**
 * `POST /api/ozint/spawn {investigationId, relationId}`.
 *
 * Searching a relation always opens a **brand-new, independent investigation**
 * — its own root, visited set, subject file and meter — linked one-way via
 * `spawnedFromInvestigationId`/`spawnedFromRelation`. It is never grafted onto
 * the tree that surfaced it (decision: one person, one tree). On success this
 * switches the cockpit onto the new investigation exactly as reopening one
 * from history does; the caller is responsible for resetting any tree-local
 * UI state (focus, expanded/collapsed sets) the same way `reopen` in
 * `OzintView` already does for history.
 *
 * A `409` here is the honest outcome the route documents: the relation the
 * analyst clicked no longer derives from the tree (its evidence was since
 * rejected or edited away), and the server's own sentence is what reaches the
 * analyst rather than a generic failure.
 */
async function spawn(
  investigationId: string,
  relationId: string,
): Promise<{ investigationId?: string; error?: string }> {
  set({ spawning: true, spawnError: null });
  try {
    const res = await fetch(api("/spawn"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ investigationId, relationId }),
      cache: "no-store",
    });
    if (!res.ok) {
      const error = await describeFailure(res);
      set({ spawning: false, spawnError: error });
      return { error };
    }
    const body = (await res.json()) as { investigation?: Investigation };
    if (!body.investigation?.id) {
      const error = "the spawn returned no investigation";
      set({ spawning: false, spawnError: error });
      return { error };
    }
    set({ spawning: false });
    const opened = await open(body.investigation.id);
    if (!opened) {
      return { error: state.reopenError ?? "the new investigation could not be opened" };
    }
    return { investigationId: body.investigation.id };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    set({ spawning: false, spawnError: error });
    return { error };
  }
}

/** Drop every open connection locally, without asking the server anything. */
function abortAll(): void {
  for (const controller of controllers) controller.abort();
  controllers.clear();
}

function reset(): void {
  abortAll();
  // The history list survives: it is a fact about the machine, not about the
  // investigation being cleared, and re-fetching it on every fire would be a
  // request nobody asked for.
  state = {
    ...EMPTY,
    tree: emptyTreeState(),
    history: state.history,
    historyError: state.historyError,
  };
  notify();
}

export const ozintStore = {
  subscribe: (listener: () => void): (() => void) => {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  },
  getSnapshot: (): OzintStoreState => state,
  getServerSnapshot: (): OzintStoreState => EMPTY,
  fire,
  cancel,
  refresh,
  editNode: (nodeId: string, value: string) => verdict(nodeId, "edit", value),
  rejectNode: (nodeId: string) => verdict(nodeId, "reject"),
  restoreNode: (nodeId: string) => verdict(nodeId, "restore"),
  listInvestigations,
  open,
  spawn,
  abortAll,
  reset,
  readMeter,
};

export function useOzintStore(): OzintStoreState {
  return useSyncExternalStore(
    ozintStore.subscribe,
    ozintStore.getSnapshot,
    ozintStore.getServerSnapshot,
  );
}
