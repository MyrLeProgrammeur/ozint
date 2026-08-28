import { describe, expect, it } from "vitest";

import type {
  Corroboration,
  LayerEvent,
  OzNode,
  ToolReport,
} from "@/lib/ozint/stream-parser";

import {
  adoptStoredLayers,
  applyEvent,
  corroborationFor,
  emptyTreeState,
  inFlightLayers,
  isInert,
  layerFor,
  nodeCount,
  treeDepth,
  type OzintTreeState,
  type StoredLayer,
} from "./state";

function node(over: Partial<OzNode> & Pick<OzNode, "id">): OzNode {
  return {
    investigationId: "inv-1",
    ordinal: 0,
    depth: over.parentId ? 1 : 0,
    type: "username",
    value: over.id,
    display: over.id,
    dedupKey: `username:${over.id}`,
    payload: { type: "username" },
    status: "idle",
    provenance: {
      sourceToolId: "github-user",
      method: "queried the users API",
      retrievedAt: "2026-08-23T10:00:00Z",
      recordStatus: { kind: "as-returned" },
    },
    createdAt: "2026-08-23T10:00:00Z",
    ...over,
  };
}

function route(over: Partial<Corroboration> = {}): Corroboration {
  return {
    toolId: "github-user",
    method: "queried the users API",
    parentNodeId: "root",
    layerId: "L2",
    foundAt: "2026-08-23T10:05:00Z",
    ...over,
  };
}

function report(over: Partial<ToolReport> = {}): ToolReport {
  return {
    toolId: "github-user",
    label: "GitHub",
    outcome: { kind: "ok-empty" },
    elapsedMs: 340,
    results: 0,
    gated: false,
    method: "queried the users API",
    ...over,
  };
}

function start(over: Partial<Extract<LayerEvent, { type: "layerStart" }>> = {}) {
  return {
    type: "layerStart" as const,
    layerId: "L1",
    investigationId: "inv-1",
    parentNodeId: "root",
    firing: 2,
    maxPossible: 7,
    gated: 1,
    ...over,
  };
}

function reduce(events: LayerEvent[], from = emptyTreeState()): OzintTreeState {
  return events.reduce(applyEvent, from);
}

/** Root node, one layer fired on it, two children found. */
function seeded(): OzintTreeState {
  return reduce([
    { type: "node", layerId: "L0", node: node({ id: "root" }) },
    start(),
    { type: "node", layerId: "L1", node: node({ id: "a", parentId: "root" }) },
    { type: "node", layerId: "L1", node: node({ id: "b", parentId: "root" }) },
    { type: "layerSettled", layerId: "L1", newChildren: 2, reports: [report()] },
  ]);
}

describe("applyEvent — tree construction", () => {
  it("adopts the first parentless node as the root and keeps it", () => {
    const state = reduce([
      { type: "node", layerId: "L0", node: node({ id: "root" }) },
      { type: "node", layerId: "L0", node: node({ id: "other" }) },
    ]);
    expect(state.rootNodeId).toBe("root");
    expect(state.investigationId).toBe("inv-1");
  });

  it("records children in arrival order and never twice", () => {
    const state = reduce(
      [
        { type: "node", layerId: "L1", node: node({ id: "a", parentId: "root" }) },
        { type: "node", layerId: "L1", node: node({ id: "b", parentId: "root" }) },
        // A re-sent frame for a node already seen must not duplicate the edge.
        { type: "node", layerId: "L1", node: node({ id: "a", parentId: "root" }) },
      ],
      seeded(),
    );
    expect(state.children.root).toEqual(["a", "b"]);
  });

  it("returns the same state object for a frame naming an unknown layer", () => {
    const state = seeded();
    for (const event of [
      { type: "toolStart", layerId: "ghost", toolId: "t", label: "T", gated: false },
      { type: "toolDone", layerId: "ghost", report: report() },
      { type: "summary", layerId: "ghost", text: "x", fallback: false },
      { type: "layerSettled", layerId: "ghost", newChildren: 0, reports: [] },
    ] satisfies LayerEvent[]) {
      expect(applyEvent(state, event)).toBe(state);
    }
  });
});

describe("applyEvent — a re-continue replaces the subtree", () => {
  it("drops the previous run's descendants, not the parent itself", () => {
    const first = reduce(
      [
        start({ layerId: "L2", parentNodeId: "a" }),
        { type: "node", layerId: "L2", node: node({ id: "a1", parentId: "a", depth: 2 }) },
        { type: "node", layerId: "L2", node: node({ id: "a2", parentId: "a", depth: 2 }) },
        {
          type: "layerSettled",
          layerId: "L2",
          newChildren: 2,
          reports: [report()],
        },
      ],
      seeded(),
    );
    expect(nodeCount(first)).toBe(5);
    expect(treeDepth(first)).toBe(2);

    // Fire `a` again: the old findings must not survive under a layer that no
    // longer claims them.
    const second = reduce(
      [
        start({ layerId: "L3", parentNodeId: "a" }),
        { type: "node", layerId: "L3", node: node({ id: "a9", parentId: "a", depth: 2 }) },
      ],
      first,
    );

    expect(second.nodes.a1).toBeUndefined();
    expect(second.nodes.a2).toBeUndefined();
    expect(second.nodes.a).toBeDefined();
    expect(second.children.a).toEqual(["a9"]);
    expect(second.nodes.b).toBeDefined();
    expect(nodeCount(second)).toBe(4);
  });

  it("removes a whole deep subtree, not just the direct children", () => {
    const deep = reduce(
      [
        start({ layerId: "L2", parentNodeId: "a" }),
        { type: "node", layerId: "L2", node: node({ id: "a1", parentId: "a", depth: 2 }) },
        start({ layerId: "L3", parentNodeId: "a1" }),
        { type: "node", layerId: "L3", node: node({ id: "a1x", parentId: "a1", depth: 3 }) },
      ],
      seeded(),
    );
    expect(deep.nodes.a1x).toBeDefined();

    const refired = applyEvent(deep, start({ layerId: "L4", parentNodeId: "a" }));
    expect(refired.nodes.a1).toBeUndefined();
    expect(refired.nodes.a1x).toBeUndefined();
    expect(refired.children.a).toEqual([]);
  });

  it("drops corroborations recorded on the discarded subtree", () => {
    const withCorroboration = reduce(
      [
        start({ layerId: "L2", parentNodeId: "a" }),
        { type: "node", layerId: "L2", node: node({ id: "a1", parentId: "a", depth: 2 }) },
        {
          type: "alreadyInTree",
          layerId: "L2",
          existingNodeId: "a1",
          annotation: "already in tree · L2",
          foundAgainBy: route({ layerId: "L2" }),
        },
      ],
      seeded(),
    );
    expect(withCorroboration.corroborations.a1).toBeDefined();

    const refired = applyEvent(withCorroboration, start({ layerId: "L4", parentNodeId: "a" }));
    expect(refired.corroborations.a1).toBeUndefined();
  });

  it("forgets the layers the discarded descendants had fired", () => {
    const deep = reduce(
      [
        start({ layerId: "L2", parentNodeId: "a" }),
        { type: "node", layerId: "L2", node: node({ id: "a1", parentId: "a", depth: 2 }) },
        start({ layerId: "L3", parentNodeId: "a1" }),
      ],
      seeded(),
    );
    expect(layerFor(deep, "a1")?.id).toBe("L3");

    const refired = applyEvent(deep, start({ layerId: "L4", parentNodeId: "a" }));
    // `a1` is gone, so nothing may still answer for it — a stale entry here
    // would keep a dead node's layer in flight forever.
    expect(layerFor(refired, "a1")).toBeUndefined();
    expect(refired.layers.L3).toBeUndefined();
    expect(inFlightLayers(refired).map((l) => l.id)).toEqual(["L4"]);
  });

  it("marks the re-fired parent as running and points it at the new layer", () => {
    const state = applyEvent(seeded(), start({ layerId: "L9", parentNodeId: "a" }));
    expect(state.nodes.a.status).toBe("running");
    expect(layerFor(state, "a")?.id).toBe("L9");
    expect(inFlightLayers(state).map((l) => l.id)).toEqual(["L9"]);
  });
});

describe("applyEvent — decision 7: the parent card enriches mid-layer", () => {
  it("merge-patches the payload while the layer is still firing", () => {
    const state = reduce(
      [
        start({ layerId: "L2", parentNodeId: "a" }),
        {
          type: "parentPayload",
          layerId: "L2",
          nodeId: "a",
          patch: { asn: "AS15169", ports: [80, 443] },
        },
        {
          type: "parentPayload",
          layerId: "L2",
          nodeId: "a",
          patch: { abuseScore: 12, ports: [80, 443, 8080] },
        },
      ],
      seeded(),
    );

    expect(layerFor(state, "a")?.status).toBe("firing");
    expect(state.nodes.a.payload).toEqual({
      type: "username",
      asn: "AS15169",
      ports: [80, 443, 8080],
      abuseScore: 12,
    });
  });

  it("replaces the preview chip and the sections when they are sent", () => {
    const state = reduce(
      [
        start({ layerId: "L2", parentNodeId: "a" }),
        {
          type: "parentPayload",
          layerId: "L2",
          nodeId: "a",
          patch: {},
          previewSignal: { text: "3 breaches", tone: "risk" },
          sections: [
            { id: "s1", label: "Network", kind: "key-value", rows: [] },
          ],
        },
      ],
      seeded(),
    );
    expect(state.nodes.a.previewSignal).toEqual({ text: "3 breaches", tone: "risk" });
    expect(state.nodes.a.sections?.map((s) => s.id)).toEqual(["s1"]);
  });

  it("leaves the sections alone when the frame omits them", () => {
    const withSections = applyEvent(seeded(), {
      type: "parentPayload",
      layerId: "L1",
      nodeId: "a",
      patch: {},
      sections: [{ id: "s1", label: "Network", kind: "key-value", rows: [] }],
    });
    const later = applyEvent(withSections, {
      type: "parentPayload",
      layerId: "L1",
      nodeId: "a",
      patch: { note: "x" },
    });
    expect(later.nodes.a.sections?.map((s) => s.id)).toEqual(["s1"]);
  });

  it("ignores a payload for a node it has never seen", () => {
    const state = seeded();
    expect(
      applyEvent(state, {
        type: "parentPayload",
        layerId: "L1",
        nodeId: "never-seen",
        patch: { a: 1 },
      }),
    ).toBe(state);
  });
});

describe("applyEvent — terminal frames", () => {
  it("replaces the report list with the terminal frame's authoritative one", () => {
    // A kill switch reaches tools that never emitted a `toolDone` of their own,
    // so the terminal list is longer than the running tally, and wins.
    const state = reduce(
      [
        start({ layerId: "L2", parentNodeId: "a", firing: 3 }),
        { type: "toolStart", layerId: "L2", toolId: "github-user", label: "GitHub", gated: false },
        { type: "toolDone", layerId: "L2", report: report({ toolId: "github-user" }) },
        { type: "toolStart", layerId: "L2", toolId: "hn-algolia", label: "HN", gated: false },
        {
          type: "layerAborted",
          layerId: "L2",
          reports: [
            report({ toolId: "github-user" }),
            report({ toolId: "hn-algolia", outcome: { kind: "cancelled" } }),
            report({ toolId: "bluesky-actor", outcome: { kind: "cancelled" } }),
          ],
        },
      ],
      seeded(),
    );

    const layer = layerFor(state, "a")!;
    expect(layer.status).toBe("aborted");
    expect(layer.running).toEqual([]);
    expect(layer.reports.map((r) => r.toolId)).toEqual([
      "github-user",
      "hn-algolia",
      "bluesky-actor",
    ]);
    expect(inFlightLayers(state)).toEqual([]);
  });

  it("maps every terminal frame to its own settle kind on the layer and the parent", () => {
    const cases = [
      ["layerSettled", "settled"],
      ["layerEmpty", "empty"],
      ["layerDegraded", "degraded"],
      ["layerFailed", "failed"],
      ["layerAborted", "aborted"],
    ] as const;

    for (const [type, kind] of cases) {
      const state = reduce(
        [
          start({ layerId: "LX", parentNodeId: "a" }),
          { type, layerId: "LX", newChildren: 0, reports: [] } as LayerEvent,
        ],
        seeded(),
      );
      expect(layerFor(state, "a")?.status).toBe(kind);
      expect(state.nodes.a.status).toBe(kind);
    }
  });

  it("keeps newChildren at zero for the frames that carry no count", () => {
    // `layerEmpty`, `layerFailed` and `layerAborted` have no `newChildren` on
    // the wire — reading one off them must not produce `undefined`/`NaN`.
    for (const type of ["layerEmpty", "layerFailed", "layerAborted"] as const) {
      const state = reduce(
        [start({ layerId: "LX", parentNodeId: "a" }), { type, layerId: "LX", reports: [] }],
        seeded(),
      );
      expect(layerFor(state, "a")?.newChildren).toBe(0);
    }
  });

  it("accepts a summary after the layer has already closed", () => {
    const state = reduce(
      [
        start({ layerId: "LX", parentNodeId: "a" }),
        { type: "layerEmpty", layerId: "LX", reports: [] },
        { type: "summary", layerId: "LX", text: "Nothing further.", fallback: true },
      ],
      seeded(),
    );
    const layer = layerFor(state, "a")!;
    expect(layer.status).toBe("empty");
    expect(layer.summary).toEqual({ text: "Nothing further.", fallback: true });
  });
});

describe("applyEvent — decision 9: corroboration", () => {
  it("accumulates one named route per re-discovery instead of duplicating the node", () => {
    const state = reduce(
      [
        {
          type: "alreadyInTree",
          layerId: "L2",
          existingNodeId: "a",
          annotation: "already in tree · L1",
          foundAgainBy: route({ toolId: "github-user", layerId: "L2" }),
          paths: 2,
        },
        {
          type: "alreadyInTree",
          layerId: "L3",
          existingNodeId: "a",
          annotation: "already in tree · L1",
          foundAgainBy: route({ toolId: "gravatar-profile", layerId: "L3" }),
          paths: 3,
        },
      ],
      seeded(),
    );

    expect(nodeCount(state)).toBe(3);
    expect(state.corroborations.a.layerIds).toEqual(["L2", "L3"]);
    expect(state.corroborations.a.foundAgainBy.map((c) => c.toolId)).toEqual([
      "github-user",
      "gravatar-profile",
    ]);
    // The card says "corroborated · 3 paths", read off the wire, not counted here.
    expect(state.corroborations.a.paths).toBe(3);
  });

  it("keeps the last path count the server sent when a later frame omits it", () => {
    const state = reduce(
      [
        {
          type: "alreadyInTree",
          layerId: "L2",
          existingNodeId: "a",
          annotation: "x",
          foundAgainBy: route({ layerId: "L2" }),
          paths: 2,
        },
        {
          type: "alreadyInTree",
          layerId: "L3",
          existingNodeId: "a",
          annotation: "x",
          foundAgainBy: route({ layerId: "L3" }),
        },
      ],
      seeded(),
    );
    expect(state.corroborations.a.paths).toBe(2);
  });
});

describe("corroborationFor", () => {
  it("says nothing for a node found by a single route", () => {
    expect(corroborationFor(seeded(), "a")).toBeUndefined();
  });

  it("merges a reopened investigation's persisted routes with the live ones", () => {
    const persisted = route({ toolId: "hn-algolia", layerId: "L-old" });
    const base = applyEvent(seeded(), {
      type: "node",
      layerId: "L1",
      node: node({ id: "a", parentId: "root", corroborations: [persisted] }),
    });
    const state = applyEvent(base, {
      type: "alreadyInTree",
      layerId: "L2",
      existingNodeId: "a",
      annotation: "already in tree · L1",
      foundAgainBy: route({ toolId: "github-user", layerId: "L2" }),
    });

    const found = corroborationFor(state, "a")!;
    expect(found.routes.map((r) => r.toolId)).toEqual(["hn-algolia", "github-user"]);
    // Two extra routes plus the node's own provenance.
    expect(found.paths).toBe(3);
  });

  it("counts a route once when it is both persisted and re-streamed", () => {
    const shared = route({ toolId: "github-user", layerId: "L2" });
    const base = applyEvent(seeded(), {
      type: "node",
      layerId: "L1",
      node: node({ id: "a", parentId: "root", corroborations: [shared] }),
    });
    const state = applyEvent(base, {
      type: "alreadyInTree",
      layerId: "L2",
      existingNodeId: "a",
      annotation: "already in tree · L1",
      foundAgainBy: { ...shared },
    });

    const found = corroborationFor(state, "a")!;
    expect(found.routes).toHaveLength(1);
    expect(found.paths).toBe(2);
  });
});

describe("applyEvent — errors", () => {
  it("appends errors with and without a layer, and never throws them away", () => {
    const state = reduce(
      [
        { type: "error", layerId: "L1", message: "tool crashed" },
        { type: "error", message: "stream died" },
      ],
      seeded(),
    );
    expect(state.errors).toEqual([
      { layerId: "L1", message: "tool crashed" },
      { layerId: undefined, message: "stream died" },
    ]);
  });
});

describe("isInert", () => {
  it("dims a sibling that was never continued while another was", () => {
    const state = applyEvent(seeded(), start({ layerId: "L2", parentNodeId: "a" }));
    expect(isInert(state, "b")).toBe(true);
    expect(isInert(state, "a")).toBe(false);
    expect(isInert(state, "root")).toBe(false);
  });

  it("holds nothing inert while no sibling has been continued", () => {
    const state = seeded();
    expect(isInert(state, "a")).toBe(false);
    expect(isInert(state, "b")).toBe(false);
  });
});

describe("adoptStoredLayers", () => {
  function stored(over: Partial<StoredLayer> = {}): StoredLayer {
    return {
      id: "L1",
      parentNodeId: "root",
      status: "settled",
      startedAt: "2026-08-23T10:00:00Z",
      settledAt: "2026-08-23T10:00:09Z",
      newChildren: 2,
      reports: [report()],
      ...over,
    };
  }

  it("rebuilds a band from a stored row", () => {
    const state = adoptStoredLayers(emptyTreeState(), "inv-1", [stored()]);
    const layer = layerFor(state, "root");
    expect(layer?.id).toBe("L1");
    expect(layer?.status).toBe("settled");
    expect(layer?.reports).toHaveLength(1);
    expect(layer?.fromStorage).toBe(true);
  });

  it("claims nothing about a plan storage never kept", () => {
    const layer = layerFor(adoptStoredLayers(emptyTreeState(), "inv-1", [stored()]), "root");
    // `held = maxPossible - firing` must not become a positive number out of
    // thin air, and `N GATED` must not appear for a row that never said so.
    expect(layer?.firing).toBe(0);
    expect(layer?.maxPossible).toBe(0);
    expect(layer?.gated).toBe(0);
    expect(layer?.running).toEqual([]);
  });

  it("never renders a layer stuck at `running` as one that is firing", () => {
    const state = adoptStoredLayers(emptyTreeState(), "inv-1", [
      stored({ status: "running", settledAt: undefined, newChildren: 0 }),
    ]);
    expect(layerFor(state, "root")?.status).toBe("interrupted");
    expect(inFlightLayers(state)).toHaveLength(0);
  });

  it("raises an error on a status this build cannot read, rather than guessing", () => {
    const state = adoptStoredLayers(emptyTreeState(), "inv-1", [
      stored({ status: "quiesced" }),
    ]);
    expect(layerFor(state, "root")?.status).toBe("interrupted");
    expect(state.errors).toHaveLength(1);
    expect(state.errors[0].message).toContain("quiesced");
  });

  it("says so when the stored tool record no longer parses", () => {
    const state = adoptStoredLayers(emptyTreeState(), "inv-1", [
      stored({ reports: [], reportsUnreadable: true }),
    ]);
    expect(layerFor(state, "root")?.reportsUnreadable).toBe(true);
    expect(state.errors[0].message).toContain("no longer parse");
  });

  it("leaves a layer this session watched alone — the live copy knows its plan", () => {
    const live = applyEvent(emptyTreeState(), start());
    const state = adoptStoredLayers(live, "inv-1", [stored()]);
    const layer = layerFor(state, "root");
    expect(layer?.maxPossible).toBe(7);
    expect(layer?.fromStorage).toBeUndefined();
  });

  it("points a parent at its newest layer when it was continued twice", () => {
    const state = adoptStoredLayers(emptyTreeState(), "inv-1", [
      stored({ id: "L-late", startedAt: "2026-08-23T11:00:00Z" }),
      stored({ id: "L-early", startedAt: "2026-08-23T10:00:00Z" }),
    ]);
    expect(layerFor(state, "root")?.id).toBe("L-late");
    expect(Object.keys(state.layers)).toHaveLength(2);
  });

  it("is idempotent — re-reading the same rows replaces them", () => {
    const once = adoptStoredLayers(emptyTreeState(), "inv-1", [stored()]);
    const twice = adoptStoredLayers(once, "inv-1", [stored()]);
    expect(Object.keys(twice.layers)).toEqual(["L1"]);
    expect(twice.errors).toEqual([]);
  });

  it("returns the state it was given when there is nothing to adopt", () => {
    const state = emptyTreeState();
    expect(adoptStoredLayers(state, "inv-1", [])).toBe(state);
  });
});
