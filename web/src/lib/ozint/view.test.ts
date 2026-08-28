import { describe, expect, it } from "vitest";

import type {
  LayerEvent,
  OzNode,
  ToolReport,
} from "@/lib/ozint/stream-parser";

import { layoutTree } from "./layout";
import { applyEvent, emptyTreeState, type OzintTreeState } from "./state";
import {
  BAND_METRICS,
  bandHeight,
  bandModel,
  blockModel,
  cardModel,
  meterLine,
  summaryHeight,
  toLayoutInput,
} from "./view";

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

const rooted = (): OzintTreeState =>
  reduce([{ type: "node", layerId: "L0", node: node({ id: "root" }) }]);

describe("bandHeight", () => {
  it("is nothing at all for a node that was never continued", () => {
    expect(bandHeight(undefined, false)).toBe(0);
  });

  it("grows by one row per tool when the list is expanded", () => {
    const state = reduce(
      [
        start(),
        {
          type: "layerEmpty",
          layerId: "L1",
          reports: [report(), report({ toolId: "hn-algolia" })],
        },
      ],
      rooted(),
    );
    const layer = state.layers.L1;
    const collapsed = bandHeight(layer, false);
    expect(bandHeight(layer, true)).toBe(collapsed + 2 * BAND_METRICS.toolRow);
  });

  it("reserves room for the summary note only when one arrived", () => {
    const withNote = reduce(
      [
        start(),
        { type: "layerEmpty", layerId: "L1", reports: [] },
        { type: "summary", layerId: "L1", text: "Nothing further.", fallback: false },
      ],
      rooted(),
    );
    const without = reduce(
      [start(), { type: "layerEmpty", layerId: "L1", reports: [] }],
      rooted(),
    );
    expect(bandHeight(withNote.layers.L1, false)).toBe(
      bandHeight(without.layers.L1, false) + summaryHeight("Nothing further."),
    );
  });

  it("grows the band for a long note rather than clipping it mid-sentence", () => {
    // Observed live: a real summary note ran four lines and a fixed reservation
    // cut it at "…YouTube was", hiding why the layer degraded.
    const short = summaryHeight("Nothing further.");
    const long = summaryHeight("x".repeat(400));
    expect(long).toBeGreaterThan(short);
    // But it stops growing, so one talkative note cannot shove the tree apart.
    expect(summaryHeight("x".repeat(100_000))).toBe(
      BAND_METRICS.summaryMaxLines * BAND_METRICS.summaryLine + 8,
    );
  });

  it("reserves enough height for a real degraded-layer note", () => {
    // The note this is measured against, verbatim from a live `torvalds` fire
    // whose layer settled `degraded`. The old 90-chars-per-line estimate gave it
    // four lines; the browser wrapped it to five, leaving 82px of text in a 68px
    // box — and the band clipped the sentence naming which tools broke.
    const real =
      "The lookup returned no new nodes; only the Mastodon lookup produced a " +
      "single result. The YouTube, WhatsMyName, GitHub, and Bluesky tools failed " +
      "(YouTube was skipped due to missing API key, WhatsMyName could not parse " +
      "the response, GitHub returned a 401 error, and Bluesky returned a 400 " +
      "error). Gravatar and Hacker News were still checked but found nothing.";
    // 14.85px per rendered line (11px at 1.35), plus the 8px the reservation adds.
    const renderedHeight = Math.ceil(real.length / 72) * 14.85;
    expect(summaryHeight(real)).toBeGreaterThanOrEqual(
      Math.min(
        renderedHeight,
        BAND_METRICS.summaryMaxLines * BAND_METRICS.summaryLine,
      ),
    );
  });
});

describe("toLayoutInput", () => {
  it("says nothing before a root exists", () => {
    expect(toLayoutInput(emptyTreeState())).toBeNull();
  });

  it("hands the layout engine a band tall enough for the expanded tool list", () => {
    const state = reduce(
      [
        start(),
        {
          type: "layerEmpty",
          layerId: "L1",
          reports: [report(), report({ toolId: "hn-algolia" })],
        },
      ],
      rooted(),
    );

    const collapsed = toLayoutInput(state)!;
    const expanded = toLayoutInput(state, { expanded: new Set(["root"]) })!;
    expect(expanded.nodes.root.band!.height).toBeGreaterThan(
      collapsed.nodes.root.band!.height,
    );

    // And the engine actually uses it: the taller band pushes the canvas down.
    expect(layoutTree(expanded).canvasHeight).toBeGreaterThan(
      layoutTree(collapsed).canvasHeight,
    );
  });

  it("draws a block for a childless layer, and none once children arrive", () => {
    const empty = reduce(
      [start(), { type: "layerEmpty", layerId: "L1", reports: [] }],
      rooted(),
    );
    expect(toLayoutInput(empty)!.nodes.root.block).toEqual({
      kind: "empty",
      width: 292,
    });

    const withChild = reduce(
      [
        start(),
        { type: "node", layerId: "L1", node: node({ id: "a", parentId: "root" }) },
        { type: "layerSettled", layerId: "L1", newChildren: 1, reports: [] },
      ],
      rooted(),
    );
    expect(toLayoutInput(withChild)!.nodes.root.block).toBeUndefined();
    expect(toLayoutInput(withChild)!.nodes.root.children).toEqual(["a"]);
  });

  it("never invents a dead end under a node the analyst merely collapsed", () => {
    const state = reduce(
      [
        start(),
        { type: "node", layerId: "L1", node: node({ id: "a", parentId: "root" }) },
        { type: "layerSettled", layerId: "L1", newChildren: 1, reports: [] },
      ],
      rooted(),
    );
    const input = toLayoutInput(state, { collapsed: new Set(["root"]) })!;
    expect(input.nodes.root.children).toEqual([]);
    expect(input.nodes.root.block).toBeUndefined();
    // The band survives: it is a fact about the node, not about the subtree.
    expect(input.nodes.root.band).toBeDefined();
  });

  it("marks a still-firing childless layer as firing, not as empty", () => {
    const state = reduce([start()], rooted());
    expect(toLayoutInput(state)!.nodes.root.block!.kind).toBe("firing");
  });
});

describe("bandModel — decision 1", () => {
  it("counts skipped tools apart from tools that ran, and keeps the plan's total", () => {
    const state = reduce(
      [
        start({ firing: 2, maxPossible: 7, gated: 1 }),
        {
          type: "layerEmpty",
          layerId: "L1",
          reports: [
            report({ toolId: "github-user", outcome: { kind: "ok-empty" } }),
            report({
              toolId: "hibp-breach",
              outcome: { kind: "skipped-no-key", env_var: "HIBP_API_KEY" },
            }),
            report({
              toolId: "peeringdb",
              outcome: {
                kind: "skipped-missing-input",
                input: "asn",
                reason: "ASN not found upstream",
              },
            }),
          ],
        },
      ],
      rooted(),
    );

    const band = bandModel(state, "root")!;
    expect(band.summary.ran).toBe(1);
    expect(band.summary.skipped).toBe(2);
    expect(band.summary.line).toContain("3 tools");
    // The plan's own numbers stay available: 2 fired of 7 possible, 1 gated.
    expect([band.firing, band.maxPossible, band.gated]).toEqual([2, 7, 1]);
    expect(band.expandable).toBe(true);
  });

  it("says nothing for a node that was never continued", () => {
    expect(bandModel(rooted(), "root")).toBeNull();
  });
});

describe("blockModel", () => {
  it("reports tools in flight rather than a settled count while firing", () => {
    const state = reduce(
      [
        start({ firing: 3 }),
        { type: "toolStart", layerId: "L1", toolId: "github-user", label: "GH", gated: false },
      ],
      rooted(),
    );
    const block = blockModel(state, "root")!;
    expect(block.label).toBe("◇ SEARCHING");
    expect(block.sub).toBe("1 of 3 tools in flight");
    expect(block.progress).toEqual({ running: 1, firing: 3 });
  });

  it("keeps a failed layer amber and retryable, never a clean dead end", () => {
    const state = reduce(
      [start(), { type: "layerFailed", layerId: "L1", reports: [] }],
      rooted(),
    );
    const block = blockModel(state, "root")!;
    expect(block.label).toBe("◇ LAYER FAILED");
    expect(block.retry).toBe(true);
    // Technical breakage is amber, and never the risk colour.
    expect(block.tone.fg).toBe("#E8B15C");
  });

  it("keeps a block for a degraded layer that found nothing, so its band survives", () => {
    // Observed for real: six tools fired, four broke, zero children. With no
    // block there is no child row, `layout.ts` places no band, and every tool
    // row disappears — leaving a bare card that reads like a quiet dead end.
    const state = reduce(
      [
        start(),
        {
          type: "layerDegraded",
          layerId: "L1",
          newChildren: 0,
          reports: [report({ outcome: { kind: "timeout", after_ms: 8000 } })],
        },
      ],
      rooted(),
    );

    expect(blockModel(state, "root")!.label).toContain("DEGRADED");
    expect(cardModel(state, "root")!.degraded).toBeUndefined();
    const input = toLayoutInput(state)!;
    expect(input.nodes.root.block!.kind).toBe("degraded");
    expect(layoutTree(input).bands).toHaveLength(1);
  });

  it("distinguishes a genuine empty dead end from a row-only tool's real findings (2026-08-26)", () => {
    // sidecar-holehe reports OkWithResults but seeds no child — a genuine ok-with-results
    // outcome must not render identically to a layer that found nothing at all.
    const withResults = reduce(
      [
        start(),
        {
          type: "layerEmpty",
          layerId: "L1",
          reports: [report({ toolId: "sidecar-holehe", outcome: { kind: "ok-with-results", count: 4 }, results: 4 })],
        },
      ],
      rooted(),
    );
    const genuineEmpty = reduce(
      [start(), { type: "layerEmpty", layerId: "L1", reports: [report()] }],
      rooted(),
    );

    expect(blockModel(withResults, "root")!.label).toBe("◇ 0 NEW ENTITIES · 4 RESULTS");
    expect(blockModel(genuineEmpty, "root")!.label).toBe("◇ 0 NEW ENTITIES");
    expect(blockModel(withResults, "root")!.label).not.toBe(blockModel(genuineEmpty, "root")!.label);
  });

  it("has no block for a degraded layer that did find children", () => {
    const state = reduce(
      [
        start(),
        { type: "node", layerId: "L1", node: node({ id: "a", parentId: "root" }) },
        { type: "layerDegraded", layerId: "L1", newChildren: 1, reports: [] },
      ],
      rooted(),
    );
    expect(blockModel(state, "root")).toBeNull();
    expect(cardModel(state, "root")!.degraded?.label).toBe(
      "1 NEW ENTITY · DEGRADED",
    );
  });
});

describe("cardModel", () => {
  it("carries the type mark and maps the wire's tone onto a palette tone", () => {
    const state = applyEvent(rooted(), {
      type: "parentPayload",
      layerId: "L1",
      nodeId: "root",
      patch: {},
      previewSignal: { text: "3 breaches", tone: "risk" },
    });
    const card = cardModel(state, "root")!;
    expect(card.mark.glyph).toBe("USR");
    expect(card.chip?.text).toBe("3 breaches");
    expect(card.chip?.tone.tier).toBeTruthy();
  });

  it("draws the correction rather than the value it replaced", () => {
    const state = applyEvent(rooted(), {
      type: "node",
      layerId: "L1",
      node: node({
        id: "a",
        parentId: "root",
        display: "Mathe0",
        editedValue: "matheo",
        provenance: {
          sourceToolId: "gravatar-profile",
          method: "queried Gravatar",
          retrievedAt: "2026-08-23T10:00:00Z",
          recordStatus: {
            kind: "corrected",
            originalValue: "Mathe0",
            editedAt: "2026-08-23T11:00:00Z",
          },
        },
      }),
    });
    const card = cardModel(state, "a")!;
    expect(card.value).toBe("matheo");
    expect(card.corrected).toBe(true);
    expect(card.rejected).toBe(false);
  });

  it("marks a rejected node so the tree shows the verdict, not just the panel", () => {
    const state = applyEvent(rooted(), {
      type: "node",
      layerId: "L1",
      node: node({
        id: "a",
        parentId: "root",
        provenance: {
          sourceToolId: "gravatar-profile",
          method: "queried Gravatar",
          retrievedAt: "2026-08-23T10:00:00Z",
          recordStatus: { kind: "rejected", rejectedAt: "2026-08-23T11:00:00Z" },
        },
      }),
    });
    expect(cardModel(state, "a")!.rejected).toBe(true);
  });

  it("names the routes of a corroborated value — decision 9", () => {
    const state = reduce(
      [
        start(),
        { type: "node", layerId: "L1", node: node({ id: "a", parentId: "root" }) },
        {
          type: "alreadyInTree",
          layerId: "L2",
          existingNodeId: "a",
          annotation: "already in tree · L1",
          foundAgainBy: {
            toolId: "gravatar-profile",
            method: "hashed the address",
            parentNodeId: "root",
            layerId: "L2",
            foundAt: "2026-08-23T10:05:00Z",
          },
          paths: 2,
        },
      ],
      rooted(),
    );
    expect(cardModel(state, "a")!.corroboration).toEqual({
      paths: 2,
      via: ["gravatar-profile"],
    });
  });

  it("dims a sibling that was never continued while another was", () => {
    const state = reduce(
      [
        start(),
        { type: "node", layerId: "L1", node: node({ id: "a", parentId: "root" }) },
        { type: "node", layerId: "L1", node: node({ id: "b", parentId: "root" }) },
        { type: "layerSettled", layerId: "L1", newChildren: 2, reports: [] },
        start({ layerId: "L2", parentNodeId: "a" }),
      ],
      rooted(),
    );
    expect(cardModel(state, "b")!.inert).toBe(true);
    expect(cardModel(state, "a")!.inert).toBe(false);
    expect(cardModel(state, "a")!.firing).toBe(true);
  });

  it("says nothing for a node it has never seen", () => {
    expect(cardModel(rooted(), "ghost")).toBeNull();
  });
});

describe("meterLine — decision 8", () => {
  it("renders real cents as euros", () => {
    expect(meterLine({ lookups: 47, costCents: 12 })).toBe("47 LOOKUPS · 0.12 €");
  });

  it("shows dashes rather than a zero that would read as free", () => {
    expect(meterLine(null)).toBe("— LOOKUPS · — €");
  });
});
