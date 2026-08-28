import { describe, it, expect } from "vitest";
import { OzintStreamReader, LayerEventRouter, isTerminalLayerEvent } from "./stream-parser";
import type { LayerEvent, ParsedFrame } from "./stream-parser";

function frame(payload: unknown): string {
  return `data: ${JSON.stringify(payload)}\n\n`;
}

function okEvents(results: ParsedFrame[]): LayerEvent[] {
  for (const r of results) {
    expect(r.ok, r.ok ? "" : `unexpected malformed frame: ${JSON.stringify((r as { malformed: unknown }).malformed)}`).toBe(true);
  }
  return results.map((r) => (r as { ok: true; event: LayerEvent }).event);
}

describe("OzintStreamReader — whole frames", () => {
  it("parses a single complete frame delivered in one chunk", () => {
    const reader = new OzintStreamReader();
    const results = reader.push(frame({ type: "layerStart", layerId: "l1", investigationId: "inv", parentNodeId: "n1", firing: 2, maxPossible: 4, gated: 1 }));
    const events = okEvents(results);
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("layerStart");
    expect(events[0].layerId).toBe("l1");
  });

  it("parses several frames delivered in one chunk", () => {
    const reader = new OzintStreamReader();
    const chunk =
      frame({ type: "toolStart", layerId: "l1", toolId: "wmn", label: "WhatsMyName", gated: false }) +
      frame({ type: "toolDone", layerId: "l1", report: { toolId: "wmn", label: "WhatsMyName", outcome: { kind: "ok-empty" }, elapsedMs: 12, results: 0, gated: false, method: "probed sites" } });
    const events = okEvents(reader.push(chunk));
    expect(events.map((e) => e.type)).toEqual(["toolStart", "toolDone"]);
  });

  it("returns nothing until the closing delimiter arrives", () => {
    const reader = new OzintStreamReader();
    const whole = frame({ type: "summary", layerId: "l1", text: "done", fallback: false });
    const splitPoint = Math.floor(whole.length / 2);

    const firstHalf = reader.push(whole.slice(0, splitPoint));
    expect(firstHalf).toHaveLength(0);

    const secondHalf = okEvents(reader.push(whole.slice(splitPoint)));
    expect(secondHalf).toHaveLength(1);
    expect(secondHalf[0].type).toBe("summary");
  });

  it("handles a JSON object split across three separate chunks", () => {
    const reader = new OzintStreamReader();
    const whole = frame({ type: "node", layerId: "l1", node: sampleNode() });
    const third = Math.floor(whole.length / 3);

    expect(reader.push(whole.slice(0, third))).toHaveLength(0);
    expect(reader.push(whole.slice(third, third * 2))).toHaveLength(0);
    const events = okEvents(reader.push(whole.slice(third * 2)));
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("node");
  });

  it("buffers a frame that arrives with its own chunk boundary mid-frame, then completes on the next push with a new frame appended", () => {
    const reader = new OzintStreamReader();
    const first = frame({ type: "toolStart", layerId: "l1", toolId: "a", label: "A", gated: false });
    // Split the first frame's JSON in half, then append a second complete frame to the tail.
    const splitPoint = first.length - 4;
    const second = frame({ type: "layerEmpty", layerId: "l1", reports: [] });

    expect(reader.push(first.slice(0, splitPoint))).toHaveLength(0);
    const events = okEvents(reader.push(first.slice(splitPoint) + second));
    expect(events.map((e) => e.type)).toEqual(["toolStart", "layerEmpty"]);
  });
});

describe("OzintStreamReader — malformed frames are surfaced, never thrown or swallowed", () => {
  it("reports invalid JSON instead of throwing", () => {
    const reader = new OzintStreamReader();
    const results = reader.push("data: {not valid json\n\n");
    expect(results).toHaveLength(1);
    expect(results[0].ok).toBe(false);
    if (!results[0].ok) {
      expect(results[0].malformed.reason.length).toBeGreaterThan(0);
    }
  });

  it("reports a block with no data: line", () => {
    const reader = new OzintStreamReader();
    const results = reader.push("just some text with no prefix\n\n");
    expect(results).toHaveLength(1);
    expect(results[0].ok).toBe(false);
    if (!results[0].ok) {
      expect(results[0].malformed.reason).toContain("data:");
    }
  });

  it("reports valid JSON with an unrecognised type tag", () => {
    const reader = new OzintStreamReader();
    const results = reader.push(frame({ type: "somethingUnexpected", layerId: "l1" }));
    expect(results).toHaveLength(1);
    expect(results[0].ok).toBe(false);
  });

  it("reports valid JSON with no type tag at all", () => {
    const reader = new OzintStreamReader();
    const results = reader.push(frame({ layerId: "l1", message: "no type field" }));
    expect(results).toHaveLength(1);
    expect(results[0].ok).toBe(false);
  });

  it("one malformed frame does not block later well-formed frames in the same chunk", () => {
    const reader = new OzintStreamReader();
    const chunk = "data: {broken\n\n" + frame({ type: "summary", layerId: "l1", text: "ok", fallback: false });
    const results = reader.push(chunk);
    expect(results).toHaveLength(2);
    expect(results[0].ok).toBe(false);
    expect(results[1].ok).toBe(true);
  });
});

describe("OzintStreamReader — flush", () => {
  it("returns nothing when the stream ended cleanly on a frame boundary", () => {
    const reader = new OzintStreamReader();
    reader.push(frame({ type: "summary", layerId: "l1", text: "done", fallback: false }));
    expect(reader.flush()).toHaveLength(0);
  });

  it("surfaces a partial frame left over when the connection drops mid-frame", () => {
    const reader = new OzintStreamReader();
    const whole = frame({ type: "toolStart", layerId: "l1", toolId: "a", label: "A", gated: false });
    reader.push(whole.slice(0, whole.length - 6)); // drop the closing "}\n\n"
    const results = reader.flush();
    expect(results).toHaveLength(1);
    expect(results[0].ok).toBe(false);
  });
});

describe("isTerminalLayerEvent", () => {
  it("is true for every terminal settle kind", () => {
    const terminalTypes: LayerEvent["type"][] = ["layerSettled", "layerEmpty", "layerDegraded", "layerFailed", "layerAborted"];
    for (const type of terminalTypes) {
      expect(isTerminalLayerEvent({ type, layerId: "l1", reports: [] } as unknown as LayerEvent)).toBe(true);
    }
  });

  it("is false for a late summary, matching runtime.rs's ordering contract", () => {
    expect(isTerminalLayerEvent({ type: "summary", layerId: "l1", text: "x", fallback: true })).toBe(false);
  });

  it("is false for toolDone and error", () => {
    expect(isTerminalLayerEvent({ type: "error", message: "boom" })).toBe(false);
    expect(
      isTerminalLayerEvent({ type: "toolDone", layerId: "l1", report: sampleToolReport() }),
    ).toBe(false);
  });
});

describe("LayerEventRouter", () => {
  it("groups interleaved events from two concurrently running layers", () => {
    const router = new LayerEventRouter();
    const l1Start: LayerEvent = { type: "layerStart", layerId: "l1", investigationId: "inv", parentNodeId: "n1", firing: 1, maxPossible: 1, gated: 0 };
    const l2Start: LayerEvent = { type: "layerStart", layerId: "l2", investigationId: "inv", parentNodeId: "n2", firing: 1, maxPossible: 1, gated: 0 };
    const l1Done: LayerEvent = { type: "layerEmpty", layerId: "l1", reports: [] };
    const l2Done: LayerEvent = { type: "layerEmpty", layerId: "l2", reports: [] };

    // Interleaved arrival order, as the multiplexed stream would actually deliver them.
    router.route(l1Start);
    router.route(l2Start);
    router.route(l1Done);
    router.route(l2Done);

    expect(router.eventsFor("l1")).toEqual([l1Start, l1Done]);
    expect(router.eventsFor("l2")).toEqual([l2Start, l2Done]);
    expect(router.layerIds()).toEqual(["l1", "l2"]);
  });

  it("puts a layer-less error into the unrouted bucket, not into any layer", () => {
    const router = new LayerEventRouter();
    const err: LayerEvent = { type: "error", message: "stream-level failure" };
    router.route(err);
    expect(router.unroutedEvents()).toEqual([err]);
    expect(router.layerIds()).toEqual([]);
  });

  it("tracks settlement per layer independently", () => {
    const router = new LayerEventRouter();
    router.route({ type: "layerStart", layerId: "l1", investigationId: "inv", parentNodeId: "n1", firing: 1, maxPossible: 1, gated: 0 });
    router.route({ type: "layerStart", layerId: "l2", investigationId: "inv", parentNodeId: "n2", firing: 1, maxPossible: 1, gated: 0 });
    expect(router.isSettled("l1")).toBe(false);
    expect(router.isSettled("l2")).toBe(false);

    router.route({ type: "layerFailed", layerId: "l1", reports: [] });
    expect(router.isSettled("l1")).toBe(true);
    expect(router.isSettled("l2")).toBe(false);
  });

  it("returns an empty list for a layer never seen, without throwing", () => {
    const router = new LayerEventRouter();
    expect(router.eventsFor("never-seen")).toEqual([]);
  });
});

describe("ToolOutcome — the two variants the first mirror missed", () => {
  // `skipped-missing-input` and `cancelled` exist in `outcome.rs` (the 13th variant and the
  // kill-switch one) but were absent from this file's union. Both are exactly the outcomes
  // that must never render as a clean empty result.
  it("carries skipped-missing-input through with its input key and reason", () => {
    const reader = new OzintStreamReader();
    const events = okEvents(
      reader.push(
        frame({
          type: "toolDone",
          layerId: "l1",
          report: {
            ...sampleToolReport(),
            toolId: "peeringdb",
            outcome: {
              kind: "skipped-missing-input",
              input: "INPUT_ASN",
              reason: "no tool published it",
            },
          },
        }),
      ),
    );
    expect(events).toHaveLength(1);
    const event = events[0];
    if (event.type !== "toolDone") throw new Error("expected a toolDone frame");
    expect(event.report.outcome).toEqual({
      kind: "skipped-missing-input",
      input: "INPUT_ASN",
      reason: "no tool published it",
    });
  });

  it("carries cancelled through, so a killed layer keeps its unreached tools", () => {
    const reader = new OzintStreamReader();
    const events = okEvents(
      reader.push(
        frame({
          type: "toolDone",
          layerId: "l1",
          report: { ...sampleToolReport(), outcome: { kind: "cancelled" } },
        }),
      ),
    );
    const event = events[0];
    if (event.type !== "toolDone") throw new Error("expected a toolDone frame");
    expect(event.report.outcome.kind).toBe("cancelled");
  });
});

describe("parentPayload — decision 7, the parent card enriches mid-layer", () => {
  it("keeps the sections the server sends alongside the patch", () => {
    const reader = new OzintStreamReader();
    const events = okEvents(
      reader.push(
        frame({
          type: "parentPayload",
          layerId: "l1",
          nodeId: "node-1",
          patch: { asn: 15169 },
          sections: [{ title: "NETWORK", kind: "kv", rows: [] }],
        }),
      ),
    );
    const event = events[0];
    if (event.type !== "parentPayload") throw new Error("expected a parentPayload frame");
    expect(event.sections).toEqual([{ title: "NETWORK", kind: "kv", rows: [] }]);
  });
});

function sampleToolReport() {
  return {
    toolId: "wmn",
    label: "WhatsMyName",
    outcome: { kind: "ok-empty" as const },
    elapsedMs: 12,
    results: 0,
    gated: false,
    method: "probed sites",
  };
}

function sampleNode() {
  return {
    id: "node-1",
    investigationId: "inv-1",
    ordinal: 0,
    depth: 0,
    type: "username",
    value: "mtrebosc",
    display: "mtrebosc",
    dedupKey: "username:mtrebosc",
    payload: { type: "username", hits: [], sitesChecked: 0, sitesConfirmed: 0 },
    status: "idle",
    provenance: {
      sourceToolId: "seed",
      method: "typed by the analyst",
      retrievedAt: "2026-08-21T00:00:00Z",
      recordStatus: { kind: "as-returned" },
    },
    createdAt: "2026-08-21T00:00:00Z",
  };
}
