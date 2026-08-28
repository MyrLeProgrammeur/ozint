import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { layoutTree } from "./layout";
import { OzintStreamReader } from "@/lib/ozint/stream-parser";

import { applyEvent, emptyTreeState } from "./state";
import { bandModel, blockModel, cardModel, toLayoutInput } from "./view";

/**
 * The client half, run against bytes the real engine actually emitted.
 *
 * Every other test in this directory builds its own frames, which proves the
 * reducer self-consistent and proves nothing about whether these types match
 * what `runtime.rs` serialises. This fixture is a verbatim recording of
 * `POST /api/ozint/fire` with `{"seed":"torvalds"}` against a locally built
 * `ozint-server` — six tools of a possible seven fired, three returned, three
 * broke, the seventh was never armed, and the layer settled `degraded`.
 *
 * **Re-recorded 2026-08-23 against `e52fd11`**, which changed the frame
 * sequence: a fire stream now opens with a `node` frame for the node it fires
 * on, *before* `layerStart`. The previous recording predates that, and its
 * sharpest assertion was that the fired node never arrived — so this file could
 * not be left alone without pinning a contract the engine no longer has. It was
 * re-recorded rather than hand-edited, so it stays real bytes.
 *
 * It is a *recording*, not a golden expectation: the network decides what those
 * six tools answer, so the assertions below pin the contract (frames parse,
 * fields land where the mirror says) and never the findings.
 */
const RECORDING = readFileSync(
  fileURLToPath(new URL("./__fixtures__/fire-degraded.sse", import.meta.url)),
  "utf8",
);

/** Feed the recording in awkward slices, the way a socket would. */
function readAll(chunkSize: number) {
  const reader = new OzintStreamReader();
  const frames = [];
  for (let i = 0; i < RECORDING.length; i += chunkSize) {
    frames.push(...reader.push(RECORDING.slice(i, i + chunkSize)));
  }
  frames.push(...reader.flush());
  return frames;
}

describe("a recorded fire stream", () => {
  it("parses every frame the server sent, at any chunk boundary", () => {
    for (const chunkSize of [7, 64, 512, RECORDING.length]) {
      const frames = readAll(chunkSize);
      const malformed = frames.filter((f) => !f.ok);
      expect(malformed).toEqual([]);
      expect(frames).toHaveLength(17);
    }
  });

  it("reduces to a degraded layer — results found, tools broken", () => {
    const frames = readAll(64);
    let state = emptyTreeState();
    for (const frame of frames) {
      if (frame.ok) state = applyEvent(state, frame.event);
    }

    expect(state.investigationId).toBeTruthy();

    // The contract's sharpest edge, now the other way up. The stream used to
    // omit the node it fired on entirely — a client that only reduced frames
    // had a running layer and no tree to show it on, which is why
    // `store.hydrate` exists. `e52fd11` closed that at the source: the fired
    // node arrives first, *before* `layerStart`, because a client can only mark
    // *running* a node it already holds.
    const layer = Object.values(state.layers)[0];
    expect(Object.keys(state.nodes)).toEqual([layer.parentNodeId]);
    expect(state.nodes[layer.parentNodeId].display).toBe("torvalds");
    expect(state.rootNodeId).toBe(layer.parentNodeId);
    // And the ordering is the point, not an accident: the node frame precedes
    // `layerStart`, so the layer finds a node to mark running.
    const order = frames.flatMap((f) => (f.ok ? [f.event.type] : []));
    expect(order.indexOf("node")).toBeLessThan(order.indexOf("layerStart"));

    // …and that ordering has a consequence worth pinning where it actually
    // holds: reduce only as far as `layerStart` and the node is already there,
    // already marked running. By the end of the stream it has settled, so this
    // is the one point at which the claim is checkable.
    let midStream = emptyTreeState();
    for (const frame of frames) {
      if (!frame.ok) continue;
      midStream = applyEvent(midStream, frame.event);
      if (frame.event.type === "layerStart") break;
    }
    expect(midStream.nodes[layer.parentNodeId].status).toBe("running");

    expect(layer.status).toBe("degraded");
    expect(layer.firing).toBe(6);
    expect(layer.maxPossible).toBe(7);
    // Seven reports for six fired tools: the terminal frame accounts for the
    // tool that was never armed too. That extra row is in the real
    // engine's own output — an earlier design mock would have shown six.
    expect(layer.reports).toHaveLength(7);
    expect(
      layer.reports.filter((r) => r.outcome.kind === "skipped-no-key"),
    ).toHaveLength(1);

    // Everything below is now reached by reducing the stream alone — no
    // hydration, no synthetic node. That is the whole gain from `e52fd11`.
    const rootId = layer.parentNodeId;

    // Against real outcomes: the tools that broke and the tool that
    // was never armed are all still individually accounted for.
    const band = bandModel(state, rootId)!;
    expect(band.summary.total).toBe(7);
    expect(band.summary.broke).toBeGreaterThan(0);
    expect(band.summary.skipped).toBeGreaterThan(0);
    expect(band.summary.ran + band.summary.skipped + band.summary.broke).toBe(7);

    // The node we fired on grew sections while its own layer ran.
    expect(state.nodes[rootId].sections?.length).toBeGreaterThan(0);

    // As the real engine actually exercises it: this layer degraded
    // with *zero* children, so the amber verdict goes in the child row rather
    // than on the card — and, crucially, the node keeps a block, because
    // without one `layout.ts` would place no band and the seven tool rows above
    // would never be drawn at all.
    const block = blockModel(state, rootId)!;
    expect(block.label).toContain("DEGRADED");
    expect(block.tone.fg).toBe("#E8B15C");
    expect(block.retry).toBe(true);
    expect(cardModel(state, rootId)!.degraded).toBeUndefined();

    const placed = toLayoutInput(state)!.nodes[rootId];
    expect(placed.block?.kind).toBe("degraded");
    expect(placed.band!.height).toBeGreaterThan(0);
    expect(layoutTree(toLayoutInput(state)!).bands).toHaveLength(1);

    expect(layer.summary?.text).toBeTruthy();
  });
});
