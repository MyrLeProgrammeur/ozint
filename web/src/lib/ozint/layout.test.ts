import { describe, expect, it } from "vitest";

import {
  clampZoom,
  layoutTree,
  STANDARD_GEOMETRY as G,
  visibleNodes,
  type LayoutInput,
  type LayoutInputNode,
} from "./layout";

function node(
  id: string,
  children: string[] = [],
  extra: Partial<LayoutInputNode> = {},
): LayoutInputNode {
  return { id, children, ...extra };
}

function build(nodes: LayoutInputNode[], rootId = "r"): LayoutInput {
  return {
    rootId,
    nodes: Object.fromEntries(nodes.map((n) => [n.id, n])),
  };
}

describe("visibleNodes", () => {
  it("walks depth-first and reports depth", () => {
    const out = visibleNodes(
      build([node("r", ["a", "b"]), node("a", ["a1"]), node("a1"), node("b")]),
    );
    expect(out).toEqual([
      { id: "r", depth: 0 },
      { id: "a", depth: 1 },
      { id: "a1", depth: 2 },
      { id: "b", depth: 1 },
    ]);
  });

  it("ignores dangling child ids rather than throwing", () => {
    const out = visibleNodes(build([node("r", ["ghost"])]));
    expect(out).toEqual([{ id: "r", depth: 0 }]);
  });

  it("terminates on a cycle", () => {
    const out = visibleNodes(build([node("r", ["a"]), node("a", ["r"])]));
    expect(out.map((n) => n.id)).toEqual(["r", "a"]);
  });
});

describe("layoutTree", () => {
  it("places a lone root at the canvas padding", () => {
    const { positions, canvasWidth, canvasHeight, depth } = layoutTree(
      build([node("r")]),
    );
    expect(positions.r).toEqual({ id: "r", x: G.PAD, y: G.PAD, depth: 0 });
    expect(depth).toBe(0);
    expect(canvasWidth).toBe(G.PAD + G.W + G.PAD);
    expect(canvasHeight).toBe(G.PAD + G.H + G.PAD);
  });

  it("lays siblings left to right separated by the subtree gap", () => {
    const { positions } = layoutTree(
      build([node("r", ["a", "b"]), node("a"), node("b")]),
    );
    expect(positions.b.x - positions.a.x).toBe(G.W + G.HG);
    expect(positions.a.y).toBe(positions.b.y);
  });

  it("centres a parent over the midpoints of its first and last child", () => {
    const { positions } = layoutTree(
      build([node("r", ["a", "b", "c"]), node("a"), node("b"), node("c")]),
    );
    const first = positions.a.x + G.W / 2;
    const last = positions.c.x + G.W / 2;
    expect(positions.r.x + G.W / 2).toBeCloseTo((first + last) / 2);
  });

  it("uses one uniform pitch for every level so rails line up", () => {
    const { positions, pitch } = layoutTree(
      build([
        node("r", ["a"]),
        node("a", ["a1"]),
        node("a1", ["a2"]),
        node("a2"),
      ]),
    );
    expect(positions.a.y - positions.r.y).toBe(pitch);
    expect(positions.a1.y - positions.a.y).toBe(pitch);
    expect(positions.a2.y - positions.a1.y).toBe(pitch);
  });

  it("grows the pitch to clear the tallest layer band", () => {
    const plain = layoutTree(build([node("r", ["a"]), node("a")]));
    const tall = layoutTree(
      build([node("r", ["a"], { band: { height: 400 } }), node("a")]),
    );
    expect(plain.pitch).toBe(G.H + G.MIN_BAND + G.ROW_GAP);
    expect(tall.pitch).toBe(G.H + 400 + G.ROW_GAP);
  });

  it("emits only axis-aligned hairline connectors", () => {
    const { connectors } = layoutTree(
      build([node("r", ["a", "b"]), node("a"), node("b")]),
    );
    expect(connectors.length).toBeGreaterThan(0);
    for (const c of connectors) {
      expect(c.w === 1 || c.h === 1).toBe(true);
      expect(c.w).toBeGreaterThan(0);
      expect(c.h).toBeGreaterThan(0);
    }
  });

  it("interrupts the parent stem with the layer band", () => {
    const { connectors, bands } = layoutTree(
      build([node("r", ["a"], { band: { height: 90 } }), node("a")]),
    );
    const band = bands.find((b) => b.nodeId === "r");
    expect(band).toBeDefined();
    expect(band!.y).toBe(G.PAD + G.H + G.BAND_GAP);
    expect(band!.w).toBe(G.SW);
    // A short stem down to the band, and no connector crossing the band's box.
    const verticals = connectors.filter((c) => c.w === 1);
    expect(verticals.some((c) => c.h === G.BAND_GAP)).toBe(true);
    for (const c of verticals) {
      const crosses = c.y < band!.y && c.y + c.h > band!.y + band!.h;
      expect(crosses).toBe(false);
    }
  });

  it("reserves a block in the child row so the subtree width never collapses", () => {
    const { blocks, positions } = layoutTree(
      build([
        node("r", ["a", "b"]),
        node("a", [], { block: { kind: "empty", width: 330 } }),
        node("b"),
      ]),
    );
    const block = blocks.find((n) => n.nodeId === "a");
    expect(block).toEqual(
      expect.objectContaining({ kind: "empty", w: 330, h: G.BLOCK_H }),
    );
    // The wide block pushes its sibling clear of it.
    expect(positions.b.x).toBeGreaterThanOrEqual(block!.x + block!.w);
  });

  it("centres a blocked node's card over its own block", () => {
    const { blocks, positions } = layoutTree(
      build([node("r", [], { block: { kind: "firing", width: G.SW } })]),
    );
    const block = blocks[0];
    expect(positions.r.x + G.W / 2).toBeCloseTo(block.x + block.w / 2);
  });

  it("counts a block towards the canvas height", () => {
    const { canvasHeight, pitch } = layoutTree(
      build([node("r", [], { block: { kind: "failed", width: 330 } })]),
    );
    expect(canvasHeight).toBe(G.PAD + pitch + G.BLOCK_H + G.PAD);
  });

  it("ignores a block on a node that actually has children", () => {
    const { blocks } = layoutTree(
      build([
        node("r", ["a"], { block: { kind: "empty", width: 330 } }),
        node("a"),
      ]),
    );
    expect(blocks).toHaveLength(0);
  });

  it("treats a collapsed node (no children passed) as a leaf", () => {
    const expanded = layoutTree(
      build([node("r", ["a"]), node("a", ["a1", "a2"]), node("a1"), node("a2")]),
    );
    const collapsed = layoutTree(build([node("r", ["a"]), node("a")]));
    expect(collapsed.depth).toBe(1);
    expect(expanded.depth).toBe(2);
    expect(collapsed.canvasWidth).toBeLessThan(expanded.canvasWidth);
  });

  it("returns an empty layout for an unknown root rather than throwing", () => {
    const out = layoutTree(build([node("a")], "missing"));
    expect(out.cards).toEqual([]);
    expect(out.connectors).toEqual([]);
  });
});

describe("clampZoom", () => {
  it("holds the canvas between 0.4 and 1.25", () => {
    expect(clampZoom(0.1)).toBe(0.4);
    expect(clampZoom(9)).toBe(1.25);
    expect(clampZoom(0.7)).toBe(0.7);
  });

  it("rounds away float drift from repeated steps", () => {
    expect(clampZoom(0.7 + 0.1)).toBe(0.8);
  });
});
