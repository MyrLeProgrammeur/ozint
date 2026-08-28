/**
 * Tidy-tree layout for the OZINT cockpit canvas.
 *
 * Ported from an earlier hand-rolled layout pass, generalised so
 * the caller owns every measurement that depends on content:
 *
 *   - `band.height` is the height of the layer band that sits on the connector
 *     between a parent and its children (the summary note plus the collapsible
 *     per-tool list). Layout only reserves the space.
 *   - `block` is a terminal layer state drawn in the child row instead of
 *     children — firing, empty, failed, aborted.
 *
 * The pass is post-order: leaves are placed left to right at a running cursor,
 * a parent is centred over the midpoints of its first and last child card.
 * Collapsed nodes are passed in with no children and so behave as leaves.
 * Connectors are axis-aligned hairline rectangles only.
 */

export interface TreeGeometry {
  /** Card width. */
  W: number;
  /** Card height. */
  H: number;
  /** Horizontal gap between sibling subtrees. */
  HG: number;
  /** Width of the layer band (summary note + tool list). */
  SW: number;
  /** Canvas padding around the tree. */
  PAD: number;
  /** Height of a terminal layer-state block. */
  BLOCK_H: number;
  /** Distance from the child row up to the horizontal rail. */
  RAIL_OFFSET: number;
  /** Gap between a card's bottom edge and the layer band. */
  BAND_GAP: number;
  /** Vertical slack added to the pitch on top of card height + tallest band. */
  ROW_GAP: number;
  /** Minimum band height reserved even when no node has a band. */
  MIN_BAND: number;
}

export const STANDARD_GEOMETRY: TreeGeometry = {
  W: 292,
  H: 212,
  HG: 28,
  SW: 566,
  PAD: 64,
  BLOCK_H: 74,
  RAIL_OFFSET: 22,
  BAND_GAP: 14,
  ROW_GAP: 52,
  MIN_BAND: 60,
};

export const COMPACT_GEOMETRY: TreeGeometry = {
  ...STANDARD_GEOMETRY,
  W: 262,
  H: 200,
  HG: 24,
  SW: 470,
  PAD: 56,
};

/**
 * A layer that produced no children still has to say *why*.
 *
 * `degraded` is here despite elsewhere being treated as a card annotation.
 * That treatment assumed a degraded layer always has children; a real
 * recorded run proved otherwise — six tools fired, two returned nothing, four
 * broke, and the layer settled `degraded` with zero new children. With no
 * children and no block there is no child row, and a band is only ever placed
 * on one, so the entire per-tool list would silently vanish in exactly the
 * case this taxonomy exists to expose. A childless degraded layer gets a block.
 */
export type LayerBlockKind =
  | "firing"
  | "empty"
  | "failed"
  | "aborted"
  | "degraded"
  /** Read back from storage still marked `running`: it never settled. */
  | "interrupted";

export interface LayoutInputNode {
  id: string;
  /** Visible children, in display order. Empty for a leaf or a collapsed node. */
  children: string[];
  /** Space to reserve for the layer band on the connector below this node. */
  band?: { height: number };
  /** Terminal layer state drawn in the child row. Ignored when `children` is non-empty. */
  block?: { kind: LayerBlockKind; width: number };
}

export interface LayoutInput {
  rootId: string;
  nodes: Record<string, LayoutInputNode>;
  geometry?: TreeGeometry;
}

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface PlacedCard {
  id: string;
  x: number;
  y: number;
  depth: number;
}

export interface PlacedBand extends Rect {
  nodeId: string;
}

export interface PlacedBlock extends Rect {
  nodeId: string;
  kind: LayerBlockKind;
}

export interface LayoutResult {
  cards: PlacedCard[];
  positions: Record<string, PlacedCard>;
  /** Axis-aligned hairline rectangles. 1px on their thin axis. */
  connectors: Rect[];
  bands: PlacedBand[];
  blocks: PlacedBlock[];
  canvasWidth: number;
  canvasHeight: number;
  /** Uniform vertical distance between one card row and the next. */
  pitch: number;
  /** Deepest depth reached, root = 0. */
  depth: number;
}

/** Depth-first walk of the visible tree, guarding against cycles and dangling ids. */
export function visibleNodes(
  input: LayoutInput,
): Array<{ id: string; depth: number }> {
  const out: Array<{ id: string; depth: number }> = [];
  const seen = new Set<string>();
  const walk = (id: string, depth: number): void => {
    if (seen.has(id)) return;
    const node = input.nodes[id];
    if (!node) return;
    seen.add(id);
    out.push({ id, depth });
    for (const child of node.children) walk(child, depth + 1);
  };
  walk(input.rootId, 0);
  return out;
}

export function layoutTree(input: LayoutInput): LayoutResult {
  const g = input.geometry ?? STANDARD_GEOMETRY;
  const visible = visibleNodes(input);
  const visibleIds = new Set(visible.map((v) => v.id));

  let maxBand = g.MIN_BAND;
  for (const { id } of visible) {
    const band = input.nodes[id]?.band;
    if (band && band.height > maxBand) maxBand = band.height;
  }
  const pitch = g.H + maxBand + g.ROW_GAP;

  const cards: PlacedCard[] = [];
  const positions: Record<string, PlacedCard> = {};
  const connectors: Rect[] = [];
  const bands: PlacedBand[] = [];
  const blocks: PlacedBlock[] = [];
  let maxRight = 0;
  let maxBottom = 0;
  let maxDepth = 0;

  const hairline = (x: number, y: number, w: number, h: number): void => {
    if (w <= 0 || h <= 0) return;
    connectors.push({ x: Math.round(x), y: Math.round(y), w, h });
  };

  interface Placed {
    x0: number;
    width: number;
    selfX: number;
  }

  const place = (id: string, depth: number, x0: number): Placed => {
    const node = input.nodes[id];
    const y = g.PAD + depth * pitch;
    maxDepth = Math.max(maxDepth, depth);

    const children = (node?.children ?? []).filter((c) => visibleIds.has(c));
    const bandHeight = node?.band?.height ?? 0;
    const block = children.length > 0 ? undefined : node?.block;

    let width: number;
    let selfX: number;

    if (children.length > 0) {
      let cursor = x0;
      let first: Placed | null = null;
      let last: Placed | null = null;
      for (const child of children) {
        const placed = place(child, depth + 1, cursor);
        if (!first) first = placed;
        last = placed;
        cursor = placed.x0 + placed.width + g.HG;
      }
      const span = last!.x0 + last!.width - x0;
      width = Math.max(span, bandHeight > 0 ? g.SW : g.W);

      const firstCentre = first!.selfX + g.W / 2;
      const lastCentre = last!.selfX + g.W / 2;
      const centre = (firstCentre + lastCentre) / 2;
      selfX = centre - g.W / 2;

      const railY = y + pitch - g.RAIL_OFFSET;
      if (bandHeight > 0) {
        const bandY = y + g.H + g.BAND_GAP;
        bands.push({
          nodeId: id,
          x: centre - g.SW / 2,
          y: bandY,
          w: g.SW,
          h: bandHeight,
        });
        hairline(centre, y + g.H, 1, g.BAND_GAP);
        hairline(centre, bandY + bandHeight, 1, railY - (bandY + bandHeight));
      } else {
        hairline(centre, y + g.H, 1, railY - (y + g.H));
      }
      hairline(
        Math.min(firstCentre, lastCentre),
        railY,
        Math.abs(lastCentre - firstCentre) || 1,
        1,
      );
      for (const child of children) {
        hairline(positions[child].x + g.W / 2, railY, 1, y + pitch - railY);
      }
    } else if (block) {
      width = Math.max(block.width, bandHeight > 0 ? g.SW : g.W);
      selfX = x0 + width / 2 - g.W / 2;
      const centre = selfX + g.W / 2;
      blocks.push({
        nodeId: id,
        kind: block.kind,
        x: centre - block.width / 2,
        y: y + pitch,
        w: block.width,
        h: g.BLOCK_H,
      });
      if (bandHeight > 0) {
        const bandY = y + g.H + g.BAND_GAP;
        bands.push({
          nodeId: id,
          x: centre - g.SW / 2,
          y: bandY,
          w: g.SW,
          h: bandHeight,
        });
        hairline(centre, y + g.H, 1, g.BAND_GAP);
        hairline(centre, bandY + bandHeight, 1, y + pitch - (bandY + bandHeight));
      } else {
        hairline(centre, y + g.H, 1, pitch - g.H);
      }
      maxBottom = Math.max(maxBottom, y + pitch + g.BLOCK_H);
    } else {
      width = g.W;
      selfX = x0;
    }

    const card: PlacedCard = { id, x: selfX, y, depth };
    cards.push(card);
    positions[id] = card;
    maxRight = Math.max(maxRight, x0 + width, selfX + g.W);
    maxBottom = Math.max(maxBottom, y + g.H);

    return { x0, width, selfX };
  };

  if (input.nodes[input.rootId]) place(input.rootId, 0, g.PAD);

  return {
    cards,
    positions,
    connectors,
    bands,
    blocks,
    canvasWidth: maxRight + g.PAD,
    canvasHeight: maxBottom + g.PAD,
    pitch,
    depth: maxDepth,
  };
}

/** Zoom bounds and step, from the original canvas controls. */
export const ZOOM_MIN = 0.4;
export const ZOOM_MAX = 1.25;
export const ZOOM_STEP = 0.1;

export function clampZoom(z: number): number {
  return Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, Math.round(z * 100) / 100));
}
