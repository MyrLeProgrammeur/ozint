/**
 * The view model: the tree state, turned into what the canvas has to draw.
 *
 * `layout.ts` deliberately does not measure content — the caller owns that,
 * because the band has to hold the per-tool list and only the caller
 * knows how many tools a layer planned and whether the analyst has expanded it.
 * This module is that caller, kept pure and away from React so the whole thing
 * can be exercised without a DOM (there is no jsdom in this project's Vitest
 * setup, so a component's correctness has to live in functions like these).
 */

import type { OzNode, ToolReport } from "@/lib/ozint/stream-parser";

import {
  describeLayerState,
  summariseReports,
  type LayerStateDescription,
  type LayerToolSummary,
} from "./outcomes";
import {
  STANDARD_GEOMETRY,
  type LayerBlockKind,
  type LayoutInput,
  type LayoutInputNode,
  type TreeGeometry,
} from "./layout";
import {
  corroborationFor,
  effectiveValue,
  isInert,
  layerFor,
  type LayerState,
  type OzintTreeState,
} from "./state";
import { TONES, TYPE_MARKS, toneOf, type Tone, type TypeMark } from "./tokens";

/** Row heights inside the band, in px — the one place they are stated. */
export const BAND_METRICS = {
  /** The always-visible collapsed line. */
  header: 26,
  /** One tool's line in the expanded list. */
  toolRow: 20,
  /** One wrapped line of the summary note. */
  summaryLine: 15,
  /**
   * Characters that fit on one line of the note.
   *
   * Was 90, derived from 566px of band at a guessed 6.1px per glyph. Measured
   * in a real run it is wrong in the direction that hurts: the note element is
   * 552px wide with 6px of padding either side, the 11px face runs nearer
   * 6.7px per glyph, and a real degraded-layer note wrapped to five lines where
   * this predicted four — leaving 82px of text in a 68px box.
   *
   * Under-estimating the height clips the note; over-estimating only leaves a
   * little empty band. So this is now the measured figure rather than the
   * generous one, and the note scrolls if it still overflows.
   */
  summaryCharsPerLine: 72,
  /**
   * The note is a real sentence about what happened, not a caption. Clipping it
   * mid-word (which a fixed height did, at "…YouTube was") hides the reason a
   * layer degraded, so the band grows to fit — up to a point, past which the
   * note scrolls rather than pushing the whole tree apart.
   */
  summaryMaxLines: 6,
  padding: 12,
} as const;

/** Height to reserve for the summary note, from the note's own length. */
export function summaryHeight(text: string): number {
  const lines = Math.max(
    1,
    Math.ceil(text.length / BAND_METRICS.summaryCharsPerLine),
  );
  return (
    Math.min(lines, BAND_METRICS.summaryMaxLines) * BAND_METRICS.summaryLine + 8
  );
}

/**
 * How tall a layer's band must be. Collapsed, it is the header alone; expanded,
 * it grows by one row per tool — including the tools that never ran, which is
 * the whole point of listing every tool rather than only the ones that fired.
 */
export function bandHeight(
  layer: LayerState | undefined,
  expanded: boolean,
): number {
  if (!layer) return 0;
  const summaryRows = layer.summary ? summaryHeight(layer.summary.text) : 0;
  const toolRows = expanded ? layer.reports.length * BAND_METRICS.toolRow : 0;
  return BAND_METRICS.padding + BAND_METRICS.header + summaryRows + toolRows;
}

/**
 * What to draw in the child row of a layer that produced no children.
 *
 * Every childless layer gets something. That is not cosmetic: `layout.ts`
 * places a band only on a connector to a child row, so a childless layer with
 * no block loses its band — and with it the whole per-tool list. A
 * real run hit this (a `degraded` layer with zero new children) and rendered as
 * a bare card reading `0 NEW ENTITIES · DEGRADED`, with the four broken tools
 * and the unarmed one nowhere on screen.
 */
function blockKindFor(layer: LayerState): LayerBlockKind {
  switch (layer.status) {
    case "firing":
      return "firing";
    case "interrupted":
      return "interrupted";
    case "failed":
      return "failed";
    case "aborted":
      return "aborted";
    case "degraded":
      return "degraded";
    case "empty":
    case "settled":
      // A `settled` layer with no children is `empty` in all but name.
      return "empty";
  }
}

export interface ViewOptions {
  /** Nodes whose tool list is open. */
  expanded?: ReadonlySet<string>;
  /** Nodes whose children are hidden. */
  collapsed?: ReadonlySet<string>;
  geometry?: TreeGeometry;
}

/**
 * Build the layout engine's input from live tree state. A collapsed node keeps
 * its band (it is still a fact about that node) but contributes no children and
 * no block — hiding a subtree must not invent a dead end where there is one.
 */
export function toLayoutInput(
  state: OzintTreeState,
  options: ViewOptions = {},
): LayoutInput | null {
  if (!state.rootNodeId) return null;
  const geometry = options.geometry ?? STANDARD_GEOMETRY;
  const expanded = options.expanded ?? new Set<string>();
  const collapsed = options.collapsed ?? new Set<string>();

  const nodes: Record<string, LayoutInputNode> = {};
  for (const id of Object.keys(state.nodes)) {
    const layer = layerFor(state, id);
    const hidden = collapsed.has(id);
    const children = hidden ? [] : (state.children[id] ?? []);
    const node: LayoutInputNode = { id, children };

    const height = bandHeight(layer, expanded.has(id));
    if (height > 0) node.band = { height };

    if (layer && children.length === 0 && !hidden) {
      node.block = { kind: blockKindFor(layer), width: geometry.W };
    }
    nodes[id] = node;
  }

  return { rootId: state.rootNodeId, nodes, geometry };
}

export interface BandModel {
  layerId: string;
  summary: LayerToolSummary;
  reports: ToolReport[];
  /** The summary note, when the server sent one. `fallback` marks a canned one. */
  note?: { text: string; fallback: boolean };
  /** Still running: how many tools are in flight, and of how many planned. */
  running: number;
  firing: number;
  /**
   * Tools the plan could have fired with every key armed — "we
   * could not look" made countable. Equal to `firing` when nothing was held back.
   */
  maxPossible: number;
  gated: number;
  expandable: boolean;
  /**
   * The stored record of what ran no longer parses. The band says so instead of
   * showing the empty list that would otherwise read as "no tools planned".
   */
  reportsUnreadable: boolean;
  /**
   * Read back from storage, so `firing` / `maxPossible` / `gated` are not
   * recorded rather than zero — everything derived from them stays hidden.
   */
  fromStorage: boolean;
}

export function bandModel(
  state: OzintTreeState,
  nodeId: string,
): BandModel | null {
  const layer = layerFor(state, nodeId);
  if (!layer) return null;
  return {
    layerId: layer.id,
    summary: summariseReports(layer.reports),
    reports: layer.reports,
    note: layer.summary
      ? { text: layer.summary.text, fallback: layer.summary.fallback }
      : undefined,
    running: layer.running.length,
    firing: layer.firing,
    maxPossible: layer.maxPossible,
    gated: layer.gated,
    expandable: layer.reports.length > 0,
    reportsUnreadable: layer.reportsUnreadable === true,
    fromStorage: layer.fromStorage === true,
  };
}

export interface CardModel {
  node: OzNode;
  mark: TypeMark;
  /** The chip on the card, already mapped from the wire's tone vocabulary. */
  chip?: { text: string; tone: Tone; meta?: string; ratio?: number };
  /** Set when this value was found more than once. */
  corroboration?: { paths: number; via: string[] };
  /** Annotation for a layer that produced children but lost tools. */
  degraded?: LayerStateDescription;
  /** Whether this node's own layer is still firing. */
  firing: boolean;
  /** Dimmed: never continued while a sibling was. */
  inert: boolean;
  /** The node was found behind an ethical gate and is marked as such. */
  gated: boolean;
  /**
   * The value to draw: the analyst's correction when there is one. `display` is
   * never rewritten by an edit, so drawing it would show the analyst the value
   * they just corrected.
   */
  value: string;
  /** Marked wrong. Still in the tree, struck through, out of everything derived. */
  rejected: boolean;
  /** Corrected by the analyst. The card says so; the panel holds the original. */
  corrected: boolean;
}

export function cardModel(
  state: OzintTreeState,
  nodeId: string,
): CardModel | null {
  const node = state.nodes[nodeId];
  if (!node) return null;

  const layer = layerFor(state, nodeId);
  const corroborated = corroborationFor(state, nodeId);
  const chip = node.previewSignal;

  return {
    node,
    mark: TYPE_MARKS[node.type],
    chip: chip
      ? {
          text: chip.text,
          tone: toneOf(chip.tone),
          meta: chip.meta,
          ratio: chip.ratio,
        }
      : undefined,
    corroboration: corroborated
      ? {
          paths: corroborated.paths,
          via: corroborated.routes.map((route) => route.toolId),
        }
      : undefined,
    // Annotates a degraded layer on the card — but only when it has
    // children. A childless degraded layer says it in the child row instead,
    // where the band that carries its tool list can hang.
    degraded:
      layer?.status === "degraded" && (state.children[nodeId] ?? []).length > 0
        ? describeLayerState("degraded", layer.newChildren)
        : undefined,
    firing: layer?.status === "firing",
    inert: isInert(state, nodeId),
    gated: node.gated === true,
    value: effectiveValue(node),
    rejected: node.provenance?.recordStatus?.kind === "rejected",
    corrected: node.provenance?.recordStatus?.kind === "corrected",
  };
}

export interface BlockModel extends LayerStateDescription {
  layerId: string;
  /** Present while the layer is still firing rather than settled. */
  progress?: { running: number; firing: number };
}

/**
 * What to draw in an empty child row. A firing layer gets a live count rather
 * than a settle description — it has not settled into anything yet, and saying
 * `0 NEW ENTITIES` while tools are still out would be a lie.
 */
export function blockModel(
  state: OzintTreeState,
  nodeId: string,
): BlockModel | null {
  const layer = layerFor(state, nodeId);
  if (!layer) return null;
  // A layer with children says what it found on the cards themselves.
  if ((state.children[nodeId] ?? []).length > 0) return null;
  if (layer.status === "firing") {
    return {
      layerId: layer.id,
      label: "◇ SEARCHING",
      sub: `${layer.running.length} of ${layer.firing} tools in flight`,
      tone: TONES.mute,
      retry: false,
      block: true,
      progress: { running: layer.running.length, firing: layer.firing },
    };
  }
  if (layer.status === "interrupted") {
    // Neither a dead end nor a live search. The row exists, it was never
    // settled, and no verdict was ever written for it — so the retry is the
    // only thing that can turn it into an answer.
    return {
      layerId: layer.id,
      label: "◇ NEVER SETTLED",
      sub: "this layer was still running when its session ended — no verdict was recorded",
      tone: TONES.warn,
      retry: true,
      block: true,
    };
  }
  const kind = blockKindFor(layer);
  if (kind === "firing" || kind === "interrupted") return null;
  const totalResults = layer.reports.reduce((sum, r) => sum + r.results, 0);
  return { layerId: layer.id, ...describeLayerState(kind, layer.newChildren, totalResults) };
}

/**
 * The status-bar line. `costCents` is an integer count of cents, so it
 * is rendered to two decimals; a missing meter says so rather than showing a
 * zero that would read as "this cost nothing".
 */
export function meterLine(
  meter: { lookups: number; costCents: number } | null,
): string {
  if (!meter) return "— LOOKUPS · — €";
  const euros = (meter.costCents / 100).toFixed(2);
  return `${meter.lookups} LOOKUPS · ${euros} €`;
}
