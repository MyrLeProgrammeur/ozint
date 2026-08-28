/**
 * The node detail panel's view model.
 *
 * Kept pure and away from React for the same reason `view.ts` is: this project's
 * Vitest setup has no jsdom, so a panel's correctness has to live in functions
 * that can be called without a DOM.
 *
 * Two things here are contract, not styling:
 *
 *   - **Provenance is always the first section**, and it is five fixed rows —
 *     `found via` / `source` / `how it was obtained` / `retrieved` /
 *     `record status` — mapping 1:1 onto the engine's `Provenance`. Every row is
 *     always present. A provenance row that vanished when its field was absent
 *     would let "the engine did not tell us how this was obtained" render as a
 *     panel that simply looks complete.
 *   - **`recordStatus` is rendered in full.** `corrected` names the value the
 *     tool actually returned, and `rejected` says the node is excluded from the
 *     subject file. A correction that hid the original would turn an analyst's
 *     edit into an unfalsifiable claim about what a source said.
 *
 * The panel reads the node the tree already holds. Nothing here fetches: the
 * persisted `sections` arrive with the node from
 * `GET /api/ozint/investigations/{id}`, which the store hydrates from.
 */

import type {
  OzNode,
  OzSection,
  Provenance,
  RecordStatus,
} from "@/lib/ozint/stream-parser";

import {
  corroborationFor,
  effectiveValue,
  layerFor,
  type OzintTreeState,
} from "./state";
import { TONES, TYPE_MARKS, toneOf, type Tone, type TypeMark } from "./tokens";

/** The provenance block's rows, in the fixed order they are drawn. */
export const PROVENANCE_LABELS = [
  "found via",
  "source",
  "how it was obtained",
  "retrieved",
  "record status",
] as const;

export type ProvenanceLabel = (typeof PROVENANCE_LABELS)[number];

export interface DetailRow {
  label: string;
  value: string;
  href?: string;
  /** A second, quieter line under the value — the original of a corrected value. */
  detail?: string;
  at?: string;
  tone?: Tone;
  gated?: boolean;
}

export interface DetailSection {
  id: string;
  label: string;
  kind: OzSection["kind"];
  rows: DetailRow[];
}

/** What a chip in the horizontal jump row has to know. */
export interface JumpChip {
  sectionId: string;
  label: string;
}

export interface DetailModel {
  node: OzNode;
  mark: TypeMark;
  /** `LAYER 2`, from the node's own depth. The root is `LAYER 0`. */
  layerLabel: string;
  /** The value, verbatim. Struck through when the analyst marked it wrong. */
  value: string;
  chip?: { text: string; tone: Tone; meta?: string; ratio?: number };
  /** `via github-user → gravatar-profile`, the full chain when there is one. */
  toolChain: string;
  gated: boolean;
  /** Corroboration routes, repeated in the panel where the full chain lives. */
  corroboration?: { paths: number; via: string[] };
  /**
   * Set when the analyst rejected this node. The panel strikes the value
   * through and says, in words, that it no longer feeds the subject file.
   */
  rejected?: { at: string; note: string };
  corrected?: { originalValue: string; at: string };
  /** Whether this node's own layer is still firing — `CONTINUE` is offered anyway. */
  firing: boolean;
  /** The one external link the engine actually produces, when it produced one. */
  link?: { label: string; href: string };
  sections: DetailSection[];
  jumps: JumpChip[];
  /**
   * A relation node is an inference, not a finding: the panel ends with a
   * `NOT SEARCHED` block saying that searching this person means starting a
   * separate root investigation. Both meanings of `NOT SEARCHED` are real; this
   * is the analyst-facing one, which keeps the words.
   */
  notSearched: boolean;
}

/** The id the provenance block always carries, so a jump chip can target it. */
export const PROVENANCE_SECTION_ID = "provenance";

/**
 * The earlier design mock gives the panel a `SOURCE ↗` button on every node.
 * The engine has no such field: no payload carries "the URL this node came
 * from". Two
 * payloads do carry a real link — a directory tile's `url`, and a coordinate's
 * `mapLinks` — and those are the only two this returns.
 *
 * Everything else gets **no button at all**, deliberately. A `SOURCE ↗` wired to
 * a guessed URL is worse than an absent one: provenance is the part of this
 * cockpit an analyst is entitled to trust literally.
 */
export function externalLink(
  node: OzNode,
): { label: string; href: string } | undefined {
  const payload = node.payload as Record<string, unknown>;

  const url = payload.url;
  if (typeof url === "string" && /^https?:\/\//i.test(url)) {
    return { label: "SOURCE ↗", href: url };
  }

  const mapLinks = payload.mapLinks;
  if (Array.isArray(mapLinks)) {
    for (const link of mapLinks) {
      const href = (link as { href?: unknown })?.href;
      if (typeof href === "string" && /^https?:\/\//i.test(href)) {
        return { label: "OPEN IN MAPS ↗", href };
      }
    }
  }

  return undefined;
}

/**
 * `2026-08-23T14:02:11Z` → `2026-08-23 14:02 UTC`.
 *
 * Rendered in UTC on purpose, and never through a locale: a retrieval time is
 * evidence, and two analysts reading the same investigation must read the same
 * instant. An unparseable timestamp is shown verbatim rather than as an
 * `Invalid Date` that would look like a rendering bug instead of a data one.
 */
export function formatRetrieved(iso: string | undefined): string {
  if (!iso) return "—";
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  const [date, time] = at.toISOString().split("T");
  return `${date} ${time.slice(0, 5)} UTC`;
}

/** The `record status` row's words, from the three `RecordStatus` variants. */
export function describeRecordStatus(status: RecordStatus | undefined): {
  value: string;
  detail?: string;
  tone: Tone;
} {
  if (!status) {
    // The engine always sends one. If it did not, say so rather than assuming
    // the benign case — "as returned by the tool" is a claim about a source.
    return { value: "unknown — the engine sent no record status", tone: TONES.warn };
  }
  switch (status.kind) {
    case "as-returned":
      return { value: "as returned by the tool", tone: TONES.mute };
    case "corrected": {
      const original = status.originalChip
        ? `${status.originalValue} · ${status.originalChip.text}`
        : status.originalValue;
      return {
        value: "corrected by the analyst",
        detail: `tool returned "${original}"`,
        tone: TONES.warn,
      };
    }
    case "rejected":
      return {
        value: "marked wrong by the analyst",
        detail: "excluded from the subject file",
        tone: TONES.risk,
      };
  }
}

/** The five fixed provenance rows, always all five. */
export function provenanceRows(
  provenance: Provenance | undefined,
  parentDisplay: string | undefined,
  parentDepth: number | undefined,
): DetailRow[] {
  const record = describeRecordStatus(provenance?.recordStatus);
  const foundVia =
    parentDisplay === undefined
      ? // The root was not found via anything: it is what the analyst typed.
        "the seed value — this is the root"
      : parentDepth === undefined
        ? parentDisplay
        : `${parentDisplay} · L${parentDepth}`;

  return [
    { label: "found via", value: foundVia },
    { label: "source", value: provenance?.sourceToolId ?? "—" },
    { label: "how it was obtained", value: provenance?.method ?? "—" },
    { label: "retrieved", value: formatRetrieved(provenance?.retrievedAt) },
    {
      label: "record status",
      value: record.value,
      detail: record.detail,
      tone: record.tone,
    },
  ];
}

function toDetailSection(section: OzSection): DetailSection {
  return {
    id: section.id,
    label: section.label,
    kind: section.kind,
    rows: section.rows.map((row) => ({
      label: row.label,
      value: row.value,
      href: row.href,
      at: row.at,
      tone: row.tone ? toneOf(row.tone) : undefined,
      gated: row.gated === true,
    })),
  };
}

export function detailModel(
  state: OzintTreeState,
  nodeId: string,
): DetailModel | null {
  const node = state.nodes[nodeId];
  if (!node) return null;

  const parent = node.provenance?.foundViaParentId
    ? state.nodes[node.provenance.foundViaParentId]
    : node.parentId
      ? state.nodes[node.parentId]
      : undefined;

  const provenanceSection: DetailSection = {
    id: PROVENANCE_SECTION_ID,
    label: "PROVENANCE",
    kind: "key-value",
    rows: provenanceRows(node.provenance, parent?.display, parent?.depth),
  };

  const sections = [
    provenanceSection,
    ...(node.sections ?? []).map(toDetailSection),
  ];

  const status = node.provenance?.recordStatus;
  const corroborated = corroborationFor(state, nodeId);
  const chain = node.provenance?.toolChain;

  return {
    node,
    mark: TYPE_MARKS[node.type],
    layerLabel: `LAYER ${node.depth}`,
    // The correction, when the analyst made one. The tool's original is not
    // lost — it is the `record status` row, two sections down.
    value: effectiveValue(node),
    chip: node.fullSignal
      ? {
          text: node.fullSignal.text,
          tone: toneOf(node.fullSignal.tone),
          meta: node.fullSignal.meta,
          ratio: node.fullSignal.ratio,
        }
      : node.previewSignal
        ? {
            text: node.previewSignal.text,
            tone: toneOf(node.previewSignal.tone),
            meta: node.previewSignal.meta,
            ratio: node.previewSignal.ratio,
          }
        : undefined,
    toolChain:
      chain && chain.length > 0
        ? chain.join(" → ")
        : (node.provenance?.sourceToolId ?? "—"),
    gated: node.gated === true || node.provenance?.gated === true,
    corroboration: corroborated
      ? {
          paths: corroborated.paths,
          via: corroborated.routes.map((route) => route.toolId),
        }
      : undefined,
    rejected:
      status?.kind === "rejected"
        ? { at: formatRetrieved(status.rejectedAt), note: "excluded from the subject file" }
        : undefined,
    corrected:
      status?.kind === "corrected"
        ? {
            originalValue: status.originalValue,
            at: formatRetrieved(status.editedAt),
          }
        : undefined,
    firing: layerFor(state, nodeId)?.status === "firing",
    link: externalLink(node),
    sections,
    jumps: sections.map((section) => ({
      sectionId: section.id,
      label: section.label,
    })),
    notSearched: node.type === "name" && Boolean(node.parentId),
  };
}
