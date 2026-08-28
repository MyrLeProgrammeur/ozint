/**
 * PAST INVESTIGATIONS — the list behind `GET /api/ozint/investigations`, and the
 * row model the overlay draws.
 *
 * **Reopening is resumable, not read-only.** The earlier design mock shows an archive with
 * an `ARCHIVE · READ-ONLY` chip and every action disabled; the backend settled
 * the opposite — `spawn.rs` notes there is no read-only state anywhere in the
 * data model. `POST /api/ozint/fire
 * {investigationId, parentNodeId}` rebuilds the visited set from the stored tree
 * and keeps going, and edit/reject/restore are local writes that are live even
 * while the kill switch is frozen. So the chip is deleted rather than
 * reinterpreted, and a reopened investigation is simply the current one.
 *
 * What the list route does **not** carry is a node or layer count — the
 * earlier design mock's `19 nodes · 5 layers` line. `Investigation` is the row from
 * `oz_investigations` and holds neither, and counting them would mean fetching
 * every investigation in full. The row states what the row knows: when, what
 * was searched, and what it cost.
 */

import { TYPE_MARKS, type OzTypeName } from "./tokens";

/** `ozint::Investigation`, as the list and detail routes serialise it. */
export interface Investigation {
  id: string;
  /** The seed exactly as the analyst typed it, before normalisation. */
  seedInput: string;
  seedType: OzTypeName;
  rootNodeId: string;
  /** ISO-8601. */
  createdAt: string;
  /** ISO-8601. */
  updatedAt: string;
  lookups: number;
  costCents: number;
  /** One-way link back to the investigation whose relation card spawned this one. */
  spawnedFromInvestigationId?: string;
  spawnedFromRelation?: string;
}

export interface HistoryRow {
  id: string;
  /** The 78px date column. */
  when: string;
  /** The seed, verbatim. */
  value: string;
  typeGlyph: string;
  typeLabel: string;
  /** The mono stats line under the seed — only ever facts the row carries. */
  stats: string;
  /** Present when this investigation was spawned from another one's relation. */
  spawnedFrom?: string;
}

/** `2026-08-23 14:07`, in the viewer's own zone. Never a "3 days ago". */
export function formatWhen(iso: string): string {
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return "date unreadable";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())} ${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

/**
 * The cost line. `costCents` is an integer count of cents; zero is a real
 * answer (every tool used was free) and says so in words rather than as
 * `0.00 €`, which reads like a missing measurement.
 */
export function formatCost(costCents: number): string {
  if (costCents === 0) return "no paid tool";
  return `${(costCents / 100).toFixed(2)} €`;
}

export function historyRow(investigation: Investigation): HistoryRow {
  const mark = TYPE_MARKS[investigation.seedType];
  const lookups = investigation.lookups;
  return {
    id: investigation.id,
    when: formatWhen(investigation.createdAt),
    value: investigation.seedInput,
    typeGlyph: mark?.glyph ?? "???",
    typeLabel: mark?.label ?? investigation.seedType,
    stats: `${lookups} ${lookups === 1 ? "lookup" : "lookups"} · ${formatCost(investigation.costCents)}`,
    spawnedFrom: investigation.spawnedFromRelation,
  };
}
