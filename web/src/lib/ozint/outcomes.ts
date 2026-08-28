/**
 * The engine goes to great lengths to keep "we could not look" apart from "we
 * looked and found nothing" — thirteen `ToolOutcome` variants, five settle
 * kinds — and the earlier design mock discarded all of it at the last inch, rendering
 * both as `0 NEW ENTITIES`. This module is where every variant gets a line of
 * its own, so a skipped tool can never be mistaken for a clean empty result.
 *
 * Nothing here decides layout; it turns one `ToolReport` into the words and the
 * tone that report deserves, and folds a layer's reports into the collapsed
 * one-line summary that sits on the connector.
 */

import type { ToolOutcome, ToolReport } from "@/lib/ozint/stream-parser";

import { TONES, type Tone } from "./tokens";

/**
 * The three things that can happen to a tool, kept separate because conflating
 * any two of them would let the UI report a finding that never happened.
 *
 *   - `ran` — the tool executed and answered. Zero results is a real finding.
 *   - `skipped` — the tool never executed. We know nothing either way.
 *   - `broke` — the tool executed and failed. We also know nothing, but for a
 *     reason worth retrying.
 */
export type OutcomeCategory = "ran" | "skipped" | "broke";

export interface OutcomeDescription {
  category: OutcomeCategory;
  /** Leading mark in the per-tool list. */
  symbol: string;
  /** The verb: `ran`, `skipped`, `failed`. */
  headline: string;
  /** Why — never empty for `skipped` or `broke`. */
  detail: string;
  tone: Tone;
  /** Whether firing the layer again could plausibly change this outcome. */
  retryable: boolean;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** Which of the three buckets an outcome falls in. */
export function categoryOf(outcome: ToolOutcome): OutcomeCategory {
  switch (outcome.kind) {
    case "ok-with-results":
    case "ok-empty":
      return "ran";
    case "skipped-no-key":
    case "skipped-gated-unarmed":
    case "skipped-phase-predicate":
    case "skipped-missing-input":
    case "skipped-circuit-open":
    case "cancelled":
      return "skipped";
    case "rate-limited-dropped":
    case "timeout":
    case "http-error":
    case "parse-error":
    case "forbidden":
      return "broke";
  }
}

export function describeOutcome(report: ToolReport): OutcomeDescription {
  const { outcome, elapsedMs } = report;
  const category = categoryOf(outcome);
  // Amber, never red, for everything that went wrong technically: a broken tool
  // is not a dangerous finding, and must never read as a security alert.
  const tone =
    category === "broke"
      ? TONES.warn
      : category === "skipped"
        ? TONES.mute
        : outcome.kind === "ok-with-results"
          ? TONES.ok
          : TONES.mute;

  const base = { category, tone };

  switch (outcome.kind) {
    case "ok-with-results":
      return {
        ...base,
        symbol: "✓",
        headline: "ran",
        detail: `${plural(outcome.count, "result")} · ${elapsedMs}ms`,
        retryable: false,
      };
    case "ok-empty":
      return {
        ...base,
        symbol: "✓",
        headline: "ran",
        detail: `0 results · ${elapsedMs}ms`,
        retryable: false,
      };
    case "skipped-no-key":
      return {
        ...base,
        symbol: "∅",
        headline: "skipped",
        detail: `no API key · ${outcome.env_var}`,
        retryable: false,
      };
    case "skipped-gated-unarmed":
      return {
        ...base,
        symbol: "∅",
        headline: "skipped",
        detail: `gated tool not armed · ${outcome.env_var}`,
        retryable: false,
      };
    case "skipped-phase-predicate":
      return {
        ...base,
        symbol: "∅",
        headline: "skipped",
        detail: outcome.reason,
        retryable: false,
      };
    case "skipped-missing-input":
      return {
        ...base,
        symbol: "∅",
        headline: "skipped",
        detail: `${outcome.input} unavailable · ${outcome.reason}`,
        retryable: false,
      };
    case "skipped-circuit-open":
      return {
        ...base,
        symbol: "∅",
        headline: "skipped",
        detail: outcome.retry_after
          ? `circuit open · retry after ${outcome.retry_after}`
          : "circuit open",
        retryable: true,
      };
    case "cancelled":
      return {
        ...base,
        symbol: "⊘",
        headline: "skipped",
        detail: "killed before it ran",
        retryable: true,
      };
    case "rate-limited-dropped":
      return {
        ...base,
        symbol: "✕",
        headline: "failed",
        detail: "dropped · rate limit",
        retryable: true,
      };
    case "timeout":
      return {
        ...base,
        symbol: "✕",
        headline: "failed",
        detail: `timed out after ${outcome.after_ms}ms`,
        retryable: true,
      };
    case "http-error":
      return {
        ...base,
        symbol: "✕",
        headline: "failed",
        detail: outcome.message
          ? `HTTP ${outcome.status} · ${outcome.message}`
          : `HTTP ${outcome.status}`,
        retryable: true,
      };
    case "parse-error":
      return {
        ...base,
        symbol: "✕",
        headline: "failed",
        detail: `unreadable response · ${outcome.message}`,
        retryable: true,
      };
    case "forbidden":
      return {
        ...base,
        symbol: "✕",
        headline: "failed",
        detail: outcome.message ? `refused · ${outcome.message}` : "refused",
        retryable: true,
      };
  }
}

export interface LayerToolSummary {
  total: number;
  ran: number;
  skipped: number;
  broke: number;
  /** The collapsed line that sits on the connector, one click from the detail. */
  line: string;
}

/**
 * The collapsed summary. It always states the total, so a plan of two tools and
 * a plan of seven where five were skipped can never look the same.
 */
export function summariseReports(reports: readonly ToolReport[]): LayerToolSummary {
  let ran = 0;
  let skipped = 0;
  let broke = 0;
  for (const report of reports) {
    const category = categoryOf(report.outcome);
    if (category === "ran") ran += 1;
    else if (category === "skipped") skipped += 1;
    else broke += 1;
  }
  const total = reports.length;
  const parts: string[] = [];
  if (ran > 0) parts.push(`${ran} ran`);
  if (skipped > 0) parts.push(`${skipped} skipped`);
  if (broke > 0) parts.push(`${broke} failed`);
  const line =
    total === 0
      ? "no tools planned"
      : `${plural(total, "tool")} · ${parts.join(", ")}`;
  return { total, ran, skipped, broke, line };
}

/** Terminal layer states, as the wire names them. */
export type SettleKind = "settled" | "empty" | "degraded" | "failed" | "aborted";

export interface LayerStateDescription {
  /** The headline drawn in the child row or on the parent card. */
  label: string;
  /** The line beneath it. Empty when the label says everything. */
  sub: string;
  tone: Tone;
  /** Whether to offer a retry. */
  retry: boolean;
  /** Whether this state is drawn as a block in the child row (no children). */
  block: boolean;
}

/**
 * `degraded` annotates a layer that *did* produce children, so it is
 * never a block; `failed` is the state that used to render as a clean dead end,
 * and it now says so in amber with a retry.
 *
 * `totalResults` (2026-08-26) is the sum of every tool's `ToolReport.results` in
 * this layer — distinct from `newChildren`, since a row-only tool
 * (`sidecar-holehe`, `geo-overpass`, …) can report real results while adding no
 * node at all. An `empty` settle with `totalResults > 0` used to render exactly
 * like a genuine "found nothing" dead end (`◇ 0 NEW ENTITIES` / `branch
 * terminates here`), which misled the analyst into skipping a node that was
 * actually carrying real findings in its own detail panel — caught on a live
 * run where holehe confirmed 4 accounts and the block still read as a dead end.
 */
export function describeLayerState(
  kind: SettleKind,
  newChildren: number,
  totalResults = 0,
): LayerStateDescription {
  switch (kind) {
    case "settled":
      return {
        label: `${newChildren} NEW ${newChildren === 1 ? "ENTITY" : "ENTITIES"}`,
        sub: "",
        tone: TONES.ok,
        retry: false,
        block: false,
      };
    case "degraded":
      return {
        label: `${newChildren} NEW ${newChildren === 1 ? "ENTITY" : "ENTITIES"} · DEGRADED`,
        sub: "some tools broke — this layer is incomplete",
        tone: TONES.warn,
        retry: true,
        block: false,
      };
    case "empty":
      return totalResults > 0
        ? {
            label: `◇ 0 NEW ENTITIES · ${totalResults} ${totalResults === 1 ? "RESULT" : "RESULTS"}`,
            sub: "no new node was created — see this node's own detail panel for what was found",
            tone: TONES.ok,
            retry: false,
            block: true,
          }
        : {
            label: "◇ 0 NEW ENTITIES",
            sub: "branch terminates here",
            tone: TONES.mute,
            retry: false,
            block: true,
          };
    case "failed":
      return {
        label: "◇ LAYER FAILED",
        sub: "no tool ran to completion — nothing was learned here",
        tone: TONES.warn,
        retry: true,
        block: true,
      };
    case "aborted":
      return {
        label: "◇ LAYER ABORTED",
        sub: "killed mid-flight · retry available",
        tone: TONES.risk,
        retry: true,
        block: true,
      };
  }
}
