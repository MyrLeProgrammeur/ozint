import { describe, expect, it } from "vitest";

import type { ToolOutcome, ToolReport } from "@/lib/ozint/stream-parser";

import {
  categoryOf,
  describeLayerState,
  describeOutcome,
  summariseReports,
} from "./outcomes";
import { TONES } from "./tokens";

function report(outcome: ToolOutcome, over: Partial<ToolReport> = {}): ToolReport {
  return {
    toolId: "github-user",
    label: "GitHub",
    outcome,
    elapsedMs: 340,
    results: 0,
    gated: false,
    method: "queried the users API",
    ...over,
  };
}

/** Every variant of the union, so a new one cannot slip through untested. */
const ALL_OUTCOMES: ToolOutcome[] = [
  { kind: "ok-with-results", count: 3 },
  { kind: "ok-empty" },
  { kind: "skipped-no-key", env_var: "HIBP_API_KEY" },
  { kind: "skipped-gated-unarmed", env_var: "OZINT_ARM_FACE_SEARCH" },
  { kind: "skipped-phase-predicate", reason: "no domain in this branch" },
  { kind: "skipped-missing-input", input: "INPUT_ASN", reason: "nobody published it" },
  { kind: "skipped-circuit-open", retry_after: "2026-08-23T19:00:00Z" },
  { kind: "cancelled" },
  { kind: "rate-limited-dropped" },
  { kind: "timeout", after_ms: 8000 },
  { kind: "http-error", status: 503, message: "upstream down" },
  { kind: "parse-error", message: "not JSON" },
  { kind: "forbidden", message: "licence forbids it" },
];

describe("describeOutcome — all thirteen variants", () => {
  it("covers every variant with a non-empty verb", () => {
    expect(ALL_OUTCOMES).toHaveLength(13);
    for (const outcome of ALL_OUTCOMES) {
      const d = describeOutcome(report(outcome));
      expect(d.headline, outcome.kind).not.toBe("");
      expect(d.symbol, outcome.kind).not.toBe("");
    }
  });

  it("never lets a tool that did not run pass as a clean empty result", () => {
    const empty = describeOutcome(report({ kind: "ok-empty" }));
    for (const outcome of ALL_OUTCOMES) {
      if (outcome.kind === "ok-empty") continue;
      const d = describeOutcome(report(outcome));
      expect(
        d.headline !== empty.headline || d.detail !== empty.detail,
        `${outcome.kind} renders identically to ok-empty`,
      ).toBe(true);
    }
  });

  it("always gives a reason for a tool that did not run", () => {
    for (const outcome of ALL_OUTCOMES) {
      const d = describeOutcome(report(outcome));
      if (d.category === "ran") continue;
      expect(d.detail.length, outcome.kind).toBeGreaterThan(0);
    }
  });

  it("reads the 13th variant's input key and reason back out", () => {
    const d = describeOutcome(
      report({ kind: "skipped-missing-input", input: "INPUT_ASN", reason: "nobody published it" }),
    );
    expect(d.category).toBe("skipped");
    expect(d.detail).toContain("INPUT_ASN");
    expect(d.detail).toContain("nobody published it");
  });

  it("names the env var a missing key needs, so it is actionable", () => {
    const d = describeOutcome(report({ kind: "skipped-no-key", env_var: "HIBP_API_KEY" }));
    expect(d.detail).toContain("HIBP_API_KEY");
  });

  it("keeps a killed tool distinct from one that was never planned", () => {
    const d = describeOutcome(report({ kind: "cancelled" }));
    expect(d.detail).toBe("killed before it ran");
    expect(d.retryable).toBe(true);
  });

  it("paints technical breakage amber, never red", () => {
    for (const outcome of ALL_OUTCOMES) {
      const d = describeOutcome(report(outcome));
      if (d.category !== "broke") continue;
      expect(d.tone, outcome.kind).toEqual(TONES.warn);
    }
  });

  it("sorts each variant into the right bucket", () => {
    expect(categoryOf({ kind: "ok-empty" })).toBe("ran");
    expect(categoryOf({ kind: "skipped-no-key", env_var: "X" })).toBe("skipped");
    expect(categoryOf({ kind: "timeout", after_ms: 1 })).toBe("broke");
  });
});

describe("summariseReports — the collapsed line", () => {
  it("states the plan's total, not just what ran", () => {
    const s = summariseReports([
      report({ kind: "ok-with-results", count: 2 }),
      report({ kind: "ok-empty" }),
      report({ kind: "skipped-no-key", env_var: "A" }),
      report({ kind: "skipped-no-key", env_var: "B" }),
      report({ kind: "skipped-circuit-open" }),
      report({ kind: "skipped-missing-input", input: "I", reason: "r" }),
      report({ kind: "skipped-phase-predicate", reason: "r" }),
    ]);
    expect(s).toMatchObject({ total: 7, ran: 2, skipped: 5, broke: 0 });
    expect(s.line).toBe("7 tools · 2 ran, 5 skipped");
  });

  it("distinguishes a two-tool plan from five skips in a seven-tool plan", () => {
    const small = summariseReports([
      report({ kind: "ok-empty" }),
      report({ kind: "ok-empty" }),
    ]);
    const large = summariseReports([
      report({ kind: "ok-empty" }),
      report({ kind: "ok-empty" }),
      ...Array.from({ length: 5 }, () =>
        report({ kind: "skipped-no-key", env_var: "K" }),
      ),
    ]);
    expect(small.line).not.toBe(large.line);
  });

  it("counts broken tools separately from skipped ones", () => {
    const s = summariseReports([
      report({ kind: "ok-empty" }),
      report({ kind: "timeout", after_ms: 8000 }),
      report({ kind: "skipped-no-key", env_var: "K" }),
    ]);
    expect(s.line).toBe("3 tools · 1 ran, 1 skipped, 1 failed");
  });

  it("says so when a layer had no plan at all", () => {
    expect(summariseReports([]).line).toBe("no tools planned");
  });
});

describe("describeLayerState — decision 6", () => {
  it("keeps degraded off the child row, since a degraded layer has children", () => {
    const d = describeLayerState("degraded", 3);
    expect(d.block).toBe(false);
    expect(d.label).toBe("3 NEW ENTITIES · DEGRADED");
    expect(d.retry).toBe(true);
  });

  it("no longer renders a failed layer as a clean dead end", () => {
    const failed = describeLayerState("failed", 0);
    const empty = describeLayerState("empty", 0);
    expect(failed.label).not.toBe(empty.label);
    expect(failed.retry).toBe(true);
    expect(empty.retry).toBe(false);
  });

  it("paints both degraded and failed amber, so neither reads as a risk finding", () => {
    expect(describeLayerState("degraded", 2).tone).toEqual(TONES.warn);
    expect(describeLayerState("failed", 0).tone).toEqual(TONES.warn);
  });

  it("singularises a one-entity layer", () => {
    expect(describeLayerState("settled", 1).label).toBe("1 NEW ENTITY");
    expect(describeLayerState("settled", 4).label).toBe("4 NEW ENTITIES");
  });

  it("distinguishes a genuine dead end from a row-only tool's real findings (2026-08-26)", () => {
    // A row-only tool (sidecar-holehe, geo-overpass, ...) settles the layer `empty` — zero new
    // nodes — while still reporting real results. Rendering that identically to a true "found
    // nothing" dead end misled the analyst into skipping a node carrying real findings.
    const genuineDeadEnd = describeLayerState("empty", 0, 0);
    expect(genuineDeadEnd.label).toBe("◇ 0 NEW ENTITIES");
    expect(genuineDeadEnd.sub).toBe("branch terminates here");
    expect(genuineDeadEnd.tone).toEqual(TONES.mute);

    const foundSomething = describeLayerState("empty", 0, 4);
    expect(foundSomething.label).toBe("◇ 0 NEW ENTITIES · 4 RESULTS");
    expect(foundSomething.sub).not.toBe("branch terminates here");
    expect(foundSomething.tone).toEqual(TONES.ok);
    expect(foundSomething.label).not.toBe(genuineDeadEnd.label);
  });

  it("singularises the result count in the findings badge", () => {
    expect(describeLayerState("empty", 0, 1).label).toBe("◇ 0 NEW ENTITIES · 1 RESULT");
  });

  it("defaults totalResults to 0 when the caller omits it", () => {
    expect(describeLayerState("empty", 0)).toEqual(describeLayerState("empty", 0, 0));
  });
});
