import { describe, expect, it } from "vitest";

import { formatCost, formatWhen, historyRow, type Investigation } from "./history";

const base: Investigation = {
  id: "inv-1",
  seedInput: "mathe0",
  seedType: "username",
  rootNodeId: "node-1",
  createdAt: "2026-08-23T14:07:00Z",
  updatedAt: "2026-08-23T14:09:00Z",
  lookups: 7,
  costCents: 0,
};

describe("formatWhen", () => {
  it("states an unreadable date rather than rendering NaN", () => {
    expect(formatWhen("not a date")).toBe("date unreadable");
  });

  it("pads to a fixed width so the date column stays aligned", () => {
    // Built from a local-time date so the assertion does not depend on the zone
    // the suite happens to run in.
    const at = new Date(2026, 0, 5, 9, 4);
    expect(formatWhen(at.toISOString())).toBe("2026-01-05 09:04");
  });
});

describe("formatCost", () => {
  it("says a free investigation was free, never 0.00 €", () => {
    // A zero currency amount reads as a measurement that failed to arrive.
    expect(formatCost(0)).toBe("no paid tool");
  });

  it("renders cents as a two-decimal amount", () => {
    expect(formatCost(12)).toBe("0.12 €");
    expect(formatCost(1234)).toBe("12.34 €");
  });
});

describe("historyRow", () => {
  it("carries only facts the list route sends — no node or layer count", () => {
    const row = historyRow(base);
    expect(row.stats).toBe("7 lookups · no paid tool");
    expect(row.stats).not.toMatch(/node|layer/i);
  });

  it("singularises a single lookup", () => {
    expect(historyRow({ ...base, lookups: 1 }).stats).toContain("1 lookup ·");
  });

  it("survives a type this build does not know without inventing a label", () => {
    const row = historyRow({ ...base, seedType: "asn" as Investigation["seedType"] });
    expect(row.typeGlyph).toBe("???");
    expect(row.typeLabel).toBe("asn");
  });

  it("surfaces the one-way spawn link", () => {
    const row = historyRow({ ...base, spawnedFromRelation: "same-avatar-hash" });
    expect(row.spawnedFrom).toBe("same-avatar-hash");
  });
});
