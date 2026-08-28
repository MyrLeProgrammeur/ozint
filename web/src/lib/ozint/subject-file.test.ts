import { describe, expect, it } from "vitest";

import {
  COMPLETENESS_DENOMINATOR,
  SUBJECT_FIELDS,
  notApplicableReason,
  railModel,
  type FieldEntry,
  type SubjectFileView,
} from "./subject-file";

function entry(over: Partial<FieldEntry> & Pick<FieldEntry, "field">): FieldEntry {
  return {
    label: over.field.toUpperCase(),
    isList: false,
    items: [],
    ...over,
  };
}

function file(over: Partial<Extract<SubjectFileView, { kind: "file" }>> = {}) {
  return {
    kind: "file" as const,
    fields: [],
    filled: 0,
    total: COMPLETENESS_DENOMINATOR,
    ...over,
  };
}

describe("the field set", () => {
  it("is twelve fields over a denominator of thirteen — decision 5", () => {
    expect(SUBJECT_FIELDS).toHaveLength(12);
    expect(COMPLETENESS_DENOMINATOR).toBe(13);
  });

  it("carries one FULL NAME and never a split name", () => {
    expect(SUBJECT_FIELDS).toContain("full-name");
    expect(SUBJECT_FIELDS).not.toContain("family-name");
    expect(SUBJECT_FIELDS).not.toContain("given-name");
  });
});

describe("railModel", () => {
  it("is absent for a root that is not a person — decision 2", () => {
    expect(railModel({ kind: "notApplicable", rootType: "cve" })).toBeNull();
    expect(notApplicableReason({ kind: "notApplicable", rootType: "cve" })).toContain(
      "cve",
    );
  });

  it("is absent, not empty, when the server sent nothing at all", () => {
    expect(railModel(null)).toBeNull();
    expect(railModel(undefined)).toBeNull();
  });

  it("renders the server's own completeness, never a recomputed one", () => {
    // Two rows on screen, but the server says 5/13 — the engine's number wins,
    // because a client-derived ratio would drift the moment the two disagreed
    // about what counts as filled.
    const model = railModel(
      file({
        filled: 5,
        total: 13,
        fields: [
          entry({ field: "city", items: [{ values: [{ value: "Lyon", sources: [] }] }] }),
          entry({ field: "role" }),
        ],
      }),
    );
    expect(model?.filled).toBe(5);
    expect(model?.total).toBe(13);
    expect(model?.percent).toBe(38);
  });

  it("marks a field with no findings as empty rather than blank", () => {
    const model = railModel(file({ fields: [entry({ field: "employer" })] }));
    expect(model?.fields[0].empty).toBe(true);
  });

  it("shows an unresolved conflict as both values, marked", () => {
    // Two tools said different things and nothing adjudicated. Picking one
    // would be the subject file asserting something no tool said.
    const model = railModel(
      file({
        fields: [
          entry({
            field: "employer",
            items: [
              {
                values: [
                  { value: "Acme", sources: [{ nodeId: "n1", toolId: "github-user" }] },
                  { value: "Initech", sources: [{ nodeId: "n2", toolId: "hn-algolia" }] },
                ],
              },
            ],
          }),
        ],
      }),
    );
    expect(model?.fields[0].items[0].conflicted).toBe(true);
    expect(model?.fields[0].items[0].values.map((v) => v.value)).toEqual([
      "Acme",
      "Initech",
    ]);
  });

  it("carries the analyst's correction mark up from the source", () => {
    const model = railModel(
      file({
        fields: [
          entry({
            field: "full-name",
            items: [
              {
                values: [
                  {
                    value: "Matthijs",
                    sources: [{ nodeId: "n1", toolId: "wmn-probe", corrected: true }],
                  },
                ],
              },
            ],
          }),
        ],
      }),
    );
    expect(model?.fields[0].items[0].values[0].corrected).toBe(true);
  });

  it("treats an absent gated flag as false, never as unknown", () => {
    const model = railModel(
      file({
        fields: [
          entry({
            field: "city",
            items: [
              { values: [{ value: "Lyon", sources: [{ nodeId: "n", toolId: "t" }] }] },
            ],
          }),
        ],
      }),
    );
    expect(model?.fields[0].items[0].values[0].gated).toBe(false);
  });

  it("assembles the identity line from the name, role and city", () => {
    const one = (value: string) => [{ values: [{ value, sources: [] }] }];
    const model = railModel(
      file({
        fields: [
          entry({ field: "full-name", items: one("Linus Torvalds") }),
          entry({ field: "role", items: one("Kernel maintainer") }),
          entry({ field: "city", items: one("Portland") }),
        ],
      }),
    );
    expect(model?.identity).toBe("Linus Torvalds");
    expect(model?.subtitle).toBe("Kernel maintainer · Portland");
  });

  it("leaves the subject unidentified rather than picking a contested name", () => {
    const model = railModel(
      file({
        fields: [
          entry({
            field: "full-name",
            items: [
              {
                values: [
                  { value: "L. Torvalds", sources: [] },
                  { value: "Linus B. Torvalds", sources: [] },
                ],
              },
            ],
          }),
        ],
      }),
    );
    expect(model?.identity).toBeNull();
  });
});
