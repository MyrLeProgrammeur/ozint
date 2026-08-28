import { describe, expect, it } from "vitest";

import type { OzNode } from "@/lib/ozint/stream-parser";

import {
  PROVENANCE_LABELS,
  PROVENANCE_SECTION_ID,
  describeRecordStatus,
  externalLink,
  detailModel,
  formatRetrieved,
  provenanceRows,
} from "./detail";
import { applyEvent, emptyTreeState, type OzintTreeState } from "./state";

function node(over: Partial<OzNode> & Pick<OzNode, "id">): OzNode {
  return {
    investigationId: "inv-1",
    ordinal: 0,
    depth: over.parentId ? 1 : 0,
    type: "username",
    value: over.id,
    display: over.id,
    dedupKey: `username:${over.id}`,
    payload: { type: "username" },
    status: "idle",
    provenance: {
      sourceToolId: "github-user",
      method: "queried the users API",
      retrievedAt: "2026-08-23T10:00:00Z",
      recordStatus: { kind: "as-returned" },
    },
    createdAt: "2026-08-23T10:00:00Z",
    ...over,
  };
}

function treeWith(...nodes: OzNode[]): OzintTreeState {
  let state = emptyTreeState();
  for (const n of nodes) {
    state = applyEvent(state, { type: "node", layerId: n.layerId ?? "", node: n });
  }
  return state;
}

describe("formatRetrieved", () => {
  it("renders in UTC, never through a locale", () => {
    expect(formatRetrieved("2026-08-23T14:02:11Z")).toBe("2026-08-23 14:02 UTC");
  });

  it("shows an unparseable timestamp verbatim rather than as Invalid Date", () => {
    expect(formatRetrieved("whenever")).toBe("whenever");
  });

  it("says nothing was sent rather than inventing an instant", () => {
    expect(formatRetrieved(undefined)).toBe("—");
  });
});

describe("describeRecordStatus", () => {
  it("names the value the tool actually returned when the analyst corrected it", () => {
    const described = describeRecordStatus({
      kind: "corrected",
      originalValue: "M.",
      originalChip: { text: "directory name", tone: "neutral" },
      editedAt: "2026-08-23T11:00:00Z",
    });
    expect(described.value).toBe("corrected by the analyst");
    expect(described.detail).toContain("M. · directory name");
  });

  it("says a rejected node is excluded from the subject file", () => {
    const described = describeRecordStatus({
      kind: "rejected",
      rejectedAt: "2026-08-23T11:00:00Z",
    });
    expect(described.detail).toBe("excluded from the subject file");
  });

  it("refuses to assume the benign case when the engine sent nothing", () => {
    const described = describeRecordStatus(undefined);
    expect(described.value).not.toContain("as returned");
    expect(described.value).toContain("unknown");
  });

  it("gives each variant a distinct wording", () => {
    const words = [
      describeRecordStatus({ kind: "as-returned" }),
      describeRecordStatus({
        kind: "corrected",
        originalValue: "x",
        editedAt: "2026-08-23T11:00:00Z",
      }),
      describeRecordStatus({ kind: "rejected", rejectedAt: "2026-08-23T11:00:00Z" }),
    ].map((d) => `${d.value}|${d.detail ?? ""}`);
    expect(new Set(words).size).toBe(3);
  });
});

describe("provenanceRows", () => {
  it("is always the five fixed rows, in order", () => {
    const rows = provenanceRows(undefined, undefined, undefined);
    expect(rows.map((r) => r.label)).toEqual([...PROVENANCE_LABELS]);
  });

  it("keeps every row even when the engine sent no provenance at all", () => {
    // A row that vanished with its field would let "we were not told" render as
    // a panel that merely looks complete.
    const rows = provenanceRows(undefined, undefined, undefined);
    expect(rows).toHaveLength(5);
    expect(rows.every((r) => r.value.length > 0)).toBe(true);
  });

  it("names the parent and its layer for a found node", () => {
    const rows = provenanceRows(
      {
        sourceToolId: "gravatar-profile",
        method: "hashed the address",
        retrievedAt: "2026-08-23T10:00:00Z",
        recordStatus: { kind: "as-returned" },
      },
      "torvalds",
      1,
    );
    expect(rows[0].value).toBe("torvalds · L1");
    expect(rows[1].value).toBe("gravatar-profile");
    expect(rows[2].value).toBe("hashed the address");
  });

  it("says the root is the seed rather than claiming a parent", () => {
    const rows = provenanceRows(undefined, undefined, undefined);
    expect(rows[0].value).toContain("root");
  });
});

describe("externalLink", () => {
  it("offers no button when no payload carries a real link", () => {
    // Better an absent control than a guessed URL: provenance is the part of
    // this cockpit an analyst is entitled to trust literally.
    expect(externalLink(node({ id: "root" }))).toBeUndefined();
  });

  it("uses a directory tile's own url", () => {
    const link = externalLink(
      node({
        id: "tile",
        type: "directory",
        payload: { type: "directory", url: "https://example.com/x" },
      }),
    );
    expect(link).toEqual({ label: "SOURCE ↗", href: "https://example.com/x" });
  });

  it("uses a coordinate's own map link", () => {
    const link = externalLink(
      node({
        id: "geo",
        type: "coordinate",
        payload: {
          type: "coordinate",
          mapLinks: [{ label: "Google Maps", value: "open", href: "https://maps.example/1" }],
        },
      }),
    );
    expect(link?.label).toBe("OPEN IN MAPS ↗");
  });

  it("refuses a non-http scheme", () => {
    expect(
      externalLink(
        node({
          id: "x",
          payload: { type: "username", url: "javascript:alert(1)" },
        }),
      ),
    ).toBeUndefined();
  });
});

describe("detailModel", () => {
  it("returns null for a node the tree does not hold", () => {
    expect(detailModel(emptyTreeState(), "nope")).toBeNull();
  });

  it("puts provenance first, before the node's own sections", () => {
    const model = detailModel(
      treeWith(
        node({
          id: "root",
          sections: [
            { id: "activity", label: "ACTIVITY", kind: "key-value", rows: [] },
          ],
        }),
      ),
      "root",
    );
    expect(model?.sections[0].id).toBe(PROVENANCE_SECTION_ID);
    expect(model?.sections[1].id).toBe("activity");
  });

  it("emits one jump chip per section, provenance included", () => {
    const model = detailModel(
      treeWith(
        node({
          id: "root",
          sections: [
            { id: "activity", label: "ACTIVITY", kind: "key-value", rows: [] },
            { id: "repos", label: "REPOS", kind: "links", rows: [] },
          ],
        }),
      ),
      "root",
    );
    expect(model?.jumps.map((j) => j.sectionId)).toEqual([
      PROVENANCE_SECTION_ID,
      "activity",
      "repos",
    ]);
  });

  it("reads the parent off the tree for the `found via` row", () => {
    const state = treeWith(
      node({ id: "root", display: "torvalds" }),
      node({
        id: "child",
        parentId: "root",
        display: "torvalds@example.com",
        type: "email",
        provenance: {
          foundViaParentId: "root",
          sourceToolId: "gravatar-profile",
          method: "hashed the address",
          retrievedAt: "2026-08-23T10:05:00Z",
          recordStatus: { kind: "as-returned" },
        },
      }),
    );
    const model = detailModel(state, "child");
    expect(model?.sections[0].rows[0].value).toBe("torvalds · L0");
  });

  it("surfaces a rejection as its own treatment, not only as a row", () => {
    const model = detailModel(
      treeWith(
        node({
          id: "root",
          provenance: {
            sourceToolId: "github-user",
            method: "queried the users API",
            retrievedAt: "2026-08-23T10:00:00Z",
            recordStatus: { kind: "rejected", rejectedAt: "2026-08-23T11:00:00Z" },
          },
        }),
      ),
      "root",
    );
    expect(model?.rejected?.note).toBe("excluded from the subject file");
  });

  it("renders the full tool chain when the engine sent one", () => {
    const model = detailModel(
      treeWith(
        node({
          id: "root",
          provenance: {
            sourceToolId: "gravatar-profile",
            method: "hashed the address",
            retrievedAt: "2026-08-23T10:00:00Z",
            recordStatus: { kind: "as-returned" },
            toolChain: ["github-user", "gravatar-profile"],
          },
        }),
      ),
      "root",
    );
    expect(model?.toolChain).toBe("github-user → gravatar-profile");
  });

  it("labels the layer from the node's own depth", () => {
    const state = treeWith(
      node({ id: "root" }),
      node({ id: "child", parentId: "root", depth: 2 }),
    );
    expect(detailModel(state, "child")?.layerLabel).toBe("LAYER 2");
  });

  it("prefers the full signal over the preview once the node has one", () => {
    const model = detailModel(
      treeWith(
        node({
          id: "root",
          previewSignal: { text: "preview", tone: "neutral" },
          fullSignal: { text: "3 breaches", tone: "risk" },
        }),
      ),
      "root",
    );
    expect(model?.chip?.text).toBe("3 breaches");
  });

  it("shows the analyst's correction, not the value they corrected", () => {
    // `store::edit_node` writes `edited_value` and leaves `display` alone, so a
    // panel reading `display` would show the analyst their own mistake back.
    const model = detailModel(
      treeWith(
        node({
          id: "root",
          display: "Mathe0",
          editedValue: "matheo",
          provenance: {
            sourceToolId: "gravatar-profile",
            method: "queried Gravatar",
            retrievedAt: "2026-08-23T10:00:00Z",
            recordStatus: {
              kind: "corrected",
              originalValue: "Mathe0",
              editedAt: "2026-08-23T11:00:00Z",
            },
          },
        }),
      ),
      "root",
    );
    expect(model?.value).toBe("matheo");
    // And the tool's original is not lost — it is in the record status.
    expect(model?.corrected?.originalValue).toBe("Mathe0");
  });
});
