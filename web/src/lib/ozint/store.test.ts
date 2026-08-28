import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { LayerEvent } from "@/lib/ozint/stream-parser";

import { ozintStore } from "./store";

function frame(event: LayerEvent): string {
  return `data: ${JSON.stringify(event)}\n\n`;
}

/** A `fetch` response whose body yields the given text chunks, in order. */
function streamed(chunks: string[], init: { ok?: boolean; status?: number } = {}) {
  const encoder = new TextEncoder();
  let i = 0;
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    body: {
      getReader: () => ({
        read: async () =>
          i < chunks.length
            ? { done: false, value: encoder.encode(chunks[i++]) }
            : { done: true, value: undefined },
      }),
    },
  };
}

const START: LayerEvent = {
  type: "layerStart",
  layerId: "L1",
  investigationId: "inv-1",
  parentNodeId: "root",
  firing: 2,
  maxPossible: 7,
  gated: 1,
};

const ROOT_NODE: LayerEvent = {
  type: "node",
  layerId: "L1",
  node: {
    id: "root",
    investigationId: "inv-1",
    ordinal: 0,
    depth: 0,
    type: "username",
    value: "kilnwright",
    display: "kilnwright",
    dedupKey: "username:kilnwright",
    payload: { type: "username" },
    status: "idle",
    provenance: {
      sourceToolId: "seed",
      method: "typed by the analyst",
      retrievedAt: "2026-08-23T10:00:00Z",
      recordStatus: { kind: "as-returned" },
    },
    createdAt: "2026-08-23T10:00:00Z",
  },
};

const SETTLED: LayerEvent = {
  type: "layerSettled",
  layerId: "L1",
  newChildren: 0,
  reports: [
    {
      toolId: "github-user",
      label: "GitHub",
      outcome: { kind: "skipped-no-key", env_var: "HIBP_API_KEY" },
      elapsedMs: 0,
      results: 0,
      gated: false,
      method: "not attempted",
    },
  ],
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  const fn = vi.fn(async (url: string, init?: RequestInit) => handler(url, init));
  vi.stubGlobal("fetch", fn);
  return fn;
}

/** The meter call every `fire` makes on close; harmless 404 by default. */
function meterMiss() {
  return { ok: false, status: 404, body: null };
}

beforeEach(() => {
  ozintStore.reset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("ozintStore.fire", () => {
  it("posts the request body to /api/ozint/fire and reduces the stream", async () => {
    const fetchMock = mockFetch((url) =>
      url.includes("/fire")
        ? streamed([frame(START), frame(ROOT_NODE), frame(SETTLED)])
        : meterMiss(),
    );

    await ozintStore.fire({ seed: "kilnwright" });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/ozint/fire");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ seed: "kilnwright" });

    const { tree, status, openStreams } = ozintStore.getSnapshot();
    expect(status).toBe("closed");
    expect(openStreams).toBe(0);
    expect(tree.investigationId).toBe("inv-1");
    expect(tree.rootNodeId).toBe("root");
    expect(tree.layers.L1.status).toBe("settled");
    // The skipped tool survives to the UI as a skipped tool.
    expect(tree.layers.L1.reports[0].outcome.kind).toBe("skipped-no-key");
  });

  it("reassembles a frame split across two chunks", async () => {
    const whole = frame(START);
    const cut = Math.floor(whole.length / 2);
    mockFetch((url) =>
      url.includes("/fire")
        ? streamed([whole.slice(0, cut), whole.slice(cut)])
        : meterMiss(),
    );

    await ozintStore.fire({ seed: "kilnwright" });
    expect(ozintStore.getSnapshot().tree.layers.L1).toBeDefined();
  });

  it("keeps a malformed frame instead of swallowing it", async () => {
    mockFetch((url) =>
      url.includes("/fire")
        ? streamed([frame(START), "data: {not json}\n\n", frame(SETTLED)])
        : meterMiss(),
    );

    await ozintStore.fire({ seed: "kilnwright" });
    const snapshot = ozintStore.getSnapshot();
    expect(snapshot.malformed).toHaveLength(1);
    // The frames on either side of it still landed.
    expect(snapshot.tree.layers.L1.status).toBe("settled");
  });

  it("reports a transport failure rather than looking like an empty result", async () => {
    mockFetch((url) =>
      url.includes("/fire") ? { ok: false, status: 500, body: null } : meterMiss(),
    );

    await ozintStore.fire({ seed: "kilnwright" });
    const snapshot = ozintStore.getSnapshot();
    expect(snapshot.status).toBe("error");
    expect(snapshot.transportError).toContain("500");
  });

  it("notifies subscribers once per chunk, not once per frame", async () => {
    mockFetch((url) =>
      url.includes("/fire")
        ? streamed([frame(START) + frame(ROOT_NODE) + frame(SETTLED)])
        : meterMiss(),
    );

    const before = ozintStore.getSnapshot().tree;
    const trees = new Set<unknown>();
    const unsubscribe = ozintStore.subscribe(() => {
      trees.add(ozintStore.getSnapshot().tree);
    });
    await ozintStore.fire({ seed: "kilnwright" });
    unsubscribe();

    // Three frames arriving in one chunk reduce to one new tree object, so a
    // view re-renders once — not once per frame. The empty tree the connection
    // opened on is the only other identity a subscriber sees.
    trees.delete(before);
    expect(trees.size).toBe(1);
    expect(Object.keys(ozintStore.getSnapshot().tree.nodes)).toEqual(["root"]);
  });

  it("reads the meter when the stream closes", async () => {
    mockFetch((url) =>
      url.includes("/fire")
        ? streamed([frame(START), frame(SETTLED)])
        : {
            ok: true,
            status: 200,
            json: async () => ({ lookups: 47, costCents: 12, inFlight: 2 }),
          },
    );

    await ozintStore.fire({ seed: "kilnwright" });
    // A real count and a real cost, never a fabricated one.
    expect(ozintStore.getSnapshot().meter).toEqual({
      lookups: 47,
      costCents: 12,
      inFlight: 2,
    });
  });

  it("reads `inFlight` as the count the server actually sends", async () => {
    // `GET .../meter` returns a *number* of in-flight layers, folded live from
    // the SSE events. This client read it as a boolean (`=== true`), so it was
    // false no matter how many layers were running — a silent nothing where the
    // server had something to say. Pinned so it cannot regress to a boolean.
    mockFetch((url) =>
      url.includes("/fire")
        ? streamed([frame(START), frame(SETTLED)])
        : {
            ok: true,
            status: 200,
            json: async () => ({ lookups: 3, costCents: 0, inFlight: 1 }),
          },
    );

    await ozintStore.fire({ seed: "kilnwright" });
    expect(ozintStore.getSnapshot().meter?.inFlight).toBe(1);
  });

  it("leaves the meter unset when the server sends a shape it cannot trust", async () => {
    mockFetch((url) =>
      url.includes("/fire")
        ? streamed([frame(START), frame(SETTLED)])
        : { ok: true, status: 200, json: async () => ({ lookups: "many" }) },
    );

    await ozintStore.fire({ seed: "kilnwright" });
    expect(ozintStore.getSnapshot().meter).toBeNull();
  });
});

describe("ozintStore — hydration", () => {
  it("fetches the node the stream fires on but never sends", async () => {
    // Measured against a real recorded stream: a seeded fire emits `layerStart`
    // for a node that has no `node` frame anywhere. Without this the canvas is
    // empty while a layer visibly runs.
    const seedNode = { ...ROOT_NODE } as Extract<LayerEvent, { type: "node" }>;
    const fetchMock = mockFetch((url) => {
      if (url.includes("/fire")) return streamed([frame(START), frame(SETTLED)]);
      if (url.endsWith("/investigations/inv-1")) {
        return { ok: true, status: 200, json: async () => ({ nodes: [seedNode.node] }) };
      }
      return meterMiss();
    });

    await ozintStore.fire({ seed: "kilnwright" });
    // Hydration is not awaited by the stream loop; let its microtask land.
    await new Promise((resolve) => setTimeout(resolve, 0));

    const { tree } = ozintStore.getSnapshot();
    expect(tree.rootNodeId).toBe("root");
    expect(tree.nodes.root.value).toBe("kilnwright");
    expect(fetchMock.mock.calls.some(([u]) => String(u).endsWith("/investigations/inv-1"))).toBe(true);
  });

  it("does not hydrate mid-stream when the fired node is already in the tree", async () => {
    // The `layerStart` for a node we already hold triggers nothing. The one read
    // that does happen is the re-read after the layer settles, which is how the
    // subject file stays current — the engine rebuilds it from the whole tree on
    // every read, so the rail is never accumulated from frames.
    const seen: string[] = [];
    mockFetch((url) => {
      seen.push(url);
      return url.includes("/fire")
        ? streamed([frame(ROOT_NODE), frame(START), frame(SETTLED)])
        : meterMiss();
    });
    await ozintStore.fire({ seed: "kilnwright" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const reads = seen.filter((u) => u.endsWith("/investigations/inv-1"));
    expect(reads).toHaveLength(1);
    expect(ozintStore.getSnapshot().tree.nodes.root).toBeDefined();
  });

  it("posts no ozType when the selector is left on auto — decision 3", async () => {
    // Auto must be byte-identical to the request made before the selector
    // existed: a `null` would still be a value the classifier has to interpret.
    const bodies: string[] = [];
    mockFetch((url, init) => {
      if (init?.body) bodies.push(String(init.body));
      return url.includes("/fire")
        ? streamed([frame(START), frame(SETTLED)])
        : meterMiss();
    });

    await ozintStore.fire({ seed: "kilnwright" });
    expect(JSON.parse(bodies[0])).toEqual({ seed: "kilnwright" });
  });

  it("posts the analyst's chosen type when one was chosen", async () => {
    const bodies: string[] = [];
    mockFetch((url, init) => {
      if (init?.body) bodies.push(String(init.body));
      return url.includes("/fire")
        ? streamed([frame(START), frame(SETTLED)])
        : meterMiss();
    });

    await ozintStore.fire({ seed: "Acme Industries", ozType: "directory" });
    expect(JSON.parse(bodies[0]).ozType).toBe("directory");
  });

  it("reports the server's own refusal rather than a bare status code", async () => {
    // A type with no orchestrator answers 501 with a sentence. `HTTP 501` would
    // read as a transient failure of something that exists; the sentence says
    // the capability was never built.
    mockFetch((url) =>
      url.includes("/fire")
        ? {
            ok: false,
            status: 501,
            json: async () => ({
              error: "no orchestrator is built for EML nodes yet",
              ozType: "email",
            }),
          }
        : meterMiss(),
    );

    await ozintStore.fire({ seed: "a@b.com", ozType: "email" });
    expect(ozintStore.getSnapshot().transportError).toContain(
      "no orchestrator is built for EML nodes yet",
    );
  });

  it("refuses to render a node that cannot be re-checked as unchanged", async () => {
    // 422: this node's tools have left the registry, so it *cannot* be re-run.
    // That is the opposite of a clean "nothing changed" and must never collapse
    // into one.
    mockFetch(() => ({
      ok: false,
      status: 422,
      json: async () => ({ error: "the tools that produced this node are gone" }),
    }));

    const { result, error } = await ozintStore.refresh("n1");
    expect(result).toBeUndefined();
    expect(error).toContain("tools that produced this node are gone");
  });

  it("folds the re-read node back in and reports what moved", async () => {
    mockFetch(() => ({
      ok: true,
      status: 200,
      json: async () => ({
        node: { ...ROOT_NODE.node, display: "torvalds (updated)" },
        changed: true,
        changedFields: ["payload.sitesConfirmed"],
        reports: [],
        childrenIgnored: 3,
        aborted: false,
      }),
    }));

    const { result } = await ozintStore.refresh("root");
    expect(result?.changed).toBe(true);
    expect(result?.changedFields).toEqual(["payload.sitesConfirmed"]);
    // A refresh never touches children; the count it declined is reported.
    expect(result?.childrenIgnored).toBe(3);
    expect(ozintStore.getSnapshot().tree.nodes.root.display).toBe(
      "torvalds (updated)",
    );
  });

  it("reports an unchanged re-check as its own answer", async () => {
    mockFetch(() => ({
      ok: true,
      status: 200,
      json: async () => ({
        node: ROOT_NODE.node,
        changed: false,
        changedFields: [],
        reports: [],
        childrenIgnored: 0,
        aborted: false,
      }),
    }));

    const { result, error } = await ozintStore.refresh("root");
    expect(error).toBeUndefined();
    expect(result?.changed).toBe(false);
    expect(result?.checkedAt).toBeGreaterThan(0);
  });

  it("reads the subject file off the investigation, verbatim", async () => {
    mockFetch((url) => {
      if (url.includes("/fire")) return streamed([frame(START), frame(SETTLED)]);
      if (url.endsWith("/investigations/inv-1")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            nodes: [],
            subjectFile: { kind: "notApplicable", rootType: "cve" },
          }),
        };
      }
      return meterMiss();
    });

    await ozintStore.fire({ seed: "CVE-2024-38063" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    // `notApplicable` is an answer worth keeping — it is what makes
    // the rail absent rather than empty — so it survives even a node-less read.
    expect(ozintStore.getSnapshot().subjectFile).toEqual({
      kind: "notApplicable",
      rootType: "cve",
    });
  });
});

describe("ozintStore — two layers on one tree", () => {
  it("reduces interleaved streams into the same tree", async () => {
    const second: LayerEvent = { ...START, layerId: "L2", parentNodeId: "a" };
    mockFetch((url) => {
      if (!url.includes("/fire")) return meterMiss();
      const body = streamed([frame(START), frame(SETTLED)]);
      return body;
    });
    await ozintStore.fire({ seed: "kilnwright" });

    mockFetch((url) =>
      url.includes("/fire") ? streamed([frame(second)]) : meterMiss(),
    );
    await ozintStore.fire({ investigationId: "inv-1", parentNodeId: "a" });

    const { tree } = ozintStore.getSnapshot();
    expect(Object.keys(tree.layers).sort()).toEqual(["L1", "L2"]);
    expect(tree.layers.L1.status).toBe("settled");
    expect(tree.layers.L2.status).toBe("firing");
  });
});

describe("ozintStore.cancel", () => {
  it("posts the target and reports what the server said", async () => {
    const fetchMock = mockFetch(() => ({
      ok: true,
      status: 200,
      json: async () => ({ cancelled: true }),
    }));

    await expect(ozintStore.cancel({ layerId: "L1" })).resolves.toBe(true);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/ozint/cancel");
    expect(JSON.parse(init.body as string)).toEqual({ layerId: "L1" });
  });

  it("answers false when the call fails, never true by omission", async () => {
    mockFetch(() => {
      throw new Error("network down");
    });
    await expect(ozintStore.cancel({ layerId: "L1" })).resolves.toBe(false);
  });
});

describe("ozintStore.reset", () => {
  it("returns an empty tree and clears the transport error", async () => {
    mockFetch((url) =>
      url.includes("/fire") ? { ok: false, status: 500, body: null } : meterMiss(),
    );
    await ozintStore.fire({ seed: "kilnwright" });
    expect(ozintStore.getSnapshot().status).toBe("error");

    ozintStore.reset();
    const snapshot = ozintStore.getSnapshot();
    expect(snapshot.status).toBe("idle");
    expect(snapshot.transportError).toBeNull();
    expect(Object.keys(snapshot.tree.nodes)).toEqual([]);
  });
});
