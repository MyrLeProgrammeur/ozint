# Architecture

OZINT is an OSINT investigation cockpit: type a seed value, watch a tree of typed findings
grow one deliberate click at a time. This document is the map a new contributor needs to find
their way around the code and add a new source without asking anyone.

## 1. The shape, in one paragraph

An analyst types a seed (a username, email, IP, domain, hash, image, video, coordinate, CVE
id, phone number, a bare name, or a directory query). The seed is **classified** into one of
twelve [`OzType`](crates/ozint/src/types.rs) variants, first by shape (deterministic, no
network) and only escalated to an LLM when the shape pass is genuinely ambiguous. That type
selects a **plan** — an ordered, phased list of tools ([`plans::plan_for`](crates/ozint/src/plans.rs))
— and firing that plan is a **layer**: every applicable tool runs in parallel (in phases, some
conditional on what earlier phases found), each tool's findings are folded into the node it
fired on and turned into new **child nodes**, and the layer **settles**. Nothing recurses
automatically — a child is created `Idle` and stays that way until the analyst clicks
"continue" on it. One seed grows one tree; the analyst drives every branch by hand.

## 2. The crate map

| Crate | Owns | Depended on by |
|---|---|---|
| `ozint-core` | Config/env access, the shared `reqwest` HTTP pool, the SSRF-guarding `net` module, the PII-redacting/cloud-egress `safety` module (including the freeze kill switch), error types. | Every other crate. |
| `ozint-db` | The single SQLite connection handle (`Db = Arc<Mutex<Connection>>`) and how to open it. Deliberately creates **no tables** — each table is owned by the module that reads it. | `ozint`, `ozint-server`. |
| `ozint-llm` | A minimal OpenAI-compatible chat-completion client. OZINT's *only* LLM dependency — used in exactly two places (the ambiguous-seed classifier escalation and the one-paragraph layer summary), both optional and both degrading honestly with no model configured. Every one of the 62 catalogued OSINT tools is deterministic HTTP + a parser; nothing else in this project calls a model. | `ozint`. |
| `ozint` | The engine: the node/tree data model, the tool registry, the phased layer runtime, classification, normalization, dedup, the scheduler, the response cache, the SSRF/egress policy, evidence capture, relations, the dossier exporter — and every source integration under `sources/`. **No HTTP framework, no UI dependency.** It is a library that produces a stream of typed events; something else has to wire that to a network. | `ozint-server`. |
| `ozint-server` | The `axum` HTTP surface: routes, the freeze-gate middleware, SSE framing, `AppState` (the process-wide scheduler/cache/freeze handles), and serving the built `web` cockpit as static files. | Nothing in this repo — it is the binary. |
| `web` | The React/TypeScript cockpit: the SSE stream parser, the tree-reducing store, and every view. Talks to `ozint-server` over `/api/ozint/*` and nothing else. | Nothing in this repo — it is the frontend. |

The dependency direction is strict: `ozint` never imports `axum`, `tokio::net`, or anything
from `web`. That is what makes the engine testable without a server and, in principle, embeddable
behind a different transport.

## 3. The life of a layer

Concretely, what happens between a browser click and pixels updating, naming the real functions.

1. **The browser** ([`web/src/lib/ozint/store.ts`](web/src/lib/ozint/store.ts)) `fetch`es
   `POST /api/ozint/fire` with either `{ seed }` (start a new investigation) or
   `{ investigationId, parentNodeId }` (continue on an existing node), and starts reading the
   response body as a stream.
2. **The route** ([`crates/ozint-server/src/routes/ozint/fire.rs`](crates/ozint-server/src/routes/ozint/fire.rs))
   handles the two branches in `setup_seed`/`setup_continue`: on a fresh seed it classifies the
   value (`classify::classify_with_llm`, or `classify::classify_forced` when the analyst's type
   selector overrode auto-detection), creates the `Investigation` and its root `OzNode`, and
   rebuilds the per-investigation `VisitedSet` so a rediscovered value annotates instead of
   duplicating. Either branch produces a `LayerContext`.
3. `fire.rs::stream_layer` looks up the plan for that node's type via `ozint::plans::plan_for`.
   **If there is no orchestrator for that type yet, it answers `501` rather than opening an
   empty stream** — an unbuilt capability and a layer that tried and found nothing must never
   look the same.
4. It spawns `ozint::runtime::fire_layer` on a background task, writing `LayerEvent`s into an
   mpsc channel; a second task relays those events onto the SSE body while also registering the
   layer's `CancelHandle` and feeding the in-flight lookup meter. The relay keeps draining the
   engine channel to completion even if the SSE body is dropped — the engine runs to settlement
   regardless of whether anyone is still reading, because cancellation is a deliberate
   `POST /api/ozint/cancel`, never an inferred disconnect.
5. Inside `fire_layer` ([`crates/ozint/src/runtime.rs`](crates/ozint/src/runtime.rs)): it
   resolves every tool applicable to the node's type via `registry::resolve`, restates the
   node and its already-stored subtree as `Node` frames, then emits `LayerStart`. For each
   phase the plan admits (`LayerPlan::firing_now`, gated on a `PhaseAcc` predicate), each tool
   is, in order: refused if its `needs_input` keys weren't published by an earlier phase, skipped
   if the circuit breaker (`health.rs`) has given up on it, admitted through the process-wide
   `Scheduler`'s per-`rate_key` quota, then dispatched via `sources::dispatch(tool_id, value, ctx)`.
   Each dispatch emits `ToolStart`/`ToolDone`; a successful yield's payload patch and rows are
   persisted onto the parent node and streamed as a `ParentPayload` frame **as that tool
   returns**, not batched at the end, and each `ChildSeed` is deduped against the tree
   (`emit_child`) — a genuinely new value becomes a persisted `Node` frame, a rediscovered one
   becomes an `AlreadyInTree` frame carrying the new route as a `Corroboration`.
6. Once every phase has run (or the layer was cancelled), `outcome::settle_kind` folds the
   accumulated `ToolReport`s into one of `Settled`/`Empty`/`Degraded`/`Failed`/`Aborted` — the
   distinction between `Empty` ("tools ran, genuinely found nothing") and `Failed` ("nothing ran
   or everything broke") is treated as inviolable, since collapsing them would silently lie to
   the analyst. The layer row and the node's status are persisted, and the terminal event is
   sent. Only after that terminal frame is already on the wire, `fire_layer` spawns
   `summary::run` in the background to attach a short LLM narration — fire-and-attach, never
   fire-and-block, so a slow or dead model can never delay settlement.
7. **The browser** feeds the raw byte stream through `OzintStreamReader` (buffers across chunk
   boundaries so a frame split mid-JSON is never mis-parsed), which yields whole
   `data: <json>\n\n` blocks; each parsed `LayerEvent` is folded into the tree by
   `applyEvent` ([`web/src/lib/ozint/state.ts`](web/src/lib/ozint/state.ts)), and the
   `useSyncExternalStore`-backed store re-renders `OzintView` with the updated tree.

## 4. The tool registry

[`crates/ozint/src/registry.rs`](crates/ozint/src/registry.rs) is the single declarative
catalogue — 62 `ToolDef` entries today — of every tool this crate can dispatch. It is
deliberately plain data: `ToolDef` is `Copy` and the whole `CATALOGUE` is a `const &'static
[ToolDef]` array, so there is no `Lazy`/`OnceLock` initialization and no dependency on an
async-fn-pointer shape that wouldn't fit a `const`. A `ToolDef` declares:

- `id` / `label` — the stable id matched against in `sources::dispatch`, and a display label.
- `types: &[OzType]` — which entity types it applies to.
- `access_tier` — `KeylessOpen`, `FreeKey`, `PaidKey`, `LocalOnly` (no network call at all —
  EXIF, a local MMDB lookup, `ffprobe`…), `DirectoryOnly` (a launch-only URL template, never
  fetched), or `Sidecar` (only reachable via a deliberately-deployed Docker container).
- `env_vars` — every env var that must be present and non-empty for the tool to be **armed**.
  Empty even for a tool that *optionally* uses a token when present (GitHub's `GITHUB_TOKEN`
  only lifts a rate limit; its absence never blocks the tool).
- `needs_input` — `layer_plan` input keys an *earlier wave of the same layer* must have
  published before this tool can run (e.g. `ip-peeringdb` needs the ASN `ip-ipinfo` publishes).
- `gated` / `gated_reason` — whether the tool sits behind an ethical-consent gate.
- `rate_key` — the scheduler bucket this tool's calls are throttled against; several tools
  intentionally share one (e.g. every VirusTotal-calling tool shares `"virustotal"`, since it
  is one account's daily budget regardless of how many tool ids call into it).
- `ttl_secs` — the cache TTL for this tool's responses; `0` for a pure local computation with
  nothing to cache, or for a genuinely no-quota concern.
- `licence` / `attribution` / `method` — the provenance sentence rendered verbatim in the UI.

**"Could run" vs. "armed".** [`registry::resolve(oz_type)`](crates/ozint/src/registry.rs)
returns a `Resolution { runnable, skipped }`: `runnable` is every tool whose `env_vars` are all
present (`is_armed`); `skipped` pairs every other applicable tool with the exact reason it
can't run right now — `SkippedNoKey` for an ordinary missing credential, `SkippedGatedUnarmed`
for an unarmed *gated* tool (a consent boundary, not an accident, and the UI must be able to
tell the two apart). This is evaluated fresh on every layer, before anything fires, and the
skipped tools are reported to the analyst exactly like the ones that ran — a capability that
exists but isn't configured must stay visible, not silently vanish from the count.

**Rate limits and the cache are process-wide, not per-investigation, and that is deliberate.**
`AppState` builds one `Scheduler` (registered with every catalogued `rate_key` via
`registry::rate_keys()`/`rate_limits_for`) and one `ToolCache`, both shared across every
concurrently running investigation. A quota is a property of the upstream source — VirusTotal's
4-per-minute/500-per-day budget doesn't multiply because two investigations happen to be open —
and the fetches most worth collapsing (CISA's ~1.6 MB KEV catalogue, WhatsMyName's ~730-site
list) are exactly the ones every investigation would otherwise re-download identically.
`rate_limits_for` only registers a window it can cite a real published or measured figure for;
a source with no entry is a stated absence of a known limit, never an invented "unlimited".

## 5. Adding a new source — a worked example

Use [`crates/ozint/src/sources/username/github.rs`](crates/ozint/src/sources/username/github.rs)
(`github-user`) as the template — it's small, keyless, and shows the full shape: a pure parser,
a pure "response → findings" mapper, and a thin async dispatcher wired to real HTTP.

1. **Pick or create the module.** One submodule per entity-type category under
   `crates/ozint/src/sources/` (`username/`, `ip/`, `hash/`, `cve/`, …). Add a new file there,
   e.g. `sources/domain/mynewsource.rs`, and `pub mod mynewsource;` in that category's `mod.rs`.
2. **Write the async runner.** Its signature matches every other dispatcher:
   `pub async fn run_mynewsource(value: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome`.
   Inside, build the request URL/headers, then call `ctx.fetch(tool_id, cache_key, url, options)`
   — this goes through the shared HTTP pool, the SSRF-guarded fetch path, and (when
   `ctx.cache`/`ctx.ttl` are set) the response cache, all for free. Map the resulting
   `OzOutcome` to a `DispatchOutcome`: `Cancelled` passes straight through; a clean "not found"
   status becomes `Ran(ToolOutcome::OkEmpty, Some(ToolYield::default()))` rather than an error;
   anything else routes through `sources::fold_fetch_failure` for the shared taxonomy mapping;
   and a successful body gets parsed into your own small struct and turned into a `ToolYield`.
3. **Build the `ToolYield` honestly.** `rows: Vec<OzRow>` become the node's detail-panel
   section (one section per tool, keyed by tool id, so a re-fire replaces rather than
   duplicates). `children: Vec<ChildSeed>` become new nodes **only for what the response
   actually contained** — never invent a child the tool didn't hand you (see `github.rs`'s
   `github_profile_to_yield`, which only adds an email/domain/name/username child when that
   field was present, and explicitly guards against emitting a self-referential child when a
   linked handle equals the one just queried). Keep the parsing function (`parse_*`) and the
   "response struct → yield" function (`*_to_yield`) pure and separately testable from the
   network-touching runner — that's what lets `github.rs`'s tests cover every branch of the
   mapping without a live HTTP call.
4. **Register it.** Add one `"my-new-source" => domain::mynewsource::run_mynewsource(value, ctx).await,`
   arm to the `match` in [`sources::dispatch`](crates/ozint/src/sources/mod.rs). An id with no
   arm here surfaces as a visible `ParseError` from the runtime, never a silent no-op.
5. **Catalogue it.** Add a `ToolDef` entry to `CATALOGUE` in `registry.rs`: `types` (which
   `OzType` it applies to), `access_tier`, `env_vars` (empty if genuinely keyless), `rate_key`
   (share an existing one if it hits the same upstream account/host — see §4 — otherwise pick a
   new, descriptive one), `ttl_secs` (justify it in a comment: how fast does this fact actually
   change?), `licence`, and a `method` sentence written in the past tense as the provenance line
   ("queried X's public API for the handle"). Every catalogued type must have an orchestrator —
   `registry`'s own test suite (`every_catalogued_tool_belongs_to_a_category_with_an_orchestrator`)
   will fail the build if you catalogue a tool for a type `plans::plan_for` doesn't build a plan
   for.
6. **Wire it into a plan.** If the type already has an orchestrator in
   [`crates/ozint/src/plans.rs`](crates/ozint/src/plans.rs), add the tool id to the appropriate
   `LayerPhase`'s `tools` list (a new phase only if it genuinely needs to wait on an earlier
   phase's `PhaseAcc` facts/values).
7. **Write tests.** At minimum: unit tests for the pure parser against inline JSON fixtures
   (valid response, missing/empty fields, a malformed response), and for the yield-mapper
   (no children when the response has none, exactly the children a full response implies, the
   self-reference guard if applicable). See §8 for the honest limits of this pattern.

## 6. The safety machinery

Three independent layers, each protecting against a different failure:

- **`ozint_core::net::safe_fetch_url`** — the SSRF guard every outbound fetch passes through.
  Accepts only `http`/`https`, rejects IPv6 literals, requires a hostname that looks like a
  public domain (contains a dot), and rejects `localhost`/`.local`/`.internal`/`.lan` suffixes
  and private/loopback/link-local IPv4 literals (`127.`, `10.`, `192.168.`, `169.254.`,
  `172.16–31.`, `0.0.0.0`). It is hostname-based only — **DNS rebinding is explicitly out of
  scope**, matching the TypeScript original it was ported from. It stops a tool (or an
  analyst-supplied URL, via `/api/ozint/media`) from being pointed at this machine's own
  internal network; it does not protect against a malicious DNS answer swapping a validated
  hostname for a private IP after the check.
- **`ozint::egress::oz_guard`** — the one choke point every cloud-bound OZINT call (the
  classifier's LLM escalation, the layer summary) passes through before any investigation
  content reaches an external model. It wraps `ozint_core::safety::guard_cloud` (PII redaction,
  sensitive-category flags) with three OZINT-specific hard refusals — raw credential material,
  full breach-record dumps, and raw image/file bytes never leave the machine, sanitised or not —
  plus a size cap. It protects the *content* of what's sent to an LLM; it has nothing to do with
  which HTTP requests a tool itself makes.
- **The freeze kill switch** — `ozint_core::safety::FreezeState`, persisted to
  `<OZINT_DATA_DIR>/freeze.json` and **failing closed**: if the file can't be read, the state
  resolves to frozen rather than guessing. Enforcement is a single `freeze_gate` middleware
  applied in [`crates/ozint-server/src/app.rs`](crates/ozint-server/src/app.rs), but only to a
  `gated` sub-router built by listing routes one `.route()` at a time — deliberately not
  inferred from a naming convention or a route prefix, because an implicit rule here is one
  nobody can audit and under-gating would be a silent egress leak while the UI says "frozen".
  The rule applied to decide each line: a route belongs in the gated group if it makes an
  outbound call or takes an action in the world (firing a layer, refreshing a node, capturing
  evidence from the Internet Archive, ingesting media from a URL); everything else — local reads,
  local edits/rejects/restores, cancel, the freeze endpoint itself — stays reachable even while
  frozen, because a frozen instance must still be inspectable and a kill switch you cannot
  un-flip is a brick. Engaging a freeze also actively cancels every layer already in flight
  (`state.ozint.cancel_all()`), rather than only refusing new requests.

None of these three make any claim about the *content* a tool receives back and acts on, and
none of them is a substitute for reviewing what a new source actually does with the bytes it
fetches.

## 7. The front-end data flow

`web/` is one cockpit, not a set of routed pages — `App.tsx` renders `OzintView` directly, no
router. The pipeline for a running investigation:

1. `POST /api/ozint/fire` opens one SSE connection per investigation call (start or continue);
   `store.ts` reads its body incrementally.
2. `stream-parser.ts`'s `OzintStreamReader` buffers raw text chunks (a `ReadableStream` delivers
   bytes with no relationship to frame boundaries) and yields whole parsed frames on `\n\n`
   boundaries, each validated against the `LayerEvent` union's `type` tag before being trusted.
3. `store.ts` folds each parsed frame into the tree via `applyEvent` (`lib/ozint/state.ts`),
   keyed by `layerId` — several branches of one investigation can be firing concurrently onto
   the same multiplexed stream, so nothing here assumes a single active layer.
4. The store exposes its state through `useSyncExternalStore`; `OzintView` and its children
   re-render as frames land, so a node's detail panel fills in live (via `ParentPayload` frames)
   while its own layer is still running, rather than snapping into its finished shape once at
   the end.

**Styling is inline, driven entirely by [`web/src/lib/ozint/tokens.ts`](web/src/lib/ozint/tokens.ts)
— there is no CSS framework and no Tailwind.** Every colour, spacing and type value a component
uses comes from that token module and is applied as a plain `style={{ ... }}` object; there is
no class-based design system to learn before a new view fits in visually.

## 8. Testing

Tests are colocated with the code they cover — every module in `crates/ozint/src/` and its
`sources/` submodules carries its own `#[cfg(test)] mod tests`, in the same file, immediately
below the code under test. There is no separate integration-test tree for the engine.

As measured directly (`cargo test --workspace`, and `npx vitest run` in `web/`): **1128 Rust
tests pass, 19 are `#[ignore]`d** (mostly live-sidecar smoke tests that need a Docker container
actually running — Maigret, holehe, Blackbird, SpiderFoot), and **183 TypeScript tests pass**
across 10 files. Re-run those two commands from the repo root and `web/` respectively for a
current count — do not trust either number staying accurate as the codebase grows.

**The known blind spot.** No mocking/HTTP-stub library is anywhere in the dependency tree of
this workspace. A source module's tests are almost always two pure-function tests — parse a
hand-built JSON fixture into the tool's own struct, then map that struct into a `ToolYield` —
never a test that drives the actual `run_*` async function against a stubbed HTTP response, the
way `github.rs`'s test module does above. That means the suite verifies "if the upstream API
still returns JSON shaped like this fixture, we parse it correctly" and says nothing about
whether the *live* request — URL, headers, auth, actual current response shape — still matches
what the code assumes. A change in an upstream API's response shape, a renamed field, or a
silently-changed auth requirement would not be caught by a green test suite; it would only
surface the next time someone actually fires a layer against that source. When adding a new
source, treat a single manual live call during development as load-bearing verification the
test suite cannot substitute for.
