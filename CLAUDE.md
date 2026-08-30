# CLAUDE.md — operating manual for this repo

For any agent (or human) working in OZINT. Read [ARCHITECTURE.md](ARCHITECTURE.md) for how the
code fits together, [STATUS.md](STATUS.md) for what is actually true today, and
[ROADMAP.md](ROADMAP.md) for what needs doing.

## What this is

An OSINT investigation cockpit. A seed value is classified into one of twelve entity types, a
layer of tools fires against it in parallel, findings become child nodes, and the analyst decides
by hand which child is worth a further layer. Rust engine, React cockpit, all local.

Extracted 2026-08-28 from a larger private project. If you find a comment or a name that only
makes sense in that context, it is a leftover — fix it.

## Run it

Rust **1.88+** (let-chains, enforced by `rust-version`), Node **20.19+ or 22.12+**, a C toolchain. `ffmpeg`,
`ffprobe`, `yt-dlp` and Docker are optional and only gate the tools that shell out to them.

```bash
cd web && npm install && npm run build && cd ..
cargo run -p ozint-server           # :3000, API + cockpit
cd web && npm run dev               # :5173, hot reload, proxies /api to :3000
```

No API keys are needed. 45 of the 62 tools are keyless. Runtime data — investigations, media,
the freeze record — lands in `.data/` (`OZINT_DATA_DIR`).

## Gates — all five green before committing

```bash
cargo test --workspace                        # 1 128 tests
cargo clippy --workspace --all-targets        # warning-free, not warning-tolerated
cd web && npm run test                        # 183 tests
cd web && npm run typecheck
cd web && npm run lint
```

## Rules that are not obvious from the code

**A green suite is weak evidence here.** Almost every source test hand-builds an already-parsed
response body, so it exercises the parser and not the request. If you change how a tool talks to
an upstream, the suite will not catch a mistake. Fire a real seed against a real server before
claiming a source works. This has cost real time more than once.

**Verify an external API by calling it, not by reading about it.** Claims about upstream
behaviour — in a plan, in a comment, from a research pass — have been wrong repeatedly. `curl` the
endpoint. If a comment in this repo states a measured fact about an upstream, it is because
somebody called it; keep that habit.

**"Produced no new nodes" and "produced no information" are different.** A tool that returns rows
but spawns no children is not a dead end. The engine models this distinction deliberately
(`SummaryCase::DeadEndWithFindings`, `describeLayerState`); do not collapse it when rendering or
summarising.

**Never require a key.** A missing key means a tool reports itself skipped, naming the variable
that would arm it. Never an error, never silent absence.

**Declare a real rate limit for every tool.** A tool with no registered limit is admitted
instantly by the scheduler. The failure mode is a ban from an upstream, noticed days later, far
from the cause.

**Go through `ozint_core::http::client()`.** It carries the pool, the timeout, the user agent and
the SSRF redirect policy. A hand-rolled `reqwest::Client` bypasses all four.

**The freeze gate's route membership is written out route by route in `app.rs`, on purpose.** An
implicit rule is one nobody can audit, and under-gating is a silent egress leak while the UI says
"frozen". When you add a route, decide explicitly which side it belongs on and say why.

## Conventions

- Comments explain **why**, not what. This codebase's comments are the reason a stranger can
  navigate it — match that register. When you correct a comment that was wrong, say it was wrong
  rather than quietly deleting it.
- Tests are named as sentences describing the property held.
- Code, identifiers and comments in English.
- The cockpit has no CSS framework: inline styles from `web/src/lib/ozint/tokens.ts`. Add a token
  rather than a hex value.
- Small commits. Append to [PROGRESS.md](PROGRESS.md) for anything meaningful.

## Do not

- Scrape anything whose terms of service forbid it, or use a login/registration flow to test
  account existence.
- Add a source requiring an account a reader cannot get themselves, free and self-serve.
- Commit a key, a real email address, or a `.mmdb` file.
- Bind the server to `0.0.0.0`. There is no authentication; the loopback bind is the mitigation.

## Where things live

| Need | Path |
|---|---|
| The tool catalogue — start here | `crates/ozint/src/registry.rs` |
| What fires for which type | `crates/ozint/src/plans.rs` |
| The layer runtime | `crates/ozint/src/runtime.rs` |
| Source implementations | `crates/ozint/src/sources/<type>/<name>.rs` |
| Dispatch to a source | `crates/ozint/src/sources/mod.rs` |
| Tables and queries | `crates/ozint/src/store.rs` |
| Routes and the freeze gate | `crates/ozint-server/src/app.rs`, `src/routes/ozint/` |
| SSRF guard, freeze state | `crates/ozint-core/src/net.rs`, `src/safety/` |
| SSE parsing, cockpit state | `web/src/lib/ozint/stream-parser.ts`, `store.ts` |
| Design tokens | `web/src/lib/ozint/tokens.ts` |
