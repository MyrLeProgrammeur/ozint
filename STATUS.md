# Status

The honest account of where this project actually is. Read this before assuming anything works.
Dated history is in [PROGRESS.md](PROGRESS.md); work that needs doing is in [ROADMAP.md](ROADMAP.md).

**Last verified: 2026-08-28**, including an independent adversarial audit of the whole repository.

---

## What is true

**The engine runs and is heavily tested.** Twelve entity types, each with a plan and a working
orchestrator. 62 catalogued tools, 45 of them keyless. 1 128 Rust tests and 183 cockpit tests
pass; clippy is warning-free; the web app typechecks and lints clean.

⚠️ *This said "the engine is complete" until 2026-08-30. It is not — see the first entry under
"What is rough". Individual tools work; what they hand back to the tree does not yet make an
investigation grow the way the product describes.*

**The whole thing runs.** `cargo run -p ozint-server`, open the port, type a seed, fire. Verified
on 2026-08-28: the root node is created, the layer starts with its armed-tool count, tools report
individually, and the tree renders.

**The cockpit is usable.** Tree with layer bands and per-tool lists, node detail panel leading
with provenance, subject-file rail, type selector, history resume, edit/reject/restore, relations
and spawn. All of it has been driven in a browser against a real server, not against fixtures.

**The kill switch works and is server-enforced.** Not a client-side toggle: a middleware over an
explicit route list, persisted to disk, failing closed if its record is unreadable, and cancelling
every live layer when engaged.

---

## What is rough

**Findings that should be nodes come back as rows, so the tree stops growing.** This is the
biggest gap in the product and it was found the obvious way — firing on an email address and
watching nothing appear. A tool returns `rows` (facts you can read) and `children` (nodes you can
pursue), and across the catalogue investigable values keep landing in the first. Fire on an email
and three of the five tools emit no children at all. `wmn-probe` confirms accounts across ~730
sites and produces neither a row nor a child from any of them. No source anywhere turns a profile
photo into something you can reverse-image-search, though the tools to do that are built. And
`entity-video`, one of the twelve advertised types, may not be reachable at all.

Three audits mapped it tool by tool; the findings are in issues #8 through #13, with #8 as the
umbrella. The fix pattern already exists in the repository — `domain/certspotter.rs` emits capped
children with an explicit `truncated` flag — so this is mostly a matter of applying it, plus one
genuine design question about images that #11 lays out.

**The test suite does not test the network.** This is the important one. Almost every source test
hand-builds an already-parsed response body, so it verifies the parser and not the request. An
upstream can change its response shape and the suite stays green while the tool silently returns
nothing. Roughly thirty tools share this blind spot. Fixing it is the top item in
[ROADMAP.md](ROADMAP.md).

**Nothing monitors source health.** There is no endpoint that says which tools have stopped
returning anything. Today you find out mid-investigation.

**The tree does not virtualise.** Every visible node is an absolutely positioned card. A genuine
fan-out is several hundred, and nothing windows them. Not yet hit in practice, but it is the
known scaling wall.

**Desktop only.** The layout was built for one 1440px-plus machine and nothing below that was ever
attempted. It will look wrong on a tablet and will not work on a phone.

**Cards are sized for the richest node, not the typical one.** Every card is 292x212 whatever it
holds, so a subdomain carrying a name and one provenance line leaves most of its card empty — a
whole row of them reads as sparse. `COMPACT_GEOMETRY` exists in `web/src/lib/ozint/layout.ts` and
is wired to nothing. Making height follow content means giving up the uniform-row assumption the
tidy-tree pass is built on, which is why it has not been done casually.

**No authentication.** This is why the server binds `127.0.0.1` rather than `0.0.0.0`. Put a
reverse proxy with real auth in front of it if you need it remote — do not just change the bind
address.

**No packaging.** No release binary, no container image, no `cargo install`. Running this
currently requires a Rust toolchain and Node, which is a real barrier for a first-time user.

**Two video tools dead-end.** `video-telegram-resolve` and `video-bluesky-resolve` resolve a media
URL and then have nowhere to feed it — `video-local-probe` never receives it, so video
investigation stops one step short of the keyframes.

**Sidecars must be started by hand.** `docker compose -f crates/ozint/docker/docker-compose.yml up -d`.
Nothing starts them for you. A layer whose container is down records that tool as an explicit
failure naming the address it tried — legible, but reported as a failure rather than as a skip,
which is arguably the wrong category for a dependency the user simply has not installed.

---

## Known unknowns

**The upstreams have not all been re-verified since extraction.** The tools were built and tested
live between 2026-08-25 and 2026-08-26. Any of the 62 could have broken since; see the blind spot
above for why the suite would not tell you.

---

## Before this goes public

This repository is still private. Two things must happen at the moment it is flipped, and both
are settings rather than code — **delete this section once they are done**:

1. **Enable private vulnerability reporting** (Settings → Security). [SECURITY.md](SECURITY.md)
   tells reporters to use it; the feature is unavailable on private repositories, so the
   instruction only becomes true at the flip. Its fallback — open an issue with no detail and ask
   for a contact — covers the gap until then.
2. **Check the licence and attribution claims survive the flip.** [CREDITS.md](CREDITS.md) states
   that no third-party code is redistributed here. That is true of this tree, and it was once
   false of what had been pushed: an encumbered file removed from the working tree remained
   fetchable from GitHub by its old commit SHA, because a force-push does not delete objects on
   their side. It was resolved by deleting and recreating the repository. If history is ever
   rewritten again to remove something, verify with an unauthenticated request to the old commit
   URL rather than with a local `git` command.

---

## Provenance of this repository

OZINT was extracted on 2026-08-28 out of a larger private project, where it had been built between
2026-08-25 and 2026-08-26. The extraction changed no engine logic. What it did change:

- Crates were renamed to the `ozint-*` prefix, and the dependency on the parent project's memory
  layer was reduced to a 60-line SQLite handle, since OZINT owns all its own tables.
- The LLM client, previously hard-wired to one private provider, became a generic
  OpenAI-compatible client configured by `OZINT_LLM_*`. Any provider works, and none is required.
- The parent project's server was replaced by a standalone one carrying only `/api/ozint/*`, the
  freeze gate and the static cockpit.
- The cockpit gained a minimal shell; its components were already self-contained and were copied
  unchanged.

The test count survived the move unchanged, which is the main evidence that nothing was lost.
