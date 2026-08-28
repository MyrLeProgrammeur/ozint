# Progress log

Append one entry per meaningful step, newest at the top. Say what changed and what it means, not
just which files moved. Current state lives in [STATUS.md](STATUS.md); this file is history.

---

## 2026-08-30 — A second audit, and what CI found in its first minute

The repository was audited again, by someone told nothing about the first round and instructed to
take none of it on trust. It found a blocker the first pass and I had both missed, and it was
right.

**Deleting the GPLv3 file did not remove it.** It was gone from the working tree and fully intact
in the first commit — `git show <first-commit>:…email-data-patched.json` returned all 532 lines,
author's name included. A public repository serves every blob in its history, so the licence
problem was untouched; it had only become invisible. The same applied to the ~190 private-project
references: they survived as *deletions* in the second commit, where `git log -p` reads them back
in full. This file claimed the history had been left behind for a publication surface of "exactly
zero", and that claim had quietly become false. The history is now squashed to a single commit.

**CI failed on its first run, and the failure was real.** Two `video/local_probe` tests shell out
to `ffmpeg`, which the runner does not have and this machine does — so `cargo test --workspace`
was broken for anyone without it, while the README calls ffmpeg optional. They now skip loudly
when it is absent, and CI installs it so the skip is honest: a test nothing guarantees will run
is a deleted test with extra steps.

**`bluesky-actor` could never have worked.** Its API takes an AT identifier — a handle containing
a dot, or a DID — and it is registered against an entity type whose seeds are bare usernames, so
it answered `400 Invalid AT identifier` for essentially every value it was given. Verified live:
`torvalds` is refused, `torvalds.bsky.social` returns a profile. Bare handles are now qualified,
and the provenance records what was actually queried. Every test it had fed it an already-valid
handle, which is why a green suite never noticed.

**The cockpit's root element was styled with Tailwind classes, in an app with no Tailwind.**
`fixed inset-0 z-50 flex flex-col`, carried over from the host application this was extracted
from, matched nothing. The column still stacked and the canvas still filled its own box, so the
only visible trace was a band of dead background below the status bar — which is what made the
screenshots look like bad captures.

**Numbers now defend themselves.** The audit confirmed every published figure was true, but two
had drifted in the source: `registry.rs`'s module doc still described a seven-tool vertical slice,
and a correction to it over-counted by mistaking the `ToolDef` struct declaration for an entry.
`registry::tests::the_catalogue_holds_the_number_of_tools_the_docs_claim` now pins the catalogue
size, the keyless count and the access-tier split, so the next drift is a red build rather than a
false README.

**An unmet licence obligation.** `ToolDef::attribution` carried credit lines for fourteen sources
— several required, not optional, including WhatsMyName's CC BY-SA 4.0 and MaxMind's GeoLite2
terms — and was read by nothing but a test asserting it was `Some`. `CREDITS.md` now carries them,
enforced by a test that fails if an attributed source is not named there. It caught a genuine
omission on its first run.

Three claims of mine were also simply wrong and are corrected: "62 upstream APIs" (nine tools make
no network call; it is 53), a screenshot caption that enumerated six tools out of five, and a test
fixture using a plausible real address at a real provider — the one thing an OSINT repository
should not ship.

Both screenshots were retaken after the layout fix, and the first now shows two layers rather than
one, including a dead end reported as a dead end.

---

## 2026-08-28 (later) — Audited, corrected, and made presentable

An independent adversarial audit was run against the repository by someone with no knowledge of
how it had been built, with one question: is this safe and honest to publish? Its verdict was
*publish after fixes*, and it confirmed something worth recording — every headline number in the
docs was exactly true, including the test counts, the 62 tools and the 45 keyless ones. Nothing
had been inflated. What it found instead was four blockers, all of which are now closed.

**A GPLv3 file was being distributed from an MIT repository.** `email-data-patched.json` was
Blackbird's own data file with a `metadata` block added to two of its sixteen entries — still
carrying its author's name. Blackbird's *code* is only cloned at build time, which is fine; this
one committed file was not. It is gone, replaced by `patch-email-data.py`, ours, which applies
the same two-entry patch to the clone inside the image. Verified against the real upstream file:
it patches correctly and fails the build loudly if a site has moved or if upstream has since
added its own spec, rather than overwriting one.

**A comment claimed third-party code had been audited when it had not.** The Blackbird Dockerfile
said "pinned to a commit read and audited"; the command beneath it was `git clone --depth 1` with
no ref, taking whatever HEAD was that day. It now pins an actual commit through a build arg, and
the comment says what is true.

**The docs promised a CI that does not run.** `.github/workflows/ci.yml` is written and correct,
but pushing it needs a token scope this repository's owner has not yet granted. Committing it
makes that scope a prerequisite for publication rather than a forgotten TODO.

**Dead references were everywhere, including in a user-facing deliverable.** Roughly 190 comments
cited planning documents, decision codenames and file paths from the private project — a stranger
following any of them found nothing. All are rewritten to state their reasoning as this project's
own; where a comment carried a measured fact, the fact was kept and only the pointer dropped. The
worst case was not a comment at all: an exported dossier told its reader to "see decision 2 of
`docs/plans/ozint-prototype-decisions.md`", a file that has never existed here.

**Two things were wrong in ways only a real run could show.**

The cockpit did not scroll. A flex child without `minWidth: 0` grew the page to the width of the
tree instead of letting the canvas clip it, so a 21-child layer put the root node at x≈3100 in a
1680px window with no way to reach it. Fixed, along with `justify-content: safe center` — plain
`center` overflows in both directions and the left half is unreachable, because `scrollLeft`
cannot go negative. The view now also follows the tree as it grows, until the analyst scrolls
themselves; a crosshair control gives that back. The first attempt at this was wrong in an
instructive way: it recentred once, when the first child arrived and the tree was two cards wide,
then held still while twenty more widened the canvas — which measured as `scrollLeft: 0`, exactly
the bug it was meant to fix.

And every default installation was being told a lie. With no model configured, each settled layer
reported "the local model was unreachable" — describing a failed call that had never been
attempted. A missing key and a dead endpoint both surfaced as the same error, and the fallback
could not tell them apart. `FallbackReason::NotConfigured` now does, before any call is made, and
says which variable would enable the narration. The test that asserted the old wording was
updated to assert the honest one; that test is why the count moved from 1 123 to 1 124.

**Documentation.** Prerequisites were incomplete and one was false: the README claimed Rust 1.85
while the code uses let-chains and needs 1.88 — `rust-version` now enforces it. `ffmpeg`,
`ffprobe` and `yt-dlp` are invoked by real tools and were listed nowhere. Where investigations are
stored was never stated. The contribution ask was rewritten: it had read as a maintenance rota,
and what this project actually needs more than patches is people willing to argue with its
design, so `ROADMAP.md` now opens with six genuinely unresolved questions. The README has its
first two screenshots — one of a layer settling, one of the provenance panel, which demonstrates
the project's central claim rather than asserting it.

---

## 2026-08-28 — Extracted into a public repository

OZINT was pulled out of the private project it was built inside and made a standalone, public,
MIT-licensed repository, so that it can be worked on by people other than its author.

**The engine came across unchanged.** 1 123 Rust tests passed before the move and 1 123 pass
after it, which is the main evidence that the extraction cost nothing. Clippy is warning-free, the
cockpit's 183 tests pass, and the whole stack was run end to end — a real seed fired, a real layer
started, tools reported individually.

What the extraction actually changed:

- **Crate layout.** Five crates: `ozint-core` (config, HTTP pool, SSRF guard, freeze kill switch),
  `ozint-db`, `ozint-llm`, `ozint` (the engine, 62 sources), `ozint-server` (axum).
- **The database dependency shrank to almost nothing.** OZINT declares all its own `oz_*` tables
  next to the code that reads them, so the parent project's 1 900-line memory crate reduced to a
  60-line SQLite handle that deliberately creates no tables at all.
- **The LLM became provider-agnostic.** It had been wired to one private inference provider by
  name, in both the layer summary and the classifier escalation. It is now a small
  OpenAI-compatible client behind `OZINT_LLM_BASE_URL` / `OZINT_LLM_API_KEY` / `OZINT_LLM_MODEL`,
  which works against OpenAI, OpenRouter, Groq, Together or a local Ollama — and, crucially, is
  entirely optional. Both call sites already degraded honestly when no model answered; that
  property is what made the substitution safe.
- **A standalone server replaced the parent's.** Only `/api/ozint/*`, the freeze gate and the
  static cockpit. It binds `127.0.0.1`, not `0.0.0.0`: an investigation cockpit holds the
  analyst's raw seeds and has no authentication of its own.
- **The cockpit needed a shell and nothing else.** Its thirty files turned out to import nothing
  from the host application — inline styles from their own token table, no CSS framework, no
  shared components. A Vite entry point and a two-line `App.tsx` were the whole port.
  `OzintView`'s close button became conditional, since standalone there is nothing behind it.
- **Two things were scrubbed before publication.** The author's real email address appeared in two
  live sidecar tests, and the private provider's name appeared in a wire field the cockpit sends
  (`showInfercom`, now `showSummary`). Neither would have been a secret leak, but both would have
  been wrong to publish.

Written for this repository at the same time: `README.md`, `ARCHITECTURE.md` (including a worked
example of adding a source), `CONTRIBUTING.md`, `ROADMAP.md`, `STATUS.md` and this log.

**What was deliberately not done:** the git history was not carried over. The commits that built
OZINT are interleaved with unrelated private work, and rewriting them would have meant auditing
every message for context that does not belong in public. The cost is `git blame`; the benefit is
a publication surface of exactly zero.
