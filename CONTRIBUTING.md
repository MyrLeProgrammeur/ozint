# Contributing

Contributions are wanted, including small ones — and including the ones that are not code at
all. This project is built in evenings by one person and covers fifty-three upstream APIs that
change without warning, so it needs more hands than it has. It also needs more *opinions* than it
has: the direction is not settled, and someone who does investigative work for real knows things
about it that its author does not. The README's [Contributing](README.md#contributing) section
says more about that; this file covers the mechanics.

## Before you start

- **An idea, a proposal, or a disagreement?** Open an issue. Half-formed is fine. Arguing with a
  design decision is a contribution, not a nuisance — every one of them is written down with its
  reasoning precisely so it can be argued with.
- **Small fix?** Just open the pull request. A dead parser, a wrong rate limit, a typo, a missing
  test — no discussion needed.
- **New source, or anything structural?** Open an issue first so we can agree on the shape before
  you spend an evening on it.
- **Taking a roadmap item?** Say so on an issue, so two people do not build the same thing. The
  roadmap is not a queue and nothing on it is sacred — if you think an item is wrong, say that
  instead of building it.

## Setting up

Rust **1.88+**, Node **20.19+ or 22.12+**, and a C toolchain (`build-essential pkg-config libssl-dev` on
Debian/Ubuntu) — SQLite, the image decoders and the QR reader all compile from source. `ffmpeg`,
`ffprobe`, `yt-dlp` and Docker are needed only by the tools that shell out to them; see the
README's table. Nothing you need to develop requires an API key.

```bash
cd web && npm install && npm run build && cd ..
cargo run -p ozint-server        # :3000, serves the API and the cockpit
cd web && npm run dev            # :5173, hot reload, proxies /api
```

Forty-five of the sixty-two tools are keyless, so a fresh clone with no `.env` at all still
exercises most of the catalogue.

## The gates

All five must be green before a pull request is merged. Run them locally; CI runs the same ones.

```bash
cargo test --workspace                        # 1 128 tests
cargo clippy --workspace --all-targets        # must be warning-free
cd web && npm run test                        # 183 tests
cd web && npm run typecheck                   # tsc --noEmit, strict
cd web && npm run lint
```

A clippy warning is a failure here, not a suggestion.

**A green clippy locally is not proof.** CI runs it on current stable, which may be newer than
your toolchain and will know lints yours does not — the first CI run on this repository failed on
a lint that did not exist in the maintainer's own compiler. That is the gate working as intended,
not CI being difficult: `rustup update` before you are surprised by it. The `rust-version = 1.88`
floor in `Cargo.toml` is about what will *build*, and says nothing about what will lint.

## Adding a source

[ARCHITECTURE.md §5](ARCHITECTURE.md) walks through it against a real file. The short version:

1. Write `crates/ozint/src/sources/<type>/<name>.rs`, following an existing sibling.
2. Register a `ToolDef` in `crates/ozint/src/registry.rs` — id, label, the entity type it serves,
   its rate limit, and the env vars it needs (empty if keyless).
3. Add it to the relevant plan in `crates/ozint/src/plans.rs`.
4. Add it to the dispatch match in `crates/ozint/src/sources/mod.rs`.
5. Write tests in the same file.

### What a source must do

**Declare a real rate limit.** Read the upstream's published limit and put it in the registry.
A tool with no declared limit is admitted instantly by the scheduler, which means the first
person to run a wide layer gets the project banned from that API.

**Never require a key to exist.** A missing key means the tool reports itself skipped, with the
name of the variable that would arm it. It must not error, and it must not be silently absent.

**Return provenance, not just values.** Every finding needs the URL it came from and enough of
the raw response to justify it. A finding a user cannot check is worse than no finding.

**Be honest about nothing.** "The API answered and had no records" and "the API did not answer"
are different outcomes and must not collapse into the same empty result. The engine models this
distinction; do not throw it away in your parser.

**Go through the shared HTTP client** (`ozint_core::http::client()`). It carries the connection
pool, the timeout, the user agent and the SSRF redirect policy. A hand-rolled `reqwest::Client`
bypasses all four.

### What a source must not do

- Scrape a site whose terms of service forbid it.
- Require an account the reader cannot get themselves, self-serve, for free.
- Use a credential-stuffing, login-flow or registration-flow trick to test account existence.
- Call an endpoint that is not publicly documented, unless you have verified it is intended to
  be public and you say so in the module doc.

## Tests

Tests live in the same file as the code, in a `#[cfg(test)] mod tests`. Name them as sentences
describing the property being held: `a_frozen_classifier_refuses_before_any_llm_attempt`, not
`test_classifier_2`.

Be aware of the standing blind spot: most source tests hand-build an already-parsed body, so they
verify the parser and not the request. If you can test the fetch path too, do — see
[ROADMAP.md](ROADMAP.md), where fixing this properly is the highest-value item in the project.

## Style

**Rust.** Standard `rustfmt`. Comments explain *why*, not *what* — the existing codebase is
heavily commented in that register, and it is the reason a stranger can navigate it. If you make
a non-obvious decision, write down the reason next to it. If you correct a comment that turned out
to be wrong, say so rather than quietly deleting it.

**TypeScript.** Strict mode, no `any`. The cockpit uses inline styles from
`web/src/lib/ozint/tokens.ts` and has no CSS framework — add a token rather than a hex value.

**Commits.** Small, and the message says what changed and why. No fixed prefix convention is
enforced.

**Language.** Code, identifiers and comments in English.

## Security

If you find something with a security impact — an SSRF bypass, a way to make the tool leak the
analyst's seed to an unintended party, a path traversal in the media store — please do not open a
public issue. [SECURITY.md](SECURITY.md) has the reporting route and what is in and out of scope.

## Licence

By contributing you agree that your contribution is licensed under the MIT licence, the same as
the rest of the project.
