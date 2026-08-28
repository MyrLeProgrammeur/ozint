# Roadmap

This is a list of work that needs doing, written so that you can pick something up without
asking anyone first. Items are scoped to be finishable alone. If you take one, open an issue
saying so, so two people do not do it twice.

Nothing here is assigned. Nothing here has a deadline. And nothing here is authoritative: this is
one person's view of what matters, from one desk, and the gaps in it are exactly the ones he
cannot see. If something important is missing, or something listed is not worth doing, that is
worth an issue on its own — proposals and disagreements are as welcome as patches.

---

## Open questions — where an opinion is worth more than a patch

These are unresolved, and I would rather be argued out of my current answer than have it
calcify. Each is an issue waiting to be opened.

**Should a layer ever expand more than one step?** Today nothing recurses: every child waits for
a click. That is the design, and it is what keeps a tree readable. But an analyst chasing a lead
through four hops clicks four times and waits four times, and I do not know whether the
discipline is worth that friction, or whether a bounded "follow this branch two deep" would keep
the property while removing the tedium.

**What belongs in a dossier?** `GET /api/ozint/investigations/{id}/export` produces JSON and
Markdown from the whole tree. I do not know what a report needs to contain to be usable as
evidence by somebody who was not present for the investigation, and I have never had to file one.

**Should rejected findings stay visible?** A node can be rejected, which hides it but keeps it.
Whether a reader of the dossier should see what was considered and dismissed — and how much
weight that should carry — is a question about investigative practice, not about code.

**Is one seed per investigation right?** An investigation has one root. Real work often starts
from three things you suspect are the same person. Spawning links them loosely; merging them does
not exist. Whether it should is genuinely open.

**What is missing from the catalogue that you reach for every day?** The 62 tools are the ones
one person could find and verify. The gap between that and what a working analyst actually uses
is the thing I most want described to me.

**Is the cost meter meaningful?** Every layer reports a lookup count and a cost in euros. With 45
keyless tools that number is almost always zero, and I am not sure the meter earns its place
rather than implying a paid product that does not exist.

---

## The most valuable thing anyone could do

### Close the live-path test blind spot

Almost every source test hand-builds an already-parsed response body and asserts the parser
turns it into the right findings. That tests the parser and nothing else. It does **not** test
that the request we send is the request the upstream expects, or that the shape we parse is
still the shape it returns.

The consequence is concrete: when an upstream changes its response, the suite stays green and
the tool silently returns nothing. This has already happened.

What would fix it, roughly in order of usefulness:

1. **A recorded-fixture harness.** Capture a real response once, commit it, and drive the whole
   fetch-and-parse path against it — not just the parser half. `web/src/lib/ozint/__fixtures__/`
   does exactly this for the SSE stream and is a good model.
2. **An opt-in live smoke test per source**, `#[ignore]`d by default and run on a schedule, that
   makes one real request against a known-stable target and asserts the shape still holds.
3. **A `GET /api/ozint/health`** that reports, per tool, when it last returned anything — so a
   dead source is visible instead of being discovered by an analyst mid-investigation.

Any one of these three is a complete, self-contained contribution.

---

## Sources

### Fix a dead one

The fastest way to help. Fifty-three upstreams change without notice. Find one returning nothing,
read its current API docs, fix the request or the parser, and add a fixture for the new shape.

### Add a new one

[ARCHITECTURE.md §5](ARCHITECTURE.md) is a worked example against a real file. Sources people
have asked for and nobody has built:

- **Wayback CDX** for a domain — every URL the Internet Archive holds for a host, which is often
  the fastest way to see what a site used to be.
- **crt.sh** as a second certificate-transparency source alongside Certspotter.
- **Shodan InternetDB** exists for IPs; the same for domains does not.
- **Telegram channel metadata** from a username, beyond the current video-resolve.
- **Have I Been Pwned** for email (needs a paid key, so it must be cleanly optional).
- **A generic RSS/sitemap crawler** for a domain, to enumerate what a site publishes.

### An absent optional dependency should be a skip, not a failure

Right now a sidecar whose container is not running is reported as an error —
`sidecar unreachable at http://localhost:5000/…`. It is legible, but it is the wrong category,
and it costs the project its first impression: following the README exactly, with no Docker and
no keys, a `torvalds` seed settles `DEGRADED` with a wall of red for two dependencies the reader
was explicitly told were optional.

`ToolOutcome` already models this distinction carefully — thirteen variants, each with a written
argument for why the alternatives would lie (read `SkippedMissingInput`'s doc, which is the
model to follow). A fourteenth belongs here: *not attempted, because an optional local
dependency is not installed*. The rule that makes it honest rather than a way of hiding errors:
a connection refused on the sidecar's port means it is not running, which is a skip; **any HTTP
response at all means it is running and something went wrong, which stays a failure.**

Touches the sidecar sources, `outcome.rs`, and `web/src/lib/ozint/outcomes.ts` on the rendering
side. Well-scoped, and it would visibly improve what a newcomer sees on their first run.

### Finish the video chain

`video-telegram-resolve` and `video-bluesky-resolve` resolve a CDN or HLS URL and then have
nowhere to put it — `video-local-probe` does keyframe extraction but the resolved URL is never
fed back into it. Wiring those two together would make video investigation actually work
end to end. Self-contained, and the two halves already exist.

### Stop dropping fields we already fetch

An audit found roughly fifteen places where a tool receives rich data from an upstream and keeps
only a fraction of it. Known examples: HudsonRock returns IP addresses we discard, PeeringDB
returns contact records we discard, `ffprobe` returns GPS metadata we discard. Each is a small,
local, obviously-correct change.

---

## The cockpit

### Virtualise the tree

Every visible node is an absolutely positioned card. A genuine fan-out is several hundred nodes,
and nothing windows them. This is the known scaling wall, and it needs someone who has done
virtualised canvas rendering before.

### Make it work below 1440px

The layout is deliberately desktop-only — it was built for one machine and no phone layout was
ever owed. That decision can be revisited now that other people might run it. A tablet-width
layout would be a real contribution; a phone layout is probably not worth it.

### Keyboard navigation

There is none. An investigation is a tree, and trees are a natural fit for the keyboard —
arrow keys to move, Enter to fire, Escape to close the detail panel.

---

## The server

### Authentication

There is none, which is why the server binds `127.0.0.1` and not `0.0.0.0`. Anyone wanting to run
this on a box they SSH into currently has to put a reverse proxy in front. A minimal token or
basic-auth layer, off by default, would remove that friction without pretending to be more than
it is.

### Structured audit of outbound calls

Every request the process makes to a third party should be recordable — which tool, which host,
when, on whose behalf. This matters for anyone who has to justify their queries after the fact,
and the plumbing (one shared HTTP client) already makes it a single place to hook.

### Package it

There is no release binary, no container image and no `cargo install` path. A `Dockerfile` and a
GitHub release workflow would let people try this without a Rust toolchain — probably the single
biggest barrier to a first-time user right now.

---

## Documentation

- **A worked investigation walkthrough** — one real seed, followed through four layers, showing
  what the tool is actually for. The README now has two screenshots of a single layer; what is
  missing is the thing they cannot show, which is judgement: why you followed *that* child and
  not the other twenty. This would do more to explain the project than any amount of
  architecture prose.
- **Surface attribution in the cockpit.** `ToolDef::attribution` carries licence-required credit
  lines for fourteen sources and nothing renders them; the obligation is currently met by
  [CREDITS.md](CREDITS.md) and a test, which is adequate but not what the code intends. Showing
  a source's credit line in the node detail panel, beside the provenance it belongs to, would be
  better. It needs `attribution` threaded onto `ToolReport` and out over the wire.
- **Screenshots of the other entity types.** The two in the README are both a domain. An image
  with EXIF, a CVE with its exposure data, and a username fan-out all look quite different and
  none of them is shown.
- **Per-source documentation** of what each tool returns and what its rate limit really is in
  practice, as opposed to what the upstream claims.
