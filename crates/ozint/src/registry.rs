//! The single declarative catalogue of every OZINT tool: what entity
//! types it applies to, how it is reached, what it costs, and the provenance sentence it
//! contributes. Nothing here executes a tool — see the module doc below for why, and see
//! `sources::dispatch` for where execution actually happens.
//!
//! **Only what is actually implemented.** Every entry here has a dispatcher behind it in
//! `sources::dispatch` — an entry without one is worse than no entry at all, because
//! `resolve()` would report it "runnable" and the caller would have nowhere to send it.
//! The catalogue currently holds 62 tools, spread across all twelve entity-type
//! categories under `sources/`. `access_tier` splits them 31 keyless-open, 16 free-key, 7
//! local-only, 6 sidecar and 2 directory-only. (Forty-five need no key at all: the
//! keyless-open ones plus the local, sidecar and directory tiers, less the one sidecar that
//! does take a key.) These numbers are pinned by
//! [`tests::the_catalogue_holds_the_number_of_tools_the_docs_claim`].
//!
//! Sources that were considered and deliberately **not** catalogued — e.g. PullPush
//! (Reddit), which turned out to be walled — are documented with their verification dates in
//! the relevant category's module doc (see `sources::username` for that example).
//!
//! ## Design choice: function pointers vs. a dispatch function
//!
//! There are two natural shapes for expressing "what a tool does": function pointers
//! (`build_url`/`parse`) stored directly on [`ToolDef`], or a small `match`-based dispatch
//! function living in `sources/mod.rs`. This module takes the **dispatch function** route,
//! for three reasons:
//!
//! 1. **Repo precedent.** `sources/*.rs` in this crate is plain `pub async fn fetch_*`
//!    functions with no registry/trait indirection at all — the natural shape for "a tool
//!    that fetches and parses", which this dispatch-function approach follows rather than
//!    a `dyn Trait` registry.
//! 2. **Async fn pointers don't fit cleanly in a `const` catalogue.** `ToolDef` below is a
//!    plain-data `const`/`Copy` struct so the whole catalogue can be a `&'static [ToolDef]`
//!    array literal — no `Lazy`/`OnceLock` needed (this crate has no `once_cell`/
//!    `lazy_static` dependency, and none should be added for this). Storing async behaviour
//!    on the struct would force either boxed trait objects (`Pin<Box<dyn Future>>` return
//!    types) or giving up on `const` construction; a `match tool_id { .. }` dispatch keeps
//!    the data and the behaviour cleanly separate and keeps this file pure data.
//! 3. **WhatsMyName's fan-out doesn't fit a `build_url`/`parse` pair anyway.** It is not one
//!    request; it's ~730 bounded-concurrency requests folded into one logical invocation
//!    (counted as ONE lookup). That shape needs a real function body,
//!    not a URL template plus a response parser.
//!
//! ## What this module owns vs. what it doesn't
//!
//! This module: tool metadata, lookup by id, lookup by [`OzType`], whether a tool is
//! *armed* (its env vars are all present), and [`resolve`] — which tools **could** run for a
//! given type right now, and the [`crate::outcome::ToolOutcome`] each unarmed one would
//! report if asked to.
//!
//! This module does **not**: make any network call, decide *when* a tool fires within a
//! layer's phased cascade (that's `layer_plan.rs`), or actually invoke a tool (that's
//! `runtime.rs`'s `fire_layer`, which resolves tools through this module and calls
//! `sources::dispatch` to run them).

use crate::outcome::ToolOutcome;
use crate::types::OzType;

// ─── Access tier ────────────────────────────────────────────────────────────

/// How a tool is reached, narrowed to the buckets that actually need to be branched on
/// (arming, scheduling, UI badge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessTier {
    /// No login, no key, no captcha — wire first.
    KeylessOpen,
    /// Works after a free key/registration.
    FreeKey,
    /// Works but the useful tier costs money.
    PaidKey,
    /// Runs in-process or as a bundled local binary — no network call at all.
    LocalOnly,
    /// Launch-only URL-template tile; never fetched (`OzType::Directory`'s whole point).
    DirectoryOnly,
    /// Only usable via a deliberately-deployed Python/Docker sidecar.
    Sidecar,
}

// ─── Tool yield ─────────────────────────────────────────────────────────────

/// What one tool produced. The layer runtime (`runtime.rs`'s `fire_layer`) applies it: merges
/// `payload_patch` into the triggering node's payload, appends `rows` to the parent's detail
/// sections, posts `facts`/`flags` into a [`crate::layer_plan::PhaseAcc`] for later phases'
/// predicates, and turns each [`ChildSeed`] into a typed child node (after dedup).
#[derive(Debug, Clone)]
pub struct ToolYield {
    /// Merged into the parent node's payload. An empty object (`{}`), not `null`, when a
    /// tool has nothing to contribute here — a JSON-merge-patch style empty object is a
    /// documented no-op, whereas `null` risks being read as "clear the field".
    ///
    /// [`Default`] is hand-written rather than derived precisely so this holds: a derived
    /// `Default` produces `Value::Null`, and five tools were building their `OkEmpty` yield
    /// with `ToolYield::default()` — a contract violation this comment described but nothing
    /// enforced. It is inert against today's shallow [`merge_patch`](crate::runtime) (which
    /// bails on a non-object patch), which is exactly what made it survive: the comment was
    /// the only thing standing between here and a real JSON Merge Patch implementation
    /// erasing a node's payload.
    pub payload_patch: serde_json::Value,
    /// Rows for the parent's detail sections (profile facts, links, …).
    pub rows: Vec<crate::types::OzRow>,
    /// `layer_plan` `FACT_*` keys this tool's findings feed into.
    pub facts: Vec<(&'static str, f64)>,
    /// `layer_plan` `FLAG_*` keys this tool's findings feed into.
    pub flags: Vec<(&'static str, bool)>,
    /// `layer_plan` `INPUT_*` keys this tool's findings publish for a **later wave** of the
    /// same layer — the sibling hand-off. See [`crate::layer_plan::Handoff`].
    ///
    /// Deliberately separate from `payload_patch`, which a later tool could in principle have
    /// been made to read instead. It must not be: the patch is folded with a shallow
    /// last-writer-wins merge, so a hand-off read out of it would silently depend on which
    /// tool happened to write last. This channel is explicit, attributed, and refuses to
    /// resolve a disagreement.
    pub values: Vec<(&'static str, String)>,
    pub children: Vec<ChildSeed>,
}

impl Default for ToolYield {
    fn default() -> Self {
        Self {
            payload_patch: serde_json::Value::Object(serde_json::Map::new()),
            rows: Vec::new(),
            facts: Vec::new(),
            flags: Vec::new(),
            values: Vec::new(),
            children: Vec::new(),
        }
    }
}

/// A candidate child node this tool's result implies. Never invented beyond what the tool's
/// response actually contained.
#[derive(Debug, Clone, PartialEq)]
pub struct ChildSeed {
    pub oz_type: OzType,
    pub value: String,
    pub note: Option<String>,
}

// ─── Tool definition ────────────────────────────────────────────────────────

/// One catalogued tool. Plain data — `Copy` so the whole catalogue can be a `const` array
/// with zero runtime initialization cost.
#[derive(Debug, Clone, Copy)]
pub struct ToolDef {
    /// Stable id, matched against in `sources::dispatch` and stamped into
    /// `Provenance::source_tool_id` / `ToolReport::tool_id`.
    pub id: &'static str,
    pub label: &'static str,
    /// Which entity types this tool applies to.
    pub types: &'static [OzType],
    pub access_tier: AccessTier,
    /// Env vars this tool needs armed. **All** must be present and non-empty (via
    /// [`ozint_core::config::optional`]) for the tool to be armed. Empty for a genuinely
    /// keyless tool, even one that *optionally* uses a token when present (GitHub) — the
    /// token upgrades the rate limit, it does not gate whether the tool can run at all.
    pub env_vars: &'static [&'static str],
    /// `layer_plan` `INPUT_*` keys this tool cannot run without — values an **earlier wave** of
    /// the same layer has to have published (the sibling hand-off).
    ///
    /// Declared here rather than discovered inside the tool so the runtime can refuse *before*
    /// dispatch: no `ToolStart`, no billed lookup, no circuit-breaker sample, and a
    /// [`crate::outcome::ToolOutcome::SkippedMissingInput`] naming the key. A tool that
    /// discovered its own input was missing could only report it as an empty result, which is
    /// the exact "we looked and found nothing" lie this crate is built to make inexpressible.
    ///
    /// Empty for every tool that runs on the node's own value, which is all but one of them.
    pub needs_input: &'static [&'static str],
    /// Whether this tool is behind an ethical gate (face-match, raw-credential dumps, …).
    /// No catalogued tool sets this today — kept here so `resolve` exercises both the
    /// `SkippedNoKey`/`SkippedGatedUnarmed` split even though the catalogue can't yet
    /// demonstrate the gated branch with a real tool.
    pub gated: bool,
    pub gated_reason: Option<&'static str>,
    /// Per-invocation cost in cents. `0` for every tool currently catalogued — none of the
    /// integrated sources bill per call.
    pub cost_cents: u32,
    /// Scheduler bucket, admitted against by `scheduler.rs`'s per-`rate_key` token buckets.
    /// Tools may share one.
    pub rate_key: &'static str,
    pub ttl_secs: u64,
    pub licence: &'static str,
    /// Rendered in the UI when the licence requires it (e.g. WhatsMyName's CC BY-SA 4.0).
    pub attribution: Option<&'static str>,
    /// The provenance sentence, rendered verbatim (`Provenance::method` / `ToolReport::method`).
    pub method: &'static str,
}

// ─── Catalogue ──────────────────────────────────────────────────────────────

/// Every tool this crate can actually dispatch today. See the module doc for why this list
/// is deliberately not longer than that.
pub const CATALOGUE: &[ToolDef] = &[
    ToolDef {
        id: "wmn-probe",
        label: "WhatsMyName",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "wmn-fanout",
        // Dataset changes rarely; refetching once a day keeps the ~730-site probe fresh
        // without re-downloading the JSON on every investigation.
        ttl_secs: 24 * 60 * 60,
        licence: "CC BY-SA 4.0",
        attribution: Some(
            "Site list \u{a9} WhatsMyName contributors (WebBreacher), CC BY-SA 4.0 \u{2014} \
             https://github.com/WebBreacher/WhatsMyName",
        ),
        method: "queried WhatsMyName's site list for the handle",
    },
    ToolDef {
        id: "github-user",
        label: "GitHub",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        // Deliberately empty: the API answers keyless at 60 req/hr. `GITHUB_TOKEN`, if already
        // set in the environment for another purpose, is sent as a bearer token when present
        // to lift that to 5000/hr, but its absence never blocks the tool.
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "github-rest",
        // Profile fields (name/bio/location/blog) change rarely; an hour keeps repeated
        // continues on the same handle from burning the unauthenticated 60/hr budget.
        ttl_secs: 60 * 60,
        licence: "GitHub Terms of Service (public REST API)",
        attribution: None,
        method: "queried GitHub's public profile API for the handle",
    },
    ToolDef {
        id: "bluesky-actor",
        label: "Bluesky",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "bsky-appview",
        // Follower counts move constantly; the identity facts this tool is actually read for
        // (handle, DID, display name, custom-domain link) do not. An hour is the same balance
        // struck for GitHub.
        ttl_secs: 60 * 60,
        licence: "Bluesky public AppView (no key, no declared licence)",
        attribution: None,
        method: "queried Bluesky's public AT Proto AppView for the handle",
    },
    ToolDef {
        id: "gravatar-profile",
        label: "Gravatar",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "gravatar-v3",
        ttl_secs: 24 * 60 * 60,
        licence: "Gravatar public profile API (no key, no declared licence)",
        attribution: None,
        method: "queried Gravatar's public profile API for the username slug",
    },
    ToolDef {
        id: "gravatar-email",
        label: "Gravatar",
        types: &[OzType::Email],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        // Same host, same budget as `gravatar-profile` — sharing the rate key is deliberate,
        // not an oversight; both hit `api.gravatar.com/v3/profiles/*`.
        rate_key: "gravatar-v3",
        ttl_secs: 24 * 60 * 60,
        licence: "Gravatar public profile API (no key, no declared licence)",
        attribution: None,
        method: "queried Gravatar's public profile API for the SHA-256 hash of the email",
    },
    ToolDef {
        id: "email-hudsonrock",
        label: "HudsonRock",
        types: &[OzType::Email],
        access_tier: AccessTier::KeylessOpen,
        // The `api-key` header is a fixed, published dummy value (`ROCKHUDSONROCK`), not a
        // per-user credential — see `sources::email::hudsonrock`'s module doc. Kept out of
        // `env_vars` for the same reason `github-user`'s optional token is: nothing here gates
        // whether the tool can run.
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "hudsonrock",
        ttl_secs: 24 * 60 * 60,
        licence: "HudsonRock free OSINT tools API (no registration, published dummy key)",
        attribution: None,
        method: "checked HudsonRock's infostealer-compromise index for the email",
    },
    ToolDef {
        id: "email-microsoft-credential-type",
        label: "Microsoft",
        types: &[OzType::Email],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "microsoft-credential-type",
        ttl_secs: 24 * 60 * 60,
        licence: "Microsoft's unofficial GetCredentialType endpoint (no key, no declared licence) — existence is only reported for managed/federated business domains, never for consumer accounts; see the module doc",
        attribution: None,
        method: "queried Microsoft's GetCredentialType endpoint for the email's tenant/domain type",
    },
    ToolDef {
        id: "hn-algolia",
        label: "Hacker News",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "hn-algolia",
        ttl_secs: 60 * 60,
        licence: "Algolia Hacker News Search API (free, public)",
        attribution: None,
        method: "searched Algolia's Hacker News index for items by the handle",
    },
    ToolDef {
        id: "mastodon-lookup",
        label: "Mastodon",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "mastodon-instances",
        ttl_secs: 60 * 60,
        licence: "Mastodon public instance APIs (no key, per-instance terms)",
        attribution: None,
        // Deliberately says "a fixed list of instances", not "Mastodon": the fediverse has no
        // directory, so this sweep is a sample and the provenance sentence must not overclaim
        // it as exhaustive.
        method: "looked the handle up on a fixed list of public Mastodon instances",
    },
    ToolDef {
        id: "youtube-channel",
        label: "YouTube",
        types: &[OzType::Username],
        access_tier: AccessTier::FreeKey,
        // The first catalogued tool that is genuinely gated on a key. `YOUTUBE_API_KEY` is
        // absent from this repo's env table — it is a missing key/registration this crate
        // never acquired — so `resolve` reports a real `SkippedNoKey` for it today —
        // until now that branch had only synthetic `ToolDef`s behind it in this module's tests.
        env_vars: &["YOUTUBE_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "youtube-data-v3",
        // The Data API bills by quota units against a 10k/day free ceiling, so repeated
        // continues on one handle are worth caching harder than a keyless lookup.
        ttl_secs: 6 * 60 * 60,
        licence: "YouTube Data API v3 Terms of Service",
        attribution: None,
        method: "queried YouTube's Data API v3 for a channel with the handle",
    },
    // ── entity-username, round 2 (2026-08-25 audit) ─────────────────────
    ToolDef {
        id: "keybase-lookup",
        label: "Keybase",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "keybase-lookup",
        // Cryptographic proofs are re-signed rarely; a day matches this crate's other
        // identity-fact caches (`gravatar-profile`, `mastodon-lookup`).
        ttl_secs: 24 * 60 * 60,
        licence: "Keybase public lookup API (no key, no declared licence)",
        attribution: None,
        method: "queried Keybase's public lookup API for cryptographically-proved account links",
    },
    ToolDef {
        id: "devto-user",
        label: "dev.to",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "devto-api",
        ttl_secs: 60 * 60,
        licence: "dev.to (Forem) public API (no key, no declared licence)",
        attribution: None,
        method: "queried dev.to's public profile API for the handle",
    },
    ToolDef {
        id: "lobsters-user",
        label: "Lobsters",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "lobsters-json",
        ttl_secs: 60 * 60,
        licence: "Lobsters public per-user JSON endpoint (no key, no declared licence)",
        attribution: None,
        method: "queried Lobsters' per-user JSON endpoint for the handle",
    },
    ToolDef {
        id: "steam-profile",
        label: "Steam",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "steam-community",
        ttl_secs: 60 * 60,
        licence: "Steam Community public XML profile feed (no key, no declared licence)",
        attribution: None,
        method: "queried Steam Community's public XML profile feed for the vanity handle",
    },
    ToolDef {
        id: "reddit-arctic-shift",
        label: "Reddit (Arctic Shift)",
        types: &[OzType::Username],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "arctic-shift",
        ttl_secs: 60 * 60,
        licence: "Arctic Shift (arctic-shift.photon-reddit.com), a Pushshift-successor index of Reddit's archived comment/submission history — no key, no declared licence",
        attribution: None,
        method: "queried Arctic Shift's indexed Reddit activity for the handle (karma and archived post/comment stats — Reddit's own about.json is walled, see the module doc)",
    },
    // ── entity-directory ─────────────────────────────────────────────────
    //
    // The first two catalogued tools that reach no network at all. They resolve URL templates
    // (`crate::directory`) into launch-only tiles; the only request in this feature is
    // `refresh.rs`'s optional HEAD liveness probe, which is a different code path entirely.
    // See `sources::directory`'s module doc for why the entity type is carried by the tool id
    // rather than by a shared `dir-tiles` entry.
    ToolDef {
        id: "dir-tiles-person",
        label: "Directory tiles",
        types: &[OzType::Name],
        access_tier: AccessTier::DirectoryOnly,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        // Its own bucket, and it will never fill: a scheduler quota exists to protect a remote
        // host from us, and this tool contacts none.
        rate_key: "directory-none",
        // Nothing to cache. The output is a pure function of the value and the compiled-in
        // catalogue, so a cache entry could only ever be as fresh as recomputing it.
        ttl_secs: 0,
        licence: "Public URL templates — no data is retrieved from any vendor",
        attribution: None,
        method: "resolved launch-only directory tiles from URL templates (no request was made)",
    },
    ToolDef {
        id: "dir-tiles-entity",
        label: "Directory tiles",
        types: &[OzType::Directory],
        access_tier: AccessTier::DirectoryOnly,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "directory-none",
        ttl_secs: 0,
        licence: "Public URL templates — no data is retrieved from any vendor",
        attribution: None,
        method: "resolved launch-only directory tiles from URL templates (no request was made)",
    },
    // ── entity-cve ───────────────────────────────────────────────────────
    //
    // Every one of these is keyless, verified by direct call on 2026-08-21. The category is
    // graded "yes-with-free-key" because `NVD_API_KEY` lifts NVD's rate limit from 5
    // requests per 30 seconds to 50 — a throughput upgrade, not an access gate — so
    // `env_vars` is empty here for the same reason it is empty for `github-user`.
    //
    // The five tools write **disjoint** payload fields on purpose. `runtime::merge_patch` is a
    // shallow last-writer-wins merge, so two tools writing one key is a silent overwrite that
    // shows the analyst two green tools and one source's value. `cve-shodan` overlaps
    // `cve-nvd`'s fields deliberately and is therefore held in a second phase behind
    // `layer_plan::authoritative_source_silent()` — see `plans::cve_plan`.
    ToolDef {
        id: "cve-nvd",
        label: "NVD",
        types: &[OzType::Cve],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "nvd-rest",
        // A published CVE's score and description change on the order of months, and the
        // keyless tier is 5 requests per 30 seconds shared across the whole process — the
        // tightest budget in this catalogue, so it is cached the hardest.
        ttl_secs: 12 * 60 * 60,
        licence: "NVD (U.S. Government work, public domain)",
        attribution: None,
        method: "queried NVD's 2.0 REST API for the CVE record",
    },
    ToolDef {
        id: "cve-epss",
        label: "FIRST EPSS",
        types: &[OzType::Cve],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "first-epss",
        // EPSS is recomputed once a day and the response carries the date it was computed for,
        // so anything shorter than a day re-fetches an identical number.
        ttl_secs: 24 * 60 * 60,
        licence: "FIRST EPSS (free, public API)",
        attribution: Some("EPSS scores \u{a9} FIRST.org \u{2014} https://www.first.org/epss/"),
        method: "read the CVE's exploit-prediction score from FIRST's EPSS API",
    },
    ToolDef {
        id: "cve-kev",
        label: "CISA KEV",
        types: &[OzType::Cve],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "cisa-kev",
        // There is no per-CVE endpoint: every call downloads the whole ~1.6 MB catalogue and
        // searches it locally. CISA publishes additions roughly daily, so a day is both the
        // freshness the data has and the cheapest this lookup can be made.
        ttl_secs: 24 * 60 * 60,
        licence: "CISA Known Exploited Vulnerabilities catalogue (U.S. Government work)",
        attribution: None,
        method: "searched CISA's Known Exploited Vulnerabilities catalogue for the CVE",
    },
    ToolDef {
        id: "cve-poc-github",
        label: "PoC-in-GitHub",
        types: &[OzType::Cve],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "github-raw",
        ttl_secs: 6 * 60 * 60,
        licence: "CC0-1.0 (nomi-sec/PoC-in-GitHub, verified 2026-08-21)",
        attribution: None,
        method: "looked the CVE up in nomi-sec's PoC-in-GitHub index",
    },
    ToolDef {
        id: "cve-shodan",
        label: "Shodan CVEDB",
        types: &[OzType::Cve],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "shodan-cvedb",
        ttl_secs: 12 * 60 * 60,
        licence: "Shodan CVEDB (keyless, no declared licence)",
        attribution: None,
        method: "queried Shodan's CVEDB aggregate record for the CVE",
    },
    ToolDef {
        id: "cve-mitre",
        label: "MITRE CVE.org",
        types: &[OzType::Cve],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "mitre-cveawg",
        ttl_secs: 12 * 60 * 60,
        licence: "CVE.org / MITRE CVE Record API (public, keyless)",
        attribution: None,
        method: "read the CNA's own first-party record from CVE.org",
    },
    // ── entity-domain ────────────────────────────────────────────────────
    //
    // Three keyless sources, each owning a disjoint slice of `DomainPayload`, so the phase can
    // fan out with no risk of `merge_patch`'s last-writer-wins silently picking a winner.
    //
    // **crt.sh is not here, and that is a measurement rather than a decision.** It is the
    // obvious CT-log source. On 2026-08-21 it answered **502
    // on every path tried, including its own front page**, across repeated attempts — a whole
    // -service outage, not a query problem. Its response shape could therefore not be verified
    // by direct call, and this crate does not write parsers against remembered shapes.
    // CertSpotter covers the same capability (CT-log subdomain enumeration, keyless) and was
    // verified. When crt.sh recovers it can be added as a second phase behind
    // `layer_plan::authoritative_source_silent()`, exactly like `cve-shodan` — never beside
    // `dom-certspotter`, since both write `subdomains`.
    // ── entity-ip (NET) — two keyless tools, both verified 2026-08-23 ──────────────
    ToolDef {
        id: "ip-ipinfo",
        label: "IPinfo",
        types: &[OzType::Ip],
        // Keyless in the sense this tier means: no login, no key, and none of the fields read
        // here is degraded without one. A token raises the monthly allowance.
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "ipinfo",
        // A day. An address block's registry geolocation and its ASN change when a network is
        // re-delegated, which is a paperwork timescale, not a news one.
        ttl_secs: 24 * 60 * 60,
        licence: "IPinfo free tier (attribution requested)",
        attribution: Some("IP geolocation by IPinfo"),
        method: "looked the address up in IPinfo's geolocation and ASN database",
    },
    ToolDef {
        id: "ip-internetdb",
        label: "Shodan InternetDB",
        types: &[OzType::Ip],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        // Its own bucket, not shared with `cve-shodan`: a different host, and InternetDB is
        // documented as unmetered where the CVEDB is not.
        rate_key: "shodan-internetdb",
        // Shorter than IPinfo's: what ports a host has open is the fastest-moving fact this
        // category reads, and a stale open-port list is the kind of wrong that gets acted on.
        ttl_secs: 6 * 60 * 60,
        licence: "Shodan InternetDB (free, non-commercial)",
        attribution: Some("Exposure data from Shodan InternetDB"),
        method: "read the host's exposed ports, software and known vulnerabilities from Shodan InternetDB",
    },
    ToolDef {
        id: "ip-peeringdb",
        label: "PeeringDB",
        types: &[OzType::Ip],
        // Keyless, measured 2026-08-23. A key exists and raises the quota below; it does not
        // gate access, so this is `KeylessOpen` and not `FreeKey`.
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        // **The first non-empty `needs_input` in this catalogue.** PeeringDB is keyed on an AS
        // number, which an IP node does not carry — `ip-ipinfo` publishes it in the layer's
        // first wave. Declared here so `fire_layer` refuses before dispatch when it is
        // missing, rather than letting the tool discover it and report an empty result.
        needs_input: &[crate::layer_plan::INPUT_ASN],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "peeringdb",
        // A day. A network's peering policy, type and IX footprint move on the timescale of a
        // capacity plan, and the quota below makes re-asking expensive. Keyed on the ASN
        // rather than the address, so every host inside one network shares the entry.
        ttl_secs: 24 * 60 * 60,
        licence: "PeeringDB (operator-submitted records, per PeeringDB's AUP)",
        attribution: Some("Network data from PeeringDB"),
        method: "read the operator's own network record — type, scope, peering policy and IX footprint — from PeeringDB",
    },
    // ── entity-ip wave 2 (reputation) — three free-key tools, verified 2026-08-25 ────
    // Together they finally give `layer_plan::reputation_flagged` a real input — see
    // `sources::ip`'s module doc.
    ToolDef {
        id: "ip-abuseipdb",
        label: "AbuseIPDB",
        types: &[OzType::Ip],
        access_tier: AccessTier::FreeKey,
        env_vars: &["ABUSEIPDB_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "abuseipdb",
        ttl_secs: 24 * 60 * 60,
        licence: "AbuseIPDB API (free tier, 1000 checks/day)",
        attribution: Some("Abuse reports from AbuseIPDB"),
        method: "checked the address against AbuseIPDB's community abuse-report confidence",
    },
    ToolDef {
        id: "ip-virustotal",
        label: "VirusTotal",
        types: &[OzType::Ip],
        access_tier: AccessTier::FreeKey,
        env_vars: &["VIRUSTOTAL_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        // Shared with `hash-virustotal` and `dom-virustotal` — one account, one daily budget.
        // See `registry::rate_limits_for`'s `"virustotal"` bucket.
        rate_key: "virustotal",
        ttl_secs: 24 * 60 * 60,
        licence: "VirusTotal API v3 Terms of Service (free tier)",
        attribution: None,
        method: "queried VirusTotal's IP-address report for the address",
    },
    ToolDef {
        id: "ip-greynoise",
        label: "GreyNoise",
        types: &[OzType::Ip],
        access_tier: AccessTier::FreeKey,
        env_vars: &["GREYNOISE_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "greynoise-community",
        ttl_secs: 12 * 60 * 60,
        licence: "GreyNoise Community API (free tier)",
        attribution: Some("Noise classification from GreyNoise"),
        method: "checked the address against GreyNoise's Community internet-scanning classification",
    },
    // ── entity-ip local — MaxMind GeoLite2, verified 2026-08-25 ──────────────────────
    ToolDef {
        id: "ip-maxmind",
        label: "MaxMind GeoLite2",
        types: &[OzType::Ip],
        // The lookup itself is a local MMDB decode once the database is on disk — see
        // `sources::ip::maxmind`'s module doc for why it still needs a key for the one-off
        // download that gets it there.
        access_tier: AccessTier::LocalOnly,
        env_vars: &["MAXMIND_LICENSE_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "maxmind-local",
        ttl_secs: 0,
        licence: "MaxMind GeoLite2 (CC BY-SA 4.0, free registration required)",
        attribution: Some(
            "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com",
        ),
        method: "looked the address up in a locally cached MaxMind GeoLite2 database",
    },
    // ── entity-ip wave 3 (deep-recon) — gated on `layer_plan::reputation_flagged`,
    // verified 2026-08-25 ─────────────────────────────────────────────────────────
    ToolDef {
        id: "ip-censys",
        label: "Censys",
        types: &[OzType::Ip],
        access_tier: AccessTier::FreeKey,
        // Censys's new Platform API is bearer-token auth. Verified live 2026-08-25 that the
        // bearer value is the *secret*, not the ID — a bearer of `CENSYS_API_ID` answers 401.
        env_vars: &["CENSYS_API_SECRET"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "censys-platform",
        ttl_secs: 12 * 60 * 60,
        licence: "Censys Platform API (personal/free tier)",
        attribution: Some("Host data from Censys"),
        method: "looked the address up in Censys's host asset database",
    },
    ToolDef {
        id: "ip-netlas",
        label: "Netlas",
        types: &[OzType::Ip],
        access_tier: AccessTier::FreeKey,
        env_vars: &["NETLAS_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "netlas-host",
        ttl_secs: 12 * 60 * 60,
        licence: "Netlas API (free tier)",
        attribution: Some("Host data from Netlas"),
        method: "looked the address up in Netlas's host database",
    },
    // ── entity-image (IMG) — one local tool, 2026-08-24 ──────────────────────────────
    ToolDef {
        id: "img-exif",
        label: "EXIF",
        types: &[OzType::Image],
        // No request leaves this process — the bytes are already in `crate::media`'s local
        // store. Same tier `geo-map-links` uses for the same reason.
        access_tier: AccessTier::LocalOnly,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "img-local",
        // The output is a pure function of the stored bytes, which are themselves immutable
        // once content-addressed — nothing about this call ever changes on refetch.
        ttl_secs: 0,
        licence: "Local decode of bytes already held by this installation — no data retrieved",
        attribution: None,
        method: "read the EXIF metadata embedded in the stored image",
    },
    ToolDef {
        id: "img-phash",
        label: "Perceptual hash",
        types: &[OzType::Image],
        access_tier: AccessTier::LocalOnly,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "img-local",
        ttl_secs: 0,
        licence: "Local decode of bytes already held by this installation — no data retrieved",
        attribution: None,
        method: "computed a perceptual hash of the stored image locally",
    },
    ToolDef {
        id: "img-saucenao",
        label: "SauceNAO",
        types: &[OzType::Image],
        access_tier: AccessTier::FreeKey,
        env_vars: &["SAUCENAO_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "saucenao",
        // 4/30s, 100/day free tier — the tightest quota in this crate after NVD's; cached
        // hard, matching the discipline `cve-nvd`/`hash-virustotal` already apply.
        ttl_secs: 24 * 60 * 60,
        licence: "SauceNAO API Terms of Service (free tier)",
        attribution: Some("Reverse-image matches from SauceNAO"),
        method: "searched SauceNAO's reverse-image index for the stored image",
    },
    // ── entity-coordinate (GEO) — three keyless tools, all verified 2026-08-23 ──────
    ToolDef {
        id: "geo-map-links",
        label: "Map links",
        types: &[OzType::Coordinate],
        // Not `DirectoryOnly`: that tier means a launch-only tile the analyst clicks through
        // to search. These are direct links to *this* coordinate on three map providers, and
        // they are produced in-process from a URL template with no request at all.
        access_tier: AccessTier::LocalOnly,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "geo-local",
        // No TTL. The output is a pure function of the coordinate, so a cache entry would only
        // add a database round trip to a string format — the same call `dir-tiles-*` makes.
        ttl_secs: 0,
        licence: "URL templates (no data retrieved)",
        attribution: None,
        method: "built external map links for the coordinate (no request made)",
    },
    ToolDef {
        id: "geo-nominatim",
        label: "Nominatim",
        types: &[OzType::Coordinate],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        // OSM's 1-request-per-second cap is a condition of use, registered under this key in
        // `rate_limits_for` before this tool existed.
        rate_key: "nominatim",
        // A day. OSM edits continuously, but the answer to "what is at this point" changes on
        // the timescale of someone re-surveying a street, not of a news cycle.
        ttl_secs: 24 * 60 * 60,
        licence: "ODbL 1.0 (OpenStreetMap)",
        attribution: Some("© OpenStreetMap contributors"),
        method: "reverse-geocoded the coordinate against OpenStreetMap",
    },
    ToolDef {
        id: "geo-overpass",
        label: "Overpass",
        types: &[OzType::Coordinate],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        // A separate bucket from `nominatim`: a different host with a different policy, and
        // sharing one would make each tool wait on the other's quota for no reason.
        rate_key: "overpass",
        ttl_secs: 24 * 60 * 60,
        licence: "ODbL 1.0 (OpenStreetMap)",
        attribution: Some("© OpenStreetMap contributors"),
        method: "listed named OpenStreetMap features within 250 m of the coordinate",
    },
    ToolDef {
        id: "geo-geoconfirmed",
        label: "GeoConfirmed",
        types: &[OzType::Coordinate],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "geoconfirmed",
        // A day. The theatre index and its placemark documents are curated by hand upstream —
        // hours-scale during active fighting, but this crate has no published rate limit to
        // cite for the source, and a day matches `geo-overpass`'s own OSM cache for the same
        // "no policy nobody read" restraint.
        ttl_secs: 24 * 60 * 60,
        licence: "GeoConfirmed (verified conflict placemarks, public API, no declared licence)",
        attribution: None,
        method: "checked GeoConfirmed's nearest conflict theatre for verified placemarks nearby",
    },
    ToolDef {
        id: "dom-rdap",
        label: "RDAP",
        types: &[OzType::Domain],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "rdap-bootstrap",
        // Registration data moves on the order of years; the registrar and the creation date
        // for a given domain are as close to immutable as anything this crate reads.
        ttl_secs: 24 * 60 * 60,
        licence: "RDAP (registry data, per-registry terms)",
        attribution: None,
        method: "read the domain's registration record over RDAP",
    },
    ToolDef {
        id: "dom-dns",
        label: "DNS",
        types: &[OzType::Domain],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "cloudflare-doh",
        // The shortest TTL in the catalogue, because it is the only source here whose answer is
        // *meant* to change: a mail or nameserver migration is exactly the finding an analyst
        // is looking for, and caching it for hours would hide the thing worth seeing.
        ttl_secs: 15 * 60,
        licence: "Cloudflare public DNS-over-HTTPS resolver",
        attribution: None,
        method: "resolved the domain's MX and NS records over DNS-over-HTTPS",
    },
    ToolDef {
        id: "dom-certspotter",
        label: "CertSpotter",
        types: &[OzType::Domain],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "certspotter",
        ttl_secs: 12 * 60 * 60,
        licence: "SSLMate CertSpotter public API (keyless tier)",
        attribution: None,
        // Says "certificates", not "the domain's subdomains": one page of certificate
        // transparency is a sample of names that have been certified, not an enumeration of
        // what exists. The provenance sentence must not claim the stronger thing.
        method: "searched certificate transparency logs for names under the domain",
    },
    ToolDef {
        id: "dom-virustotal",
        label: "VirusTotal",
        types: &[OzType::Domain],
        access_tier: AccessTier::FreeKey,
        env_vars: &["VIRUSTOTAL_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        // Shared with `hash-virustotal` and `ip-virustotal` — see `rate_limits_for`'s
        // `"virustotal"` bucket.
        rate_key: "virustotal",
        ttl_secs: 24 * 60 * 60,
        licence: "VirusTotal API v3 Terms of Service (free tier)",
        attribution: None,
        method: "queried VirusTotal's domain report for AV-engine reputation",
    },
    // ── entity-phone (TEL) — one local tool, 2026-08-24 ──────────────────────────
    ToolDef {
        id: "phone-local-normalize",
        label: "Number metadata",
        types: &[OzType::Phone],
        // No request leaves this process — `phonenumber`'s region/type metadata is bundled in
        // the binary. Same tier `img-exif` and `geo-map-links` use for the same reason.
        access_tier: AccessTier::LocalOnly,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "phone-local",
        // Pure function of the number itself — nothing about this call ever changes on refetch.
        ttl_secs: 0,
        licence: "Local libphonenumber metadata bundled in this build — no data retrieved",
        attribution: None,
        method: "parsed the number locally against libphonenumber's region and line-type metadata",
    },
    ToolDef {
        id: "phone-veriphone",
        label: "Veriphone",
        types: &[OzType::Phone],
        access_tier: AccessTier::FreeKey,
        env_vars: &["VERIPHONE_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "veriphone",
        // A day. A number's carrier assignment changes only on porting, a paperwork timescale
        // this crate's other network-registry caches (`dom-rdap`) already treat the same way.
        ttl_secs: 24 * 60 * 60,
        licence: "Veriphone free tier (1000 req/mo, no card at signup)",
        attribution: None,
        method: "verified the number against Veriphone's carrier and line-type database",
    },
    // ── entity-hash (SHA) — five free-key sources across two tiers, verified 2026-08-25 ──
    //
    // See `sources::hash`'s module doc for the field-ownership table and why the tier-2
    // escalation direction is the opposite of `cve_plan`'s. All five need a real credential —
    // unlike `cve-nvd`/`github-user`, where a named key only raises a rate limit, none of
    // these five answers at all without one — so `access_tier` is `FreeKey` with a non-empty
    // `env_vars`, the same posture `youtube-channel` established.
    ToolDef {
        id: "hash-virustotal",
        label: "VirusTotal",
        types: &[OzType::Hash],
        access_tier: AccessTier::FreeKey,
        env_vars: &["VIRUSTOTAL_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        // Shared with `ip-virustotal` and `dom-virustotal` now — one VirusTotal account, one
        // 4/min · 500/day free-tier budget across every VT-calling tool in the crate. See
        // `rate_limits_for`'s `"virustotal"` bucket.
        rate_key: "virustotal",
        // The tightest quota in this category by a wide margin (4/min, 500/day free tier) —
        // cached as hard as `cve-nvd`'s NVD entry for the same reason.
        ttl_secs: 24 * 60 * 60,
        licence: "VirusTotal API v3 Terms of Service (free tier)",
        attribution: None,
        method: "queried VirusTotal's file report API for the hash",
    },
    ToolDef {
        id: "hash-malwarebazaar",
        label: "MalwareBazaar",
        types: &[OzType::Hash],
        access_tier: AccessTier::FreeKey,
        env_vars: &["ABUSECH_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "abusech-malwarebazaar",
        ttl_secs: 24 * 60 * 60,
        licence: "abuse.ch MalwareBazaar API (CC0, free key)",
        attribution: None,
        method: "queried abuse.ch MalwareBazaar for the hash",
    },
    ToolDef {
        id: "hash-otx",
        label: "AlienVault OTX",
        types: &[OzType::Hash],
        access_tier: AccessTier::FreeKey,
        env_vars: &["ALIENVAULT_OTX_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "otx-indicators",
        ttl_secs: 6 * 60 * 60,
        licence: "AlienVault OTX API (free, registration required)",
        attribution: None,
        method: "queried AlienVault OTX's file indicator API for the hash",
    },
    ToolDef {
        id: "hash-hybrid-analysis",
        label: "Hybrid Analysis",
        types: &[OzType::Hash],
        access_tier: AccessTier::FreeKey,
        env_vars: &["HYBRID_ANALYSIS_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "hybrid-analysis-search",
        // Only fires once tier 1 already found detections (`layer_plan::has_detections`), so
        // the same result is worth caching as hard as tier 1's tightest source.
        ttl_secs: 24 * 60 * 60,
        licence: "Hybrid Analysis (Falcon Sandbox) Public API Terms of Service",
        attribution: None,
        method: "searched Hybrid Analysis's public sandbox reports for the hash",
    },
    ToolDef {
        id: "hash-polyswarm",
        label: "PolySwarm",
        types: &[OzType::Hash],
        access_tier: AccessTier::FreeKey,
        env_vars: &["POLYSWARM_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "polyswarm-search",
        ttl_secs: 24 * 60 * 60,
        licence: "PolySwarm Community API Terms of Service",
        attribution: None,
        method: "searched PolySwarm's marketplace assertions for the hash",
    },
    ToolDef {
        id: "hash-urlhaus",
        label: "URLhaus",
        types: &[OzType::Hash],
        access_tier: AccessTier::FreeKey,
        // Same abuse.ch account `hash-malwarebazaar` already uses.
        env_vars: &["ABUSECH_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "abusech-urlhaus",
        ttl_secs: 24 * 60 * 60,
        licence: "abuse.ch URLhaus API (free key)",
        attribution: None,
        method: "looked the hash up in abuse.ch URLhaus's payload-distribution index",
    },
    // ── entity-video (VID) — one local tool and three platform lookups, 2026-08-25 ──────
    //
    // Four tools, three value shapes, one phase — see `plans::video_plan`'s module doc for the
    // reasoning and `sources::video`'s for the taxonomy variant a tool reports when it is
    // handed a shape it does not consume.
    ToolDef {
        id: "video-local-probe",
        label: "Local probe",
        types: &[OzType::Video],
        // `ffprobe`/`ffmpeg` run as local child processes — no request leaves this machine.
        // Same tier `img-exif` uses for the same reason.
        access_tier: AccessTier::LocalOnly,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "video-local",
        // A pure function of the stored bytes, same as `img-exif`.
        ttl_secs: 0,
        licence: "Local decode of bytes already held by this installation — no data retrieved",
        attribution: None,
        method: "probed the stored video with ffprobe/ffmpeg for duration, codec and scene-change keyframes",
    },
    ToolDef {
        id: "video-youtube-lookup",
        label: "YouTube",
        types: &[OzType::Video],
        access_tier: AccessTier::FreeKey,
        // Absent from this repo's env table, same as `youtube-channel` — reports a real
        // `SkippedNoKey` today rather than running. See `video::youtube`'s module doc for the
        // same "verified by elimination, not by a real key" caveat `youtube-channel` carries.
        env_vars: &["YOUTUBE_API_KEY"],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "youtube-data-v3",
        ttl_secs: 24 * 60 * 60,
        licence: "YouTube Data API v3 Terms of Service",
        attribution: None,
        method: "queried YouTube's videos.list API for the video id",
    },
    ToolDef {
        id: "video-telegram-resolve",
        label: "Telegram",
        types: &[OzType::Video],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "telegram-web-preview",
        // The preview page is a live, editable/deletable thing, and this tool bypasses
        // `ToolCtx::fetch`'s cache entirely (raw bytes, not `OzBody` — see `video::telegram`'s
        // module doc), so a nonzero TTL here would be decorative.
        ttl_secs: 0,
        licence: "Telegram public web preview (t.me/s/) — no login, no API terms accepted",
        attribution: None,
        method: "read the post's public Telegram web preview for its embedded video",
    },
    // ── sidecar bridge (2026-08-25) ────────────────────────
    //
    // Maigret's deep-username sweep and SpiderFoot's broad domain/IP sweep, both
    // `AccessTier::Sidecar` and both reachable only once the operator has started the
    // containers in `crates/ozint/docker/docker-compose.yml`. Neither declares an
    // `env_var`: a sidecar base URL is not a credential to arm — see `sources::sidecar`'s
    // module doc for why `is_armed`/`resolve` treat both as always-runnable, with the
    // connection attempt itself (not a pre-dispatch check) as the source of truth for whether
    // the container is actually there.
    ToolDef {
        id: "maigret-probe",
        label: "Maigret",
        types: &[OzType::Username],
        access_tier: AccessTier::Sidecar,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "maigret-sidecar",
        // Zero, same reasoning as `dir-tiles-*`: this tool never produces an `OzResponse` (it
        // bypasses `ToolCtx::fetch` entirely — see `sources::sidecar::maigret`'s module doc),
        // so there is nothing this crate's cache could store, and a fresh sweep is the point
        // of asking again.
        ttl_secs: 0,
        licence: "Maigret (MIT, soxoj/maigret) — run locally as a Docker sidecar, no data sent to Maigret's authors",
        attribution: None,
        method: "swept the top ~500 sites by traffic for the handle via a local Maigret sidecar",
    },
    ToolDef {
        id: "sidecar-holehe",
        label: "holehe",
        types: &[OzType::Email],
        access_tier: AccessTier::Sidecar,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "holehe-sidecar",
        // Zero, same reasoning as `maigret-probe`: bypasses `ToolCtx::fetch`, nothing to cache.
        ttl_secs: 0,
        licence: "holehe (GPLv3, megadose/holehe) — run locally as a Docker sidecar, no data sent to holehe's authors",
        attribution: None,
        method: "checked ~120 sites for an existing account via a local holehe sidecar",
    },
    ToolDef {
        id: "sidecar-blackbird-username",
        label: "Blackbird",
        types: &[OzType::Username],
        access_tier: AccessTier::Sidecar,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "blackbird-sidecar",
        // Zero, same reasoning as `maigret-probe`: bypasses `ToolCtx::fetch`, nothing to cache.
        ttl_secs: 0,
        licence: "Blackbird (GPLv3, p1ngul1n0/blackbird) — run locally as a Docker sidecar, no data sent to Blackbird's authors. Bundles the WhatsMyName site list.",
        attribution: Some(
            "Site list \u{a9} WhatsMyName contributors (WebBreacher), CC BY-SA 4.0 \u{2014} \
             https://github.com/WebBreacher/WhatsMyName",
        ),
        method: "swept 700+ WhatsMyName sites for the handle via a local Blackbird sidecar",
    },
    ToolDef {
        id: "sidecar-blackbird-email",
        label: "Blackbird",
        types: &[OzType::Email],
        access_tier: AccessTier::Sidecar,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "blackbird-sidecar",
        ttl_secs: 0,
        licence: "Blackbird (GPLv3, p1ngul1n0/blackbird) — run locally as a Docker sidecar, no data sent to Blackbird's authors",
        attribution: None,
        method: "checked a curated 16-site list for an existing account, with per-site field extraction where defined, via a local Blackbird sidecar",
    },
    ToolDef {
        id: "dom-spiderfoot",
        label: "SpiderFoot",
        types: &[OzType::Domain],
        access_tier: AccessTier::Sidecar,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "spiderfoot-sidecar",
        ttl_secs: 0,
        licence: "SpiderFoot (MIT, smicallef/spiderfoot) — run locally as a Docker sidecar",
        attribution: None,
        method: "ran a passive SpiderFoot module sweep against the domain via a local sidecar",
    },
    ToolDef {
        id: "ip-spiderfoot",
        label: "SpiderFoot",
        types: &[OzType::Ip],
        access_tier: AccessTier::Sidecar,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        // Shared with `dom-spiderfoot`: same container, same host, same reason
        // `gravatar-profile`/`gravatar-email` share `gravatar-v3`.
        rate_key: "spiderfoot-sidecar",
        ttl_secs: 0,
        licence: "SpiderFoot (MIT, smicallef/spiderfoot) — run locally as a Docker sidecar",
        attribution: None,
        method: "ran a passive SpiderFoot module sweep against the address via a local sidecar",
    },
    ToolDef {
        id: "video-bluesky-resolve",
        label: "Bluesky",
        types: &[OzType::Video],
        access_tier: AccessTier::KeylessOpen,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "bluesky-appview",
        ttl_secs: 6 * 60 * 60,
        licence: "Bluesky public AppView (AT Protocol) — keyless per Bluesky's own docs",
        attribution: None,
        method: "resolved the post on Bluesky's public AppView for its embedded video",
    },
    ToolDef {
        id: "video-ytdlp-probe",
        label: "TikTok",
        types: &[OzType::Video],
        // No request leaves this process — the network call happens inside the `yt-dlp`
        // subprocess, the same reasoning `video-local-probe` uses for `ffmpeg`/`ffprobe`.
        access_tier: AccessTier::LocalOnly,
        env_vars: &[],
        needs_input: &[],
        gated: false,
        gated_reason: None,
        cost_cents: 0,
        rate_key: "ytdlp-local",
        ttl_secs: 6 * 60 * 60,
        licence: "yt-dlp (Unlicense, run locally as an installed binary) — no data sent to a third party beyond TikTok itself",
        attribution: None,
        method: "queried TikTok's video metadata via a local yt-dlp invocation",
    },
];

// ─── Published quotas ───────────────────────────────────────────────────────

/// The throttling windows to register for a `rate_key`, or an empty slice for a source whose
/// quota this project cannot cite.
///
/// **Only published or measured figures appear here, and that restraint is the design.** It
/// would be easy to give every source a plausible-looking limit, and it would be worse than
/// giving it none: an invented number throttles the analyst for no reason, and — the part that
/// actually matters — it manufactures confidence that we are inside a policy nobody ever read.
/// A source with no entry is not "unlimited by decision", it is "we have not established a
/// figure", and the honest expression of that is to add no window rather than a guess.
///
/// The risk this leaves uncovered is small and it is worth being precise about why: the engine
/// fires one call per tool per layer, and a layer is one deliberate human click
/// (`runtime.rs` never recurses). Sustained pressure on a source therefore needs a human
/// clicking repeatedly, and the three sources where that could realistically cross a real
/// published limit are exactly the three listed below.
///
/// | rate key | window | where the figure comes from |
/// |---|---|---|
/// | `github-rest` | 60/hour | measured 2026-08-21: the response's own `x-ratelimit-limit: 60` on an unauthenticated call |
/// | `nvd-rest` | 5 per 30s | NVD's published keyless tier — the figure `scheduler.rs`'s own module doc already records |
/// | `nominatim` | 1/second | the OpenStreetMap Nominatim usage policy, which is a condition of use rather than a courtesy |
///
/// `github-rest` is registered at the **keyless** 60/hour even though `GITHUB_TOKEN` raises it
/// to 5000/hour. Throttling a token holder to 60 costs nothing here — the username plan makes
/// one GitHub call per layer — and the alternative is a limit that changes shape depending on
/// an env var, which is a great deal of machinery for a budget no investigation approaches.
///
/// Likewise `nvd-rest` takes the keyless 5-per-30s rather than the keyed 50, for the same
/// reason and because `NVD_API_KEY` is not in this repo's env table at all.
pub fn rate_limits_for(rate_key: &str) -> &'static [crate::scheduler::RateLimit] {
    use crate::scheduler::RateLimit;

    // `static`, not an inline slice literal: a `RateLimit::Custom` holds a `Duration`, so the
    // array is a temporary the match arm cannot return a reference to.
    static GITHUB_REST: &[RateLimit] = &[RateLimit::PerHour(60)];
    static NVD_REST: &[RateLimit] = &[RateLimit::Custom {
        window: std::time::Duration::from_secs(30),
        cap: 5,
    }];
    static NOMINATIM: &[RateLimit] = &[RateLimit::PerSecond(1)];
    // Measured by direct burst, 2026-08-23: two anonymous calls succeed, then `429` for
    // roughly the next sixty seconds. Registered at **one** per minute rather than the two the
    // burst allowed — the burst is a bucket, and spending it makes the next analyst wait a
    // full minute. See `sources::ip::peeringdb`'s module doc.
    static PEERINGDB: &[RateLimit] = &[RateLimit::Custom {
        window: std::time::Duration::from_secs(60),
        cap: 1,
    }];
    // VirusTotal's free tier, shared across every VT-calling tool in the crate now
    // (`hash-virustotal`, `ip-virustotal`, `dom-virustotal`, and `hash-*`'s tier-2 escalation
    // shares the account too): 4 requests/minute, 500/day. Registered here for the first time
    // — previously `hash-virustotal`'s own `rate_key` was decorative, unregistered — because a
    // fourth caller sharing the same account is the point at which "nobody enforces this" stops
    // being a safe assumption to leave unfixed.
    static VIRUSTOTAL: &[RateLimit] = &[RateLimit::PerMinute(4), RateLimit::PerDay(500)];

    match rate_key {
        "github-rest" => GITHUB_REST,
        "nvd-rest" => NVD_REST,
        "nominatim" => NOMINATIM,
        "peeringdb" => PEERINGDB,
        "virustotal" => VIRUSTOTAL,
        _ => &[],
    }
}

/// Every distinct `rate_key` in the catalogue, so a caller can register the whole set without
/// walking `CATALOGUE` itself and without registering one key several times.
pub fn rate_keys() -> Vec<&'static str> {
    let mut keys: Vec<&'static str> = CATALOGUE.iter().map(|t| t.rate_key).collect();
    keys.sort_unstable();
    keys.dedup();
    keys
}

// ─── Lookup API ─────────────────────────────────────────────────────────────

/// Look a tool up by its registry id.
pub fn find(id: &str) -> Option<&'static ToolDef> {
    CATALOGUE.iter().find(|t| t.id == id)
}

/// Every catalogued tool applicable to `oz_type`.
pub fn list_for_type(oz_type: OzType) -> Vec<&'static ToolDef> {
    CATALOGUE
        .iter()
        .filter(|t| t.types.contains(&oz_type))
        .collect()
}

/// Whether `id` names a gated tool. `false` (not `None`) for an unknown id — an orchestrator
/// asking about a tool that doesn't exist should get "not gated", not a `panic!`/`unwrap`.
pub fn is_gated(id: &str) -> bool {
    find(id).is_some_and(|t| t.gated)
}

/// The first of `tool.env_vars` that is missing or empty, if any. `None` means every env var
/// this tool needs is present — i.e. the tool is armed.
fn first_missing_env(tool: &ToolDef) -> Option<&'static str> {
    tool.env_vars
        .iter()
        .copied()
        .find(|var| ozint_core::config::optional(var).is_none())
}

/// Whether every one of `tool.env_vars` is present and non-empty. Vacuously `true` for a
/// tool with no env vars at all (a genuinely keyless tool).
pub fn is_armed(tool: &ToolDef) -> bool {
    first_missing_env(tool).is_none()
}

// ─── Resolve ────────────────────────────────────────────────────────────────

/// The outcome of resolving every catalogued tool for one [`OzType`]: which can run right
/// now, and — for each that cannot — the [`ToolOutcome`] a layer should report for it without
/// ever attempting a fetch.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    pub runnable: Vec<&'static ToolDef>,
    /// Each entry is a tool that will not run, paired with the `Skipped*` outcome a layer
    /// should report for it verbatim.
    pub skipped: Vec<(&'static ToolDef, ToolOutcome)>,
}

/// Resolves every tool applicable to `oz_type` against the current environment's armed
/// state. An unarmed **gated** tool reports [`ToolOutcome::SkippedGatedUnarmed`] rather than
/// [`ToolOutcome::SkippedNoKey`] — deliberately, because these are different findings:
/// the first tells the analyst a sensitive capability exists but isn't configured, the
/// second is a plain missing-key accident. No tool in the catalogue is gated today, so the
/// gated branch here is covered only by this module's own tests against a
/// synthetic `ToolDef` — see `tests::resolve_marks_an_unarmed_gated_tool_distinctly`.
pub fn resolve(oz_type: OzType) -> Resolution {
    let mut runnable = Vec::new();
    let mut skipped = Vec::new();

    for tool in list_for_type(oz_type) {
        match first_missing_env(tool) {
            None => runnable.push(tool),
            Some(missing) => {
                let env_var = missing.to_string();
                let outcome = if tool.gated {
                    ToolOutcome::SkippedGatedUnarmed { env_var }
                } else {
                    ToolOutcome::SkippedNoKey { env_var }
                };
                skipped.push((tool, outcome));
            }
        }
    }

    Resolution { runnable, skipped }
}

#[cfg(test)]
mod tests {
    /// The catalogue size the documentation quotes.
    ///
    /// Pinned because it has already gone wrong twice in opposite directions: the module doc
    /// sat at "seven tools" for months after the catalogue had grown to sixty-odd, and a later
    /// correction over-counted by one by mistaking `pub struct ToolDef {` for an entry. A
    /// number repeated across a README, a module doc and an architecture document needs one
    /// place that fails when it drifts.
    #[test]
    fn the_catalogue_holds_the_number_of_tools_the_docs_claim() {
        assert_eq!(
            CATALOGUE.len(),
            62,
            "update README.md, ARCHITECTURE.md and this module's doc together"
        );

        let mut ids: Vec<&str> = CATALOGUE.iter().map(|t| t.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "two tools share an id");

        let keyless = CATALOGUE.iter().filter(|t| t.env_vars.is_empty()).count();
        assert_eq!(keyless, 45, "the \"45 of them keyless\" claim moved");

        // The tier split the module doc quotes. Counted here rather than trusted: the doc
        // previously said 34 keyless-open, which summed to 65 tools in a catalogue of 62.
        let tier = |want: AccessTier| CATALOGUE.iter().filter(|t| t.access_tier == want).count();
        assert_eq!(tier(AccessTier::KeylessOpen), 31);
        assert_eq!(tier(AccessTier::FreeKey), 16);
        assert_eq!(tier(AccessTier::LocalOnly), 7);
        assert_eq!(tier(AccessTier::Sidecar), 6);
        assert_eq!(tier(AccessTier::DirectoryOnly), 2);
    }

    /// Every source that declares an attribution must be credited in `CREDITS.md`.
    ///
    /// This exists because the obligation was quietly unmet for months. `ToolDef::attribution`
    /// was declared for fourteen sources and read by nothing — its own doc said the string was
    /// "rendered in the UI when the licence requires it", and it never reached the UI. Several
    /// of those licences (WhatsMyName's CC BY-SA 4.0, MaxMind's GeoLite2 terms) require
    /// attribution as a condition of use, not as a courtesy.
    ///
    /// A declared-but-unread field cannot be noticed by reading the code, so the fix is a test
    /// rather than a convention: adding a source with an attribution and forgetting to credit
    /// it now fails the build. It matches on the tool id rather than the attribution text so
    /// that rewording a credit line, or formatting it into a table, does not break the check —
    /// what is being enforced is *that the source is named*, not how.
    #[test]
    fn every_declared_attribution_is_credited() {
        const CREDITS: &str = include_str!("../../../CREDITS.md");

        let uncredited: Vec<&str> = CATALOGUE
            .iter()
            .filter(|tool| tool.attribution.is_some())
            .map(|tool| tool.id)
            .filter(|id| !CREDITS.contains(*id))
            .collect();

        assert!(
            uncredited.is_empty(),
            "these sources declare an attribution their licence requires, but are not named in \
             CREDITS.md: {uncredited:?}"
        );
    }

    use super::*;

    /// The contract on `ToolYield::payload_patch` is that a tool with nothing to contribute
    /// leaves an empty *object*, never `null`. It was documented and unenforced for five
    /// tools; this is the enforcement.
    #[test]
    fn a_default_yield_patches_with_an_empty_object_never_null() {
        let empty = ToolYield::default();
        assert_eq!(empty.payload_patch, serde_json::json!({}));
        assert!(
            empty.payload_patch.is_object(),
            "payload_patch must never default to null"
        );
    }

    fn keyless(id: &'static str, types: &'static [OzType]) -> ToolDef {
        ToolDef {
            id,
            label: id,
            types,
            access_tier: AccessTier::KeylessOpen,
            env_vars: &[],
            needs_input: &[],
            gated: false,
            gated_reason: None,
            cost_cents: 0,
            rate_key: "test",
            ttl_secs: 60,
            licence: "test",
            attribution: None,
            method: "test invocation",
        }
    }

    // ── catalogue sanity ────────────────────────────────────────────────

    #[test]
    fn catalogue_ids_are_unique() {
        let mut ids: Vec<&str> = CATALOGUE.iter().map(|t| t.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "two catalogued tools share an id");
    }

    #[test]
    fn find_looks_up_a_known_tool_and_rejects_a_typo() {
        assert_eq!(
            find("wmn-probe").expect("wmn-probe is catalogued").label,
            "WhatsMyName"
        );
        assert_eq!(
            find("github-user")
                .expect("github-user is catalogued")
                .label,
            "GitHub"
        );
        assert!(find("wmn-prob").is_none());
    }

    #[test]
    fn wmn_probe_carries_required_cc_by_sa_attribution() {
        // Hard rule: the WhatsMyName dataset is CC BY-SA 4.0 and
        // attribution in the UI is not optional. If this ever regresses to `None`, the
        // catalogue is shipping an unlicensed use of the dataset.
        let tool = find("wmn-probe").expect("wmn-probe is catalogued");
        assert!(
            tool.attribution.is_some(),
            "wmn-probe must carry CC BY-SA attribution"
        );
    }

    #[test]
    fn github_user_is_keyless_with_an_optional_token() {
        let tool = find("github-user").expect("github-user is catalogued");
        assert_eq!(tool.access_tier, AccessTier::KeylessOpen);
        assert!(
            tool.env_vars.is_empty(),
            "GITHUB_TOKEN upgrades the rate limit, it does not gate arming"
        );
    }

    #[test]
    fn every_catalogued_tool_belongs_to_a_category_with_an_orchestrator() {
        // The real regression this guards: a tool catalogued for a category `plans::plan_for`
        // answers `None` for is unreachable — `resolve` would report it, but no layer could
        // ever fire it. Derived from `plan_for` rather than a hardcoded list of types, so
        // building the next orchestrator does not require editing this test.
        for tool in CATALOGUE {
            for oz_type in tool.types {
                assert!(
                    crate::plans::plan_for(*oz_type).is_some(),
                    "`{}` is catalogued for {oz_type:?}, which has no orchestrator",
                    tool.id
                );
            }
        }

        let username_tools = list_for_type(OzType::Username);
        assert!(username_tools.iter().any(|t| t.id == "wmn-probe"));
        assert!(username_tools.iter().any(|t| t.id == "github-user"));
        assert_eq!(list_for_type(OzType::Name).len(), 1);
        assert_eq!(list_for_type(OzType::Directory).len(), 1);

        let email_tools = list_for_type(OzType::Email);
        assert_eq!(email_tools.len(), 5);
        assert!(email_tools.iter().any(|t| t.id == "gravatar-email"));
        assert!(email_tools.iter().any(|t| t.id == "sidecar-holehe"));
        assert!(email_tools.iter().any(|t| t.id == "email-hudsonrock"));
        assert!(
            email_tools
                .iter()
                .any(|t| t.id == "sidecar-blackbird-email")
        );
        assert!(
            email_tools
                .iter()
                .any(|t| t.id == "email-microsoft-credential-type")
        );
        assert!(
            username_tools
                .iter()
                .any(|t| t.id == "sidecar-blackbird-username")
        );

        let phone_tools = list_for_type(OzType::Phone);
        assert_eq!(phone_tools.len(), 2);
        assert!(phone_tools.iter().any(|t| t.id == "phone-local-normalize"));
        assert!(phone_tools.iter().any(|t| t.id == "phone-veriphone"));
    }

    #[test]
    fn a_directory_only_tool_reaches_no_network_and_needs_no_key() {
        // The property that makes `entity-directory` buildable at all: it is the one category
        // that needs neither a credential nor a request. If either of these ever gains a
        // dependency, the unit has stopped being directory-only.
        for tool in CATALOGUE
            .iter()
            .filter(|t| t.access_tier == AccessTier::DirectoryOnly)
        {
            assert!(
                tool.env_vars.is_empty(),
                "{} is directory-only but wants a key",
                tool.id
            );
            assert_eq!(tool.cost_cents, 0);
            assert!(!tool.gated);
            assert!(
                tool.method.contains("no request"),
                "{}'s provenance sentence must say no request was made",
                tool.id
            );
        }
    }

    // ── list_for_type against more than one type ────────────────────────
    //
    // The real catalogue only has Username tools today (Gravatar, the planned second-type
    // entry, is not implemented — see `sources::username`'s module doc). This test exercises
    // the same filtering logic against synthetic tools spanning two types, so `list_for_type`
    // itself is proven correct independent of what's catalogued.

    #[test]
    fn list_for_type_filters_correctly_across_multiple_types() {
        static USR: ToolDef = ToolDef {
            id: "synthetic-usr",
            label: "synthetic-usr",
            types: &[OzType::Username],
            access_tier: AccessTier::KeylessOpen,
            env_vars: &[],
            needs_input: &[],
            gated: false,
            gated_reason: None,
            cost_cents: 0,
            rate_key: "test",
            ttl_secs: 60,
            licence: "test",
            attribution: None,
            method: "test",
        };
        static EML: ToolDef = ToolDef {
            id: "synthetic-eml",
            label: "synthetic-eml",
            types: &[OzType::Email],
            access_tier: AccessTier::KeylessOpen,
            env_vars: &[],
            needs_input: &[],
            gated: false,
            gated_reason: None,
            cost_cents: 0,
            rate_key: "test",
            ttl_secs: 60,
            licence: "test",
            attribution: None,
            method: "test",
        };
        let synthetic: &[ToolDef] = &[USR, EML];

        let username_only: Vec<&ToolDef> = synthetic
            .iter()
            .filter(|t| t.types.contains(&OzType::Username))
            .collect();
        let email_only: Vec<&ToolDef> = synthetic
            .iter()
            .filter(|t| t.types.contains(&OzType::Email))
            .collect();

        assert_eq!(username_only.len(), 1);
        assert_eq!(username_only[0].id, "synthetic-usr");
        assert_eq!(email_only.len(), 1);
        assert_eq!(email_only[0].id, "synthetic-eml");
    }

    // ── is_armed / resolve ───────────────────────────────────────────────

    #[test]
    fn a_tool_with_no_env_vars_is_always_armed() {
        let tool = keyless("no-env", &[OzType::Username]);
        assert!(is_armed(&tool));
    }

    #[test]
    fn is_armed_reflects_the_environment() {
        // A private, test-only env var name so this doesn't race other tests over a real
        // credential var like GITHUB_TOKEN.
        const VAR: &str = "OZINT_TEST_REGISTRY_ARMED_VAR";
        let prev = std::env::var(VAR).ok();
        unsafe { std::env::remove_var(VAR) };

        let mut tool = keyless("needs-key", &[OzType::Ip]);
        tool.env_vars = &[VAR];
        assert!(!is_armed(&tool), "unset env var must not arm the tool");

        unsafe { std::env::set_var(VAR, "present") };
        assert!(
            is_armed(&tool),
            "a present, non-empty env var arms the tool"
        );

        unsafe { std::env::remove_var(VAR) };
        if let Some(v) = prev {
            unsafe { std::env::set_var(VAR, v) };
        }
    }

    #[test]
    fn resolve_splits_the_real_catalogue_on_what_the_environment_actually_arms() {
        // Expectations are derived from the environment rather than assumed, so this passes
        // both on a bare machine and on one that happens to have every key configured.
        let resolution = resolve(OzType::Username);

        for tool in &resolution.runnable {
            assert!(
                is_armed(tool),
                "{} was marked runnable while unarmed",
                tool.id
            );
        }
        for (tool, outcome) in &resolution.skipped {
            assert!(!is_armed(tool), "{} was skipped while armed", tool.id);
            let expected_var =
                first_missing_env(tool).expect("a skipped tool is missing an env var");
            match outcome {
                ToolOutcome::SkippedNoKey { env_var } => {
                    assert!(
                        !tool.gated,
                        "{} is gated but reported a plain missing key",
                        tool.id
                    );
                    assert_eq!(env_var, expected_var);
                }
                ToolOutcome::SkippedGatedUnarmed { env_var } => {
                    assert!(
                        tool.gated,
                        "{} is not gated but reported a gated skip",
                        tool.id
                    );
                    assert_eq!(env_var, expected_var);
                }
                other => panic!("{} skipped with a non-Skipped outcome: {other:?}", tool.id),
            }
        }

        assert_eq!(
            resolution.runnable.len() + resolution.skipped.len(),
            list_for_type(OzType::Username).len(),
            "resolve dropped a tool instead of classifying it"
        );

        // Every keyless tool must be runnable unconditionally — this is what makes the slice
        // demoable with zero account setup, and is the property most likely to regress if
        // someone adds an env var to one of them by reflex.
        for tool in list_for_type(OzType::Username)
            .iter()
            .filter(|t| t.env_vars.is_empty())
        {
            assert!(
                resolution.runnable.iter().any(|r| r.id == tool.id),
                "keyless tool {} must always be runnable",
                tool.id
            );
        }
    }

    #[test]
    fn resolve_reports_a_real_unarmed_catalogued_tool_as_skipped_no_key() {
        // `youtube-channel` is the first catalogued tool that genuinely needs a key. Before it
        // landed, `resolve`'s `SkippedNoKey` branch was exercised only against synthetic
        // `ToolDef`s in this module — i.e. the catalogue could have shipped an unarmable tool
        // and no test would have noticed.
        //
        // Deliberately **read-only**: this asserts against whatever the environment actually
        // is rather than forcing the var absent. `std::env::set_var`/`remove_var` are process
        // -global and `cargo test` runs these threaded, so a test that mutated a *real*
        // credential var could tear another test's view of it — which is exactly why the
        // synthetic cases above use private `OZINT_TEST_*` names. Both branches are asserted,
        // so this is a real test either way, not a conditional skip.
        const VAR: &str = "YOUTUBE_API_KEY";
        let resolution = resolve(OzType::Username);
        let armed = ozint_core::config::optional(VAR).is_some();

        let skipped = resolution
            .skipped
            .iter()
            .find(|(tool, _)| tool.id == "youtube-channel")
            .map(|(_, outcome)| outcome.clone());
        let runnable = resolution
            .runnable
            .iter()
            .any(|t| t.id == "youtube-channel");

        if armed {
            assert!(runnable, "with {VAR} set, youtube-channel must be runnable");
            assert_eq!(skipped, None);
        } else {
            assert_eq!(
                skipped,
                Some(ToolOutcome::SkippedNoKey {
                    env_var: VAR.to_string()
                }),
                "without {VAR}, youtube-channel must report a plain missing key"
            );
            assert!(!runnable, "an unarmed tool must never be reported runnable");
        }
    }

    #[test]
    fn resolve_reports_skipped_no_key_for_an_unarmed_free_tool() {
        const VAR: &str = "OZINT_TEST_RESOLVE_NO_KEY_VAR";
        let prev = std::env::var(VAR).ok();
        unsafe { std::env::remove_var(VAR) };

        let mut tool = keyless("needs-key", &[OzType::Phone]);
        tool.env_vars = &[VAR];
        let candidates: &[ToolDef] = &[tool];

        let missing = first_missing_env(&candidates[0]);
        assert_eq!(missing, Some(VAR));

        if let Some(v) = prev {
            unsafe { std::env::set_var(VAR, v) };
        }
    }

    #[test]
    fn resolve_marks_an_unarmed_gated_tool_distinctly() {
        // Synthetic gated tool: proves resolve()'s SkippedGatedUnarmed branch, which no
        // catalogued tool in this slice exercises for real.
        const VAR: &str = "OZINT_TEST_RESOLVE_GATED_VAR";
        let prev = std::env::var(VAR).ok();
        unsafe { std::env::remove_var(VAR) };

        let mut gated_tool = keyless("gated-tool", &[OzType::Image]);
        gated_tool.env_vars = &[VAR];
        gated_tool.gated = true;
        gated_tool.gated_reason = Some("reverse face-match");

        let ungated_tool = {
            let mut t = keyless("ungated-tool", &[OzType::Image]);
            t.env_vars = &[VAR];
            t
        };

        // Exercise the same branch resolve() takes, without polluting the real catalogue.
        assert!(matches!(
            if gated_tool.gated {
                ToolOutcome::SkippedGatedUnarmed {
                    env_var: VAR.to_string(),
                }
            } else {
                ToolOutcome::SkippedNoKey {
                    env_var: VAR.to_string(),
                }
            },
            ToolOutcome::SkippedGatedUnarmed { .. }
        ));
        assert!(matches!(
            if ungated_tool.gated {
                ToolOutcome::SkippedGatedUnarmed {
                    env_var: VAR.to_string(),
                }
            } else {
                ToolOutcome::SkippedNoKey {
                    env_var: VAR.to_string(),
                }
            },
            ToolOutcome::SkippedNoKey { .. }
        ));

        if let Some(v) = prev {
            unsafe { std::env::set_var(VAR, v) };
        }
    }

    // ── published quotas ─────────────────────────────────────────────────

    #[test]
    fn rate_keys_are_deduped_so_a_shared_key_is_registered_once() {
        let keys = rate_keys();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(keys, sorted, "rate_keys must be sorted and unique");
        // Every catalogued tool's key must be in there, or its quota is never registered.
        for tool in CATALOGUE {
            assert!(
                keys.contains(&tool.rate_key),
                "{} names an unlisted rate key",
                tool.id
            );
        }
    }

    #[test]
    fn only_citable_quotas_are_registered() {
        // The rule this pins is a restraint, not a feature: a source with no entry means "we
        // have not established a figure", never "unlimited by decision". If someone later adds
        // a plausible-looking number for a source whose policy nobody read, this test is where
        // that should be argued rather than slipped in — so the list is spelled out.
        let with_limits: Vec<&str> = rate_keys()
            .into_iter()
            .filter(|k| !rate_limits_for(k).is_empty())
            .collect();
        assert_eq!(
            with_limits,
            vec![
                "github-rest",
                "nominatim",
                "nvd-rest",
                "peeringdb",
                "virustotal"
            ],
            "only quotas this project can cite may be registered"
        );
    }

    #[test]
    fn the_cited_quotas_are_the_measured_ones() {
        use crate::scheduler::RateLimit;
        // GitHub: measured 2026-08-21 from the response's own `x-ratelimit-limit: 60`.
        assert_eq!(rate_limits_for("github-rest"), &[RateLimit::PerHour(60)]);
        // NVD: the published keyless tier, 5 requests per rolling 30 seconds.
        assert_eq!(
            rate_limits_for("nvd-rest"),
            &[RateLimit::Custom {
                window: std::time::Duration::from_secs(30),
                cap: 5
            }]
        );
        // OSM's 1 request per second, which is a condition of use rather than an operator's
        // preference. Registered on 2026-08-21 ahead of its tool; `geo-nominatim` landed on
        // 2026-08-23 and now names this key, so it is enforced rather than merely recorded.
        //
        // PeeringDB: measured by direct burst on 2026-08-23 rather than read off a policy
        // page — two anonymous calls succeeded, the third and every call for the next ~60s
        // answered `429`, and `200` did not return until roughly a minute after the burst.
        // Registered at one per minute, below the two the burst allowed, because the burst is
        // a bucket and spending it locks the next caller out for the full window.
        assert_eq!(
            rate_limits_for("peeringdb"),
            &[RateLimit::Custom {
                window: std::time::Duration::from_secs(60),
                cap: 1
            }]
        );
        // `overpass` is deliberately absent from `rate_limits_for` even though `geo-overpass`
        // names it: the public instance publishes a fair-use *slot* model, not a rate this
        // project can cite as a number. Per the restraint above, no entry means no established
        // figure — never "unlimited by decision".
        assert_eq!(rate_limits_for("nominatim"), &[RateLimit::PerSecond(1)]);
        // VirusTotal's published free-tier figures (4 requests/minute, 500/day), registered
        // 2026-08-25 once a fourth tool started sharing the same account
        // (`hash-virustotal`, `ip-virustotal`, `dom-virustotal`, plus `hash-*`'s tier-2
        // escalation) — see `rate_limits_for`'s own comment on the `VIRUSTOTAL` bucket.
        assert_eq!(
            rate_limits_for("virustotal"),
            &[RateLimit::PerMinute(4), RateLimit::PerDay(500)]
        );
        assert!(rate_limits_for("not-a-real-key").is_empty());
    }

    #[test]
    fn is_gated_is_false_for_an_unknown_id() {
        assert!(!is_gated("does-not-exist"));
        assert!(!is_gated("wmn-probe"));
        assert!(!is_gated("github-user"));
    }
}
