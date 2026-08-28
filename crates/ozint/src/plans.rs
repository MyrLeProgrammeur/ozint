//! The per-entity-type orchestrator catalogue — which tools fire, in what order, for a node
//! of a given [`OzType`].
//!
//! This is the seam between `layer_plan.rs` (the phase/predicate *primitive*) and
//! `runtime.rs` (the engine that executes one). `fire_layer` takes a [`LayerPlan`] and asks
//! no questions about where it came from; [`plan_for`] is where a node's type becomes a
//! concrete plan. The split mirrors `registry.rs` (data) versus `sources/` (behaviour):
//! `layer_plan.rs` stays pure control flow with no knowledge of any specific tool id, and
//! this module holds the per-type composition.
//!
//! ## Why `Option`, and not an empty plan
//!
//! [`plan_for`] returns `None` for a type with no orchestrator built yet. That is not
//! defensive style — it is forced by the engine's own contract. `fire_layer` settles an
//! empty plan as **`Failed`**, deliberately: a layer that ran nothing learned nothing and
//! must never render as the "0 NEW ENTITIES" block, which claims we looked and there was
//! genuinely nothing there (`runtime.rs`'s `an_empty_plan_settles_failed_not_empty` calls
//! this the single most important assertion in the crate).
//!
//! But "we have not built this orchestrator" and "we tried and every tool lost" are
//! different facts, and `Failed` is the wrong one for the first. Handing back an empty plan
//! would launder a missing feature into an apparent failure. `None` lets the caller say the
//! true thing instead, and keeps `Failed` meaning what the engine needs it to mean.

use crate::layer_plan::{LayerPhase, LayerPlan};
use crate::types::OzType;

/// The plan for one entity type, or `None` when that type has no orchestrator yet.
///
/// Every [`OzType`] this crate defines answers today — twelve types. Nine of them share one
/// thing worth naming: **none needs a credential**. [`OzType::Username`] was picked as the
/// first vertical slice because its whole tool chain is keyless or already-keyed.
/// [`OzType::Name`]/[`OzType::Directory`] make no request at all. [`OzType::Cve`],
/// [`OzType::Domain`] and [`OzType::Coordinate`] were all expected to need a free key, and all
/// three turned out to be fully keyless once each source was actually called — for CVE and DOM
/// the named key raises a rate limit rather than opening a door, and for GEO the three named
/// keys buy *additional* sources rather than access to the ones that answer the question.
/// [`OzType::Email`] was expected to need a paid key for its full chain, but its first tool
/// (`gravatar-email`) needed no key at all — the same email-hash lookup
/// `username_plan`'s `gravatar-profile` already proved keyless, aimed at the other Gravatar
/// endpoint. [`OzType::Phone`] is the same story: the first step is a keyless local
/// `libphonenumber` normalise pass, and that is exactly what `phone_plan`'s one tool does — the
/// keyed steps behind it (Veriphone, IPQualityScore, Telnyx, DeHashed) stay unbuilt.
///
/// [`OzType::Hash`] breaks that pattern, deliberately: it is the first type in this module
/// whose tools genuinely need a real credential to answer at all (see `sources::hash`'s module
/// doc) rather than a key that only raises a rate limit. Its five sources — VirusTotal,
/// MalwareBazaar, AlienVault OTX, Hybrid Analysis, PolySwarm — are all free-key, all held in
/// this repo's env table, and all verified by direct call on 2026-08-25, which is what earns
/// it a plan despite the credential.
///
/// [`OzType::Video`] breaks a different pattern: it is the first type where one `OzType` does
/// not mean one value shape — see `video_plan`'s own doc. Every arm below is written out
/// explicitly (no catch-all `_ => Some(..)`), so a future `OzType` variant fails to compile
/// here rather than silently inheriting a plan it was never given, per this module's own "why
/// `Option`, not an empty plan" reasoning.
pub fn plan_for(oz_type: OzType) -> Option<LayerPlan> {
    match oz_type {
        OzType::Username => Some(username_plan()),
        OzType::Name => Some(directory_plan("dir-tiles-person")),
        OzType::Directory => Some(directory_plan("dir-tiles-entity")),
        OzType::Cve => Some(cve_plan()),
        OzType::Domain => Some(domain_plan()),
        OzType::Coordinate => Some(coordinate_plan()),
        OzType::Ip => Some(ip_plan()),
        OzType::Image => Some(image_plan()),
        OzType::Email => Some(email_plan()),
        OzType::Phone => Some(phone_plan()),
        OzType::Hash => Some(hash_plan()),
        OzType::Video => Some(video_plan()),
    }
}

/// `entity-username (USR)` — one unconditional breadth phase across every catalogued
/// username tool.
///
/// **Why a single phase.** A phase exists to hold something back until an earlier phase
/// justifies the spend — a paid API, a strict rate limit, an ethically gated source. None of
/// that applies here: every tool but one is keyless and free, and `youtube-channel` is free
/// within its quota. Splitting them would buy nothing and would delay the fast single-request
/// lookups behind WhatsMyName's ~730-site sweep, which is the slowest by a wide margin. They
/// fan out together and the analyst watches them land.
///
/// **Four more keyless tools, landed by the 2026-08-25 category audit.** `keybase-lookup`,
/// `devto-user`, `lobsters-user` and `steam-profile` join the breadth phase for the same
/// reason the original seven do — cheap, free, single-request. `keybase-lookup` is the one
/// genuinely new *kind* of signal in this plan: every other tool answers "does this handle
/// exist on platform X", but Keybase's `proofs_summary` is a cryptographically-signed record
/// of the *same person's* accounts on other platforms, so it is the plan's first
/// cross-platform corroboration source rather than another single-platform hit.
///
/// **`reddit-arctic-shift`, landed 2026-08-26.** Reddit's own `about.json` was verified dead
/// (`403`/login-redirect on all three domains tried) while extending the tool catalogue's rich-
/// field coverage; Arctic Shift (`sources::username::reddit`'s module doc) is the keyless
/// fallback that survived — activity stats, not identity fields. Joins the breadth phase like
/// the other seven keyless additions.
///
/// **Phase `deep-sweep`, landed 2026-08-25.** The deep-username tier — Maigret, Naminter,
/// Sherlock, Aliens Eye, Snoop — was sidecar-only and waited here as a documented gap; only
/// Maigret is built (see `sources::sidecar::maigret`'s
/// module doc for why the other four stay out of scope). It runs behind
/// [`crate::layer_plan::enough_confirmed_hits`], exactly the predicate this doc comment
/// named before any tool existed to use it: an expensive deep sweep only fires once
/// WhatsMyName's own confirmed-hit count says the handle looks real. Nothing else in this
/// plan changed — the prediction that "nothing else needs to change" held.
///
/// **`sidecar-blackbird-username`, landed 2026-08-26.** Joins the same `deep-sweep` phase as
/// Maigret, gated on the same predicate — it is a second, wider (700+ site) existence sweep,
/// not a different kind of tool, so it earns the same "only after the handle looks real" gate.
/// See `sources::sidecar::blackbird`'s module doc.
///
/// `youtube-channel` is named even though `YOUTUBE_API_KEY` is absent from the env table.
/// That is intentional: the plan names capabilities, `registry::resolve` decides what is
/// armed, and the runtime reports the unarmed one as `SkippedNoKey`. Dropping it from the
/// plan would hide a real capability instead of showing it as unconfigured.
pub fn username_plan() -> LayerPlan {
    LayerPlan::new(vec![
        LayerPhase::new(
            "breadth",
            [
                "wmn-probe",
                "github-user",
                "bluesky-actor",
                "gravatar-profile",
                "hn-algolia",
                "mastodon-lookup",
                "youtube-channel",
                "keybase-lookup",
                "devto-user",
                "lobsters-user",
                "steam-profile",
                "reddit-arctic-shift",
            ],
        ),
        LayerPhase::new(
            "deep-sweep",
            ["maigret-probe", "sidecar-blackbird-username"],
        )
        .gated_on(crate::layer_plan::enough_confirmed_hits()),
    ])
}

/// `entity-directory (DIR/NAM)` — one unconditional phase holding one tool.
///
/// **Why one tool and not a phase per tile family.** Not a simplification: the engine's
/// shallow last-writer-wins `merge_patch` means two tools writing `DirectoryPayload`'s single
/// `tiles` key would silently clobber each other, showing the analyst two green tools and one
/// family's links. `sources::directory`'s module doc spells the trap out. One tool resolves the
/// whole set.
///
/// **Why no phases.** A phase exists to hold expensive work back until cheap work justifies it.
/// This plan spends nothing — no request, no key, no quota — so there is nothing to hold back
/// and no predicate that could honestly gate it.
///
/// **What a `DIR`/`NAM` layer settles as.** `Empty`, always: the tiles patch the firing node's
/// own payload and no child node is ever created, which is precisely
/// `outcome::settle_kind`'s "ran, produced results, zero new entities" case. That is the
/// truthful verdict — a directory layer is a dead end by design — and
/// `summary::classify_case` catches [`OzType::is_directory_only`] ahead of the settle kind so
/// the analyst reads "no automated lookup exists for this type", not "we searched and found
/// nothing".
pub fn directory_plan(tool_id: &'static str) -> LayerPlan {
    LayerPlan::new(vec![LayerPhase::new("tiles", [tool_id])])
}

/// `entity-cve (CVE)` — a breadth phase of four field-disjoint sources, and one aggregator
/// held behind them as a fallback.
///
/// **Phase `breadth`.** NVD, FIRST EPSS, CISA KEV and PoC-in-GitHub. All keyless, all cheap,
/// and — the property that matters — each one owns a **different** part of
/// [`crate::types::CvePayload`]: NVD writes the score, its revision, the severity, the
/// publication instant and the description; EPSS writes only `epss`; KEV writes only `kev`;
/// PoC-in-GitHub writes only `pocUrls`. Nothing here can overwrite anything else here, so
/// they fan out together.
///
/// **Phase `aggregate-fallback`.** Shodan CVEDB returns, in one keyless call, its own copy of
/// the score, the EPSS probability, the KEV flag and the description. That makes it a genuine
/// one-stop — and exactly the wrong thing to run alongside the four above, because
/// `runtime::merge_patch` is a shallow last-writer-wins merge: whichever of NVD and Shodan
/// finished second would silently win the `cvss` key, and the analyst would see two green
/// tools with no indication that a second-hand copy had displaced the source of record. (The
/// two genuinely disagree: for `CVE-2021-34527`, Shodan's flat `cvss` is `8.8` while NVD's
/// only `Primary` metric is a CVSS **v2** `9.0`.)
///
/// So it is held behind [`crate::layer_plan::authoritative_source_silent`], which opens only
/// when NVD did not come back with a record — a timeout, a rate-limit, or a CVE NVD does not
/// carry. In that case Shodan writes fields nobody else wrote, and there is no collision to
/// resolve. `cve-epss` and `cve-kev` still own `epss`/`kev` regardless, which is why
/// `sources::cve::shodan` deliberately drops those two fields from its yield even though the
/// response contains them.
///
/// **The escalation rule is not a phase.** The rule "EPSS>0.7 AND KEV" is the rule for painting the chip
/// `Critical`, and it already lives in `signal.rs` (`cve_epss_071_with_kev_is_critical`). It
/// gates no tool: there is no more expensive tier of CVE lookup to escalate *to*, since every
/// source in the category is free and keyless. Adding a phase for it would report "skipped:
/// predicate false" for zero tools.
///
/// **Two sources considered and not fired here**, both measured rather than assumed:
/// - **OSV.dev.** `GET /v1/vulns/CVE-2021-34527` answers **404 `Vulnerability not found`**,
///   while `CVE-2021-44228` answers 200. OSV indexes open-source *package* ecosystems, so it
///   simply has no record for the large majority of CVEs — its natural direction is
///   package→CVE dispatch, the *reverse* of what this node has, a package name it does not
///   hold. Its unique content (GHSA aliases, affected version ranges) has no field in
///   `CvePayload`. Left unwired rather than added as a tool that reports empty on most inputs.
/// - **MITRE ATT&CK STIX bundle.** No official CVE↔technique mapping exists, so using it would
///   mean best-effort correlation. A correlation nobody publishes is an assertion this crate
///   would be inventing, and it would be rendered next to sourced facts. Not built.
pub fn cve_plan() -> LayerPlan {
    LayerPlan::new(vec![
        LayerPhase::new(
            "breadth",
            ["cve-nvd", "cve-epss", "cve-kev", "cve-poc-github"],
        ),
        LayerPhase::new("aggregate-fallback", ["cve-shodan"])
            .gated_on(crate::layer_plan::authoritative_source_silent()),
        // The last-resort fallback, one gate further back than `aggregate-fallback` — see
        // `layer_plan::no_authoritative_or_aggregate_answer`'s doc for why it needs its own,
        // stricter predicate rather than sharing `authoritative_source_silent` with
        // `cve-shodan`: sharing it would let both fire in the same run and collide on
        // `cvss`/`severity`/`summary`.
        LayerPhase::new("mitre-fallback", ["cve-mitre"])
            .gated_on(crate::layer_plan::no_authoritative_or_aggregate_answer()),
    ])
}

/// `entity-domain (DOM)` — one unconditional phase of three field-disjoint keyless sources.
///
/// RDAP writes `registrar` and `createdAt`; DNS writes `mx` and `ns`; CertSpotter writes
/// `subdomains` and `subdomainsTruncated`. Nothing overlaps, so — unlike `cve_plan` — there is
/// no aggregator to hold back and no predicate that would earn its place.
///
/// **Why RDAP does not write `ns`, although it carries nameservers.** The registry's delegation
/// record and the zone's live answer are different facts, and they diverge exactly when it
/// matters (a domain mid-migration serves new nameservers before the registry reflects them).
/// An analyst asking where a domain resolves wants the live answer, so `dom-dns` owns `ns` and
/// `dom-rdap` drops it. Letting both write it would not surface the disagreement — a shallow
/// last-writer-wins merge would just pick whichever finished second.
///
/// **The only source with children.** A domain layer's pivots are its subdomains, capped by
/// `types::MAX_SUBDOMAIN_CHILDREN`. MX and NS hosts are deliberately *not* children: they
/// belong to third-party providers, and seeding `aspmx.l.google.com` would grow the analyst's
/// tree with Google's infrastructure instead of the subject's.
///
/// **What is not built, and why**, so the gap is not mistaken for an oversight:
/// - **crt.sh** — the natural CT source for this category. Measured 2026-08-21: **502 on every
///   path, including its own front page**, across repeated attempts. Its shape could not be
///   verified, and this crate does not write parsers against remembered shapes. CertSpotter
///   covers the same capability and was verified. See `registry::CATALOGUE`'s note for how
///   crt.sh should be added back when it recovers.
/// - **Hunter.io** (`emailPattern`) — needs a free key this repo does not hold.
/// - **Wayback CDX** — `DomainPayload` has no field a first-archived date would go in, and
///   archival is a different, not-yet-built unit's subject, not this one's.
/// - **MXToolbox, ThreatMiner, VirusTotal, abuse.ch, GitHub code search, Grep.app** — a
///   keyed-or-reputational second tier; **SecurityTrails, Netlas, ViewDNS** — a paid tier
///   above that.
///
/// **Phase `sidecar-sweep`, landed 2026-08-25.** `dom-spiderfoot`
/// runs a broad passive module sweep behind the three RDAP/DNS/CertSpotter tools above, always
/// — not behind a predicate. Every gated phase elsewhere in this crate holds back on either a
/// field collision (`cve_plan`'s aggregator) or a cost-justifying signal (`hash_plan`'s tier 2,
/// `ip_plan`'s new sidecar wave gated on `reputation_flagged`). Neither applies here: this
/// tool's findings are heterogeneous SpiderFoot event rows, not a `DomainPayload` field any
/// other tool here writes, so there is no collision to avoid; and unlike an IP's abuse score, no
/// signal in `breadth`'s three sources predicts whether a broad sweep of a *domain* will be
/// productive — a clean RDAP record and a dirty one are equally likely to sit in front of a
/// domain worth sweeping. An unconditional final phase is the honest shape: it costs one more
/// (slow, local) lookup on every domain rather than a lookup nothing here can justify skipping.
pub fn domain_plan() -> LayerPlan {
    LayerPlan::new(vec![
        LayerPhase::new("breadth", ["dom-rdap", "dom-dns", "dom-certspotter"]),
        LayerPhase::new("sidecar-sweep", ["dom-spiderfoot"]),
        // Unconditional, own phase: `dom-virustotal` is keyed and rate-limited (unlike
        // `breadth`'s three keyless sources), but nothing in this plan predicts whether it is
        // worth spending — a clean RDAP record and a flagged one are equally worth a VT
        // opinion, the same reasoning `sidecar-sweep`'s own doc gives for staying unconditional.
        LayerPhase::new("reputation", ["dom-virustotal"]),
    ])
}

/// `entity-coordinate (GEO)` — a fast unconditional breadth phase, then GeoConfirmed's own
/// bounded-but-still-bulky phase.
///
/// **Field-disjoint, so the breadth phase fans out together.** `geo-map-links` writes
/// `mapLinks`, `geo-nominatim` writes `place` and `country`, and `geo-overpass` writes no
/// payload key at all — its whole output is rows. Nothing here can overwrite anything else
/// here, which is the property `runtime::merge_patch`'s shallow last-writer-wins merge makes
/// load-bearing.
///
/// **Why the three breadth tools share one phase.** A phase holds expensive work back until
/// cheap work justifies it. All three are keyless, free and single-request; `geo-overpass` is
/// the slowest at roughly two seconds, not a spend worth gating. There is also no honest
/// predicate available: "did the reverse geocoder find a place" does not bear on whether it is
/// worth asking what is nearby — a coordinate with *nothing* named at it is exactly the one
/// where the surroundings matter most.
///
/// **`geo-geoconfirmed`, its own unconditional phase, landed by the 2026-08-25 category
/// audit.** Not merged into `breadth`: it can still mean downloading several MB (the theatre
/// index bounds *which* theatre, not the size of that theatre's own placemark document — see
/// `sources::coordinate::geoconfirmed`'s module doc), a different cost class from the three
/// fast lookups above, the same reasoning `image_plan` uses to keep `img-saucenao` out of its
/// own local `breadth` phase. Unconditional rather than gated for the same reason `breadth`'s
/// three tools are: nothing local predicts whether a coordinate is conflict-adjacent, and a
/// coordinate that *looks* unremarkable is exactly the one a verified nearby placemark would
/// be worth surfacing on. Sentinel Hub / Earth Engine before-after imagery is still deferred,
/// a deliberately unbuilt gap rather than an oversight.
pub fn coordinate_plan() -> LayerPlan {
    LayerPlan::new(vec![
        LayerPhase::new(
            "breadth",
            ["geo-map-links", "geo-nominatim", "geo-overpass"],
        ),
        LayerPhase::new("geoconfirmed", ["geo-geoconfirmed"]),
    ])
}

/// `entity-image (IMG)` — a local `breadth` phase, then a keyed reverse-image phase.
///
/// `img-exif` and `img-phash` make no request and cost nothing, so they fan out together with
/// no predicate to hold either back. `img-saucenao` is exactly the tool this module's doc
/// comment anticipated before it existed: "a paid/keyed network call, a different class of
/// cost entirely from a local decode" — it earns its own, unconditional second phase rather
/// than joining `breadth`. See `sources::image`'s module doc for why that phase is
/// unconditional rather than gated: nothing local predicts whether a reverse-image search will
/// be productive.
pub fn image_plan() -> LayerPlan {
    LayerPlan::new(vec![
        LayerPhase::new("breadth", ["img-exif", "img-phash"]),
        LayerPhase::new("reverse-image", ["img-saucenao"]),
    ])
}

/// `entity-ip (NET)` — a breadth phase, then the one tool that runs on what it found.
///
/// **Field-disjoint.** `ip-ipinfo` writes the location and network block (`country`, `city`,
/// `lat`, `lon`, `asn`, `isp`); `ip-internetdb` writes `ports` and `anonymizer`; `ip-peeringdb`
/// writes no payload key at all. Nothing here can overwrite anything else here.
///
/// **Three design waves, and how they map onto these two phases.** Wave 1 is geo/ASN,
/// wave 2 reputation, wave 3 ports *only if wave 2 flags*. Of wave 1, IPinfo is keyless and
/// built, and **PeeringDB now runs too**: it was blocked not on a key but on the engine, since
/// its lookup is keyed on an ASN that a *sibling* learns and `dispatch` used to hand every tool
/// the node's own value and nothing else. The sibling hand-off
/// ([`crate::layer_plan::Handoff`]) is what unblocks it, and `asn-derived` below is that
/// mechanism's only structural requirement: a hand-off crosses *waves*, so the consumer cannot
/// share a phase with its producer. MaxMind still needs a registration-gated licence key. Of
/// wave 2, only Shodan InternetDB is keyless, and it reports exposure rather than reputation.
/// Every wave-3 source is keyed.
///
/// **`asn-derived` carries no predicate, deliberately.** Gating it on "did anyone publish an
/// ASN" would report a held-back *phase*, when what actually happened is that one tool lacked
/// one input — and `ToolOutcome::SkippedMissingInput` says exactly that, naming the key. A
/// predicate here would replace a precise sentence with a vaguer one, and would additionally be
/// a second place where the same condition is expressed.
///
/// **The phase that is deliberately absent, and this is the one that has a named predicate.**
/// [`crate::layer_plan::reputation_flagged`] is the "one exact, shared rule" wave 3 needs,
/// and it is not wired here. Adding the phase with nothing behind it would inflate the
/// `max_possible` denominator the cockpit shows and report "skipped: reputation-flagged" for
/// zero tools — telling the analyst a cascade was held back when there is nothing behind it,
/// the same reason `username_plan` leaves `enough_confirmed_hits()` unwired. Its *input* is
/// live: `ip-internetdb` sets [`crate::layer_plan::FLAG_ANONYMIZER`] from Shodan's own tags, so
/// the predicate would genuinely fire on a Tor exit.
///
/// **Phase `sidecar-sweep`, landed 2026-08-25 — the wave-3 phase
/// above finally has a tool.** `ip-spiderfoot` runs behind
/// [`crate::layer_plan::reputation_flagged`], the exact predicate this doc comment named
/// before anything existed to gate — a broad passive OSINT sweep is precisely the kind of
/// spend that predicate exists to hold back until reputation already gave a concrete reason
/// to look closer. It does not compete with the keyed Shodan/Censys/Netlas tier envisioned
/// for wave 3 (still unbuilt, still keyed) — when one of those lands it earns its
/// own phase behind the same predicate, not a merge into this one, for the same field-
/// disjointness reasoning `cve_plan`'s aggregator phase spells out.
pub fn ip_plan() -> LayerPlan {
    LayerPlan::new(vec![
        LayerPhase::new("breadth", ["ip-ipinfo", "ip-internetdb", "ip-maxmind"]),
        LayerPhase::new("asn-derived", ["ip-peeringdb"]),
        // Wave 2 — the phase that finally gives `reputation_flagged` a real input. Every tool
        // here posts to `PhaseAcc` (`FACT_ABUSE_SCORE`, `FLAG_ANONYMIZER`, `FLAG_MALICIOUS`),
        // so it must run — and settle — before either gated phase below.
        LayerPhase::new(
            "reputation",
            ["ip-abuseipdb", "ip-virustotal", "ip-greynoise"],
        ),
        LayerPhase::new("sidecar-sweep", ["ip-spiderfoot"])
            .gated_on(crate::layer_plan::reputation_flagged()),
        // Fast keyed API calls, a different cost class from `sidecar-sweep`'s slow local
        // sweep — see `sources::ip::censys`'s module doc for why they get their own phase
        // rather than joining it.
        LayerPhase::new("deep-recon", ["ip-censys", "ip-netlas"])
            .gated_on(crate::layer_plan::reputation_flagged()),
    ])
}

/// `entity-email (EML)` — one unconditional breadth phase, now two tools.
///
/// The full chain envisioned for this category (EmailRep triage gate, HIBP, BreachDirectory,
/// IntelX, Hunter.io, MXToolbox, DeHashed, LeakCheck) is "yes-with-paid-key" and stays
/// unbuilt: HIBP is a paid key, DeHashed/LeakCheck Pro are gated, and the rest of the chain
/// exists to enrich a breach finding that only a keyed source can produce in the first place.
/// `gravatar-email` is not that chain — it is a keyless identity lookup by email-hash, the
/// same shape as `gravatar-profile` in `username_plan`, and it is the type's first tool
/// specifically because it needed no key at all, not because of any priority ordering.
///
/// **`sidecar-holehe`, landed by the 2026-08-25 category audit.** This category was this
/// crate's thinnest — one keyless Gravatar lookup, nothing else — and a real product
/// comparison the same night surfaced exactly why that mattered: a commercial competitor
/// returned 12 confirmed account registrations for a seed email this crate returned empty on.
/// `holehe` (`sources::sidecar::holehe`) closes most of that gap for free, keylessly, via a
/// local Docker sidecar — the same "own the missing server" shape `maigret-probe` already
/// proved for `entity-username`. EmailRep.io was researched alongside it and **not built**:
/// its unauthenticated tier, reported free hours earlier in the same audit, answered `429`
/// "please use an API key" when re-verified before wiring — a policy change caught by this
/// crate's own "verify by direct call" discipline rather than trusted from the earlier report.
///
/// **`email-hudsonrock`, landed the same audit.** Found while researching external OSINT
/// repos for this category (`N0rz3/Zehef`'s `hudsonrock.py` module) — a free, keyless
/// infostealer-compromise lookup, a genuinely new signal class (malware captured this email's
/// credentials on a victim machine) neither `gravatar-email` nor `sidecar-holehe` touches.
/// Writes `EmailPayload.breaches`, which no other tool in this plan writes — see
/// `sources::email::hudsonrock`'s module doc for why an infostealer capture maps onto
/// `BreachEvent`'s existing shape rather than a new field.
///
/// **Why one phase.** Same reasoning as `username_plan`'s breadth phase: nothing here needs to
/// be held back — all four tools are free and each owns a payload key (or none) the others
/// never touch: `gravatar-email` patches identity fields directly; `sidecar-holehe` and
/// `sidecar-blackbird-email` are both row-only, the same shape `maigret-probe` uses to avoid
/// colliding with `wmn-probe`'s payload write; `email-hudsonrock` is the sole writer of
/// `breaches`.
///
/// **`sidecar-blackbird-email`, landed 2026-08-26.** A different 16-site list from holehe's
/// ~120 (`sources::sidecar::blackbird`'s module doc), so it joins the same unconditional
/// breadth phase rather than a gated one — nothing here is expensive enough to hold back.
///
/// **`email-microsoft-credential-type`, landed 2026-08-26.** This category's first GAFAM unit
/// (`sources::email::microsoft`'s module doc) — a tenant-type fingerprint, existence claimed
/// only for managed/federated business domains, never for consumer accounts. Free, keyless,
/// joins the same breadth phase.
pub fn email_plan() -> LayerPlan {
    LayerPlan::new(vec![LayerPhase::new(
        "breadth",
        [
            "gravatar-email",
            "sidecar-holehe",
            "email-hudsonrock",
            "sidecar-blackbird-email",
            "email-microsoft-credential-type",
        ],
    )])
}

/// `entity-phone (TEL)` — one unconditional breadth phase, two tools as of the 2026-08-25
/// category audit.
///
/// The plan's own first step for this category is exactly this: local `libphonenumber`
/// normalisation, ahead of Veriphone/IPQualityScore/Telnyx/DeHashed/LeakCheck.
/// `phone-local-normalize` is that first step, unchanged. `phone-veriphone` is the second:
/// free (1000/mo, no card), and picked over IPQualityScore specifically — the audit judged
/// IPQualityScore's marginal signal (fraud score, VOIP flag) low relative to Veriphone's
/// carrier lookup, and Mathéo had already hit an IPQualityScore duplicate-account block the
/// same night, so the friction wasn't worth it for a smaller gain. Telnyx/DeHashed/LeakCheck
/// stay unbuilt — no key held.
///
/// **Why one phase, and why the two tools never collide.** Same reasoning as `email_plan`:
/// nothing here needs to be held back, both are free. `phone-local-normalize` owns `valid`/
/// `country`/`lineType`; `phone-veriphone` owns only `carrier` and reports its own live
/// classification as rows rather than contesting `lineType` — see `veriphone`'s own module doc
/// for why a live, carrier-aware source and a static local one are kept as two blocks rather
/// than merged, the same convention `coordinate_plan`'s raw-vs-reverse-geocoded split uses.
pub fn phone_plan() -> LayerPlan {
    LayerPlan::new(vec![LayerPhase::new(
        "breadth",
        ["phone-local-normalize", "phone-veriphone"],
    )])
}

/// `entity-hash (SHA)` — a breadth phase of three field-disjoint free-key sources, and a
/// tier-2 phase held behind them.
///
/// **Phase `breadth`.** VirusTotal, MalwareBazaar and AlienVault OTX. Each owns a different
/// slice of [`crate::types::HashPayload`] — VirusTotal writes `md5`/`sha1`/`sha256`/
/// `detections`/`engines_total`, MalwareBazaar writes `fileType`/`firstSeen`/`family`, OTX
/// writes `pulseCount` — so nothing here can overwrite anything else here, the same
/// field-disjoint fan-out `cve_plan`'s breadth phase uses. See `sources::hash`'s module doc
/// for the full ownership table and the direct-call verification behind each source.
///
/// **Phase `escalate-if-detected`.** Hybrid Analysis and PolySwarm, gated on
/// [`crate::layer_plan::has_detections`] — opens only once VirusTotal's `detections` fact
/// crosses [`crate::layer_plan::HASH_TIER2_MIN_DETECTIONS`] (3 engines, the same number
/// `signal.rs`'s chip rule uses).
///
/// **The escalation direction is the mirror image of `cve_plan`'s.** `cve-shodan` is held
/// behind `authoritative_source_silent()` because it duplicates fields NVD already writes, so
/// it must only run when NVD said *nothing*. Hybrid Analysis and PolySwarm write fields no
/// tier-1 tool writes at all — there is no collision to avoid — so the reason to hold them
/// back is pure cost: two more keyed lookups are not worth spending on a hash tier 1 already
/// found clean. The gate opens on the opposite condition as a result: tier 1 finding
/// *something*, not tier 1 finding nothing.
///
/// **What this plan deliberately does not fire**: Tier 3 (Triage/Joe Sandbox,
/// gated on "no family consensus") and the non-malware Hashes.com branch. Neither has a free
/// key in this repo's env table, Hashes.com is explicitly on the "do not build"
/// list (paid, ethically gated, no auto-fire path exists), and "family consensus" across this
/// plan's several family-ish fields is a correlation this crate was not asked to invent. See
/// `sources::hash`'s module doc for the full reasoning.
pub fn hash_plan() -> LayerPlan {
    LayerPlan::new(vec![
        LayerPhase::new(
            "breadth",
            [
                "hash-virustotal",
                "hash-malwarebazaar",
                "hash-otx",
                "hash-urlhaus",
            ],
        ),
        LayerPhase::new(
            "escalate-if-detected",
            ["hash-hybrid-analysis", "hash-polyswarm"],
        )
        .gated_on(crate::layer_plan::has_detections()),
    ])
}

/// `entity-video (VID)` — one unconditional breadth phase across four tools spanning three
/// different value shapes.
///
/// **Why one `OzType` and not three.** The product brief's cross-platform verification-chain
/// idea (a video's own frames re-entering `entity-image`'s EXIF chain, a platform post
/// resolving to the same downstream tree) only holds together if "a video" is one node type
/// regardless of where it came from. Splitting `VID` into `VID-LOCAL`/`VID-YOUTUBE`/… would
/// solve the value-shape question by pushing it onto the analyst instead — they would have to
/// already know which kind of video a node is before creating it.
///
/// **Why one phase despite that split.** A phase exists to hold expensive work back until
/// cheap work justifies the spend — see `cve_plan`'s aggregator or `hash_plan`'s tier 2. None
/// of that applies here: the five tools do not compete for the same field
/// (`video-local-probe` and the four platform lookups are mutually exclusive by construction,
/// since exactly one of them ever finds its own value shape in a given node's value — see
/// below), and there is no cost relationship between them to gate on. They fan out together and
/// four of the five report a clean, honest
/// [`crate::outcome::ToolOutcome::SkippedNotApplicable`] every single time.
///
/// **The field-disjointness argument, and why it is different from `cve_plan`'s or
/// `domain_plan`'s.** Those plans avoid a collision because each tool writes a genuinely
/// different key of the same payload while running on the *same* value. Here the tools avoid a
/// collision because at most one of them ever runs *at all*: `video-local-probe` only fires on
/// a `media_id` (checked via `media::is_media_id`), the platform tools only fire on their own
/// URL shape (`video::youtube::extract_video_id`, `video::telegram::parse_telegram_post_url`,
/// `video::bluesky::parse_bluesky_post_url`, `video::ytdlp::is_tiktok_url`), and a `VID` node's
/// own value is always exactly one of those five shapes, never more than one.
/// `runtime::merge_patch`'s shallow last-writer-wins merge is therefore never actually
/// exercised across two of this phase's tools disagreeing — there is nothing for it to
/// arbitrate.
///
/// **`video-ytdlp-probe`, landed by the 2026-08-25 category audit.** TikTok, via the `yt-dlp`
/// binary's `--dump-json` mode — the audit's single highest-leverage finding for this
/// category: one external tool legitimately subsumes what would otherwise be a bespoke parser,
/// the same "shell out to a real binary" shape `video-local-probe` already uses for
/// `ffmpeg`/`ffprobe`. Deliberately scoped to TikTok only, not "any URL `yt-dlp` recognises" —
/// see `video::ytdlp`'s own module doc for why a wider claim would risk two tools both
/// answering for the same YouTube URL.
///
/// **What the four network tools deliberately do not do.** None downloads the video's bytes —
/// each reports a URL (a YouTube watch link, a Telegram CDN URL, a Bluesky HLS playlist, a
/// TikTok webpage link), the same "links, not content" posture `geo-map-links` takes. Fetching
/// and storing those bytes is a different, not-yet-built unit's job —
/// and so is closing the dead end the audit also flagged: `video-telegram-resolve` and
/// `video-bluesky-resolve` emit no children today, so a resolved CDN/HLS URL currently has
/// nowhere further to go in this product (it cannot yet be handed to `video-local-probe` for
/// keyframe extraction). Left as a documented gap rather than built in this pass.
pub fn video_plan() -> LayerPlan {
    LayerPlan::new(vec![LayerPhase::new(
        "breadth",
        [
            "video-local-probe",
            "video-youtube-lookup",
            "video-telegram-resolve",
            "video-bluesky-resolve",
            "video-ytdlp-probe",
        ],
    )])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer_plan::{
        FACT_DETECTIONS, FLAG_AUTHORITATIVE_ANSWERED, HASH_TIER2_MIN_DETECTIONS, PhaseAcc,
    };
    use crate::registry;

    /// Every type that has an orchestrator today, paired with nothing else — the single list
    /// the tests below iterate so a new orchestrator is wired into all of them at once.
    const PLANNED: &[OzType] = &[
        OzType::Username,
        OzType::Name,
        OzType::Directory,
        OzType::Cve,
        OzType::Domain,
        OzType::Coordinate,
        OzType::Ip,
        OzType::Image,
        OzType::Email,
        OzType::Phone,
        OzType::Hash,
        OzType::Video,
    ];

    #[test]
    fn exactly_the_built_orchestrators_hand_back_a_plan() {
        // Every `OzType` this crate defines is in `PLANNED` today — there is no unbuilt type
        // left to assert `None` against. `no_plan_is_ever_empty` below is what still enforces
        // `plan_for`'s "never `Some(<empty>)`" half of the contract.
        for oz_type in PLANNED {
            assert!(
                plan_for(*oz_type).is_some(),
                "{oz_type:?} should have a plan"
            );
        }
    }

    #[test]
    fn no_plan_is_ever_empty() {
        // The contract `fire_layer`'s `an_empty_plan_settles_failed_not_empty` depends on from
        // the other side: `plan_for` must answer `None`, never `Some(<empty>)`.
        for oz_type in PLANNED {
            let plan = plan_for(*oz_type).expect("planned");
            assert!(
                plan.max_possible() > 0,
                "{oz_type:?} handed back an empty plan"
            );
        }
    }

    // ── directory ────────────────────────────────────────────────────────

    #[test]
    fn the_two_directory_plans_fire_different_tools() {
        // They resolve genuinely different tile sets (a person is not a company), so sharing
        // one tool id would send a company name to five people-search aggregators.
        let person = plan_for(OzType::Name).expect("NAM plan");
        let entity = plan_for(OzType::Directory).expect("DIR plan");
        assert_eq!(person.all_tools(), vec!["dir-tiles-person"]);
        assert_eq!(entity.all_tools(), vec!["dir-tiles-entity"]);
    }

    #[test]
    fn a_directory_plan_holds_exactly_one_tool_in_one_phase() {
        // Guards the shallow-merge trap documented on `directory_plan`: a second tool in this
        // plan would silently overwrite the first's tiles.
        for oz_type in [OzType::Name, OzType::Directory] {
            let plan = plan_for(oz_type).expect("planned");
            assert_eq!(plan.phases.len(), 1, "{oz_type:?} grew a phase");
            assert_eq!(
                plan.max_possible(),
                1,
                "{oz_type:?} names a second tool — two tools writing `tiles` clobber each other"
            );
        }
    }

    // ── plan ↔ registry drift ────────────────────────────────────────────
    //
    // These two are the point of this module's test suite. A tool id exists in two places —
    // the catalogue and a plan — and nothing in the type system ties them together, so
    // either can drift silently. The runtime reports an unknown tool id rather than going
    // quiet, but that surfaces at *runtime*, on a real investigation. These fail at build
    // time instead.

    #[test]
    fn every_tool_any_plan_names_exists_in_the_registry() {
        for oz_type in PLANNED {
            for id in plan_for(*oz_type).expect("planned").all_tools() {
                assert!(
                    registry::find(id).is_some(),
                    "the {oz_type:?} plan names `{id}`, which is not in the registry catalogue"
                );
            }
        }
    }

    #[test]
    fn every_catalogued_tool_is_reachable_from_its_type_s_plan() {
        // The converse, and the easier one to get wrong: a tool that is built, catalogued
        // and dispatchable but named by no plan is dead weight no investigation can ever
        // reach.
        for oz_type in PLANNED {
            let plan = plan_for(*oz_type).expect("planned");
            let planned = plan.all_tools();
            for tool in registry::list_for_type(*oz_type) {
                assert!(
                    planned.contains(&tool.id),
                    "`{}` is catalogued for {oz_type:?} but no plan fires it",
                    tool.id
                );
            }
        }
    }

    #[test]
    fn no_plan_names_a_tool_twice() {
        for oz_type in PLANNED {
            let plan = plan_for(*oz_type).expect("planned");
            let mut ids = plan.all_tools();
            let before = ids.len();
            ids.sort_unstable();
            ids.dedup();
            assert_eq!(
                before,
                ids.len(),
                "a tool is named twice in the {oz_type:?} plan"
            );
        }
    }

    #[test]
    fn the_username_plan_fans_out_in_one_unconditional_phase_plus_a_gated_deep_sweep() {
        let plan = username_plan();
        assert_eq!(plan.phases.len(), 2);
        assert_eq!(
            plan.phases[0].tools.len(),
            12,
            "the unconditional breadth phase now includes the 2026-08-25 audit's four keyless additions plus reddit-arctic-shift"
        );
        assert_eq!(
            plan.phases[1].tools,
            vec!["maigret-probe", "sidecar-blackbird-username"]
        );
        assert_eq!(plan.phases[1].when.name(), "enough-confirmed-hits");
        assert_eq!(
            plan.max_possible(),
            registry::list_for_type(OzType::Username).len(),
            "the denominator the UI shows must be the whole catalogued fan-out, sidecar phase included"
        );
    }

    // ── cve ──────────────────────────────────────────────────────────────

    #[test]
    fn the_cve_aggregator_stays_shut_while_the_source_of_record_answered() {
        // The assertion this plan's whole shape exists for. If this predicate ever inverts or
        // is dropped, `cve-shodan` and `cve-nvd` fire in the same layer, both write `cvss`,
        // and `merge_patch`'s last-writer-wins silently picks one — two green tools, one
        // value, no way to see that they disagreed. They genuinely do disagree: for
        // CVE-2021-34527 Shodan's flat score is 8.8 and NVD's only Primary metric is a CVSS
        // v2 9.0.
        let plan = plan_for(OzType::Cve).expect("CVE plan");

        let mut answered = PhaseAcc::default();
        answered.set_flag(FLAG_AUTHORITATIVE_ANSWERED, true);
        // Phase 0 has run; ask what phase 1 would do.
        assert!(
            plan.firing_now(1, &answered).is_none(),
            "the aggregator must not fire when NVD already answered"
        );

        // And it must genuinely open otherwise — a fallback that never runs is the same as
        // not having one, and a CVE NVD does not carry would stay silently unscored.
        let silent = PhaseAcc::default();
        let (idx, phase) = plan.firing_now(1, &silent).expect("the fallback must open");
        assert_eq!(idx, 1);
        assert_eq!(phase.tools, vec!["cve-shodan"]);
    }

    #[test]
    fn a_skipped_cve_fallback_says_why_rather_than_shrinking_the_fan_out() {
        // `max_possible` counts the conditional phase, so the UI's denominator is the whole
        // capability and the skip is reported with its predicate name.
        let plan = plan_for(OzType::Cve).expect("CVE plan");
        assert_eq!(
            plan.max_possible(),
            6,
            "four breadth sources plus the two held-back fallbacks (shodan, mitre)"
        );

        let mut answered = PhaseAcc::default();
        answered.set_flag(FLAG_AUTHORITATIVE_ANSWERED, true);
        let skipped = plan.skipped_from(1, &answered);
        assert_eq!(
            skipped.len(),
            2,
            "NVD alone answering must shut both fallbacks"
        );
        assert_eq!(skipped[0].0.tools, vec!["cve-shodan"]);
        assert_eq!(skipped[1].0.tools, vec!["cve-mitre"]);
    }

    #[test]
    fn every_cve_breadth_tool_owns_a_different_payload_field() {
        // The four breadth tools fan out together precisely because none of them can overwrite
        // another. This pins the phase membership; the field disjointness itself is asserted
        // in each tool's own module against its yield.
        let plan = plan_for(OzType::Cve).expect("CVE plan");
        assert_eq!(
            plan.phases[0].tools,
            vec!["cve-nvd", "cve-epss", "cve-kev", "cve-poc-github"]
        );
        assert_eq!(plan.phases.len(), 3);
    }

    #[test]
    fn the_mitre_fallback_only_opens_once_both_earlier_sources_stayed_silent() {
        // `cve-mitre`'s own reason for a stricter gate than `cve-shodan`'s: sharing
        // `authoritative_source_silent` would let both fire in the same run and collide on
        // `cvss`/`severity`/`summary`.
        let plan = plan_for(OzType::Cve).expect("CVE plan");

        // NVD silent, Shodan answered — mitre must still stay shut.
        let mut shodan_answered = PhaseAcc::default();
        shodan_answered.set_flag(crate::layer_plan::FLAG_AGGREGATE_ANSWERED, true);
        assert!(
            plan.firing_now(2, &shodan_answered).is_none(),
            "mitre must not fire once shodan already answered"
        );

        // Both silent — mitre opens.
        let both_silent = PhaseAcc::default();
        let (idx, phase) = plan.firing_now(2, &both_silent).expect("mitre must open");
        assert_eq!(idx, 2);
        assert_eq!(phase.tools, vec!["cve-mitre"]);
    }

    // ── domain ───────────────────────────────────────────────────────────

    #[test]
    fn the_domain_plan_fans_out_with_an_unconditional_sidecar_sweep_phase() {
        // Unlike `cve_plan`, nothing in `breadth` overlaps, so there is nothing to hold back
        // there. `sidecar-sweep` and `reputation` are unconditional too, for the different
        // reason `domain_plan`'s own doc gives: no signal here predicts whether a broad sweep
        // or a VT lookup will be productive.
        let plan = plan_for(OzType::Domain).expect("DOM plan");
        assert_eq!(plan.phases.len(), 3);
        assert_eq!(
            plan.phases[0].tools,
            vec!["dom-rdap", "dom-dns", "dom-certspotter"]
        );
        assert_eq!(plan.phases[1].tools, vec!["dom-spiderfoot"]);
        assert_eq!(plan.phases[2].tools, vec!["dom-virustotal"]);
        assert!(matches!(
            plan.phases[1].when,
            crate::layer_plan::Predicate::Always
        ));
        assert!(matches!(
            plan.phases[2].when,
            crate::layer_plan::Predicate::Always
        ));
        assert_eq!(plan.max_possible(), 5);
    }

    #[test]
    fn every_planned_type_is_reachable_without_a_credential_today_except_hash() {
        // The property that made most of these types buildable without any registration, and
        // the one most likely to be lost by reflex — adding an env var to a tool that does not
        // actually need one would make its whole category unreachable on a bare machine,
        // reported as `SkippedNoKey`. `hash_plan` is the deliberate exception at the type
        // level — see `plan_for`'s module doc — where every tool genuinely needs a real
        // credential, not just a rate-limit upgrade. Every other type keeps at least one
        // keyless tool reachable; `KEYED_EXCEPTIONS` below is the closed list of individual
        // tools this crate has decided genuinely need a key, so this test still catches an
        // *unexpected* new credential dependency rather than needing constant re-tuning.
        const KEYED_EXCEPTIONS: &[&str] = &[
            "youtube-channel",
            "video-youtube-lookup",
            "ip-abuseipdb",
            "ip-virustotal",
            "ip-greynoise",
            "ip-maxmind",
            "ip-censys",
            "ip-netlas",
            "dom-virustotal",
            "img-saucenao",
            "phone-veriphone",
        ];
        for oz_type in PLANNED {
            let plan = plan_for(*oz_type).expect("planned");
            let all_tools = plan.all_tools();
            let keyed: Vec<&str> = all_tools
                .iter()
                .filter(|id| registry::find(id).is_some_and(|t| !t.env_vars.is_empty()))
                .copied()
                .collect();
            if *oz_type == OzType::Hash {
                assert_eq!(
                    keyed.len(),
                    all_tools.len(),
                    "every entity-hash tool must be genuinely keyed"
                );
                continue;
            }
            let unexpected: Vec<&str> = keyed
                .iter()
                .filter(|id| !KEYED_EXCEPTIONS.contains(id))
                .copied()
                .collect();
            assert!(
                unexpected.is_empty(),
                "{oz_type:?} now depends on an unlisted credential: {unexpected:?}"
            );
            assert!(
                keyed.len() < all_tools.len(),
                "{oz_type:?} must keep at least one keyless tool reachable"
            );
        }
    }

    // ── hash ─────────────────────────────────────────────────────────────

    #[test]
    fn hash_tier2_only_opens_once_tier1_finds_real_detections() {
        // The mirror image of `the_cve_aggregator_stays_shut_while_the_source_of_record_answered`:
        // there the aggregator opens on *silence*, here tier 2 opens on *detections*. If this
        // predicate ever inverts, Hybrid Analysis and PolySwarm fire on every clean hash — two
        // wasted keyed lookups on the common case this gate exists to spare.
        let plan = plan_for(OzType::Hash).expect("Hash plan");

        let clean = PhaseAcc::default();
        assert!(
            plan.firing_now(1, &clean).is_none(),
            "tier 2 must stay shut when VirusTotal found nothing"
        );

        let mut below_threshold = PhaseAcc::default();
        below_threshold.set_fact(FACT_DETECTIONS, HASH_TIER2_MIN_DETECTIONS - 1.0);
        assert!(
            plan.firing_now(1, &below_threshold).is_none(),
            "a handful of detections below the threshold must not open tier 2 either"
        );

        let mut detected = PhaseAcc::default();
        detected.set_fact(FACT_DETECTIONS, HASH_TIER2_MIN_DETECTIONS);
        let (idx, phase) = plan
            .firing_now(1, &detected)
            .expect("tier 2 must open once detections cross the threshold");
        assert_eq!(idx, 1);
        assert_eq!(phase.tools, vec!["hash-hybrid-analysis", "hash-polyswarm"]);
    }

    #[test]
    fn no_planned_tool_is_ethically_gated_yet() {
        // Every built plan was chosen to need no ethically gated source. If this ever fails,
        // a blanket-consent gate has to be wired into the fire path before the offending plan
        // can ship — firing a gated tool without asking is the thing this pins shut.
        for oz_type in PLANNED {
            assert_eq!(
                plan_for(*oz_type)
                    .expect("planned")
                    .gated_count(registry::is_gated),
                0,
                "{oz_type:?} now fires a gated tool"
            );
        }
    }

    // ── video ────────────────────────────────────────────────────────────

    #[test]
    fn the_video_plan_fans_out_once_across_all_five_tools() {
        let plan = plan_for(OzType::Video).expect("VID plan");
        assert_eq!(plan.phases.len(), 1);
        assert_eq!(
            plan.phases[0].tools,
            vec![
                "video-local-probe",
                "video-youtube-lookup",
                "video-telegram-resolve",
                "video-bluesky-resolve",
                "video-ytdlp-probe",
            ]
        );
        assert_eq!(plan.max_possible(), 5);
    }

    #[test]
    fn exactly_one_video_tool_recognises_any_given_value_shape() {
        // The property `video_plan`'s doc leans on: a `media_id`, a YouTube URL, a Telegram
        // post URL, a Bluesky post URL and a TikTok URL are recognised by exactly one of the
        // five tools each, never zero and never more than one — which is what makes firing all
        // five in one phase collision-free despite four different value shapes.
        let media_id = "a".repeat(64);
        let cases: &[(&str, &[bool])] = &[
            (&media_id, &[true, false, false, false, false]),
            (
                "https://youtu.be/dQw4w9WgXcQ",
                &[false, true, false, false, false],
            ),
            (
                "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                &[false, true, false, false, false],
            ),
            (
                "https://t.me/durov/531",
                &[false, false, true, false, false],
            ),
            (
                "https://bsky.app/profile/bsky.app/post/3mk4lzkrnk22d",
                &[false, false, false, true, false],
            ),
            (
                "https://www.tiktok.com/@scout2015/video/6718335390845095173",
                &[false, false, false, false, true],
            ),
        ];
        for (value, expected) in cases {
            let recognised = [
                crate::media::is_media_id(value),
                crate::sources::video::youtube::extract_video_id(value).is_some(),
                crate::sources::video::telegram::parse_telegram_post_url(value).is_some(),
                crate::sources::video::bluesky::parse_bluesky_post_url(value).is_some(),
                crate::sources::video::ytdlp::is_tiktok_url(value),
            ];
            assert_eq!(
                &recognised, expected,
                "value {value:?} was recognised as {recognised:?}"
            );
            assert_eq!(
                recognised.iter().filter(|r| **r).count(),
                1,
                "value {value:?} must be recognised by exactly one video tool"
            );
        }
    }
}
