//! The OZINT tool roster — one submodule per entity-type category: [`coordinate`], [`cve`],
//! [`directory`], [`domain`], [`email`], [`hash`], [`image`], [`ip`], [`phone`], [`sidecar`],
//! [`username`] and [`video`].
//!
//! This module is deliberately thin: module wiring, the [`dispatch`] function that maps a
//! `registry::ToolDef::id` onto the async function that actually runs it, and
//! [`fold_fetch_failure`], a shared helper every tool module can reuse to turn a non-`Ok`
//! [`crate::fetch::OzOutcome`] into the [`ToolOutcome`] taxonomy per the mapping documented
//! on `OzOutcome` itself.
//!
//! `dispatch` is **not** `runtime.rs`. `runtime.rs` owns the layer-plan bookkeeping, dedup,
//! node creation and provenance stamping around a tool call; `dispatch` only answers "given
//! this tool id and this seed value, run the tool and report what happened" — the same scope
//! each individual `fetch_*` function has, collected behind one lookup so a caller doesn't
//! need a giant `match` of its own.

pub mod coordinate;
pub mod cve;
pub mod directory;
pub mod domain;
pub mod email;
pub mod hash;
pub mod image;
pub mod ip;
pub mod phone;
pub mod sidecar;
pub mod username;
pub mod video;

use std::sync::Arc;
use std::time::Duration;

use crate::cache::ToolCache;
use crate::fetch::{self, CancelSignal, OzFetchOptions, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;

/// Everything a dispatcher needs beyond the seed value: the cancel signal it must honour, and
/// the fetch-cache handle plus the policy (TTL, bypass) to use it with.
///
/// **This type exists because the cache had no caller.** The fetch cache shipped complete —
/// TTL, single-flight, a bypass flag, six tests — and then every dispatcher went on calling
/// [`fetch::oz_fetch`] directly. `registry::ToolDef::ttl_secs` was decorative on all seventeen
/// tools, the refresh bypass had nothing to bypass, and a CVE layer re-downloaded
/// CISA's 1.6 MB KEV catalogue on every single lookup. Threading this through `dispatch` is
/// what connects the three.
///
/// `Default` is the uncached context (no cache, zero TTL, no bypass), which is what every unit
/// test wants and is behaviourally identical to the pre-cache code path.
#[derive(Clone, Default)]
pub struct ToolCtx {
    pub cancel: Option<CancelSignal>,
    /// `None` means "no cache configured" and behaves exactly like a zero TTL. Kept optional
    /// for the same reason `LayerContext::scheduler` is: dozens of tests say "not the thing
    /// under test" without each having to build a database.
    pub cache: Option<Arc<ToolCache>>,
    /// This tool's TTL, straight from `registry::ToolDef::ttl_secs`. Zero disables caching for
    /// the tool entirely — which is exactly what the two `dir-tiles-*` entries want, since
    /// their output is a pure function of the value and a compiled-in catalogue.
    pub ttl: Duration,
    /// The refresh feature's force-a-miss flag. A refresh that could be served from cache
    /// would make the whole refresh feature a lie.
    pub bypass: bool,
    /// **The sibling hand-off.** What earlier waves of this layer published, frozen at phase
    /// start — see [`crate::layer_plan::Handoff`] for why it is a snapshot and why there is no
    /// intra-wave variant of it.
    ///
    /// A tool reads it through [`ToolCtx::input`]. It is empty by [`Default`], which is the
    /// honest state for every context that is not a layer's: a direct unit-test call and a
    /// `refresh` of a chain whose node holds nothing both genuinely have nothing to hand over.
    /// The runtime refuses to dispatch a tool whose `needs_input` is unmet before it gets here,
    /// so a tool finding its key absent means it was called outside a layer.
    pub handoff: crate::layer_plan::Handoff,
}

/// Marks a cache error string as a round-tripped [`OzOutcome`] rather than a message from the
/// cache's own machinery. Without a discriminator, a database error and a `404` would arrive
/// at the same place as the same type and one would have to be guessed at.
const CACHED_FAILURE: &str = "\u{1}ozfail\u{1}";

impl ToolCtx {
    /// A context with a cancel signal and no cache — the pre-cache behaviour, kept as a named
    /// constructor so a call site that genuinely wants no caching says so out loud.
    pub fn uncached(cancel: Option<CancelSignal>) -> Self {
        Self {
            cancel,
            ..Default::default()
        }
    }

    /// A hand-off value published by an earlier wave, by `layer_plan` `INPUT_*` key.
    ///
    /// `None` only ever means "this tool was dispatched outside a layer runtime", because the
    /// runtime gates on `ToolDef::needs_input` before dispatching. A tool must still handle it
    /// — with [`ToolOutcome::SkippedMissingInput`], never with an empty result.
    pub fn input(&self, key: &str) -> Option<&str> {
        self.handoff.get(key).map(String::as_str)
    }

    /// The outcome a tool returns when [`ToolCtx::input`] came back `None`. One function so the
    /// second, third and fourth hand-off consumer cannot each phrase this differently.
    pub fn missing_input(key: &str) -> DispatchOutcome {
        DispatchOutcome::Ran(
            ToolOutcome::SkippedMissingInput {
                input: key.to_string(),
                reason: format!(
                    "no earlier tool in this layer published `{key}`, so there was nothing to look up"
                ),
            },
            None,
        )
    }

    /// One upstream request, served from the tool cache when a fresh entry exists.
    ///
    /// `cache_key` identifies the *request*, not the node: a tool whose URL does not vary with
    /// the seed value (the KEV catalogue, the WhatsMyName site list) passes a constant, which
    /// is the whole point — those are the fetches worth collapsing across investigations.
    ///
    /// Only a settled `Ok` response is persisted. Every other outcome — including `Cancelled`
    /// and a `404` that a tool reads as a genuine "no such account" — travels through the
    /// cache's error channel, so it is never stored and the next call retries. It is still
    /// handed to concurrent single-flight followers verbatim, which is the honest answer for
    /// them: they asked for the same request and that request failed.
    ///
    /// One consequence worth naming: if the *leading* caller of a single-flight group is
    /// cancelled, its followers receive `Cancelled` too, even though nobody cancelled them.
    /// Within a layer that is correct (one signal per layer). Across two layers racing on the
    /// same key it is a spurious abort, bounded by the fact that nothing was cached and the
    /// next call starts a genuinely new fetch.
    pub async fn fetch(
        &self,
        tool_id: &str,
        cache_key: &str,
        url: &str,
        mut opts: OzFetchOptions,
    ) -> OzOutcome {
        // The cancel signal is injected here rather than left to each tool to remember.
        //
        // It was left to each tool, and thirteen of the fifteen fetching tools did not
        // remember: they built an `OzFetchOptions::default()`, whose `cancel` is `None`, so
        // `oz_fetch` had nothing to abort on and every in-flight request ran to completion or
        // to the end of its retry budget after the analyst hit cancel. It produced no visible
        // symptom because cancellation *also* works between tools and while queued on the
        // scheduler — the layer did stop, just one whole request later than it claimed, and a
        // `LayerAborted` frame looks identical either way.
        //
        // A tool that sets its own signal keeps it; nothing here overrides an explicit choice.
        if opts.cancel.is_none() {
            opts.cancel = self.cancel.clone();
        }

        let Some(cache) = self.cache.as_ref().filter(|_| !self.ttl.is_zero()) else {
            return fetch::oz_fetch(url, opts).await;
        };

        let outcome = cache
            .get_or_fetch(tool_id, cache_key, self.ttl, self.bypass, || async {
                match fetch::oz_fetch(url, opts).await {
                    OzOutcome::Ok(resp) => serde_json::to_value(&resp).map_err(|e| {
                        format!(
                            "{CACHED_FAILURE}{}",
                            encode_failure(&OzOutcome::ParseError {
                                content_type: "cache".to_string(),
                                message: format!(
                                    "response could not be serialized for the cache: {e}"
                                ),
                            })
                        )
                    }),
                    other => Err(format!("{CACHED_FAILURE}{}", encode_failure(&other))),
                }
            })
            .await;

        match outcome {
            Ok(value) => match serde_json::from_value::<crate::fetch::OzResponse>(value) {
                Ok(resp) => OzOutcome::Ok(resp),
                // A stored row that no longer deserializes means this build's `OzResponse`
                // shape moved under an older cache file. Loud, not silent: the alternative is
                // reporting an empty result for a request that was never actually made.
                Err(e) => OzOutcome::ParseError {
                    content_type: "cache".to_string(),
                    message: format!("cached response does not fit this build's shape: {e}"),
                },
            },
            Err(raw) => decode_failure(&raw),
        }
    }
}

fn encode_failure(outcome: &OzOutcome) -> String {
    serde_json::to_string(outcome).unwrap_or_else(|e| format!("unencodable outcome: {e}"))
}

fn decode_failure(raw: &str) -> OzOutcome {
    match raw.strip_prefix(CACHED_FAILURE) {
        Some(json) => serde_json::from_str(json).unwrap_or_else(|e| OzOutcome::ParseError {
            content_type: "cache".to_string(),
            message: format!("cached failure could not be decoded ({e}): {json}"),
        }),
        // The cache no longer produces errors of its own — a failed write is warned about and
        // the value is served anyway — so this branch should be unreachable. If it ever fires,
        // it must be visible rather than folded into a plausible-looking network error.
        None => OzOutcome::TransportError {
            message: format!("tool cache: {raw}"),
        },
    }
}

/// The result of dispatching one tool invocation.
///
/// Split into `Ran`/`Cancelled` rather than folding cancellation into [`ToolOutcome`]
/// because `fetch.rs`'s own doc comment on [`OzOutcome::Cancelled`] is explicit that
/// cancellation "has no equivalent in the [`ToolOutcome`] union … and should short-circuit
/// before a `ToolOutcome` is even constructed" — it is the caller stopping the
/// investigation, not a tool failure.
#[derive(Debug, Clone)]
pub enum DispatchOutcome {
    /// The tool ran to some conclusion. `produced` is `Some` exactly when `outcome` is
    /// `OkWithResults`/`OkEmpty` — every other outcome carries nothing to apply.
    Ran(ToolOutcome, Option<ToolYield>),
    /// Cancelled via a `CancelSignal` before the tool reached a conclusion.
    Cancelled,
}

/// Maps a `registry::ToolDef::id` to the async function that actually runs it. Returns a
/// `ParseError`-shaped [`DispatchOutcome`] for an id with no dispatcher — this should only
/// happen if the registry catalogue and this `match` drift apart, which is exactly the kind
/// of thing that should surface as a visible tool failure, not a panic.
pub async fn dispatch(tool_id: &str, value: &str, ctx: &ToolCtx) -> DispatchOutcome {
    match tool_id {
        "wmn-probe" => username::wmn::run_wmn_probe(value, ctx).await,
        "github-user" => username::github::run_github_user(value, ctx).await,
        "bluesky-actor" => username::bluesky::run_bluesky_actor(value, ctx).await,
        "gravatar-profile" => username::gravatar::run_gravatar_profile(value, ctx).await,
        "gravatar-email" => email::gravatar::run_gravatar_email(value, ctx).await,
        "email-hudsonrock" => email::hudsonrock::run_hudsonrock(value, ctx).await,
        "email-microsoft-credential-type" => {
            email::microsoft::run_microsoft_credential_type(value, ctx).await
        }
        "sidecar-holehe" => sidecar::holehe::run_holehe(value, ctx).await,
        "hn-algolia" => username::hn::run_hn_algolia(value, ctx).await,
        "mastodon-lookup" => username::mastodon::run_mastodon_lookup(value, ctx).await,
        "youtube-channel" => username::youtube::run_youtube_channel(value, ctx).await,
        "keybase-lookup" => username::keybase::run_keybase_lookup(value, ctx).await,
        "devto-user" => username::devto::run_devto_user(value, ctx).await,
        "lobsters-user" => username::lobsters::run_lobsters_user(value, ctx).await,
        "steam-profile" => username::steam::run_steam_profile(value, ctx).await,
        "reddit-arctic-shift" => username::reddit::run_reddit_arctic_shift(value, ctx).await,
        // Synchronous on purpose — these two make no network call at all. See
        // `sources::directory`'s module doc for why the entity type rides on the tool id.
        "dir-tiles-person" => directory::run_dir_tiles(crate::types::OzType::Name, value),
        "dir-tiles-entity" => directory::run_dir_tiles(crate::types::OzType::Directory, value),
        "cve-nvd" => cve::nvd::run_nvd(value, ctx).await,
        "cve-epss" => cve::epss::run_epss(value, ctx).await,
        "cve-kev" => cve::kev::run_kev(value, ctx).await,
        "cve-poc-github" => cve::poc_github::run_poc_github(value, ctx).await,
        "cve-shodan" => cve::shodan::run_shodan(value, ctx).await,
        "cve-mitre" => cve::mitre::run_mitre(value, ctx).await,
        "dom-rdap" => domain::rdap::run_rdap(value, ctx).await,
        "dom-dns" => domain::dns::run_dns(value, ctx).await,
        "dom-certspotter" => domain::certspotter::run_certspotter(value, ctx).await,
        "dom-virustotal" => domain::virustotal::run_domain_virustotal(value, ctx).await,
        "hash-virustotal" => hash::virustotal::run_virustotal(value, ctx).await,
        "hash-malwarebazaar" => hash::malwarebazaar::run_malwarebazaar(value, ctx).await,
        "hash-otx" => hash::otx::run_otx(value, ctx).await,
        "hash-hybrid-analysis" => hash::hybrid_analysis::run_hybrid_analysis(value, ctx).await,
        "hash-polyswarm" => hash::polyswarm::run_polyswarm(value, ctx).await,
        "hash-urlhaus" => hash::urlhaus::run_urlhaus(value, ctx).await,
        // Synchronous for the same reason `dir-tiles-*` is: no network call at all.
        "geo-map-links" => coordinate::map_links::run_map_links(value),
        "geo-nominatim" => coordinate::nominatim::run_nominatim(value, ctx).await,
        "geo-overpass" => coordinate::overpass::run_overpass(value, ctx).await,
        "geo-geoconfirmed" => coordinate::geoconfirmed::run_geoconfirmed(value, ctx).await,
        // Synchronous, same reason `geo-map-links` is: a local disk read and a decode, no
        // request to await.
        "img-exif" => image::local_exif::run_local_exif(value),
        "img-phash" => image::phash::run_phash(value),
        "img-saucenao" => image::saucenao::run_saucenao(value, ctx).await,
        "ip-ipinfo" => ip::ipinfo::run_ipinfo(value, ctx).await,
        "ip-internetdb" => ip::internetdb::run_internetdb(value, ctx).await,
        // Takes the node value like every other dispatcher, and ignores it: it runs on the ASN
        // an earlier wave handed over through `ctx`. See its module doc.
        "ip-peeringdb" => ip::peeringdb::run_peeringdb(value, ctx).await,
        "ip-abuseipdb" => ip::abuseipdb::run_abuseipdb(value, ctx).await,
        "ip-virustotal" => ip::virustotal::run_ip_virustotal(value, ctx).await,
        "ip-greynoise" => ip::greynoise::run_greynoise(value, ctx).await,
        "ip-censys" => ip::censys::run_censys(value, ctx).await,
        "ip-netlas" => ip::netlas::run_netlas(value, ctx).await,
        // Synchronous — a local MMDB lookup, downloading the database on demand if missing or
        // stale. See its module doc for why that still counts as `LocalOnly`.
        "ip-maxmind" => ip::maxmind::run_maxmind(value).await,
        // Synchronous — no network call, see `sources::phone`'s module doc.
        "phone-local-normalize" => phone::local_normalize::run_phone_local_normalize(value),
        "phone-veriphone" => phone::veriphone::run_veriphone(value, ctx).await,
        // `async` despite making no network call — see `video::local_probe`'s module doc.
        "video-local-probe" => video::local_probe::run_video_local_probe(value).await,
        "video-youtube-lookup" => video::youtube::run_video_youtube_lookup(value, ctx).await,
        "video-telegram-resolve" => video::telegram::run_video_telegram_resolve(value, ctx).await,
        "video-bluesky-resolve" => video::bluesky::run_video_bluesky_resolve(value, ctx).await,
        "video-ytdlp-probe" => video::ytdlp::run_video_ytdlp_probe(value).await,
        "maigret-probe" => sidecar::maigret::run_maigret(value, ctx).await,
        "sidecar-blackbird-username" => {
            sidecar::blackbird::run_blackbird_username(value, ctx).await
        }
        "sidecar-blackbird-email" => sidecar::blackbird::run_blackbird_email(value, ctx).await,
        "dom-spiderfoot" | "ip-spiderfoot" => sidecar::spiderfoot::run_spiderfoot(value, ctx).await,
        other => DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("no dispatcher registered for tool id `{other}`"),
            },
            None,
        ),
    }
}

/// Folds a non-`Ok` [`OzOutcome`] into the [`ToolOutcome`] taxonomy, following the mapping
/// `fetch.rs`'s own doc comment on [`OzOutcome`] lays out. Returns `None` for `Ok` (the
/// caller handles the success path itself, since only it knows how to turn the body into a
/// [`ToolYield`]) and for `Cancelled` (see [`DispatchOutcome`] — the caller must short-circuit
/// to `DispatchOutcome::Cancelled` instead of calling this at all).
pub fn fold_fetch_failure(outcome: &OzOutcome) -> Option<ToolOutcome> {
    match outcome {
        OzOutcome::Ok(_) | OzOutcome::Cancelled => None,
        OzOutcome::Blocked { url } => Some(ToolOutcome::Forbidden {
            message: Some(format!("blocked by SSRF guard: {url}")),
        }),
        OzOutcome::Timeout { elapsed_ms, .. } => Some(ToolOutcome::Timeout {
            after_ms: (*elapsed_ms).try_into().unwrap_or(u64::MAX),
        }),
        OzOutcome::TooLarge { cap_bytes } => Some(ToolOutcome::ParseError {
            message: format!("response exceeded the {cap_bytes} byte cap"),
        }),
        OzOutcome::HttpError {
            status,
            body_snippet,
        } => Some(ToolOutcome::HttpError {
            status: *status,
            message: body_snippet.clone(),
        }),
        // No exact match in the 11-variant union (per fetch.rs's own doc comment) — folded
        // into HttpError with a synthesized status, as that comment suggests, rather than
        // inventing a 12th taxonomy variant from this crate.
        OzOutcome::TransportError { message } => Some(ToolOutcome::HttpError {
            status: 0,
            message: Some(message.clone()),
        }),
        OzOutcome::ParseError {
            content_type,
            message,
        } => Some(ToolOutcome::ParseError {
            message: format!("{content_type}: {message}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_fetch_failure_is_none_for_ok_and_cancelled() {
        assert!(fold_fetch_failure(&OzOutcome::Cancelled).is_none());
    }

    #[test]
    fn fold_fetch_failure_maps_blocked_to_forbidden() {
        let mapped = fold_fetch_failure(&OzOutcome::Blocked {
            url: "http://127.0.0.1".into(),
        });
        assert!(matches!(mapped, Some(ToolOutcome::Forbidden { .. })));
    }

    #[test]
    fn fold_fetch_failure_maps_timeout_directly() {
        let mapped = fold_fetch_failure(&OzOutcome::Timeout {
            attempts: 4,
            elapsed_ms: 12_000,
        });
        assert_eq!(mapped, Some(ToolOutcome::Timeout { after_ms: 12_000 }));
    }

    #[test]
    fn fold_fetch_failure_maps_http_error_directly() {
        let mapped = fold_fetch_failure(&OzOutcome::HttpError {
            status: 404,
            body_snippet: None,
        });
        assert_eq!(
            mapped,
            Some(ToolOutcome::HttpError {
                status: 404,
                message: None
            })
        );
    }

    #[test]
    fn fold_fetch_failure_synthesizes_status_zero_for_transport_errors() {
        let mapped = fold_fetch_failure(&OzOutcome::TransportError {
            message: "connection reset".into(),
        });
        assert_eq!(
            mapped,
            Some(ToolOutcome::HttpError {
                status: 0,
                message: Some("connection reset".into())
            })
        );
    }

    #[test]
    fn fold_fetch_failure_maps_too_large_and_parse_error_to_parse_error() {
        assert!(matches!(
            fold_fetch_failure(&OzOutcome::TooLarge {
                cap_bytes: 8_388_608
            }),
            Some(ToolOutcome::ParseError { .. })
        ));
        assert!(matches!(
            fold_fetch_failure(&OzOutcome::ParseError {
                content_type: "application/json".into(),
                message: "unexpected EOF".into(),
            }),
            Some(ToolOutcome::ParseError { .. })
        ));
    }

    #[tokio::test]
    async fn dispatch_reports_a_parse_error_for_an_unknown_tool_id() {
        let outcome = dispatch("not-a-real-tool", "someone", &ToolCtx::default()).await;
        assert_dispatch_parse_error(outcome);
    }

    // ── the cache, which until now had no caller at all ───────────────────────────────
    //
    // These three are hermetic by construction: the URL they pass is one the SSRF guard
    // rejects outright, so a request that actually goes out comes back `Blocked` and a
    // request served from cache comes back `Ok`. The two are impossible to confuse, which is
    // the property the unwired version of this unit could never have been tested for.

    /// A URL `ozint_core::net`'s guard refuses before any socket is opened. Any call that
    /// reaches the network answers `Blocked`; only a cache hit can answer `Ok`.
    const UNREACHABLE: &str = "http://127.0.0.1:1/never-requested";

    /// Passes the SSRF guard (a public-shaped hostname) so the cancel check downstream of it
    /// is the thing under test, and is guaranteed by RFC 2606 never to resolve, so an
    /// un-cancelled run fails at DNS rather than reaching anyone.
    const UNRESOLVABLE: &str = "https://never-requested.invalid/";

    fn seeded_cache(tool_id: &str, key: &str, body: serde_json::Value) -> Arc<ToolCache> {
        let db = ozint_db::open_memory().unwrap();
        let response = crate::fetch::OzResponse {
            status: 200,
            url: UNREACHABLE.to_string(),
            body: crate::fetch::OzBody::Json(body),
            elapsed_ms: 1,
            attempts: 1,
        };
        let payload = serde_json::to_string(&serde_json::to_value(&response).unwrap()).unwrap();
        crate::store::put_cache_entry(
            &db,
            tool_id,
            key,
            &payload,
            chrono::Utc::now().timestamp_millis(),
            None,
        )
        .unwrap();
        Arc::new(ToolCache::new(db))
    }

    #[tokio::test]
    async fn a_fresh_cache_entry_is_served_instead_of_a_request() {
        let cache = seeded_cache("test-tool", "the-key", serde_json::json!({"cached": true}));
        let ctx = ToolCtx {
            cache: Some(cache),
            ttl: Duration::from_secs(3600),
            ..Default::default()
        };

        let outcome = ctx
            .fetch(
                "test-tool",
                "the-key",
                UNREACHABLE,
                OzFetchOptions::default(),
            )
            .await;

        match outcome {
            OzOutcome::Ok(resp) => {
                assert_eq!(
                    resp.body,
                    crate::fetch::OzBody::Json(serde_json::json!({"cached": true}))
                );
            }
            other => panic!("a fresh cache entry must be served without a request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_zero_ttl_bypasses_the_cache_entirely() {
        // The control for the test above: same seeded row, same key, but the tool declares no
        // TTL — so the request must genuinely go out (and be blocked). Without this, a cache
        // that was never consulted at all could still pass the previous test by accident.
        let cache = seeded_cache("test-tool", "the-key", serde_json::json!({"cached": true}));
        let ctx = ToolCtx {
            cache: Some(cache),
            ttl: Duration::ZERO,
            ..Default::default()
        };

        let outcome = ctx
            .fetch(
                "test-tool",
                "the-key",
                UNREACHABLE,
                OzFetchOptions::default(),
            )
            .await;

        assert!(
            matches!(outcome, OzOutcome::Blocked { .. }),
            "a zero TTL must not read the cache, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn bypass_forces_a_request_past_a_fresh_entry() {
        // The refresh feature's bypass flag, now with a caller. Same seeded row, but a refresh must
        // reach the upstream — here, be blocked reaching it — rather than replay the cache.
        let cache = seeded_cache("test-tool", "the-key", serde_json::json!({"cached": true}));
        let ctx = ToolCtx {
            cache: Some(cache),
            ttl: Duration::from_secs(3600),
            bypass: true,
            ..Default::default()
        };

        let outcome = ctx
            .fetch(
                "test-tool",
                "the-key",
                UNREACHABLE,
                OzFetchOptions::default(),
            )
            .await;

        assert!(
            matches!(outcome, OzOutcome::Blocked { .. }),
            "a bypassed fetch must not be served from cache, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_reaches_the_cache_the_kev_catalogue_is_not_refetched() {
        // The concrete complaint this wiring answers: `cve-kev` downloads a 1.6 MB catalogue
        // under a constant URL, and did so once per CVE looked up. The synthetic id below
        // cannot exist in the real catalogue, so a `true` verdict is only possible if the
        // seeded entry — not CISA — answered.
        let catalogue = serde_json::json!({
            "vulnerabilities": [{ "cveID": "CVE-2026-99999" }]
        });
        let cache = seeded_cache("cve-kev", "catalogue", catalogue);
        let ctx = ToolCtx {
            cache: Some(cache),
            ttl: Duration::from_secs(24 * 3600),
            ..Default::default()
        };

        match dispatch("cve-kev", "CVE-2026-99999", &ctx).await {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { count }, Some(produced)) => {
                assert_eq!(count, 1);
                assert_eq!(produced.payload_patch, serde_json::json!({ "kev": true }));
            }
            other => panic!("the KEV catalogue must be served from cache, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_cancelled_context_aborts_the_request_every_tool_makes() {
        // The regression: thirteen tools passed `OzFetchOptions::default()`, so their requests
        // were uncancellable. `UNREACHABLE` distinguishes the two failures unambiguously — a
        // request that goes out answers `Blocked`, and only an honoured cancel answers
        // `Cancelled`.
        let (handle, signal) = crate::fetch::CancelHandle::new();
        handle.cancel();
        let ctx = ToolCtx::uncached(Some(signal));

        let outcome = ctx
            .fetch("test-tool", "k", UNRESOLVABLE, OzFetchOptions::default())
            .await;

        assert!(
            matches!(outcome, OzOutcome::Cancelled),
            "a tool that did not set `cancel` itself must still be cancellable, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_tools_own_cancel_signal_is_not_overridden_by_the_context() {
        // The inverse property: `wmn-probe` and `mastodon-lookup` pass their own signal, and a
        // context-level default must not replace it. Here the context is cancelled and the
        // tool's own signal is not — the request must go out.
        let (handle, ctx_signal) = crate::fetch::CancelHandle::new();
        handle.cancel();
        let (_live_handle, tool_signal) = crate::fetch::CancelHandle::new();
        let ctx = ToolCtx::uncached(Some(ctx_signal));

        let outcome = ctx
            .fetch(
                "test-tool",
                "k",
                UNRESOLVABLE,
                OzFetchOptions {
                    cancel: Some(tool_signal),
                    ..Default::default()
                },
            )
            .await;

        assert!(
            !matches!(outcome, OzOutcome::Cancelled),
            "an explicitly-set signal must win over the context's, got {outcome:?}"
        );
    }

    fn assert_dispatch_parse_error(outcome: DispatchOutcome) {
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, produced) => {
                assert!(message.contains("not-a-real-tool"));
                assert!(produced.is_none());
            }
            other => panic!("expected a ParseError DispatchOutcome, got {other:?}"),
        }
    }
}
