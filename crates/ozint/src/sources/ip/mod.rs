//! `entity-ip (NET)` — the IP sources.
//!
//! Ten tools across three waves plus a keyless ASN pivot, every one verified by direct call
//! (three on 2026-08-23, the rest on 2026-08-25).
//!
//! ## Field ownership
//!
//! `runtime::merge_patch` is a shallow last-writer-wins merge, so two tools writing one
//! [`crate::types::IpPayload`] key is a silent overwrite. No field has two writers:
//!
//! | tool | writes | rows |
//! |---|---|---|
//! | [`ipinfo`] | `country`, `city`, `lat`, `lon`, `asn`, `isp` | the location block and the external map links |
//! | [`internetdb`] | `ports`, `anonymizer` | hostnames, software (CPE), Shodan tags |
//! | [`peeringdb`] | *nothing* | the operator's own network record — see its module doc |
//! | [`abuseipdb`] | `abuseScore` | confidence, report count |
//! | [`virustotal`] | `vtMalicious`, `vtReputation` | AS owner, communicating files, passive DNS |
//! | [`greynoise`] | `classification` | noise/RIOT status |
//! | [`maxmind`] | *nothing* | corroborating geo, see its module doc |
//! | [`censys`], [`netlas`] | *nothing* | location/ASN/ports/software corroboration |
//!
//! Two tools in this category seed children into the tree: [`peeringdb`] (the operator's own
//! website and its published points of contact) and [`virustotal`] (`Hash` children for files
//! observed communicating with the address, `Domain` children for passive-DNS resolutions).
//! The passive-DNS children carry a caveat in their note for a reason its module doc spells
//! out — on shared infrastructure a resolution is somebody else's traffic, and unlike a
//! certificate log there is no scoping rule that can tell the two apart.
//!
//! ## Three waves, now built end to end
//!
//! The design is a 3-wave workflow: **Wave 1** geo/ASN, **Wave 2** reputation, **Wave 3**
//! ports *only if wave 2 flags*.
//!
//! - **Wave 1** (`breadth` + `asn-derived` phases) — [`ipinfo`] and [`internetdb`] answer
//!   keyless; [`peeringdb`] runs on the ASN [`ipinfo`] hands off (see
//!   [`crate::layer_plan::Handoff`]); [`maxmind`] runs alongside them on a local MMDB, gated on
//!   `MAXMIND_LICENSE_KEY` only for its one-off download, not for the lookup itself.
//! - **Wave 2** (`reputation` phase, unconditional) — [`abuseipdb`], [`virustotal`] and
//!   [`greynoise`] all need a free key and are all built. [`internetdb`] stays wave 1's own
//!   member; it reports *exposure*, not reputation, and still writes no `abuseScore`/
//!   `classification` of its own — those are now genuinely owned by wave 2's tools.
//! - **Wave 3** (`sidecar-sweep` + `deep-recon` phases, both gated on
//!   [`crate::layer_plan::reputation_flagged`]) — [`censys`] and [`netlas`] join the
//!   pre-existing `ip-spiderfoot` sweep. Shodan's paid tier is the one wave-3 source that
//!   stays unbuilt.
//!
//! ## `reputation_flagged()` is reachable now, 2026-08-25
//!
//! `layer_plan::reputation_flagged()` was a fully-built, tested predicate with no caller —
//! nothing wrote [`crate::layer_plan::FACT_ABUSE_SCORE`], the fact its own threshold reads.
//! [`abuseipdb`] fixes that: every call posts the fact, clean or not (a `0` confidence is a
//! real finding, not an absent measurement). [`virustotal`] and [`greynoise`] join it in the
//! same unconditional **wave 2 / `reputation`** phase, each owning a disjoint slice of
//! [`crate::types::IpPayload`] (`vtMalicious`/`vtReputation`, `classification`). Wave 3 —
//! [`censys`] and [`netlas`], plus the pre-existing `ip-spiderfoot` sidecar sweep — is gated on
//! the predicate they finally feed.
//!
//! [`maxmind`] and PeeringDB's key stay unclaimed by wave 2's phase: MaxMind writes rows only
//! (see its module doc), and PeeringDB keeps its own `asn-derived` phase since its lookup key
//! is a hand-off, not the node's own address.
//!
//! ## Absence
//!
//! Every routable address is a valid address, so absence here is never "no such entity". Both
//! endpoints answer a `404` for an address they hold nothing on — mapped to
//! [`crate::outcome::ToolOutcome::OkEmpty`], because "Shodan has never scanned this host" is a
//! finding about the host and not a failure to look.

pub mod abuseipdb;
pub mod censys;
pub mod greynoise;
pub mod internetdb;
pub mod ipinfo;
pub mod maxmind;
pub mod netlas;
pub mod peeringdb;
pub mod virustotal;

#[cfg(test)]
mod live_tests {
    //! `#[ignore]`d tests that actually call both endpoints.
    //!
    //! Same reasoning as the other categories': every other test here runs against fixtures
    //! transcribed by hand from a live call, and only this can catch an upstream changing
    //! shape. Shape and plausibility only — a host's open ports are a moving target.
    //!
    //! `cargo test -p ozint -- --ignored`

    use crate::outcome::ToolOutcome;
    use crate::sources::{DispatchOutcome, ToolCtx};

    /// Google Public DNS. Anycast, stable for a decade, and present in both services.
    const SUBJECT: &str = "8.8.8.8";

    /// `scanme.nmap.org` — the host Nmap operates expressly to be scanned. The only address
    /// this project will assert has open ports and known vulnerabilities, because its operator
    /// publishes it for exactly that.
    const SCANNABLE: &str = "45.33.32.156";

    /// A Tor exit relay, which Shodan tags `tor`. The one address that exercises the
    /// anonymizer flag end to end — the input `reputation_flagged()` waits on.
    const TOR_EXIT: &str = "185.220.101.1";

    fn produced(outcome: DispatchOutcome) -> crate::registry::ToolYield {
        match outcome {
            DispatchOutcome::Ran(o, produced) => {
                assert!(
                    matches!(o, ToolOutcome::OkWithResults { .. } | ToolOutcome::OkEmpty),
                    "endpoint answered with a non-Ok outcome: {o:?}"
                );
                produced.expect("an Ok outcome must carry a yield")
            }
            DispatchOutcome::Cancelled => panic!("nothing cancelled this"),
        }
    }

    #[tokio::test]
    #[ignore = "hits two live third-party endpoints"]
    async fn the_ip_endpoints_still_answer_the_shape_we_parse() {
        let ctx = ToolCtx::default();

        let info = produced(super::ipinfo::run_ipinfo(SUBJECT, &ctx).await);
        assert_eq!(info.payload_patch["country"], "US");
        assert!(
            info.payload_patch["asn"]
                .as_str()
                .is_some_and(|s| s.starts_with("AS"))
        );
        assert!(
            info.payload_patch["isp"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        // `loc` is one `"lat,lon"` string; a split that silently fails would leave both
        // unset and look identical to an address with no location.
        assert!(info.payload_patch["lat"].as_f64().is_some());
        assert!(info.payload_patch["lon"].as_f64().is_some());
        assert!(
            info.payload_patch.get("ports").is_none(),
            "ipinfo must not write ports — ip-internetdb owns them"
        );

        let db = produced(super::internetdb::run_internetdb(SCANNABLE, &ctx).await);
        let ports = db.payload_patch["ports"].as_array().expect("open ports");
        assert!(
            !ports.is_empty(),
            "scanme.nmap.org exists to have open ports"
        );
        assert!(
            db.payload_patch.get("country").is_none(),
            "internetdb must not write geo fields — ip-ipinfo owns them"
        );
        assert!(
            db.payload_patch.get("abuseScore").is_none(),
            "InternetDB reports exposure, never reputation — an abuse score here would be invented"
        );
        // The CVEs it reports become pivots; anything else would strand them in a row.
        assert!(
            db.children
                .iter()
                .all(|c| c.oz_type == crate::types::OzType::Cve),
            "only vulns become children — a hostname pointed at an IP is not owned by it"
        );
        assert!(
            !db.children.is_empty(),
            "this host has published vulnerabilities"
        );
    }

    #[tokio::test]
    #[ignore = "hits two live third-party endpoints, and spends PeeringDB's one-per-minute quota"]
    async fn the_hand_off_carries_an_asn_from_ipinfo_to_peeringdb() {
        // The whole mechanism, end to end against the real endpoints: wave 1 learns the AS,
        // wave 2 looks it up. Deliberately *not* asserting the record's contents — a network's
        // IX count is a moving target — only that the value crossed the wave boundary and
        // produced a real answer rather than the typed skip.
        let ctx = ToolCtx::default();

        let info = produced(super::ipinfo::run_ipinfo(SUBJECT, &ctx).await);
        let asn = info
            .values
            .iter()
            .find(|(k, _)| *k == crate::layer_plan::INPUT_ASN)
            .map(|(_, v)| v.clone())
            .expect("ip-ipinfo must publish the ASN for the next wave");
        assert!(
            asn.starts_with("AS"),
            "the hand-off carries the AS-prefixed form: {asn}"
        );

        let mut handoff = crate::layer_plan::Handoff::new();
        handoff.insert(crate::layer_plan::INPUT_ASN.to_string(), asn);
        let ctx = ToolCtx {
            handoff,
            ..Default::default()
        };

        let net = produced(super::peeringdb::run_peeringdb(SUBJECT, &ctx).await);
        assert!(
            net.payload_patch
                .as_object()
                .is_some_and(serde_json::Map::is_empty),
            "PeeringDB owns no IpPayload field"
        );
        // AS15169 is one of the most thoroughly documented records PeeringDB holds; if this is
        // empty, the endpoint changed shape rather than the network having gone quiet.
        assert!(
            !net.rows.is_empty(),
            "Google's network record must produce rows"
        );
    }

    #[tokio::test]
    #[ignore = "hits a live third-party endpoint"]
    async fn a_tor_exit_sets_the_flag_wave_three_waits_on() {
        let db = produced(
            super::internetdb::run_internetdb(TOR_EXIT, &crate::sources::ToolCtx::default()).await,
        );
        assert_eq!(db.payload_patch["anonymizer"], true);
        assert!(
            db.flags
                .contains(&(crate::layer_plan::FLAG_ANONYMIZER, true)),
            "the flag must reach the phase accumulator, not only the payload"
        );
    }
}
