//! `entity-domain (DOM)` — the domain sources.
//!
//! Four tools — three keyless (2026-08-21) plus [`virustotal`], free-key (2026-08-25). This
//! category is graded "yes-with-free-key" overall; measured, the other keys under
//! consideration (Hunter.io, and the paid tier) buy *additional* sources, not access to the
//! three keyless ones — [`virustotal`] is the first key here that genuinely gates a real
//! source rather than just raising a rate limit.
//!
//! ## Field ownership
//!
//! `runtime::merge_patch` is a shallow last-writer-wins merge, so two tools writing one
//! [`crate::types::DomainPayload`] key is a silent overwrite. The fan-out is built so no field
//! has two writers:
//!
//! | tool | writes |
//! |---|---|
//! | [`rdap`] | `registrar`, `createdAt` |
//! | [`dns`] | `mx`, `ns` |
//! | [`certspotter`] | `subdomains`, `subdomainsTruncated` |
//! | [`virustotal`] | `vtMalicious`, `vtReputation` |
//!
//! The one that took a decision rather than an inventory: RDAP's record *also* carries
//! `nameservers`, and it deliberately does not write `ns`. The registry's delegation record and
//! the zone's live answer are different facts that diverge exactly when it matters — a domain
//! mid-migration serves new nameservers before the registry reflects them — and an analyst
//! asking where a domain resolves wants the live answer. Letting both write `ns` would not
//! surface the disagreement; it would pick whichever finished second.
//!
//! ## Children
//!
//! Only [`certspotter`] emits any, capped by [`crate::types::MAX_SUBDOMAIN_CHILDREN`]. MX and
//! NS hosts are pointedly *not* children: `aspmx.l.google.com` and `randy.ns.cloudflare.com`
//! belong to third-party providers, and seeding them would grow the analyst's tree with
//! Google's and Cloudflare's infrastructure instead of the subject's.
//!
//! ## crt.sh is missing, and that is a measurement
//!
//! crt.sh is the obvious certificate-transparency source, and it is deliberately not used here.
//! On 2026-08-21 it answered **502 on every path tried, including its own front page**, across
//! repeated attempts, and later stopped completing the connection at all. Its response shape
//! could not be verified by direct call, and this crate does not write parsers against
//! remembered shapes. [`certspotter`] covers the same capability, keyless, and was verified.
//! When crt.sh recovers it belongs in a **second phase** behind
//! `layer_plan::authoritative_source_silent()` — never beside `dom-certspotter`, since both
//! write `subdomains`.
//!
//! ## Absence, again, in three different disguises
//!
//! - **RDAP**: HTTP **404** for a domain that is not registered — a positive finding.
//! - **CertSpotter**: HTTP **200** with an empty array.
//! - **DNS**: HTTP **200** carrying a DNS **rcode**. `0` (NOERROR) with no `Answer`, and `3`
//!   (NXDOMAIN), are both absence. Any other rcode is a failure, because a resolver that
//!   refused us taught us nothing and "no MX records" would be a lie.

pub mod certspotter;
pub mod dns;
pub mod rdap;
pub mod virustotal;

#[cfg(test)]
mod live_tests {
    //! `#[ignore]`d tests that actually call the three endpoints.
    //!
    //! Same reasoning as `sources::cve`'s: every other test here runs against fixtures
    //! transcribed by hand, and a transcription can be subtly wrong or quietly go stale. This
    //! is the only thing that can catch an upstream changing shape. In `sources::cve` it
    //! immediately caught a bug 42 unit tests had missed, so it is not a formality.
    //!
    //! `cargo test -p ozint -- --ignored`
    //!
    //! Shape and plausibility only — never exact values. A registrar can change, and a
    //! certificate-transparency page is a moving target by construction.

    use crate::outcome::ToolOutcome;
    use crate::sources::{DispatchOutcome, ToolCtx};

    /// Registered since 2001, on Cloudflare nameservers, Google mail, and with a large,
    /// long-lived certificate-transparency footprint — every field this category reads is
    /// populated and none of it is about to disappear.
    const SUBJECT: &str = "anthropic.com";

    fn patch(outcome: DispatchOutcome) -> serde_json::Value {
        match outcome {
            DispatchOutcome::Ran(o, produced) => {
                assert!(
                    matches!(o, ToolOutcome::OkWithResults { .. } | ToolOutcome::OkEmpty),
                    "endpoint answered with a non-Ok outcome: {o:?}"
                );
                produced
                    .expect("an Ok outcome must carry a yield")
                    .payload_patch
            }
            DispatchOutcome::Cancelled => panic!("nothing cancelled this"),
        }
    }

    #[tokio::test]
    #[ignore = "hits three live third-party endpoints"]
    async fn domain_endpoints_still_answer_the_shape_we_parse() {
        // RDAP also exercises the redirect path end to end: rdap.org is a bootstrap
        // redirector, so this only passes if `ozint_core::http`'s SSRF-screening redirect
        // policy still lets a public-to-public hop through. That policy was written because
        // the guard used to screen only the first hop; a regression that closed redirects
        // entirely would show up right here.
        let ctx = ToolCtx::default();
        let rdap = patch(super::rdap::run_rdap(SUBJECT, &ctx).await);
        assert!(
            rdap["registrar"].as_str().is_some_and(|s| !s.is_empty()),
            "RDAP still returns a registrar (and the bootstrap redirect still resolves)"
        );
        assert!(
            rdap["createdAt"].as_str().is_some(),
            "registration event still present"
        );
        assert!(
            rdap.get("ns").is_none(),
            "rdap must not write ns — dom-dns owns it"
        );

        let dns = patch(super::dns::run_dns(SUBJECT, &ctx).await);
        let mx = dns["mx"].as_array().expect("MX records");
        let ns = dns["ns"].as_array().expect("NS records");
        assert!(!mx.is_empty() && !ns.is_empty());
        for host in mx.iter().chain(ns.iter()) {
            let host = host.as_str().expect("a hostname string");
            assert!(!host.ends_with('.'), "trailing dot not stripped: {host}");
            assert!(!host.is_empty());
            // The preference number must not have survived into the hostname.
            assert!(
                !host.contains(' '),
                "MX preference leaked into the host: {host}"
            );
        }

        let cs = patch(super::certspotter::run_certspotter(SUBJECT, &ctx).await);
        let subs = cs["subdomains"].as_array().expect("subdomains");
        assert!(!subs.is_empty());
        assert!(subs.len() <= crate::types::MAX_SUBDOMAIN_CHILDREN);
        for s in subs {
            let s = s.as_str().expect("a name");
            // The trap this asserts against is real and measured: one page of CertSpotter for
            // `anthropic.com` contains `advancedjs.bitinvestor.net`, an unrelated domain that
            // merely shares a certificate. Unfiltered, it would render as a subdomain.
            assert!(
                s.ends_with(&format!(".{SUBJECT}")),
                "{s} is not under {SUBJECT} — the SAN filter regressed"
            );
            assert!(!s.starts_with('*'), "a wildcard is not a host: {s}");
            assert_ne!(s, SUBJECT, "the subject is not its own subdomain");
        }
    }

    #[tokio::test]
    #[ignore = "hits three live third-party endpoints"]
    async fn an_unregistered_domain_reads_as_absence_and_never_as_failure() {
        const UNKNOWN: &str = "zzqq-not-a-real-domain-9999.com";
        let ctx = ToolCtx::default();
        for outcome in [
            super::rdap::run_rdap(UNKNOWN, &ctx).await,
            super::dns::run_dns(UNKNOWN, &ctx).await,
            super::certspotter::run_certspotter(UNKNOWN, &ctx).await,
        ] {
            match outcome {
                DispatchOutcome::Ran(ToolOutcome::OkEmpty, _) => {}
                other => panic!("an unregistered domain must read as OkEmpty, got {other:?}"),
            }
        }
    }
}
