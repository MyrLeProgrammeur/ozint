//! `entity-cve (CVE)` — the vulnerability sources.
//!
//! Six tools, **all keyless**, every one verified by direct call (five on 2026-08-21, `mitre`
//! on 2026-08-25). `NVD_API_KEY` raises NVD's rate limit from 5 requests per 30 seconds to 50;
//! it does not gate access, so nothing here is blocked on a credential.
//!
//! ## Field ownership is the design
//!
//! `runtime::merge_patch` is a **shallow, last-writer-wins** merge, deliberately — a deep
//! merge would blend two sources' conflicting views of one object, and conflicts belong in the
//! subject file as two visible values, not blended invisibly inside one payload. The
//! consequence for this category is concrete: several of
//! these sources can fill the *same* [`crate::types::CvePayload`] field, and if two of them
//! run in one phase the later one silently overwrites the earlier. Two green tools, one
//! source's value, and nothing anywhere saying they disagreed.
//!
//! So the fan-out is built so that no field has two writers:
//!
//! | tool | writes | and nothing else |
//! |---|---|---|
//! | [`nvd`] | `cvss`, `cvssVersion`, `severity`, `publishedAt`, `summary`, `configurations`, `weaknesses` | ✓ |
//! | [`epss`] | `epss` | ✓ |
//! | [`kev`] | `kev` | ✓ |
//! | [`poc_github`] | `pocUrls` (each entry with `stargazersCount`/`updatedAt`) | ✓ |
//! | [`shodan`] | the same five score/description fields as [`nvd`] | held in a second phase |
//! | [`mitre`] | the same fields as [`nvd`], `configurations`/`weaknesses` reshaped from CVE Record v5 | held in a third phase, behind both |
//!
//! [`shodan`] is the exception that proves the rule. Shodan's CVEDB returns the score, the
//! EPSS probability, the KEV flag and the description in one keyless call — a genuine one-stop,
//! and exactly the wrong thing to run beside the four above. It is held behind
//! `layer_plan::authoritative_source_silent()` (see `plans::cve_plan`) so it only ever fires
//! when NVD came back with nothing, and it drops `epss`/`kev` from its yield unconditionally
//! because those belong to FIRST and CISA directly, not to a second-hand copy of them.
//!
//! [`mitre`] is the last-resort fallback behind Shodan: CVE.org's own CNA record, first-party
//! rather than derived, so it is safe to write `cvss`/`severity`/`summary` directly — but it is
//! still held behind `layer_plan::no_authoritative_or_aggregate_answer()`, one gate further
//! back than Shodan's, so the two fallbacks never both fire in the same run. See `mitre`'s
//! module doc for why.
//!
//! ## Absence is not failure, four times over
//!
//! Every source in this category has a way of saying "I have nothing for this CVE", and in
//! three of them it looks like an error at the HTTP layer. Each is mapped to
//! `ToolOutcome::OkEmpty` in its own module, with the measurement that justifies it:
//!
//! - **NVD**: HTTP **200** with `"vulnerabilities": []`. No mapping needed.
//! - **PoC-in-GitHub**: HTTP **404** — no indexed public exploit, which is the common case.
//! - **Shodan CVEDB**: HTTP **404** with `{"detail":"No information available"}`.
//! - **EPSS**: HTTP **200** with `"total":0,"data":[]`.
//! - **CISA KEV**: present in the catalogue or not; absence means "not known to be exploited
//!   in the wild", which is a finding an analyst acts on.
//!
//! Folding any of those into `ToolOutcome::HttpError` would let `outcome::settle_kind` drag an
//! otherwise clean layer to `Degraded` for the ordinary case of a CVE with no public exploit.
//!
//! ## Two sources considered and deliberately left out
//!
//! - **OSV.dev** — measured: `GET /v1/vulns/CVE-2021-34527` returns **404 `Vulnerability not
//!   found`**, while `CVE-2021-44228` returns 200. OSV indexes open-source *package*
//!   ecosystems, so it has no record for the large majority of CVEs; the lookup it is actually
//!   good at is package→CVE dispatch, the *reverse* direction, which needs a package name a
//!   CVE node does not have. Its unique content — GHSA aliases, affected version ranges — has
//!   no field in `CvePayload`.
//! - **MITRE ATT&CK STIX bundle** — no official CVE↔technique mapping exists, so using it
//!   would mean inventing a best-effort correlation nobody publishes, rendered beside sourced
//!   facts as if it were one.

pub mod epss;
pub mod kev;
pub mod mitre;
pub mod nvd;
pub mod poc_github;
pub mod shodan;

#[cfg(test)]
mod live_tests {
    //! One `#[ignore]`d test that actually calls all five endpoints.
    //!
    //! Every other test in this category runs against inline fixtures transcribed by hand from
    //! a real response, and a transcription is exactly the kind of thing that can be subtly
    //! wrong — or right on the day it was written and wrong six months later. This test is the
    //! only thing in the crate that can catch an upstream changing shape, and it is `#[ignore]`d
    //! for the reason the repo already ignores `local_embedder`: a unit suite that reaches the
    //! network fails on a plane, in a sandbox, and whenever someone else's server has a bad
    //! afternoon.
    //!
    //! Run it deliberately:
    //! `cargo test -p ozint -- --ignored cve_endpoints_still_answer_the_shape_we_parse`
    //!
    //! It asserts *shape and plausibility*, never exact values — a CVSS score is not ours to
    //! pin, and an EPSS probability changes daily.

    use crate::outcome::ToolOutcome;
    use crate::sources::{DispatchOutcome, ToolCtx};

    /// The Print Spooler RCE ("PrintNightmare"): scored, in KEV, high EPSS, public PoCs, and
    /// old enough that none of that will change. It is also the CVE whose NVD record carries a
    /// CVSS v2 `Primary` alongside two v3.1 `Secondary` entries, which is the metric-selection
    /// trap `nvd::select_metric` exists for.
    const SUBJECT: &str = "CVE-2021-34527";

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
    #[ignore = "hits five live third-party endpoints"]
    async fn cve_endpoints_still_answer_the_shape_we_parse() {
        let ctx = ToolCtx::default();
        let nvd = patch(super::nvd::run_nvd(SUBJECT, &ctx).await);
        assert!(nvd["cvss"].as_f64().expect("NVD still returns a score") > 0.0);
        assert!(
            nvd["cvssVersion"]
                .as_str()
                .expect("a score must carry its scale")
                .starts_with('3'),
            "expected the v3 branch to win over the v2 Primary, got {:?}",
            nvd["cvssVersion"]
        );
        assert!(nvd["summary"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(nvd["publishedAt"].as_str().is_some());

        let epss = patch(super::epss::run_epss(SUBJECT, &ctx).await);
        let score = epss["epss"]
            .as_f64()
            .expect("EPSS still returns a parseable score");
        assert!((0.0..=1.0).contains(&score), "EPSS out of range: {score}");
        assert!(
            score > 0.5,
            "PrintNightmare's EPSS should stay high, got {score}"
        );

        let kev = patch(super::kev::run_kev(SUBJECT, &ctx).await);
        assert_eq!(
            kev["kev"],
            serde_json::json!(true),
            "PrintNightmare is in the KEV catalogue"
        );

        let poc = patch(super::poc_github::run_poc_github(SUBJECT, &ctx).await);
        assert!(
            !poc["pocUrls"]
                .as_array()
                .expect("PoC index still lists repos")
                .is_empty(),
            "PrintNightmare has public PoC repos"
        );

        let shodan = patch(super::shodan::run_shodan(SUBJECT, &ctx).await);
        assert!(shodan["cvss"].as_f64().is_some_and(|s| s > 0.0));
        assert!(shodan["severity"].as_str().is_some());
        // The field-ownership rule, checked against the live body rather than a fixture: the
        // response genuinely contains `epss` and `kev`, and this tool must still drop them.
        assert!(shodan.get("epss").is_none(), "shodan must not write epss");
        assert!(shodan.get("kev").is_none(), "shodan must not write kev");
    }

    #[tokio::test]
    #[ignore = "hits three live third-party endpoints"]
    async fn absence_reads_as_absence_and_never_as_failure() {
        // The three endpoints that express "I have nothing for this CVE" as something that
        // looks like an error at the HTTP layer. A regression here is invisible in the unit
        // tests, because the fixtures cannot reproduce a status code.
        const UNKNOWN: &str = "CVE-2021-99999";
        let ctx = ToolCtx::default();
        for outcome in [
            super::nvd::run_nvd(UNKNOWN, &ctx).await,
            super::epss::run_epss(UNKNOWN, &ctx).await,
            super::poc_github::run_poc_github(UNKNOWN, &ctx).await,
            super::shodan::run_shodan(UNKNOWN, &ctx).await,
        ] {
            match outcome {
                DispatchOutcome::Ran(ToolOutcome::OkEmpty, _) => {}
                other => panic!("an unknown CVE must read as OkEmpty, got {other:?}"),
            }
        }
    }
}
