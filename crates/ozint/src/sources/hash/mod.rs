//! `entity-hash (SHA)` — file-hash reputation and sandbox lookups.
//!
//! Six tools across two tiers, every one verified by direct call on 2026-08-25 against the
//! EICAR test file's SHA-256
//! (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` — a real, universally
//! detected antivirus test string, safe to query) and a random 64-hex-char string with no
//! known meaning, to see both the "detected" and "nobody has ever seen this" shapes.
//!
//! ## Field ownership is the design, same as `cve::mod`'s doc
//!
//! `runtime::merge_patch` is a shallow, last-writer-wins merge, so two tools writing the same
//! [`crate::types::HashPayload`] field is a silent overwrite, not a conflict anyone would see.
//! The fan-out is built so no field has two writers:
//!
//! | tool | writes | and nothing else |
//! |---|---|---|
//! | [`virustotal`] | `md5`, `sha1`, `sha256`, `detections`, `engines_total` | ✓ |
//! | [`malwarebazaar`] | `fileType`, `firstSeen`, `family` | ✓ |
//! | [`otx`] | `pulseCount` | ✓ |
//! | [`urlhaus`] | `distribution_urls` | ✓ (tier 1, a pivot to hosting infra) |
//! | [`hybrid_analysis`] | `sandboxVerdict`, `sandboxReports` | ✓ (tier 2 only) |
//! | [`polyswarm`] | `polyswarmScore` | ✓ (tier 2 only) |
//!
//! `virustotal` is the only tool that posts [`crate::layer_plan::FACT_DETECTIONS`] — it is the
//! one source in tier 1 whose "how many engines flagged this" number is a real multi-engine
//! consensus, and the tier-2 escalation predicate needs exactly one owner for that fact, the
//! same reason `cve-nvd` is the sole poster of `FLAG_AUTHORITATIVE_ANSWERED`.
//!
//! ## The escalation direction is the opposite of `cve_plan`'s
//!
//! `cve_plan`'s second phase opens when the source of record stayed **silent**
//! (`authoritative_source_silent`). This category's second phase opens when tier 1 found
//! **something** — [`crate::layer_plan::has_detections`], already declared in `layer_plan.rs`
//! ahead of this unit being built, gated at `HASH_TIER2_MIN_DETECTIONS` (3 engines, the same
//! number `signal.rs`'s chip rule uses so escalation and colour agree). Spending two more
//! keyed lookups on a hash nothing flagged would be exactly the wasted-fan-out mistake
//! `authoritative_source_silent` exists to prevent in the other direction — here the waste
//! runs the other way, so the predicate does too.
//!
//! ## What this unit deliberately does not build
//!
//! For this entity type, tier 1 is VirusTotal+MalwareBazaar+OTX and tier 2 is
//! Hybrid-Analysis+PolySwarm — both built here. Two more branches are deliberately **not**:
//!
//! - **Tier 3 (Triage / Joe Sandbox), gated on "no family consensus".** Neither source has a
//!   free key held in this repo's env table, and inventing a "family consensus" heuristic
//!   across tier 1/2's disjoint family-ish fields (`family`, OTX's pulse-level tags,
//!   PolySwarm's per-engine `malware_family` metadata) would be exactly the kind of
//!   uncorroborated blend this codebase avoids elsewhere — a real consensus needs a defined
//!   algorithm this unit was not asked to invent.
//! - **The non-malware branch (Hashes.com, rainbow-table reversal).** Deliberately out of
//!   scope: paid and ethically gated, and the "Autofire = full
//!   consent" decision means it would need product sign-off before a per-tool confirm dialog
//!   or auto-fire path exists at all. `layer_plan::not_malware()` is declared and unused for
//!   the same reason `enough_confirmed_hits()` sits unwired on `username_plan` — the predicate
//!   is ready, the phase behind it is not.
//!
//! Both are left **unwired rather than added as empty phases**, per `plans.rs`'s own module
//! doc: an empty phase would inflate `max_possible`'s denominator and report a skip for zero
//! tools, telling the analyst a cascade was held back when nothing is actually behind it.
//!
//! **Correcting a stale claim.** An earlier version of this doc comment said URLhaus was
//! abuse.ch's *URL*-only reputation feed with no hash-lookup endpoint, and used that to justify
//! leaving it unbuilt. That was wrong — `POST /v1/payload/` looks a file up by its own hash,
//! verified live 2026-08-25, and [`urlhaus`] is built on it. What is genuinely true is narrower:
//! URLhaus's tier is the abuse.ch *distribution* graph (which URLs served this payload), not an
//! AV-engine consensus, which is why it joins tier 1 as a field-disjoint addition rather than
//! competing with `virustotal`'s `detections`.

pub mod hybrid_analysis;
pub mod malwarebazaar;
pub mod otx;
pub mod polyswarm;
pub mod urlhaus;
pub mod virustotal;

/// The hash length a normalized value is guaranteed to have — `normalize::normalize_hash`
/// only accepts exactly these three. Shared by [`polyswarm`], the one tool whose endpoint
/// needs the hash *type* as well as the hash itself.
pub(crate) fn hash_kind(value: &str) -> Option<&'static str> {
    match value.len() {
        32 => Some("md5"),
        40 => Some("sha1"),
        64 => Some("sha256"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_kind_reads_length_the_same_way_normalize_hash_classifies_it() {
        assert_eq!(hash_kind(&"a".repeat(32)), Some("md5"));
        assert_eq!(hash_kind(&"a".repeat(40)), Some("sha1"));
        assert_eq!(hash_kind(&"a".repeat(64)), Some("sha256"));
        assert_eq!(hash_kind(&"a".repeat(10)), None);
    }
}
