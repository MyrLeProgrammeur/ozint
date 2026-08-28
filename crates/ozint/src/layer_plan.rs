//! The phased fan-out primitive every orchestrator expresses its conditional cascade in.
//!
//! A layer is not one flat burst of tools. IP fires three waves (geo/ASN → reputation →
//! ports, the last only if reputation flagged); email triages before it sweeps; hash walks
//! three tiers; username only opens its deep phase at ≥3 confirmed hits. All of that is the
//! same shape: **an ordered list of phases, each with a predicate over what earlier phases
//! accumulated.**
//!
//! This module exists so that shape lives in exactly one place. The IP wave-3 condition
//! ("only when wave 2 flags") needs one exact, shared rule, not something invented ad hoc per
//! orchestrator. The named predicates below are that shared vocabulary — an orchestrator picks
//! one, it does not write its own threshold.
//!
//! Deliberately pure control flow: no I/O, no async, no knowledge of what a tool *is*
//! beyond its id. Executing a plan is `runtime.rs`'s job.

use std::collections::BTreeMap;

/// What a phase's predicate gets to look at: everything the phases before it produced.
///
/// Deliberately not `Vec<OzNode>`. A predicate needs to ask coarse questions ("did anything
/// look malicious?", "did we confirm at least three sites?"), and giving it the full node
/// list invites orchestrators to reach into payloads and re-derive thresholds locally —
/// exactly the ad-hoc drift this unit exists to prevent. Facts are posted here by the
/// runtime under well-known keys instead.
#[derive(Debug, Clone, Default)]
pub struct PhaseAcc {
    /// Tool ids that have completed, whatever their outcome.
    pub tools_run: Vec<String>,
    /// Tool ids that returned at least one usable result.
    pub tools_with_results: Vec<String>,
    /// Children emitted so far by this layer.
    pub children: usize,
    /// Numeric facts posted by earlier phases, e.g. `abuse-score`, `detections`,
    /// `confirmed-sites`, `breach-count`.
    pub facts: BTreeMap<String, f64>,
    /// Boolean facts posted by earlier phases, e.g. `anonymizer`, `malicious`, `freemail`.
    pub flags: BTreeMap<String, bool>,
    /// **The sibling hand-off.** String values one tool discovered that a *later wave's* tool
    /// needs as its own lookup key — see [`Handoff`] for the whole rationale.
    pub values: BTreeMap<String, HandoffValue>,
}

/// A value published for a later wave, and who published it.
///
/// `from` is carried because a hand-off is a provenance claim as much as a value: a tool that
/// ran on an ASN did not learn that ASN itself, and the report has to be able to say where it
/// came from.
#[derive(Debug, Clone, PartialEq)]
pub struct HandoffValue {
    pub value: String,
    /// The tool id that published it.
    pub from: String,
    /// Set when a second tool published a *different* value for the same key. The value then
    /// stops being readable — see [`PhaseAcc::value`].
    pub disputed_by: Option<(String, String)>,
}

/// What a later wave's tools may read: the flat, unambiguous subset of [`PhaseAcc::values`].
///
/// **Why a snapshot and not a live handle.** `LayerPhase`'s own doc says order within a phase
/// is irrelevant because a phase fans out in parallel; today `fire_layer` happens to run a
/// phase's tools one after another, but nothing in the contract promises that and a future
/// `join_all` would be a legal change. A tool that read a live accumulator would therefore work
/// by accident of the current loop and break silently the day the fan-out becomes concurrent.
/// So the runtime freezes this map once, at phase start, and every tool in the phase sees
/// exactly what the phases *before* it published — a guarantee the plan already makes.
///
/// The consequence, stated plainly so nobody looks for it: **there is no intra-wave hand-off.**
/// A tool that needs a sibling's output goes in a later phase. That is one line in an
/// orchestrator, and it buys an ordering guarantee that actually exists.
pub type Handoff = BTreeMap<String, String>;

/// Why a hand-off input is not readable. Distinct cases because they call for different
/// sentences in the tool report: nobody produced it, versus two tools disagreed about it.
#[derive(Debug, Clone, PartialEq)]
pub enum ValueStatus<'a> {
    /// No earlier wave published this key.
    Absent,
    /// Exactly one value, from `from`.
    Ready { value: &'a str, from: &'a str },
    /// Two tools published different values. Deliberately **not** resolved: picking one would
    /// be the invisible blend this codebase refuses to make, and picking the last would make
    /// the hand-off depend on tool ordering — the precise trap `runtime::merge_patch` already
    /// sprang once on `entity-directory`.
    Disputed {
        first: (&'a str, &'a str),
        second: (&'a str, &'a str),
    },
}

// ─── Well-known hand-off keys ──────────────────────────────────────────────
// Same discipline as the fact/flag keys above: a constant, so a typo is a compile error and
// not a tool that is skipped for a missing input forever.

/// The autonomous system number, `AS`-prefixed (`"AS15169"`). Published by the tool that
/// resolves an address to its network; consumed by every source keyed on the AS rather than on
/// the address — PeeringDB is the first.
pub const INPUT_ASN: &str = "asn";

impl PhaseAcc {
    /// Publishes a hand-off value on behalf of `from`.
    ///
    /// First writer wins, and a *disagreeing* second writer poisons the key rather than
    /// overwriting it. Two tools re-publishing the same value is not a conflict — it is
    /// corroboration, and the first publisher keeps the attribution.
    pub fn set_value(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
        from: impl Into<String>,
    ) {
        let (key, value, from) = (key.into(), value.into(), from.into());
        match self.values.get_mut(&key) {
            None => {
                self.values.insert(
                    key,
                    HandoffValue {
                        value,
                        from,
                        disputed_by: None,
                    },
                );
            }
            Some(held) if held.value == value => {}
            Some(held) => {
                // Keep the first dispute: the point is that the key is unusable, and the
                // report only needs one concrete example of who disagreed with whom.
                held.disputed_by.get_or_insert((from, value));
            }
        }
    }

    /// The readable value for `key`, or `None` when it is absent or disputed. Callers wanting
    /// to explain *which* use [`PhaseAcc::value_status`].
    pub fn value(&self, key: &str) -> Option<&str> {
        match self.value_status(key) {
            ValueStatus::Ready { value, .. } => Some(value),
            _ => None,
        }
    }

    pub fn value_status(&self, key: &str) -> ValueStatus<'_> {
        match self.values.get(key) {
            None => ValueStatus::Absent,
            Some(HandoffValue {
                value,
                from,
                disputed_by: None,
            }) => ValueStatus::Ready { value, from },
            Some(HandoffValue {
                value,
                from,
                disputed_by: Some((other_from, other_value)),
            }) => ValueStatus::Disputed {
                first: (from, value),
                second: (other_from, other_value),
            },
        }
    }

    /// The frozen view a phase's tools get. Disputed keys are simply absent from it — a tool
    /// downstream of a disagreement must be told nothing rather than told one side of it.
    pub fn handoff(&self) -> Handoff {
        self.values
            .iter()
            .filter(|(_, v)| v.disputed_by.is_none())
            .map(|(k, v)| (k.clone(), v.value.clone()))
            .collect()
    }

    pub fn fact(&self, key: &str) -> Option<f64> {
        self.facts.get(key).copied()
    }

    pub fn flag(&self, key: &str) -> bool {
        self.flags.get(key).copied().unwrap_or(false)
    }

    pub fn set_fact(&mut self, key: impl Into<String>, value: f64) {
        self.facts.insert(key.into(), value);
    }

    pub fn set_flag(&mut self, key: impl Into<String>, value: bool) {
        self.flags.insert(key.into(), value);
    }
}

// ─── Well-known fact keys ──────────────────────────────────────────────────
// Named constants rather than bare strings so a typo in an orchestrator is a compile error
// instead of a predicate that silently never fires.

/// AbuseIPDB confidence, 0–100.
pub const FACT_ABUSE_SCORE: &str = "abuse-score";
/// Count of AV engines flagging a sample.
pub const FACT_DETECTIONS: &str = "detections";
/// Sites where a handle was confirmed to exist.
pub const FACT_CONFIRMED_SITES: &str = "confirmed-sites";
/// Breaches an address appeared in.
pub const FACT_BREACH_COUNT: &str = "breach-count";
/// The address/IP is behind VPN/proxy/Tor.
pub const FLAG_ANONYMIZER: &str = "anonymizer";
/// A reputation source classified the subject as outright malicious.
pub const FLAG_MALICIOUS: &str = "malicious";
/// The email domain is a free consumer provider, so a domain pivot is not worth firing.
pub const FLAG_FREEMAIL: &str = "freemail";
/// A malware verdict exists, so the non-malware (rainbow-table) branch is not applicable.
pub const FLAG_MALWARE: &str = "malware";
/// The category's authoritative source answered with a record. Posted by the one tool that
/// owns a category's core fields (NVD for a CVE), so a later phase can tell "the source of
/// record said nothing" apart from "the source of record was never asked".
pub const FLAG_AUTHORITATIVE_ANSWERED: &str = "authoritative-answered";
/// A category's keyless *aggregator* fallback (e.g. `cve-shodan`) answered with a record.
/// Posted so a second, later fallback can tell "the aggregator already covered this" apart
/// from "the aggregator was never reached" — see `no_authoritative_or_aggregate_answer`.
pub const FLAG_AGGREGATE_ANSWERED: &str = "aggregate-answered";

// ─── Predicates ────────────────────────────────────────────────────────────

/// Gate on a phase. `Always` is the common case; `When` carries a named, testable rule.
pub enum Predicate {
    Always,
    /// A named rule. The name is carried so a skipped phase can say *why* it was skipped —
    /// `skipped-phase-predicate` is one of the eleven tool outcomes and the UI renders the
    /// reason, so an anonymous closure would lose information the analyst needs.
    When {
        name: &'static str,
        test: Box<dyn Fn(&PhaseAcc) -> bool + Send + Sync>,
    },
}

impl Predicate {
    pub fn holds(&self, acc: &PhaseAcc) -> bool {
        match self {
            Predicate::Always => true,
            Predicate::When { test, .. } => test(acc),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Predicate::Always => "always",
            Predicate::When { name, .. } => name,
        }
    }

    pub fn when(
        name: &'static str,
        test: impl Fn(&PhaseAcc) -> bool + Send + Sync + 'static,
    ) -> Self {
        Predicate::When {
            name,
            test: Box::new(test),
        }
    }
}

impl std::fmt::Debug for Predicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Predicate({})", self.name())
    }
}

// ─── The shared named rules ────────────────────────────────────────────────

/// **The IP wave-3 rule**, owned here and nowhere else.
///
/// "Only when wave 2 flags" needs *one exact, shared rule (abuse score cutoff + anonymizer
/// flags + GreyNoise classification)*, so every wave-3 gate goes through the same predicate
/// instead of re-deriving the threshold. This is it:
/// port-scanning escalates when reputation gave any concrete reason to look closer —
/// an AbuseIPDB confidence at or above the warn boundary, an anonymizer flag, or an
/// outright malicious classification.
///
/// The `25` is not a new number: it is the same AbuseIPDB warn boundary `signal.rs` paints
/// a chip with. Escalation and colour must agree, otherwise the cockpit shows a clean chip
/// while quietly spending a paid Shodan lookup — or the reverse.
pub const ABUSE_ESCALATION_THRESHOLD: f64 = 25.0;

pub fn reputation_flagged() -> Predicate {
    Predicate::when("reputation-flagged", |acc| {
        acc.fact(FACT_ABUSE_SCORE).unwrap_or(0.0) >= ABUSE_ESCALATION_THRESHOLD
            || acc.flag(FLAG_ANONYMIZER)
            || acc.flag(FLAG_MALICIOUS)
    })
}

/// Username phase C (the deep, expensive sweep) opens at **≥3 confirmed hits**, per the
/// plan's `entity-username` bullet. Below that the handle is too thin to be worth a
/// 3100-site dossier run.
pub const USERNAME_DEEP_PHASE_MIN_HITS: f64 = 3.0;

pub fn enough_confirmed_hits() -> Predicate {
    Predicate::when("enough-confirmed-hits", |acc| {
        acc.fact(FACT_CONFIRMED_SITES).unwrap_or(0.0) >= USERNAME_DEEP_PHASE_MIN_HITS
    })
}

/// Email's deep-leak phase only runs once a breach sweep actually hit something.
pub fn has_breach_hits() -> Predicate {
    Predicate::when("has-breach-hits", |acc| {
        acc.fact(FACT_BREACH_COUNT).unwrap_or(0.0) > 0.0
    })
}

/// Email's domain pivot is pointless on a free consumer provider — Hunter.io has no naming
/// pattern for `gmail.com`.
pub fn not_freemail() -> Predicate {
    Predicate::when("not-freemail", |acc| !acc.flag(FLAG_FREEMAIL))
}

/// Hash tier 2 opens above the VirusTotal meaningful-detection boundary. Same `3` as
/// `signal.rs`'s chip rule, for the same reason as the abuse threshold above.
pub const HASH_TIER2_MIN_DETECTIONS: f64 = 3.0;

pub fn has_detections() -> Predicate {
    Predicate::when("has-detections", |acc| {
        acc.fact(FACT_DETECTIONS).unwrap_or(0.0) >= HASH_TIER2_MIN_DETECTIONS
    })
}

/// The non-malware branch (rainbow-table reversal) only makes sense when nothing identified
/// the sample as malware.
pub fn not_malware() -> Predicate {
    Predicate::when("not-malware", |acc| !acc.flag(FLAG_MALWARE))
}

/// A phase that only runs if an earlier one produced nothing — the "we found no family
/// consensus, escalate to a sandbox" shape.
pub fn no_children_yet() -> Predicate {
    Predicate::when("no-children-yet", |acc| acc.children == 0)
}

/// A fallback phase that only opens when the category's source of record produced nothing.
///
/// The shape it exists for: several sources can fill the *same* payload fields, and
/// `runtime::merge_patch` is shallow last-writer-wins, so if two of them run in one phase the
/// later one silently overwrites the earlier — two green tools, one set of values, and no way
/// for the analyst to see that they disagreed. Rather than blend them, which this codebase
/// forbids outright, the aggregator is held in a second phase behind this predicate and only
/// ever writes fields nobody else did.
///
/// It is deliberately **not** `no_children_yet`: a CVE layer produces no children at all, so
/// that predicate would be vacuously true and the fallback would fire on every single
/// investigation, doubling the fan-out and reintroducing exactly the collision it prevents.
pub fn authoritative_source_silent() -> Predicate {
    Predicate::when("authoritative-source-silent", |acc| {
        !acc.flag(FLAG_AUTHORITATIVE_ANSWERED)
    })
}

/// A second-tier fallback that only opens once **both** the source of record and the first
/// aggregator fallback produced nothing. `cve_plan`'s shape: NVD (source of record), then
/// `cve-shodan` (a keyless aggregator, gated on `authoritative_source_silent`), then
/// `cve-mitre` (CVE.org's own CNA record — first-party, not a derived copy). If `cve-mitre`
/// were gated on `authoritative_source_silent` alone it would fire in the same breath as
/// `cve-shodan` whenever NVD stayed silent, and both would then be free to write `cvss`/
/// `severity`/`summary` in the same run — exactly the last-writer-wins collision
/// `authoritative_source_silent`'s own doc comment exists to prevent, just one level down.
/// Requiring `cve-shodan` to have *also* answered nothing keeps the two fallbacks strictly
/// ordered rather than blended.
pub fn no_authoritative_or_aggregate_answer() -> Predicate {
    Predicate::when("no-authoritative-or-aggregate-answer", |acc| {
        !acc.flag(FLAG_AUTHORITATIVE_ANSWERED) && !acc.flag(FLAG_AGGREGATE_ANSWERED)
    })
}

// ─── Plan ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct LayerPhase {
    pub id: &'static str,
    pub when: Predicate,
    /// Registry tool ids. Order within a phase is irrelevant — a phase fans out in parallel.
    pub tools: Vec<String>,
}

impl LayerPhase {
    pub fn new(id: &'static str, tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            id,
            when: Predicate::Always,
            tools: tools.into_iter().map(Into::into).collect(),
        }
    }

    pub fn gated_on(mut self, when: Predicate) -> Self {
        self.when = when;
        self
    }
}

#[derive(Debug)]
pub struct LayerPlan {
    pub phases: Vec<LayerPhase>,
}

/// Why a phase will not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseSkip {
    /// Its predicate did not hold. Carries the predicate's name so the UI can say which.
    Predicate(&'static str),
}

impl LayerPlan {
    pub fn new(phases: Vec<LayerPhase>) -> Self {
        Self { phases }
    }

    /// A single unconditional phase — the shape most orchestrators start with.
    pub fn flat(tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::new(vec![LayerPhase::new("main", tools)])
    }

    /// The tools the next runnable phase would fire, given what has accumulated so far.
    /// `None` once every phase has been consumed.
    ///
    /// Returns the *first* not-yet-run phase whose predicate holds, skipping over phases
    /// whose predicate failed. A failed predicate is permanent for this layer: phases are
    /// evaluated once, in order, as the runtime advances — a layer does not loop back to
    /// re-test an earlier phase after a later one posted new facts. That keeps a layer's
    /// fan-out bounded and its cost predictable, which is the whole reason the engine never
    /// auto-recurses in the first place.
    pub fn firing_now(&self, phase_index: usize, acc: &PhaseAcc) -> Option<(usize, &LayerPhase)> {
        self.phases
            .iter()
            .enumerate()
            .skip(phase_index)
            .find(|(_, phase)| phase.when.holds(acc))
    }

    /// Every phase from `phase_index` onward that will *not* run, with its reason. This is
    /// what lets a settled layer state "3 tools skipped: reputation-flagged did not hold"
    /// rather than quietly reporting a smaller fan-out than the analyst expected.
    pub fn skipped_from(
        &self,
        phase_index: usize,
        acc: &PhaseAcc,
    ) -> Vec<(&LayerPhase, PhaseSkip)> {
        self.phases
            .iter()
            .skip(phase_index)
            .filter(|phase| !phase.when.holds(acc))
            .map(|phase| (phase, PhaseSkip::Predicate(phase.when.name())))
            .collect()
    }

    /// Total tools across every phase, conditional ones included — the denominator behind
    /// "fired 6 of a possible 14". Reporting only the tools that actually ran would hide
    /// the conditional cascade from the analyst.
    pub fn max_possible(&self) -> usize {
        self.phases.iter().map(|p| p.tools.len()).sum()
    }

    /// How many of this plan's tools are ethically gated.
    ///
    /// Takes the gated test as a parameter rather than importing the registry: this module
    /// stays pure control flow, and the registry is the single source of truth for what
    /// `gated` means.
    pub fn gated_count(&self, is_gated: impl Fn(&str) -> bool) -> usize {
        self.phases
            .iter()
            .flat_map(|p| p.tools.iter())
            .filter(|id| is_gated(id))
            .count()
    }

    /// Every tool id in the plan, in phase order.
    pub fn all_tools(&self) -> Vec<&str> {
        self.phases
            .iter()
            .flat_map(|p| p.tools.iter())
            .map(String::as_str)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc_with(facts: &[(&str, f64)], flags: &[(&str, bool)]) -> PhaseAcc {
        let mut acc = PhaseAcc::default();
        for (k, v) in facts {
            acc.set_fact(*k, *v);
        }
        for (k, v) in flags {
            acc.set_flag(*k, *v);
        }
        acc
    }

    #[test]
    fn a_flat_plan_fires_everything_at_once() {
        let plan = LayerPlan::flat(["a", "b", "c"]);
        let acc = PhaseAcc::default();
        let (idx, phase) = plan.firing_now(0, &acc).expect("first phase fires");
        assert_eq!(idx, 0);
        assert_eq!(phase.tools.len(), 3);
        assert_eq!(plan.max_possible(), 3);
        assert!(
            plan.firing_now(1, &acc).is_none(),
            "nothing left after the only phase"
        );
    }

    #[test]
    fn abuse_score_escalates_at_exactly_25() {
        let p = reputation_flagged();
        assert!(!p.holds(&acc_with(&[(FACT_ABUSE_SCORE, 24.0)], &[])));
        assert!(p.holds(&acc_with(&[(FACT_ABUSE_SCORE, 25.0)], &[])));
        assert!(p.holds(&acc_with(&[(FACT_ABUSE_SCORE, 99.0)], &[])));
    }

    #[test]
    fn anonymizer_or_malicious_escalates_on_a_clean_score() {
        let p = reputation_flagged();
        assert!(!p.holds(&acc_with(&[(FACT_ABUSE_SCORE, 0.0)], &[])));
        assert!(p.holds(&acc_with(
            &[(FACT_ABUSE_SCORE, 0.0)],
            &[(FLAG_ANONYMIZER, true)]
        )));
        assert!(p.holds(&acc_with(
            &[(FACT_ABUSE_SCORE, 0.0)],
            &[(FLAG_MALICIOUS, true)]
        )));
    }

    #[test]
    fn an_absent_fact_never_escalates() {
        // A wave-2 tool that died must not open wave 3 by accident — a missing fact is not
        // a zero-risk finding, but it is certainly not evidence to spend a paid lookup on.
        assert!(!reputation_flagged().holds(&PhaseAcc::default()));
        assert!(!has_detections().holds(&PhaseAcc::default()));
        assert!(!enough_confirmed_hits().holds(&PhaseAcc::default()));
    }

    #[test]
    fn username_deep_phase_opens_at_three_hits() {
        let p = enough_confirmed_hits();
        assert!(!p.holds(&acc_with(&[(FACT_CONFIRMED_SITES, 2.0)], &[])));
        assert!(p.holds(&acc_with(&[(FACT_CONFIRMED_SITES, 3.0)], &[])));
    }

    #[test]
    fn hash_tier_two_opens_at_three_detections() {
        let p = has_detections();
        assert!(!p.holds(&acc_with(&[(FACT_DETECTIONS, 2.0)], &[])));
        assert!(p.holds(&acc_with(&[(FACT_DETECTIONS, 3.0)], &[])));
    }

    #[test]
    fn a_failed_predicate_skips_its_phase_and_names_the_reason() {
        let plan = LayerPlan::new(vec![
            LayerPhase::new("wave-1", ["ipinfo"]),
            LayerPhase::new("wave-2", ["abuseipdb"]),
            LayerPhase::new("wave-3", ["shodan", "censys"]).gated_on(reputation_flagged()),
        ]);
        let clean = acc_with(&[(FACT_ABUSE_SCORE, 3.0)], &[]);

        // wave-3 is unreachable on a clean IP...
        assert!(plan.firing_now(2, &clean).is_none());
        let skipped = plan.skipped_from(2, &clean);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].1, PhaseSkip::Predicate("reputation-flagged"));

        // ...but the denominator still admits it existed.
        assert_eq!(plan.max_possible(), 4);

        let dirty = acc_with(&[(FACT_ABUSE_SCORE, 80.0)], &[]);
        let (idx, phase) = plan
            .firing_now(2, &dirty)
            .expect("wave 3 opens on a flagged IP");
        assert_eq!(idx, 2);
        assert_eq!(phase.tools, vec!["shodan", "censys"]);
        assert!(plan.skipped_from(2, &dirty).is_empty());
    }

    #[test]
    fn firing_now_jumps_over_a_dead_phase_to_the_next_live_one() {
        let plan = LayerPlan::new(vec![
            LayerPhase::new("triage", ["emailrep"]),
            LayerPhase::new("domain-pivot", ["hunter"]).gated_on(not_freemail()),
            LayerPhase::new("always-last", ["gravatar"]),
        ]);
        let freemail = acc_with(&[], &[(FLAG_FREEMAIL, true)]);
        let (idx, phase) = plan
            .firing_now(1, &freemail)
            .expect("skips the pivot, runs the tail");
        assert_eq!(idx, 2);
        assert_eq!(phase.id, "always-last");
    }

    #[test]
    fn gated_count_asks_the_caller_what_gated_means() {
        let plan = LayerPlan::new(vec![
            LayerPhase::new("free", ["emailrep", "breachdirectory"]),
            LayerPhase::new("paid", ["dehashed", "leakcheck"]),
        ]);
        let gated = |id: &str| matches!(id, "dehashed" | "leakcheck");
        assert_eq!(plan.gated_count(gated), 2);
        assert_eq!(plan.gated_count(|_| false), 0);
        assert_eq!(plan.all_tools().len(), 4);
    }

    // ─── The sibling hand-off ──────────────────────────────────────────────

    #[test]
    fn a_published_value_is_readable_with_its_publisher() {
        let mut acc = PhaseAcc::default();
        acc.set_value(INPUT_ASN, "AS15169", "ip-ipinfo");
        assert_eq!(acc.value(INPUT_ASN), Some("AS15169"));
        assert_eq!(
            acc.value_status(INPUT_ASN),
            ValueStatus::Ready {
                value: "AS15169",
                from: "ip-ipinfo"
            }
        );
        assert_eq!(
            acc.handoff().get(INPUT_ASN).map(String::as_str),
            Some("AS15169")
        );
    }

    #[test]
    fn an_unpublished_key_is_absent_not_empty() {
        let acc = PhaseAcc::default();
        assert_eq!(acc.value(INPUT_ASN), None);
        assert_eq!(acc.value_status(INPUT_ASN), ValueStatus::Absent);
        assert!(acc.handoff().is_empty());
    }

    #[test]
    fn two_tools_agreeing_is_corroboration_and_the_first_keeps_the_attribution() {
        let mut acc = PhaseAcc::default();
        acc.set_value(INPUT_ASN, "AS15169", "ip-ipinfo");
        acc.set_value(INPUT_ASN, "AS15169", "ip-other");
        assert_eq!(
            acc.value_status(INPUT_ASN),
            ValueStatus::Ready {
                value: "AS15169",
                from: "ip-ipinfo"
            },
            "a second tool reporting the same value must not poison the key"
        );
    }

    #[test]
    fn two_tools_disagreeing_makes_the_key_unreadable_rather_than_last_writer_wins() {
        // The property the whole hand-off rests on. `runtime::merge_patch` resolves a
        // collision by taking whoever wrote last, which made a tool's output depend on the
        // order its siblings happened to run in — the trap `entity-directory` had to be
        // restructured around. A hand-off must not reintroduce it, so a disagreement is
        // surfaced and the value withheld, never silently arbitrated.
        let mut acc = PhaseAcc::default();
        acc.set_value(INPUT_ASN, "AS15169", "ip-ipinfo");
        acc.set_value(INPUT_ASN, "AS36040", "ip-other");

        assert_eq!(
            acc.value(INPUT_ASN),
            None,
            "a disputed value must not be readable"
        );
        assert_eq!(
            acc.value_status(INPUT_ASN),
            ValueStatus::Disputed {
                first: ("ip-ipinfo", "AS15169"),
                second: ("ip-other", "AS36040"),
            }
        );
        assert!(
            !acc.handoff().contains_key(INPUT_ASN),
            "a downstream tool must be told nothing, not one side of a disagreement"
        );
    }

    #[test]
    fn a_third_disagreement_does_not_overwrite_the_recorded_one() {
        let mut acc = PhaseAcc::default();
        acc.set_value(INPUT_ASN, "AS1", "a");
        acc.set_value(INPUT_ASN, "AS2", "b");
        acc.set_value(INPUT_ASN, "AS3", "c");
        assert_eq!(
            acc.value_status(INPUT_ASN),
            ValueStatus::Disputed {
                first: ("a", "AS1"),
                second: ("b", "AS2")
            },
            "the key is already unusable; one concrete example is what the report needs"
        );
    }

    #[test]
    fn no_children_yet_reflects_the_accumulator() {
        let p = no_children_yet();
        let mut acc = PhaseAcc::default();
        assert!(p.holds(&acc));
        acc.children = 1;
        assert!(!p.holds(&acc));
    }
}
