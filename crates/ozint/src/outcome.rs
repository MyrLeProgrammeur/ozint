//! The canonical outcome of a single tool invocation, and the function that folds a layer's
//! [`ToolReport`]s into a [`SettleKind`].
//!
//! Conventions follow `types.rs`: `camelCase` on the wire for structs, enums `kebab-case`
//! (internally tagged so a client can switch on the same `kind`/`type`-shaped field it
//! already reads elsewhere).
//!
//! **The point of this module, stated once and enforced by `settle_kind`:** `Empty` and
//! `Failed` are never interchangeable. `Empty` is itself a finding — the tools ran and
//! genuinely turned up nothing new. `Failed` means the layer taught us nothing because
//! everything broke. Rendering a layer where every tool errored as `0 NEW ENTITIES` would
//! silently lie to the analyst; `settle_kind` exists to make that impossible to express.

use serde::{Deserialize, Serialize};

// ─── Outcome ────────────────────────────────────────────────────────────────

/// The 11-variant outcome of one tool invocation. Each variant carries the detail it needs
/// rather than flattening everything to a message string, so a caller can branch on structured
/// data (an HTTP status, a missing env var name) without re-parsing text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ToolOutcome {
    /// The tool ran and returned at least one usable result.
    OkWithResults {
        /// How many results it produced — the numerator a `ToolReport` echoes verbatim.
        count: u32,
    },
    /// The tool ran to completion and genuinely found nothing. Distinct from every
    /// `Skipped*`/error variant — this is a real, positive finding.
    OkEmpty,
    /// Not attempted: the env var this tool needs was never set.
    SkippedNoKey {
        /// The missing env var name, so the UI can render "set `HIBP_API_KEY`" verbatim.
        env_var: String,
    },
    /// Not attempted: the tool is ethically gated and its key is not armed. Distinct from
    /// `SkippedNoKey` because a gated-unarmed tool is a consent boundary, not a missing-config
    /// accident.
    SkippedGatedUnarmed { env_var: String },
    /// Not attempted: the layer plan's `when(acc)` predicate for this tool's phase was false
    /// (e.g. username's phase-C only fires at ≥3 confirmed hits).
    SkippedPhasePredicate {
        /// Human-readable reason, for the tool_start/tool_done event and the report.
        reason: String,
    },
    /// Not attempted: this tool runs on a value an **earlier wave of the same layer** was
    /// supposed to publish (the sibling hand-off — see [`crate::layer_plan::Handoff`]), and
    /// that value is not readable. Either nobody published it, or two tools published
    /// different ones and the key was left disputed rather than resolved by ordering.
    ///
    /// **The 13th variant**, and it earns its place for the same reason `Cancelled` did: the
    /// alternatives all lie. Reporting it as `OkEmpty` claims we asked PeeringDB about this
    /// network and it held nothing; `SkippedPhasePredicate` claims a cascade rule held it back
    /// when the phase's predicate was true and it was the *input* that was missing;
    /// `SkippedNoKey` claims a configuration problem the analyst could fix by arming a key.
    /// What actually happened is that an upstream tool did not answer, and only this says so.
    SkippedMissingInput {
        /// The `layer_plan` `INPUT_*` key that was not readable.
        input: String,
        /// Which of the two cases it was, rendered verbatim.
        reason: String,
    },
    /// Not attempted: the source's circuit breaker is open (too many recent failures).
    SkippedCircuitOpen {
        /// When the breaker is expected to close again, if known.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        retry_after: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Attempted, but the scheduler dropped it under a rate limit before it ran (distinct
    /// from `HttpError` with a 429 — that variant is for a request that *was sent* and got
    /// a 429 back; this one never left the queue).
    RateLimitedDropped,
    /// The request was sent but did not complete within the tool's deadline.
    Timeout { after_ms: u64 },
    /// The request completed with a non-2xx HTTP status.
    HttpError {
        status: u16,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        message: Option<String>,
    },
    /// The response was received but could not be parsed into the expected shape.
    ParseError { message: String },
    /// The request completed but the source explicitly refused it (e.g. an IP ban, a ToS
    /// block) — distinct from a generic `HttpError` so the UI can render "blocked" rather
    /// than "broken".
    Forbidden {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        message: Option<String>,
    },
    /// The layer was killed before this tool could produce anything — either it never
    /// started, or its in-flight request was aborted mid-way. Either way it observed
    /// nothing, so it counts as neither an attempt nor an error.
    ///
    /// **The 12th variant, added after the other 11 were enumerated.** The taxonomy started
    /// at eleven because it enumerated the ways a tool can *fail*; being killed is not one
    /// of those, and until this existed a cancelled layer's report list simply **omitted**
    /// every tool it never reached. That made "you killed it after 2 of 7 tools" and "the
    /// plan only ever had 2 tools" render identically — a `kill` that erased its own
    /// evidence. It is retryable by definition: firing the layer again is all it takes.
    Cancelled,
    /// Not attempted: this invocation's own precondition on what it was given was not met —
    /// either the seed value's *shape* is not what this tool consumes, or a local capability
    /// the tool depends on is absent from this machine.
    ///
    /// **The 14th variant, earned by `entity-video`.** Every earlier type has exactly one
    /// value shape per node (a hash is a hash, a domain is a domain), so no tool ever had to
    /// ask "does this even apply to me". `entity-video` breaks that: one `OzType::Video` node
    /// might hold a local `media_id` (`video-local-probe`'s whole job) or a platform URL
    /// (`video-youtube-lookup`/`video-telegram-resolve`/`video-bluesky-resolve`'s), and the
    /// three-tool breadth phase fires all of them at once. A tool handed the wrong shape did
    /// not search anything and found nothing to disagree with — `ParseError` would claim the
    /// response was malformed (there was no response), and `OkEmpty` would claim a genuine
    /// "searched, found nothing" the tool never performed. Neither is true; this is.
    ///
    /// The same variant also covers `video-local-probe` finding no `ffmpeg`/`ffprobe` binary
    /// on `PATH`: `SkippedNoKey`'s own doc is explicit that it is "an env-var/API-key concept",
    /// not a missing local binary, so reusing it here would misname the fix (there is no key
    /// to set). Both causes share the same shape — a fact about this invocation, not about the
    /// world it queried — and neither is retryable by simply asking again.
    SkippedNotApplicable { reason: String },
}

impl ToolOutcome {
    /// Whether the caller should retry this tool on the next refresh/continue without
    /// waiting for anything external to change. Skips driven by policy (no key, gated,
    /// phase predicate false) are **not** retryable by simply trying again — the analyst
    /// has to change something first (arm a key, reach the phase condition). Circuit-open
    /// and the transient-network family are retryable because time alone can fix them.
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            ToolOutcome::SkippedCircuitOpen { .. }
                | ToolOutcome::RateLimitedDropped
                | ToolOutcome::Timeout { .. }
                | ToolOutcome::HttpError { .. }
                | ToolOutcome::ParseError { .. }
                | ToolOutcome::Cancelled
        )
    }

    /// Whether this outcome counts as a genuine attempt that ran (as opposed to a `Skipped*`
    /// variant, which never left the gate). Used by `settle_kind` to tell "everyone was
    /// skipped" apart from "everyone errored".
    const fn was_attempted(&self) -> bool {
        !matches!(
            self,
            ToolOutcome::SkippedNoKey { .. }
                | ToolOutcome::SkippedGatedUnarmed { .. }
                | ToolOutcome::SkippedPhasePredicate { .. }
                | ToolOutcome::SkippedMissingInput { .. }
                | ToolOutcome::SkippedCircuitOpen { .. }
                | ToolOutcome::Cancelled
                | ToolOutcome::SkippedNotApplicable { .. }
        )
    }

    /// Whether this outcome is an error (an attempt that failed), as opposed to a success
    /// (`OkWithResults`/`OkEmpty`) or a skip.
    const fn is_error(&self) -> bool {
        matches!(
            self,
            ToolOutcome::RateLimitedDropped
                | ToolOutcome::Timeout { .. }
                | ToolOutcome::HttpError { .. }
                | ToolOutcome::ParseError { .. }
                | ToolOutcome::Forbidden { .. }
        )
    }

    /// Whether this outcome produced results. Public because the layer runtime needs it to
    /// decide whether a *gated* tool actually contributed to a verdict — a gated tool that
    /// was skipped or errored must not mark the resulting chip.
    pub const fn is_success(&self) -> bool {
        matches!(
            self,
            ToolOutcome::OkWithResults { .. } | ToolOutcome::OkEmpty
        )
    }

    /// A short human sentence for the UI (`tool_done` event / detail panel), one per variant.
    pub fn human_sentence(&self) -> String {
        match self {
            ToolOutcome::OkWithResults { count } => {
                format!(
                    "returned {count} result{}",
                    if *count == 1 { "" } else { "s" }
                )
            }
            ToolOutcome::OkEmpty => "ran and found nothing".to_string(),
            ToolOutcome::SkippedNoKey { env_var } => format!("skipped — set `{env_var}`"),
            ToolOutcome::SkippedGatedUnarmed { env_var } => {
                format!("skipped — gated tool, set `{env_var}` to arm")
            }
            ToolOutcome::SkippedPhasePredicate { reason } => format!("skipped — {reason}"),
            ToolOutcome::SkippedMissingInput { reason, .. } => format!("skipped — {reason}"),
            ToolOutcome::SkippedCircuitOpen { retry_after } => match retry_after {
                Some(at) => format!("skipped — circuit open until {}", at.to_rfc3339()),
                None => "skipped — circuit open".to_string(),
            },
            ToolOutcome::RateLimitedDropped => "dropped — rate limit".to_string(),
            ToolOutcome::Timeout { after_ms } => format!("timed out after {after_ms}ms"),
            ToolOutcome::HttpError { status, message } => match message {
                Some(m) => format!("HTTP {status} — {m}"),
                None => format!("HTTP {status}"),
            },
            ToolOutcome::ParseError { message } => format!("could not parse response — {message}"),
            ToolOutcome::Forbidden { message } => match message {
                Some(m) => format!("forbidden — {m}"),
                None => "forbidden".to_string(),
            },
            ToolOutcome::Cancelled => "not run — the layer was killed".to_string(),
            ToolOutcome::SkippedNotApplicable { reason } => format!("skipped — {reason}"),
        }
    }
}

// ─── Tool report ────────────────────────────────────────────────────────────

/// One tool's contribution to a layer. What the SSE stream emits per `tool_done` event, and
/// what a settled layer stores verbatim for provenance/replay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolReport {
    pub tool_id: String,
    pub label: String,
    pub outcome: ToolOutcome,
    pub elapsed_ms: u64,
    /// How many results this tool produced. Redundant with `OkWithResults.count` for the
    /// success case, but present uniformly (0 for every non-success variant) so callers can
    /// sum `results` across a layer without matching on `outcome` first.
    pub results: u32,
    /// Whether this tool is behind an ethical gate (FaceCheck/PimEyes/DeHashed/…), regardless
    /// of whether it ran.
    pub gated: bool,
    /// Provenance sentence for this specific invocation ("queried WhatsMyName's site list for
    /// the handle"). Rendered verbatim in the UI, same convention as `Provenance::method`.
    pub method: String,
}

impl ToolReport {
    pub fn new(
        tool_id: impl Into<String>,
        label: impl Into<String>,
        outcome: ToolOutcome,
        elapsed_ms: u64,
        gated: bool,
        method: impl Into<String>,
    ) -> Self {
        let results = match &outcome {
            ToolOutcome::OkWithResults { count } => *count,
            _ => 0,
        };
        Self {
            tool_id: tool_id.into(),
            label: label.into(),
            outcome,
            elapsed_ms,
            results,
            gated,
            method: method.into(),
        }
    }
}

// ─── Settle kind ────────────────────────────────────────────────────────────

/// How a layer settled, folding every tool's outcome into one verdict. Mirrors
/// `NodeStatus`'s `Settled`/`Empty`/`Degraded`/`Failed`/`Aborted` (minus `Idle`/`Running`,
/// which are not settle outcomes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SettleKind {
    /// Produced at least one new child (after dedup).
    Settled,
    /// Ran — at least one tool was actually attempted and none of the attempted tools
    /// errored — and produced no new children. A real, positive finding.
    Empty,
    /// Attempted tools disagree: some produced results or ran clean-empty, others errored.
    Degraded,
    /// Every tool that was attempted errored, OR nothing was even attempted (all tools were
    /// skipped). Either way, the layer taught us nothing — see the module doc.
    Failed,
    /// The layer was killed mid-flight before it could settle on its own.
    Aborted,
}

/// Folds a layer's tool reports into a [`SettleKind`].
///
/// `new_children` is the count of children actually added to the tree **after** dedup
/// (dedup may turn a tool's raw hits into zero new nodes if every one of them was already in
/// the tree). That case still settles to `Empty`, not `Settled`: `NodeStatus` defines `Empty`
/// as "completed and produced nothing new", and zero new nodes is exactly that, however many
/// raw hits fed into dedup. The rediscovered values are not lost — each one lands as an
/// `already_in_tree` annotation on the parent — but the layer's own verdict is still "nothing
/// new here", which is the honest `0 NEW ENTITIES`.
///
/// Pass `aborted = true` when the caller killed the layer mid-flight; every other rule is
/// short-circuited to `Aborted` in that case, because "some tools errored and we were also
/// killed" should still read as an abort to the analyst, not a degraded finding.
///
/// # Truth table (every case this module considers)
///
/// | tools attempted | tools errored | new_children | aborted | → SettleKind |
/// |---|---|---|---|---|
/// | any | any | any | **true** | `Aborted` |
/// | 0 (all skipped) | — | — | false | `Failed` — see below |
/// | ≥1 | 0 | >0 | false | `Settled` |
/// | ≥1 | 0 | 0 | false | `Empty` |
/// | ≥1 | some, not all | any | false | `Degraded` |
/// | ≥1 | all attempted | any | false | `Failed` |
///
/// Two cells not obvious from the table above, decided here:
///
/// - **"some tools errored, the rest returned empty" → `Degraded`, not `Empty`.** `Empty`
///   must mean "every tool that ran told us cleanly there was nothing" — the moment even one
///   tool couldn't tell us anything (it broke instead of reporting), the analyst has lost
///   information the `Empty` state promises they *didn't* lose. Folding that into `Empty`
///   would hide the exact failure this taxonomy exists to surface; `Degraded` keeps
///   the per-tool report visible as the honest place to see what broke.
/// - **"every tool was skipped (no keys armed at all)" → `Failed`, not `Empty`.** No tool
///   ran, so nothing was learned — this is exactly the "we learned nothing" case the module
///   doc defines `Failed` around, even though the reason is configuration rather than a
///   network error. Calling it `Empty` would claim a genuine "searched, found nothing"
///   result when in truth no search happened at all.
pub fn settle_kind(reports: &[ToolReport], new_children: usize, aborted: bool) -> SettleKind {
    if aborted {
        return SettleKind::Aborted;
    }

    let attempted: Vec<&ToolReport> = reports
        .iter()
        .filter(|r| r.outcome.was_attempted())
        .collect();

    if attempted.is_empty() {
        // Either there were no tools at all, or every one of them was skipped. Both are
        // "nothing ran" — see the doc comment above.
        return SettleKind::Failed;
    }

    let errored = attempted.iter().filter(|r| r.outcome.is_error()).count();
    let succeeded = attempted.iter().filter(|r| r.outcome.is_success()).count();
    debug_assert_eq!(
        errored + succeeded,
        attempted.len(),
        "every attempted outcome is either an error or a success"
    );

    if errored == attempted.len() {
        SettleKind::Failed
    } else if errored > 0 {
        SettleKind::Degraded
    } else if new_children > 0 {
        SettleKind::Settled
    } else {
        SettleKind::Empty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(id: &str, outcome: ToolOutcome) -> ToolReport {
        ToolReport::new(id, id, outcome, 10, false, "test invocation")
    }

    fn ok(id: &str, count: u32) -> ToolReport {
        report(id, ToolOutcome::OkWithResults { count })
    }

    fn ok_empty(id: &str) -> ToolReport {
        report(id, ToolOutcome::OkEmpty)
    }

    fn http_err(id: &str) -> ToolReport {
        report(
            id,
            ToolOutcome::HttpError {
                status: 500,
                message: None,
            },
        )
    }

    fn timeout(id: &str) -> ToolReport {
        report(id, ToolOutcome::Timeout { after_ms: 5000 })
    }

    fn skipped_no_key(id: &str) -> ToolReport {
        report(
            id,
            ToolOutcome::SkippedNoKey {
                env_var: format!("{id}_KEY"),
            },
        )
    }

    fn skipped_gated(id: &str) -> ToolReport {
        report(
            id,
            ToolOutcome::SkippedGatedUnarmed {
                env_var: format!("{id}_KEY"),
            },
        )
    }

    fn skipped_predicate(id: &str) -> ToolReport {
        report(
            id,
            ToolOutcome::SkippedPhasePredicate {
                reason: "not enough hits yet".into(),
            },
        )
    }

    fn skipped_circuit(id: &str) -> ToolReport {
        report(id, ToolOutcome::SkippedCircuitOpen { retry_after: None })
    }

    // ── aborted short-circuits everything ──────────────────────────────

    #[test]
    fn aborted_wins_over_all_ok() {
        let reports = vec![ok("a", 3)];
        assert_eq!(settle_kind(&reports, 3, true), SettleKind::Aborted);
    }

    #[test]
    fn aborted_wins_over_all_error() {
        let reports = vec![http_err("a"), timeout("b")];
        assert_eq!(settle_kind(&reports, 0, true), SettleKind::Aborted);
    }

    #[test]
    fn aborted_wins_over_all_skipped() {
        let reports = vec![skipped_no_key("a")];
        assert_eq!(settle_kind(&reports, 0, true), SettleKind::Aborted);
    }

    // ── zero tools / zero children combos ──────────────────────────────

    #[test]
    fn no_reports_at_all_is_failed() {
        let reports: Vec<ToolReport> = vec![];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Failed);
    }

    #[test]
    fn all_ok_with_children_is_settled() {
        let reports = vec![ok("a", 2), ok("b", 1)];
        assert_eq!(settle_kind(&reports, 3, false), SettleKind::Settled);
    }

    #[test]
    fn all_ok_but_zero_new_children_is_empty_even_if_tools_had_raw_hits() {
        // A tool reported results, but every single one deduped away (already in tree).
        // settle_kind only sees new_children, and 0 new children is exactly what `Empty`
        // means — the rediscovered values still surface via `already_in_tree` on the
        // parent, they just don't make this layer's own verdict `Settled`.
        let reports = vec![ok("a", 5)];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Empty);
    }

    #[test]
    fn all_ok_empty_is_empty() {
        let reports = vec![ok_empty("a"), ok_empty("b")];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Empty);
    }

    #[test]
    fn mixed_ok_and_ok_empty_with_children_is_settled() {
        let reports = vec![ok("a", 4), ok_empty("b")];
        assert_eq!(settle_kind(&reports, 4, false), SettleKind::Settled);
    }

    // ── the honesty rule: all-error must never be Empty ────────────────

    #[test]
    fn all_error_is_failed_never_empty() {
        let reports = vec![http_err("a"), timeout("b")];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Failed);
    }

    #[test]
    fn single_tool_error_is_failed() {
        let reports = vec![http_err("a")];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Failed);
    }

    // ── degraded: mixed error + success ─────────────────────────────────

    #[test]
    fn some_error_some_results_is_degraded() {
        let reports = vec![ok("a", 2), http_err("b")];
        assert_eq!(settle_kind(&reports, 2, false), SettleKind::Degraded);
    }

    #[test]
    fn some_error_rest_empty_is_degraded_not_empty() {
        // The decided middle case: a tool broke instead of reporting cleanly, so even
        // though nobody found anything, we did NOT learn "cleanly nothing" from every tool.
        let reports = vec![ok_empty("a"), http_err("b")];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Degraded);
    }

    #[test]
    fn some_error_some_success_some_ok_empty_is_degraded() {
        let reports = vec![ok("a", 1), ok_empty("b"), timeout("c")];
        assert_eq!(settle_kind(&reports, 1, false), SettleKind::Degraded);
    }

    // ── all skipped: Failed, not Empty ──────────────────────────────────

    #[test]
    fn all_skipped_no_key_is_failed_not_empty() {
        let reports = vec![skipped_no_key("a"), skipped_no_key("b")];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Failed);
    }

    #[test]
    fn all_skipped_mixed_reasons_is_failed() {
        let reports = vec![
            skipped_no_key("a"),
            skipped_gated("b"),
            skipped_predicate("c"),
            skipped_circuit("d"),
        ];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Failed);
    }

    // ── skipped tools mixed with attempted tools: skips don't count ────

    #[test]
    fn skipped_plus_all_ok_is_settled_ignoring_the_skip() {
        let reports = vec![ok("a", 3), skipped_no_key("b")];
        assert_eq!(settle_kind(&reports, 3, false), SettleKind::Settled);
    }

    #[test]
    fn skipped_plus_all_error_is_failed_ignoring_the_skip() {
        let reports = vec![http_err("a"), skipped_no_key("b")];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Failed);
    }

    #[test]
    fn skipped_plus_ok_empty_is_empty_ignoring_the_skip() {
        let reports = vec![ok_empty("a"), skipped_gated("b")];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Empty);
    }

    #[test]
    fn skipped_plus_mixed_ok_and_error_is_degraded() {
        let reports = vec![ok("a", 1), http_err("b"), skipped_predicate("c")];
        assert_eq!(settle_kind(&reports, 1, false), SettleKind::Degraded);
    }

    // ── outcome helpers ──────────────────────────────────────────────────

    #[test]
    fn retryable_outcomes() {
        assert!(
            !ToolOutcome::SkippedNoKey {
                env_var: "X".into()
            }
            .is_retryable()
        );
        assert!(
            !ToolOutcome::SkippedGatedUnarmed {
                env_var: "X".into()
            }
            .is_retryable()
        );
        assert!(!ToolOutcome::SkippedPhasePredicate { reason: "x".into() }.is_retryable());
        assert!(ToolOutcome::SkippedCircuitOpen { retry_after: None }.is_retryable());
        assert!(ToolOutcome::RateLimitedDropped.is_retryable());
        assert!(ToolOutcome::Timeout { after_ms: 1 }.is_retryable());
        assert!(
            ToolOutcome::HttpError {
                status: 500,
                message: None
            }
            .is_retryable()
        );
        assert!(
            ToolOutcome::ParseError {
                message: "x".into()
            }
            .is_retryable()
        );
        assert!(!ToolOutcome::Forbidden { message: None }.is_retryable());
        assert!(!ToolOutcome::OkWithResults { count: 1 }.is_retryable());
        assert!(!ToolOutcome::OkEmpty.is_retryable());
        assert!(!ToolOutcome::SkippedNotApplicable { reason: "x".into() }.is_retryable());
    }

    #[test]
    fn skipped_not_applicable_never_counts_as_an_attempt() {
        // A tool that declined a shape it doesn't operate on taught us nothing — same
        // "nothing ran" bucket as every other Skipped* variant, not an error.
        let reports = vec![report(
            "a",
            ToolOutcome::SkippedNotApplicable { reason: "x".into() },
        )];
        assert_eq!(settle_kind(&reports, 0, false), SettleKind::Failed);
    }

    #[test]
    fn outcome_serialises_kebab_case_tag() {
        let json = serde_json::to_value(ToolOutcome::HttpError {
            status: 404,
            message: None,
        })
        .unwrap();
        assert_eq!(json["kind"], "http-error");
        assert_eq!(json["status"], 404);
        assert!(json.get("message").is_none());
    }

    #[test]
    fn all_eleven_variants_round_trip() {
        let variants = vec![
            ToolOutcome::OkWithResults { count: 3 },
            ToolOutcome::OkEmpty,
            ToolOutcome::SkippedNoKey {
                env_var: "X".into(),
            },
            ToolOutcome::SkippedGatedUnarmed {
                env_var: "X".into(),
            },
            ToolOutcome::SkippedPhasePredicate { reason: "x".into() },
            ToolOutcome::SkippedCircuitOpen { retry_after: None },
            ToolOutcome::RateLimitedDropped,
            ToolOutcome::Timeout { after_ms: 500 },
            ToolOutcome::HttpError {
                status: 500,
                message: Some("boom".into()),
            },
            ToolOutcome::ParseError {
                message: "bad json".into(),
            },
            ToolOutcome::Forbidden { message: None },
        ];
        assert_eq!(
            variants.len(),
            11,
            "the taxonomy must have exactly 11 variants"
        );
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: ToolOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn human_sentence_is_nonempty_for_every_variant() {
        let variants = vec![
            ToolOutcome::OkWithResults { count: 3 },
            ToolOutcome::OkEmpty,
            ToolOutcome::SkippedNoKey {
                env_var: "X".into(),
            },
            ToolOutcome::SkippedGatedUnarmed {
                env_var: "X".into(),
            },
            ToolOutcome::SkippedPhasePredicate { reason: "x".into() },
            ToolOutcome::SkippedCircuitOpen { retry_after: None },
            ToolOutcome::RateLimitedDropped,
            ToolOutcome::Timeout { after_ms: 500 },
            ToolOutcome::HttpError {
                status: 500,
                message: None,
            },
            ToolOutcome::ParseError {
                message: "bad json".into(),
            },
            ToolOutcome::Forbidden { message: None },
            ToolOutcome::SkippedNotApplicable { reason: "x".into() },
        ];
        for v in variants {
            assert!(!v.human_sentence().is_empty());
        }
    }

    #[test]
    fn tool_report_results_mirrors_ok_with_results_count() {
        let r = report("a", ToolOutcome::OkWithResults { count: 7 });
        assert_eq!(r.results, 7);
        let r = report("a", ToolOutcome::OkEmpty);
        assert_eq!(r.results, 0);
        let r = report(
            "a",
            ToolOutcome::HttpError {
                status: 500,
                message: None,
            },
        );
        assert_eq!(r.results, 0);
    }
}
