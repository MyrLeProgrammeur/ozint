//! The one 2-4 sentence note attached to a settled layer.
//!
//! **Fire-and-attach, never fire-and-block.** [`run`] is the whole unit: classify what kind of
//! settle this was, build a payload-free prompt from the tool reports, pass it through
//! [`crate::egress::oz_guard`], call the LLM (or don't, if the gate refused), and persist
//! whatever sentence results — real or honest fallback — via [`store::attach_layer_summary`].
//! `runtime.rs::fire_layer` spawns this *after* its terminal frame is already on the wire, so a
//! slow or dead the LLM can never delay settlement; see that function for why the spawn point
//! is there and not in the route layer.
//!
//! **Six named cases, one classifier.** Each case must read as
//! genuinely different wording across normal-settle / dead-end (explain why) /
//! directory-only-dead-end / aborted / degraded / gated-contributed. [`SummaryCase`] has eight
//! variants, not six: the "dead-end" bucket collapses two settle outcomes that
//! `settle_kind`'s own honesty rule (`outcome.rs`) exists specifically to keep apart: `Empty`
//! ("ran clean, found nothing — a real finding") and `Failed` ("nothing ran or everything
//! broke — we learned nothing"). Folding those into one wording would recreate, in the summary
//! text, the exact ambiguity the settle-kind taxonomy was built to eliminate everywhere else.
//! `Empty` itself splits again into [`SummaryCase::DeadEndClean`] and
//! [`SummaryCase::DeadEndWithFindings`] — added 2026-08-26 after a live run showed a row-only
//! tool's real findings (`sidecar-holehe`, 4 confirmed accounts) summarised as "found nothing",
//! because `settle_kind::Empty` only ever meant "zero new nodes," never "zero information."
//! [`classify_case`]'s priority order mirrors [`crate::outcome::settle_kind`]'s own: an abort
//! short-circuits everything (a killed layer is a killed layer, whatever else was true of it),
//! then a directory-only entity (dead-end by design, not by failure — this branch is currently
//! unreachable from `fire_layer` since no orchestrator exists yet for `Directory`/`Name`, see
//! `plans.rs`, but the classifier still has to get it right for when one does), then a gated
//! contribution (an ethical-consent fact the analyst must see regardless of how the layer
//! otherwise settled), and only then the plain settle kind.
//!
//! **Even the fallback is case-shaped.** The unit's honesty requirement ("a sentence that says
//! what actually happened", never a blank string or false cheer) is usually read as being about
//! *why* the LLM didn't answer. But every fact [`case_detail`] states — how many tools ran, how
//! many new nodes appeared, whether a gated tool was involved — comes from the reports already
//! sitting in memory, no network required. So the fallback describes *what the layer did* as
//! well as *why there's no AI gloss on it*, and that first half is exactly what makes fallback
//! sentences differ from each other per case, testable with zero network access.

use ozint_db::Db;
use ozint_llm::{CallOpts, call_llm};

use crate::egress::{self, OzEgressDecision, OzEgressRefusal, OzEgressRequest};
use crate::outcome::{SettleKind, ToolReport};
use crate::runtime::{SUMMARY_NOT_CONFIGURED, SUMMARY_UNAVAILABLE};
use crate::store;
use crate::types::OzType;

/// Cap on the persisted/emitted summary text. "2-4 sentences" has no hard character count, but
/// an LLM reply that ignored the instruction should not be forwarded verbatim — 600 chars
/// is generous for 4 sentences of plain English and mirrors the order of magnitude other
/// cloud-derived text caps in this codebase use (`egress::MAX_TEXT_CHARS` for the *input* side;
/// this is the analogous cap for the *output* side).
const MAX_SUMMARY_CHARS: usize = 600;

// ─── Case classification ────────────────────────────────────────────────────

/// Which of the six named archetypes a settled layer's summary belongs to. See the module
/// doc for why this has seven variants against six named cases, and for the priority order
/// [`classify_case`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryCase {
    /// Ran, produced new children, no gated tool involved.
    NormalSettle,
    /// A gated (ethically-sensitive) tool's success is part of what this layer now claims —
    /// takes priority over the plain settle kind because the consent fact matters more than
    /// whether the layer also happened to be `Settled` or `Degraded`.
    GatedContributed,
    /// This entity type has no automated lookup at all (`OzType::is_directory_only`) — a
    /// dead end by design, never by failure.
    DirectoryOnlyDeadEnd,
    /// `SettleKind::Empty` — every attempted tool ran clean and genuinely found nothing new.
    DeadEndClean,
    /// `SettleKind::Empty`, but at least one tool reported real results (`ToolReport.results >
    /// 0`) — a row-only tool (`sidecar-holehe`, `geo-overpass`, …) that found something real
    /// without spawning a child node. Distinct from `DeadEndClean` for the same reason
    /// `settle_kind` keeps `Empty`/`Failed` apart: "no new nodes" and "no new information" are
    /// different facts, and this case is the one place they used to get collapsed into one
    /// misleading sentence.
    DeadEndWithFindings,
    /// `SettleKind::Failed` — nothing was attempted, or everything attempted broke. Distinct
    /// from `DeadEndClean` for the same reason `settle_kind` keeps `Empty`/`Failed` apart: one
    /// is a finding, the other is a failure to look.
    DeadEndBroken,
    /// `SettleKind::Degraded` — some tools succeeded, some broke.
    Degraded,
    /// `SettleKind::Aborted` — killed mid-flight. Wins over every other signal, mirroring
    /// `settle_kind`'s own short-circuit.
    Aborted,
}

/// Maps a settle outcome onto its [`SummaryCase`]. Pure and total — every `(OzType, SettleKind,
/// bool)` triple lands on exactly one case, so a caller can never end up with no wording to use.
pub fn classify_case(
    oz_type: OzType,
    kind: SettleKind,
    gated_verdict: bool,
    has_results: bool,
) -> SummaryCase {
    if kind == SettleKind::Aborted {
        return SummaryCase::Aborted;
    }
    if oz_type.is_directory_only() {
        return SummaryCase::DirectoryOnlyDeadEnd;
    }
    if gated_verdict {
        return SummaryCase::GatedContributed;
    }
    match kind {
        SettleKind::Settled => SummaryCase::NormalSettle,
        SettleKind::Degraded => SummaryCase::Degraded,
        // `settle_kind`'s `Empty` means "zero new child nodes" — nothing more. A row-only
        // tool (`sidecar-holehe`, `geo-overpass`, `phone-veriphone`'s own rows) can genuinely
        // find real information and still add no node, since its whole contribution is rows
        // on the parent, by design (see e.g. `sources::sidecar::holehe`'s module doc). Folding
        // that into the same wording as a true "nothing at all" result told the analyst a real
        // finding was a dead end — caught 2026-08-26 on a live run where holehe confirmed 4
        // accounts and the summary still said "returned no new information".
        SettleKind::Empty if has_results => SummaryCase::DeadEndWithFindings,
        SettleKind::Empty => SummaryCase::DeadEndClean,
        SettleKind::Failed => SummaryCase::DeadEndBroken,
        SettleKind::Aborted => unreachable!("handled by the early return above"),
    }
}

// ─── Prompt construction ────────────────────────────────────────────────────

fn settle_label(kind: SettleKind) -> &'static str {
    match kind {
        SettleKind::Settled => "settled with new findings",
        SettleKind::Empty => "settled empty — ran clean, found nothing new",
        SettleKind::Degraded => "settled degraded — mixed success and failure",
        SettleKind::Failed => "failed — nothing could be learned",
        SettleKind::Aborted => "aborted — killed mid-flight",
    }
}

const BASE_SYSTEM: &str = "You are an OSINT investigation analyst writing a short internal note for another \
analyst reviewing an automated lookup layer. Write 2 to 4 plain English sentences. Never invent a finding the \
reports below do not state, never use exclamation points, and never call an incomplete or failed layer a \
success. ";

/// The case-specific instruction appended to [`BASE_SYSTEM`]. This is the whole mechanism by
/// which "genuinely different wording" is enforced on the LLM side — the reports fed in can look
/// nearly identical across cases (same tool ids, same counts), so the instruction is what steers
/// the model to write about the *right thing* for each one.
fn case_instruction(case: SummaryCase) -> &'static str {
    match case {
        SummaryCase::NormalSettle => {
            "This layer produced new findings. Summarize what kinds of new nodes were found and which tools \
             produced them."
        }
        SummaryCase::GatedContributed => {
            "This layer's findings were produced in part by an ethically-gated tool (one requiring analyst \
             consent, e.g. face-recognition or a breach lookup). Say so explicitly, then summarize what it \
             and the other tools found."
        }
        SummaryCase::DirectoryOnlyDeadEnd => {
            "This entity type has no automated lookup at all — it only offers manual directory/search \
             reference links. Explain that continuing here opens links rather than running any tool."
        }
        SummaryCase::DeadEndClean => {
            "Every tool this layer attempted ran to completion and found nothing new. Explain that this is a \
             genuine clean result, not a failure, and name which tools were checked."
        }
        SummaryCase::DeadEndWithFindings => {
            "No new nodes were created, but at least one tool reported real results — say what it found and \
             name the tool, then explain that no new node was created because that tool's findings are rows \
             on this node's own detail panel, not a lead pointing elsewhere. Never say this layer found \
             nothing."
        }
        SummaryCase::DeadEndBroken => {
            "Every tool this layer attempted either failed or could never run, so nothing was actually \
             learned here. Explain plainly that this is a failure to look, not a finding of absence, and \
             name what broke or was skipped."
        }
        SummaryCase::Degraded => {
            "Some tools in this layer succeeded and others failed. Summarize what was found, then name which \
             tool(s) broke so the analyst knows what to distrust."
        }
        SummaryCase::Aborted => {
            "This layer was killed mid-flight before it could finish. State plainly that it was interrupted \
             and can be retried — do not describe it as complete."
        }
    }
}

fn system_prompt(case: SummaryCase) -> String {
    format!("{BASE_SYSTEM}{}", case_instruction(case))
}

/// Builds the model input: entity type, target value, settle outcome, new-node count, and one
/// line per tool report (id, label, its own `human_sentence()`, gated flag). **Deliberately
/// nothing else** — no payload JSON, no raw tool response bodies, no free-text bios. This is
/// what requirement 6 ("the model never sees raw material it shouldn't") means in practice: the
/// prompt is built entirely from already-structured, already-summarised fields.
///
/// `human_sentence()` on an error variant (`HttpError`/`ParseError`/`Forbidden`) can echo a
/// message that ultimately traces back to a third-party response, so this text still has to run
/// through [`egress::oz_guard`] before it leaves the process — see [`run`].
fn build_prompt(
    oz_type: OzType,
    value: &str,
    kind: SettleKind,
    new_children: usize,
    reports: &[ToolReport],
) -> String {
    let mut lines = vec![
        format!("Entity type: {}", oz_type.code()),
        format!("Target value: {value}"),
        format!("Settle outcome: {}", settle_label(kind)),
        format!("New nodes discovered: {new_children}"),
        "Tool reports:".to_string(),
    ];
    for r in reports {
        lines.push(format!(
            "- {} ({}): {}, gated={}",
            r.label,
            r.tool_id,
            r.outcome.human_sentence(),
            r.gated
        ));
    }
    lines.join("\n")
}

// ─── Fallback text ───────────────────────────────────────────────────────────

/// Why [`run`] fell back to a canned sentence instead of an LLM reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// `oz_guard` allowed the call and a model was configured, but it did not answer usefully
    /// — network error, timeout, an upstream error, or an empty reply.
    Unreachable,
    /// No model is configured, so nothing was attempted. Kept apart from [`Self::Unreachable`]
    /// because it is not a fault: running with no model is supported, and every finding in the
    /// tree is produced without one.
    NotConfigured,
    /// `oz_guard` refused the payload before any network call was attempted.
    Refused(OzEgressRefusal),
}

fn refusal_sentence(r: OzEgressRefusal) -> &'static str {
    match r {
        OzEgressRefusal::Frozen => {
            "No summary: OZINT is frozen, so no cloud call was attempted for this layer."
        }
        OzEgressRefusal::CredentialMaterial => {
            "No summary: this layer's report text matched a credential-shaped pattern and was withheld from \
             analysis rather than sent anywhere."
        }
        OzEgressRefusal::RawBreachRecordDump => {
            "No summary: this layer's findings were flagged as an unprocessed breach-record dump and were \
             withheld from analysis."
        }
        OzEgressRefusal::MediaBytes => {
            "No summary: this layer's findings were flagged as carrying raw media bytes and were withheld \
             from analysis."
        }
    }
}

/// The locally-computable half of a fallback sentence — what the layer actually did, stated from
/// the reports already in memory. This is what keeps fallback text distinct **per case** even
/// though every case shares the same "why no AI gloss" lead-in.
fn case_detail(case: SummaryCase, new_children: usize, reports: &[ToolReport]) -> String {
    let tool_count = reports.len();
    match case {
        SummaryCase::NormalSettle => format!(
            "{new_children} new node(s) were added from {tool_count} tool report(s) — see them below for the \
             detail this note could not fetch."
        ),
        SummaryCase::GatedContributed => format!(
            "An ethically-gated tool contributed to this layer's {new_children} new node(s); its provenance \
             is marked accordingly below."
        ),
        SummaryCase::DirectoryOnlyDeadEnd => {
            "This entity has no automated lookup; the tiles below are manual reference links, not findings."
                .to_string()
        }
        SummaryCase::DeadEndClean => format!(
            "All {tool_count} tool(s) ran to completion and found nothing new — a genuine dead end, not a \
             failure."
        ),
        SummaryCase::DeadEndWithFindings => {
            let total_results: u32 = reports.iter().map(|r| r.results).sum();
            format!(
                "No new nodes were created, but {tool_count} tool(s) reported {total_results} result(s) — \
                 see the node's own detail panel below, this is a real finding, not a dead end."
            )
        }
        SummaryCase::DeadEndBroken => format!(
            "Every one of the {tool_count} tool(s) attempted here failed or could not run, so this layer \
             taught us nothing — distinct from a clean empty result."
        ),
        SummaryCase::Degraded => format!(
            "Some of the {tool_count} tool(s) succeeded and others failed — check the reports below for what \
             broke."
        ),
        SummaryCase::Aborted => {
            "This layer was killed mid-flight and can be retried; nothing below should be read as a completed \
             result."
                .to_string()
        }
    }
}

/// The complete fallback sentence: a reason lead-in plus the case detail. The `Unreachable` arm
/// reuses [`SUMMARY_UNAVAILABLE`] verbatim as the lead-in rather than duplicating that sentence —
/// see `runtime.rs`'s own doc on that const — **except for [`SummaryCase::Aborted`]**.
/// `SUMMARY_UNAVAILABLE` asserts "the tool reports below are complete and unaffected", which is
/// simply false for a killed layer: some tools have a `Cancelled` outcome precisely because they
/// never got to run. Reusing it there would have the fallback contradict its own case detail in
/// the same sentence — caught by `aborted_fallback_never_claims_completion` — so `Aborted` gets
/// its own, otherwise-identical, reason lead instead of the shared const.
pub fn fallback_for(
    case: SummaryCase,
    reason: FallbackReason,
    new_children: usize,
    reports: &[ToolReport],
) -> String {
    let detail = case_detail(case, new_children, reports);
    let lead = match (case, reason) {
        (SummaryCase::Aborted, FallbackReason::Unreachable) => {
            "No summary: the model did not answer before this layer was killed."
        }
        (SummaryCase::Aborted, FallbackReason::NotConfigured) => {
            "No summary: no language model is configured, so none was asked."
        }
        (_, FallbackReason::Unreachable) => SUMMARY_UNAVAILABLE,
        (_, FallbackReason::NotConfigured) => SUMMARY_NOT_CONFIGURED,
        (_, FallbackReason::Refused(r)) => refusal_sentence(r),
    };
    format!("{lead} {detail}")
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

// ─── The unit ────────────────────────────────────────────────────────────────

/// Generates and persists the summary for a just-settled layer, or does nothing if one is
/// already attached. Returns `None` when skipped (already summarised, or a store error while
/// checking — see the comment at the call site), `Some((text, fallback))` otherwise.
///
/// **Never called for a layer whose summary already exists.** `runtime.rs::fire_layer` mints a
/// fresh `layer_id` on every fire, so in practice this check never trips today — it exists so
/// that "no regenerate-and-rebill on reopen" is an invariant of this function itself, not merely
/// a property of how its one caller happens to behave. `xcut_history_resume`-style reopen flows
/// never call this at all: they read `list_layers`/`get_layer`, which already carry the
/// persisted `summary` column, straight from the store — this function's whole existence is
/// firing a layer, not viewing one.
///
/// **`showSummary = false` is enforced by the caller, not here.** `fire_layer` simply never
/// spawns this function when the flag is off, so the "no LLM call, no cost, no Summary frame at
/// all" contract is a fact about the call site, not a branch inside this one.
// Nine arguments is two over clippy's default threshold — every one is a distinct fact
// `fire_layer` already has in hand at the point it spawns this call (same reasoning as
// `store::insert_layer`'s own `#[allow]`): there is no natural sub-grouping (`kind` and
// `gated_verdict` are both "settle facts" but bundling them with `new_children`/`reports` into a
// struct would just move the same fields one level out without adding clarity for a function
// with exactly one real caller).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    db: &Db,
    layer_id: &str,
    oz_type: OzType,
    value: &str,
    kind: SettleKind,
    new_children: usize,
    gated_verdict: bool,
    reports: &[ToolReport],
    frozen: bool,
) -> Option<(String, bool)> {
    match store::get_layer(db, layer_id) {
        Ok(Some(layer)) if layer.summary.is_some() => return None,
        Err(e) => {
            tracing::warn!(
                layer_id = %layer_id,
                error = %e,
                "ozint summary: could not check for an existing summary before generating — proceeding anyway"
            );
        }
        _ => {}
    }

    let has_results = reports.iter().any(|r| r.results > 0);
    let case = classify_case(oz_type, kind, gated_verdict, has_results);
    let prompt = build_prompt(oz_type, value, kind, new_children, reports);
    let decision = egress::oz_guard(&OzEgressRequest::new(prompt).frozen(frozen));

    let (text, fallback) = match decision {
        OzEgressDecision::Refused(refusal) => (
            fallback_for(
                case,
                FallbackReason::Refused(refusal),
                new_children,
                reports,
            ),
            true,
        ),
        // Asked before the call rather than inferred from its error: a missing key and a dead
        // endpoint both come back as an `Err` here, and only the caller can tell them apart
        // honestly.
        OzEgressDecision::Allowed(_) if !ozint_llm::llm_configured() => (
            fallback_for(case, FallbackReason::NotConfigured, new_children, reports),
            true,
        ),
        OzEgressDecision::Allowed(allowed) => {
            let opts = CallOpts {
                system: Some(system_prompt(case)),
                ..Default::default()
            };
            match call_llm(&allowed.text, opts).await {
                Ok(reply) if !reply.trim().is_empty() => {
                    (truncate_chars(reply.trim(), MAX_SUMMARY_CHARS), false)
                }
                _ => (
                    fallback_for(case, FallbackReason::Unreachable, new_children, reports),
                    true,
                ),
            }
        }
    };

    if let Err(e) = store::attach_layer_summary(db, layer_id, &text) {
        tracing::warn!(layer_id = %layer_id, error = %e, "ozint summary: failed to persist the layer summary");
    }

    Some((text, fallback))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use chrono::Utc;

    use super::*;
    use crate::outcome::ToolOutcome;
    use crate::types::{Investigation, NodeStatus, OzNode, OzPayload, Provenance};

    fn report(tool_id: &str, gated: bool, outcome: ToolOutcome) -> ToolReport {
        ToolReport::new(tool_id, tool_id, outcome, 10, gated, "test invocation")
    }

    fn ok_reports() -> Vec<ToolReport> {
        vec![report(
            "wmn-probe",
            false,
            ToolOutcome::OkWithResults { count: 3 },
        )]
    }

    // ── classify_case: priority order ──────────────────────────────────

    #[test]
    fn normal_settle_is_settled_not_gated_not_directory() {
        assert_eq!(
            classify_case(OzType::Username, SettleKind::Settled, false, false),
            SummaryCase::NormalSettle
        );
    }

    #[test]
    fn gated_contributed_wins_over_the_plain_settle_kind() {
        assert_eq!(
            classify_case(OzType::Username, SettleKind::Settled, true, false),
            SummaryCase::GatedContributed
        );
        assert_eq!(
            classify_case(OzType::Username, SettleKind::Degraded, true, false),
            SummaryCase::GatedContributed
        );
    }

    #[test]
    fn directory_only_wins_over_gated_and_settle_kind() {
        // Currently unreachable via fire_layer (no orchestrator exists for Directory/Name
        // yet — see plans.rs), but the classifier must still get it right for when one does.
        assert_eq!(
            classify_case(OzType::Directory, SettleKind::Settled, true, false),
            SummaryCase::DirectoryOnlyDeadEnd,
            "a directory-only entity is a dead end by design, not by whatever settle_kind says"
        );
        assert_eq!(
            classify_case(OzType::Name, SettleKind::Failed, false, false),
            SummaryCase::DirectoryOnlyDeadEnd
        );
    }

    #[test]
    fn dead_end_clean_is_the_empty_settle_kind() {
        assert_eq!(
            classify_case(OzType::Username, SettleKind::Empty, false, false),
            SummaryCase::DeadEndClean
        );
    }

    #[test]
    fn dead_end_with_findings_wins_over_dead_end_clean_when_a_tool_reported_results() {
        // The exact bug caught live 2026-08-26: `sidecar-holehe` settles the layer `Empty`
        // (zero new children, by design — see its module doc) while still reporting real
        // results. `has_results=true` must steer classification away from `DeadEndClean`.
        assert_eq!(
            classify_case(OzType::Email, SettleKind::Empty, false, true),
            SummaryCase::DeadEndWithFindings
        );
    }

    #[test]
    fn dead_end_with_findings_never_fires_without_the_empty_settle_kind() {
        // `has_results` only matters when the settle kind is genuinely `Empty` — a `Settled`
        // layer with results is just `NormalSettle`, not a new case.
        assert_eq!(
            classify_case(OzType::Email, SettleKind::Settled, false, true),
            SummaryCase::NormalSettle
        );
    }

    #[test]
    fn dead_end_with_findings_case_detail_reports_the_real_result_count() {
        let reports = vec![
            report(
                "sidecar-holehe",
                false,
                ToolOutcome::OkWithResults { count: 4 },
            ),
            report("gravatar-email", false, ToolOutcome::OkEmpty),
        ];
        let text = case_detail(SummaryCase::DeadEndWithFindings, 0, &reports);
        assert!(
            text.contains('4'),
            "must cite the real result count: {text}"
        );
        assert!(
            text.contains("real finding"),
            "must frame this as a real finding, not silently agree it's empty: {text}"
        );
    }

    #[test]
    fn dead_end_broken_is_the_failed_settle_kind() {
        assert_eq!(
            classify_case(OzType::Username, SettleKind::Failed, false, false),
            SummaryCase::DeadEndBroken
        );
    }

    #[test]
    fn degraded_maps_straight_across() {
        assert_eq!(
            classify_case(OzType::Username, SettleKind::Degraded, false, false),
            SummaryCase::Degraded
        );
    }

    #[test]
    fn aborted_wins_over_everything_mirroring_settle_kind_itself() {
        assert_eq!(
            classify_case(OzType::Directory, SettleKind::Aborted, true, false),
            SummaryCase::Aborted
        );
        assert_eq!(
            classify_case(OzType::Username, SettleKind::Aborted, false, false),
            SummaryCase::Aborted
        );
    }

    // ── fallback sentences: genuinely different wording per case ────────

    fn all_cases() -> [SummaryCase; 8] {
        [
            SummaryCase::NormalSettle,
            SummaryCase::GatedContributed,
            SummaryCase::DirectoryOnlyDeadEnd,
            SummaryCase::DeadEndClean,
            SummaryCase::DeadEndWithFindings,
            SummaryCase::DeadEndBroken,
            SummaryCase::Degraded,
            SummaryCase::Aborted,
        ]
    }

    #[test]
    fn fallback_sentences_differ_across_every_case() {
        let reports = ok_reports();
        let sentences: Vec<String> = all_cases()
            .iter()
            .map(|c| fallback_for(*c, FallbackReason::Unreachable, 3, &reports))
            .collect();
        let unique: HashSet<&String> = sentences.iter().collect();
        assert_eq!(
            unique.len(),
            sentences.len(),
            "every case must produce distinct fallback wording: {sentences:#?}"
        );
    }

    #[test]
    fn an_unconfigured_model_reads_differently_from_an_unreachable_one() {
        // Two states a user must be able to tell apart from the sentence alone: nothing is
        // configured (a supported way to run) versus something is configured and broke.
        let absent = fallback_for(
            SummaryCase::NormalSettle,
            FallbackReason::NotConfigured,
            2,
            &ok_reports(),
        );
        let broken = fallback_for(
            SummaryCase::NormalSettle,
            FallbackReason::Unreachable,
            2,
            &ok_reports(),
        );
        assert_ne!(absent, broken);
        assert!(
            absent.contains("OZINT_LLM_API_KEY"),
            "an unconfigured model must name what would configure it: {absent}"
        );
    }

    #[test]
    fn unreachable_fallback_reuses_the_shared_lead_in_verbatim() {
        let text = fallback_for(
            SummaryCase::NormalSettle,
            FallbackReason::Unreachable,
            2,
            &ok_reports(),
        );
        assert!(
            text.starts_with(SUMMARY_UNAVAILABLE),
            "must reuse the existing const, not a second copy: {text}"
        );
    }

    #[test]
    fn dead_end_broken_fallback_names_the_failure_not_the_absence() {
        let text = fallback_for(
            SummaryCase::DeadEndBroken,
            FallbackReason::Unreachable,
            0,
            &ok_reports(),
        );
        assert!(text.contains("taught us nothing"), "{text}");
        let clean = fallback_for(
            SummaryCase::DeadEndClean,
            FallbackReason::Unreachable,
            0,
            &ok_reports(),
        );
        assert!(clean.contains("not a failure"), "{clean}");
        assert_ne!(text, clean);
    }

    #[test]
    fn aborted_fallback_never_claims_the_reports_are_complete() {
        let text = fallback_for(SummaryCase::Aborted, FallbackReason::Unreachable, 0, &[]);
        assert!(text.contains("killed mid-flight"), "{text}");
        // The generic SUMMARY_UNAVAILABLE lead says "the tool reports below are complete and
        // unaffected" — true for every other case, false here, since a killed layer's reports
        // include tools that never got to run at all. This is the exact bug the Aborted carve-out
        // in `fallback_for` exists to avoid; assert the false claim specifically, not the
        // substring "complete" (which also appears, truthfully, inside "not be read as a
        // completed result").
        assert!(
            !text.contains("are complete and unaffected"),
            "an abort's reports are not complete: {text}"
        );
    }

    #[test]
    fn refusal_reasons_each_produce_their_own_sentence() {
        let reports = ok_reports();
        let frozen = fallback_for(
            SummaryCase::NormalSettle,
            FallbackReason::Refused(OzEgressRefusal::Frozen),
            1,
            &reports,
        );
        let cred = fallback_for(
            SummaryCase::NormalSettle,
            FallbackReason::Refused(OzEgressRefusal::CredentialMaterial),
            1,
            &reports,
        );
        let unreachable = fallback_for(
            SummaryCase::NormalSettle,
            FallbackReason::Unreachable,
            1,
            &reports,
        );
        assert_ne!(frozen, cred);
        assert_ne!(frozen, unreachable);
        assert!(frozen.contains("frozen"));
        assert!(cred.contains("credential"));
    }

    // ── run(): the unit's actual persistence/skip/refusal behaviour, network-free ───────
    //
    // `OZINT_LLM_API_KEY` is never set in this test environment (same premise `runtime.rs`'s
    // own LLM tests rely on), so `call_llm` always errs before opening a socket. Every case
    // below is therefore network-free by construction, not by luck.

    fn seed_investigation_and_layer(
        db: &Db,
        inv_id: &str,
        layer_id: &str,
        existing_summary: Option<&str>,
    ) {
        let now = Utc::now();
        store::create_investigation(
            db,
            &Investigation {
                id: inv_id.to_string(),
                seed_input: "mtrebosc".to_string(),
                seed_type: OzType::Username,
                root_node_id: "root".to_string(),
                created_at: now,
                updated_at: now,
                lookups: 0,
                cost_cents: 0,
                spawned_from_investigation_id: None,
                spawned_from_relation: None,
            },
        )
        .unwrap();
        store::insert_node(
            db,
            &OzNode {
                id: "root".to_string(),
                investigation_id: inv_id.to_string(),
                parent_id: None,
                layer_id: None,
                ordinal: 0,
                depth: 0,
                oz_type: OzType::Username,
                value: "mtrebosc".to_string(),
                display: "mtrebosc".to_string(),
                dedup_key: "username:mtrebosc".to_string(),
                payload: OzPayload::empty_for(OzType::Username),
                preview_signal: None,
                full_signal: None,
                sections: Vec::new(),
                gated: false,
                status: NodeStatus::Idle,
                provenance: Provenance::new("seed", "typed by the analyst"),
                already_in_tree: None,
                corroborations: Vec::new(),
                edited_value: None,
                created_at: now,
            },
        )
        .unwrap();
        store::insert_layer(
            db,
            layer_id,
            inv_id,
            "root",
            OzType::Username,
            "mtrebosc",
            "settled",
            now,
        )
        .unwrap();
        if let Some(summary) = existing_summary {
            store::attach_layer_summary(db, layer_id, summary).unwrap();
        }
    }

    #[tokio::test]
    async fn a_layer_with_no_llm_key_settles_on_the_honest_fallback() {
        let db = ozint_db::open_memory().unwrap();
        seed_investigation_and_layer(&db, "inv-1", "layer-1", None);

        let reports = ok_reports();
        let (text, fallback) = run(
            &db,
            "layer-1",
            OzType::Username,
            "mtrebosc",
            SettleKind::Settled,
            3,
            false,
            &reports,
            false,
        )
        .await
        .expect("a fresh layer must always produce a summary or fallback");

        assert!(
            fallback,
            "no OZINT_LLM_API_KEY in this test env — must degrade honestly"
        );
        // The property that matters, and the one this test used to get wrong: with no key set,
        // nothing was ever asked, so the sentence must say so rather than report a failure that
        // did not happen. It previously asserted `SUMMARY_UNAVAILABLE` — which is why every
        // default installation was told "the local model was unreachable" on every single
        // layer, for a call it had never attempted.
        assert!(
            text.starts_with(SUMMARY_NOT_CONFIGURED),
            "an unconfigured model must not be reported as an unreachable one: {text}"
        );
        assert!(
            !text.contains("unreachable") && !text.contains("did not answer"),
            "the sentence must not imply an attempt was made: {text}"
        );
        let stored = store::get_layer(&db, "layer-1").unwrap().unwrap();
        assert_eq!(
            stored.summary.as_deref(),
            Some(text.as_str()),
            "the fallback must still be persisted"
        );
    }

    #[tokio::test]
    async fn a_layer_that_already_has_a_summary_is_never_regenerated() {
        let db = ozint_db::open_memory().unwrap();
        seed_investigation_and_layer(&db, "inv-1", "layer-1", Some("the original summary"));

        let result = run(
            &db,
            "layer-1",
            OzType::Username,
            "mtrebosc",
            SettleKind::Settled,
            3,
            false,
            &ok_reports(),
            false,
        )
        .await;

        assert!(
            result.is_none(),
            "an already-summarised layer must be skipped, not rebilled"
        );
        let stored = store::get_layer(&db, "layer-1").unwrap().unwrap();
        assert_eq!(
            stored.summary.as_deref(),
            Some("the original summary"),
            "must not be overwritten"
        );
    }

    #[tokio::test]
    async fn a_frozen_call_is_refused_before_any_llm_attempt() {
        let db = ozint_db::open_memory().unwrap();
        seed_investigation_and_layer(&db, "inv-1", "layer-1", None);

        let (text, fallback) = run(
            &db,
            "layer-1",
            OzType::Username,
            "mtrebosc",
            SettleKind::Settled,
            3,
            false,
            &ok_reports(),
            true,
        )
        .await
        .unwrap();

        assert!(fallback);
        assert!(
            text.contains("frozen"),
            "a frozen refusal must read differently from a plain unreachable: {text}"
        );
    }

    #[tokio::test]
    async fn credential_shaped_report_text_never_reaches_the_network_and_still_gets_a_summary() {
        let db = ozint_db::open_memory().unwrap();
        seed_investigation_and_layer(&db, "inv-1", "layer-1", None);

        // A tool's own HTTP-error message can echo back untrusted third-party text — this is
        // the realistic vector, not a hand-typed field. It must be caught downstream by
        // `oz_guard`, not by anything upstream trusting the tool report shape.
        let reports = vec![report(
            "ghost-tool",
            false,
            ToolOutcome::HttpError {
                status: 500,
                message: Some(
                    "leaked token aB3dE9fG1hJ4kL6mN8pQ0rS2tU4vW6xY8zA1bC3 in the body".to_string(),
                ),
            },
        )];

        let (text, fallback) = run(
            &db,
            "layer-1",
            OzType::Username,
            "mtrebosc",
            SettleKind::Degraded,
            0,
            false,
            &reports,
            false,
        )
        .await
        .unwrap();

        assert!(fallback);
        assert!(
            text.contains("credential"),
            "must be the credential-refusal sentence, not a generic one: {text}"
        );
    }
}
