//! The POTENTIAL RELATIONS panel, derived from the tree.
//!
//! A relation card says: *this other entity may be connected to your subject, here is the
//! evidence, and searching it will open a **separate** investigation* — spawning is a create;
//! one person, one tree; a relation is never grafted onto the tree that surfaced it.
//!
//! Relations are **derived, never stored**. That is not a storage preference, it is the only
//! way this module's first hard rule can hold: *a relation resting on a rejected node
//! disappears*. A stored relation would have to be hunted down and deleted on every reject,
//! restore and edit; a derived one simply stops being produced the moment
//! [`OzNode::contributes`] turns false.
//!
//! ## Deterministic first, and mostly deterministic-only
//!
//! Every relation here is produced by a rule that can be read, argued with and unit-tested.
//! An *optional* LLM phrasing/arbitration pass is allowed on top; this module ships
//! its guard rails ([`coerce_relation`], [`relation_fallback`]) but not its call site — see
//! "The LLM pass" below.
//!
//! ## The rules, and why three of them do not run in this build
//!
//! There are six: shared surname, co-listed address, employer+role overlap, bio/contact
//! mentions, co-signed records, gated face-match. Three of them have no input in this build,
//! and the difference between *ran and found nothing* and *never ran* is reported explicitly
//! in [`RelationReport::rules_without_input`] rather than being allowed to look like a clean
//! sweep:
//!
//! ⚠️ **This is not the analyst-facing `NOT SEARCHED`.** The cockpit's `NOT SEARCHED` block
//! says *this person has not been investigated yet*; this field says *this inference rule had
//! no input to run on*. They are different claims about different subjects, and they shared a
//! name until 2026-08-23, when this was settled: the analyst-facing wording keeps the words;
//! the engine's field was the one renamed.
//!
//! - **Co-listed address** needs a street-level address. Every location this build can
//!   actually see is a city ("Location" on GitHub/Gravatar, "Country" on YouTube). Treating a
//!   city as a co-listed address would relate every person in Paris to every other one — a
//!   rule that fires constantly and means nothing is worse than one that admits it has no
//!   input.
//! - **Co-signed records** needs a public-records source. This build catalogues none.
//! - **Gated face-match** needs a gated pixel tool (FaceCheck/PimEyes). The registry
//!   catalogues no gated tool at all today. If one is ever added, its relations are `Gated`
//!   tier forever — see [`RelationTier::Gated`].
//!
//! ## Tiers
//!
//! `Gated` is not a confidence level, it is a provenance fact, and it **overrides** any
//! computed confidence — the settled answer to whether a tier conflict overrides or layers is
//! override. Nothing downstream — the LLM included — may move a relation off `Gated`.
//!
//! Otherwise: `Low` for a shared surname (a surname is weak evidence and pretending otherwise
//! would launder a guess into a finding), `Medium` for an explicit self-declared mention or a
//! shared employer, and `High` only when **two independent rules** land on the same subject —
//! corroboration is the one thing here that genuinely earns more confidence than any single
//! rule provides.
//!
//! ## The LLM pass
//!
//! [`coerce_relation`] is `coerceRelation`: it accepts a model's
//! suggestion for *phrasing only* and silently discards everything else — a changed subject,
//! a changed kind, any tier movement
//! on a gated relation, and any tier the deterministic rules did not already justify. The
//! call site is deliberately **not built in this unit**: the pass is optional, and
//! `crate::egress`'s `oz_guard` (which every cloud-bound OZINT call must pass through) is
//! already being wired for the LLM summary pass. Adding a second concurrent caller to that
//! choke point would race it for no gain, since a relation without its LLM rephrasing is
//! complete and correct — it just says [`relation_fallback`]'s deterministic sentence instead.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::classify;
use crate::normalize;
use crate::types::{OzNode, OzPayload, OzRow, OzType};

// ─── Types ─────────────────────────────────────────────────────────────────

/// Which rule produced a relation. Serialised as the panel's own vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationKind {
    /// Two distinct full names in the tree share a surname.
    SharedSurname,
    /// Two distinct people are listed at the same street address. **No input in this build.**
    CoListedAddress,
    /// Two distinct people list the same employer.
    EmployerOverlap,
    /// A profile's own free text names another handle, address or account.
    MentionedInBio,
    /// Two parties appear on the same public record. **No input in this build.**
    CoSignedRecord,
    /// A gated reverse-image tool matched a face. **No input in this build.**
    FaceMatch,
}

impl RelationKind {
    pub const fn label(self) -> &'static str {
        match self {
            RelationKind::SharedSurname => "shared surname",
            RelationKind::CoListedAddress => "co-listed address",
            RelationKind::EmployerOverlap => "employer overlap",
            RelationKind::MentionedInBio => "mentioned in a profile",
            RelationKind::CoSignedRecord => "co-signed record",
            RelationKind::FaceMatch => "face match",
        }
    }

    fn slug(self) -> &'static str {
        match self {
            RelationKind::SharedSurname => "shared-surname",
            RelationKind::CoListedAddress => "co-listed-address",
            RelationKind::EmployerOverlap => "employer-overlap",
            RelationKind::MentionedInBio => "mentioned-in-bio",
            RelationKind::CoSignedRecord => "co-signed-record",
            RelationKind::FaceMatch => "face-match",
        }
    }
}

/// How much weight a relation carries. See the module doc — `Gated` is a provenance fact that
/// overrides the rest, not a point on the same scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationTier {
    /// Produced with the help of an ethically-gated tool. Never downgraded by anything —
    /// not by another rule, and not by the LLM.
    Gated,
    High,
    Medium,
    Low,
}

/// One node's contribution to a relation. Carries the node id so the card can link straight
/// back to the finding, which is what makes a relation auditable rather than an assertion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationEvidence {
    pub node_id: String,
    pub tool_id: String,
    /// The fact itself, verbatim from the row that carried it.
    pub detail: String,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub gated: bool,
}

/// A candidate connection to another entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Relation {
    /// Stable across re-derivations of the same tree: `<kind>:<normalized subject>`. The panel
    /// can key on it, and a spawned investigation records it verbatim in
    /// `spawned_from_relation`.
    pub id: String,
    /// The other entity — what searching this relation would seed.
    pub subject: String,
    /// What that seed would be classified as, so spawning it does not have to guess.
    pub subject_type: OzType,
    pub kind: RelationKind,
    pub tier: RelationTier,
    /// The sentence the card shows. Deterministic by default (see [`relation_fallback`]); an
    /// LLM may only rephrase it, under [`coerce_relation`].
    pub rationale: String,
    pub evidence: Vec<RelationEvidence>,
    /// True when any evidence came from a gated tool. Never cleared.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub gated: bool,
}

/// One inference **rule** that had no input to run on, and why.
///
/// This is the reason the panel can be read honestly. A relation list with three cards looks
/// identical whether the other three rules found nothing or never had an input, and only one
/// of those two readings is true.
///
/// ⚠️ **Not the analyst-facing `NOT SEARCHED`**, which is a claim about a *person* who has not
/// been investigated. This is a claim about a *rule*.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleWithoutInput {
    pub kind: RelationKind,
    pub reason: String,
}

/// What one derivation produced.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationReport {
    pub relations: Vec<Relation>,
    /// Rules that could not run at all, distinct from rules that ran and found nothing.
    /// Always non-empty in this build — three rules have no source at all.
    pub rules_without_input: Vec<RuleWithoutInput>,
}

// ─── Extraction ────────────────────────────────────────────────────────────

/// Row labels that carry a person's name, as actually emitted by this build's tools
/// (`github`, `bluesky`, `mastodon` all use `Name`). Matched case-insensitively.
const NAME_LABELS: &[&str] = &["name", "real name", "full name", "display name"];
/// Row labels carrying an employer.
const EMPLOYER_LABELS: &[&str] = &["company", "employer", "organisation", "organization"];
/// Row labels carrying a role/title.
const ROLE_LABELS: &[&str] = &["job title", "role", "title", "position"];
/// Row labels carrying free text a person wrote about themselves.
const BIO_LABELS: &[&str] = &["bio", "about", "description"];

fn label_matches(row: &OzRow, labels: &[&str]) -> bool {
    let l = row.label.trim().to_ascii_lowercase();
    labels.contains(&l.as_str())
}

/// Lowercased, whitespace-collapsed form used for comparison and for relation ids. Deliberately
/// **not** diacritic-folded: this crate has no unicode-normalization dependency, and quietly
/// treating `Muller` and `Müller` as one name is exactly the kind of invisible merge this
/// crate's conflict rule forbids elsewhere.
fn norm(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// The surname half of a full name: the last whitespace-separated token.
///
/// A Western-ordered heuristic, and knowingly so. It is why this rule's tier is `Low` and its
/// panel is called POTENTIAL RELATIONS: it surfaces a candidate for a human to accept or
/// discard, and never asserts kinship on its own.
fn surname_of(full_name: &str) -> Option<String> {
    let tokens: Vec<&str> = full_name.split_whitespace().collect();
    if tokens.len() < 2 {
        return None;
    }
    Some(norm(tokens[tokens.len() - 1]))
}

/// Every row of a node, wherever a payload keeps them.
///
/// `pub(crate)` for `subject_file`, which folds the same rows into a different deliverable —
/// one harvester, so a payload that starts keeping rows somewhere new reaches both at once.
pub(crate) fn rows_of(node: &OzNode) -> Vec<&OzRow> {
    let mut rows: Vec<&OzRow> = Vec::new();
    match &node.payload {
        OzPayload::Username(p) => rows.extend(p.profile.iter()),
        OzPayload::Image(p) => rows.extend(p.exif.iter().chain(p.reverse_matches.iter())),
        OzPayload::Video(p) => rows.extend(p.metadata.iter()),
        OzPayload::Coordinate(p) => rows.extend(p.map_links.iter()),
        _ => {}
    }
    for section in &node.sections {
        rows.extend(section.rows.iter());
    }
    rows
}

/// One person as this tree describes them, assembled from the rows of one node.
#[derive(Debug, Clone)]
struct Identity {
    name: String,
    node_id: String,
    tool_id: String,
    gated: bool,
    employer: Option<String>,
    role: Option<String>,
}

fn identities(nodes: &[&OzNode]) -> Vec<Identity> {
    let mut out = Vec::new();
    for node in nodes {
        let rows = rows_of(node);
        let employer = rows
            .iter()
            .find(|r| label_matches(r, EMPLOYER_LABELS))
            .map(|r| r.value.trim().trim_start_matches('@').to_string())
            .filter(|v| !v.is_empty());
        let role = rows
            .iter()
            .find(|r| label_matches(r, ROLE_LABELS))
            .map(|r| r.value.trim().to_string())
            .filter(|v| !v.is_empty());

        for row in rows.iter().filter(|r| label_matches(r, NAME_LABELS)) {
            let name = row.value.trim().to_string();
            if name.is_empty() {
                continue;
            }
            out.push(Identity {
                name,
                node_id: node.id.clone(),
                tool_id: row
                    .source_tool_id
                    .clone()
                    .unwrap_or_else(|| node.provenance.source_tool_id.clone()),
                gated: node.gated || row.gated,
                employer: employer.clone(),
                role: role.clone(),
            });
        }
    }
    out
}

/// Emails and `@handle`s named inside free text. Emails are consumed first, so the local part
/// of `someone@example.com` is never re-read as a handle.
fn mentions_in(text: &str) -> Vec<String> {
    let email_re = regex::Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
        .expect("static email regex");
    let handle_re = regex::Regex::new(r"@([A-Za-z0-9_.\-]{2,30})").expect("static handle regex");

    let mut found: Vec<String> = Vec::new();
    let mut remaining = text.to_string();
    for m in email_re.find_iter(text) {
        found.push(m.as_str().to_string());
        remaining = remaining.replace(m.as_str(), " ");
    }
    for c in handle_re.captures_iter(&remaining) {
        let handle = c[1].trim_end_matches(['.', '-']).to_string();
        if handle.len() >= 2 {
            found.push(handle);
        }
    }
    found
}

// ─── Inference ─────────────────────────────────────────────────────────────

fn tier_for(kind: RelationKind, gated: bool) -> RelationTier {
    if gated {
        return RelationTier::Gated;
    }
    match kind {
        // A surname is weak evidence; calling it anything more would launder a guess.
        RelationKind::SharedSurname => RelationTier::Low,
        RelationKind::EmployerOverlap | RelationKind::MentionedInBio => RelationTier::Medium,
        // These three cannot be produced by this build at all; the arms exist so adding a
        // source later is a compile-checked decision rather than a silent default.
        RelationKind::CoListedAddress | RelationKind::CoSignedRecord => RelationTier::Medium,
        RelationKind::FaceMatch => RelationTier::Gated,
    }
}

/// The deterministic sentence a relation carries when no model has rephrased it. Never
/// fabricates: it says which rule fired and on what.
pub fn relation_fallback(kind: RelationKind, subject: &str, detail: &str) -> String {
    match kind {
        RelationKind::SharedSurname => {
            format!("Shares the surname of a name found in this tree ({detail}).")
        }
        RelationKind::EmployerOverlap => {
            format!("Listed at the same employer as another identity in this tree ({detail}).")
        }
        RelationKind::MentionedInBio => {
            format!("Named in a profile this investigation already found ({detail}).")
        }
        RelationKind::CoListedAddress => {
            format!("Listed at the same address ({detail}).")
        }
        RelationKind::CoSignedRecord => format!("Appears on the same record ({detail})."),
        RelationKind::FaceMatch => {
            format!("Matched by a gated reverse-image tool ({detail}). Treat as gated evidence.")
        }
        #[allow(unreachable_patterns)]
        _ => format!("{subject}: {detail}"),
    }
}

/// Derives every relation this tree supports, plus the block naming what was never searched.
///
/// `nodes` is the whole investigation; rejected nodes are filtered out here rather than by the
/// caller, so no call site can forget to.
pub fn infer(nodes: &[OzNode]) -> RelationReport {
    let live: Vec<&OzNode> = nodes.iter().filter(|n| n.contributes()).collect();

    // Values already in the tree are not "potential relations" — they are nodes. Keyed the same
    // way the visited-set dedup keys them, so the two agree on what "already here" means.
    let in_tree: HashSet<String> = live
        .iter()
        .map(|n| format!("{}|{}", n.oz_type.code(), n.dedup_key))
        .collect();

    let people = identities(&live);
    let mut candidates: Vec<Relation> = Vec::new();

    // ── Shared surname ────────────────────────────────────────────────────
    for (i, a) in people.iter().enumerate() {
        for b in people.iter().skip(i + 1) {
            if norm(&a.name) == norm(&b.name) {
                continue; // the same person, seen twice — that is dedup, not a relation
            }
            let (Some(sa), Some(sb)) = (surname_of(&a.name), surname_of(&b.name)) else {
                continue;
            };
            if sa != sb {
                continue;
            }
            let gated = a.gated || b.gated;
            candidates.push(Relation {
                id: format!("{}:{}", RelationKind::SharedSurname.slug(), norm(&b.name)),
                subject: b.name.clone(),
                subject_type: OzType::Name,
                kind: RelationKind::SharedSurname,
                tier: tier_for(RelationKind::SharedSurname, gated),
                rationale: relation_fallback(
                    RelationKind::SharedSurname,
                    &b.name,
                    &format!("{} and {}", a.name, b.name),
                ),
                evidence: vec![
                    RelationEvidence {
                        node_id: a.node_id.clone(),
                        tool_id: a.tool_id.clone(),
                        detail: a.name.clone(),
                        gated: a.gated,
                    },
                    RelationEvidence {
                        node_id: b.node_id.clone(),
                        tool_id: b.tool_id.clone(),
                        detail: b.name.clone(),
                        gated: b.gated,
                    },
                ],
                gated,
            });
        }
    }

    // ── Employer overlap ──────────────────────────────────────────────────
    for (i, a) in people.iter().enumerate() {
        for b in people.iter().skip(i + 1) {
            let (Some(ea), Some(eb)) = (a.employer.as_ref(), b.employer.as_ref()) else {
                continue;
            };
            if norm(ea) != norm(eb) || norm(&a.name) == norm(&b.name) {
                continue;
            }
            let gated = a.gated || b.gated;
            let detail = match (&a.role, &b.role) {
                (Some(ra), Some(rb)) => format!("{ea} — {} as {ra}, {} as {rb}", a.name, b.name),
                _ => format!("{ea} — {} and {}", a.name, b.name),
            };
            candidates.push(Relation {
                id: format!("{}:{}", RelationKind::EmployerOverlap.slug(), norm(&b.name)),
                subject: b.name.clone(),
                subject_type: OzType::Name,
                kind: RelationKind::EmployerOverlap,
                tier: tier_for(RelationKind::EmployerOverlap, gated),
                rationale: relation_fallback(RelationKind::EmployerOverlap, &b.name, &detail),
                evidence: vec![
                    RelationEvidence {
                        node_id: a.node_id.clone(),
                        tool_id: a.tool_id.clone(),
                        detail: format!("{} @ {ea}", a.name),
                        gated: a.gated,
                    },
                    RelationEvidence {
                        node_id: b.node_id.clone(),
                        tool_id: b.tool_id.clone(),
                        detail: format!("{} @ {eb}", b.name),
                        gated: b.gated,
                    },
                ],
                gated,
            });
        }
    }

    // ── Bio / contact mentions ────────────────────────────────────────────
    for node in &live {
        for row in rows_of(node)
            .into_iter()
            .filter(|r| label_matches(r, BIO_LABELS))
        {
            for mention in mentions_in(&row.value) {
                let classification = classify::classify(&mention);
                let oz_type = classification.oz_type;
                let key = format!(
                    "{}|{}",
                    oz_type.code(),
                    normalize::dedup_key(oz_type, &mention)
                );
                if in_tree.contains(&key) {
                    // Already a node. Surfacing it as a "potential relation" would invite the
                    // analyst to spawn a second investigation into something they already have.
                    continue;
                }
                let gated = node.gated || row.gated;
                candidates.push(Relation {
                    id: format!("{}:{}", RelationKind::MentionedInBio.slug(), norm(&mention)),
                    subject: mention.clone(),
                    subject_type: oz_type,
                    kind: RelationKind::MentionedInBio,
                    tier: tier_for(RelationKind::MentionedInBio, gated),
                    rationale: relation_fallback(
                        RelationKind::MentionedInBio,
                        &mention,
                        &format!("{} on {}", row.label, node.display),
                    ),
                    evidence: vec![RelationEvidence {
                        node_id: node.id.clone(),
                        tool_id: row
                            .source_tool_id
                            .clone()
                            .unwrap_or_else(|| node.provenance.source_tool_id.clone()),
                        detail: row.value.trim().to_string(),
                        gated,
                    }],
                    gated,
                });
            }
        }
    }

    RelationReport {
        relations: corroborate(candidates),
        rules_without_input: rules_without_input(&people),
    }
}

/// Merges duplicate cards for one subject and applies the one deterministic promotion this
/// module allows: a subject two *different* rules both point at is `High`.
///
/// Gated always wins the merge, in both directions — a gated card never loses its tier by
/// being merged with an ordinary one, and an ordinary card that merges gated evidence becomes
/// gated.
fn corroborate(candidates: Vec<Relation>) -> Vec<Relation> {
    let mut by_subject: BTreeMap<String, Vec<Relation>> = BTreeMap::new();
    for relation in candidates {
        by_subject
            .entry(norm(&relation.subject))
            .or_default()
            .push(relation);
    }

    let mut out = Vec::new();
    for (_, group) in by_subject {
        let mut kinds: HashSet<RelationKind> = HashSet::new();
        let mut gated = false;
        for r in &group {
            kinds.insert(r.kind);
            gated |= r.gated;
        }

        let mut merged = group.into_iter().next().expect("groups are never empty");
        if kinds.len() > 1 {
            merged.rationale = format!(
                "{} Corroborated by {} independent rules ({}).",
                merged.rationale,
                kinds.len(),
                {
                    let mut names: Vec<&str> = kinds.iter().map(|k| k.label()).collect();
                    names.sort_unstable();
                    names.join(", ")
                }
            );
        }
        merged.gated = gated;
        merged.tier = if gated {
            RelationTier::Gated
        } else if kinds.len() > 1 {
            RelationTier::High
        } else {
            merged.tier
        };
        out.push(merged);
    }

    // Strongest first, then alphabetically — a stable order so a re-derived panel does not
    // reshuffle under the analyst.
    out.sort_by(|a, b| {
        let rank = |t: RelationTier| match t {
            RelationTier::Gated => 0,
            RelationTier::High => 1,
            RelationTier::Medium => 2,
            RelationTier::Low => 3,
        };
        rank(a.tier)
            .cmp(&rank(b.tier))
            .then_with(|| a.subject.cmp(&b.subject))
    });
    out
}

/// Every rule that had no input, and why. See [`RuleWithoutInput`].
fn rules_without_input(people: &[Identity]) -> Vec<RuleWithoutInput> {
    let mut out = vec![
        RuleWithoutInput {
            kind: RelationKind::CoListedAddress,
            reason: "no source in this build returns a street-level address — the only locations available are city-level, which cannot establish a shared address".to_string(),
        },
        RuleWithoutInput {
            kind: RelationKind::CoSignedRecord,
            reason: "no public-records source is catalogued in this build".to_string(),
        },
        RuleWithoutInput {
            kind: RelationKind::FaceMatch,
            reason: "no gated reverse-image tool is catalogued in this build".to_string(),
        },
    ];

    // A rule with no input did not "find nothing" — it never ran, and says so.
    if people.len() < 2 {
        out.push(RuleWithoutInput {
            kind: RelationKind::SharedSurname,
            reason: "fewer than two distinct names have been found in this tree, so there was nothing to compare".to_string(),
        });
    }
    if people.iter().filter(|p| p.employer.is_some()).count() < 2 {
        out.push(RuleWithoutInput {
            kind: RelationKind::EmployerOverlap,
            reason: "fewer than two identities in this tree list an employer".to_string(),
        });
    }
    out
}

// ─── The LLM guard rail ────────────────────────────────────────────────────

/// What a model is allowed to return about one relation. Anything outside this shape is not
/// parsed at all.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationSuggestion {
    pub id: String,
    /// A rephrasing of the rationale. This is the only field that can survive.
    pub rationale: String,
    /// A tier the model would prefer. Accepted only when it neither touches a gated relation
    /// nor invents confidence the rules did not justify.
    #[serde(default)]
    pub tier: Option<RelationTier>,
}

/// Applies a model's suggestion to a deterministically-derived relation, keeping only what a
/// model is entitled to change.
///
/// The deterministic result is the floor: the model can only make it read better, never
/// change what it asserts. Specifically it may **not**:
///
/// - move a `Gated` relation to any other tier (the hard rule: gated is forever);
/// - raise a tier — corroboration is the only thing that promotes, and only [`corroborate`]
///   can see whether it happened;
/// - blank the rationale, which would leave a card with nothing to say.
///
/// A mismatched `id` is ignored outright: a model answering about a relation that was not
/// asked about is not evidence of anything.
pub fn coerce_relation(mut base: Relation, suggestion: &RelationSuggestion) -> Relation {
    if suggestion.id != base.id {
        return base;
    }

    let rationale = suggestion.rationale.trim();
    if !rationale.is_empty() {
        base.rationale = rationale.to_string();
    }

    if let Some(tier) = suggestion.tier {
        let rank = |t: RelationTier| match t {
            RelationTier::Gated => 0,
            RelationTier::High => 1,
            RelationTier::Medium => 2,
            RelationTier::Low => 3,
        };
        let downgrade_only = rank(tier) > rank(base.tier);
        if base.tier != RelationTier::Gated && !base.gated && downgrade_only {
            base.tier = tier;
        }
    }

    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        NodeStatus, OzSection, Provenance, RecordStatus, SectionKind, UsernamePayload,
    };
    use chrono::Utc;

    fn row(label: &str, value: &str) -> OzRow {
        OzRow {
            label: label.into(),
            value: value.into(),
            ..Default::default()
        }
    }

    fn node(id: &str, display: &str, rows: Vec<OzRow>) -> OzNode {
        OzNode {
            id: id.into(),
            investigation_id: "inv-1".into(),
            parent_id: None,
            layer_id: None,
            ordinal: 0,
            depth: 0,
            oz_type: OzType::Username,
            value: display.into(),
            display: display.into(),
            dedup_key: normalize::dedup_key(OzType::Username, display),
            payload: OzPayload::Username(UsernamePayload {
                profile: rows,
                ..Default::default()
            }),
            preview_signal: None,
            full_signal: None,
            sections: Vec::new(),
            gated: false,
            status: NodeStatus::Settled,
            provenance: Provenance::new("github-user", "queried the GitHub user API"),
            already_in_tree: None,
            corroborations: Vec::new(),
            edited_value: None,
            created_at: Utc::now(),
        }
    }

    // ── Rules ──────────────────────────────────────────────────────────────

    #[test]
    fn a_shared_surname_is_a_low_tier_relation() {
        let nodes = vec![
            node("n1", "mtrebosc", vec![row("Name", "Mathéo Trebosc")]),
            node("n2", "atrebosc", vec![row("Name", "Alice Trebosc")]),
        ];
        let report = infer(&nodes);
        let r = report
            .relations
            .iter()
            .find(|r| r.kind == RelationKind::SharedSurname)
            .expect("a surname relation");
        assert_eq!(
            r.tier,
            RelationTier::Low,
            "a surname is weak evidence and must stay Low"
        );
        assert_eq!(r.subject, "Alice Trebosc");
        assert_eq!(r.evidence.len(), 2, "both names are the evidence");
    }

    #[test]
    fn the_same_person_seen_twice_is_not_a_relation_to_themselves() {
        let nodes = vec![
            node("n1", "mtrebosc", vec![row("Name", "Mathéo Trebosc")]),
            node("n2", "mtrebosc2", vec![row("Name", "mathéo trebosc")]),
        ];
        let report = infer(&nodes);
        assert!(
            report
                .relations
                .iter()
                .all(|r| r.kind != RelationKind::SharedSurname),
            "one identity found twice is dedup, not kinship: {:?}",
            report.relations
        );
    }

    #[test]
    fn a_single_token_name_cannot_produce_a_surname_relation() {
        let nodes = vec![
            node("n1", "a", vec![row("Name", "Prince")]),
            node("n2", "b", vec![row("Name", "Madonna")]),
        ];
        assert!(infer(&nodes).relations.is_empty());
    }

    #[test]
    fn a_shared_employer_relates_two_different_people() {
        let nodes = vec![
            node(
                "n1",
                "a",
                vec![
                    row("Name", "Ada Lovelace"),
                    row("Company", "@acme"),
                    row("Job title", "CTO"),
                ],
            ),
            node(
                "n2",
                "b",
                vec![
                    row("Name", "Grace Hopper"),
                    row("Company", "acme"),
                    row("Job title", "Admiral"),
                ],
            ),
        ];
        let report = infer(&nodes);
        let r = report
            .relations
            .iter()
            .find(|r| r.kind == RelationKind::EmployerOverlap)
            .expect("an employer relation");
        assert_eq!(r.tier, RelationTier::Medium);
        assert!(
            r.rationale.contains("CTO") && r.rationale.contains("Admiral"),
            "{}",
            r.rationale
        );
    }

    #[test]
    fn a_bio_mention_becomes_a_typed_relation() {
        let nodes = vec![node(
            "n1",
            "mtrebosc",
            vec![row(
                "Bio",
                "building things with @someoneelse — reach me at team@example.com",
            )],
        )];
        let report = infer(&nodes);
        let subjects: Vec<&str> = report
            .relations
            .iter()
            .map(|r| r.subject.as_str())
            .collect();
        assert!(subjects.contains(&"someoneelse"), "{subjects:?}");
        assert!(subjects.contains(&"team@example.com"), "{subjects:?}");

        let email = report
            .relations
            .iter()
            .find(|r| r.subject == "team@example.com")
            .unwrap();
        assert_eq!(
            email.subject_type,
            OzType::Email,
            "the classifier types the seed for spawn"
        );
    }

    #[test]
    fn an_email_local_part_is_never_re_read_as_a_handle() {
        // `someone@example.com` must not also yield a handle `example`.
        let found = mentions_in("write to someone@example.com");
        assert_eq!(found, vec!["someone@example.com".to_string()]);
    }

    #[test]
    fn a_mention_already_in_the_tree_is_not_offered_as_a_relation() {
        // Otherwise the panel invites the analyst to open a second investigation into a node
        // they are already looking at.
        let mut nodes = vec![node(
            "n1",
            "mtrebosc",
            vec![row("Bio", "my other account is @altmtrebosc")],
        )];
        nodes.push(node("n2", "altmtrebosc", vec![]));
        let report = infer(&nodes);
        assert!(
            report.relations.iter().all(|r| r.subject != "altmtrebosc"),
            "{:?}",
            report.relations
        );
    }

    // ── Hard rules ─────────────────────────────────────────────────────────

    #[test]
    fn a_relation_resting_on_a_rejected_node_disappears() {
        // This module's first hard rule, and the reason relations are derived rather than stored.
        let mut nodes = vec![
            node("n1", "a", vec![row("Name", "Ada Lovelace")]),
            node("n2", "b", vec![row("Name", "Grace Lovelace")]),
        ];
        assert!(!infer(&nodes).relations.is_empty());

        nodes[1].provenance.record_status = RecordStatus::Rejected {
            rejected_at: Utc::now(),
        };
        assert!(
            infer(&nodes).relations.is_empty(),
            "rejecting the node that supplied the second name must remove the relation"
        );
    }

    #[test]
    fn a_gated_node_makes_its_relation_gated_forever() {
        let mut nodes = vec![
            node("n1", "a", vec![row("Name", "Ada Lovelace")]),
            node("n2", "b", vec![row("Name", "Grace Lovelace")]),
        ];
        nodes[1].gated = true;
        let report = infer(&nodes);
        let r = report.relations.first().expect("a relation");
        assert_eq!(r.tier, RelationTier::Gated);
        assert!(r.gated);
    }

    #[test]
    fn two_independent_rules_on_one_subject_promote_it_to_high() {
        let nodes = vec![
            node(
                "n1",
                "a",
                vec![row("Name", "Ada Lovelace"), row("Company", "acme")],
            ),
            node(
                "n2",
                "b",
                vec![row("Name", "Grace Lovelace"), row("Company", "acme")],
            ),
        ];
        let report = infer(&nodes);
        let r = report.relations.first().expect("a merged relation");
        assert_eq!(
            r.tier,
            RelationTier::High,
            "corroboration is the only promotion"
        );
        assert!(r.rationale.contains("Corroborated by 2"), "{}", r.rationale);
        assert_eq!(report.relations.len(), 1, "one subject renders as one card");
    }

    #[test]
    fn a_gated_relation_stays_gated_even_when_corroborated() {
        let mut nodes = vec![
            node(
                "n1",
                "a",
                vec![row("Name", "Ada Lovelace"), row("Company", "acme")],
            ),
            node(
                "n2",
                "b",
                vec![row("Name", "Grace Lovelace"), row("Company", "acme")],
            ),
        ];
        nodes[0].gated = true;
        let report = infer(&nodes);
        assert_eq!(report.relations[0].tier, RelationTier::Gated);
    }

    #[test]
    fn rows_from_detail_sections_count_as_evidence_too() {
        let mut n = node("n1", "a", vec![]);
        n.sections = vec![OzSection {
            id: "profile".into(),
            label: "Profile".into(),
            kind: SectionKind::KeyValue,
            rows: vec![row("Name", "Ada Lovelace")],
        }];
        let mut m = node("n2", "b", vec![row("Name", "Grace Lovelace")]);
        m.ordinal = 1;
        assert_eq!(infer(&[n, m]).relations.len(), 1);
    }

    // ── Rules without input ────────────────────────────────────────────────

    #[test]
    fn the_three_sourceless_rules_are_always_declared_without_input() {
        let report = infer(&[]);
        let kinds: Vec<RelationKind> = report.rules_without_input.iter().map(|n| n.kind).collect();
        for kind in [
            RelationKind::CoListedAddress,
            RelationKind::CoSignedRecord,
            RelationKind::FaceMatch,
        ] {
            assert!(
                kinds.contains(&kind),
                "{kind:?} has no source and must say so"
            );
        }
    }

    #[test]
    fn a_rule_with_no_input_says_it_never_ran_rather_than_finding_nothing() {
        // An empty relations list plus a silent rule set reads as "we looked everywhere and
        // there is nobody". Only one of those two readings is true here.
        let report = infer(&[node("n1", "a", vec![row("Name", "Ada Lovelace")])]);
        assert!(report.relations.is_empty());
        let surname = report
            .rules_without_input
            .iter()
            .find(|n| n.kind == RelationKind::SharedSurname)
            .expect("the surname rule had one name and nothing to compare it to");
        assert!(
            surname.reason.contains("fewer than two"),
            "{}",
            surname.reason
        );
    }

    #[test]
    fn a_rule_that_did_run_is_not_listed_as_without_input() {
        let nodes = vec![
            node("n1", "a", vec![row("Name", "Ada Lovelace")]),
            node("n2", "b", vec![row("Name", "Grace Hopper")]),
        ];
        let report = infer(&nodes);
        assert!(
            !report
                .rules_without_input
                .iter()
                .any(|n| n.kind == RelationKind::SharedSurname),
            "the rule ran and found no match — that is a finding, not an omission"
        );
    }

    // ── The LLM guard rail ─────────────────────────────────────────────────

    fn sample_relation(tier: RelationTier, gated: bool) -> Relation {
        Relation {
            id: "shared-surname:alice trebosc".into(),
            subject: "Alice Trebosc".into(),
            subject_type: OzType::Name,
            kind: RelationKind::SharedSurname,
            tier,
            rationale: "Shares the surname of a name found in this tree.".into(),
            evidence: Vec::new(),
            gated,
        }
    }

    #[test]
    fn the_model_may_rephrase() {
        let base = sample_relation(RelationTier::Low, false);
        let out = coerce_relation(
            base,
            &RelationSuggestion {
                id: "shared-surname:alice trebosc".into(),
                rationale: "Same family name as the subject; likely a relative.".into(),
                tier: None,
            },
        );
        assert_eq!(
            out.rationale,
            "Same family name as the subject; likely a relative."
        );
    }

    #[test]
    fn the_model_may_never_move_a_gated_relation() {
        // A hard rule. A model that could talk a gated finding down to LOW would
        // erase the consent boundary the gating exists to record.
        let base = sample_relation(RelationTier::Gated, true);
        let out = coerce_relation(
            base,
            &RelationSuggestion {
                id: "shared-surname:alice trebosc".into(),
                rationale: "weak".into(),
                tier: Some(RelationTier::Low),
            },
        );
        assert_eq!(out.tier, RelationTier::Gated);
    }

    #[test]
    fn the_model_may_downgrade_but_never_promote() {
        let promoted = coerce_relation(
            sample_relation(RelationTier::Low, false),
            &RelationSuggestion {
                id: "shared-surname:alice trebosc".into(),
                rationale: "certain".into(),
                tier: Some(RelationTier::High),
            },
        );
        assert_eq!(
            promoted.tier,
            RelationTier::Low,
            "only corroboration promotes"
        );

        let demoted = coerce_relation(
            sample_relation(RelationTier::High, false),
            &RelationSuggestion {
                id: "shared-surname:alice trebosc".into(),
                rationale: "thin".into(),
                tier: Some(RelationTier::Low),
            },
        );
        assert_eq!(demoted.tier, RelationTier::Low);
    }

    #[test]
    fn a_suggestion_about_another_relation_is_ignored_entirely() {
        let base = sample_relation(RelationTier::Low, false);
        let before = base.rationale.clone();
        let out = coerce_relation(
            base,
            &RelationSuggestion {
                id: "some-other-relation".into(),
                rationale: "hijacked".into(),
                tier: Some(RelationTier::Low),
            },
        );
        assert_eq!(out.rationale, before);
    }

    #[test]
    fn an_empty_rationale_never_blanks_the_card() {
        let base = sample_relation(RelationTier::Low, false);
        let before = base.rationale.clone();
        let out = coerce_relation(
            base,
            &RelationSuggestion {
                id: "shared-surname:alice trebosc".into(),
                rationale: "   ".into(),
                tier: None,
            },
        );
        assert_eq!(out.rationale, before);
    }

    #[test]
    fn relation_ids_are_stable_across_re_derivations() {
        let nodes = vec![
            node("n1", "a", vec![row("Name", "Ada Lovelace")]),
            node("n2", "b", vec![row("Name", "Grace Lovelace")]),
        ];
        let first: Vec<String> = infer(&nodes)
            .relations
            .iter()
            .map(|r| r.id.clone())
            .collect();
        let second: Vec<String> = infer(&nodes)
            .relations
            .iter()
            .map(|r| r.id.clone())
            .collect();
        assert_eq!(first, second);
    }
}
