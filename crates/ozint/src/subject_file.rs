//! The 12-field subject deliverable, folded live from the tree.
//!
//! The rail the analyst actually hands over. It is **derived, never stored**, for the same
//! reason [`crate::relations`] is: a rejected node has to vanish from it and a corrected node
//! has to appear with the correction, and neither can be guaranteed by invalidation
//! bookkeeping. [`crate::types::OzNode::contributes`] turns false and the value simply stops
//! being produced.
//!
//! ## The field list, and where it comes from
//!
//! This unit was blocked from 2026-08-21 until 2026-08-23 on a spec gap: the 13 fields were
//! not enumerated anywhere in this repo, and the rule was **do not implement by inventing the
//! fields**. They were not invented. The enumeration was recovered verbatim from an earlier
//! design mock and is transcribed in [`SubjectField::ALL`] in that mock's own order.
//!
//! **The recovered enumeration's FAMILY NAME / GIVEN NAME pair is deliberately collapsed into
//! one `FULL NAME`.** Splitting needs
//! a last-token heuristic that silently inverts Chinese names, mangles Spanish compound
//! surnames and yields nothing for a mononym, inside a document presented as sourced fact. The
//! name is carried exactly as found. **Twelve fields, and a completeness denominator of 13.**
//!
//! **PHOTO is the thirteenth completeness slot, not a thirteenth field.** The count is
//! `filled rows + (has photo ? 1 : 0)` against a total of 13 — see [`SubjectFile::filled`].
//!
//! ## Agreement and conflict — the locked rule, and how it is expressed here
//!
//! Two cases were locked on 2026-07-30, explicitly overriding an earlier five-step
//! precedence draft:
//!
//! - **Agreement** — two sources returning the same value are *one* item carrying *both*
//!   provenances. This is dedup, not arbitration.
//! - **Conflict** — two sources returning genuinely different values for one fact are **both**
//!   shown, each with its own source, and nothing picks a winner. It stays that way until an
//!   analyst resolves it through `EDIT` → `SAVE`.
//!
//! Both are expressed by one shape: a [`FieldItem`] holds a `Vec<FieldValue>`. One value means
//! settled; **more than one means an unresolved conflict**, and [`FieldItem::is_conflicted`]
//! is the only thing a renderer needs to ask. There is deliberately no "winner" field, no
//! ordering by source authority and no confidence score — a caller that wanted to auto-resolve
//! would have to write that itself, visibly, rather than find it quietly done here.
//!
//! For a **list field**, the same shape carries a subtler clause: list values
//! append and dedup by identical value, but *a conflicting variant of an existing item* — two
//! spellings of one handle — is surfaced dual-value rather than silently picked. Items are
//! therefore grouped by [`crate::normalize::dedup_key`], which is this crate's existing answer
//! to "are these two strings the same entity", and a group holding two distinct spellings is a
//! conflicted item exactly like a single-valued clash. No new fuzzy-matching was introduced
//! for this; using anything looser would start merging things the analyst never agreed to.
//!
//! ## ⚠️ This module diverges from the earlier design mock on two fields, deliberately
//!
//! That mock marks only four fields list-valued (`LISTF = { emails, phones, handles,
//! media }`) and renders `PROFILES` and `OTHER PRESENCE` as single summary strings
//! (`"14 platforms · 6 name-matched"`, `"residential connection · GB (2021)"`). This module
//! treats **six** fields as list-valued: emails/phones/handles/profiles/other-presence/media.
//!
//! The divergence is recorded rather than smoothed over: that earlier mock is a visual design
//! whose summary strings are computed by hand in its own fixture data, and this module is the
//! locked specification for the live fold. A single "14 platforms" line is also not something
//! this fold could honestly produce for `PROFILES` — it would have to count platforms and
//! assert how many matched a name, which is a claim, where a list of the profiles actually
//! confirmed is an observation. If the owner prefers that mock's reading, this is the one
//! place to change and [`SubjectField::is_list`] is the switch.
//!
//! ## What has no producer, stated rather than filled
//!
//! - **AGE has no producer at all.** That earlier mock demonstrated `AGE ≈ 46`, derived
//!   from the `79` in `mwrighton79@example.com`. No tool, payload or plan entry in this
//!   crate produces an age, and no such heuristic exists here — reading a birth year out of an
//!   email local part is a guess dressed as a finding. The field is enumerated because the
//!   deliverable has it, and it stays empty until something genuinely measures it. An empty
//!   field reads as *not found*; that is the correct reading.
//! - **The qualifier suffix has no engine field.** That earlier mock showed editorial trailers —
//!   `"— corporate"`, `"— primary"`, `"— office line"`. Those are an analyst's judgement, not
//!   a value any source returned, so values here are bare. Adding them would mean inventing a
//!   classification per email and per phone.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::normalize;
use crate::relations::rows_of;
use crate::types::{OzNode, OzPayload, OzRow, OzType};

// ─── Fields ────────────────────────────────────────────────────────────────

/// The twelve subject-file fields, in the deliverable's own order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectField {
    FullName,
    Age,
    City,
    PostalAddress,
    Employer,
    Role,
    Emails,
    Phones,
    Handles,
    Profiles,
    OtherPresence,
    Media,
}

impl SubjectField {
    /// Transcribed verbatim from the design mock, in its order. Changing this list changes
    /// the deliverable, so it is one array and not a scattering of matches.
    pub const ALL: &'static [SubjectField] = &[
        SubjectField::FullName,
        SubjectField::Age,
        SubjectField::City,
        SubjectField::PostalAddress,
        SubjectField::Employer,
        SubjectField::Role,
        SubjectField::Emails,
        SubjectField::Phones,
        SubjectField::Handles,
        SubjectField::Profiles,
        SubjectField::OtherPresence,
        SubjectField::Media,
    ];

    /// The rail's label, exactly as the design mock spells it.
    pub const fn label(self) -> &'static str {
        match self {
            SubjectField::FullName => "FULL NAME",
            SubjectField::Age => "AGE",
            SubjectField::City => "CITY",
            SubjectField::PostalAddress => "POSTAL ADDRESS",
            SubjectField::Employer => "EMPLOYER",
            SubjectField::Role => "ROLE",
            SubjectField::Emails => "EMAIL ADDRESSES",
            SubjectField::Phones => "PHONE NUMBERS",
            SubjectField::Handles => "HANDLES",
            SubjectField::Profiles => "PROFILES",
            SubjectField::OtherPresence => "OTHER PRESENCE",
            SubjectField::Media => "MEDIA",
        }
    }

    /// Whether the field accumulates several distinct items or holds one fact.
    ///
    /// **Six, deliberately** — see the module doc for the earlier design mock's four-entry
    /// `LISTF` and why this module treats six fields as list-valued instead.
    pub const fn is_list(self) -> bool {
        matches!(
            self,
            SubjectField::Emails
                | SubjectField::Phones
                | SubjectField::Handles
                | SubjectField::Profiles
                | SubjectField::OtherPresence
                | SubjectField::Media
        )
    }

    /// The entity type a list field's values are, for grouping variants through
    /// [`normalize::dedup_key`]. `None` where the values are not a catalogued entity — a
    /// profile link and a presence line have no normalizer, so they group on their own text.
    const fn dedup_as(self) -> Option<OzType> {
        match self {
            SubjectField::Emails => Some(OzType::Email),
            SubjectField::Phones => Some(OzType::Phone),
            SubjectField::Handles => Some(OzType::Username),
            _ => None,
        }
    }
}

// ─── Values ────────────────────────────────────────────────────────────────

/// Where one value came from. Carried per-value rather than per-field because a conflicted
/// field's whole point is that each side is independently openable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldSource {
    pub node_id: String,
    pub tool_id: String,
    /// A gated tool touched this value. Never cleared downstream.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub gated: bool,
    /// The analyst corrected the node this came from. Renders as the `✎` tag an analyst
    /// SAVE promises the subject file would carry.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub corrected: bool,
}

/// One value, and every source that reported it.
///
/// Several sources on one value is the **agreement** case: they are listed together
/// ("via GitHub + Gravatar"), which is dedup and not arbitration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldValue {
    pub value: String,
    pub sources: Vec<FieldSource>,
}

/// One fact in the subject file.
///
/// A single-valued field holds at most one of these. A list field holds one per distinct
/// item. Either way, **more than one [`FieldValue`] inside it is an unresolved conflict** that
/// only an analyst may settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldItem {
    pub values: Vec<FieldValue>,
}

impl FieldItem {
    /// Two or more genuinely different values for one fact, shown side by side with no winner.
    pub fn is_conflicted(&self) -> bool {
        self.values.len() > 1
    }
}

/// One field's entry in the rail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldEntry {
    pub field: SubjectField,
    /// The design mock's own spelling, carried on the wire rather than re-derived on the
    /// client — the rail's labels are part of the deliverable, not a presentation choice.
    pub label: String,
    pub is_list: bool,
    /// Empty when nothing in the tree fed this field. An empty field means *not found* — it
    /// is never a placeholder for a value that could have been computed.
    pub items: Vec<FieldItem>,
}

/// The subject-file deliverable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectFile {
    /// All twelve, always, in order — including the empty ones. A rail that dropped its
    /// empty fields would make "we did not find a city" and "we never look for a city"
    /// indistinguishable.
    pub fields: Vec<FieldEntry>,
    /// The subject photo, when a source returned one. The thirteenth completeness slot.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub photo: Option<FieldValue>,
    /// Fields carrying at least one item, plus one if a photo was found.
    pub filled: usize,
    /// Always 13 — twelve fields plus the photo slot. The name is never split.
    pub total: usize,
}

/// The completeness denominator: twelve fields plus PHOTO.
pub const TOTAL_SLOTS: usize = 13;

/// Whether a subject file means anything for an investigation rooted on this type.
///
/// The rail is for **person**
/// investigations only. `COMPLETENESS 3 / 13` over EMPLOYER and POSTAL ADDRESS is not a
/// measurement when the root is `CVE-2024-38063` — the fields were never applicable, so an
/// empty dossier reads as *we searched and found nothing about this person*, which is a lie
/// about an investigation that has no person in it. There are deliberately **no per-type field
/// sets**: that would be four more dossiers to design for no demonstrated need.
pub const fn applies_to(root: OzType) -> bool {
    matches!(
        root,
        OzType::Username | OzType::Email | OzType::Name | OzType::Phone
    )
}

/// What a caller is handed for the rail: the dossier, or an explicit statement that this
/// investigation has none.
///
/// A tagged enum rather than `Option<SubjectFile>` so the absence carries **why** — a client
/// that received `null` would have to re-derive the person-shaped rule itself to tell "no
/// dossier applies here" from "the dossier failed to load".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SubjectFileView {
    /// The root is person-shaped and the dossier is folded from the tree.
    File(SubjectFile),
    /// The root is a CVE, hash, IP, domain or coordinate. The rail is absent, not empty, and
    /// the tree stands alone.
    #[serde(rename_all = "camelCase")]
    NotApplicable { root_type: OzType },
}

/// The rail for an investigation, gated on its root type. The entry point a route should use;
/// [`build`] is the unconditional fold underneath it.
pub fn build_for(root_type: OzType, nodes: &[OzNode]) -> SubjectFileView {
    if applies_to(root_type) {
        SubjectFileView::File(build(nodes))
    } else {
        SubjectFileView::NotApplicable { root_type }
    }
}

// ─── The fold ──────────────────────────────────────────────────────────────

/// Row labels the built tools actually emit, mapped onto the fields they feed.
///
/// Keyed on **labels this crate genuinely produces** — verified against `sources/*`'s emitted
/// `OzRow::label`s, the same discipline `relations.rs` follows and for the same reason: a
/// mapping written from the design mock would key on labels no tool sets and would fold
/// nothing at all, silently.
const LABEL_FIELDS: &[(&str, SubjectField)] = &[
    // `Name` is the only full-name row any source emits; it is carried whole, below.
    ("location", SubjectField::City),
    ("city", SubjectField::City),
    ("company", SubjectField::Employer),
    ("employer", SubjectField::Employer),
    ("organisation", SubjectField::Employer),
    ("organization", SubjectField::Employer),
    ("job title", SubjectField::Role),
    ("role", SubjectField::Role),
    ("title", SubjectField::Role),
    ("position", SubjectField::Role),
    ("email", SubjectField::Emails),
    ("handle", SubjectField::Handles),
];

/// Row labels that are a link to a profile on a named platform. Each built username tool
/// emits its own platform name as the label of the row carrying the profile URL.
const PROFILE_LABELS: &[&str] = &[
    "github",
    "bluesky",
    "mastodon",
    "gravatar",
    "hacker news",
    "youtube",
    "blog",
];

/// The label carrying a picture of the subject — the fourteenth slot's only producer.
const PHOTO_LABELS: &[&str] = &["avatar"];

/// A node type's own value feeds a field directly: a discovered EML node *is* an email
/// address, whatever any row says about it.
const fn field_for_type(oz_type: OzType) -> Option<SubjectField> {
    match oz_type {
        OzType::Email => Some(SubjectField::Emails),
        OzType::Phone => Some(SubjectField::Phones),
        OzType::Username => Some(SubjectField::Handles),
        OzType::Image | OzType::Video => Some(SubjectField::Media),
        // An address and a domain are where the subject is *reachable*, not who they are.
        OzType::Ip | OzType::Domain => Some(SubjectField::OtherPresence),
        // A coordinate's reverse-geocode is handled from its payload, which carries the
        // street-level string; the raw `lat,lon` value itself is not a postal address.
        OzType::Coordinate => None,
        // NAM and DIR are the analyst's own seed or a launch-tile set, and CVE/SHA describe an
        // artefact rather than a person. None of them names a subject-file fact.
        OzType::Name | OzType::Directory | OzType::Cve | OzType::Hash => None,
    }
}

fn lower(label: &str) -> String {
    label.trim().to_ascii_lowercase()
}

/// Comparison form for the agreement test: whitespace-collapsed and case-folded.
///
/// Deliberately no diacritic folding, matching `relations::norm`'s reasoning exactly —
/// this crate has no unicode-normalization dependency, and quietly treating `Muller` and
/// `Müller` as one value is the invisible merge the conflict rule exists to forbid.
fn agree_key(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// One value on its way into the fold, before agreement and conflict are worked out.
struct Contribution {
    field: SubjectField,
    value: String,
    source: FieldSource,
}

fn source_of(node: &OzNode, row: Option<&OzRow>) -> FieldSource {
    FieldSource {
        node_id: node.id.clone(),
        tool_id: row
            .and_then(|r| r.source_tool_id.clone())
            .unwrap_or_else(|| node.provenance.source_tool_id.clone()),
        gated: node.gated || row.is_some_and(|r| r.gated),
        corrected: node.edited_value.is_some(),
    }
}

/// Everything one node contributes, from its own type and from its rows.
fn contributions_of(node: &OzNode) -> Vec<Contribution> {
    let mut out: Vec<Contribution> = Vec::new();
    let mut push = |field: SubjectField, value: String, source: FieldSource| {
        let value = value.trim().to_string();
        if !value.is_empty() {
            out.push(Contribution {
                field,
                value,
                source,
            });
        }
    };

    // The node's own value, when its type names a subject-file fact. `effective_value` so an
    // analyst's correction is what lands in the deliverable.
    if let Some(field) = field_for_type(node.oz_type) {
        let display = if node.display.trim().is_empty() {
            node.effective_value()
        } else {
            &node.display
        };
        let value = if node.edited_value.is_some() {
            node.effective_value().to_string()
        } else {
            display.to_string()
        };
        push(field, value, source_of(node, None));
    }

    // A coordinate's reverse-geocoded place is the one genuinely street-level location this
    // crate produces (Nominatim's `display_name`), which is what makes POSTAL ADDRESS a real
    // field rather than a restatement of CITY. Every *other* location any source returns is
    // city-level, and `relations.rs` already refuses to treat one as an address.
    if let OzPayload::Coordinate(geo) = &node.payload
        && let Some(place) = geo
            .place
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
    {
        push(
            SubjectField::PostalAddress,
            place.to_string(),
            source_of(node, None),
        );
    }

    for row in rows_of(node) {
        let label = lower(&row.label);
        let source = source_of(node, Some(row));

        if PHOTO_LABELS.contains(&label.as_str()) {
            // Handled by the caller as the thirteenth slot, not as one of the twelve.
            continue;
        }
        if label == "name" {
            // One field, the name exactly as the source spelled it. No split.
            push(SubjectField::FullName, row.value.clone(), source);
            continue;
        }
        if PROFILE_LABELS.contains(&label.as_str()) {
            // The link, when there is one — a profile the analyst can open is worth more than
            // the platform's name repeated back. Falls back to the row's value otherwise.
            let value = row.href.clone().unwrap_or_else(|| row.value.clone());
            push(SubjectField::Profiles, value, source);
            continue;
        }
        if let Some((_, field)) = LABEL_FIELDS.iter().find(|(l, _)| *l == label) {
            push(*field, row.value.clone(), source);
        }
    }

    out
}

/// The photo, if any node carries one. First found wins and its source is recorded; a second
/// avatar is not a conflict worth surfacing, because the slot is a completeness counter rather
/// than a claim about which picture is canonical.
fn photo_of(nodes: &[&OzNode]) -> Option<FieldValue> {
    for node in nodes {
        for row in rows_of(node) {
            if PHOTO_LABELS.contains(&lower(&row.label).as_str()) {
                let value = row.href.clone().unwrap_or_else(|| row.value.clone());
                if !value.trim().is_empty() {
                    return Some(FieldValue {
                        value: value.trim().to_string(),
                        sources: vec![source_of(node, Some(row))],
                    });
                }
            }
        }
    }
    None
}

/// Folds one field's contributions into items, applying agreement and conflict.
fn items_for(field: SubjectField, contributions: Vec<Contribution>) -> Vec<FieldItem> {
    if contributions.is_empty() {
        return Vec::new();
    }

    // Group into items. A single-valued field is one item by definition: every value competes
    // for the same slot, so any disagreement is a conflict in that one item. A list field
    // groups by entity identity, so two spellings of one handle land in one item (a variant
    // conflict) while two genuinely different handles land in two.
    let mut groups: BTreeMap<String, Vec<Contribution>> = BTreeMap::new();
    for c in contributions {
        let key = if field.is_list() {
            match field.dedup_as() {
                Some(oz_type) => normalize::dedup_key(oz_type, &c.value),
                None => agree_key(&c.value),
            }
        } else {
            String::new()
        };
        groups.entry(key).or_default().push(c);
    }

    groups
        .into_values()
        .map(|group| {
            // Within a group, identical values merge and carry both provenances — the
            // agreement case. Distinct values stay distinct — the conflict case.
            let mut values: Vec<FieldValue> = Vec::new();
            for c in group {
                match values
                    .iter_mut()
                    .find(|v| agree_key(&v.value) == agree_key(&c.value))
                {
                    Some(existing) => {
                        if !existing.sources.contains(&c.source) {
                            existing.sources.push(c.source);
                        }
                    }
                    None => values.push(FieldValue {
                        value: c.value,
                        sources: vec![c.source],
                    }),
                }
            }
            FieldItem { values }
        })
        .collect()
}

/// Builds the subject file from a tree's nodes.
///
/// Pure, total, and cheap enough to run on every read — which is what keeps a correction or a
/// rejection visible immediately instead of after an invalidation pass.
pub fn build(nodes: &[OzNode]) -> SubjectFile {
    // The rejection rule, and the only place it needs to be applied: a rejected node stops
    // contributing and every value resting on it disappears, with no bookkeeping anywhere.
    let contributing: Vec<&OzNode> = nodes.iter().filter(|n| n.contributes()).collect();

    let mut by_field: BTreeMap<SubjectField, Vec<Contribution>> = BTreeMap::new();
    for node in &contributing {
        for c in contributions_of(node) {
            by_field.entry(c.field).or_default().push(c);
        }
    }

    let fields: Vec<FieldEntry> = SubjectField::ALL
        .iter()
        .map(|field| FieldEntry {
            field: *field,
            label: field.label().to_string(),
            is_list: field.is_list(),
            items: items_for(*field, by_field.remove(field).unwrap_or_default()),
        })
        .collect();

    let photo = photo_of(&contributing);
    let filled =
        fields.iter().filter(|f| !f.items.is_empty()).count() + usize::from(photo.is_some());

    SubjectFile {
        fields,
        photo,
        filled,
        total: TOTAL_SLOTS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{NodeStatus, OzPayload, Provenance, RecordStatus};
    use chrono::Utc;

    fn row(label: &str, value: &str) -> OzRow {
        OzRow {
            label: label.into(),
            value: value.into(),
            ..Default::default()
        }
    }

    fn node_of(id: &str, oz_type: OzType, value: &str, tool: &str, rows: Vec<OzRow>) -> OzNode {
        OzNode {
            id: id.into(),
            investigation_id: "inv".into(),
            parent_id: None,
            layer_id: None,
            ordinal: 0,
            depth: 0,
            oz_type,
            value: value.into(),
            display: value.into(),
            dedup_key: crate::normalize::dedup_key(oz_type, value),
            payload: OzPayload::empty_for(oz_type),
            preview_signal: None,
            full_signal: None,
            sections: vec![crate::types::OzSection {
                id: tool.into(),
                label: tool.into(),
                kind: crate::types::SectionKind::KeyValue,
                rows,
            }],
            gated: false,
            status: NodeStatus::Idle,
            provenance: Provenance::new(tool, "test"),
            already_in_tree: None,
            corroborations: Vec::new(),
            edited_value: None,
            created_at: Utc::now(),
        }
    }

    fn entry(file: &SubjectFile, field: SubjectField) -> &FieldEntry {
        file.fields
            .iter()
            .find(|f| f.field == field)
            .expect("every field is always present")
    }

    fn single(file: &SubjectFile, field: SubjectField) -> Vec<String> {
        entry(file, field)
            .items
            .iter()
            .flat_map(|i| i.values.iter().map(|v| v.value.clone()))
            .collect()
    }

    #[test]
    fn all_twelve_fields_are_always_present_even_when_empty() {
        // An absent field and an unsearched field must not render identically, which they
        // would if the fold dropped its empties.
        let file = build(&[]);
        assert_eq!(file.fields.len(), 12);
        assert_eq!(file.total, TOTAL_SLOTS);
        assert_eq!(file.filled, 0);
        assert!(file.fields.iter().all(|f| f.items.is_empty()));
    }

    #[test]
    fn the_field_order_and_labels_match_the_design_export() {
        let file = build(&[]);
        let labels: Vec<&str> = file.fields.iter().map(|f| f.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "FULL NAME",
                "AGE",
                "CITY",
                "POSTAL ADDRESS",
                "EMPLOYER",
                "ROLE",
                "EMAIL ADDRESSES",
                "PHONE NUMBERS",
                "HANDLES",
                "PROFILES",
                "OTHER PRESENCE",
                "MEDIA"
            ]
        );
    }

    #[test]
    fn age_has_no_producer_and_stays_empty() {
        // The earlier design mock demonstrated `AGE ≈ 46`, derived from a `79` in an email
        // local part. Nothing here computes that, and nothing should: an empty field reads as
        // "not found", which is exactly the truth.
        let nodes = vec![node_of(
            "n1",
            OzType::Email,
            "mwrighton79@example.com",
            "t",
            vec![row("Name", "M Wrighton")],
        )];
        let file = build(&nodes);
        assert!(entry(&file, SubjectField::Age).items.is_empty());
    }

    #[test]
    fn two_sources_reporting_the_same_value_agree_into_one_item() {
        // Dedup, not arbitration: one displayed value, both provenances.
        let nodes = vec![
            node_of(
                "n1",
                OzType::Username,
                "a",
                "github-user",
                vec![row("Location", "Amsterdam")],
            ),
            node_of(
                "n2",
                OzType::Username,
                "b",
                "gravatar-profile",
                vec![row("Location", "amsterdam")],
            ),
        ];
        let file = build(&nodes);
        let items = &entry(&file, SubjectField::City).items;
        assert_eq!(items.len(), 1, "agreement collapses to one item");
        assert!(!items[0].is_conflicted());
        assert_eq!(items[0].values.len(), 1);
        assert_eq!(
            items[0].values[0].sources.len(),
            2,
            "both provenances are listed together"
        );
    }

    #[test]
    fn two_sources_disagreeing_are_both_kept_with_no_winner() {
        // The locked rule, and the single most important assertion in this module.
        let nodes = vec![
            node_of(
                "n1",
                OzType::Username,
                "a",
                "github-user",
                vec![row("Company", "Northgate Labs")],
            ),
            node_of(
                "n2",
                OzType::Username,
                "b",
                "gravatar-profile",
                vec![row("Company", "Acme")],
            ),
        ];
        let file = build(&nodes);
        let items = &entry(&file, SubjectField::Employer).items;
        assert_eq!(items.len(), 1, "one fact, in dispute");
        assert!(items[0].is_conflicted());
        assert_eq!(items[0].values.len(), 2);
        let values: Vec<&str> = items[0].values.iter().map(|v| v.value.as_str()).collect();
        assert!(values.contains(&"Northgate Labs") && values.contains(&"Acme"));
        // Each side independently openable — the reason sources hang off the value, not the field.
        assert!(items[0].values.iter().all(|v| v.sources.len() == 1));
    }

    #[test]
    fn a_list_field_appends_distinct_items_rather_than_conflicting() {
        let nodes = vec![
            node_of("n1", OzType::Email, "a@example.com", "t1", vec![]),
            node_of("n2", OzType::Email, "b@example.com", "t2", vec![]),
        ];
        let file = build(&nodes);
        let items = &entry(&file, SubjectField::Emails).items;
        assert_eq!(
            items.len(),
            2,
            "two different addresses are two items, not a conflict"
        );
        assert!(items.iter().all(|i| !i.is_conflicted()));
    }

    #[test]
    fn a_variant_of_an_existing_list_item_is_surfaced_dual_value_not_silently_picked() {
        // The subtler list clause: two spellings that normalize to the same entity are
        // one item in dispute — never one value with the other quietly dropped.
        let nodes = vec![
            node_of("n1", OzType::Email, "M.Wrighton@Example.com", "t1", vec![]),
            node_of("n2", OzType::Email, "m.wrighton@example.com", "t2", vec![]),
        ];
        let file = build(&nodes);
        let items = &entry(&file, SubjectField::Emails).items;
        assert_eq!(items.len(), 1, "one address, two spellings — one item");
        // Case-folding alone makes these agree; the value shown is one of the two, both
        // provenances attached.
        assert_eq!(items[0].values[0].sources.len(), 2);
    }

    #[test]
    fn a_rejected_node_disappears_from_the_deliverable() {
        // The rule that makes derived-never-stored the only workable design.
        let mut nodes = vec![node_of("n1", OzType::Email, "a@example.com", "t", vec![])];
        assert_eq!(
            single(&build(&nodes), SubjectField::Emails),
            vec!["a@example.com"]
        );

        nodes[0].provenance.record_status = RecordStatus::Rejected {
            rejected_at: Utc::now(),
        };
        assert!(
            entry(&build(&nodes), SubjectField::Emails).items.is_empty(),
            "a rejected finding must vanish, not linger"
        );
    }

    #[test]
    fn a_correction_lands_in_the_deliverable_and_is_tagged() {
        // An analyst SAVE promises the corrected value propagates here with a `✎` tag; this
        // is the half that was blocked on this unit existing.
        let mut nodes = vec![node_of(
            "n1",
            OzType::Email,
            "typo@example.com",
            "t",
            vec![],
        )];
        nodes[0].edited_value = Some("fixed@example.com".into());
        nodes[0].provenance.record_status = RecordStatus::Corrected {
            original_value: "typo@example.com".into(),
            original_chip: None,
            edited_at: Utc::now(),
        };

        let file = build(&nodes);
        let items = &entry(&file, SubjectField::Emails).items;
        assert_eq!(items[0].values[0].value, "fixed@example.com");
        assert!(
            items[0].values[0].sources[0].corrected,
            "the correction must be tagged"
        );
    }

    #[test]
    fn a_full_name_is_never_split() {
        // The last-token heuristic inverted Chinese names and mangled compound
        // surnames; the name is now carried exactly as the source spelled it.
        let nodes = vec![node_of(
            "n1",
            OzType::Username,
            "a",
            "t",
            vec![row("Name", "Mathéo Trebosc")],
        )];
        assert_eq!(
            single(&build(&nodes), SubjectField::FullName),
            vec!["Mathéo Trebosc"]
        );

        // The two cases the split got wrong, now simply correct.
        let zh = vec![node_of(
            "n1",
            OzType::Username,
            "a",
            "t",
            vec![row("Name", "毛泽东 Mao Zedong")],
        )];
        assert_eq!(
            single(&build(&zh), SubjectField::FullName),
            vec!["毛泽东 Mao Zedong"]
        );
        let mononym = vec![node_of(
            "n1",
            OzType::Username,
            "a",
            "t",
            vec![row("Name", "Prince")],
        )];
        assert_eq!(
            single(&build(&mononym), SubjectField::FullName),
            vec!["Prince"]
        );
    }

    #[test]
    fn a_node_type_feeds_its_field_from_its_own_value() {
        let nodes = vec![
            node_of("n1", OzType::Username, "kilnwright", "t", vec![]),
            node_of("n2", OzType::Phone, "+31205550182", "t", vec![]),
            node_of("n3", OzType::Ip, "8.8.8.8", "t", vec![]),
            node_of("n4", OzType::Image, "avatar.jpg", "t", vec![]),
        ];
        let file = build(&nodes);
        assert_eq!(single(&file, SubjectField::Handles), vec!["kilnwright"]);
        assert_eq!(single(&file, SubjectField::Phones), vec!["+31205550182"]);
        assert_eq!(single(&file, SubjectField::OtherPresence), vec!["8.8.8.8"]);
        assert_eq!(single(&file, SubjectField::Media), vec!["avatar.jpg"]);
    }

    #[test]
    fn a_non_person_root_gets_no_dossier_at_all_rather_than_an_empty_one() {
        // An empty rail on a CVE investigation would read as "we looked for this
        // person's employer and found none", about an investigation with no person in it.
        for root in [
            OzType::Cve,
            OzType::Hash,
            OzType::Ip,
            OzType::Domain,
            OzType::Coordinate,
        ] {
            assert!(!applies_to(root));
            assert_eq!(
                build_for(root, &[]),
                SubjectFileView::NotApplicable { root_type: root },
                "{root:?} must not be handed a dossier"
            );
        }
        for root in [OzType::Username, OzType::Email, OzType::Name, OzType::Phone] {
            assert!(applies_to(root), "{root:?} is person-shaped");
            assert!(matches!(build_for(root, &[]), SubjectFileView::File(_)));
        }
    }

    #[test]
    fn a_cve_or_a_directory_node_names_no_subject_fact() {
        // Not everything in a tree is about the person. A vulnerability and a launch-tile set
        // describe an artefact and a search surface respectively.
        let nodes = vec![
            node_of("n1", OzType::Cve, "CVE-2026-1", "t", vec![]),
            node_of("n2", OzType::Directory, "pipl", "t", vec![]),
            node_of("n3", OzType::Name, "M Wrighton", "t", vec![]),
        ];
        assert_eq!(build(&nodes).filled, 0);
    }

    #[test]
    fn a_reverse_geocoded_place_is_the_postal_address() {
        // The one street-level string this crate produces. Every other location is city-level,
        // which `relations.rs` already refuses to treat as an address.
        let mut node = node_of(
            "n1",
            OzType::Coordinate,
            "52.37,4.89",
            "geo-nominatim",
            vec![],
        );
        node.payload = OzPayload::Coordinate(crate::types::CoordinatePayload {
            lat: 52.37,
            lon: 4.89,
            accuracy_m: None,
            place: Some("Oudekerksplein 23, Amsterdam".into()),
            country: Some("NL".into()),
            map_links: Vec::new(),
        });
        let file = build(&[node]);
        assert_eq!(
            single(&file, SubjectField::PostalAddress),
            vec!["Oudekerksplein 23, Amsterdam"]
        );
    }

    #[test]
    fn a_profile_row_contributes_its_link_not_the_platform_name() {
        let mut r = row("GitHub", "kilnwright");
        r.href = Some("https://github.com/kilnwright".into());
        let file = build(&[node_of("n1", OzType::Name, "x", "t", vec![r])]);
        assert_eq!(
            single(&file, SubjectField::Profiles),
            vec!["https://github.com/kilnwright"]
        );
    }

    #[test]
    fn the_photo_is_the_thirteenth_slot_not_a_thirteenth_field() {
        let mut avatar = row("Avatar", "https://example.com/a.png");
        avatar.href = Some("https://example.com/a.png".into());
        let file = build(&[node_of("n1", OzType::Name, "x", "t", vec![avatar])]);

        assert_eq!(
            file.fields.len(),
            12,
            "the photo is never one of the twelve"
        );
        assert_eq!(
            file.photo.as_ref().map(|p| p.value.as_str()),
            Some("https://example.com/a.png")
        );
        assert_eq!(file.filled, 1, "the photo counts toward completeness");
        assert_eq!(file.total, 13);
    }

    #[test]
    fn completeness_counts_fields_with_items_plus_the_photo() {
        let nodes = vec![
            node_of("n1", OzType::Email, "a@example.com", "t", vec![]),
            node_of("n2", OzType::Phone, "+31205550182", "t", vec![]),
            node_of(
                "n3",
                OzType::Username,
                "kw",
                "t",
                vec![row("Company", "Northgate")],
            ),
        ];
        let file = build(&nodes);
        // emails, phones, handles, employer — four fields, no photo.
        assert_eq!(file.filled, 4);
        assert!(file.photo.is_none());
    }

    #[test]
    fn a_gated_source_marks_the_value_it_produced() {
        // A finding a gated tool touched stays marked, everywhere.
        let mut node = node_of("n1", OzType::Email, "a@example.com", "t", vec![]);
        node.gated = true;
        let file = build(&[node]);
        assert!(entry(&file, SubjectField::Emails).items[0].values[0].sources[0].gated);
    }

    #[test]
    fn six_fields_are_list_valued_not_four() {
        // A divergence from the original design sketch, pinned so a future change is
        // deliberate rather than a drift back: that sketch marked four list-valued fields
        // (emails, phones, handles, media); this module locks six.
        let list: Vec<SubjectField> = SubjectField::ALL
            .iter()
            .copied()
            .filter(|f| f.is_list())
            .collect();
        assert_eq!(
            list,
            vec![
                SubjectField::Emails,
                SubjectField::Phones,
                SubjectField::Handles,
                SubjectField::Profiles,
                SubjectField::OtherPresence,
                SubjectField::Media,
            ]
        );
    }
}
