//! The whole investigation, as a document a person can leave the
//! cockpit with.
//!
//! The export's shape (subject file + tree + provenance +
//! layer summaries + relations + cost totals) was originally gated on an unresolved product
//! decision ("do not schedule implementation until product confirms export is wanted"). That
//! confirmation is this unit's own commissioning — the earlier UI mock made the case for why an
//! export matters: *"the tree is the method, the dossier is the product"*, and completeness
//! (`SubjectFile::filled` / [`subject_file::TOTAL_SLOTS`]) is what makes a session
//! **terminable** — the analyst is done at 13/13, not when they run out of ideas. An export
//! that could not say that number, or that dropped the provenance behind it, would defeat the
//! reason the unit exists.
//!
//! ## Two formats, one assembly
//!
//! [`Dossier`] is the lossless shape — every [`OzNode`] verbatim, including rejected ones and
//! full [`crate::types::Provenance`] (tool chain, evidence captures, corroborations). It is
//! exactly what `GET /api/ozint/investigations/{id}` already serves, plus per-layer summaries
//! and an export timestamp; nothing is recomputed or thinned. [`to_markdown`] renders the same
//! [`Dossier`] as a document a human reads top to bottom — the subject file first (the
//! deliverable), then the tree (the method), then layers and relations, then cost. A rejected
//! node still appears in the tree (the tree stands even when a subject file does not), but is
//! marked `REJECTED` rather than rendered as a live finding — `OzNode::contributes`
//! already excludes it from the subject file and relations, and the markdown must not
//! contradict that by presenting it as one.
//!
//! ## Provenance is not optional
//!
//! The 2026-07-30 decision that per-node provenance is the *only* traceability mechanism (no
//! separate audit log) only holds if every exported claim still carries its source. Both
//! formats honour it: JSON because [`OzNode::provenance`] is never stripped, and Markdown
//! because [`render_node`] prints `source_tool_id`, `method`, `retrieved_at`, the gated flag and
//! every corroboration for every node it renders — never just the value.
//!
//! ## Person-shaped roots, and non-person roots
//!
//! [`Dossier`] carries [`subject_file::SubjectFileView`] verbatim, including its
//! `NotApplicable` case — a CVE/hash/IP/domain/coordinate root gets an honest
//! statement that no dossier applies, in both formats, never a hollow 0/13 document that reads
//! as a fruitless search for a person who was never the subject.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::relations::RelationReport;
use crate::store::OzLayerRow;
use crate::subject_file::{self, SubjectFileView};
use crate::types::{Investigation, OzNode, RecordStatus};

/// Current export shape. Bump when a field is added, renamed or removed — a consumer reading
/// an old export can at least tell it is old rather than silently misparsing a moved field.
pub const FORMAT_VERSION: u32 = 1;

/// One fired layer, narrowed to what a dossier reader needs: the verdict and the summary
/// sentence, not the raw per-tool report blobs already implied by each node's own provenance.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DossierLayer {
    pub id: String,
    pub parent_node_id: String,
    pub value: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<DateTime<Utc>>,
    pub new_children: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl From<&OzLayerRow> for DossierLayer {
    fn from(row: &OzLayerRow) -> Self {
        Self {
            id: row.id.clone(),
            parent_node_id: row.parent_node_id.clone(),
            value: row.value.clone(),
            status: row.status.clone(),
            started_at: row.started_at,
            settled_at: row.settled_at,
            new_children: row.new_children,
            summary: row.summary.clone(),
        }
    }
}

/// The whole investigation, exportable. Lossless: every field a caller already had in
/// [`Investigation`]/[`OzNode`]/[`RelationReport`]/[`SubjectFileView`] survives verbatim.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dossier {
    pub format_version: u32,
    pub exported_at: DateTime<Utc>,
    pub investigation: Investigation,
    /// `(depth, ordinal)` order, same contract as `store::list_nodes` — includes rejected
    /// nodes, so the export can show what was found and later dismissed, not just what
    /// currently stands.
    pub nodes: Vec<OzNode>,
    /// Oldest-fired-first.
    pub layers: Vec<DossierLayer>,
    pub relations: RelationReport,
    pub subject_file: SubjectFileView,
}

/// Assembles a [`Dossier`] from everything a caller already fetched for
/// `GET /api/ozint/investigations/{id}` — no new store reads, no recomputation beyond the
/// export timestamp.
pub fn build(
    investigation: Investigation,
    nodes: Vec<OzNode>,
    layers: &[OzLayerRow],
    relations: RelationReport,
    subject_file: SubjectFileView,
) -> Dossier {
    Dossier {
        format_version: FORMAT_VERSION,
        exported_at: Utc::now(),
        investigation,
        nodes,
        layers: layers.iter().map(DossierLayer::from).collect(),
        relations,
        subject_file,
    }
}

// ─── Markdown rendering ──────────────────────────────────────────────────────

fn ts(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn render_subject_file(out: &mut String, view: &SubjectFileView) {
    out.push_str("## Subject file\n\n");
    match view {
        SubjectFileView::NotApplicable { root_type } => {
            out.push_str(&format!(
                "No subject file applies to this investigation — the root is `{}` ({}), \
                 not a person. The subject file is mounted only for investigations rooted on a \
                 person, so its absence here is a statement about the subject, not a gap in the \
                 record.\n\n",
                root_type.code(),
                root_type_label(*root_type),
            ));
        }
        SubjectFileView::File(file) => {
            out.push_str(&format!(
                "**Completeness: {} / {}**\n\n",
                file.filled,
                subject_file::TOTAL_SLOTS
            ));
            for entry in &file.fields {
                out.push_str(&format!("### {}\n\n", entry.label));
                if entry.items.is_empty() {
                    out.push_str("_not found_\n\n");
                    continue;
                }
                for item in &entry.items {
                    if item.is_conflicted() {
                        out.push_str("- **CONFLICT** — sources disagree:\n");
                        for value in &item.values {
                            out.push_str(&format!(
                                "  - `{}` (via {})\n",
                                value.value,
                                sources_list(&value.sources)
                            ));
                        }
                    } else if let Some(value) = item.values.first() {
                        out.push_str(&format!(
                            "- {} (via {})\n",
                            value.value,
                            sources_list(&value.sources)
                        ));
                    }
                }
                out.push('\n');
            }
            if let Some(photo) = &file.photo {
                out.push_str(&format!(
                    "### PHOTO\n\n- {} (via {})\n\n",
                    photo.value,
                    sources_list(&photo.sources)
                ));
            }
        }
    }
}

fn sources_list(sources: &[crate::subject_file::FieldSource]) -> String {
    if sources.is_empty() {
        return "unknown source".to_string();
    }
    sources
        .iter()
        .map(|s| s.tool_id.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn root_type_label(t: crate::types::OzType) -> &'static str {
    t.code()
}

fn render_node(out: &mut String, node: &OzNode) {
    let indent = "  ".repeat(node.depth.max(0) as usize);
    let rejected = node.provenance.record_status.is_rejected();
    let marker = if rejected { " — REJECTED" } else { "" };
    out.push_str(&format!(
        "{indent}- **[{}]** {}{marker}\n",
        node.oz_type.code(),
        node.effective_value(),
    ));
    if let RecordStatus::Corrected { original_value, .. } = &node.provenance.record_status {
        out.push_str(&format!("{indent}  - corrected from `{original_value}`\n"));
    }
    out.push_str(&format!(
        "{indent}  - via `{}` — {} ({})",
        node.provenance.source_tool_id,
        node.provenance.method,
        ts(node.provenance.retrieved_at)
    ));
    if node.gated {
        out.push_str(" — GATED");
    }
    out.push('\n');
    if let Some(via) = &node.already_in_tree {
        out.push_str(&format!("{indent}  - already in tree · {via}\n"));
    }
    if !node.corroborations.is_empty() {
        out.push_str(&format!(
            "{indent}  - corroborated by {} additional path(s): {}\n",
            node.corroborations.len(),
            node.corroborations
                .iter()
                .map(|c| c.tool_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

fn render_tree(out: &mut String, nodes: &[OzNode]) {
    out.push_str("## Investigation tree\n\n");
    if nodes.is_empty() {
        out.push_str("_empty_\n\n");
        return;
    }
    for node in nodes {
        render_node(out, node);
    }
    out.push('\n');
}

fn render_layers(out: &mut String, layers: &[DossierLayer]) {
    out.push_str("## Layers fired\n\n");
    if layers.is_empty() {
        out.push_str("_none_\n\n");
        return;
    }
    for layer in layers {
        out.push_str(&format!(
            "- `{}` on `{}` — **{}**",
            layer.id, layer.value, layer.status
        ));
        if layer.new_children > 0 {
            out.push_str(&format!(", {} new", layer.new_children));
        }
        out.push('\n');
        if let Some(summary) = &layer.summary {
            out.push_str(&format!("  - {summary}\n"));
        }
    }
    out.push('\n');
}

fn render_relations(out: &mut String, relations: &RelationReport) {
    out.push_str("## Potential relations\n\n");
    if relations.relations.is_empty() {
        out.push_str("_none found_\n\n");
    } else {
        for relation in &relations.relations {
            out.push_str(&format!(
                "- **{}** ({}, {:?} tier) — {}\n",
                relation.subject,
                relation.kind.label(),
                relation.tier,
                relation.rationale
            ));
            for evidence in &relation.evidence {
                out.push_str(&format!(
                    "  - {} (via `{}`)\n",
                    evidence.detail, evidence.tool_id
                ));
            }
        }
        out.push('\n');
    }
    if !relations.rules_without_input.is_empty() {
        out.push_str("Rules with no source to run on in this tree:\n\n");
        for rule in &relations.rules_without_input {
            out.push_str(&format!("- {} — {}\n", rule.kind.label(), rule.reason));
        }
        out.push('\n');
    }
}

/// Renders a [`Dossier`] as a Markdown document: subject file, tree, layers, relations, cost.
pub fn to_markdown(dossier: &Dossier) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# OZINT dossier — {}\n\n",
        dossier.investigation.seed_input
    ));
    out.push_str(&format!(
        "- Investigation `{}`, seeded as `{}`\n- Created {}, updated {}\n- {} lookup(s), \
         ${:.2} spent\n- Exported {}\n\n",
        dossier.investigation.id,
        dossier.investigation.seed_type.code(),
        ts(dossier.investigation.created_at),
        ts(dossier.investigation.updated_at),
        dossier.investigation.lookups,
        dossier.investigation.cost_cents as f64 / 100.0,
        ts(dossier.exported_at),
    ));

    render_subject_file(&mut out, &dossier.subject_file);
    render_tree(&mut out, &dossier.nodes);
    render_layers(&mut out, &dossier.layers);
    render_relations(&mut out, &dossier.relations);

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OzNode, OzPayload, OzType, Provenance};

    fn root_node(oz_type: OzType, value: &str) -> OzNode {
        OzNode {
            id: "n1".to_string(),
            investigation_id: "inv1".to_string(),
            parent_id: None,
            layer_id: None,
            ordinal: 0,
            depth: 0,
            oz_type,
            value: value.to_string(),
            display: value.to_string(),
            dedup_key: value.to_string(),
            payload: OzPayload::empty_for(oz_type),
            preview_signal: None,
            full_signal: None,
            sections: Vec::new(),
            gated: false,
            status: crate::types::NodeStatus::Idle,
            provenance: Provenance::new("seed", "seeded by the analyst"),
            already_in_tree: None,
            corroborations: Vec::new(),
            edited_value: None,
            created_at: Utc::now(),
        }
    }

    fn investigation(seed_type: OzType) -> Investigation {
        Investigation {
            id: "inv1".to_string(),
            seed_input: "torvalds".to_string(),
            seed_type,
            root_node_id: "n1".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            lookups: 3,
            cost_cents: 0,
            spawned_from_investigation_id: None,
            spawned_from_relation: None,
        }
    }

    #[test]
    fn build_carries_every_node_verbatim_including_rejected_ones() {
        let mut rejected = root_node(OzType::Username, "someone");
        rejected.provenance.record_status = RecordStatus::Rejected {
            rejected_at: Utc::now(),
        };
        let nodes = vec![root_node(OzType::Username, "torvalds"), rejected];
        let dossier = build(
            investigation(OzType::Username),
            nodes.clone(),
            &[],
            RelationReport::default(),
            subject_file::build_for(OzType::Username, &nodes),
        );
        assert_eq!(
            dossier.nodes.len(),
            2,
            "a rejected node must still be exported, not dropped"
        );
        assert_eq!(dossier.format_version, FORMAT_VERSION);
    }

    #[test]
    fn markdown_names_the_source_tool_for_every_node() {
        let nodes = vec![root_node(OzType::Username, "torvalds")];
        let dossier = build(
            investigation(OzType::Username),
            nodes.clone(),
            &[],
            RelationReport::default(),
            subject_file::build_for(OzType::Username, &nodes),
        );
        let md = to_markdown(&dossier);
        assert!(
            md.contains("via `seed`"),
            "provenance must render for every node: {md}"
        );
        assert!(md.contains("torvalds"));
    }

    #[test]
    fn markdown_marks_a_rejected_node_rather_than_omitting_it() {
        let mut rejected = root_node(OzType::Username, "gone");
        rejected.provenance.record_status = RecordStatus::Rejected {
            rejected_at: Utc::now(),
        };
        let nodes = vec![root_node(OzType::Username, "torvalds"), rejected];
        let dossier = build(
            investigation(OzType::Username),
            nodes.clone(),
            &[],
            RelationReport::default(),
            subject_file::build_for(OzType::Username, &nodes),
        );
        let md = to_markdown(&dossier);
        assert!(
            md.contains("REJECTED"),
            "a rejected node must be visibly marked: {md}"
        );
        assert!(
            md.contains("gone"),
            "a rejected node must still appear, not vanish: {md}"
        );
    }

    #[test]
    fn markdown_states_not_applicable_for_a_non_person_root_rather_than_a_hollow_dossier() {
        let nodes = vec![root_node(OzType::Cve, "CVE-2024-38063")];
        let dossier = build(
            investigation(OzType::Cve),
            nodes.clone(),
            &[],
            RelationReport::default(),
            subject_file::build_for(OzType::Cve, &nodes),
        );
        let md = to_markdown(&dossier);
        assert!(
            md.contains("No subject file applies"),
            "must state absence, not render 0/13: {md}"
        );
        assert!(!md.contains("0 / 13"));
    }

    #[test]
    fn markdown_shows_completeness_for_a_person_root() {
        let nodes = vec![root_node(OzType::Username, "torvalds")];
        let dossier = build(
            investigation(OzType::Username),
            nodes.clone(),
            &[],
            RelationReport::default(),
            subject_file::build_for(OzType::Username, &nodes),
        );
        let md = to_markdown(&dossier);
        assert!(md.contains(&format!("/ {}", subject_file::TOTAL_SLOTS)));
    }
}
