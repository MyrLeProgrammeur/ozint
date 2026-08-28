//! The per-investigation visited set keyed on `(OzType, dedup_key)`.
//!
//! This module **consumes** `OzNode::dedup_key`; it does not compute one. Key normalization
//! is `normalize.rs`'s job (a concurrent unit) — this module only ever sees the `&str` a
//! node already carries.
//!
//! The whole point: a rediscovered value must be **annotated on the parent**
//! (`OzNode::already_in_tree`, e.g. `"already in tree · L1"`) instead of spawned as a new
//! node. Without this, a re-found value inflates the child count and an honest
//! `0 NEW ENTITIES` becomes impossible — a repeated site hit, or a manual continue-loop
//! (email → username → back to the same email), would otherwise re-fan-out forever.

use std::collections::HashMap;

use crate::types::{OzNode, OzType};

// ─── Visited entry ──────────────────────────────────────────────────────────

/// Where a value was first (or currently) seen in the tree — enough to render the
/// `already in tree · L{depth}` annotation and to let the caller navigate to the original.
#[derive(Debug, Clone, PartialEq)]
pub struct VisitedEntry {
    /// Id of the node that already holds this value.
    pub node_id: String,
    /// Tree depth of that node (root = 0), matching `OzNode::depth`.
    pub depth: i64,
    /// Id of the layer that produced that node, when known. `None` for the root seed.
    pub layer_id: Option<String>,
}

impl VisitedEntry {
    pub fn new(node_id: impl Into<String>, depth: i64, layer_id: Option<String>) -> Self {
        Self {
            node_id: node_id.into(),
            depth,
            layer_id,
        }
    }

    /// The exact annotation string (`already in tree · L1`), ready to
    /// assign straight to `OzNode::already_in_tree`.
    pub fn annotation(&self) -> String {
        format!("already in tree · L{}", self.depth)
    }
}

// ─── Visited set ────────────────────────────────────────────────────────────

/// A per-investigation-tree visited set keyed on `(OzType, dedup_key)`. Two nodes with the
/// same key are the same entity — see `OzNode::dedup_key`'s own doc comment in `types.rs`.
#[derive(Debug, Clone, Default)]
pub struct VisitedSet {
    entries: HashMap<(OzType, String), VisitedEntry>,
}

impl VisitedSet {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Rehydrates a visited set from a resumed investigation's stored nodes.
    /// This **must** be called before any new layer fires on a reopened
    /// investigation, or the resumed tree will duplicate everything it already contains.
    ///
    /// Decision: rejected nodes are included too. `contributes()`/`RecordStatus::Rejected`
    /// governs whether a value counts toward the subject file and relation inference — a
    /// separate, later judgment about correctness. Dedup is about tree *identity*: the value
    /// is still a node sitting in this tree, still visible (struck through) in the UI, and
    /// re-finding it should still annotate rather than duplicate. Excluding rejected nodes
    /// here would let a manual continue re-create a node the analyst explicitly rejected.
    pub fn from_nodes(nodes: &[OzNode]) -> Self {
        let mut set = Self::new();
        for node in nodes {
            set.entries.insert(
                (node.oz_type, node.dedup_key.clone()),
                VisitedEntry::new(node.id.clone(), node.depth, node.layer_id.clone()),
            );
        }
        set
    }

    /// Looks up whether `(oz_type, dedup_key)` is already in the tree. Callers use this
    /// **before** turning a tool's raw hit into a new child node: a hit → check → if
    /// `Some`, annotate the parent instead of inserting a node.
    pub fn check(&self, oz_type: OzType, dedup_key: &str) -> Option<&VisitedEntry> {
        self.entries.get(&(oz_type, dedup_key.to_string()))
    }

    /// Records a newly-created node's value. Returns `true` when it was genuinely new
    /// (nothing has claimed this key yet — the caller may proceed with the insert it's
    /// backing), `false` when the key was already visited (the existing entry is left
    /// untouched — first-seen wins, since that is the node the annotation should point at).
    pub fn insert(&mut self, oz_type: OzType, dedup_key: &str, entry: VisitedEntry) -> bool {
        if self.entries.contains_key(&(oz_type, dedup_key.to_string())) {
            return false;
        }
        self.entries.insert((oz_type, dedup_key.to_string()), entry);
        true
    }

    /// Removes every visited entry whose `node_id` is in `node_ids`. A re-fire on a node
    /// must call this with the ids of the old subtree it is about to discard **before**
    /// re-running the layer, otherwise the fresh run's hits will all read back as "already in
    /// tree" against the very nodes being replaced, and a refresh could never re-add what it
    /// just removed.
    pub fn clear_subtree(&mut self, node_ids: &[String]) {
        if node_ids.is_empty() {
            return;
        }
        self.entries
            .retain(|_, entry| !node_ids.iter().any(|id| id == &entry.node_id));
    }

    /// Number of distinct visited values. Test/debug convenience.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::types::{OzPayload, Provenance};

    fn node(
        id: &str,
        oz_type: OzType,
        dedup_key: &str,
        depth: i64,
        parent_id: Option<&str>,
    ) -> OzNode {
        OzNode {
            id: id.into(),
            investigation_id: "inv-1".into(),
            parent_id: parent_id.map(|s| s.into()),
            layer_id: Some(format!("layer-{depth}")),
            ordinal: 0,
            depth,
            oz_type,
            value: dedup_key.into(),
            display: dedup_key.into(),
            dedup_key: dedup_key.into(),
            payload: OzPayload::empty_for(oz_type),
            preview_signal: None,
            full_signal: None,
            sections: Vec::new(),
            gated: false,
            status: crate::types::NodeStatus::Idle,
            provenance: Provenance::new("seed", "typed by the analyst"),
            already_in_tree: None,
            corroborations: Vec::new(),
            edited_value: None,
            created_at: Utc::now(),
        }
    }

    // ── basic check/insert ──────────────────────────────────────────────

    #[test]
    fn unknown_key_checks_none() {
        let set = VisitedSet::new();
        assert!(set.check(OzType::Email, "a@b.com").is_none());
    }

    #[test]
    fn insert_then_check_finds_it() {
        let mut set = VisitedSet::new();
        assert!(set.insert(
            OzType::Email,
            "a@b.com",
            VisitedEntry::new("node-1", 1, Some("layer-1".into()))
        ));
        let found = set.check(OzType::Email, "a@b.com").expect("present");
        assert_eq!(found.node_id, "node-1");
        assert_eq!(found.depth, 1);
    }

    #[test]
    fn insert_is_type_scoped_not_just_key_scoped() {
        // Same raw string, different OzType, must not collide (e.g. a domain and a hash that
        // happen to share a normalized form).
        let mut set = VisitedSet::new();
        set.insert(OzType::Domain, "x", VisitedEntry::new("node-1", 0, None));
        assert!(set.check(OzType::Hash, "x").is_none());
    }

    #[test]
    fn second_insert_of_same_key_is_rejected_and_keeps_first_entry() {
        let mut set = VisitedSet::new();
        assert!(set.insert(
            OzType::Email,
            "a@b.com",
            VisitedEntry::new("node-1", 1, None)
        ));
        assert!(!set.insert(
            OzType::Email,
            "a@b.com",
            VisitedEntry::new("node-2", 3, None)
        ));
        // First-seen wins: the annotation should point at the original node.
        assert_eq!(
            set.check(OzType::Email, "a@b.com").unwrap().node_id,
            "node-1"
        );
    }

    // ── annotation ───────────────────────────────────────────────────────

    #[test]
    fn annotation_matches_the_locked_format() {
        let entry = VisitedEntry::new("node-1", 1, None);
        assert_eq!(entry.annotation(), "already in tree · L1");
        let entry = VisitedEntry::new("node-2", 3, None);
        assert_eq!(entry.annotation(), "already in tree · L3");
    }

    // ── the continue-loop guard (email → username → same email) ────────

    #[test]
    fn continue_loop_is_caught_by_check_before_reinsert() {
        let mut set = VisitedSet::new();
        // L0: seed email.
        set.insert(OzType::Email, "a@b.com", VisitedEntry::new("root", 0, None));
        // L1: a username child found from that email.
        set.insert(
            OzType::Username,
            "handle",
            VisitedEntry::new("child-usr", 1, Some("layer-1".into())),
        );
        // L2: the username's own layer resolves back to the very same email.
        let rediscovered = set.check(OzType::Email, "a@b.com");
        assert!(
            rediscovered.is_some(),
            "the manual continue-loop must be caught, not re-inserted"
        );
        assert_eq!(rediscovered.unwrap().node_id, "root");
    }

    // ── from_nodes rehydration ───────────────────────────────────────────

    #[test]
    fn from_nodes_rehydrates_every_node() {
        let nodes = vec![
            node("root", OzType::Email, "a@b.com", 0, None),
            node("n1", OzType::Username, "handle", 1, Some("root")),
            node("n2", OzType::Domain, "example.com", 1, Some("root")),
        ];
        let set = VisitedSet::from_nodes(&nodes);
        assert_eq!(set.len(), 3);
        assert_eq!(set.check(OzType::Email, "a@b.com").unwrap().node_id, "root");
        assert_eq!(set.check(OzType::Username, "handle").unwrap().node_id, "n1");
        assert_eq!(
            set.check(OzType::Domain, "example.com").unwrap().node_id,
            "n2"
        );
    }

    #[test]
    fn from_nodes_includes_rejected_nodes() {
        let mut rejected = node("n1", OzType::Username, "handle", 1, None);
        rejected.provenance.record_status = crate::types::RecordStatus::Rejected {
            rejected_at: Utc::now(),
        };
        assert!(!rejected.contributes());
        let set = VisitedSet::from_nodes(&[rejected]);
        // Still visited: a rejected node is a correctness judgment, not a tree-identity one.
        assert!(set.check(OzType::Username, "handle").is_some());
    }

    #[test]
    fn resumed_investigation_does_not_duplicate_on_first_new_layer() {
        let nodes = vec![
            node("root", OzType::Domain, "example.com", 0, None),
            node("n1", OzType::Domain, "sub.example.com", 1, Some("root")),
        ];
        let set = VisitedSet::from_nodes(&nodes);
        // A brand-new layer re-discovers the same subdomain.
        assert!(set.check(OzType::Domain, "sub.example.com").is_some());
    }

    // ── clear_subtree ────────────────────────────────────────────────────

    #[test]
    fn clear_subtree_removes_only_listed_nodes() {
        let mut set = VisitedSet::new();
        set.insert(
            OzType::Domain,
            "example.com",
            VisitedEntry::new("root", 0, None),
        );
        set.insert(
            OzType::Domain,
            "sub.example.com",
            VisitedEntry::new("n1", 1, Some("layer-1".into())),
        );
        set.insert(
            OzType::Ip,
            "1.2.3.4",
            VisitedEntry::new("n2", 1, Some("layer-1".into())),
        );

        set.clear_subtree(&["n1".to_string(), "n2".to_string()]);

        assert!(
            set.check(OzType::Domain, "example.com").is_some(),
            "root must survive"
        );
        assert!(set.check(OzType::Domain, "sub.example.com").is_none());
        assert!(set.check(OzType::Ip, "1.2.3.4").is_none());
    }

    #[test]
    fn clear_subtree_then_reinsert_succeeds() {
        // The exact "re-fire must clear old keys first" scenario: without clear_subtree, a
        // refresh could never re-add what it just removed.
        let mut set = VisitedSet::new();
        set.insert(
            OzType::Domain,
            "sub.example.com",
            VisitedEntry::new("n1", 1, Some("layer-1".into())),
        );

        // Naive re-fire without clearing: blocked.
        assert!(!set.insert(
            OzType::Domain,
            "sub.example.com",
            VisitedEntry::new("n1-v2", 1, Some("layer-2".into()))
        ));

        set.clear_subtree(&["n1".to_string()]);

        // Now the re-fire can re-add the (possibly re-generated) node.
        assert!(set.insert(
            OzType::Domain,
            "sub.example.com",
            VisitedEntry::new("n1-v2", 1, Some("layer-2".into()))
        ));
        assert_eq!(
            set.check(OzType::Domain, "sub.example.com")
                .unwrap()
                .node_id,
            "n1-v2"
        );
    }

    #[test]
    fn clear_subtree_with_empty_list_is_a_no_op() {
        let mut set = VisitedSet::new();
        set.insert(
            OzType::Domain,
            "example.com",
            VisitedEntry::new("root", 0, None),
        );
        set.clear_subtree(&[]);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn is_empty_reflects_state() {
        let mut set = VisitedSet::new();
        assert!(set.is_empty());
        set.insert(
            OzType::Domain,
            "example.com",
            VisitedEntry::new("root", 0, None),
        );
        assert!(!set.is_empty());
    }
}
