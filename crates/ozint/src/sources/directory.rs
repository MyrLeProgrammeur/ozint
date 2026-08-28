//! `entity-directory (DIR/NAM)` — the dispatcher half of the launch-only tile resolver.
//!
//! The catalogue, the URL templates and their hand-verification live in
//! [`crate::directory`]. This module is the thin adapter that lets the layer runtime fire it
//! like any other tool.
//!
//! ## Why one tool per entity type, and not one per tile family
//!
//! It would read better in the UI to fan a `NAM` layer out into "people search", "dorks" and
//! so on, each reporting its own outcome. The engine forbids it, for a reason worth naming
//! because the failure would be **completely silent**: `runtime::merge_patch` is a *shallow*
//! last-writer-wins merge, deliberately (its own doc explains why a deep merge would blend two
//! tools' conflicting views of one object). Every directory tool writes the same key —
//! `tiles`, the only field [`crate::types::DirectoryPayload`] has — so a second family tool
//! would overwrite the first's tiles wholesale. The layer would report two tools green, and
//! the node would silently carry one family's links. Nothing would raise an error, and the
//! tile list would simply be short.
//!
//! So there is exactly one dispatchable tool per directory-shaped entity type, each resolving
//! its whole tile set in one call: `dir-tiles-person` for [`OzType::Name`] and
//! `dir-tiles-entity` for [`OzType::Directory`]. The type is carried by the *tool id* rather
//! than by a parameter because [`crate::sources::dispatch`]'s signature does not pass one —
//! and two ids is a truthful split anyway, since the two resolve genuinely different tile sets.
//!
//! ## Zero network calls, and therefore no cancellation
//!
//! `dispatch` hands every tool a [`crate::fetch::CancelSignal`]. This one ignores it, and that
//! is correct rather than sloppy: resolution is a few string substitutions with no await point
//! in it, so there is no window in which a cancel could land. `fire_layer` checks the signal
//! itself before each tool, which is where a kill during a directory layer is actually
//! honoured.

use crate::directory;
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzType;

/// Resolves every launch-only tile for `oz_type`/`value` and folds them into a
/// [`ToolYield`] that patches the firing node's own payload.
///
/// The tiles are **not** children. A directory layer creates no new entities by design — the
/// links it produces are facts about the node it fired on, exactly like a `USR` node's
/// `14 / 312 sites`, so they travel on `payload_patch` and the layer settles `Empty`. That is
/// the honest verdict for this shape: zero new entities, and `summary::classify_case` overrides
/// the wording with `DirectoryOnlyDeadEnd` so the analyst is told it is a dead end *by design*
/// rather than a search that came up short.
pub fn run_dir_tiles(oz_type: OzType, value: &str) -> DispatchOutcome {
    let tiles = directory::resolve_tiles(oz_type, value);

    if tiles.is_empty() {
        // Reachable only for a value with nothing substitutable in it at all. `OkEmpty`, not
        // an error: the resolver ran to completion and genuinely produced nothing, which is
        // the exact distinction `outcome.rs` exists to keep.
        return DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        );
    }

    let count = tiles.len() as u32;
    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults { count },
        Some(ToolYield {
            payload_patch: serde_json::json!({ "tiles": tiles }),
            ..Default::default()
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DirectoryPayload, OzPayload};

    fn yielded(outcome: DispatchOutcome) -> (ToolOutcome, ToolYield) {
        match outcome {
            DispatchOutcome::Ran(o, Some(y)) => (o, y),
            other => panic!("expected a yielding Ran, got {other:?}"),
        }
    }

    #[test]
    fn a_person_resolves_tiles_and_reports_their_count() {
        let (outcome, produced) = yielded(run_dir_tiles(OzType::Name, "John Doe"));
        let tiles = produced.payload_patch["tiles"]
            .as_array()
            .expect("tiles array")
            .len();
        assert_eq!(
            outcome,
            ToolOutcome::OkWithResults {
                count: tiles as u32
            }
        );
        assert_eq!(tiles, 7, "5 people-search vendors + 2 dork builders");
    }

    #[test]
    fn the_patch_round_trips_into_a_directory_payload() {
        // The contract the runtime actually relies on: `persist_parent_payload` serialises the
        // node's payload, shallow-merges this patch into it, and deserialises it back. If the
        // patch's shape did not match `DirectoryPayload`, that `from_value` would return `None`
        // and the whole layer's findings would vanish with no error anywhere.
        let (_, produced) = yielded(run_dir_tiles(OzType::Name, "John Doe"));

        let mut payload_json =
            serde_json::to_value(OzPayload::Name(DirectoryPayload::default())).expect("serialise");
        let (serde_json::Value::Object(dst), serde_json::Value::Object(src)) =
            (&mut payload_json, &produced.payload_patch)
        else {
            panic!("both sides must be objects for the shallow merge")
        };
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }

        let merged: OzPayload = serde_json::from_value(payload_json).expect("re-typed");
        match merged {
            OzPayload::Name(p) => {
                assert_eq!(p.tiles.len(), 7);
                assert!(p.tiles.iter().all(|t| t.live.is_none()));
            }
            other => panic!("the merge changed the payload's type: {other:?}"),
        }
    }

    #[test]
    fn an_entity_resolves_only_the_dork_builders() {
        let (outcome, produced) = yielded(run_dir_tiles(OzType::Directory, "Acme Corporation"));
        assert_eq!(outcome, ToolOutcome::OkWithResults { count: 2 });
        assert_eq!(
            produced.payload_patch["tiles"]
                .as_array()
                .expect("tiles")
                .len(),
            2
        );
    }

    #[test]
    fn the_layer_produces_no_children_ever() {
        // The rule that makes a directory layer settle `Empty` rather than `Settled`, and the
        // one thing that would quietly turn this unit into an auto-expanding tree if it broke.
        for (oz_type, value) in [
            (OzType::Name, "John Doe"),
            (OzType::Directory, "Acme Corporation"),
        ] {
            let (_, produced) = yielded(run_dir_tiles(oz_type, value));
            assert!(
                produced.children.is_empty(),
                "{oz_type:?} produced a child node"
            );
            assert!(produced.facts.is_empty());
            assert!(produced.flags.is_empty());
        }
    }

    #[test]
    fn a_value_with_nothing_substitutable_reports_ok_empty_with_an_empty_object_patch() {
        let (outcome, produced) = yielded(run_dir_tiles(OzType::Directory, "!!! ???"));
        assert_eq!(outcome, ToolOutcome::OkEmpty);
        // `{}`, not `null`: `ToolYield::payload_patch`'s own doc requires the JSON-merge-patch
        // no-op, and `merge_patch` would silently drop a `null` instead.
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }
}
