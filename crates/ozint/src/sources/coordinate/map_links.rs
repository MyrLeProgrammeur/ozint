//! `geo-map-links` — the external map links for a coordinate. **Makes no network call**, the
//! same way `sources::directory` doesn't: it is a set of keyless URL templates.
//!
//! ## Finally getting a caller
//!
//! `geo_links.rs` shipped complete on 2026-08-21 — three providers, signed and zero-preserving
//! component formatting, a `format_coordinate` that round-trips, twelve tests — and then
//! nothing in the repo called `map_links()` or `coordinate_sections()`. `relations.rs` reads
//! `payload.map_links` when it mines a coordinate node for evidence, so the *consumer* existed
//! too; only the producer-to-consumer wire was missing, and `map_links` is `Vec<OzRow>` with a
//! `skip_serializing_if = "Vec::is_empty"`, so an always-empty vector serialized to nothing
//! and looked exactly like a coordinate node with no links yet. Same shape as the fetch cache,
//! the source scheduler and the classifier's LLM tier before it.
//!
//! ## Why the links are both a payload field and rows
//!
//! Not duplication for its own sake — two different consumers that must not be collapsed.
//! `CoordinatePayload::map_links` is what `relations::infer` walks, and it is typed; the rows
//! are what the analyst's detail panel renders through the generic per-tool section fold in
//! `runtime.rs`. Writing only the payload would give a coordinate node an empty panel; writing
//! only the rows would silently remove a coordinate from relation inference. They are built
//! from the one call to [`crate::geo_links::map_links`], so they cannot drift.
//!
//! ## Why a tool and not something node creation does
//!
//! A tool is accountable. It appears in the layer's `ToolReport` list with a method sentence,
//! so the analyst can see that the links were produced and by what — where a side effect of
//! node creation would just make three rows appear with no stated origin. It is also the only
//! honest place for the failure case: handed a value that is not a coordinate, it reports a
//! `ParseError` rather than an empty link set.

use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;

/// Resolves the external map links for `value`. Synchronous — there is nothing to await.
pub fn run_map_links(value: &str) -> DispatchOutcome {
    let Some((lat, lon)) = super::parse_lat_lon(value) else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("`{value}` is not a normalized `lat,lon` coordinate"),
            },
            None,
        );
    };

    let rows = crate::geo_links::map_links(lat, lon);
    let count = rows.len() as u32;

    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults { count },
        Some(ToolYield {
            payload_patch: serde_json::json!({ "mapLinks": rows }),
            rows,
            ..Default::default()
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yielded(outcome: DispatchOutcome) -> ToolYield {
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { .. }, Some(produced)) => produced,
            other => panic!("expected results, got {other:?}"),
        }
    }

    #[test]
    fn the_payload_field_and_the_rows_are_the_same_links() {
        // The property that keeps the two consumers from drifting: `relations::infer` reads
        // the payload, the detail panel reads the rows, and a coordinate must never be in one
        // and not the other.
        let produced = yielded(run_map_links("48.85840,2.29450"));
        let patched = produced.payload_patch["mapLinks"]
            .as_array()
            .expect("mapLinks");
        assert_eq!(patched.len(), produced.rows.len());
        assert_eq!(patched.len(), 3, "Google Maps, OpenStreetMap, Apple Maps");
        for (row, value) in produced.rows.iter().zip(patched) {
            assert_eq!(&serde_json::to_value(row).unwrap(), value);
        }
    }

    #[test]
    fn every_link_carries_an_href_and_the_coordinate_itself() {
        let produced = yielded(run_map_links("-33.86880,-151.20930"));
        for row in &produced.rows {
            let href = row
                .href
                .as_deref()
                .expect("a map link without a URL is not a link");
            // The sign is the trap `geo_links` was written around: a link that drops the
            // minus points at a different hemisphere without erroring.
            assert!(href.contains("-33.868800"), "latitude sign lost: {href}");
            assert!(href.contains("-151.209300"), "longitude sign lost: {href}");
        }
    }

    #[test]
    fn a_non_coordinate_value_is_a_parse_error_and_never_an_empty_link_set() {
        // "We produced no links" and "that was not a coordinate" are different facts, and only
        // the first would let a broken node render as a finished one.
        match run_map_links("not-a-coordinate") {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None) => {
                assert!(message.contains("not-a-coordinate"));
            }
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }
}
