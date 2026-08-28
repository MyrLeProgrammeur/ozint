//! `entity-coordinate (GEO)` — the coordinate sources.
//!
//! Four tools, **all keyless**. The first three were verified by direct call on 2026-08-23. This
//! category was expected to need a free key — `GEONAMES_USERNAME`, `YANDEX_GEOCODER_KEY` and
//! `WINDY_API_KEY` were all under consideration — but measured, those three buy *additional*
//! sources (place context, a CIS-specific cross-check, weather-at-date) and none of them is
//! needed to answer the question a GEO node actually asks: where is this, what is around it,
//! and how do I open it somewhere I can look at it. That is the third time a "needs a free key"
//! assumption for this category has turned out to be wrong once each source was actually
//! called.
//!
//! ## Field ownership
//!
//! `runtime::merge_patch` is a shallow last-writer-wins merge, so two tools writing one
//! [`crate::types::CoordinatePayload`] key is a silent overwrite. No field has two writers:
//!
//! | tool | writes | rows |
//! |---|---|---|
//! | [`map_links`] | `mapLinks` | the three external map links |
//! | [`nominatim`] | `place`, `country` | the address breakdown |
//! | [`overpass`] | *nothing* | the named features around the point |
//! | [`geoconfirmed`] | *nothing* | verified conflict placemarks nearby |
//!
//! [`overpass`] is the first tool in this crate whose entire contribution is rows.
//! [`crate::types::CoordinatePayload`] has no field for "what is nearby" and it should not
//! grow one: a POI list is evidence about the surroundings, not a property of the coordinate.
//! It is also what forced `runtime.rs`'s persist guard to widen from "the payload patch is
//! non-empty" to "patch **or** sections" — under the old guard this tool's whole output would
//! have been computed and then dropped.
//!
//! ## The two-block convention, which is a rule and not a layout preference
//!
//! `geo_links.rs` states it: the raw coordinate and the reverse-geocoded place are **never
//! merged**. A coordinate is a measurement; a place name is an interpretation of it by a
//! gazetteer that can be wrong, stale, or simply pointing at the nearest thing it knows about.
//! Nominatim's answer for the Hôtel de Ville in Paris is a *clock* — `amenity=clock`, 40 m
//! away, because that is the nearest tagged node. Presented as one block, "48.856600, 2.352200
//! — 6, Place de l'Hôtel-de-Ville" reads as a fact about the coordinate. Kept apart, it reads
//! as what it is: the closest thing OSM has a name for.
//!
//! ## Absence
//!
//! Every coordinate on Earth is a valid coordinate, so "not found" here never means "no such
//! entity" the way an unregistered domain does. It means the gazetteer has nothing tagged
//! nearby — mid-ocean, empty desert — which is a real finding about the place and is reported
//! as [`crate::outcome::ToolOutcome::OkEmpty`]. Nominatim answers that with a `200` carrying
//! an `{"error": ...}` object rather than a non-2xx status, which is the one shape here that
//! would otherwise be read as a successful parse of nothing.
//!
//! ## GeoConfirmed, landed by the 2026-08-25 category audit
//!
//! This module used to say GeoConfirmed was unwired because "no endpoint enumerates the
//! theatres" — verified **false**: `GET /api/Conflict` (`geoconfirmed.org`) is exactly that
//! index, keyless, 20 entries with their own centre coordinates. The bulk-download half of the
//! old blocker is still real (`GET /api/Placemark/{theatre}` has no spatial filter — Ukraine's
//! is 6.9 MB), but it is now *bounded*: [`geoconfirmed::nearest_theatre`] picks the one closest
//! theatre by haversine distance to its own declared centre instead of guessing from a
//! hand-maintained country table, so at most one theatre's document is ever fetched per
//! coordinate, not all twenty. See `geoconfirmed`'s own module doc for the full two-call shape
//! and both distance thresholds.
//!
//! Sentinel Hub / Google Earth Engine before-after imagery is still deliberately deferred.

pub mod geoconfirmed;
pub mod map_links;
pub mod nominatim;
pub mod overpass;

/// Parses the `lat,lon` node value `normalize::normalize(OzType::Coordinate, …)` produces
/// (`"48.85840,2.29450"` — five decimal places, comma-separated, no space).
///
/// Every tool here re-parses rather than being handed a pair, because `dispatch` speaks in
/// `&str` values for every type and a GEO-shaped exception to that signature would be a worse
/// trade than parsing a string this crate itself wrote five lines earlier. `None` when the
/// value is not that shape at all, which each caller turns into a visible `ParseError` — a
/// coordinate tool handed something that is not a coordinate must say so, never quietly
/// report that it looked and found nothing.
pub fn parse_lat_lon(value: &str) -> Option<(f64, f64)> {
    let (lat, lon) = value.split_once(',')?;
    let lat: f64 = lat.trim().parse().ok()?;
    let lon: f64 = lon.trim().parse().ok()?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some((lat, lon))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_normalizers_own_output_round_trips() {
        let normalized =
            crate::normalize::normalize(crate::types::OzType::Coordinate, "48.8584, 2.2945");
        let (lat, lon) = parse_lat_lon(&normalized.key).expect("the normalizer's own key parses");
        assert!((lat - 48.8584).abs() < 1e-4);
        assert!((lon - 2.2945).abs() < 1e-4);
    }

    #[test]
    fn negative_and_zero_components_survive() {
        assert_eq!(
            parse_lat_lon("-33.86880,-151.20930"),
            Some((-33.8688, -151.2093))
        );
        // Null Island is a real, valid coordinate — dropping it as falsy is a classic bug.
        assert_eq!(parse_lat_lon("0.00000,0.00000"), Some((0.0, 0.0)));
    }

    #[test]
    fn a_value_that_is_not_a_coordinate_is_rejected_rather_than_guessed_at() {
        assert_eq!(parse_lat_lon("anthropic.com"), None);
        assert_eq!(parse_lat_lon("48.8584"), None);
        assert_eq!(parse_lat_lon("48.8584,"), None);
        // Out of range: parseable as two floats, but not a place on Earth.
        assert_eq!(parse_lat_lon("200.0,50.0"), None);
        assert_eq!(parse_lat_lon("48.0,999.0"), None);
    }
}

#[cfg(test)]
mod live_tests {
    //! `#[ignore]`d tests that actually call the two networked endpoints.
    //!
    //! Same reasoning as `sources::domain`'s and `sources::cve`'s: every other test in this
    //! category runs against fixtures transcribed by hand from a live call, and a
    //! transcription can be subtly wrong or quietly go stale. This is the only thing that can
    //! catch an upstream changing shape.
    //!
    //! `cargo test -p ozint -- --ignored`
    //!
    //! Shape and plausibility only — never exact values. Which café is nearest to the Hôtel de
    //! Ville is a moving target by construction, and so is whether OSM's nearest tagged node
    //! is still a clock.

    use crate::outcome::ToolOutcome;
    use crate::sources::{DispatchOutcome, ToolCtx};

    /// The Hôtel de Ville, Paris — normalized to the five-decimal `lat,lon` key shape every
    /// tool here is handed. Dense enough that both endpoints return something, and it is the
    /// point the fixtures in `nominatim.rs` and `overpass.rs` were transcribed from.
    const SUBJECT: &str = "48.85660,2.35220";

    /// Point Nemo, the oceanic pole of inaccessibility. ~2,700 km from the nearest land, so
    /// both endpoints must report genuine absence rather than fail.
    const OPEN_OCEAN: &str = "-48.87600,-123.39330";

    fn produced(outcome: DispatchOutcome) -> crate::registry::ToolYield {
        match outcome {
            DispatchOutcome::Ran(o, produced) => {
                assert!(
                    matches!(o, ToolOutcome::OkWithResults { .. } | ToolOutcome::OkEmpty),
                    "endpoint answered with a non-Ok outcome: {o:?}"
                );
                produced.expect("an Ok outcome must carry a yield")
            }
            DispatchOutcome::Cancelled => panic!("nothing cancelled this"),
        }
    }

    #[tokio::test]
    #[ignore = "hits two live third-party endpoints"]
    async fn the_coordinate_endpoints_still_answer_the_shape_we_parse() {
        let ctx = ToolCtx::default();

        let nominatim = produced(super::nominatim::run_nominatim(SUBJECT, &ctx).await);
        assert!(
            nominatim.payload_patch["place"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
            "Nominatim still returns a display_name for a mapped point"
        );
        assert_eq!(nominatim.payload_patch["country"], "France");
        assert!(
            nominatim.rows.iter().any(|r| r.label == "OSM feature"),
            "the matched-feature row is what keeps a gazetteer's guess from reading as a fact"
        );
        assert!(
            nominatim.payload_patch.get("mapLinks").is_none(),
            "nominatim must not write mapLinks — geo-map-links owns it"
        );

        let overpass = produced(super::overpass::run_overpass(SUBJECT, &ctx).await);
        assert!(
            !overpass.rows.is_empty(),
            "central Paris has named features within 250 m"
        );
        assert!(
            overpass
                .payload_patch
                .as_object()
                .is_some_and(|o| o.is_empty()),
            "overpass contributes rows only — a payload key here would clobber a sibling's"
        );
        for pair in overpass.rows.windows(2) {
            let metres = |row: &crate::types::OzRow| -> i64 {
                row.value
                    .rsplit_once(" · ")
                    .and_then(|(_, d)| d.trim_end_matches(" m").parse().ok())
                    .unwrap_or_else(|| panic!("row value lost its distance suffix: {row:?}"))
            };
            assert!(
                metres(&pair[0]) <= metres(&pair[1]),
                "rows must stay in distance order"
            );
            assert!(
                pair[0].href.is_some(),
                "every feature links to its own OSM page"
            );
        }
    }

    #[tokio::test]
    #[ignore = "hits two live third-party endpoints"]
    async fn the_open_ocean_reads_as_absence_and_never_as_failure() {
        // The whole point of the OkEmpty/failure split. Nominatim answers this with a `200`
        // carrying an `error` key, which is the one shape that would otherwise be read as a
        // successful parse of nothing.
        let ctx = ToolCtx::default();
        for outcome in [
            super::nominatim::run_nominatim(OPEN_OCEAN, &ctx).await,
            super::overpass::run_overpass(OPEN_OCEAN, &ctx).await,
        ] {
            match outcome {
                DispatchOutcome::Ran(ToolOutcome::OkEmpty, _) => {}
                other => panic!("open ocean must read as OkEmpty, got {other:?}"),
            }
        }
    }
}
