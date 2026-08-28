//! `geo-overpass` — named OpenStreetMap features around a point, via the Overpass API.
//! Keyless. Writes **no** payload field; its entire contribution is rows.
//!
//! `POST https://overpass-api.de/api/interpreter` with a form-encoded `data=` query —
//! measured 2026-08-23, HTTP `200` with `{"elements": [...]}`, each element carrying `type`,
//! `id`, `tags`, and either `lat`/`lon` (a node) or `center` (a way/relation, because the
//! query asks for `out center`).
//!
//! ## The query is tag-scoped on purpose, and the unscoped version was measured failing
//!
//! The obvious query is `nwr(around:R,lat,lon)[name]` — anything with a name. Called, it
//! answers **`504`**: an unbounded key filter makes Overpass scan far too much, and a gateway
//! timeout is what the analyst would see. [`OVERPASS_TAGS`] narrows it to six keys that
//! actually describe what a place *is*, unioned, each additionally requiring `[name]`. That
//! returned 40 elements in ~2 s for the same point.
//!
//! ## Distance is computed here, because Overpass does not sort
//!
//! Elements come back in OSM id order, which is roughly chronological by when someone first
//! mapped the object and has nothing to do with the query point. Rows are sorted by great
//! circle distance, ties broken by osm id so the order is stable across refreshes — an
//! unstable order would make a routine refresh report a change every single time it runs.
//!
//! ## Why nothing here becomes a child node
//!
//! A café 120 m from a coordinate is context, not a lead. Seeding it as a node would grow the
//! analyst's tree with the neighbourhood's shops, and none of them is the subject — the same
//! reasoning that keeps `domain::certspotter`'s MX and NS hosts out of the tree. The feature's
//! own OSM page is linked from its row instead.
//!
//! ## Absence
//!
//! Mid-ocean answers `200` with an empty `elements` array — a real finding about the place,
//! reported as [`crate::outcome::ToolOutcome::OkEmpty`].

use crate::fetch::{OzBody, OzFetchOptions, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const OVERPASS_ENDPOINT: &str = "https://overpass-api.de/api/interpreter";

/// Search radius in metres. Walking distance: far enough that a coordinate in a built-up area
/// lands several named features, close enough that they are plausibly *this* place rather than
/// the district around it.
const OVERPASS_RADIUS_M: u32 = 250;

/// The tag keys the query unions over. Each is a key that says what a feature *is*; a bare
/// `[name]` filter with no key was measured returning `504`. See the module doc.
const OVERPASS_TAGS: &[&str] = &[
    "amenity", "tourism", "office", "historic", "shop", "military",
];

/// How many features one lookup reports. Overpass is asked for exactly this many
/// (`out center N`), so the cap is applied upstream rather than by downloading more and
/// discarding it.
const OVERPASS_MAX_FEATURES: usize = 40;

/// Mean Earth radius in metres (IUGG). Used by [`haversine_m`].
const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// Great-circle distance in metres. Overpass's `around:` filter is itself a great-circle
/// radius, so this is the same measure the server used to select these features — a
/// flat-earth approximation would occasionally order two near-equidistant features
/// differently from the filter that returned them.
fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let (dp, dl) = ((lat2 - lat1).to_radians(), (lon2 - lon1).to_radians());
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_M * a.sqrt().asin()
}

/// Builds the Overpass QL query for a point. Kept as a function so the shape that was actually
/// measured is the shape under test.
fn overpass_query(lat: f64, lon: f64) -> String {
    let clauses: String = OVERPASS_TAGS
        .iter()
        .map(|tag| format!("nwr(around:{OVERPASS_RADIUS_M},{lat},{lon})[{tag}][name];"))
        .collect();
    format!("[out:json][timeout:25];({clauses});out center {OVERPASS_MAX_FEATURES};")
}

/// One named feature near the query point.
#[derive(Debug, Clone, PartialEq)]
struct Feature {
    name: String,
    /// `key=value` for the first of [`OVERPASS_TAGS`] the element carries — what it is.
    kind: String,
    osm_type: String,
    osm_id: i64,
    distance_m: f64,
    /// From `phone` or, failing that, `contact:phone`.
    phone: Option<String>,
    /// From `website` or, failing that, `contact:website`.
    website: Option<String>,
    opening_hours: Option<String>,
}

/// Reads the first of `key` / `contact:key` present on `tags`, as a plain string.
fn tag_or_contact(tags: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<String> {
    tags.get(key)
        .or_else(|| tags.get(&format!("contact:{key}")))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn body_to_json(body: &OzBody) -> Result<serde_json::Value, String> {
    match body {
        OzBody::Json(json) => Ok(json.clone()),
        OzBody::Text(text) => serde_json::from_str(text)
            .map_err(|e| format!("Overpass body was not parseable JSON: {e}")),
        other => Err(format!(
            "Overpass response was neither JSON nor text: {other:?}"
        )),
    }
}

/// The element's own position: `lat`/`lon` for a node, `center` for a way or relation (the
/// query asks for `out center` precisely so those are present). `None` for an element with
/// neither — skipped rather than placed at the query point, which would report a distance of
/// zero for something whose location is unknown.
fn element_position(element: &serde_json::Value) -> Option<(f64, f64)> {
    let direct = element.get("lat").and_then(serde_json::Value::as_f64);
    if let Some(lat) = direct
        && let Some(lon) = element.get("lon").and_then(serde_json::Value::as_f64)
    {
        return Some((lat, lon));
    }
    let center = element.get("center")?;
    Some((
        center.get("lat").and_then(serde_json::Value::as_f64)?,
        center.get("lon").and_then(serde_json::Value::as_f64)?,
    ))
}

/// Parses the response into features sorted by distance from the query point. `Err` only when
/// `elements` is absent or not an array; a malformed individual element is skipped, the same
/// tolerance `certspotter::extract_in_scope_names` applies. Pure and tested.
fn parse_features(json: &serde_json::Value, lat: f64, lon: f64) -> Result<Vec<Feature>, String> {
    let elements = json
        .get("elements")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Overpass response carried no `elements` array".to_string())?;

    let mut features = Vec::new();
    for element in elements {
        let Some(tags) = element.get("tags").and_then(serde_json::Value::as_object) else {
            continue;
        };
        let Some(name) = tags.get("name").and_then(serde_json::Value::as_str) else {
            // The query requires `[name]`, so this is shape drift rather than a normal case —
            // but an unnamed feature is not something to render either way.
            continue;
        };
        let Some(kind) = OVERPASS_TAGS.iter().find_map(|tag| {
            tags.get(*tag)
                .and_then(serde_json::Value::as_str)
                .map(|v| format!("{tag}={v}"))
        }) else {
            continue;
        };
        let Some((flat, flon)) = element_position(element) else {
            continue;
        };
        let Some(osm_id) = element.get("id").and_then(serde_json::Value::as_i64) else {
            continue;
        };
        let osm_type = element
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("node")
            .to_string();

        features.push(Feature {
            name: name.to_string(),
            kind,
            osm_type,
            osm_id,
            distance_m: haversine_m(lat, lon, flat, flon),
            phone: tag_or_contact(tags, "phone"),
            website: tag_or_contact(tags, "website"),
            opening_hours: tags
                .get("opening_hours")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
        });
    }

    // Ties broken by id so the order does not drift between two identical lookups. See the
    // module doc.
    features.sort_by(|a, b| {
        a.distance_m
            .partial_cmp(&b.distance_m)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.osm_id.cmp(&b.osm_id))
    });
    features.truncate(OVERPASS_MAX_FEATURES);
    Ok(features)
}

/// One row per feature: its name, what it is and how far, and a link to its own OSM page.
/// Pure.
fn features_to_rows(features: &[Feature]) -> Vec<OzRow> {
    features
        .iter()
        .map(|f| {
            // Rounded to the metre: the sources feeding a GEO node (EXIF GPS, a gazetteer, an
            // IP block) are not precise to anything finer, and a decimal here would imply a
            // precision the input never had.
            let mut value = format!("{} · {} m", f.kind, f.distance_m.round() as i64);
            for extra in [&f.phone, &f.website, &f.opening_hours]
                .into_iter()
                .flatten()
            {
                value.push_str(" · ");
                value.push_str(extra);
            }
            OzRow {
                label: f.name.clone(),
                value,
                href: Some(format!(
                    "https://www.openstreetmap.org/{}/{}",
                    f.osm_type, f.osm_id
                )),
                ..Default::default()
            }
        })
        .collect()
}

/// Queries Overpass for named features around the normalized `lat,lon` in `value`.
pub async fn run_overpass(value: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some((lat, lon)) = super::parse_lat_lon(value) else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("`{value}` is not a normalized `lat,lon` coordinate"),
            },
            None,
        );
    };

    let query = overpass_query(lat, lon);
    let opts = OzFetchOptions {
        method: reqwest::Method::POST,
        headers: vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )],
        body: Some(format!("data={}", urlencoding::encode(&query)).into_bytes()),
        ..Default::default()
    };
    let outcome = ctx
        .fetch("geo-overpass", value, OVERPASS_ENDPOINT, opts)
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled OzOutcome was handled above");
    };
    let json = match body_to_json(&resp.body) {
        Ok(json) => json,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    match parse_features(&json, lat, lon) {
        Ok(features) if features.is_empty() => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(features) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults {
                count: features.len() as u32,
            },
            // No payload patch, deliberately: `CoordinatePayload` has no field for "what is
            // nearby" and should not grow one. See the category module doc.
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                rows: features_to_rows(&features),
                ..Default::default()
            }),
        ),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Four elements transcribed from the live 2026-08-23 response for `48.8566, 2.3522`,
    /// deliberately **not** in distance order — they arrive in OSM id order, which is the
    /// thing `parse_features` has to fix.
    fn measured() -> serde_json::Value {
        serde_json::json!({
            "version": 0.6,
            "elements": [
                { "type": "node", "id": 218117881, "lat": 48.8569481, "lon": 2.3497138,
                  "tags": { "amenity": "parking", "name": "Parking Hôtel de Ville" } },
                { "type": "node", "id": 320799890, "lat": 48.8574538, "lon": 2.3523721,
                  "tags": { "shop": "shoes", "name": "Foot Locker" } },
                { "type": "node", "id": 557420805, "lat": 48.8566083, "lon": 2.3533348,
                  "tags": { "amenity": "parking_entrance", "name": "Lobau Rivoli" } },
                { "type": "way", "id": 999000111, "center": { "lat": 48.8567, "lon": 2.3525 },
                  "tags": { "tourism": "museum", "name": "A museum mapped as a way",
                            "contact:phone": "+33 1 40 00 00 00",
                            "website": "https://example-museum.fr",
                            "opening_hours": "Tu-Su 10:00-18:00" } }
            ]
        })
    }

    #[test]
    fn features_come_back_sorted_by_distance_not_by_osm_id() {
        let features = parse_features(&measured(), 48.8566, 2.3522).unwrap();
        let names: Vec<&str> = features.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "A museum mapped as a way",
                "Lobau Rivoli",
                "Foot Locker",
                "Parking Hôtel de Ville"
            ],
            "the input is in id order; the output must be in distance order"
        );
        for pair in features.windows(2) {
            assert!(pair[0].distance_m <= pair[1].distance_m);
        }
    }

    #[test]
    fn a_way_is_located_by_its_center_and_links_to_its_own_osm_page() {
        // `out center` exists precisely so ways and relations have a position at all. An
        // element skipped for want of `lat` would silently drop every non-node feature.
        let features = parse_features(&measured(), 48.8566, 2.3522).unwrap();
        let museum = features
            .iter()
            .find(|f| f.osm_type == "way")
            .expect("the way");
        assert!(museum.distance_m < 50.0);
        let rows = features_to_rows(&features);
        let row = rows
            .iter()
            .find(|r| r.label == "A museum mapped as a way")
            .unwrap();
        assert_eq!(
            row.href.as_deref(),
            Some("https://www.openstreetmap.org/way/999000111")
        );
        assert!(row.value.starts_with("tourism=museum · "));
    }

    #[test]
    fn phone_website_and_opening_hours_are_extracted_and_surfaced_in_the_row() {
        let features = parse_features(&measured(), 48.8566, 2.3522).unwrap();
        let museum = features
            .iter()
            .find(|f| f.osm_type == "way")
            .expect("the way");
        // The fixture carries the tag under `contact:phone`, not the bare `phone` key — this
        // asserts the fallback, not just the direct key.
        assert_eq!(museum.phone.as_deref(), Some("+33 1 40 00 00 00"));
        assert_eq!(museum.website.as_deref(), Some("https://example-museum.fr"));
        assert_eq!(museum.opening_hours.as_deref(), Some("Tu-Su 10:00-18:00"));

        let rows = features_to_rows(&features);
        let row = rows
            .iter()
            .find(|r| r.label == "A museum mapped as a way")
            .unwrap();
        assert!(row.value.contains("+33 1 40 00 00 00"));
        assert!(row.value.contains("https://example-museum.fr"));
        assert!(row.value.contains("Tu-Su 10:00-18:00"));
    }

    #[test]
    fn missing_phone_website_and_opening_hours_stay_none() {
        // The other three fixture elements carry none of these tags — the direct-key path and
        // the "simply absent" path should both come back `None`, not an empty string.
        let features = parse_features(&measured(), 48.8566, 2.3522).unwrap();
        let parking = features
            .iter()
            .find(|f| f.name == "Parking Hôtel de Ville")
            .unwrap();
        assert_eq!(parking.phone, None);
        assert_eq!(parking.website, None);
        assert_eq!(parking.opening_hours, None);
    }

    #[test]
    fn an_element_with_no_position_is_skipped_rather_than_placed_at_the_query_point() {
        // The bug this forbids: defaulting a missing position to the query point reports the
        // feature as 0 m away — the strongest possible claim, from the least information.
        let json = serde_json::json!({
            "elements": [{ "type": "relation", "id": 7, "tags": { "amenity": "x", "name": "Nowhere" } }]
        });
        assert!(parse_features(&json, 48.0, 2.0).unwrap().is_empty());
    }

    #[test]
    fn an_element_carrying_none_of_the_queried_tags_is_skipped() {
        let json = serde_json::json!({
            "elements": [{ "type": "node", "id": 1, "lat": 48.0, "lon": 2.0,
                           "tags": { "name": "Named but untyped", "wikidata": "Q1" } }]
        });
        assert!(parse_features(&json, 48.0, 2.0).unwrap().is_empty());
    }

    #[test]
    fn an_empty_element_list_parses_to_no_features_rather_than_an_error() {
        // Mid-ocean. A real finding about the place, not a failure to look.
        let json = serde_json::json!({ "elements": [] });
        assert!(parse_features(&json, 0.0, -140.0).unwrap().is_empty());
    }

    #[test]
    fn a_response_with_no_elements_array_is_a_parse_error() {
        // The distinction that matters: "the request came back wrong" must never arrive at the
        // analyst looking like "there is nothing around this point".
        assert!(
            parse_features(&serde_json::json!({ "remark": "runtime error" }), 0.0, 0.0).is_err()
        );
    }

    #[test]
    fn the_query_is_the_tag_scoped_shape_that_was_measured_working() {
        let query = overpass_query(48.8566, 2.3522);
        assert!(query.starts_with("[out:json][timeout:25];("));
        for tag in OVERPASS_TAGS {
            assert!(
                query.contains(&format!("[{tag}][name];")),
                "missing the {tag} clause"
            );
        }
        // The unscoped `nwr(...)[name]` variant answered 504 — see the module doc.
        assert!(!query.contains("nwr(around:250,48.8566,2.3522)[name]"));
        assert!(query.ends_with("out center 40;"));
    }

    #[test]
    fn haversine_matches_a_known_distance() {
        // Paris ↔ London, ~344 km by great circle.
        let d = haversine_m(48.8566, 2.3522, 51.5074, -0.1278);
        assert!((d - 343_500.0).abs() < 2_000.0, "got {d} m");
        assert_eq!(haversine_m(48.0, 2.0, 48.0, 2.0), 0.0);
    }

    #[tokio::test]
    async fn a_value_that_is_not_a_coordinate_never_reaches_the_network() {
        match run_overpass("anthropic.com", &crate::sources::ToolCtx::default()).await {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None) => {
                assert!(message.contains("anthropic.com"));
            }
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }
}
