//! `geo-nominatim` — OpenStreetMap's Nominatim reverse geocoder. Keyless. Owns only the
//! `place` and `country` fields of [`crate::types::CoordinatePayload`].
//!
//! `GET https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={lat}&lon={lon}&zoom=18&addressdetails=1`
//! — measured 2026-08-23, HTTP `200` with a JSON object carrying `display_name`, an `address`
//! object (`house_number`, `road`, `suburb`, `city`, `state`, `postcode`, `country`,
//! `country_code`), plus `category`/`type`/`addresstype` naming *what OSM feature was
//! matched*, and the feature's own `lat`/`lon`, which are **not** the queried ones.
//!
//! ## The matched feature is the finding, not a footnote
//!
//! Queried with the Hôtel de Ville in Paris (`48.8566, 2.3522`), Nominatim answered
//! `category: "amenity"`, `type: "clock"` — a public clock 40 m away, because that is the
//! nearest node OSM has tagged. Its `display_name` still reads like a street address, so an
//! answer that is really "the closest named thing is a clock" renders as "this coordinate is
//! 6, Place de l'Hôtel-de-Ville" unless the feature type travels with it. [`osm_feature`]
//! extracts it and it is emitted as a row, so the analyst can see what was actually matched.
//! This is the same restraint the module doc's two-block rule states: a gazetteer's answer is
//! an interpretation of a coordinate, never a property of it.
//!
//! ## Absence arrives as a `200`
//!
//! A coordinate with nothing tagged near it — mid-ocean — answers HTTP **`200`** with
//! `{"error": "Unable to geocode"}`. It is not a failure and it is not an empty success by
//! shape: parsed naively, the `display_name` is simply missing and the tool would report
//! `OkEmpty` for the right reason by accident. [`parse_reverse`] reads the `error` key
//! explicitly so the honest case and the shape-drifted case stay distinguishable.
//!
//! ## Rate limit
//!
//! OSM's usage policy caps this endpoint at **one request per second**, which is a condition
//! of use and not a soft target. The figure was registered in `registry::rate_limits_for`
//! under the `nominatim` key before this tool existed; the tool declares that `rate_key`, so
//! the source scheduler enforces it. This is the first tool in the crate whose rate limit
//! is a licence term rather than an operator's preference.

use crate::fetch::{OzBody, OzFetchOptions, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const NOMINATIM_REVERSE: &str = "https://nominatim.openstreetmap.org/reverse";

/// Reads the response body as JSON, accepting `text/plain` defensively — same reasoning as
/// `domain::certspotter::body_to_json`.
fn body_to_json(body: &OzBody) -> Result<serde_json::Value, String> {
    match body {
        OzBody::Json(json) => Ok(json.clone()),
        OzBody::Text(text) => serde_json::from_str(text)
            .map_err(|e| format!("Nominatim body was not parseable JSON: {e}")),
        other => Err(format!(
            "Nominatim response was neither JSON nor text: {other:?}"
        )),
    }
}

/// The OSM feature Nominatim actually matched, rendered `category / type` (`"amenity /
/// clock"`). `None` when the response names neither — never a fabricated `"unknown"`, which
/// would assert that OSM said something it did not.
fn osm_feature(json: &serde_json::Value) -> Option<String> {
    let category = json.get("category").and_then(serde_json::Value::as_str);
    let kind = json.get("type").and_then(serde_json::Value::as_str);
    match (category, kind) {
        (Some(c), Some(t)) => Some(format!("{c} / {t}")),
        (Some(one), None) | (None, Some(one)) => Some(one.to_string()),
        (None, None) => None,
    }
}

/// The address components worth showing, in the order a postal address reads. Deliberately a
/// fixed list rather than "every key in `address`": Nominatim's address object carries
/// administrative levels (`ISO3166-2-lvl4`, `city_block`, `region`) whose presence and
/// meaning vary by country, and rendering them all would fill the panel with keys that mean
/// different things in different places.
const ADDRESS_PARTS: &[(&str, &str)] = &[
    ("house_number", "House number"),
    ("road", "Road"),
    ("suburb", "Suburb"),
    ("city", "City"),
    ("state", "State"),
    ("postcode", "Postcode"),
    ("country", "Country"),
];

/// What one reverse lookup resolved to. `place`/`country` are the two payload fields this tool
/// owns; `rows` is everything else it learned.
#[derive(Debug, Clone, PartialEq)]
struct ReverseResult {
    place: Option<String>,
    country: Option<String>,
    rows: Vec<OzRow>,
}

impl ReverseResult {
    /// Nothing was resolved at all — the `OkEmpty` case.
    fn is_empty(&self) -> bool {
        self.place.is_none() && self.country.is_none() && self.rows.is_empty()
    }
}

/// Parses a `jsonv2` reverse response. `Err` only for a body that is not an object at all;
/// an `{"error": …}` body and an object with no usable keys both come back as an empty
/// [`ReverseResult`], which the caller reports as `OkEmpty`. Pure and tested.
fn parse_reverse(json: &serde_json::Value) -> Result<ReverseResult, String> {
    let obj = json
        .as_object()
        .ok_or_else(|| "Nominatim response was not a JSON object".to_string())?;

    // The documented "nothing here" answer, served with a 200. See the module doc.
    if obj.contains_key("error") {
        return Ok(ReverseResult {
            place: None,
            country: None,
            rows: Vec::new(),
        });
    }

    let place = obj
        .get("display_name")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string);

    let address = obj.get("address").and_then(serde_json::Value::as_object);
    let country = address
        .and_then(|a| a.get("country"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string);

    let mut rows = Vec::new();
    if let Some(feature) = osm_feature(json) {
        rows.push(OzRow {
            label: "OSM feature".into(),
            value: feature,
            ..Default::default()
        });
    }
    if let Some(address) = address {
        for (key, label) in ADDRESS_PARTS {
            let Some(value) = address.get(*key).and_then(serde_json::Value::as_str) else {
                continue;
            };
            if value.trim().is_empty() {
                continue;
            }
            rows.push(OzRow {
                label: (*label).into(),
                value: value.to_string(),
                ..Default::default()
            });
        }
    }

    Ok(ReverseResult {
        place,
        country,
        rows,
    })
}

/// Turns a non-empty [`ReverseResult`] into a [`ToolYield`]. Writes `place`/`country` only
/// when actually resolved — a `null` would be a claim that Nominatim answered "no country",
/// which is not the same as it not having said. Pure.
fn reverse_to_yield(result: &ReverseResult) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if let Some(place) = &result.place {
        patch.insert("place".to_string(), serde_json::json!(place));
    }
    if let Some(country) = &result.country {
        patch.insert("country".to_string(), serde_json::json!(country));
    }
    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows: result.rows.clone(),
        ..Default::default()
    }
}

/// Reverse-geocodes the normalized `lat,lon` in `value`.
pub async fn run_nominatim(value: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some((lat, lon)) = super::parse_lat_lon(value) else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("`{value}` is not a normalized `lat,lon` coordinate"),
            },
            None,
        );
    };

    // `zoom=18` is building/POI level — the finest Nominatim offers for reverse lookups, and
    // the level at which the "nearest tagged feature" caveat in the module doc applies. A
    // coarser zoom would return a neighbourhood and hide the caveat rather than remove it.
    let url =
        format!("{NOMINATIM_REVERSE}?format=jsonv2&lat={lat}&lon={lon}&zoom=18&addressdetails=1");
    let outcome = ctx
        .fetch("geo-nominatim", value, &url, OzFetchOptions::default())
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

    match parse_reverse(&json) {
        Ok(result) if result.is_empty() => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(result) => {
            // Counted as one finding — the place — plus each address/feature row. A count of
            // "1" for a full address would understate the block the analyst is about to read.
            let count = result.rows.len() as u32 + u32::from(result.place.is_some());
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count },
                Some(reverse_to_yield(&result)),
            )
        }
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The measured response for `48.8566, 2.3522`, transcribed from a live call on
    /// 2026-08-23 and trimmed to the keys this module reads. Note `type: "clock"`.
    fn paris() -> serde_json::Value {
        serde_json::json!({
            "place_id": 98201593,
            "osm_type": "node",
            "category": "amenity",
            "type": "clock",
            "addresstype": "amenity",
            "name": "",
            "lat": "48.8565592",
            "lon": "2.3519706",
            "display_name": "6, Place de l'Hôtel-de-Ville - Esplanade de la Libération, Quartier Saint-Merri, Paris 4e Arrondissement, Paris, Île-de-France, France métropolitaine, 75004, France",
            "address": {
                "house_number": "6",
                "road": "Place de l'Hôtel-de-Ville - Esplanade de la Libération",
                "city_block": "Quartier Saint-Merri",
                "suburb": "Paris 4e Arrondissement",
                "city_district": "Paris",
                "city": "Paris",
                "ISO3166-2-lvl6": "FR-75C",
                "state": "Île-de-France",
                "ISO3166-2-lvl4": "FR-IDF",
                "region": "France métropolitaine",
                "postcode": "75004",
                "country": "France",
                "country_code": "fr"
            }
        })
    }

    #[test]
    fn the_matched_osm_feature_is_reported_and_not_hidden_behind_the_address() {
        // The clock. Without this row, "6, Place de l'Hôtel-de-Ville" reads as a fact about
        // the queried point instead of as the nearest thing OSM has a name for.
        let result = parse_reverse(&paris()).unwrap();
        let feature = result
            .rows
            .iter()
            .find(|r| r.label == "OSM feature")
            .expect("a feature row");
        assert_eq!(feature.value, "amenity / clock");
    }

    #[test]
    fn only_place_and_country_are_written_to_the_payload() {
        // Field ownership: `overpass` and `map_links` own the rest, and a shallow merge would
        // let an extra key here silently overwrite one of theirs.
        let produced = reverse_to_yield(&parse_reverse(&paris()).unwrap());
        let keys: Vec<&String> = produced.payload_patch.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["country", "place"]);
        assert_eq!(produced.payload_patch["country"], "France");
    }

    #[test]
    fn the_address_rows_read_in_postal_order_and_skip_the_administrative_noise() {
        let result = parse_reverse(&paris()).unwrap();
        let labels: Vec<&str> = result.rows.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "OSM feature",
                "House number",
                "Road",
                "Suburb",
                "City",
                "State",
                "Postcode",
                "Country"
            ]
        );
        // The keys deliberately dropped — country-specific and meaningless side by side.
        for row in &result.rows {
            assert!(
                !row.value.starts_with("FR-"),
                "an ISO3166-2 level leaked in: {row:?}"
            );
        }
    }

    #[test]
    fn the_two_hundred_carrying_an_error_is_absence_and_not_a_parse_failure() {
        // Mid-ocean. The trap: this body parses fine as JSON and has no `display_name`, so a
        // naive reader reports "we looked and found nothing" for a reason it never checked.
        let json = serde_json::json!({ "error": "Unable to geocode" });
        let result = parse_reverse(&json).expect("an error body is not a parse failure");
        assert!(result.is_empty());
    }

    #[test]
    fn a_response_with_no_address_still_yields_its_place() {
        let json = serde_json::json!({ "display_name": "Somewhere", "category": "place" });
        let result = parse_reverse(&json).unwrap();
        assert_eq!(result.place.as_deref(), Some("Somewhere"));
        assert_eq!(
            result.country, None,
            "a country must never be invented from a display name"
        );
        assert_eq!(result.rows.len(), 1, "only the feature row");
    }

    #[test]
    fn a_body_that_is_not_an_object_is_a_parse_error() {
        assert!(parse_reverse(&serde_json::json!([])).is_err());
    }

    #[test]
    fn blank_strings_are_treated_as_absent_rather_than_rendered_as_empty_rows() {
        let json = serde_json::json!({
            "display_name": "   ",
            "address": { "road": "", "country": "France" }
        });
        let result = parse_reverse(&json).unwrap();
        assert_eq!(result.place, None);
        assert_eq!(result.country.as_deref(), Some("France"));
        assert_eq!(result.rows.len(), 1, "the blank road must not become a row");
    }

    #[tokio::test]
    async fn a_value_that_is_not_a_coordinate_never_reaches_the_network() {
        match run_nominatim("anthropic.com", &crate::sources::ToolCtx::default()).await {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None) => {
                assert!(message.contains("anthropic.com"));
            }
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }
}
