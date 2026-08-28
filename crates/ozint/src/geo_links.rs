//! Turns a GPS coordinate into outbound links to real map providers. Keyless URL templates
//! only; zero network calls, zero API keys.
//!
//! ## The hard rule this module exists to enforce
//!
//! **No map rendering of any OZINT geo finding, ever.** This is a hard rule, not a
//! "not yet": the locked decision is that a coordinate links out and nothing more.
//! This module must never mount a map/WebGL context of its own or draw a pin on one.
//! Linking out is the *entire* mechanism by which that rule is kept satisfiable — there is
//! no rendering surface here for a pin to even attach to.
//!
//! ## The second rule: raw coordinate and reverse-geocoded place never merge
//!
//! [`CoordinatePayload`] keeps `lat`/`lon` separate from `place` for exactly this reason
//! (see its field doc). [`coordinate_sections`] mirrors that split at the section level: the
//! raw coordinate is one section, the reverse-geocoded place (when present) is a distinct
//! second section, and no function in this module ever hands back a single string that
//! blends the two. A caller cannot get a blended "location" string out of this module
//! because none is ever constructed.

use crate::types::{CoordinatePayload, OzRow, OzSection, SectionKind};

// ─── Formatting ──────────────────────────────────────────────────────────────

/// Decimal places used everywhere a coordinate is rendered or put in a URL. 6 places is the
/// conventional choice (~11cm of resolution at the equator) — far finer than any signal this
/// crate can source, but stable and unambiguous to round-trip, which matters more here than
/// trimming trailing zeros.
const COORDINATE_PRECISION: usize = 6;

/// One coordinate component, fixed to [`COORDINATE_PRECISION`] decimal places. Used both for
/// the human-readable display string and for URL query parameters, so the sign and precision
/// are identical in both places.
fn format_component(value: f64) -> String {
    format!(
        "{value:.COORDINATE_PRECISION$}",
        COORDINATE_PRECISION = COORDINATE_PRECISION
    )
}

/// A stable, human-readable rendering of a coordinate pair (`"48.856600, 2.352200"`). Signed,
/// fixed precision, and depends on nothing else in the payload — this is the raw coordinate,
/// never blended with a place name.
pub fn format_coordinate(lat: f64, lon: f64) -> String {
    format!("{}, {}", format_component(lat), format_component(lon))
}

/// GPS accuracy thresholds for [`format_accuracy`]. Chosen defaults for this module, not
/// sourced from any provider spec — no source tool states its own accuracy-display
/// convention, so this crate picks one and documents it here rather than inventing a rule
/// silently at each call site.
///
/// - Below 1 m: shown to one decimal place (`±0.5 m`) — GPS chips occasionally report
///   sub-metre accuracy and rounding it to `±0 m` or `±1 m` would misrepresent it.
/// - 1 m up to 1 km: rounded to the nearest whole metre (`±12 m`) — finer than a metre is not
///   meaningfully different for a human reading a finding.
/// - 1 km and above: shown in kilometres to one decimal place (`±1.2 km`) — the usual point at
///   which a metre count stops being legible at a glance.
const ACCURACY_SUBMETRE_AT: f64 = 1.0;
const ACCURACY_KM_AT: f64 = 1000.0;

/// Renders a GPS accuracy in metres as a short, human-readable string, per the thresholds
/// documented above.
pub fn format_accuracy(accuracy_m: f64) -> String {
    if accuracy_m < ACCURACY_SUBMETRE_AT {
        format!("±{accuracy_m:.1} m")
    } else if accuracy_m < ACCURACY_KM_AT {
        format!("±{:.0} m", accuracy_m.round())
    } else {
        format!("±{:.1} km", accuracy_m / 1000.0)
    }
}

// ─── Map links ─────────────────────────────────────────────────────────────

/// Neutral label used for the Apple Maps pin query — this module has no place name to hand
/// it (see the module doc's second rule), so it names the pin generically rather than reach
/// for `payload.place`, which would blend the two blocks through a side channel.
const APPLE_MAPS_PIN_LABEL: &str = "Location";

/// Builds one [`OzRow`] per external map provider for a coordinate: Google Maps (primary),
/// OpenStreetMap and Apple Maps (alternates). All three are keyless URL templates — no
/// network call is made, no API key is consulted, and nothing here ever renders a pin on a
/// map or globe of its own (see the module doc).
pub fn map_links(lat: f64, lon: f64) -> Vec<OzRow> {
    let lat_s = format_component(lat);
    let lon_s = format_component(lon);
    let value = format_coordinate(lat, lon);

    vec![
        OzRow {
            label: "Google Maps".into(),
            value: value.clone(),
            href: Some(format!(
                "https://www.google.com/maps/search/?api=1&query={lat_s},{lon_s}"
            )),
            ..Default::default()
        },
        OzRow {
            label: "OpenStreetMap".into(),
            value: value.clone(),
            href: Some(format!(
                "https://www.openstreetmap.org/?mlat={lat_s}&mlon={lon_s}#map=17/{lat_s}/{lon_s}"
            )),
            ..Default::default()
        },
        OzRow {
            label: "Apple Maps".into(),
            value,
            href: Some(format!(
                "https://maps.apple.com/?ll={lat_s},{lon_s}&q={}",
                urlencoding::encode(APPLE_MAPS_PIN_LABEL)
            )),
            ..Default::default()
        },
    ]
}

// ─── Detail-panel sections ─────────────────────────────────────────────────

/// Stable section ids, per the "each detail-panel section needs a stable id" convention
/// (`OzSection::id` docs).
const RAW_COORDINATE_SECTION_ID: &str = "geo-coordinate";
const PLACE_SECTION_ID: &str = "geo-place";
const MAP_LINKS_SECTION_ID: &str = "geo-map-links";

/// Builds the detail-panel sections for a [`CoordinatePayload`]: the raw coordinate block,
/// the reverse-geocoded place block (only when the payload actually has one), and the
/// external map links. Never fewer than two sections (coordinate + links), never a place
/// section with nothing in it — see the module doc's second rule.
pub fn coordinate_sections(payload: &CoordinatePayload) -> Vec<OzSection> {
    let mut sections = Vec::with_capacity(3);

    let mut raw = OzSection::new(
        RAW_COORDINATE_SECTION_ID,
        "Coordinate",
        SectionKind::KeyValue,
    );
    raw.rows.push(OzRow {
        label: "Coordinates".into(),
        value: format_coordinate(payload.lat, payload.lon),
        ..Default::default()
    });
    if let Some(accuracy_m) = payload.accuracy_m {
        raw.rows.push(OzRow {
            label: "Accuracy".into(),
            value: format_accuracy(accuracy_m),
            ..Default::default()
        });
    }
    sections.push(raw);

    if payload.place.is_some() || payload.country.is_some() {
        let mut place = OzSection::new(PLACE_SECTION_ID, "Place", SectionKind::KeyValue);
        if let Some(p) = &payload.place {
            place.rows.push(OzRow {
                label: "Place".into(),
                value: p.clone(),
                ..Default::default()
            });
        }
        if let Some(c) = &payload.country {
            place.rows.push(OzRow {
                label: "Country".into(),
                value: c.clone(),
                ..Default::default()
            });
        }
        sections.push(place);
    }

    let mut links = OzSection::new(MAP_LINKS_SECTION_ID, "Map links", SectionKind::Links);
    links.rows = map_links(payload.lat, payload.lon);
    sections.push(links);

    sections
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── map_links ──────────────────────────────────────────────────────────

    #[test]
    fn map_links_returns_the_three_providers_in_order() {
        let links = map_links(48.8566, 2.3522);
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].label, "Google Maps");
        assert_eq!(links[1].label, "OpenStreetMap");
        assert_eq!(links[2].label, "Apple Maps");
        for row in &links {
            assert!(row.href.is_some(), "every map link row must carry an href");
            assert_eq!(row.value, "48.856600, 2.352200");
        }
    }

    #[test]
    fn map_links_use_the_documented_url_shapes() {
        let links = map_links(48.8566, 2.3522);
        assert_eq!(
            links[0].href.as_deref(),
            Some("https://www.google.com/maps/search/?api=1&query=48.856600,2.352200")
        );
        assert_eq!(
            links[1].href.as_deref(),
            Some(
                "https://www.openstreetmap.org/?mlat=48.856600&mlon=2.352200#map=17/48.856600/2.352200"
            )
        );
        assert_eq!(
            links[2].href.as_deref(),
            Some("https://maps.apple.com/?ll=48.856600,2.352200&q=Location")
        );
    }

    #[test]
    fn map_links_preserve_the_sign_for_negative_coordinates() {
        // A dropped minus sign silently relocates a finding across a hemisphere — assert the
        // sign survives into every URL explicitly, not just the display string.
        let links = map_links(-33.8688, -151.2093);
        for row in &links {
            let href = row.href.as_deref().unwrap();
            assert!(
                href.contains("-33.868800") && href.contains("-151.209300"),
                "href lost a sign: {href}"
            );
        }
        assert_eq!(links[0].value, "-33.868800, -151.209300");
    }

    #[test]
    fn map_links_preserve_zero_coordinates() {
        // Zero is a real, valid coordinate (Null Island) and must not be dropped or
        // rendered as if the field were absent.
        let links = map_links(0.0, 0.0);
        for row in &links {
            let href = row.href.as_deref().unwrap();
            assert!(
                href.contains("0.000000"),
                "href lost a zero coordinate: {href}"
            );
        }
        assert_eq!(links[0].value, "0.000000, 0.000000");
    }

    // ── format_coordinate ──────────────────────────────────────────────────

    #[test]
    fn format_coordinate_uses_six_decimal_places() {
        assert_eq!(format_coordinate(48.8566, 2.3522), "48.856600, 2.352200");
        assert_eq!(
            format_coordinate(-33.8688, -151.2093),
            "-33.868800, -151.209300"
        );
    }

    #[test]
    fn format_coordinate_round_trips_stably() {
        let a = format_coordinate(48.856_614_1, 2.352_221_9);
        let b = format_coordinate(48.856_614_1, 2.352_221_9);
        assert_eq!(a, b, "the same input must always render identically");
    }

    // ── format_accuracy ────────────────────────────────────────────────────

    #[test]
    fn format_accuracy_submetre_shows_one_decimal() {
        assert_eq!(format_accuracy(0.5), "±0.5 m");
        assert_eq!(format_accuracy(0.0), "±0.0 m");
    }

    #[test]
    fn format_accuracy_metre_scale_rounds_to_whole_metres() {
        assert_eq!(format_accuracy(1.0), "±1 m");
        assert_eq!(format_accuracy(12.0), "±12 m");
        assert_eq!(format_accuracy(999.4), "±999 m");
    }

    #[test]
    fn format_accuracy_kilometre_scale_shows_one_decimal_km() {
        assert_eq!(format_accuracy(1000.0), "±1.0 km");
        assert_eq!(format_accuracy(1234.0), "±1.2 km");
        assert_eq!(format_accuracy(50_000.0), "±50.0 km");
    }

    // ── coordinate_sections ────────────────────────────────────────────────

    #[test]
    fn coordinate_sections_without_place_or_country_has_no_place_section() {
        let payload = CoordinatePayload {
            lat: 48.8566,
            lon: 2.3522,
            ..Default::default()
        };
        let sections = coordinate_sections(&payload);
        assert_eq!(
            sections.len(),
            2,
            "must be exactly coordinate + links, never a stray place section"
        );
        assert_eq!(sections[0].id, RAW_COORDINATE_SECTION_ID);
        assert_eq!(sections[1].id, MAP_LINKS_SECTION_ID);
        assert!(
            sections.iter().all(|s| s.id != PLACE_SECTION_ID),
            "an empty place must never be rendered as an empty section"
        );
    }

    #[test]
    fn coordinate_sections_with_place_has_exactly_two_content_sections_plus_links() {
        let payload = CoordinatePayload {
            lat: 48.8566,
            lon: 2.3522,
            place: Some("Paris, France".into()),
            country: Some("France".into()),
            ..Default::default()
        };
        let sections = coordinate_sections(&payload);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].id, RAW_COORDINATE_SECTION_ID);
        assert_eq!(sections[1].id, PLACE_SECTION_ID);
        assert_eq!(sections[2].id, MAP_LINKS_SECTION_ID);
    }

    #[test]
    fn coordinate_sections_place_only_still_yields_a_place_section() {
        let payload = CoordinatePayload {
            lat: 48.8566,
            lon: 2.3522,
            country: Some("France".into()),
            ..Default::default()
        };
        let sections = coordinate_sections(&payload);
        let place_section = sections
            .iter()
            .find(|s| s.id == PLACE_SECTION_ID)
            .expect("country alone must still yield a place section");
        assert_eq!(place_section.rows.len(), 1);
        assert_eq!(place_section.rows[0].label, "Country");
    }

    #[test]
    fn coordinate_sections_raw_block_includes_accuracy_when_present() {
        let payload = CoordinatePayload {
            lat: 48.8566,
            lon: 2.3522,
            accuracy_m: Some(12.0),
            ..Default::default()
        };
        let sections = coordinate_sections(&payload);
        let raw = &sections[0];
        assert_eq!(raw.rows.len(), 2);
        assert_eq!(raw.rows[1].label, "Accuracy");
        assert_eq!(raw.rows[1].value, "±12 m");
    }

    #[test]
    fn coordinate_sections_raw_block_omits_accuracy_when_absent() {
        let payload = CoordinatePayload {
            lat: 48.8566,
            lon: 2.3522,
            ..Default::default()
        };
        let sections = coordinate_sections(&payload);
        assert_eq!(
            sections[0].rows.len(),
            1,
            "no accuracy row when accuracy_m is None"
        );
    }

    #[test]
    fn no_row_ever_merges_the_raw_coordinate_and_the_place_name() {
        let payload = CoordinatePayload {
            lat: 48.8566,
            lon: 2.3522,
            place: Some("Paris, France".into()),
            country: Some("France".into()),
            ..Default::default()
        };
        let sections = coordinate_sections(&payload);
        for section in &sections {
            for row in &section.rows {
                let has_coordinate_digits =
                    row.value.contains("48.8566") || row.value.contains("2.3522");
                let has_place_text = row.value.contains("Paris") || row.value == "France";
                assert!(
                    !(has_coordinate_digits && has_place_text),
                    "row `{}` blends the raw coordinate and the place name: {}",
                    row.label,
                    row.value
                );
            }
        }
    }

    #[test]
    fn coordinate_sections_preserve_sign_for_negative_coordinates() {
        let payload = CoordinatePayload {
            lat: -33.8688,
            lon: -151.2093,
            ..Default::default()
        };
        let sections = coordinate_sections(&payload);
        assert_eq!(sections[0].rows[0].value, "-33.868800, -151.209300");
    }
}
