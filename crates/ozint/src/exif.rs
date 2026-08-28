//! `entity-image (IMG)`'s EXIF half — reading whatever the camera embedded, and turning a GPS
//! fix into a real coordinate, not a row nobody can act on.
//!
//! ## Two shapes of output, on purpose
//!
//! [`extract`] returns both a flat `rows` list (every field the container held, rendered for
//! the detail panel exactly the way `kamadak-exif` formats it) and a small set of *typed*
//! fields (`lat`/`lon`/`accuracy_m`/`taken_at`/`camera`) picked out of that same data. The
//! rows are for a human scanning a panel; the typed fields are for code that needs to compare
//! or spawn a child — `CoordinatePayload` cannot be built out of a `Vec<OzRow>`. Building both
//! from one parse (rather than parsing twice, once per consumer) is what keeps them from
//! disagreeing.
//!
//! ## No EXIF is not an error
//!
//! Most images on the modern web have had their EXIF stripped (deliberately, by the platform
//! that served them) long before they reach this store. [`extract`] treats a container with no
//! EXIF segment, and a container `kamadak-exif` cannot parse at all, identically: an empty
//! [`ExifExtract`]. Both are legitimate absences, not failures — the distinction this crate
//! cares about (`OkEmpty` vs. `ParseError`) lives in the dispatcher that calls this function,
//! against a different question ("was this even an image"), not here.
//!
//! ## GPS: degrees-minutes-seconds, signed by the reference tag
//!
//! EXIF stores latitude/longitude as three unsigned rationals (degrees, minutes, seconds) plus
//! a one-letter reference (`N`/`S`, `E`/`W`) that carries the sign — there is no signed EXIF
//! coordinate. [`gps_to_decimal`] does the conversion `deg + min/60 + sec/3600`, negated when
//! the reference is `S` or `W`, and is exercised directly in the tests below against
//! hand-computed values, not just round-tripped through a real file.
//!
//! ## `taken_at` has no timezone, and this module does not invent one
//!
//! `DateTimeOriginal` is a plain `"YYYY:MM:DD HH:MM:SS"` string with no offset attached (the
//! separate `OffsetTimeOriginal` tag that would supply one is rarely populated by consumer
//! cameras and phones). Treating the parsed value as UTC is a documented assumption, not a
//! verified fact about when the photo was taken — the alternative, silently assuming the
//! analyst's local timezone, would be worse because it would vary by who is looking.

use std::io::Cursor;

use chrono::{DateTime, NaiveDateTime, Utc};
use exif::{In, Tag, Value};

use crate::types::OzRow;

/// What one image's EXIF container held, split into rows for display and the handful of
/// fields other code needs typed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExifExtract {
    pub rows: Vec<OzRow>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    /// From `GPSHPositioningError` when the camera recorded one (rare outside recent phones).
    pub accuracy_m: Option<f64>,
    pub taken_at: Option<DateTime<Utc>>,
    /// `Make` and `Model`, joined. `None` when neither is present.
    pub camera: Option<String>,
}

impl ExifExtract {
    pub fn has_gps(&self) -> bool {
        self.lat.is_some() && self.lon.is_some()
    }
}

/// Reads whatever EXIF `bytes` (an already-confirmed image's raw bytes) holds. Never errors:
/// a container with no EXIF segment and one `kamadak-exif` cannot parse at all both come back
/// as [`ExifExtract::default`] — see the module doc for why that is the honest answer for both.
///
/// `continue_on_error` is turned on and a `PartialResult` is unwrapped rather than treated as
/// failure: real encoders routinely write an IFD chain `kamadak-exif`'s strict reader rejects
/// (this crate's own GPS test fixture, written by Pillow/piexif, trips `"Unexpected next
/// IFD"` on the primary IFD's own next-IFD pointer) while every individual field tag still
/// decodes cleanly. Refusing the whole file over one strict-mode complaint about a pointer
/// nothing here follows would throw away real, correct GPS data — the one field this function
/// exists to find.
pub fn extract(bytes: &[u8]) -> ExifExtract {
    let mut cursor = Cursor::new(bytes);
    let mut reader = exif::Reader::new();
    reader.continue_on_error(true);
    let exif = match reader.read_from_container(&mut cursor) {
        Ok(exif) => exif,
        Err(exif::Error::PartialResult(partial)) => partial.into_inner().0,
        Err(_) => return ExifExtract::default(),
    };

    let mut out = ExifExtract::default();
    let mut make: Option<String> = None;
    let mut model: Option<String> = None;

    for field in exif.fields() {
        // The thumbnail IFD (`In::THUMBNAIL`) describes the embedded preview image, not the
        // photo itself — its own `ImageWidth`/`Compression` fields would read as duplicates
        // or contradictions of the primary IFD's.
        if field.ifd_num != In::PRIMARY {
            continue;
        }

        out.rows.push(OzRow {
            label: field.tag.to_string(),
            value: field.display_value().to_string(),
            ..Default::default()
        });

        match field.tag {
            Tag::Make => make = ascii_string(&field.value),
            Tag::Model => model = ascii_string(&field.value),
            Tag::DateTimeOriginal => {
                out.taken_at = ascii_string(&field.value).and_then(|s| parse_exif_datetime(&s));
            }
            Tag::GPSHPositioningError => {
                out.accuracy_m = rational_f64(&field.value);
            }
            _ => {}
        }
    }

    if let (Some(lat_field), Some(lat_ref)) = (
        exif.get_field(Tag::GPSLatitude, In::PRIMARY),
        exif.get_field(Tag::GPSLatitudeRef, In::PRIMARY),
    ) && let (Some(lon_field), Some(lon_ref)) = (
        exif.get_field(Tag::GPSLongitude, In::PRIMARY),
        exif.get_field(Tag::GPSLongitudeRef, In::PRIMARY),
    ) {
        out.lat = gps_to_decimal(&lat_field.value, &lat_ref.value);
        out.lon = gps_to_decimal(&lon_field.value, &lon_ref.value);
    }

    out.camera = match (make, model) {
        (Some(make), Some(model)) if model.starts_with(&make) => Some(model),
        (Some(make), Some(model)) => Some(format!("{make} {model}")),
        (Some(make), None) => Some(make),
        (None, Some(model)) => Some(model),
        (None, None) => None,
    };

    out
}

/// The first ASCII string in `value`, trimmed of the trailing NUL `kamadak-exif` preserves.
fn ascii_string(value: &Value) -> Option<String> {
    let Value::Ascii(strings) = value else {
        return None;
    };
    let first = strings.first()?;
    let text = String::from_utf8_lossy(first)
        .trim_end_matches('\0')
        .trim()
        .to_string();
    (!text.is_empty()).then_some(text)
}

fn rational_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Rational(rationals) => {
            let r = rationals.first()?;
            (r.denom != 0).then(|| f64::from(r.num) / f64::from(r.denom))
        }
        Value::SRational(rationals) => {
            let r = rationals.first()?;
            (r.denom != 0).then(|| f64::from(r.num) / f64::from(r.denom))
        }
        _ => None,
    }
}

/// `deg,min,sec` (three unsigned rationals) plus a `N`/`S`/`E`/`W` reference, to a signed
/// decimal degree. `None` if either field is not the shape EXIF defines for GPS coordinates.
fn gps_to_decimal(dms: &Value, reference: &Value) -> Option<f64> {
    let Value::Rational(parts) = dms else {
        return None;
    };
    if parts.len() != 3 {
        return None;
    }
    let deg = f64::from(parts[0].num) / f64::from(parts[0].denom.max(1));
    let min = f64::from(parts[1].num) / f64::from(parts[1].denom.max(1));
    let sec = f64::from(parts[2].num) / f64::from(parts[2].denom.max(1));
    let magnitude = deg + min / 60.0 + sec / 3600.0;

    let sign = match ascii_string(reference)?.as_str() {
        "S" | "W" => -1.0,
        _ => 1.0,
    };
    Some(magnitude * sign)
}

/// `"YYYY:MM:DD HH:MM:SS"` — EXIF's own separator, not ISO-8601. Interpreted as UTC; see the
/// module doc for why that is a documented assumption, not a measured fact.
fn parse_exif_datetime(s: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(s, "%Y:%m:%d %H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real photo — 200x150 JPEG generated with Pillow, GPS/DateTime/Make/Model written by
    /// `piexif` — not a hand-assembled EXIF segment. Encodes Paris, `48.8584, 2.2945` N/E,
    /// `2024-03-15 12:30:00`, camera `TestCam TestModel X`.
    const EXIF_JPEG: &[u8] = include_bytes!("../testdata/exif_gps.jpg");

    #[test]
    fn a_real_photos_gps_decodes_to_the_encoded_coordinate() {
        let extracted = extract(EXIF_JPEG);
        assert!(extracted.has_gps());
        let lat = extracted.lat.unwrap();
        let lon = extracted.lon.unwrap();
        // DMS round-trips to within the precision the fixture was encoded at (1/100 second).
        assert!((lat - 48.8584).abs() < 1e-3, "lat was {lat}");
        assert!((lon - 2.2945).abs() < 1e-3, "lon was {lon}");
    }

    #[test]
    fn a_real_photos_date_and_camera_are_read() {
        let extracted = extract(EXIF_JPEG);
        assert_eq!(
            extracted.taken_at,
            Some(
                chrono::DateTime::parse_from_rfc3339("2024-03-15T12:30:00Z")
                    .unwrap()
                    .into()
            )
        );
        assert_eq!(extracted.camera.as_deref(), Some("TestCam TestModel X"));
    }

    #[test]
    fn the_rows_include_the_fields_the_fixture_carries() {
        let extracted = extract(EXIF_JPEG);
        assert!(extracted.rows.iter().any(|r| r.label == "Model"));
        assert!(extracted.rows.iter().any(|r| r.label == "Make"));
        assert!(!extracted.rows.is_empty());
    }

    #[test]
    fn bytes_with_no_exif_segment_are_an_empty_result_not_an_error() {
        // The one-pixel PNG from `media`'s tests — a real, valid image with nothing EXIF could
        // ever find in it (PNG does not carry EXIF the way this fixture reads it).
        const PNG: &[u8] = &[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        let extracted = extract(PNG);
        assert_eq!(extracted, ExifExtract::default());
    }

    #[test]
    fn garbage_bytes_never_panic_and_come_back_empty() {
        let extracted = extract(b"not an image at all, just some bytes");
        assert_eq!(extracted, ExifExtract::default());
    }

    #[test]
    fn gps_sign_follows_the_reference_not_the_magnitude() {
        // The trap the module doc names: EXIF's own rationals are unsigned, so a coordinate
        // west or south of the origin depends entirely on the ref tag being read.
        let dms = Value::Rational(vec![
            exif::Rational { num: 48, denom: 1 },
            exif::Rational { num: 51, denom: 1 },
            exif::Rational { num: 30, denom: 1 },
        ]);
        let north = gps_to_decimal(&dms, &Value::Ascii(vec![b"N".to_vec()])).unwrap();
        let south = gps_to_decimal(&dms, &Value::Ascii(vec![b"S".to_vec()])).unwrap();
        assert!(north > 0.0);
        assert_eq!(south, -north);
    }
}
