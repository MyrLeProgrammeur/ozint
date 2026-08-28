//! `img-exif` — `entity-image`'s one tool today: read whatever EXIF the stored bytes carry,
//! and turn a GPS fix into a real `Coordinate` child rather than a lat/lon pair sitting inert
//! in a row nobody can act on.
//!
//! ## `LocalOnly`, and why that is not `KeylessOpen`
//!
//! No request leaves this process. The "source" is the bytes this crate's own media store
//! already holds — the file-upload path already screened and content-addressed them — so this
//! tool's whole job is decoding what is already on disk. `AccessTier::LocalOnly` is the same
//! tier `geo-map-links` and `dir-tiles-*` use for the same reason: a tool that makes no
//! network call has no rate limit to respect and nothing to be keyless *about*.
//!
//! ## Why the GPS fix becomes a child instead of staying a payload field
//!
//! `CoordinatePayload` already exists, `entity-coordinate` already runs three tools against
//! it (map links, Nominatim reverse-geocode, Overpass POIs), and none of that fires unless a
//! `Coordinate` node exists to fire it from. Writing `lat`/`lon` onto the image node's own
//! payload (which this tool *also* does, for the detail panel) would leave the analyst one
//! extra manual step away from "where is this and what is nearby" — the exact question a GPS
//! fix in a photo exists to answer. One [`crate::registry::ChildSeed`] closes that gap the
//! same way a domain tool's subdomain children do.

use std::path::Path;

use crate::exif;
use crate::media;
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::OzType;

/// Runs `img-exif` against `value` (a `media_id`, per `normalize::normalize(OzType::Image, …)`).
/// Synchronous — there is no request to await, only a local read and a decode.
pub fn run_local_exif(value: &str) -> DispatchOutcome {
    run_local_exif_in(&media::media_dir(), value)
}

/// [`run_local_exif`] against an explicit media-store root — the form the tests use, so this
/// tool's tests never race other tests over the process-global `OZINT_DATA_DIR`/`media_dir()`
/// the way a `set_var`-based test would.
pub fn run_local_exif_in(root: &Path, value: &str) -> DispatchOutcome {
    let loaded = match media::load_in(root, value) {
        Ok(loaded) => loaded,
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("could not read the stored media object: {e}"),
                },
                None,
            );
        }
    };

    let Some((meta, bytes)) = loaded else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!(
                    "`{value}` names no object in the media store — upload or fetch it before EXIF can run"
                ),
            },
            None,
        );
    };

    if !meta.is_image() {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("`{}` is not a decodable image type", meta.mime),
            },
            None,
        );
    }

    let extracted = exif::extract(&bytes);
    let count = extracted.rows.len() as u32;

    let mut patch = serde_json::Map::new();
    patch.insert("mediaId".into(), serde_json::json!(meta.media_id));
    patch.insert("exif".into(), serde_json::json!(extracted.rows));
    if let Some(lat) = extracted.lat {
        patch.insert("lat".into(), serde_json::json!(lat));
    }
    if let Some(lon) = extracted.lon {
        patch.insert("lon".into(), serde_json::json!(lon));
    }
    if let Some(accuracy) = extracted.accuracy_m {
        patch.insert("accuracyM".into(), serde_json::json!(accuracy));
    }
    if let Some(taken_at) = extracted.taken_at {
        patch.insert("takenAt".into(), serde_json::json!(taken_at));
    }
    if let Some(camera) = &extracted.camera {
        patch.insert("camera".into(), serde_json::json!(camera));
    }

    let mut children = Vec::new();
    if let (Some(lat), Some(lon)) = (extracted.lat, extracted.lon) {
        children.push(ChildSeed {
            oz_type: OzType::Coordinate,
            value: format!("{lat:.5},{lon:.5}"),
            note: Some("EXIF GPS fix".to_string()),
        });
    }

    let outcome = if count == 0 {
        ToolOutcome::OkEmpty
    } else {
        ToolOutcome::OkWithResults { count }
    };

    DispatchOutcome::Ran(
        outcome,
        Some(ToolYield {
            payload_patch: serde_json::Value::Object(patch),
            rows: extracted.rows,
            children,
            ..Default::default()
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXIF_JPEG: &[u8] = include_bytes!("../../../testdata/exif_gps.jpg");

    fn temp_root() -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join("ozint-img-exif-tests")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn yielded(outcome: DispatchOutcome) -> ToolYield {
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { .. }, Some(produced)) => produced,
            other => panic!("expected results, got {other:?}"),
        }
    }

    #[test]
    fn a_media_id_absent_from_the_store_is_a_parse_error() {
        let root = temp_root();
        match run_local_exif_in(&root, &"0".repeat(64)) {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None) => {
                assert!(message.contains("names no object"));
            }
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }

    #[test]
    fn a_non_media_id_value_is_a_parse_error_not_a_panic() {
        let root = temp_root();
        match run_local_exif_in(&root, "not-a-media-id") {
            DispatchOutcome::Ran(ToolOutcome::ParseError { .. }, None) => {}
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }

    #[test]
    fn a_real_photos_gps_becomes_a_coordinate_child() {
        let root = temp_root();
        let stored = media::store_bytes_in(&root, EXIF_JPEG, None).unwrap();
        let produced = yielded(run_local_exif_in(&root, &stored.media_id));

        assert_eq!(produced.children.len(), 1);
        let child = &produced.children[0];
        assert_eq!(child.oz_type, OzType::Coordinate);
        assert_eq!(child.value, "48.85840,2.29450");
        assert_eq!(child.note.as_deref(), Some("EXIF GPS fix"));

        assert_eq!(produced.payload_patch["mediaId"], stored.media_id);
        assert!((produced.payload_patch["lat"].as_f64().unwrap() - 48.8584).abs() < 1e-3);
        assert_eq!(produced.payload_patch["camera"], "TestCam TestModel X");
        assert!(!produced.rows.is_empty());
    }

    #[test]
    fn an_image_with_no_exif_produces_no_child_and_settles_ok_empty() {
        const PNG: &[u8] = &[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        let root = temp_root();
        let stored = media::store_bytes_in(&root, PNG, None).unwrap();
        match run_local_exif_in(&root, &stored.media_id) {
            DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(produced)) => {
                assert!(produced.children.is_empty());
                assert_eq!(produced.payload_patch["mediaId"], stored.media_id);
            }
            other => panic!("expected OkEmpty, got {other:?}"),
        }
    }

    #[test]
    fn html_masquerading_as_an_upload_is_refused_before_any_decoder_sees_it() {
        let root = temp_root();
        let stored =
            media::store_bytes_in(&root, b"<html><script>alert(1)</script>", None).unwrap();
        match run_local_exif_in(&root, &stored.media_id) {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None) => {
                assert!(message.contains("text/html"));
            }
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }
}
