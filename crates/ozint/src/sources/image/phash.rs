//! `img-phash` — a perceptual hash of the stored image bytes. `LocalOnly`, the same decode-only
//! tier `img-exif` uses: `image_hasher` runs against bytes already in `crate::media`'s local
//! store, no request leaves this process. Owns `phash` on [`crate::types::ImagePayload`].
//!
//! ## What this pass builds, and what it deliberately does not
//!
//! [`image_hasher`]'s default configuration (an 8×8 DCT hash) produces a base64-encoded
//! fingerprint that is stable under recompression and minor edits — two copies of visually
//! the same photo, one re-saved as a lower-quality JPEG, hash close together. That fingerprint
//! is computed and stored on the node here.
//!
//! **Comparison against other stored media is not built in this pass.** `crate::media` has no
//! enumeration of what else the store holds — it is a content-addressed key/value store keyed
//! by `media_id`, with no index over the hashes of everything in it — so "does this image
//! already exist elsewhere in the investigation" would need a new small index this pass does
//! not add. Scoped down deliberately: this tool computes and persists the hash so a future
//! comparison pass has something to compare against, rather than building a full duplicate-
//! detection engine to fit inside this one.
//!
//! ## Field ownership
//!
//! Owns `phash` alone — disjoint from every field `img-exif` writes.

use image::ImageReader;
use image_hasher::HasherConfig;

use crate::media;
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;

pub fn run_phash(value: &str) -> DispatchOutcome {
    run_phash_in(&media::media_dir(), value)
}

pub fn run_phash_in(root: &std::path::Path, value: &str) -> DispatchOutcome {
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
                    "`{value}` names no object in the media store — upload or fetch it before a hash can be computed"
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

    let decoded = match ImageReader::new(std::io::Cursor::new(&bytes)).with_guessed_format() {
        Ok(reader) => reader.decode(),
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("could not sniff the image format: {e}"),
                },
                None,
            );
        }
    };
    let image = match decoded {
        Ok(image) => image,
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("could not decode the stored image: {e}"),
                },
                None,
            );
        }
    };

    let hasher = HasherConfig::new().to_hasher();
    let phash = hasher.hash_image(&image).to_base64();

    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults { count: 1 },
        Some(ToolYield {
            payload_patch: serde_json::json!({ "phash": phash }),
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
            .join("ozint-img-phash-tests")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_real_photo_produces_a_stable_base64_hash() {
        let root = temp_root();
        let stored = media::store_bytes_in(&root, EXIF_JPEG, None).unwrap();
        let outcome = run_phash_in(&root, &stored.media_id);
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::OkWithResults { count: 1 }, Some(produced)) => {
                let hash = produced.payload_patch["phash"]
                    .as_str()
                    .expect("a phash string");
                assert!(!hash.is_empty());
                // Deterministic: re-decoding the same bytes must produce the same hash.
                let again = run_phash_in(&root, &stored.media_id);
                let DispatchOutcome::Ran(_, Some(again)) = again else {
                    panic!("expected results")
                };
                assert_eq!(
                    again.payload_patch["phash"],
                    produced.payload_patch["phash"]
                );
            }
            other => panic!("expected results, got {other:?}"),
        }
    }

    #[test]
    fn a_media_id_absent_from_the_store_is_a_parse_error() {
        let root = temp_root();
        match run_phash_in(&root, &"0".repeat(64)) {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None) => {
                assert!(message.contains("names no object"));
            }
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }

    #[test]
    fn html_masquerading_as_an_upload_is_refused_before_any_decoder_sees_it() {
        let root = temp_root();
        let stored =
            media::store_bytes_in(&root, b"<html><script>alert(1)</script>", None).unwrap();
        match run_phash_in(&root, &stored.media_id) {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None) => {
                assert!(message.contains("text/html"));
            }
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }
}
