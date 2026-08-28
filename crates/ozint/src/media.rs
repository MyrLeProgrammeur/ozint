//! The content-addressed byte store every file-shaped entity type (IMG, VID, SHA) ingresses
//! through.
//!
//! ## Content-hash-keyed, never filename-keyed
//!
//! This is not a tidiness preference. A filename arrives
//! from outside — from an upload form, or from the last path segment of a remote URL — and
//! is attacker-controlled in both cases. Keying on it hands a stranger a say in where bytes
//! land on disk, and it makes the same image stored twice under two names two different
//! objects. Keying on the SHA-256 of the bytes makes the identity intrinsic: the store is
//! idempotent by construction, re-uploading the same file is a no-op that returns the same
//! `media_id`, and no caller can name a path.
//!
//! ## The MIME on the wire is a claim, not a fact
//!
//! Nothing here trusts a declared `Content-Type` or a file extension. The type is sniffed
//! from the leading magic bytes ([`infer`]) and *that* is what is stored and later served.
//! A `.jpg` that is really an HTML document must not come back out of this store labelled as
//! an image — a same-origin `GET` of attacker-supplied bytes with an attacker-chosen type is
//! how a media proxy becomes an XSS vector.
//!
//! A type we cannot recognise is stored as `application/octet-stream` and stays storable: the
//! hash route (`entity-hash`) is interested in bytes it cannot identify, so refusing them
//! would break the very case malware triage exists for. What an unrecognised type does *not*
//! get is a claim about what it is.
//!
//! ## Three digests, computed once
//!
//! MD5, SHA-1 and SHA-256 are all computed on ingress, in one pass over the bytes each,
//! because the hash-shaped tools disagree about which one they take (VirusTotal accepts all
//! three, MalwareBazaar is SHA-256-first, older corpora are MD5) and re-reading a stored file
//! to answer "what is its MD5" later would be strictly worse. MD5 and SHA-1 are here as
//! *lookup keys into other people's databases*, never as integrity claims — both are broken
//! for that, and nothing in this crate uses them to decide whether two files are the same.
//! `media_id` is the SHA-256, and it is the only digest identity is derived from.
//!
//! ## What this module deliberately does not do
//!
//! No video poster/duration, no reverse-image lookup. Thumbnails and EXIF now live here
//! ([`thumbnail`]) and in [`crate::exif`] respectively — the decoders they need (`image`,
//! `kamadak-exif`) arrived 2026-08-24. Video keyframing still needs a binary (`ffmpeg`), not a
//! crate, and stays out of this crate's reach until something packages that dependency for the
//! local runtime; a thumbnail field that silently held the original bytes would be worse than
//! an absent one.
//!
//! ## Thumbnails are derived, never stored
//!
//! [`thumbnail`] decodes and re-encodes on every call rather than writing a second object
//! beside the original. The alternative — a `<media_id>-thumb.jpg` sidecar — would need its
//! own invalidation story for zero benefit: decoding a capped-size image and re-encoding a
//! ≤212px JPEG is cheap enough (bounded by [`crate::decode`]-style limits below) that caching
//! it would be optimizing a cost that is not there.

use std::io;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use image::{DynamicImage, ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
// One import for all three: `md-5`, `sha1` and `sha2` are the same `digest` family, so
// `Digest` here is literally the same trait each of them re-exports.
use sha2::Digest as _;

/// The largest file the store accepts, in bytes.
///
/// Deliberately the same number as [`crate::fetch::MAX_BODY_BYTES`]: a remote fetch through
/// the guard already refuses past that, so a larger cap here would be unreachable on that
/// path and would only ever apply to uploads — two different limits for the same store,
/// differing by which door the bytes came through.
pub const MAX_MEDIA_BYTES: usize = crate::fetch::MAX_BODY_BYTES as usize;

/// What a stored object is, with no claim we cannot back.
pub const UNKNOWN_MIME: &str = "application/octet-stream";

/// Everything known about one stored object. Persisted beside the bytes as JSON, so the
/// store answers a metadata question without reading (or re-hashing) the payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredMedia {
    /// The SHA-256, lowercase hex. The object's only identity.
    pub media_id: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub bytes: usize,
    /// Sniffed from the leading bytes, never taken from the caller.
    pub mime: String,
    /// Where the bytes came from, when they came from a URL. `None` for an upload — an
    /// upload has no provenance beyond "the analyst supplied it", and inventing a filename
    /// here would give attacker-controlled text a place to live in the record.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source_url: Option<String>,
    pub stored_at: DateTime<Utc>,
}

impl StoredMedia {
    /// Whether the sniffed type is an image. The gate for anything pixel-shaped (EXIF, QR,
    /// reverse-image lookup) — asked of the sniff, never of a declared type.
    ///
    /// SVG is excluded on purpose and is not an oversight: an SVG is a script host, and every
    /// pixel-shaped consumer downstream of this flag would be handing it to a decoder or to a
    /// browser. `infer` does not identify SVG at all (it has no magic bytes), so this is a
    /// statement of intent for the day a text-sniffing tier is added, not a live filter.
    pub fn is_image(&self) -> bool {
        self.mime.starts_with("image/") && self.mime != "image/svg+xml"
    }

    pub fn is_video(&self) -> bool {
        self.mime.starts_with("video/")
    }

    /// The `Content-Type` this object may be served under, which is **not** always the type
    /// it is.
    ///
    /// Found by writing the test below: `infer` recognises HTML, so an honest sniff of an
    /// uploaded page returns `text/html` — and the media route serves same-origin, by design,
    /// so that the source never sees a referrer. Same-origin plus an attacker-chosen
    /// `text/html` is stored XSS against the cockpit. The sniff stays honest (the record says
    /// `text/html`, because that is what the bytes are); what is *served* is narrowed to an
    /// allow-list of inert media types, and everything else leaves as an opaque download.
    ///
    /// An allow-list, not a deny-list of the types known to execute today: a deny-list is a
    /// list of the attacks someone has already thought of.
    pub fn serve_mime(&self) -> &str {
        if self.is_image() || self.is_video() || self.mime.starts_with("audio/") {
            &self.mime
        } else {
            UNKNOWN_MIME
        }
    }
}

/// Why an ingress was refused. Both variants are refusals *before* anything reaches disk.
#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("the file is empty")]
    Empty,
    #[error("the file is {got} bytes, over the {cap}-byte cap")]
    TooLarge { got: usize, cap: usize },
    #[error("media store i/o: {0}")]
    Io(#[from] io::Error),
}

/// `<OZINT_DATA_DIR>/ozint/media` — alongside `geo`'s snapshot directory, under the same
/// root, so one `OZINT_DATA_DIR` still describes the whole installation's state.
pub fn media_dir() -> PathBuf {
    ozint_core::config::data_dir().join("ozint").join("media")
}

/// Lowercase hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The three digests of `bytes`, as lowercase hex, in `(md5, sha1, sha256)` order.
pub fn digests(bytes: &[u8]) -> (String, String, String) {
    let md5 = hex(&md5::Md5::digest(bytes));
    let sha1 = hex(&sha1::Sha1::digest(bytes));
    let sha256 = hex(&sha2::Sha256::digest(bytes));
    (md5, sha1, sha256)
}

/// The MIME type of `bytes`, read from their magic bytes alone.
///
/// Returns [`UNKNOWN_MIME`] rather than `None` for anything unrecognised: every stored object
/// has a type, and "we could not tell" is a type — the one that promises nothing and is safe
/// to serve.
pub fn sniff_mime(bytes: &[u8]) -> &'static str {
    infer::get(bytes).map_or(UNKNOWN_MIME, |kind| kind.mime_type())
}

/// Why a thumbnail could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum ThumbnailError {
    #[error("`{0}` is not a decodable image type")]
    NotAnImage(String),
    #[error("the image exceeds the decode limits (dimensions or memory)")]
    TooLarge,
    #[error("the image bytes could not be decoded: {0}")]
    Decode(String),
    #[error("the thumbnail could not be encoded: {0}")]
    Encode(String),
}

/// The widest dimension a source image is allowed to decode to. This is a decompression-bomb
/// guard, not a quality choice: a hostile file can claim any pixel count in its header while
/// staying a few KB on disk, and the decoder allocates the *decoded* buffer, not the file
/// size. 12000px is generous for anything a phone or camera produces (a 108MP sensor tops out
/// well under it) and small enough that the worst case is tens of megabytes, not gigabytes.
const MAX_DECODE_DIMENSION: u32 = 12_000;

/// The decoder's own working-memory ceiling, independent of the dimension cap above: a
/// 12000×12000 RGBA buffer is ~576MB, comfortably past what one thumbnail request should be
/// allowed to hold. 256MB covers that image at three bytes/pixel with room for the decoder's
/// own scratch space.
const MAX_DECODE_ALLOC_BYTES: u64 = 256 * 1024 * 1024;

fn decode_limits() -> Limits {
    // `Limits` is `#[non_exhaustive]`, so it is built from `Default` (max_alloc 512MiB, no
    // dimension cap) and narrowed rather than struct-literal constructed.
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DECODE_DIMENSION);
    limits.max_image_height = Some(MAX_DECODE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC_BYTES);
    limits
}

/// Decodes `bytes` as `mime` under [`decode_limits`]. Shared by [`thumbnail`] and
/// [`crate::decode`]'s QR path so the two decoders in this crate answer to one bomb guard.
pub(crate) fn decode_bounded(bytes: &[u8], mime: &str) -> Result<DynamicImage, ThumbnailError> {
    let format = ImageFormat::from_mime_type(mime)
        .ok_or_else(|| ThumbnailError::NotAnImage(mime.to_string()))?;
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(decode_limits());
    reader.decode().map_err(|e| match e {
        image::ImageError::Limits(_) => ThumbnailError::TooLarge,
        other => ThumbnailError::Decode(other.to_string()),
    })
}

/// A downscaled JPEG of `bytes`, fit within `max_dim` on its longest side, aspect preserved.
///
/// `bytes` must already be known-image (`StoredMedia::is_image`) — this function does not
/// re-sniff, since the caller already has that answer. Always encodes to JPEG regardless of
/// the source format: a thumbnail is a rendering aid, not an archival copy, and one output
/// format means one code path instead of one per source format. Transparency is flattened
/// onto black, which is acceptable for a small preview and keeps the encoder simple — the
/// full-size original (served un-transformed by the `GET` route) is always available for
/// anything that needs the real pixels.
pub fn thumbnail(bytes: &[u8], mime: &str, max_dim: u32) -> Result<Vec<u8>, ThumbnailError> {
    let image = decode_bounded(bytes, mime)?;
    let scaled = image.thumbnail(max_dim, max_dim).to_rgb8();

    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 82)
        .encode_image(&scaled)
        .map_err(|e| ThumbnailError::Encode(e.to_string()))?;
    Ok(out)
}

/// The two paths one object occupies: its bytes and its metadata sidecar.
///
/// Fanned out one level on the first byte of the hash, the same shape git uses for its object
/// store and for the same reason — a flat directory of tens of thousands of entries is slow
/// to list on every filesystem this ships to.
fn object_paths(root: &Path, media_id: &str) -> (PathBuf, PathBuf) {
    let shard = root.join(&media_id[..2]);
    (
        shard.join(format!("{media_id}.bin")),
        shard.join(format!("{media_id}.json")),
    )
}

/// A `media_id` we are willing to turn into a path.
///
/// Every read path runs through this. `media_id` reaches this crate from a URL segment, and
/// a store keyed by "whatever the client said" is a directory traversal with extra steps —
/// so the check is not "does it look tidy" but "is it exactly 64 lowercase hex characters",
/// which no `..` or separator can satisfy.
pub fn is_media_id(candidate: &str) -> bool {
    candidate.len() == 64
        && candidate
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Stores `bytes`, returning what was stored.
///
/// Idempotent: storing bytes already present rewrites the same content to the same path and
/// returns the same `media_id`. The metadata sidecar *is* rewritten, so a re-store through a
/// different door refreshes `source_url` and `stored_at` — the bytes are immutable, the
/// record of how we last obtained them is not.
pub fn store_bytes(bytes: &[u8], source_url: Option<String>) -> Result<StoredMedia, MediaError> {
    store_bytes_in(&media_dir(), bytes, source_url)
}

/// [`store_bytes`] against an explicit root — the form the tests use, so they never touch the
/// real `OZINT_DATA_DIR`.
pub fn store_bytes_in(
    root: &Path,
    bytes: &[u8],
    source_url: Option<String>,
) -> Result<StoredMedia, MediaError> {
    if bytes.is_empty() {
        return Err(MediaError::Empty);
    }
    if bytes.len() > MAX_MEDIA_BYTES {
        return Err(MediaError::TooLarge {
            got: bytes.len(),
            cap: MAX_MEDIA_BYTES,
        });
    }

    let (md5, sha1, sha256) = digests(bytes);
    let record = StoredMedia {
        media_id: sha256.clone(),
        md5,
        sha1,
        sha256: sha256.clone(),
        bytes: bytes.len(),
        mime: sniff_mime(bytes).to_string(),
        source_url,
        stored_at: Utc::now(),
    };

    let (bin_path, meta_path) = object_paths(root, &sha256);
    if let Some(parent) = bin_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&bin_path, bytes)?;
    std::fs::write(
        &meta_path,
        serde_json::to_vec_pretty(&record).expect("StoredMedia always serialises"),
    )?;
    Ok(record)
}

/// The metadata for `media_id`, or `None` if the store does not hold it.
pub fn load_meta_in(root: &Path, media_id: &str) -> Result<Option<StoredMedia>, MediaError> {
    if !is_media_id(media_id) {
        return Ok(None);
    }
    let (_, meta_path) = object_paths(root, media_id);
    match std::fs::read(&meta_path) {
        Ok(raw) => Ok(serde_json::from_slice(&raw).ok()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn load_meta(media_id: &str) -> Result<Option<StoredMedia>, MediaError> {
    load_meta_in(&media_dir(), media_id)
}

/// The metadata and the bytes for `media_id`, or `None` if the store does not hold it.
pub fn load_in(root: &Path, media_id: &str) -> Result<Option<(StoredMedia, Vec<u8>)>, MediaError> {
    let Some(meta) = load_meta_in(root, media_id)? else {
        return Ok(None);
    };
    let (bin_path, _) = object_paths(root, media_id);
    match std::fs::read(&bin_path) {
        Ok(bytes) => Ok(Some((meta, bytes))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn load(media_id: &str) -> Result<Option<(StoredMedia, Vec<u8>)>, MediaError> {
    load_in(&media_dir(), media_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-pixel PNG, as real magic bytes — a hand-written `\x89PNG` prefix would test the
    /// sniffer against a fixture built from the sniffer's own assumptions.
    const PNG: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    fn temp_root() -> PathBuf {
        let dir = std::env::temp_dir()
            .join("ozint-media-tests")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ── Digests: pinned to published vectors, not to our own output ──────────────────

    #[test]
    fn the_three_digests_match_their_published_vectors_for_abc() {
        let (md5, sha1, sha256) = digests(b"abc");
        assert_eq!(md5, "900150983cd24fb0d6963f7d28e17f72", "RFC 1321");
        assert_eq!(
            sha1, "a9993e364706816aba3e25717850c26c9cd0d89d",
            "FIPS 180-2"
        );
        assert_eq!(
            sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "FIPS 180-2"
        );
    }

    #[test]
    fn the_three_digests_match_their_published_vectors_for_the_empty_input() {
        // Never reachable through `store_bytes` (empty is refused), but the digest helper is
        // also the thing `entity-hash` will reuse, and the empty vector is the classic
        // off-by-one catcher for a streaming implementation.
        let (md5, sha1, sha256) = digests(b"");
        assert_eq!(md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ── Sniffing: the declared type never enters the picture ─────────────────────────

    #[test]
    fn a_png_is_recognised_from_its_magic_bytes() {
        assert_eq!(sniff_mime(PNG), "image/png");
    }

    #[test]
    fn html_wearing_an_image_name_is_not_an_image() {
        // The XSS shape this module exists to refuse: bytes that a `.png` filename and a
        // `Content-Type: image/png` header both call an image. Only the bytes get a vote.
        let record =
            store_bytes_in(&temp_root(), b"<html><script>alert(1)</script>", None).unwrap();
        assert_eq!(
            record.mime, "text/html",
            "the record states what the bytes are"
        );
        assert!(!record.is_image(), "nothing may treat this as pixels");
        assert_eq!(
            record.serve_mime(),
            UNKNOWN_MIME,
            "and the one thing it must never leave as is renderable HTML"
        );
    }

    #[test]
    fn only_inert_media_types_are_served_under_their_own_name() {
        let root = temp_root();
        let png = store_bytes_in(&root, PNG, None).unwrap();
        assert_eq!(png.serve_mime(), "image/png");

        // A deliberately hand-built record: the point is the allow-list, and the types worth
        // asserting about (SVG, PDF, a zip full of anything) are ones `infer` would need a
        // real sample of to reach.
        let mut record = png.clone();
        for renderable in [
            "image/svg+xml",
            "application/pdf",
            "text/html",
            "application/zip",
        ] {
            record.mime = renderable.to_string();
            assert_eq!(
                record.serve_mime(),
                UNKNOWN_MIME,
                "{renderable} must not be served under its own name"
            );
        }
        for inert in ["image/jpeg", "image/webp", "video/mp4", "audio/mpeg"] {
            record.mime = inert.to_string();
            assert_eq!(record.serve_mime(), inert);
        }
    }

    #[test]
    fn unrecognised_bytes_are_stored_rather_than_refused() {
        // Malware triage is the case for bytes nobody can identify; refusing them would
        // break `entity-hash`'s whole reason for taking a file at all.
        let root = temp_root();
        let record = store_bytes_in(&root, &[0x00, 0x01, 0x02, 0x03, 0x04], None).unwrap();
        assert_eq!(record.mime, UNKNOWN_MIME);
        assert!(load_in(&root, &record.media_id).unwrap().is_some());
    }

    // ── Addressing ───────────────────────────────────────────────────────────────────

    #[test]
    fn the_media_id_is_the_sha256_of_the_bytes() {
        let record = store_bytes_in(&temp_root(), b"abc", None).unwrap();
        assert_eq!(
            record.media_id,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(record.media_id, record.sha256);
    }

    #[test]
    fn storing_the_same_bytes_twice_is_one_object() {
        let root = temp_root();
        let first = store_bytes_in(&root, PNG, Some("https://a.example/x.png".into())).unwrap();
        let second = store_bytes_in(&root, PNG, Some("https://b.example/y.png".into())).unwrap();
        assert_eq!(first.media_id, second.media_id);

        // The bytes are immutable; the record of how we last obtained them is not.
        let meta = load_meta_in(&root, &first.media_id).unwrap().unwrap();
        assert_eq!(meta.source_url.as_deref(), Some("https://b.example/y.png"));
    }

    #[test]
    fn stored_bytes_come_back_unchanged() {
        let root = temp_root();
        let record = store_bytes_in(&root, PNG, None).unwrap();
        let (meta, bytes) = load_in(&root, &record.media_id).unwrap().unwrap();
        assert_eq!(bytes, PNG);
        assert_eq!(meta, record);
    }

    #[test]
    fn an_object_the_store_does_not_hold_is_absent_not_an_error() {
        let root = temp_root();
        let absent = "0".repeat(64);
        assert!(load_in(&root, &absent).unwrap().is_none());
        assert!(load_meta_in(&root, &absent).unwrap().is_none());
    }

    // ── Path safety ──────────────────────────────────────────────────────────────────

    #[test]
    fn only_64_lowercase_hex_characters_are_a_media_id() {
        assert!(is_media_id(&"a".repeat(64)));
        assert!(is_media_id(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ));
        assert!(
            !is_media_id(&"A".repeat(64)),
            "uppercase is not the form we mint"
        );
        assert!(!is_media_id(&"a".repeat(63)));
        assert!(!is_media_id(&"a".repeat(65)));
        assert!(!is_media_id("../../../../etc/passwd"));
        assert!(!is_media_id(""));
        assert!(!is_media_id(&format!("{}/x", "a".repeat(62))));
    }

    #[test]
    fn a_traversal_shaped_id_reads_nothing_rather_than_escaping_the_root() {
        // The check has to happen before any path is built, so this must be `None` and not
        // an i/o error about a file outside the store.
        let root = temp_root();
        std::fs::write(root.join("secret.json"), b"{}").unwrap();
        assert!(load_meta_in(&root, "../secret").unwrap().is_none());
    }

    // ── Caps ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_empty_file_is_refused_before_it_reaches_disk() {
        assert!(matches!(
            store_bytes_in(&temp_root(), b"", None),
            Err(MediaError::Empty)
        ));
    }

    #[test]
    fn a_file_over_the_cap_is_refused() {
        let too_big = vec![0u8; MAX_MEDIA_BYTES + 1];
        assert!(matches!(
            store_bytes_in(&temp_root(), &too_big, None),
            Err(MediaError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_upload_cap_and_the_fetch_cap_are_the_same_number() {
        // Two doors into one store must not disagree about what fits through them.
        assert_eq!(MAX_MEDIA_BYTES as u64, crate::fetch::MAX_BODY_BYTES);
    }

    // ── Thumbnails ──────────────────────────────────────────────────────────────────

    /// A real photo, not a synthetic pixel: `EXIF_JPEG` below is the same fixture the EXIF
    /// tests decode, generated with Pillow/piexif rather than hand-assembled, so both suites
    /// exercise a JPEG a real encoder produced.
    const EXIF_JPEG: &[u8] = include_bytes!("../testdata/exif_gps.jpg");

    #[test]
    fn a_thumbnail_is_smaller_and_still_a_valid_jpeg() {
        let thumb = thumbnail(EXIF_JPEG, "image/jpeg", 64).unwrap();
        assert!(
            thumb.len() < EXIF_JPEG.len(),
            "a 64px thumbnail must not be bigger than a 200x150 source"
        );
        let decoded = image::load_from_memory_with_format(&thumb, ImageFormat::Jpeg).unwrap();
        assert!(decoded.width() <= 64 && decoded.height() <= 64);
    }

    #[test]
    fn a_png_thumbnails_to_a_jpeg() {
        // One output format regardless of source, per the function's own doc.
        let thumb = thumbnail(PNG, "image/png", 32).unwrap();
        assert_eq!(
            infer::get(&thumb).map(|k| k.mime_type()),
            Some("image/jpeg")
        );
    }

    #[test]
    fn aspect_ratio_is_preserved() {
        // The fixture is 200x150 (4:3). A 100px box must not stretch it square.
        let thumb = thumbnail(EXIF_JPEG, "image/jpeg", 100).unwrap();
        let decoded = image::load_from_memory_with_format(&thumb, ImageFormat::Jpeg).unwrap();
        let ratio = decoded.width() as f64 / decoded.height() as f64;
        assert!((ratio - 200.0 / 150.0).abs() < 0.05, "ratio was {ratio}");
    }

    #[test]
    fn html_bytes_are_refused_rather_than_handed_to_a_decoder() {
        // The mime here is what `sniff_mime` actually returns for HTML — this function must
        // reject it by format, not attempt a decode of arbitrary bytes.
        let err = thumbnail(b"<html></html>", "text/html", 64).unwrap_err();
        assert!(matches!(err, ThumbnailError::NotAnImage(_)));
    }

    #[test]
    fn a_claimed_mime_that_does_not_match_the_bytes_fails_to_decode_rather_than_panicking() {
        // `image/png` claimed over bytes that are not a PNG: the decoder must error, not
        // guess. This is the same "the type on the wire is a claim, not a fact" boundary the
        // store itself enforces, exercised here against the decoder directly.
        let err = thumbnail(b"not actually a png", "image/png", 64).unwrap_err();
        assert!(matches!(err, ThumbnailError::Decode(_)));
    }
}
