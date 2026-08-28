//! The HTTP half of file upload and the media proxy — the two doors bytes enter by, and
//! the one door they leave by.
//!
//! - `POST /api/ozint/upload` — multipart ingress. Reaches nothing outside this process.
//! - `POST /api/ozint/media {url}` — fetch a remote object through the SSRF guard. Outbound,
//!   so it sits behind the freeze gate with the rest of the outbound routes.
//! - `GET  /api/ozint/media/{mediaId}` — serve a stored object **same-origin**.
//! - `GET  /api/ozint/media/{mediaId}/thumbnail?size=` — a downscaled JPEG of a stored image,
//!   same-origin, same headers.
//!
//! ## Why serving same-origin is the point, and what it costs
//!
//! The cockpit must never render a remote `<img src>` straight from the source: the request
//! would carry a referrer, a cookie jar and the analyst's IP to a host that is, quite often,
//! the subject of the investigation. Proxying removes that. But it moves the bytes onto the
//! cockpit's own origin, which is why [`ozint::media::StoredMedia::serve_mime`] exists
//! and why every response below carries `nosniff` and a `default-src 'none'` CSP: the whole
//! benefit of proxying is undone if the proxy can be talked into serving a document.
//!
//! ## What is not here
//!
//! No video poster or duration — video keyframing needs a bundled `ffmpeg` binary, not a
//! crate, and stays out of this crate's reach until a local utility runtime packages one.
//! Reverse-image lookup (SauceNAO et al.) needs a key nothing in this environment holds.

use axum::Json;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use ozint::fetch::{OzFetchOptions, OzOutcome, oz_fetch_bytes};
use ozint::media::{self, MediaError, StoredMedia, ThumbnailError};

use crate::state::AppState;

/// A remote fetch of a *media object* is not a page fetch: 12 seconds is generous for a JSON
/// API and thin for a multi-megabyte image on a slow host. Measured against the same class of
/// problem the Wayback CDX call turned up last session — a default tuned for one shape of
/// call silently failing every call of another shape.
const MEDIA_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

fn bad_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": message.into() })),
    )
        .into_response()
}

fn server_error(err: impl std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": err.to_string() })),
    )
        .into_response()
}

/// A refused ingress, translated to the status the client should see. A file over the cap is
/// the client's problem (413), not ours (500) — and saying so is what lets the cockpit show
/// "too large" instead of "something went wrong".
fn ingress_error(err: MediaError) -> Response {
    match err {
        MediaError::Empty => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        ),
        MediaError::TooLarge { .. } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": err.to_string() })),
        ),
        MediaError::Io(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        ),
    }
    .into_response()
}

/// What both ingress doors answer with.
///
/// The whole `StoredMedia` record, digests included — an uploaded file must offer **both**
/// routes (an IMG/VID node by metadata, a SHA node by hash)
/// rather than the server silently picking one, and the client cannot offer a choice it was
/// not told about. Nothing here decides which node gets created; that is the analyst's call,
/// and this response is what makes it an informed one.
fn stored_response(record: StoredMedia, status: StatusCode) -> Response {
    (status, Json(record)).into_response()
}

/// `POST /api/ozint/upload` — multipart, one file.
///
/// Every non-file field is ignored, including any the client sends to name the object: the
/// store is content-addressed precisely so no caller can name anything. A declared filename
/// and a declared `Content-Type` both arrive here and both go no further than this function.
pub async fn upload(mut multipart: Multipart) -> Response {
    let mut bytes: Option<Vec<u8>> = None;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            // A malformed multipart body, a body over the route's limit, a client that hung
            // up mid-upload — all of them are the request's fault, and all of them arrive
            // here as one opaque error.
            Err(e) => return bad_request(format!("could not read the uploaded file: {e}")),
        };
        // The first field carrying data wins. A second file in one request is not an error to
        // reject noisily — it is a client sending something this route never promised to
        // handle, and the analyst gets the file they can see was taken.
        let data = match field.bytes().await {
            Ok(data) => data,
            Err(e) => return bad_request(format!("could not read the uploaded file: {e}")),
        };
        if !data.is_empty() {
            bytes = Some(data.to_vec());
            break;
        }
    }

    let Some(bytes) = bytes else {
        return bad_request("the request carried no file");
    };

    match media::store_bytes(&bytes, None) {
        Ok(record) => stored_response(record, StatusCode::CREATED),
        Err(e) => ingress_error(e),
    }
}

/// A failed remote fetch, as a status and a sentence an analyst can act on.
///
/// Written out rather than `format!("{outcome:?}")`, which is what this first shipped as and
/// which put `Blocked { url: "http://127.0.0.1:3999/…" }` — Rust's `Debug` syntax — on the
/// wire as a user-facing message.
fn fetch_refusal(outcome: &OzOutcome) -> (StatusCode, String) {
    match outcome {
        OzOutcome::Blocked { .. } => (
            StatusCode::FORBIDDEN,
            "the SSRF guard refused that address — it is not a public host".to_string(),
        ),
        OzOutcome::TooLarge { cap_bytes } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("the object is larger than the {cap_bytes}-byte cap"),
        ),
        OzOutcome::Timeout { attempts, .. } => (
            StatusCode::GATEWAY_TIMEOUT,
            format!("the source did not answer within the timeout ({attempts} attempts)"),
        ),
        OzOutcome::HttpError { status, .. } => (
            StatusCode::BAD_GATEWAY,
            format!("the source answered {status}"),
        ),
        OzOutcome::TransportError { message } => (
            StatusCode::BAD_GATEWAY,
            format!("could not reach the source: {message}"),
        ),
        OzOutcome::Cancelled => (
            StatusCode::BAD_GATEWAY,
            "the fetch was cancelled".to_string(),
        ),
        // Unreachable on this path — `oz_fetch_bytes` parses nothing, so it never produces
        // these. Answered rather than `unreachable!()`: a panic in a route is a 500 with no
        // message, and this is not worth one.
        OzOutcome::Ok(_) | OzOutcome::ParseError { .. } => {
            (StatusCode::BAD_GATEWAY, "the fetch failed".to_string())
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestBody {
    url: String,
}

/// `POST /api/ozint/media {url}` — fetch a remote object and store it.
///
/// The URL is screened by the same `safe_fetch_url` guard every other OZINT call goes
/// through, inside `oz_fetch_bytes`. There is deliberately no second screen here: a guard
/// applied twice in two places is a guard that will one day be applied in one.
///
/// `ozint::egress::oz_guard` is **not** consulted, and that is not an omission. That
/// gate governs text this process *sends to a cloud model* — its `carries_media_bytes` flag
/// refuses handing image bytes to an LLM. Pulling bytes from the URL the analyst is already
/// investigating is the opposite direction and a different question.
pub async fn ingest(State(_state): State<AppState>, Json(body): Json<IngestBody>) -> Response {
    let url = body.url.trim();
    if url.is_empty() {
        return bad_request("url must not be empty");
    }

    let opts = OzFetchOptions {
        timeout: MEDIA_FETCH_TIMEOUT,
        ..Default::default()
    };
    let fetched = match oz_fetch_bytes(url, opts).await {
        Ok(fetched) => fetched,
        // Every failure is already a settled `OzOutcome`; it is reported as the JSON the
        // cockpit can render, not flattened into a 500.
        Err(outcome) => {
            let (status, message) = fetch_refusal(&outcome);
            return (status, Json(json!({ "error": message }))).into_response();
        }
    };

    // `fetched.content_type` is recorded nowhere and trusted nowhere. What the object is gets
    // decided by sniffing the bytes, inside the store.
    match media::store_bytes(&fetched.bytes, Some(fetched.url)) {
        Ok(record) => stored_response(record, StatusCode::CREATED),
        Err(e) => ingress_error(e),
    }
}

/// `GET /api/ozint/media/{mediaId}` — the bytes, under a type we are willing to stand behind.
pub async fn get(Path(media_id): Path<String>) -> Response {
    let loaded = match media::load(&media_id) {
        Ok(loaded) => loaded,
        Err(e) => return server_error(e),
    };
    let Some((record, bytes)) = loaded else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such media object" })),
        )
            .into_response();
    };

    let serve_mime = record.serve_mime();
    // An object we will not vouch for is handed over as a download rather than rendered. The
    // pair matters: `nosniff` stops a browser from second-guessing the type we chose, and
    // `attachment` stops it from being a top-level document if it is ever opened directly.
    let disposition = if serve_mime == media::UNKNOWN_MIME {
        HeaderValue::from_static("attachment")
    } else {
        HeaderValue::from_static("inline")
    };

    let mut response = (StatusCode::OK, bytes).into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(serve_mime) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    // Defence in depth behind the allow-list: even if something renderable ever reached this
    // response, it would have no scripts, no styles, no subresources and no origin.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    // Content-addressed, so the bytes behind a `mediaId` can never change. `private` because
    // an investigation's media is not something a shared cache should hold.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=31536000, immutable"),
    );
    response
}

#[derive(Debug, Deserialize)]
pub struct ThumbnailQuery {
    /// Longest side in pixels. The cockpit only ever asks for two concrete sizes — 48 for a
    /// tree/card tile, 212 for the detail panel — but this route takes whatever the caller asks for
    /// rather than an enum of exactly two, clamped to a sane range so a client typo cannot
    /// turn into a multi-thousand-pixel decode-and-encode on every request.
    size: Option<u32>,
}

/// The smallest a thumbnail may be asked for. Below this a request is not asking for a
/// preview, it is asking for a pathological number of tiny requests.
const MIN_THUMBNAIL_DIM: u32 = 16;
/// The largest — bigger than this and the caller wants the original, which `GET
/// /api/ozint/media/{mediaId}` already serves.
const MAX_THUMBNAIL_DIM: u32 = 512;
const DEFAULT_THUMBNAIL_DIM: u32 = 212;

/// The `size` query param, defaulted and clamped. Pulled out of [`thumbnail`] so the clamping
/// itself — the one thing here with a request-cost consequence — is testable without a stored
/// object.
fn resolve_size(query: &ThumbnailQuery) -> u32 {
    query
        .size
        .unwrap_or(DEFAULT_THUMBNAIL_DIM)
        .clamp(MIN_THUMBNAIL_DIM, MAX_THUMBNAIL_DIM)
}

fn thumbnail_error_response(err: ThumbnailError) -> Response {
    match err {
        ThumbnailError::NotAnImage(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "this object is not a decodable image type" })),
        ),
        ThumbnailError::TooLarge => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "the image exceeds this server's decode limits" })),
        ),
        ThumbnailError::Decode(_) | ThumbnailError::Encode(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "the thumbnail could not be produced" })),
        ),
    }
    .into_response()
}

/// `GET /api/ozint/media/{mediaId}/thumbnail?size=` — a downscaled JPEG of a stored image,
/// same-origin and under the same `nosniff`/CSP/`private` headers as the full-size route.
/// The media proxy's thumbnail half — see `ozint::media`'s module doc.
pub async fn thumbnail(
    Path(media_id): Path<String>,
    Query(query): Query<ThumbnailQuery>,
) -> Response {
    let loaded = match media::load(&media_id) {
        Ok(loaded) => loaded,
        Err(e) => return server_error(e),
    };
    let Some((record, bytes)) = loaded else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such media object" })),
        )
            .into_response();
    };
    if !record.is_image() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "this object is not a decodable image type" })),
        )
            .into_response();
    }

    let max_dim = resolve_size(&query);
    let thumb = match media::thumbnail(&bytes, &record.mime, max_dim) {
        Ok(thumb) => thumb,
        Err(e) => return thumbnail_error_response(e),
    };

    let mut response = (StatusCode::OK, thumb).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/jpeg"));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("inline"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );
    // Immutable like the full-size route: a thumbnail is a pure function of the (immutable,
    // content-addressed) bytes plus `size`, so nothing behind this URL ever changes.
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=31536000, immutable"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingest_body_deserializes_camel_case() {
        let body: IngestBody =
            serde_json::from_str(r#"{"url":"https://example.com/a.png"}"#).unwrap();
        assert_eq!(body.url, "https://example.com/a.png");
    }

    #[test]
    fn an_over_cap_upload_is_the_clients_fault_not_a_server_error() {
        // A 500 here would read as "OZINT broke" for a file the analyst can simply resize.
        let response = ingress_error(MediaError::TooLarge { got: 99, cap: 10 });
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let response = ingress_error(MediaError::Empty);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn only_an_allow_listed_type_is_served_inline() {
        // The one line of this route with a security consequence, asserted directly rather
        // than trusted to the reading of it.
        let mut record = StoredMedia {
            media_id: "a".repeat(64),
            md5: String::new(),
            sha1: String::new(),
            sha256: "a".repeat(64),
            bytes: 1,
            mime: "image/png".into(),
            source_url: None,
            stored_at: chrono::Utc::now(),
        };
        assert_eq!(record.serve_mime(), "image/png");

        record.mime = "text/html".into();
        assert_eq!(
            record.serve_mime(),
            media::UNKNOWN_MIME,
            "an uploaded HTML page must never come back as a document on our own origin"
        );
    }

    #[test]
    fn thumbnail_size_defaults_and_clamps() {
        assert_eq!(
            resolve_size(&ThumbnailQuery { size: None }),
            DEFAULT_THUMBNAIL_DIM
        );
        assert_eq!(
            resolve_size(&ThumbnailQuery { size: Some(1) }),
            MIN_THUMBNAIL_DIM
        );
        assert_eq!(
            resolve_size(&ThumbnailQuery { size: Some(50_000) }),
            MAX_THUMBNAIL_DIM
        );
        assert_eq!(resolve_size(&ThumbnailQuery { size: Some(64) }), 64);
    }

    #[tokio::test]
    async fn a_thumbnail_request_for_an_absent_media_id_is_a_404() {
        let response = thumbnail(Path("0".repeat(64)), Query(ThumbnailQuery { size: None })).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
