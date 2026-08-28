use axum::Router;
use axum::http::StatusCode;
use axum::routing::{any, get, post};
use tower_http::compression::CompressionLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::routes;
use crate::state::AppState;

/// Assemble the whole HTTP surface: the `/api/*` handlers plus the built web cockpit.
pub fn router(state: AppState) -> Router {
    // ── Routes the kill switch refuses while frozen ──────────────────────────────────
    //
    // The rule, applied per line below: a route belongs here if it makes an outbound call
    // or takes an action in the world. `routes::safety`'s module doc explains why the
    // membership is written out route by route instead of inferred — an implicit rule is
    // one nobody can audit, and under-gating is a silent egress leak while the UI says
    // "frozen".
    let gated = Router::new()
        // OSINT fan-out at third parties — the case that motivated the whole unit.
        .route("/api/ozint/fire", post(routes::ozint::fire::fire))
        // Re-running a node's tool chain is the same outbound fan-out as firing a layer, one
        // node wide instead of one layer wide — it belongs behind the same gate.
        .route("/api/ozint/refresh", post(routes::ozint::refresh::refresh))
        // Asking the Internet Archive what it holds for a URL tells a third party which URL is
        // under investigation — an outbound call with an OpSec cost, so it belongs here rather
        // than beside the local annotation routes below.
        .route(
            "/api/ozint/node/{id}/evidence",
            post(routes::ozint::evidence::capture),
        )
        // Pulls bytes from a URL the analyst supplies — an outbound call, screened by the
        // same SSRF guard as every other one. The upload and read halves of the media store
        // are local and stay open below.
        .route("/api/ozint/media", post(routes::ozint::media::ingest))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            routes::safety::freeze_gate,
        ));

    // ── Routes that stay live while frozen ───────────────────────────────────────────
    //
    // Local reads (a frozen instance must still be inspectable), local writes that reach
    // nothing, `/api/ozint/cancel` (a *stop* must never be blocked by a stop), and the
    // freeze namespace itself (a kill switch you cannot un-flip is a brick).
    let open = Router::new()
        .route("/api/health", get(routes::health::health))
        .route(
            "/api/safety/freeze",
            get(routes::safety::get).post(routes::safety::set),
        )
        .route("/api/ozint/cancel", post(routes::ozint::cancel::cancel))
        .route(
            "/api/ozint/investigations",
            get(routes::ozint::investigations::list),
        )
        .route(
            "/api/ozint/investigations/{id}",
            get(routes::ozint::investigations::get),
        )
        // Derived live from the stored tree, reaches nothing outside this process — a frozen
        // instance must still show what it already knows.
        .route(
            "/api/ozint/investigations/{id}/relations",
            get(routes::ozint::investigations::relations_for),
        )
        .route(
            "/api/ozint/investigations/{id}/meter",
            get(routes::ozint::investigations::meter),
        )
        // Same reasoning as `relations`: a pure local fold, nothing gated behind a frozen kill switch.
        .route(
            "/api/ozint/investigations/{id}/export",
            get(routes::ozint::investigations::export),
        )
        // Creates an investigation row and its root node, and nothing else — spawning reaches
        // no third party. The layer it will eventually fire goes through `/api/ozint/fire`,
        // which is gated.
        .route("/api/ozint/spawn", post(routes::ozint::spawn::spawn))
        // The analyst annotating their own findings reaches nothing outside this process, so
        // a frozen instance stays correctable.
        .route("/api/ozint/node/{id}/edit", post(routes::ozint::node::edit))
        .route(
            "/api/ozint/node/{id}/reject",
            post(routes::ozint::node::reject),
        )
        .route(
            "/api/ozint/node/{id}/restore",
            post(routes::ozint::node::restore),
        )
        // Pure local string work — eight decoders and the classifier, no network at all.
        .route("/api/ozint/decode", post(routes::ozint::decode::decode))
        // Bytes the analyst hands us directly: no outbound call, so a frozen instance can
        // still take a file. The default 2 MB body limit is raised to the store's own cap —
        // left alone, every upload over 2 MB would be refused by axum before the route's cap
        // (and its honest 413 message) was ever reached.
        .route(
            "/api/ozint/upload",
            post(routes::ozint::media::upload).layer(axum::extract::DefaultBodyLimit::max(
                ozint::media::MAX_MEDIA_BYTES,
            )),
        )
        // Reading back bytes we already hold. Local, and the one route that must be careful
        // about *how* it answers — see `routes::ozint::media`.
        .route("/api/ozint/media/{mediaId}", get(routes::ozint::media::get))
        // A downscaled re-encode of bytes we already hold — decode + resize + re-encode, no
        // network. Same care about how it answers as the route above.
        .route(
            "/api/ozint/media/{mediaId}/thumbnail",
            get(routes::ozint::media::thumbnail),
        );

    Router::new()
        .merge(gated)
        .merge(open)
        // Unmatched /api paths must 404 as JSON. Without this they fall through to the
        // cockpit's static fallback and return index.html with a 200 — a typo'd endpoint
        // would then look like a successful call returning HTML.
        .route("/api/{*rest}", any(api_not_found))
        .fallback_service(web_service())
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Any `/api/*` path with no handler. Kept JSON so a client that mistypes an endpoint gets a
/// parseable error instead of a page of HTML.
async fn api_not_found() -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({ "error": "Not Found" })),
    )
}

/// Serve the built web cockpit, falling back to `index.html` so client-side routes resolve
/// on a hard refresh.
fn web_service() -> ServeDir<ServeFile> {
    let dist = ozint_core::config::or_default("OZINT_WEB_DIST", "web/dist");
    let index = std::path::Path::new(&dist).join("index.html");
    ServeDir::new(&dist).fallback(ServeFile::new(index))
}
