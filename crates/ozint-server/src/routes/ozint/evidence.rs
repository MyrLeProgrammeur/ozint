//! `POST /api/ozint/node/{id}/evidence {url}` — the wire half of evidence capture.
//!
//! Asks the Internet Archive what captures it already holds for one URL and records the answer
//! on the node's provenance. The engine half, and everything measured about the endpoint, is
//! `ozint::evidence`.
//!
//! ## Why the analyst names the URL
//!
//! A node has no single canonical URL. Its findings carry links in payload fields, in detail
//! section rows and in the tools' own source links, and picking one of those automatically
//! would mean writing a heuristic for "the important link on this card" that nothing in the
//! data supports. So this route captures **the URL it is given** — the analyst clicks the
//! `SRC ↗` row they actually want preserved. No URL is derived, guessed, or expanded.
//!
//! ## Why it sits behind the freeze gate
//!
//! Unlike `edit`/`reject`/`restore`, which are local annotations, this reaches a third party —
//! and it tells that third party which URL is under investigation. That is an outbound call
//! with an OpSec cost, so it belongs behind the kill switch with `fire` and `refresh`, not
//! beside the annotation routes.
//!
//! ## One call, no meter tick
//!
//! It bills nothing to the lookup meter. The meter counts *tool* invocations inside a layer —
//! the thing `GET /api/ozint/investigations/{id}/meter` reports as the cost of the
//! investigation — and an archive check is neither a tool in the registry nor part of any
//! layer's plan. Counting it there would inflate the number the analyst reads as "what this
//! investigation cost to run".

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use ozint::evidence::{self, EvidenceRecord};
use ozint::store;

use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBody {
    url: Option<String>,
}

/// `POST /api/ozint/node/{id}/evidence` — see the module doc.
pub async fn capture(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<EvidenceBody>,
) -> Response {
    let Some(url) = body.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "`url` is required" })),
        )
            .into_response();
    };

    // Checked before the call, not after: the archive query takes tens of seconds, and
    // spending them to then discover the node was never there is both slow and a request to a
    // third party made on behalf of nothing.
    match store::get_node(&state.db, &id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "node not found" })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }

    let record = EvidenceRecord::new(url, evidence::capture(url).await);
    // A failed check is stored too. "We asked and the archive did not answer" is a different
    // fact from "nobody ever asked", and only one of them is a reason to ask again.
    match store::record_evidence(&state.db, &id, record) {
        Ok(Some(evidence)) => Json(json!({ "evidence": evidence })).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "node not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_url_is_rejected_rather_than_defaulted_to_the_nodes_value() {
        // There is no sensible default here: a node's *value* is a handle or an address, not a
        // URL, and archiving something the analyst did not name would record evidence about a
        // page they never asked about.
        let body: EvidenceBody = serde_json::from_str("{}").unwrap();
        assert!(body.url.is_none());
    }

    #[test]
    fn the_url_deserializes_from_the_wire() {
        let body: EvidenceBody =
            serde_json::from_str(r#"{"url":"https://github.com/torvalds"}"#).unwrap();
        assert_eq!(body.url.as_deref(), Some("https://github.com/torvalds"));
    }
}
