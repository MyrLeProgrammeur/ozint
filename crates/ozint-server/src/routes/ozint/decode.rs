//! `POST /api/ozint/decode {value}` — local decode prepass over a seed.
//!
//! Answers "what else could this seed be?" — base64, hex, percent-encoding, HTML entities,
//! ROT13, a JWT payload, punycode, Morse, and short chains of those — with each reading typed
//! by the same classifier the Autofire button uses.
//!
//! **Entirely local**: no network, no key, no LLM, nothing persisted. That is why it sits in
//! the un-gated router and why it is safe to call freely from the seed bar. It is a POST only
//! because a seed can contain characters that have no business in a URL path (that being
//! rather the point of this endpoint).
//!
//! It decides nothing. The response is a list of candidates plus the codecs this build cannot
//! attempt at all; the analyst picks one and fires it as an ordinary seed.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use ozint::decode::{DecodeReport, prepass};

use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodeBody {
    value: Option<String>,
}

pub async fn decode(State(_state): State<AppState>, Json(body): Json<DecodeBody>) -> Response {
    let Some(value) = body
        .value
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "value is required" })),
        )
            .into_response();
    };
    let report: DecodeReport = prepass(value);
    Json(report).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn a_wrapped_seed_comes_back_decoded_and_typed() {
        let state = crate::test_support::test_state();
        let json = body_json(
            decode(
                State(state),
                Json(DecodeBody {
                    value: Some("bXRyZWJvc2NAZXhhbXBsZS5jb20=".into()),
                }),
            )
            .await,
        )
        .await;

        let hit = json["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["value"] == "mtrebosc@example.com")
            .expect("the decoded email");
        assert_eq!(hit["ozType"], "email");
        assert_eq!(hit["chain"][0], "base64");
        assert_eq!(hit["searchable"], true);
    }

    #[tokio::test]
    async fn a_plain_seed_comes_back_with_no_candidates_but_still_declares_what_it_skipped() {
        let state = crate::test_support::test_state();
        let json = body_json(
            decode(
                State(state),
                Json(DecodeBody {
                    value: Some("mtrebosc".into()),
                }),
            )
            .await,
        )
        .await;
        assert!(
            json["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["chain"][0] != "base64")
        );
        assert!(
            !json["unavailable"].as_array().unwrap().is_empty(),
            "QR and AES are always declared"
        );
    }

    #[tokio::test]
    async fn an_empty_value_is_a_400() {
        let state = crate::test_support::test_state();
        assert_eq!(
            decode(
                State(state),
                Json(DecodeBody {
                    value: Some("  ".into())
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
}
