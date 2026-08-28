//! `ip-censys` — Censys's new Platform API host asset lookup. Writes rows only; owns no
//! [`crate::types::IpPayload`] field (same posture as `ip-peeringdb` — see its module doc for
//! why a rows-only tool is not a gap).
//!
//! `GET https://api.platform.censys.io/v3/global/asset/host/{ip}`, `Authorization: Bearer
//! {CENSYS_API_SECRET}`. **Migrated endpoint, verified live 2026-08-25**: Censys's old v2
//! basic-auth shape (`-u API_ID:API_SECRET` against `search.censys.io/api/v2/...`) answers
//! `401` today. The Platform API is bearer-token auth, and — resolved by direct test against
//! both env values — the bearer is `CENSYS_API_SECRET` (a personal access token); a bearer of
//! `CENSYS_API_ID` answers `401 {"error":{"code":401,"message":"Access credentials are
//! invalid"}}`. `CENSYS_API_ID` is not used by this tool at all.
//!
//! A `200` carries `result.resource.location` (city/country/coordinates), `autonomous_system`
//! (ASN, description, BGP prefix), and per-port service data this tool does not yet parse
//! beyond a count — the free/personal tier's rate limit is tight enough that a first cut
//! favours breadth of what it reads over depth on any one field.
//!
//! Gated behind [`crate::layer_plan::reputation_flagged`], in `plans::ip_plan`'s `deep-recon`
//! phase alongside `ip-netlas`: both are fast keyed API calls, a different cost class from
//! `ip-spiderfoot`'s slow sidecar sweep, which is why they get their own phase rather than
//! joining it.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const CENSYS_BASE: &str = "https://api.platform.censys.io/v3/global/asset/host/";
const ENV_VAR: &str = "CENSYS_API_SECRET";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct CensysResult {
    pub city: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u64>,
    pub as_description: Option<String>,
    pub service_ports: Vec<u64>,
}

fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

pub fn parse_censys(json: &serde_json::Value) -> Result<CensysResult, String> {
    let resource = json
        .get("result")
        .and_then(|r| r.get("resource"))
        .ok_or_else(|| "Censys response has no `result.resource`".to_string())?;

    let location = resource.get("location");
    let asys = resource.get("autonomous_system");
    let ports = resource
        .get("services")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.get("port").and_then(|p| p.as_u64()))
                .collect()
        })
        .unwrap_or_default();

    Ok(CensysResult {
        city: location
            .and_then(|l| l.get("city"))
            .and_then(|v| v.as_str())
            .and_then(|s| nonempty(Some(s))),
        country: location
            .and_then(|l| l.get("country"))
            .and_then(|v| v.as_str())
            .and_then(|s| nonempty(Some(s))),
        asn: asys.and_then(|a| a.get("asn")).and_then(|v| v.as_u64()),
        as_description: asys
            .and_then(|a| a.get("description"))
            .and_then(|v| v.as_str())
            .and_then(|s| nonempty(Some(s))),
        service_ports: ports,
    })
}

pub fn censys_to_yield(result: &CensysResult) -> ToolYield {
    let mut rows = Vec::new();
    if let (Some(city), Some(country)) = (&result.city, &result.country) {
        rows.push(OzRow {
            label: "Censys location".to_string(),
            value: format!("{city}, {country}"),
            ..Default::default()
        });
    }
    if let Some(asn) = result.asn {
        let mut value = format!("AS{asn}");
        if let Some(desc) = &result.as_description {
            value.push_str(&format!(" — {desc}"));
        }
        rows.push(OzRow {
            label: "Censys ASN".to_string(),
            value,
            ..Default::default()
        });
    }
    if !result.service_ports.is_empty() {
        rows.push(OzRow {
            label: "Censys services".to_string(),
            value: result
                .service_ports
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            ..Default::default()
        });
    }

    ToolYield {
        payload_patch: serde_json::json!({}),
        rows,
        ..Default::default()
    }
}

pub async fn run_censys(ip: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(secret) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!("{CENSYS_BASE}{}", urlencoding::encode(ip));
    let headers = vec![("Authorization".to_string(), format!("Bearer {secret}"))];
    let outcome = ctx
        .fetch(
            "ip-censys",
            ip,
            &url,
            fetch::OzFetchOptions {
                headers,
                ..Default::default()
            },
        )
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // Censys answers 404 for a host it holds no asset record for — absence, not failure.
    if let OzOutcome::HttpError { status: 404, .. } = &outcome {
        return DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        );
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled, non-404 OzOutcome was handled above");
    };
    let OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "Censys response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_censys(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(result) => {
            let count = (result.city.is_some() as u32)
                + (result.asn.is_some() as u32)
                + result.service_ports.len() as u32;
            if count == 0 {
                DispatchOutcome::Ran(
                    ToolOutcome::OkEmpty,
                    Some(ToolYield {
                        payload_patch: serde_json::json!({}),
                        ..Default::default()
                    }),
                )
            } else {
                DispatchOutcome::Ran(
                    ToolOutcome::OkWithResults { count },
                    Some(censys_to_yield(&result)),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from a live 2026-08-25 call against `8.8.8.8`.
    fn google_dns() -> serde_json::Value {
        serde_json::json!({
            "result": {
                "resource": {
                    "ip": "8.8.8.8",
                    "location": {
                        "city": "Mountain View",
                        "country": "United States"
                    },
                    "autonomous_system": {
                        "asn": 15169,
                        "description": "GOOGLE - Google LLC"
                    }
                }
            }
        })
    }

    #[test]
    fn parses_a_real_record() {
        let result = parse_censys(&google_dns()).unwrap();
        assert_eq!(result.city.as_deref(), Some("Mountain View"));
        assert_eq!(result.asn, Some(15169));
        assert_eq!(
            result.as_description.as_deref(),
            Some("GOOGLE - Google LLC")
        );
    }

    #[test]
    fn writes_no_payload_field() {
        let result = parse_censys(&google_dns()).unwrap();
        assert_eq!(
            censys_to_yield(&result).payload_patch,
            serde_json::json!({})
        );
    }

    #[test]
    fn rejects_a_response_missing_the_envelope() {
        assert!(parse_censys(&serde_json::json!({})).is_err());
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_secret_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_censys("8.8.8.8", &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNoKey { env_var }, produced) => {
                assert_eq!(env_var, ENV_VAR);
                assert!(produced.is_none());
            }
            other => panic!("expected SkippedNoKey without a key, got {other:?}"),
        }

        if let Some(v) = prev {
            unsafe { std::env::set_var(ENV_VAR, v) };
        }
    }
}
