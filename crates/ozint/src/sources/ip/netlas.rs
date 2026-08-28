//! `ip-netlas` — Netlas's host lookup. Writes rows only; owns no [`crate::types::IpPayload`]
//! field, same posture as `ip-peeringdb`/`ip-censys`.
//!
//! `GET https://app.netlas.io/api/host/{ip}/`, header `X-Api-Key: {NETLAS_API_KEY}`. Verified
//! live 2026-08-25 against `8.8.8.8`: **HTTP 200**, `ports[]` (each `{port, protocol, prot4,
//! prot7}`), `software[]` (tagged, e.g. `http_3`), `domains_count`. **The path is
//! `/api/host/{ip}/` — not `/api/v1/host/` or `/api/ip/`, both of which are wrong**, confirmed
//! by direct call: this crate's own doc comments elsewhere must not be trusted for Netlas's
//! shape without re-checking, since neither of those two plausible-looking paths resolves.
//! Header auth (`X-Api-Key`) works; Netlas also documents a `?apikey=` query-param form, not
//! used here since the header form was the one verified.
//!
//! Gated behind [`crate::layer_plan::reputation_flagged`], in `plans::ip_plan`'s `deep-recon`
//! phase alongside `ip-censys` — see that module's doc for why the two share a phase distinct
//! from `ip-spiderfoot`'s sidecar sweep.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const NETLAS_BASE: &str = "https://app.netlas.io/api/host/";
const ENV_VAR: &str = "NETLAS_API_KEY";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetlasResult {
    pub ports: Vec<u16>,
    pub software_tags: Vec<String>,
    pub domains_count: Option<u64>,
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub is_tor: bool,
}

fn dedup_sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort_unstable();
    v.dedup();
    v
}

pub fn parse_netlas(json: &serde_json::Value) -> Result<NetlasResult, String> {
    if !json.is_object() {
        return Err("Netlas response was not a JSON object".to_string());
    }

    let ports: Vec<u16> = json
        .get("ports")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("port").and_then(|v| v.as_u64()))
                .filter_map(|p| u16::try_from(p).ok())
                .collect()
        })
        .unwrap_or_default();

    let software_tags = dedup_sorted(
        json.get("software")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .flat_map(|s| {
                        s.get("tag")
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default()
                    })
                    .filter_map(|t| t.get("name").and_then(|v| v.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    );

    let privacy = json.get("privacy");
    let flag = |key: &str| {
        privacy
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };

    Ok(NetlasResult {
        ports,
        software_tags,
        domains_count: json.get("domains_count").and_then(|v| v.as_u64()),
        is_vpn: flag("is_vpn"),
        is_proxy: flag("is_proxy"),
        is_tor: flag("is_tor"),
    })
}

pub fn netlas_to_yield(result: &NetlasResult) -> ToolYield {
    let mut rows = Vec::new();
    if !result.ports.is_empty() {
        rows.push(OzRow {
            label: "Netlas ports".to_string(),
            value: result
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            ..Default::default()
        });
    }
    if !result.software_tags.is_empty() {
        rows.push(OzRow {
            label: "Netlas software".to_string(),
            value: result.software_tags.join(", "),
            ..Default::default()
        });
    }
    if let Some(n) = result.domains_count.filter(|n| *n > 0) {
        rows.push(OzRow {
            label: "Domains pointed here".to_string(),
            value: n.to_string(),
            ..Default::default()
        });
    }
    for (flagged, label) in [
        (result.is_vpn, "VPN"),
        (result.is_proxy, "Proxy"),
        (result.is_tor, "Tor"),
    ] {
        if flagged {
            rows.push(OzRow {
                label: "Netlas".to_string(),
                value: format!("flagged as {label}"),
                ..Default::default()
            });
        }
    }

    ToolYield {
        payload_patch: serde_json::json!({}),
        rows,
        // Corroborates `ip-internetdb`'s own anonymizer tag through the flag channel, never
        // the payload key — same discipline `ip-abuseipdb`'s `isTor` follows.
        flags: if result.is_vpn || result.is_proxy || result.is_tor {
            vec![(crate::layer_plan::FLAG_ANONYMIZER, true)]
        } else {
            Vec::new()
        },
        ..Default::default()
    }
}

pub async fn run_netlas(ip: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!("{NETLAS_BASE}{}/", urlencoding::encode(ip));
    let headers = vec![("X-Api-Key".to_string(), key)];
    let outcome = ctx
        .fetch(
            "ip-netlas",
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
                message: "Netlas response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_netlas(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(result) if result.ports.is_empty() && result.software_tags.is_empty() => {
            DispatchOutcome::Ran(
                ToolOutcome::OkEmpty,
                Some(ToolYield {
                    payload_patch: serde_json::json!({}),
                    ..Default::default()
                }),
            )
        }
        Ok(result) => {
            let count = (result.ports.len() + result.software_tags.len()) as u32;
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count },
                Some(netlas_to_yield(&result)),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from a live 2026-08-25 call against `8.8.8.8`.
    fn google_dns() -> serde_json::Value {
        serde_json::json!({
            "ports": [
                { "port": 443, "protocol": "https", "prot4": "tcp", "prot7": "http" },
                { "port": 53, "protocol": "dns_udp", "prot4": "udp", "prot7": "dns" }
            ],
            "software": [
                { "tag": [{ "name": "http_3", "description": "HTTP/3" }] }
            ],
            "domains_count": 12
        })
    }

    #[test]
    fn parses_ports_and_software_tags() {
        let result = parse_netlas(&google_dns()).unwrap();
        assert_eq!(result.ports, vec![443, 53].into_iter().collect::<Vec<_>>());
        assert_eq!(result.software_tags, vec!["http_3".to_string()]);
        assert_eq!(result.domains_count, Some(12));
    }

    #[test]
    fn writes_no_payload_field() {
        let result = parse_netlas(&google_dns()).unwrap();
        assert_eq!(
            netlas_to_yield(&result).payload_patch,
            serde_json::json!({})
        );
    }

    #[test]
    fn privacy_flags_set_the_shared_anonymizer_flag_not_a_payload_key() {
        let json = serde_json::json!({ "privacy": { "is_vpn": true } });
        let result = parse_netlas(&json).unwrap();
        let produced = netlas_to_yield(&result);
        assert_eq!(
            produced.flags,
            vec![(crate::layer_plan::FLAG_ANONYMIZER, true)]
        );
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }

    #[test]
    fn a_non_object_body_is_a_parse_error() {
        assert!(parse_netlas(&serde_json::json!([1, 2])).is_err());
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_netlas("8.8.8.8", &crate::sources::ToolCtx::default()).await;
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
