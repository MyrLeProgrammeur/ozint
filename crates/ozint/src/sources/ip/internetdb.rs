//! `ip-internetdb` — Shodan's free InternetDB. Keyless. Owns the `ports` and `anonymizer`
//! fields of [`crate::types::IpPayload`].
//!
//! `GET https://internetdb.shodan.io/{ip}` — measured 2026-08-23, HTTP `200` with `ip`,
//! `ports` (an array of **bare integers**), `hostnames`, `cpes`, `tags` and `vulns` (CVE ids).
//! An address Shodan holds nothing on answers HTTP **`404`** with
//! `{"detail": "No information available"}`.
//!
//! ## Exposure is not reputation, and this tool must not be read as if it were
//!
//! InternetDB sits in wave 2, "reputation". It is the only keyless member of that
//! wave and it reports no reputation at all: no abuse confidence, no classification, no verdict.
//! So `abuseScore` and `classification` stay **unwritten**, rather than being filled with a `0`
//! and an `"unknown"`. A `0` there is not a neutral placeholder — `signal.rs` paints a chip
//! from that number, and zero renders as *confirmed clean*, which would be this crate asserting
//! an all-clear it never obtained. An absent field renders as nothing, which is the truth.
//!
//! ## The one reputation-shaped fact it does carry
//!
//! `tags`. Measured: a Tor exit relay (`185.220.101.1`) comes back `tags: ["tor"]`, and a cloud
//! host comes back `tags: ["cloud"]`. [`ANONYMIZER_TAGS`] maps the anonymity-network tags onto
//! `anonymizer` and [`crate::layer_plan::FLAG_ANONYMIZER`] — which is the input
//! `layer_plan::reputation_flagged()` waits on, and the reason that predicate is a pending
//! phase rather than a permanently-false one. Every other tag is rendered verbatim as a row and
//! interpreted by nobody.
//!
//! **`anonymizer` is only ever set to `true`.** An address with no anonymity tag is an address
//! Shodan has not tagged, which is not the same as an address that is not a proxy; writing
//! `false` would turn a silence into a clearance.
//!
//! ## Vulns become children, hostnames do not
//!
//! A CVE reported against a host is a fact about that host, and `entity-cve` is built — so each
//! becomes a [`crate::types::OzType::Cve`] child the analyst can fire on, capped at
//! [`MAX_VULN_CHILDREN`].
//!
//! Hostnames deliberately stay rows. Reverse DNS and certificate names are not ownership:
//! measured, `1.1.1.1` answers with `ci.com` and `chef.payomatic.com` alongside
//! `one.one.one.one`, and `8.8.8.8` answers with `abcd.dev.vpn.sse.cisco.com`. Anyone may point
//! a name they control at an address they do not. Seeding those as `Domain` children would grow
//! the tree with strangers' DNS records and present them as the subject's infrastructure —
//! the same trap `domain::certspotter` filters SAN entries for, in the opposite direction.

use crate::fetch::{OzBody, OzFetchOptions, OzOutcome};
use crate::layer_plan::FLAG_ANONYMIZER;
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{MAX_VULN_CHILDREN, OzRow, OzType};

const INTERNETDB_BASE: &str = "https://internetdb.shodan.io/";

/// Shodan tags that mean "traffic from here is not from whoever is behind it". `tor` was
/// observed directly on a live exit relay; `vpn` and `proxy` are from Shodan's published tag
/// vocabulary and have **not** been observed by this project — which is why they only ever add
/// a flag and never remove one.
const ANONYMIZER_TAGS: &[&str] = &["tor", "vpn", "proxy"];

fn body_to_json(body: &OzBody) -> Result<serde_json::Value, String> {
    match body {
        OzBody::Json(json) => Ok(json.clone()),
        OzBody::Text(text) => serde_json::from_str(text)
            .map_err(|e| format!("InternetDB body was not parseable JSON: {e}")),
        other => Err(format!(
            "InternetDB response was neither JSON nor text: {other:?}"
        )),
    }
}

/// What one InternetDB lookup reported.
#[derive(Debug, Clone, PartialEq, Default)]
struct ExposureResult {
    ports: Vec<u16>,
    anonymizer: bool,
    vulns: Vec<String>,
    rows: Vec<OzRow>,
}

impl ExposureResult {
    fn is_empty(&self) -> bool {
        self.ports.is_empty() && !self.anonymizer && self.vulns.is_empty() && self.rows.is_empty()
    }
}

/// Every non-empty string in `key`'s array, deduplicated and sorted. Sorted because an unstable
/// order would make a routine refresh report a change every single time it runs.
fn string_list(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> Vec<String> {
    let Some(array) = obj.get(key).and_then(serde_json::Value::as_array) else {
        return Vec::new();
    };
    let mut values: Vec<String> = array
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    values.sort_unstable();
    values.dedup();
    values
}

/// Parses an InternetDB response. `Err` only for a body that is not an object. Pure and tested.
fn parse_exposure(json: &serde_json::Value) -> Result<ExposureResult, String> {
    let obj = json
        .as_object()
        .ok_or_else(|| "InternetDB response was not a JSON object".to_string())?;

    let mut ports: Vec<u16> = obj
        .get("ports")
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(serde_json::Value::as_u64)
                .filter_map(|p| u16::try_from(p).ok())
                .collect()
        })
        .unwrap_or_default();
    ports.sort_unstable();
    ports.dedup();

    let hostnames = string_list(obj, "hostnames");
    let cpes = string_list(obj, "cpes");
    let tags = string_list(obj, "tags");
    let vulns = string_list(obj, "vulns");

    let anonymizer = tags
        .iter()
        .any(|t| ANONYMIZER_TAGS.contains(&t.to_ascii_lowercase().as_str()));

    let mut rows = Vec::new();
    for tag in &tags {
        rows.push(OzRow {
            label: "Tag".into(),
            value: tag.clone(),
            ..Default::default()
        });
    }
    for hostname in &hostnames {
        rows.push(OzRow {
            label: "Hostname".into(),
            // Stated on the row itself, because the panel is where the mistake gets made: a
            // list of hostnames under an IP reads as "these belong to it" unless told otherwise.
            value: format!("{hostname} (resolves here — not necessarily operated by this host)"),
            ..Default::default()
        });
    }
    for cpe in &cpes {
        rows.push(OzRow {
            label: "Software".into(),
            value: cpe.clone(),
            ..Default::default()
        });
    }

    Ok(ExposureResult {
        ports,
        anonymizer,
        vulns,
        rows,
    })
}

fn exposure_to_yield(result: &ExposureResult) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if !result.ports.is_empty() {
        // `OpenPort`'s `transport`/`service`/`product` stay absent: InternetDB returns bare
        // integers, and inventing `tcp` for every one of them would be a guess rendered as a
        // measurement. Shodan's paid tier is where those come from.
        let ports: Vec<serde_json::Value> = result
            .ports
            .iter()
            .map(|p| serde_json::json!({ "port": p }))
            .collect();
        patch.insert("ports".to_string(), serde_json::Value::Array(ports));
    }
    if result.anonymizer {
        patch.insert("anonymizer".to_string(), serde_json::json!(true));
    }

    let children = result
        .vulns
        .iter()
        .take(MAX_VULN_CHILDREN)
        .map(|cve| ChildSeed {
            oz_type: OzType::Cve,
            value: cve.clone(),
            note: Some("reported against this host by Shodan InternetDB".to_string()),
        })
        .collect();

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows: result.rows.clone(),
        // Only ever `true`. See the module doc: a missing tag is a silence, not a clearance,
        // and a `false` here would let `reputation_flagged()` read one as the other.
        flags: if result.anonymizer {
            vec![(FLAG_ANONYMIZER, true)]
        } else {
            Vec::new()
        },
        children,
        ..Default::default()
    }
}

/// Looks `ip` up against Shodan's InternetDB.
pub async fn run_internetdb(ip: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{INTERNETDB_BASE}{}", urlencoding::encode(ip));
    let outcome = ctx
        .fetch("ip-internetdb", ip, &url, OzFetchOptions::default())
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // Measured: an address Shodan has never seen answers 404. That is absence, not failure —
    // "this host has never been scanned" is a finding about the host.
    if let OzOutcome::HttpError { status: 404, .. } = outcome {
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
        unreachable!("every non-Ok, non-Cancelled OzOutcome was handled above");
    };
    let json = match body_to_json(&resp.body) {
        Ok(json) => json,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    match parse_exposure(&json) {
        Ok(result) if result.is_empty() => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(result) => {
            let count = (result.ports.len() + result.vulns.len() + result.rows.len()) as u32;
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count },
                Some(exposure_to_yield(&result)),
            )
        }
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `scanme.nmap.org`, transcribed from a live call on 2026-08-23 and trimmed to four
    /// vulns. Nmap operates this host expressly to be scanned.
    fn scanme() -> serde_json::Value {
        serde_json::json!({
            "cpes": ["cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/a:apache:http_server:2.4.7"],
            "hostnames": ["scanme.nmap.org"],
            "ip": "45.33.32.156",
            "ports": [80, 22, 31337, 123],
            "tags": ["cloud"],
            "vulns": ["CVE-2015-3185", "CVE-2014-0226", "CVE-2020-1927", "CVE-2023-25690"]
        })
    }

    /// A Tor exit relay, transcribed from a live call on 2026-08-23.
    fn tor_exit() -> serde_json::Value {
        serde_json::json!({
            "cpes": ["cpe:/a:f5:nginx"],
            "hostnames": ["berlin01.tor-exit.artikel10.org"],
            "ip": "185.220.101.1",
            "ports": [80, 443, 9001],
            "tags": ["tor"],
            "vulns": []
        })
    }

    #[test]
    fn ports_are_sorted_and_deduplicated_so_a_refresh_sees_no_spurious_change() {
        let result = parse_exposure(&scanme()).unwrap();
        assert_eq!(result.ports, vec![22, 80, 123, 31337]);
    }

    #[test]
    fn bare_integers_become_ports_with_nothing_invented_around_them() {
        let produced = exposure_to_yield(&parse_exposure(&scanme()).unwrap());
        let ports = produced.payload_patch["ports"].as_array().unwrap();
        assert_eq!(ports[0], serde_json::json!({ "port": 22 }));
        // `tcp` would be a guess. InternetDB does not say.
        assert!(ports[0].get("transport").is_none());
        assert!(ports[0].get("service").is_none());
    }

    #[test]
    fn reputation_fields_are_never_written_because_this_source_has_none() {
        // The trap: `abuseScore: 0` renders through `signal.rs` as *confirmed clean*, which
        // is a verdict nothing here obtained.
        let produced = exposure_to_yield(&parse_exposure(&scanme()).unwrap());
        let obj = produced.payload_patch.as_object().unwrap();
        assert!(!obj.contains_key("abuseScore"));
        assert!(!obj.contains_key("classification"));
    }

    #[test]
    fn a_tor_tag_sets_the_anonymizer_flag_in_the_payload_and_the_accumulator() {
        let produced = exposure_to_yield(&parse_exposure(&tor_exit()).unwrap());
        assert_eq!(produced.payload_patch["anonymizer"], true);
        assert_eq!(produced.flags, vec![(FLAG_ANONYMIZER, true)]);
    }

    #[test]
    fn an_untagged_address_is_left_silent_rather_than_cleared() {
        // `anonymizer: false` would turn "Shodan has not tagged this" into "this is not a
        // proxy", and `reputation_flagged()` would then be reading a clearance nobody issued.
        let json = serde_json::json!({ "ip": "1.2.3.4", "ports": [443], "tags": [] });
        let produced = exposure_to_yield(&parse_exposure(&json).unwrap());
        assert!(produced.payload_patch.get("anonymizer").is_none());
        assert!(produced.flags.is_empty());
    }

    #[test]
    fn vulns_become_cve_children_and_hostnames_stay_rows() {
        let produced = exposure_to_yield(&parse_exposure(&scanme()).unwrap());
        assert_eq!(produced.children.len(), 4);
        assert!(produced.children.iter().all(|c| c.oz_type == OzType::Cve));
        assert!(produced.children.iter().any(|c| c.value == "CVE-2015-3185"));
        // The trap: anyone may point a name they control at an address they do not.
        assert!(
            produced
                .children
                .iter()
                .all(|c| c.oz_type != OzType::Domain),
            "a hostname resolving to an IP is not the IP's infrastructure"
        );
        let hostname = produced
            .rows
            .iter()
            .find(|r| r.label == "Hostname")
            .unwrap();
        assert!(
            hostname
                .value
                .contains("not necessarily operated by this host")
        );
    }

    #[test]
    fn the_child_list_is_capped() {
        let vulns: Vec<String> = (0..MAX_VULN_CHILDREN + 15)
            .map(|i| format!("CVE-2020-{:05}", i))
            .collect();
        let json = serde_json::json!({ "ip": "1.2.3.4", "vulns": vulns });
        let produced = exposure_to_yield(&parse_exposure(&json).unwrap());
        assert_eq!(produced.children.len(), MAX_VULN_CHILDREN);
    }

    #[test]
    fn a_response_with_nothing_in_it_reads_as_empty_rather_than_as_a_finding() {
        let json = serde_json::json!({ "ip": "1.2.3.4", "ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": [] });
        assert!(parse_exposure(&json).unwrap().is_empty());
    }

    #[test]
    fn a_body_that_is_not_an_object_is_a_parse_error() {
        assert!(parse_exposure(&serde_json::json!([1, 2, 3])).is_err());
    }
}
