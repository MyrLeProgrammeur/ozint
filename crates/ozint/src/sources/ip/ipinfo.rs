//! `ip-ipinfo` — IPinfo's free lookup. Keyless. Owns the `country`, `city`, `lat`, `lon`,
//! `asn` and `isp` fields of [`crate::types::IpPayload`].
//!
//! `GET https://ipinfo.io/{ip}/json` — measured 2026-08-23, HTTP `200` with `ip`, `hostname`,
//! `city`, `region`, `country` (a two-letter code), `loc` (**one string**, `"lat,lon"`), `org`
//! (**one string**, `"AS15169 Google LLC"`), `postal`, `timezone`, `anycast`, plus a
//! `readme: "https://ipinfo.io/missingauth"` field it adds to un-keyed responses. None of the
//! fields this module reads is degraded without a token; the token raises the monthly request
//! allowance.
//!
//! ## Two fields that arrive glued together
//!
//! `loc` and `org` are each one string carrying two facts, and both are split here rather than
//! stored as-is. A `loc` that failed to split would leave `lat`/`lon` unset, which reads
//! identically to an address IPinfo has no location for — so [`split_loc`] is `Option`-typed
//! and its failure is simply the absence of a location, never a `0.0, 0.0` default. Null Island
//! is a real coordinate and must not become the resting place of every parse failure.
//!
//! ## A bogon is a finding, not an absence
//!
//! Asked about a reserved or unrouted address (`203.0.113.9`), IPinfo answers HTTP `200` with
//! `{"ip": …, "bogon": true}` and nothing else. That is a positive fact — the address is not
//! routable on the public internet, so no geolocation exists to fail to find — and it is
//! reported as a result carrying that row, not as `OkEmpty`. `OkEmpty` would say "we looked and
//! there was nothing", which is exactly the wrong reading.
//!
//! ## The location links out and nothing more
//!
//! An IP geolocation is city-level at best and frequently just the registrant's postal address.
//! The hard rule applies unchanged: the coordinate becomes external map links via
//! [`crate::geo_links::map_links`] and never a pin on a map or globe of this engine's own.

use crate::fetch::{OzBody, OzFetchOptions, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const IPINFO_BASE: &str = "https://ipinfo.io/";

fn body_to_json(body: &OzBody) -> Result<serde_json::Value, String> {
    match body {
        OzBody::Json(json) => Ok(json.clone()),
        OzBody::Text(text) => serde_json::from_str(text)
            .map_err(|e| format!("IPinfo body was not parseable JSON: {e}")),
        other => Err(format!(
            "IPinfo response was neither JSON nor text: {other:?}"
        )),
    }
}

/// Splits IPinfo's `loc` (`"37.4056,-122.0775"`) into a coordinate pair. `None` for anything
/// that is not two in-range decimals — see the module doc on why this is never defaulted.
fn split_loc(loc: &str) -> Option<(f64, f64)> {
    let (lat, lon) = loc.split_once(',')?;
    let lat: f64 = lat.trim().parse().ok()?;
    let lon: f64 = lon.trim().parse().ok()?;
    (-90.0..=90.0).contains(&lat).then_some(())?;
    (-180.0..=180.0).contains(&lon).then_some(())?;
    Some((lat, lon))
}

/// Splits IPinfo's `org` (`"AS15169 Google LLC"`) into the AS number and the operator name.
/// An `org` with no leading `AS…` token is all operator and no ASN — returned as
/// `(None, Some(whole))` rather than having a fake ASN carved out of it.
fn split_org(org: &str) -> (Option<String>, Option<String>) {
    let org = org.trim();
    if org.is_empty() {
        return (None, None);
    }
    let Some((first, rest)) = org.split_once(char::is_whitespace) else {
        // A lone token: an ASN on its own, or an operator name with no ASN.
        return if is_asn(org) {
            (Some(org.to_string()), None)
        } else {
            (None, Some(org.to_string()))
        };
    };
    if is_asn(first) {
        let rest = rest.trim();
        (
            Some(first.to_string()),
            (!rest.is_empty()).then(|| rest.to_string()),
        )
    } else {
        (None, Some(org.to_string()))
    }
}

/// `AS` followed by at least one digit and nothing else.
fn is_asn(token: &str) -> bool {
    token
        .strip_prefix("AS")
        .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
}

/// The plain string fields worth showing, in the order a location reads. `hostname` leads
/// because reverse DNS is the one field here that is about the host rather than about where a
/// registry says its address block lives.
const INFO_ROWS: &[(&str, &str)] = &[
    ("hostname", "Hostname"),
    ("city", "City"),
    ("region", "Region"),
    ("country", "Country"),
    ("postal", "Postal code"),
    ("timezone", "Timezone"),
];

/// What one IPinfo lookup resolved to.
#[derive(Debug, Clone, PartialEq, Default)]
struct InfoResult {
    country: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    asn: Option<String>,
    isp: Option<String>,
    rows: Vec<OzRow>,
}

/// Parses an IPinfo response. `Err` only for a body that is not an object. Pure and tested.
fn parse_info(json: &serde_json::Value) -> Result<InfoResult, String> {
    let obj = json
        .as_object()
        .ok_or_else(|| "IPinfo response was not a JSON object".to_string())?;

    // A reserved or unrouted address. Everything else is absent by construction, so it is
    // reported on its own rather than alongside empty location fields. See the module doc.
    if obj.get("bogon").and_then(serde_json::Value::as_bool) == Some(true) {
        return Ok(InfoResult {
            rows: vec![OzRow {
                label: "Bogon".into(),
                value: "reserved or unrouted — not routable on the public internet".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
    }

    let text = |key: &str| -> Option<String> {
        obj.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    let (lat, lon) = match obj
        .get("loc")
        .and_then(serde_json::Value::as_str)
        .and_then(split_loc)
    {
        Some((lat, lon)) => (Some(lat), Some(lon)),
        None => (None, None),
    };
    let (asn, isp) = match text("org") {
        Some(org) => split_org(&org),
        None => (None, None),
    };

    let mut rows = Vec::new();
    for (key, label) in INFO_ROWS {
        if let Some(value) = text(key) {
            rows.push(OzRow {
                label: (*label).into(),
                value,
                ..Default::default()
            });
        }
    }
    if let Some(asn) = &asn {
        rows.push(OzRow {
            label: "ASN".into(),
            value: asn.clone(),
            // The public registry record for the AS, which is where an analyst goes next.
            href: Some(format!(
                "https://bgp.tools/as/{}",
                asn.trim_start_matches("AS")
            )),
            ..Default::default()
        });
    }
    if let Some(isp) = &isp {
        rows.push(OzRow {
            label: "Operator".into(),
            value: isp.clone(),
            ..Default::default()
        });
    }
    if obj.get("anycast").and_then(serde_json::Value::as_bool) == Some(true) {
        // Worth its own row: an anycast address is announced from many physical places at
        // once, so the city below it is one of several and not *the* location.
        rows.push(OzRow {
            label: "Anycast".into(),
            value: "announced from multiple locations — the geolocation is one of several".into(),
            ..Default::default()
        });
    }
    if let (Some(lat), Some(lon)) = (lat, lon) {
        rows.extend(crate::geo_links::map_links(lat, lon));
    }

    Ok(InfoResult {
        country: text("country"),
        city: text("city"),
        lat,
        lon,
        asn,
        isp,
        rows,
    })
}

fn info_to_yield(result: &InfoResult) -> ToolYield {
    let mut patch = serde_json::Map::new();
    let mut put = |key: &str, value: Option<serde_json::Value>| {
        if let Some(value) = value {
            patch.insert(key.to_string(), value);
        }
    };
    put(
        "country",
        result.country.clone().map(serde_json::Value::from),
    );
    put("city", result.city.clone().map(serde_json::Value::from));
    put("lat", result.lat.map(serde_json::Value::from));
    put("lon", result.lon.map(serde_json::Value::from));
    put("asn", result.asn.clone().map(serde_json::Value::from));
    put("isp", result.isp.clone().map(serde_json::Value::from));

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows: result.rows.clone(),
        // The sibling hand-off. Published here as well as into the payload, and the
        // duplication is the point: `ip-peeringdb` runs on the AS number, and reading it back
        // out of the accumulated payload patch would make it depend on which tool in the
        // earlier wave happened to write last. This channel is attributed and refuses to be
        // arbitrated — see `layer_plan::Handoff`.
        values: result
            .asn
            .clone()
            .map(|asn| vec![(crate::layer_plan::INPUT_ASN, asn)])
            .unwrap_or_default(),
        ..Default::default()
    }
}

/// Looks `ip` up against IPinfo.
pub async fn run_ipinfo(ip: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{IPINFO_BASE}{}/json", urlencoding::encode(ip));
    let outcome = ctx
        .fetch("ip-ipinfo", ip, &url, OzFetchOptions::default())
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
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

    match parse_info(&json) {
        Ok(result) if result.rows.is_empty() && result.country.is_none() => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(result) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults {
                count: result.rows.len() as u32,
            },
            Some(info_to_yield(&result)),
        ),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The measured response for `8.8.8.8`, transcribed from a live call on 2026-08-23.
    fn google_dns() -> serde_json::Value {
        serde_json::json!({
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "org": "AS15169 Google LLC",
            "postal": "94043",
            "timezone": "America/Los_Angeles",
            "readme": "https://ipinfo.io/missingauth",
            "anycast": true
        })
    }

    #[test]
    fn the_glued_loc_and_org_fields_are_split_into_their_own_payload_keys() {
        let result = parse_info(&google_dns()).unwrap();
        assert_eq!(result.lat, Some(37.4056));
        assert_eq!(result.lon, Some(-122.0775));
        assert_eq!(result.asn.as_deref(), Some("AS15169"));
        assert_eq!(result.isp.as_deref(), Some("Google LLC"));
    }

    #[test]
    fn only_the_six_owned_keys_are_written() {
        // Field ownership: `ip-internetdb` owns `ports` and `anonymizer`, and the shallow
        // merge means an extra key here would silently clobber one of them.
        let produced = info_to_yield(&parse_info(&google_dns()).unwrap());
        let mut keys: Vec<&str> = produced
            .payload_patch
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["asn", "city", "country", "isp", "lat", "lon"]);
    }

    #[test]
    fn an_anycast_address_says_so_next_to_its_city() {
        let result = parse_info(&google_dns()).unwrap();
        assert!(
            result.rows.iter().any(|r| r.label == "Anycast"),
            "without this row a city reads as the location of a host announced from dozens"
        );
    }

    #[test]
    fn the_coordinate_becomes_external_links_and_never_a_pin() {
        let result = parse_info(&google_dns()).unwrap();
        let links: Vec<&OzRow> = result.rows.iter().filter(|r| r.href.is_some()).collect();
        assert!(links.iter().any(|r| r.label == "Google Maps"));
        assert!(links.iter().any(|r| r.label == "OpenStreetMap"));
        assert!(links.iter().any(|r| r.label == "Apple Maps"));
    }

    #[test]
    fn a_bogon_is_reported_as_a_finding_and_not_as_an_empty_lookup() {
        let result =
            parse_info(&serde_json::json!({ "ip": "203.0.113.9", "bogon": true })).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].label, "Bogon");
        assert_eq!(result.country, None, "a bogon has no country to report");
        assert_eq!(result.lat, None);
    }

    #[test]
    fn a_malformed_loc_leaves_the_location_absent_rather_than_at_null_island() {
        // The bug this forbids: `unwrap_or(0.0)` puts every parse failure in the Gulf of
        // Guinea, and a map link to Null Island is indistinguishable from a real finding.
        for loc in ["", "not-a-pair", "37.4056", "999,999", "37.4056,abc"] {
            let json = serde_json::json!({ "ip": "1.2.3.4", "loc": loc });
            let result = parse_info(&json).unwrap();
            assert_eq!(
                result.lat, None,
                "loc {loc:?} must not produce a coordinate"
            );
            assert_eq!(result.lon, None);
        }
        // …while a genuine zero survives, because Null Island is also a real place.
        assert_eq!(split_loc("0,0"), Some((0.0, 0.0)));
    }

    #[test]
    fn an_org_with_no_as_number_is_all_operator_and_never_a_carved_up_name() {
        assert_eq!(
            split_org("Some Hosting Ltd"),
            (None, Some("Some Hosting Ltd".to_string()))
        );
        assert_eq!(split_org("AS15169"), (Some("AS15169".to_string()), None));
        assert_eq!(
            split_org("ASN Consulting Group"),
            (None, Some("ASN Consulting Group".to_string()))
        );
        assert_eq!(split_org("  "), (None, None));
        assert_eq!(
            split_org("AS64512 Example Net AB"),
            (
                Some("AS64512".to_string()),
                Some("Example Net AB".to_string())
            )
        );
    }

    #[test]
    fn the_asn_row_links_to_the_public_registry_record() {
        let result = parse_info(&google_dns()).unwrap();
        let asn = result.rows.iter().find(|r| r.label == "ASN").unwrap();
        assert_eq!(asn.href.as_deref(), Some("https://bgp.tools/as/15169"));
    }

    #[test]
    fn a_body_that_is_not_an_object_is_a_parse_error() {
        assert!(parse_info(&serde_json::json!("nope")).is_err());
    }
}
