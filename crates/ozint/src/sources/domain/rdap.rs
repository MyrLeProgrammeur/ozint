//! `dom-rdap` — registration data over RDAP, the protocol that replaced WHOIS.
//!
//! Keyless. `GET https://rdap.org/domain/{domain}` — verified live 2026-08-21: HTTP 200 for
//! `anthropic.com`, HTTP **404** for a domain that is not registered.
//!
//! Owns exactly two fields of [`crate::types::DomainPayload`]: `registrar` and `createdAt`.
//!
//! ## Why not the nameservers, which are right there in the response
//!
//! The RDAP record carries `nameservers[].ldhName`, and `DomainPayload` has an `ns` field. It
//! is deliberately not written here: `dom-dns` owns `ns`, from a live NS query.
//! `runtime::merge_patch` is a shallow last-writer-wins merge, so two tools writing `ns` would
//! silently overwrite each other, and there would be no way to see that they disagreed.
//!
//! Choosing which one owns it is not arbitrary. The registry's delegation record and the zone's
//! live answer are different facts that usually — not always — agree, and the divergence is
//! itself the interesting case: a domain mid-migration serves new nameservers before the
//! registry reflects them. An analyst asking "where does this domain resolve" wants the live
//! answer, so DNS owns `ns`. (When both tools matter enough to show together, they need two
//! fields and a rendered comparison, not one field and a race — a conflict belongs in the
//! subject file as two visible values, never blended.)
//!
//! ## rdap.org is a bootstrap redirector, and that is why the SSRF guard had to be fixed first
//!
//! `https://rdap.org/domain/anthropic.com` answers **302** to
//! `https://rdap.verisign.com/com/v1/domain/anthropic.com` — rdap.org holds no data, it routes
//! to the authoritative server for each TLD from IANA's bootstrap registry. This is the first
//! tool in the crate that depends on following a redirect on purpose, and it is what surfaced
//! the fact that `ozint_core::net::safe_fetch_url` only ever screened the *first* hop while
//! the shared client followed the rest unscreened. That is fixed in `ozint_core::http`; this
//! tool works because a public-to-public hop is still allowed.
//!
//! ## jCard, which is the fiddly part
//!
//! The registrar's name is not a string field. RDAP carries contact data as **jCard**
//! (RFC 7095) — a two-element array `["vcard", [ [name, params, type, value], … ]]`, where the
//! display name is the entry whose first element is `"fn"`. Measured for `anthropic.com`:
//! `["vcard",[["version",{},"text","4.0"],["fn",{},"text","MarkMonitor Inc."]]]`. Every level
//! of that is positional, so [`jcard_fn`] indexes defensively rather than assuming any of it.
//!
//! One more shape note: the top-level `entities` array holds the registrar, and the registrar
//! entity has its own **nested** `entities` (the abuse contact) with its own `fn` — which in
//! the measured response is the **empty string**. Reaching for "the first `fn` anywhere in the
//! document" therefore finds a plausible-looking blank. The registrar is selected by its
//! `roles` containing `"registrar"`, at the top level only.

use chrono::{DateTime, Utc};

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;

const RDAP_BOOTSTRAP_BASE: &str = "https://rdap.org/domain/";

/// The fields this tool reads out of an RDAP domain record.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RdapRecord {
    pub registrar: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

/// Pulls the display name out of a jCard array. See the module doc for the shape.
///
/// Returns `None` for an absent or **empty** `fn` — an empty display name is not a registrar
/// name, and storing `""` would render as a blank field that looks like a successful lookup.
pub fn jcard_fn(vcard_array: &serde_json::Value) -> Option<String> {
    // `["vcard", [ … ]]` — the entries are the second element, never the first.
    let entries = vcard_array.as_array()?.get(1)?.as_array()?;
    for entry in entries {
        let entry = entry.as_array()?;
        if entry.first().and_then(|v| v.as_str()) != Some("fn") {
            continue;
        }
        // `[name, params, type, value]` — the value is at index 3.
        let value = entry.get(3).and_then(|v| v.as_str())?.trim();
        if value.is_empty() {
            return None;
        }
        return Some(value.to_string());
    }
    None
}

/// The registrar's name, selected by role at the **top level** of `entities`.
///
/// Not "the first `fn` in the document": the registrar entity nests an abuse contact with its
/// own `fn`, measured as the empty string for `anthropic.com`. A search that recursed would
/// find a blank and report it as the registrar.
pub fn registrar_name(json: &serde_json::Value) -> Option<String> {
    let entities = json.get("entities")?.as_array()?;
    entities
        .iter()
        .find(|e| {
            e.get("roles")
                .and_then(|r| r.as_array())
                .is_some_and(|roles| roles.iter().any(|r| r.as_str() == Some("registrar")))
        })
        .and_then(|e| e.get("vcardArray"))
        .and_then(jcard_fn)
}

/// The registration instant from `events[]`.
///
/// RDAP event dates are RFC 3339 with an explicit offset (measured:
/// `"2001-10-02T18:10:32Z"`), unlike NVD's timezone-less instants — so this parses strictly
/// and does not assume a zone.
///
/// `"registration"` only. The same array carries `expiration`, `last changed` and
/// `last update of RDAP database`, and the last of those is *today's* date on every response —
/// taking `events[0]` or the newest event would silently populate `createdAt` with the moment
/// we made the request, which reads as a brand-new domain for every lookup.
pub fn registration_date(json: &serde_json::Value) -> Option<DateTime<Utc>> {
    let events = json.get("events")?.as_array()?;
    events
        .iter()
        .find(|e| e.get("eventAction").and_then(|a| a.as_str()) == Some("registration"))
        .and_then(|e| e.get("eventDate").and_then(|d| d.as_str()))
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

/// Parses an RDAP domain response.
///
/// `Err` only when the body is not an RDAP domain object at all — a shape change must stay
/// loud rather than degrade into "this domain has no registrar".
pub fn parse_rdap_domain(json: &serde_json::Value) -> Result<RdapRecord, String> {
    if !json.is_object() {
        return Err("RDAP response was not a JSON object".to_string());
    }
    // Every RDAP domain response carries this discriminator. Without it we are looking at an
    // error document or a redirect landing page, not a record.
    let class = json.get("objectClassName").and_then(|v| v.as_str());
    if class != Some("domain") {
        return Err(format!(
            "RDAP response is not a domain object (objectClassName = {class:?})"
        ));
    }

    Ok(RdapRecord {
        registrar: registrar_name(json),
        created_at: registration_date(json),
    })
}

/// Turns a record into the payload patch. Writes only `registrar` and `createdAt` — see the
/// module doc on why `ns` is left to `dom-dns`.
pub fn rdap_record_to_yield(record: &RdapRecord) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if let Some(registrar) = &record.registrar {
        patch.insert("registrar".into(), serde_json::json!(registrar));
    }
    if let Some(created) = record.created_at {
        patch.insert("createdAt".into(), serde_json::json!(created));
    }
    // No children. A registrar is a company, not an entity this crate can look up: there is no
    // `Company` type, and seeding `MarkMonitor Inc.` as a `Name` node would send a corporation
    // to five people-search aggregators.
    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        ..Default::default()
    }
}

pub async fn run_rdap(domain: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{RDAP_BOOTSTRAP_BASE}{}", urlencoding::encode(domain));
    // The domain being looked up — RDAP's whole record is keyed on it.
    let outcome = ctx
        .fetch(
            "dom-rdap",
            domain,
            &url,
            fetch::OzFetchOptions {
                headers: vec![("Accept".to_string(), "application/rdap+json".to_string())],
                ..Default::default()
            },
        )
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // Measured: an unregistered domain answers 404. That is a positive finding — the domain is
    // not registered — not a broken lookup, and folding it into `HttpError` would let
    // `settle_kind` drag the layer to `Degraded` for a perfectly good answer.
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

    // `application/rdap+json` contains "json", so `dispatch_content_type` routes it correctly;
    // the text fallback is defensive, and cheap insurance after `poc_github` cost a real bug to
    // a host that declared its JSON as `text/plain`.
    let json = match &resp.body {
        OzBody::Json(json) => json.clone(),
        OzBody::Text(text) => match serde_json::from_str(text) {
            Ok(value) => value,
            Err(e) => {
                return DispatchOutcome::Ran(
                    ToolOutcome::ParseError {
                        message: format!("RDAP body was not parseable JSON: {e}"),
                    },
                    None,
                );
            }
        },
        other => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("RDAP response was neither JSON nor text: {other:?}"),
                },
                None,
            );
        }
    };

    match parse_rdap_domain(&json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(record) if record.registrar.is_none() && record.created_at.is_none() => {
            // A real domain object that carried neither fact. Honest emptiness, not an error.
            DispatchOutcome::Ran(
                ToolOutcome::OkEmpty,
                Some(ToolYield {
                    payload_patch: serde_json::json!({}),
                    ..Default::default()
                }),
            )
        }
        Ok(record) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(rdap_record_to_yield(&record)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real `anthropic.com` response, trimmed to what this tool reads — including the
    /// nested abuse contact whose `fn` is the empty string, which is the thing that makes a
    /// naive "first `fn` anywhere" search wrong.
    fn anthropic_rdap() -> serde_json::Value {
        serde_json::json!({
            "objectClassName": "domain",
            "ldhName": "ANTHROPIC.COM",
            "events": [
                { "eventAction": "registration", "eventDate": "2001-10-02T18:10:32Z" },
                { "eventAction": "expiration", "eventDate": "2033-10-02T18:10:32Z" },
                { "eventAction": "last changed", "eventDate": "2023-10-09T16:06:41Z" },
                { "eventAction": "last update of RDAP database", "eventDate": "2026-08-21T15:30:17Z" }
            ],
            "nameservers": [
                { "objectClassName": "nameserver", "ldhName": "ISLA.NS.CLOUDFLARE.COM" },
                { "objectClassName": "nameserver", "ldhName": "RANDY.NS.CLOUDFLARE.COM" }
            ],
            "entities": [{
                "objectClassName": "entity",
                "handle": "292",
                "roles": ["registrar"],
                "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "MarkMonitor Inc."]
                ]],
                "entities": [{
                    "objectClassName": "entity",
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", ""],
                        ["tel", { "type": "voice" }, "uri", "tel:+1.2086851750"]
                    ]]
                }]
            }]
        })
    }

    // ── jCard ────────────────────────────────────────────────────────────

    #[test]
    fn the_registrar_name_comes_out_of_the_positional_jcard() {
        assert_eq!(
            registrar_name(&anthropic_rdap()).as_deref(),
            Some("MarkMonitor Inc.")
        );
    }

    #[test]
    fn the_nested_abuse_contacts_blank_name_is_never_mistaken_for_the_registrar() {
        // The measured abuse contact's `fn` is `""`. A search that recursed, or that took the
        // first `fn` in the document, would find a plausible-looking blank and report it.
        let json = anthropic_rdap();
        let abuse = &json["entities"][0]["entities"][0]["vcardArray"];
        assert_eq!(jcard_fn(abuse), None, "an empty `fn` is not a name");
        assert_eq!(registrar_name(&json).as_deref(), Some("MarkMonitor Inc."));
    }

    #[test]
    fn an_entity_without_the_registrar_role_is_not_used() {
        let json = serde_json::json!({
            "objectClassName": "domain",
            "entities": [
                { "roles": ["technical"],
                  "vcardArray": ["vcard", [["fn", {}, "text", "Some Tech Contact"]]] }
            ]
        });
        assert_eq!(registrar_name(&json), None);
    }

    #[test]
    fn a_malformed_jcard_yields_nothing_rather_than_panicking() {
        // Every level of jCard is positional, so each index is a chance to trip.
        for broken in [
            serde_json::json!("vcard"),
            serde_json::json!(["vcard"]),
            serde_json::json!(["vcard", "not-an-array"]),
            serde_json::json!(["vcard", [["fn", {}, "text"]]]),
            serde_json::json!(["vcard", [["fn"]]]),
            serde_json::json!(["vcard", [[]]]),
            serde_json::json!(["vcard", [["fn", {}, "text", "   "]]]),
        ] {
            assert_eq!(jcard_fn(&broken), None, "{broken:?} should yield nothing");
        }
    }

    // ── events ───────────────────────────────────────────────────────────

    #[test]
    fn only_the_registration_event_sets_created_at() {
        // The trap: `last update of RDAP database` is today's date on every single response.
        // Taking the first, the last, or the newest event would stamp `createdAt` with the
        // moment of the request — every domain would look brand new.
        let created = registration_date(&anthropic_rdap()).expect("a registration event");
        assert_eq!(created.to_rfc3339(), "2001-10-02T18:10:32+00:00");
    }

    #[test]
    fn a_record_with_no_registration_event_has_no_created_at() {
        let json = serde_json::json!({
            "objectClassName": "domain",
            "events": [{ "eventAction": "last changed", "eventDate": "2023-10-09T16:06:41Z" }]
        });
        assert_eq!(registration_date(&json), None);
        assert_eq!(registration_date(&serde_json::json!({})), None);
    }

    #[test]
    fn an_unparseable_event_date_is_dropped_not_guessed() {
        let json = serde_json::json!({
            "events": [{ "eventAction": "registration", "eventDate": "October 2001" }]
        });
        assert_eq!(registration_date(&json), None);
    }

    // ── envelope ─────────────────────────────────────────────────────────

    #[test]
    fn a_non_domain_object_is_loud() {
        // An RDAP error document or a redirect landing page must not read as "this domain has
        // no registrar and no registration date".
        let err = parse_rdap_domain(&serde_json::json!({
            "errorCode": 404, "title": "Not Found"
        }))
        .expect_err("an error document is not a record");
        assert!(err.contains("not a domain object"), "{err}");
        assert!(parse_rdap_domain(&serde_json::json!("a string")).is_err());
    }

    #[test]
    fn the_full_record_parses() {
        let record = parse_rdap_domain(&anthropic_rdap()).expect("parses");
        assert_eq!(record.registrar.as_deref(), Some("MarkMonitor Inc."));
        assert!(record.created_at.is_some());
    }

    // ── yield ────────────────────────────────────────────────────────────

    #[test]
    fn the_yield_writes_only_the_two_fields_this_tool_owns() {
        // `ns` is right there in the response and is deliberately not written — `dom-dns` owns
        // it, and a shallow last-writer-wins merge would let these two silently fight over it.
        let record = parse_rdap_domain(&anthropic_rdap()).expect("parses");
        let yielded = rdap_record_to_yield(&record);
        let obj = yielded.payload_patch.as_object().expect("object patch");

        assert_eq!(obj["registrar"], "MarkMonitor Inc.");
        assert!(obj.contains_key("createdAt"));
        assert!(!obj.contains_key("ns"), "ns belongs to dom-dns");
        assert!(!obj.contains_key("mx"), "mx belongs to dom-dns");
        assert!(
            !obj.contains_key("subdomains"),
            "subdomains belong to dom-certspotter"
        );
        assert!(
            yielded.children.is_empty(),
            "a registrar is not an entity to pivot on"
        );
    }

    #[test]
    fn the_patch_round_trips_into_a_domain_payload() {
        let record = parse_rdap_domain(&anthropic_rdap()).expect("parses");
        let mut payload = serde_json::to_value(crate::types::OzPayload::Domain(
            crate::types::DomainPayload::default(),
        ))
        .expect("serialise");
        let (serde_json::Value::Object(dst), serde_json::Value::Object(src)) =
            (&mut payload, &rdap_record_to_yield(&record).payload_patch)
        else {
            panic!("both sides must be objects")
        };
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }

        match serde_json::from_value::<crate::types::OzPayload>(payload).expect("re-typed") {
            crate::types::OzPayload::Domain(p) => {
                assert_eq!(p.registrar.as_deref(), Some("MarkMonitor Inc."));
                assert_eq!(
                    p.created_at.expect("created").to_rfc3339(),
                    "2001-10-02T18:10:32+00:00"
                );
                assert!(p.ns.is_empty(), "an untouched field keeps its default");
            }
            other => panic!("the merge changed the payload type: {other:?}"),
        }
    }
}
