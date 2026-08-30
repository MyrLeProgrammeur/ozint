//! `dom-rdap` — registration data over RDAP, the protocol that replaced WHOIS.
//!
//! Keyless. `GET https://rdap.org/domain/{domain}` — verified live 2026-08-21: HTTP 200 for
//! `anthropic.com`, HTTP **404** for a domain that is not registered.
//!
//! Owns exactly two fields of [`crate::types::DomainPayload`]: `registrar` and `createdAt`. It
//! also surfaces the abuse contact's email and phone as rows plus [`OzType::Email`]/
//! [`OzType::Phone`] children — see "The abuse contact" below — neither of which has a
//! `DomainPayload` field of its own.
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
//!
//! ## The abuse contact
//!
//! The registrar's nested `entities` carry `email` and `tel` jCard entries alongside the blank
//! `fn` above — this is the whole reason RDAP replaced WHOIS's free-text abuse block with a
//! structured one. [`abuse_contacts`] walks every nested entity (not just the one with
//! `roles: ["abuse"]` — a registrar can publish more than one contact, and a role that doesn't
//! say "abuse" is still a real reachable address) and collects every `email`/`tel` value found,
//! deduplicated case-insensitively for email and byte-for-byte for `tel` URIs. `tel` values
//! arrive as `tel:+1.2086851750`; the `tel:` scheme prefix is stripped since [`OzType::Phone`]
//! expects a bare number, same convention as every other phone-emitting tool in this crate.

use std::collections::HashSet;

use chrono::{DateTime, Utc};

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

const RDAP_BOOTSTRAP_BASE: &str = "https://rdap.org/domain/";

/// The fields this tool reads out of an RDAP domain record.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RdapRecord {
    pub registrar: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    /// Every abuse-and-otherwise contact email found in `entities`, at any depth. See
    /// [`abuse_contacts`].
    pub emails: Vec<Contact>,
    /// Every abuse-and-otherwise contact phone number found in `entities`, at any depth. See
    /// [`abuse_contacts`].
    pub phones: Vec<Contact>,
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

/// Every value of a given jCard property name (`"email"`, `"tel"`, …), in document order.
/// Shares `jcard_fn`'s traversal and its defensive indexing — a malformed entry is skipped, not
/// a reason to fail the whole record — but keeps *all* matches rather than the first, since a
/// vCard can carry more than one email or phone.
fn jcard_values(vcard_array: &serde_json::Value, name: &str) -> Vec<String> {
    let Some(entries) = vcard_array
        .as_array()
        .and_then(|a| a.get(1))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let entry = entry.as_array()?;
            if entry.first().and_then(|v| v.as_str()) != Some(name) {
                return None;
            }
            let value = entry.get(3).and_then(|v| v.as_str())?.trim();
            (!value.is_empty()).then(|| value.to_string())
        })
        .collect()
}

/// Strips a `tel:` or `mailto:` URI scheme, if present. jCard's `type` element (`"uri"` vs.
/// `"text"`) decides whether the value carries one — measured on the abuse contact's `tel`
/// (`"tel:+1.2086851750"`) — but email has not been observed with a `mailto:` prefix, so this
/// strips defensively rather than trusting the sibling `type` element.
fn strip_uri_scheme(value: &str) -> &str {
    value
        .strip_prefix("tel:")
        .or_else(|| value.strip_prefix("mailto:"))
        .unwrap_or(value)
}

/// Every abuse-and-otherwise contact detail found anywhere in `entities`, recursing into each
/// entity's own nested `entities` — the abuse contact in the module doc's fixture lives one
/// level down from the registrar, and nothing says a deeper nesting can't exist. Not scoped to
/// `roles: ["abuse"]`: a registrar can publish more than one contact, and any published address
/// is a real, reachable one worth surfacing. Deduplicated case-insensitively for email and
/// byte-for-byte for phone (already E.164-shaped at the source, so a case fold would be
/// meaningless there).
/// A published contact, and whether it is the subject's to pursue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub value: String,
    /// False when the contact hangs under a `registrar` entity — see [`contact_details`].
    pub pivotable: bool,
}

/// Emails and phones published by a record, each tagged with whose they are.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContactDetails {
    pub emails: Vec<Contact>,
    pub phones: Vec<Contact>,
}

/// True if this entity declares the `registrar` role.
fn is_registrar(entity: &serde_json::Value) -> bool {
    entity
        .get("roles")
        .and_then(|v| v.as_array())
        .is_some_and(|roles| roles.iter().any(|r| r.as_str() == Some("registrar")))
}

/// Published contact details, and **whose they are**.
///
/// The second half of that sentence is the whole difficulty, and getting it wrong was this
/// function's first bug. Measured against live RDAP on 2026-08-30: `kernel.org` publishes
/// `abuse@support.gandi.net`, `github.com` publishes `abusecomplaints@markmonitor.com`. Both sit
/// on an abuse entity **nested under a `registrar` entity**, and neither belongs to the domain's
/// owner — they are the registrar's own complaints desk, shared by every domain that registrar
/// serves.
///
/// So they are a fact worth showing and a terrible thing to pivot on: firing a layer on
/// `abuse@support.gandi.net` investigates Gandi, and the same address would attach itself to
/// thousands of unrelated investigations as if it were a shared identity. That is the same error
/// `sources/ip/internetdb.rs` refuses when it declines to attribute a stranger's reverse-DNS
/// records to the subject.
///
/// Hence the split: everything published becomes a **row**, and only contacts that are *not*
/// under a registrar entity become **children**. After GDPR most gTLD records carry nothing but
/// the registrar's desk, so the child list is usually empty — which is the honest answer, not a
/// gap. A registrant or technical contact that does survive redaction is genuinely the subject's
/// and is worth pursuing.
fn contact_details(json: &serde_json::Value) -> ContactDetails {
    /// `pivotable` is false once any ancestor is the registrar: a contact inherits the identity
    /// of the entity it hangs under, not of the record it was found in.
    fn walk<'a>(
        entities: &'a [serde_json::Value],
        under_registrar: bool,
        out: &mut Vec<(&'a serde_json::Value, bool)>,
    ) {
        for entity in entities {
            let registrar_scope = under_registrar || is_registrar(entity);
            out.push((entity, !registrar_scope));
            if let Some(nested) = entity.get("entities").and_then(|v| v.as_array()) {
                walk(nested, registrar_scope, out);
            }
        }
    }

    let mut all_entities = Vec::new();
    if let Some(top) = json.get("entities").and_then(|v| v.as_array()) {
        walk(top, false, &mut all_entities);
    }

    let mut emails: Vec<Contact> = Vec::new();
    let mut seen_emails = HashSet::new();
    let mut phones: Vec<Contact> = Vec::new();
    let mut seen_phones = HashSet::new();

    for (entity, pivotable) in all_entities {
        let Some(vcard) = entity.get("vcardArray") else {
            continue;
        };
        for raw in jcard_values(vcard, "email") {
            let value = strip_uri_scheme(&raw).to_string();
            if seen_emails.insert(value.to_ascii_lowercase()) {
                emails.push(Contact { value, pivotable });
            }
        }
        for raw in jcard_values(vcard, "tel") {
            let value = strip_uri_scheme(&raw).to_string();
            if seen_phones.insert(value.clone()) {
                phones.push(Contact { value, pivotable });
            }
        }
    }

    ContactDetails { emails, phones }
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

    let contacts = contact_details(json);
    Ok(RdapRecord {
        registrar: registrar_name(json),
        created_at: registration_date(json),
        emails: contacts.emails,
        phones: contacts.phones,
    })
}

/// Turns a record into the payload patch. Writes only `registrar` and `createdAt` — see the
/// module doc on why `ns` is left to `dom-dns` — plus rows and children for the contact
/// details, which carry no payload field of their own.
pub fn rdap_record_to_yield(record: &RdapRecord) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if let Some(registrar) = &record.registrar {
        patch.insert("registrar".into(), serde_json::json!(registrar));
    }
    if let Some(created) = record.created_at {
        patch.insert("createdAt".into(), serde_json::json!(created));
    }
    // Registering an entity itself is deliberately not done here: a registrar is a company, not
    // an entity this crate can look up — there is no `Company` type, and seeding
    // `MarkMonitor Inc.` as a `Name` node would send a corporation to five people-search
    // aggregators.
    //
    // Contacts are shown in full and pivoted on selectively. Every published address and number
    // becomes a row, because they are the reason RDAP exists and an analyst should see them.
    // Only the ones that are not the registrar's become children — see [`contact_details`] for
    // the measurement behind that, and for why the child list is empty on most gTLD records.
    // The row says which it is, so an absent child never reads as a missing finding.
    let mut rows = Vec::new();
    let mut children = Vec::new();
    for email in &record.emails {
        rows.push(OzRow {
            label: if email.pivotable {
                "Contact email".into()
            } else {
                "Registrar abuse email".into()
            },
            value: email.value.clone(),
            ..Default::default()
        });
        if email.pivotable {
            children.push(ChildSeed {
                oz_type: OzType::Email,
                value: email.value.clone(),
                note: Some("published contact address on the domain's RDAP record".into()),
            });
        }
    }
    for phone in &record.phones {
        rows.push(OzRow {
            label: if phone.pivotable {
                "Contact phone".into()
            } else {
                "Registrar abuse phone".into()
            },
            value: phone.value.clone(),
            ..Default::default()
        });
        if phone.pivotable {
            children.push(ChildSeed {
                oz_type: OzType::Phone,
                value: phone.value.clone(),
                note: Some("published contact number on the domain's RDAP record".into()),
            });
        }
    }

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        rows,
        children,
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
        Ok(record)
            if record.registrar.is_none()
                && record.created_at.is_none()
                && record.emails.is_empty()
                && record.phones.is_empty() =>
        {
            // A real domain object that carried none of the facts this tool reads. Honest
            // emptiness, not an error.
            DispatchOutcome::Ran(
                ToolOutcome::OkEmpty,
                Some(ToolYield {
                    payload_patch: serde_json::json!({}),
                    ..Default::default()
                }),
            )
        }
        Ok(record) => {
            // 1 for the registrar/date payload patch (even when both are absent but a contact
            // was found, this still counts as "found the record itself"), plus one per contact
            // detail surfaced.
            let count = 1 + record.emails.len() as u32 + record.phones.len() as u32;
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count },
                Some(rdap_record_to_yield(&record)),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real `anthropic.com` response, trimmed to what this tool reads — including the
    /// nested abuse contact whose `fn` is the empty string, which is the thing that makes a
    /// naive "first `fn` anywhere" search wrong. The `email` entry is added by hand to the
    /// transcription (the live fetch this was measured from predates the contact-extraction
    /// code and this test suite only recorded `tel`) — same convention as `peeringdb`'s
    /// hand-added `poc_set`; MarkMonitor's abuse address is publicly documented as
    /// `abusecomplaints@markmonitor.com`.
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
                        ["tel", { "type": "voice" }, "uri", "tel:+1.2086851750"],
                        ["email", {}, "text", "abusecomplaints@markmonitor.com"]
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

    // ── contacts ─────────────────────────────────────────────────────────

    #[test]
    fn jcard_values_finds_every_match_not_just_the_first() {
        let vcard = serde_json::json!([
            "vcard",
            [
                ["email", {}, "text", "first@example.com"],
                ["fn", {}, "text", "irrelevant"],
                ["email", {}, "text", "second@example.com"],
            ]
        ]);
        assert_eq!(
            jcard_values(&vcard, "email"),
            vec!["first@example.com", "second@example.com"]
        );
        assert_eq!(jcard_values(&vcard, "tel"), Vec::<String>::new());
    }

    #[test]
    fn strip_uri_scheme_removes_tel_and_mailto_but_leaves_a_bare_value_alone() {
        assert_eq!(strip_uri_scheme("tel:+1.2086851750"), "+1.2086851750");
        assert_eq!(
            strip_uri_scheme("mailto:abuse@example.com"),
            "abuse@example.com"
        );
        assert_eq!(strip_uri_scheme("abuse@example.com"), "abuse@example.com");
    }

    #[test]
    fn contact_details_recurses_into_nested_entities_and_strips_uri_schemes() {
        let found = contact_details(&anthropic_rdap());
        // The registrar entity itself carries no email/tel — only its nested abuse entity does.
        assert_eq!(found.emails[0].value, "abusecomplaints@markmonitor.com");
        assert_eq!(found.phones[0].value, "+1.2086851750");
    }

    #[test]
    fn a_registrars_own_abuse_desk_is_never_pivotable() {
        // The property this whole split exists for. Measured against live RDAP on 2026-08-30:
        // both kernel.org and github.com publish only their registrar's shared complaints desk,
        // nested under a `registrar` entity. Seeding that as an Email node would send the
        // analyst to investigate Gandi or MarkMonitor, and would attach one address to every
        // unrelated investigation of a domain that registrar happens to serve.
        let found = contact_details(&anthropic_rdap());
        assert!(
            found.emails.iter().all(|c| !c.pivotable),
            "a contact under a registrar entity must not be offered as a node"
        );
        assert!(found.phones.iter().all(|c| !c.pivotable));
    }

    #[test]
    fn a_contact_outside_the_registrar_subtree_is_pivotable() {
        // The case that survives GDPR redaction: a registrant or technical contact published on
        // the record itself. That one genuinely is the subject's, and is worth pursuing.
        let json = serde_json::json!({
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["email", {}, "text", "owner@example.com"]]]
            }]
        });
        let found = contact_details(&json);
        assert_eq!(found.emails.len(), 1);
        assert!(found.emails[0].pivotable);
    }

    #[test]
    fn abuse_contacts_dedupes_email_case_insensitively_and_phone_exactly() {
        let json = serde_json::json!({
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["email", {}, "text", "Abuse@Example.com"],
                        ["tel", {}, "uri", "tel:+15551234567"]
                    ]]
                },
                {
                    "roles": ["technical"],
                    "vcardArray": ["vcard", [
                        ["email", {}, "text", "abuse@example.com"],
                        ["tel", {}, "uri", "tel:+15551234567"]
                    ]]
                }
            ]
        });
        let found = contact_details(&json);
        assert_eq!(
            found
                .emails
                .iter()
                .map(|c| c.value.as_str())
                .collect::<Vec<_>>(),
            vec!["Abuse@Example.com"],
            "the first-seen casing is kept, the repeat is dropped"
        );
        assert_eq!(
            found
                .phones
                .iter()
                .map(|c| c.value.as_str())
                .collect::<Vec<_>>(),
            vec!["+15551234567"]
        );
    }

    #[test]
    fn a_record_with_no_contact_details_yields_no_emails_or_phones() {
        let json = serde_json::json!({
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Some Registrar"]]]
            }]
        });
        assert_eq!(contact_details(&json), ContactDetails::default());
        assert_eq!(
            contact_details(&serde_json::json!({})),
            ContactDetails::default()
        );
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
        assert_eq!(record.emails[0].value, "abusecomplaints@markmonitor.com");
        assert_eq!(record.phones[0].value, "+1.2086851750");
    }

    // ── yield ────────────────────────────────────────────────────────────

    #[test]
    fn the_yield_writes_only_the_two_payload_fields_this_tool_owns() {
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
        // This record publishes only the registrar's own abuse desk, so it yields the contact
        // as rows and offers no children. An empty child list here is the correct answer, not a
        // missing finding — see `contact_details`.
        assert!(
            yielded
                .rows
                .iter()
                .any(|r| r.label == "Registrar abuse email"),
            "the abuse contact must still be visible as a row"
        );
        assert!(
            yielded.children.is_empty(),
            "a registrar's shared abuse desk must not be offered as a node"
        );
    }

    #[test]
    fn a_pivotable_contact_becomes_both_a_row_and_a_typed_child() {
        // The mirror of `the_yield_writes_only_the_two_payload_fields_this_tool_owns`: when the
        // contact is genuinely the subject's, it is offered as a node as well as shown.
        let json = serde_json::json!({
            "objectClassName": "domain",
            "ldhName": "example.com",
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [
                    ["email", {}, "text", "owner@example.com"],
                    ["tel", {}, "uri", "tel:+15550001111"]
                ]]
            }]
        });
        let record = parse_rdap_domain(&json).expect("parses");
        let yielded = rdap_record_to_yield(&record);

        assert!(
            yielded
                .rows
                .iter()
                .any(|r| r.label == "Contact email" && r.value == "owner@example.com"),
            "a pivotable contact is labelled as the contact, not as the registrar's desk"
        );

        let email_child = yielded
            .children
            .iter()
            .find(|c| c.oz_type == OzType::Email)
            .expect("an email child");
        assert_eq!(email_child.value, "owner@example.com");

        let phone_child = yielded
            .children
            .iter()
            .find(|c| c.oz_type == OzType::Phone)
            .expect("a phone child");
        assert_eq!(phone_child.value, "+15550001111");

        assert_eq!(yielded.children.len(), 2, "no other children are produced");
    }

    #[test]
    fn a_record_with_no_contacts_yields_no_contact_rows_or_children() {
        let record = RdapRecord {
            registrar: Some("Some Registrar".to_string()),
            created_at: None,
            emails: Vec::new(),
            phones: Vec::new(),
        };
        let yielded = rdap_record_to_yield(&record);
        assert!(yielded.rows.is_empty());
        assert!(yielded.children.is_empty());
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
