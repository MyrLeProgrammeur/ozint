//! `ip-peeringdb` — the network record an address's operator publishes about itself.
//!
//! **The first tool in this crate that runs on a sibling's output rather than on the node's
//! own value.** Its lookup key is an AS number, which an IP node does not carry; `ip-ipinfo`
//! learns it in the layer's first wave and publishes it as
//! [`crate::layer_plan::INPUT_ASN`]. See `layer_plan::Handoff` for the mechanism and for why
//! it is a per-phase snapshot rather than a live read.
//!
//! `GET https://www.peeringdb.com/api/net?asn={n}` — measured 2026-08-23, keyless:
//! - `AS15169` → HTTP `200`, `{"data": [ {…one net record…} ], "meta": {}}`
//! - `AS3215`, `AS213230` (a large incumbent and a small European AS) → `200`, likewise
//! - `AS64512` (a private-use ASN, and any AS with no PeeringDB record) → HTTP **`404`**
//!
//! This category was graded "yes-with-free-key" up front. Measured, this endpoint needs none —
//! the fifth time such a grading has turned out wrong once actually called. A key exists and
//! raises the quota; it does not gate access.
//!
//! ## The quota is the real constraint, and it is severe
//!
//! Measured by direct burst on 2026-08-23: **two anonymous calls succeed, the third and every
//! call for the next ~60 seconds answer `429`.** Probed at 10-second intervals, `200` did not
//! return until roughly a minute after the burst. So the scheduler registers this as one call
//! per minute (`registry::rate_limits_for`), deliberately below the two the burst allowed:
//! the burst is a bucket, not a rate, and spending it means the next analyst waits.
//!
//! One call per layer, with a 24-hour cache TTL, keeps a normal session comfortably inside
//! that. A second IP layer fired within the same minute waits on the scheduler and, past
//! `SCHEDULER_MAX_WAIT`, is reported `RateLimitedDropped` — visibly, as a tool that was held
//! back, never as a network with nothing to show.
//!
//! ## Absence here is a finding about the network
//!
//! A `404`, or a `200` with an empty `data` array, means this AS has no PeeringDB record.
//! That is [`ToolOutcome::OkEmpty`] and it says something real: PeeringDB is where networks
//! that peer publish their peering policy, so an AS absent from it is one that does not
//! interconnect publicly — typical of an end-user network, a hosting reseller inside someone
//! else's AS, or a purely transit-buying enterprise. It is not "we failed to look".
//!
//! ## Field ownership
//!
//! **It writes no payload key at all.** [`crate::types::IpPayload`] has no field for a peering
//! posture, and inventing one to be filled by a single source would put a second writer next
//! to `ip-ipinfo`'s `isp` under the shallow last-writer-wins merge this module's siblings
//! already document. Its whole contribution is rows — one detail section owned by this tool —
//! plus the operator's own website as a `Domain` child, and (see below) the published points of
//! contact as `Email`/`Phone` children.
//!
//! ## Contact children
//!
//! `poc_set` entries were, until now, joined into a single `" · ")`-separated row and nothing
//! else — the parsed `email`/`phone` fields existed for one call and were then discarded. They
//! are structured data the moment PeeringDB returns them; throwing that away on the way to the
//! screen means a later pass that wants them back has to re-parse the rendered string instead
//! of reading the response. [`build_contact_children`] reads the same already-parsed `email`/
//! `phone` fields the display row uses and turns each into its own child, capped at
//! [`MAX_CONTACTS`] (same pattern as `dom-certspotter`'s `MAX_SUBDOMAIN_CHILDREN`: a network
//! the size of Google's carries dozens of `poc_set` entries, and spawning a child per one would
//! flood the graph far past what a peering contact list is worth pivoting on). The existing
//! per-contact row is unchanged — this is additive, not a redesign of the display.

use crate::fetch::{OzBody, OzFetchOptions, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::{DispatchOutcome, ToolCtx};
use crate::types::{OzRow, OzType};

const PEERINGDB_NET: &str = "https://www.peeringdb.com/api/net?asn=";

/// The most `poc_set` contacts turned into `Email`/`Phone` children per lookup. See the module
/// doc's "Contact children" — a large network's contact list is not something worth pivoting on
/// in full, and this caps the graph fan-out the same way `dom-certspotter` caps subdomains.
const MAX_CONTACTS: usize = 5;

fn body_to_json(body: &OzBody) -> Result<serde_json::Value, String> {
    match body {
        OzBody::Json(json) => Ok(json.clone()),
        OzBody::Text(text) => serde_json::from_str(text)
            .map_err(|e| format!("PeeringDB body was not parseable JSON: {e}")),
        other => Err(format!(
            "PeeringDB response was neither JSON nor text: {other:?}"
        )),
    }
}

/// Strips the `AS` prefix the hand-off carries and validates the rest is a bare AS number.
///
/// `None` rather than a best effort: the value reaches here from another tool's parse, and an
/// unrecognised shape must become a visible `ParseError` rather than a request built around
/// whatever text happened to arrive.
fn asn_digits(asn: &str) -> Option<&str> {
    let digits = asn
        .trim()
        .strip_prefix("AS")
        .or_else(|| asn.trim().strip_prefix("as"))?;
    (!digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())).then_some(digits)
}

/// The plain fields worth showing, in the order a peering posture reads: who the network is,
/// then how it interconnects, then how much of it there is.
const NET_ROWS: &[(&str, &str)] = &[
    ("name", "Network"),
    ("aka", "Also known as"),
    ("info_type", "Network type"),
    ("info_scope", "Scope"),
    ("info_ratio", "Traffic ratio"),
    ("policy_general", "Peering policy"),
    ("irr_as_set", "IRR AS-SET"),
];

#[derive(Debug, Clone, PartialEq, Default)]
struct NetResult {
    rows: Vec<OzRow>,
    /// The operator's own website, as a domain pivot. Taken from the record, never derived
    /// from the network name.
    website_host: Option<String>,
    /// `poc_set` emails and phones, in the order encountered, before the [`MAX_CONTACTS`] cap —
    /// see [`build_contact_children`].
    contacts: Vec<ContactChild>,
    /// Set when more contacts carried an email or phone than [`MAX_CONTACTS`] kept — same
    /// two-cause convention as `dom-certspotter`'s `truncated`, except this tool has no
    /// payload field to carry it, so [`net_to_yield`] renders it as an extra row instead.
    contacts_truncated: bool,
}

/// One `poc_set` contact detail worth pivoting on, carrying enough to build both the
/// `ChildSeed` and its note.
#[derive(Debug, Clone, PartialEq)]
struct ContactChild {
    oz_type: OzType,
    value: String,
    role: Option<String>,
}

impl NetResult {
    fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.website_host.is_none()
    }
}

/// The registrable host of a URL the record carries. `None` for anything that is not an
/// `http(s)` URL with a dotted host — a `Domain` child built from junk is worse than no child.
fn website_host(url: &str) -> Option<String> {
    let rest = url
        .trim()
        .strip_prefix("https://")
        .or_else(|| url.trim().strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next()?.split('@').next_back()?;
    let host = host
        .split(':')
        .next()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (host.contains('.')
        && !host.starts_with('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    .then_some(host)
}

/// Parses one PeeringDB `net` response. `Err` only for a body that is not the documented
/// envelope; an empty `data` array is a successful parse of an absent record.
fn parse_net(json: &serde_json::Value, asn: &str) -> Result<NetResult, String> {
    let data = json
        .get("data")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "PeeringDB response had no `data` array".to_string())?;
    let Some(net) = data.first().and_then(serde_json::Value::as_object) else {
        return Ok(NetResult::default());
    };

    let text = |key: &str| -> Option<String> {
        net.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    let mut rows = Vec::new();
    for (key, label) in NET_ROWS {
        if let Some(value) = text(key) {
            rows.push(OzRow {
                label: (*label).into(),
                value,
                ..Default::default()
            });
        }
    }

    // Counts, which are the one thing here that quantifies reach. Rendered only when present
    // and non-zero: a `0` from an absent field and a genuine "peers at no exchanges" are
    // different claims, and this endpoint does not distinguish them.
    for (key, label, one, many) in [
        ("ix_count", "Internet exchanges", "exchange", "exchanges"),
        ("fac_count", "Facilities", "facility", "facilities"),
    ] {
        if let Some(n) = net
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .filter(|n| *n > 0)
        {
            let unit = if n == 1 { one } else { many };
            rows.push(OzRow {
                label: label.into(),
                value: format!("{n} {unit}"),
                ..Default::default()
            });
        }
    }

    if let Some(website) = text("website") {
        rows.push(OzRow {
            label: "Website".into(),
            value: website.clone(),
            href: Some(website),
            ..Default::default()
        });
    }

    // Named points of contact the network published for itself — the highest-value field this
    // tool used to drop entirely. `poc_set` entries carry `role`, `visible`, `name`, `phone`,
    // `email`, `url`; the API already scopes the response to what the requester may see, so
    // every entry present here is rendered rather than re-filtered on `visible`.
    let mut contacts = Vec::new();
    if let Some(pocs) = net.get("poc_set").and_then(serde_json::Value::as_array) {
        for poc in pocs {
            let Some(poc) = poc.as_object() else { continue };
            let poc_text = |key: &str| -> Option<String> {
                poc.get(key)
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            };
            let role = poc_text("role");
            let name = poc_text("name");
            let email = poc_text("email");
            let phone = poc_text("phone");
            let url = poc_text("url");

            let mut parts = Vec::new();
            if let Some(name) = &name {
                parts.push(name.clone());
            }
            if let Some(email) = &email {
                parts.push(email.clone());
            }
            if let Some(phone) = &phone {
                parts.push(phone.clone());
            }
            if parts.is_empty() && url.is_none() {
                continue;
            }
            let label = match &role {
                Some(role) => format!("Contact ({role})"),
                None => "Contact".to_string(),
            };
            rows.push(OzRow {
                label,
                value: if parts.is_empty() {
                    url.clone().unwrap_or_default()
                } else {
                    parts.join(" · ")
                },
                href: url,
                ..Default::default()
            });

            // The same already-parsed `email`/`phone` the row above just joined into a string —
            // read here from the original fields, not by re-splitting `parts`, so nothing here
            // depends on the display's separator or ordering.
            if let Some(email) = &email {
                contacts.push(ContactChild {
                    oz_type: OzType::Email,
                    value: email.clone(),
                    role: role.clone(),
                });
            }
            if let Some(phone) = &phone {
                contacts.push(ContactChild {
                    oz_type: OzType::Phone,
                    value: phone.clone(),
                    role: role.clone(),
                });
            }
        }
    }
    let contacts_truncated = contacts.len() > MAX_CONTACTS;
    contacts.truncate(MAX_CONTACTS);

    // The record itself, so the analyst can read the operator's peering contacts and notes by
    // hand rather than have this tool relay a free-text block.
    if let Some(id) = net.get("id").and_then(serde_json::Value::as_u64) {
        rows.push(OzRow {
            label: "PeeringDB record".into(),
            value: format!("AS{asn} · net/{id}"),
            href: Some(format!("https://www.peeringdb.com/net/{id}")),
            ..Default::default()
        });
    }

    Ok(NetResult {
        rows,
        website_host: text("website").as_deref().and_then(website_host),
        contacts,
        contacts_truncated,
    })
}

fn net_to_yield(result: &NetResult) -> ToolYield {
    let mut rows = result.rows.clone();
    if result.contacts_truncated {
        // No payload field exists to carry a `truncated` flag (see the module doc's "Field
        // ownership"), so the signal is a row instead — same "only when true" convention as
        // `dom-certspotter`'s `subdomainsTruncated`, just rendered rather than merged.
        rows.push(OzRow {
            label: "Contacts".into(),
            value: format!("only the first {MAX_CONTACTS} contacts became pivotable nodes"),
            ..Default::default()
        });
    }

    let mut children: Vec<ChildSeed> = result
        .website_host
        .iter()
        .map(|host| ChildSeed {
            oz_type: OzType::Domain,
            value: host.clone(),
            note: Some("the network operator's own website, from its PeeringDB record".into()),
        })
        .collect();
    children.extend(result.contacts.iter().map(|contact| ChildSeed {
        oz_type: contact.oz_type,
        value: contact.value.clone(),
        note: Some(match &contact.role {
            Some(role) => format!("published PeeringDB point of contact ({role})"),
            None => "published PeeringDB point of contact".to_string(),
        }),
    }));

    ToolYield {
        // No payload key — see the module doc's "Field ownership".
        payload_patch: serde_json::json!({}),
        rows,
        children,
        ..Default::default()
    }
}

pub async fn run_peeringdb(_ip: &str, ctx: &ToolCtx) -> DispatchOutcome {
    // The node's own value is deliberately unused: this tool runs on the AS an earlier wave
    // published. `runtime::fire_layer` refuses to dispatch it when that key is unreadable, so
    // reaching this branch means it was called outside a layer — reported as the typed skip,
    // never as an empty result.
    let Some(asn) = ctx.input(crate::layer_plan::INPUT_ASN) else {
        return ToolCtx::missing_input(crate::layer_plan::INPUT_ASN);
    };
    let Some(digits) = asn_digits(asn) else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: format!("`{asn}` was handed over as an AS number but is not one"),
            },
            None,
        );
    };

    let url = format!("{PEERINGDB_NET}{digits}");
    // Keyed on the ASN, not on the IP: every address inside one network resolves to the same
    // record, and caching per-address would re-spend a one-per-minute quota on an answer we
    // already hold.
    let outcome = ctx
        .fetch("ip-peeringdb", digits, &url, OzFetchOptions::default())
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // Measured: an AS with no record answers 404. See the module doc — absence here is a
    // statement about how the network interconnects, not a failed lookup.
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

    match parse_net(&json, digits) {
        Ok(result) if result.is_empty() => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(result) => {
            let count = (result.rows.len() + usize::from(result.website_host.is_some())) as u32;
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count },
                Some(net_to_yield(&result)),
            )
        }
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transcribed by hand from a live `GET /api/net?asn=15169` on 2026-08-23, trimmed to the
    /// fields this module reads plus one it deliberately ignores (`notes`). `poc_set` is a
    /// documented PeeringDB shape (`role`, `visible`, `name`, `phone`, `email`, `url`), added
    /// by hand to the transcription since the live fetch did not return contacts for this AS.
    fn google_net() -> serde_json::Value {
        serde_json::json!({
            "data": [{
                "id": 433,
                "name": "Google LLC",
                "aka": "Google, YouTube (for Google Fiber see AS16591 record)",
                "website": "https://about.google/intl/en/",
                "asn": 15169,
                "irr_as_set": "RADB::AS-GOOGLE",
                "info_type": "Content",
                "info_ratio": "Mostly Outbound",
                "info_scope": "Global",
                "ix_count": 176,
                "fac_count": 137,
                "notes": "Peering Operational Issues: Contact noc@google.com 24x7",
                "policy_general": "Selective",
                "status": "ok",
                "poc_set": [
                    {
                        "id": 1001,
                        "role": "NOC",
                        "visible": "Public",
                        "name": "Google NOC",
                        "phone": "+1-650-253-0000",
                        "email": "noc@google.com",
                        "url": ""
                    },
                    {
                        "id": 1002,
                        "role": "Policy",
                        "visible": "Users",
                        "name": "",
                        "phone": "",
                        "email": "peering@google.com",
                        "url": "https://peering.google.com/"
                    }
                ]
            }],
            "meta": {}
        })
    }

    #[test]
    fn a_real_record_becomes_rows_and_a_domain_child() {
        let result = parse_net(&google_net(), "15169").unwrap();
        let value = |label: &str| {
            result
                .rows
                .iter()
                .find(|r| r.label == label)
                .map(|r| r.value.clone())
        };
        assert_eq!(value("Network").as_deref(), Some("Google LLC"));
        assert_eq!(value("Network type").as_deref(), Some("Content"));
        assert_eq!(value("Peering policy").as_deref(), Some("Selective"));
        assert_eq!(
            value("Internet exchanges").as_deref(),
            Some("176 exchanges")
        );
        assert_eq!(value("Facilities").as_deref(), Some("137 facilities"));
        assert_eq!(result.website_host.as_deref(), Some("about.google"));

        let produced = net_to_yield(&result);
        assert_eq!(
            produced.payload_patch,
            serde_json::json!({}),
            "PeeringDB owns no IpPayload field — a second writer next to ip-ipinfo's `isp` \
             would be silently resolved by the shallow merge"
        );
        let domain_children: Vec<_> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Domain)
            .collect();
        assert_eq!(domain_children.len(), 1);
        assert_eq!(domain_children[0].value, "about.google");
    }

    #[test]
    fn poc_set_email_and_phone_become_typed_children_from_the_parsed_fields_not_the_row() {
        // Google's poc_set has two contacts: NOC (email + phone) and Policy (email only, the
        // blank phone field must not become a child). Read from the original `email`/`phone`
        // fields, so this must hold independent of how the row above joins them.
        let result = parse_net(&google_net(), "15169").unwrap();
        let produced = net_to_yield(&result);

        let emails: Vec<&str> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Email)
            .map(|c| c.value.as_str())
            .collect();
        assert_eq!(emails, vec!["noc@google.com", "peering@google.com"]);

        let phones: Vec<&str> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Phone)
            .map(|c| c.value.as_str())
            .collect();
        assert_eq!(
            phones,
            vec!["+1-650-253-0000"],
            "the blank phone on the Policy contact must not become a child"
        );

        for child in produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Email || c.oz_type == OzType::Phone)
        {
            assert!(
                child.note.as_deref().unwrap().contains("point of contact"),
                "{:?}",
                child
            );
        }
    }

    #[test]
    fn more_than_max_contacts_is_capped_and_signalled_by_a_row() {
        // No payload field exists to carry a truncated flag (this tool writes none — see the
        // module doc), so the signal has to be a row instead of a patch key.
        let pocs: Vec<serde_json::Value> = (0..(MAX_CONTACTS + 3))
            .map(|i| {
                serde_json::json!({
                    "role": "NOC",
                    "name": format!("Contact {i}"),
                    "email": format!("contact{i}@example.com"),
                    "phone": "",
                    "url": ""
                })
            })
            .collect();
        let json = serde_json::json!({
            "data": [{ "id": 1, "name": "Big Network", "poc_set": pocs }]
        });
        let result = parse_net(&json, "1").unwrap();
        assert_eq!(result.contacts.len(), MAX_CONTACTS);
        assert!(result.contacts_truncated);

        let produced = net_to_yield(&result);
        let email_children = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Email)
            .count();
        assert_eq!(email_children, MAX_CONTACTS);
        assert!(
            produced.rows.iter().any(|r| r.label == "Contacts"),
            "a truncation row must be present"
        );
        // The per-contact rows themselves are unaffected by the cap — only the children are
        // capped, since rows were never the thing generating fan-out.
        assert_eq!(
            result
                .rows
                .iter()
                .filter(|r| r.label.starts_with("Contact ("))
                .count(),
            MAX_CONTACTS + 3
        );
    }

    #[test]
    fn at_or_under_max_contacts_no_truncation_row_appears() {
        let result = parse_net(&google_net(), "15169").unwrap();
        assert!(!result.contacts_truncated);
        let produced = net_to_yield(&result);
        assert!(!produced.rows.iter().any(|r| r.label == "Contacts"));
    }

    #[test]
    fn the_record_links_back_to_peeringdb() {
        let result = parse_net(&google_net(), "15169").unwrap();
        let row = result
            .rows
            .iter()
            .find(|r| r.label == "PeeringDB record")
            .expect("a record row");
        assert_eq!(
            row.href.as_deref(),
            Some("https://www.peeringdb.com/net/433")
        );
    }

    #[test]
    fn poc_set_becomes_named_contact_rows() {
        let result = parse_net(&google_net(), "15169").unwrap();
        let noc = result
            .rows
            .iter()
            .find(|r| r.label == "Contact (NOC)")
            .expect("a NOC contact row");
        assert_eq!(noc.value, "Google NOC · noc@google.com · +1-650-253-0000");
        assert_eq!(noc.href, None, "no url on this contact");

        let policy = result
            .rows
            .iter()
            .find(|r| r.label == "Contact (Policy)")
            .expect("a Policy contact row");
        assert_eq!(policy.value, "peering@google.com");
        assert_eq!(policy.href.as_deref(), Some("https://peering.google.com/"));
    }

    #[test]
    fn an_empty_data_array_is_an_absent_record_not_a_parse_failure() {
        let json = serde_json::json!({ "data": [], "meta": {} });
        let result = parse_net(&json, "64512").unwrap();
        assert!(
            result.is_empty(),
            "an AS with no record must produce nothing to show"
        );
    }

    #[test]
    fn a_body_without_the_envelope_is_a_parse_error() {
        assert!(parse_net(&serde_json::json!({ "detail": "throttled" }), "15169").is_err());
    }

    #[test]
    fn zero_counts_are_omitted_rather_than_rendered_as_zero() {
        // The endpoint does not distinguish "peers nowhere" from "did not say", so a `0` here
        // would be a claim about interconnection that nothing measured.
        let json = serde_json::json!({
            "data": [{ "id": 1, "name": "Someone", "ix_count": 0, "fac_count": 0 }]
        });
        let result = parse_net(&json, "1").unwrap();
        assert!(
            !result
                .rows
                .iter()
                .any(|r| r.label == "Internet exchanges" || r.label == "Facilities"),
            "a zero count must not be rendered"
        );
    }

    #[test]
    fn asn_digits_accepts_the_handed_over_shape_and_nothing_else() {
        assert_eq!(asn_digits("AS15169"), Some("15169"));
        assert_eq!(asn_digits(" as15169 "), Some("15169"));
        assert_eq!(
            asn_digits("15169"),
            None,
            "the hand-off carries the AS prefix"
        );
        assert_eq!(asn_digits("AS15169; DROP"), None);
        assert_eq!(asn_digits("AS"), None);
        assert_eq!(asn_digits("Google LLC"), None);
    }

    #[test]
    fn website_host_refuses_anything_that_is_not_a_url_with_a_dotted_host() {
        assert_eq!(
            website_host("https://about.google/intl/en/").as_deref(),
            Some("about.google")
        );
        assert_eq!(
            website_host("http://WWW.Example.COM:8080/x").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(website_host("about.google"), None, "no scheme, no child");
        assert_eq!(
            website_host("https://localhost/"),
            None,
            "no dot, not a domain"
        );
        assert_eq!(website_host("ftp://example.com/"), None);
        assert_eq!(website_host(""), None);
    }

    #[tokio::test]
    async fn without_the_hand_off_it_skips_typed_rather_than_reporting_nothing_found() {
        // The property the whole mechanism exists for. Called with no ASN published, this must
        // be distinguishable from "PeeringDB holds no record for this network" — those are
        // opposite findings and `OkEmpty` would conflate them.
        match run_peeringdb("8.8.8.8", &ToolCtx::default()).await {
            DispatchOutcome::Ran(ToolOutcome::SkippedMissingInput { input, .. }, produced) => {
                assert_eq!(input, crate::layer_plan::INPUT_ASN);
                assert!(produced.is_none());
            }
            other => panic!("a missing hand-off must be a typed skip, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_handed_over_value_that_is_not_an_asn_is_a_visible_parse_error() {
        let mut handoff = crate::layer_plan::Handoff::new();
        handoff.insert(
            crate::layer_plan::INPUT_ASN.to_string(),
            "Google LLC".to_string(),
        );
        let ctx = ToolCtx {
            handoff,
            ..Default::default()
        };
        match run_peeringdb("8.8.8.8", &ctx).await {
            DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None) => {
                assert!(message.contains("Google LLC"));
            }
            other => panic!("expected a ParseError, got {other:?}"),
        }
    }
}
