//! `phone-local-normalize` — `entity-phone`'s local, keyless first tool.
//!
//! `crate::normalize::normalize(OzType::Phone, …)` already runs `phonenumber::parse` at
//! classification time, to produce the E.164 dedup key and an international display string —
//! but it only asks "does this parse, and is it valid", and neither answer survives onto the
//! node's own [`crate::types::PhonePayload`]. This tool asks the same library one step
//! further: `PhoneNumber::country()` for the region, and `PhoneNumber::number_type` for a
//! `mobile`/`fixed-line`/`voip`/… classification, both read straight out of the metadata
//! `phonenumber` already bundles. No request leaves this process, so this is `LocalOnly`, the
//! same tier `img-exif` and `geo-map-links` use for the same reason.
//!
//! **What this deliberately does not claim.** `carrier`, `fraud_score` and `subscriber_name`
//! stay `None` — those are Veriphone/IPQualityScore/Telnyx territory, none of which are wired
//! in this build, and inventing a plausible-looking value for any of them would be worse than
//! leaving the field empty. An empty field reads as *not found*, which is the honest reading
//! here: nothing beyond local metadata was consulted.

use phonenumber::Type as PhoneType;

use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

/// The `PhonePayload.lineType` string for a `phonenumber::Type`, verbatim lowercase-kebab —
/// matches the free-text convention `PhonePayload::line_type`'s own doc comment describes
/// ("mobile / fixed-line / voip / prepaid …, verbatim from the source").
fn line_type_label(t: PhoneType) -> &'static str {
    match t {
        PhoneType::FixedLine => "fixed-line",
        PhoneType::Mobile => "mobile",
        PhoneType::FixedLineOrMobile => "fixed-line-or-mobile",
        PhoneType::TollFree => "toll-free",
        PhoneType::PremiumRate => "premium-rate",
        PhoneType::SharedCost => "shared-cost",
        PhoneType::PersonalNumber => "personal-number",
        PhoneType::Voip => "voip",
        PhoneType::Pager => "pager",
        PhoneType::Uan => "uan",
        PhoneType::Emergency => "emergency",
        PhoneType::Voicemail => "voicemail",
        PhoneType::ShortCode => "short-code",
        PhoneType::StandardRate => "standard-rate",
        PhoneType::Carrier => "carrier",
        PhoneType::NoInternational => "no-international",
        PhoneType::Unknown => "unknown",
    }
}

/// Runs `phone-local-normalize` against `value` — the E.164 key
/// `normalize::normalize(OzType::Phone, …)` already produced for this node. Synchronous: the
/// `phonenumber` crate's metadata is bundled in the binary, so there is no request to await.
pub fn run_phone_local_normalize(value: &str) -> DispatchOutcome {
    let parsed = match phonenumber::parse(None, value) {
        Ok(parsed) => parsed,
        Err(e) => {
            return DispatchOutcome::Ran(
                ToolOutcome::ParseError {
                    message: format!("could not parse phone number: {e}"),
                },
                None,
            );
        }
    };

    let valid = parsed.is_valid();
    let country = parsed.country().id().map(|id| id.as_ref().to_string());
    let line_type = line_type_label(parsed.number_type(&phonenumber::metadata::DATABASE));

    let mut rows = vec![OzRow {
        label: "Valid".to_string(),
        value: if valid {
            "yes".to_string()
        } else {
            "no".to_string()
        },
        ..Default::default()
    }];
    if let Some(country) = &country {
        rows.push(OzRow {
            label: "Country".to_string(),
            value: country.clone(),
            ..Default::default()
        });
    }
    rows.push(OzRow {
        label: "Line type".to_string(),
        value: line_type.to_string(),
        ..Default::default()
    });

    let mut patch = serde_json::Map::new();
    patch.insert("valid".to_string(), serde_json::json!(valid));
    if let Some(country) = &country {
        patch.insert("country".to_string(), serde_json::json!(country));
    }
    patch.insert("lineType".to_string(), serde_json::json!(line_type));

    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults { count: 1 },
        Some(ToolYield {
            payload_patch: serde_json::Value::Object(patch),
            rows,
            facts: Vec::new(),
            flags: Vec::new(),
            values: Vec::new(),
            children: Vec::new(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yield_of(outcome: DispatchOutcome) -> ToolYield {
        match outcome {
            DispatchOutcome::Ran(_, Some(y)) => y,
            other => panic!("expected Ran(_, Some(_)), got {other:?}"),
        }
    }

    #[test]
    fn a_valid_french_mobile_reports_valid_country_and_line_type() {
        let out = run_phone_local_normalize("+33612345678");
        let y = yield_of(out);
        assert_eq!(y.payload_patch["valid"], serde_json::json!(true));
        assert_eq!(y.payload_patch["country"], serde_json::json!("FR"));
        assert_eq!(y.payload_patch["lineType"], serde_json::json!("mobile"));
        assert!(
            y.rows
                .iter()
                .any(|r| r.label == "Valid" && r.value == "yes")
        );
        assert!(
            y.rows
                .iter()
                .any(|r| r.label == "Country" && r.value == "FR")
        );
    }

    #[test]
    fn an_unparseable_string_is_a_parse_error_not_a_silent_empty_result() {
        let out = run_phone_local_normalize("not a phone number");
        match out {
            DispatchOutcome::Ran(ToolOutcome::ParseError { .. }, None) => {}
            other => panic!("expected a ParseError with no yield, got {other:?}"),
        }
    }

    #[test]
    fn a_short_code_never_claims_carrier_fraud_score_or_subscriber_name() {
        // The whole point of this tool being local-only: it must never populate the fields
        // only a keyed provider can honestly fill.
        let out = run_phone_local_normalize("+33612345678");
        let y = yield_of(out);
        assert!(y.payload_patch.get("carrier").is_none());
        assert!(y.payload_patch.get("fraudScore").is_none());
        assert!(y.payload_patch.get("subscriberName").is_none());
    }
}
