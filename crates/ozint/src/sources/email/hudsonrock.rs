//! `email-hudsonrock` — HudsonRock's free, keyless infostealer-compromise lookup. Found while
//! auditing external OSINT repos for `entity-email` gaps (inside `N0rz3/Zehef`'s
//! `modules/breaches/hudsonrock.py`) — the only tool of the eight repos surveyed that added a
//! genuinely new signal class this category didn't have: not a profile (`gravatar-email`), not
//! an account-existence check (`sidecar-holehe`), but whether malware on a *victim's own
//! machine* ever captured credentials tied to this email.
//!
//! Endpoint: `GET https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email`,
//! query param `email`, header `api-key: ROCKHUDSONROCK` (a fixed, published dummy value — not
//! a real per-user credential; HudsonRock's own free-tools demo uses it verbatim, confirmed by
//! reading the source this tool was found in). No registration, no real key to hold.
//!
//! ## Verified by direct call, 2026-08-25 — both branches
//!
//! A clean email answers `200` with `stealers: []` and a fixed "not associated with a
//! computer infected by an info-stealer" message — a genuine `OkEmpty`. A compromised email
//! (`test@test.com`, a well-known canary that returns real hits) answers `200` with a non-empty
//! `stealers` array; each entry carries `date_compromised`, `computer_name`, `malware_path`,
//! `total_user_services`/`total_corporate_services` (how many other accounts on that same
//! infected machine were also captured), and `top_passwords`/`top_logins` — both already
//! **masked server-side** by HudsonRock (`"N***********7"`, `"l*************@gmail.com"`), so
//! this tool never handles or stores a raw credential.
//!
//! ## Maps onto `EmailPayload.breaches`, not a new field
//!
//! An infostealer capture is not a company data breach, but it is the same shape of fact
//! `BreachEvent` already models — a dated, named credential-exposure event — and no other
//! `entity-email` tool writes `breaches` today, so there is no collision to design around.
//! `name` carries the compromised machine's name (the closest thing to an incident identifier
//! HudsonRock provides); `data_classes` is a fixed `["Passwords", "Logins"]`, since that is
//! what an infostealer capture always means, not something the response enumerates per entry.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{BreachEvent, OzRow, OzType, SignalTone};

const HUDSONROCK_ENDPOINT: &str =
    "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=";
const API_KEY_HEADER_VALUE: &str = "ROCKHUDSONROCK";

/// One `stealers[]` entry, narrowed to the fields this tool reports. `date_compromised` is
/// kept as the raw ISO-8601 string HudsonRock sends rather than parsed to `DateTime<Utc>` here
/// — parsing happens once, in [`stealer_to_breach_event`], so a malformed date degrades to a
/// missing `breached_at` rather than rejecting the whole entry.
#[derive(Debug, Clone, PartialEq)]
pub struct StealerHit {
    pub date_compromised: Option<String>,
    pub computer_name: Option<String>,
    pub total_user_services: Option<u64>,
    pub total_corporate_services: Option<u64>,
    /// The infected machine's IP, already masked server-side by HudsonRock
    /// (`"110.38.***.**"`) same as `top_passwords`/`top_logins` — a pivot to `entity-ip`.
    pub ip: Option<String>,
    /// Filesystem path of the infostealer binary on the infected machine.
    pub malware_path: Option<String>,
}

/// Parses the endpoint's response body into its `stealers[]` list. An absent `stealers` key is
/// rejected as a shape mismatch — HudsonRock always includes it, even as `[]`, per both
/// verified branches, so a response missing it entirely is not this endpoint's documented
/// shape. Pure and tested.
pub fn parse_hudsonrock_response(json: &serde_json::Value) -> Result<Vec<StealerHit>, String> {
    let stealers = json
        .get("stealers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "HudsonRock response is missing `stealers`".to_string())?;

    Ok(stealers
        .iter()
        .map(|s| StealerHit {
            date_compromised: s
                .get("date_compromised")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            computer_name: s
                .get("computer_name")
                .and_then(|v| v.as_str())
                .filter(|s| *s != "Not Found")
                .map(str::to_string),
            total_user_services: s.get("total_user_services").and_then(|v| v.as_u64()),
            total_corporate_services: s.get("total_corporate_services").and_then(|v| v.as_u64()),
            ip: s.get("ip").and_then(|v| v.as_str()).map(str::to_string),
            malware_path: s
                .get("malware_path")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        })
        .collect())
}

fn stealer_to_breach_event(hit: &StealerHit) -> BreachEvent {
    let breached_at = hit
        .date_compromised
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    BreachEvent {
        name: hit
            .computer_name
            .clone()
            .unwrap_or_else(|| "Infostealer log".to_string()),
        breached_at,
        added_at: None,
        data_classes: vec!["Passwords".to_string(), "Logins".to_string()],
        tone: SignalTone::Risk,
        source_tool_id: "email-hudsonrock".to_string(),
    }
}

fn hudsonrock_to_yield(hits: &[StealerHit]) -> ToolYield {
    let events: Vec<BreachEvent> = hits.iter().map(stealer_to_breach_event).collect();

    let rows = hits
        .iter()
        .map(|h| {
            let mut services = String::new();
            if let Some(user) = h.total_user_services {
                services.push_str(&format!("{user} personal"));
            }
            if let Some(corp) = h.total_corporate_services.filter(|c| *c > 0) {
                if !services.is_empty() {
                    services.push_str(", ");
                }
                services.push_str(&format!("{corp} corporate"));
            }
            let mut value = if services.is_empty() {
                "credentials captured".to_string()
            } else {
                format!("{services} accounts' credentials captured")
            };
            if let Some(ip) = &h.ip {
                value.push_str(&format!(" · {ip}"));
            }
            if let Some(malware_path) = &h.malware_path {
                value.push_str(&format!(" · {malware_path}"));
            }
            OzRow {
                label: h
                    .computer_name
                    .clone()
                    .unwrap_or_else(|| "Infostealer capture".to_string()),
                value,
                ..Default::default()
            }
        })
        .collect();

    let children = hits
        .iter()
        .filter_map(|h| h.ip.clone())
        .map(|ip| ChildSeed {
            oz_type: OzType::Ip,
            value: ip,
            note: Some("the infected machine's IP, from a HudsonRock infostealer capture".into()),
        })
        .collect();

    ToolYield {
        payload_patch: serde_json::json!({ "breaches": events }),
        rows,
        facts: Vec::new(),
        flags: Vec::new(),
        values: Vec::new(),
        children,
    }
}

/// Looks `value` (an email) up against HudsonRock's infostealer-compromise index. Keyless — the
/// `api-key` header is a fixed published value, not a credential to arm.
pub async fn run_hudsonrock(value: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{HUDSONROCK_ENDPOINT}{}", urlencoding::encode(value));
    let opts = fetch::OzFetchOptions {
        headers: vec![("api-key".to_string(), API_KEY_HEADER_VALUE.to_string())],
        ..Default::default()
    };

    let outcome = ctx.fetch("email-hudsonrock", value, &url, opts).await;
    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return DispatchOutcome::Ran(failure, None);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled OzOutcome was handled above");
    };
    let OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "HudsonRock response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_hudsonrock_response(json) {
        Ok(hits) if hits.is_empty() => {
            DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default()))
        }
        Ok(hits) => {
            let count = hits.len() as u32;
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count },
                Some(hudsonrock_to_yield(&hits)),
            )
        }
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compromised_response() -> serde_json::Value {
        serde_json::json!({
            "message": "This email address is associated with a computer that was infected by an info-stealer.",
            "stealers": [{
                "total_corporate_services": 0,
                "total_user_services": 52,
                "date_compromised": "2026-08-20T00:00:00.000Z",
                "computer_name": "DESKTOP-SD48CEG (NTECH)",
                "operating_system": "Not Found",
                "malware_path": "C:\\Users\\NTECH\\AppData\\Local\\Zooms\\SC298.exe",
                "antiviruses": [],
                "ip": "110.38.***.**",
                "top_passwords": ["N***********7"],
                "top_logins": ["l*************@gmail.com"]
            }]
        })
    }

    fn clean_response() -> serde_json::Value {
        serde_json::json!({
            "message": "This email address is not associated with a computer infected by an info-stealer.",
            "stealers": []
        })
    }

    #[test]
    fn parses_a_compromised_response() {
        let hits = parse_hudsonrock_response(&compromised_response()).expect("parses");
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].computer_name.as_deref(),
            Some("DESKTOP-SD48CEG (NTECH)")
        );
        assert_eq!(hits[0].total_user_services, Some(52));
        assert_eq!(hits[0].ip.as_deref(), Some("110.38.***.**"));
        assert_eq!(
            hits[0].malware_path.as_deref(),
            Some("C:\\Users\\NTECH\\AppData\\Local\\Zooms\\SC298.exe")
        );
    }

    #[test]
    fn parses_a_clean_response_as_an_empty_list() {
        let hits = parse_hudsonrock_response(&clean_response()).expect("parses");
        assert!(hits.is_empty());
    }

    #[test]
    fn a_not_found_computer_name_is_treated_as_absent() {
        let json = serde_json::json!({
            "stealers": [{"computer_name": "Not Found", "date_compromised": null}]
        });
        let hits = parse_hudsonrock_response(&json).unwrap();
        assert_eq!(hits[0].computer_name, None);
    }

    #[test]
    fn rejects_a_response_missing_stealers() {
        assert!(parse_hudsonrock_response(&serde_json::json!({"message": "x"})).is_err());
    }

    #[test]
    fn yield_writes_breach_events_never_touched_by_another_email_tool() {
        let hits = parse_hudsonrock_response(&compromised_response()).unwrap();
        let produced = hudsonrock_to_yield(&hits);
        let breaches = produced.payload_patch["breaches"].as_array().unwrap();
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0]["sourceToolId"], "email-hudsonrock");
        assert_eq!(
            breaches[0]["dataClasses"],
            serde_json::json!(["Passwords", "Logins"])
        );
    }

    #[test]
    fn yield_row_carries_the_ip_and_malware_path() {
        let hits = parse_hudsonrock_response(&compromised_response()).unwrap();
        let produced = hudsonrock_to_yield(&hits);
        assert!(produced.rows[0].value.contains("110.38.***.**"));
        assert!(
            produced.rows[0]
                .value
                .contains("C:\\Users\\NTECH\\AppData\\Local\\Zooms\\SC298.exe")
        );
    }

    #[test]
    fn yield_spawns_an_ip_child_seed_from_the_infected_machine() {
        let hits = parse_hudsonrock_response(&compromised_response()).unwrap();
        let produced = hudsonrock_to_yield(&hits);
        assert_eq!(produced.children.len(), 1);
        assert_eq!(produced.children[0].oz_type, OzType::Ip);
        assert_eq!(produced.children[0].value, "110.38.***.**");
    }

    #[test]
    fn yield_parses_the_compromised_date() {
        let hits = parse_hudsonrock_response(&compromised_response()).unwrap();
        let event = stealer_to_breach_event(&hits[0]);
        assert!(event.breached_at.is_some());
    }
}
