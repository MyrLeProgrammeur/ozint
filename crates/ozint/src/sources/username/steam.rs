//! `steam-profile` — Steam Community's public, keyless XML profile feed.
//!
//! Endpoint: `GET https://steamcommunity.com/id/{handle}?xml=1`. No auth. Verified by direct
//! call 2026-08-25: a real vanity handle (`gaben`) answers `200` with a `<profile>` document
//! (`steamID64`, `steamID` display name, `realname`, `location`, `summary`, avatar URLs,
//! `memberSince`); an unknown handle answers `200` with an `<response><error>The specified
//! profile could not be found.</error></response>` body — a genuine absence signal, but on the
//! *same* status code as success, so [`parse_steam_profile`] discriminates on which root
//! element is present, not on HTTP status, the same shape `bluesky.rs`'s body-text check uses
//! for its own same-status absence case.
//!
//! ## No XML crate
//!
//! This crate carries an XML body as raw, unparsed text ([`crate::fetch::OzBody::Xml`]'s own
//! doc comment: "`quick-xml` is not a dependency of this crate"). Steam's feed is a small,
//! stable, flat tag set, so [`extract_tag`] pulls each field with a targeted regex rather than
//! pulling in a general XML parser for one caller — consistent with that existing restraint.
//!
//! ## Groups are a cross-link
//!
//! The feed's `<groups>` block lists the user's visible Steam group memberships, each a
//! `<group><groupID64>…</groupID64><groupName>…</groupName>…</group>` entry. [`extract_groups`]
//! pulls the `groupName` of every entry with a small regex rather than [`extract_tag`] (which
//! only ever matches the *first* occurrence of a tag and would miss every group past the
//! first). Group names are reported as rows; this tool does not turn them into child seeds
//! today (no `OzType` fits a Steam group), but they are real, verified cross-link data — an
//! earlier version of this doc comment claimed Steam's feed "carries no machine-readable
//! cross-links," which the `<groups>` block itself contradicts.

use std::sync::OnceLock;

use regex::Regex;

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

use super::nonempty;

const STEAM_PROFILE_BASE: &str = "https://steamcommunity.com/id/";

/// A Steam profile, narrowed to the fields this tool reports.
#[derive(Debug, Clone, PartialEq)]
pub struct SteamProfile {
    pub steam_id64: Option<String>,
    pub persona_name: Option<String>,
    pub real_name: Option<String>,
    pub location: Option<String>,
    pub summary: Option<String>,
    pub member_since: Option<String>,
    pub avatar_full: Option<String>,
    pub groups: Vec<String>,
}

/// Extracts one tag's text content — `<CDATA[...]]>`-wrapped or plain — from a small, flat XML
/// document. Not a general XML parser: matches the first occurrence of `<tag>...</tag>` at any
/// depth, which is safe because every tag it is asked for by name here is unique within the
/// document it is searched in — top-level fields are unique in the full feed, and
/// [`extract_groups`] only ever asks this function for `groupName` within one already-isolated
/// `<group>…</group>` block, never across the whole `<groups>` list at once.
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    static CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<String, Regex>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut cache = cache.lock().expect("regex cache lock");
    let re = cache.entry(tag.to_string()).or_insert_with(|| {
        Regex::new(&format!(
            r"(?s)<{tag}>(?:<!\[CDATA\[(.*?)\]\]>|([^<]*))</{tag}>"
        ))
        .expect("valid tag regex")
    });
    let caps = re.captures(xml)?;
    let raw = caps.get(1).or_else(|| caps.get(2))?.as_str();
    nonempty(Some(raw))
}

/// Extracts every `<groupName>` from the feed's `<groups>` block — one per `<group>…</group>`
/// entry. Unlike [`extract_tag`], this must find *all* occurrences, not just the first, so it
/// matches each `<group>` block separately and pulls its `groupName` with [`extract_tag`].
fn extract_groups(xml: &str) -> Vec<String> {
    static GROUP_RE: OnceLock<Regex> = OnceLock::new();
    let re = GROUP_RE
        .get_or_init(|| Regex::new(r"(?s)<group>(.*?)</group>").expect("valid group block regex"));
    re.captures_iter(xml)
        .filter_map(|caps| extract_tag(caps.get(1).map(|m| m.as_str()).unwrap_or(""), "groupName"))
        .collect()
}

/// Parses a Steam Community XML profile response. `Ok(None)` is the verified-absent finding
/// (an `<error>` element is present, matching the "profile could not be found" body verified
/// live); `Err` covers a response that is neither a profile nor a recognisable error envelope.
/// Pure and tested.
pub fn parse_steam_profile(xml: &str) -> Result<Option<SteamProfile>, String> {
    if xml.contains("<error>") {
        return Ok(None);
    }
    if !xml.contains("<profile>") {
        return Err("Steam response is neither a profile nor an error envelope".to_string());
    }

    Ok(Some(SteamProfile {
        steam_id64: extract_tag(xml, "steamID64"),
        persona_name: extract_tag(xml, "steamID"),
        real_name: extract_tag(xml, "realname"),
        location: extract_tag(xml, "location"),
        summary: extract_tag(xml, "summary"),
        member_since: extract_tag(xml, "memberSince"),
        avatar_full: extract_tag(xml, "avatarFull"),
        groups: extract_groups(xml),
    }))
}

/// Turns a parsed [`SteamProfile`] into a [`ToolYield`]. Group memberships are reported as rows
/// (see the module doc's "Groups are a cross-link" section); this tool still emits no children
/// — no `OzType` fits a Steam group today, and every other field on this feed is a
/// single-platform profile fact, not a verified external-account link.
pub fn steam_profile_to_yield(profile: &SteamProfile, handle: &str) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "Steam".to_string(),
        value: profile
            .persona_name
            .clone()
            .unwrap_or_else(|| handle.to_string()),
        href: Some(format!("{STEAM_PROFILE_BASE}{handle}")),
        ..Default::default()
    }];
    if let Some(real_name) = &profile.real_name {
        rows.push(OzRow {
            label: "Real name".to_string(),
            value: real_name.clone(),
            ..Default::default()
        });
    }
    if let Some(location) = &profile.location {
        rows.push(OzRow {
            label: "Location".to_string(),
            value: location.clone(),
            ..Default::default()
        });
    }
    if let Some(summary) = &profile.summary {
        rows.push(OzRow {
            label: "Summary".to_string(),
            value: summary.clone(),
            ..Default::default()
        });
    }
    if let Some(member_since) = &profile.member_since {
        rows.push(OzRow {
            label: "Member since".to_string(),
            value: member_since.clone(),
            ..Default::default()
        });
    }
    if let Some(steam_id64) = &profile.steam_id64 {
        rows.push(OzRow {
            label: "SteamID64".to_string(),
            value: steam_id64.clone(),
            ..Default::default()
        });
    }
    for group in &profile.groups {
        rows.push(OzRow {
            label: "Group".to_string(),
            value: group.clone(),
            ..Default::default()
        });
    }

    ToolYield {
        payload_patch: serde_json::json!({}),
        rows,
        facts: Vec::new(),
        flags: Vec::new(),
        values: Vec::new(),
        children: Vec::new(),
    }
}

/// Looks `handle` up as a Steam Community vanity URL. Keyless.
pub async fn run_steam_profile(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{STEAM_PROFILE_BASE}{}?xml=1", urlencoding::encode(handle));

    let outcome = ctx
        .fetch(
            "steam-profile",
            handle,
            &url,
            fetch::OzFetchOptions::default(),
        )
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
    let OzBody::Xml(xml) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "Steam response was not XML".to_string(),
            },
            None,
        );
    };

    match parse_steam_profile(xml) {
        Ok(Some(profile)) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(steam_profile_to_yield(&profile, handle)),
        ),
        Ok(None) => DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default())),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_PROFILE: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><profile>
        <steamID64>76561197968052866</steamID64>
        <steamID><![CDATA[Gaben]]></steamID>
        <realname><![CDATA[Jake]]></realname>
        <location><![CDATA[Idaho, United States]]></location>
        <summary><![CDATA[I've been busy on and off.]]></summary>
        <memberSince><![CDATA[August 8, 2004]]></memberSince>
        <avatarFull><![CDATA[https://avatars.example.com/full.jpg]]></avatarFull>
        <groups>
            <group>
                <groupID64>103582791429521412</groupID64>
                <groupName><![CDATA[Valve]]></groupName>
                <groupURL><![CDATA[Valve]]></groupURL>
            </group>
            <group>
                <groupID64>103582791429521413</groupID64>
                <groupName><![CDATA[Steam Users' Forums]]></groupName>
                <groupURL><![CDATA[steamforums]]></groupURL>
            </group>
        </groups>
    </profile>"#;

    const ABSENT_PROFILE: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><response><error><![CDATA[The specified profile could not be found.]]></error></response>"#;

    #[test]
    fn extracts_cdata_wrapped_tags() {
        assert_eq!(
            extract_tag(REAL_PROFILE, "steamID").as_deref(),
            Some("Gaben")
        );
        assert_eq!(
            extract_tag(REAL_PROFILE, "realname").as_deref(),
            Some("Jake")
        );
    }

    #[test]
    fn extracts_plain_unwrapped_tags() {
        assert_eq!(
            extract_tag(REAL_PROFILE, "steamID64").as_deref(),
            Some("76561197968052866")
        );
    }

    #[test]
    fn missing_tag_returns_none() {
        assert_eq!(extract_tag(REAL_PROFILE, "nonexistentTag"), None);
    }

    #[test]
    fn parses_a_real_profile() {
        let profile = parse_steam_profile(REAL_PROFILE)
            .expect("parses")
            .expect("a profile");
        assert_eq!(profile.persona_name.as_deref(), Some("Gaben"));
        assert_eq!(profile.real_name.as_deref(), Some("Jake"));
        assert_eq!(profile.steam_id64.as_deref(), Some("76561197968052866"));
        assert_eq!(
            profile.groups,
            vec!["Valve".to_string(), "Steam Users' Forums".to_string()]
        );
    }

    #[test]
    fn extracts_all_group_names_not_just_the_first() {
        assert_eq!(
            extract_groups(REAL_PROFILE),
            vec!["Valve".to_string(), "Steam Users' Forums".to_string()]
        );
    }

    #[test]
    fn no_groups_block_yields_an_empty_vec() {
        assert!(extract_groups("<profile></profile>").is_empty());
    }

    #[test]
    fn an_error_envelope_is_the_verified_empty_finding() {
        assert_eq!(parse_steam_profile(ABSENT_PROFILE), Ok(None));
    }

    #[test]
    fn a_body_that_is_neither_shape_is_rejected() {
        assert!(parse_steam_profile("<unrelated/>").is_err());
    }

    #[test]
    fn yield_includes_the_steam_row_and_real_name() {
        let profile = parse_steam_profile(REAL_PROFILE).unwrap().unwrap();
        let produced = steam_profile_to_yield(&profile, "gaben");
        assert_eq!(produced.rows[0].label, "Steam");
        assert_eq!(produced.rows[0].value, "Gaben");
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Real name" && r.value == "Jake")
        );
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Group" && r.value == "Valve")
        );
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Group" && r.value == "Steam Users' Forums")
        );
        assert!(
            produced.children.is_empty(),
            "no OzType fits a Steam group today, so groups surface as rows only"
        );
    }

    #[test]
    fn yield_falls_back_to_the_queried_handle_when_persona_name_is_absent() {
        let profile = SteamProfile {
            steam_id64: None,
            persona_name: None,
            real_name: None,
            location: None,
            summary: None,
            member_since: None,
            avatar_full: None,
            groups: Vec::new(),
        };
        let produced = steam_profile_to_yield(&profile, "somehandle");
        assert_eq!(produced.rows[0].value, "somehandle");
    }
}
