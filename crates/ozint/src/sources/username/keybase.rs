//! `keybase-lookup` — Keybase's public, keyless user-lookup API. The one tool in this
//! category that returns **cryptographically-proved** cross-account links rather than a
//! single-platform profile: a Keybase user signs a proof (a public post/gist/DNS record) for
//! each external account they claim, and `proofs_summary` is Keybase's own verified record of
//! those signatures — not a scrape, not an inference.
//!
//! Endpoint: `GET https://keybase.io/_/api/1.0/user/lookup.json?usernames={handle}`. No auth.
//!
//! ## The absent-case shape, verified by direct call 2026-08-25
//!
//! A genuinely unregistered (but syntactically valid) handle answers **`200`** with
//! `status.code: 0` and `them: [null]` — the honest empty finding this crate's "empty is a
//! finding" doctrine (`outcome.rs`) expects. A handle Keybase's own username rules reject
//! outright (over 16 characters, in this API's case) answers `200` with `status.code: 100`
//! (`INPUT_ERROR`) — a genuine validation failure, not an absence, and [`parse_keybase_lookup`]
//! keeps the two apart rather than folding both into `OkEmpty`.
//!
//! ## Children
//!
//! Each proof in `proofs_summary.all` names a `proof_type` (`twitter`, `github`, `reddit`,
//! `hackernews`, `dns`, …) and a `nametag` (the linked account's handle on that platform, or
//! the domain for a `dns` proof). A `dns` proof becomes a [`OzType::Domain`] child. Every other
//! proof type becomes a [`OzType::Username`] child **only when its `nametag` differs from the
//! handle that was queried** — Keybase proofs are very often the same handle on every
//! platform, and re-emitting the seed value as its own child would loop the investigation on
//! itself, the same self-reference guard `youtube.rs`'s `youtube_channel_to_yield` applies to
//! its own custom-URL handle.

use std::collections::HashSet;

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

use super::nonempty;

const KEYBASE_LOOKUP_URL: &str = "https://keybase.io/_/api/1.0/user/lookup.json?usernames=";

/// One verified proof from `proofs_summary.all`, narrowed to what this tool reports.
#[derive(Debug, Clone, PartialEq)]
pub struct KeybaseProof {
    pub proof_type: String,
    pub nametag: String,
    pub service_url: Option<String>,
}

/// A Keybase user, narrowed to the fields this tool cares about.
#[derive(Debug, Clone, PartialEq)]
pub struct KeybaseUser {
    pub username: String,
    pub full_name: Option<String>,
    pub bio: Option<String>,
    pub location: Option<String>,
    pub proofs: Vec<KeybaseProof>,
    /// PGP key fingerprints — Keybase's cryptographically-proved key material, not a scrape.
    /// Collected from `public_keys.primary.key_fingerprint` (the user's primary PGP key) plus
    /// any per-key `key_fingerprint`/`kid` on `public_keys.pgp_public_keys[]` entries, for users
    /// who have registered more than one PGP key. Deduplicated, order preserved.
    pub pgp_fingerprints: Vec<String>,
}

/// Pulls a per-key fingerprint out of one `public_keys.pgp_public_keys[]` (or `all_bundles[]`)
/// entry. Keybase has returned these both as plain fingerprint strings and as objects carrying
/// `key_fingerprint`/`kid` — this accepts either shape.
fn fingerprint_from_key_entry(entry: &serde_json::Value) -> Option<String> {
    // A raw string entry is only ever a bare fingerprint/kid (hex digits) here — Keybase's
    // *armored* key blocks are multi-line PGP text, never mistaken for one of these.
    if let Some(s) = entry.as_str() {
        return nonempty(Some(s))
            .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit()));
    }
    nonempty(entry.get("key_fingerprint").and_then(|v| v.as_str()))
        .or_else(|| nonempty(entry.get("kid").and_then(|v| v.as_str())))
}

/// Parses `lookup.json`'s top-level status/them shape. `Ok(None)` is the verified-absent
/// finding (`status.code == 0`, `them: [null]`); `Err` covers both a genuine `INPUT_ERROR`
/// status and a response shape this endpoint does not document. Pure and tested.
pub fn parse_keybase_lookup(json: &serde_json::Value) -> Result<Option<KeybaseUser>, String> {
    let status_code = json
        .get("status")
        .and_then(|s| s.get("code"))
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "Keybase response is missing `status.code`".to_string())?;
    if status_code != 0 {
        let desc = json
            .get("status")
            .and_then(|s| s.get("desc"))
            .and_then(|v| v.as_str())
            .unwrap_or("no description");
        return Err(format!(
            "Keybase lookup failed (status {status_code}): {desc}"
        ));
    }

    let them = json
        .get("them")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Keybase response is missing `them`".to_string())?;
    let Some(first) = them.first() else {
        return Err("Keybase response's `them` array is empty".to_string());
    };
    if first.is_null() {
        return Ok(None);
    }

    let basics = first.get("basics");
    let username = basics
        .and_then(|b| b.get("username"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Keybase user is missing `basics.username`".to_string())?
        .to_string();

    let profile = first.get("profile");
    let full_name = nonempty(
        profile
            .and_then(|p| p.get("full_name"))
            .and_then(|v| v.as_str()),
    );
    let bio = nonempty(profile.and_then(|p| p.get("bio")).and_then(|v| v.as_str()));
    let location = nonempty(
        profile
            .and_then(|p| p.get("location"))
            .and_then(|v| v.as_str()),
    );

    let proofs = first
        .get("proofs_summary")
        .and_then(|p| p.get("all"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let proof_type = nonempty(p.get("proof_type").and_then(|v| v.as_str()))?;
                    let nametag = nonempty(p.get("nametag").and_then(|v| v.as_str()))?;
                    let service_url = nonempty(p.get("service_url").and_then(|v| v.as_str()));
                    Some(KeybaseProof {
                        proof_type,
                        nametag,
                        service_url,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let public_keys = first.get("public_keys");
    let mut pgp_fingerprints = Vec::new();
    let mut seen_fingerprints = HashSet::new();
    if let Some(primary_fp) = nonempty(
        public_keys
            .and_then(|pk| pk.get("primary"))
            .and_then(|p| p.get("key_fingerprint"))
            .and_then(|v| v.as_str()),
    ) && seen_fingerprints.insert(primary_fp.clone())
    {
        pgp_fingerprints.push(primary_fp);
    }
    for key in ["pgp_public_keys", "all_bundles"] {
        if let Some(entries) = public_keys
            .and_then(|pk| pk.get(key))
            .and_then(|v| v.as_array())
        {
            for entry in entries {
                if let Some(fp) = fingerprint_from_key_entry(entry)
                    && seen_fingerprints.insert(fp.clone())
                {
                    pgp_fingerprints.push(fp);
                }
            }
        }
    }

    Ok(Some(KeybaseUser {
        username,
        full_name,
        bio,
        location,
        proofs,
        pgp_fingerprints,
    }))
}

/// Turns a parsed [`KeybaseUser`] into a [`ToolYield`]. `queried_handle` suppresses a proof
/// child whose `nametag` is the same handle that was queried — see the module doc. Pure and
/// tested.
pub fn keybase_user_to_yield(user: &KeybaseUser, queried_handle: &str) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "Keybase".to_string(),
        value: user.username.clone(),
        href: Some(format!("https://keybase.io/{}", user.username)),
        ..Default::default()
    }];
    if let Some(full_name) = &user.full_name {
        rows.push(OzRow {
            label: "Name".to_string(),
            value: full_name.clone(),
            ..Default::default()
        });
    }
    if let Some(location) = &user.location {
        rows.push(OzRow {
            label: "Location".to_string(),
            value: location.clone(),
            ..Default::default()
        });
    }
    if let Some(bio) = &user.bio {
        rows.push(OzRow {
            label: "Bio".to_string(),
            value: bio.clone(),
            ..Default::default()
        });
    }
    for proof in &user.proofs {
        rows.push(OzRow {
            label: format!("Proof · {}", proof.proof_type),
            value: proof.nametag.clone(),
            href: proof.service_url.clone(),
            ..Default::default()
        });
    }
    for fingerprint in &user.pgp_fingerprints {
        rows.push(OzRow {
            label: "PGP Fingerprint".to_string(),
            value: fingerprint.clone(),
            ..Default::default()
        });
    }

    let queried_lower = queried_handle.to_ascii_lowercase();
    let mut children = Vec::new();
    let mut seen_usernames = HashSet::new();
    let mut seen_domains = HashSet::new();
    for proof in &user.proofs {
        if proof.proof_type == "dns" {
            if seen_domains.insert(proof.nametag.clone()) {
                children.push(ChildSeed {
                    oz_type: OzType::Domain,
                    value: proof.nametag.clone(),
                    note: Some("Keybase-verified DNS proof".to_string()),
                });
            }
            continue;
        }
        if proof.nametag.to_ascii_lowercase() == queried_lower {
            continue;
        }
        if seen_usernames.insert(proof.nametag.clone()) {
            children.push(ChildSeed {
                oz_type: OzType::Username,
                value: proof.nametag.clone(),
                note: Some(format!("Keybase-verified {} proof", proof.proof_type)),
            });
        }
    }

    ToolYield {
        payload_patch: serde_json::json!({}),
        rows,
        facts: Vec::new(),
        flags: Vec::new(),
        values: Vec::new(),
        children,
    }
}

/// Looks `handle` up on Keybase. Keyless — no `SkippedNoKey` branch exists for this tool.
pub async fn run_keybase_lookup(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!("{KEYBASE_LOOKUP_URL}{}", urlencoding::encode(handle));

    let outcome = ctx
        .fetch(
            "keybase-lookup",
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
    let OzBody::Json(json) = &resp.body else {
        return DispatchOutcome::Ran(
            ToolOutcome::ParseError {
                message: "Keybase response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_keybase_lookup(json) {
        Ok(Some(user)) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(keybase_user_to_yield(&user, handle)),
        ),
        Ok(None) => DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default())),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_response() -> serde_json::Value {
        serde_json::json!({
            "status": {"code": 0, "name": "OK"},
            "them": [{
                "basics": {"username": "max"},
                "profile": {
                    "full_name": "Max Krohn",
                    "location": "New York, NY",
                    "bio": "Keybase.io co-founder"
                },
                "proofs_summary": {
                    "all": [
                        {"proof_type": "twitter", "nametag": "maxtaco", "service_url": "https://twitter.com/maxtaco"},
                        {"proof_type": "github", "nametag": "maxtaco", "service_url": "https://github.com/maxtaco"},
                        {"proof_type": "dns", "nametag": "oneshallpass.com", "service_url": null}
                    ]
                },
                "public_keys": {
                    "primary": {
                        "kid": "0101c...0a",
                        "key_fingerprint": "8efbe2e1e376e8e924801caf0851bf9587433004"
                    },
                    "pgp_public_keys": [
                        {"key_fingerprint": "1234567890abcdef1234567890abcdef12345678", "kid": "0101abc"}
                    ]
                }
            }]
        })
    }

    #[test]
    fn parses_a_full_user_with_proofs() {
        let user = parse_keybase_lookup(&full_response())
            .expect("parses")
            .expect("a user");
        assert_eq!(user.username, "max");
        assert_eq!(user.full_name.as_deref(), Some("Max Krohn"));
        assert_eq!(user.proofs.len(), 3);
        assert_eq!(user.proofs[0].proof_type, "twitter");
        assert_eq!(user.proofs[0].nametag, "maxtaco");
    }

    #[test]
    fn parses_pgp_fingerprints_from_primary_and_pgp_public_keys() {
        let user = parse_keybase_lookup(&full_response())
            .expect("parses")
            .expect("a user");
        assert_eq!(
            user.pgp_fingerprints,
            vec![
                "8efbe2e1e376e8e924801caf0851bf9587433004".to_string(),
                "1234567890abcdef1234567890abcdef12345678".to_string(),
            ]
        );
    }

    #[test]
    fn yield_emits_a_row_per_pgp_fingerprint() {
        let user = parse_keybase_lookup(&full_response()).unwrap().unwrap();
        let produced = keybase_user_to_yield(&user, "max");
        let fingerprint_rows: Vec<_> = produced
            .rows
            .iter()
            .filter(|r| r.label == "PGP Fingerprint")
            .collect();
        assert_eq!(fingerprint_rows.len(), 2);
        assert_eq!(
            fingerprint_rows[0].value,
            "8efbe2e1e376e8e924801caf0851bf9587433004"
        );
    }

    #[test]
    fn a_null_them_entry_is_the_verified_empty_finding() {
        let json = serde_json::json!({
            "status": {"code": 0, "name": "OK"},
            "them": [null]
        });
        assert_eq!(parse_keybase_lookup(&json), Ok(None));
    }

    #[test]
    fn a_nonzero_status_code_is_a_real_error_not_empty() {
        let json = serde_json::json!({
            "status": {"code": 100, "name": "INPUT_ERROR", "desc": "bad list value"}
        });
        assert!(parse_keybase_lookup(&json).is_err());
    }

    #[test]
    fn a_response_missing_them_is_rejected() {
        let json = serde_json::json!({ "status": {"code": 0} });
        assert!(parse_keybase_lookup(&json).is_err());
    }

    #[test]
    fn a_user_missing_username_is_rejected() {
        let json = serde_json::json!({
            "status": {"code": 0},
            "them": [{"basics": {}}]
        });
        assert!(parse_keybase_lookup(&json).is_err());
    }

    #[test]
    fn a_user_with_no_proofs_still_parses() {
        let json = serde_json::json!({
            "status": {"code": 0},
            "them": [{"basics": {"username": "bare"}}]
        });
        let user = parse_keybase_lookup(&json).unwrap().unwrap();
        assert_eq!(user.username, "bare");
        assert!(user.proofs.is_empty());
    }

    #[test]
    fn yield_emits_a_domain_child_from_a_dns_proof() {
        let user = parse_keybase_lookup(&full_response()).unwrap().unwrap();
        let produced = keybase_user_to_yield(&user, "max");
        assert!(
            produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Domain && c.value == "oneshallpass.com")
        );
    }

    #[test]
    fn yield_emits_a_username_child_for_a_differing_nametag() {
        let user = parse_keybase_lookup(&full_response()).unwrap().unwrap();
        let produced = keybase_user_to_yield(&user, "max");
        // Both twitter and github proofs share the nametag "maxtaco" — deduped to one child.
        let username_children: Vec<_> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Username)
            .collect();
        assert_eq!(username_children.len(), 1);
        assert_eq!(username_children[0].value, "maxtaco");
    }

    #[test]
    fn yield_suppresses_a_proof_that_matches_the_queried_handle() {
        let user = parse_keybase_lookup(&full_response()).unwrap().unwrap();
        // Query with the same handle the proofs happen to carry — must not re-emit itself.
        let produced = keybase_user_to_yield(&user, "maxtaco");
        assert!(
            !produced
                .children
                .iter()
                .any(|c| c.oz_type == OzType::Username)
        );
    }
}
