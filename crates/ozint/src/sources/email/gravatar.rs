//! `gravatar-email` — Gravatar's v3 public profile API, looked up by **email hash**. Keyless.
//!
//! `sources::username::gravatar`'s module doc left this path unbuilt, reasoning the crate had
//! no hashing dependency. That reasoning was already stale when it was written — `sha2` has
//! been a dependency since `media.rs`'s digest computation — and is corrected here rather than
//! there, since an email-hash lookup is an `entity-email` tool, not an `entity-username` one
//! (the two must stay separate: a username tool takes a public slug, this one takes a value
//! nobody else should be able to reverse from the response).
//!
//! **Hash algorithm: SHA-256, not MD5.** Verified live 2026-08-23 against `beau@automattic.com`
//! (the profile documented in `username::gravatar`'s own test fixtures shares its `hash` field
//! with this address): the SHA-256 hex digest of the trimmed, lowercased address resolves
//! `200` with the full profile; the MD5 digest of the same address resolves a clean `404`.
//! Gravatar's own docs confirm this is not a fluke of one account — MD5 is deprecated for
//! their API specifically because it is reversible, and SHA-256 is what a v3 lookup expects.
//! This module hashes with `sha2::Sha256` only; it does not fall back to MD5.
//!
//! Parsing and shaping reuse [`super::super::username::gravatar::parse_gravatar_profile`] and
//! [`super::super::username::gravatar::gravatar_profile_to_yield`] verbatim — the response
//! shape is identical regardless of which identifier resolved it, so there is nothing
//! email-specific to duplicate below the hashing step.

use sha2::Digest as _;

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::sources::username::gravatar::{gravatar_profile_to_yield, parse_gravatar_profile};

const GRAVATAR_API_BASE: &str = "https://api.gravatar.com/v3/profiles/";

/// Trims and lowercases `email` per Gravatar's own normalisation rule, then returns its
/// SHA-256 hex digest. Pure, tested against Gravatar's own published example
/// (`MyEmailAddress@example.com` → `84059b07d4be67b806386c0aad8070a23f18836bbaae342275dc0a83414c32ee`).
pub fn email_hash(email: &str) -> String {
    let normalized = email.trim().to_ascii_lowercase();
    let digest = sha2::Sha256::digest(normalized.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Queries Gravatar's v3 public profile API for the SHA-256 hash of `email`. Untested beyond
/// its pure helpers, same convention as `username::gravatar::run_gravatar_profile`.
pub async fn run_gravatar_email(email: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let hash = email_hash(email);
    let url = format!("{GRAVATAR_API_BASE}{hash}");

    // Cache key is the hash, not the raw address — the hash is already what travels on the
    // wire, and nothing is gained by also keying the cache on the plaintext.
    let outcome = ctx
        .fetch(
            "gravatar-email",
            &hash,
            &url,
            fetch::OzFetchOptions::default(),
        )
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    // Same clean "not found" semantics as the username path: a 404 here means no Gravatar
    // account is registered under this address, not a probe failure.
    if let OzOutcome::HttpError { status: 404, .. } = &outcome {
        return DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default()));
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
                message: "Gravatar response was not JSON".to_string(),
            },
            None,
        );
    };
    let profile = match parse_gravatar_profile(json) {
        Ok(profile) => profile,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    // `queried_handle` only feeds a row-value fallback and the self-referential Username-child
    // suppression, both of which stay harmless for an email seed: there is no verified
    // account whose handle collides with a raw email address in practice.
    DispatchOutcome::Ran(
        ToolOutcome::OkWithResults { count: 1 },
        Some(gravatar_profile_to_yield(&profile, email)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_hash_matches_gravatars_own_published_example() {
        assert_eq!(
            email_hash("MyEmailAddress@example.com"),
            "84059b07d4be67b806386c0aad8070a23f18836bbaae342275dc0a83414c32ee"
        );
    }

    #[test]
    fn email_hash_trims_and_lowercases_before_hashing() {
        assert_eq!(
            email_hash("  MyEmailAddress@example.com  "),
            email_hash("myemailaddress@example.com")
        );
    }

    #[test]
    fn email_hash_is_stable_and_deterministic() {
        assert_eq!(email_hash("a@b.com"), email_hash("a@b.com"));
        assert_ne!(email_hash("a@b.com"), email_hash("c@b.com"));
    }
}
