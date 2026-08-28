//! The single choke point every cloud-bound OZINT call must pass
//! through before a byte of investigation content reaches an LLM/embedder.
//!
//! This is an OZINT-specific wrapper around [`ozint_core::safety::guard_cloud`], not a
//! reimplementation of it. `guard_cloud` already knows how to redact IBAN/card numbers and
//! flag sensitive life-topic categories (health/finance/legal/relationship); this module adds
//! the three things that are specific to an investigation payload and that `guard_cloud` has
//! no way to know about on its own: a hard refusal for raw credential material, a hard
//! refusal for unprocessed breach-record dumps and media bytes, and a documented size cap.
//!
//! ## Allow / strip / never
//!
//! - **Never leaves the machine** (refused, not sanitised — see "Refusal is not redaction"
//!   below): raw credential material, full breach-record dumps, and raw image/file bytes.
//! - **Always allowed, unchanged**: entity types, counts, signal chips/verdicts, place names,
//!   and the target values themselves (the handle/email/domain under investigation). The
//!   subject of an investigation is not a secret from the model that summarises it — if it
//!   were, the summarisation feature could not exist at all.
//! - **Stripped, then allowed**: IBAN/card numbers (delegated to `redact_pii` inside
//!   `guard_cloud` — no new PII regexes live here) and oversized text (truncated to
//!   [`MAX_TEXT_CHARS`]).
//!
//! ## Refusal is not redaction
//!
//! A refusal and a sanitised pass are different outcomes and callers must be able to tell
//! them apart — that is why [`OzEgressDecision`] is an enum with a distinct `Refused` arm
//! carrying a machine-readable [`OzEgressRefusal`], rather than an `Allowed` payload that
//! happens to be empty. Breach dumps and media bytes are never "cleaned up and sent anyway";
//! the caller is expected to synthesise a summary (counts, chip text, category labels — all
//! on the always-allowed list) and pass *that* through this gate instead.
//!
//! ## The freeze gate is an input, and there is now something to feed it
//!
//! [`OzEgressRequest::frozen`] is the per-request freeze flag. The server-side kill switch it
//! was waiting for now **exists**: `ozint_core::safety::FreezeState`
//! holds the state, and the `freeze_gate` middleware in `ozint-server` already refuses every
//! acting/outbound route — `/api/ozint/fire` included — while it is set. So the primary
//! enforcement no longer lives here.
//!
//! What that leaves this field for is the **long-running** case the route gate cannot cover:
//! a layer that was already in flight when the freeze landed. The kill switch cancels those,
//! but any cloud call assembled inside one should still ask, i.e. any caller holding a
//! `&FreezeState` should pass `.frozen(state.is_frozen())`. **No caller sets it today** for
//! the mundane reason that `oz_guard` has no callers yet at all — the first will be the
//! LLM-summary unit. Do not read the presence of this field as proof that some
//! particular call site checks the freeze; read `app.rs`'s gated route list for what is
//! actually enforced.
//!
//! ## Where the credential-detection line is drawn
//!
//! The detectors in [`looks_like_credential_material`] are deliberately high-confidence and
//! deliberately incomplete. Aggressive detection (refusing anything containing the word
//! "password") makes the feature unusable and trains people to route around it; a conservative
//! detector that misses an exotic key shape is a narrower, more honest failure. What is
//! caught:
//!
//! - PEM-style private key blocks (`-----BEGIN ... PRIVATE KEY-----`).
//! - AWS-style access key ids (`AKIA`/`ASIA` prefix + 16 uppercase-alnum).
//! - An explicit assignment with a value attached — `password=`, `api_key:`, `secret_token=`,
//!   and similar, only when followed by a real value. Bare mentions of the *word* "password"
//!   or "key" in prose never match this — that is the point: `pattern = keyword`, not
//!   `pattern = keyword + operator + value`.
//! - Long high-entropy tokens: a contiguous run of 32+ chars from the base64-ish alphabet
//!   (**excluding `/` and `.`**) that mixes an uppercase letter, a lowercase letter, and a
//!   digit. This is the fuzziest of the four and is deliberately loose about which token
//!   *kinds* it catches, but strict about requiring real character-class diversity, which
//!   UUIDs and lowercase hex hashes do not have.
//!
//!   ⚠️ **URLs are excised before this one heuristic runs** — and only this one; the three
//!   patterns above still scan the full text, so `?api_key=…` inside a URL is still caught.
//!   An earlier version of this module assumed URLs lacked the character-class diversity to
//!   trip the entropy test. That was simply wrong: a mixed-case CDN path segment
//!   (`…/ytc/AIdro_kX9f2QweRtY…`, a YouTube avatar) satisfies it easily, and OZINT payloads
//!   are largely URLs. Because a refusal is *silent* to the analyst, the resulting false
//!   positive would have presented as the layer summary mysteriously never arriving.
//!
//! What is deliberately **not** caught, stated plainly rather than left to be discovered
//! later: lowercase-only or digits-only secrets of any length (many hex-encoded API keys and
//! all UUIDs look like this — a UUID in a `HashPayload` row must not be refused, so this
//! detector cannot flag "looks like hex"); short secrets (below the 32-char entropy floor);
//! secrets split across multiple lines or otherwise not contiguous; **a bare secret sitting in
//! a URL path segment with no `key=`-style assignment around it** (the direct cost of the URL
//! exemption above — `tests::documents_what_the_url_exemption_gives_up` pins this so the trade
//! stays visible); and any credential handed over as structured data outside of `text` (this
//! module only ever inspects the `text` field). A caller with a credential-shaped structured value should simply never put it in
//! an [`OzEgressRequest`] in the first place — this gate is a backstop on free text, not a
//! guarantee that no caller anywhere can misuse a typed field.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use ozint_core::safety::guard_cloud;
use regex::Regex;

/// Cap on how much text a single egress call may carry, applied to the already
/// PII-redacted text. Investigation summaries are prose paragraphs (a node's sections
/// rendered to text, a chip explanation), not documents — 4,000 chars is generous for that
/// and mirrors the order of magnitude other cloud-bound truncation caps in this codebase use
/// for similar "one summary, not a document" calls.
pub const MAX_TEXT_CHARS: usize = 4_000;

// ─── Credential detectors ───────────────────────────────────────────────────

static PEM_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").expect("pem pattern"));

/// AWS long-term (`AKIA`) and temporary/STS (`ASIA`) access key id prefixes.
static AWS_KEY_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("aws key pattern"));

/// `password=`, `api_key:`, `secret_token =`, … with a real value attached. The value must
/// be at least 4 chars of non-whitespace, non-quote content — long enough to exclude
/// placeholders like `password=***` written as literal asterisks but short enough to catch
/// real secrets, and requiring an operator (`:`/`=`) is what keeps bare prose mentions of
/// "password" or "key" out of this pattern entirely.
static ASSIGNED_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:password|passwd|pwd|api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*['"]?[^\s'"]{4,}"#,
    )
    .expect("assigned secret pattern")
});

/// Candidate contiguous runs from a base64/hex-ish alphabet, 32+ chars. Character-class
/// diversity (checked in [`looks_high_entropy`]) is what turns a candidate into a match —
/// this regex alone is deliberately over-broad.
/// A candidate opaque-secret run.
///
/// **`/` and `.` are deliberately excluded from this class.** With them in, the pattern
/// matched whole *URL paths* — and OZINT payloads are made of URLs. A single mixed-case CDN
/// path (`…/ytc/AIdro_kX9f2QweRtY…`, an avatar or media URL) would satisfy the entropy test
/// below and refuse the entire request, and because a refusal is silent to the analyst that
/// failure mode would look like the summary simply never arriving. A real secret is a
/// contiguous opaque run; a slash or a dot is almost always structure around one, not part of
/// it. JWTs survive the exclusion because each of their dot-separated segments clears the
/// 32-char floor on its own.
static LONG_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9_\-+=]{32,}").expect("long token pattern"));

/// A whole URL run, excised before the opaque-token heuristic runs — see
/// [`looks_like_credential_material`] for why, and for exactly what that gives up.
static URL_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"https?://\S+").expect("url run pattern"));

/// A 32+ char run that mixes an uppercase letter, a lowercase letter and a digit. Plain hex
/// (lowercase only, as in a git SHA or MD5/SHA1 hash string) and UUIDs never satisfy this —
/// both are common, benign, long strings in OZINT payloads and must never trip a refusal.
fn looks_high_entropy(token: &str) -> bool {
    let has_upper = token.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = token.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = token.bytes().any(|b| b.is_ascii_digit());
    has_upper && has_lower && has_digit
}

/// True if `text` contains a high-confidence credential signal. See the module doc's
/// "Where the credential-detection line is drawn" for exactly what this does and does not
/// catch.
fn looks_like_credential_material(text: &str) -> bool {
    // The three high-confidence patterns scan the FULL text, URLs included — so a secret
    // handed over as a query parameter (`?api_key=…`) is still caught inside a URL.
    if PEM_BLOCK.is_match(text) || AWS_KEY_ID.is_match(text) || ASSIGNED_SECRET.is_match(text) {
        return true;
    }
    // The opaque-token heuristic, and only it, ignores URLs. A long mixed-case URL *path
    // segment* (`…/ytc/AIdro_kX9f2QweRtY…`) is indistinguishable by shape from a secret, and
    // OZINT payloads are largely URLs — avatars, media, profile links — so scanning them here
    // refuses ordinary findings.
    //
    // This is a deliberate trade, and it is asymmetric. A false positive refuses the whole
    // request, and a refusal is *silent* to the analyst: the layer summary would simply never
    // appear, with no error to explain it, on any investigation touching a CDN URL. A false
    // negative lets an opaque secret embedded in a URL path reach the summariser — which is
    // the configured LLM provider, not an arbitrary third party — in text that is meant to be a
    // summary of findings, not credential material (the caller contract already says raw
    // credentials must not be put in `text`). What this gives up: **a bare secret sitting in
    // a URL path segment, with no `key=`-style assignment around it, is not detected.**
    let without_urls = URL_RUN.replace_all(text, " ");
    LONG_TOKEN
        .find_iter(&without_urls)
        .any(|m| looks_high_entropy(m.as_str()))
}

// ─── Char-based truncation ───────────────────────────────────────────────────

/// Truncate to at most `max` chars (not bytes) and report whether truncation happened.
fn truncate_chars(s: &str, max: usize) -> (String, bool) {
    if s.chars().count() <= max {
        (s.to_string(), false)
    } else {
        (s.chars().take(max).collect(), true)
    }
}

// ─── Request / decision ─────────────────────────────────────────────────────

/// One call's worth of text a caller wants to send to a cloud LLM/embedder, plus the flags
/// that steer [`oz_guard`] toward a refusal before it ever looks at the text.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OzEgressRequest {
    pub text: String,
    /// Set when this call would carry raw image/file bytes alongside (or instead of) `text`.
    /// Refused outright — see the module doc.
    pub carries_media_bytes: bool,
    /// Set when `text` is (or contains) an unprocessed dump of breach records rather than a
    /// synthesised summary. Refused outright — see the module doc.
    pub carries_raw_breach_dump: bool,
    /// Set by the caller from a real freeze/kill-switch source. **Nothing sets this today**
    /// — see the module doc's "The freeze gate is an input, not an enforcement".
    pub frozen: bool,
}

impl OzEgressRequest {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ..Self::default()
        }
    }

    pub fn with_media_bytes(mut self) -> Self {
        self.carries_media_bytes = true;
        self
    }

    pub fn with_raw_breach_dump(mut self) -> Self {
        self.carries_raw_breach_dump = true;
        self
    }

    pub fn frozen(mut self, frozen: bool) -> Self {
        self.frozen = frozen;
        self
    }
}

/// Why [`oz_guard`] refused a request. Kept as a closed enum rather than free strings so a
/// caller can branch on it and the UI can explain itself without parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OzEgressRefusal {
    /// The freeze gate was set on the request. See the module doc — nothing sets this today.
    Frozen,
    /// `text` matched a high-confidence credential signal.
    CredentialMaterial,
    /// The request was flagged as an unprocessed breach-record dump.
    RawBreachRecordDump,
    /// The request was flagged as carrying raw image/file bytes.
    MediaBytes,
}

/// What survived the gate: sanitised text, plus what was done to it. Redaction and
/// truncation are facts the caller (and, eventually, the UI) may want to surface, not just
/// side effects to discard.
#[derive(Debug, Clone, PartialEq)]
pub struct OzEgressAllowed {
    pub text: String,
    /// Per-kind PII redaction counts from `guard_cloud` (today: `iban`, `card`).
    pub redactions: BTreeMap<String, usize>,
    /// True when `text` was cut down to [`MAX_TEXT_CHARS`].
    pub truncated: bool,
    /// True if `guard_cloud` flagged a sensitive life-topic category (health/finance/legal/
    /// relationship). Advisory, same as in `guard_cloud` itself — does not block the call.
    pub sensitive: bool,
    pub categories: Vec<String>,
}

/// The result of running a request through the gate. Deliberately not "allowed with possibly
/// empty content" — see the module doc's "Refusal is not redaction".
#[derive(Debug, Clone, PartialEq)]
pub enum OzEgressDecision {
    Allowed(OzEgressAllowed),
    Refused(OzEgressRefusal),
}

impl OzEgressDecision {
    pub const fn is_allowed(&self) -> bool {
        matches!(self, OzEgressDecision::Allowed(_))
    }

    pub const fn refusal(&self) -> Option<OzEgressRefusal> {
        match self {
            OzEgressDecision::Refused(r) => Some(*r),
            OzEgressDecision::Allowed(_) => None,
        }
    }
}

/// Run one OZINT egress request through the gate. See the module doc for the allow/strip/
/// never policy and its rationale.
pub fn oz_guard(input: &OzEgressRequest) -> OzEgressDecision {
    if input.frozen {
        return OzEgressDecision::Refused(OzEgressRefusal::Frozen);
    }
    if input.carries_media_bytes {
        return OzEgressDecision::Refused(OzEgressRefusal::MediaBytes);
    }
    if input.carries_raw_breach_dump {
        return OzEgressDecision::Refused(OzEgressRefusal::RawBreachRecordDump);
    }
    if looks_like_credential_material(&input.text) {
        return OzEgressDecision::Refused(OzEgressRefusal::CredentialMaterial);
    }

    let guarded = guard_cloud(&input.text);
    let (text, truncated) = truncate_chars(&guarded.text, MAX_TEXT_CHARS);

    OzEgressDecision::Allowed(OzEgressAllowed {
        text,
        redactions: guarded.redactions,
        truncated,
        sensitive: guarded.sensitive,
        categories: guarded.categories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(decision: OzEgressDecision) -> OzEgressAllowed {
        match decision {
            OzEgressDecision::Allowed(a) => a,
            OzEgressDecision::Refused(r) => panic!("expected Allowed, got Refused({r:?})"),
        }
    }

    // ── ordinary pass-through ────────────────────────────────────────────

    #[test]
    fn an_ordinary_summary_passes_through_unchanged() {
        let req = OzEgressRequest::new("14 of 312 sites confirmed for handle mtrebosc");
        let out = allowed(oz_guard(&req));
        assert_eq!(out.text, "14 of 312 sites confirmed for handle mtrebosc");
        assert!(out.redactions.is_empty());
        assert!(!out.truncated);
        assert!(!out.sensitive);
    }

    #[test]
    fn the_always_allowed_categories_survive_untouched() {
        // Entity type, count, place name, and the target value itself — none of it is PII
        // by this gate's rules, and none of it should be altered.
        let req =
            OzEgressRequest::new("target: mtrebosc, type: username, 14 confirmed, Paris, France");
        let out = allowed(oz_guard(&req));
        assert_eq!(out.text, req.text);
    }

    // ── strip, don't refuse ──────────────────────────────────────────────

    #[test]
    fn iban_and_card_are_stripped_not_refused() {
        let req = OzEgressRequest::new(
            "IBAN FR7630001007941234567890185 et carte 4242 4242 4242 4242 fin",
        );
        let out = allowed(oz_guard(&req));
        assert_eq!(out.text, "IBAN [IBAN] et carte [card]fin");
        assert_eq!(out.redactions.get("iban"), Some(&1));
        assert_eq!(out.redactions.get("card"), Some(&1));
    }

    #[test]
    fn oversized_text_is_truncated_at_the_documented_cap() {
        let long = "lorem ipsum dolor sit amet ".repeat(200);
        assert!(long.chars().count() > MAX_TEXT_CHARS);
        let req = OzEgressRequest::new(long);
        let out = allowed(oz_guard(&req));
        assert_eq!(out.text.chars().count(), MAX_TEXT_CHARS);
        assert!(out.truncated);
    }

    // ── refusals ──────────────────────────────────────────────────────────

    #[test]
    fn frozen_refuses_before_anything_else_runs() {
        let req = OzEgressRequest::new("perfectly ordinary text").frozen(true);
        assert_eq!(oz_guard(&req).refusal(), Some(OzEgressRefusal::Frozen));
    }

    #[test]
    fn media_bytes_are_refused_outright() {
        let req = OzEgressRequest::new("caption for the attached image").with_media_bytes();
        assert_eq!(oz_guard(&req).refusal(), Some(OzEgressRefusal::MediaBytes));
    }

    #[test]
    fn raw_breach_dumps_are_refused_outright() {
        let req = OzEgressRequest::new("email:pass1,email2:pass2,...").with_raw_breach_dump();
        assert_eq!(
            oz_guard(&req).refusal(),
            Some(OzEgressRefusal::RawBreachRecordDump)
        );
    }

    #[test]
    fn pem_private_key_block_is_refused() {
        let req = OzEgressRequest::new(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----",
        );
        assert_eq!(
            oz_guard(&req).refusal(),
            Some(OzEgressRefusal::CredentialMaterial)
        );
    }

    #[test]
    fn aws_style_access_key_id_is_refused() {
        let req = OzEgressRequest::new("found aws key AKIAIOSFODNN7EXAMPLE in a paste");
        assert_eq!(
            oz_guard(&req).refusal(),
            Some(OzEgressRefusal::CredentialMaterial)
        );
    }

    #[test]
    fn explicit_assignment_with_a_value_is_refused() {
        let req = OzEgressRequest::new("config dump: password=Sup3rSecret!23 follows");
        assert_eq!(
            oz_guard(&req).refusal(),
            Some(OzEgressRefusal::CredentialMaterial)
        );
    }

    #[test]
    fn a_long_high_entropy_token_is_refused() {
        let req = OzEgressRequest::new(
            "leaked string aB3dE9fG1hJ4kL6mN8pQ0rS2tU4vW6xY8zA1bC3 in the paste",
        );
        assert_eq!(
            oz_guard(&req).refusal(),
            Some(OzEgressRefusal::CredentialMaterial)
        );
    }

    // ── do not overreach ─────────────────────────────────────────────────

    #[test]
    fn merely_mentioning_password_in_prose_is_not_refused() {
        let req = OzEgressRequest::new(
            "the account uses a password reset flow before a two-factor prompt",
        );
        assert!(oz_guard(&req).is_allowed());
    }

    #[test]
    fn merely_mentioning_key_in_prose_is_not_refused() {
        let req = OzEgressRequest::new("note: the api key rotation policy changed last month");
        assert!(oz_guard(&req).is_allowed());
    }

    #[test]
    fn plain_hex_hashes_and_uuids_do_not_trip_the_entropy_check() {
        // A HashPayload row and a dedup key both look like this — neither is a credential.
        let req = OzEgressRequest::new(
            "sha256 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d, \
             id 3fa85f64-5717-4562-b3fc-2c963f66afa6",
        );
        assert!(oz_guard(&req).is_allowed());
    }

    // ── no overreach on URLs, the payload this crate is actually made of ──
    //
    // These are verbatim URL shapes returned by tools in `sources/username/`. Every one of
    // them contains a long mixed-case run, and every one must pass: a refusal here is silent
    // to the analyst, so a false positive would present as the layer summary mysteriously
    // never arriving rather than as a visible error.

    #[test]
    fn real_media_and_profile_urls_are_not_mistaken_for_secrets() {
        for url in [
            // Bluesky avatar CDN (bluesky-actor)
            "https://cdn.bsky.app/img/avatar/plain/did:plc:z72i7hdynmk6r22z27h6tvur/bafkreihwihm6kpd6zuwhhlro75p5qks5qtrcu55jp3gddbfjsieiv7wuka@jpeg",
            // Gravatar avatar, a 64-char SHA-256 hex (gravatar-profile)
            "https://0.gravatar.com/avatar/27205e5c51cb03f862138b22bcb5dc20f94a342e744ff6df1b8dc8af3c865109",
            // Mastodon avatar (mastodon-lookup)
            "https://files.mastodon.social/accounts/avatars/000/000/001/original/6b2384b33799a0dd.png",
            // YouTube channel URL — a mixed-case id, the exact shape that motivated
            // excluding `/` and `.` from LONG_TOKEN (youtube-channel)
            "https://www.youtube.com/channel/UCX6OQ3DkcsbYNE6H8uQQuVA",
            "https://yt3.ggpht.com/ytc/AIdro_kX9f2QweRtYuIoPasDfGhJkLzXcVbNm1234567890",
            // A map link (geo_links)
            "https://www.openstreetmap.org/?mlat=48.856600&mlon=2.352200#map=17/48.856600/2.352200",
        ] {
            let req = OzEgressRequest::new(format!("Found a profile at {url} for the handle."));
            assert!(
                oz_guard(&req).is_allowed(),
                "a legitimate URL must never be refused as credential material: {url}"
            );
        }
    }

    #[test]
    fn excluding_slash_and_dot_does_not_stop_catching_a_jwt() {
        // The exclusion must not buy its lower false-positive rate by going blind: a JWT's
        // dot-separated segments each clear the 32-char floor on their own.
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
                   SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let req = OzEgressRequest::new(format!("token {jwt}"));
        assert_eq!(
            oz_guard(&req).refusal(),
            Some(OzEgressRefusal::CredentialMaterial)
        );
    }

    #[test]
    fn a_bare_opaque_secret_is_still_caught() {
        let req = OzEgressRequest::new("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
        assert_eq!(
            oz_guard(&req).refusal(),
            Some(OzEgressRefusal::CredentialMaterial)
        );
    }

    #[test]
    fn a_secret_assigned_inside_a_url_query_is_still_caught() {
        // Excising URLs applies ONLY to the opaque-token heuristic. The high-confidence
        // assignment pattern still scans the full text, so the common real leak — a key
        // handed over as a query parameter — does not slip through the exemption.
        let req = OzEgressRequest::new(
            "fetched https://api.example.com/v1/lookup?api_key=A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
        );
        assert_eq!(
            oz_guard(&req).refusal(),
            Some(OzEgressRefusal::CredentialMaterial)
        );
    }

    #[test]
    fn documents_what_the_url_exemption_gives_up() {
        // This test asserts a KNOWN GAP rather than a desired behaviour, so that the trade is
        // visible and any future tightening breaks here loudly instead of silently. A bare
        // secret sitting in a URL *path* segment, with no `key=` assignment around it, is not
        // detected. See `looks_like_credential_material` for why this was accepted.
        let req = OzEgressRequest::new(
            "reset link https://example.com/reset/A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0",
        );
        assert!(
            oz_guard(&req).is_allowed(),
            "if this now refuses, the URL exemption was tightened — update the module doc's \
             stated gap to match, rather than deleting this test"
        );
    }
}
