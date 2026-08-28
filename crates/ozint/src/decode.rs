//! "What else could this seed be?", answered locally.
//!
//! Before an investigation fires anything, a seed that is *wrapped* — base64 of an email, a
//! percent-encoded handle, a JWT whose payload carries a subject, a punycode domain — should
//! be offered to the analyst as its decoded self. This module does that, entirely offline: no
//! network, no key, no cloud call, and it never decides anything on its own. It produces
//! candidates; `classify` types them; the analyst picks.
//!
//! ## The failure mode this module is built around
//!
//! Decoders are promiscuous. Base64 and hex will happily "decode" arbitrary text into binary
//! noise, and a candidate that reaches the classifier is a candidate the analyst may *search* —
//! spending real quota on an entity that never existed. So every step here has to earn its
//! output twice:
//!
//! 1. **The input must look like that encoding** (alphabet, length, padding, prefix), and
//! 2. **the output must look like text a human wrote** — printable, mostly ASCII, and not the
//!    same string it started from.
//!
//! A decoder that cannot meet both stays silent. The bias is deliberately toward missing a
//! real encoding rather than inventing a plausible-looking one, because a false candidate is
//! indistinguishable from a real finding once it is on screen.
//!
//! ## Chains
//!
//! Encodings nest (base64 of a percent-encoded string is common in URL parameters), so this is
//! a breadth-first walk to [`MAX_DEPTH`] with a visited set. The visited set is not an
//! optimisation: ROT13 is its own inverse, so without it every ROT13 candidate would decode
//! back to the input and then forward again, forever.
//!
//! ## QR, now that bytes ingress exists
//!
//! File upload and media proxying shipped their store half 2026-08-23, so the blocker
//! this module's doc comment used to name is gone. QR is wired at the one seam that makes
//! sense for it: [`prepass`] still takes a `&str`, and when that string is exactly a
//! [`crate::media::is_media_id`]-shaped reference to a *stored image*, the pipeline decodes
//! whatever QR codes the image holds and folds their text back into the same chain-following
//! walk as every other codec — so a QR that encodes base64 that encodes a URL is still found.
//! A bare string is never handed to a QR decoder (there is no such thing — QR needs pixels),
//! and an ordinary seed that happens to look like 64 hex characters but names nothing in the
//! store falls through unchanged, same as today.
//!
//! ## What is deliberately not implemented, and why
//!
//! Ten codecs were scoped. Nine are implemented; one is not, and is reported as an
//! [`UnavailableCodec`] rather than quietly omitted — same reason `relations.rs` closes with a
//! `rules_without_input` block: a list that looks complete must not silently be missing an
//! attempt.
//!
//! - **AES** needs a key. A decrypt with no key is not a decode, and this pipeline is handed a
//!   seed value, never a key. It becomes implementable only if the cockpit grows a place for
//!   an analyst to supply one.
//!
//! The eight string codecs use dependencies this crate already had (`base64`, `idna`,
//! `urlencoding`, `serde_json`); QR uses `image` + `rqrr`, added 2026-08-24. An npm-based stack
//! (`cyberchef`, `morsify`, `entities`, `@paulmillr/qr`, `jimp`) was considered for this
//! pipeline; none of it was needed for any of these nine, and this implementation depends on
//! none of it.

use std::collections::{HashSet, VecDeque};

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::classify;
use crate::media;
use crate::types::OzType;

/// How deep a nested chain is followed. Three covers every real case seen in the wild
/// (base64(url(text)) and friends) and keeps the fan-out bounded: eight codecs at depth 3 is
/// at most a few hundred cheap string operations, all local.
pub const MAX_DEPTH: usize = 3;

/// Longest input this pipeline will look at. A seed is a handle, an address or a token — not a
/// document. Anything larger is not a mis-encoded seed and running eight decoders over it
/// would just be work.
const MAX_INPUT_CHARS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Codec {
    Base64,
    Hex,
    UrlPercent,
    HtmlEntities,
    Rot13,
    Jwt,
    Punycode,
    Morse,
    /// Text read out of a QR code found in a stored image. Never a member of [`Codec::ALL`] —
    /// it needs pixels, not a string, so it is only ever produced by [`prepass`]'s media-id
    /// special case, never by [`apply`].
    Qr,
}

impl Codec {
    pub const fn label(self) -> &'static str {
        match self {
            Codec::Base64 => "base64",
            Codec::Hex => "hex",
            Codec::UrlPercent => "percent-encoding",
            Codec::HtmlEntities => "HTML entities",
            Codec::Rot13 => "ROT13",
            Codec::Jwt => "JWT payload",
            Codec::Punycode => "punycode",
            Codec::Morse => "Morse",
            Codec::Qr => "QR code",
        }
    }

    const ALL: [Codec; 8] = [
        Codec::Base64,
        Codec::Hex,
        Codec::UrlPercent,
        Codec::HtmlEntities,
        Codec::Jwt,
        Codec::Punycode,
        Codec::Morse,
        // Last on purpose: ROT13 accepts any Latin text, so it is the most likely to produce a
        // shrug of a candidate. Ordering does not change what is found, only the order results
        // appear in, and a reader scanning the list should meet the specific codecs first.
        Codec::Rot13,
    ];
}

/// A known codec that this build cannot attempt, and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnavailableCodec {
    pub codec: String,
    pub reason: String,
}

/// One decoded reading of the seed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodeCandidate {
    pub value: String,
    /// Outermost codec first: `[Base64, UrlPercent]` means the input was base64, and what came
    /// out of that was percent-encoded.
    pub chain: Vec<Codec>,
    /// What `classify` makes of the decoded value. The prepass never overrides it.
    pub oz_type: OzType,
    pub confidence: f64,
    /// True when the decoded value classifies to a type with an actual orchestrator behind it.
    /// A decode that lands on a bare name or a directory tile is worth *showing* ("this reads
    /// as `Ada Lovelace`") but is not a lookup anyone can fire.
    pub searchable: bool,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodeReport {
    /// Shortest chain first, so the most likely reading leads.
    pub candidates: Vec<DecodeCandidate>,
    pub unavailable: Vec<UnavailableCodec>,
}

// ─── Plausibility ──────────────────────────────────────────────────────────

/// Whether a decoded string is something a human could have written. Rejects control
/// characters and replacement characters outright, and requires the result to be
/// predominantly printable ASCII — the alternative is offering the analyst a candidate made of
/// mojibake because base64 accepted a string that merely happened to fit its alphabet.
fn looks_like_text(s: &str) -> bool {
    if s.trim().is_empty() {
        return false;
    }
    let mut printable_ascii = 0usize;
    let mut total = 0usize;
    for c in s.chars() {
        total += 1;
        if c == '\u{FFFD}' {
            return false;
        }
        if c.is_control() && c != '\n' && c != '\t' && c != '\r' {
            return false;
        }
        if c.is_ascii_graphic() || c == ' ' {
            printable_ascii += 1;
        }
    }
    // Deliberately generous toward non-ASCII (a decoded name or a punycode domain is often
    // accented or non-Latin) while still refusing a string that is mostly high bytes.
    total > 0 && printable_ascii * 2 >= total
}

// ─── Codecs ────────────────────────────────────────────────────────────────

fn decode_base64(input: &str) -> Option<String> {
    let trimmed = input.trim();
    // Guards, in order of how much noise each one prevents: too short to carry anything;
    // wrong alphabet; and a length that no base64 encoder would ever emit.
    if trimmed.len() < 8 {
        return None;
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '='))
    {
        return None;
    }
    if !trimmed.chars().any(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    let unpadded = trimmed.trim_end_matches('=');
    if unpadded.len() % 4 == 1 {
        return None;
    }

    // Both alphabets, because a seed lifted out of a URL is as likely to be url-safe base64 as
    // standard. Whichever yields readable text first wins; neither is preferred a priori.
    let standard = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(unpadded)
        .ok();
    let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(unpadded)
        .ok();
    for bytes in [standard, url_safe].into_iter().flatten() {
        if let Ok(text) = String::from_utf8(bytes)
            && looks_like_text(&text)
        {
            return Some(text);
        }
    }
    None
}

fn decode_hex(input: &str) -> Option<String> {
    let trimmed = input.trim().strip_prefix("0x").unwrap_or(input.trim());
    if trimmed.len() < 8 || !trimmed.len().is_multiple_of(2) {
        return None;
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..trimmed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    looks_like_text(&text).then_some(text)
}

fn decode_url_percent(input: &str) -> Option<String> {
    if !input.contains('%') && !input.contains('+') {
        return None;
    }
    let decoded = urlencoding::decode(input).ok()?.into_owned();
    (decoded != input && looks_like_text(&decoded)).then_some(decoded)
}

/// Numeric entities plus the handful of named ones that actually appear in scraped profile
/// text. A full named-entity table is a dependency; this covers what a bio or a display name
/// realistically carries, and anything else is simply left alone rather than half-decoded.
fn decode_html_entities(input: &str) -> Option<String> {
    if !input.contains('&') {
        return None;
    }
    const NAMED: &[(&str, char)] = &[
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&apos;", '\''),
        ("&nbsp;", ' '),
    ];

    let mut out = String::with_capacity(input.len());
    let bytes: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut replaced = false;
    'outer: while i < bytes.len() {
        if bytes[i] == '&' {
            let rest: String = bytes[i..].iter().take(12).collect();
            for (name, ch) in NAMED {
                if rest.starts_with(name) {
                    out.push(*ch);
                    i += name.chars().count();
                    replaced = true;
                    continue 'outer;
                }
            }
            if let Some(semi) = rest.find(';')
                && let Some(entity) = rest.get(..=semi)
                && let Some(body) = entity.strip_prefix("&#").and_then(|b| b.strip_suffix(';'))
            {
                let code = match body.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => body.parse::<u32>().ok(),
                };
                if let Some(ch) = code.and_then(char::from_u32) {
                    out.push(ch);
                    i += entity.chars().count();
                    replaced = true;
                    continue 'outer;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }

    (replaced && looks_like_text(&out)).then_some(out)
}

fn decode_rot13(input: &str) -> Option<String> {
    if !input.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let out: String = input
        .chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect();
    (out != input).then_some(out)
}

/// A JWT's *payload*, decoded and pretty-printed. Never verified — this is a decode pass, and
/// claiming a signature check it does not perform would be worse than not looking at all.
fn decode_jwt(input: &str) -> Option<String> {
    let trimmed = input.trim();
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header).ok()?;
    // Without this the pipeline would call any three dot-separated base64ish runs a JWT.
    header.get("alg")?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let text = serde_json::to_string(&payload).ok()?;
    looks_like_text(&text).then_some(text)
}

fn decode_punycode(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if !trimmed.to_ascii_lowercase().contains("xn--") {
        return None;
    }
    let (unicode, result) = idna::domain_to_unicode(trimmed);
    result.ok()?;
    (unicode != trimmed && looks_like_text(&unicode)).then_some(unicode)
}

const MORSE: &[(&str, char)] = &[
    (".-", 'A'),
    ("-...", 'B'),
    ("-.-.", 'C'),
    ("-..", 'D'),
    (".", 'E'),
    ("..-.", 'F'),
    ("--.", 'G'),
    ("....", 'H'),
    ("..", 'I'),
    (".---", 'J'),
    ("-.-", 'K'),
    (".-..", 'L'),
    ("--", 'M'),
    ("-.", 'N'),
    ("---", 'O'),
    (".--.", 'P'),
    ("--.-", 'Q'),
    (".-.", 'R'),
    ("...", 'S'),
    ("-", 'T'),
    ("..-", 'U'),
    ("...-", 'V'),
    (".--", 'W'),
    ("-..-", 'X'),
    ("-.--", 'Y'),
    ("--..", 'Z'),
    ("-----", '0'),
    (".----", '1'),
    ("..---", '2'),
    ("...--", '3'),
    ("....-", '4'),
    (".....", '5'),
    ("-....", '6'),
    ("--...", '7'),
    ("---..", '8'),
    ("----.", '9'),
    (".-.-.-", '.'),
    ("--..--", ','),
    ("..--..", '?'),
    (".--.-.", '@'),
    ("-....-", '-'),
];

fn decode_morse(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if !trimmed
        .chars()
        .all(|c| matches!(c, '.' | '-' | ' ' | '/' | '\n'))
    {
        return None;
    }
    // A lone `...` is "S", and calling that a decoded seed would be noise. Real Morse carries
    // several letters and mixes both symbols.
    if !trimmed.contains('.') || !trimmed.contains('-') {
        return None;
    }
    let mut out = String::new();
    for word in trimmed.split('/') {
        if !out.is_empty() {
            out.push(' ');
        }
        for token in word.split_whitespace() {
            let ch = MORSE
                .iter()
                .find(|(code, _)| *code == token)
                .map(|(_, c)| *c)?;
            out.push(ch);
        }
    }
    (out.chars().filter(|c| !c.is_whitespace()).count() >= 3).then_some(out)
}

fn apply(codec: Codec, input: &str) -> Option<String> {
    match codec {
        Codec::Base64 => decode_base64(input),
        Codec::Hex => decode_hex(input),
        Codec::UrlPercent => decode_url_percent(input),
        Codec::HtmlEntities => decode_html_entities(input),
        Codec::Rot13 => decode_rot13(input),
        Codec::Jwt => decode_jwt(input),
        Codec::Punycode => decode_punycode(input),
        Codec::Morse => decode_morse(input),
        // Never reached: `Qr` is never a member of `Codec::ALL`, so the BFS loop that calls
        // `apply` never dispatches it — QR needs pixels, and is only ever produced by
        // `prepass`'s media-id seam, which calls `decode_qr_image` directly.
        Codec::Qr => None,
    }
}

// ─── QR ──────────────────────────────────────────────────────────────────

/// Every QR code [`crate::media::decode_bounded`] can find in an already-decoded image.
///
/// `rqrr` requires a greyscale image; the colour source is decoded once (under the same
/// dimension/allocation guard [`crate::media::thumbnail`] uses — a QR decoder is still a
/// decoder, and gets no exemption from the decompression-bomb guard) and converted with
/// [`image::DynamicImage::to_luma8`]. Multiple codes in one image all come back; an image
/// with none returns an empty, non-error, vector — "no QR here" is not a failure.
fn decode_qr_image(bytes: &[u8], mime: &str) -> Vec<String> {
    let Ok(decoded) = media::decode_bounded(bytes, mime) else {
        return Vec::new();
    };
    let mut prepared = rqrr::PreparedImage::prepare(decoded.to_luma8());
    prepared
        .detect_grids()
        .iter()
        .filter_map(|grid| grid.decode().ok())
        .map(|(_meta, content)| content)
        .collect()
}

// ─── The pipeline ──────────────────────────────────────────────────────────

/// Every reading of `input` this build can produce locally, plus what it could not attempt.
///
/// Purely local and side-effect free: no network, no key, no cloud call, nothing persisted.
/// (Reading an already-ingressed file back out of [`crate::media`]'s local store is not a
/// network call — the byte ingress itself happened, and was screened, elsewhere.) The
/// classifier types each candidate; this function never overrides it.
pub fn prepass(input: &str) -> DecodeReport {
    let trimmed = input.trim();

    // The one seam where a `&str` seed can mean "read these bytes": a media id naming a
    // stored image. Every QR text found is seeded into the same walk any other codec output
    // joins, at chain `[Qr]`, so a QR that encodes (say) base64 is still followed.
    let mut extra_seeds = Vec::new();
    if media::is_media_id(trimmed)
        && let Ok(Some((meta, bytes))) = media::load(trimmed)
        && meta.is_image()
    {
        for text in decode_qr_image(&bytes, &meta.mime) {
            extra_seeds.push((text, vec![Codec::Qr]));
        }
    }

    walk(input, extra_seeds)
}

/// The codec breadth-first walk, taking `extra_seeds` — readings of `input` found outside the
/// string-codec loop below (today, only QR text) — as already-decoded first-generation
/// results: each is reported as a candidate and queued so anything nested inside it is still
/// found, exactly as a string codec's own output would be.
///
/// Factored out of [`prepass`] so the QR seam can be exercised directly against explicit bytes
/// in tests, without going through [`crate::media`]'s process-global data directory.
fn walk(input: &str, extra_seeds: Vec<(String, Vec<Codec>)>) -> DecodeReport {
    let mut report = DecodeReport {
        candidates: Vec::new(),
        unavailable: unavailable(),
    };
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_INPUT_CHARS {
        return report;
    }

    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(trimmed.to_string());

    let mut queue: VecDeque<(String, Vec<Codec>)> = VecDeque::new();
    queue.push_back((trimmed.to_string(), Vec::new()));

    for (text, chain) in extra_seeds {
        if !seen.insert(text.clone()) {
            continue;
        }
        let classification = classify::classify(&text);
        report.candidates.push(DecodeCandidate {
            value: text.clone(),
            chain: chain.clone(),
            oz_type: classification.oz_type,
            confidence: classification.confidence,
            searchable: !classification.oz_type.is_directory_only(),
        });
        queue.push_back((text, chain));
    }

    while let Some((value, chain)) = queue.pop_front() {
        if chain.len() >= MAX_DEPTH {
            continue;
        }
        for codec in Codec::ALL {
            let Some(decoded) = apply(codec, &value) else {
                continue;
            };
            // ROT13 is its own inverse and percent-decoding is idempotent; without this the
            // walk would keep rediscovering strings it has already reported.
            if !seen.insert(decoded.clone()) {
                continue;
            }
            let mut next_chain = chain.clone();
            next_chain.push(codec);

            let classification = classify::classify(&decoded);
            report.candidates.push(DecodeCandidate {
                value: decoded.clone(),
                chain: next_chain.clone(),
                oz_type: classification.oz_type,
                confidence: classification.confidence,
                searchable: !classification.oz_type.is_directory_only(),
            });
            queue.push_back((decoded, next_chain));
        }
    }

    // Shortest chain first: one decode is a likelier reading of a seed than three, and the
    // analyst should meet the plain answer before the elaborate one.
    report.candidates.sort_by(|a, b| {
        a.chain
            .len()
            .cmp(&b.chain.len())
            .then_with(|| a.value.cmp(&b.value))
    });
    report
}

fn unavailable() -> Vec<UnavailableCodec> {
    vec![UnavailableCodec {
        codec: "AES".into(),
        reason: "needs a key, and this pipeline is only ever handed a seed value — a decrypt without a key is not a decode".into(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(report: &DecodeReport) -> Vec<&str> {
        report.candidates.iter().map(|c| c.value.as_str()).collect()
    }

    // ── Individual codecs ──────────────────────────────────────────────────

    #[test]
    fn base64_of_an_email_decodes_and_classifies() {
        let report = prepass("bXRyZWJvc2NAZXhhbXBsZS5jb20=");
        let hit = report
            .candidates
            .iter()
            .find(|c| c.value == "mtrebosc@example.com")
            .expect("the email must be found");
        assert_eq!(hit.chain, vec![Codec::Base64]);
        assert_eq!(
            hit.oz_type,
            OzType::Email,
            "the classifier types it, not this module"
        );
        assert!(hit.searchable);
    }

    #[test]
    fn hex_decodes_only_from_a_clean_hex_string() {
        let report = prepass("6d747265626f7363");
        assert!(values(&report).contains(&"mtrebosc"));
    }

    #[test]
    fn percent_encoding_round_trips() {
        let report = prepass("mtrebosc%40example.com");
        assert!(values(&report).contains(&"mtrebosc@example.com"));
    }

    #[test]
    fn html_entities_decode_named_and_numeric_forms() {
        let report = prepass("Ada &amp; Grace &#76;ovelace &#x4C;td");
        assert!(
            values(&report)
                .iter()
                .any(|v| v.contains("Ada & Grace Lovelace Ltd")),
            "{:?}",
            values(&report)
        );
    }

    #[test]
    fn rot13_is_offered() {
        let report = prepass("zgerobfp");
        assert!(values(&report).contains(&"mtrebosc"));
    }

    #[test]
    fn a_jwt_yields_its_payload_but_is_never_verified() {
        // {"alg":"HS256","typ":"JWT"} . {"sub":"mtrebosc@example.com"} . <not a real signature>
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtdHJlYm9zY0BleGFtcGxlLmNvbSJ9.bm90LWEtcmVhbC1zaWduYXR1cmU";
        let report = prepass(jwt);
        assert!(
            report
                .candidates
                .iter()
                .any(|c| c.chain.first() == Some(&Codec::Jwt)
                    && c.value.contains("mtrebosc@example.com")),
            "{:?}",
            values(&report)
        );
    }

    #[test]
    fn three_dot_separated_runs_are_not_automatically_a_jwt() {
        // No `alg` in the first segment: this is not a JWT, and calling it one would put a
        // fabricated payload in front of the analyst.
        assert_eq!(decode_jwt("aGVsbG8.d29ybGQ.dGhpcmQ"), None);
    }

    #[test]
    fn punycode_becomes_its_unicode_domain() {
        let report = prepass("xn--bcher-kva.example");
        assert!(
            values(&report).iter().any(|v| v.starts_with("bücher")),
            "{:?}",
            values(&report)
        );
    }

    #[test]
    fn morse_needs_more_than_one_letter_and_both_symbols() {
        assert_eq!(
            decode_morse("..."),
            None,
            "a lone S is noise, not a decoded seed"
        );
        assert_eq!(decode_morse("....."), None);
        assert_eq!(
            decode_morse(".... . .-.. .--. -- ."),
            Some("HELPME".to_string())
        );
    }

    // ── The anti-garbage guard ─────────────────────────────────────────────

    #[test]
    fn a_plain_handle_is_not_tortured_into_a_fake_decoding() {
        // The property the whole module rests on: an ordinary seed must not sprout candidates.
        // A false candidate is indistinguishable from a real finding once it is on screen, and
        // searching it spends real quota on an entity that never existed.
        let report = prepass("mtrebosc");
        assert!(
            report
                .candidates
                .iter()
                .all(|c| c.chain != vec![Codec::Base64]),
            "base64 must not claim a plain handle: {:?}",
            values(&report)
        );
        assert!(
            report
                .candidates
                .iter()
                .all(|c| c.chain != vec![Codec::Hex])
        );
    }

    #[test]
    fn base64_that_decodes_to_binary_noise_is_rejected() {
        // Valid base64, but the bytes are not text. Offering the mojibake would be worse than
        // offering nothing.
        let noise = base64::engine::general_purpose::STANDARD_NO_PAD
            .encode([0xff, 0xfe, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(decode_base64(&noise), None);
    }

    #[test]
    fn an_email_is_never_read_as_hex_or_base64() {
        assert_eq!(decode_hex("mtrebosc@example.com"), None);
        assert_eq!(decode_base64("mtrebosc@example.com"), None);
    }

    #[test]
    fn html_entity_decoding_leaves_unknown_entities_alone_rather_than_half_decoding() {
        // `&hearts;` is not in the small named table; the string must come back untouched
        // instead of losing the entity.
        assert_eq!(decode_html_entities("Ada &hearts; Grace"), None);
    }

    // ── Chains and termination ─────────────────────────────────────────────

    #[test]
    fn a_nested_encoding_is_followed_and_reports_its_chain() {
        // base64( "mtrebosc%40example.com" )
        let nested =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode("mtrebosc%40example.com");
        let report = prepass(&nested);
        let hit = report
            .candidates
            .iter()
            .find(|c| c.value == "mtrebosc@example.com")
            .expect("the two-layer reading must be found");
        assert_eq!(
            hit.chain,
            vec![Codec::Base64, Codec::UrlPercent],
            "outermost codec first"
        );
    }

    #[test]
    fn rot13_being_its_own_inverse_does_not_loop() {
        // Without the visited set this walk never terminates.
        let report = prepass("uryyb jbeyq");
        assert!(values(&report).contains(&"hello world"));
        assert!(
            report.candidates.iter().all(|c| c.value != "uryyb jbeyq"),
            "the input is not a candidate"
        );
        assert!(
            report.candidates.len() < 50,
            "an unbounded walk would produce far more"
        );
    }

    #[test]
    fn candidates_are_shortest_chain_first() {
        let nested =
            base64::engine::general_purpose::STANDARD_NO_PAD.encode("mtrebosc%40example.com");
        let report = prepass(&nested);
        let lengths: Vec<usize> = report.candidates.iter().map(|c| c.chain.len()).collect();
        let mut sorted = lengths.clone();
        sorted.sort_unstable();
        assert_eq!(lengths, sorted);
    }

    #[test]
    fn no_chain_ever_exceeds_the_depth_cap() {
        let nested = base64::engine::general_purpose::STANDARD_NO_PAD.encode(
            base64::engine::general_purpose::STANDARD_NO_PAD.encode("mtrebosc%40example.com"),
        );
        let report = prepass(&nested);
        assert!(report.candidates.iter().all(|c| c.chain.len() <= MAX_DEPTH));
    }

    #[test]
    fn an_empty_or_oversized_input_produces_nothing() {
        assert!(prepass("   ").candidates.is_empty());
        assert!(
            prepass(&"a".repeat(MAX_INPUT_CHARS + 1))
                .candidates
                .is_empty()
        );
    }

    // ── Honesty about what is missing ──────────────────────────────────────

    #[test]
    fn the_one_unbuildable_codec_is_always_declared() {
        // A results list looks the same whether AES found nothing or was never attempted.
        let report = prepass("mtrebosc");
        let named: Vec<&str> = report
            .unavailable
            .iter()
            .map(|u| u.codec.as_str())
            .collect();
        assert_eq!(
            named,
            vec!["AES"],
            "QR is implemented now — only AES stays unavailable"
        );
        assert!(report.unavailable.iter().all(|u| !u.reason.is_empty()));
    }

    #[test]
    fn a_decode_landing_on_a_bare_name_is_shown_but_not_searchable() {
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode("Ada Lovelace");
        let report = prepass(&encoded);
        let hit = report
            .candidates
            .iter()
            .find(|c| c.value == "Ada Lovelace")
            .expect("found");
        assert_eq!(hit.oz_type, OzType::Name);
        assert!(!hit.searchable, "a bare name has no orchestrator to fire");
    }

    // ── QR ────────────────────────────────────────────────────────────────

    /// A real QR PNG generated with `qrcode` (Python), encoding
    /// `https://example.com/mtrebosc` — not a hand-assembled fixture, so this exercises the
    /// same bit pattern a phone-scanned QR would produce.
    const QR_PNG: &[u8] = include_bytes!("../testdata/qr_url.png");

    #[test]
    fn a_real_qr_image_decodes_to_its_encoded_text() {
        let texts = decode_qr_image(QR_PNG, "image/png");
        assert_eq!(texts, vec!["https://example.com/mtrebosc".to_string()]);
    }

    #[test]
    fn an_image_with_no_qr_code_yields_no_candidates_and_no_error() {
        // The one-pixel PNG from `media`'s own tests: a valid image, no QR in it.
        const PNG: &[u8] = &[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78,
            0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
        ];
        assert!(decode_qr_image(PNG, "image/png").is_empty());
    }

    #[test]
    fn non_image_bytes_never_reach_the_qr_decoder() {
        assert!(decode_qr_image(b"not an image at all", "text/plain").is_empty());
        assert!(decode_qr_image(b"<html></html>", "text/html").is_empty());
    }

    #[test]
    fn a_qr_seed_is_reported_at_chain_qr_and_further_encodings_inside_it_are_still_found() {
        // `walk` is what `prepass`'s media-id branch calls into; exercised directly here so
        // the QR-to-store wiring is testable without touching the process-global data dir.
        let texts = decode_qr_image(QR_PNG, "image/png");
        let extra_seeds: Vec<(String, Vec<Codec>)> =
            texts.into_iter().map(|t| (t, vec![Codec::Qr])).collect();
        let report = walk("irrelevant-seed-value", extra_seeds);

        let hit = report
            .candidates
            .iter()
            .find(|c| c.value == "https://example.com/mtrebosc")
            .expect("the QR's own text must be a candidate");
        assert_eq!(hit.chain, vec![Codec::Qr]);
        assert_eq!(
            hit.oz_type,
            classify::classify("https://example.com/mtrebosc").oz_type,
            "the classifier types the QR text exactly as it would type the same string elsewhere"
        );
    }

    #[test]
    fn a_media_id_naming_nothing_in_the_store_is_a_harmless_passthrough() {
        // No store entry exists for this hash (it is not derived from any real bytes), so
        // `prepass` must behave exactly as it does for any other plain string: no panic, no
        // QR candidates, string codecs still run.
        let report = prepass(&"0".repeat(64));
        assert!(report.candidates.iter().all(|c| c.chain != vec![Codec::Qr]));
    }
}
