//! Classifies a raw seed string into `{ oz_type, normalized_value, confidence, method,
//! alternates }`.
//!
//! **Deterministic-first.** [`classify`] resolves almost everything by shape alone (an `@`
//! plus a dotted domain is an email, `IpAddr` either parses or it doesn't, 32/40/64 hex chars
//! is a hash, `CVE-\d{4}-\d{4,}` is a CVE, a leading `+` with digits is a phone, two
//! comma-separated decimals in range are coordinates, a dotted label with a plausible TLD is a
//! domain, a leading `@` or a bare word is a username) and never touches the network. Actual
//! per-type validity comes entirely from [`crate::normalize::normalize`] — this module only
//! decides *which* type to hand it, it does not re-validate anything normalize already does.
//!
//! **The LLM tier ([`classify_with_llm`]) is the exception, not the default path**, fired only
//! when the deterministic guess is genuinely ambiguous (see [`CONFIDENCE_CUTOFF`] /
//! [`ALTERNATE_MARGIN`] below). It degrades honestly: an absent/erroring/unparseable LLM never
//! gets to overwrite a deterministic result with a fake "LLM-confirmed" label — see
//! [`ClassifyMethod::DeterministicFallback`].
//!
//! ## The personal-name / DIR open question, resolved
//!
//! Whether "personal name → DIR" should *always* defer to the LLM tier was an open design
//! question, since a
//! two-word company name and a two-word person name are indistinguishable by shape. Decision
//! made here: **yes, exactly the one case where free-text input matches no machine-resolvable
//! shape (multi-word, not a phone/coordinate) is the sole case that is genuinely ambiguous by
//! construction** — there is no regex to write that would improve on a coin flip between
//! `OzType::Name` and `OzType::Directory`. The deterministic tier still must return *something*
//! usable when no LLM is wired up (this classifier degrades honestly, never blocks), so it picks
//! [`OzType::Name`] as the default guess — matching `types.rs`'s own doc comment that a bare
//! name "falls back to DIR" at dispatch time — with [`OzType::Directory`] listed as the
//! close alternate. Both are covered by `OzType::is_directory_only()` downstream, so a wrong
//! deterministic guess here costs a display label, not a broken orchestrator dispatch.
//!
//! ## Locked rule — restated here because it is easy to violate by accident
//!
//! **This classifier must only ever be invoked from the Autofire button handler, never from an
//! `onChange`/`onKeyDown` live-typing handler.** "No live feedback while typing" is a locked
//! decision; a caller that runs [`classify`] or [`classify_with_llm`] per keystroke violates it
//! even though nothing in this module's signature prevents that call pattern.
//!
//! ## Out of scope
//!
//! File inputs (image/video/hash-file uploads) belong to
//! the file-upload path, a different unit. This module classifies **strings** only; it never
//! returns `OzType::Image`/`OzType::Video` because there is no string-only shape signal that
//! distinguishes "this is a media reference" from a generic domain/hash/username — that
//! distinction requires the actual bytes or a dedicated upload path, not a classifier over text.

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::normalize::normalize;
use crate::types::OzType;

// ─── Tunable thresholds — picked defaults, not measured ────────────────────────────────────
//
// Both of these are picked defaults, not measured against real fixtures — tuning them against
// real data is still open. They are named constants here specifically so that stays true in
// code, not just prose.

/// Below this confidence, a classification is not presented as confident on its own and — when
/// an LLM tier is available — gets escalated to it. **Picked, not measured.**
pub const CONFIDENCE_CUTOFF: f64 = 0.7;

/// How close a runner-up alternate's confidence must be to the winner's to count as a genuine
/// tie — close enough that even a winner clearing [`CONFIDENCE_CUTOFF`] on its own still gets
/// escalated to the LLM tier when available. **Picked, not measured.**
pub const ALTERNATE_MARGIN: f64 = 0.2;

/// Confidence for a shape with no plausible competing type: email, IP, phone, coordinate, CVE,
/// or a bare single token once nothing more specific matched. Picked, not measured.
const CONFIDENCE_UNAMBIGUOUS: f64 = 0.95;

/// Confidence for the winning type in the two shapes that are genuinely ambiguous by design
/// (domain vs. username, hash vs. username) — high enough to resolve without an LLM
/// call (deterministic-first resolves "almost everything"), but short of
/// [`CONFIDENCE_UNAMBIGUOUS`] since a second reading genuinely exists. Picked, not measured.
const CONFIDENCE_STRONG_PRIMARY: f64 = 0.9;

/// Confidence for the secondary reading in those same two cases. Picked, not measured.
const CONFIDENCE_WEAK_ALTERNATE: f64 = 0.3;

/// Confidence for the deterministic-only guess on multi-word free text — the one case with
/// genuinely nothing for a shape rule to grip (see the module doc's "personal name / DIR"
/// section). Deliberately below [`CONFIDENCE_CUTOFF`] so it always escalates when an LLM is
/// available. Picked, not measured.
const CONFIDENCE_FREE_TEXT: f64 = 0.35;

/// Confidence for `Directory` as the alternate reading of free text. Picked, not measured.
const CONFIDENCE_FREE_TEXT_ALTERNATE: f64 = 0.3;

/// Confidence assigned when a shape-matched candidate fails its own normalizer. Deliberately
/// far below [`CONFIDENCE_CUTOFF`] so an invalid value is never presented as a confident answer
/// of the wrong (or any) type — see `Classification::valid`. Picked, not measured.
const CONFIDENCE_INVALID: f64 = 0.05;

/// Confidence used when the LLM tier resolves ambiguity but its reply carries no numeric
/// confidence of its own. Picked, not measured.
const CONFIDENCE_LLM_RESOLVED: f64 = 0.85;

// ─── Public shape ────────────────────────────────────────────────────────────────────────────

/// One other type that plausibly matches the same raw value, alongside the winning
/// [`Classification::oz_type`]. The consumer needs to see the ambiguity, not just the winner.
#[derive(Debug, Clone, PartialEq)]
pub struct Alternate {
    pub oz_type: OzType,
    pub confidence: f64,
}

/// How a [`Classification`] was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifyMethod {
    /// Resolved by shape rules alone; no LLM was consulted (either because the deterministic
    /// guess was confident enough, or because [`classify`] — the sync, LLM-free entry point —
    /// was called directly).
    Deterministic,
    /// The deterministic guess was ambiguous and an LLM tier resolved it.
    Llm,
    /// The deterministic guess was ambiguous, an LLM tier was consulted, and it errored or
    /// returned something unparseable. The result is the deterministic guess, unchanged — this
    /// variant exists so a caller can tell "resolved by shape" apart from "wanted to ask an
    /// LLM, couldn't, fell back" without either case silently masquerading as the other.
    DeterministicFallback,
    /// **No classification happened.** The analyst set the type explicitly in the search bar's
    /// selector and this classifier was bypassed — the type selector replaces the classifier
    /// rather than biasing it. It is a separate variant rather than a
    /// `Deterministic` with confidence `1.0` because the two are opposite claims: one says the
    /// shape rules resolved it, the other says nobody looked at the shape at all. The value is
    /// still normalized against the chosen type, so `valid`/`note` remain a real verdict on
    /// whether the analyst's choice actually parses.
    AnalystForced,
}

/// Result of classifying one raw string.
#[derive(Debug, Clone, PartialEq)]
pub struct Classification {
    pub oz_type: OzType,
    /// The winning type's normalized display form (`Normalized::display`) — or, when `valid`
    /// is false, the raw input echoed back verbatim (`Normalized::invalid`'s convention).
    pub normalized_value: String,
    pub confidence: f64,
    pub method: ClassifyMethod,
    pub alternates: Vec<Alternate>,
    /// Whether `oz_type`'s normalizer actually accepted the value. `false` means: this is the
    /// best shape/LLM guess, but the value itself doesn't parse as that type — callers must not
    /// treat a `false` result as a confident classification of anything.
    pub valid: bool,
    /// The normalizer's rejection reason when `valid` is false, or a caveat note when true
    /// (e.g. hash's "classified as MD5"). Verbatim from `normalize()`.
    pub note: Option<String>,
}

/// Injection point for an optional LLM classification tier — a "define the trait and prompt
/// here, implement it against a concrete client one layer up" seam: this crate defines
/// the trait and the prompt, a higher layer (`ozint-server`) implements it against the ported
/// the LLM client. `ozint` never depends on an LLM client crate directly.
#[async_trait]
pub trait ClassifierLlm: Send + Sync {
    async fn complete(&self, system: &str, user: &str) -> anyhow::Result<String>;
}

/// System prompt for the LLM tier. Requests a bare JSON object so the tolerant local parser
/// below (a small local reimplementation, kept local rather than pulled in as a dependency —
/// see the module doc on cross-crate dependencies) can extract it even through a
/// markdown-fenced or prose-wrapped reply.
pub const SYSTEM_PROMPT: &str = r#"You are an OSINT investigation input classifier. An analyst typed one raw seed value into a search box. A deterministic shape-based pass already ran and found more than one plausible type for it. Decide which single type is the best read.

Respond with ONLY a JSON object, no surrounding text or markdown fences:
{ "type": "<one of: username, email, phone, ip, domain, hash, image, video, coordinate, cve, directory, name>", "confidence": <0.0-1.0> }

"directory" means the value reads as a company, product, or other non-person entity that should launch a directory/aggregator search. "name" means it reads as a specific individual's personal name. Never invent a type outside the list."#;

/// Classify `raw` using deterministic shape rules only. Never calls out, never fails — always
/// returns a usable [`Classification`], even for garbage or empty input.
///
/// **Locked rule: call this (or [`classify_with_llm`]) only from the Autofire button
/// handler — never from `onChange`/`onKeyDown`.** See the module doc.
pub fn classify(raw: &str) -> Classification {
    build_deterministic(raw)
}

/// The analyst chose the type themself: normalize `raw` against `oz_type` and report it as
/// [`ClassifyMethod::AnalystForced`], consulting neither the shape rules nor the LLM tier.
///
/// This is the search bar's type selector when it is set to anything but *auto*.
/// It exists as its own entry point rather than a flag on [`classify`] so that a forced type can
/// never be quietly downgraded into a classifier verdict on its way through: there is no code
/// path here that could return a type other than the one it was handed.
///
/// **`alternates` is empty and `confidence` is `1.0` by construction.** Not a measurement — the
/// analyst asserted the type, so there is nothing to be uncertain between. `valid` and `note`
/// are still the normalizer's honest verdict, so forcing `Ip` on `not-an-ip` yields a forced
/// classification that says plainly it does not parse.
pub fn classify_forced(raw: &str, oz_type: OzType) -> Classification {
    let normalized = normalize(oz_type, raw.trim());
    Classification {
        oz_type,
        normalized_value: normalized.display,
        confidence: 1.0,
        method: ClassifyMethod::AnalystForced,
        alternates: Vec::new(),
        valid: normalized.valid,
        note: normalized.note,
    }
}

/// Classify `raw`, escalating to `llm` when the deterministic guess is genuinely ambiguous
/// (see [`CONFIDENCE_CUTOFF`] / [`ALTERNATE_MARGIN`]). Falls back to the deterministic result —
/// tagged [`ClassifyMethod::DeterministicFallback`], never silently presented as LLM-confirmed —
/// on any LLM error or unparseable reply.
///
/// **Locked rule: call this only from the Autofire button handler.** See the module doc.
pub async fn classify_with_llm(raw: &str, llm: &dyn ClassifierLlm) -> Classification {
    let deterministic = build_deterministic(raw);
    if !is_ambiguous(&deterministic) {
        return deterministic;
    }

    let user_prompt = build_user_prompt(raw, &deterministic);
    let reply = match llm.complete(SYSTEM_PROMPT, &user_prompt).await {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "ozint classifier: LLM tier errored, falling back to the deterministic result"
            );
            return Classification {
                method: ClassifyMethod::DeterministicFallback,
                ..deterministic
            };
        }
    };

    let Some((llm_type, llm_confidence)) = parse_llm_classification(&reply) else {
        tracing::warn!(
            "ozint classifier: LLM tier returned an unparseable reply, falling back to the \
             deterministic result"
        );
        return Classification {
            method: ClassifyMethod::DeterministicFallback,
            ..deterministic
        };
    };

    let normalized = normalize(llm_type, raw);
    let mut alternates = Vec::new();
    if deterministic.oz_type != llm_type {
        alternates.push(Alternate {
            oz_type: deterministic.oz_type,
            confidence: deterministic.confidence,
        });
    }
    for a in &deterministic.alternates {
        if a.oz_type != llm_type {
            alternates.push(a.clone());
        }
    }

    Classification {
        oz_type: llm_type,
        normalized_value: normalized.display,
        confidence: llm_confidence.unwrap_or(CONFIDENCE_LLM_RESOLVED),
        method: ClassifyMethod::Llm,
        alternates,
        valid: normalized.valid,
        note: normalized.note,
    }
}

// ─── Deterministic tier ──────────────────────────────────────────────────────────────────────

fn build_deterministic(raw: &str) -> Classification {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        // Nothing to grip at all. Route through the username normalizer purely to get a
        // consistent `Normalized::invalid` shape (echoed input + a real rejection reason)
        // instead of hand-rolling a second "invalid" representation here.
        let normalized = normalize(OzType::Username, trimmed);
        return Classification {
            oz_type: OzType::Username,
            normalized_value: normalized.display,
            confidence: CONFIDENCE_INVALID,
            method: ClassifyMethod::Deterministic,
            alternates: Vec::new(),
            valid: normalized.valid,
            note: normalized.note,
        };
    }

    let (primary, alt_guesses) = pick_shape(trimmed);
    let normalized = normalize(primary.oz_type, raw);
    let confidence = if normalized.valid {
        primary.confidence
    } else {
        CONFIDENCE_INVALID
    };
    let alternates = alt_guesses
        .into_iter()
        .map(|g| Alternate {
            oz_type: g.oz_type,
            confidence: g.confidence,
        })
        .collect();

    Classification {
        oz_type: primary.oz_type,
        normalized_value: normalized.display,
        confidence,
        method: ClassifyMethod::Deterministic,
        alternates,
        valid: normalized.valid,
        note: normalized.note,
    }
}

struct ShapeGuess {
    oz_type: OzType,
    confidence: f64,
}

/// Pick a primary type (plus zero or more alternates) by shape alone. Order matters: earlier
/// checks are shapes that are unambiguous by construction, so they win outright over later,
/// looser ones.
/// `normalize()` still gets the final say on whether the picked type actually validates —
/// this function only decides *which* type to try.
fn pick_shape(trimmed: &str) -> (ShapeGuess, Vec<ShapeGuess>) {
    if looks_like_cve(trimmed) {
        return (
            ShapeGuess {
                oz_type: OzType::Cve,
                confidence: CONFIDENCE_UNAMBIGUOUS,
            },
            Vec::new(),
        );
    }
    if looks_like_email(trimmed) {
        return (
            ShapeGuess {
                oz_type: OzType::Email,
                confidence: CONFIDENCE_UNAMBIGUOUS,
            },
            Vec::new(),
        );
    }
    if looks_like_ip(trimmed) {
        return (
            ShapeGuess {
                oz_type: OzType::Ip,
                confidence: CONFIDENCE_UNAMBIGUOUS,
            },
            Vec::new(),
        );
    }
    if looks_like_phone(trimmed) {
        return (
            ShapeGuess {
                oz_type: OzType::Phone,
                confidence: CONFIDENCE_UNAMBIGUOUS,
            },
            Vec::new(),
        );
    }
    if looks_like_coordinate(trimmed) {
        return (
            ShapeGuess {
                oz_type: OzType::Coordinate,
                confidence: CONFIDENCE_UNAMBIGUOUS,
            },
            Vec::new(),
        );
    }
    // The two shapes that are genuinely ambiguous: a strong primary reading plus a
    // weak-but-real "could also be a username" alternate.
    if looks_like_hash(trimmed) {
        return (
            ShapeGuess {
                oz_type: OzType::Hash,
                confidence: CONFIDENCE_STRONG_PRIMARY,
            },
            vec![ShapeGuess {
                oz_type: OzType::Username,
                confidence: CONFIDENCE_WEAK_ALTERNATE,
            }],
        );
    }
    if looks_like_domain(trimmed) {
        return (
            ShapeGuess {
                oz_type: OzType::Domain,
                confidence: CONFIDENCE_STRONG_PRIMARY,
            },
            vec![ShapeGuess {
                oz_type: OzType::Username,
                confidence: CONFIDENCE_WEAK_ALTERNATE,
            }],
        );
    }
    // Multi-word free text matching none of the above: the one honest LLM case (see the module
    // doc). Default to Name with Directory as the close alternate rather than blocking.
    if trimmed.split_whitespace().count() > 1 {
        return (
            ShapeGuess {
                oz_type: OzType::Name,
                confidence: CONFIDENCE_FREE_TEXT,
            },
            vec![ShapeGuess {
                oz_type: OzType::Directory,
                confidence: CONFIDENCE_FREE_TEXT_ALTERNATE,
            }],
        );
    }
    // A bare single token that matched nothing more specific: a handle is the only remaining
    // plausible read, and — having ruled out every other shape — an unambiguous one.
    (
        ShapeGuess {
            oz_type: OzType::Username,
            confidence: CONFIDENCE_UNAMBIGUOUS,
        },
        Vec::new(),
    )
}

fn looks_like_cve(s: &str) -> bool {
    s.to_ascii_lowercase().starts_with("cve-")
}

fn looks_like_email(s: &str) -> bool {
    match s.rfind('@') {
        Some(pos) => s[pos + 1..].contains('.'),
        None => false,
    }
}

fn looks_like_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn looks_like_phone(s: &str) -> bool {
    s.starts_with('+') && s.chars().skip(1).any(|c| c.is_ascii_digit())
}

fn looks_like_coordinate(s: &str) -> bool {
    // A degree sign is a strong enough DMS signal on its own — let normalize()'s DMS parser do
    // the real work rather than duplicating its regex here.
    if s.contains('°') {
        return true;
    }
    let parts: Vec<&str> = s.split(',').map(str::trim).collect();
    parts.len() == 2 && parts.iter().all(|p| p.parse::<f64>().is_ok())
}

fn looks_like_hash(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_domain(s: &str) -> bool {
    if s.contains('@') || s.chars().any(char::is_whitespace) || s.starts_with('+') {
        return false;
    }
    let host = s.trim_end_matches('.');
    if host.is_empty() || host.starts_with('.') || !host.contains('.') {
        return false;
    }
    let Some(tld) = host.rsplit('.').next() else {
        return false;
    };
    tld.len() >= 2
        && tld.chars().all(|c| c.is_ascii_alphanumeric())
        && host.split('.').all(|label| !label.is_empty())
}

// ─── LLM tier plumbing ───────────────────────────────────────────────────────────────────────

/// Whether `c` is ambiguous enough to escalate to the LLM tier: either the winner itself isn't
/// confident enough ([`CONFIDENCE_CUTOFF`]), or a runner-up is close enough to be a genuine
/// contest ([`ALTERNATE_MARGIN`]) even though the winner alone would clear the cutoff.
fn is_ambiguous(c: &Classification) -> bool {
    if c.confidence < CONFIDENCE_CUTOFF {
        return true;
    }
    c.alternates
        .iter()
        .any(|a| a.confidence >= c.confidence - ALTERNATE_MARGIN)
}

fn build_user_prompt(raw: &str, det: &Classification) -> String {
    let mut candidates = vec![format!(
        "{} (confidence {:.2})",
        type_kebab(det.oz_type),
        det.confidence
    )];
    for a in &det.alternates {
        candidates.push(format!(
            "{} (confidence {:.2})",
            type_kebab(a.oz_type),
            a.confidence
        ));
    }
    format!(
        "Raw value: {raw:?}\nShape-based candidates, most to least likely: {}\nWhich type is correct?",
        candidates.join(", ")
    )
}

/// Kebab-case wire form of an `OzType`, read off its own `Serialize` impl so this can never
/// drift from what the type actually serializes to. Small enough to duplicate locally rather
/// than making `normalize.rs`'s private helper of the same shape `pub(crate)`.
fn type_kebab(oz_type: OzType) -> String {
    match serde_json::to_value(oz_type) {
        Ok(Value::String(s)) => s,
        _ => unreachable!("OzType always serializes to a bare kebab-case string"),
    }
}

/// Tolerant extraction of `{"type": ..., "confidence": ...}` from a raw LLM reply — strips a
/// ```` ``` ```` / ` ```json ` fence and grabs the outermost `{...}`. Deliberately a small
/// local reimplementation rather than an import: this crate must not take a dependency on an
/// LLM-facing crate just to reuse a parser.
fn extract_json_object(raw: &str) -> Option<Map<String, Value>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let stripped = if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("```json") {
        &trimmed[7..]
    } else if let Some(rest) = trimmed.strip_prefix("```") {
        rest
    } else {
        trimmed
    };
    let stripped = stripped.strip_suffix("```").unwrap_or(stripped);

    let start = stripped.find('{')?;
    let end = stripped.rfind('}')?;
    if end <= start {
        return None;
    }
    match serde_json::from_str::<Value>(&stripped[start..=end]) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

fn parse_llm_classification(raw: &str) -> Option<(OzType, Option<f64>)> {
    let map = extract_json_object(raw)?;
    let type_str = map.get("type")?.as_str()?;
    let oz_type: OzType = serde_json::from_value(Value::String(type_str.to_string())).ok()?;
    let confidence = map
        .get("confidence")
        .and_then(Value::as_f64)
        .map(|c| c.clamp(0.0, 1.0));
    Some((oz_type, confidence))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ─── Unambiguous, per type ────────────────────────────────────────────────────────────

    #[test]
    fn classifies_email() {
        let c = classify("MTrebosc@Example.COM");
        assert_eq!(c.oz_type, OzType::Email);
        assert!(c.valid);
        assert!(c.confidence >= CONFIDENCE_CUTOFF);
        assert!(c.alternates.is_empty());
        assert_eq!(c.method, ClassifyMethod::Deterministic);
    }

    #[test]
    fn classifies_ip() {
        let c = classify("8.8.8.8");
        assert_eq!(c.oz_type, OzType::Ip);
        assert!(c.valid);
        assert!(c.alternates.is_empty());
    }

    #[test]
    fn classifies_phone() {
        let c = classify("+33 6 12 34 56 78");
        assert_eq!(c.oz_type, OzType::Phone);
        assert!(c.valid, "note: {:?}", c.note);
        assert_eq!(c.normalized_value, "+33 6 12 34 56 78");
    }

    #[test]
    fn classifies_coordinate() {
        let c = classify("48.8584, 2.2945");
        assert_eq!(c.oz_type, OzType::Coordinate);
        assert!(c.valid, "note: {:?}", c.note);
    }

    #[test]
    fn classifies_cve() {
        let c = classify("cve-2021-34527");
        assert_eq!(c.oz_type, OzType::Cve);
        assert!(c.valid);
        assert_eq!(c.normalized_value, "CVE-2021-34527");
    }

    #[test]
    fn classifies_bare_username() {
        let c = classify("@MTrebosc");
        assert_eq!(c.oz_type, OzType::Username);
        assert!(c.valid);
        assert!(c.alternates.is_empty());
        assert!(c.confidence >= CONFIDENCE_CUTOFF);
    }

    // ─── Genuinely ambiguous, producing alternates ───────────────────────────────────────

    #[test]
    fn domain_vs_username_is_ambiguous_but_resolves_deterministically() {
        let c = classify("example.com");
        assert_eq!(c.oz_type, OzType::Domain);
        assert!(c.valid);
        assert_eq!(c.alternates.len(), 1);
        assert_eq!(c.alternates[0].oz_type, OzType::Username);
        // Domain/hash are meant to resolve by shape alone — deterministic-first resolves
        // almost everything — so the winner alone should still clear the cutoff even though an
        // alternate exists.
        assert!(c.confidence >= CONFIDENCE_CUTOFF);
        assert!(
            !is_ambiguous(&c),
            "domain reading should not need LLM escalation"
        );
    }

    #[test]
    fn hash_vs_username_is_ambiguous_but_resolves_deterministically() {
        let c = classify("D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(c.oz_type, OzType::Hash);
        assert!(c.valid);
        assert_eq!(c.alternates.len(), 1);
        assert_eq!(c.alternates[0].oz_type, OzType::Username);
        assert!(c.confidence >= CONFIDENCE_CUTOFF);
    }

    #[test]
    fn multiword_free_text_is_genuinely_ambiguous() {
        let c = classify("John Doe");
        assert_eq!(c.oz_type, OzType::Name);
        assert!(c.valid);
        assert_eq!(c.alternates.len(), 1);
        assert_eq!(c.alternates[0].oz_type, OzType::Directory);
        assert!(c.confidence < CONFIDENCE_CUTOFF);
        assert!(
            is_ambiguous(&c),
            "free text has nothing for a shape rule to grip"
        );
    }

    #[test]
    fn is_ambiguous_also_triggers_on_a_close_alternate_above_cutoff() {
        // Synthetic: winner clears CONFIDENCE_CUTOFF on its own, but a runner-up sits within
        // ALTERNATE_MARGIN — this exercises the margin branch specifically, which no real shape
        // pairing in this file happens to hit (domain/hash keep their alternate well below the
        // margin on purpose, so they resolve deterministically).
        let c = Classification {
            oz_type: OzType::Domain,
            normalized_value: "example.com".into(),
            confidence: 0.8,
            method: ClassifyMethod::Deterministic,
            alternates: vec![Alternate {
                oz_type: OzType::Username,
                confidence: 0.75,
            }],
            valid: true,
            note: None,
        };
        assert!(is_ambiguous(&c));
    }

    // ─── Garbage / invalid ────────────────────────────────────────────────────────────────

    #[test]
    fn empty_input_is_invalid_not_a_confident_guess() {
        let c = classify("");
        assert!(!c.valid);
        assert!(c.confidence < CONFIDENCE_CUTOFF);
        assert!(c.note.is_some());
    }

    #[test]
    fn shape_matched_but_invalid_value_carries_the_normalizer_rejection() {
        // Matches the CVE shape (starts with "CVE-") but fails normalize_cve's stricter regex
        // (year must be 4 digits) — must NOT be reported as a confident CVE.
        let c = classify("CVE-99-1");
        assert_eq!(c.oz_type, OzType::Cve);
        assert!(!c.valid);
        assert!(c.confidence < CONFIDENCE_CUTOFF);
        let note = c
            .note
            .expect("invalid classification must carry the normalizer's reason");
        assert!(note.contains("CVE-YYYY-NNNN"), "note: {note}");
    }

    #[test]
    fn shape_matched_but_out_of_range_coordinate_is_invalid() {
        let c = classify("200, 50");
        assert_eq!(c.oz_type, OzType::Coordinate);
        assert!(!c.valid);
        assert!(c.note.unwrap().contains("out of range"));
    }

    // ─── LLM tier ─────────────────────────────────────────────────────────────────────────

    struct RepliesWith(&'static str);

    #[async_trait]
    impl ClassifierLlm for RepliesWith {
        async fn complete(&self, _system: &str, _user: &str) -> anyhow::Result<String> {
            Ok(self.0.to_string())
        }
    }

    struct AlwaysErrors;

    #[async_trait]
    impl ClassifierLlm for AlwaysErrors {
        async fn complete(&self, _system: &str, _user: &str) -> anyhow::Result<String> {
            Err(anyhow::anyhow!("simulated network failure"))
        }
    }

    struct PanicsIfCalled;

    #[async_trait]
    impl ClassifierLlm for PanicsIfCalled {
        async fn complete(&self, _system: &str, _user: &str) -> anyhow::Result<String> {
            panic!("must not be called for an unambiguous deterministic result");
        }
    }

    #[tokio::test]
    async fn llm_tier_resolves_a_genuine_ambiguity() {
        let llm = RepliesWith(
            r#"```json
{ "type": "directory", "confidence": 0.9 }
```"#,
        );
        let c = classify_with_llm("John Doe", &llm).await;
        assert_eq!(c.oz_type, OzType::Directory);
        assert_eq!(c.method, ClassifyMethod::Llm);
        assert!((c.confidence - 0.9).abs() < f64::EPSILON);
        // The deterministic winner (Name) is preserved as an alternate now that it lost.
        assert!(c.alternates.iter().any(|a| a.oz_type == OzType::Name));
    }

    #[tokio::test]
    async fn llm_tier_is_never_consulted_when_deterministic_result_is_confident() {
        // A panicking fake proves classify_with_llm didn't even attempt the call.
        let c = classify_with_llm("8.8.8.8", &PanicsIfCalled).await;
        assert_eq!(c.oz_type, OzType::Ip);
        assert_eq!(c.method, ClassifyMethod::Deterministic);
    }

    #[tokio::test]
    async fn llm_tier_is_not_consulted_for_domain_vs_username_either() {
        // Alternate (0.3) sits far below CONFIDENCE_CUTOFF - ALTERNATE_MARGIN (0.5) of the
        // winner (0.9), so this must resolve deterministically without an LLM call.
        let c = classify_with_llm("example.com", &PanicsIfCalled).await;
        assert_eq!(c.oz_type, OzType::Domain);
        assert_eq!(c.method, ClassifyMethod::Deterministic);
    }

    #[tokio::test]
    async fn llm_tier_falls_back_honestly_on_error() {
        let deterministic = classify("John Doe");
        let c = classify_with_llm("John Doe", &AlwaysErrors).await;
        assert_eq!(c.oz_type, deterministic.oz_type);
        assert_eq!(c.confidence, deterministic.confidence);
        assert_eq!(c.method, ClassifyMethod::DeterministicFallback);
        assert_ne!(
            c.method,
            ClassifyMethod::Llm,
            "must never present a failed call as LLM-confirmed"
        );
    }

    #[tokio::test]
    async fn llm_tier_falls_back_honestly_on_unparseable_reply() {
        let deterministic = classify("John Doe");
        let llm = RepliesWith("I'm not sure, could be either honestly");
        let c = classify_with_llm("John Doe", &llm).await;
        assert_eq!(c.oz_type, deterministic.oz_type);
        assert_eq!(c.method, ClassifyMethod::DeterministicFallback);
    }

    #[tokio::test]
    async fn llm_tier_falls_back_on_reply_naming_an_unknown_type() {
        let llm = RepliesWith(r#"{ "type": "not-a-real-type" }"#);
        let c = classify_with_llm("John Doe", &llm).await;
        assert_eq!(c.method, ClassifyMethod::DeterministicFallback);
    }

    #[tokio::test]
    async fn llm_tier_defaults_confidence_when_reply_omits_it() {
        let llm = RepliesWith(r#"{ "type": "name" }"#);
        let c = classify_with_llm("John Doe", &llm).await;
        assert_eq!(c.method, ClassifyMethod::Llm);
        assert!((c.confidence - CONFIDENCE_LLM_RESOLVED).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn llm_tier_can_be_invoked_more_than_once_without_state_bleed() {
        struct CountingReplies(AtomicUsize);
        #[async_trait]
        impl ClassifierLlm for CountingReplies {
            async fn complete(&self, _s: &str, _u: &str) -> anyhow::Result<String> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(r#"{ "type": "name", "confidence": 0.8 }"#.to_string())
            }
        }
        let llm = CountingReplies(AtomicUsize::new(0));
        let _ = classify_with_llm("John Doe", &llm).await;
        let _ = classify_with_llm("Jane Roe", &llm).await;
        assert_eq!(llm.0.load(Ordering::SeqCst), 2);
    }
}
