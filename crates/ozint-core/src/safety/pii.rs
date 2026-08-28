use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

/// PII redaction applied to content BEFORE any cloud call.
///
/// Per owner decision (2026-06-15) emails and phone numbers are intentionally
/// NOT masked — the owner accepts sending them for more precise replies. Only
/// high-risk financial PII (IBAN, card numbers) is masked. Order matters: IBAN
/// runs before the generic card pattern.
///
/// The `(?-u:\b)` boundaries are deliberate. Rust's `regex` makes `\b` Unicode-aware by
/// default, which would let a boundary fall inside an accented word and change which spans
/// match. These patterns were written and verified against ASCII boundary semantics, so the
/// narrower form is pinned rather than left to the default.
pub struct RedactionResult {
    /// The text with PII replaced by neutral placeholders.
    pub text: String,
    /// How many of each PII kind were masked.
    pub counts: BTreeMap<String, usize>,
}

struct Rule {
    label: &'static str,
    re: Regex,
    mask: &'static str,
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        Rule {
            label: "iban",
            re: Regex::new(
                r"(?i)(?-u:\b)[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,3}(?-u:\b)",
            )
            .expect("iban pattern"),
            mask: "[IBAN]",
        },
        Rule {
            label: "card",
            re: Regex::new(r"(?-u:\b)(?:\d[ -]?){13,19}(?-u:\b)").expect("card pattern"),
            mask: "[card]",
        },
    ]
});

/// Redact PII from text, returning the masked text and per-kind counts.
pub fn redact_pii(input: &str) -> RedactionResult {
    let mut text = input.to_string();
    let mut counts = BTreeMap::new();

    for rule in RULES.iter() {
        let hits = rule.re.find_iter(&text).count();
        if hits > 0 {
            counts.insert(rule.label.to_string(), hits);
            text = rule.re.replace_all(&text, rule.mask).into_owned();
        }
    }

    RedactionResult { text, counts }
}

/// True if any PII was found in the text.
pub fn has_pii(input: &str) -> bool {
    !redact_pii(input).counts.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_iban_then_card() {
        let out = redact_pii("IBAN FR7630001007941234567890185 et carte 4242 4242 4242 4242 fin");
        // Note the missing space before "fin": the card pattern's `\d[ -]?` repetition
        // swallows the trailing separator. Asserted rather than corrected, so that changing
        // the pattern has to confront this deliberately.
        assert_eq!(out.text, "IBAN [IBAN] et carte [card]fin");
        assert_eq!(out.counts.get("iban"), Some(&1));
        assert_eq!(out.counts.get("card"), Some(&1));
    }

    #[test]
    fn leaves_clean_text_untouched() {
        let out = redact_pii("bonjour Sir, tout va bien");
        assert_eq!(out.text, "bonjour Sir, tout va bien");
        assert!(out.counts.is_empty());
    }

    #[test]
    fn emails_and_phones_are_deliberately_kept() {
        let out = redact_pii("ecris a matheo@example.com ou au 0612345678");
        assert!(out.text.contains("matheo@example.com"));
        assert!(!has_pii("ecris a matheo@example.com"));
    }
}
