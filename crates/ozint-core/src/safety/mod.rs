pub mod freeze;
pub mod pii;

use std::sync::LazyLock;

use regex::Regex;

pub use freeze::{FreezeRecord, FreezeState, FreezeUpdate};
pub use pii::{RedactionResult, has_pii, redact_pii};

/// The single choke point every cloud-bound path calls BEFORE sending text to a cloud LLM.
///
/// It does two things. (a) It redacts high-risk financial PII — IBANs and card numbers, via
/// [`pii`]. Email addresses and phone numbers are deliberately **not** redacted: in an OSINT
/// cockpit they are frequently the subject of the investigation itself, and masking them would
/// make the summary describe nothing. (b) It flags four sensitive life-topic categories —
/// health, finance, legal, relationships. That flag is **advisory**: it is recorded on the
/// result so a caller can decide, and it does not block the call.
pub struct GuardResult {
    /// PII-redacted text, safe(r) to send to a cloud LLM/embedder.
    pub text: String,
    /// Per-kind PII masking counts.
    pub redactions: std::collections::BTreeMap<String, usize>,
    /// True if the text touches a sensitive category → quarantine, keep local.
    pub sensitive: bool,
    /// Which sensitive categories matched.
    pub categories: Vec<String>,
}

/// Sensitive-category detectors.
///
/// **They are bilingual, French and English**, which is worth stating because it looks
/// arbitrary otherwise: this guard predates the rest of the crate and was written for a
/// French-speaking user. The English terms are not a translation layer bolted on — both
/// languages sit in the same pattern and either will match. Adding a third language means
/// extending these four regexes and nothing else.
///
/// `(?-u:\b)` is an ASCII-only word boundary, deliberately. Under those semantics a term
/// ending in an accented letter (`santé`) does not match while its unaccented form (`sante`)
/// does — which is why each pattern spells out both forms (`sant[ée]`) rather than relying on
/// the boundary to do it. Widening the boundary to Unicode would change what matches, so it is
/// left narrow and the patterns carry the burden explicitly.
static SENSITIVE: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        (
            "health",
            Regex::new(r"(?i)(?-u:\b)(sant[ée]|m[ée]decin|maladie|sympt[oô]mes?|diagnostic|ordonnance|traitements?|d[ée]pression|anxi[ée]t[ée]|th[ée]rapie|psy|h[oô]pital|douleurs?|health|doctor|illness|disease|diagnosis|therapy|medication|symptom)(?-u:\b)").expect("health pattern"),
        ),
        (
            "finance",
            Regex::new(r"(?i)(?-u:\b)(salaires?|revenus?|banque|compte|dettes?|cr[ée]dit|emprunts?|imp[oô]ts?|loyer|argent|[ée]pargne|patrimoine|salary|income|bank|debt|loan|tax|mortgage|savings)(?-u:\b)").expect("finance pattern"),
        ),
        (
            "legal",
            Regex::new(r"(?i)(?-u:\b)(avocat|tribunal|proc[èe]s|contrats?|litige|plainte|juridique|notaire|h[ée]ritage|divorce|lawyer|court|lawsuit|legal|contract)(?-u:\b)").expect("legal pattern"),
        ),
        (
            "relationship",
            Regex::new(r"(?i)(?-u:\b)(copines?|copains?|petite?\s+ami\w*|conjoints?|[ée]pouses?|mari|famille|rupture|disputes?|girlfriend|boyfriend|partner|spouse|breakup)(?-u:\b)").expect("relationship pattern"),
        ),
    ]
});

/// Redact PII and detect sensitive categories before any cloud call.
pub fn guard_cloud(input: &str) -> GuardResult {
    let red = redact_pii(input);
    let categories: Vec<String> = SENSITIVE
        .iter()
        .filter(|(_, re)| re.is_match(input))
        .map(|(category, _)| category.to_string())
        .collect();

    GuardResult {
        text: red.text,
        redactions: red.counts,
        sensitive: !categories.is_empty(),
        categories,
    }
}

/// The most salient sensitive category of a stored fact, or `None`.
pub fn classify_category(input: &str) -> Option<&'static str> {
    SENSITIVE
        .iter()
        .find(|(_, re)| re.is_match(input))
        .map(|(category, _)| *category)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sensitive_categories() {
        assert!(guard_cloud("ma sante fragile").sensitive);
        assert!(guard_cloud("le medecin arrive").sensitive);
        assert!(guard_cloud("une maladie rare").sensitive);
        assert_eq!(classify_category("mon salaire"), Some("finance"));
        assert_eq!(classify_category("rendez-vous avocat"), Some("legal"));
    }

    #[test]
    fn ascii_word_boundary_quirk_is_preserved() {
        // A trailing accented letter defeats the ASCII `\b`, so bare "santé" does not
        // trigger the health rule — which is exactly why each pattern spells out both forms
        // (`sant[ée]`). This test pins the quirk so a future widening of the boundary is a
        // conscious change rather than an accident.
        assert!(!guard_cloud("ma santé fragile").sensitive);
        assert!(guard_cloud("ma sante fragile").sensitive);
    }

    #[test]
    fn plain_text_is_not_sensitive() {
        let out = guard_cloud("il fait beau a Toulouse");
        assert!(!out.sensitive);
        assert!(out.categories.is_empty());
        assert_eq!(out.text, "il fait beau a Toulouse");
    }
}
