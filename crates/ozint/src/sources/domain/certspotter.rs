//! `certspotter` — SSLMate CertSpotter, a certificate-transparency-log search. Keyless. Owns
//! only the `subdomains` and `subdomainsTruncated` fields of [`crate::types::DomainPayload`].
//!
//! `GET https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names`
//! — measured 2026-08-21, HTTP `200` with a JSON **array** of issuance objects, each carrying
//! `id` (a numeric *string*), `dns_names` (array of strings covered by the certificate),
//! `issuer`, `cert_sha256`, and more this crate doesn't need. Absence
//! (`zzqq-not-a-real-domain-9999.com`) is also HTTP `200`, with an empty array — mapped to
//! [`crate::outcome::ToolOutcome::OkEmpty`], not an error.
//!
//! **Pagination, measured.** Exactly [`CERTSPOTTER_PAGE_SIZE`] issuances per page, with a
//! `Link: …; rel="next"` header this module never follows: one page already yielded 92 unique
//! names for `anthropic.com`, far past the child cap, and a full CT-log crawl is not what a
//! single tool invocation is for. The result is therefore **a first page, not an exhaustive
//! enumeration** — [`run_certspotter`] marks `subdomainsTruncated: true` whenever the page came
//! back full, independent of whether the child cap also cut anything, so the provenance sentence
//! never overclaims completeness the tool doesn't have.
//!
//! ## The trap that matters most here
//!
//! Measured on `anthropic.com`: the 100 returned certificates include the name
//! **`advancedjs.bitinvestor.net`** — a domain with nothing to do with Anthropic. CertSpotter
//! matches any certificate that *mentions* the queried domain anywhere in its SAN list, and one
//! certificate's SAN list can cover many unrelated domains (a shared hosting cert, a CDN
//! wildcard bundle, …). Collecting every `dns_names` entry naively would present
//! `advancedjs.bitinvestor.net` as a subdomain of `anthropic.com` — a fabricated finding sitting
//! right next to real ones, with nothing marking it as junk. [`extract_in_scope_names`] keeps
//! only names that *are* the queried domain or end with `.{domain}`, case-insensitively;
//! everything else is silently dropped, not flagged — it was never a candidate to begin with.
//!
//! ## Wildcards
//!
//! Measured names include `*.anthropic.com` and `*.atlas.anthropic.com`. A wildcard is not a
//! host that exists on its own; [`extract_in_scope_names`] strips the `*.` prefix and keeps the
//! parent name (`atlas.anthropic.com` is a real, pivot-worthy name). A bare `*.anthropic.com`
//! strips down to `anthropic.com` itself, which would only repeat the subject the investigation
//! is already on — those are excluded rather than kept as a self-referential "subdomain".
//!
//! ## Dedup and order
//!
//! 100 certificates yielded 92 unique names with heavy repetition (the same subdomain reissued
//! across renewals, SAN bundles, …). Names are deduplicated case-insensitively and sorted before
//! anything downstream sees them, so the same domain queried twice — refreshed a day apart —
//! produces the same list. An unstable order here would make refresh diffs report
//! spurious changes on every routine refresh, not just on a genuine new certificate.
//!
//! ## Children
//!
//! Each kept, capped subdomain becomes a `Domain` [`crate::registry::ChildSeed`] noting it came
//! from a certificate transparency log — capped at
//! [`crate::types::MAX_SUBDOMAIN_CHILDREN`] identically to `subdomains` itself, since a child is
//! never created for a name the payload doesn't also list.

use std::collections::HashSet;

use crate::fetch::{OzBody, OzFetchOptions, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{MAX_SUBDOMAIN_CHILDREN, OzType};

const CERTSPOTTER_BASE: &str = "https://api.certspotter.com/v1/issuances?domain=";

/// CertSpotter's measured page size. A response with at least this many issuances means the
/// upstream enumeration itself was cut off by pagination, not just by this tool's own cap —
/// see the module doc's "first page, not an exhaustive enumeration".
const CERTSPOTTER_PAGE_SIZE: usize = 100;

/// Reads the response body as JSON, accepting `text/plain` defensively. Same reasoning as
/// `dns::body_to_json` and the module this pattern originates from, `cve::poc_github`: cheap
/// insurance against a host that turns out not to declare `application/json` the way it's
/// expected to.
fn body_to_json(body: &OzBody) -> Result<serde_json::Value, String> {
    match body {
        OzBody::Json(json) => Ok(json.clone()),
        OzBody::Text(text) => serde_json::from_str(text)
            .map_err(|e| format!("CertSpotter body was not parseable JSON: {e}")),
        other => Err(format!(
            "CertSpotter response was neither JSON nor text: {other:?}"
        )),
    }
}

/// Strips a leading `*.` wildcard label, if present, leaving the parent name. A name with no
/// wildcard prefix is returned unchanged.
fn strip_wildcard(name: &str) -> &str {
    name.strip_prefix("*.").unwrap_or(name)
}

/// Collects every `dns_names` entry across all issuances that is genuinely `domain` or a
/// subdomain of it, case-insensitively, after stripping any wildcard prefix — dropping
/// everything else (the unrelated-SAN trap the module doc describes) and dropping the queried
/// domain itself (a bare wildcard resolving back to the subject is not a new finding). Not yet
/// deduplicated, sorted, or capped — see [`build_subdomains_result`]. `Err` only when the body
/// isn't a JSON array at all. Pure and tested.
fn extract_in_scope_names(json: &serde_json::Value, domain: &str) -> Result<Vec<String>, String> {
    let issuances = json
        .as_array()
        .ok_or_else(|| "CertSpotter response was not a JSON array".to_string())?;
    let domain_lower = domain.to_ascii_lowercase();
    let domain_suffix = format!(".{domain_lower}");

    let mut names = Vec::new();
    for issuance in issuances {
        let Some(dns_names) = issuance
            .get("dns_names")
            .and_then(serde_json::Value::as_array)
        else {
            // A malformed or shape-drifted issuance entry — tolerated, same as
            // `poc_github::parse_poc_repos` tolerating an entry with no `html_url`. One odd
            // entry in a 100-issuance page must not fail the whole lookup.
            continue;
        };

        for raw in dns_names {
            let Some(raw_name) = raw.as_str() else {
                continue;
            };
            let candidate = strip_wildcard(raw_name);
            let candidate_lower = candidate.to_ascii_lowercase();

            let in_scope =
                candidate_lower == domain_lower || candidate_lower.ends_with(&domain_suffix);
            if !in_scope {
                // The advancedjs.bitinvestor.net trap — a SAN on the same cert, not a
                // subdomain. See the module doc.
                continue;
            }
            if candidate_lower == domain_lower {
                // A bare wildcard (`*.anthropic.com` → `anthropic.com`) repeating the subject.
                continue;
            }
            names.push(candidate.to_string());
        }
    }
    Ok(names)
}

/// The parsed, deduplicated, capped result of one CertSpotter lookup.
#[derive(Debug, Clone, PartialEq)]
struct SubdomainsResult {
    subdomains: Vec<String>,
    truncated: bool,
}

/// Deduplicates `extract_in_scope_names`'s output case-insensitively, sorts it for a stable
/// order across refreshes, then caps it at [`MAX_SUBDOMAIN_CHILDREN`]. `truncated` is set when
/// either the cap actually cut something *or* the upstream page came back full — the two causes
/// are tested independently because either alone must be enough to mark the list incomplete.
/// Pure and tested.
fn build_subdomains_result(
    json: &serde_json::Value,
    domain: &str,
) -> Result<SubdomainsResult, String> {
    let mut names = extract_in_scope_names(json, domain)?;
    names.sort_by_key(|n| n.to_ascii_lowercase());
    let mut seen = HashSet::new();
    names.retain(|n| seen.insert(n.to_ascii_lowercase()));

    let page_was_full = json
        .as_array()
        .is_some_and(|arr| arr.len() >= CERTSPOTTER_PAGE_SIZE);
    let cap_was_hit = names.len() > MAX_SUBDOMAIN_CHILDREN;

    names.truncate(MAX_SUBDOMAIN_CHILDREN);
    Ok(SubdomainsResult {
        subdomains: names,
        truncated: page_was_full || cap_was_hit,
    })
}

/// Turns a non-empty [`SubdomainsResult`] into a [`ToolYield`]: `subdomains` and, only when
/// true, `subdomainsTruncated`; one `Domain` child per kept name, capped identically because a
/// child is never created for a name the payload itself doesn't list. Pure.
fn certspotter_to_yield(result: &SubdomainsResult) -> ToolYield {
    let mut patch = serde_json::Map::new();
    patch.insert(
        "subdomains".to_string(),
        serde_json::json!(result.subdomains),
    );
    if result.truncated {
        patch.insert("subdomainsTruncated".to_string(), serde_json::json!(true));
    }

    let children = result
        .subdomains
        .iter()
        .map(|name| ChildSeed {
            oz_type: OzType::Domain,
            value: name.clone(),
            note: Some("found via a certificate transparency log (CertSpotter)".to_string()),
        })
        .collect();

    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        children,
        ..Default::default()
    }
}

/// Queries CertSpotter's issuances endpoint for `domain`. Untested beyond its pure helpers,
/// same convention as the rest of this crate.
pub async fn run_certspotter(domain: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let url = format!(
        "{CERTSPOTTER_BASE}{}&include_subdomains=true&expand=dns_names",
        urlencoding::encode(domain)
    );
    // The domain being looked up — CertSpotter's issuance list is keyed on it.
    let outcome = ctx
        .fetch("dom-certspotter", domain, &url, OzFetchOptions::default())
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
    let json = match body_to_json(&resp.body) {
        Ok(json) => json,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    match build_subdomains_result(&json, domain) {
        Ok(result) if result.subdomains.is_empty() => DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        ),
        Ok(result) => {
            let count = result.subdomains.len() as u32;
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count },
                Some(certspotter_to_yield(&result)),
            )
        }
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuance(dns_names: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "id": "1234567890",
            "issuer": {"name": "Test CA"},
            "cert_sha256": "deadbeef",
            "dns_names": dns_names,
        })
    }

    // ── the content-type fallback ────────────────────────────────────────

    #[test]
    fn a_text_plain_body_is_still_read_as_json() {
        let raw = r#"[{"id":"1","dns_names":["www.anthropic.com"]}]"#;
        let json = body_to_json(&OzBody::Text(raw.to_string())).expect("text/plain must parse");
        assert_eq!(
            extract_in_scope_names(&json, "anthropic.com"),
            Ok(vec!["www.anthropic.com".to_string()])
        );
    }

    #[test]
    fn a_json_body_still_works_and_a_non_text_body_is_loud() {
        let value = serde_json::json!([]);
        assert_eq!(
            body_to_json(&OzBody::Json(value.clone())).expect("json"),
            value
        );
        assert!(body_to_json(&OzBody::Empty).is_err());
        assert!(body_to_json(&OzBody::Text("not json".into())).is_err());
    }

    // ── the unrelated-SAN trap ───────────────────────────────────────────

    #[test]
    fn a_dns_name_from_an_unrelated_shared_certificate_is_dropped() {
        // The trap fixture: measured 2026-08-21, a real cert covering both anthropic.com and
        // advancedjs.bitinvestor.net came back in a live CertSpotter query. If this test starts
        // returning bitinvestor.net, the scope filter regressed.
        let json = serde_json::json!([issuance(&[
            "anthropic.com",
            "www.anthropic.com",
            "advancedjs.bitinvestor.net",
        ])]);
        let names = extract_in_scope_names(&json, "anthropic.com").expect("parses");
        assert!(names.contains(&"www.anthropic.com".to_string()));
        assert!(
            !names.iter().any(|n| n.contains("bitinvestor")),
            "an unrelated SAN on the same certificate must never be reported as a subdomain, got {names:?}"
        );
    }

    // ── wildcards ────────────────────────────────────────────────────────

    #[test]
    fn a_wildcard_keeps_its_parent_but_a_bare_wildcard_is_excluded() {
        let json = serde_json::json!([issuance(&["*.anthropic.com", "*.atlas.anthropic.com"])]);
        let names = extract_in_scope_names(&json, "anthropic.com").expect("parses");
        assert_eq!(names, vec!["atlas.anthropic.com".to_string()]);
    }

    // ── pagination truncation ────────────────────────────────────────────

    #[test]
    fn a_full_page_is_marked_truncated_even_under_the_cap() {
        // 100 issuances, each contributing one unique in-scope name well under
        // MAX_SUBDOMAIN_CHILDREN's cap on its own count — truncation here can only be the
        // page-size cause, not the cap cause.
        let issuances: Vec<serde_json::Value> = (0..CERTSPOTTER_PAGE_SIZE)
            .map(|i| issuance(&[&format!("s{i}.anthropic.com")]))
            .collect();
        let json = serde_json::Value::Array(issuances);
        let result = build_subdomains_result(&json, "anthropic.com").expect("parses");
        assert!(
            result.truncated,
            "a full page must be marked truncated regardless of the cap"
        );
        assert!(result.subdomains.len() <= MAX_SUBDOMAIN_CHILDREN);
    }

    #[test]
    fn a_short_page_under_the_cap_is_not_truncated() {
        let json = serde_json::json!([issuance(&["a.anthropic.com", "b.anthropic.com"])]);
        let result = build_subdomains_result(&json, "anthropic.com").expect("parses");
        assert!(!result.truncated);
        assert_eq!(
            result.subdomains,
            vec!["a.anthropic.com", "b.anthropic.com"]
        );
    }

    #[test]
    fn the_cap_alone_marks_truncated_on_a_short_page() {
        // Fewer than CERTSPOTTER_PAGE_SIZE issuances (so the page-full cause cannot fire), but
        // more unique names than MAX_SUBDOMAIN_CHILDREN allows — truncation here can only be
        // the cap cause.
        let unique_count = MAX_SUBDOMAIN_CHILDREN + 5;
        let issuances: Vec<serde_json::Value> = (0..unique_count)
            .map(|i| issuance(&[&format!("s{i}.anthropic.com")]))
            .collect();
        assert!(
            issuances.len() < CERTSPOTTER_PAGE_SIZE,
            "test fixture must stay under the page size"
        );
        let json = serde_json::Value::Array(issuances);
        let result = build_subdomains_result(&json, "anthropic.com").expect("parses");
        assert!(
            result.truncated,
            "exceeding the cap alone must mark the list truncated"
        );
        assert_eq!(result.subdomains.len(), MAX_SUBDOMAIN_CHILDREN);
    }

    // ── dedup and stable order ───────────────────────────────────────────

    #[test]
    fn dedup_is_case_insensitive_and_the_result_is_sorted() {
        let json = serde_json::json!([
            issuance(&["WWW.anthropic.com", "api.anthropic.com"]),
            issuance(&["www.anthropic.com", "api.anthropic.com"]),
        ]);
        let result = build_subdomains_result(&json, "anthropic.com").expect("parses");
        assert_eq!(
            result.subdomains.len(),
            2,
            "case-variant repeats must collapse to one entry"
        );
        let mut sorted = result.subdomains.clone();
        sorted.sort_by_key(|n| n.to_ascii_lowercase());
        assert_eq!(
            result.subdomains, sorted,
            "result must already be in sorted order"
        );
    }

    #[test]
    fn querying_the_same_domain_twice_yields_the_same_list() {
        // Not literally two calls (the parse is pure and deterministic), but the property this
        // guards: given identical upstream JSON, the output must not depend on hash-map
        // iteration order or any other non-determinism, or a refresh diff would
        // report spurious changes on every routine refresh.
        let json = serde_json::json!([issuance(&[
            "b.anthropic.com",
            "a.anthropic.com",
            "a.anthropic.com"
        ])]);
        let first = build_subdomains_result(&json, "anthropic.com").expect("parses");
        let second = build_subdomains_result(&json, "anthropic.com").expect("parses");
        assert_eq!(first, second);
    }

    // ── absence and error shapes ─────────────────────────────────────────

    #[test]
    fn an_empty_array_is_a_clean_absence_not_an_error() {
        let json = serde_json::json!([]);
        let result = build_subdomains_result(&json, "anthropic.com").expect("parses");
        assert_eq!(result.subdomains, Vec::<String>::new());
        assert!(!result.truncated);
    }

    #[test]
    fn a_non_array_body_is_an_error() {
        let json = serde_json::json!({"not": "an array"});
        assert!(extract_in_scope_names(&json, "anthropic.com").is_err());
    }

    #[test]
    fn an_issuance_with_no_dns_names_is_tolerated() {
        let json = serde_json::json!([{"id": "1"}, issuance(&["a.anthropic.com"])]);
        assert_eq!(
            extract_in_scope_names(&json, "anthropic.com"),
            Ok(vec!["a.anthropic.com".to_string()])
        );
    }

    // ── certspotter_to_yield ─────────────────────────────────────────────

    #[test]
    fn yield_children_match_the_kept_subdomains_exactly() {
        let result = SubdomainsResult {
            subdomains: vec!["a.anthropic.com".to_string(), "b.anthropic.com".to_string()],
            truncated: false,
        };
        let produced = certspotter_to_yield(&result);
        assert_eq!(
            produced.payload_patch,
            serde_json::json!({"subdomains": ["a.anthropic.com", "b.anthropic.com"]})
        );
        assert!(produced.payload_patch.get("subdomainsTruncated").is_none());

        let child_values: Vec<&str> = produced.children.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(child_values, vec!["a.anthropic.com", "b.anthropic.com"]);
        for child in &produced.children {
            assert_eq!(child.oz_type, OzType::Domain);
            assert!(child.note.is_some());
        }
    }

    #[test]
    fn yield_carries_truncated_only_when_true() {
        let result = SubdomainsResult {
            subdomains: vec!["a.anthropic.com".to_string()],
            truncated: true,
        };
        let produced = certspotter_to_yield(&result);
        assert_eq!(
            produced.payload_patch["subdomainsTruncated"],
            serde_json::json!(true)
        );
    }
}
