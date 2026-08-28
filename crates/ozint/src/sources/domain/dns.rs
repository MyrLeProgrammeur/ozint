//! `dns` — MX, NS and TXT records via Cloudflare DNS over HTTPS. Keyless. Owns the `mx`, `ns`
//! and `txt` fields of [`crate::types::DomainPayload`]. TXT records routinely carry SPF/DKIM/
//! domain-verification entries that name a linked SaaS provider (Google Workspace, Microsoft
//! 365, Cloudflare, …) — a third DoH request costs the same retry/timeout/SSRF-guarded budget as
//! the other two and reveals infrastructure the MX/NS answers alone do not.
//!
//! ## Why DoH, not a resolver
//!
//! The obvious starting point was `node:dns/promises`, which has no Rust equivalent: `std`'s only DNS surface
//! is `ToSocketAddrs`, good for A/AAAA only, with no path to an MX or NS record. The real
//! alternatives were a new dependency (`hickory-resolver`) or DNS over HTTPS. DoH wins on three
//! counts: it adds no dependency, it reuses [`fetch::oz_fetch`] — so the shared retry, timeout,
//! body cap and SSRF guard all apply to a DNS lookup exactly as they do to every other tool in
//! this crate — and it works through outbound HTTPS where raw UDP/53 is filtered, which this
//! project's own sandboxes have hit before.
//!
//! `GET https://cloudflare-dns.com/dns-query?name={domain}&type=MX` (and `type=NS`, `type=TXT`),
//! header `accept: application/dns-json`. Keyless. **Three requests per invocation** — one
//! logical tool call, the same rule `wmn-probe`'s ~730-request fan-out is counted under.
//!
//! Measured 2026-08-21, `anthropic.com` MX:
//! `{"Status":0, …, "Answer":[{"data":"1 aspmx.l.google.com."},{"data":"10 alt3.aspmx.l.google.com."},{"data":"5 alt1.aspmx.l.google.com."}]}`
//! — note the answer is not preference-sorted on the wire.
//! `anthropic.com` NS: same envelope, `"Answer":[{"data":"isla.ns.cloudflare.com."},{"data":"randy.ns.cloudflare.com."}]`.
//! `zzqq-not-a-real-domain-9999.com`: HTTP **200**, `"Status":3`, **no `Answer` key at all**
//! (an `Authority` key stands in its place). A domain that exists but has no records of the
//! queried type: `"Status":0`, also no `Answer` key.
//!
//! ## Traps
//!
//! **RFC 7505 "null MX".** `example.com`'s MX answer is `{"data":"0 ."}` — preference 0
//! pointing at the DNS root, the standard way a domain declares "I accept no mail at all". A
//! parser that doesn't know this records `.` (or, after dot-stripping, an empty string) as a
//! mail host: a fabricated finding presented as a real one. [`parse_mx_records`] detects an
//! empty host after stripping and drops the entry instead of yielding it.
//!
//! **`data` is `"<preference> <host>"` for MX, not a bare host.** Preference comes first and
//! must be split off before the host is usable; NS `data` has no preference, it's a bare host.
//! [`parse_mx_records`] sorts by preference ascending — lowest number wins, which is what an
//! analyst reads as "primary" — before dropping the number from the output.
//!
//! **Trailing dots.** Every FQDN in `data` comes back fully qualified (`aspmx.l.google.com.`).
//! Stripped on the way out: a trailing dot is rendering noise, and left in it would also break
//! any future dedup against a name written without one.
//!
//! **TXT `data` comes back wrapped in a literal pair of double quotes** (e.g.
//! `"\"v=spf1 include:_spf.google.com ~all\""`) — the wire representation of the record's own
//! quoted-string encoding, not JSON escaping artifact. [`parse_txt_records`] strips one leading
//! and one trailing `"` when both are present so the yielded string is the bare record text.
//!
//! **`Status` is a DNS RCODE, not an HTTP status.** `0` (NOERROR) and `3` (NXDOMAIN) both mean
//! *absence* when there's no `Answer` — a clean "nothing to report", not a tool failure. Any
//! other `Status` — `2` (SERVFAIL), `5` (REFUSED), or anything else — means the resolver itself
//! refused or failed to answer, which taught this tool nothing and must not be reported as "no
//! MX records exist". [`check_status`] rejects every RCODE outside `{0, 3}` as a
//! [`crate::outcome::ToolOutcome::ParseError`], naming the RCODE where a name is known.
//!
//! ## No children
//!
//! `mx`/`ns` hosts (`aspmx.l.google.com`, `randy.ns.cloudflare.com`) belong to third-party mail
//! and DNS providers, not to the domain under investigation. Turning them into `Domain` child
//! nodes would fill an analyst's tree with Google's and Cloudflare's own infrastructure instead
//! of the subject's. [`run_dns`] never populates [`ToolYield::children`].

use crate::fetch::{OzBody, OzFetchOptions, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;

const CLOUDFLARE_DOH_BASE: &str = "https://cloudflare-dns.com/dns-query?name=";

/// Reads the DoH response body as JSON, accepting the `text/plain` a strict client might send
/// it as. Cloudflare declares `application/dns-json`, which does contain "json" so
/// `fetch::dispatch_content_type` already routes it to [`OzBody::Json`] today — this fallback
/// is defensive, not observed. It costs one extra match arm; `poc_github::body_to_json` exists
/// because the equivalent assumption for `raw.githubusercontent.com` was wrong and silently
/// broke every successful lookup, so the same cheap insurance is applied here rather than
/// re-learning that lesson on a second source.
fn body_to_json(body: &OzBody) -> Result<serde_json::Value, String> {
    match body {
        OzBody::Json(json) => Ok(json.clone()),
        OzBody::Text(text) => serde_json::from_str(text)
            .map_err(|e| format!("Cloudflare DoH body was not parseable JSON: {e}")),
        other => Err(format!(
            "Cloudflare DoH response was neither JSON nor text: {other:?}"
        )),
    }
}

/// The standard name for the RCODEs this module can see: `0`/`1`/`2`/`3`/`5`. `None` for
/// anything else — `check_status`'s error message falls back to the bare number in that case.
const fn rcode_name(status: u64) -> Option<&'static str> {
    match status {
        0 => Some("NOERROR"),
        1 => Some("FORMERR"),
        2 => Some("SERVFAIL"),
        3 => Some("NXDOMAIN"),
        5 => Some("REFUSED"),
        _ => None,
    }
}

/// Accepts RCODE `0` (NOERROR) and `3` (NXDOMAIN) — both are absence, not failure, per the
/// module doc. Rejects everything else as an error naming the RCODE. Pure and tested.
fn check_status(json: &serde_json::Value) -> Result<(), String> {
    let status = json
        .get("Status")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "DoH response is missing `Status`".to_string())?;

    if status == 0 || status == 3 {
        return Ok(());
    }

    match rcode_name(status) {
        Some(name) => Err(format!(
            "DoH resolver returned RCODE {status} ({name}) — a resolver failure, not an absence"
        )),
        None => Err(format!(
            "DoH resolver returned RCODE {status} — a resolver failure, not an absence"
        )),
    }
}

/// The `Answer` array, or an empty slice when absent — both `NOERROR`-with-no-records and
/// `NXDOMAIN` omit the key entirely (see the module doc's measured fixtures).
fn answer_entries(json: &serde_json::Value) -> &[serde_json::Value] {
    json.get("Answer")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Parses a DoH MX response into mail hosts, sorted by preference ascending (lowest = highest
/// priority) with the preference number itself dropped from the output. Drops the RFC 7505
/// null-MX entry (an empty host after trailing-dot stripping) rather than yielding it as a
/// fabricated mail host — see the module doc. `Err` only for a genuine resolver failure or a
/// malformed `data` field. Pure and tested.
fn parse_mx_records(json: &serde_json::Value) -> Result<Vec<String>, String> {
    check_status(json)?;

    let mut prioritized: Vec<(u32, String)> = Vec::new();
    for entry in answer_entries(json) {
        let data = entry
            .get("data")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "MX Answer entry is missing `data`".to_string())?;

        let mut parts = data.split_whitespace();
        let preference: u32 = parts
            .next()
            .ok_or_else(|| format!("MX `data` `{data}` had no preference field"))?
            .parse()
            .map_err(|e| format!("MX `data` `{data}` preference did not parse as u32: {e}"))?;
        let host = parts
            .next()
            .ok_or_else(|| format!("MX `data` `{data}` had no host field"))?
            .trim_end_matches('.');

        if host.is_empty() {
            // RFC 7505 null MX ("0 .") — "this domain accepts no mail", not a mail host.
            continue;
        }
        prioritized.push((preference, host.to_string()));
    }

    prioritized.sort_by_key(|(preference, _)| *preference);
    Ok(prioritized.into_iter().map(|(_, host)| host).collect())
}

/// Parses a DoH NS response into nameserver hosts, trailing dots stripped. `Err` only for a
/// genuine resolver failure or a malformed `data` field. Pure and tested.
fn parse_ns_records(json: &serde_json::Value) -> Result<Vec<String>, String> {
    check_status(json)?;

    let mut hosts = Vec::new();
    for entry in answer_entries(json) {
        let data = entry
            .get("data")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "NS Answer entry is missing `data`".to_string())?;
        let host = data.trim_end_matches('.');
        if !host.is_empty() {
            hosts.push(host.to_string());
        }
    }
    Ok(hosts)
}

/// Parses a DoH TXT response into raw record strings, with the record's own wrapping double
/// quotes stripped (see the module doc's TXT trap). `Err` only for a genuine resolver failure or
/// a malformed `data` field. Pure and tested.
fn parse_txt_records(json: &serde_json::Value) -> Result<Vec<String>, String> {
    check_status(json)?;

    let mut records = Vec::new();
    for entry in answer_entries(json) {
        let data = entry
            .get("data")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "TXT Answer entry is missing `data`".to_string())?;
        let stripped = data
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(data);
        if !stripped.is_empty() {
            records.push(stripped.to_string());
        }
    }
    Ok(records)
}

/// Turns the parsed MX/NS/TXT lists into a [`ToolYield`] carrying only the non-empty fields — an
/// empty list is written as absent, matching the rest of this crate's "empty patch, not an
/// empty array" convention for a field with nothing to say. Pure.
fn dns_to_yield(mx: &[String], ns: &[String], txt: &[String]) -> ToolYield {
    let mut patch = serde_json::Map::new();
    if !mx.is_empty() {
        patch.insert("mx".to_string(), serde_json::json!(mx));
    }
    if !ns.is_empty() {
        patch.insert("ns".to_string(), serde_json::json!(ns));
    }
    if !txt.is_empty() {
        patch.insert("txt".to_string(), serde_json::json!(txt));
    }
    ToolYield {
        payload_patch: serde_json::Value::Object(patch),
        ..Default::default()
    }
}

/// Queries Cloudflare's DoH resolver for `domain`'s MX, NS and TXT records. Untested beyond its
/// pure helpers, same convention as the rest of this crate. If any request fails at the HTTP
/// layer, the failure is reported and nothing is half-applied from the others.
pub async fn run_dns(domain: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let headers = vec![("accept".to_string(), "application/dns-json".to_string())];
    let encoded = urlencoding::encode(domain);

    let mx_url = format!("{CLOUDFLARE_DOH_BASE}{encoded}&type=MX");
    // The MX query for this domain — namespaced so it never shares a cache row with the NS
    // query below, which is a different question about the same domain.
    let mx_outcome = ctx
        .fetch(
            "dom-dns",
            &format!("mx:{domain}"),
            &mx_url,
            OzFetchOptions {
                headers: headers.clone(),
                ..Default::default()
            },
        )
        .await;
    if matches!(mx_outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&mx_outcome) {
        return DispatchOutcome::Ran(failure, None);
    }

    let ns_url = format!("{CLOUDFLARE_DOH_BASE}{encoded}&type=NS");
    // The NS query for this domain — see the MX key above for why the two must not collide.
    let ns_outcome = ctx
        .fetch(
            "dom-dns",
            &format!("ns:{domain}"),
            &ns_url,
            OzFetchOptions {
                headers: headers.clone(),
                ..Default::default()
            },
        )
        .await;
    if matches!(ns_outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&ns_outcome) {
        return DispatchOutcome::Ran(failure, None);
    }

    let txt_url = format!("{CLOUDFLARE_DOH_BASE}{encoded}&type=TXT");
    // The TXT query for this domain — same collision-avoidance reasoning as MX/NS above.
    let txt_outcome = ctx
        .fetch(
            "dom-dns",
            &format!("txt:{domain}"),
            &txt_url,
            OzFetchOptions {
                headers,
                ..Default::default()
            },
        )
        .await;
    if matches!(txt_outcome, OzOutcome::Cancelled) {
        return DispatchOutcome::Cancelled;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&txt_outcome) {
        return DispatchOutcome::Ran(failure, None);
    }

    let OzOutcome::Ok(mx_resp) = mx_outcome else {
        unreachable!("every non-Ok, non-Cancelled MX OzOutcome was handled above");
    };
    let OzOutcome::Ok(ns_resp) = ns_outcome else {
        unreachable!("every non-Ok, non-Cancelled NS OzOutcome was handled above");
    };
    let OzOutcome::Ok(txt_resp) = txt_outcome else {
        unreachable!("every non-Ok, non-Cancelled TXT OzOutcome was handled above");
    };

    let mx_json = match body_to_json(&mx_resp.body) {
        Ok(json) => json,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };
    let ns_json = match body_to_json(&ns_resp.body) {
        Ok(json) => json,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };
    let txt_json = match body_to_json(&txt_resp.body) {
        Ok(json) => json,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    let mx = match parse_mx_records(&mx_json) {
        Ok(mx) => mx,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };
    let ns = match parse_ns_records(&ns_json) {
        Ok(ns) => ns,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };
    let txt = match parse_txt_records(&txt_json) {
        Ok(txt) => txt,
        Err(message) => return DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    };

    let count = (mx.len() + ns.len() + txt.len()) as u32;
    if count == 0 {
        DispatchOutcome::Ran(
            ToolOutcome::OkEmpty,
            Some(ToolYield {
                payload_patch: serde_json::json!({}),
                ..Default::default()
            }),
        )
    } else {
        DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count },
            Some(dns_to_yield(&mx, &ns, &txt)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── the content-type fallback ────────────────────────────────────────

    #[test]
    fn a_text_plain_body_is_still_read_as_json() {
        let raw = r#"{"Status":0,"Answer":[{"type":2,"data":"a.ns.example.com."}]}"#;
        let json = body_to_json(&OzBody::Text(raw.to_string())).expect("text/plain must parse");
        assert_eq!(
            parse_ns_records(&json),
            Ok(vec!["a.ns.example.com".to_string()])
        );
    }

    #[test]
    fn a_json_body_still_works_and_a_non_text_body_is_loud() {
        let value = serde_json::json!({"Status": 0});
        assert_eq!(
            body_to_json(&OzBody::Json(value.clone())).expect("json"),
            value
        );
        assert!(body_to_json(&OzBody::Empty).is_err());
        assert!(body_to_json(&OzBody::Text("not json".into())).is_err());
    }

    // ── check_status / rcode_name ────────────────────────────────────────

    #[test]
    fn noerror_and_nxdomain_are_accepted_as_absence() {
        assert_eq!(check_status(&serde_json::json!({"Status": 0})), Ok(()));
        assert_eq!(check_status(&serde_json::json!({"Status": 3})), Ok(()));
    }

    #[test]
    fn servfail_and_refused_are_reported_as_named_failures() {
        let servfail = check_status(&serde_json::json!({"Status": 2})).unwrap_err();
        assert!(servfail.contains("SERVFAIL"), "message was: {servfail}");

        let refused = check_status(&serde_json::json!({"Status": 5})).unwrap_err();
        assert!(refused.contains("REFUSED"), "message was: {refused}");
    }

    #[test]
    fn an_unnamed_rcode_still_fails_with_the_bare_number() {
        let err = check_status(&serde_json::json!({"Status": 9})).unwrap_err();
        assert!(err.contains('9'), "message was: {err}");
    }

    #[test]
    fn missing_status_is_an_error() {
        assert!(check_status(&serde_json::json!({})).is_err());
    }

    // ── parse_mx_records ─────────────────────────────────────────────────

    #[test]
    fn parses_and_sorts_the_real_anthropic_com_mx_fixture() {
        // Measured 2026-08-21. Deliberately transcribed in non-sorted wire order (1, 10, 5) so
        // this test actually exercises the preference sort, not just the parse.
        let json = serde_json::json!({
            "Status": 0,
            "Answer": [
                {"name": "anthropic.com", "type": 15, "TTL": 1614, "data": "1 aspmx.l.google.com."},
                {"name": "anthropic.com", "type": 15, "TTL": 1614, "data": "10 alt3.aspmx.l.google.com."},
                {"name": "anthropic.com", "type": 15, "TTL": 1614, "data": "5 alt1.aspmx.l.google.com."}
            ]
        });
        assert_eq!(
            parse_mx_records(&json),
            Ok(vec![
                "aspmx.l.google.com".to_string(),
                "alt1.aspmx.l.google.com".to_string(),
                "alt3.aspmx.l.google.com".to_string(),
            ])
        );
    }

    #[test]
    fn rfc7505_null_mx_is_dropped_not_recorded_as_a_host() {
        // This is the trap fixture. `example.com`'s real MX answer, measured 2026-08-21. A
        // naive parser records `.` (or, post-dot-stripping, an empty string) as a mail host —
        // a fabricated finding. If this test starts returning a non-empty vec, that bug is back.
        let json = serde_json::json!({
            "Status": 0,
            "Answer": [{"name": "example.com", "type": 15, "TTL": 300, "data": "0 ."}]
        });
        assert_eq!(parse_mx_records(&json), Ok(Vec::new()));
    }

    #[test]
    fn nxdomain_with_no_answer_key_is_a_clean_empty_list() {
        let json = serde_json::json!({"Status": 3, "Authority": []});
        assert_eq!(parse_mx_records(&json), Ok(Vec::new()));
        assert_eq!(parse_ns_records(&json), Ok(Vec::new()));
    }

    #[test]
    fn noerror_with_no_answer_key_is_a_clean_empty_list() {
        let json = serde_json::json!({"Status": 0});
        assert_eq!(parse_mx_records(&json), Ok(Vec::new()));
        assert_eq!(parse_ns_records(&json), Ok(Vec::new()));
    }

    #[test]
    fn a_resolver_failure_status_is_an_error_not_an_empty_result() {
        let json = serde_json::json!({"Status": 2});
        assert!(parse_mx_records(&json).is_err());
        assert!(parse_ns_records(&json).is_err());
    }

    #[test]
    fn malformed_mx_data_without_a_preference_is_an_error() {
        let json = serde_json::json!({
            "Status": 0,
            "Answer": [{"data": "aspmx.l.google.com."}]
        });
        assert!(parse_mx_records(&json).is_err());
    }

    // ── parse_ns_records ─────────────────────────────────────────────────

    #[test]
    fn parses_the_real_anthropic_com_ns_fixture_and_strips_trailing_dots() {
        // Measured 2026-08-21.
        let json = serde_json::json!({
            "Status": 0,
            "Answer": [
                {"name": "anthropic.com", "type": 2, "TTL": 76925, "data": "isla.ns.cloudflare.com."},
                {"name": "anthropic.com", "type": 2, "TTL": 76925, "data": "randy.ns.cloudflare.com."}
            ]
        });
        assert_eq!(
            parse_ns_records(&json),
            Ok(vec![
                "isla.ns.cloudflare.com".to_string(),
                "randy.ns.cloudflare.com".to_string()
            ])
        );
    }

    // ── parse_txt_records ────────────────────────────────────────────────

    #[test]
    fn txt_records_have_their_wrapping_quotes_stripped() {
        let json = serde_json::json!({
            "Status": 0,
            "Answer": [
                {"name": "example.com", "type": 16, "TTL": 300, "data": "\"v=spf1 include:_spf.google.com ~all\""},
                {"name": "example.com", "type": 16, "TTL": 300, "data": "\"google-site-verification=abc123\""}
            ]
        });
        assert_eq!(
            parse_txt_records(&json),
            Ok(vec![
                "v=spf1 include:_spf.google.com ~all".to_string(),
                "google-site-verification=abc123".to_string(),
            ])
        );
    }

    #[test]
    fn txt_records_without_wrapping_quotes_pass_through_unchanged() {
        let json = serde_json::json!({
            "Status": 0,
            "Answer": [{"name": "example.com", "type": 16, "TTL": 300, "data": "unquoted-value"}]
        });
        assert_eq!(
            parse_txt_records(&json),
            Ok(vec!["unquoted-value".to_string()])
        );
    }

    #[test]
    fn txt_nxdomain_with_no_answer_key_is_a_clean_empty_list() {
        let json = serde_json::json!({"Status": 3, "Authority": []});
        assert_eq!(parse_txt_records(&json), Ok(Vec::new()));
    }

    #[test]
    fn txt_resolver_failure_status_is_an_error_not_an_empty_result() {
        let json = serde_json::json!({"Status": 2});
        assert!(parse_txt_records(&json).is_err());
    }

    // ── dns_to_yield ─────────────────────────────────────────────────────

    #[test]
    fn yield_carries_only_non_empty_fields_and_no_children() {
        let mx = vec!["aspmx.l.google.com".to_string()];
        let ns = vec!["isla.ns.cloudflare.com".to_string()];
        let txt = vec!["v=spf1 include:_spf.google.com ~all".to_string()];
        let produced = dns_to_yield(&mx, &ns, &txt);
        assert_eq!(
            produced.payload_patch,
            serde_json::json!({
                "mx": ["aspmx.l.google.com"],
                "ns": ["isla.ns.cloudflare.com"],
                "txt": ["v=spf1 include:_spf.google.com ~all"],
            })
        );
        assert!(
            produced.children.is_empty(),
            "mail/nameserver hosts must never become children"
        );
        assert!(produced.rows.is_empty());
    }

    #[test]
    fn yield_omits_an_empty_side_entirely() {
        let mx: Vec<String> = Vec::new();
        let ns = vec!["isla.ns.cloudflare.com".to_string()];
        let txt: Vec<String> = Vec::new();
        let produced = dns_to_yield(&mx, &ns, &txt);
        assert_eq!(
            produced.payload_patch,
            serde_json::json!({"ns": ["isla.ns.cloudflare.com"]})
        );
        assert!(produced.payload_patch.get("mx").is_none());
        assert!(produced.payload_patch.get("txt").is_none());
    }
}
