//! `mastodon-lookup` — Mastodon account lookup across a fixed list of large public instances.
//!
//! Mastodon is federated: there is no single directory to query, so this tool fans a handle
//! out across [`MASTODON_INSTANCES`] and reports which of them have an account under that
//! name. Endpoint per instance (verified live 2026-08-21):
//! `GET https://{instance}/api/v1/accounts/lookup?acct={handle}` (handle URL-encoded). A
//! present account answers `200` with the account JSON; an absent one answers a clean `404`
//! `{"error":"Record not found"}`.
//!
//! Same convention as [`super::wmn`]: bounded concurrency via a [`tokio::sync::Semaphore`] +
//! `futures::future::join_all`, and this whole fan-out **counts as ONE lookup**, not eight —
//! the per-instance detail lives inside the one [`ToolYield`] this produces.
//!
//! Everything here except [`run_mastodon_lookup`] and `probe_one_instance` is pure and tested
//! against inline fixtures; those two make real network calls and are deliberately kept thin,
//! per this crate's convention (see `fetch.rs`'s module doc).

use std::collections::HashSet;

use tokio::sync::Semaphore;

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{OzRow, OzType};

use super::{extract_domain, nonempty};

/// Large public Mastodon instances this tool fans a handle out across: the largest
/// general-purpose and infosec-adjacent public instances, not an exhaustive federation sweep
/// — a handle absent here is not proof of absence from the fediverse, only absence from these
/// eight. Verified reachable 2026-08-21.
const MASTODON_INSTANCES: &[&str] = &[
    "mastodon.social",
    "mstdn.social",
    "mas.to",
    "fosstodon.org",
    "hachyderm.io",
    "infosec.exchange",
    "techhub.social",
    "mastodon.world",
];

/// Bounded concurrency for the eight-instance fan-out, same [`tokio::sync::Semaphore`] pattern
/// `wmn.rs` uses for its much larger ~730-site fan-out. With only eight instances this permit
/// count is effectively unbounded in practice — kept here for consistency with that pattern
/// (and so a future addition to the instance list doesn't need this reconsidered) rather than
/// because eight concurrent requests actually need throttling.
const MASTODON_CONCURRENCY: usize = 8;

// ─── Pure data + parsing ────────────────────────────────────────────────────

/// One profile field (Mastodon's "verified links" mechanism). `value_html` is kept as the raw
/// HTML the API returned (an `<a href="...">` tag, typically) — [`accounts_to_yield`] strips
/// it for display and extracts the link separately.
#[derive(Debug, Clone, PartialEq)]
pub struct MastodonField {
    pub name: String,
    pub value_html: String,
    /// Non-`None` means Mastodon itself verified the linked page proves ownership back — a
    /// materially stronger claim than an unverified self-declared link.
    pub verified_at: Option<String>,
}

/// One account found on one instance. Pure struct — parsed by [`parse_mastodon_account`],
/// turned into rows/children by [`accounts_to_yield`].
#[derive(Debug, Clone, PartialEq)]
pub struct MastodonAccount {
    pub instance: String,
    pub acct: String,
    pub url: String,
    pub display_name: Option<String>,
    /// HTML-stripped `note` (the bio). `None` when absent or blank.
    pub note: Option<String>,
    pub followers_count: Option<u64>,
    pub statuses_count: Option<u64>,
    pub created_at: Option<String>,
    pub fields: Vec<MastodonField>,
}

/// Parses one `GET /api/v1/accounts/lookup` response body into a [`MastodonAccount`]. Pure and
/// tested against an inline fixture.
pub fn parse_mastodon_account(
    json: &serde_json::Value,
    instance: &str,
) -> Result<MastodonAccount, String> {
    let acct = json
        .get("acct")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("mastodon account response from {instance} is missing `acct`"))?
        .to_string();
    if json.get("username").and_then(|v| v.as_str()).is_none() {
        return Err(format!(
            "mastodon account response from {instance} is missing `username`"
        ));
    }

    let url = json
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let display_name = nonempty(json.get("display_name").and_then(|v| v.as_str()));
    let note = json
        .get("note")
        .and_then(|v| v.as_str())
        .map(strip_html)
        .filter(|s| !s.is_empty());
    let followers_count = json.get("followers_count").and_then(|v| v.as_u64());
    let statuses_count = json.get("statuses_count").and_then(|v| v.as_u64());
    let created_at = nonempty(json.get("created_at").and_then(|v| v.as_str()));

    let mut fields = Vec::new();
    if let Some(arr) = json.get("fields").and_then(|v| v.as_array()) {
        for entry in arr {
            let (Some(name), Some(value_html)) = (
                entry.get("name").and_then(|v| v.as_str()),
                entry.get("value").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            let verified_at = entry
                .get("verified_at")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            fields.push(MastodonField {
                name: name.to_string(),
                value_html: value_html.to_string(),
                verified_at,
            });
        }
    }

    Ok(MastodonAccount {
        instance: instance.to_string(),
        acct,
        url,
        display_name,
        note,
        followers_count,
        statuses_count,
        created_at,
        fields,
    })
}

/// Turns every found [`MastodonAccount`] into a [`ToolYield`]: one row group per instance, and
/// only the children the responses actually contained (never invented) — a `Name` child from
/// each distinct `display_name`, a `Domain` child only from a profile field whose `verified_at`
/// is non-null (an unverified field is anyone's self-declared text and must not seed a child).
/// Children are deduplicated across instances, since the same person on three instances must
/// not yield the same `Name`/`Domain` child three times. Pure and tested.
pub fn accounts_to_yield(accounts: &[MastodonAccount]) -> ToolYield {
    let mut rows = Vec::new();
    let mut children = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    let mut seen_domains: HashSet<String> = HashSet::new();

    for account in accounts {
        rows.push(OzRow {
            label: "Mastodon".to_string(),
            value: format!("{}@{}", account.acct, account.instance),
            href: (!account.url.is_empty()).then(|| account.url.clone()),
            ..Default::default()
        });
        if let Some(name) = &account.display_name {
            rows.push(OzRow {
                label: "Name".to_string(),
                value: name.clone(),
                ..Default::default()
            });
        }
        if let Some(note) = &account.note {
            rows.push(OzRow {
                label: "Bio".to_string(),
                value: note.clone(),
                ..Default::default()
            });
        }
        if let Some(followers) = account.followers_count {
            rows.push(OzRow {
                label: "Followers".to_string(),
                value: followers.to_string(),
                ..Default::default()
            });
        }
        if let Some(statuses) = account.statuses_count {
            rows.push(OzRow {
                label: "Posts".to_string(),
                value: statuses.to_string(),
                ..Default::default()
            });
        }
        if let Some(created) = &account.created_at {
            rows.push(OzRow {
                label: "Created".to_string(),
                value: created.clone(),
                ..Default::default()
            });
        }

        for field in &account.fields {
            let verified = field.verified_at.is_some();
            let label = if verified {
                format!("{} (verified)", field.name)
            } else {
                field.name.clone()
            };
            let field_href = extract_href(&field.value_html);
            rows.push(OzRow {
                label,
                value: strip_html(&field.value_html),
                href: field_href.clone(),
                ..Default::default()
            });

            // Only a verified field proves the linked site back — an unverified field is just
            // typed text, anyone can put anything there, so it must never seed a Domain child.
            if verified
                && let Some(domain) = field_href.as_deref().and_then(extract_domain)
                && seen_domains.insert(domain.clone())
            {
                children.push(ChildSeed {
                    oz_type: OzType::Domain,
                    value: domain,
                    note: Some(format!(
                        "verified Mastodon profile field \"{}\" on {}",
                        field.name, account.instance
                    )),
                });
            }
        }

        if let Some(name) = &account.display_name
            && seen_names.insert(name.clone())
        {
            children.push(ChildSeed {
                oz_type: OzType::Name,
                value: name.clone(),
                note: Some("Mastodon profile display name".to_string()),
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

// ─── HTML helpers (pure, tested) ────────────────────────────────────────────

/// Decodes the five HTML entities Mastodon's `note`/`fields[].value` actually use. `&amp;` is
/// decoded last so a doubly-escaped `&amp;lt;` does not get accidentally unescaped twice.
fn decode_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// Drops every `<...>` tag, decodes entities, and collapses whitespace. Pure and tested.
pub fn strip_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for c in input.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if in_tag => {}
            _ => out.push(c),
        }
    }
    decode_entities(&out)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Pulls the first `href="..."` target out of a fragment of HTML, entity-decoded. `None` when
/// there is no `href` attribute at all. Pure and tested.
pub fn extract_href(html: &str) -> Option<String> {
    const NEEDLE: &str = "href=\"";
    let idx = html.find(NEEDLE)?;
    let rest = html.get(idx + NEEDLE.len()..)?;
    let end = rest.find('"')?;
    Some(decode_entities(&rest[..end]))
}

// ─── Network (untested — see module docs) ──────────────────────────────────

/// What probing one instance produced.
enum InstanceProbe {
    Found(MastodonAccount),
    /// A clean 404 — the instance answered and the account genuinely does not exist there.
    NotFound,
    /// The probe itself failed — we learned nothing from this instance.
    Error(ToolOutcome),
    Cancelled,
}

async fn probe_one_instance(
    instance: &str,
    handle: &str,
    ctx: &crate::sources::ToolCtx,
) -> InstanceProbe {
    let url = format!(
        "https://{instance}/api/v1/accounts/lookup?acct={}",
        urlencoding::encode(handle)
    );
    // Which instance and which handle this probe answers for — the two together are the whole
    // request, and every instance in the fan-out must get its own cache row.
    let outcome = ctx
        .fetch(
            "mastodon-lookup",
            &format!("{instance}:{handle}"),
            &url,
            fetch::OzFetchOptions {
                cancel: ctx.cancel.clone(),
                ..Default::default()
            },
        )
        .await;

    if matches!(outcome, OzOutcome::Cancelled) {
        return InstanceProbe::Cancelled;
    }
    // A clean 404 is Mastodon's documented "no such account" answer, not a probe failure.
    if let OzOutcome::HttpError { status: 404, .. } = &outcome {
        return InstanceProbe::NotFound;
    }
    if let Some(failure) = crate::sources::fold_fetch_failure(&outcome) {
        return InstanceProbe::Error(failure);
    }
    let OzOutcome::Ok(resp) = outcome else {
        unreachable!("every non-Ok, non-Cancelled, non-404 OzOutcome was handled above");
    };
    let OzBody::Json(json) = &resp.body else {
        return InstanceProbe::Error(ToolOutcome::ParseError {
            message: format!("mastodon response from {instance} was not JSON"),
        });
    };
    match parse_mastodon_account(json, instance) {
        Ok(account) => InstanceProbe::Found(account),
        Err(message) => InstanceProbe::Error(ToolOutcome::ParseError { message }),
    }
}

/// Fans a handle out across [`MASTODON_INSTANCES`]. **Counts as ONE lookup**, not eight — the
/// per-instance detail lives inside the one [`ToolYield`] this produces, same convention as
/// [`super::wmn::run_wmn_probe`].
///
/// Outcome rule (see this module's caller brief for the full rationale): at least one instance
/// with an account → `OkWithResults`; every instance a clean 404 → `OkEmpty` (a real, positive
/// finding — checked N instances, present on none); every single instance erroring → **not**
/// `OkEmpty`, the folded failure from the first error, because that case means the sweep taught
/// us nothing at all; a mix of clean answers (found or 404) and errors reports the successful
/// outcome computed from the clean answers alone, with an "Instances unreachable" row so the
/// analyst can see the sweep was partial rather than exhaustive.
pub async fn run_mastodon_lookup(handle: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let semaphore = Semaphore::new(MASTODON_CONCURRENCY);
    let probes: Vec<InstanceProbe> =
        futures::future::join_all(MASTODON_INSTANCES.iter().map(|instance| {
            let semaphore = &semaphore;
            async move {
                let _permit = semaphore
                    .acquire()
                    .await
                    .expect("semaphore is never closed");
                probe_one_instance(instance, handle, ctx).await
            }
        }))
        .await;

    if probes.iter().any(|p| matches!(p, InstanceProbe::Cancelled)) {
        return DispatchOutcome::Cancelled;
    }

    let mut accounts = Vec::new();
    let mut clean_not_found: u32 = 0;
    let mut errors: Vec<ToolOutcome> = Vec::new();
    for probe in probes {
        match probe {
            InstanceProbe::Found(account) => accounts.push(account),
            InstanceProbe::NotFound => clean_not_found += 1,
            InstanceProbe::Error(outcome) => errors.push(outcome),
            InstanceProbe::Cancelled => unreachable!("cancellation was handled above"),
        }
    }

    let clean_answers = accounts.len() as u32 + clean_not_found;
    if clean_answers == 0 {
        // Every instance errored: this is "we learned nothing", never a verified absence.
        let first = errors
            .into_iter()
            .next()
            .expect("clean_answers == 0 with a non-empty instance list implies at least one error");
        return DispatchOutcome::Ran(first, None);
    }

    let tool_outcome = if !accounts.is_empty() {
        ToolOutcome::OkWithResults {
            count: accounts.len() as u32,
        }
    } else {
        ToolOutcome::OkEmpty
    };

    let mut produced = accounts_to_yield(&accounts);
    if !errors.is_empty() {
        produced.rows.push(OzRow {
            label: "Instances unreachable".to_string(),
            value: format!("{} of {}", errors.len(), MASTODON_INSTANCES.len()),
            ..Default::default()
        });
    }

    DispatchOutcome::Ran(tool_outcome, Some(produced))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_account_json() -> serde_json::Value {
        serde_json::json!({
            "id": "1",
            "username": "Gargron",
            "acct": "Gargron",
            "display_name": "Eugen Rochko",
            "note": "<p>Executive Strategy &amp; Product Advisor, Founder of ...</p>",
            "url": "https://mastodon.social/@Gargron",
            "avatar": "https://files.mastodon.social/accounts/avatars/original/x.png",
            "created_at": "2016-03-16T00:00:00.000Z",
            "followers_count": 382282,
            "following_count": 734,
            "statuses_count": 82088,
            "bot": false,
            "locked": false,
            "fields": [
                {
                    "name": "GitHub",
                    "value": "<a href=\"https://github.com/Gargron\" target=\"_blank\" rel=\"nofollow noopener me\">github.com/Gargron</a>",
                    "verified_at": "2023-02-07T23:24:40.347+00:00"
                }
            ]
        })
    }

    // ── parsing ──────────────────────────────────────────────────────────

    #[test]
    fn parses_a_full_mastodon_account() {
        let account = parse_mastodon_account(&full_account_json(), "mastodon.social")
            .expect("account parses");
        assert_eq!(account.instance, "mastodon.social");
        assert_eq!(account.acct, "Gargron");
        assert_eq!(account.url, "https://mastodon.social/@Gargron");
        assert_eq!(account.display_name.as_deref(), Some("Eugen Rochko"));
        assert_eq!(
            account.note.as_deref(),
            Some("Executive Strategy & Product Advisor, Founder of ...")
        );
        assert_eq!(account.followers_count, Some(382282));
        assert_eq!(account.statuses_count, Some(82088));
        assert_eq!(
            account.created_at.as_deref(),
            Some("2016-03-16T00:00:00.000Z")
        );
        assert_eq!(account.fields.len(), 1);
        assert_eq!(account.fields[0].name, "GitHub");
        assert!(account.fields[0].verified_at.is_some());
    }

    #[test]
    fn rejects_a_response_missing_acct() {
        let json = serde_json::json!({ "username": "someone" });
        assert!(parse_mastodon_account(&json, "mastodon.social").is_err());
    }

    #[test]
    fn rejects_a_response_missing_username() {
        let json = serde_json::json!({ "acct": "someone" });
        assert!(parse_mastodon_account(&json, "mastodon.social").is_err());
    }

    #[test]
    fn parses_an_account_with_no_fields_and_no_note() {
        let json =
            serde_json::json!({ "username": "bare", "acct": "bare", "url": "https://x/@bare" });
        let account = parse_mastodon_account(&json, "mas.to").expect("account parses");
        assert!(account.fields.is_empty());
        assert_eq!(account.note, None);
        assert_eq!(account.display_name, None);
    }

    // ── strip_html / extract_href ───────────────────────────────────────

    #[test]
    fn strip_html_drops_tags_and_collapses_whitespace() {
        assert_eq!(
            strip_html("<p>Hello   <b>World</b></p>\n<p>!</p>"),
            "Hello World !"
        );
    }

    #[test]
    fn strip_html_decodes_entities() {
        assert_eq!(
            strip_html("Tom &amp; Jerry &lt;3 &quot;fun&quot; &#39;times&#39;"),
            "Tom & Jerry <3 \"fun\" 'times'"
        );
    }

    #[test]
    fn strip_html_does_not_double_decode_escaped_ampersand() {
        assert_eq!(strip_html("&amp;lt;not a tag&amp;gt;"), "&lt;not a tag&gt;");
    }

    #[test]
    fn extract_href_pulls_the_first_link_target() {
        let html =
            "<a href=\"https://github.com/Gargron\" target=\"_blank\">github.com/Gargron</a>";
        assert_eq!(
            extract_href(html).as_deref(),
            Some("https://github.com/Gargron")
        );
    }

    #[test]
    fn extract_href_decodes_entities_in_the_target() {
        let html = "<a href=\"https://example.com/x?a=1&amp;b=2\">link</a>";
        assert_eq!(
            extract_href(html).as_deref(),
            Some("https://example.com/x?a=1&b=2")
        );
    }

    #[test]
    fn extract_href_is_none_without_an_href_attribute() {
        assert_eq!(extract_href("<span>no link here</span>"), None);
        assert_eq!(extract_href("plain text"), None);
    }

    // ── accounts_to_yield: children only from what the response contained ─

    #[test]
    fn yield_emits_no_children_for_an_account_with_nothing_to_offer() {
        let account = MastodonAccount {
            instance: "mas.to".to_string(),
            acct: "bare".to_string(),
            url: "https://mas.to/@bare".to_string(),
            display_name: None,
            note: None,
            followers_count: None,
            statuses_count: None,
            created_at: None,
            fields: Vec::new(),
        };
        let produced = accounts_to_yield(&[account]);
        assert!(produced.children.is_empty());
        assert_eq!(produced.rows.len(), 1, "only the Mastodon row itself");
    }

    #[test]
    fn yield_emits_a_domain_child_only_for_a_verified_field() {
        let account = MastodonAccount {
            instance: "mastodon.social".to_string(),
            acct: "Gargron".to_string(),
            url: "https://mastodon.social/@Gargron".to_string(),
            display_name: Some("Eugen Rochko".to_string()),
            note: None,
            followers_count: None,
            statuses_count: None,
            created_at: None,
            fields: vec![
                MastodonField {
                    name: "GitHub".to_string(),
                    value_html: "<a href=\"https://github.com/Gargron\">github.com/Gargron</a>"
                        .to_string(),
                    verified_at: Some("2023-02-07T23:24:40.347+00:00".to_string()),
                },
                MastodonField {
                    name: "Blog".to_string(),
                    value_html:
                        "<a href=\"https://unverified.example.com\">unverified.example.com</a>"
                            .to_string(),
                    verified_at: None,
                },
            ],
        };
        let produced = accounts_to_yield(&[account]);

        let domain_children: Vec<&ChildSeed> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Domain)
            .collect();
        assert_eq!(
            domain_children.len(),
            1,
            "only the verified field seeds a Domain child"
        );
        assert_eq!(domain_children[0].value, "github.com");

        let name_children: Vec<&ChildSeed> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Name)
            .collect();
        assert_eq!(name_children.len(), 1);
        assert_eq!(name_children[0].value, "Eugen Rochko");

        // The verified field's row is labelled distinctly; the unverified one is not.
        assert!(produced.rows.iter().any(|r| r.label == "GitHub (verified)"));
        assert!(produced.rows.iter().any(|r| r.label == "Blog"));
        assert!(!produced.rows.iter().any(|r| r.label == "Blog (verified)"));
    }

    #[test]
    fn yield_dedups_children_across_instances_for_the_same_person() {
        let field = MastodonField {
            name: "GitHub".to_string(),
            value_html: "<a href=\"https://github.com/Gargron\">github.com/Gargron</a>".to_string(),
            verified_at: Some("2023-02-07T23:24:40.347+00:00".to_string()),
        };
        let account_a = MastodonAccount {
            instance: "mastodon.social".to_string(),
            acct: "Gargron".to_string(),
            url: "https://mastodon.social/@Gargron".to_string(),
            display_name: Some("Eugen Rochko".to_string()),
            note: None,
            followers_count: None,
            statuses_count: None,
            created_at: None,
            fields: vec![field.clone()],
        };
        let account_b = MastodonAccount {
            instance: "hachyderm.io".to_string(),
            acct: "Gargron".to_string(),
            url: "https://hachyderm.io/@Gargron".to_string(),
            display_name: Some("Eugen Rochko".to_string()),
            note: None,
            followers_count: None,
            statuses_count: None,
            created_at: None,
            fields: vec![field],
        };

        let produced = accounts_to_yield(&[account_a, account_b]);

        let name_children: Vec<&ChildSeed> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Name)
            .collect();
        assert_eq!(
            name_children.len(),
            1,
            "the same display name must not be duplicated"
        );

        let domain_children: Vec<&ChildSeed> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Domain)
            .collect();
        assert_eq!(
            domain_children.len(),
            1,
            "the same verified domain must not be duplicated"
        );

        // But both instances' rows are still present — dedup applies to children, not rows.
        assert_eq!(
            produced
                .rows
                .iter()
                .filter(|r| r.label == "Mastodon")
                .count(),
            2
        );
    }
}
