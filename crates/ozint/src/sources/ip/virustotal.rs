//! `ip-virustotal` — VirusTotal v3's IP-address report. Owns `vtMalicious`/`vtReputation` on
//! [`crate::types::IpPayload`], and seeds the two pivots that are VirusTotal's real value for
//! an address: the malware that talked to it, and the hosts that resolved to it.
//!
//! `GET /api/v3/ip_addresses/{ip}?relationships=communicating_files,resolutions`, header
//! `x-apikey`. Verified live 2026-08-31 against `8.8.8.8`: **HTTP 200**,
//! `data.attributes.last_analysis_stats` (the same eight-bucket shape `hash-virustotal`
//! reads), `data.attributes.reputation` (signed), `data.attributes.as_owner`,
//! `data.attributes.country`, plus `data.relationships.{communicating_files,resolutions}`.
//!
//! Shares the API key and the account quota with `hash-virustotal` and `dom-virustotal` — see
//! `registry::rate_limits_for`'s `"virustotal"` bucket, registered once for all three so the
//! 4/min · 500/day free-tier budget is a crate-wide fact, not a per-tool one nobody enforces.
//! Cached for 24h, same as `hash-virustotal`, for the same reason: the tightest quota in this
//! crate deserves the hardest cache.
//!
//! ## `detections` is `malicious` alone, same convention as `hash-virustotal`
//!
//! [`IpVtRecord::malicious`] reads `last_analysis_stats.malicious` — the plain positive count,
//! not a blend with `suspicious`/`harmless`/etc. Kept as its own field on `IpPayload`
//! (`vtMalicious`) rather than reusing `abuseScore`: a VT engine-consensus count and an
//! AbuseIPDB community-report confidence are different metrics from different providers, and
//! collapsing them into one number would hide which source said what.
//!
//! ## One request, not three — the quota is why
//!
//! The relationships are also reachable as their own sub-resources
//! (`/ip_addresses/{ip}/communicating_files`, `/resolutions`), which return **full objects**
//! rather than descriptors. Measured 2026-08-31, a resolution fetched that way carries `date`
//! (the passive-DNS timestamp), `host_name`, `resolver` and per-host
//! `host_name_last_analysis_stats`. None of that is available through the inline form used
//! here, and the `date` in particular is a real loss: "when did this host point here" is a
//! question an analyst asks and this tool cannot answer.
//!
//! It is given up on purpose. `runtime.rs` acquires **one scheduler permit per tool dispatch**,
//! before `ToolStart` — extra requests made inside a tool are invisible to the `"virustotal"`
//! token bucket. `dom-dns` fires three DoH requests on one permit and that is harmless against
//! a keyless resolver; doing the same against a 4/min · 500/day budget shared by four callers
//! would spend triple what the scheduler believes it is spending, and the failure mode is a
//! ban noticed days later, far from the cause. The inline `relationships=` parameter costs
//! **zero extra quota**, so the permit stays honest. If the sub-resource form is ever wanted,
//! the accounting has to be fixed first, not after.
//!
//! ## The trap: a resolution id is the IP and the hostname concatenated
//!
//! Measured. `data.relationships.resolutions.data[].id` is `"8.8.8.8tst23638229.cn.trust`
//! `exporter.com"` — the queried address and the hostname joined with **no separator**. Read
//! naively it yields `8.8.8.8tst23638229.cn.trustexporter.com`, a hostname that does not
//! exist: a fabricated finding sitting next to real ones, which is exactly the shape of
//! `certspotter`'s `advancedjs.bitinvestor.net` problem. [`hostname_from_resolution_id`]
//! strips the address prefix — taken from `data.id`, VirusTotal's own canonical spelling of
//! it, not from the string this crate happened to query with — and **drops** any id that does
//! not carry that prefix rather than guessing where the boundary is. Corroborated against the
//! sub-resource form, whose `host_name` field equals the stripped remainder exactly.
//!
//! ## The trap that matters more: a resolution is not a relationship
//!
//! `8.8.8.8`'s twenty resolutions are `tst23638229.cn.trustexporter.com`,
//! `haicheng.yowefilm.com`, `m.xueliyingyu.com` and similar — spam and parking hosts with
//! nothing whatever to do with Google. Pointing a DNS record at a public resolver, a CDN edge
//! or any shared address is something anyone can do unilaterally, so passive DNS on shared
//! infrastructure is mostly other people's noise. Unlike `certspotter`, **there is no scoping
//! rule that can filter it** — the relationship asserts no ownership, so there is nothing to
//! test a candidate against.
//!
//! Two things are done about it instead of pretending otherwise: the cap is
//! [`MAX_VT_RELATION_CHILDREN`], half the subdomain cap (see its own doc), and the caveat is
//! stated as a **row** on the address the children hang off, so an analyst reading the tree a
//! week later sees why those nodes are there without having to remember this file.
//!
//! The row is the caveat's only real home, and that is worth saying plainly, because the
//! obvious home is a lie. [`ChildSeed::note`] looks like the field for exactly this, and every
//! seeded child here sets it — but `runtime::emit_child` builds its `Provenance` from
//! `ToolDef::id`/`ToolDef::method` and **never reads `seed.note`**. The note is dead for the
//! whole catalogue, not just here (`dom-certspotter`, `ip-peeringdb`, `hash-urlhaus`,
//! `dom-rdap` and `cve-poc-github` all write one nothing reads). It is still set, because it
//! is the right data in the right place and wiring it is an engine change, not a source one —
//! but nothing in this file may claim it reaches a reader until it does.
//!
//! ## Descriptors, order, and the cache key
//!
//! With `relationships=` the items are descriptors — `{"type", "id"}`, no attributes.
//! `communicating_files` ids are the file SHA-256 (verified: 20/20 were 64 lowercase hex),
//! which is directly a `Hash` node value. Both relationships returned exactly
//! [`VT_RELATIONSHIP_PAGE`] items with a `meta.cursor` for the next page; the cursor's presence
//! is what marks the list incomplete, independent of whether the cap also bit.
//!
//! Upstream order is **preserved**, unlike `certspotter`, which sorts. A CT log has no
//! meaningful order so sorting it buys refresh stability for free; VirusTotal ranks
//! resolutions newest-first (its cursor is date-keyed), so sorting before truncating would
//! discard the ten most recent in favour of ten alphabetically-first ones — trading a real
//! signal for a cosmetic one.
//!
//! The cache key is namespaced `rel:{ip}`. `ToolCtx::fetch` keys on `(tool_id, cache_key)` and
//! **not** on the URL, so leaving it as the bare address would let a row written by the older
//! relationship-less request satisfy this one for up to 24h — a body with no `relationships`
//! key parses perfectly and yields no children, which is indistinguishable from an address
//! that genuinely has none. Same reasoning as `dom-dns`'s `mx:`/`ns:`/`txt:` prefixes.

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::{ChildSeed, ToolYield};
use crate::sources::DispatchOutcome;
use crate::types::{MAX_VT_RELATION_CHILDREN, OzRow, OzType};

const VT_IP_BASE: &str = "https://www.virustotal.com/api/v3/ip_addresses/";
const ENV_VAR: &str = "VIRUSTOTAL_API_KEY";

/// The relationships requested inline. Order is VirusTotal's to decide; this is a set.
const VT_IP_RELATIONSHIPS: &str = "communicating_files,resolutions";

/// Items VirusTotal returns per relationship when they are requested inline — measured
/// 2026-08-31, exactly 20 for both, alongside a `meta.cursor`. Not used as a cap (that is
/// [`MAX_VT_RELATION_CHILDREN`]); recorded so a future drift in the page size is a visible
/// constant rather than a magic number nobody re-measured.
const VT_RELATIONSHIP_PAGE: usize = 20;

/// The sentence an analyst must read before treating a passive-DNS child as a connection.
/// Stated once, on the address, rather than repeated on twenty rows.
const PASSIVE_DNS_CAVEAT: &str = "hostnames that pointed here at some point — anyone can point a record at a shared \
     address, so each is a lead, not a link";

/// `https://www.virustotal.com/gui/…` — the human-readable page for a descriptor, so a row
/// carries the analyst to the evidence rather than only naming it.
const VT_GUI_FILE: &str = "https://www.virustotal.com/gui/file/";
const VT_GUI_DOMAIN: &str = "https://www.virustotal.com/gui/domain/";

/// One relationship's descriptors after deduplication and capping.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VtRelation {
    pub values: Vec<String>,
    /// The list is not the complete set — either the upstream page carried a `meta.cursor`, or
    /// [`MAX_VT_RELATION_CHILDREN`] cut it. Both mean the same thing to the analyst.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct IpVtRecord {
    pub malicious: u32,
    pub reputation: i64,
    pub as_owner: Option<String>,
    pub country: Option<String>,
    /// SHA-256 of files VirusTotal observed communicating with this address.
    pub communicating_files: VtRelation,
    /// Hostnames that resolved to this address, per VirusTotal's passive DNS. Read the module
    /// doc's second trap before treating one as related to the subject.
    pub resolutions: VtRelation,
}

fn nonempty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// A file descriptor's id is the sample's SHA-256. Anything that is not 64 lowercase hex is
/// dropped rather than seeded: a `Hash` node whose value is not a hash is a dead end that
/// looks like a finding. Pure and tested.
fn is_sha256(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Splits `{ip}{hostname}` — VirusTotal's resolution id — into the hostname, given the address
/// spelled as VirusTotal itself spells it. `None` when the id does not carry that prefix, or
/// when what remains is not plausibly a hostname: the boundary is knowable only through the
/// prefix, so an id that lacks it is dropped rather than cut at a guessed offset. Pure and
/// tested.
fn hostname_from_resolution_id(id: &str, ip: &str) -> Option<String> {
    let host = id.strip_prefix(ip)?.trim();
    // A hostname with no dot cannot be a public name, and an empty remainder would mean the id
    // was the bare address — neither is a domain worth seeding.
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// Reads one `data.relationships.{name}` block: maps each descriptor id through `keep`,
/// deduplicates while preserving VirusTotal's order (see the module doc), then caps at
/// [`MAX_VT_RELATION_CHILDREN`].
///
/// A relationship VirusTotal did not return at all and one it returned empty are both an empty
/// [`VtRelation`] — the distinction is not observable here and inventing one would be a claim
/// this tool cannot support. Pure and tested.
fn read_relation(
    relationships: Option<&serde_json::Value>,
    name: &str,
    keep: impl Fn(&str) -> Option<String>,
) -> VtRelation {
    let Some(block) = relationships.and_then(|r| r.get(name)) else {
        return VtRelation::default();
    };
    let items = block
        .get("data")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    let mut values: Vec<String> = Vec::new();
    for item in items {
        let Some(id) = item.get("id").and_then(serde_json::Value::as_str) else {
            // A shape-drifted descriptor — tolerated the way `certspotter` tolerates one
            // malformed issuance. One odd entry must not cost the other nineteen.
            continue;
        };
        if let Some(value) = keep(id)
            && !values.contains(&value)
        {
            values.push(value);
        }
    }

    // A cursor means VirusTotal has more to give; a full page without one still means this
    // tool asked for a page and got a page. Either way the enumeration is not exhaustive.
    let has_more = block
        .get("meta")
        .and_then(|m| m.get("cursor"))
        .is_some_and(|c| !c.is_null())
        || items.len() >= VT_RELATIONSHIP_PAGE;
    let cap_was_hit = values.len() > MAX_VT_RELATION_CHILDREN;
    values.truncate(MAX_VT_RELATION_CHILDREN);

    VtRelation {
        values,
        truncated: has_more || cap_was_hit,
    }
}

pub fn parse_ip_vt_response(json: &serde_json::Value) -> Result<IpVtRecord, String> {
    let data = json
        .get("data")
        .ok_or_else(|| "VirusTotal response has no `data`".to_string())?;
    let attrs = data
        .get("attributes")
        .ok_or_else(|| "VirusTotal response has no `data.attributes`".to_string())?;

    let malicious = attrs
        .get("last_analysis_stats")
        .and_then(|v| v.get("malicious"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let reputation = attrs
        .get("reputation")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let relationships = data.get("relationships");
    let communicating_files = read_relation(relationships, "communicating_files", |id| {
        is_sha256(id).then(|| id.to_string())
    });
    // VirusTotal's own spelling of the address, which is what the resolution ids are built
    // from. Absent it, no id can be split safely, so no resolution is kept — see the module
    // doc's first trap.
    let canonical_ip = data.get("id").and_then(serde_json::Value::as_str);
    let resolutions = match canonical_ip {
        Some(ip) => read_relation(relationships, "resolutions", |id| {
            hostname_from_resolution_id(id, ip)
        }),
        None => VtRelation::default(),
    };

    Ok(IpVtRecord {
        malicious,
        reputation,
        as_owner: nonempty(attrs.get("as_owner").and_then(|v| v.as_str())),
        country: nonempty(attrs.get("country").and_then(|v| v.as_str())),
        communicating_files,
        resolutions,
    })
}

/// The row a truncated relationship adds, saying what was kept and what that means. No payload
/// field exists to carry the flag — `IpPayload` has no list for either relationship and adding
/// one nothing reads would be a dead field — so the signal is rendered, the same choice
/// `ip-peeringdb` makes for its contacts.
///
/// The ` (partial)` suffix is not decoration. Labelled identically to the rows it qualifies,
/// this row reads as one more finding of the same kind — a caught test, not a hypothetical.
fn truncation_row(label: &str, kept: usize) -> OzRow {
    OzRow {
        label: format!("{label} (partial)"),
        value: format!("VirusTotal has more; the first {kept} became pivotable nodes"),
        ..Default::default()
    }
}

/// Owns `vtMalicious`/`vtReputation` alone. Deliberately does not touch `country` — `ip-ipinfo`
/// owns that field, and VT's own country attribute is a coarser, less-current signal (it moves
/// on VT's re-scan cadence, not on address-block delegation) that would only ever agree or
/// silently lose to whichever tool wrote second.
///
/// Neither relationship is written to the payload either, for the same reason `ip-peeringdb`
/// writes none: nothing reads it. `signal.rs`'s `ip_chip` reads `abuse_score`, `vt_malicious`
/// and `classification`, and a new `IpPayload` list would be parsed, stored and rendered
/// nowhere — the exact shape of the dead fields issue #13 catalogues. Rows and children carry
/// it instead, and both are rendered generically.
pub fn ip_vt_record_to_yield(record: &IpVtRecord) -> ToolYield {
    let mut rows = Vec::new();
    if let Some(owner) = &record.as_owner {
        rows.push(OzRow {
            label: "VT AS owner".to_string(),
            value: owner.clone(),
            ..Default::default()
        });
    }

    for sha in &record.communicating_files.values {
        rows.push(OzRow {
            label: "Communicating file".to_string(),
            value: sha.clone(),
            href: Some(format!("{VT_GUI_FILE}{sha}")),
            ..Default::default()
        });
    }
    if record.communicating_files.truncated {
        rows.push(truncation_row(
            "Communicating file",
            record.communicating_files.values.len(),
        ));
    }

    if !record.resolutions.values.is_empty() {
        rows.push(OzRow {
            // Parenthesised like the `(partial)` markers: a row that qualifies findings must
            // not be labelled as one of them. See `truncation_row`.
            label: "Passive DNS (caution)".to_string(),
            value: PASSIVE_DNS_CAVEAT.to_string(),
            tone: Some(crate::types::SignalTone::Warn),
            ..Default::default()
        });
    }
    for host in &record.resolutions.values {
        rows.push(OzRow {
            label: "Passive DNS".to_string(),
            value: host.clone(),
            href: Some(format!("{VT_GUI_DOMAIN}{host}")),
            ..Default::default()
        });
    }
    if record.resolutions.truncated {
        rows.push(truncation_row(
            "Passive DNS",
            record.resolutions.values.len(),
        ));
    }

    let mut children: Vec<ChildSeed> = record
        .communicating_files
        .values
        .iter()
        .map(|sha| ChildSeed {
            oz_type: OzType::Hash,
            value: sha.clone(),
            note: Some("a file VirusTotal observed communicating with this address".to_string()),
        })
        .collect();
    children.extend(record.resolutions.values.iter().map(|host| {
        ChildSeed {
            oz_type: OzType::Domain,
            value: host.clone(),
            // Set, but not yet read by anything — see the module doc's last paragraph. The caveat
            // an analyst actually sees is `PASSIVE_DNS_CAVEAT`, rendered as a row above.
            note: Some(
                "resolved to this address at some point (VirusTotal passive DNS) — anyone can \
             point a hostname at a shared address, so this is a lead, not a link"
                    .to_string(),
            ),
        }
    }));

    ToolYield {
        payload_patch: serde_json::json!({
            "vtMalicious": record.malicious,
            "vtReputation": record.reputation,
        }),
        rows,
        children,
        ..Default::default()
    }
}

pub async fn run_ip_virustotal(ip: &str, ctx: &crate::sources::ToolCtx) -> DispatchOutcome {
    let Some(key) = ozint_core::config::optional(ENV_VAR) else {
        return DispatchOutcome::Ran(
            ToolOutcome::SkippedNoKey {
                env_var: ENV_VAR.to_string(),
            },
            None,
        );
    };

    let url = format!(
        "{VT_IP_BASE}{}?relationships={VT_IP_RELATIONSHIPS}",
        urlencoding::encode(ip)
    );
    let headers = vec![("x-apikey".to_string(), key)];
    let outcome = ctx
        .fetch(
            "ip-virustotal",
            // Namespaced by request shape, not by address alone — see the module doc's last
            // paragraph for what an un-namespaced key would silently serve.
            &format!("rel:{ip}"),
            &url,
            fetch::OzFetchOptions {
                headers,
                ..Default::default()
            },
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
                message: "VirusTotal response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_ip_vt_response(json) {
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
        Ok(record) => {
            // The report itself is one result; each pivot the analyst can now take is another.
            // Counting only the report would have this tool report the same "1" whether it
            // found twenty leads or none.
            let count = 1
                + record.communicating_files.values.len() as u32
                + record.resolutions.values.len() as u32;
            DispatchOutcome::Ran(
                ToolOutcome::OkWithResults { count },
                Some(ip_vt_record_to_yield(&record)),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real file SHA-256s, verbatim from the live 2026-08-31 `8.8.8.8` call. Real ones rather
    /// than `"a".repeat(64)` so a change to [`is_sha256`] is tested against what VirusTotal
    /// actually sends, including the leading-zero ids that look malformed and are not.
    const REAL_FILE_IDS: [&str; 12] = [
        "00000006e9d3a7e85d1f1e7711787b9a117655e249a565122ee12e9962199007",
        "0000002a10959ec38b808d8252eed2e814294fbb25d2cd016b24bf853a44857e",
        "000000663c7400a78ee27404b7b7a8d2705aff4cc1fd2ddc8e1ebff2c4875913",
        "000000716fa472f01dbafd6f3adc57f4c476b11854d8304ee36afea88397ba45",
        "00000075d77e227cdb2d386181e42f42b579eb16403143dc54cd4a3d17fc8622",
        "00000078afd5c2441b0a4ca628c1b7bcc961a68f2b779d281af6d2af405b5f1a",
        "0000007e69ce5aed0e23ca1c5f85ac2bda42f71f84841aea9db049633b7a1677",
        "00000085882dc946e2ec5dd74baaa0ffc880e9a0f3c0ccb3e037fe71a28eea96",
        "0000009cb00b240966baee8acfdcd80a517756866c395e36f391b33109464c34",
        "000000c82b887e512b6f391b1314fea3fdef4ffb027d84e483c5d99a66d696fd",
        "0000014137c91a689f5e304a25eb97ddd8bb33d427d82e3ef091e33276a4c43e",
        "000001685664a2ff3ad69db775ba8dbe67898b76e9507879d216b6580840cdb4",
    ];

    /// Real resolution ids, verbatim from the same call — the concatenated form the module
    /// doc's first trap is about.
    const REAL_RESOLUTION_IDS: [&str; 12] = [
        "8.8.8.8tst23638229.cn.trustexporter.com",
        "8.8.8.8haicheng.yowefilm.com",
        "8.8.8.8wap.haicheng.yowefilm.com",
        "8.8.8.8m.xueliyingyu.com",
        "8.8.8.83g.article.lxygl.cn",
        "8.8.8.8article.hysys.com.cn",
        "8.8.8.8m.article.hysys.com.cn",
        "8.8.8.8dns.xiaoli.top",
        "8.8.8.8article.vipcqsa.com",
        "8.8.8.8m.article.vipcqsa.com",
        "8.8.8.8m.article.chenresin.com",
        "8.8.8.8shuhan101212.cn.trustexporter.com",
    ];

    fn descriptors(kind: &str, ids: &[&str]) -> serde_json::Value {
        serde_json::json!(
            ids.iter()
                .map(|id| serde_json::json!({ "type": kind, "id": id }))
                .collect::<Vec<_>>()
        )
    }

    /// Trimmed from a live 2026-08-31 call against `8.8.8.8`, relationships included. `cursor`
    /// is present on both blocks exactly as VirusTotal sent it.
    fn google_dns() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "id": "8.8.8.8",
                "type": "ip_address",
                "attributes": {
                    "as_owner": "Google LLC",
                    "country": "US",
                    "reputation": 557,
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0, "undetected": 20, "harmless": 68, "timeout": 0
                    }
                },
                "relationships": {
                    "communicating_files": {
                        "data": descriptors("file", &REAL_FILE_IDS),
                        "meta": { "cursor": "eyJsaW1pdCI6IDIwLCAib2Zmc2V0IjogMjB9" }
                    },
                    "resolutions": {
                        "data": descriptors("resolution", &REAL_RESOLUTION_IDS),
                        "meta": { "cursor": "CloKEQoEZGF0ZRIJCP_e7Pygy5YD" }
                    }
                }
            }
        })
    }

    /// The pre-relationships response: the shape this tool asked for until 2026-08-31, and the
    /// shape a stale cache row can still hold. It must parse, not error.
    fn google_dns_without_relationships() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "id": "8.8.8.8",
                "attributes": {
                    "as_owner": "Google LLC",
                    "country": "US",
                    "reputation": 557,
                    "last_analysis_stats": { "malicious": 0, "harmless": 68 }
                }
            }
        })
    }

    // ── the report itself, unchanged by the relationships work ───────────────

    #[test]
    fn parses_a_real_record() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        assert_eq!(record.malicious, 0);
        assert_eq!(record.reputation, 557);
        assert_eq!(record.as_owner.as_deref(), Some("Google LLC"));
    }

    #[test]
    fn yield_owns_only_the_two_documented_keys() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        let produced = ip_vt_record_to_yield(&record);
        let obj = produced.payload_patch.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["vtMalicious", "vtReputation"]);
    }

    #[test]
    fn rejects_a_response_missing_attributes() {
        assert!(parse_ip_vt_response(&serde_json::json!({})).is_err());
    }

    // ── splitting a resolution id, the trap this module exists to avoid ──────

    #[test]
    fn a_resolution_id_is_split_on_the_address_prefix_leaving_only_the_hostname() {
        assert_eq!(
            hostname_from_resolution_id("8.8.8.8tst23638229.cn.trustexporter.com", "8.8.8.8")
                .as_deref(),
            Some("tst23638229.cn.trustexporter.com"),
            "the address prefix must be removed — keeping it fabricates a hostname that does \
             not exist"
        );
    }

    #[test]
    fn a_resolution_id_that_does_not_carry_the_address_prefix_is_dropped_not_cut() {
        // The boundary between address and hostname is knowable only through the prefix.
        assert_eq!(
            hostname_from_resolution_id("1.1.1.1example.com", "8.8.8.8"),
            None
        );
    }

    #[test]
    fn a_resolution_id_that_is_the_bare_address_yields_no_hostname() {
        assert_eq!(hostname_from_resolution_id("8.8.8.8", "8.8.8.8"), None);
    }

    #[test]
    fn a_remainder_with_no_dot_is_not_treated_as_a_hostname() {
        assert_eq!(
            hostname_from_resolution_id("8.8.8.8localhost", "8.8.8.8"),
            None
        );
    }

    #[test]
    fn resolutions_are_dropped_entirely_when_the_response_names_no_canonical_address() {
        let mut json = google_dns();
        json["data"].as_object_mut().unwrap().remove("id");
        let record = parse_ip_vt_response(&json).unwrap();
        assert!(
            record.resolutions.values.is_empty(),
            "with no canonical address there is no safe split, so nothing may be seeded"
        );
        assert!(
            !record.communicating_files.values.is_empty(),
            "the file relationship does not depend on the address and must survive"
        );
    }

    // ── descriptor validation ────────────────────────────────────────────────

    #[test]
    fn a_communicating_file_descriptor_that_is_not_a_sha256_is_not_seeded() {
        assert!(is_sha256(REAL_FILE_IDS[0]));
        assert!(!is_sha256("deadbeef"), "too short");
        assert!(
            !is_sha256("0000006E9D3A7E85D1F1E7711787B9A117655E249A565122EE12E9962199007A"),
            "uppercase is not the form VirusTotal sends, and a Hash node value must be canonical"
        );
    }

    #[test]
    fn a_malformed_descriptor_costs_only_itself() {
        let json = serde_json::json!({
            "data": {
                "id": "8.8.8.8",
                "attributes": { "last_analysis_stats": { "malicious": 1 } },
                "relationships": {
                    "communicating_files": { "data": [
                        { "type": "file" },
                        { "type": "file", "id": REAL_FILE_IDS[0] }
                    ]}
                }
            }
        });
        let record = parse_ip_vt_response(&json).unwrap();
        assert_eq!(record.communicating_files.values, vec![REAL_FILE_IDS[0]]);
    }

    #[test]
    fn a_descriptor_repeated_by_the_upstream_is_seeded_once() {
        let json = serde_json::json!({
            "data": {
                "id": "8.8.8.8",
                "attributes": { "last_analysis_stats": { "malicious": 0 } },
                "relationships": {
                    "resolutions": { "data": descriptors(
                        "resolution",
                        &["8.8.8.8a.example.com", "8.8.8.8a.example.com", "8.8.8.8b.example.com"]
                    )}
                }
            }
        });
        let record = parse_ip_vt_response(&json).unwrap();
        assert_eq!(
            record.resolutions.values,
            vec!["a.example.com", "b.example.com"]
        );
    }

    // ── order and the cap ────────────────────────────────────────────────────

    #[test]
    fn upstream_order_survives_the_cap_rather_than_being_sorted_away() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        // VirusTotal ranks resolutions newest-first. Sorting before truncating would keep the
        // ten alphabetically-first hostnames instead of the ten most recent — `3g.article…`
        // sorts ahead of every other name here and must NOT lead the kept list.
        assert_eq!(
            record.resolutions.values.first().map(String::as_str),
            Some("tst23638229.cn.trustexporter.com"),
            "the first kept resolution must be VirusTotal's first, not the alphabetical first"
        );
        assert_eq!(record.resolutions.values.len(), MAX_VT_RELATION_CHILDREN);
    }

    #[test]
    fn the_cap_bounds_each_relationship_separately() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        assert_eq!(
            record.communicating_files.values.len(),
            MAX_VT_RELATION_CHILDREN
        );
        assert_eq!(record.resolutions.values.len(), MAX_VT_RELATION_CHILDREN);
    }

    #[test]
    fn a_cursor_marks_a_relationship_truncated() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        assert!(record.communicating_files.truncated);
        assert!(record.resolutions.truncated);
    }

    #[test]
    fn a_short_relationship_with_no_cursor_is_not_truncated() {
        let json = serde_json::json!({
            "data": {
                "id": "8.8.8.8",
                "attributes": { "last_analysis_stats": { "malicious": 0 } },
                "relationships": {
                    "resolutions": { "data": descriptors("resolution", &["8.8.8.8a.example.com"]) }
                }
            }
        });
        let record = parse_ip_vt_response(&json).unwrap();
        assert_eq!(record.resolutions.values, vec!["a.example.com"]);
        assert!(
            !record.resolutions.truncated,
            "one item and no cursor is a complete answer, and saying otherwise would teach the \
             analyst to distrust a list that is in fact whole"
        );
    }

    // ── what reaches the tree ────────────────────────────────────────────────

    #[test]
    fn every_kept_descriptor_becomes_a_child_of_the_right_type() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        let produced = ip_vt_record_to_yield(&record);

        let hashes: Vec<&str> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Hash)
            .map(|c| c.value.as_str())
            .collect();
        let domains: Vec<&str> = produced
            .children
            .iter()
            .filter(|c| c.oz_type == OzType::Domain)
            .map(|c| c.value.as_str())
            .collect();

        assert_eq!(hashes, &REAL_FILE_IDS[..MAX_VT_RELATION_CHILDREN]);
        assert_eq!(domains.first(), Some(&"tst23638229.cn.trustexporter.com"));
        assert_eq!(domains.len(), MAX_VT_RELATION_CHILDREN);
        assert!(
            domains.iter().all(|d| !d.starts_with("8.8.8.8")),
            "a child whose value still carries the address prefix is a fabricated hostname"
        );
    }

    #[test]
    fn every_kept_descriptor_is_also_readable_as_a_row() {
        // The steam.rs lesson: a value that becomes a child and not a row is invisible to an
        // analyst who does not click, and `cve-poc-github` shipped exactly that way.
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        let produced = ip_vt_record_to_yield(&record);

        for sha in &record.communicating_files.values {
            assert!(
                produced.rows.iter().any(|r| &r.value == sha),
                "{sha} became a child but no row"
            );
        }
        for host in &record.resolutions.values {
            assert!(
                produced.rows.iter().any(|r| &r.value == host),
                "{host} became a child but no row"
            );
        }
    }

    #[test]
    fn every_relationship_row_links_out_to_the_evidence() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        let produced = ip_vt_record_to_yield(&record);
        for row in produced
            .rows
            .iter()
            .filter(|r| r.label == "Communicating file" || r.label == "Passive DNS")
        {
            assert!(
                row.href
                    .as_deref()
                    .is_some_and(|h| h.starts_with("https://")),
                "row {:?} carries no link to what it claims",
                row.label
            );
        }
    }

    #[test]
    fn the_passive_dns_caveat_reaches_the_analyst_through_a_row_not_only_a_child_note() {
        // `ChildSeed::note` is set on every seeded child and read by nothing — `emit_child`
        // builds its provenance from the `ToolDef` alone. Asserting the note said the right
        // thing would be the `steam.rs` mistake: a test passing on a value that never leaves
        // the crate. This asserts the channel that renders.
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        let produced = ip_vt_record_to_yield(&record);
        let caveat = produced
            .rows
            .iter()
            .find(|r| r.value == PASSIVE_DNS_CAVEAT)
            .expect("a layer that seeds passive-DNS children must state what they mean");
        assert_eq!(caveat.tone, Some(crate::types::SignalTone::Warn));
        assert!(caveat.label.ends_with("(caution)"));
    }

    #[test]
    fn no_caveat_row_appears_when_there_is_nothing_to_caveat() {
        let record = parse_ip_vt_response(&google_dns_without_relationships()).unwrap();
        let produced = ip_vt_record_to_yield(&record);
        assert!(
            !produced.rows.iter().any(|r| r.value == PASSIVE_DNS_CAVEAT),
            "a warning about findings that do not exist is noise"
        );
    }

    #[test]
    fn a_passive_dns_child_still_carries_the_caveat_in_its_note_for_when_notes_are_wired() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        let produced = ip_vt_record_to_yield(&record);
        let domain_child = produced
            .children
            .iter()
            .find(|c| c.oz_type == OzType::Domain)
            .expect("the fixture seeds domain children");
        let note = domain_child.note.as_deref().unwrap_or_default();
        assert!(
            note.contains("lead, not a link"),
            "nothing reads this yet, but the day `emit_child` does, the right sentence has to \
             already be in it: {note}"
        );
    }

    #[test]
    fn a_truncated_relationship_says_so_in_a_row() {
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        let produced = ip_vt_record_to_yield(&record);
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Passive DNS (partial)"
                    && r.value.contains("VirusTotal has more")),
            "a capped list with nothing marking it partial reads as a complete enumeration"
        );
    }

    #[test]
    fn a_partial_list_marker_is_never_labelled_as_one_of_the_findings_it_qualifies() {
        // It was, and the "every row links out" test above is what caught it: the marker row
        // carries no href, so a reader filtering on the data label got a finding with no
        // evidence behind it.
        let record = parse_ip_vt_response(&google_dns()).unwrap();
        let produced = ip_vt_record_to_yield(&record);
        for row in &produced.rows {
            let qualifies_rather_than_finds =
                row.value.contains("VirusTotal has more") || row.value == PASSIVE_DNS_CAVEAT;
            assert_eq!(
                qualifies_rather_than_finds,
                row.label.ends_with(')'),
                "row {:?} / {:?} is ambiguous about whether it is a finding",
                row.label,
                row.value
            );
        }
    }

    // ── the shapes that must not look like an empty answer ───────────────────

    #[test]
    fn a_response_carrying_no_relationships_still_parses_and_seeds_nothing() {
        // A cache row written before 2026-08-31 has exactly this shape. It must parse — but
        // note that the cache key is namespaced precisely so this is never actually served
        // for a request that asked for relationships.
        let record = parse_ip_vt_response(&google_dns_without_relationships()).unwrap();
        assert_eq!(record.reputation, 557);
        assert!(record.communicating_files.values.is_empty());
        assert!(record.resolutions.values.is_empty());
        assert!(
            !record.communicating_files.truncated && !record.resolutions.truncated,
            "absent is not truncated"
        );
        assert!(ip_vt_record_to_yield(&record).children.is_empty());
    }

    #[tokio::test]
    async fn reports_skipped_no_key_when_the_api_key_is_absent() {
        let prev = std::env::var(ENV_VAR).ok();
        unsafe { std::env::remove_var(ENV_VAR) };

        let outcome = run_ip_virustotal("8.8.8.8", &crate::sources::ToolCtx::default()).await;
        match outcome {
            DispatchOutcome::Ran(ToolOutcome::SkippedNoKey { env_var }, produced) => {
                assert_eq!(env_var, ENV_VAR);
                assert!(produced.is_none());
            }
            other => panic!("expected SkippedNoKey without a key, got {other:?}"),
        }

        if let Some(v) = prev {
            unsafe { std::env::set_var(ENV_VAR, v) };
        }
    }
}
