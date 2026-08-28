//! "What did this URL look like, and can I prove it later."
//!
//! An OSINT finding is a claim about a page that can change or vanish between the moment a tool
//! read it and the moment anyone checks the investigation. This unit records the **Internet
//! Archive captures that already exist** for a URL, so a finding can be re-read as it stood.
//!
//! ## What is built here, and what deliberately is not
//!
//! Four tiers were scoped. Only the first is built, and the other three are *blocked*, not
//! merely unwritten — recorded here so nobody rediscovers it:
//!
//! - ✅ **Wayback CDX** (`web.archive.org/cdx/search/cdx`) — keyless, no account, no quota
//!   documented. This module.
//! - ❌ **Save Page Now 2** — *creates* a capture rather than listing existing ones, and needs a
//!   free Internet Archive account's S3-style keys. Despite the name these are **not AWS
//!   credentials**; no such key exists in this deployment and none may be invented.
//! - ❌ **ArchiveBox sidecar** — needs the sidecar bridge and a deployed container.
//! - ❌ **TrueScreen eIDAS sealing** — paid.
//!
//! The distinction that matters for honesty: CDX **reports** archival, it never **performs** it.
//! A node with zero snapshots is not a node that failed to be archived — it is a node nobody
//! ever archived, which is a different (and, for a fresh finding, entirely expected) fact.
//!
//! ## Opt-in, per investigation, never automatic
//!
//! This is a fixed rule: **must be opt-in per investigation** (SPN2 is slow/rate-limited), never
//! automatic per node. The measurement below turns that from a policy into a hard constraint:
//!
//! **CDX is slow.** Measured 2026-08-23 against the live endpoint: 20 s, 25 s and 40 s for three
//! ordinary queries. That is an order of magnitude past any tool in the registry, and it is why
//! [`CDX_TIMEOUT`] is 60 s rather than [`crate::fetch`]'s 12 s default — under that default
//! *every* call here would time out, retry three times, spend ~48 s hammering the endpoint and
//! then report a `Timeout` that says nothing true about the archive. Retries are cut to one for
//! the same reason: retrying an endpoint that is slow by design multiplies load without
//! improving the odds.
//!
//! A capture is therefore something the analyst asks for, on a node, when they want it. Firing
//! it automatically per node would add half a minute per finding to every layer.
//!
//! ## The header row, and why parsing is by name
//!
//! `output=json` returns an array of arrays whose **first row is the field-name header**, not
//! data. Treating it as data yields a phantom snapshot timestamped `"timestamp"`. Fields are
//! therefore resolved *by name* against that header row rather than by position: the column
//! order follows the `fl` parameter, so positional parsing would keep working right up until
//! someone reorders [`CDX_FIELDS`], and would then silently swap two columns rather than fail.

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::fetch::{OzBody, OzFetchOptions, OzOutcome, oz_fetch};

/// Per-attempt timeout. See the module doc: the live endpoint was measured at 20–40 s, so the
/// crate-wide 12 s default guarantees a timeout on every call.
pub const CDX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Columns requested from CDX, in the order they arrive. Resolved by name at parse time — see
/// the module doc on why order must not be load-bearing.
const CDX_FIELDS: &str = "timestamp,original,statuscode,digest,mimetype,length";

/// How many captures are recorded for one URL. The archive holds tens of thousands for a busy
/// page; a provenance row is not a place to put them. The **most recent** are kept
/// (`limit=-N`), because the question this answers is "can I still read what the tool read".
pub const MAX_SNAPSHOTS: usize = 10;

/// One Internet Archive capture of a URL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// The capture instant, parsed from CDX's `yyyyMMddHHmmss` stamp, which is UTC.
    pub captured_at: DateTime<Utc>,
    /// A permanent, directly openable replay URL for this exact capture.
    pub url: String,
    /// The URL as the crawler recorded it — not necessarily the one we asked for. CDX
    /// canonicalises, so asking for `github.com/x` returns captures of `http://github.com:80/x`
    /// among others, and the difference is worth showing rather than smoothing away.
    pub original: String,
    /// The status the crawler got. Kept verbatim as a string: CDX returns `"-"` for records
    /// where it is unknown, and coercing that to a number would invent a status nobody saw.
    pub status: String,
    /// CDX's payload digest — **base32-encoded SHA-1**, which is the archive's own content
    /// identity. This is deliberately **not** a content-SHA256, and is not relabelled as one:
    /// computing a SHA-256 would require downloading every capture's bytes, which this tier
    /// deliberately does not do.
    pub sha1_base32: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mime: Option<String>,
}

/// What one capture attempt found. There is no `Result` here for the same reason
/// [`crate::fetch::OzOutcome`] has none: every branch a caller needs to *render differently* is
/// a variant, and the one that matters most is the difference between the two empty cases.
#[derive(Debug, Clone, PartialEq)]
pub enum CaptureOutcome {
    /// The archive holds captures, most recent first.
    Found(Vec<Snapshot>),
    /// The archive answered, and holds nothing for this URL. **A finding, not a failure** —
    /// CDX returns `200` with a literal `[]`, verified against the live endpoint. Rendering
    /// this as an error would claim the archive was unreachable when it plainly answered.
    NeverArchived,
    /// The request never completed. Carries the reason verbatim rather than collapsing to a
    /// bare "failed", so a timeout, an SSRF refusal and a 5xx stay distinguishable.
    Failed(String),
}

/// One completed evidence check on one URL, as stored on the node.
///
/// **The failed check is recorded, not only the successful one.** A capture that reached
/// nothing and a capture nobody ever ran are different facts, and with only a snapshot list to
/// look at they render identically as "no evidence" — the exact shape of silent failure this
/// project keeps finding. So the three outcomes stay three: snapshots present, an answered
/// check with nothing archived, and a check that did not complete.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRecord {
    /// The URL asked about, as the analyst gave it.
    pub url: String,
    /// When the archive was asked — **not** when anything was captured. A record checked a
    /// year ago says nothing about what the archive holds today.
    pub checked_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub snapshots: Vec<Snapshot>,
    /// `Some(reason)` when the check did not complete. `None` with an empty `snapshots` is the
    /// archive answering that it holds nothing — a finding, and never to be conflated with
    /// this field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub unavailable: Option<String>,
}

impl EvidenceRecord {
    pub fn new(url: impl Into<String>, outcome: CaptureOutcome) -> Self {
        let (snapshots, unavailable) = match outcome {
            CaptureOutcome::Found(s) => (s, None),
            CaptureOutcome::NeverArchived => (Vec::new(), None),
            CaptureOutcome::Failed(reason) => (Vec::new(), Some(reason)),
        };
        Self {
            url: url.into(),
            checked_at: Utc::now(),
            snapshots,
            unavailable,
        }
    }

    /// True when the check itself completed, whatever it found.
    pub fn answered(&self) -> bool {
        self.unavailable.is_none()
    }
}

/// Replaces any earlier record for the same URL and appends genuinely new ones — the same rule
/// [`crate::runtime::merge_sections`] follows, for the same reason: re-checking a URL is that
/// URL's current answer in full, not a second entry to accumulate beside the stale one.
pub fn merge_records(existing: &mut Vec<EvidenceRecord>, incoming: EvidenceRecord) {
    match existing.iter_mut().find(|r| r.url == incoming.url) {
        Some(slot) => *slot = incoming,
        None => existing.push(incoming),
    }
}

/// Builds the CDX query for `url`. Separate from the call so the query shape is testable
/// without the network — and so the escaping is visible in one place.
fn cdx_query(url: &str) -> String {
    format!(
        "https://web.archive.org/cdx/search/cdx?url={}&output=json&fl={}&filter=statuscode:200&collapse=digest&limit=-{}",
        urlencoding::encode(url),
        CDX_FIELDS,
        MAX_SNAPSHOTS
    )
}

/// `yyyyMMddHHmmss`, UTC. Returns `None` rather than a wrong instant for anything else — a
/// snapshot whose date cannot be read is dropped, never dated `now` or the epoch.
fn parse_cdx_timestamp(stamp: &str) -> Option<DateTime<Utc>> {
    if stamp.len() != 14 || !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let num = |a: usize, b: usize| stamp[a..b].parse::<u32>().ok();
    Utc.with_ymd_and_hms(
        stamp[0..4].parse::<i32>().ok()?,
        num(4, 6)?,
        num(6, 8)?,
        num(8, 10)?,
        num(10, 12)?,
        num(12, 14)?,
    )
    .single()
}

/// Turns a CDX `output=json` body into snapshots, newest first.
///
/// Pure and total: any row it cannot read fully is skipped rather than partially trusted. The
/// header row is consumed as the column index and never emitted as data.
pub fn parse_cdx(body: &serde_json::Value) -> Vec<Snapshot> {
    let Some(rows) = body.as_array() else {
        return Vec::new();
    };
    let Some(header) = rows.first().and_then(|r| r.as_array()) else {
        return Vec::new();
    };

    let col = |name: &str| header.iter().position(|h| h.as_str() == Some(name));
    let (Some(i_ts), Some(i_orig), Some(i_digest)) =
        (col("timestamp"), col("original"), col("digest"))
    else {
        // The three fields a snapshot cannot be built without. Missing means CDX answered in a
        // shape this code does not understand — which is a parse failure, not zero snapshots.
        return Vec::new();
    };
    let i_status = col("statuscode");
    let i_mime = col("mimetype");

    let mut out: Vec<Snapshot> = rows[1..]
        .iter()
        .filter_map(|row| {
            let row = row.as_array()?;
            let get = |i: usize| row.get(i).and_then(|v| v.as_str());
            let stamp = get(i_ts)?;
            let captured_at = parse_cdx_timestamp(stamp)?;
            let original = get(i_orig)?.to_string();
            Some(Snapshot {
                captured_at,
                // `id_` asks the replay for the original bytes without the archive's own
                // toolbar injected — the point of the record is what the crawler saw.
                url: format!("https://web.archive.org/web/{stamp}id_/{original}"),
                original,
                status: i_status.and_then(get).unwrap_or("-").to_string(),
                sha1_base32: get(i_digest)?.to_string(),
                mime: i_mime
                    .and_then(get)
                    .filter(|m| *m != "unk")
                    .map(str::to_string),
            })
        })
        .collect();

    // CDX returns oldest-first even under a negative limit. The caller wants the most recent
    // capture at the top, which is the one that answers "can I still read what the tool read".
    out.sort_by_key(|s| std::cmp::Reverse(s.captured_at));
    out
}

/// Asks the Internet Archive what captures exist for `url`. Performs no archiving — see the
/// module doc.
pub async fn capture(url: &str) -> CaptureOutcome {
    let outcome = oz_fetch(
        &cdx_query(url),
        OzFetchOptions {
            timeout: CDX_TIMEOUT,
            // One retry, not three. See the module doc: this endpoint is slow by design.
            max_retries: 1,
            ..Default::default()
        },
    )
    .await;

    let response = match outcome {
        OzOutcome::Ok(r) => r,
        OzOutcome::Cancelled => return CaptureOutcome::Failed("cancelled".into()),
        other => {
            // Reuse the taxonomy every tool folds into rather than inventing a second wording
            // for the same failures.
            let reason = crate::sources::fold_fetch_failure(&other)
                .map(|o| o.human_sentence())
                .unwrap_or_else(|| "the archive did not answer".into());
            return CaptureOutcome::Failed(reason);
        }
    };

    match response.body {
        // An empty JSON array is the archive saying "nothing here", verified live.
        OzBody::Json(v) if v.as_array().is_some_and(|a| a.is_empty()) => {
            CaptureOutcome::NeverArchived
        }
        OzBody::Json(v) => {
            let snapshots = parse_cdx(&v);
            if snapshots.is_empty() {
                // Non-empty body, zero readable rows: the shape changed. Saying "never
                // archived" here would be a lie about the archive rather than about us.
                CaptureOutcome::Failed("the archive answered in an unrecognised shape".into())
            } else {
                CaptureOutcome::Found(snapshots)
            }
        }
        // `output=json` is requested explicitly, so anything else is the endpoint misbehaving
        // (or an interception page), not a body to guess at.
        _ => CaptureOutcome::Failed("the archive did not answer with JSON".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from the live endpoint on 2026-08-23, header row included.
    fn live_body() -> serde_json::Value {
        serde_json::json!([
            [
                "timestamp",
                "original",
                "statuscode",
                "digest",
                "mimetype",
                "length"
            ],
            [
                "20130718044710",
                "https://github.com/torvalds",
                "200",
                "HHMZ6WRBCARVR4VTSLH36FAT2RIFKLA4",
                "text/html",
                "5087"
            ],
            [
                "20260811125706",
                "https://github.com/torvalds",
                "200",
                "Y5CKZ32DKQFMHK3L3CV77PUPWKM2RH5F",
                "text/html",
                "9080"
            ]
        ])
    }

    #[test]
    fn the_header_row_is_an_index_not_a_snapshot() {
        // The trap this endpoint sets: `output=json` puts the field names in row 0. Consuming
        // it as data yields a phantom capture stamped `"timestamp"`.
        let snaps = parse_cdx(&live_body());
        assert_eq!(snaps.len(), 2);
        assert!(snaps.iter().all(|s| s.original.contains("github.com")));
    }

    #[test]
    fn the_most_recent_capture_comes_first() {
        // CDX answers oldest-first even under a negative limit.
        let snaps = parse_cdx(&live_body());
        assert_eq!(snaps[0].captured_at.format("%Y").to_string(), "2026");
        assert!(snaps[0].captured_at > snaps[1].captured_at);
    }

    #[test]
    fn fields_are_read_by_name_so_reordering_the_query_cannot_swap_them() {
        // Same rows, `digest` and `statuscode` swapped in both header and data. Positional
        // parsing would hand back a status of `HHMZ…` and never complain.
        let reordered = serde_json::json!([
            ["timestamp", "original", "digest", "statuscode"],
            [
                "20130718044710",
                "https://github.com/torvalds",
                "HHMZ6WRB",
                "200"
            ]
        ]);
        let snaps = parse_cdx(&reordered);
        assert_eq!(snaps[0].status, "200");
        assert_eq!(snaps[0].sha1_base32, "HHMZ6WRB");
    }

    #[test]
    fn a_body_missing_the_load_bearing_columns_yields_nothing_rather_than_half_a_snapshot() {
        let no_digest = serde_json::json!([
            ["timestamp", "original"],
            ["20130718044710", "http://x.test/"]
        ]);
        assert!(parse_cdx(&no_digest).is_empty());
    }

    #[test]
    fn an_unreadable_timestamp_drops_its_row_rather_than_dating_it_now() {
        let bad = serde_json::json!([
            ["timestamp", "original", "digest"],
            ["not-a-date", "http://x.test/", "AAAA"],
            ["20130718044710", "http://x.test/", "BBBB"]
        ]);
        let snaps = parse_cdx(&bad);
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].sha1_base32, "BBBB");
    }

    #[test]
    fn the_replay_url_asks_for_the_original_bytes() {
        // `id_` suppresses the archive's injected toolbar. A record of "what the crawler saw"
        // that silently includes the archive's own chrome is a worse record.
        let snaps = parse_cdx(&live_body());
        assert!(snaps[0].url.contains("id_/"), "got {}", snaps[0].url);
    }

    #[test]
    fn unknown_mime_is_absent_rather_than_the_literal_string_unk() {
        let unk = serde_json::json!([
            ["timestamp", "original", "digest", "mimetype"],
            ["20130718044710", "http://x.test/", "AAAA", "unk"]
        ]);
        assert_eq!(parse_cdx(&unk)[0].mime, None);
    }

    #[test]
    fn the_query_escapes_the_url_and_asks_for_the_most_recent_captures() {
        let q = cdx_query("http://x.test/a b?c=1&d=2");
        assert!(
            !q.contains("a b"),
            "an unescaped space would truncate the query: {q}"
        );
        assert!(q.contains(&format!("limit=-{MAX_SNAPSHOTS}")), "{q}");
        assert!(q.contains("output=json"), "{q}");
    }

    #[test]
    fn a_failed_check_and_an_empty_archive_are_not_the_same_record() {
        // With only a snapshot list to look at these render identically as "no evidence".
        let empty = EvidenceRecord::new("http://x.test/", CaptureOutcome::NeverArchived);
        let failed =
            EvidenceRecord::new("http://x.test/", CaptureOutcome::Failed("timeout".into()));
        assert!(empty.snapshots.is_empty() && failed.snapshots.is_empty());
        assert!(
            empty.answered(),
            "the archive answered; it just holds nothing"
        );
        assert!(!failed.answered());
        assert_ne!(empty.unavailable, failed.unavailable);
    }

    #[test]
    fn re_checking_a_url_replaces_its_record_rather_than_stacking_a_stale_one_beside_it() {
        let mut records = vec![EvidenceRecord::new(
            "http://x.test/",
            CaptureOutcome::Failed("timeout".into()),
        )];
        merge_records(
            &mut records,
            EvidenceRecord::new("http://y.test/", CaptureOutcome::NeverArchived),
        );
        assert_eq!(records.len(), 2);

        merge_records(
            &mut records,
            EvidenceRecord::new(
                "http://x.test/",
                CaptureOutcome::Found(parse_cdx(&live_body())),
            ),
        );
        assert_eq!(records.len(), 2, "a re-check is an update, not an append");
        let x = records.iter().find(|r| r.url == "http://x.test/").unwrap();
        assert!(x.answered() && x.snapshots.len() == 2);
    }

    /// Live, opt-in — the same convention as this crate's other network tests. Run with
    /// `cargo test -p ozint -- --ignored evidence`. Expect it to take ~20–40 s.
    #[tokio::test]
    #[ignore = "hits the live Internet Archive; slow by design (20-40s measured)"]
    async fn live_cdx_finds_captures_and_distinguishes_never_archived() {
        match capture("github.com/torvalds").await {
            CaptureOutcome::Found(s) => assert!(!s.is_empty()),
            other => panic!("expected captures for a heavily archived URL, got {other:?}"),
        }
        // The case the whole outcome enum exists for: the archive answering `200` with `[]`.
        match capture("example.com/definitely-not-archived-9f8a7b6c5d4e").await {
            CaptureOutcome::NeverArchived => {}
            other => panic!("expected NeverArchived, got {other:?}"),
        }
    }
}
