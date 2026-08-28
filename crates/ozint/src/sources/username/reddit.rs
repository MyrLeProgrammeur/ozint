//! `reddit-arctic-shift` — a keyless Reddit username lookup via Arctic Shift
//! (`arctic-shift.photon-reddit.com`), the actively-maintained Pushshift successor. Landed
//! 2026-08-26 after Reddit's own public `GET /user/{u}/about.json` was verified dead
//! (`403` on `www.reddit.com`/`api.reddit.com`, a login redirect on `old.reddit.com`) and
//! PullPush — this crate's other Pushshift-family candidate, already noted elsewhere as
//! "walled" — turned out to now answer `429` with an explicit anti-agent refusal, not merely
//! rate-limited.
//!
//! ## What this tool can and cannot answer
//!
//! Arctic Shift indexes Reddit's *comment and submission history*, not the live account object
//! `about.json` exposed — so this tool reports **activity**, not identity: karma totals, post/
//! comment counts, and the first/last timestamps seen in that archived activity. It cannot
//! report account-creation date, verified-email status, suspension state, or trophies — those
//! live only on the now-walled `about.json`/`/api/v1/user/{u}/trophies` endpoints, which need a
//! registered Reddit OAuth "installed app" `client_id` (no secret required, but a one-time
//! human registration at reddit.com/prefs/apps — out of scope for an automated fix, left as a
//! documented follow-up rather than built blind).
//!
//! An account that exists but has never posted or commented answers with an empty `data: []`,
//! identical to an account that does not exist at all — this tool cannot tell the two apart, and
//! settles `OkEmpty` for both, honestly reporting no activity found rather than claiming
//! non-existence.
//!
//! ## Verified by direct call, 2026-08-26
//!
//! `GET .../api/users/search?author=torvalds&limit=1` → `200` with one `data[]` entry, fields
//! nested under `_meta` (`post_karma`, `comment_karma`, `total_karma`, `num_posts`,
//! `num_comments`, `earliest_comment_at`/`earliest_post_at`/`last_comment_at`/`last_post_at`,
//! all Unix seconds). A short, plausible-but-unused handle answers `200` with `data: []` — the
//! empty-result shape this tool settles as `OkEmpty` on.

use chrono::{DateTime, Utc};

use crate::fetch::{self, OzBody, OzOutcome};
use crate::outcome::ToolOutcome;
use crate::registry::ToolYield;
use crate::sources::DispatchOutcome;
use crate::types::OzRow;

const ARCTIC_SHIFT_ENDPOINT: &str =
    "https://arctic-shift.photon-reddit.com/api/users/search?limit=1&author=";

/// One hit's `_meta` block, narrowed to what this tool reports. Every field is optional —
/// Arctic Shift's own schema does not guarantee all of them are populated for every account.
#[derive(Debug, Clone, PartialEq, Default)]
struct RedditActivity {
    post_karma: Option<i64>,
    comment_karma: Option<i64>,
    total_karma: Option<i64>,
    num_posts: Option<i64>,
    num_comments: Option<i64>,
    /// The earlier of `earliest_comment_at`/`earliest_post_at` — a lower bound on account age,
    /// not the creation date itself (Arctic Shift does not carry `created_utc`).
    earliest_activity_at: Option<i64>,
    last_activity_at: Option<i64>,
}

/// Parses the endpoint's `{"data": [...]}` body. `Ok(None)` is the genuine "no archived
/// activity found" case (empty `data`), distinct from a parse failure. Pure and tested.
fn parse_reddit_response(json: &serde_json::Value) -> Result<Option<RedditActivity>, String> {
    let data = json
        .get("data")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "arctic shift response is missing `data`".to_string())?;

    let Some(first) = data.first() else {
        return Ok(None);
    };
    let meta = first
        .get("_meta")
        .ok_or_else(|| "arctic shift hit is missing `_meta`".to_string())?;

    let get_i64 = |key: &str| meta.get(key).and_then(|v| v.as_i64());
    let earliest = [get_i64("earliest_comment_at"), get_i64("earliest_post_at")]
        .into_iter()
        .flatten()
        .min();
    let last = [get_i64("last_comment_at"), get_i64("last_post_at")]
        .into_iter()
        .flatten()
        .max();

    Ok(Some(RedditActivity {
        post_karma: get_i64("post_karma"),
        comment_karma: get_i64("comment_karma"),
        total_karma: get_i64("total_karma"),
        num_posts: get_i64("num_posts"),
        num_comments: get_i64("num_comments"),
        earliest_activity_at: earliest,
        last_activity_at: last,
    }))
}

fn format_unix(secs: i64) -> String {
    DateTime::<Utc>::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| secs.to_string())
}

fn reddit_to_yield(activity: &RedditActivity, handle: &str) -> ToolYield {
    let mut rows = vec![OzRow {
        label: "Reddit".to_string(),
        value: format!("u/{handle}"),
        href: Some(format!("https://reddit.com/user/{handle}")),
        ..Default::default()
    }];
    if let Some(karma) = activity.total_karma {
        rows.push(OzRow {
            label: "Total karma".to_string(),
            value: karma.to_string(),
            ..Default::default()
        });
    }
    if let (Some(post), Some(comment)) = (activity.post_karma, activity.comment_karma) {
        rows.push(OzRow {
            label: "Karma breakdown".to_string(),
            value: format!("{post} post / {comment} comment"),
            ..Default::default()
        });
    }
    if let (Some(posts), Some(comments)) = (activity.num_posts, activity.num_comments) {
        rows.push(OzRow {
            label: "Activity".to_string(),
            value: format!("{posts} posts, {comments} comments (archived)"),
            ..Default::default()
        });
    }
    if let Some(earliest) = activity.earliest_activity_at {
        rows.push(OzRow {
            label: "Earliest activity seen".to_string(),
            value: format_unix(earliest),
            ..Default::default()
        });
    }
    if let Some(last) = activity.last_activity_at {
        rows.push(OzRow {
            label: "Last activity seen".to_string(),
            value: format_unix(last),
            ..Default::default()
        });
    }
    ToolYield {
        rows,
        ..Default::default()
    }
}

/// Looks `handle` up against Arctic Shift's indexed Reddit activity. Keyless.
pub async fn run_reddit_arctic_shift(
    handle: &str,
    ctx: &crate::sources::ToolCtx,
) -> DispatchOutcome {
    let url = format!("{ARCTIC_SHIFT_ENDPOINT}{}", urlencoding::encode(handle));

    let outcome = ctx
        .fetch(
            "reddit-arctic-shift",
            handle,
            &url,
            fetch::OzFetchOptions::default(),
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
                message: "arctic shift response was not JSON".to_string(),
            },
            None,
        );
    };

    match parse_reddit_response(json) {
        Ok(None) => DispatchOutcome::Ran(ToolOutcome::OkEmpty, Some(ToolYield::default())),
        Ok(Some(activity)) => DispatchOutcome::Ran(
            ToolOutcome::OkWithResults { count: 1 },
            Some(reddit_to_yield(&activity, handle)),
        ),
        Err(message) => DispatchOutcome::Ran(ToolOutcome::ParseError { message }, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_response() -> serde_json::Value {
        serde_json::json!({
            "data": [{
                "author": "torvalds",
                "id": "64m6f",
                "_meta": {
                    "earliest_comment_at": 1431807581,
                    "earliest_post_at": 1332943236,
                    "last_comment_at": 1678310710,
                    "last_post_at": 1678302837,
                    "num_comments": 46,
                    "num_posts": 14,
                    "post_karma": 54,
                    "comment_karma": 420,
                    "total_karma": 474
                }
            }]
        })
    }

    #[test]
    fn parses_a_full_hit() {
        let activity = parse_reddit_response(&full_response())
            .unwrap()
            .expect("some");
        assert_eq!(activity.total_karma, Some(474));
        assert_eq!(activity.earliest_activity_at, Some(1332943236));
        assert_eq!(activity.last_activity_at, Some(1678310710));
    }

    #[test]
    fn an_empty_data_array_is_a_genuine_none_not_an_error() {
        let json = serde_json::json!({ "data": [] });
        assert_eq!(parse_reddit_response(&json), Ok(None));
    }

    #[test]
    fn a_response_missing_data_is_rejected() {
        assert!(parse_reddit_response(&serde_json::json!({})).is_err());
    }

    #[test]
    fn format_unix_renders_a_date() {
        assert_eq!(format_unix(1332943236), "2012-03-28");
    }

    #[test]
    fn yield_builds_rows_from_a_full_hit() {
        let activity = parse_reddit_response(&full_response()).unwrap().unwrap();
        let produced = reddit_to_yield(&activity, "torvalds");
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Total karma" && r.value == "474")
        );
        assert!(
            produced
                .rows
                .iter()
                .any(|r| r.label == "Earliest activity seen" && r.value == "2012-03-28")
        );
        assert_eq!(
            produced.rows[0].href.as_deref(),
            Some("https://reddit.com/user/torvalds")
        );
    }

    #[test]
    fn yield_never_touches_the_payload() {
        let activity = parse_reddit_response(&full_response()).unwrap().unwrap();
        let produced = reddit_to_yield(&activity, "torvalds");
        assert_eq!(produced.payload_patch, serde_json::json!({}));
    }
}
