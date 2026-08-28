//! SSRF guard for server-side URL fetching + a minimal HTML→text extractor.
//!
//! Originally lived as a private module of `ozint-server` (`routes/url_guard.rs`, shared by
//! `/api/summarize` and `/api/run-task`'s `summarize` branch); moved here 2026-08-21 once
//! `ozint`'s `oz_fetch` became a second consumer that `ozint-server`'s private module
//! couldn't reach. Behaviour and tests are unchanged by the move.

use std::sync::LazyLock;

use regex::Regex;
use url::Url;

/// Parse + validate `raw` as a safe outbound target: `http(s)` only, no IPv6
/// literals, hostname must look like a public domain (contains a dot), and no
/// localhost/`.local`/`.internal`/`.lan` suffix or private/loopback/link-local
/// IPv4 literal. Hostname-based only — DNS rebinding is explicitly out of
/// scope — see the module doc for why, and for what that leaves uncovered.
pub fn safe_fetch_url(raw: &str) -> Option<Url> {
    let u = Url::parse(raw.trim()).ok()?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return None;
    }

    let h = u.host_str()?.to_lowercase();
    if h.starts_with('[') {
        return None;
    }
    if !h.contains('.') {
        return None;
    }
    if h == "localhost" || h.ends_with(".local") || h.ends_with(".internal") || h.ends_with(".lan")
    {
        return None;
    }

    static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:127\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)")
            .expect("ipv4 pattern")
    });
    if IPV4_RE.is_match(&h) || h == "0.0.0.0" {
        return None;
    }

    Some(u)
}

/// Extract a `<title>` (140-char cap) + plain text from raw HTML. No DOM —
/// regex-only, and deliberately so: this exists to give an LLM something readable, not to
/// parse a document. Entity decoding covers six named entities and stops there — anything
/// rarer survives as its literal `&…;` form rather than pulling in a full entity table.
pub fn html_to_text(html: &str) -> (String, String) {
    static TITLE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").expect("title pattern"));
    static SCRIPT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<script.*?</script>").expect("script pattern"));
    static STYLE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<style.*?</style>").expect("style pattern"));
    static NOSCRIPT_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<noscript.*?</noscript>").expect("noscript pattern"));
    static TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").expect("tag pattern"));
    static WS_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\s+").expect("whitespace pattern"));

    let title = TITLE_RE
        .captures(html)
        .map(|c| {
            decode_entities(&c[1])
                .trim()
                .chars()
                .take(140)
                .collect::<String>()
        })
        .unwrap_or_default();

    let stripped = SCRIPT_RE.replace_all(html, " ");
    let stripped = STYLE_RE.replace_all(&stripped, " ");
    let stripped = NOSCRIPT_RE.replace_all(&stripped, " ");
    let stripped = TAG_RE.replace_all(&stripped, " ");
    let text = WS_RE
        .replace_all(&decode_entities(&stripped), " ")
        .trim()
        .to_string();

    (title, text)
}

fn decode_entities(s: &str) -> String {
    static NUMERIC_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"&#(\d+);").expect("numeric entity pattern"));

    let s = s
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");

    NUMERIC_RE
        .replace_all(&s, |caps: &regex::Captures| {
            caps[1]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .map(|c| c.to_string())
                .unwrap_or_default()
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_private_and_local_targets() {
        assert!(safe_fetch_url("http://127.0.0.1/x").is_none());
        assert!(safe_fetch_url("http://10.0.0.5/x").is_none());
        assert!(safe_fetch_url("http://192.168.1.1/x").is_none());
        assert!(safe_fetch_url("http://localhost/x").is_none());
        assert!(safe_fetch_url("http://foo.internal/x").is_none());
        assert!(safe_fetch_url("http://nodothost/x").is_none());
        assert!(safe_fetch_url("ftp://example.com/x").is_none());
    }

    #[test]
    fn accepts_a_public_https_url() {
        assert!(safe_fetch_url("https://example.com/article").is_some());
    }

    #[test]
    fn html_to_text_strips_tags_and_decodes_entities() {
        let html = "<html><head><title>Hello &amp; World</title></head><body><script>evil()</script><p>Body &lt;text&gt;</p></body></html>";
        let (title, text) = html_to_text(html);
        assert_eq!(title, "Hello & World");
        // Only script/style/noscript blocks are stripped before every remaining tag is
        // removed, so <title>'s text survives into the body text as well. That duplication is
        // intended: the title is returned separately for display, and a summariser reading the
        // body should still see it. Do not "fix" this by stripping <head>.
        assert_eq!(text, "Hello & World Body <text>");
    }
}
