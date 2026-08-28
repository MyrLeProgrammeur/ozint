use std::sync::OnceLock;
use std::time::Duration;

/// Re-exported so downstream crates share one `reqwest` version by construction.
pub use reqwest::Client;

use crate::net::safe_fetch_url;

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Redirect hops allowed before the chain is abandoned. Matches `reqwest`'s own default, which
/// this client used to inherit implicitly — kept explicit now that the policy is written out.
const MAX_REDIRECTS: usize = 10;

/// Whether a redirect hop is allowed to be followed.
///
/// **The hole this closes.** [`crate::net::safe_fetch_url`] is applied by callers to the URL
/// they are about to request — `ozint::fetch::screen_url` does exactly that, once,
/// before the request goes out. But this client used to follow redirects under `reqwest`'s
/// default policy, and a redirect target is never screened by that call. A public host we were
/// asked to fetch could therefore answer `302 Location: http://169.254.169.254/…` (cloud
/// metadata) or `http://127.0.0.1:…` (a service on the box), and the body would come back to
/// the caller as an ordinary `200` with the guard none the wiser. The guard read as if it
/// covered outbound fetching; it covered the first hop of one.
///
/// This matters most for OZINT, whose whole job is fetching hosts chosen from analyst input and
/// third-party data, but the fix belongs on the shared client so every other outbound caller
/// in the workspace gets it too.
///
/// **Why an escape hatch for a chain that began privately.** `OZINT_LLM_BASE_URL` and other
/// self-hosted endpoints are legitimately private addresses, and a caller that deliberately
/// started at one must be allowed to follow a redirect within it — that request was never
/// screened in the first place, so blocking its second hop would break a working local setup
/// while protecting nothing. What must never happen is a chain that *starts* public and is
/// walked inward. The first URL of the chain is what decides which case this is.
fn redirect_is_allowed(target: &str, chain: &[url::Url]) -> Result<(), String> {
    if chain.len() >= MAX_REDIRECTS {
        return Err(format!("too many redirects ({MAX_REDIRECTS})"));
    }
    // A chain that began at an address the guard would have rejected was never guarded, and
    // staying inside it changes nothing about our exposure.
    if chain
        .first()
        .is_some_and(|first| safe_fetch_url(first.as_str()).is_none())
    {
        return Ok(());
    }
    if safe_fetch_url(target).is_none() {
        return Err(format!("SSRF guard blocked a redirect to {target}"));
    }
    Ok(())
}

/// The shared outbound HTTP client.
///
/// `reqwest::Client` is a handle around a connection pool: cloning is cheap and
/// every caller must reuse this one rather than building its own, otherwise each
/// upstream source opens a separate pool.
///
/// Redirects are followed only through [`redirect_is_allowed`] — see its doc for the SSRF
/// bypass that policy exists to close.
pub fn client() -> reqwest::Client {
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .user_agent(concat!(
                    "OZINT/",
                    env!("CARGO_PKG_VERSION"),
                    " (+https://github.com/MyrLeProgrammeur/ozint)"
                ))
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::custom(|attempt| {
                    match redirect_is_allowed(attempt.url().as_str(), attempt.previous()) {
                        Ok(()) => attempt.follow(),
                        // `error`, not `stop`: `stop` would hand the caller the 3xx response as
                        // if it were the answer, and a tool would then try to parse a redirect
                        // body. A refused hop is a failed fetch, and it says why.
                        Err(reason) => attempt.error(reason),
                    }
                }))
                .build()
                .expect("failed to build the shared HTTP client")
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn chain(urls: &[&str]) -> Vec<Url> {
        urls.iter()
            .map(|u| Url::parse(u).expect("test url"))
            .collect()
    }

    #[test]
    fn a_public_chain_may_not_be_walked_inward() {
        // The attack this policy exists for: we ask for a public host, it answers with a
        // redirect to something only the server can reach. Before the policy, this fetched.
        for target in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:3000/api/memory",
            "http://10.0.0.5/admin",
            "http://192.168.1.1/",
            "http://172.16.0.9/",
            "http://localhost/",
            "http://ozint.internal/",
            "file:///etc/passwd",
        ] {
            let refused = redirect_is_allowed(target, &chain(&["https://example.com/start"]))
                .expect_err("must be refused");
            assert!(
                refused.contains("SSRF guard"),
                "{target} was refused for the wrong reason"
            );
        }
    }

    #[test]
    fn a_public_chain_may_be_walked_to_another_public_host() {
        // rdap.org is a bootstrap redirector by design — `https://rdap.org/domain/anthropic.com`
        // answers 302 to `https://rdap.verisign.com/...`, so `entity-domain` depends on
        // ordinary public redirects continuing to work.
        assert!(
            redirect_is_allowed(
                "https://rdap.verisign.com/com/v1/domain/anthropic.com",
                &chain(&["https://rdap.org/domain/anthropic.com"]),
            )
            .is_ok()
        );
    }

    #[test]
    fn a_chain_that_began_privately_is_left_alone() {
        // A self-hosted `OZINT_LLM_BASE_URL` was never screened to begin with; refusing its own
        // internal redirect would break a working setup and protect nothing.
        assert!(
            redirect_is_allowed(
                "http://127.0.0.1:8642/v1/chat/completions",
                &chain(&["http://127.0.0.1:8642/chat"]),
            )
            .is_ok()
        );
        // …but only because the *first* hop was private. A public start is still fenced in,
        // however many public hops it has already taken.
        assert!(
            redirect_is_allowed(
                "http://127.0.0.1:8642/",
                &chain(&["https://example.com/a", "https://example.org/b"]),
            )
            .is_err()
        );
    }

    #[test]
    fn the_hop_limit_is_enforced_before_the_guard_runs() {
        let long: Vec<String> = (0..MAX_REDIRECTS)
            .map(|i| format!("https://example.com/{i}"))
            .collect();
        let refs: Vec<&str> = long.iter().map(String::as_str).collect();
        let refused = redirect_is_allowed("https://example.com/next", &chain(&refs))
            .expect_err("the chain is at the limit");
        assert!(refused.contains("too many redirects"), "{refused}");
    }

    #[test]
    fn an_empty_chain_is_still_screened() {
        // Defensive: `previous()` should always carry the original, but a policy that fell
        // open on an empty chain would be a bypass with no attacker effort at all.
        assert!(redirect_is_allowed("http://127.0.0.1/", &[]).is_err());
        assert!(redirect_is_allowed("https://example.com/", &[]).is_ok());
    }
}
