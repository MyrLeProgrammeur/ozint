//! Per-type canonicalization of a raw seed string into `{display, key, valid, note}`.
//!
//! `key` is the dedup identity body: the dedup-visited set and `OzNode::dedup_key` combine it
//! with the type tag (see `dedup_key`) to decide whether a rediscovered value is the same
//! entity already in the tree. `display` is purely cosmetic and never compared.

use crate::types::OzType;
use std::net::IpAddr;

/// Result of normalizing one raw value against its `OzType`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// How the value is shown to the analyst.
    pub display: String,
    /// The dedup key **body** for this value, unique only within its own type — combine with
    /// the type tag via `dedup_key` for the full `OzNode::dedup_key` form.
    pub key: String,
    pub valid: bool,
    /// Why `valid` is false, or a caveat worth surfacing even when it is true.
    pub note: Option<String>,
}

impl Normalized {
    fn valid(display: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            display: display.into(),
            key: key.into(),
            valid: true,
            note: None,
        }
    }

    fn valid_with_note(
        display: impl Into<String>,
        key: impl Into<String>,
        note: impl Into<String>,
    ) -> Self {
        Self {
            display: display.into(),
            key: key.into(),
            valid: true,
            note: Some(note.into()),
        }
    }

    /// `display`/`key` both echo the raw input verbatim — there is no canonical form to fall
    /// back to for a value that failed to parse, and the analyst still needs *something*
    /// shown and something to (uselessly) dedup on.
    fn invalid(raw: &str, note: impl Into<String>) -> Self {
        Self {
            display: raw.to_string(),
            key: raw.to_string(),
            valid: false,
            note: Some(note.into()),
        }
    }
}

/// Normalize `raw` per the canonicalization rules for `oz_type`.
pub fn normalize(oz_type: OzType, raw: &str) -> Normalized {
    match oz_type {
        OzType::Email => normalize_email(raw),
        OzType::Phone => normalize_phone(raw),
        OzType::Domain => normalize_domain(raw),
        OzType::Ip => normalize_ip(raw),
        OzType::Hash => normalize_hash(raw),
        OzType::Coordinate => normalize_coordinate(raw),
        OzType::Username => normalize_username(raw),
        OzType::Cve => normalize_cve(raw),
        OzType::Image | OzType::Video => normalize_media(raw),
        OzType::Directory | OzType::Name => normalize_free_text(raw),
    }
}

/// `"<type-kebab>:<key>"`, e.g. `"username:mtrebosc"` — the exact identity the dedup-visited
/// set keys on and `OzNode::dedup_key` stores.
pub fn dedup_key(oz_type: OzType, raw: &str) -> String {
    format!("{}:{}", type_kebab(oz_type), normalize(oz_type, raw).key)
}

/// Kebab-case type tag, read off `OzType`'s own `Serialize` impl (`#[serde(rename_all =
/// "kebab-case")]` in `types.rs`) instead of re-declaring the mapping here — so this can never
/// drift from the wire representation the cockpit and `OzNode::dedup_key` both rely on.
fn type_kebab(oz_type: OzType) -> String {
    match serde_json::to_value(oz_type) {
        Ok(serde_json::Value::String(s)) => s,
        _ => unreachable!("OzType always serializes to a bare kebab-case string"),
    }
}

// ─── Email ──────────────────────────────────────────────────────────────────

fn normalize_email(raw: &str) -> Normalized {
    let trimmed = raw.trim();
    // Split on the LAST '@': an unquoted local part never contains one, and we don't attempt
    // to parse RFC 5321 quoted-local-part addresses, so this is the correct split for every
    // realistic input.
    let Some(at_pos) = trimmed.rfind('@') else {
        return Normalized::invalid(trimmed, "missing '@'");
    };
    let local = &trimmed[..at_pos];
    let domain_raw = &trimmed[at_pos + 1..];

    if local.is_empty() || local.chars().any(char::is_whitespace) {
        return Normalized::invalid(trimmed, "empty or whitespace-containing local part");
    }
    if domain_raw.is_empty() || !domain_raw.contains('.') {
        return Normalized::invalid(trimmed, "domain has no dot — not a valid host");
    }

    let ascii_domain = match idna::domain_to_ascii(domain_raw) {
        Ok(d) => d,
        Err(_) => return Normalized::invalid(trimmed, "domain fails IDNA encoding"),
    };
    let domain_lower = ascii_domain.to_lowercase();

    // `display` keeps the local part's original case — it IS case-sensitive per RFC 5321.
    let display = format!("{local}@{domain_lower}");
    // `key` lowercases the local part too, deliberately deviating from the RFC: no real-world
    // mailbox provider actually distinguishes on local-part case, so two spellings of the same
    // working address should dedup to one node rather than silently spawning duplicates.
    let key = format!("{}@{}", local.to_lowercase(), domain_lower);
    Normalized::valid(display, key)
}

// ─── Phone ──────────────────────────────────────────────────────────────────

fn normalize_phone(raw: &str) -> Normalized {
    let trimmed = raw.trim();
    if !trimmed.starts_with('+') {
        return Normalized::invalid(
            trimmed,
            "no region can be inferred from a number without a leading '+' and country code — \
             provide one rather than guessing a default region",
        );
    }
    let parsed = match phonenumber::parse(None, trimmed) {
        Ok(n) => n,
        Err(e) => {
            return Normalized::invalid(trimmed, format!("could not parse phone number: {e}"));
        }
    };
    if !phonenumber::is_valid(&parsed) {
        return Normalized::invalid(trimmed, "parsed but not a valid number for its region");
    }
    let key = parsed.format().mode(phonenumber::Mode::E164).to_string();
    let display = parsed
        .format()
        .mode(phonenumber::Mode::International)
        .to_string();
    Normalized::valid(display, key)
}

// ─── Domain ─────────────────────────────────────────────────────────────────

fn normalize_domain(raw: &str) -> Normalized {
    let trimmed = raw.trim();
    // Force a scheme so `url::Url` will parse a bare host, then let it shed path/query/port.
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let host = match url::Url::parse(&with_scheme) {
        Ok(u) => match u.host_str() {
            Some(h) => h.to_string(),
            None => return Normalized::invalid(trimmed, "no host found"),
        },
        Err(_) => return Normalized::invalid(trimmed, "not a parseable URL/host"),
    };

    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Normalized::invalid(trimmed, "empty host");
    }

    let ascii = match idna::domain_to_ascii(host) {
        Ok(d) => d,
        Err(_) => return Normalized::invalid(trimmed, "domain fails IDNA encoding"),
    };
    let lower = ascii.to_lowercase();

    if !lower.contains('.') {
        return Normalized::invalid(trimmed, "no dot — not a valid host with a TLD");
    }
    // `rsplit` already yields the last label first, so the TLD is its **`next`**. This used to
    // read `.next_back()`, which walks the reversed iterator backwards and therefore returned
    // the *leftmost* label — the check was validating the wrong end of the name while its
    // variable, its condition and its error message all said "TLD".
    //
    // It failed in both directions, silently. `x.com` was rejected as having an implausible
    // TLD because the label `x` is one character long, so a real and rather well-known domain
    // could not be investigated at all; and `example.c` was accepted, because `example` looks
    // fine — which is exactly the malformed TLD this check exists to catch.
    let tld = lower.rsplit('.').next().unwrap_or("");
    let tld_plausible =
        !tld.is_empty() && tld.chars().all(|c| c.is_ascii_alphanumeric()) && tld.len() >= 2;
    if !tld_plausible {
        return Normalized::invalid(trimmed, "TLD shape looks implausible");
    }

    // `www.` stays IN `display` (stripping it there would misrepresent what the analyst
    // actually typed/found) but is stripped from the dedup `key`: it names a naming
    // convention, not a different entity, so `www.example.com` and `example.com` are the same
    // domain node.
    let key = lower.strip_prefix("www.").unwrap_or(&lower).to_string();

    Normalized::valid(lower, key)
}

// ─── IP ─────────────────────────────────────────────────────────────────────

fn normalize_ip(raw: &str) -> Normalized {
    let trimmed = raw.trim();
    match trimmed.parse::<IpAddr>() {
        // `IpAddr`'s `Display` already produces the RFC 5952 canonical compressed lowercase
        // form for IPv6 and plain dotted-decimal for IPv4 — nothing left to normalize.
        Ok(ip) => {
            let s = ip.to_string();
            Normalized::valid(s.clone(), s)
        }
        Err(_) => Normalized::invalid(trimmed, "not a valid IPv4 or IPv6 address"),
    }
}

// ─── Hash ───────────────────────────────────────────────────────────────────

fn normalize_hash(raw: &str) -> Normalized {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Normalized::invalid(trimmed, "not a hex string");
    }
    let lower = trimmed.to_lowercase();
    let kind = match lower.len() {
        32 => "MD5",
        40 => "SHA-1",
        64 => "SHA-256",
        n => {
            return Normalized::invalid(
                trimmed,
                format!("hex length {n} matches no known hash (MD5=32, SHA-1=40, SHA-256=64)"),
            );
        }
    };
    Normalized::valid_with_note(lower.clone(), lower, format!("classified as {kind}"))
}

// ─── Coordinate ─────────────────────────────────────────────────────────────

fn normalize_coordinate(raw: &str) -> Normalized {
    let trimmed = raw.trim();
    let Some((lat, lon)) = parse_decimal_pair(trimmed).or_else(|| parse_dms_pair(trimmed)) else {
        return Normalized::invalid(
            trimmed,
            "not a recognized decimal-degree (\"48.8584, 2.2945\") or DMS (48°51'30\"N \
             2°17'40\"E) coordinate pair",
        );
    };
    if !(-90.0..=90.0).contains(&lat) {
        return Normalized::invalid(trimmed, format!("latitude {lat} out of range [-90, 90]"));
    }
    if !(-180.0..=180.0).contains(&lon) {
        return Normalized::invalid(trimmed, format!("longitude {lon} out of range [-180, 180]"));
    }

    // 5 decimal places ≈ 1.1 m at the equator — finer than any of our actual sources' precision
    // (EXIF GPS, IP geolocation, reverse-geocoding), so this is the resolution at which two
    // independently-reported readings of the same real-world spot collapse to one dedup key
    // without merging genuinely distinct nearby points.
    let display = format!("{lat:.5}, {lon:.5}");
    let key = format!("{lat:.5},{lon:.5}");
    Normalized::valid(display, key)
}

fn parse_decimal_pair(s: &str) -> Option<(f64, f64)> {
    let parts: Vec<&str> = s
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() != 2 {
        return None;
    }
    let lat: f64 = parts[0].parse().ok()?;
    let lon: f64 = parts[1].parse().ok()?;
    Some((lat, lon))
}

fn parse_dms_pair(s: &str) -> Option<(f64, f64)> {
    // Accepts both the ASCII apostrophe/quote and the Unicode prime/double-prime marks for
    // minutes/seconds, since sources copy-paste either. Hemisphere letter decides the axis, so
    // "N ... E" and "E ... N" both parse the same regardless of which comes first.
    let re = regex::Regex::new(
        r#"(?i)(\d+(?:\.\d+)?)\s*°\s*(\d+(?:\.\d+)?)\s*['′]\s*(\d+(?:\.\d+)?)\s*(?:["″])?\s*([NSEW])"#,
    )
    .expect("static DMS regex is valid");

    let mut lat = None;
    let mut lon = None;
    for cap in re.captures_iter(s) {
        let deg: f64 = cap[1].parse().ok()?;
        let min: f64 = cap[2].parse().ok()?;
        let sec: f64 = cap[3].parse().ok()?;
        let hemi = cap[4].to_ascii_uppercase();
        let mut value = deg + min / 60.0 + sec / 3600.0;
        if hemi == "S" || hemi == "W" {
            value = -value;
        }
        match hemi.as_str() {
            "N" | "S" => lat = Some(value),
            "E" | "W" => lon = Some(value),
            _ => {}
        }
    }
    Some((lat?, lon?))
}

// ─── Username ───────────────────────────────────────────────────────────────

fn normalize_username(raw: &str) -> Normalized {
    let trimmed = raw.trim();
    let stripped = trimmed.strip_prefix('@').unwrap_or(trimmed);
    if stripped.is_empty() {
        return Normalized::invalid(trimmed, "empty username");
    }
    if stripped.chars().any(char::is_whitespace) {
        return Normalized::invalid(trimmed, "usernames cannot contain whitespace");
    }
    let key = stripped.to_lowercase();
    Normalized::valid(stripped, key)
}

// ─── CVE ────────────────────────────────────────────────────────────────────

fn normalize_cve(raw: &str) -> Normalized {
    let trimmed = raw.trim();
    let upper = trimmed.to_uppercase();
    let re = regex::Regex::new(r"^CVE-\d{4}-\d{4,}$").expect("static CVE regex is valid");
    if re.is_match(&upper) {
        Normalized::valid(upper.clone(), upper)
    } else {
        Normalized::invalid(
            trimmed,
            "does not match CVE-YYYY-NNNN (year + 4-or-more digit id)",
        )
    }
}

// ─── Image / Video ──────────────────────────────────────────────────────────

fn normalize_media(raw: &str) -> Normalized {
    let trimmed = raw.trim();
    let looks_like_hash = !trimmed.is_empty()
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
        && matches!(trimmed.len(), 32 | 40 | 64);
    if looks_like_hash {
        let lower = trimmed.to_lowercase();
        return Normalized::valid(lower.clone(), lower);
    }
    // Not a recognizable content hash — pass through verbatim. This unit has no authority to
    // reject a mediaId/URL/other reference; classifying what it IS belongs to another unit.
    Normalized::valid(trimmed, trimmed)
}

// ─── Directory / Name ───────────────────────────────────────────────────────

fn normalize_free_text(raw: &str) -> Normalized {
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let key = collapsed.to_lowercase();
    // A name/directory tile label has no wrong shape — always valid, per spec.
    Normalized::valid(collapsed, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Email ──────────────────────────────────────────────────────────────

    #[test]
    fn email_happy_path_lowercases_domain_only_in_display() {
        let n = normalize(OzType::Email, "MTrebosc@Example.COM");
        assert!(n.valid);
        assert_eq!(n.display, "MTrebosc@example.com");
        assert_eq!(n.key, "mtrebosc@example.com");
    }

    #[test]
    fn email_rejects_missing_at() {
        let n = normalize(OzType::Email, "not-an-email");
        assert!(!n.valid);
        assert!(n.note.is_some());
    }

    #[test]
    fn email_rejects_dotless_domain() {
        let n = normalize(OzType::Email, "a@localhost");
        assert!(!n.valid);
    }

    #[test]
    fn email_dedup_key_stable_across_case_spellings() {
        let a = dedup_key(OzType::Email, "Foo@EXAMPLE.com");
        let b = dedup_key(OzType::Email, "foo@example.com");
        assert_eq!(a, b);
        assert_eq!(a, "email:foo@example.com");
    }

    // ─── Phone ──────────────────────────────────────────────────────────────

    #[test]
    fn phone_happy_path_produces_e164_key() {
        let n = normalize(OzType::Phone, "+33 6 12 34 56 78");
        assert!(n.valid, "note: {:?}", n.note);
        assert_eq!(n.key, "+33612345678");
    }

    #[test]
    fn phone_without_plus_is_invalid_no_default_region() {
        let n = normalize(OzType::Phone, "0612345678");
        assert!(!n.valid);
        assert!(n.note.unwrap().contains("region"));
    }

    #[test]
    fn phone_dedup_key_stable_across_formatting() {
        let a = dedup_key(OzType::Phone, "+33 6 12 34 56 78");
        let b = dedup_key(OzType::Phone, "+33612345678");
        assert_eq!(a, b);
    }

    // ─── Domain ─────────────────────────────────────────────────────────────

    #[test]
    fn domain_happy_path_strips_scheme_path_port_and_www_from_key() {
        let n = normalize(OzType::Domain, "https://WWW.Example.com:8080/some/path");
        assert!(n.valid);
        assert_eq!(n.display, "www.example.com");
        assert_eq!(n.key, "example.com");
    }

    #[test]
    fn domain_rejects_hostname_without_dot() {
        let n = normalize(OzType::Domain, "localhost");
        assert!(!n.valid);
    }

    #[test]
    fn the_tld_check_looks_at_the_tld_and_not_the_first_label() {
        // Regression: this check read `rsplit('.').next_back()`, which walks the reversed
        // iterator backwards and hands back the *leftmost* label. It therefore failed in both
        // directions at once, and neither direction raised anything.
        //
        // Rejected what it should accept:
        let n = normalize(OzType::Domain, "x.com");
        assert!(
            n.valid,
            "a one-character first label is not an implausible TLD"
        );
        assert_eq!(n.key, "x.com");
        assert!(normalize(OzType::Domain, "a.co").valid);

        // Accepted what it exists to reject:
        let short_tld = normalize(OzType::Domain, "example.c");
        assert!(
            !short_tld.valid,
            "a one-character TLD must still be refused"
        );

        // And the ordinary case, which worked by accident before and must keep working.
        assert!(normalize(OzType::Domain, "anthropic.com").valid);
        assert!(normalize(OzType::Domain, "sub.domain.co.uk").valid);
    }

    #[test]
    fn domain_dedup_key_stable_across_www_and_trailing_dot() {
        let a = dedup_key(OzType::Domain, "example.com");
        let b = dedup_key(OzType::Domain, "WWW.EXAMPLE.com.");
        assert_eq!(a, b);
        assert_eq!(a, "domain:example.com");
    }

    // ─── IP ─────────────────────────────────────────────────────────────────

    #[test]
    fn ip_v4_happy_path() {
        let n = normalize(OzType::Ip, " 8.8.8.8 ");
        assert!(n.valid);
        assert_eq!(n.key, "8.8.8.8");
    }

    #[test]
    fn ip_v6_canonicalizes_to_compressed_lowercase() {
        let n = normalize(OzType::Ip, "2001:0DB8:0000:0000:0000:0000:0000:0001");
        assert!(n.valid);
        assert_eq!(n.key, "2001:db8::1");
    }

    #[test]
    fn ip_rejects_garbage() {
        let n = normalize(OzType::Ip, "999.999.999.999");
        assert!(!n.valid);
    }

    #[test]
    fn ip_dedup_key_stable_across_v6_spellings() {
        let a = dedup_key(OzType::Ip, "2001:db8:0:0:0:0:0:1");
        let b = dedup_key(OzType::Ip, "2001:0db8::0001");
        assert_eq!(a, b);
    }

    // ─── Hash ───────────────────────────────────────────────────────────────

    #[test]
    fn hash_md5_classified() {
        let n = normalize(OzType::Hash, "D41D8CD98F00B204E9800998ECF8427E");
        assert!(n.valid);
        assert_eq!(n.key, "d41d8cd98f00b204e9800998ecf8427e");
        assert!(n.note.unwrap().contains("MD5"));
    }

    #[test]
    fn hash_rejects_non_hex() {
        let n = normalize(OzType::Hash, "not-a-hash-at-all!!");
        assert!(!n.valid);
    }

    #[test]
    fn hash_rejects_wrong_length() {
        let n = normalize(OzType::Hash, "abc123");
        assert!(!n.valid);
    }

    #[test]
    fn hash_dedup_key_stable_across_case() {
        let a = dedup_key(OzType::Hash, "D41D8CD98F00B204E9800998ECF8427E");
        let b = dedup_key(OzType::Hash, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(a, b);
    }

    // ─── Coordinate ─────────────────────────────────────────────────────────

    #[test]
    fn coordinate_decimal_happy_path() {
        let n = normalize(OzType::Coordinate, "48.8584, 2.2945");
        assert!(n.valid);
        assert_eq!(n.key, "48.85840,2.29450");
    }

    #[test]
    fn coordinate_dms_happy_path_close_to_decimal_equivalent() {
        let n = normalize(OzType::Coordinate, "48°51'30\"N 2°17'40\"E");
        assert!(n.valid, "note: {:?}", n.note);
        // 48°51'30"N == 48.858333..., 2°17'40"E == 2.294444...
        assert!(n.key.starts_with("48.8583"));
        assert!(n.key.ends_with("2.29444"));
    }

    #[test]
    fn coordinate_rejects_out_of_range_latitude() {
        let n = normalize(OzType::Coordinate, "200, 50");
        assert!(!n.valid);
    }

    #[test]
    fn coordinate_dedup_key_stable_at_fixed_precision() {
        let a = dedup_key(OzType::Coordinate, "48.85840, 2.29450");
        let b = dedup_key(OzType::Coordinate, "48.858401, 2.294499");
        assert_eq!(a, b);
    }

    // ─── Username ───────────────────────────────────────────────────────────

    #[test]
    fn username_happy_path_strips_at_and_preserves_display_case() {
        let n = normalize(OzType::Username, "@MTrebosc");
        assert!(n.valid);
        assert_eq!(n.display, "MTrebosc");
        assert_eq!(n.key, "mtrebosc");
    }

    #[test]
    fn username_rejects_internal_whitespace() {
        let n = normalize(OzType::Username, "bad user name");
        assert!(!n.valid);
    }

    #[test]
    fn username_dedup_key_stable_across_at_and_case() {
        let a = dedup_key(OzType::Username, "@MTrebosc");
        let b = dedup_key(OzType::Username, "mtrebosc");
        assert_eq!(a, b);
        assert_eq!(a, "username:mtrebosc");
    }

    // ─── CVE ────────────────────────────────────────────────────────────────

    #[test]
    fn cve_happy_path_uppercases() {
        let n = normalize(OzType::Cve, "cve-2021-34527");
        assert!(n.valid);
        assert_eq!(n.key, "CVE-2021-34527");
    }

    #[test]
    fn cve_rejects_short_year() {
        let n = normalize(OzType::Cve, "CVE-21-345");
        assert!(!n.valid);
    }

    #[test]
    fn cve_dedup_key_stable_across_case() {
        let a = dedup_key(OzType::Cve, "cve-2021-34527");
        let b = dedup_key(OzType::Cve, "CVE-2021-34527");
        assert_eq!(a, b);
    }

    // ─── Image / Video ──────────────────────────────────────────────────────

    #[test]
    fn image_hash_like_input_is_lowercased() {
        let n = normalize(OzType::Image, "ABCDEF0123456789ABCDEF0123456789");
        assert!(n.valid);
        assert_eq!(n.key, "abcdef0123456789abcdef0123456789");
    }

    #[test]
    fn video_non_hash_input_passes_through() {
        let n = normalize(OzType::Video, "media-ref-xyz-123");
        assert!(n.valid);
        assert_eq!(n.key, "media-ref-xyz-123");
    }

    #[test]
    fn image_dedup_key_stable_across_hash_case() {
        let a = dedup_key(OzType::Image, "ABCDEF0123456789ABCDEF0123456789");
        let b = dedup_key(OzType::Image, "abcdef0123456789abcdef0123456789");
        assert_eq!(a, b);
    }

    // ─── Directory / Name ───────────────────────────────────────────────────

    #[test]
    fn name_collapses_whitespace_and_is_always_valid() {
        let n = normalize(OzType::Name, "  John   Doe  ");
        assert!(n.valid);
        assert_eq!(n.display, "John Doe");
        assert_eq!(n.key, "john doe");
    }

    #[test]
    fn directory_is_always_valid_even_for_weird_input() {
        let n = normalize(OzType::Directory, "@#$% not a real value");
        assert!(n.valid);
    }

    #[test]
    fn name_dedup_key_stable_across_case_and_spacing() {
        let a = dedup_key(OzType::Name, "John   Doe");
        let b = dedup_key(OzType::Name, "john doe");
        assert_eq!(a, b);
        assert_eq!(a, "name:john doe");
    }
}
