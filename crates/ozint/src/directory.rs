//! `entity-directory (DIR)` — the launch-only tile resolver.
//!
//! Not a fetcher. This module turns a subject value into a set of [`DirectoryTile`]s: URLs a
//! human opens by hand, in their own browser, with their own session. **It makes zero network
//! calls.** Every function here is pure and synchronous, and that is the unit's entire point,
//! not a limitation of it — the vendors below are Cloudflare-walled, login-walled or have no
//! API at all, so they are launch-only tiles, never scraped.
//!
//! The one network call in the wider feature is the *optional* HEAD liveness probe, and it
//! already lives elsewhere: `refresh.rs`'s `probe_tiles` re-checks a stored node's tiles when
//! the analyst hits refresh. Tiles are born with `live: None` here and stay that way until
//! that probe runs. That split is deliberate — resolving a tile must never cost a request.
//!
//! ## Hand-verification of the URL templates (2026-08-21)
//!
//! The exact URL templates for each vendor needed hand-verification — knowing a site is
//! directory-only/dead-end says nothing about its exact query-string shape. They were verified
//! by direct call, and the result is not uniform, so it is recorded per vendor rather than as a
//! blanket "checked":
//!
//! | Vendor | Evidence | Confidence |
//! |---|---|---|
//! | Spokeo `/{First-Last}` | `200`, title `John Doe (5,564 matches)…`; a bogus path returns `404 Page Not Found` | **confirmed end to end** |
//! | WhitePages `/name/{First-Last}` | real path `403`, bogus path `404 We Could Not Find That Page` — the app, not a WAF, distinguishes them, so the route exists | **route confirmed** |
//! | BeenVerified `/people/{first-last}/` | real path `403`, bogus path `404 Page not found`; Wayback holds `https://www.beenverified.com/people/john-doe/` | **route confirmed** |
//! | FastPeopleSearch `/name/{first-last}` | Cloudflare fronts *every* path with `403`, so HTTP cannot discriminate. Wayback's `/name/*` index holds the literal archived template `/name/${FIRSTNAME}-${LASTNAME}_${STATE}` | **shape from the archive, not from a live response** |
//! | Radaris `/p/{First}/{Last}/` | same Cloudflare `Just a moment…` on every path. Wayback's `/p/*` index holds two-segment paths (`/p/"lee/Suan"`) | **shape from the archive, not from a live response** |
//! | Google dork `?q=%22…%22` | `200` | confirmed |
//! | Yandex dork `?text=%22…%22` | `302` to `showcaptcha` for a scripted client; a real browser session is the intended consumer and this is a launch-only tile, so that is not a defect | confirmed, with the caveat |
//! | Google Lens `uploadbyurl?url=` | `303` to a real Lens result page | confirmed |
//! | Yandex Images `?rpt=imageview&url=` | `200` | confirmed |
//!
//! `truescreen.eu` — the originally recorded domain — **does not serve TLS** (`unrecognized
//! name`). The TrueScreen eIDAS evidence product is at `truescreen.io` (title: "TrueScreen:
//! Certified Digital Evidence with Legal Value"). Corrected here.
//!
//! ## Two scope decisions worth stating explicitly
//!
//! **1. Analyst-facing references are not subject tiles.** The OpSec checklist
//! (BrowserLeaks, Cover Your Tracks, Am I Unique, DNSleaktest) and the desktop-tool row
//! (Maltego, Hunchly, InVID, Autopsy) fall under this unit's coverage. Neither family takes the
//! subject's value: they are about the *analyst's* browser and the *analyst's* toolbox. Hanging
//! "test your own browser fingerprint" off a node called `John Doe` would read as a claim about
//! John Doe. They are catalogued here and reachable through [`static_references`], and
//! [`resolve_tiles`] never attaches them to a node.
//!
//! **2. Reverse-face tiles belong to an image, not to a name.** PimEyes, Social Catfish, Yandex
//! Images and Google Lens all need an image, and two of them need an image *URL* in the query
//! string. They are catalogued against [`OzType::Image`], so `resolve_tiles(OzType::Image, …)`
//! answers them today even though `plans::plan_for(Image)` is still `None` — `entity-image`
//! picks them up with no change here. Emitting them for a `NAM`/`DIR` node would produce a tile
//! that cannot work.

use crate::types::{DirectoryTile, OzType};

// ─── Families ───────────────────────────────────────────────────────────────

/// Which group a tile belongs to. Drives nothing in the resolver except the
/// subject-tile / analyst-reference split (see the module doc's first decision).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileFamily {
    /// People-search aggregator keyed on a personal name.
    PeopleSearch,
    /// Reverse-image / face search keyed on an image URL.
    ReverseFace,
    /// A pre-built search-engine query. Links only — scraping any engine's results is
    /// forbidden outright.
    DorkBuilder,
    /// A desktop application the analyst runs themselves. Static reference row.
    DesktopTool,
    /// The analyst's own operational-security checklist. Static, never substituted.
    OpSec,
    /// Certified-evidence sealing (the evidence capturer's paid tier). Static reference.
    EvidenceSealing,
}

impl TileFamily {
    /// Whether a family's tiles describe the *subject* of the investigation (and so belong on
    /// a node) rather than the analyst's own setup.
    const fn is_about_the_subject(self) -> bool {
        matches!(
            self,
            TileFamily::PeopleSearch | TileFamily::ReverseFace | TileFamily::DorkBuilder
        )
    }
}

// ─── Substitution ───────────────────────────────────────────────────────────

/// How a subject value is written into a template's `{q}` slot. One variant per shape a
/// verified vendor URL actually uses — deliberately not a general templating language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Substitution {
    /// The whole value, percent-encoded and wrapped in `"…"` — a search engine's exact-phrase
    /// operator, which is what makes a dork a dork rather than a bag of words.
    QuotedPhrase,
    /// `john-doe` — alphanumeric runs, lowercased, joined by a single hyphen.
    LowerHyphen,
    /// `John-Doe` — the same, with each token's first character upper-cased.
    TitleHyphen,
    /// `John/Doe` — **two** path segments: the first token, then the last token. A middle name
    /// is dropped, because the vendor's route has exactly two slots and inventing a third
    /// segment would 404. Falls back when the value has only one token.
    FirstLastPath,
    /// The value percent-encoded as an opaque URL (an image address).
    EncodedUrl,
    /// No substitution, ever. The template *is* the URL.
    Fixed,
}

// ─── Tile catalogue ─────────────────────────────────────────────────────────

/// One catalogued launch-only destination. Plain `Copy` data, like `registry::ToolDef`, so the
/// whole catalogue is a `const` array with no runtime initialization.
#[derive(Debug, Clone, Copy)]
pub struct TileDef {
    /// Stable id, stamped onto the resulting [`DirectoryTile::tool_id`]. Namespaced `dir-` so
    /// it can never be confused with a `registry::CATALOGUE` id that has a real dispatcher —
    /// nothing here is dispatchable, by design.
    pub tool_id: &'static str,
    pub label: &'static str,
    pub family: TileFamily,
    /// Entity types this destination applies to. Empty for the analyst-facing families, which
    /// [`resolve_tiles`] must never attach to a node.
    pub types: &'static [OzType],
    template: &'static str,
    substitution: Substitution,
    /// Used when [`Substitution::FirstLastPath`] cannot be satisfied. The tile is still emitted
    /// — pointing at the vendor's own front door with a `reason` that says why — because
    /// dropping it would shrink the tile list with no explanation, and a silently shorter list
    /// is indistinguishable from a vendor we never catalogued.
    fallback: Option<(&'static str, &'static str)>,
    /// Why this destination is launch-only. Rendered verbatim as [`DirectoryTile::reason`].
    pub reason: &'static str,
}

/// Every launch-only destination this crate knows.
pub const TILES: &[TileDef] = &[
    // ── People search (NAM) ──────────────────────────────────────────────
    TileDef {
        tool_id: "dir-spokeo",
        label: "Spokeo",
        family: TileFamily::PeopleSearch,
        types: &[OzType::Name],
        template: "https://www.spokeo.com/{q}",
        substitution: Substitution::TitleHyphen,
        fallback: None,
        reason: "login wall — results are behind a paid account",
    },
    TileDef {
        tool_id: "dir-beenverified",
        label: "BeenVerified",
        family: TileFamily::PeopleSearch,
        types: &[OzType::Name],
        template: "https://www.beenverified.com/people/{q}/",
        substitution: Substitution::LowerHyphen,
        fallback: None,
        reason: "bot wall (403 to any non-browser client) — open it yourself",
    },
    TileDef {
        tool_id: "dir-whitepages",
        label: "WhitePages",
        family: TileFamily::PeopleSearch,
        types: &[OzType::Name],
        template: "https://www.whitepages.com/name/{q}",
        substitution: Substitution::TitleHyphen,
        fallback: None,
        reason: "bot wall (403 to any non-browser client) — open it yourself",
    },
    TileDef {
        tool_id: "dir-fastpeoplesearch",
        label: "FastPeopleSearch",
        family: TileFamily::PeopleSearch,
        types: &[OzType::Name],
        template: "https://www.fastpeoplesearch.com/name/{q}",
        substitution: Substitution::LowerHyphen,
        fallback: None,
        reason: "Cloudflare challenge on every path — never scraped",
    },
    TileDef {
        tool_id: "dir-radaris",
        label: "Radaris",
        family: TileFamily::PeopleSearch,
        types: &[OzType::Name],
        template: "https://radaris.com/p/{q}/",
        substitution: Substitution::FirstLastPath,
        fallback: Some((
            "https://radaris.com/",
            "Cloudflare challenge on every path — and its deep link needs a first *and* a last \
             name, which this value does not have, so this opens the site's own search instead",
        )),
        reason: "Cloudflare challenge on every path — never scraped",
    },
    // ── Dork builders (NAM + DIR) ────────────────────────────────────────
    //
    // Links only. Google/Bing/Yandex/Cloudflare
    // aggregator scraping of any kind is explicitly forbidden — only pre-built dork *links*
    // are allowed, never scraped results.
    TileDef {
        tool_id: "dir-google-dork",
        label: "Google (exact phrase)",
        family: TileFamily::DorkBuilder,
        types: &[OzType::Name, OzType::Directory],
        template: "https://www.google.com/search?q={q}",
        substitution: Substitution::QuotedPhrase,
        fallback: None,
        reason: "scraping search results is forbidden — this is a pre-built query link",
    },
    TileDef {
        tool_id: "dir-yandex-dork",
        label: "Yandex (exact phrase)",
        family: TileFamily::DorkBuilder,
        types: &[OzType::Name, OzType::Directory],
        template: "https://yandex.com/search/?text={q}",
        substitution: Substitution::QuotedPhrase,
        fallback: None,
        reason: "scraping search results is forbidden — this is a pre-built query link",
    },
    // ── Reverse face / image (IMG) ───────────────────────────────────────
    //
    // Catalogued against Image, unreachable until `entity-image` lands. See the module doc.
    TileDef {
        tool_id: "dir-pimeyes",
        label: "PimEyes",
        family: TileFamily::ReverseFace,
        types: &[OzType::Image],
        template: "https://pimeyes.com/en",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "no API and no URL-driven search — upload the image by hand",
    },
    TileDef {
        tool_id: "dir-social-catfish",
        label: "Social Catfish",
        family: TileFamily::ReverseFace,
        types: &[OzType::Image],
        template: "https://socialcatfish.com/reverse-image-search/",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "no API and no URL-driven search — upload the image by hand",
    },
    TileDef {
        tool_id: "dir-yandex-images",
        label: "Yandex Images",
        family: TileFamily::ReverseFace,
        types: &[OzType::Image],
        template: "https://yandex.com/images/search?rpt=imageview&url={q}",
        substitution: Substitution::EncodedUrl,
        fallback: None,
        reason: "no API — the tile hands the image URL to the web UI",
    },
    TileDef {
        tool_id: "dir-google-lens",
        label: "Google Lens",
        family: TileFamily::ReverseFace,
        types: &[OzType::Image],
        template: "https://lens.google.com/uploadbyurl?url={q}",
        substitution: Substitution::EncodedUrl,
        fallback: None,
        reason: "no API — the tile hands the image URL to the web UI",
    },
    // ── Analyst references: never attached to a node ─────────────────────
    TileDef {
        tool_id: "dir-maltego",
        label: "Maltego",
        family: TileFamily::DesktopTool,
        types: &[],
        template: "https://www.maltego.com/",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "desktop application — reference row only",
    },
    TileDef {
        tool_id: "dir-hunchly",
        label: "Hunchly",
        family: TileFamily::DesktopTool,
        types: &[],
        // `www.hunch.ly` 308-redirects here; the canonical host is recorded directly.
        template: "https://hunch.ly/",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "desktop/browser-extension capture tool — reference row only",
    },
    TileDef {
        tool_id: "dir-invid",
        label: "InVID / WeVerify",
        family: TileFamily::DesktopTool,
        types: &[],
        template: "https://www.invid-project.eu/tools-and-services/invid-verification-plugin/",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "browser plugin for video verification — reference row only",
    },
    TileDef {
        tool_id: "dir-autopsy",
        label: "Autopsy",
        family: TileFamily::DesktopTool,
        types: &[],
        template: "https://www.autopsy.com/",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "desktop forensics suite — reference row only",
    },
    TileDef {
        tool_id: "dir-browserleaks",
        label: "BrowserLeaks",
        family: TileFamily::OpSec,
        types: &[],
        template: "https://browserleaks.com/",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "fixed OpSec checklist link — never substituted, never automated",
    },
    TileDef {
        tool_id: "dir-cover-your-tracks",
        label: "Cover Your Tracks (EFF)",
        family: TileFamily::OpSec,
        types: &[],
        template: "https://coveryourtracks.eff.org/",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "fixed OpSec checklist link — never substituted, never automated",
    },
    TileDef {
        tool_id: "dir-amiunique",
        label: "Am I Unique?",
        family: TileFamily::OpSec,
        types: &[],
        template: "https://amiunique.org/fingerprint",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "fixed OpSec checklist link — never substituted, never automated",
    },
    TileDef {
        tool_id: "dir-dnsleaktest",
        label: "DNS Leak Test",
        family: TileFamily::OpSec,
        types: &[],
        template: "https://www.dnsleaktest.com/",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "fixed OpSec checklist link — never substituted, never automated",
    },
    TileDef {
        tool_id: "dir-truescreen",
        label: "TrueScreen",
        family: TileFamily::EvidenceSealing,
        types: &[],
        // NOT `truescreen.eu`: that host does not serve TLS. See the module doc's
        // verification table.
        template: "https://truescreen.io/",
        substitution: Substitution::Fixed,
        fallback: None,
        reason: "paid eIDAS evidence sealing — listed for reference beside the built-in, free \
                 Internet Archive capture",
    },
];

// ─── Value shaping ──────────────────────────────────────────────────────────

/// Splits a subject value into alphanumeric tokens. Everything else — punctuation, quotes,
/// the `@` in a handle — is a separator, so `"Doe, John Q."` and `"John Doe"` tokenize the
/// same way and a stray comma cannot leak into a path segment.
fn tokens(value: &str) -> Vec<String> {
    value
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect()
}

/// Upper-cases the first character of an already-lowercased token, leaving the rest alone.
fn title_case(token: &str) -> String {
    let mut chars = token.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Fills a [`TileDef`]'s `{q}` slot, or returns `None` when the value cannot satisfy it.
fn substitute(def: &TileDef, value: &str) -> Option<String> {
    if def.substitution == Substitution::Fixed {
        return Some(def.template.to_string());
    }

    // One emptiness test for every substituting shape, and it is *alphanumeric* content, not
    // a non-empty string. `"!!! ???"` trims to something, so a naive check would hand a search
    // engine a query for pure punctuation and call the resulting tile a result. There is
    // nothing searchable in it, and the honest answer is no tile at all.
    let parts = tokens(value);
    if parts.is_empty() {
        return None;
    }

    let slot = match def.substitution {
        // The raw value, not the tokens: a dork is an exact-phrase search, so the subject's own
        // punctuation and casing are part of what is being looked for. Quotes are
        // percent-encoded along with it — `%22` is what every engine's own UI emits, and a bare
        // `"` in a query string is illegal even where it happens to work.
        Substitution::QuotedPhrase => {
            let quoted = format!("\"{}\"", value.trim());
            return Some(def.template.replace("{q}", &urlencoding::encode(&quoted)));
        }
        Substitution::EncodedUrl => {
            return Some(
                def.template
                    .replace("{q}", &urlencoding::encode(value.trim())),
            );
        }
        Substitution::LowerHyphen => parts.join("-"),
        Substitution::TitleHyphen => parts
            .iter()
            .map(|t| title_case(t))
            .collect::<Vec<_>>()
            .join("-"),
        Substitution::FirstLastPath => {
            if parts.len() < 2 {
                return None;
            }
            let first = title_case(&parts[0]);
            let last = title_case(parts.last().expect("len >= 2"));
            format!("{first}/{last}")
        }
        Substitution::Fixed => unreachable!("returned before the token check"),
    };

    Some(def.template.replace("{q}", &slot))
}

// ─── Resolution ─────────────────────────────────────────────────────────────

/// Turns a [`TileDef`] plus a subject value into a tile, using the definition's fallback when
/// the template cannot be filled. `None` only when there is no fallback either.
fn build_tile(def: &TileDef, value: &str) -> Option<DirectoryTile> {
    let (url, reason) = match substitute(def, value) {
        Some(url) => (url, def.reason),
        None => {
            let (url, reason) = def.fallback?;
            (url.to_string(), reason)
        }
    };
    Some(DirectoryTile {
        tool_id: def.tool_id.to_string(),
        label: def.label.to_string(),
        url,
        reason: reason.to_string(),
        // Never probed at resolve time — this module makes no network call. `refresh.rs`
        // fills this in when the analyst asks for it.
        live: None,
    })
}

/// Every launch-only tile that applies to `oz_type` for this subject `value`.
///
/// Only families that are *about the subject* are ever returned (see the module doc): the
/// OpSec checklist and the desktop-tool references are analyst-facing and reachable through
/// [`static_references`] instead.
pub fn resolve_tiles(oz_type: OzType, value: &str) -> Vec<DirectoryTile> {
    TILES
        .iter()
        .filter(|def| def.family.is_about_the_subject() && def.types.contains(&oz_type))
        .filter_map(|def| build_tile(def, value))
        .collect()
}

/// The analyst-facing reference rows: desktop tools, the OpSec checklist and certified-evidence
/// sealing. Fixed URLs, no substitution, and deliberately **not** attached to any node — see
/// the module doc's first decision.
pub fn static_references() -> Vec<DirectoryTile> {
    TILES
        .iter()
        .filter(|def| !def.family.is_about_the_subject())
        .filter_map(|def| build_tile(def, ""))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── catalogue sanity ────────────────────────────────────────────────

    #[test]
    fn tile_ids_are_unique() {
        let mut ids: Vec<&str> = TILES.iter().map(|t| t.tool_id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "two catalogued tiles share an id");
    }

    #[test]
    fn every_template_is_https() {
        // A launch-only tile is opened in the analyst's own browser with their own session.
        // A plaintext one would leak the subject's name over the wire in the query string.
        for def in TILES {
            assert!(
                def.template.starts_with("https://"),
                "{} is not https",
                def.tool_id
            );
            if let Some((url, _)) = def.fallback {
                assert!(
                    url.starts_with("https://"),
                    "{}'s fallback is not https",
                    def.tool_id
                );
            }
        }
    }

    #[test]
    fn a_substituting_template_has_a_slot_and_a_fixed_one_does_not() {
        // The pairing that goes wrong silently: a `{q}` template marked `Fixed` would ship the
        // literal string `{q}` in a URL, and a substituting template with no slot would send
        // every subject to the same page.
        for def in TILES {
            let has_slot = def.template.contains("{q}");
            match def.substitution {
                Substitution::Fixed => {
                    assert!(
                        !has_slot,
                        "{} is Fixed but its template has a {{q}}",
                        def.tool_id
                    )
                }
                _ => assert!(
                    has_slot,
                    "{} substitutes but its template has no {{q}}",
                    def.tool_id
                ),
            }
        }
    }

    #[test]
    fn analyst_reference_families_declare_no_entity_type() {
        // The mechanical half of the "references are not subject tiles" decision: if one of
        // them ever gained a type, `resolve_tiles` would still refuse it on family — this
        // asserts the data agrees with the code so the two cannot drift into confusion.
        for def in TILES {
            if def.family.is_about_the_subject() {
                assert!(
                    !def.types.is_empty(),
                    "{} is a subject tile with no type",
                    def.tool_id
                );
            } else {
                assert!(
                    def.types.is_empty(),
                    "{} is a reference row with a type",
                    def.tool_id
                );
            }
        }
    }

    // ── substitution ────────────────────────────────────────────────────

    #[test]
    fn tokens_treat_every_non_alphanumeric_as_a_separator() {
        assert_eq!(tokens("  John   Doe  "), vec!["john", "doe"]);
        assert_eq!(tokens("Doe, John Q."), vec!["doe", "john", "q"]);
        assert_eq!(tokens("@jean-luc_picard"), vec!["jean", "luc", "picard"]);
        assert!(tokens("!!! ???").is_empty());
    }

    #[test]
    fn lower_and_title_hyphen_shapes_match_the_verified_vendor_urls() {
        let tiles = resolve_tiles(OzType::Name, "John Doe");
        let by = |id: &str| {
            tiles
                .iter()
                .find(|t| t.tool_id == id)
                .unwrap_or_else(|| panic!("{id} missing"))
                .url
                .clone()
        };
        // Verified end to end: this exact URL returns 200 with a real result page.
        assert_eq!(by("dir-spokeo"), "https://www.spokeo.com/John-Doe");
        assert_eq!(
            by("dir-whitepages"),
            "https://www.whitepages.com/name/John-Doe"
        );
        assert_eq!(
            by("dir-beenverified"),
            "https://www.beenverified.com/people/john-doe/"
        );
        assert_eq!(
            by("dir-fastpeoplesearch"),
            "https://www.fastpeoplesearch.com/name/john-doe"
        );
        assert_eq!(by("dir-radaris"), "https://radaris.com/p/John/Doe/");
    }

    #[test]
    fn a_dork_wraps_the_value_in_percent_encoded_quotes() {
        let tiles = resolve_tiles(OzType::Name, "John Doe");
        let google = tiles
            .iter()
            .find(|t| t.tool_id == "dir-google-dork")
            .expect("google dork");
        assert_eq!(
            google.url,
            "https://www.google.com/search?q=%22John%20Doe%22"
        );
        let yandex = tiles
            .iter()
            .find(|t| t.tool_id == "dir-yandex-dork")
            .expect("yandex dork");
        assert_eq!(
            yandex.url,
            "https://yandex.com/search/?text=%22John%20Doe%22"
        );
    }

    #[test]
    fn a_middle_name_is_dropped_from_the_two_segment_path_not_smuggled_in() {
        // Radaris's route has exactly two slots. Joining three tokens into two segments would
        // produce a path the vendor has no handler for — a tile that always 404s.
        let tiles = resolve_tiles(OzType::Name, "John Quincy Doe");
        let radaris = tiles
            .iter()
            .find(|t| t.tool_id == "dir-radaris")
            .expect("radaris");
        assert_eq!(radaris.url, "https://radaris.com/p/John/Doe/");
        // The vendors that take one flat slug keep every token.
        let fps = tiles
            .iter()
            .find(|t| t.tool_id == "dir-fastpeoplesearch")
            .expect("fps");
        assert_eq!(
            fps.url,
            "https://www.fastpeoplesearch.com/name/john-quincy-doe"
        );
    }

    #[test]
    fn a_single_token_name_still_gets_a_radaris_tile_that_says_why_it_is_shallow() {
        // The silent-shrink case this fallback exists for: without it, "Cher" would come back
        // with four people-search tiles instead of five and nothing would say a fifth vendor
        // was ever catalogued.
        let tiles = resolve_tiles(OzType::Name, "Cher");
        let radaris = tiles
            .iter()
            .find(|t| t.tool_id == "dir-radaris")
            .expect("radaris tile");
        assert_eq!(radaris.url, "https://radaris.com/");
        assert!(
            radaris.reason.contains("first"),
            "the fallback must explain itself"
        );
        assert_eq!(
            tiles.len(),
            resolve_tiles(OzType::Name, "John Doe").len(),
            "the tile count must not depend on how many words the name has"
        );
    }

    #[test]
    fn punctuation_never_reaches_a_path_segment() {
        let tiles = resolve_tiles(OzType::Name, "O'Brien, Seán/");
        for tile in &tiles {
            // Everything after the scheme's `//` must be free of the characters that would
            // change the URL's structure.
            let after_scheme = &tile.url["https://".len()..];
            assert!(
                !after_scheme.contains("//"),
                "{} has an empty path segment",
                tile.url
            );
            assert!(!after_scheme.contains('\''), "{} leaked a quote", tile.url);
        }
    }

    #[test]
    fn a_value_with_no_alphanumerics_produces_no_searchable_tile() {
        // Not even a dork: `"!!! ???"` trims to a non-empty string, so a naive emptiness check
        // would hand Google a query for pure punctuation and present the tile as a lead.
        let tiles = resolve_tiles(OzType::Name, "!!! ???");
        assert!(
            !tiles.iter().any(|t| t.tool_id.contains("dork")),
            "a value with nothing searchable in it must not yield a search tile"
        );
        for tile in &tiles {
            assert!(
                !tile.url.contains("{q}"),
                "{} shipped an unfilled slot",
                tile.url
            );
            assert!(tile.url.starts_with("https://"));
        }
        // Only Radaris has a fallback, so that is all that survives — and it says why.
        assert_eq!(tiles.len(), 1);
        assert_eq!(tiles[0].tool_id, "dir-radaris");
    }

    // ── typing ──────────────────────────────────────────────────────────

    #[test]
    fn a_directory_node_gets_dorks_and_never_a_people_search_tile() {
        // `classify.rs` reserves DIR for "a company, product, or other non-person entity".
        // Sending a company name to a people-search aggregator would be a guaranteed miss
        // dressed up as a lead.
        let tiles = resolve_tiles(OzType::Directory, "Acme Corporation");
        assert!(!tiles.is_empty());
        for tile in &tiles {
            assert!(
                tile.tool_id.contains("dork"),
                "{} is not a dork builder but was offered for a DIR node",
                tile.tool_id
            );
        }
    }

    #[test]
    fn reverse_face_tiles_answer_for_an_image_and_never_for_a_name() {
        let for_name = resolve_tiles(OzType::Name, "John Doe");
        assert!(
            !for_name.iter().any(|t| t.tool_id == "dir-google-lens"),
            "a reverse-image tile fed a personal name cannot work"
        );

        let for_image = resolve_tiles(OzType::Image, "https://example.com/a.jpg");
        let lens = for_image
            .iter()
            .find(|t| t.tool_id == "dir-google-lens")
            .expect("lens tile");
        assert_eq!(
            lens.url,
            "https://lens.google.com/uploadbyurl?url=https%3A%2F%2Fexample.com%2Fa.jpg"
        );
        assert!(for_image.iter().any(|t| t.tool_id == "dir-pimeyes"));
        assert_eq!(
            for_image.len(),
            4,
            "all four reverse-face tiles resolve for an image"
        );
    }

    #[test]
    fn a_type_with_no_catalogued_tile_gets_an_empty_list_not_a_wrong_one() {
        for oz_type in [OzType::Email, OzType::Phone, OzType::Ip, OzType::Cve] {
            assert!(
                resolve_tiles(oz_type, "whatever").is_empty(),
                "{oz_type:?} has no catalogued directory tile and must get none"
            );
        }
    }

    // ── static references ───────────────────────────────────────────────

    #[test]
    fn static_references_are_the_analyst_facing_rows_and_carry_no_subject() {
        let refs = static_references();
        assert_eq!(
            refs.len(),
            9,
            "4 desktop tools + 4 OpSec links + TrueScreen"
        );
        for r in &refs {
            assert!(!r.url.contains("{q}"));
            assert_eq!(r.live, None);
        }
        assert!(refs.iter().any(|r| r.tool_id == "dir-maltego"));
        assert!(refs.iter().any(|r| r.tool_id == "dir-browserleaks"));
        // The correction recorded in the module doc: `truescreen.eu` does not serve TLS at
        // all.
        let ts = refs
            .iter()
            .find(|r| r.tool_id == "dir-truescreen")
            .expect("truescreen");
        assert_eq!(ts.url, "https://truescreen.io/");
    }

    #[test]
    fn no_reference_row_is_ever_reachable_from_a_node_tile_list() {
        let reference_ids: Vec<String> =
            static_references().into_iter().map(|r| r.tool_id).collect();
        for oz_type in [
            OzType::Username,
            OzType::Email,
            OzType::Phone,
            OzType::Ip,
            OzType::Domain,
            OzType::Hash,
            OzType::Image,
            OzType::Video,
            OzType::Coordinate,
            OzType::Cve,
            OzType::Directory,
            OzType::Name,
        ] {
            for tile in resolve_tiles(oz_type, "John Doe") {
                assert!(
                    !reference_ids.contains(&tile.tool_id),
                    "{} is an analyst reference and must never attach to a {oz_type:?} node",
                    tile.tool_id
                );
            }
        }
    }

    // ── liveness is somebody else's job ─────────────────────────────────

    #[test]
    fn resolution_never_claims_a_tile_is_live() {
        // This module makes no network call, so it has no basis for a liveness verdict.
        // `refresh.rs`'s HEAD probe is the only thing allowed to set this.
        for tile in resolve_tiles(OzType::Name, "John Doe") {
            assert_eq!(
                tile.live, None,
                "{} was born with a liveness claim",
                tile.tool_id
            );
        }
    }
}
