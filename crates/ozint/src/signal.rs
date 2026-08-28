//! The one glanceable verdict per node, computed from its payload alone.
//!
//! Pure, synchronous, no I/O: `signal_for` turns an [`OzPayload`] into an `Option<SignalChip>`.
//! `None` means "nothing has been looked up yet" — a chip must never assert a verdict it does
//! not have, so every per-type function treats the payload's own `Default` value as "empty" and
//! bails out before the dispatcher even calls it.
//!
//! **There is no universal risk score.** Each
//! category speaks its own language (`14 / 312 sites`, `4 breaches`, `VoIP · elevated`) and
//! colour is reserved for genuine risk — types with no risk dimension (username, domain,
//! directory/name) always render [`SignalTone::Neutral`], in both modes.
//!
//! [`SignalMode::Tier`] collapses any of those into a short comparable word sharing the same
//! tone, so nodes of different types can be ranked against each other without inventing a fake
//! score.
//!
//! Gating is a caller concern: this module only sees a payload, never
//! provenance, so it cannot know whether the data came from an ethically-gated tool. The caller
//! must call [`apply_gated`] last, after computing the normal chip, whenever `node.gated` (or
//! `provenance.gated`) is true.

use crate::types::{
    CoordinatePayload, CvePayload, DirectoryPayload, DomainPayload, EmailPayload, HashPayload,
    ImagePayload, IpPayload, OzPayload, PhonePayload, SignalChip, SignalTone, UsernamePayload,
    VideoPayload,
};

/// How a chip should read: in the category's own language, or collapsed to a coarse band that
/// is comparable across types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalMode {
    /// Native, per-category phrasing (`14 / 312 sites`, `VoIP · elevated`).
    Native,
    /// A short word + the same tone, for cross-type ranking.
    Tier,
}

/// Computes the one glanceable verdict for a node's payload, or `None` when the payload is
/// still at its type's default — i.e. nothing has been looked up for this node yet.
pub fn signal_for(payload: &OzPayload, mode: SignalMode) -> Option<SignalChip> {
    let chip = native_signal(payload)?;
    Some(match mode {
        SignalMode::Native => chip,
        SignalMode::Tier => SignalChip::new(tier_word(chip.tone), chip.tone),
    })
}

/// Applies the gated override: a chip built from an ethically-gated tool's data
/// must read `Gated`, and nothing downstream may ever downgrade it. This function only sees a
/// chip, never provenance — **the caller owns checking `node.gated`** before invoking it, and
/// must call it last, after any other tone computation on the chip.
pub fn apply_gated(mut chip: SignalChip) -> SignalChip {
    chip.tone = SignalTone::Gated;
    chip
}

// ─── Dispatch ──────────────────────────────────────────────────────────────

fn native_signal(payload: &OzPayload) -> Option<SignalChip> {
    Some(match payload {
        OzPayload::Username(p) => {
            if is_default(p) {
                return None;
            }
            username_chip(p)
        }
        OzPayload::Email(p) => {
            if is_default(p) {
                return None;
            }
            email_chip(p)
        }
        OzPayload::Phone(p) => {
            if is_default(p) {
                return None;
            }
            phone_chip(p)
        }
        OzPayload::Ip(p) => {
            if is_default(p) {
                return None;
            }
            ip_chip(p)
        }
        OzPayload::Domain(p) => {
            if is_default(p) {
                return None;
            }
            domain_chip(p)
        }
        OzPayload::Hash(p) => {
            if is_default(p) {
                return None;
            }
            hash_chip(p)
        }
        OzPayload::Image(p) => {
            if is_default(p) {
                return None;
            }
            image_chip(p)
        }
        OzPayload::Video(p) => {
            if is_default(p) {
                return None;
            }
            video_chip(p)
        }
        OzPayload::Coordinate(p) => {
            if is_default(p) {
                return None;
            }
            coordinate_chip(p)
        }
        OzPayload::Cve(p) => {
            if is_default(p) {
                return None;
            }
            cve_chip(p)
        }
        // Directory and Name share the same tile-set payload shape.
        OzPayload::Directory(p) => {
            if is_default(p) {
                return None;
            }
            directory_chip(p)
        }
        OzPayload::Name(p) => {
            if is_default(p) {
                return None;
            }
            directory_chip(p)
        }
    })
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

// ─── Tone helpers ──────────────────────────────────────────────────────────

/// Ordering used to combine several tone signals into one "worst wins" tone. `Gated` ranks
/// highest so a chip that already carries it (e.g. a per-breach tone set upstream by a gated
/// tool) is never accidentally downgraded by aggregation — though the documented, supported path
/// for gating is still [`apply_gated`], applied by the caller.
fn tone_rank(tone: SignalTone) -> u8 {
    match tone {
        SignalTone::Neutral => 0,
        SignalTone::Ok => 1,
        SignalTone::Warn => 2,
        SignalTone::Risk => 3,
        SignalTone::Critical => 4,
        SignalTone::Gated => 5,
    }
}

fn escalate(a: SignalTone, b: SignalTone) -> SignalTone {
    if tone_rank(b) > tone_rank(a) { b } else { a }
}

fn worst_tone(tones: impl Iterator<Item = SignalTone>) -> SignalTone {
    tones.fold(SignalTone::Neutral, escalate)
}

/// Tier-mode word for each tone. Types with no risk dimension always carry `Neutral` in their
/// native chip, so they collapse to `N/A` here rather than a fake "clear" — colour/verdict is
/// earned, not painted everywhere, and that applies to Tier mode too.
fn tier_word(tone: SignalTone) -> &'static str {
    match tone {
        SignalTone::Neutral => "N/A",
        SignalTone::Ok => "CLEAR",
        SignalTone::Warn => "ELEVATED",
        SignalTone::Risk => "RISK",
        SignalTone::Critical => "CRITICAL",
        SignalTone::Gated => "GATED",
    }
}

// ─── Username ──────────────────────────────────────────────────────────────

fn username_chip(p: &UsernamePayload) -> SignalChip {
    // A handle existing is not itself a risk — always Neutral.
    let mut chip = SignalChip::new(
        format!("{} / {} sites", p.sites_confirmed, p.sites_checked),
        SignalTone::Neutral,
    );
    if p.sites_checked > 0 {
        chip = chip.with_ratio(p.sites_confirmed as f64 / p.sites_checked as f64);
    }
    chip
}

// ─── Email ─────────────────────────────────────────────────────────────────

fn email_chip(p: &EmailPayload) -> SignalChip {
    if p.breaches.is_empty() {
        // The payload isn't default (checked by the caller), so something did run;
        // a clean sweep reads as an explicit Ok, not a missing verdict.
        return SignalChip::new("no breaches", SignalTone::Ok);
    }
    // Each BreachEvent already carries its own tone (the per-breach severity rubric is this
    // module's own call — aggregation-by-worst is the answer for the *chip*, it does not
    // redefine any individual breach's tone).
    let tone = worst_tone(p.breaches.iter().map(|b| b.tone));
    let n = p.breaches.len();
    let noun = if n == 1 { "breach" } else { "breaches" };
    SignalChip::new(format!("{n} {noun}"), tone)
}

// ─── Phone ─────────────────────────────────────────────────────────────────

// Own thresholds — no source gives a numeric fraud-score banding for PhonePayload.fraud_score.
// Mirrored from the AbuseIPDB 25/75 shape (see ip_chip) for a consistent feel across the crate's
// several independent 0-100 provider scores.
const PHONE_FRAUD_WARN_AT: u8 = 25;
const PHONE_FRAUD_RISK_AT: u8 = 75;

fn phone_chip(p: &PhonePayload) -> SignalChip {
    if p.valid == Some(false) {
        return SignalChip::new("invalid number", SignalTone::Warn);
    }

    // PhonePayload has a single free-text `line_type` field, not a separate prepaid boolean, so
    // "VoIP + prepaid" (own reading) is detected as both substrings present in that one string
    // (e.g. a source returning "voip, prepaid" or "voip prepaid").
    let line_lower = p.line_type.as_deref().unwrap_or("").to_lowercase();
    let is_voip = line_lower.contains("voip");
    let is_prepaid = line_lower.contains("prepaid");

    let mut tone = SignalTone::Neutral;
    if let Some(score) = p.fraud_score {
        tone = escalate(
            tone,
            if score >= PHONE_FRAUD_RISK_AT {
                SignalTone::Risk
            } else if score >= PHONE_FRAUD_WARN_AT {
                SignalTone::Warn
            } else {
                SignalTone::Ok
            },
        );
    }
    if is_voip {
        // VoIP alone is at least a Warn ("VoIP · elevated").
        tone = escalate(tone, SignalTone::Warn);
    }
    if is_voip && is_prepaid {
        // Hard floor: VoIP + prepaid can never read better than `risk`.
        tone = escalate(tone, SignalTone::Risk);
    }
    if !p.breaches.is_empty() {
        tone = escalate(tone, worst_tone(p.breaches.iter().map(|b| b.tone)));
    }

    let descriptor = match tone {
        SignalTone::Critical => "critical",
        SignalTone::Risk => "risk",
        SignalTone::Warn => "elevated",
        SignalTone::Ok => "clear",
        SignalTone::Neutral | SignalTone::Gated => "unclassified",
    };
    let label = p.line_type.clone().unwrap_or_else(|| "phone".to_string());
    SignalChip::new(format!("{label} · {descriptor}"), tone)
}

// ─── IP ────────────────────────────────────────────────────────────────────

// AbuseIPDB confidence bands.
const ABUSE_WARN_AT: u8 = 25; // 25 = warn
const ABUSE_RISK_AT: u8 = 75; // 75 = risk/critical boundary

fn abuse_tone(score: u8) -> SignalTone {
    if score >= ABUSE_RISK_AT {
        SignalTone::Risk
    } else if score >= ABUSE_WARN_AT {
        SignalTone::Warn
    } else {
        SignalTone::Ok
    }
}

fn ip_chip(p: &IpPayload) -> SignalChip {
    let mut ratio = None;
    let (text, mut tone) = if let Some(score) = p.abuse_score {
        ratio = Some(score as f64 / 100.0);
        (format!("abuse {score} / 100"), abuse_tone(score))
    } else {
        match p.classification.as_deref() {
            Some(c) => (c.to_string(), SignalTone::Neutral),
            None => ("no reputation data".to_string(), SignalTone::Neutral),
        }
    };
    // Own additions — only the AbuseIPDB 25/75 bands are fixed above; GreyNoise's
    // `classification`/`anonymizer` are separate providers with no numeric rule of their own,
    // so they can only ever raise the tone, never define it outright.
    if p.classification.as_deref() == Some("malicious") {
        tone = escalate(tone, SignalTone::Risk);
    }
    if p.anonymizer == Some(true) {
        tone = escalate(tone, SignalTone::Warn);
    }
    let mut chip = SignalChip::new(text, tone);
    if let Some(r) = ratio {
        chip = chip.with_ratio(r);
    }
    chip
}

// ─── Domain ────────────────────────────────────────────────────────────────

fn domain_chip(p: &DomainPayload) -> SignalChip {
    let count = p.subdomains.len();
    let suffix = if p.subdomains_truncated { "+" } else { "" };
    // No risk dimension for a subdomain count — always Neutral.
    SignalChip::new(format!("{count}{suffix} subdomains"), SignalTone::Neutral)
}

// ─── Hash ──────────────────────────────────────────────────────────────────

// VirusTotal — meaningful-malware boundary.
const VT_MEANINGFUL_DETECTIONS: u32 = 3;

fn hash_chip(p: &HashPayload) -> SignalChip {
    match (p.detections, p.engines_total) {
        (Some(detections), Some(total)) if total > 0 => {
            let tone = if detections == 0 {
                SignalTone::Ok
            } else if detections < VT_MEANINGFUL_DETECTIONS {
                SignalTone::Warn
            } else if detections.saturating_mul(2) >= total {
                // Own addition — only the ≥3 boundary is fixed above; a majority of engines
                // flagging the sample reads as unambiguous confirmed malware, not merely
                // "meaningful", so it earns Critical rather than Risk.
                SignalTone::Critical
            } else {
                SignalTone::Risk
            };
            SignalChip::new(format!("{detections} / {total} engines"), tone)
                .with_ratio(detections as f64 / total as f64)
        }
        // No AV verdict yet — fall back to whatever static info the payload does carry rather
        // than asserting a "0 / 0 engines" chip that looks like a clean scan.
        _ => {
            let text = p
                .family
                .clone()
                .or_else(|| p.file_type.clone())
                .unwrap_or_else(|| "no AV data".to_string());
            SignalChip::new(text, SignalTone::Neutral)
        }
    }
}

// ─── Image ─────────────────────────────────────────────────────────────────

fn image_chip(p: &ImagePayload) -> SignalChip {
    if p.lat.is_some() || p.lon.is_some() {
        let text = match p.accuracy_m {
            Some(acc) => format!("±{acc:.0} m"),
            None => "GPS present".to_string(),
        };
        return SignalChip::new(text, SignalTone::Neutral).with_meta("from EXIF");
    }
    if !p.exif.is_empty() {
        return SignalChip::new(format!("{} EXIF fields", p.exif.len()), SignalTone::Neutral);
    }
    if !p.reverse_matches.is_empty() {
        return SignalChip::new(
            format!("{} reverse matches", p.reverse_matches.len()),
            SignalTone::Neutral,
        );
    }
    SignalChip::new("no EXIF data", SignalTone::Neutral)
}

// ─── Video ─────────────────────────────────────────────────────────────────

fn video_chip(p: &VideoPayload) -> SignalChip {
    if let Some(dur) = p.duration_s {
        let mins = (dur / 60.0).floor() as u64;
        let secs = (dur % 60.0).round() as u64;
        let kf = p.keyframe_media_ids.len();
        return SignalChip::new(
            format!("{mins}:{secs:02} · {kf} keyframes"),
            SignalTone::Neutral,
        );
    }
    if !p.metadata.is_empty() {
        return SignalChip::new(
            format!("{} metadata fields", p.metadata.len()),
            SignalTone::Neutral,
        );
    }
    SignalChip::new("no video metadata", SignalTone::Neutral)
}

// ─── Coordinate ────────────────────────────────────────────────────────────

fn coordinate_chip(p: &CoordinatePayload) -> SignalChip {
    let text = match &p.place {
        Some(place) => place.clone(),
        None => format!("{:.5}, {:.5}", p.lat, p.lon),
    };
    let mut chip = SignalChip::new(text, SignalTone::Neutral);
    if let Some(country) = &p.country {
        chip = chip.with_meta(country.clone());
    }
    chip
}

// ─── CVE ───────────────────────────────────────────────────────────────────

// FIRST EPSS — one half of the critical combination.
const EPSS_CRITICAL_AT: f64 = 0.7; // EPSS > 0.7 AND in the CISA KEV catalogue = critical

fn cve_chip(p: &CvePayload) -> SignalChip {
    let epss_high = p.epss.map(|e| e > EPSS_CRITICAL_AT).unwrap_or(false);

    // Own addition — CVSS v3.1 qualitative severity rating scale (FIRST.org spec): none 0.0,
    // low 0.1-3.9, medium 4.0-6.9, high 7.0-8.9, critical 9.0-10.0. Deliberately capped below
    // `Critical` here: this module reserves the Critical *tone* strictly for the
    // EPSS-and-KEV combination below, never from CVSS alone.
    let mut tone = match p.cvss {
        Some(c) if c >= 7.0 => SignalTone::Risk,
        Some(c) if c >= 4.0 => SignalTone::Warn,
        Some(c) if c > 0.0 => SignalTone::Ok,
        _ => SignalTone::Neutral,
    };
    if p.kev {
        // Own addition — presence in the CISA KEV catalogue is significant on its own, even
        // without the epss>0.7 half of the rule below.
        tone = escalate(tone, SignalTone::Risk);
    }
    if epss_high {
        tone = escalate(tone, SignalTone::Risk);
    }
    if epss_high && p.kev {
        // The explicit rule: both halves required, hard override to Critical.
        tone = escalate(tone, SignalTone::Critical);
    }

    let text = match (p.cvss, p.kev, p.epss) {
        (Some(c), true, _) => format!("{c:.1} · exploited ITW"),
        (Some(c), false, Some(e)) => format!("{c:.1} · EPSS {:.0}%", e * 100.0),
        (Some(c), false, None) => format!("{c:.1}"),
        (None, true, _) => "exploited ITW".to_string(),
        (None, false, Some(e)) => format!("EPSS {:.0}%", e * 100.0),
        (None, false, None) => "no CVSS score".to_string(),
    };

    let mut chip = SignalChip::new(text, tone);
    if let Some(c) = p.cvss {
        chip = chip.with_ratio(c / 10.0);
    }
    chip
}

// ─── Directory / Name ──────────────────────────────────────────────────────

fn directory_chip(p: &DirectoryPayload) -> SignalChip {
    let n = p.tiles.len();
    // These are launch-only links, never fetched — text makes that explicit, tone always
    // Neutral: no risk dimension for a link list.
    SignalChip::new(format!("{n} tools · no native search"), SignalTone::Neutral)
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BreachEvent, DirectoryTile, OzRow};

    fn breach(tone: SignalTone) -> BreachEvent {
        BreachEvent {
            name: "Example Co".into(),
            breached_at: None,
            added_at: None,
            data_classes: vec!["Passwords".into()],
            tone,
            source_tool_id: "hibp".into(),
        }
    }

    // ── empty payload → None, for every type ──────────────────────────────

    #[test]
    fn empty_payload_is_none_for_every_type() {
        assert_eq!(
            signal_for(&OzPayload::Username(Default::default()), SignalMode::Native),
            None
        );
        assert_eq!(
            signal_for(&OzPayload::Email(Default::default()), SignalMode::Native),
            None
        );
        assert_eq!(
            signal_for(&OzPayload::Phone(Default::default()), SignalMode::Native),
            None
        );
        assert_eq!(
            signal_for(&OzPayload::Ip(Default::default()), SignalMode::Native),
            None
        );
        assert_eq!(
            signal_for(&OzPayload::Domain(Default::default()), SignalMode::Native),
            None
        );
        assert_eq!(
            signal_for(&OzPayload::Hash(Default::default()), SignalMode::Native),
            None
        );
        assert_eq!(
            signal_for(&OzPayload::Image(Default::default()), SignalMode::Native),
            None
        );
        assert_eq!(
            signal_for(&OzPayload::Video(Default::default()), SignalMode::Native),
            None
        );
        assert_eq!(
            signal_for(
                &OzPayload::Coordinate(Default::default()),
                SignalMode::Native
            ),
            None
        );
        assert_eq!(
            signal_for(&OzPayload::Cve(Default::default()), SignalMode::Native),
            None
        );
        assert_eq!(
            signal_for(
                &OzPayload::Directory(Default::default()),
                SignalMode::Native
            ),
            None
        );
        assert_eq!(
            signal_for(&OzPayload::Name(Default::default()), SignalMode::Native),
            None
        );
    }

    // ── one sensible chip per type ─────────────────────────────────────────

    #[test]
    fn username_chip_is_sensible() {
        let p = OzPayload::Username(UsernamePayload {
            sites_checked: 312,
            sites_confirmed: 14,
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "14 / 312 sites");
        assert_eq!(chip.tone, SignalTone::Neutral);
        assert!((chip.ratio.unwrap() - 14.0 / 312.0).abs() < 1e-9);
    }

    #[test]
    fn email_chip_with_breaches() {
        let p = OzPayload::Email(EmailPayload {
            breaches: vec![breach(SignalTone::Warn), breach(SignalTone::Risk)],
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "2 breaches");
        assert_eq!(chip.tone, SignalTone::Risk); // worst of Warn/Risk
    }

    #[test]
    fn email_chip_clean_sweep_is_ok() {
        let p = OzPayload::Email(EmailPayload {
            reputation: Some("low".into()),
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "no breaches");
        assert_eq!(chip.tone, SignalTone::Ok);
    }

    #[test]
    fn domain_chip_is_always_neutral() {
        let p = OzPayload::Domain(DomainPayload {
            subdomains: vec!["a.example.com".into(), "b.example.com".into()],
            subdomains_truncated: true,
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "2+ subdomains");
        assert_eq!(chip.tone, SignalTone::Neutral);
    }

    #[test]
    fn image_chip_gps_present() {
        let p = OzPayload::Image(ImagePayload {
            lat: Some(48.8566),
            lon: Some(2.3522),
            accuracy_m: Some(12.0),
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "±12 m");
        assert_eq!(chip.meta.as_deref(), Some("from EXIF"));
    }

    #[test]
    fn image_chip_exif_only() {
        let p = OzPayload::Image(ImagePayload {
            exif: vec![OzRow {
                label: "Camera".into(),
                value: "Pixel 8".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "1 EXIF fields");
    }

    #[test]
    fn video_chip_duration_and_keyframes() {
        let p = OzPayload::Video(VideoPayload {
            duration_s: Some(125.6),
            keyframe_media_ids: vec!["k1".into(), "k2".into()],
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "2:06 · 2 keyframes");
    }

    #[test]
    fn coordinate_chip_prefers_place_name() {
        let with_place = OzPayload::Coordinate(CoordinatePayload {
            lat: 48.8566,
            lon: 2.3522,
            place: Some("Paris, France".into()),
            ..Default::default()
        });
        assert_eq!(
            signal_for(&with_place, SignalMode::Native).unwrap().text,
            "Paris, France"
        );

        let without_place = OzPayload::Coordinate(CoordinatePayload {
            lat: 48.8566,
            lon: 2.3522,
            ..Default::default()
        });
        assert_eq!(
            signal_for(&without_place, SignalMode::Native).unwrap().text,
            "48.85660, 2.35220"
        );
    }

    #[test]
    fn directory_chip_states_launch_only() {
        let p = OzPayload::Directory(DirectoryPayload {
            tiles: vec![DirectoryTile {
                tool_id: "spokeo".into(),
                label: "Spokeo".into(),
                url: "https://spokeo.com".into(),
                reason: "no API".into(),
                live: None,
            }],
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "1 tools · no native search");
        assert_eq!(chip.tone, SignalTone::Neutral);
    }

    #[test]
    fn name_type_shares_the_directory_shape() {
        let p = OzPayload::Name(DirectoryPayload { tiles: vec![] });
        // tiles empty but this is still the *default* payload, so this must be None, not a
        // "0 tools" chip — nothing has actually been resolved for this Name node yet.
        assert_eq!(signal_for(&p, SignalMode::Native), None);
    }

    // ── AbuseIPDB 25/75 boundary ───────────────────────────────────────────

    #[test]
    fn abuse_score_boundary_24_is_ok_25_is_warn() {
        let at24 = OzPayload::Ip(IpPayload {
            abuse_score: Some(24),
            ..Default::default()
        });
        let at25 = OzPayload::Ip(IpPayload {
            abuse_score: Some(25),
            ..Default::default()
        });
        assert_eq!(
            signal_for(&at24, SignalMode::Native).unwrap().tone,
            SignalTone::Ok
        );
        assert_eq!(
            signal_for(&at25, SignalMode::Native).unwrap().tone,
            SignalTone::Warn
        );
    }

    #[test]
    fn abuse_score_boundary_74_is_warn_75_is_risk() {
        let at74 = OzPayload::Ip(IpPayload {
            abuse_score: Some(74),
            ..Default::default()
        });
        let at75 = OzPayload::Ip(IpPayload {
            abuse_score: Some(75),
            ..Default::default()
        });
        assert_eq!(
            signal_for(&at74, SignalMode::Native).unwrap().tone,
            SignalTone::Warn
        );
        assert_eq!(
            signal_for(&at75, SignalMode::Native).unwrap().tone,
            SignalTone::Risk
        );
    }

    #[test]
    fn ip_chip_text_and_ratio() {
        let p = OzPayload::Ip(IpPayload {
            abuse_score: Some(42),
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "abuse 42 / 100");
        assert!((chip.ratio.unwrap() - 0.42).abs() < 1e-9);
    }

    #[test]
    fn ip_malicious_classification_forces_at_least_risk() {
        let p = OzPayload::Ip(IpPayload {
            abuse_score: Some(10), // would be Ok on its own
            classification: Some("malicious".into()),
            ..Default::default()
        });
        assert_eq!(
            signal_for(&p, SignalMode::Native).unwrap().tone,
            SignalTone::Risk
        );
    }

    // ── VirusTotal ≥3 detections boundary ──────────────────────────────────

    #[test]
    fn hash_detection_boundary_2_is_warn_3_is_risk() {
        let at2 = OzPayload::Hash(HashPayload {
            detections: Some(2),
            engines_total: Some(68),
            ..Default::default()
        });
        let at3 = OzPayload::Hash(HashPayload {
            detections: Some(3),
            engines_total: Some(68),
            ..Default::default()
        });
        assert_eq!(
            signal_for(&at2, SignalMode::Native).unwrap().tone,
            SignalTone::Warn
        );
        assert_eq!(
            signal_for(&at3, SignalMode::Native).unwrap().tone,
            SignalTone::Risk
        );
    }

    #[test]
    fn hash_chip_zero_detections_is_ok() {
        let p = OzPayload::Hash(HashPayload {
            detections: Some(0),
            engines_total: Some(68),
            ..Default::default()
        });
        assert_eq!(
            signal_for(&p, SignalMode::Native).unwrap().tone,
            SignalTone::Ok
        );
    }

    #[test]
    fn hash_majority_detections_is_critical() {
        let p = OzPayload::Hash(HashPayload {
            detections: Some(40),
            engines_total: Some(68),
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "40 / 68 engines");
        assert_eq!(chip.tone, SignalTone::Critical);
        assert!((chip.ratio.unwrap() - 40.0 / 68.0).abs() < 1e-9);
    }

    #[test]
    fn hash_chip_falls_back_without_av_data() {
        let p = OzPayload::Hash(HashPayload {
            file_type: Some("PE32".into()),
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "PE32");
        assert_eq!(chip.tone, SignalTone::Neutral);
    }

    // ── EPSS > 0.7 AND KEV = critical boundary ─────────────────────────────

    #[test]
    fn cve_epss_069_no_kev_is_not_critical() {
        let p = OzPayload::Cve(CvePayload {
            epss: Some(0.69),
            kev: false,
            ..Default::default()
        });
        assert_ne!(
            signal_for(&p, SignalMode::Native).unwrap().tone,
            SignalTone::Critical
        );
    }

    #[test]
    fn cve_epss_069_with_kev_is_risk_not_critical() {
        let p = OzPayload::Cve(CvePayload {
            epss: Some(0.69),
            kev: true,
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.tone, SignalTone::Risk);
    }

    #[test]
    fn cve_epss_071_no_kev_is_risk_not_critical() {
        let p = OzPayload::Cve(CvePayload {
            epss: Some(0.71),
            kev: false,
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.tone, SignalTone::Risk);
    }

    #[test]
    fn cve_epss_071_with_kev_is_critical() {
        let p = OzPayload::Cve(CvePayload {
            epss: Some(0.71),
            kev: true,
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.tone, SignalTone::Critical);
        assert_eq!(chip.text, "exploited ITW");
    }

    #[test]
    fn cve_chip_text_and_ratio_with_cvss() {
        let p = OzPayload::Cve(CvePayload {
            cvss: Some(9.8),
            epss: Some(0.9),
            kev: true,
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "9.8 · exploited ITW");
        assert!((chip.ratio.unwrap() - 0.98).abs() < 1e-9);
    }

    // ── Phone: VoIP + prepaid floor, invalid number ────────────────────────

    #[test]
    fn phone_voip_prepaid_floor_is_at_least_risk() {
        let p = OzPayload::Phone(PhonePayload {
            line_type: Some("voip, prepaid".into()),
            fraud_score: Some(0), // would be Ok on its own
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.tone, SignalTone::Risk);
    }

    #[test]
    fn phone_voip_alone_is_warn_not_risk() {
        let p = OzPayload::Phone(PhonePayload {
            line_type: Some("voip".into()),
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.tone, SignalTone::Warn);
        assert_eq!(chip.text, "voip · elevated");
    }

    #[test]
    fn phone_invalid_number_is_warn() {
        let p = OzPayload::Phone(PhonePayload {
            valid: Some(false),
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.text, "invalid number");
        assert_eq!(chip.tone, SignalTone::Warn);
    }

    #[test]
    fn phone_voip_prepaid_floor_does_not_cap_a_higher_tone() {
        // A high fraud score can still push it past the Risk floor to Critical territory —
        // the floor is a minimum, not a ceiling. fraud_score alone tops out at Risk (own
        // banding), so combine it with breaches to prove the floor never *lowers* a worse tone.
        let p = OzPayload::Phone(PhonePayload {
            line_type: Some("voip prepaid".into()),
            breaches: vec![breach(SignalTone::Critical)],
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.tone, SignalTone::Critical);
    }

    // ── apply_gated overrides a would-be-Ok tone ───────────────────────────

    #[test]
    fn apply_gated_overrides_ok_tone() {
        let p = OzPayload::Email(EmailPayload {
            reputation: Some("low".into()),
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Native).unwrap();
        assert_eq!(chip.tone, SignalTone::Ok);
        let gated = apply_gated(chip);
        assert_eq!(gated.tone, SignalTone::Gated);
        assert_eq!(gated.text, "no breaches"); // text/meta/ratio untouched, only tone changes
    }

    // ── Tier mode ───────────────────────────────────────────────────────────

    #[test]
    fn tier_mode_collapses_to_word_and_tone() {
        let p = OzPayload::Ip(IpPayload {
            abuse_score: Some(90),
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Tier).unwrap();
        assert_eq!(chip.text, "RISK");
        assert_eq!(chip.tone, SignalTone::Risk);
        assert_eq!(chip.ratio, None); // Tier mode drops the bar-renderable ratio
    }

    #[test]
    fn tier_mode_is_honestly_neutral_for_types_without_a_risk_dimension() {
        let p = OzPayload::Username(UsernamePayload {
            sites_checked: 100,
            sites_confirmed: 99,
            ..Default::default()
        });
        let chip = signal_for(&p, SignalMode::Tier).unwrap();
        // Must not read as a fake "clear" — no risk dimension means N/A, not Ok.
        assert_eq!(chip.text, "N/A");
        assert_eq!(chip.tone, SignalTone::Neutral);
    }
}
