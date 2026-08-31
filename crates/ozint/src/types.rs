//! OZINT domain — the shared `OzNode` contract every layer, tool, orchestrator and the
//! frontend type against: **every other unit's data shape depends on this**.
//!
//! Conventions: `camelCase` on the wire (these structs cross to the frontend unchanged),
//! `Option<T>` skipped when absent, enums `kebab-case`.
//!
//! Two modelling choices worth stating:
//!
//! 1. **`OzPayload` is a real tagged enum**, not a flat `Partial<>`-style struct (which is
//!    what `GeoEvent` had to be, for TypeScript-spread reasons that no longer apply here).
//!    OZINT payloads genuinely differ per type and are never spread-merged across types, so
//!    the union buys exhaustiveness checking in every orchestrator.
//! 2. **`OzType::Name` exists** even though it sits outside the ten machine-resolvable
//!    types plus `Directory`. A bare personal name is a real seed the classifier must be able
//!    to return, and it falls back to DIR; modelling it as its own type keeps that fallback
//!    explicit at the dispatch table instead of erasing the distinction at classification time.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Entity types ──────────────────────────────────────────────────────────

/// The entity category a node (or a seed value) belongs to. One orchestrator per variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OzType {
    Username,
    Email,
    Phone,
    Ip,
    Domain,
    Hash,
    Image,
    Video,
    Coordinate,
    Cve,
    /// A launch-only tile set (people-search aggregators, dork builders, OpSec checklists).
    /// Never fetched, by deliberate design — this type only ever produces launch tiles.
    Directory,
    /// A bare personal name. Dispatches to the directory orchestrator.
    Name,
}

impl OzType {
    /// Short code used in the UI and in log lines (`USR`, `EML`, …).
    pub const fn code(self) -> &'static str {
        match self {
            OzType::Username => "USR",
            OzType::Email => "EML",
            OzType::Phone => "TEL",
            OzType::Ip => "NET",
            OzType::Domain => "DOM",
            OzType::Hash => "SHA",
            OzType::Image => "IMG",
            OzType::Video => "VID",
            OzType::Coordinate => "GEO",
            OzType::Cve => "CVE",
            OzType::Directory => "DIR",
            OzType::Name => "NAM",
        }
    }

    /// Whether this type has any automated lookup at all. `Directory` (and a bare `Name`,
    /// which resolves to directory tiles) are link-resolvers with zero network calls in
    /// their base path.
    pub const fn is_directory_only(self) -> bool {
        matches!(self, OzType::Directory | OzType::Name)
    }
}

// ─── Signal chip ───────────────────────────────────────────────────────────

/// Tone of a signal chip. Colour is reserved for genuine risk, so `Neutral`
/// is the default and `Ok`/`Warn`/`Risk`/`Critical` are earned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignalTone {
    #[default]
    Neutral,
    Ok,
    Warn,
    Risk,
    Critical,
    /// Produced by an ethically-gated tool. Never downgraded by anything downstream.
    Gated,
}

/// The one glanceable verdict a settled node carries, in its own category's language
/// (`14 / 312 sites`, `4 breaches`, `VoIP · elevated`). There is deliberately **no**
/// universal risk score across categories.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalChip {
    pub text: String,
    pub tone: SignalTone,
    /// Secondary line (`from EXIF`, `via HIBP`) — never load-bearing on its own.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub meta: Option<String>,
    /// 0.0–1.0 when the chip is renderable as a bar (`12 / 68 engines` → 0.18).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ratio: Option<f64>,
}

impl SignalChip {
    pub fn new(text: impl Into<String>, tone: SignalTone) -> Self {
        Self {
            text: text.into(),
            tone,
            meta: None,
            ratio: None,
        }
    }

    pub fn with_meta(mut self, meta: impl Into<String>) -> Self {
        self.meta = Some(meta.into());
        self
    }

    pub fn with_ratio(mut self, ratio: f64) -> Self {
        self.ratio = Some(ratio.clamp(0.0, 1.0));
        self
    }
}

// ─── Detail-panel sections ─────────────────────────────────────────────────

/// How a section's rows render. The detail panel is continuous scroll with a section-jump
/// index, so a section is a heading + rows, never a tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SectionKind {
    /// `label: value` rows.
    KeyValue,
    /// A flat set of short tags.
    Tags,
    /// Dated rows, newest first (breach history, first-seen/last-seen).
    Timeline,
    /// Rows whose value is an outbound URL.
    Links,
    /// Rows referencing stored media by `mediaId`, served through the media proxy.
    Media,
}

/// One row inside a section.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OzRow {
    pub label: String,
    pub value: String,
    /// Outbound link for this row (`SRC ↗`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub href: Option<String>,
    /// ISO-8601 instant, for `Timeline` sections.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub at: Option<DateTime<Utc>>,
    /// Tone for rows that carry their own severity (a critical breach class).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tone: Option<SignalTone>,
    /// Which tool produced this specific row, when a section merges several.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source_tool_id: Option<String>,
    /// `mediaId` for `Media` rows.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub media_id: Option<String>,
    /// Set when this row was produced by an ethically-gated tool.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub gated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OzSection {
    pub id: String,
    pub label: String,
    pub kind: SectionKind,
    pub rows: Vec<OzRow>,
}

impl OzSection {
    pub fn new(id: impl Into<String>, label: impl Into<String>, kind: SectionKind) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            kind,
            rows: Vec::new(),
        }
    }
}

// ─── Per-type payloads ─────────────────────────────────────────────────────

/// One site probed by the username fan-out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteHit {
    pub site: String,
    /// WhatsMyName `cat` field — used to group hits in the panel.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub category: Option<String>,
    pub url: String,
    pub status: SiteHitStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SiteHitStatus {
    /// The probe matched the site's declared "account exists" string.
    Confirmed,
    /// Ambiguous response (soft-404, redirect, unexpected body).
    Possible,
    /// Probe ran and the account does not exist.
    Absent,
    /// Probe itself failed (timeout, network, blocked).
    Error,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsernamePayload {
    pub hits: Vec<SiteHit>,
    /// Total sites actually probed (denominator of the `14 / 312 sites` chip).
    pub sites_checked: u32,
    /// Sites that answered `Confirmed`.
    pub sites_confirmed: u32,
    /// Profile facts scraped from confirmed hits (real name, bio, location, avatar…).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub profile: Vec<OzRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BreachEvent {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub breached_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub added_at: Option<DateTime<Utc>>,
    /// Data classes exposed (`Passwords`, `Email addresses`, …), verbatim from the source.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub data_classes: Vec<String>,
    /// Severity of this breach. The rubric ("do passwords alone = critical?") is an open
    /// question — the signal-chip module owns the decision, this field only carries it.
    pub tone: SignalTone,
    pub source_tool_id: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailPayload {
    pub breaches: Vec<BreachEvent>,
    /// Reputation tier as returned (`none`/`low`/`medium`/`high`), not re-scored by us.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reputation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub suspicious: Option<bool>,
    /// Organisational naming pattern for a non-freemail domain (`{first}.{last}@`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub domain_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub freemail: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhonePayload {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub carrier: Option<String>,
    /// `mobile` / `fixed-line` / `voip` / `prepaid` …, verbatim from the source.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub line_type: Option<String>,
    /// 0–100 fraud score when a provider supplies one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fraud_score: Option<u8>,
    /// CNAM / subscriber name, when a provider returns one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subscriber_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub breaches: Vec<BreachEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenPort {
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub product: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpPayload {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub city: Option<String>,
    /// Raw coordinates. Renders as its own block and links to external maps — **never**
    /// a globe pin (hard rule: OZINT stays a separate product from any geo-visualization
    /// feature).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lat: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lon: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub isp: Option<String>,
    /// AbuseIPDB confidence 0–100.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub abuse_score: Option<u8>,
    /// GreyNoise classification (`benign`/`malicious`/`unknown`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub anonymizer: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ports: Vec<OpenPort>,
    /// VirusTotal's AV-engine detection consensus for this address. Owned by `ip-virustotal` —
    /// disjoint from `abuseScore` (`ip-abuseipdb`'s own confidence number, a different metric
    /// from a different provider) and from `classification` (`ip-greynoise`'s).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vt_malicious: Option<u32>,
    /// VirusTotal's own reputation score for this address (signed; community-voted). Owned by
    /// `ip-virustotal`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vt_reputation: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainPayload {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub subdomains: Vec<String>,
    /// True when `subdomains` is **not** the complete set — either because
    /// [`MAX_SUBDOMAIN_CHILDREN`] cut it, or because the upstream enumeration was itself
    /// incomplete. Both causes mean the same thing to the analyst: do not read this list as
    /// exhaustive.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub subdomains_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub mx: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ns: Vec<String>,
    /// Raw TXT record strings — SPF/DKIM/domain-verification entries routinely name the linked
    /// SaaS provider (Google Workspace, Microsoft 365, Cloudflare, …). Owned by `dom-dns`,
    /// queried alongside `mx`/`ns` at zero extra request cost.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub txt: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub registrar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email_pattern: Option<String>,
    /// VirusTotal AV-engine detections against the domain itself. Owned by `dom-virustotal` —
    /// deliberately does **not** write `subdomains`: VT does not reliably enumerate them, and
    /// that field's source of record is `dom-certspotter`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vt_malicious: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vt_reputation: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashPayload {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub md5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sha256: Option<String>,
    /// Engines that flagged the sample (numerator of the `12 / 68 engines` bar).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detections: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub engines_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub first_seen: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub file_type: Option<String>,
    /// Distribution URLs abuse.ch URLhaus recorded this payload being served from. Owned by
    /// `hash-urlhaus` — a pivot to hosting infrastructure no other tier-1 hash tool provides.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub distribution_urls: Vec<String>,
    /// Number of AlienVault OTX pulses (threat-intel reports) referencing this hash. Owned by
    /// `hash-otx` — disjoint from `detections`/`engines_total`, which `hash-virustotal` owns.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pulse_count: Option<u32>,
    /// Tier-2 sandbox verdict (`"malicious"`, `"no-detections"`), owned by
    /// `hash-hybrid-analysis`. Only ever populated once tier 1 already found detections — see
    /// `plans::hash_plan`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sandbox_verdict: Option<String>,
    /// Count of Hybrid Analysis sandbox runs found for this hash (`state == "SUCCESS"` plus
    /// `"ERROR"` reports both count — a submitter's run, whatever its outcome). Owned by
    /// `hash-hybrid-analysis`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sandbox_reports: Option<u32>,
    /// PolySwarm's aggregate marketplace score, 0.0-1.0. Owned by `hash-polyswarm` — a
    /// different signal from `detections`/`engines_total` (VirusTotal's per-engine ratio),
    /// never merged with it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub polyswarm_score: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImagePayload {
    /// Stored-media reference (content-hash keyed) — never a filesystem path.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub media_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exif: Vec<OzRow>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lat: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lon: Option<f64>,
    /// GPS accuracy in metres, when EXIF states one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub accuracy_m: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub taken_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub camera: Option<String>,
    /// Reverse-image appearances. Rows produced by a gated tool carry `gated: true`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub reverse_matches: Vec<OzRow>,
    /// A perceptual hash of the decoded image (`image_hasher`'s default 8×8 DCT hash, base64).
    /// Owned by `img-phash` — computed locally, disjoint from `img-exif`'s fields, and not yet
    /// compared against anything else in the store; see `sources::image::phash`'s module doc.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub phash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoPayload {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub media_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub duration_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub codec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub poster_media_id: Option<String>,
    /// `mediaId` per extracted keyframe; each becomes an IMG child.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub keyframe_media_ids: Vec<String>,
    /// Where a video not held in the local store was identified — a YouTube/Telegram/Bluesky
    /// URL. `None` for a locally probed file, which has no remote origin to name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source_url: Option<String>,
    /// Which platform tool identified this video (`"youtube"`, `"telegram"`, `"bluesky"`).
    /// `None` for a locally probed file.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub metadata: Vec<OzRow>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoordinatePayload {
    pub lat: f64,
    pub lon: f64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub accuracy_m: Option<f64>,
    /// Reverse-geocoded place. Kept as its **own** field, never merged into the raw
    /// coordinates block — a convention every studied tool converged on.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub place: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub country: Option<String>,
    /// External map links (Google Maps primary, OSM/Apple alternates).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub map_links: Vec<OzRow>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvePayload {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cvss: Option<f64>,
    /// Which CVSS revision `cvss` is on (`"3.1"`, `"2.0"`, …).
    ///
    /// Not decoration. NVD routinely publishes several scores for one CVE on **different
    /// scales** — CVE-2021-34527 carries a CVSS v3.1 `8.8` and a CVSS v2 `9.0`, and v2's
    /// `9.0` is the one NVD marks `Primary`. A bare `8.8` next to a bare `9.0` with nothing
    /// saying which scale either is on is not a comparison, it is a coin toss, so the scale
    /// travels with the number.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cvss_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub severity: Option<String>,
    /// FIRST EPSS probability 0.0–1.0.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub epss: Option<f64>,
    /// Present in the CISA Known-Exploited-Vulnerabilities catalogue.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub kev: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub published_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub summary: Option<String>,
    /// The exact vulnerable product/version ranges — NVD's `configurations[].nodes[].cpeMatch[]`,
    /// MITRE's `containers.cna.affected[].versions[]` mapped onto the same shape. Arguably the
    /// single most actionable field on a CVE: it says which builds are affected, not just how
    /// bad the CVE is.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub configurations: Vec<CpeMatch>,
    /// CWE weakness ids (`"CWE-79"`, …) — NVD's `weaknesses[].description[].value`, MITRE's
    /// `containers.cna.problemTypes[].descriptions[].cweId`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub weaknesses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub poc_urls: Vec<PocRepo>,
}

/// One vulnerable product/version range, as reported either by NVD's `cpeMatch` entries or
/// derived from MITRE's `affected[].versions[]`. `criteria` is a CPE 2.3 URI when the source
/// gives one (always for NVD; only sometimes for MITRE, which falls back to `vendor:product`).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch {
    pub criteria: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version_start_including: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version_start_excluding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version_end_including: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version_end_excluding: Option<String>,
}

/// One PoC-in-GitHub repo result — enough to tell a maintained PoC from an abandoned
/// fork-of-a-fork, which a bare URL cannot.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PocRepo {
    pub html_url: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub stargazers_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub updated_at: Option<String>,
}

/// How many subdomains one domain layer may keep, and therefore how many `DOM` children it may
/// spawn.
///
/// The subdomain child cap needs a concrete default (a shared config constant), and 20
/// was adopted rather than re-argued. A cap is not optional here: certificate
/// transparency routinely returns dozens to hundreds of names for one domain, and without a
/// bound a single click would bury the tree under a provider's entire estate.
///
/// The cap governs both the stored `DomainPayload::subdomains` list and the child seeds, so
/// the two can never disagree about what was kept. When it bites,
/// `DomainPayload::subdomains_truncated` says so — a shorter list with nothing marking it as
/// partial would read as a complete enumeration.
pub const MAX_SUBDOMAIN_CHILDREN: usize = 20;

/// How many scene-change keyframes one `video-local-probe` invocation may extract, and
/// therefore how many `Image` children one `VID` layer may spawn from a single video.
///
/// Unspecified by any plan document — this crate's own pick, the same "picked default, tune
/// against real fixtures" posture `classify.rs`'s two thresholds carry. 12 is generous enough
/// to cover a genuinely eventful few minutes of footage (a scene-change filter on a mostly
/// static clip produces far fewer) while keeping a single upload from spawning a wall of
/// Image children the way an unpatched host's port list could without
/// [`MAX_SUBDOMAIN_CHILDREN`]'s domain-side cap.
pub const MAX_VIDEO_KEYFRAMES: usize = 12;

/// How many CVE children one host's vulnerability list may seed. Same figure and same reason
/// as [`MAX_SUBDOMAIN_CHILDREN`]: an unpatched host can report dozens, and a tree that grows a
/// node for each stops being readable well before it stops being accurate.
pub const MAX_VULN_CHILDREN: usize = 20;

/// How many children one VirusTotal relationship may seed on an IP node — applied separately
/// to `communicating_files` and to `resolutions`, so one `ip-virustotal` invocation seeds at
/// most twice this many.
///
/// Half [`MAX_SUBDOMAIN_CHILDREN`], and deliberately below the 20 items VirusTotal returns per
/// relationship, for a reason specific to passive DNS: a subdomain from a certificate log is
/// in-scope by construction (`certspotter::extract_in_scope_names` proves it), whereas a
/// resolution is only ever "some host pointed here once". On shared infrastructure that is
/// mostly unrelated traffic — measured against `8.8.8.8`, whose 20 resolutions are spam hosts
/// with no connection to Google — and there is no scoping rule that can filter it, because
/// the relationship carries no ownership claim to test. The cap is therefore the only bound
/// available, and it is set where a wrong lead costs a glance rather than a screen.
pub const MAX_VT_RELATION_CHILDREN: usize = 10;

/// A launch-only tile: a tool with no usable API, rendered as `NO NATIVE SEARCH` / `OPEN ↗`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryTile {
    pub tool_id: String,
    pub label: String,
    pub url: String,
    /// Why it is directory-only (`Cloudflare`, `login wall`, `desktop app`, `no API`).
    pub reason: String,
    /// Result of the optional HEAD liveness probe; `None` when not probed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub live: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryPayload {
    pub tiles: Vec<DirectoryTile>,
}

/// Payload of a node, narrowed by its `type`. Internally tagged so the cockpit can switch on
/// the same `type` field it already reads off the node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum OzPayload {
    Username(UsernamePayload),
    Email(EmailPayload),
    Phone(PhonePayload),
    Ip(IpPayload),
    Domain(DomainPayload),
    Hash(HashPayload),
    Image(ImagePayload),
    Video(VideoPayload),
    Coordinate(CoordinatePayload),
    Cve(CvePayload),
    Directory(DirectoryPayload),
    Name(DirectoryPayload),
}

impl OzPayload {
    /// The `OzType` this payload belongs to. Must always agree with the owning node's `type`.
    pub const fn oz_type(&self) -> OzType {
        match self {
            OzPayload::Username(_) => OzType::Username,
            OzPayload::Email(_) => OzType::Email,
            OzPayload::Phone(_) => OzType::Phone,
            OzPayload::Ip(_) => OzType::Ip,
            OzPayload::Domain(_) => OzType::Domain,
            OzPayload::Hash(_) => OzType::Hash,
            OzPayload::Image(_) => OzType::Image,
            OzPayload::Video(_) => OzType::Video,
            OzPayload::Coordinate(_) => OzType::Coordinate,
            OzPayload::Cve(_) => OzType::Cve,
            OzPayload::Directory(_) => OzType::Directory,
            OzPayload::Name(_) => OzType::Name,
        }
    }

    /// An empty payload of the given type — what a node carries before its own layer runs.
    pub fn empty_for(oz_type: OzType) -> Self {
        match oz_type {
            OzType::Username => OzPayload::Username(UsernamePayload::default()),
            OzType::Email => OzPayload::Email(EmailPayload::default()),
            OzType::Phone => OzPayload::Phone(PhonePayload::default()),
            OzType::Ip => OzPayload::Ip(IpPayload::default()),
            OzType::Domain => OzPayload::Domain(DomainPayload::default()),
            OzType::Hash => OzPayload::Hash(HashPayload::default()),
            OzType::Image => OzPayload::Image(ImagePayload::default()),
            OzType::Video => OzPayload::Video(VideoPayload::default()),
            OzType::Coordinate => OzPayload::Coordinate(CoordinatePayload::default()),
            OzType::Cve => OzPayload::Cve(CvePayload::default()),
            OzType::Directory => OzPayload::Directory(DirectoryPayload::default()),
            OzType::Name => OzPayload::Name(DirectoryPayload::default()),
        }
    }
}

// ─── Provenance ────────────────────────────────────────────────────────────

/// Analyst-facing status of a node's value. This **is** the corrections log — per-node
/// provenance is the only traceability mechanism, so nothing here is duplicated into a
/// separate audit table.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum RecordStatus {
    /// Untouched since the tool returned it.
    #[default]
    AsReturned,
    /// An analyst edited the value. The original is preserved verbatim, never overwritten.
    #[serde(rename_all = "camelCase")]
    Corrected {
        original_value: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        original_chip: Option<SignalChip>,
        edited_at: DateTime<Utc>,
    },
    /// An analyst marked the finding wrong. Excluded from the subject file and from
    /// relation inference, but still rendered (struck through) — nothing is ever deleted.
    #[serde(rename_all = "camelCase")]
    Rejected { rejected_at: DateTime<Utc> },
}

impl RecordStatus {
    pub const fn is_rejected(&self) -> bool {
        matches!(self, RecordStatus::Rejected { .. })
    }
}

/// A prior observation of this node's value, pushed here by a node refresh when a
/// re-run returns something different. Distinct from `RecordStatus::Corrected`, which is
/// reserved for analyst edits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PriorObservation {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chip: Option<SignalChip>,
    pub observed_at: DateTime<Utc>,
}

/// Where a node came from. Complete on **every** node, including rejected ones.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    /// Id of the parent node this was found via. `None` only for an investigation root.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub found_via_parent_id: Option<String>,
    /// Registry id of the tool that produced this node.
    pub source_tool_id: String,
    /// Human sentence describing how it was obtained — rendered verbatim in the UI
    /// ("queried WhatsMyName's site list for the handle").
    pub method: String,
    pub retrieved_at: DateTime<Utc>,
    pub record_status: RecordStatus,
    /// Every tool that contributed, in order. A node refresh re-invokes exactly this.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tool_chain: Vec<String>,
    /// True when any tool in `tool_chain` is ethically gated. Never cleared downstream.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub gated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub prior_observations: Vec<PriorObservation>,
    /// Evidence-capture findings for this node, one record per URL checked.
    ///
    /// Lives here rather than in a table of its own because it piggybacks on this struct's own
    /// columns rather than needing a separate table, and because it *is*
    /// provenance: what the archive holds for a source is part of how defensible the finding
    /// is. Empty on every node until an analyst asks — a capture is opt-in and slow, never
    /// automatic. See [`crate::evidence`].
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub evidence: Vec<crate::evidence::EvidenceRecord>,
}

impl Provenance {
    pub fn new(source_tool_id: impl Into<String>, method: impl Into<String>) -> Self {
        let tool_id = source_tool_id.into();
        Self {
            found_via_parent_id: None,
            source_tool_id: tool_id.clone(),
            method: method.into(),
            retrieved_at: Utc::now(),
            record_status: RecordStatus::AsReturned,
            tool_chain: vec![tool_id],
            gated: false,
            prior_observations: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

// ─── Node ──────────────────────────────────────────────────────────────────

/// Lifecycle of the layer fired **from** this node. A node the analyst never continues
/// stays `Idle` forever — inert but permanently visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeStatus {
    /// Never continued. The default, and a terminal state unless the analyst acts.
    #[default]
    Idle,
    /// A layer fired from this node is in flight.
    Running,
    /// Its layer completed and produced children.
    Settled,
    /// Its layer completed and produced nothing new — stated explicitly, never silently.
    Empty,
    /// Its layer completed but some tools failed.
    Degraded,
    /// Its layer completed with **every** tool erroring. Must never render as `Empty`.
    Failed,
    /// Its layer was killed mid-flight. Retryable.
    Aborted,
}

/// One route by which a value reached the tree, after the first.
///
/// Carries the tool and its human phrasing so the card can render `└ via github-user`
/// without a lookup, and the parent so the analyst can navigate to where the second path
/// actually ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Corroboration {
    pub tool_id: String,
    /// The tool's own phrasing of what it did — `ToolDef::method`.
    pub method: String,
    /// The node this rediscovery was found from.
    pub parent_node_id: String,
    /// The layer that rediscovered it.
    pub layer_id: String,
    pub found_at: DateTime<Utc>,
    /// A gated tool walked this route. Never cleared.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub gated: bool,
}

impl Corroboration {
    /// Whether two routes are the same one. A different tool, or the same tool reached from a
    /// different parent, is a genuinely different path; the same tool from the same parent is
    /// the same probe running twice and must not inflate the count.
    pub fn same_route_as(&self, tool_id: &str, parent_node_id: &str) -> bool {
        self.tool_id == tool_id && self.parent_node_id == parent_node_id
    }
}

/// A node in an investigation tree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OzNode {
    pub id: String,
    pub investigation_id: String,
    /// `None` for the root seed node.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent_id: Option<String>,
    /// Id of the layer that produced this node. `None` for the root.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub layer_id: Option<String>,
    /// Stable sibling ordering, assigned at insert so a rehydrated tree renders identically.
    pub ordinal: i64,
    /// Tree depth, root = 0.
    pub depth: i64,
    #[serde(rename = "type")]
    pub oz_type: OzType,
    /// Canonical value (the normalized `key`-bearing form) — what a continue
    /// fires on.
    pub value: String,
    /// How the value is shown to the analyst (`+33 6 12 34 56 78` vs the E.164 key).
    pub display: String,
    /// Stable identity for the visited-set dedup. Two nodes with the same `(type, dedup_key)`
    /// are the same entity.
    pub dedup_key: String,
    pub payload: OzPayload,
    /// The one glanceable verdict. `None` until the node's producing layer settles.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub preview_signal: Option<SignalChip>,
    /// Richer signal for the detail panel, when it differs from the card chip.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub full_signal: Option<SignalChip>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sections: Vec<OzSection>,
    /// Produced by, or downstream of, an ethically-gated tool.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub gated: bool,
    pub status: NodeStatus,
    pub provenance: Provenance,
    /// Set when this value was already present elsewhere in the tree — the node is
    /// annotated rather than duplicated (`already in tree · L1`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub already_in_tree: Option<String>,
    /// **Every route to this value after the first.** The first is the node's own
    /// [`Provenance`]; each later rediscovery appends one entry here instead of creating a
    /// duplicate node, so `1 + corroborations.len()` is the number of independent paths.
    ///
    /// Two independent routes to the same entity is evidential reinforcement, among the most
    /// valuable things an investigation produces, and the opposite of a duplicate to suppress.
    /// Persisted rather
    /// than left on the SSE frame, or every corroboration in the tree would silently vanish
    /// the moment the analyst reopened the investigation.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub corroborations: Vec<Corroboration>,
    /// Analyst-supplied replacement value. The original stays in `provenance.record_status`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub edited_value: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl OzNode {
    /// The value the subject file and relation inference should read: the analyst's
    /// correction when there is one, otherwise what the tool returned.
    pub fn effective_value(&self) -> &str {
        self.edited_value.as_deref().unwrap_or(&self.value)
    }

    /// Whether this node contributes to derived views (subject file, relations).
    pub fn contributes(&self) -> bool {
        !self.provenance.record_status.is_rejected()
    }
}

// ─── Investigation ─────────────────────────────────────────────────────────

/// A whole investigation tree. One seed = one tree; a relation always spawns a **new**
/// investigation rather than grafting onto this one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Investigation {
    pub id: String,
    /// The seed value as typed by the analyst, before normalization.
    pub seed_input: String,
    pub seed_type: OzType,
    pub root_node_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Cumulative tool invocations (WhatsMyName's ~730-site fan-out counts as **one**).
    pub lookups: i64,
    /// Cumulative cost in USD cents, for paid tools only.
    pub cost_cents: i64,
    /// One-way link back to the investigation whose relation card spawned this one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub spawned_from_investigation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub spawned_from_relation: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_codes_are_unique() {
        let all = [
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
        ];
        let mut codes: Vec<&str> = all.iter().map(|t| t.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(before, codes.len(), "two OzType variants share a UI code");
    }

    #[test]
    fn empty_payload_matches_its_type() {
        for t in [
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
            assert_eq!(OzPayload::empty_for(t).oz_type(), t);
        }
    }

    #[test]
    fn node_type_serialises_as_type_on_the_wire() {
        let node = sample_node();
        let json = serde_json::to_value(&node).expect("node serialises");
        assert_eq!(json["type"], "username");
        assert_eq!(json["investigationId"], "inv-1");
        // Absent optionals must not appear at all — the cockpit distinguishes missing from null.
        assert!(json.get("parentId").is_none());
        assert!(json.get("previewSignal").is_none());
    }

    #[test]
    fn payload_round_trips() {
        let node = sample_node();
        let json = serde_json::to_string(&node).expect("serialise");
        let back: OzNode = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(node, back);
    }

    #[test]
    fn rejected_node_does_not_contribute() {
        let mut node = sample_node();
        assert!(node.contributes());
        node.provenance.record_status = RecordStatus::Rejected {
            rejected_at: Utc::now(),
        };
        assert!(!node.contributes());
    }

    #[test]
    fn effective_value_prefers_the_analyst_correction() {
        let mut node = sample_node();
        assert_eq!(node.effective_value(), "mtrebosc");
        node.edited_value = Some("m.trebosc".into());
        assert_eq!(node.effective_value(), "m.trebosc");
    }

    #[test]
    fn directory_types_are_the_only_automation_free_ones() {
        assert!(OzType::Directory.is_directory_only());
        assert!(OzType::Name.is_directory_only());
        assert!(!OzType::Username.is_directory_only());
        assert!(!OzType::Cve.is_directory_only());
    }

    fn sample_node() -> OzNode {
        OzNode {
            id: "node-1".into(),
            investigation_id: "inv-1".into(),
            parent_id: None,
            layer_id: None,
            ordinal: 0,
            depth: 0,
            oz_type: OzType::Username,
            value: "mtrebosc".into(),
            display: "mtrebosc".into(),
            dedup_key: "username:mtrebosc".into(),
            payload: OzPayload::empty_for(OzType::Username),
            preview_signal: None,
            full_signal: None,
            sections: Vec::new(),
            gated: false,
            status: NodeStatus::Idle,
            provenance: Provenance::new("seed", "typed by the analyst"),
            already_in_tree: None,
            corroborations: Vec::new(),
            edited_value: None,
            created_at: Utc::now(),
        }
    }
}
