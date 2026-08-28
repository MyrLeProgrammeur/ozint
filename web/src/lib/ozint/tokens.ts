/**
 * The OZINT cockpit's visual token system. Colours, type and spacing are
 * locked; this file is the single place they live so no component hard-codes
 * a hex.
 *
 * Two deliberate additions beyond the original design palette:
 *
 *   - `critical` — the wire's `SignalTone` has six values and that earlier
 *     palette has five. `Critical` needs a colour it does not yet have; it
 *     gets one here, hotter and more saturated than `risk` so the two read as
 *     a genuine escalation rather than a repaint.
 *   - `gated` — an ethically-gated finding is amber, sharing `warn`'s hue
 *     because it is a caution about provenance, not a severity.
 *
 * Copy is English throughout, per this repo's language convention; any
 * French sample strings seen during early design were ideation notes, not a
 * copy spec.
 */

// ── Surfaces ────────────────────────────────────────────────────────────────

export const SURFACE = {
  canvas: "#0C1118",
  chrome: "#0E141C",
  panel: "#101821",
  card: "#141C25",
  cardFiring: "#141F29",
  cardFocus: "#182430",
  cardInner: "#121A23",
  input: "#0D141B",
  track: "#1A242E",
  hairline: "#1D2833",
  border: "#22303D",
  borderCard: "#2A3A4A",
  borderSoft: "#253340",
  borderInert: "#1F2C38",
  borderFocus: "#3E5B72",
  connector: "#263849",
  rowRule: "rgba(150,190,220,.05)",
} as const;

/** The blueprint grid, 34px repeat. Slightly brighter on the canvas than idle. */
export const GRID = {
  size: 34,
  idle: "rgba(120,160,200,.045)",
  canvas: "rgba(120,160,200,.05)",
} as const;

// ── Text ────────────────────────────────────────────────────────────────────

export const TEXT = {
  panelTitle: "#E7EFF7",
  cardValue: "#E4EDF5",
  data: "#DCE6F0",
  body: "#D5DFE9",
  prose: "#A3B6C8",
  secondary: "#9FB2C4",
  iconButton: "#8397AB",
  ghostLabel: "#7C90A4",
  typeLabel: "#647A8E",
  panelKey: "#61768A",
  monoCaption: "#5F7488",
  cardMeta: "#5D7285",
  fileLabel: "#556A7D",
  footnote: "#4E6376",
  emptyStrong: "#3F5162",
  empty: "#3B4C5C",
  inertValue: "#93A6B8",
} as const;

// ── Signal tones ────────────────────────────────────────────────────────────

export interface Tone {
  fg: string;
  bg: string;
  border: string;
  /** The uniform severity word, for the optional `tier` signal mode. */
  tier: string;
}

/**
 * Presentational tones. `mute` and `off` are presentation-only and never appear
 * on the wire; the wire's `neutral` maps onto `mute`.
 */
export type ToneName = "ok" | "warn" | "risk" | "critical" | "gated" | "mute" | "off";

export const TONES: Record<ToneName, Tone> = {
  ok: {
    fg: "#4FD3E0",
    bg: "rgba(79,211,224,.09)",
    border: "rgba(79,211,224,.28)",
    tier: "LOW",
  },
  warn: {
    fg: "#E8B15C",
    bg: "rgba(232,177,92,.09)",
    border: "rgba(232,177,92,.30)",
    tier: "ELEVATED",
  },
  risk: {
    fg: "#EA6D5E",
    bg: "rgba(234,109,94,.10)",
    border: "rgba(234,109,94,.32)",
    tier: "CRITICAL",
  },
  critical: {
    fg: "#FF5340",
    bg: "rgba(255,83,64,.14)",
    border: "rgba(255,83,64,.46)",
    tier: "CRITICAL",
  },
  gated: {
    fg: "#E8B15C",
    bg: "rgba(232,177,92,.09)",
    border: "rgba(232,177,92,.30)",
    tier: "GATED",
  },
  mute: {
    fg: "#7C90A4",
    bg: "rgba(124,144,164,.09)",
    border: "rgba(124,144,164,.24)",
    tier: "UNSCORED",
  },
  off: {
    fg: "#5A6C7C",
    bg: "rgba(90,108,124,.07)",
    border: "rgba(90,108,124,.20)",
    tier: "—",
  },
};

/** `SignalTone` as it arrives on the wire (`types.rs`, kebab-case). */
export type WireTone = "neutral" | "ok" | "warn" | "risk" | "critical" | "gated";

/** The mechanical mapping from the settled-points table: `Neutral` ↔ `mute`. */
export function toneOf(wire: WireTone | undefined): Tone {
  if (!wire || wire === "neutral") return TONES.mute;
  return TONES[wire];
}

export const ACCENT = "#4FD3E0";
export const ACCENT_HOVER = "#8FE9F2";
export const SELECTION = "rgba(79,211,224,.22)";

/**
 * Amber, and deliberately not red. A `DEGRADED` or `FAILED` layer is a technical
 * breakage, and an analyst must never read a broken layer as a dangerous
 * finding.
 */
export const LAYER_TROUBLE = TONES.warn;

// ── Typography ──────────────────────────────────────────────────────────────

export const FONT = {
  sans: "'IBM Plex Sans', system-ui, sans-serif",
  mono: "'IBM Plex Mono', ui-monospace, monospace",
} as const;

// ── Entity types ────────────────────────────────────────────────────────────

/** `OzType` as it arrives on the wire. */
export type OzTypeName =
  | "username"
  | "email"
  | "phone"
  | "ip"
  | "domain"
  | "hash"
  | "image"
  | "video"
  | "coordinate"
  | "cve"
  | "directory"
  | "name";

export interface TypeMark {
  /** Three-letter badge glyph. One distinct mark per entity type. */
  glyph: string;
  /** The spelled-out type label under the badge. */
  label: string;
}

export const TYPE_MARKS: Record<OzTypeName, TypeMark> = {
  username: { glyph: "USR", label: "USERNAME" },
  email: { glyph: "EML", label: "EMAIL" },
  phone: { glyph: "TEL", label: "PHONE" },
  ip: { glyph: "NET", label: "IP ADDRESS" },
  domain: { glyph: "DOM", label: "DOMAIN" },
  hash: { glyph: "SHA", label: "FILE HASH" },
  image: { glyph: "IMG", label: "IMAGE" },
  video: { glyph: "VID", label: "VIDEO" },
  coordinate: { glyph: "GEO", label: "COORDINATE" },
  cve: { glyph: "CVE", label: "VULNERABILITY" },
  directory: { glyph: "DIR", label: "DIRECTORY-ONLY" },
  // `name` post-dates the original glyph vocabulary, which stops at eleven.
  name: { glyph: "NAM", label: "NAME" },
};

/**
 * The roots that get a subject file. The rail and its completeness
 * meter appear only for person-shaped roots — a completeness ratio over EMPLOYER
 * and CITY is meaningless when the root is a CVE. Mirrors
 * `subject_file::applies_to` in the engine.
 */
export const PERSON_ROOT_TYPES: readonly OzTypeName[] = [
  "username",
  "email",
  "phone",
  "name",
];

export function hasSubjectFile(rootType: OzTypeName): boolean {
  return PERSON_ROOT_TYPES.includes(rootType);
}

// ── Chrome geometry ─────────────────────────────────────────────────────────

export const CHROME = {
  topBarHeight: 46,
  statusBarHeight: 34,
  railWidth: 348,
  railCollapsedWidth: 34,
  panelWidth: 492,
  searchBarWidth: 680,
  searchInputHeight: 58,
} as const;

export const SHADOW = {
  searchBar: "0 24px 60px rgba(0,0,0,.45)",
  panel: "-24px 0 60px rgba(0,0,0,.5)",
  history: "0 30px 80px rgba(0,0,0,.6)",
} as const;
