/**
 * The subject file — the rail down the left of the cockpit, and the one place
 * an investigation says what it believes about a person.
 *
 * Two rules are load-bearing here.
 *
 * **The rail exists only for person-shaped roots.** The engine says
 * so itself: `subjectFile` arrives as `{"kind":"notApplicable","rootType":…}`
 * for a CVE, hash, IP, domain, coordinate or directory root, and the rail is
 * then absent entirely rather than shown empty. A `COMPLETENESS 0 / 13` over
 * EMPLOYER and CITY is not a fact about `CVE-2024-38063`.
 *
 * **One `FULL NAME`, never split into family and given.** The
 * server sends twelve fields and a denominator of thirteen (twelve + the photo
 * slot). Any copy still saying fourteen is stale.
 *
 * **The numbers are the server's.** `filled` and `total` are rendered as sent,
 * never recomputed from the rows on screen: a completeness ratio the client
 * derived would drift from the one the engine persisted the moment the two
 * disagreed about what counts as filled, and the analyst would have no way to
 * tell which they were reading.
 *
 * The one thing this module refuses to smooth over: a field whose item carries
 * more than one value is an **unresolved conflict** — two tools said different
 * things and nothing has adjudicated. It renders as both values, marked. Picking
 * one would be the subject file asserting something no tool said.
 */

import type { OzType } from "@/lib/ozint/stream-parser";

// ── The wire shapes (`subject_file.rs`, camelCase) ──────────────────────────

export interface FieldSource {
  nodeId: string;
  toolId: string;
  /** Omitted on the wire when false — absence means false, not unknown. */
  gated?: boolean;
  corrected?: boolean;
}

export interface FieldValue {
  value: string;
  sources: FieldSource[];
}

export interface FieldItem {
  values: FieldValue[];
}

export interface FieldEntry {
  /** kebab-case: `full-name`, `postal-address`, `other-presence`, … */
  field: string;
  /** The design-export label, verbatim: `FULL NAME`. */
  label: string;
  isList: boolean;
  items: FieldItem[];
}

export type SubjectFileView =
  | {
      kind: "file";
      fields: FieldEntry[];
      photo?: FieldValue;
      filled: number;
      total: number;
    }
  | { kind: "notApplicable"; rootType: OzType };

/**
 * The twelve fields, in the order the engine sends them. Kept here only so a
 * test can pin the count and catch a silent drift back to a split name — the
 * rail renders whatever the server sends, in the order it sent it.
 */
export const SUBJECT_FIELDS = [
  "full-name",
  "age",
  "city",
  "postal-address",
  "employer",
  "role",
  "emails",
  "phones",
  "handles",
  "profiles",
  "other-presence",
  "media",
] as const;

/** Twelve fields plus the photo slot: thirteen, not fourteen. */
export const COMPLETENESS_DENOMINATOR = SUBJECT_FIELDS.length + 1;

// ── The view model ──────────────────────────────────────────────────────────

export interface RailValue {
  value: string;
  sources: FieldSource[];
  /** Any source of this value carries the analyst's correction mark. */
  corrected: boolean;
  gated: boolean;
}

export interface RailItem {
  values: RailValue[];
  /** More than one value in one item: two tools disagreed, nothing adjudicated. */
  conflicted: boolean;
}

export interface RailField {
  field: string;
  label: string;
  isList: boolean;
  items: RailItem[];
  /** No finding has landed here yet. The row says so rather than staying blank. */
  empty: boolean;
}

export interface RailModel {
  fields: RailField[];
  photo?: FieldValue;
  filled: number;
  total: number;
  /** 0–100, from the server's own ratio. */
  percent: number;
  /** The subject's assembled identity line, when a name has landed. */
  identity: string | null;
  /** `role · city`, the quieter second line. Empty string when neither exists. */
  subtitle: string;
}

function toRailValue(value: FieldValue): RailValue {
  return {
    value: value.value,
    sources: value.sources,
    corrected: value.sources.some((s) => s.corrected === true),
    gated: value.sources.some((s) => s.gated === true),
  };
}

/** The first single value of a field, when the field holds exactly one. */
function soleValue(field: RailField | undefined): string | null {
  if (!field || field.items.length === 0) return null;
  const first = field.items[0];
  if (first.values.length !== 1) return null;
  return first.values[0].value;
}

/**
 * Build the rail. Returns `null` for a file that does not apply — the caller
 * renders no rail at all in that case.
 */
export function railModel(file: SubjectFileView | null | undefined): RailModel | null {
  if (!file || file.kind !== "file") return null;

  const fields: RailField[] = file.fields.map((entry) => ({
    field: entry.field,
    label: entry.label,
    isList: entry.isList,
    items: entry.items.map((item) => ({
      values: item.values.map(toRailValue),
      conflicted: item.values.length > 1,
    })),
    empty: entry.items.length === 0,
  }));

  const byName = new Map(fields.map((f) => [f.field, f]));
  const name = soleValue(byName.get("full-name"));
  const role = soleValue(byName.get("role"));
  const city = soleValue(byName.get("city"));

  return {
    fields,
    photo: file.photo,
    filled: file.filled,
    total: file.total,
    percent:
      file.total > 0 ? Math.round((file.filled / file.total) * 100) : 0,
    identity: name,
    subtitle: [role, city].filter(Boolean).join(" · "),
  };
}

/**
 * The other half of the "no rail for a non-person root" rule, for the caller
 * that has a `notApplicable` file: the words to show instead of a rail, naming
 * the root type so the absence reads as a deliberate statement rather than a
 * missing panel.
 */
export function notApplicableReason(
  file: SubjectFileView | null | undefined,
): string | null {
  if (!file || file.kind !== "notApplicable") return null;
  return `no subject file — this investigation is rooted on a ${file.rootType}, not a person`;
}
