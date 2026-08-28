"use client";

import type { OzTypeName, Tone, ToneName } from "./tokens";
import { TONES } from "./tokens";

/**
 * The POTENTIAL RELATIONS section of the subject-file rail, and the "search
 * this person" action that spawns a brand-new investigation from a relation
 * card.
 *
 * Mirrors `crates/ozint/src/relations.rs`, camelCase over the wire.
 * Relations are **derived, never stored**: the server re-derives them on every
 * `GET /api/ozint/investigations/{id}` read, folded into that same response
 * (`InvestigationDetail.relations`) rather than a route of its own — so a
 * rejected node's relation disappears on the very next read, with nothing
 * client-side to invalidate.
 */

export type RelationKind =
  | "shared-surname"
  | "co-listed-address"
  | "employer-overlap"
  | "mentioned-in-bio"
  | "co-signed-record"
  | "face-match";

export type RelationTier = "gated" | "high" | "medium" | "low";

export interface RelationEvidence {
  nodeId: string;
  toolId: string;
  detail: string;
  gated?: boolean;
}

export interface Relation {
  id: string;
  subject: string;
  subjectType: OzTypeName;
  kind: RelationKind;
  tier: RelationTier;
  rationale: string;
  evidence: RelationEvidence[];
  gated?: boolean;
}

/**
 * One inference *rule* that had no input to run on this build — distinct from
 * a rule that ran and found nothing. **Not** the analyst-facing "this person
 * has not been investigated" wording; see the module doc in `relations.rs`.
 * Three of six rules always land here in this build (co-listed address,
 * co-signed record, face match — none has a data source yet).
 */
export interface RuleWithoutInput {
  kind: RelationKind;
  reason: string;
}

export interface RelationReport {
  relations: Relation[];
  rulesWithoutInput: RuleWithoutInput[];
}

const KIND_LABEL: Record<RelationKind, string> = {
  "shared-surname": "shared surname",
  "co-listed-address": "co-listed address",
  "employer-overlap": "employer overlap",
  "mentioned-in-bio": "mentioned in a profile",
  "co-signed-record": "co-signed record",
  "face-match": "face match",
};

export function relationKindLabel(kind: RelationKind): string {
  return KIND_LABEL[kind];
}

/**
 * Confidence chip, tone-coloured per the original design's `MEDIUM` / `LOW` /
 * `GATED` samples — `HIGH` post-dates those examples but the engine
 * emits it, so it needs a reading here too. Confidence tones are reused from
 * the severity palette (decision-adjacent, not itself a decision): high
 * confidence reads as the calm `ok` cyan, low as `mute` grey, and `gated`
 * keeps its own amber regardless of tier, since a gated route is a provenance
 * fact that overrides the rest (see `RelationTier` in `relations.rs`).
 */
export function relationTierTone(tier: RelationTier): Tone {
  const name: ToneName = tier === "gated" ? "gated" : tier === "high" ? "ok" : tier === "medium" ? "warn" : "mute";
  return TONES[name];
}

export function relationTierLabel(tier: RelationTier): string {
  return tier.toUpperCase();
}
