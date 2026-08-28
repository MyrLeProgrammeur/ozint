"use client";

import type { CardModel } from "@/lib/ozint/view";
import { FONT, SELECTION, SURFACE, TEXT, TONES } from "@/lib/ozint/tokens";

/**
 * One entity in the tree.
 *
 * Two things here are deliberate, not decoration. A corroborated value shows its
 * routes by name — two independent paths to the same entity is the
 * most valuable thing an investigation produces, not a duplicate to suppress.
 * And a degraded layer is annotated on the card in amber: results
 * were found but tools broke, and an analyst must never read that as a security
 * alert.
 */
export function NodeCard({
  card,
  focused,
  onFocus,
  onContinue,
}: {
  card: CardModel;
  focused: boolean;
  onFocus: () => void;
  onContinue: () => void;
}) {
  const { node, mark } = card;

  return (
    <div
      onClick={onFocus}
      onDoubleClick={onContinue}
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        gap: 6,
        padding: 12,
        background: card.firing
          ? SURFACE.cardFiring
          : focused
            ? SURFACE.cardFocus
            : SURFACE.card,
        border: `1px solid ${
          focused
            ? SURFACE.borderFocus
            : card.inert
              ? SURFACE.borderInert
              : SURFACE.borderCard
        }`,
        borderRadius: 6,
        boxShadow: focused ? `0 0 0 3px ${SELECTION}` : "none",
        // Inert: never continued while a sibling was. Dimmed, never removed —
        // nothing in this tree disappears.
        opacity: card.inert ? 0.62 : 1,
        fontFamily: FONT.mono,
        cursor: "pointer",
        overflow: "hidden",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span
          style={{
            padding: "2px 6px",
            border: `1px solid ${SURFACE.border}`,
            borderRadius: 3,
            color: TEXT.typeLabel,
            fontSize: 10,
            letterSpacing: ".1em",
          }}
        >
          {mark.glyph}
        </span>
        <span style={{ color: TEXT.typeLabel, fontSize: 10, letterSpacing: ".1em" }}>
          {mark.label}
        </span>
        {card.gated && (
          <span style={{ color: TONES.gated.fg, fontSize: 10 }}>GATED</span>
        )}
        {card.firing && (
          <span style={{ color: TONES.ok.fg, fontSize: 10 }}>SEARCHING</span>
        )}
        {/* The analyst's verdict, on the card and not only in the panel: a
            finding marked wrong that looked untouched in the tree would be a
            correction the investigation does not appear to have made. */}
        {card.rejected && (
          <span style={{ color: TONES.risk.fg, fontSize: 10 }}>WRONG</span>
        )}
        {card.corrected && (
          <span style={{ color: TONES.ok.fg, fontSize: 10 }}>✎ CORRECTED</span>
        )}
      </div>

      <div
        style={{
          color: card.inert ? TEXT.inertValue : TEXT.cardValue,
          fontSize: 15,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          // Nothing is deleted: a rejected finding stays legible, struck
          // through, and keeps its place in the tree.
          textDecoration: card.rejected ? "line-through" : "none",
          opacity: card.rejected ? 0.42 : 1,
        }}
        title={card.value}
      >
        {card.value}
      </div>

      {card.chip && (
        <div
          style={{
            alignSelf: "flex-start",
            padding: "2px 8px",
            background: card.chip.tone.bg,
            border: `1px solid ${card.chip.tone.border}`,
            borderRadius: 3,
            color: card.chip.tone.fg,
            fontSize: 11,
          }}
        >
          {card.chip.text}
          {card.chip.meta && (
            <span style={{ color: TEXT.footnote, marginLeft: 6 }}>
              {card.chip.meta}
            </span>
          )}
        </div>
      )}

      {card.degraded && (
        <div style={{ color: card.degraded.tone.fg, fontSize: 10 }}>
          {card.degraded.label}
        </div>
      )}

      {card.corroboration && (
        <div style={{ fontSize: 10, color: TONES.ok.fg, lineHeight: 1.4 }}>
          <div>◈ corroborated · {card.corroboration.paths} paths</div>
          {card.corroboration.via.map((toolId) => (
            <div key={toolId} style={{ color: TEXT.footnote }}>
              └ via {toolId}
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: "auto", color: TEXT.cardMeta, fontSize: 10 }}>
        via {node.provenance.sourceToolId}
      </div>
    </div>
  );
}
