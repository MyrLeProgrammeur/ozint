"use client";

import { describeOutcome } from "@/lib/ozint/outcomes";
import { BAND_METRICS, summaryHeight, type BandModel } from "@/lib/ozint/view";
import { FONT, SURFACE, TEXT, TONES } from "@/lib/ozint/tokens";

/**
 * The collapsed line that always states the plan's total,
 * and the per-tool list one click behind it.
 *
 * The list is what stops "five tools were skipped because we have no API key"
 * and "every tool ran and this is a dead end" from rendering identically. Every
 * report gets its own row with its own verb and its own reason — including the
 * ones that never ran, which is the whole point.
 */
export function LayerBand({
  band,
  expanded,
  onToggle,
}: {
  band: BandModel;
  expanded: boolean;
  onToggle: () => void;
}) {
  const held = band.maxPossible - band.firing;

  return (
    <div
      style={{
        height: "100%",
        background: SURFACE.panel,
        border: `1px solid ${SURFACE.hairline}`,
        borderRadius: 4,
        padding: BAND_METRICS.padding / 2,
        fontFamily: FONT.mono,
        overflow: "hidden",
      }}
    >
      <button
        type="button"
        onClick={onToggle}
        disabled={!band.expandable}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          width: "100%",
          height: BAND_METRICS.header,
          background: "none",
          border: "none",
          padding: "0 4px",
          color: TEXT.secondary,
          fontFamily: FONT.mono,
          fontSize: 11,
          letterSpacing: ".06em",
          cursor: band.expandable ? "pointer" : "default",
          textAlign: "left",
        }}
      >
        <span style={{ color: TEXT.footnote }}>{expanded ? "▾" : "▸"}</span>
        {/* An unreadable record is not an empty plan. `summary.line` would say
            `NO TOOLS PLANNED` for a layer whose stored reports simply no longer
            parse — the same sentence a layer that really planned nothing gets. */}
        {band.reportsUnreadable ? (
          <span style={{ color: TONES.warn.fg }}>
            TOOL RECORD UNREADABLE — WHAT RAN CANNOT BE RECOVERED
          </span>
        ) : (
          <span>{band.summary.line.toUpperCase()}</span>
        )}
        {band.running > 0 && (
          <span style={{ color: TONES.ok.fg }}>
            {band.running} IN FLIGHT
          </span>
        )}
        {/* Tools the plan could have fired if every key were armed. Silent when
            nothing was held back, so it never becomes decoration. */}
        {held > 0 && (
          <span style={{ color: TONES.warn.fg }}>
            {held} NOT ARMED
          </span>
        )}
        {band.gated > 0 && (
          <span style={{ color: TONES.gated.fg }}>{band.gated} GATED</span>
        )}
      </button>

      {band.note && (
        <div
          style={{
            height: summaryHeight(band.note.text),
            padding: "4px 6px",
            // `overflow: hidden` used to sit below this line and silently won,
            // so a note taller than its reserved height was cut off mid-sentence
            // with no scrollbar and no way to reach the rest. Measured in a real
            // run: 82px of text in a 68px box, losing the last line of the
            // explanation of *why* the layer degraded — the one thing this band
            // exists to keep on screen.
            overflowY: "auto",
            color: band.note.fallback ? TEXT.footnote : TEXT.body,
            fontSize: 11,
            lineHeight: 1.35,
          }}
          title={band.note.fallback ? "canned note — no model answered" : undefined}
        >
          {band.note.text}
        </div>
      )}

      {expanded && (
        <ul style={{ listStyle: "none", margin: 0, padding: "2px 4px" }}>
          {band.reports.map((report) => {
            const described = describeOutcome(report);
            return (
              <li
                key={`${report.toolId}-${report.method}`}
                style={{
                  display: "flex",
                  alignItems: "baseline",
                  gap: 8,
                  height: BAND_METRICS.toolRow,
                  fontSize: 11,
                  color: TEXT.secondary,
                  whiteSpace: "nowrap",
                }}
              >
                <span style={{ color: described.tone.fg, width: 12 }}>
                  {described.symbol}
                </span>
                <span style={{ color: TEXT.body, minWidth: 132 }}>
                  {report.toolId}
                </span>
                <span style={{ color: described.tone.fg }}>{described.headline}</span>
                <span style={{ color: TEXT.footnote, overflow: "hidden" }}>
                  {described.detail}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
