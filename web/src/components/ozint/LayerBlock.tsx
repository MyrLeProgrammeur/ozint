"use client";

import type { BlockModel } from "@/lib/ozint/view";
import { FONT, SURFACE, TEXT } from "@/lib/ozint/tokens";

/**
 * What sits where children would have been, when there are none.
 *
 * This is the exact spot where the earlier design mock lied: every childless layer drew
 * `0 NEW ENTITIES`, whether the tools found nothing, all broke, or were killed
 * mid-flight. Each of those now says its own words, and the two that a retry
 * could change offer one.
 */
export function LayerBlock({
  block,
  onRetry,
}: {
  block: BlockModel;
  onRetry: () => void;
}) {
  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 4,
        background: SURFACE.panel,
        border: `1px dashed ${block.tone.border}`,
        borderRadius: 6,
        fontFamily: FONT.mono,
        textAlign: "center",
        padding: 8,
      }}
    >
      <div style={{ color: block.tone.fg, fontSize: 12, letterSpacing: ".08em" }}>
        {block.label}
      </div>
      {block.sub && (
        <div style={{ color: TEXT.footnote, fontSize: 10 }}>{block.sub}</div>
      )}
      {block.retry && (
        <button
          type="button"
          onClick={onRetry}
          style={{
            marginTop: 2,
            padding: "2px 10px",
            background: "none",
            border: `1px solid ${block.tone.border}`,
            borderRadius: 3,
            color: block.tone.fg,
            fontFamily: FONT.mono,
            fontSize: 10,
            letterSpacing: ".08em",
            cursor: "pointer",
          }}
        >
          RETRY
        </button>
      )}
    </div>
  );
}
