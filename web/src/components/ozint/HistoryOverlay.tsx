"use client";

import { motion } from "framer-motion";
import { X } from "lucide-react";

import { historyRow, type Investigation } from "@/lib/ozint/history";
import { ACCENT, FONT, SHADOW, SURFACE, TEXT, TONES } from "@/lib/ozint/tokens";

/**
 * PAST INVESTIGATIONS.
 *
 * The earlier design mock's archive chip is **gone, not reworded**: reopening resumes.
 * Every row says `REOPEN ↗` and lands in a cockpit where continue, edit, reject
 * and refresh all work, because the backend has no read-only state to put the
 * tree into.
 *
 * Four different things can be true of this list and each says its own words:
 * never asked, being read, read and empty, and unreadable. A failed read must
 * never look like "you have run no investigations".
 */
export function HistoryOverlay({
  items,
  loading,
  error,
  currentId,
  onReopen,
  onClose,
}: {
  items: Investigation[] | null;
  loading: boolean;
  error: string | null;
  currentId: string | null;
  onReopen: (id: string) => void;
  onClose: () => void;
}) {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 60,
        background: "rgba(6,10,14,.72)",
        display: "flex",
        justifyContent: "center",
        alignItems: "flex-start",
        paddingTop: 96,
      }}
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.18, ease: "easeOut" }}
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 580,
          maxHeight: "70vh",
          display: "flex",
          flexDirection: "column",
          background: SURFACE.panel,
          border: `1px solid ${SURFACE.border}`,
          borderRadius: 3,
          boxShadow: SHADOW.history,
          fontFamily: FONT.mono,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            padding: "12px 14px",
            borderBottom: `1px solid ${SURFACE.hairline}`,
          }}
        >
          <span style={{ color: ACCENT, fontSize: 10, letterSpacing: ".18em" }}>
            PAST INVESTIGATIONS
          </span>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close history"
            style={{
              marginLeft: "auto",
              background: "none",
              border: "none",
              color: TEXT.iconButton,
              cursor: "pointer",
            }}
          >
            <X size={14} />
          </button>
        </div>

        <div style={{ overflowY: "auto" }}>
          {error && (
            <div style={{ padding: 14, color: TONES.warn.fg, fontSize: 11, lineHeight: 1.4 }}>
              THE HISTORY COULD NOT BE READ
              <div style={{ color: TEXT.footnote, marginTop: 4 }}>{error}</div>
            </div>
          )}

          {!error && loading && items === null && (
            <div style={{ padding: 14, color: TEXT.empty, fontSize: 11, letterSpacing: ".1em" }}>
              READING THE HISTORY…
            </div>
          )}

          {!error && items !== null && items.length === 0 && (
            <div style={{ padding: 14, color: TEXT.empty, fontSize: 11, letterSpacing: ".1em" }}>
              NO INVESTIGATION HAS BEEN STORED YET
            </div>
          )}

          {!error &&
            items?.map((investigation) => {
              const row = historyRow(investigation);
              const isCurrent = investigation.id === currentId;
              return (
                <button
                  key={row.id}
                  type="button"
                  onClick={() => onReopen(row.id)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    width: "100%",
                    padding: "10px 14px",
                    background: isCurrent ? "rgba(79,211,224,.05)" : "none",
                    border: "none",
                    borderBottom: `1px solid ${SURFACE.hairline}`,
                    textAlign: "left",
                    cursor: "pointer",
                    fontFamily: FONT.mono,
                  }}
                >
                  <span
                    style={{
                      width: 78,
                      flexShrink: 0,
                      color: TEXT.footnote,
                      fontSize: 10,
                      lineHeight: 1.3,
                    }}
                  >
                    {row.when}
                  </span>
                  <span
                    style={{
                      width: 34,
                      flexShrink: 0,
                      color: TEXT.typeLabel,
                      fontSize: 10,
                      letterSpacing: ".08em",
                    }}
                    title={row.typeLabel}
                  >
                    {row.typeGlyph}
                  </span>
                  <span style={{ flex: 1, minWidth: 0 }}>
                    <span
                      style={{
                        display: "block",
                        color: TEXT.cardValue,
                        fontFamily: FONT.sans,
                        fontSize: 13.5,
                        fontWeight: 500,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {row.value}
                    </span>
                    <span style={{ display: "block", color: TEXT.monoCaption, fontSize: 9.5 }}>
                      {row.stats}
                    </span>
                    {/* A spawned investigation says where it came from: the link
                        is one-way and nothing else on screen would show it. */}
                    {row.spawnedFrom && (
                      <span style={{ display: "block", color: TEXT.footnote, fontSize: 9.5 }}>
                        spawned from · {row.spawnedFrom}
                      </span>
                    )}
                  </span>
                  <span style={{ color: ACCENT, fontSize: 10, letterSpacing: ".1em", flexShrink: 0 }}>
                    {isCurrent ? "OPEN" : "REOPEN ↗"}
                  </span>
                </button>
              );
            })}
        </div>

        <div
          style={{
            padding: "8px 14px",
            borderTop: `1px solid ${SURFACE.hairline}`,
            color: TEXT.footnote,
            fontSize: 9.5,
            lineHeight: 1.4,
          }}
        >
          Reopening resumes: continuing, correcting and refreshing all stay
          available. Node and layer counts are not shown because the list route
          does not carry them.
        </div>
      </motion.div>
    </div>
  );
}
