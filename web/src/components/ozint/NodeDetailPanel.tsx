"use client";

import { motion } from "framer-motion";
import { X } from "lucide-react";
import { useCallback, useRef, useState } from "react";

import type { DetailModel, DetailRow, DetailSection } from "@/lib/ozint/detail";
import { formatRetrieved } from "@/lib/ozint/detail";
import { ozintStore, type RefreshResult } from "@/lib/ozint/store";
import {
  ACCENT,
  CHROME,
  FONT,
  SHADOW,
  SURFACE,
  TEXT,
  TONES,
  type Tone,
} from "@/lib/ozint/tokens";

/**
 * The node detail panel — a right overlay, never a popup and never inline.
 *
 * **Provenance is the first section, always, and it is five fixed rows.** The
 * body is one continuous scroll with a horizontal row of jump chips that set
 * `scrollTop`; deliberately not tabs, because tabs would let an analyst read a
 * finding without its provenance ever having been on screen.
 *
 * A rejected node keeps its panel. The value is struck through and the record
 * status says, in words, that it is excluded from the subject file — the finding
 * is not deleted, because an investigation has to be able to show what it
 * considered and threw out.
 */
export function NodeDetailPanel({
  model,
  onClose,
  onContinue,
}: {
  model: DetailModel;
  onClose: () => void;
  onContinue: () => void;
}) {
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const sectionRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const [refreshing, setRefreshing] = useState(false);
  const [refreshed, setRefreshed] = useState<RefreshResult | null>(null);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  /** The correction being typed. `null` means the panel is not in edit mode. */
  const [draft, setDraft] = useState<string | null>(null);
  const [verdictBusy, setVerdictBusy] = useState(false);
  const [verdictError, setVerdictError] = useState<string | null>(null);
  /** What the last verdict actually did, in the analyst's words. */
  const [verdictNote, setVerdictNote] = useState<string | null>(null);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    setRefreshError(null);
    const { result, error } = await ozintStore.refresh(model.node.id);
    // A refusal is never rendered as "nothing changed". A 422 means this node's
    // tools have left the registry and it *cannot* be re-checked — the opposite
    // of a clean unchanged answer.
    if (error) setRefreshError(error);
    setRefreshed(result ?? null);
    setRefreshing(false);
  }, [model.node.id]);

  /**
   * SAVE. The one field the route takes is `value`; there is no chip input,
   * because `edited_chip` has no producer — an analyst corrects a value, and no
   * tool re-runs to produce a new verdict for it.
   */
  const onSave = useCallback(async () => {
    const value = (draft ?? "").trim();
    if (value.length === 0) {
      setVerdictError("a correction cannot be empty");
      return;
    }
    if (value === model.value) {
      // The route answers 200 here and records nothing, deliberately: a no-op
      // correction in the provenance record would be a fabricated audit entry.
      // Said out loud rather than reported as a save that happened.
      setVerdictError("that is already the value — nothing was recorded");
      return;
    }
    setVerdictBusy(true);
    setVerdictError(null);
    setVerdictNote(null);
    const { node, error } = await ozintStore.editNode(model.node.id, value);
    if (error) setVerdictError(error);
    else {
      setDraft(null);
      setVerdictNote(
        node && node.type !== model.node.type
          ? `corrected · the classifier re-read the seed as ${node.type.toUpperCase()}`
          : "corrected · the tool's original value is kept in the record status",
      );
    }
    setVerdictBusy(false);
  }, [draft, model.node.id, model.node.type, model.value]);

  const onVerdict = useCallback(
    async (action: "reject" | "restore") => {
      setVerdictBusy(true);
      setVerdictError(null);
      setVerdictNote(null);
      const { error } =
        action === "reject"
          ? await ozintStore.rejectNode(model.node.id)
          : await ozintStore.restoreNode(model.node.id);
      if (error) setVerdictError(error);
      else {
        setDraft(null);
        setVerdictNote(
          action === "reject"
            ? "marked wrong · still in the tree, out of the subject file and out of anything inferred from it"
            : "restored · a correction made before the rejection comes back with it",
        );
      }
      setVerdictBusy(false);
    },
    [model.node.id],
  );

  const jumpTo = useCallback((sectionId: string) => {
    const body = bodyRef.current;
    const section = sectionRefs.current[sectionId];
    if (!body || !section) return;
    body.scrollTo({ top: section.offsetTop - 8, behavior: "smooth" });
  }, []);

  const rejected = Boolean(model.rejected);

  return (
    <motion.aside
      initial={{ opacity: 0, x: 24 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 24 }}
      transition={{ duration: 0.18, ease: "easeOut" }}
      style={{
        position: "absolute",
        top: 0,
        right: 0,
        bottom: 0,
        width: CHROME.panelWidth,
        maxWidth: "92vw",
        display: "flex",
        flexDirection: "column",
        background: SURFACE.panel,
        borderLeft: `1px solid ${SURFACE.border}`,
        boxShadow: SHADOW.panel,
        fontFamily: FONT.mono,
        zIndex: 10,
      }}
    >
      {/* ── header ──────────────────────────────────────────────────────── */}
      <div style={{ padding: "14px 16px 12px", borderBottom: `1px solid ${SURFACE.hairline}` }}>
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
            {model.mark.glyph}
          </span>
          <span style={{ color: TEXT.typeLabel, fontSize: 10, letterSpacing: ".1em" }}>
            {model.mark.label} · {model.layerLabel}
          </span>
          {model.gated && (
            <span style={{ color: TONES.gated.fg, fontSize: 10, letterSpacing: ".1em" }}>
              GATED
            </span>
          )}
          <button
            type="button"
            onClick={onClose}
            aria-label="Close detail panel"
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

        <div
          style={{
            marginTop: 10,
            color: TEXT.panelTitle,
            fontFamily: FONT.sans,
            fontSize: 19,
            fontWeight: 600,
            wordBreak: "break-all",
            // Marked wrong by the analyst: struck through, dimmed, still here.
            textDecoration: rejected ? "line-through" : "none",
            opacity: rejected ? 0.42 : 1,
          }}
        >
          {model.value}
        </div>

        <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          {model.chip && (
            <span
              style={{
                padding: "2px 8px",
                background: model.chip.tone.bg,
                border: `1px solid ${model.chip.tone.border}`,
                borderRadius: 3,
                color: model.chip.tone.fg,
                fontSize: 11,
              }}
            >
              {model.chip.text}
              {model.chip.meta && (
                <span style={{ color: TEXT.footnote, marginLeft: 6 }}>{model.chip.meta}</span>
              )}
            </span>
          )}
          <span style={{ color: TEXT.cardMeta, fontSize: 10 }}>via {model.toolChain}</span>
        </div>

        {model.corroboration && (
          <div style={{ marginTop: 8, fontSize: 10, color: TONES.ok.fg, lineHeight: 1.5 }}>
            <div>◈ corroborated · {model.corroboration.paths} paths</div>
            {model.corroboration.via.map((toolId, i) => (
              <div key={`${toolId}-${i}`} style={{ color: TEXT.footnote }}>
                └ via {toolId}
              </div>
            ))}
          </div>
        )}

        <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button
            type="button"
            onClick={onContinue}
            disabled={model.firing}
            style={{
              padding: "5px 12px",
              background: model.firing ? "none" : TONES.ok.bg,
              border: `1px solid ${TONES.ok.border}`,
              borderRadius: 3,
              color: model.firing ? TEXT.footnote : ACCENT,
              fontFamily: FONT.mono,
              fontSize: 10,
              letterSpacing: ".1em",
              cursor: model.firing ? "default" : "pointer",
            }}
          >
            {model.firing ? "SEARCHING…" : "CONTINUE SEARCH ON THIS"}
          </button>

          <button
            type="button"
            onClick={() => void onRefresh()}
            disabled={refreshing}
            style={{
              padding: "5px 12px",
              background: "none",
              border: `1px solid ${SURFACE.border}`,
              borderRadius: 3,
              color: refreshing ? TEXT.footnote : TEXT.secondary,
              fontFamily: FONT.mono,
              fontSize: 10,
              letterSpacing: ".1em",
              cursor: refreshing ? "default" : "pointer",
            }}
          >
            {refreshing ? "RE-CHECKING…" : "REFRESH"}
          </button>

          {/* Only the two payloads that carry a real link get a button. */}
          {model.link && (
            <a
              href={model.link.href}
              target="_blank"
              rel="noreferrer noopener"
              style={{
                padding: "5px 12px",
                border: `1px solid ${SURFACE.border}`,
                borderRadius: 3,
                color: TEXT.secondary,
                fontSize: 10,
                letterSpacing: ".1em",
                textDecoration: "none",
              }}
            >
              {model.link.label}
            </a>
          )}

          {/* The analyst's three verdicts. A rejected node is offered RESTORE
              and nothing else: the route refuses a correction written over a
              rejection, because one enum slot holds both and the rejection
              would be erased without a trace. */}
          {rejected ? (
            <VerdictButton
              label="RESTORE"
              tone={TONES.ok}
              busy={verdictBusy}
              onClick={() => void onVerdict("restore")}
            />
          ) : (
            <>
              <VerdictButton
                label={draft === null ? "EDIT" : "CANCEL"}
                busy={verdictBusy}
                onClick={() => {
                  setVerdictError(null);
                  setVerdictNote(null);
                  setDraft(draft === null ? model.value : null);
                }}
              />
              <VerdictButton
                label="MARK WRONG"
                tone={TONES.risk}
                busy={verdictBusy}
                onClick={() => void onVerdict("reject")}
              />
            </>
          )}
        </div>

        {draft !== null && (
          <div style={{ marginTop: 10 }}>
            <input
              value={draft}
              autoFocus
              spellCheck={false}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void onSave();
                if (e.key === "Escape") setDraft(null);
              }}
              aria-label="Corrected value"
              style={{
                width: "100%",
                height: 30,
                padding: "0 10px",
                background: SURFACE.input,
                border: `1px solid ${SURFACE.border}`,
                borderRadius: 3,
                color: TEXT.data,
                fontFamily: FONT.mono,
                fontSize: 12,
                outline: "none",
              }}
            />
            <div style={{ marginTop: 6, display: "flex", gap: 8, alignItems: "center" }}>
              <VerdictButton
                label={verdictBusy ? "SAVING…" : "SAVE"}
                tone={TONES.ok}
                busy={verdictBusy}
                onClick={() => void onSave()}
              />
              <span style={{ color: TEXT.footnote, fontSize: 9.5, lineHeight: 1.4 }}>
                {/* Two honest limits, both from the route rather than from taste. */}
                {model.node.parentId
                  ? "the value only — nothing re-runs, so the finding's own verdict is left as the tool returned it"
                  : "this is the root: correcting it sends the seed back through the classifier, and a change of type is refused once the root carries findings"}
              </span>
            </div>
          </div>
        )}

        {verdictError && (
          <div style={{ marginTop: 8, color: TONES.warn.fg, fontSize: 10, lineHeight: 1.45 }}>
            {verdictError}
          </div>
        )}
        {verdictNote && !verdictError && (
          <div style={{ marginTop: 8, color: TEXT.footnote, fontSize: 10, lineHeight: 1.45 }}>
            {verdictNote}
          </div>
        )}
      </div>

        {/* The refresh verdict. Three outcomes, none allowed to look like
            another: it could not be re-checked, it was re-checked and moved, it
            was re-checked and did not. */}
        {refreshError && (
          <div style={{ marginTop: 8, color: TONES.warn.fg, fontSize: 10 }}>
            could not re-check — {refreshError}
          </div>
        )}
        {refreshed && !refreshError && (
          <div style={{ marginTop: 8, fontSize: 10, lineHeight: 1.5 }}>
            <span style={{ color: refreshed.changed ? TONES.ok.fg : TEXT.footnote }}>
              {refreshed.aborted
                ? "re-check aborted before it finished"
                : refreshed.changed
                  ? `changed · ${refreshed.changedFields.join(", ")}`
                  : "unchanged since it was first retrieved"}
            </span>
            <span style={{ color: TEXT.footnote }}>
              {" "}
              · re-checked {formatRetrieved(new Date(refreshed.checkedAt).toISOString())}
            </span>
            {refreshed.childrenIgnored > 0 && (
              <div style={{ color: TEXT.footnote }}>
                {/* A refresh never touches children; saying how many it declined
                    is what stops that rule looking like a source gone quiet. */}
                {refreshed.childrenIgnored} child{" "}
                {refreshed.childrenIgnored === 1 ? "seed" : "seeds"} offered and
                not acted on — a refresh re-checks this node only
              </div>
            )}
          </div>
        )}

      {/* ── jump chips: scroll positions, never tabs ────────────────────── */}
      <div
        style={{
          display: "flex",
          gap: 6,
          padding: "8px 16px",
          overflowX: "auto",
          borderBottom: `1px solid ${SURFACE.hairline}`,
          flexShrink: 0,
        }}
      >
        {model.jumps.map((jump) => (
          <button
            key={jump.sectionId}
            type="button"
            onClick={() => jumpTo(jump.sectionId)}
            style={{
              flexShrink: 0,
              padding: "3px 8px",
              background: "none",
              border: `1px solid ${SURFACE.border}`,
              borderRadius: 3,
              color: TEXT.ghostLabel,
              fontFamily: FONT.mono,
              fontSize: 9,
              letterSpacing: ".14em",
              cursor: "pointer",
            }}
          >
            {jump.label}
          </button>
        ))}
      </div>

      {/* ── body: one continuous scroll ─────────────────────────────────── */}
      <div ref={bodyRef} style={{ flex: 1, overflowY: "auto", padding: "0 16px 24px" }}>
        {model.sections.map((section) => (
          <div
            key={section.id}
            ref={(el) => {
              sectionRefs.current[section.id] = el;
            }}
            style={{ paddingTop: 16 }}
          >
            <div
              style={{
                paddingBottom: 8,
                borderBottom: `1px solid ${SURFACE.hairline}`,
                color: ACCENT,
                fontSize: 9,
                letterSpacing: ".18em",
              }}
            >
              {section.label}
            </div>
            <SectionBody section={section} />
          </div>
        ))}

        {model.notSearched && (
          <div
            style={{
              marginTop: 20,
              padding: 12,
              border: `1px dashed ${TONES.warn.border}`,
              borderRadius: 3,
              color: TEXT.prose,
              fontFamily: FONT.sans,
              fontSize: 11.5,
              lineHeight: 1.5,
            }}
          >
            <div
              style={{
                color: TONES.warn.fg,
                fontFamily: FONT.mono,
                fontSize: 9,
                letterSpacing: ".18em",
                marginBottom: 6,
              }}
            >
              NOT SEARCHED
            </div>
            This person is an inference drawn from the findings above, not a
            finding of its own. Searching them means starting a separate root
            investigation.
          </div>
        )}
      </div>
    </motion.aside>
  );
}

function SectionBody({ section }: { section: DetailSection }) {
  if (section.rows.length === 0) {
    return (
      <div
        style={{
          padding: "10px 0",
          color: TEXT.empty,
          fontSize: 10,
          letterSpacing: ".1em",
        }}
      >
        NOTHING RECORDED HERE
      </div>
    );
  }

  if (section.kind === "tags") {
    return (
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, padding: "10px 0" }}>
        {section.rows.map((row, i) => {
          const tone = row.tone ?? TONES.mute;
          return (
            <span
              key={`${row.label}-${i}`}
              style={{
                padding: "4px 7px",
                background: tone.bg,
                border: `1px solid ${tone.border}`,
                borderRadius: 3,
                color: tone.fg,
                fontSize: 10,
              }}
            >
              {row.value || row.label}
            </span>
          );
        })}
      </div>
    );
  }

  if (section.kind === "timeline") {
    return (
      <div style={{ padding: "6px 0" }}>
        {section.rows.map((row, i) => {
          const tone = row.tone ?? TONES.mute;
          return (
            <div key={`${row.label}-${i}`} style={{ display: "flex", gap: 10, padding: "6px 0" }}>
              <span style={{ width: 76, flexShrink: 0, color: TEXT.footnote, fontSize: 10 }}>
                {row.at ? row.at.slice(0, 10) : "—"}
              </span>
              <span
                style={{
                  width: 7,
                  height: 7,
                  marginTop: 4,
                  flexShrink: 0,
                  borderRadius: "50%",
                  border: `1px solid ${tone.fg}`,
                }}
              />
              <span>
                <span
                  style={{
                    display: "block",
                    color: TEXT.data,
                    fontFamily: FONT.sans,
                    fontSize: 12.8,
                    fontWeight: 500,
                  }}
                >
                  {row.label}
                </span>
                <span style={{ color: TEXT.footnote, fontSize: 10 }}>{row.value}</span>
              </span>
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <div>
      {section.rows.map((row, i) => (
        <KeyValueRow key={`${row.label}-${i}`} row={row} />
      ))}
    </div>
  );
}

function KeyValueRow({ row }: { row: DetailRow }) {
  return (
    <div
      style={{
        display: "flex",
        gap: 10,
        padding: "6px 0",
        borderBottom: `1px solid ${SURFACE.rowRule}`,
      }}
    >
      <span
        style={{
          width: 132,
          flexShrink: 0,
          color: TEXT.panelKey,
          fontSize: 10,
          letterSpacing: ".06em",
        }}
      >
        {row.label}
      </span>
      <span style={{ minWidth: 0 }}>
        {row.href ? (
          <a
            href={row.href}
            target="_blank"
            rel="noreferrer noopener"
            style={{
              color: ACCENT,
              fontFamily: FONT.sans,
              fontSize: 12.8,
              wordBreak: "break-all",
            }}
          >
            {row.value}
          </a>
        ) : (
          <span
            style={{
              color: row.tone ? row.tone.fg : TEXT.data,
              fontFamily: FONT.sans,
              fontSize: 12.8,
              wordBreak: "break-word",
            }}
          >
            {row.value}
          </span>
        )}
        {row.gated && (
          <span style={{ color: TONES.gated.fg, fontSize: 9, marginLeft: 6 }}>GATED</span>
        )}
        {row.detail && (
          <span
            style={{
              display: "block",
              marginTop: 2,
              color: TEXT.footnote,
              fontFamily: FONT.mono,
              fontSize: 10,
            }}
          >
            {row.detail}
          </span>
        )}
      </span>
    </div>
  );
}

/**
 * One of the analyst's verdict controls. Uniform because the three of them are
 * the same kind of act — a judgement on a finding — and only their consequence
 * differs.
 */
function VerdictButton({
  label,
  tone,
  busy,
  onClick,
}: {
  label: string;
  tone?: Tone;
  busy: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      style={{
        padding: "5px 12px",
        background: "none",
        border: `1px solid ${tone ? tone.border : SURFACE.border}`,
        borderRadius: 3,
        color: busy ? TEXT.footnote : tone ? tone.fg : TEXT.secondary,
        fontFamily: FONT.mono,
        fontSize: 10,
        letterSpacing: ".1em",
        cursor: busy ? "default" : "pointer",
      }}
    >
      {label}
    </button>
  );
}
