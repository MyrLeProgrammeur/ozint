"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Crosshair, History, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { detailModel } from "@/lib/ozint/detail";
import { clampZoom, ZOOM_STEP } from "@/lib/ozint/layout";
import { inFlightLayers } from "@/lib/ozint/state";
import { ozintStore, useOzintStore } from "@/lib/ozint/store";
import {
  ACCENT,
  CHROME,
  FONT,
  SURFACE,
  TEXT,
  TONES,
  TYPE_MARKS,
  type OzTypeName,
} from "@/lib/ozint/tokens";
import type { Relation } from "@/lib/ozint/relations";
import { notApplicableReason, railModel } from "@/lib/ozint/subject-file";
import { meterLine } from "@/lib/ozint/view";

import { HistoryOverlay } from "./HistoryOverlay";
import { NodeDetailPanel } from "./NodeDetailPanel";
import { SubjectFileRail } from "./SubjectFileRail";
import { OzintTree } from "./OzintTree";

/**
 * The OZINT cockpit. One investigation, one tree, one stream.
 *
 * Desktop only, deliberately — this runs on the desktop machine
 * and no phone layout is owed, so nothing here is responsive below ~1440px.
 *
 * History reopens **resumable**, never read-only — there is no read-only state
 * in the data model, so the earlier design mock's `ARCHIVE · READ-ONLY` chip is deleted
 * rather than reinterpreted.
 *
 * The subject-file rail is mounted only when the server
 * sent a file to mount. A CVE or hash root answers `notApplicable`, and the
 * cockpit says so once in the status bar rather than showing an empty rail whose
 * zeroes would read as findings that failed to arrive.
 */
/**
 * `onClose` is optional: when OZINT is embedded in a host application the host owns a
 * way back, and when it runs standalone there is nothing behind it. The button is
 * rendered only when a handler exists — a visible X that does nothing is worse than none.
 */
export function OzintView({ onClose }: { onClose?: () => void }) {
  const {
    tree,
    status,
    malformed,
    transportError,
    meter,
    openStreams,
    subjectFile,
    relations,
    spawning,
    spawnError,
    history,
    historyLoading,
    historyError,
    reopenError,
  } = useOzintStore();
  const [seed, setSeed] = useState("");
  /**
   * `auto` — the default — sends no type at all and the classifier
   * decides, exactly as before. An explicit choice replaces the classifier, so
   * an analyst who pastes `Acme Industries` and meant DIRECTORY can say so
   * *upstream* rather than discovering the wrong type after the fire.
   */
  const [seedType, setSeedType] = useState<"auto" | OzTypeName>("auto");
  const [zoom, setZoom] = useState(1);
  const [focusedId, setFocusedId] = useState<string | null>(null);
  /**
   * The scroll port around the canvas. The tree is laid out centred inside a canvas as wide as
   * the tree itself, so "show me the root" is exactly "scroll to the horizontal middle" — no
   * DOM measurement of any particular card is needed.
   */
  const canvasRef = useRef<HTMLDivElement | null>(null);
  const recentre = useCallback((behavior: ScrollBehavior = "smooth") => {
    const el = canvasRef.current;
    if (!el) return;
    el.scrollTo({ left: (el.scrollWidth - el.clientWidth) / 2, behavior });
  }, []);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(new Set());
  /** The node whose detail panel is open. Independent of tree focus. */
  const [openNodeId, setOpenNodeId] = useState<string | null>(null);

  /**
   * Keep the root in view while the canvas is still growing under the analyst.
   *
   * The naive version of this — recentre once, when the first child lands — is wrong, and
   * wrong in a way that looks like it works: nodes stream in one at a time, so it fires when
   * the tree is two cards wide and then sits still while the next twenty widen the canvas to
   * several thousand pixels. The viewport ends up parked on the far-left edge with the root
   * thousands of pixels away, which is exactly the state it was meant to prevent.
   *
   * So it recentres on every change *until the analyst scrolls*. Their first deliberate scroll
   * hands control over for the rest of the investigation, and the crosshair button gives it
   * back. Opening a different investigation resets that.
   */
  const rootNodeId = tree.rootNodeId;
  const nodeCount = Object.keys(tree.nodes).length;
  const analystHasScrolled = useRef(false);
  useEffect(() => {
    analystHasScrolled.current = false;
  }, [rootNodeId]);
  useEffect(() => {
    if (!rootNodeId || analystHasScrolled.current) return;
    // After paint: the canvas is only as wide as the tree once the new cards are laid out.
    const frame = requestAnimationFrame(() => recentre("auto"));
    return () => cancelAnimationFrame(frame);
  }, [rootNodeId, nodeCount, recentre]);
  const [historyOpen, setHistoryOpen] = useState(false);

  const firing = inFlightLayers(tree);

  // Recomputed on every tree change on purpose: the node you
  // continued grows richer *while its own layer runs*, and a panel frozen at
  // the instant it opened would be exactly the earlier design mock's frozen parent card.
  const detail = useMemo(
    () => (openNodeId ? detailModel(tree, openNodeId) : null),
    [tree, openNodeId],
  );

  // No model means no rail, and the tree stands alone.
  const rail = useMemo(() => railModel(subjectFile), [subjectFile]);
  const railAbsence = useMemo(() => notApplicableReason(subjectFile), [subjectFile]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // The overlay sits on top, so it is what Escape closes first.
      if (historyOpen) setHistoryOpen(false);
      else if (openNodeId) setOpenNodeId(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [openNodeId, historyOpen]);

  const submit = useCallback(() => {
    const value = seed.trim();
    if (value.length === 0) return;
    ozintStore.reset();
    // `auto` sends no `ozType` at all, which is exactly the request
    // this cockpit made before the selector existed. Only an explicit choice
    // adds the field, and the server then bypasses the classifier entirely.
    void ozintStore.fire(
      seedType === "auto" ? { seed: value } : { seed: value, ozType: seedType },
    );
  }, [seed, seedType]);

  const toggle = (set: ReadonlySet<string>, id: string): ReadonlySet<string> => {
    const next = new Set(set);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    return next;
  };

  const onContinue = useCallback(
    (nodeId: string) => {
      if (!tree.investigationId) return;
      void ozintStore.fire({
        investigationId: tree.investigationId,
        parentNodeId: nodeId,
      });
    },
    [tree.investigationId],
  );

  const openHistory = useCallback(() => {
    setHistoryOpen(true);
    void ozintStore.listInvestigations();
  }, []);

  /**
   * Reopening is resuming. Nothing is fired and nothing is locked: the tree,
   * its layer bands and the subject file are read back, and every action stays
   * available on it.
   */
  const reopen = useCallback((investigationId: string) => {
    setOpenNodeId(null);
    setFocusedId(null);
    setExpanded(new Set());
    setCollapsed(new Set());
    void ozintStore.open(investigationId).then((ok) => {
      // A failed reopen leaves the overlay up, with the reason in the status
      // bar — closing onto an empty canvas would read as an empty investigation.
      if (ok) setHistoryOpen(false);
    });
  }, []);

  /**
   * Searching a relation opens a brand-new investigation, never grafted onto
   * the one open now, so the local tree-UI state (focus, expanded/collapsed,
   * any open detail panel) is reset exactly as `reopen` resets it for a
   * history entry — the same kind of switch under the hood.
   */
  const spawnRelation = useCallback((relation: Relation) => {
    if (!tree.investigationId) return;
    setOpenNodeId(null);
    setFocusedId(null);
    setExpanded(new Set());
    setCollapsed(new Set());
    void ozintStore.spawn(tree.investigationId, relation.id);
  }, [tree.investigationId]);

  const killAll = useCallback(() => {
    if (!tree.investigationId) return;
    void ozintStore.cancel({ investigationId: tree.investigationId });
  }, [tree.investigationId]);

  return (
    <motion.div
      /*
        These were Tailwind classes — `fixed inset-0 z-50 flex flex-col` — carried over from a
        host application that had Tailwind. This one does not: the cockpit styles everything
        inline from `tokens.ts` and ships no CSS framework, so those four classes matched
        nothing and the root had no height, no positioning and no flex context at all. The
        symptom was subtle enough to survive a long time: the column still stacked (blocks do)
        and the canvas still filled its own box, so the only visible trace was a band of dead
        background below the status bar on any viewport taller than the content. Written out as
        styles, which is also the convention every other element here follows.
      */
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 50,
        display: "flex",
        flexDirection: "column",
        background: SURFACE.canvas,
        fontFamily: FONT.mono,
      }}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.35 }}
    >
      {/* ── top bar ─────────────────────────────────────────────────────── */}
      <div
        style={{
          height: CHROME.topBarHeight,
          display: "flex",
          alignItems: "center",
          gap: 16,
          padding: "0 16px",
          background: SURFACE.chrome,
          borderBottom: `1px solid ${SURFACE.hairline}`,
          flexShrink: 0,
        }}
      >
        <span style={{ color: ACCENT, fontSize: 12, letterSpacing: ".18em" }}>
          OZINT
        </span>

        <div style={{ display: "flex", flex: 1, maxWidth: CHROME.searchBarWidth }}>
          <input
            value={seed}
            onChange={(e) => setSeed(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submit();
            }}
            placeholder="username, email, domain, IP, hash, CVE…"
            spellCheck={false}
            style={{
              flex: 1,
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
          {/* The type selector. Offers every type with no client-side list of
              which ones have an orchestrator: the server owns that, and answers
              a type it cannot fire with a sentence saying so. */}
          <select
            value={seedType}
            onChange={(e) => setSeedType(e.target.value as "auto" | OzTypeName)}
            aria-label="Seed type"
            style={{
              marginLeft: 8,
              height: 30,
              padding: "0 6px",
              background: SURFACE.input,
              border: `1px solid ${SURFACE.border}`,
              borderRadius: 3,
              color: seedType === "auto" ? TEXT.ghostLabel : ACCENT,
              fontFamily: FONT.mono,
              fontSize: 11,
              letterSpacing: ".08em",
              outline: "none",
              cursor: "pointer",
            }}
          >
            <option value="auto">AUTO</option>
            {(Object.keys(TYPE_MARKS) as OzTypeName[]).map((type) => (
              <option key={type} value={type}>
                {TYPE_MARKS[type].label}
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={submit}
            style={{
              marginLeft: 8,
              padding: "0 14px",
              background: "none",
              border: `1px solid ${TONES.ok.border}`,
              borderRadius: 3,
              color: ACCENT,
              fontFamily: FONT.mono,
              fontSize: 11,
              letterSpacing: ".1em",
              cursor: "pointer",
            }}
          >
            FIRE
          </button>
        </div>

        <button
          type="button"
          onClick={openHistory}
          aria-label="Past investigations"
          title="Past investigations"
          style={{
            marginLeft: "auto",
            width: 30,
            height: 30,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "none",
            border: `1px solid ${SURFACE.border}`,
            borderRadius: 3,
            color: TEXT.iconButton,
            cursor: "pointer",
          }}
        >
          <History size={14} />
        </button>

        <div style={{ display: "flex", gap: 6 }}>
          <button
            type="button"
            onClick={() => recentre()}
            aria-label="Centre the tree"
            title="Centre the tree"
            style={{
              width: 26,
              height: 26,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "none",
              border: `1px solid ${SURFACE.border}`,
              borderRadius: 3,
              color: TEXT.iconButton,
              cursor: "pointer",
            }}
          >
            <Crosshair size={13} />
          </button>
          <ZoomButton label="−" onClick={() => setZoom((z) => clampZoom(z - ZOOM_STEP))} />
          <span style={{ color: TEXT.footnote, fontSize: 11, alignSelf: "center" }}>
            {Math.round(zoom * 100)}%
          </span>
          <ZoomButton label="+" onClick={() => setZoom((z) => clampZoom(z + ZOOM_STEP))} />
        </div>

        {onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Close OZINT"
            style={{ background: "none", border: "none", color: TEXT.iconButton, cursor: "pointer" }}
          >
            <X size={16} />
          </button>
        )}
      </div>

      {/* ── canvas ──────────────────────────────────────────────────────── */}
      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
      {rail && (
        <SubjectFileRail
          model={rail}
          building={firing.length > 0}
          onSelectNode={(id) => {
            setFocusedId(id);
            setOpenNodeId(id);
          }}
          relations={relations}
          onSelectSourceNode={(id) => {
            setFocusedId(id);
            setOpenNodeId(id);
          }}
          onSpawn={spawnRelation}
          spawning={spawning}
          spawnError={spawnError}
        />
      )}

      {/*
        `minWidth: 0` is load-bearing, not defensive. A flex item defaults to `min-width: auto`,
        which refuses to shrink below its content — so a wide tree grew this wrapper to the
        tree's own width instead of letting the scroller below clip it, and the whole page
        overflowed sideways with no way to scroll back. A 21-child layer put the root node at
        x≈3100 in a 1680px window, unreachable. `minHeight: 0` was already here for the same
        reason vertically; the horizontal half was missing.
      */}
      <div style={{ position: "relative", flex: 1, minWidth: 0, minHeight: 0 }}>
      {/*
        `safe center` rather than `center`: when the content is wider than the scroll port,
        plain `center` overflows equally in both directions and the left overflow is
        unreachable — scrollLeft cannot go negative. `safe` falls back to start-alignment in
        exactly that case, which is the difference between a centred small tree and a
        half-lost large one.
      */}
      <div
        ref={canvasRef}
        onScroll={(e) => {
          // Our own recentring scrolls here too, so "did a human do this?" is answered by
          // where it landed: anything but the centre is theirs. The tolerance covers
          // sub-pixel rounding on fractional canvas widths.
          const el = e.currentTarget;
          const centre = (el.scrollWidth - el.clientWidth) / 2;
          if (Math.abs(el.scrollLeft - centre) > 2) analystHasScrolled.current = true;
        }}
        style={{ height: "100%", overflow: "auto", display: "flex", justifyContent: "safe center" }}
      >
        {tree.rootNodeId ? (
          <OzintTree
            tree={tree}
            zoom={zoom}
            expanded={expanded}
            collapsed={collapsed}
            focusedId={focusedId}
            onFocus={(id) => {
              setFocusedId(id);
              setOpenNodeId(id);
              setCollapsed((c) => (c.has(id) ? toggle(c, id) : c));
            }}
            onContinue={onContinue}
            onToggleBand={(id) => setExpanded((e) => toggle(e, id))}
          />
        ) : (
          <div
            style={{
              alignSelf: "center",
              color: TEXT.empty,
              fontSize: 12,
              letterSpacing: ".1em",
              textAlign: "center",
            }}
          >
            {status === "streaming"
              ? "OPENING THE STREAM…"
              : "ENTER A SEED VALUE TO OPEN AN INVESTIGATION"}
          </div>
        )}
      </div>

        <AnimatePresence>
          {detail && (
            <NodeDetailPanel
              key={detail.node.id}
              model={detail}
              onClose={() => setOpenNodeId(null)}
              onContinue={() => onContinue(detail.node.id)}
            />
          )}
        </AnimatePresence>
      </div>
      </div>

      {historyOpen && (
        <HistoryOverlay
          items={history}
          loading={historyLoading}
          error={historyError}
          currentId={tree.investigationId}
          onReopen={reopen}
          onClose={() => setHistoryOpen(false)}
        />
      )}

      {/* ── status bar ──────────────────────────────────────────────────── */}
      <div
        style={{
          height: CHROME.statusBarHeight,
          display: "flex",
          alignItems: "center",
          gap: 18,
          padding: "0 16px",
          background: SURFACE.chrome,
          borderTop: `1px solid ${SURFACE.hairline}`,
          color: TEXT.monoCaption,
          fontSize: 11,
          letterSpacing: ".08em",
          flexShrink: 0,
        }}
      >
        {/* The server's own lookup count and cost, never a
            fabricated one — dashes until the meter has actually answered. */}
        <span>{meterLine(meter)}</span>
        <span>{Object.keys(tree.nodes).length} NODES</span>
        {/* The absence of a rail is stated, never left ambiguous. */}
        {railAbsence && <span style={{ color: TEXT.footnote }}>{railAbsence}</span>}
        {firing.length > 0 && (
          <span style={{ color: TONES.ok.fg }}>
            {firing.length} {firing.length === 1 ? "LAYER" : "LAYERS"} FIRING
          </span>
        )}
        {openStreams > 0 && <span>{openStreams} OPEN</span>}

        {firing.length > 0 && (
          <button
            type="button"
            onClick={killAll}
            style={{
              padding: "1px 10px",
              background: "none",
              border: `1px solid ${TONES.risk.border}`,
              borderRadius: 3,
              color: TONES.risk.fg,
              fontFamily: FONT.mono,
              fontSize: 10,
              letterSpacing: ".1em",
              cursor: "pointer",
            }}
          >
            KILL
          </button>
        )}

        <span style={{ marginLeft: "auto", display: "flex", gap: 14 }}>
          {/* Neither of these is allowed to look like a clean empty result. */}
          {reopenError && (
            <span style={{ color: TONES.warn.fg }}>REOPEN · {reopenError}</span>
          )}
          {transportError && (
            <span style={{ color: TONES.warn.fg }}>STREAM · {transportError}</span>
          )}
          {malformed.length > 0 && (
            <span style={{ color: TONES.warn.fg }}>
              {malformed.length} UNREADABLE {malformed.length === 1 ? "FRAME" : "FRAMES"}
            </span>
          )}
          {tree.errors.length > 0 && (
            <span style={{ color: TONES.warn.fg }}>
              {tree.errors.length} ENGINE {tree.errors.length === 1 ? "ERROR" : "ERRORS"}
            </span>
          )}
        </span>
      </div>
    </motion.div>
  );
}

function ZoomButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        width: 22,
        height: 22,
        background: "none",
        border: `1px solid ${SURFACE.border}`,
        borderRadius: 3,
        color: TEXT.iconButton,
        fontFamily: FONT.mono,
        fontSize: 12,
        cursor: "pointer",
      }}
    >
      {label}
    </button>
  );
}
