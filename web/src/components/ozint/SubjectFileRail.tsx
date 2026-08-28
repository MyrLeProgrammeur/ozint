"use client";

import { useState } from "react";

import {
  relationKindLabel,
  relationTierLabel,
  relationTierTone,
  type Relation,
  type RelationReport,
} from "@/lib/ozint/relations";
import type { RailField, RailModel } from "@/lib/ozint/subject-file";
import { ACCENT, CHROME, FONT, SURFACE, TEXT, TONES } from "@/lib/ozint/tokens";

/**
 * The subject file rail.
 *
 * Rendered only when there is a file to render — the rail is
 * *absent* for a CVE, hash, IP, domain or coordinate root, not empty. The caller
 * owns that: it passes no model and this component is never mounted.
 *
 * Twelve fields over a denominator of thirteen. The ratio shown is
 * the server's own; nothing here recomputes it.
 *
 * A field with two values in one item is an unresolved conflict, and it is drawn
 * as one — both values, marked. The rail never picks a winner, because picking
 * one would be the subject file asserting something no tool said.
 */
export function SubjectFileRail({
  model,
  building,
  onSelectNode,
  relations,
  onSelectSourceNode,
  onSpawn,
  spawning,
  spawnError,
}: {
  model: RailModel;
  /** Any layer in flight — the header says so. */
  building: boolean;
  /** Jump to the node that produced a value. */
  onSelectNode: (nodeId: string) => void;
  /**
   * POTENTIAL RELATIONS, re-derived on every read. `null` means never read —
   * rendered as absent, same treatment as the subject file itself.
   */
  relations: RelationReport | null;
  /** Jump to the node that carried one piece of a relation's evidence. */
  onSelectSourceNode: (nodeId: string) => void;
  /** Opens a brand-new investigation on this relation. */
  onSpawn: (relation: Relation) => void;
  spawning: boolean;
  spawnError: string | null;
}) {
  const [open, setOpen] = useState(true);

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label="Expand subject file"
        style={{
          width: CHROME.railCollapsedWidth,
          flexShrink: 0,
          background: SURFACE.chrome,
          borderRight: `1px solid ${SURFACE.hairline}`,
          border: "none",
          color: TEXT.ghostLabel,
          fontFamily: FONT.mono,
          fontSize: 9,
          letterSpacing: ".18em",
          cursor: "pointer",
          writingMode: "vertical-rl",
        }}
      >
        SUBJECT FILE · {model.percent}%
      </button>
    );
  }

  return (
    <aside
      style={{
        width: CHROME.railWidth,
        flexShrink: 0,
        display: "flex",
        flexDirection: "column",
        background: SURFACE.chrome,
        borderRight: `1px solid ${SURFACE.hairline}`,
        fontFamily: FONT.mono,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "12px 14px 10px",
          borderBottom: `1px solid ${SURFACE.hairline}`,
        }}
      >
        <span style={{ color: ACCENT, fontSize: 9.5, letterSpacing: ".16em" }}>
          SUBJECT FILE
        </span>
        <span
          style={{
            color: building ? ACCENT : TEXT.footnote,
            fontSize: 9,
            letterSpacing: ".14em",
          }}
        >
          {building ? "BUILDING…" : "IDLE"}
        </span>
        <button
          type="button"
          onClick={() => setOpen(false)}
          aria-label="Collapse subject file"
          style={{
            marginLeft: "auto",
            background: "none",
            border: "none",
            color: TEXT.iconButton,
            fontFamily: FONT.mono,
            cursor: "pointer",
          }}
        >
          ‹
        </button>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "12px 14px 24px" }}>
        {/* Completeness — the server's own numbers, over a denominator of 13. */}
        <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
          <span style={{ color: TEXT.fileLabel, fontSize: 8.5, letterSpacing: ".14em" }}>
            COMPLETENESS
          </span>
          <span style={{ marginLeft: "auto", color: TEXT.data, fontSize: 12 }}>
            {model.percent}%
          </span>
          <span style={{ color: TEXT.footnote, fontSize: 10 }}>
            {model.filled} / {model.total}
          </span>
        </div>
        <div
          style={{
            height: 3,
            marginTop: 6,
            background: SURFACE.track,
            borderRadius: 2,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              height: "100%",
              width: `${model.percent}%`,
              background: ACCENT,
              transition: "width .5s ease",
            }}
          />
        </div>

        {/* Photo — a real retrieved image or an honest absence. */}
        <div
          style={{
            marginTop: 14,
            height: model.photo ? 150 : 64,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            border: model.photo
              ? `1px solid ${SURFACE.border}`
              : `1px dashed ${SURFACE.border}`,
            borderRadius: 3,
            overflow: "hidden",
          }}
        >
          {model.photo ? (
            <img
              src={model.photo.value}
              alt="subject"
              style={{ width: "100%", height: "100%", objectFit: "cover" }}
            />
          ) : (
            <span style={{ color: TEXT.empty, fontSize: 9.5, letterSpacing: ".14em" }}>
              NO PHOTO FOUND YET
            </span>
          )}
        </div>

        {/* Identity line. */}
        <div style={{ marginTop: 12 }}>
          <div
            style={{
              fontFamily: FONT.sans,
              fontSize: 16,
              fontWeight: 600,
              color: model.identity ? TEXT.panelTitle : TEXT.footnote,
            }}
          >
            {model.identity ?? "unidentified subject"}
          </div>
          {model.subtitle && (
            <div style={{ marginTop: 2, color: TEXT.monoCaption, fontSize: 10 }}>
              {model.subtitle}
            </div>
          )}
        </div>

        <div style={{ marginTop: 16 }}>
          {model.fields.map((field) => (
            <FieldRow key={field.field} field={field} onSelectNode={onSelectNode} />
          ))}
        </div>

        <RelationsSection
          relations={relations}
          onSelectSourceNode={onSelectSourceNode}
          onSpawn={onSpawn}
          spawning={spawning}
          spawnError={spawnError}
        />
      </div>
    </aside>
  );
}

/**
 * POTENTIAL RELATIONS. Each card expands on click to show its evidence and
 * the dashed inference notice — clicking opens the relation's own file in the
 * detail panel; this build has no separate file for an entity that has never
 * been investigated, so the expansion happens in place rather than opening a
 * second panel over a thing that does not yet exist.
 */
function RelationsSection({
  relations,
  onSelectSourceNode,
  onSpawn,
  spawning,
  spawnError,
}: {
  relations: RelationReport | null;
  onSelectSourceNode: (nodeId: string) => void;
  onSpawn: (relation: Relation) => void;
  spawning: boolean;
  spawnError: string | null;
}) {
  const [openId, setOpenId] = useState<string | null>(null);

  // `null` — never read yet — renders nothing, same as the rail itself before
  // its first hydrate. That is different from a read that came back empty.
  if (!relations) return null;

  return (
    <div style={{ marginTop: 20 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
        <span style={{ color: ACCENT, fontSize: 9.5, letterSpacing: ".16em" }}>
          POTENTIAL RELATIONS
        </span>
        <span style={{ color: TEXT.footnote, fontSize: 10 }}>
          {relations.relations.length}
        </span>
      </div>

      {relations.relations.length === 0 ? (
        <div
          style={{
            marginTop: 8,
            padding: "8px 9px",
            border: `1px dashed ${SURFACE.borderInert}`,
            borderRadius: 3,
            color: TEXT.empty,
            fontSize: 10,
          }}
        >
          no linked person yet
        </div>
      ) : (
        <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 6 }}>
          {relations.relations.map((relation) => (
            <RelationCard
              key={relation.id}
              relation={relation}
              open={openId === relation.id}
              onToggle={() =>
                setOpenId((cur) => (cur === relation.id ? null : relation.id))
              }
              onSelectSourceNode={onSelectSourceNode}
              onSpawn={() => onSpawn(relation)}
              spawning={spawning}
              spawnError={spawnError}
            />
          ))}
        </div>
      )}

      {relations.rulesWithoutInput.length > 0 && (
        <div style={{ marginTop: 8, color: TEXT.footnote, fontSize: 9, letterSpacing: ".04em" }}>
          {relations.rulesWithoutInput.length}{" "}
          {relations.rulesWithoutInput.length === 1 ? "rule" : "rules"} had no input to run on
          this build ({relations.rulesWithoutInput.map((r) => relationKindLabel(r.kind)).join(", ")})
        </div>
      )}
    </div>
  );
}

function RelationCard({
  relation,
  open,
  onToggle,
  onSelectSourceNode,
  onSpawn,
  spawning,
  spawnError,
}: {
  relation: Relation;
  open: boolean;
  onToggle: () => void;
  onSelectSourceNode: (nodeId: string) => void;
  onSpawn: () => void;
  spawning: boolean;
  spawnError: string | null;
}) {
  const tone = relationTierTone(relation.tier);
  return (
    <div
      style={{
        border: `1px solid ${SURFACE.border}`,
        background: SURFACE.cardInner,
        borderRadius: 3,
        padding: "8px 9px",
      }}
    >
      <button
        type="button"
        onClick={onToggle}
        style={{
          display: "flex",
          width: "100%",
          alignItems: "baseline",
          gap: 6,
          background: "none",
          border: "none",
          padding: 0,
          cursor: "pointer",
          textAlign: "left",
        }}
      >
        <span
          style={{
            fontFamily: FONT.sans,
            fontSize: 12.5,
            fontWeight: 500,
            color: TEXT.data,
          }}
        >
          {relation.subject}
        </span>
        <span
          style={{
            marginLeft: "auto",
            color: tone.fg,
            background: tone.bg,
            border: `1px solid ${tone.border}`,
            borderRadius: 2,
            padding: "1px 5px",
            fontFamily: FONT.mono,
            fontSize: 8,
            letterSpacing: ".08em",
          }}
        >
          {relationTierLabel(relation.tier)}
        </span>
      </button>
      <div style={{ marginTop: 3, color: TEXT.monoCaption, fontSize: 9.5, fontFamily: FONT.mono }}>
        {relationKindLabel(relation.kind)}
      </div>
      <div style={{ marginTop: 3, color: TEXT.prose, fontSize: 11, fontFamily: FONT.sans }}>
        {relation.rationale}
      </div>

      {open && (
        <div style={{ marginTop: 8, borderTop: `1px solid ${SURFACE.hairline}`, paddingTop: 8 }}>
          {relation.evidence.map((ev, i) => (
            <button
              key={`${ev.nodeId}-${i}`}
              type="button"
              onClick={() => onSelectSourceNode(ev.nodeId)}
              style={{
                display: "block",
                width: "100%",
                textAlign: "left",
                marginBottom: 4,
                background: "none",
                border: `1px solid ${SURFACE.border}`,
                borderRadius: 2,
                padding: "4px 6px",
                color: TEXT.body,
                fontFamily: FONT.mono,
                fontSize: 9.5,
                cursor: "pointer",
              }}
            >
              {ev.gated && <span style={{ color: TONES.gated.fg }}>GATED · </span>}
              via {ev.toolId} — {ev.detail}
            </button>
          ))}

          <div
            style={{
              marginTop: 6,
              padding: "7px 8px",
              border: `1px dashed ${TONES.warn.border}`,
              borderRadius: 3,
              color: TONES.warn.fg,
              fontSize: 10,
              fontFamily: FONT.mono,
              lineHeight: 1.5,
            }}
          >
            NOT SEARCHED — this is an inference, not an investigated person.
            Searching them opens a brand-new, separate investigation; nothing
            here is added to this tree.
          </div>

          <button
            type="button"
            onClick={onSpawn}
            disabled={spawning}
            style={{
              marginTop: 8,
              width: "100%",
              padding: "6px 0",
              background: "none",
              border: `1px solid ${TONES.ok.border}`,
              borderRadius: 3,
              color: spawning ? TEXT.footnote : ACCENT,
              fontFamily: FONT.mono,
              fontSize: 10,
              letterSpacing: ".08em",
              cursor: spawning ? "default" : "pointer",
            }}
          >
            {spawning ? "OPENING…" : "SEARCH THIS PERSON →"}
          </button>
          {spawnError && (
            <div style={{ marginTop: 6, color: TONES.warn.fg, fontSize: 9.5 }}>
              {spawnError}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FieldRow({
  field,
  onSelectNode,
}: {
  field: RailField;
  onSelectNode: (nodeId: string) => void;
}) {
  return (
    <div style={{ padding: "8px 0", borderBottom: `1px solid ${SURFACE.rowRule}` }}>
      <div style={{ color: TEXT.fileLabel, fontSize: 8.5, letterSpacing: ".14em" }}>
        {field.label}
      </div>

      {field.empty ? (
        <div
          style={{
            marginTop: 4,
            padding: "3px 6px",
            border: `1px dashed ${SURFACE.borderInert}`,
            borderRadius: 3,
            color: TEXT.empty,
            fontSize: 10,
          }}
        >
          awaiting a finding
        </div>
      ) : (
        field.items.map((item, i) => (
          <div key={i} style={{ marginTop: 4 }}>
            {item.conflicted && (
              <div style={{ color: TONES.warn.fg, fontSize: 9, letterSpacing: ".12em" }}>
                UNRESOLVED · {item.values.length} SOURCES DISAGREE
              </div>
            )}
            {item.values.map((value, j) => (
              <div
                key={j}
                style={{
                  display: "flex",
                  alignItems: "baseline",
                  gap: 6,
                  flexWrap: "wrap",
                }}
              >
                <span
                  style={{
                    fontFamily: FONT.sans,
                    fontSize: 12.5,
                    color: item.conflicted ? TONES.warn.fg : TEXT.data,
                    wordBreak: "break-word",
                  }}
                >
                  {value.value}
                </span>
                {value.gated && (
                  <span style={{ color: TONES.gated.fg, fontSize: 8 }}>GATED</span>
                )}
                {value.sources.map((source, k) => (
                  <button
                    key={`${source.nodeId}-${k}`}
                    type="button"
                    onClick={() => onSelectNode(source.nodeId)}
                    title={`found by ${source.toolId}`}
                    style={{
                      padding: "0 4px",
                      background: "none",
                      border: `1px solid ${SURFACE.border}`,
                      borderRadius: 2,
                      color: TEXT.footnote,
                      fontFamily: FONT.mono,
                      fontSize: 8,
                      cursor: "pointer",
                    }}
                  >
                    {source.corrected ? "✎ " : ""}
                    {source.toolId}
                  </button>
                ))}
              </div>
            ))}
          </div>
        ))
      )}
    </div>
  );
}
