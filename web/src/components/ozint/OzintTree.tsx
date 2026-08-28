"use client";

import { useMemo } from "react";

import { layoutTree } from "@/lib/ozint/layout";
import type { OzintTreeState } from "@/lib/ozint/state";
import { GRID, SURFACE } from "@/lib/ozint/tokens";
import { bandModel, blockModel, cardModel, toLayoutInput } from "@/lib/ozint/view";

import { LayerBand } from "./LayerBand";
import { LayerBlock } from "./LayerBlock";
import { NodeCard } from "./NodeCard";

/**
 * The tidy tree, drawn.
 *
 * Everything positional comes from `layout.ts` and everything semantic from
 * `view.ts`; this file only turns those two into absolutely positioned boxes.
 *
 * ⚠️ It does not virtualise — this is the open rendering
 * problem: the widest case exercised so far is 26 nodes and a real fan-out is
 * several hundred, all of them mounted here at once. Independent of screen
 * size, and not solved by this component.
 */
export function OzintTree({
  tree,
  zoom,
  expanded,
  collapsed,
  focusedId,
  onFocus,
  onContinue,
  onToggleBand,
}: {
  tree: OzintTreeState;
  zoom: number;
  expanded: ReadonlySet<string>;
  collapsed: ReadonlySet<string>;
  focusedId: string | null;
  onFocus: (nodeId: string) => void;
  onContinue: (nodeId: string) => void;
  onToggleBand: (nodeId: string) => void;
}) {
  const input = useMemo(
    () => toLayoutInput(tree, { expanded, collapsed }),
    [tree, expanded, collapsed],
  );
  const layout = useMemo(() => (input ? layoutTree(input) : null), [input]);

  if (!layout) return null;

  const geometry = input!.geometry!;

  return (
    <div
      style={{
        position: "relative",
        width: layout.canvasWidth,
        height: layout.canvasHeight,
        transform: `scale(${zoom})`,
        transformOrigin: "top center",
        backgroundImage: `linear-gradient(${GRID.canvas} 1px, transparent 1px), linear-gradient(90deg, ${GRID.canvas} 1px, transparent 1px)`,
        backgroundSize: `${GRID.size}px ${GRID.size}px`,
      }}
    >
      {layout.connectors.map((rect, i) => (
        <div
          key={`c${i}`}
          style={{
            position: "absolute",
            left: rect.x,
            top: rect.y,
            width: rect.w,
            height: rect.h,
            background: SURFACE.connector,
          }}
        />
      ))}

      {layout.bands.map((band) => {
        const model = bandModel(tree, band.nodeId);
        if (!model) return null;
        return (
          <div
            key={`band-${band.nodeId}`}
            style={{
              position: "absolute",
              left: band.x,
              top: band.y,
              width: band.w,
              height: band.h,
            }}
          >
            <LayerBand
              band={model}
              expanded={expanded.has(band.nodeId)}
              onToggle={() => onToggleBand(band.nodeId)}
            />
          </div>
        );
      })}

      {layout.blocks.map((placed) => {
        const model = blockModel(tree, placed.nodeId);
        if (!model) return null;
        return (
          <div
            key={`block-${placed.nodeId}`}
            style={{
              position: "absolute",
              left: placed.x,
              top: placed.y,
              width: placed.w,
              height: placed.h,
            }}
          >
            <LayerBlock block={model} onRetry={() => onContinue(placed.nodeId)} />
          </div>
        );
      })}

      {layout.cards.map((placed) => {
        const model = cardModel(tree, placed.id);
        if (!model) return null;
        return (
          <div
            key={placed.id}
            style={{
              position: "absolute",
              left: placed.x,
              top: placed.y,
              width: geometry.W,
              height: geometry.H,
            }}
          >
            <NodeCard
              card={model}
              focused={focusedId === placed.id}
              onFocus={() => onFocus(placed.id)}
              onContinue={() => onContinue(placed.id)}
            />
          </div>
        );
      })}
    </div>
  );
}
