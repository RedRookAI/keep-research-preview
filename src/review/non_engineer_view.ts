/**
 * Plain-language decision content shared by the CLI and web review views.
 * Shows the disposition, evidence, consequences and points requiring review.
 */

import type { DecisionPacket } from "../cli/decision_packet.js";

export interface NonEngineerView {
  readonly disposition: "auto-approved" | "human-approval-required" | "blocked";
  readonly needsDecision: boolean;
  /** The disposition line — FIRST and never omitted. */
  readonly headline: string;
  readonly whatItDoes: string;
  readonly checked: readonly { readonly label: string; readonly value: string }[];
  readonly reversalText: string;
  readonly affects?: string;
  /** Present ONLY for items that need a decision (the anti-overcorrection move). */
  readonly onlyYou?: readonly string[];
  readonly confidenceText?: string;
  /** The explicitly non-recommending close. */
  readonly framing?: string;
}

/** Build the structured, non-persuasive view from the packet. Single source of truth for both renderers. */
export function buildNonEngineerView(p: DecisionPacket): NonEngineerView {
  const headline =
    p.disposition === "blocked" ? "Keep blocked this change. It will not proceed."
    : p.disposition === "auto-approved" ? "Passed automated checks and auto-approved. A spot-check is optional. Merging still requires a person's approval."
    : "This change needs your approval before it can proceed.";

  const reversalText = p.reversible
    ? "Yes. This change can be reverted."
    : "This change would be hard to undo.";

  let onlyYou: string[] | undefined;
  if (p.disposition !== "auto-approved") {
    onlyYou = [];
    for (const w of p.whyAttention) onlyYou.push(w);
    if (p.verifyThis && p.verifyThis.trim()) onlyYou.push(`Check: ${p.verifyThis.trim()}`);
    onlyYou.push("Confirm that the change matches the outcome you want.");
  }

  const confidenceText = typeof p.confidence === "number"
    ? `Keep's reported confidence in these checks: ${Math.round(p.confidence * 100)}%. Review the change against your goal before deciding.`
    : undefined;

  const framing =
    p.disposition === "human-approval-required" ? "Review these points, then approve or decline."
    : p.disposition === "blocked" ? "A maintainer can review the reason for this block."
    : undefined;

  return {
    disposition: p.disposition,
    needsDecision: p.disposition !== "auto-approved",
    headline,
    whatItDoes: p.intent.trim() || "(no description was provided)",
    checked: p.evidence.map((f) => ({ label: f.label, value: f.value })),
    reversalText,
    ...(p.blastRadius.trim() ? { affects: p.blastRadius.trim() } : {}),
    ...(onlyYou ? { onlyYou } : {}),
    ...(confidenceText ? { confidenceText } : {}),
    ...(framing ? { framing } : {}),
  };
}

/** Render the view as plain text (for `keep review --plain`). */
export function renderNonEngineerView(p: DecisionPacket): string {
  const v = buildNonEngineerView(p);
  const L: string[] = [];
  L.push(v.headline);
  L.push("\nWhat it does:");
  L.push(`  ${v.whatItDoes}`);
  if (v.checked.length > 0) {
    L.push("\nWhat Keep checked:");
    for (const f of v.checked) L.push(`  • ${f.label}: ${f.value}`);
  }
  L.push("\nCan it be undone?");
  L.push(`  ${v.reversalText}`);
  if (v.affects) L.push(`  What it affects: ${v.affects}`);
  if (v.onlyYou) {
    L.push("\nYour review:");
    for (const item of v.onlyYou) L.push(`  • ${item}`);
  }
  if (v.confidenceText) L.push(`\n${v.confidenceText}`);
  if (v.framing) L.push(`\n${v.framing}`);
  return L.join("\n");
}
