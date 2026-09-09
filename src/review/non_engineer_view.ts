/**
 * Non-engineer review view (Increment S3). A plain-language rendering of the S1 DecisionPacket for someone who
 * can't read a diff — so they can exercise MEANINGFUL oversight, not rubber-stamp.
 *
 * SOTA basis (2026-08-06):
 *  - Rubber-stamping is THE default failure of non-expert oversight — reviewers "trust accurate systems, stop
 *    verifying, and approve by default while the paperwork records a human choice" (MIT Sloan; Masood 2026;
 *    Springer layered-agency 2026). Plain-language explanation of the basic logic + consequences is a prerequisite
 *    for oversight that isn't merely superficial (EU AI Act Art. 14).
 *  - Explain via EXTERNAL criteria (what the change does + its consequences), not model internals; the human's job
 *    is evaluative agency — verification, steering, substitution (Springer 2026).
 *  - Cognitive-forcing: surface the SPECIFIC thing to verify so the reviewer engages analytically (Buçinca 2021);
 *    state uncertainty and never argue one side (confirmation-bias mitigation, arXiv 2507.19486).
 *  - BUT don't overcorrect: forcing scrutiny on everything breeds fatigue + a bias against AI outputs, which loops
 *    back to rubber-stamping (arXiv 2502.10036). So PRESERVE THE DISPOSITION — only what needs a decision gets the
 *    analytical framing; routine auto-approved work is explicitly "optional spot-check, already verified."
 *
 * This module owns the CONTENT of the non-engineer view as a structured value (buildNonEngineerView). Both the
 * text renderer (here) and the web HTML renderer (S2) render from that one structure, so the neutrality (I2) and
 * disposition (I1) guarantees can never drift between the two surfaces. Non-persuasive by construction. Zero deps.
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
    p.disposition === "blocked" ? "⛔ Keep STOPPED this change. It will not proceed."
    : p.disposition === "auto-approved" ? "✓ This passed Keep's automated checks and was auto-approved. It does NOT need a decision from you — a quick spot-check is optional. (Nothing merges until a person approves the merge.)"
    : "This needs your decision. It will NOT proceed unless you approve it.";

  const reversalText = p.reversible
    ? "Yes — if this turns out wrong, it can be reverted."
    : "Not easily — this would be hard to undo, so it's worth looking carefully.";

  let onlyYou: string[] | undefined;
  if (p.disposition !== "auto-approved") {
    onlyYou = [];
    for (const w of p.whyAttention) onlyYou.push(w);
    if (p.verifyThis && p.verifyThis.trim()) onlyYou.push(`Check this specifically: ${p.verifyThis.trim()}`);
    onlyYou.push("Does this actually do what you wanted? Keep can't judge that — only you know what you intended.");
  }

  const confidenceText = typeof p.confidence === "number"
    ? `Keep's confidence in its own checks: ${Math.round(p.confidence * 100)}%. That's about the checks — not about whether this is what you meant.`
    : undefined;

  const framing =
    p.disposition === "human-approval-required" ? "Your call: approve only if you're satisfied with the points above. Keep is not recommending either way."
    : p.disposition === "blocked" ? "There is nothing to approve — Keep blocked it. If you believe that's wrong, a maintainer can review why."
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
    L.push("\nWhat Keep already checked for you:");
    for (const f of v.checked) L.push(`  • ${f.label}: ${f.value}`);
  }
  L.push("\nCan it be undone?");
  L.push(`  ${v.reversalText}`);
  if (v.affects) L.push(`  What it affects: ${v.affects}`);
  if (v.onlyYou) {
    L.push("\nWhat only you can decide:");
    for (const item of v.onlyYou) L.push(`  • ${item}`);
  }
  if (v.confidenceText) L.push(`\n${v.confidenceText}`);
  if (v.framing) L.push(`\n${v.framing}`);
  return L.join("\n");
}
