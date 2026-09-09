/**
 * DecisionPacketAssembler (Increment S1) — fuse everything a reviewer needs into ONE standard packet, rendered
 * identically by the CLI (now) and the web review UI (later). This is the "make the moat legible" surface: the
 * point where execution evidence, consequence forecast, semantic-correctness, and reversibility become visible
 * at approval time.
 *
 * It does NOT duplicate existing work — it CONSUMES the DecisionBrief (16.9b), the ForecastVerdict
 * (consequence_forecast), and the PrManifest, and composes them behind one shape + one renderer.
 *
 * SOTA basis (2026-08-05, re-verified this increment — the counterintuitive constraint still holds):
 *  - "Review the code, not the story": reviewers need an EVIDENCE view grounded in EXECUTED artifacts, not an
 *    author-controlled narrative (arXiv 2606.07683). Narrative rationales make oversight WORSE — deference rises
 *    when the AI explains persuasively (the DecisionBrief's founding constraint). → the packet leads with what
 *    Keep RAN and what it would touch; the "why" is factual, never persuasive.
 *  - The minimum decision packet is exact action, changed state, authority, evidence, uncertainty, alternatives,
 *    limits on reversal — hiding any of these "adds latency without oversight" (Edilec 2026-07). → the packet
 *    carries all of them as fields.
 *  - Structured uncertainty, not a second recommendation: surface the ONE specific thing to verify as an action,
 *    not a consensus to rubber-stamp (Pfuetze 2026). → `verifyThis` is a question, sourced from the brief.
 *  - Progressive disclosure WITHOUT hiding material facts; match review depth to reversibility + impact (Edilec,
 *    getclaw). → compact by default, `full` expands diff+trace; irreversible/high-band forces the richer view.
 *
 * Zero runtime deps. Pure and deterministic (no model calls) — the packet is assembled from structured verdicts.
 */

import type { PrManifest } from "../git/pull_request.js";
import type { DecisionBrief } from "../pipeline/decision_brief.js";
import type { ForecastVerdict } from "../pipeline/consequence_forecast.js";

/** A labelled fact the reviewer positively acknowledges (mirrors the brief's BriefItem; a fact, not advice). */
export interface PacketFact {
  readonly label: string;
  readonly value: string;
}

/** The standard, surface-agnostic decision packet (Edilec-minimum fields). */
export interface DecisionPacket {
  readonly id: string;
  /** INTENT — what the human asked for (the approved goal). */
  readonly intent: string;
  /** CHANGED STATE — the unified diff (the exact delta). */
  readonly diff: string;
  /** EXECUTED — what Keep actually did, per edit (factual, no adjectives). */
  readonly executed: readonly string[];
  /** EVIDENCE — the checks Keep RAN (execution-adjudicated), what the machine verified. */
  readonly evidence: readonly PacketFact[];
  /** REVERSIBILITY — is the change reversible/bounded, and the blast-radius read. */
  readonly reversible: boolean;
  readonly blastRadius: string;
  /** UNCERTAINTY — calibrated confidence (0..1), surfaced selectively (low or high-stakes). */
  readonly confidence?: number;
  /** WHY ATTENTION — the factual triggers that routed this to a human (never persuasion). */
  readonly whyAttention: readonly string[];
  /** THE ONE THING TO VERIFY — structured uncertainty as an action, not a conclusion. */
  readonly verifyThis?: string;
  /** ATTENTION BAND — how loudly this asks for review (never affects the merge gate). */
  readonly band: "low" | "medium" | "high";
  /** DISPOSITION — the machine vetting's verdict: whether the human is even needed here (risk-tiered). */
  readonly disposition: "auto-approved" | "human-approval-required" | "blocked";
  /** Whether the machine routed this to the human as needing prompt attention (the dangerous few). */
  readonly requiresImmediateAttention: boolean;
  /** REVIEW DEPTH — compact (reversible/low) vs full (irreversible/high). Scales the renderer. */
  readonly depth: "compact" | "full";
  /** Attribution for the audit record. */
  readonly attribution: string;
}

export interface AssembleInputs {
  readonly manifest: PrManifest;
  readonly brief?: DecisionBrief;
  readonly forecast?: ForecastVerdict;
  readonly confidence?: number;
}

/**
 * Assemble the packet from the manifest + (optional) brief + forecast + confidence. Everything degrades
 * gracefully: absent a brief/forecast, the packet still carries the manifest's own evidence and oversight —
 * the packet is never blocked on an optional input (N=1 / free-tier produces a valid packet).
 */
export function assembleDecisionPacket(inputs: AssembleInputs): DecisionPacket {
  const { manifest: m, brief, forecast, confidence } = inputs;
  const band = m.oversight?.band ?? "medium";
  // The machine vetting's verdict. Safe default when absent: require a human decision (never silently auto-clear).
  const disposition = m.oversight?.disposition ?? "human-approval-required";
  const requiresImmediateAttention = m.oversight?.requiresImmediateAttention ?? true;

  // EVIDENCE: the checks Keep ran (execution-adjudicated) — evidence-first, not narrative.
  const evidence: PacketFact[] = m.checks.map((c) => ({ label: c.name, value: c.passed ? "passed" : "did not pass" }));
  // Fold in the brief's challenge-and-response facts (also non-persuasive), de-duplicated by label.
  if (brief) {
    const seen = new Set(evidence.map((e) => e.label.toLowerCase()));
    for (const f of brief.facts) if (!seen.has(f.label.toLowerCase())) evidence.push({ label: f.label, value: f.value });
  }

  // REVERSIBILITY + BLAST RADIUS: prefer the forecast (forward, multi-order), fall back to the brief.
  const reversible = forecast ? forecast.reachedSinks.length === 0 && forecast.risks.every((r) => r.reversible) : (brief?.reversible ?? true);
  const blastRadius = describeBlast(forecast, reversible);

  // WHY ATTENTION: the factual triggers (the brief's routedBecause + the oversight reasons), de-duplicated.
  const whyAttention = dedupe([...(brief?.routedBecause ?? []), ...(m.oversight?.reasons ?? [])]);

  // REVIEW DEPTH: irreversible or high-band → full (richer evidence); else compact (Edilec: match depth to risk).
  const depth: DecisionPacket["depth"] = !reversible || band === "high" ? "full" : "compact";

  return {
    id: m.id,
    intent: brief?.whatChanges ?? m.intent,
    diff: m.diff,
    executed: m.executed,
    evidence,
    reversible,
    blastRadius,
    ...(confidence !== undefined ? { confidence } : {}),
    whyAttention,
    ...(brief?.verifyThis ? { verifyThis: brief.verifyThis } : {}),
    band,
    disposition,
    requiresImmediateAttention,
    depth,
    attribution: m.attribution,
  };
}

function describeBlast(forecast: ForecastVerdict | undefined, reversible: boolean): string {
  if (!forecast) return reversible ? "reversible, bounded" : "not fully reversible — review carefully";
  if (forecast.reachedSinks.length > 0) {
    const sinks = forecast.reachedSinks.map((s) => s.sink).join(", ");
    return `reaches sensitive outcome(s): ${sinks} (up to order ${forecast.maxOrder}) — irreversible/high-blast`;
  }
  return reversible ? `reversible, bounded (no sensitive sinks reached; max order ${forecast.maxOrder})` : "bounded but not fully reversible";
}

function dedupe(items: readonly string[]): string[] {
  const seen = new Set<string>(); const out: string[] = [];
  for (const i of items) { const k = i.trim().toLowerCase(); if (k && !seen.has(k)) { seen.add(k); out.push(i); } }
  return out;
}

/**
 * Render the packet for a text surface (the CLI now; the web UI reuses the same field set). Progressive
 * disclosure: `compact` shows identity/intent/executed/evidence/blast/attention + the one-verify; `full`
 * additionally shows the diff. Framed as "you're confirming, not catching" — the machine did the scrutiny.
 */
export function renderPacket(p: DecisionPacket, opts: { full?: boolean } = {}): string {
  const full = opts.full || p.depth === "full";
  const executed = p.executed.length ? p.executed.map((e) => `  - ${e}`).join("\n") : "  (no summary)";
  const evidence = p.evidence.length ? p.evidence.map((e) => `  - ${e.label}: ${e.value}`).join("\n") : "  (no checks)";
  const why = p.whyAttention.length ? p.whyAttention.map((r) => `  - ${r}`).join("\n") : "  - routine, reversible change";
  const conf = p.confidence !== undefined && (p.confidence < 0.6 || p.band === "high")
    ? `\nConfidence: ${(p.confidence * 100).toFixed(0)}% ${p.confidence < 0.6 ? "(lower than usual — look closely)" : ""}`
    : "";
  const diffBlock = full
    ? `\nThe change (diff):\n${p.diff.length > 6000 ? p.diff.slice(0, 6000) + "\n… (diff truncated; full diff in the audit record)" : p.diff}`
    : `\n(${countDiffLines(p.diff)} changed line(s). Run \`keep review ${p.id} --full\` to see the diff.)`;
  const dispositionLine = p.disposition === "auto-approved"
    ? `Keep's verification cleared this and auto-approved it for batch review — nothing is merged. You're spot-checking already-vetted work; approving is optional confirmation, not a required gate.`
    : `Keep's verification routed this to you for a decision${p.requiresImmediateAttention ? " (please look soon)" : ""}. It does not proceed without you.`;
  return [
    `\n═══ Review: ${p.id}  [${p.band}]  ${p.reversible ? "reversible" : "NOT fully reversible"} ═══`,
    dispositionLine,
    `What you asked for:\n  ${p.intent}`,
    `What Keep did:\n${executed}`,
    `What Keep verified (you're confirming, not catching):\n${evidence}`,
    `Reversibility / reach:\n  ${p.blastRadius}`,
    `Why this needs your attention:\n${why}${conf}`,
    p.verifyThis ? `Before you approve, please verify:\n  ${p.verifyThis}` : "",
    diffBlock,
    `\nKeep proposes; you dispose. Approving records your decision; it does not auto-merge.`,
  ].filter(Boolean).join("\n\n");
}

function countDiffLines(diff: string): number {
  return diff.split("\n").filter((l) => (l.startsWith("+") || l.startsWith("-")) && !l.startsWith("+++") && !l.startsWith("---")).length;
}
