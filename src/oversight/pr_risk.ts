/**
 * PR risk assessment (Increment 15.5a).
 *
 * SOTA basis (2026-08-05): risk-tiered oversight is the dominant paradigm — classify by risk,
 * auto-approve the safe majority, focus human attention on the dangerous few (Changkun 2026). Gate on
 * REVERSIBILITY, BLAST RADIUS, DATA SENSITIVITY, CONFIDENCE, and CHANGE SIZE (Arthur 2026), not on
 * "is it a PR." Certain change types ALWAYS gate regardless of confidence (MetaCTO rule+confidence
 * hybrid): auth, crypto, migrations, secrets, protected paths. Every score carries its contributing
 * REASONS so a human can audit why a PR was tiered where it was (Arthur: "oversight is only governance
 * if you can prove it worked"). Pure policy logic — zero model calls, zero deps (works on free tier).
 *
 * This layer NEVER changes the merge gate. It only decides how loudly to ask the human.
 */

import type { PrProposal, SolveResult } from "../solve/issue_model.js";

export type RiskBand = "low" | "medium" | "high";

export interface RiskReason {
  readonly axis: "reversibility" | "blast-radius" | "sensitivity" | "confidence" | "size" | "rule";
  readonly detail: string;
  /** Signed contribution to the risk score (positive = riskier). */
  readonly weight: number;
}

export interface PrRiskScore {
  readonly band: RiskBand;
  /** 0..1, higher = riskier. */
  readonly score: number;
  readonly reasons: readonly RiskReason[];
  /** True if a rule-based always-gate path was touched (forces human review regardless of score). */
  readonly forcedGate: boolean;
  /** Band from blast + size + reversibility ONLY (excludes the confidence axis) — for merge-authority gating. */
  readonly consequenceBand: RiskBand;
}

export interface PrRiskInputs {
  readonly proposal: PrProposal;
  readonly result: SolveResult;
  /** Optional fan-in per file (how many files depend on it) from the code graph — higher = bigger blast. */
  readonly fanIn?: Readonly<Record<string, number>>;
  /** Optional override of the always-gate path patterns. */
  readonly alwaysGatePatterns?: readonly RegExp[];
}

/** Paths that ALWAYS require human review regardless of confidence (rule-based tier, MetaCTO 2026). */
export const DEFAULT_ALWAYS_GATE_PATTERNS: readonly RegExp[] = [
  /(^|\/)auth(entication|orization)?\b/i,
  /(crypto|encrypt|decrypt|secret|credential|password|passwd|token|apikey|api[_-]?key|private[_-]?key|oauth|\.pem|\.key)/i,
  /(^|\/)(migrations?|schema)\//i,
  /\.(sql)$/i,
  /(^|\/)(security|iam|rbac|acl)\b/i,
  /(dockerfile|\.github\/workflows\/|deploy|infra|terraform|k8s|kubernetes)/i,
  /(^|\/)(payment|billing|charge)\b/i,
];

export class PrRiskAssessor {
  private readonly alwaysGate: readonly RegExp[];
  constructor(opts: { alwaysGatePatterns?: readonly RegExp[] } = {}) {
    this.alwaysGate = opts.alwaysGatePatterns ?? DEFAULT_ALWAYS_GATE_PATTERNS;
  }

  assess(inputs: PrRiskInputs): PrRiskScore {
    const { proposal, result } = inputs;
    const reasons: RiskReason[] = [];
    const files = [...new Set(proposal.edits.map((e) => e.file))];

    // ── rule-based always-gate (overrides everything) ──
    let forcedGate = false;
    for (const f of files) {
      const hit = this.alwaysGate.find((re) => re.test(f));
      if (hit) {
        forcedGate = true;
        reasons.push({ axis: "rule", detail: `sensitive path '${f}' always requires human review`, weight: 1 });
      }
    }

    // ── confidence (from solve validation) ── lower confidence = higher risk
    const v = result.validation;
    let confidenceRisk = 0.5;
    if (v) {
      confidenceRisk = 0;
      if (!v.testsPassed) { confidenceRisk += 0.6; reasons.push({ axis: "confidence", detail: "tests did not all pass", weight: 0.6 }); }
      if (!v.vettingCleared) { confidenceRisk += 0.3; reasons.push({ axis: "confidence", detail: "vetting did not clear", weight: 0.3 }); }
      if (result.repairRounds > 0) {
        const w = Math.min(0.2, result.repairRounds * 0.1);
        confidenceRisk += w;
        reasons.push({ axis: "confidence", detail: `needed ${result.repairRounds} repair round(s)`, weight: w });
      }
      if (v.testsPassed && v.vettingCleared && result.repairRounds === 0) {
        reasons.push({ axis: "confidence", detail: "clean solve: tests + vetting passed, no repair", weight: -0.1 });
      }
    } else {
      reasons.push({ axis: "confidence", detail: "no validation present — treated as uncertain", weight: 0.5 });
    }

    // ── blast radius (files touched + fan-in) ──
    let blast = 0;
    const fileCountRisk = Math.min(0.4, Math.max(0, (files.length - 1) * 0.12));
    if (fileCountRisk > 0) { blast += fileCountRisk; reasons.push({ axis: "blast-radius", detail: `${files.length} files touched`, weight: fileCountRisk }); }
    if (inputs.fanIn) {
      const maxFan = Math.max(0, ...files.map((f) => inputs.fanIn![f] ?? 0));
      if (maxFan >= 3) {
        const w = Math.min(0.3, maxFan * 0.05);
        blast += w;
        reasons.push({ axis: "blast-radius", detail: `high fan-in (${maxFan} dependents) — widely depended upon`, weight: w });
      }
    }

    // ── change size (diff magnitude, proxied by replacement text length) ──
    const totalChars = proposal.edits.reduce((s, e) => s + e.search.length + e.replace.length, 0);
    let sizeRisk = 0;
    if (totalChars > 2000) { sizeRisk = 0.3; reasons.push({ axis: "size", detail: `large change (~${totalChars} chars)`, weight: 0.3 }); }
    else if (totalChars > 600) { sizeRisk = 0.15; reasons.push({ axis: "size", detail: `moderate change (~${totalChars} chars)`, weight: 0.15 }); }

    // ── reversibility (Keep edits are revert-safe by construction; deletions/large rewrites lower it) ──
    const looksDestructive = proposal.edits.some((e) => e.replace.trim() === "" && e.search.trim().length > 40);
    let reversibilityRisk = 0;
    if (looksDestructive) { reversibilityRisk = 0.2; reasons.push({ axis: "reversibility", detail: "contains large deletion(s)", weight: 0.2 }); }
    else reasons.push({ axis: "reversibility", detail: "revert-safe search/replace edits", weight: -0.05 });

    // ── aggregate ──
    const raw = confidenceRisk + blast + sizeRisk + reversibilityRisk;
    const score = clamp01(raw);
    let band: RiskBand = score >= 0.6 ? "high" : score >= 0.3 ? "medium" : "low";
    if (forcedGate) band = "high"; // rule override

    // Consequence-only band (blast + size + reversibility, EXCLUDING confidence). The merge-authority decision
    // gates a human on consequence, not on uncertainty, so it must see risk independent of how the solve went.
    const consequenceRaw = clamp01(blast + sizeRisk + reversibilityRisk);
    let consequenceBand: RiskBand = consequenceRaw >= 0.6 ? "high" : consequenceRaw >= 0.3 ? "medium" : "low";
    if (forcedGate) consequenceBand = "high";

    return { band, score, reasons, forcedGate, consequenceBand };
  }
}

function clamp01(x: number): number { return x < 0 ? 0 : x > 1 ? 1 : x; }
