/**
 * Decides whether resolving intent uncertainty justifies interrupting the user.
 *
 * Uses value of information and consequence, with proceed, proceed-with-note and ask verdicts.
 * It returns a verdict and never executes an action. Execution still requires its own authority checks.
 * The default configuration needs no personal history; deployments can inject calibrated parameters.
 */

import type { ConsequenceClass } from "../routing/uncertainty_router.js";

export type AskVerdict = "proceed" | "proceed-with-note" | "ask";

export interface AskGateInput {
  /** Uncertainty about the user's intent, 0..1 (e.g. 1 - intent-router confidence). */
  readonly intentUncertainty: number;
  /** The consequence of PROCEEDING on a best-guess interpretation (reversible / irreversible / unknown). */
  readonly consequence: ConsequenceClass;
}

export interface AskGateConfig {
  /** How costly a wrong best-guess is, per consequence class. Irreversible ≫ reversible. */
  readonly lossWeight: Readonly<Record<ConsequenceClass, number>>;
  /** The autonomy cost of interrupting to ask — the floor the value-of-information must clear. Minimize-asks knob. */
  readonly askCost: number;
  /** On a reversible action above this uncertainty, PROCEED-WITH-NOTE (state the assumption) rather than silently. */
  readonly noteThreshold: number;
}

/** n=1 floor defaults (the zero-data case). Reversible loss is low, irreversible high, unknown precautionary. */
export const DEFAULT_ASK_GATE_CONFIG: AskGateConfig = {
  lossWeight: { reversible: 0.1, irreversible: 1.0, unknown: 0.7 },
  askCost: 0.15,
  noteThreshold: 0.5,
};

export interface AskDecision {
  readonly verdict: AskVerdict;
  /** The computed value of information of asking (expected loss avoided − ask cost). Ask iff > 0. */
  readonly valueOfInformation: number;
  /** Transparent WHY. */
  readonly rationale: string;
}

function clamp01(x: number): number {
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

/**
 * The gate. VOI(ask) ≈ (intentUncertainty × loss-if-wrong) − askCost, where loss-if-wrong is CONSEQUENCE-SCALED.
 * Ask iff VOI > 0. Neutering the consequence-scaling (a constant lossWeight) collapses the gate to confidence-only
 * — it then asks on reversible trivia OR proceeds on the irreversible-and-uncertain — which is the disproof.
 */
export function decideAsk(input: AskGateInput, cfg: AskGateConfig = DEFAULT_ASK_GATE_CONFIG): AskDecision {
  const u = clamp01(input.intentUncertainty);
  const loss = cfg.lossWeight[input.consequence];
  const voi = u * loss - cfg.askCost;

  if (voi > 0) {
    return {
      verdict: "ask",
      valueOfInformation: voi,
      rationale: `uncertain (${u.toFixed(2)}) AND ${input.consequence} (loss ${loss.toFixed(2)}): value of asking ${voi.toFixed(2)} > 0`,
    };
  }
  if (input.consequence === "reversible" && u >= cfg.noteThreshold) {
    return {
      verdict: "proceed-with-note",
      valueOfInformation: voi,
      rationale: `reversible but uncertain (${u.toFixed(2)}): proceed on the best guess and state the assumption`,
    };
  }
  return {
    verdict: "proceed",
    valueOfInformation: voi,
    rationale: `value of asking ${voi.toFixed(2)} ≤ 0: proceed autonomously`,
  };
}

/** Convenience: derive uncertainty from an intent-router confidence (0..1) and apply the gate. */
export function decideAskFromConfidence(
  intentConfidence: number,
  consequence: ConsequenceClass,
  cfg: AskGateConfig = DEFAULT_ASK_GATE_CONFIG,
): AskDecision {
  return decideAsk({ intentUncertainty: 1 - clamp01(intentConfidence), consequence }, cfg);
}

/**
 * The gate as an injectable object (carries a config for the org-calibrated track; defaults for the n=1 floor).
 * A deployment calibrates `askCost`/`lossWeight` from observed (uncertainty, consequence, regret) records; the
 * constant defaults are the honest zero-data fallback.
 */
export class AskGate {
  constructor(private readonly cfg: AskGateConfig = DEFAULT_ASK_GATE_CONFIG) {}

  decide(input: AskGateInput): AskDecision {
    return decideAsk(input, this.cfg);
  }

  fromConfidence(intentConfidence: number, consequence: ConsequenceClass): AskDecision {
    return decideAskFromConfidence(intentConfidence, consequence, this.cfg);
  }
}
