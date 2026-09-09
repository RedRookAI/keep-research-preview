/**
 * THE ASK-GATE (moat-heart #1) — the humility valve: ask the human, or proceed autonomously?
 *
 * Keep's posture is autonomous-by-default, human-by-exception. The failure mode of most assistants is the inverse:
 * they ask whenever they are UNSURE (low classifier confidence), which floods the user with questions and defeats
 * autonomy. `intent_router` today does exactly this — ambiguity falls through to a clarifying question regardless of
 * stakes. That is the wrong gate.
 *
 * The right gate is VALUE OF INFORMATION. Asking is worth its cost only when the ambiguity is BOTH genuine AND
 * consequential: resolving it must avoid more expected loss than the autonomy cost of interrupting. So the gate is
 * scaled by CONSEQUENCE, not confidence:
 *   - reversible + uncertain      → PROCEED (reversibility beats asking; do it, let the user redirect cheaply).
 *   - reversible + very uncertain → PROCEED-WITH-NOTE (proceed on the best guess, but state the assumption).
 *   - irreversible + confident    → PROCEED (the action-side consequence-gate/veto still backstops the act itself).
 *   - irreversible + uncertain    → ASK (the ONE case worth a question: costly AND genuinely unclear).
 *   - unknown consequence         → precautionary (treated between reversible and irreversible).
 * This MINIMIZES asks and inverts the industry default, and it is invariant to a cold-start baseline (it uses only
 * intent-uncertainty + consequence — no personal cues/history — so it works correctly on turn 1).
 *
 * This is the "understand → ASK" valve of the moat-heart, sibling to `anticipate` ("predict"). It NEVER executes;
 * it returns a verdict. n=1 floor: the constant DEFAULT config (the degenerate zero-data case, mirroring
 * `floor_calibration`). Org: a calibrated config injected from (uncertainty, consequence, regret) records.
 *
 * BUILT + proven in-env: the VOI decision + consequence-scaling + verdict logic. SEAM: the consequence estimator
 * that classifies "what proceeding on a best guess would trigger" (a deployment supplies it; the front-door wiring
 * that consults this gate on the `ambiguous` branch is the next increment).
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
