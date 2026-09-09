/**
 * ANTICIPATION ENGINE — Round 4 of the personalization moat (Horvitz-calibrated proactivity).
 *
 * Horvitz's mixed-initiative principles (1999): intervene only when calibrated to CONFIDENCE and the COST OF
 * ERRORS; weigh the user's ATTENTION; MINIMIZE the cost of poor guesses; leave the user in control. The 2026
 * refinement is "always-on, not-always-speaking": notice a context shift, infer whether it matters, and choose
 * notify / question / draft / STAY SILENT — after SIMULATING the intervention (vet before surfacing).
 *
 * The research reshaped this round. Naive "predict and do" causes DESKILLING (skill atrophy) and AUTOMATION
 * COMPLACENCY — the rubber-stamp trap ("operators did not assess the recommendation and simply complied") — and
 * anticipatory help BACKFIRES via self-threat (it can feel like the system thinks you're incompetent). So the
 * engine is MINIMUM-INTERVENTION: it automates toil but preserves judgment, NEVER rubber-stamps, and prefers
 * PREPARE-SILENTLY / OFFER-ON-PULL over interrupt-on-push. It surfaces (interrupts) only when utility ≫
 * interruption-cost AND the action is low-consequence AND reversible AND the engine is confident. A CONSEQUENTIAL
 * action is never surfaced and never auto-done — it is at most offered for the human to decide (gate-on-
 * consequence). Sensitive context is read THROUGH Round 1's CI vault, which governs cross-context egress.
 *
 * BUILT + proven in-env: the vet / calibration / consequence-gate / pull-vs-push LOGIC. SEAM: the intent/next-need
 * predictor and the context-shift detector (they supply the candidate's utility, interruption cost, confidence,
 * and consequence class — the perception; the decision is deterministic).
 */

import { successLCB, type SuccessPosterior } from "../routing/uncertainty_router.js";
import type { SensitiveContextVault, VaultEntry, FlowRequest } from "../privacy/contextual_integrity.js";

/** Only surface (interrupt) when net value clears this margin; below it, prepare and offer on pull. */
const SURFACE_MARGIN = 3;
/** Only surface when the pessimistic confidence (LCB) clears this — minimize the cost of a poor guess. */
const CONF_THRESHOLD = 0.5;

export type Disposition = "prepare-silently" | "offer-on-pull" | "surface" | "stay-silent";

export interface CandidateNeed {
  readonly description: string;
  /** SEAM (predicted): expected benefit if acted on. */
  readonly utility: number;
  /** SEAM (predicted): cost of interrupting the user now (weighs their attention). */
  readonly interruptionCost: number;
  /** consequence class — a consequential action is never surfaced/auto-done. */
  readonly consequence: "reversible" | "consequential";
  /** did the candidate clear vetting (plan-vetting)? An un-vettable candidate is never surfaced. */
  readonly vettable: boolean;
  /** the routers' posterior on "this is genuinely what they want". */
  readonly confidence: SuccessPosterior;
}

export interface Decision {
  readonly disposition: Disposition;
  /** transparent WHY (anti-self-threat: the user can always see the reasoning). */
  readonly reason: string;
  /** structural: the engine NEVER executes; it only decides a disposition. Always false. */
  readonly autoExecuted: false;
}

/** Optional sensitive-context read: a candidate DERIVED from a user's sensitive disclosure must clear the CI
 *  vault's egress gate for the anticipation purpose+recipient before it may be used. */
export interface SensitiveRead {
  readonly vault: SensitiveContextVault;
  readonly entry: VaultEntry;
  readonly request: FlowRequest;
}

export interface AnticipateOptions {
  readonly sensitive?: SensitiveRead | undefined;
}

/**
 * Resolve a candidate need to a disposition. Deterministic. Defaults to pull over push; never auto-executes;
 * never surfaces a consequential action; reads sensitive context only through the CI vault.
 */
export function anticipate(candidate: CandidateNeed, opts?: AnticipateOptions): Decision {
  // Sensitive context is read THROUGH the vault: if the candidate depends on sensitive context that may not flow
  // for this purpose/recipient, it cannot be used — stay silent rather than leak.
  if (opts?.sensitive !== undefined) {
    const { vault, entry, request } = opts.sensitive;
    if (!vault.mayFlow(entry, request)) {
      return { disposition: "stay-silent", reason: "sensitive context not permitted to flow for this purpose", autoExecuted: false };
    }
  }

  // VET first — an un-vettable candidate is never surfaced (simulate before surfacing).
  if (!candidate.vettable) {
    return { disposition: "stay-silent", reason: "candidate did not clear vetting", autoExecuted: false };
  }

  const conf = successLCB(candidate.confidence); // pessimistic confidence — minimize the cost of a poor guess
  const net = candidate.utility - candidate.interruptionCost;

  // GATE ON CONSEQUENCE: a consequential action is NEVER surfaced or auto-done — at most offered for the human to
  // decide (no rubber-stamp, no deskilling of the meaningful decision).
  if (candidate.consequence === "consequential") {
    return net > 0
      ? { disposition: "offer-on-pull", reason: "consequential ⇒ offered for the human to decide, never auto-done", autoExecuted: false }
      : { disposition: "stay-silent", reason: "consequential and not worth the user's attention", autoExecuted: false };
  }

  // reversible + low-consequence:
  if (net <= 0) {
    return { disposition: "stay-silent", reason: "interruption cost outweighs the benefit", autoExecuted: false };
  }
  if (net >= SURFACE_MARGIN && conf >= CONF_THRESHOLD) {
    return { disposition: "surface", reason: "high utility, low interruption, confident, reversible", autoExecuted: false };
  }
  // DEFAULT: prepare and offer on pull rather than interrupt (prefer pull over push).
  return { disposition: "offer-on-pull", reason: "prepared; offered on pull (default: pull over push)", autoExecuted: false };
}
