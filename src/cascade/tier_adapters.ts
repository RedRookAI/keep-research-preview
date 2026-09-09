/**
 * Domain tier adapters (Increment 3.9c) — concrete tiers wrapping existing checks.
 *
 * The cascade is "mostly composition" (spec §5): these adapters plug Keep's existing sound checks
 * in as tiers. The headline is LogicVetFloorTier — the deterministic critics from item 3.8 ARE the
 * Tier-0 sound floor, so a sound block short-circuits the whole cascade (soundness dominates). The
 * single-brain and external-brain tiers are ports: the one-key operator runs Tiers 0-1; a fleet
 * operator additionally runs Tier 2 on the residual. One architecture, graceful either way.
 *
 * Zero deps.
 */

import type { VerificationItem, VerificationTier, TierResult } from "./verification_cascade.js";
import { deterministicCritics, type Plan, type PlanConstraints } from "../logicvet/deterministic_critics.js";
import { consensus, type VetPosture } from "../logicvet/consensus.js";

/** Payload for a logic-vetting item. */
export interface PlanVetPayload {
  readonly plan: Plan;
  readonly constraints: PlanConstraints;
  readonly posture: VetPosture;
}

/**
 * TIER 0 — the deterministic LogicVet floor. Runs the sound critics (order/constraint/proportion/
 * contradiction). A sound block → `fail` (short-circuits; cannot be overturned above). A clean pass
 * → `pass`. Concerns (rework) → `undecided` (climb for a brain to weigh in). Zero models.
 */
export class LogicVetFloorTier implements VerificationTier<PlanVetPayload> {
  readonly tier = 0;
  readonly name = "logicvet-deterministic-floor";
  readonly sound = true;
  available(): boolean {
    return true; // the floor is ALWAYS available (no brain needed)
  }
  verify(item: VerificationItem<PlanVetPayload>): TierResult {
    const { plan, constraints, posture } = item.payload;
    const critics = deterministicCritics(plan, constraints);
    const verdict = consensus(critics, posture);
    if (verdict.decision === "block") {
      return { tier: 0, name: this.name, decision: "fail", reason: verdict.reason, sound: true, certainty: 1 };
    }
    if (verdict.decision === "pass") {
      return { tier: 0, name: this.name, decision: "pass", reason: verdict.reason, sound: true, certainty: 1 };
    }
    // rework/concern → the floor can't decide alone; a brain should look. Undecided (climb).
    return { tier: 0, name: this.name, decision: "undecided", reason: verdict.reason, sound: true, certainty: 0.5 };
  }
}

/** A single-brain self-verification function (flag-only on fuzzy dims). Injected. */
export type SingleBrainVerifier<T> = (item: VerificationItem<T>) => { decision: "pass" | "fail" | "undecided"; reason: string; certainty: number };

/**
 * TIER 1 — the single brain (the operator's one model). Selective self-verification: it resolves
 * the floor's residual, but on fuzzy dimensions it FLAGS rather than blesses (never sound).
 */
export class SingleBrainTier<T> implements VerificationTier<T> {
  readonly tier = 1;
  readonly name = "single-brain";
  readonly sound = false;
  constructor(private readonly verifier: SingleBrainVerifier<T>) {}
  available(): boolean {
    return true;
  }
  verify(item: VerificationItem<T>): TierResult {
    const r = this.verifier(item);
    return { tier: 1, name: this.name, decision: r.decision, reason: r.reason, sound: false, certainty: r.certainty };
  }
}

/** An external/second-brain reviewer (independent of the author). Injected; may be absent. */
export type ExternalBrainReviewer<T> = (item: VerificationItem<T>) => { decision: "pass" | "fail" | "undecided"; reason: string; certainty: number };

/**
 * TIER 2 — the external / second brain. Available ONLY when an independent reviewer is registered;
 * otherwise the cascade skips it cleanly (single-model degradation). Runs on the residual only.
 */
export class ExternalBrainTier<T> implements VerificationTier<T> {
  readonly tier = 2;
  readonly name = "external-second-brain";
  readonly sound = false;
  constructor(private readonly reviewer: ExternalBrainReviewer<T> | undefined) {}
  available(): boolean {
    return this.reviewer !== undefined;
  }
  verify(item: VerificationItem<T>): TierResult {
    if (!this.reviewer) {
      return { tier: 2, name: this.name, decision: "undecided", reason: "no external brain registered", sound: false, certainty: 0 };
    }
    const r = this.reviewer(item);
    return { tier: 2, name: this.name, decision: r.decision, reason: r.reason, sound: false, certainty: r.certainty };
  }
}

/**
 * TIER 3 — the human. Terminal; always "undecided" from the machine's view, which the cascade
 * interprets as escalate-human. Present so the ladder is explicit and auditable.
 */
export class HumanTier<T> implements VerificationTier<T> {
  readonly tier = 3;
  readonly name = "human";
  readonly sound = false;
  available(): boolean {
    return true;
  }
  verify(_item: VerificationItem<T>): TierResult {
    return { tier: 3, name: this.name, decision: "undecided", reason: "deferred to human review", sound: false, certainty: 0 };
  }
}

/**
 * Assemble the standard tier set for logic vetting: deterministic floor + single brain + (optional)
 * external brain + human. Pass `externalReviewer=undefined` for a one-key operator (Tiers 0-1-3).
 */
export function logicVettingTiers(
  singleBrain: SingleBrainVerifier<PlanVetPayload>,
  externalReviewer?: ExternalBrainReviewer<PlanVetPayload>,
): VerificationTier<PlanVetPayload>[] {
  return [
    new LogicVetFloorTier(),
    new SingleBrainTier<PlanVetPayload>(singleBrain),
    new ExternalBrainTier<PlanVetPayload>(externalReviewer),
    new HumanTier<PlanVetPayload>(),
  ];
}
