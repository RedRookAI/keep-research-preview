/**
 * Autonomy calibration — tuning the ask-vs-proceed balance in a research-backed way.
 *
 * The problem (empirically real): over-asking is not merely annoying, it is a SAFETY
 * failure. Telemetry shows users approve ~93% of prompts and become "button mashers";
 * over-restriction also causes disuse and excess workload (adaptive-trust literature).
 * Under- and over-restriction are both first-class risks. This layer hits the balance:
 *
 *  1. USER-SELECTABLE AUTONOMY LEVEL (Feng, McDonald & Zhang 2025 — the canonical "levels
 *     of autonomy"): the operator chooses their seat. Autonomy is "a deliberate design
 *     decision, separate from capability." Some operators want to approve everything
 *     risky; some want to be told after. Forcing one level on everyone handicaps autonomy.
 *
 *  2. MULTI-SIGNAL CRITICALITY (Ericsson GRV 2607.02210; reversibility is "an agency
 *     property of available actions — determined by tool semantics and rollback cost",
 *     arXiv 2605.12105): score reversibility + rollback cost + scope + novelty, rather
 *     than a binary tier, and gate at the "commit point" (reversible -> side-effect).
 *
 *  3. CALIBRATION FROM CORRECTIONS (The Oversight Game 2510.26752): coordination on when
 *     to ask emerges from the operator's own past approve/deny decisions. Keep asks LESS
 *     over time on classes this operator consistently approves, stays cautious elsewhere.
 *
 * HARD CEILING: none of this touches the irreversible/destructive floor. Those remain
 * structurally human-gated (Article 5, non-overridable). Autonomy levels only ever
 * modulate the REVERSIBLE + external-confidence band. Zero deps.
 */

import type { ActionKind } from "./action_schema.js";

/**
 * The operator's seat (Feng et al.). Higher = more agent autonomy in the REVERSIBLE band
 * only. None of these can auto-approve irreversible/destructive actions.
 */
export type AutonomyLevel =
  | "observer" // agent proposes; human approves nearly everything (max oversight)
  | "approver" // human approves external-touching + medium-risk; internal auto-flows
  | "collaborator" // DEFAULT: reversible auto-flows; external/medium asks; irreversible always asks
  | "operator" // reversible + vetted-external auto-flows at lower confidence; irreversible always asks
  | "delegator"; // maximum hands-off within the reversible band; irreversible STILL always asks

const LEVEL_ORDER: readonly AutonomyLevel[] = ["observer", "approver", "collaborator", "operator", "delegator"];

/** Per-level external-confidence threshold: higher autonomy => lower bar in reversible band. */
const CONFIDENCE_THRESHOLD_BY_LEVEL: Record<AutonomyLevel, number> = {
  observer: 0.95, // almost always ask
  approver: 0.85,
  collaborator: 0.7, // default
  operator: 0.55,
  delegator: 0.4, // hands-off within reversible band (never below the floor)
};

/** Signals that compose the criticality score (0..1; higher = more consequential). */
export interface CriticalitySignals {
  /** 0 = fully reversible, 1 = irreversible. */
  readonly irreversibility: number;
  /** 0 = trivial rollback, 1 = very costly/impossible to roll back. */
  readonly rollbackCost: number;
  /** 0 = single local artifact, 1 = broad/production/external blast radius. */
  readonly scope: number;
  /** 0 = routine/seen-before, 1 = novel/never-done capability. */
  readonly novelty: number;
}

/** Weighted criticality per the GRV multi-dimensional model. Weights sum to 1. */
export function criticalityScore(s: CriticalitySignals): number {
  const score = 0.35 * s.irreversibility + 0.25 * s.rollbackCost + 0.15 * s.scope + 0.25 * s.novelty;
  return Math.max(0, Math.min(1, score));
}

/**
 * Per-action-class calibration learned from the operator's own decisions. Tracks how
 * often this operator approves a given action kind; a consistently-approved reversible
 * class earns a small confidence discount (ask less), a consistently-denied class earns
 * a surcharge (ask more). Bounded so it can never cross the safety floor.
 */
export class AutonomyCalibration {
  // kind -> {appro}/{deny} counts of PAST human decisions on reversible actions.
  private readonly approvals = new Map<ActionKind, number>();
  private readonly denials = new Map<ActionKind, number>();

  /** Record a past human decision for a reversible-band action (calibration signal). */
  record(kind: ActionKind, approved: boolean): void {
    const map = approved ? this.approvals : this.denials;
    map.set(kind, (map.get(kind) ?? 0) + 1);
  }

  /**
   * A confidence adjustment in [-0.15, +0.2] for this action kind based on history.
   * Positive = this operator reliably approves it -> we can require slightly less
   * behavioral confidence (ask less). Negative = they push back -> require more (ask more).
   * Needs a minimum sample before nudging (avoid over-fitting one click).
   */
  adjustmentFor(kind: ActionKind): number {
    const a = this.approvals.get(kind) ?? 0;
    const d = this.denials.get(kind) ?? 0;
    const n = a + d;
    if (n < 3) return 0; // not enough evidence yet
    const approvalRate = a / n;
    if (approvalRate >= 0.9) return Math.min(0.2, 0.05 * Math.log2(n)); // reliably approved -> ask less
    if (approvalRate <= 0.4) return -Math.min(0.15, 0.05 * Math.log2(n)); // pushed back -> ask more
    return 0;
  }
}

export interface AutonomyProfile {
  readonly level: AutonomyLevel;
  /** Effective external-confidence threshold for the reversible band. */
  readonly reversibleConfidenceThreshold: number;
  /** Criticality above which we always ask, regardless of level (safety ceiling). */
  readonly alwaysAskAboveCriticality: number;
}

/**
 * Build the effective profile for a decision: the level's base threshold, adjusted by
 * per-class calibration, with a HARD criticality ceiling that no level can cross.
 */
export function autonomyProfileFor(
  level: AutonomyLevel,
  kind: ActionKind,
  calibration?: AutonomyCalibration,
): AutonomyProfile {
  const base = CONFIDENCE_THRESHOLD_BY_LEVEL[level];
  const adj = calibration?.adjustmentFor(kind) ?? 0;
  // A positive adjustment LOWERS the threshold (ask less); negative RAISES it (ask more).
  const threshold = clamp01(base - adj);
  return {
    level,
    reversibleConfidenceThreshold: threshold,
    // Even the most hands-off level always asks when criticality is high. This ceiling is
    // never removable — it's the structural backstop behind user preference.
    alwaysAskAboveCriticality: level === "delegator" ? 0.52 : level === "operator" ? 0.5 : 0.4,
  };
}

/**
 * The reversible-band decision: should we proceed autonomously, or ask? Returns a clear
 * reason either way. This NEVER sees irreversible/destructive actions — those are gated
 * structurally upstream and never reach here.
 */
export function shouldProceedInReversibleBand(
  profile: AutonomyProfile,
  criticality: number,
  behavioralConfidence: number,
): { proceed: boolean; reason: string } {
  if (criticality > profile.alwaysAskAboveCriticality) {
    return { proceed: false, reason: `This one's consequential enough (criticality ${criticality.toFixed(2)}) that I'll check with you even though it's technically reversible.` };
  }
  if (behavioralConfidence < profile.reversibleConfidenceThreshold) {
    return { proceed: false, reason: `I'm not confident enough yet for your "${profile.level}" setting, so I'll check with you.` };
  }
  return { proceed: true, reason: `Handled autonomously — within your "${profile.level}" autonomy setting and low-risk.` };
}

/** Is level a at least as autonomous as level b? */
export function atLeastAsAutonomous(a: AutonomyLevel, b: AutonomyLevel): boolean {
  return LEVEL_ORDER.indexOf(a) >= LEVEL_ORDER.indexOf(b);
}

/**
 * Derive criticality signals STRUCTURALLY from the action's tier + kind — never from the
 * model's self-description (GRV anti-spoofing: a malicious agent must not be able to
 * downgrade its own criticality by describing a write as a read). `recentSameKind` is a
 * temporal-burst count (repeated same-kind actions in a short window raise criticality,
 * catching runaway loops before the killswitch has to).
 */
export function deriveCriticality(
  tier: "read-only" | "reversible-internal" | "external-touching" | "irreversible",
  kind: ActionKind,
  recentSameKind = 0,
): CriticalitySignals {
  const irreversibility = tier === "irreversible" ? 1 : tier === "external-touching" ? 0.4 : tier === "reversible-internal" ? 0.15 : 0;
  const rollbackCost = tier === "irreversible" ? 1 : tier === "external-touching" ? 0.35 : 0.1;
  // Scope: external-touching reaches outside the instance; internal is local.
  const scope = tier === "irreversible" ? 0.7 : tier === "external-touching" ? 0.4 : 0.15;
  // Novelty/burst proxy: only a GENUINE burst (>=3 rapid repeats of the same action) is
  // abnormal — normal repeated use (1–2) must not inflate criticality. A sustained burst
  // signals a possible runaway loop (passive loss of control) and scales up from there.
  const burstExcess = Math.max(0, recentSameKind - 2); // 0 until the 3rd rapid repeat
  const novelty = Math.min(1, burstExcess / 3);
  return { irreversibility, rollbackCost, scope, novelty };
}

/**
 * A tiny sliding-window burst tracker for the temporal-pattern signal. Counts how many
 * times a kind was seen within `windowMs`. Zero deps, bounded memory.
 */
export class BurstTracker {
  private readonly hits = new Map<ActionKind, number[]>();
  constructor(private readonly windowMs = 60_000) {}

  /** Record an occurrence and return how many of this kind are in the current window. */
  observe(kind: ActionKind, now = Date.now()): number {
    const arr = (this.hits.get(kind) ?? []).filter((t) => now - t < this.windowMs);
    arr.push(now);
    this.hits.set(kind, arr);
    return arr.length;
  }

  /** Current count in-window without recording a new hit. */
  countFor(kind: ActionKind, now = Date.now()): number {
    return (this.hits.get(kind) ?? []).filter((t) => now - t < this.windowMs).length;
  }
}

function clamp01(x: number): number {
  return Math.max(0, Math.min(1, x));
}

/**
 * AUTONOMY-MEASURE — an honest unattended-autonomy scorecard over a run's events. It composes the run's escalation /
 * touchpoint events into operational autonomy metrics (the field has moved from capability metrics to operational ones —
 * digitalapplied 2026; formalized as HITL-load + TCR@0 in arXiv 2602.11416): unattended-completion (finished with ZERO
 * human touchpoints — institutepm 2026), human-touchpoint BURDEN (count + kind, distinguishing planned consequence-gated
 * holds from unplanned confidence-escalations — digitalapplied), and ENVELOPE ADHERENCE.
 *
 * Envelope adherence is a HARD invariant (TCR@0's "no policy violations allowed", arXiv 2602.11416; "hard orchestration
 * limits", agileleadershipday 2026): a SINGLE out-of-envelope action reads as a breach (adherence false), NEVER averaged
 * or rounded to "mostly adherent". HONEST: this measures AUTONOMY, which is "a deliberate design decision, separate from
 * capability" (Feng et al.) — NOT correctness; a fully-unattended run can still be wrong ("a safety dimension completion
 * rate hides entirely"). It reflects only REAL events (never fabricated) and is REPORT-ONLY (changes no gate). ZERO-DEP.
 */

export type HoldKind = "consequence-gated" | "confidence-escalation" | "resource-limit";

export interface RunEvent {
  readonly kind: "action" | "hold";
  /** For a hold: which kind (planned consequence-gate vs unplanned escalation vs resource limit). */
  readonly holdKind?: HoldKind;
  /** For an action: was it within the run's stated autonomy envelope? */
  readonly inEnvelope?: boolean;
}

export interface AutonomyScorecardInput {
  readonly events: readonly RunEvent[];
  readonly completed: boolean;
}

export interface AutonomyScorecard {
  /** Completed AND zero human touchpoints. */
  readonly unattendedComplete: boolean;
  readonly humanTouchpoints: number;
  readonly touchpointsByKind: Readonly<Record<HoldKind, number>>;
  /** HARD invariant: true iff EVERY action stayed in-envelope. Any breach ⇒ false (never averaged). */
  readonly envelopeAdherence: boolean;
  readonly outOfEnvelopeCount: number;
  /** HONEST: measures autonomy, NOT correctness — a fully-unattended run can still be wrong. */
  readonly measures: "autonomy-not-correctness";
  /** HONEST: report-only — changes no gate. */
  readonly changesGate: false;
  readonly summary: string;
}

export function autonomyScorecard(input: AutonomyScorecardInput): AutonomyScorecard {
  const touchpointsByKind: Record<HoldKind, number> = { "consequence-gated": 0, "confidence-escalation": 0, "resource-limit": 0 };
  let humanTouchpoints = 0;
  let outOfEnvelopeCount = 0;
  for (const e of input.events) {
    if (e.kind === "hold") {
      humanTouchpoints++;
      if (e.holdKind !== undefined) touchpointsByKind[e.holdKind]++;
    } else if (e.kind === "action" && e.inEnvelope === false) {
      outOfEnvelopeCount++;
    }
  }
  const unattendedComplete = input.completed && humanTouchpoints === 0;
  // HARD: any out-of-envelope action is a breach. Never averaged to "mostly adherent".
  const envelopeAdherence = outOfEnvelopeCount === 0;

  const parts = [
    unattendedComplete ? "unattended-complete" : input.completed ? `completed with ${humanTouchpoints} touchpoint(s)` : "incomplete",
    envelopeAdherence ? "envelope adherent" : `ENVELOPE BREACH (${outOfEnvelopeCount} out-of-envelope action(s))`,
  ];
  const summary = `autonomy: ${parts.join("; ")} — measures autonomy, not correctness`;

  return { unattendedComplete, humanTouchpoints, touchpointsByKind, envelopeAdherence, outOfEnvelopeCount, measures: "autonomy-not-correctness", changesGate: false, summary };
}
