/**
 * Merge authority (Increment AM1) — the single deterministic decision for "who, if anyone, must approve this merge?"
 *
 * The whole point of Keep is to run autonomously UNLESS a change is irreversible, high blast radius, or would
 * seriously screw things up — and to resolve everything else without bothering a human, because at scale "just ask
 * the human" is rubber-stamping (companies) or a dead end (a non-engineer who can't review a diff).
 *
 * SOTA basis (2026-08-06): autonomy is granted in proportion to REVERSIBILITY, not confidence ("the safety is in the
 * blast radius, not the click"); gate only when consequence is elevated; low confidence ALONE on a reversible,
 * low-blast action must not gate; use human-on-the-loop (act, then auto-revert on regression) for reversible work.
 *
 * The load-bearing idea: CONSEQUENCE and CONFIDENCE are different axes and must be judged separately.
 *  - CONSEQUENCE (irreversible tier / high blast / sensitive always-gate path) → a human owns it, verified or not.
 *    Irreversibility gates even when fully verified, because the auto-revert safety net only works for reversible
 *    changes — you cannot undo an irreversible one, so a human must own it.
 *  - CONFIDENCE (tests didn't pass / vetting didn't clear / candidates forked) on a REVERSIBLE, low-blast change is
 *    NOT a reason to bother a human. The change simply shouldn't merge; it should be abandoned/retried autonomously.
 *
 * A human is therefore bothered only when consequence is elevated (≈ the 2-of-3 rule, but with irreversibility as a
 * hard gate). Everything reversible and low-blast is handled by the machine: merge it if verified, retry/drop it if
 * not. The owner owns the ENVELOPE (what may auto-merge) and can disable it entirely or narrow it — that is what
 * "the merge gate stays the owner's" means: they own the policy and can always intervene, not that they click merge.
 */

import type { ActionTier } from "../control/action_tier.js";
import type { RiskBand } from "./pr_risk.js";
import type { CascadeOutcome } from "../cascade/verification_cascade.js";

export type MergeAuthorityVerdict = "autonomous-merge" | "human-merge" | "abandon-retry" | "block";

export interface MergeVerificationState {
  readonly testsPassed: boolean;
  readonly vettingCleared: boolean;
  /** R3 behavioral fork — verified candidates disagree; treat as unverified (don't silently pick one). */
  readonly behavioralFork?: boolean;
  /** A SOUND safety check failed — never mergeable, not a judgement call. */
  readonly soundFailure?: boolean;
}

export interface MergeConsequence {
  readonly actionTier: ActionTier;
  /** Band from blast + reversibility + size ONLY (no confidence) — pr_risk.consequenceBand. */
  readonly consequenceBand: RiskBand;
  /** A sensitive always-gate path (auth, crypto, migrations, deploy, payment, …) was touched. */
  readonly alwaysGatePath: boolean;
}

export interface MergeEnvelope {
  /** Master switch — the owner can disable ALL autonomous merges (falls back to human-merge for verified changes). */
  readonly autonomousMergeEnabled: boolean;
  /** Widest consequence band eligible for autonomous merge. "as autonomous as possible" → "medium". */
  readonly maxAutonomousBand: "low" | "medium";
  /** Action tiers eligible for autonomous merge. Default: read-only + reversible-internal (revert-safe). */
  readonly autoMergeTiers: ReadonlySet<ActionTier>;
}

export interface MergeAuthorityInputs {
  readonly verification: MergeVerificationState;
  readonly consequence: MergeConsequence;
  readonly envelope: MergeEnvelope;
  /**
   * ROUND 41 — safety controls the operator has configured into silence (round 40's
   * `inertFloorInputs` / `inertBudgetInputs` output). Empty or omitted ⇒ no effect.
   *
   * WHY THIS BELONGS IN THE MERGE DECISION AND NOT ONLY IN A WARNING. Measured before building:
   * a run under an inert allowlist emitted round 40's warning AND still returned
   * `autonomous-merge`, and the change was merged. **Autonomous merge is defined by there being
   * no human in the loop**, so a warning written for a human reader reached nobody — the one
   * path where the report cannot work is the one that needed it most.
   *
   * The warning-habituation research says the same thing from the other side: users "click
   * through 50% of SSL warnings in 1.7 seconds", visual processing drops "after only the second
   * exposure", and habituation to unrelated frequent notifications *generalises* to a one-time
   * security warning. A line in a progress feed beside a successful result is precisely that
   * case. "Actively interrupting people's workflows is more effective than using passive
   * indicators" — so this changes the control flow rather than adding another notice.
   *
   * NOT A BLOCK. An inert control makes the change CONSEQUENTIAL, which routes to `human-merge`:
   * the PR is still produced and a person decides. It never returns `block`, because a
   * misconfigured barrier is a legal state and this round does not turn it into a failure.
   *
   * This does not violate the "never bother a human for low-risk uncertainty" invariant below.
   * An inert control is not uncertainty about a change — it is a barrier the operator believes
   * is on and which is off. Rare, specific, and actionable, which is exactly the profile of an
   * interrupt that keeps its meaning.
   */
  readonly inertControls?: readonly string[];
  /**
   * ROUND 42 — the AI-generated code was executed with NO isolation at all
   * (`isolationTier: "none"`, whose autonomy ceiling is `refuse-risky`). Omitted ⇒ no effect.
   *
   * FOUND BY MEASURING THE DECISION MATRIX, not by reading. Isolation was wired into
   * `autoApprovable` — "weaker ceilings suppress auto-approval" — and never reached merge
   * authority, so a run under `none` measured as `autonomous-merge` and **merged**. The
   * codebase's own strongest word for that tier is *refuse-risky*, and autonomous merge is the
   * most autonomous act available; the two cannot coherently coexist.
   *
   * WHY IT IS A VERIFICATION CONCERN AND SO BELONGS HERE. Merge authority trusts `testsPassed`.
   * Under no isolation, the patch under test could reach the machine running it, so the test
   * result is weaker evidence than it appears. The isolation tier is not merely about blast
   * radius during execution — it bounds how much the verification can be believed.
   *
   * DELIBERATELY NARROW. `process` (minimal) and `container` (reduced) still permit autonomous
   * merge. Gating those would suppress autonomous merge at the DEFAULT tier — a large behaviour
   * change the measurement does not support, and the round's own instruction was not to close
   * gaps mechanically. Only the tier the codebase already calls `refuse-risky` is gated.
   */
  readonly executionUnisolated?: boolean;
}

export interface MergeAuthorityDecision {
  readonly verdict: MergeAuthorityVerdict;
  readonly reason: string;
  /** True if the change is consequential (irreversible / high-blast / sensitive / beyond the envelope). */
  readonly consequential: boolean;
  /** True if the change proved itself (tests + vetting, no fork, no sound failure). */
  readonly verified: boolean;
}

/** "as autonomous as possible" within a safe, revert-guarded envelope. Owner-overridable. */
export const DEFAULT_MERGE_ENVELOPE: MergeEnvelope = {
  autonomousMergeEnabled: true,
  maxAutonomousBand: "medium",
  autoMergeTiers: new Set<ActionTier>(["read-only", "reversible-internal"]),
};

const BAND_RANK: Record<RiskBand, number> = { low: 0, medium: 1, high: 2 };
function bandExceeds(band: RiskBand, max: "low" | "medium"): boolean {
  return BAND_RANK[band] > BAND_RANK[max];
}

export function decideMergeAuthority(i: MergeAuthorityInputs): MergeAuthorityDecision {
  const { verification: v, consequence: c, envelope: e } = i;

  // 1. Safety floor — a sound failure is never mergeable. Not a human decision; simply not allowed.
  if (v.soundFailure) {
    return { verdict: "block", reason: "a sound safety check failed — never mergeable", consequential: true, verified: false };
  }

  // 2. CONSEQUENCE (independent of how the solve went): is a human required to own this, come what may?
  const tierConsequential = !e.autoMergeTiers.has(c.actionTier); // external-touching / irreversible are not auto-merge tiers
  // ROUND 41: a barrier configured into silence makes the change consequential. The evidence
  // that it is safe is weaker than it appears, and the only path that could report that to a
  // human is the one this suppresses.
  const controlsInert = (i.inertControls?.length ?? 0) > 0;
  const unisolated = i.executionUnisolated === true; // ROUND 42
  const consequential =
    tierConsequential ||
    c.alwaysGatePath ||
    c.consequenceBand === "high" ||
    controlsInert ||
    unisolated ||
    bandExceeds(c.consequenceBand, e.maxAutonomousBand);

  // 3. CONFIDENCE: did the change prove itself?
  const verified = v.testsPassed && v.vettingCleared && !v.behavioralFork;

  // 4. Decide — consequence-primary; uncertainty alone (reversible + low-blast) never bothers a human.
  if (!verified) {
    if (consequential) {
      return { verdict: "human-merge", reason: "unverified AND consequential (irreversible / high-blast / sensitive) — a person should decide", consequential, verified };
    }
    return { verdict: "abandon-retry", reason: "unverified but reversible + low-blast — retry or drop autonomously; never bother a human", consequential, verified };
  }
  // verified:
  if (consequential) {
    // Name the inert control specifically. "Irreversible / high-blast / sensitive" would be a
    // false explanation here, and an operator told the wrong reason cannot fix the right thing.
    if (unisolated) {
      return {
        verdict: "human-merge",
        reason: "the code was executed with no isolation (refuse-risky tier) — the test evidence cannot be trusted enough to merge without a person",
        consequential, verified,
      };
    }
    if (controlsInert) {
      return {
        verdict: "human-merge",
        reason: `a safety control is configured off (${i.inertControls!.join("; ")}) — autonomous merge is suppressed until a person decides`,
        consequential, verified,
      };
    }
    return { verdict: "human-merge", reason: "verified, but irreversible / high-blast / sensitive — the owner owns this merge", consequential, verified };
  }
  if (!e.autonomousMergeEnabled) {
    return { verdict: "human-merge", reason: "verified + reversible, but the owner disabled autonomous merge", consequential, verified };
  }
  return { verdict: "autonomous-merge", reason: "verified + reversible + low-blast + within envelope — merge autonomously (human-on-the-loop)", consequential, verified };
}

/**
 * Adapt a vetting-cascade outcome into merge-authority verification inputs — the ONE correct way to consume a cascade
 * verdict for a merge decision.
 *
 * MISSION-CRITICAL invariant: a cascade `escalate-human` is a VERIFICATION-confidence signal ("the automated tiers could
 * not clear this"), NOT a consequence signal. It must NEVER be treated as a direct human interrupt. Here it becomes
 * `vettingCleared: false` (unverified) and is then run through the consequence-primary `decideMergeAuthority`, where a
 * REVERSIBLE + low-blast change resolves autonomously (abandon-retry) and a human is bothered ONLY when the change is
 * genuinely consequential (irreversible / high-blast / sensitive). This is the 2026 HITL consensus: gate on reversibility
 * and blast radius, not on confidence — bothering a human for every low-risk uncertainty trains rubber-stamping and
 * devalues the approvals that matter.
 *
 * Mapping: fail → sound failure (block, authoritative); escalate-human → unverified (consequence gate decides);
 * pass → vetting cleared.
 */
export function mergeVerificationFromCascade(
  outcome: CascadeOutcome,
  signals: { testsPassed: boolean; behavioralFork?: boolean },
): MergeVerificationState {
  return {
    testsPassed: signals.testsPassed,
    vettingCleared: outcome.finalDecision === "pass",
    soundFailure: outcome.finalDecision === "fail",
    ...(signals.behavioralFork !== undefined ? { behavioralFork: signals.behavioralFork } : {}),
  };
}

// ── Comprehension receipt (BUILD-ORDER 2.4, COMPREHENSION-RECEIPT) — Z176 ──────────────────────────
/**
 * Nothing in the merge seam proves a human READ a warning. Keep produces decision briefs, human-merge
 * reasons, and inert-control / unisolated warnings for a person — but PRODUCTION IS NOT COMPREHENSION,
 * and the one path that most needs the human's attention (a consequential human-merge) is exactly where
 * "it was surfaced" is the weakest evidence. Measured before building (see the round's measurement
 * artifact): the spine records that a human-merge verdict was reached and that a brief was produced, but
 * NOTHING records that a person took an accountable action on those specific facts.
 *
 * HONEST BOUND (2.4 reframe, ledger 402). This function is a DECISION POINT (PDP) + audit primitive — it
 * RECORDS and SURFACES a per-consequence acknowledgment requirement as a durable, auditable spine fact. It
 * does NOT itself enforce: nothing here holds a merge, and the pipeline's one consultation of it is
 * redundant (see the merge-seam note). Two bounds, both stated plainly rather than overclaimed:
 *  (1) COMPREHENSION — a receipt never proves understanding; an "acknowledged" click is rubber-stampable and
 *      habituation to warnings generalises unconsciously (Amran/Zaaba; FTC/CCPA 2026 dark-pattern posture).
 *  (2) ACCOUNTABILITY — today's receipt is an UNAUTHENTICATED token (a forgeable decisionId match + a free
 *      `acknowledgedBy` string), so it does not yet prove a specific human acted. A genuinely accountable
 *      ack needs a signed identity (Ed25519 / signed mandate — SOTA 2026); that + a downstream lander (PEP)
 *      that actually enforces `mayProceed:false` are FILED for Phase 5.
 * It is bound to CONSEQUENCE — never blanket — because an ack demanded everywhere trains the reflex that
 * defeats it (habituation-generalisation).
 *
 * PER-CONSEQUENCE, composed with the EXISTING classification from decideMergeAuthority (never re-derived):
 *  - a genuinely consequential human-merge DECIDES delivery-receipt (mayProceed:false, RECORDED as an audit
 *    fact — enforcement of that decision is a downstream lander's job, not this function's);
 *  - a reversible human-merge surfacing is ACCEPT-AND-DOCUMENT: recorded (so habituation is auditable),
 *    NEVER blocked — the anti-bottleneck invariant;
 *  - everything the machine already auto-resolves (autonomous-merge / abandon-retry / block) demands
 *    NOTHING — the operator's default autonomy is untouched (front-of-house unchanged).
 */
export type ReceiptDisposition = "not-required" | "delivery-receipt" | "accept-and-document";

/**
 * A recorded, accountable human acknowledgment of a SPECIFIC merge decision. `decisionId` binds it to
 * exactly one decision + the facts surfaced with it; a stale/mismatched id does not satisfy anything.
 * This is evidence of an accountable action, NOT of comprehension (see the bound above).
 */
export interface ComprehensionReceipt {
  readonly decisionId: string;
  /** The accountable actor who acknowledged. */
  readonly acknowledgedBy: string;
  /** When the acknowledgment was taken (ms since epoch). */
  readonly acknowledgedAt: number;
}

export interface ComprehensionReceiptInputs {
  /** The merge-authority verdict — a receipt requirement appears ONLY at `human-merge`. */
  readonly verdict: MergeAuthorityVerdict;
  /** The EXISTING consequence classification from decideMergeAuthority — NOT re-derived here. */
  readonly consequential: boolean;
  /** Stable id for THIS merge decision + its surfaced facts (see mergeDecisionId). */
  readonly decisionId: string;
  /** A recorded acknowledgment for this decision, if one was captured. */
  readonly receipt?: ComprehensionReceipt;
  /**
   * An operator-DECLARED allowance loosening a delivery-receipt to accept-and-document. Additive: it can
   * only LOOSEN a consequential gate, never tighten reversible work, and it is recorded (never silent).
   */
  readonly operatorAllowance?: boolean;
}

export interface ComprehensionReceiptDecision {
  readonly disposition: ReceiptDisposition;
  /** The gated merge may proceed. FALSE only for a consequential human-merge with no valid receipt and no allowance. */
  readonly mayProceed: boolean;
  /** The un-acknowledged surfacing must be durably recorded (so habituation is auditable). */
  readonly recordUnacknowledged: boolean;
  readonly reason: string;
  /** Echoed back so the audit fact names what to acknowledge. */
  readonly decisionId: string;
  /** The receipt that satisfied a delivery-receipt requirement, echoed for the audit fact. */
  readonly satisfiedBy?: ComprehensionReceipt;
}

/**
 * A stable identifier for a specific merge decision + the facts surfaced with it. A comprehension
 * receipt must carry the MATCHING id or it is stale/mismatched — this is what binds a receipt to THIS
 * decision and no other. Deterministic and dependency-free (the verdict, the consequence classification,
 * the band, and the human-readable reason together pin the decision + its facts).
 */
export function mergeDecisionId(issueId: string, d: MergeAuthorityDecision, consequenceBand: RiskBand): string {
  return [issueId, d.verdict, d.consequential ? "consequential" : "reversible", consequenceBand, d.reason].join("|");
}

/**
 * The ONE receipt decision function. Fed by the existing consequence classification (never a second
 * consequence probe). See the module note above for the honest bound and the per-consequence rationale.
 */
export function decideComprehensionReceipt(i: ComprehensionReceiptInputs): ComprehensionReceiptDecision {
  // FRONT OF HOUSE: a receipt is demanded ONLY where a human already owns the merge. Everything the
  // machine auto-resolves (autonomous-merge / abandon-retry / block) demands nothing — no click, no wait.
  if (i.verdict !== "human-merge") {
    return {
      disposition: "not-required", mayProceed: true, recordUnacknowledged: false,
      reason: "no human owns this merge — a comprehension receipt applies only to a human-merge",
      decisionId: i.decisionId,
    };
  }

  // Bound to THIS decision: a stale/mismatched receipt does not satisfy anything.
  const validReceipt = i.receipt !== undefined && i.receipt.decisionId === i.decisionId;

  if (i.consequential) {
    // DELIVERY-RECEIPT: a genuinely consequential human-merge (irreversible / high-blast / sensitive /
    // unisolated) does not proceed autonomously without an acknowledgment bound to this decision.
    if (validReceipt) {
      return {
        disposition: "delivery-receipt", mayProceed: true, recordUnacknowledged: false,
        reason: "consequential human-merge — a receipt matching this decision id is recorded (unauthenticated token; a decision fact, not enforced here)",
        decisionId: i.decisionId, satisfiedBy: i.receipt,
      };
    }
    if (i.operatorAllowance) {
      // Additive loosening: the operator DECLARED this consequential path may proceed without a receipt.
      // Recorded as an un-acknowledged surfacing so the loosening is auditable, never silent.
      return {
        disposition: "accept-and-document", mayProceed: true, recordUnacknowledged: true,
        reason: "consequential human-merge, but the operator declared an allowance loosening the delivery-receipt — proceeding; the un-acknowledged surfacing is recorded",
        decisionId: i.decisionId,
      };
    }
    return {
      disposition: "delivery-receipt", mayProceed: false, recordUnacknowledged: true,
      reason: "consequential human-merge — DECISION: should not proceed without a recorded receipt; recorded as an audit fact for a downstream lander (PEP) to enforce",
      decisionId: i.decisionId,
    };
  }

  // ACCEPT-AND-DOCUMENT: a reversible human-merge surfacing (e.g. a verified reversible change under a
  // disabled autonomous-merge envelope). Recorded, NEVER blocked — the anti-bottleneck invariant.
  return {
    disposition: "accept-and-document", mayProceed: true, recordUnacknowledged: !validReceipt,
    reason: validReceipt
      ? "reversible human-merge — acknowledged; the surfacing is recorded"
      : "reversible human-merge — proceeding un-acknowledged; the surfacing is durably recorded for habituation audit",
    decisionId: i.decisionId,
    ...(validReceipt ? { satisfiedBy: i.receipt } : {}),
  };
}
