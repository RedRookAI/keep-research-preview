/**
 * MetaHarness (Increment 18) — the safe self-improvement orchestrator. Keep "gets better with use" by
 * improving its own HARNESS (prompts, heuristics, routing, calibration) — never the model, never the
 * safety floor. This is where Keep exceeds; it is also where MISEVOLUTION lives (a self-improving system
 * optimizing a proxy that quietly degrades its own safety). The design defends against that architecturally.
 *
 * SOTA basis (2026-08-05): the central unsolved problem is the SELF-AUTHORED VERIFIER — "an authored judge
 * under enough optimization pressure is not a judge, it is a puzzle, and puzzles get solved" (ilands.ai;
 * arXiv 2607.24300). The EXTERNAL ANCHOR PRINCIPLE (ICLR 2026 RSI Workshop, 110 papers; eugenevyborov
 * 2026): the fix is architectural — an immutable external eval signal the improver cannot touch makes
 * gaming structurally impossible. Guardrails (Godel Agent / o-mega 2026): verify every edit against safety
 * invariants first; freeze the core; fixed criteria; compile-time versioned artifacts; halt + rollback on
 * regression. Improve the HARNESS, not the model (Weng 2026 heuristic-learning; agyn.io PostTrainBench).
 *
 * Four architectural invariants: (1) external immutable anchor; (2) frozen safety floor (allowlist); (3)
 * compile-time versioned + reversible; (4) bounded + halt-on-regression. Zero deps (node:crypto builtin).
 */

import { createHash } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import type { GovernanceLedger } from "../governance/decision_record.js";
import { ProposalTriad, type TriadInput, type TriadVerdict } from "./proposal_triad.js";

/**
 * The components self-improvement is ALLOWED to touch — the full SOTA improvable surface (arXiv 2512.16301
 * "Adaptation of Agentic AI"; arXiv 2506.05109 metacognitive survey): prompts, retrieval, orchestration,
 * calibration, MEMORY (episodic + semantic), TOOLS/SKILLS (discovered reusable capabilities), and MODEL
 * ADAPTERS (LoRA/RLVR). The safety floor is structurally NOT in this set. Model adapters carry EXTRA gates.
 */
export type ImprovableComponent =
  | "prompt"
  | "localizer-heuristic"
  | "routing-threshold"
  | "oversight-calibration"
  | "memory-lesson" // episodic/semantic memory (drift/poison-guarded by MemoryStore demotion)
  | "tool-skill" // a discovered reusable capability (audited skill graph — ASG-SI arXiv 2512.23760)
  | "model-adapter"; // LoRA/RLVR weight-level adaptation — the MOST gated axis (provenance + poison + RLVR)
export const IMPROVABLE_ALLOWLIST: readonly ImprovableComponent[] = [
  "prompt", "localizer-heuristic", "routing-threshold", "oversight-calibration", "memory-lesson", "tool-skill", "model-adapter",
];

/** Axes that carry EXTRA mandatory gates beyond the anchor (checked BEFORE the anchor comparison). */
export const EXTRA_GATED: readonly ImprovableComponent[] = ["model-adapter"];

/** Components that self-improvement may NEVER touch (the frozen safety floor — the anchor of trust). */
export const FROZEN_FLOOR: readonly string[] = [
  "consequence-floor", "patch-verifier", "isolation-tier", "sovereignty-manifest", "eval-anchor", "spine",
];

/** A frozen, held-out evaluation the improver CANNOT modify (the external anchor). */
export interface EvalAnchor {
  /** Held-out cases; the improver never sees or edits these. */
  readonly cases: readonly { readonly id: string; readonly input: string; readonly expected: string }[];
  /** Score a candidate component version against the held-out cases → [0,1]. Higher is better. */
  score(componentVersion: string): number;
  /** Does this candidate version WEAKEN the deterministic safety floor? (a hard reject) */
  weakensSafetyFloor(componentVersion: string): boolean;
  /**
   * MULTI-SET no-regression (18.0, Goodhart-resistant): beyond the target `score`, an anchor MAY expose a
   * SAFETY set and a CAPABILITY set the candidate must NOT regress. A win on the target set alone ships
   * nothing if it regresses safety/capability (FutureAGI four-set playbook 2026). Optional so single-set
   * anchors remain valid; when present, `propose` enforces no-regression on these BEFORE accepting.
   * Returns the candidate's score on the named set → [0,1].
   */
  scoreSet?(setName: "safety" | "capability", componentVersion: string): number;
  /** The baseline score on a named set (what the candidate must not fall below). */
  baselineSet?(setName: "safety" | "capability"): number;
}

/** A proposed self-improvement to one improvable component. */
export interface ImprovementProposal {
  readonly component: ImprovableComponent | string; // string allows an illegal target to be REJECTED
  readonly fromVersion: string;
  readonly toVersion: string;
  readonly rationale: string; // GEPA-style natural-language reason
  /**
   * For EXTRA_GATED axes (model-adapter): a gate that must pass BEFORE the anchor comparison. This is where
   * a model-adapter proposal delegates to the LoRA tier's checkEntryGates (provenance + poison-screen +
   * verifiable-reward + sandbox + session-auth). Returns {passed, reason}. Stricter, never looser.
   */
  readonly extraGate?: () => { passed: boolean; reason: string };
  /** 18.0: structured description of what the change does, for the triad's consequence reachability check. */
  readonly declaredEffects?: readonly string[];
}

export type MetaDecision =
  | "accepted"
  | "rejected-no-gain"
  | "rejected-floor"
  | "rejected-anchor-tamper"
  | "rejected-not-improvable"
  | "rejected-extra-gate"
  | "rejected-triad" // 18.0: failed research/logic/consequence BEFORE the anchor comparison
  | "rejected-set-regression"; // 18.0: regressed the safety/capability set (multi-set no-regression)

export interface MetaOutcome {
  readonly decision: MetaDecision;
  readonly component: string;
  readonly baselineScore?: number;
  readonly candidateScore?: number;
  readonly reason: string;
}

/** A record of the current live version + its safe baseline (for rollback). */
interface ComponentState { live: string; baseline: string; baselineScore: number; }

export interface MetaHarnessConfig {
  readonly anchor: EvalAnchor;
  readonly spine?: Spine;
  readonly governance?: GovernanceLedger;
  /** Minimum score improvement to accept (guards against noise). Default 0 (any strict gain). */
  readonly minGain?: number;
  /** 18.0: the mandatory triad gate. Defaults to the deterministic ProposalTriad if not supplied. */
  readonly triad?: ProposalTriad;
  /** 18.0: whether the environment has research egress (gates the research check's strength). Default false. */
  readonly hasEgress?: boolean;
}

/**
 * 18.0 — the bounded, execution-adjudicated LOOP result. A proposal is REFINED against each failure
 * (triad counterexample OR anchor no-gain) until it converges (accepted) or the round budget is exhausted
 * (abandoned). Caps at 3 refine rounds (hard ceiling 5) — the diminishing-returns + reward-hacking plateau
 * (Self-Refine; Nexus 2510.26423; "Mind the Gap" 2412.02674 saturate 2-3 rounds). Early-stop on convergence.
 */
export interface LoopResult {
  readonly outcome: MetaOutcome;
  readonly rounds: number;
  /** Every attempt's decision + counterexample, in order (the audit trail of the refinement). */
  readonly trail: readonly { readonly round: number; readonly decision: MetaDecision; readonly counterexample: string }[];
}

/** A refiner turns a failed proposal + its counterexample into the next candidate (or null to abandon). */
export type Refiner = (previous: ImprovementProposal, counterexample: string, round: number) => ImprovementProposal | null;

export class MetaHarness {
  private readonly anchor: EvalAnchor;
  private readonly anchorHash: string; // content-hash sealed at construction — the tamper guard
  private readonly spine: Spine | undefined;
  private readonly governance: GovernanceLedger | undefined;
  private readonly minGain: number;
  private readonly triad: ProposalTriad;
  private readonly hasEgress: boolean;
  private readonly state = new Map<string, ComponentState>();
  /** 18.0: caps for the bounded refine loop — plateau at 3, hard ceiling 5 (SOTA convergence + anti-hacking). */
  static readonly REFINE_TARGET_ROUNDS = 3;
  static readonly REFINE_CEILING_ROUNDS = 5;

  constructor(config: MetaHarnessConfig) {
    this.anchor = config.anchor;
    this.anchorHash = hashAnchor(config.anchor);
    this.spine = config.spine;
    this.governance = config.governance;
    this.minGain = config.minGain ?? 0;
    this.triad = config.triad ?? new ProposalTriad();
    this.hasEgress = config.hasEgress ?? false;
  }

  /** Register a component's current live version as its safe baseline. */
  register(component: ImprovableComponent, version: string): void {
    const baselineScore = this.anchor.score(version);
    this.state.set(component, { live: version, baseline: version, baselineScore });
  }

  /**
   * Evaluate a self-improvement proposal against the four invariants. Accepts ONLY if the target is
   * improvable, the anchor was not tampered with, the candidate does not weaken the safety floor, and it
   * strictly beats the frozen baseline on the held-out anchor. Every decision is audited (compile-time).
   */
  propose(proposal: ImprovementProposal): MetaOutcome {
    // INVARIANT 2: the target must be an allowlisted soft component; the safety floor is excluded.
    if (FROZEN_FLOOR.includes(proposal.component) || !IMPROVABLE_ALLOWLIST.includes(proposal.component as ImprovableComponent)) {
      return this.decide(proposal, "rejected-not-improvable", `"${proposal.component}" is not an improvable component (safety floor is frozen)`);
    }
    // INVARIANT 1a: the external anchor must not have been tampered with since loop start.
    if (hashAnchor(this.anchor) !== this.anchorHash) {
      return this.decide(proposal, "rejected-anchor-tamper", "the eval anchor was modified — self-improvement cannot grade its own homework");
    }
    // INVARIANT 1b/2: the candidate must NOT weaken the deterministic safety floor.
    if (this.anchor.weakensSafetyFloor(proposal.toVersion)) {
      return this.decide(proposal, "rejected-floor", "candidate weakens the deterministic safety floor — rejected regardless of score");
    }
    // EXTRA GATE (model-adapter): the most-gated axis must clear provenance + poison-screen + verifiable-
    // reward + sandbox + session-auth (delegated to the LoRA tier) BEFORE it can even be scored.
    if (EXTRA_GATED.includes(proposal.component as ImprovableComponent)) {
      const g = proposal.extraGate ? proposal.extraGate() : { passed: false, reason: "model-adapter requires the LoRA entry-gate delegate (provenance + poison + RLVR); none supplied" };
      if (!g.passed) {
        return this.decide(proposal, "rejected-extra-gate", `extra gate failed for ${proposal.component}: ${g.reason}`);
      }
    }
    // 18.0 — MANDATORY TRIAD: research-currency + logic + 2nd/3rd-order consequence, BEFORE the anchor.
    // A triad failure is a counterexample (drives loop refinement); it can never be bypassed.
    const triadInput: TriadInput = {
      component: proposal.component, fromVersion: proposal.fromVersion, toVersion: proposal.toVersion,
      rationale: proposal.rationale, hasEgress: this.hasEgress,
      ...(proposal.declaredEffects ? { declaredEffects: proposal.declaredEffects } : {}),
    };
    const triad = this.triad.evaluate(triadInput);
    if (!triad.pass) {
      return this.decideTriad(proposal, triad);
    }
    // INVARIANT 1: the candidate must STRICTLY beat the frozen baseline on the held-out anchor.
    const st = this.state.get(proposal.component) ?? { live: proposal.fromVersion, baseline: proposal.fromVersion, baselineScore: this.anchor.score(proposal.fromVersion) };
    const candidateScore = this.anchor.score(proposal.toVersion);
    if (candidateScore - st.baselineScore <= this.minGain) {
      return this.decide(proposal, "rejected-no-gain", `candidate did not beat the frozen anchor (baseline=${st.baselineScore.toFixed(3)}, candidate=${candidateScore.toFixed(3)})`, st.baselineScore, candidateScore);
    }
    // 18.0 — MULTI-SET NO-REGRESSION (Goodhart-resistant): a target-set gain that REGRESSES the safety or
    // capability set ships nothing (FutureAGI four-set 2026). Enforced only when the anchor exposes the sets.
    const setReg = this.checkSetRegression(proposal.toVersion);
    if (setReg) {
      return this.decide(proposal, "rejected-set-regression", setReg, st.baselineScore, candidateScore);
    }
    // ACCEPTED: version it (compile-time, reversible), keep the OLD version as the safe baseline for rollback.
    this.state.set(proposal.component, { live: proposal.toVersion, baseline: st.live, baselineScore: st.baselineScore });
    return this.decide(proposal, "accepted", `improved on the frozen anchor (${st.baselineScore.toFixed(3)} → ${candidateScore.toFixed(3)})`, st.baselineScore, candidateScore);
  }

  /**
   * INVARIANT 4: report a live regression for a component (from post-graduation outcomes). If the live
   * version now scores WORSE than its baseline, HALT + ROLL BACK to the safe baseline, audited.
   */
  checkRegression(component: ImprovableComponent): { rolledBack: boolean; reason: string } {
    const st = this.state.get(component);
    if (!st) return { rolledBack: false, reason: "unknown component" };
    const liveScore = this.anchor.score(st.live);
    if (liveScore < st.baselineScore) {
      this.state.set(component, { live: st.baseline, baseline: st.baseline, baselineScore: this.anchor.score(st.baseline) });
      this.audit("meta.rollback", "warn", `${component} regressed (live=${liveScore.toFixed(3)} < baseline=${st.baselineScore.toFixed(3)}) — rolled back to safe baseline`, "escalated-to-human");
      return { rolledBack: true, reason: `regression → rolled back ${component} to its safe baseline` };
    }
    return { rolledBack: false, reason: "no regression" };
  }

  /**
   * 18.0 — the BOUNDED, execution-adjudicated LOOP. Propose → (triad + anchor) → on failure, hand the
   * counterexample to the refiner for the next candidate → resubmit until ACCEPTED or the round budget is
   * spent. Early-stops on convergence. Caps at REFINE_TARGET_ROUNDS (3), hard ceiling REFINE_CEILING_ROUNDS
   * (5): the diminishing-returns + reward-hacking plateau. Every attempt is on the audit trail.
   */
  proposeLoop(initial: ImprovementProposal, refine: Refiner, maxRounds = MetaHarness.REFINE_TARGET_ROUNDS): LoopResult {
    const ceiling = Math.min(Math.max(1, maxRounds), MetaHarness.REFINE_CEILING_ROUNDS);
    const trail: { round: number; decision: MetaDecision; counterexample: string }[] = [];
    let current: ImprovementProposal | null = initial;
    let last: MetaOutcome = { decision: "rejected-no-gain", component: initial.component, reason: "loop did not run" };
    for (let round = 1; round <= ceiling && current; round++) {
      const outcome = this.propose(current);
      const counterexample = this.counterexampleOf(outcome);
      trail.push({ round, decision: outcome.decision, counterexample });
      last = outcome;
      if (outcome.decision === "accepted") {
        return { outcome, rounds: round, trail };
      }
      // Non-convergent + non-refinable decisions (tamper/floor/not-improvable/extra-gate) are terminal —
      // refining them would be loopmaxxing against an architectural boundary. Stop immediately.
      if (!this.isRefinable(outcome.decision)) {
        return { outcome, rounds: round, trail };
      }
      current = refine(current, counterexample, round); // null → refiner gave up → abandon
    }
    return { outcome: last, rounds: trail.length, trail };
  }

  /** Decisions the loop may attempt to refine (a counterexample can plausibly be addressed). */
  private isRefinable(d: MetaDecision): boolean {
    return d === "rejected-triad" || d === "rejected-no-gain" || d === "rejected-set-regression";
  }

  /** The counterexample text a decision hands back to the refiner. */
  private counterexampleOf(o: MetaOutcome): string {
    return o.reason;
  }

  /** The current live version of a component (for wiring the improved version back in). */
  liveVersion(component: ImprovableComponent): string | undefined {
    return this.state.get(component)?.live;
  }

  /** 18.0: multi-set no-regression. Returns a reason string if the candidate regresses a set, else null. */
  private checkSetRegression(candidateVersion: string): string | null {
    if (!this.anchor.scoreSet || !this.anchor.baselineSet) return null;
    for (const set of ["safety", "capability"] as const) {
      const baseline = this.anchor.baselineSet(set);
      const candidate = this.anchor.scoreSet(set, candidateVersion);
      if (candidate < baseline) {
        return `candidate regressed the ${set} set (baseline=${baseline.toFixed(3)}, candidate=${candidate.toFixed(3)}) — a target gain that weakens ${set} ships nothing`;
      }
    }
    return null;
  }

  /** Record a triad-gate rejection (audited like any other decision). */
  private decideTriad(p: ImprovementProposal, triad: TriadVerdict): MetaOutcome {
    return this.decide(p, "rejected-triad", triad.reason);
  }

  private decide(p: ImprovementProposal, decision: MetaDecision, reason: string, baselineScore?: number, candidateScore?: number): MetaOutcome {
    const effect = decision === "accepted" ? "allow" : "deny";
    this.audit("meta.propose", decision === "accepted" ? "allow" : "warn",
      `[${decision}] ${p.component} ${p.fromVersion}→${p.toVersion}: ${reason}`, decision === "accepted" ? "proceeded" : "blocked");
    // Record the versioned artifact to the spine (compile-time, reviewable).
    this.spine?.stage({
      type: "identity.action", actor: "keep-meta-harness",
      payload: { event: "self_improvement", decision, component: p.component, fromVersion: p.fromVersion, toVersion: p.toVersion, rationale: p.rationale, baselineScore, candidateScore },
    });
    void effect;
    return { decision, component: p.component, ...(baselineScore !== undefined ? { baselineScore } : {}), ...(candidateScore !== undefined ? { candidateScore } : {}), reason };
  }

  private audit(action: string, effect: "allow" | "warn" | "deny", reason: string, outcome: "proceeded" | "blocked" | "warned-and-proceeded" | "escalated-to-human"): void {
    this.governance?.record({
      action, actor: "keep-meta-harness",
      policy: { effect, ruleId: "meta-harness", reason, matchedRuleIds: ["meta-harness"], policyVersion: "1" },
      outcome,
    });
  }
}

/** Content-hash the held-out anchor cases (the tamper guard). Deterministic canonical serialization. */
function hashAnchor(anchor: EvalAnchor): string {
  const canonical = JSON.stringify(anchor.cases.map((c) => [c.id, c.input, c.expected]));
  return createHash("sha256").update(canonical).digest("hex");
}
