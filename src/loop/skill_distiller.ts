/**
 * SkillDistiller (Increment 18.4, Phase S) — distills a reusable SKILL from successful solve trajectories.
 * This is the first headline moat increment: Keep does not just tune prompts, it BUILDS its own validated
 * capabilities. The distiller only PRODUCES a candidate skill (safely); 18.5's CEGIS loop VALIDATES it before
 * anything goes live, and 18.3's lifecycle manages its provisional→full journey. The human merge gate remains.
 *
 * SOTA basis (2026-08-05):
 *  - Trajectory distillation pairs EXECUTABLE structure with step-level NL guidance (WebXSkill 2026;
 *    Anthropic agent-skills standard: activation conditions + execution steps + termination conditions;
 *    ProcMEM). → the HYBRID representation (D1): a StructuredEnvelope + an NL description.
 *  - FAITHFULNESS must be EXPLICITLY VERIFIED (MIND-Skill 2605.08670): the shared failure of prior work is
 *    that "the faithfulness of the abstraction is never verified." MIND-Skill's fix is round-trip
 *    reconstruction. → zero-dep faithfulness check: the skill's structured steps must reconstruct the
 *    trajectory's ESSENTIAL actions. This DOUBLES as the cross-modal consistency guard (SkillMutator
 *    2606.14154): NL and structure must agree, and declared effects must be DERIVED from the steps (no hidden
 *    sink smuggled into free-form text).
 *  - Distill from BATCHES not single runs where possible (Ni et al. 2026): comparing traces isolates reusable
 *    patterns from task-specific noise. → multi-trajectory corroboration raises confidence; a single
 *    trajectory yields a LOW-confidence provisional (which the canary/CEGIS path then stresses).
 *
 * Zero runtime deps. Everything behind ports.
 */

/** One step of a solve trajectory (the raw material). Structurally minimal + provider-agnostic. */
import type { Issue, SolveResult } from "../solve/issue_model.js";

export interface TrajectoryStep {
  /** The action verb (e.g. "localize", "edit", "add-test", "run-tests"). */
  readonly action: string;
  /** The concrete target the action operated on (e.g. a file path, a symbol). Parameterized on distill. */
  readonly target: string;
  /** Optional structured effect this step had (drives declared-effects derivation). */
  readonly effect?: string;
}

export interface SolveTrajectory {
  readonly solveId: string;
  readonly taskShape: string;
  readonly steps: readonly TrajectoryStep[];
  /** Only successful trajectories are distilled (never distill failure into a skill). */
  readonly succeeded: boolean;
  /** Authority actually required by this successful execution, recorded by the execution boundary. */
  readonly requiredAuthority: readonly SkillAuthority[];
}

/** The structured half of the HYBRID skill — the safety-bearing envelope the monitor + CEGIS verify against. */
export interface StructuredEnvelope {
  /** When the skill applies (activation conditions) — derived from the task shape + trajectory preamble. */
  readonly preconditions: readonly string[];
  /** The reusable, PARAMETERIZED action pattern (concrete targets abstracted to {slots}). */
  readonly steps: readonly { readonly action: string; readonly targetPattern: string }[];
  /** Explicit portable slots consumed by the parameterized steps; data only, never executable code. */
  readonly parameters?: readonly { readonly name: "file" | "symbol" | "arg"; readonly type: "string"; readonly required: true }[];
  /** What should hold after (termination conditions). */
  readonly postconditions: readonly string[];
  /** Declared effects DERIVED from the steps (never free-form) — for the triad + reference monitor. */
  readonly declaredEffects: readonly string[];
}

export interface DistilledSkill {
  /** Versioned, JSON-portable format identifier. Importers reject/translate unknown versions. */
  readonly format: "keep.skill/v1";
  readonly id: string;
  /** Human-readable name + description (the NL half; a non-engineer authors/reads this). */
  readonly name: string;
  readonly description: string;
  readonly relevanceKey: string; // task shape it applies to
  readonly envelope: StructuredEnvelope;
  /** Optional portable contract for a deterministic implementation. Code stays host-supplied by entrypoint. */
  readonly program?: SkillProgramContract;
  /** Authority observed across source executions; recorded, never inferred at activation time. */
  readonly requiredAuthority: readonly SkillAuthority[];
  /** Provenance: which trajectories it was distilled from (audit + corroboration count). */
  readonly provenance: readonly string[];
  /** Confidence: "low" from a single trajectory, "corroborated" from ≥2 of the same shape. */
  readonly confidence: "low" | "corroborated";
}

export type SkillPrimitiveType = "string" | "number" | "boolean";
export type SkillJson = null | boolean | number | string | readonly SkillJson[] | { readonly [key: string]: SkillJson };

/** JSON-only test contract: portable data, never embedded executable code. */
export interface SkillProgramContract {
  readonly entrypoint: string;
  readonly inputs: Readonly<Record<string, SkillPrimitiveType>>;
  readonly cases: readonly {
    readonly name: string;
    readonly input: Readonly<Record<string, SkillJson>>;
    readonly expected: SkillJson;
  }[];
}

export type SkillAuthority = "workspace:read" | "workspace:write" | "sandbox:execute";

export interface DistillResult {
  readonly skill?: DistilledSkill;
  readonly rejected?: string; // why nothing was distilled (unsuccessful, unfaithful, inconsistent)
}

/** Sinks that may never appear in a distilled skill's declared effects without an explicit human gate. */
const FORBIDDEN_SINKS = ["exfil", "external-send", "credential", "escalate-privilege", "delete-external"];

export class SkillDistiller {
  private readonly produced = new Map<string, DistilledSkill>();

  /** Candidates produced by real solves in this process. Read-only snapshots; validation still gates activation. */
  candidates(): readonly DistilledSkill[] { return [...this.produced.values()]; }

  /** Translate an execution-grounded solve result into a candidate; declarations never mint or carry authority. */
  observeSolve(result: SolveResult, issue: Issue): DistillResult {
    if (!result.solved || !result.prProposal || result.validation?.testsPassed !== true) return { rejected: "solve did not complete successfully with passing tests" };
    if (!result.authority) return { rejected: "successful solve lacks execution-bound authority provenance" };
    const taskShape = typeof issue.hints?.["taskShape"] === "string" && issue.hints["taskShape"].trim() ? issue.hints["taskShape"].trim() : "software-change";
    const steps: TrajectoryStep[] = [];
    if (result.stagesRun.includes("localize")) steps.push({ action: "localize", target: result.localization?.selected[0]?.path ?? issue.repoRef, effect: "reads repository files" });
    if (result.stagesRun.includes("plan")) steps.push({ action: "plan", target: taskShape });
    if (result.stagesRun.includes("apply")) for (const edit of result.prProposal.edits) steps.push({ action: "edit", target: edit.file, effect: "modifies repository files" });
    if (result.stagesRun.includes("validate")) steps.push({ action: "run-tests", target: "suite", effect: "runs tests in the sandbox" });
    const requiredAuthority: SkillAuthority[] = [];
    if (result.stagesRun.some((stage) => stage === "localize" || stage === "plan")) requiredAuthority.push("workspace:read");
    if (result.stagesRun.includes("apply")) requiredAuthority.push("workspace:write");
    if (result.stagesRun.includes("validate")) requiredAuthority.push("sandbox:execute");
    const distilled = this.distill([{ solveId: result.issueId, taskShape, steps, succeeded: true, requiredAuthority }]);
    if (distilled.skill) this.produced.set(distilled.skill.id, distilled.skill);
    return distilled;
  }

  /**
   * Distill a candidate skill from one or more trajectories of the SAME task shape. Multiple successful
   * trajectories → corroborated (higher confidence); one → low-confidence provisional. Returns a rejection
   * reason if the input is unsuitable (failure, no common pattern, unfaithful, or a forbidden sink).
   */
  distill(trajectories: readonly SolveTrajectory[]): DistillResult {
    const successful = trajectories.filter((t) => t.succeeded);
    if (successful.length === 0) return { rejected: "no successful trajectory to distill from (never distill failure)" };

    const shape = successful[0]!.taskShape;
    if (!successful.every((t) => t.taskShape === shape)) {
      return { rejected: "trajectories span multiple task shapes — cannot distill a single coherent skill" };
    }

    // Abstract the COMMON action pattern across the trajectories (the reusable core, noise-filtered).
    const pattern = this.commonPattern(successful);
    if (pattern.length === 0) return { rejected: "no common action pattern across trajectories" };

    // Build the parameterized structured steps + derive declared effects FROM those steps (cross-modal guard).
    const steps = pattern.map((p) => ({ action: p.action, targetPattern: parameterize(p.target) }));
    const declaredEffects = deriveEffects(pattern);

    // Cross-modal safety: a forbidden sink can never be smuggled in.
    const sink = declaredEffects.find((e) => FORBIDDEN_SINKS.some((s) => e.toLowerCase().includes(s)));
    if (sink) return { rejected: `distilled skill declares a forbidden sink ("${sink}") — requires a human gate, not auto-distill` };

    const envelope: StructuredEnvelope = {
      preconditions: [`task shape is "${shape}"`],
      steps,
      parameters: [...new Set(steps.map((step) => step.targetPattern.slice(1, -1) as "file" | "symbol" | "arg"))].map((name) => ({ name, type: "string" as const, required: true as const })),
      postconditions: ["produced patch passes its tests", "no safety regression"],
      declaredEffects,
    };

    // FAITHFULNESS (MIND-Skill round-trip): the envelope must reconstruct each trajectory's ESSENTIAL actions.
    for (const t of successful) {
      if (!this.reconstructs(envelope, t)) {
        return { rejected: `faithfulness check failed — the skill does not reconstruct trajectory ${t.solveId}` };
      }
    }

    const id = `skill:${shape}:${hashShort(steps.map((s) => s.action + s.targetPattern).join(">"))}`;
    const skill: DistilledSkill = {
      format: "keep.skill/v1",
      id,
      name: `${shape} skill (${steps.length} steps)`,
      description: `Reusable pattern for "${shape}" tasks: ${steps.map((s) => `${s.action} ${s.targetPattern}`).join(" → ")}.`,
      relevanceKey: shape,
      envelope,
      requiredAuthority: [...new Set(successful.flatMap((t) => t.requiredAuthority))],
      provenance: successful.map((t) => t.solveId),
      confidence: successful.length >= 2 ? "corroborated" : "low",
    };
    return { skill };
  }

  /** The longest common action subsequence across trajectories (the reusable core). Simple + deterministic. */
  private commonPattern(trajectories: readonly SolveTrajectory[]): readonly TrajectoryStep[] {
    if (trajectories.length === 1) return trajectories[0]!.steps;
    // Intersect on (action) sequence: keep steps whose action appears (in order) in every trajectory.
    let common = [...trajectories[0]!.steps];
    for (let i = 1; i < trajectories.length; i++) {
      const actions = new Set(trajectories[i]!.steps.map((s) => s.action));
      common = common.filter((s) => actions.has(s.action));
    }
    return common;
  }

  /** Round-trip faithfulness: every structured step's action must appear in the trajectory, in order. */
  private reconstructs(envelope: StructuredEnvelope, trajectory: SolveTrajectory): boolean {
    let ti = 0;
    for (const step of envelope.steps) {
      let found = false;
      while (ti < trajectory.steps.length) {
        if (trajectory.steps[ti]!.action === step.action) { found = true; ti++; break; }
        ti++;
      }
      if (!found) return false;
    }
    return true;
  }
}

/** Abstract a concrete target into a parameter slot (generalization): a path/symbol → {file}/{symbol}. */
function parameterize(target: string): string {
  if (target.includes("/") || target.includes(".")) return "{file}";
  if (/^[A-Z]/.test(target)) return "{symbol}";
  return "{arg}";
}

/** Derive declared effects FROM the steps' actions/effects — never free-form (the cross-modal guard). */
function deriveEffects(pattern: readonly TrajectoryStep[]): readonly string[] {
  const effects = new Set<string>();
  for (const step of pattern) {
    if (step.effect) { effects.add(step.effect); continue; }
    if (step.action.includes("edit") || step.action.includes("add") || step.action.includes("write")) effects.add("modifies repository files");
    if (step.action.includes("test") || step.action.includes("run")) effects.add("runs tests in the sandbox");
    if (step.action.includes("localize") || step.action.includes("read")) effects.add("reads repository files");
  }
  return [...effects];
}

/** Deterministic short content hash (FNV-1a) for a stable skill id. */
function hashShort(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(16).slice(0, 8);
}
