/**
 * Extract candidate reusable action patterns from supplied successful trajectories. The structured
 * envelope parameterizes targets, retains common action ordering, and derives declared effects from
 * recorded steps. The order check compares action names, not executable semantic equivalence.
 *
 * Success and effect records are trusted inputs. Keyword screening of declared effects does not
 * establish containment, consistency of arbitrary prose, or the absence of undeclared effects.
 * Candidates need separate execution checks and, for improvement claims, comparative evaluation.
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
  /** "corroborated" counts distinct supplied solve IDs of one task shape, not independent administration. */
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
  readonly extraction?: {
    readonly retainedActions: readonly string[];
    readonly omittedSourceSteps: number;
    readonly distinctSourceSolves: number;
    readonly collapsedTargetSlots: boolean;
  };
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

    // Parameterize the common steps and derive declarations from the supplied action/effect records.
    const steps = pattern.map((p) => ({ action: p.action, targetPattern: parameterize(p.target) }));
    const retainedActions = new Set(pattern.map(step => step.action));
    const contributing = successful.flatMap(t => t.steps.filter(step => retainedActions.has(step.action)));
    // Every occurrence of a retained action contributes: repeated-action ambiguity
    // must not hide another supplied effect. Distinct omitted actions remain outside
    // this pattern's screen; this is not an all-trace safety verdict.
    const declaredEffects = [...deriveEffects(contributing)].sort();
    const distinctSources = [...new Set(successful.map(t => t.solveId))];
    const extraction = {
      retainedActions: [...retainedActions],
      omittedSourceSteps: successful.reduce((n, t) => n + t.steps.filter(step => !retainedActions.has(step.action)).length, 0),
      distinctSourceSolves: distinctSources.length,
      collapsedTargetSlots: successful.some(t => {
        const slots = new Map<string, Set<string>>();
        for (const step of t.steps.filter(step => retainedActions.has(step.action))) {
          const slot = parameterize(step.target), targets = slots.get(slot) ?? new Set<string>();
          targets.add(step.target); slots.set(slot, targets);
        }
        return [...slots.values()].some(targets => targets.size > 1);
      }),
    };

    // Screen declared effects for known forbidden terms; this does not observe actual execution.
    const sink = declaredEffects.find((e) => FORBIDDEN_SINKS.some((s) => e.toLowerCase().includes(s)));
    if (sink) return { rejected: `distilled skill declares a forbidden sink ("${sink}") — requires a human gate, not auto-distill`, extraction };

    const envelope: StructuredEnvelope = {
      preconditions: [`task shape is "${shape}"`],
      steps,
      parameters: [...new Set(steps.map((step) => step.targetPattern.slice(1, -1) as "file" | "symbol" | "arg"))].map((name) => ({ name, type: "string" as const, required: true as const })),
      postconditions: ["produced patch passes its tests", "no safety regression"],
      declaredEffects,
    };

    // Require the extracted action names to occur in order in each source trajectory.
    for (const t of successful) {
      if (!this.reconstructs(envelope, t)) {
        return { rejected: `faithfulness check failed — the skill does not reconstruct trajectory ${t.solveId}`, extraction };
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
      provenance: distinctSources,
      confidence: distinctSources.length >= 2 ? "corroborated" : "low",
    };
    return { skill, extraction };
  }

  /** First-source action-membership intersection, followed by an order check; not an LCS algorithm. */
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

  /** Action-name subsequence check; not target, effect, or executable-behavior equivalence. */
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

/** Derive declarations from supplied effects or action-name heuristics; these are not observed effects. */
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
