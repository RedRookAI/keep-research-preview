/**
 * Deterministic sound critics (Increment 3.8a) — the author-independent logic gate.
 *
 * SOTA basis (re-verified 2026-08-04): intrinsic self-critique DEGRADES reasoning (Huang ICLR 2024;
 * Kamoi TACL 2024; Stechly; arXiv 2402.08115) — "the self-critiquing loop performs worse than
 * guessing up front." What works is a SOUND EXTERNAL verifier / "a menagerie of partial critics
 * where consensus is verification." And crucially (SAVeR arXiv 2604.08401; preprints.org):
 * "consensus is NOT faithfulness — correlated LLM critics share blind spots." So the strongest
 * independence is a DETERMINISTIC, non-model critic. These four critics are pure executable logic:
 * they run with ZERO models, cannot be fooled by fluent prose, and are the load-bearing gate that
 * works even for a single-key operator (AutoPyVerifier arXiv 2604.22937).
 *
 * Zero deps.
 */

/** A step in a plan being vetted. `dependsOn` references other step ids (prerequisites). */
export interface PlanStep {
  readonly id: string;
  readonly description: string;
  /** Ids of steps that MUST complete before this one. */
  readonly dependsOn: readonly string[];
  /** Optional: assertions this step establishes (for contradiction checking). */
  readonly asserts?: readonly string[];
  /** Optional: assertions this step requires to be TRUE (for contradiction checking). */
  readonly requires?: readonly string[];
}

/** A plan = ordered steps + metadata the critics check against. */
export interface Plan {
  readonly goal: string;
  readonly steps: readonly PlanStep[];
}

/** Hard constraints the plan must satisfy (from estimator/autonomy/feasibility/user). */
export interface PlanConstraints {
  readonly maxSteps?: number; // proportionality ceiling
  readonly minSteps?: number; // proportionality floor
  readonly budgetTokens?: number;
  readonly estimatedTokens?: number;
  readonly feasibilityClass?: "deliverable" | "assist-only" | "infeasible" | "out-of-scope";
  /** User-set rigid boundaries (VeriPlan pattern): forbidden actions the plan must not include. */
  readonly forbiddenActions?: readonly string[];
}

/** Every critic returns one of these, with a grounded reason. */
export type CriticStatus = "pass" | "concern" | "block";
export interface CriticVerdict {
  readonly critic: string;
  readonly status: CriticStatus;
  readonly reason: string;
  /** Which step ids are implicated (for targeted rework — rethink, not global recheck). */
  readonly implicated: readonly string[];
  /** True if this critic is SOUND (deterministic) — its block is authoritative. */
  readonly sound: boolean;
}

// ── Order-of-operations critic (dependency graph — sound) ────────────────────

/**
 * Build a dependency graph and detect: (1) references to unknown steps (missing prerequisite),
 * (2) cycles, (3) forward references relative to the given ordering (a step depends on one that
 * appears later). Directly answers "order of operations is always logical." Deterministic.
 */
export function orderCritic(plan: Plan): CriticVerdict {
  const ids = new Set(plan.steps.map((s) => s.id));
  const index = new Map(plan.steps.map((s, i) => [s.id, i]));
  const missing: string[] = [];
  const forwardRefs: string[] = [];

  for (const step of plan.steps) {
    for (const dep of step.dependsOn) {
      if (!ids.has(dep)) {
        missing.push(`${step.id}→${dep}`);
      } else if ((index.get(dep) ?? -1) > (index.get(step.id) ?? -1)) {
        forwardRefs.push(`${step.id} depends on later step ${dep}`);
      }
    }
  }

  const cycle = findCycle(plan);

  if (missing.length > 0) {
    return {
      critic: "order-of-operations",
      status: "block",
      reason: `missing prerequisite step(s): ${missing.join(", ")}`,
      implicated: missing.map((m) => m.split("→")[0]!),
      sound: true,
    };
  }
  if (cycle.length > 0) {
    return {
      critic: "order-of-operations",
      status: "block",
      reason: `dependency cycle: ${cycle.join(" → ")}`,
      implicated: cycle,
      sound: true,
    };
  }
  if (forwardRefs.length > 0) {
    return {
      critic: "order-of-operations",
      status: "block",
      reason: `steps out of order: ${forwardRefs.join("; ")}`,
      implicated: forwardRefs.map((f) => f.split(" ")[0]!),
      sound: true,
    };
  }
  return { critic: "order-of-operations", status: "pass", reason: "dependencies acyclic and ordered", implicated: [], sound: true };
}

/** DFS cycle detection over the dependsOn edges. Returns a cycle path or []. */
function findCycle(plan: Plan): string[] {
  const adj = new Map<string, readonly string[]>(plan.steps.map((s) => [s.id, s.dependsOn]));
  const WHITE = 0, GRAY = 1, BLACK = 2;
  const color = new Map<string, number>(plan.steps.map((s) => [s.id, WHITE]));
  const stack: string[] = [];

  function dfs(node: string): string[] | null {
    color.set(node, GRAY);
    stack.push(node);
    for (const next of adj.get(node) ?? []) {
      if (!color.has(next)) continue; // unknown dep handled by missing-check
      if (color.get(next) === GRAY) {
        const i = stack.indexOf(next);
        return stack.slice(i).concat(next);
      }
      if (color.get(next) === WHITE) {
        const c = dfs(next);
        if (c) return c;
      }
    }
    stack.pop();
    color.set(node, BLACK);
    return null;
  }

  for (const s of plan.steps) {
    if (color.get(s.id) === WHITE) {
      const c = dfs(s.id);
      if (c) return c;
    }
  }
  return [];
}

// ── Constraint-satisfaction critic (sound) ──────────────────────────────────

export function constraintCritic(plan: Plan, c: PlanConstraints): CriticVerdict {
  const problems: string[] = [];
  if (c.feasibilityClass === "infeasible" || c.feasibilityClass === "out-of-scope") {
    problems.push(`feasibility class is ${c.feasibilityClass}`);
  }
  if (c.budgetTokens !== undefined && c.estimatedTokens !== undefined && c.estimatedTokens > c.budgetTokens) {
    problems.push(`estimated ${c.estimatedTokens} tokens exceeds budget ${c.budgetTokens}`);
  }
  if (c.forbiddenActions && c.forbiddenActions.length > 0) {
    for (const step of plan.steps) {
      for (const forbidden of c.forbiddenActions) {
        if (step.description.toLowerCase().includes(forbidden.toLowerCase())) {
          problems.push(`step ${step.id} includes forbidden action "${forbidden}"`);
        }
      }
    }
  }
  if (problems.length > 0) {
    return { critic: "constraint-satisfaction", status: "block", reason: problems.join("; "), implicated: [], sound: true };
  }
  return { critic: "constraint-satisfaction", status: "pass", reason: "within budget, feasibility, and boundaries", implicated: [], sound: true };
}

// ── Proportionality critic (sound-ish: structural, catches over/under-reaction) ──

export function proportionalityCritic(plan: Plan, c: PlanConstraints): CriticVerdict {
  const n = plan.steps.length;
  if (c.maxSteps !== undefined && n > c.maxSteps) {
    return {
      critic: "proportionality",
      status: "concern",
      reason: `plan has ${n} steps; goal warrants at most ${c.maxSteps} (possible over-engineering)`,
      implicated: [],
      sound: true,
    };
  }
  if (c.minSteps !== undefined && n < c.minSteps) {
    return {
      critic: "proportionality",
      status: "concern",
      reason: `plan has ${n} steps; goal needs at least ${c.minSteps} (possible under-scoping)`,
      implicated: [],
      sound: true,
    };
  }
  return { critic: "proportionality", status: "pass", reason: "plan size proportionate to the goal", implicated: [], sound: true };
}

// ── Contradiction critic (sound: pairwise assertion conflict) ────────────────

/**
 * Detect internal contradictions: a step that REQUIRES an assertion whose negation is ASSERTED by
 * another step (or vice versa). Grounded, cheap, deterministic. Negation detected by a "not "
 * prefix convention on assertions (e.g. "authenticated" vs "not authenticated").
 */
export function contradictionCritic(plan: Plan): CriticVerdict {
  const asserted = new Map<string, string>(); // assertion → step id
  for (const step of plan.steps) {
    for (const a of step.asserts ?? []) asserted.set(normalize(a), step.id);
  }
  const conflicts: string[] = [];
  const implicated: string[] = [];
  for (const step of plan.steps) {
    for (const need of step.requires ?? []) {
      const neg = negate(normalize(need));
      if (asserted.has(neg)) {
        conflicts.push(`step ${step.id} requires "${need}" but step ${asserted.get(neg)} asserts its negation`);
        implicated.push(step.id, asserted.get(neg)!);
      }
    }
  }
  // also detect direct assert/assert conflicts
  for (const [a, sid] of asserted) {
    const neg = negate(a);
    if (asserted.has(neg)) {
      conflicts.push(`steps assert contradictory facts: "${a}" (${sid}) vs its negation (${asserted.get(neg)})`);
      implicated.push(sid, asserted.get(neg)!);
    }
  }
  if (conflicts.length > 0) {
    return { critic: "contradiction", status: "block", reason: dedupe(conflicts).join("; "), implicated: dedupe(implicated), sound: true };
  }
  return { critic: "contradiction", status: "pass", reason: "no internal contradictions found", implicated: [], sound: true };
}

function normalize(s: string): string {
  return s.trim().toLowerCase();
}
function negate(s: string): string {
  return s.startsWith("not ") ? s.slice(4) : `not ${s}`;
}
function dedupe(a: readonly string[]): string[] {
  return [...new Set(a)];
}

/** The full deterministic critic panel (all sound, zero models). */
export function deterministicCritics(plan: Plan, constraints: PlanConstraints): CriticVerdict[] {
  return [
    orderCritic(plan),
    constraintCritic(plan, constraints),
    proportionalityCritic(plan, constraints),
    contradictionCritic(plan),
  ];
}
