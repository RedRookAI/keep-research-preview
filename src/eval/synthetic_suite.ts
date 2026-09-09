/**
 * Synthetic eval suite (Increment 16b) — proves the harness end-to-end HERE.
 *
 * A TaskSource of self-contained planted-bug repos, each with REAL fail-to-pass + pass-to-pass tests
 * (actual functions evaluated against the patched file content). SyntheticInstanceRunner wires each
 * task through a real SolvePipeline under a scripted/replay model, then runs the tests against the
 * patched in-memory tree. No Docker, no dataset, no network — the whole harness contract is provable
 * in the sandbox. Real SWE-bench Verified/Pro adapters replace this suite behind the same TaskSource +
 * InstanceRunner ports on Hetzner. Zero deps.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../spine/spine.js";
import { FileSpineStore } from "../spine/store.js";
import { SchemaRegistry } from "../spine/upcaster.js";
import { InProcessLock } from "../lock/lock.js";
import { RollbackLedger } from "../control/rollback.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../gateway/gateway.js";

import { InMemoryFileTree } from "../solve/patch.js";
import { HierarchicalLocalizer } from "../solve/localize.js";
import type { TestRunner, TestRunResult } from "../solve/validate.js";
import { SolvePipeline } from "../solve/solve_pipeline.js";
import type { Issue, SolveResult } from "../solve/issue_model.js";

import type { EvalTask, TestExecution, TaskSource } from "./swebench_task.js";
import type { InstanceRunner } from "./harness.js";

/** A synthetic instance bundles the task, the buggy file, the fix, and executable test predicates. */
interface SyntheticInstance {
  readonly task: EvalTask;
  readonly files: Record<string, string>;
  readonly targetFile: string;
  /** The canned edit the (replay) model will produce. */
  readonly plannedEdit: { file: string; search: string; replace: string; intent: string };
  /** Test predicates evaluated against the CURRENT content of targetFile → pass/fail. */
  readonly tests: Record<string, (content: string) => boolean>;
}

/** Three planted-bug instances: a correct fix, a fix that regresses, and one the solver can't fix. */
const INSTANCES: SyntheticInstance[] = [
  {
    task: {
      instanceId: "calc__add-subtracts",
      repo: "synthetic/calc",
      baseCommit: "base",
      problemStatement: "add(a,b) returns a-b instead of a+b",
      failToPass: ["test_add_2_3_is_5"],
      passToPass: ["test_has_add_export"],
    },
    files: { "src/calc.ts": "export function add(a, b) { return a - b; }" },
    targetFile: "src/calc.ts",
    plannedEdit: { file: "src/calc.ts", search: "return a - b;", replace: "return a + b;", intent: "use + not -" },
    tests: {
      test_add_2_3_is_5: (c) => c.includes("a + b"),
      test_has_add_export: (c) => c.includes("export function add"),
    },
  },
  {
    task: {
      instanceId: "str__upper-broken",
      repo: "synthetic/str",
      baseCommit: "base",
      problemStatement: "shout() should upper-case; it currently lower-cases",
      failToPass: ["test_shout_upper"],
      passToPass: ["test_shout_exists"],
    },
    files: { "src/str.ts": "export function shout(s) { return s.toLowerCase(); }" },
    targetFile: "src/str.ts",
    plannedEdit: { file: "src/str.ts", search: "s.toLowerCase()", replace: "s.toUpperCase()", intent: "upper not lower" },
    tests: {
      test_shout_upper: (c) => c.includes("toUpperCase"),
      test_shout_exists: (c) => c.includes("export function shout"),
    },
  },
  {
    task: {
      instanceId: "math__unfixable",
      repo: "synthetic/math",
      baseCommit: "base",
      problemStatement: "square() is wrong (the model won't find the right fix in this instance)",
      failToPass: ["test_square_4_is_16"],
      passToPass: ["test_square_exists"],
    },
    files: { "src/math.ts": "export function square(x) { return x + x; }" },
    targetFile: "src/math.ts",
    // The planned edit is WRONG on purpose (search won't match) → solver gives up → unresolved.
    plannedEdit: { file: "src/math.ts", search: "return x * x;", replace: "return x * x;", intent: "no-op (won't match)" },
    tests: {
      test_square_4_is_16: (c) => c.includes("x * x"),
      test_square_exists: (c) => c.includes("export function square"),
    },
  },
];

/**
 * BUILD-ORDER 2.6 (ARM-THE-THIRD-CONSTRUCTION-SITE, Z138) — the arm-vs-refuse DECISION for the
 * eval construction site, recorded as a durable, auditable fact rather than a silent gap.
 *
 * Z138 threads the operator's kill switch + per-agent authority through the two OPERATOR entry
 * points (KeepPipeline round 35, buildDefaultSolver round 35). This — the synthetic suite — is the
 * THIRD site that news a real SolvePipeline (see the `new SolvePipeline({...})` below). It is left
 * DELIBERATELY un-armed, and this record is WHY.
 *
 * MEASURED (see redrook-ops/.round-artifacts/ARM-THE-THIRD-CONSTRUCTION-SITE/measurement.txt):
 * this construction site is a CLOSED, offline, IN-MEMORY measurement fixture — the solve target is
 * an `InMemoryFileTree`, the model is `scriptedModel` (isLocal, no network), "No Docker, no dataset,
 * no network". There is no operator (`new SyntheticInstanceRunner()` takes no registry; no caller
 * supplies one) and no external effect on the governed surface. So a kill switch here is inert-by-
 * construction: a switch only a test could throw, on a path nothing escapes, exercising an
 * intersection (2.2 agentScope) no eval uses. Arming it would be control-theatre — the 2026 SOTA
 * (kill-switch containment) attaches the obligation to effect/escape surfaces, and Saltzer-Schroeder
 * complete mediation guards OBJECTS that on this path do not exist.
 *
 * The EFFECT-BEARING eval runner already carries the seam: swe_eval.ts `RealSolverRunner`, which
 * materializes real on-disk dirs, routes through `buildDefaultSolver` (an already-armed entry
 * point). Only THIS runner news the pipeline bare, because it is the pure in-memory fixture.
 *
 * HONESTY BOUND: this record attests that the kill switch is DELIBERATELY ABSENT here and WHY — it
 * NEVER claims revocation is armed on the eval path. Emitted to the spine on every synthetic solve
 * (see `solve()`), so the exemption is auditable, never silent drift.
 */
export interface EvalKillSwitchRefusal {
  readonly site: string;
  readonly disposition: string;
  /** The SPECIFIC measured reason the eval construction site needs no kill switch. */
  readonly reason: string;
  /** The concrete trigger that flips this from refuse to arm — tied to an observable change. */
  readonly revisitWhen: string;
}

export const EVAL_KILL_SWITCH_REFUSAL: EvalKillSwitchRefusal = {
  site: "src/eval/synthetic_suite.ts SyntheticInstanceRunner.solve → new SolvePipeline",
  disposition: "refused (inert-by-construction; kill switch deliberately absent)",
  reason:
    "the synthetic eval construction site is a closed, offline, in-memory measurement fixture — the " +
    "solve target is an InMemoryFileTree and the model is a scripted local provider (no Docker, no " +
    "dataset, no network); there is no operator (the runner takes no registry and no caller supplies " +
    "one) and no external effect on the governed surface, so revocation and the 2.2 agentScope " +
    "intersection would be inert (a switch only a test could throw on a path nothing escapes, an " +
    "intersection no eval exercises) — arming it would be control-theatre, not a reachable capability.",
  revisitWhen:
    "re-arm (thread an operator-supplied identity + registry through the round-35 SolvePipeline deps) " +
    "if this construction site ever gains an external-effect surface — i.e. it stops driving a pure " +
    "InMemoryFileTree + scripted local model; the established pattern for a real effect surface is to " +
    "route through buildDefaultSolver, which already carries the seam (as swe_eval.ts RealSolverRunner does).",
};

/**
 * Return the eval kill-switch refusal as a plain audit fact, FAIL-CLOSED: a refusal with no recorded
 * reason OR no revisit condition is not a governed decision, it is silent drift — the exact gap the
 * Z138 family exists to close — so an empty record throws rather than auditing a hollow "refused".
 * Mirrors reversibleEnvelopeStabilizationFact() (solve_pipeline.ts). The solve path audits the
 * returned value to the spine.
 */
export function evalKillSwitchRefusalFact(
  record: EvalKillSwitchRefusal = EVAL_KILL_SWITCH_REFUSAL,
): EvalKillSwitchRefusal {
  const reason = record.reason?.trim() ?? "";
  const revisit = record.revisitWhen?.trim() ?? "";
  if (reason.length === 0 || revisit.length === 0) {
    throw new Error(
      "eval kill-switch REFUSAL is undocumented — a deliberately un-armed construction site must " +
        "record BOTH the specific reason it needs no kill switch AND a revisit condition " +
        "(fail-closed: no silent latent gap).",
    );
  }
  return {
    site: record.site,
    disposition: record.disposition,
    reason,
    revisitWhen: revisit,
  };
}

export class SyntheticSuite implements TaskSource {
  readonly name = "synthetic-planted-bugs";
  async load(): Promise<readonly EvalTask[]> { return INSTANCES.map((i) => i.task); }
  caveats(): readonly string[] {
    return ["synthetic suite — proves the harness contract; not a real-world resolution number (that is the Hetzner seam)"];
  }
}

/** The instance runner: real SolvePipeline per task; tests evaluated against the patched tree. */
export class SyntheticInstanceRunner implements InstanceRunner {
  private readonly byId = new Map(INSTANCES.map((i) => [i.task.instanceId, i]));
  private readonly trees = new Map<string, InMemoryFileTree>();

  /**
   * BUILD-ORDER 2.6 (Z138) — an OPTIONAL operator-visible spine for the kill-switch refusal audit.
   * Omit ⇒ the refusal is staged to the fixture's own per-instance spine exactly as before, so
   * `new SyntheticInstanceRunner()` is byte-identical. Supplied ⇒ the refusal fact also lands where
   * the operator can read it. This is an AUDIT sink, NOT an identity/registry — the measured decision
   * is that this construction site needs no kill switch (see {@link EVAL_KILL_SWITCH_REFUSAL}); it
   * needs its deliberate absence to be auditable, which is what this makes observable.
   */
  constructor(private readonly auditSink?: Spine) {}

  async solve(task: EvalTask): Promise<SolveResult> {
    const inst = this.byId.get(task.instanceId);
    if (!inst) throw new Error(`unknown synthetic instance ${task.instanceId}`);

    const dir = mkdtempSync(join(tmpdir(), "keep-eval-"));
    const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
    const tree = new InMemoryFileTree({ ...inst.files });
    this.trees.set(task.instanceId, tree);

    // BUILD-ORDER 2.6 (Z138) — this construction site news a real SolvePipeline WITHOUT an operator
    // identity/registry, and that is a DECISION, not an oversight. Emit the fail-closed refusal fact
    // to the spine so the deliberately-absent kill switch is AUDITABLE (never silent drift). Fails
    // closed if the record is ever hollowed out. Observe-only: it never changes the SolveResult, so a
    // no-identity eval run (the only way this suite runs) is byte-identical — the outcomes/score do
    // not move. HONESTY BOUND: this attests the switch is deliberately absent and WHY; it never
    // claims revocation is armed here.
    (this.auditSink ?? spine).stage({
      type: "identity.action",
      actor: "eval-construction-site",
      payload: { event: "kill_switch.refused", instanceId: task.instanceId, ...evalKillSwitchRefusalFact() },
    });

    const model = scriptedModel(inst.plannedEdit);
    const repoFiles = Object.entries(inst.files).map(([path, content]) => ({ path, content }));

    // The pipeline's own TestRunner checks the primary (fail-to-pass) predicate against the tree.
    const runner: TestRunner = {
      async run(): Promise<TestRunResult> {
        const content = (await tree.read(inst.targetFile)) ?? "";
        const results = inst.task.failToPass.map((name) => {
          const ok = inst.tests[name]!(content);
          return { name, passed: ok, ...(ok ? {} : { output: `predicate ${name} failed` }) };
        });
        return { results };
      },
    };

    const pipeline = new SolvePipeline({
      spine, ledger: new RollbackLedger(spine), tree, runner,
      localizer: new HierarchicalLocalizer(), model,
    });
    const issue: Issue = { id: task.instanceId, text: task.problemStatement, repoRef: task.instanceId };
    return pipeline.run(issue, repoFiles);
  }

  async runTests(task: EvalTask, testNames: readonly string[]): Promise<TestExecution> {
    const inst = this.byId.get(task.instanceId)!;
    const tree = this.trees.get(task.instanceId);
    const content = tree ? (await tree.read(inst.targetFile)) ?? "" : inst.files[inst.targetFile] ?? "";
    const passed: Record<string, boolean> = {};
    for (const name of testNames) {
      const pred = inst.tests[name];
      passed[name] = pred ? pred(content) : false; // unknown test → not run → false
    }
    return { passed };
  }

  costUsd(_task: EvalTask, result: SolveResult): number {
    // Synthetic cost proxy: a small fixed cost per stage run (real cost comes from the gateway on Hetzner).
    return result.stagesRun.length * 0.001;
  }
}

/** A model that returns the canned edit plan JSON (stands in for the replay provider). */
function scriptedModel(edit: { file: string; search: string; replace: string; intent: string }): ModelProvider {
  return {
    name: "scripted-eval",
    isLocal: true,
    async generate(_req: GenerateRequest): Promise<GenerateResult> {
      const json = JSON.stringify({ rationale: "planted-bug fix", edits: [edit] });
      return { text: json, model: "scripted-eval", tokensIn: 10, tokensOut: 20 };
    },
    async embed(_texts: readonly string[]): Promise<Embedding[]> { return []; },
  };
}
