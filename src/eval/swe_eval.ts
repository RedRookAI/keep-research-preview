/**
 * Real SWE-eval runner (Increment 4.2) — produces a GENUINE resolved-rate by running Keep's ACTUAL solver on a
 * decontaminated suite with REAL sandboxed test execution and the exact SWE-bench oracle.
 *
 * Per instance: decontaminate → materialize the buggy repo on disk → run the solver (buildDefaultSolver over a real
 * LocalFsWorkspace, patching real files) → independently run the hidden FAIL_TO_PASS + PASS_TO_PASS tests inside the
 * process-isolation sandbox (SandboxedCommandRunner + node --test) → judgeResolution (FAIL_TO_PASS must flip to passing,
 * PASS_TO_PASS must not regress) → aggregate with computeReport.
 *
 * HONEST SCOPE (stated in the report): the in-environment default brain is the deterministic LocalProvider (a stub that
 * cannot synthesize patches), so its resolved-rate is a genuine FLOOR, not a capability measure. Swap `provider` for a
 * frontier model (reachable but key-gated here) and the SAME harness yields a real capability number. This suite is a
 * self-authored, decontaminated micro-suite — NOT the official SWE-bench Verified number.
 */

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";

import { LOCAL_SUITE, type LocalEvalInstance } from "./local_suite.js";
import { decontaminate, type DecontaminationPolicy } from "./decontamination.js";
import { judgeResolution, type EvalTask, type TestExecution } from "./swebench_task.js";
import { runInstance, type InstanceRunner } from "./harness.js";
import { computeReport, type EvalReport } from "./report.js";
import { Spine } from "../spine/spine.js";
import { FileSpineStore } from "../spine/store.js";
import { InProcessLock } from "../lock/lock.js";
import { SchemaRegistry } from "../spine/upcaster.js";
import { LocalFsWorkspace } from "../solve/workspace.js";
import { buildDefaultSolver, validatorRunner } from "../solve/default_solver.js";
import { SandboxedCommandRunner } from "../solve/sandboxed_runner.js";
import { LocalProvider } from "../gateway/local_provider.js";
import type { ModelProvider } from "../gateway/gateway.js";

function writeTree(dir: string, files: Readonly<Record<string, string>>): void {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, content, "utf8");
  }
}

/** Run node --test in the repo (sandboxed) and map each requested test name → passed (via TAP per-case parsing). */
async function runNamedTests(projectDir: string, testNames: readonly string[]): Promise<TestExecution> {
  const runner = new SandboxedCommandRunner({ command: "node", args: ["--test"], projectDir, timeoutMs: 30_000 });
  const res = await runner.run(projectDir);
  const passed: Record<string, boolean> = {};
  for (const name of testNames) passed[name] = false; // default: not-run ⇒ fail
  // SandboxedCommandRunner already parses TAP per-case; map the requested test names to their pass/fail.
  for (const c of res.results) if (c.name in passed) passed[c.name] = c.passed;
  return { passed };
}

/** A runner backed by Keep's real solver (the model attempts the fix), with sandboxed hidden-test judging. */
class RealSolverRunner implements InstanceRunner {
  private dirs = new Map<string, string>();
  constructor(private readonly provider: ModelProvider, private readonly spine: Spine) {}

  private materialize(inst: LocalEvalInstance): string {
    let dir = this.dirs.get(inst.task.instanceId);
    if (!dir) {
      dir = mkdtempSync(join(tmpdir(), `keep-eval-${inst.task.instanceId.replace(/[^\w]/g, "_")}-`));
      writeTree(dir, inst.files);
      this.dirs.set(inst.task.instanceId, dir);
    }
    return dir;
  }

  async solve(task: EvalTask): Promise<import("../solve/issue_model.js").SolveResult> {
    const inst = byId(task.instanceId);
    const base = this.materialize(inst);
    const ws = new LocalFsWorkspace(base);
    // The solver's OWN validation runner is deterministic here; the eval's judgment uses the hidden tests separately.
    const solve = buildDefaultSolver({
      spine: this.spine, model: this.provider, workspace: ws,
      runnerFor: (_ref, tree) => validatorRunner(tree, async () => true),
    });
    const out = await solve({ id: task.instanceId, text: task.problemStatement, repoRef: "." });
    return out.solveResult;
  }

  async runTests(task: EvalTask, testNames: readonly string[]): Promise<TestExecution> {
    return runNamedTests(this.dirs.get(task.instanceId)!, testNames);
  }

  cleanup(): void { for (const d of this.dirs.values()) try { rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } }
}

/** An ORACLE runner: applies the gold patch (never shown to a solver). Validates that the harness + hidden tests are
 * real — a correct patch MUST resolve, a buggy tree must NOT. */
class OracleRunner implements InstanceRunner {
  private dirs = new Map<string, string>();
  constructor(private readonly applyGold: boolean) {}
  async solve(task: EvalTask): Promise<import("../solve/issue_model.js").SolveResult> {
    const inst = byId(task.instanceId);
    const dir = mkdtempSync(join(tmpdir(), `keep-oracle-${this.applyGold ? "gold" : "buggy"}-`));
    writeTree(dir, inst.files);
    if (this.applyGold) writeTree(dir, inst.goldFiles);
    this.dirs.set(task.instanceId, dir);
    return { issueId: task.instanceId, solved: this.applyGold, stagesRun: [], repairRounds: 0,
      validation: { testsPassed: this.applyGold, failures: [], vettingCleared: this.applyGold, detail: "oracle" } as never,
      ...(this.applyGold ? { prProposal: { title: "gold", body: "", branch: "b", edits: [], testsPassed: true } } : {}) };
  }
  async runTests(task: EvalTask, testNames: readonly string[]): Promise<TestExecution> {
    return runNamedTests(this.dirs.get(task.instanceId)!, testNames);
  }
  cleanup(): void { for (const d of this.dirs.values()) try { rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } }
}

function byId(id: string): LocalEvalInstance {
  const inst = LOCAL_SUITE.find((i) => i.task.instanceId === id);
  if (!inst) throw new Error(`unknown instance ${id}`);
  return inst;
}

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-eval-spine-"))), new InProcessLock(), new SchemaRegistry());
}

export interface SweEvalResult {
  readonly report: EvalReport;
  readonly admitted: number;
  readonly excluded: number;
  readonly excludedByReason: Readonly<Record<string, number>>;
}

/** Run the eval over the decontaminated local suite with a given solver runner factory. */
async function runSuite(makeRunner: () => InstanceRunner & { cleanup(): void }, suiteName: string, policy: DecontaminationPolicy, caveats: readonly string[]): Promise<SweEvalResult> {
  const decon = decontaminate(LOCAL_SUITE.map((i) => i.task), policy);
  const runner = makeRunner();
  const spine = newSpine();
  try {
    const runs = [];
    for (const task of decon.admitted) runs.push(await runInstance(task, runner, spine));
    const report = computeReport(suiteName, runs, caveats);
    return { report, admitted: decon.admitted.length, excluded: decon.rejected.length, excludedByReason: decon.excludedByReason };
  } finally { runner.cleanup(); }
}

/** The honest baseline: Keep's real pipeline with the in-env LOCAL provider (a floor — the stub can't synthesize). */
export async function runLocalBaseline(provider: ModelProvider = new LocalProvider()): Promise<SweEvalResult> {
  const spine = newSpine();
  return runSuite(() => new RealSolverRunner(provider, spine), "keep-local-decontaminated", { modelCutoff: "2026-01-31" }, [
    "Self-authored decontaminated micro-suite — NOT official SWE-bench Verified.",
    "Solver brain = deterministic LocalProvider (a stub); this resolved-rate is a FLOOR, not a capability measure.",
    "A frontier model behind the same ModelProvider port yields a real capability number (reachable but key-gated here).",
  ]);
}

/** Harness validation: an oracle that applies the gold patch must resolve; the buggy tree must not. */
export async function runOracleValidation(applyGold: boolean): Promise<SweEvalResult> {
  return runSuite(() => new OracleRunner(applyGold), applyGold ? "oracle-gold" : "oracle-buggy", {}, [
    applyGold ? "Oracle applies the gold patch — validates the harness resolves a correct fix." : "Oracle applies NO fix — validates the harness does NOT resolve a buggy tree.",
  ]);
}

export function formatEvalReport(r: SweEvalResult): string {
  const p = r.report;
  const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
  const line = "─".repeat(64);
  const out = [
    line,
    `  KEEP — SWE-eval: ${p.suiteName}`,
    line,
    `  Instances (decontaminated) : ${p.instanceCount}   (excluded ${r.excluded}${r.excluded ? ` — ${JSON.stringify(r.excludedByReason)}` : ""})`,
    `  Resolve@1                  : ${pct(p.resolveAt1)}   (${p.failureBreakdown.resolved}/${p.instanceCount})`,
    `  Regression rate            : ${pct(p.regressionRate)}`,
    `  Failure breakdown          : ${JSON.stringify(p.failureBreakdown)}`,
    `  Mean latency               : ${p.meanLatencyMs.toFixed(0)} ms`,
    line,
    "  Caveats:",
    ...p.caveats.map((c) => `   • ${c}`),
    line,
  ];
  return out.join("\n");
}

// Runnable: `node dist/src/eval/swe_eval.js`
if (import.meta.url === `file://${process.argv[1]}`) {
  const baseline = await runLocalBaseline();
  console.log(formatEvalReport(baseline));
  const goldOk = await runOracleValidation(true);
  const buggy = await runOracleValidation(false);
  console.log("\n  Harness validation (does the oracle measure real resolution?):");
  console.log(`   • gold-patch oracle resolves : ${(goldOk.report.resolveAt1 * 100).toFixed(1)}%  (expect 100% — a correct patch resolves)`);
  console.log(`   • buggy (no-fix) oracle       : ${(buggy.report.resolveAt1 * 100).toFixed(1)}%  (expect 0% — a broken tree never resolves)`);
}
