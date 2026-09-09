/**
 * BOUND-THE-DEFAULT-INPROCESS-PATH (Z189) — the DEFAULT in-process isolation path must NEVER audit a
 * "time-bounded" bound it did not apply. MEASURED: all three production constructions of
 * ProcessIsolationExecutor pass NO timeoutMs (keep_pipeline.ts:370, isolated_executor.ts:348/:352), and the
 * production inner runner is the operator's OPAQUE `deps.runner` (keep_pipeline.ts:444) — so the default path
 * runs UNBOUNDED (isolated_executor.ts:137) yet used to audit "in-process, time-bounded". DECISION (evidence-
 * bound): HONEST-THE-CLAIM — a universal default timeout would murder a legitimately-long opaque operator
 * suite, so arming stays opt-in via the EXISTING opts.timeoutMs->raceTimeout seam; the audit branches on the
 * bound ACTUALLY applied, never on command-vs-in-process.
 *
 * DISPROOF (each neuter isolates ONE property):
 *   HONEST-(a): revert the in-process label back to always "time-bounded" -> the UNBOUNDED default audit
 *               claims a bound it never applied -> RED (assertion #a fails).
 *   HONEST-(b): drop the "in-process, time-bounded" label on a genuinely-armed run -> RED (#b fails).
 *   WIRING (ledger 298): the PRODUCTION default pipeline path (no caps, opaque operator runner) must audit
 *               its in-process run as UNBOUNDED — reverting the label reddens the end-to-end default path.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { ProcessIsolationExecutor } from "../src/isolation/isolated_executor.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { KeepPipeline } from "../src/pipeline/keep_pipeline.js";
import { InMemoryMergePort } from "./helpers/in_memory_merge_port.js";
import { pinnedGitDependencies } from "./helpers/pinned_git_dependencies.js";
import type { ModelProvider, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { RepoFile } from "../src/solve/localize.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-ibh-"))), new InProcessLock(), new SchemaRegistry());
}
function isoDetails(s: Spine): string[] {
  return s.replay()
    .map((e: { payload?: Record<string, unknown> }) => e.payload)
    .filter((p): p is Record<string, unknown> => !!p && p["event"] === "isolated_execution")
    .map((p) => String(p["detail"]));
}
// An OPAQUE in-process runner — exactly the shape the production `deps.runner` is (NOT a SandboxedCommandRunner).
const opaqueGreen: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "x", passed: true }] }; } };

test("HONEST-(a): the DEFAULT (unarmed) in-process run is audited UNBOUNDED, NEVER 'time-bounded'", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-ibh-a-"));
  const s = newSpine();
  // The EXACT production floor construction (keep_pipeline.ts:370 / isolated_executor.ts:348/:352): no timeout.
  const exec = new ProcessIsolationExecutor(s);
  const out = await exec.runIsolated(opaqueGreen, { projectDir: base, repoRef: ".", patchRisk: "medium" });
  await s.seal();
  assert.equal(out.executed, true, "the run executed (an unbounded run still runs — we do not force a kill)");
  const details = isoDetails(s);
  assert.ok(details.some((d) => /UNBOUNDED/.test(d)), `an unarmed in-process run must be audited UNBOUNDED; got: ${JSON.stringify(details)}`);
  assert.ok(!details.some((d) => /time-bounded/.test(d)), "an UNBOUNDED run must NEVER claim 'time-bounded' — the honesty invariant");
});

test("HONEST-(b): a genuinely ARMED in-process run IS audited 'time-bounded' (the bound was applied)", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-ibh-b-"));
  const s = newSpine();
  // Operator armed the seam: a real applied bound -> the audit truthfully says time-bounded (generous ms; the
  // green runner returns immediately, so the bound never fires — we assert the LABEL, not a timeout).
  const exec = new ProcessIsolationExecutor(s, { timeoutMs: 30_000 });
  const out = await exec.runIsolated(opaqueGreen, { projectDir: base, repoRef: ".", patchRisk: "medium" });
  await s.seal();
  assert.equal(out.executed, true, "the in-bounds run completed normally — an armed bound does not change a normal outcome");
  const details = isoDetails(s);
  assert.ok(details.some((d) => /in-process, time-bounded/.test(d)), `an armed in-process run must be audited time-bounded; got: ${JSON.stringify(details)}`);
  assert.ok(!details.some((d) => /UNBOUNDED/.test(d)), "an armed run is not UNBOUNDED");
});

// ---- WIRING (ledger 298): the PRODUCTION default pipeline path audits UNBOUNDED, end-to-end ----
const BROKEN = "export function add(a, b) { return a - b; }";
function setupRemote(): string {
  const root = mkdtempSync(join(tmpdir(), "ibh-w-"));
  const bare = join(root, "o.git"), work = join(root, "w");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  execFileSync("git", ["clone", "-q", bare, work]);
  const g = (a: string[]) => execFileSync("git", a, { cwd: work });
  g(["config", "user.email", "t@t"]); g(["config", "user.name", "t"]); g(["checkout", "-qb", "main"]);
  execFileSync("bash", ["-c", `mkdir -p ${join(work, "src")} && printf '%s' '${BROKEN}\n' > ${join(work, "src/calc.ts")}`]);
  g(["add", "-A"]); g(["commit", "-qm", "init"]); g(["push", "-q", "-u", "origin", "main"]);
  execFileSync("bash", ["-c", `printf '%s' 'export function add(a, b) { return a + b; }\n' > ${join(work, "src/calc.ts")}`]);
  return work;
}
const model: ModelProvider = {
  name: "fix", isLocal: true,
  async generate(): Promise<GenerateResult> {
    return { text: JSON.stringify({ rationale: "fix", edits: [{ file: "src/calc.ts", search: "a - b", replace: "a + b", intent: "fix" }] }), model: "fix", tokensIn: 1, tokensOut: 1 };
  },
  async embed(): Promise<Embedding[]> { return []; },
};

test("WIRING (ledger 298): the DEFAULT pipeline path audits its in-process run UNBOUNDED, never 'time-bounded'", async () => {
  const work = setupRemote();
  const spine = newSpine();
  const tree = new InMemoryFileTree({ "src/calc.ts": BROKEN });
  // The operator's OWN runner — opaque (NOT a SandboxedCommandRunner), exactly the production `deps.runner`.
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  const files: RepoFile[] = [{ path: "src/calc.ts", content: BROKEN }];
  // No isolationCapabilities, no injected isolationExecutor -> resolveIsolationExecutor() builds the process
  // floor with NO timeout (the exact production default), wrapping the opaque runner above.
  await new KeepPipeline({ spine, tree, runner, model } as never).solveIssueToPR(
    { id: "IBH", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" },
    files,
    pinnedGitDependencies(work, new InMemoryMergePort()),
    { autonomyLevel: "operator" },
  );
  await spine.seal();
  const details = isoDetails(spine);
  assert.ok(details.length > 0, "the default path audited an isolated execution");
  assert.ok(details.some((d) => /UNBOUNDED/.test(d)), `the production default in-process run must audit UNBOUNDED; got: ${JSON.stringify(details)}`);
  assert.ok(!details.some((d) => /time-bounded/.test(d)), "the production default path must NEVER claim a bound it did not apply");
});
