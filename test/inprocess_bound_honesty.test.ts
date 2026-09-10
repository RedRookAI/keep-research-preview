/**
 * An opaque runner's audit must describe the bound actually applied. A direct call with no timeout or
 * caller deadline remains unbounded. The pipeline now supplies its operation deadline even when the
 * executor has no timeout option. These useful-work tests inspect that forwarding and its audit label;
 * process_cancellation_audit.test.ts separately exercises timeout, continued work and late results.
 * A bounded wait and cancellation signal are not enforced termination of an arbitrary callback.
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
import type { TestRunner, TestRunResult, TestExecutionContext } from "../src/solve/validate.js";
import type { RepoFile } from "../src/solve/localize.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-ibh-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
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
  // Neither an executor timeout nor a caller deadline is supplied to this direct call.
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
  assert.ok(details.some((d) => /time-bounded wait; callback termination not enforced/.test(d)));
  assert.ok(!details.some((d) => /UNBOUNDED/.test(d)), "an armed run is not UNBOUNDED");
});

// Pipeline wiring: the inherited operation deadline is part of the actual execution context.
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

test("WIRING: default pipeline forwards its operation deadline and reports bounded waiting, not callback termination", async () => {
  const work = setupRemote();
  const spine = newSpine();
  const tree = new InMemoryFileTree({ "src/calc.ts": BROKEN });
  const observed: { context: TestExecutionContext | undefined; startedAt: number }[] = [];
  // The operator's OWN runner — opaque (NOT a SandboxedCommandRunner), exactly the production `deps.runner`.
  const runner: TestRunner = {
    async run(_repoRef, context): Promise<TestRunResult> {
      observed.push({ context, startedAt: Date.now() });
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  const files: RepoFile[] = [{ path: "src/calc.ts", content: BROKEN }];
  // No isolationCapabilities, no injected isolationExecutor -> resolveIsolationExecutor() builds the process
  // floor with no timeout option. SolvePipeline must still forward its operation's deadline and signal.
  await new KeepPipeline({ spine, tree, runner, model } as never).solveIssueToPR(
    { id: "IBH", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" },
    files,
    pinnedGitDependencies(work, new InMemoryMergePort()),
    { autonomyLevel: "operator" },
  );
  await spine.seal();
  assert.ok(observed.length > 0, "the useful-work oracle actually ran");
  for (const { context, startedAt } of observed) {
    assert.ok(context?.signal instanceof AbortSignal, "the actual runner receives cancellation notification");
    assert.ok(Number.isFinite(context?.deadline), "the actual runner receives a finite deadline");
    assert.ok(context!.deadline! > startedAt, "the runner was admitted before its deadline");
  }
  const details = isoDetails(spine);
  assert.ok(details.length > 0, "the default path audited an isolated execution");
  assert.ok(details.some((d) => /time-bounded wait; callback termination not enforced/.test(d)), JSON.stringify(details));
  assert.ok(!details.some((d) => /UNBOUNDED/.test(d)), "an actual inherited deadline must not be reported absent");
});
