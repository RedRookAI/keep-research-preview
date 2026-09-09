/**
 * BUILD-ORDER 1.5 — WIRING (ledger 298): does the PIPELINE actually SELECT the Windows Job Object floor on a
 * win32 host? The predicate tests (windows_isolation_backend) prove `selectExecutor`; this proves the wiring
 * end-to-end through `solveIssueToPR`, on the spine audit artifact. The Windows floor shares the `process`
 * tier with the POSIX floor, so the audit is distinguished by the boundary MECHANISM label the
 * `BoundaryExecutor` records ("windows-job-object" vs the POSIX "process isolation"). With
 * `resolveIsolationExecutor()` neutered to always `new ProcessIsolationExecutor(...)`, the pipeline stops
 * selecting the Windows backend on win32 and this reddens — the audited mechanism drops back to the POSIX floor.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { KeepPipeline } from "../src/pipeline/keep_pipeline.js";
import { InMemoryMergePort } from "./helpers/in_memory_merge_port.js";
import { pinnedGitDependencies } from "./helpers/pinned_git_dependencies.js";
import type { ModelProvider, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { RepoFile } from "../src/solve/localize.js";
import type { WindowsRuntimeInfo } from "../src/infra/windows_isolation.js";

const BROKEN = "export function add(a, b) { return a - b; }";

function setupRemote(): string {
  const root = mkdtempSync(join(tmpdir(), "winw-"));
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

/** The isolated_execution audit details (the boundary MECHANISM is named here — 'windows-job-object' vs POSIX). */
function auditedDetails(s: Spine): string[] {
  return s.replay()
    .map((e: { payload?: Record<string, unknown> }) => e.payload)
    .filter((p): p is Record<string, unknown> => !!p && p["event"] === "isolated_execution" && p["executed"] === true)
    .map((p) => String(p["detail"]));
}

async function run(extra: Record<string, unknown>): Promise<{ details: string[] }> {
  const work = setupRemote();
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "winws-"))), new InProcessLock(), new SchemaRegistry());
  const tree = new InMemoryFileTree({ "src/calc.ts": BROKEN });
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  const files: RepoFile[] = [{ path: "src/calc.ts", content: BROKEN }];
  await new KeepPipeline({ spine, tree, runner, model, ...extra } as never).solveIssueToPR(
    { id: "WINW", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" },
    files,
    pinnedGitDependencies(work, new InMemoryMergePort()),
    { autonomyLevel: "operator" },
  );
  await spine.seal();
  return { details: auditedDetails(spine) };
}

test("WIRING: on a win32 host with a Job Object, the pipeline SELECTS the Windows Job Object floor", async () => {
  const detectWindows: () => WindowsRuntimeInfo = () => ({ kind: "job-object", available: true, tier: "process", platform: "win32", wsl2Present: false, netDenyEnforceable: true, detail: "test" });
  const { details } = await run({
    isolationCapabilities: { kvmAvailable: false, gvisorAvailable: false, containerRuntime: false, canScopeProcess: true },
    strongBoundary: {
      platform: "win32",
      detectWindows,
      // An explicit boundary runner standing in for the host Job Object (VERIFIED-SEAM stand-in) so the run executes.
      windowsBoundaryRun: (r: TestRunner, s: { repoRef: string }) => r.run(s.repoRef),
    },
  });
  assert.ok(details.some((d) => /windows-job-object/.test(d)), `the Windows floor must be selected+audited on win32; got: ${JSON.stringify(details)}`);
  assert.ok(!details.some((d) => /process isolation/.test(d)), "the POSIX process floor was NOT used when a Windows Job Object was available on win32");
});

test("WIRING: off-platform (the default) stays the POSIX process floor — no false Windows claim", async () => {
  const { details } = await run({});
  assert.ok(details.some((d) => /process isolation/.test(d)), `the default is the POSIX process floor; got: ${JSON.stringify(details)}`);
  assert.ok(!details.some((d) => /windows-job-object/.test(d)), "no Windows tier is claimed off-platform (honest)");
});
