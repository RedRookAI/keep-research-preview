/**
 * BUILD-ORDER 1.3c — WIRING (ledger 298): does the PIPELINE actually SELECT the strong executor where a
 * runtime is available? The predicate tests (strong_tier_boundary) prove `selectExecutor`; this proves the
 * wiring. With `resolveIsolationExecutor()` neutered to always `new ProcessIsolationExecutor(...)`, the
 * pipeline stops selecting the strong tier and this reddens — the audited tier drops from `container` back
 * to `process`. Asserted end-to-end through `solveIssueToPR`, on the spine audit artifact.
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
import type { ContainerRuntimeInfo } from "../src/infra/container_boundary.js";

const BROKEN = "export function add(a, b) { return a - b; }";

function setupRemote(): string {
  const root = mkdtempSync(join(tmpdir(), "stw-"));
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

/** Collect the isolation tiers the pipeline actually audited during a run. */
function auditedTiers(s: Spine): string[] {
  return s.replay()
    .map((e: { payload?: Record<string, unknown> }) => e.payload)
    .filter((p): p is Record<string, unknown> => !!p && p["event"] === "isolated_execution")
    .map((p) => String(p["tier"]));
}

async function run(extra: Record<string, unknown>): Promise<{ tiers: string[] }> {
  const work = setupRemote();
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "stws-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
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
    { id: "STW", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" },
    files,
    pinnedGitDependencies(work, new InMemoryMergePort()),
    { autonomyLevel: "operator" },
  );
  await spine.seal();
  return { tiers: auditedTiers(spine) };
}

test("WIRING: with detected container caps + a strong boundary, the pipeline SELECTS the container tier", async () => {
  // A probe-backed container runtime + a boundary runner that runs the inner runner (VERIFIED-SEAM stand-in).
  const detectRuntime: () => ContainerRuntimeInfo = () => ({ kind: "docker", available: true, tier: "container", detail: "test" });
  const { tiers } = await run({
    isolationCapabilities: { kvmAvailable: false, gvisorAvailable: false, containerRuntime: true, canScopeProcess: true },
    strongBoundary: {
      detectRuntime,
      // A boundary runner standing in for the host: runs the inner runner so the run still executes.
      boundaryRun: (r: TestRunner, spec: { repoRef: string }) => r.run(spec.repoRef),
    },
  });
  // The pipeline selected the strong tier — neutering resolveIsolationExecutor to the process floor drops
  // this to "process" (RED).
  assert.ok(tiers.includes("container"), `the strong container tier must be selected+audited; got: ${JSON.stringify(tiers)}`);
  assert.ok(!tiers.includes("process"), "the process floor was NOT used when a strong runtime was available");
});

test("WIRING: the default (no capabilities) stays the process floor — unchanged", async () => {
  const { tiers } = await run({});
  assert.ok(tiers.includes("process"), `the default is the process floor; got: ${JSON.stringify(tiers)}`);
  assert.ok(!tiers.includes("container"), "no strong tier is claimed by default (honest)");
});
