/**
 * BUILD-ORDER 1.3b — WIRING (ledger 298): does the PIPELINE actually SELECT the microVM executor where a
 * KVM+Firecracker boundary is available? The predicate tests (microvm_tier_boundary) prove `selectExecutor`;
 * this proves the wiring end-to-end through `solveIssueToPR`, on the spine audit artifact. With
 * `resolveIsolationExecutor()` neutered to always `new ProcessIsolationExecutor(...)`, the pipeline stops
 * selecting the microVM tier and this reddens — the audited tier drops from `microvm` back to `process`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
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
import { buildMicrovmBoundaryRun, type MicrovmRuntimeInfo } from "../src/infra/microvm_boundary.js";

const BROKEN = "export function add(a, b) { return a - b; }";

function setupRemote(): string {
  const root = mkdtempSync(join(tmpdir(), "mvw-"));
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

function auditedTiers(s: Spine): string[] {
  return s.replay()
    .map((e: { payload?: Record<string, unknown> }) => e.payload)
    .filter((p): p is Record<string, unknown> => !!p && p["event"] === "isolated_execution")
    .map((p) => String(p["tier"]));
}

async function run(extra: Record<string, unknown>): Promise<{ tiers: string[]; verdict: string | undefined }> {
  const work = setupRemote();
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "mvws-"))), new InProcessLock(), new SchemaRegistry());
  const tree = new InMemoryFileTree({ "src/calc.ts": BROKEN });
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  const files: RepoFile[] = [{ path: "src/calc.ts", content: BROKEN }];
  const result = await new KeepPipeline({ spine, tree, runner, model, ...extra } as never).solveIssueToPR(
    { id: "MVW", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" },
    files,
    pinnedGitDependencies(work, new InMemoryMergePort()),
    { autonomyLevel: "operator" },
  );
  await spine.seal();
  return { tiers: auditedTiers(spine), verdict: result.mergeAuthority?.verdict };
}

test("WIRING: with detected KVM caps + a microVM boundary, the pipeline SELECTS the microvm tier", async () => {
  // A probe-backed microVM runtime + a boundary runner standing in for the host guest (VERIFIED-SEAM stand-in).
  const detectMicrovm: () => MicrovmRuntimeInfo = () => ({ kind: "firecracker", available: true, tier: "microvm", kvmPresent: true, detail: "test" });
  const { tiers, verdict } = await run({
    isolationCapabilities: { kvmAvailable: true, gvisorAvailable: false, containerRuntime: false, canScopeProcess: true },
    strongBoundary: {
      detectMicrovm,
      // An explicit boundary runner (host-provided guest) so the run executes; `selectExecutor` honours it
      // as the wired boundary for the kvm-selected microvm tier.
      boundaryRun: (r: TestRunner, s: { repoRef: string }) => r.run(s.repoRef),
    },
  });
  assert.ok(tiers.includes("microvm"), `the microVM tier must be selected+audited; got: ${JSON.stringify(tiers)}`);
  assert.ok(!tiers.includes("process"), "the process floor was NOT used when a microVM boundary was available");
  assert.notEqual(verdict, "autonomous-merge", "an injected boundary without a verifier-owned real-run receipt cannot mint microVM authority");
});

test("WIRING: the default (no capabilities) stays the process floor — unchanged", async () => {
  const { tiers } = await run({});
  assert.ok(tiers.includes("process"), `the default is the process floor; got: ${JSON.stringify(tiers)}`);
  assert.ok(!tiers.includes("microvm"), "no microVM tier is claimed by default (honest)");
});

test("production Firecracker authority refuses unsupported network and extra-write policy", async () => {
  const root = mkdtempSync(join(tmpdir(), "mv-policy-"));
  const kernel = join(root, "kernel");
  const rootfs = join(root, "rootfs");
  writeFileSync(kernel, "fixture");
  writeFileSync(rootfs, "fixture");
  const runtime: MicrovmRuntimeInfo = { kind: "firecracker", available: true, tier: "microvm", kvmPresent: true, detail: "test" };
  for (const policy of [{ allowNet: true }, { allowWritePaths: [join(root, "extra")] }]) {
    const boundary = buildMicrovmBoundaryRun(runtime, {
      projectDir: root, kernelImage: kernel, rootfsImage: rootfs, command: "/bin/true", args: [],
      memoryBytes: 64 * 1024 * 1024, vmmBin: "/does/not/run", jailerBin: "/does/not/run", ...policy,
    });
    const result = await boundary({} as TestRunner, { projectDir: root, repoRef: ".", patchRisk: "high" });
    assert.match(result.runnerError ?? "", /refuses unsupported allowNet\/allowWritePaths policy/);
  }
});
