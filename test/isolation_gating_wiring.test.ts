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
import { BoundaryExecutor, ProcessIsolationExecutor } from "../src/isolation/isolated_executor.js";
import { seamEvidenceForTier, type IsolationEvidence } from "../src/isolation/isolation_attestation.js";
import { InMemoryMergePort } from "./helpers/in_memory_merge_port.js";
import { pinnedGitDependencies } from "./helpers/pinned_git_dependencies.js";
import type { ModelProvider, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { RepoFile } from "../src/solve/localize.js";

/**
 * BUILD-ORDER 2.3 (REVISIT-ISOLATION-GATING) — DOES THE PIPELINE FEED MEASURED EVIDENCE INTO THE CEILING?
 *
 * `isolation_ceiling_evidence.test.ts` proves the PREDICATE (the decision function). That is not enough —
 * the same Z140 trap Round 43 hit: with the pipeline's ceiling line neutered to read the static LABEL
 * table, the predicate tests still pass. This file drives the REAL pipeline through `solveIssueToPR` and
 * asserts the observable an operator would notice: a DEGRADED boundary loses auto-approval (produces the
 * decision brief) that a CLEAN boundary of the same tier keeps, and a degraded default floor is EXTENDED
 * into the refuse-risky merge gate.
 *
 * WIRING NEUTER (ledger 298): revert the pipeline's ceiling line to
 * `isolationAutonomyCeiling(effectiveTier)` (read the LABEL, drop `measuredDegradations`) → the degraded
 * runs get the clean tier's ceiling → the brief is suppressed / the gate does not fire → these reddens.
 */

const BROKEN = "export function add(a, b) { return a - b; }";

function setupRemote(): string {
  const root = mkdtempSync(join(tmpdir(), "b23w-"));
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

async function run(extra: Record<string, unknown>) {
  const work = setupRemote();
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "b23ws-"))), new InProcessLock(), new SchemaRegistry());
  const tree = new InMemoryFileTree({ "src/calc.ts": BROKEN });
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  const files: RepoFile[] = [{ path: "src/calc.ts", content: BROKEN }];
  return new KeepPipeline({ spine, tree, runner, model, ...extra } as never).solveIssueToPR(
    { id: "B23W", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" },
    files,
    pinnedGitDependencies(work, new InMemoryMergePort()),
    { autonomyLevel: "operator" },
  );
}

/** A gVisor-backing evidence carrying a runtime degradation. MicroVM evidence is tested separately because
 * it now requires a verifier-owned completed-run receipt and can no longer be minted by an injected seam. */
function degradedGvisorEvidence(): IsolationEvidence {
  return { ...seamEvidenceForTier("gvisor"), degraded: ["net-deny-degraded"] };
}

test("2.3 WIRING: declared clean/degraded gVisor seams are both non-authorizing", async () => {
  const spineForExec = () => new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "b23x-"))), new InProcessLock(), new SchemaRegistry());

  // A caller-provided function is not a completed gVisor transaction, even if labelled clean.
  const clean = await run({
    isolationTier: "gvisor",
    isolationExecutor: new BoundaryExecutor("gvisor", (r, s) => r.run(s.repoRef), spineForExec(), "gvisor", seamEvidenceForTier("gvisor")),
  });
  assert.ok(clean.safety?.decisionBrief, "an injected gVisor function remains review-routed");
  assert.notEqual(clean.mergeAuthority?.verdict, "autonomous-merge", "a declared seam cannot buy full autonomy");

  // A degradation cannot make the same unverified seam more authoritative.
  const degraded = await run({
    isolationTier: "gvisor",
    isolationExecutor: new BoundaryExecutor("gvisor", (r, s) => r.run(s.repoRef), spineForExec(), "gvisor", degradedGvisorEvidence()),
  });
  assert.ok(degraded.safety?.decisionBrief, "a DEGRADED boundary loses auto-approval — the ceiling tracked the MEASURED containment, not the label");
  assert.notEqual(degraded.mergeAuthority?.verdict, "autonomous-merge");
});

test("2.3 WIRING: a degraded DEFAULT floor is EXTENDED into the refuse-risky merge gate", async () => {
  // A process-tier executor whose evidence measured a degradation (net-deny unenforceable) — the ceiling
  // drops minimal → refuse-risky, so the round-42 merge gate now fires: the operator gets a human-merge.
  const spineForExec = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "b23p-"))), new InProcessLock(), new SchemaRegistry());
  const degradedProcess: IsolationEvidence = { platform: process.platform, runtimeKind: "process", kvmPresent: false, imagesPresent: false, jobObjectSupport: false, degraded: ["net-deny-degraded"] };
  const r = await run({
    // default isolationTier is "process"; the executor attests the SAME tier with a degradation.
    isolationExecutor: new ProcessIsolationExecutor(spineForExec, { evidence: degradedProcess }),
  });
  assert.equal(r.mergeAuthority?.verdict, "human-merge", "a degraded floor cannot auto-merge — the gate extends to the real boundary");
  assert.match(r.mergeAuthority?.reason ?? "", /no isolation|refuse-risky/, "and the reason names the isolation gate");
});

test("2.3 WIRING: the default process floor cannot autonomously merge", async () => {
  // Process scoping shares Keep's principal and is not a security boundary. Even a completed command run
  // therefore remains human-gated; only a clean completed strong-tier receipt can grant autonomous merge.
  const r = await run({});
  assert.ok(r.safety?.decisionBrief, "the default process tier still produces a brief");
  assert.equal(r.mergeAuthority?.verdict, "human-merge", "a process-scoped run cannot buy autonomous merge");
});
