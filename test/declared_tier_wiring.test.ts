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
import { BoundaryExecutor } from "../src/isolation/isolated_executor.js";
import { seamEvidenceForTier, processFloorEvidence } from "../src/isolation/isolation_attestation.js";
import { InMemoryMergePort } from "./helpers/in_memory_merge_port.js";
import { pinnedGitDependencies } from "./helpers/pinned_git_dependencies.js";
import type { ModelProvider, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { RepoFile } from "../src/solve/localize.js";

/**
 * ROUND 43 — DOES THE WIRING ACTUALLY USE THE WEAKER TIER?
 *
 * `declared_vs_actual_isolation.test.ts` proves the PREDICATE. It is not enough, and this file
 * exists because that was checked rather than assumed: with the pipeline's `weakerTier(...)` call
 * neutered, **the entire 2477-test suite still passed.** The predicate tests measure the helper,
 * not the wiring — Z140, caught by neutering before declaring the round done.
 *
 * The observable an operator would actually notice: declaring `microvm` while a process-tier
 * executor really runs must NOT buy the `full` autonomy ceiling, and therefore must still produce
 * a decision brief. Asserted on the artifact (Z108), through `solveIssueToPR`.
 */

const BROKEN = "export function add(a, b) { return a - b; }";

function setupRemote(): string {
  const root = mkdtempSync(join(tmpdir(), "r43w-"));
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
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "r43ws-"))), new InProcessLock(), new SchemaRegistry());
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
    { id: "R43W", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" },
    files,
    pinnedGitDependencies(work, new InMemoryMergePort()),
    { autonomyLevel: "operator" },
  );
}

test("R43 WIRING: a FALSE microvm claim does not buy the full ceiling", async () => {
  // `isolationTier: "microvm"` with no matching executor — the pipeline builds
  // ProcessIsolationExecutor. Before this round the claim alone granted `full`, which made
  // `autoApprovable` true and suppressed the decision brief. A stronger claim made Keep LESS
  // careful.
  const r = await run({ isolationTier: "microvm" });

  assert.ok(
    r.safety?.decisionBrief,
    "a claim the executor does not back must not suppress the brief",
  );
});

test("R43 WIRING: a declared microvm seam cannot stand in for a completed real run", async () => {
  // A typed seam is useful for wiring tests but is deliberately nonauthorizing. Only the production
  // Firecracker boundary can mint and consume the completed-run receipt required for the full ceiling.
  const spineForExec = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "r43x-"))), new InProcessLock(), new SchemaRegistry());
  const r = await run({
    isolationTier: "microvm",
    // The seam evidence identifies itself as lacking a completed transaction receipt.
    isolationExecutor: new BoundaryExecutor("microvm", (runner, spec) => runner.run(spec.repoRef), spineForExec, "microvm", seamEvidenceForTier("microvm")),
  });

  assert.ok(r.safety?.decisionBrief, "a seam cannot suppress the human-facing decision brief");
  assert.equal(r.mergeAuthority?.verdict, "human-merge", "a seam cannot grant autonomous merge authority");
});

test("BUILD-ORDER 1.7 WIRING: a mislabelled executor's tier claim does not survive attestation", async () => {
  // Z193: `isoExecutor.tier` was the executor's WORD. A `BoundaryExecutor("microvm", …)` running over the
  // process floor (its evidence is the process floor) previously bought the `full` ceiling on the label
  // alone — a mislabel or supply-chain swap claiming more autonomy than the real boundary earns. Now the
  // executor EMITS a signed attestation {tier: microvm, evidence: process}; the pipeline VERIFIES it and
  // the evidence recomputes to `process` → minimal ceiling → the brief is produced.
  //
  // WIRING NEUTER (ledger 298): revert the pipeline's line to `weakerTier(this.isolationTier,
  // isoExecutor.tier)` (re-trust the word, drop the attestation) → the forged microvm is honoured, the
  // brief is suppressed → this assertion reddens.
  const spineForExec = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "r17w-"))), new InProcessLock(), new SchemaRegistry());
  const r = await run({
    isolationTier: "microvm",
    isolationExecutor: new BoundaryExecutor("microvm", (runner, spec) => runner.run(spec.repoRef), spineForExec, "microvm", processFloorEvidence()),
  });

  assert.ok(r.safety?.decisionBrief, "a microvm claim the EVIDENCE does not back must not suppress the brief");
});

test("R43 WIRING: the default remains the honest process floor", async () => {
  // An operator who declares nothing gets the measured process floor, never an implicit strong tier.
  const r = await run({});
  assert.ok(r.safety?.decisionBrief, "the default process tier still produces a brief");
  assert.equal(r.mergeAuthority?.verdict, "human-merge", "the process floor cannot autonomously merge");
});
