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
import type { ModelProvider, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { Issue } from "../src/solve/issue_model.js";
import type { RepoFile } from "../src/solve/localize.js";
import { pinnedGitDependencies } from "./helpers/pinned_git_dependencies.js";
import { KeepPipeline, KEEP_SOLVE_IDENTITY_ID } from "../src/pipeline/keep_pipeline.js";
import { IdentityRegistry } from "../src/identity/agent_identity.js";

/**
 * ROUND 35 — IS THE SWITCH REACHABLE WHERE AN OPERATOR ACTUALLY STANDS?
 *
 * `killswitch_production_path.test.ts` proves the MECHANISM by handing SolvePipeline an
 * identity directly. Round 30 already proved that much. **The gap this round exists to close
 * is the WIRING**, so the decisive test has to go through `KeepPipeline` — "the one call an
 * operator makes" — supplying nothing but a registry, exactly as an operator would.
 *
 * If this test passed while the wiring were absent, it would be measuring the mechanism again
 * and reporting it as reach. The neuter in the round doc is what rules that out.
 */

function setupRemote(seedFile: string, seedContent: string): { work: string } {
  const root = mkdtempSync(join(tmpdir(), "r35-e2e-"));
  const bare = join(root, "o.git"); const work = join(root, "w");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  execFileSync("git", ["clone", "-q", bare, work]);
  const g = (a: string[]) => execFileSync("git", a, { cwd: work });
  g(["config", "user.email", "t@t"]); g(["config", "user.name", "t"]); g(["checkout", "-qb", "main"]);
  execFileSync("bash", ["-c", `mkdir -p "$(dirname ${join(work, seedFile)})" && printf '%s' ${JSON.stringify(seedContent)} > ${join(work, seedFile)}`]);
  g(["add", "-A"]); g(["commit", "-qm", "init"]); g(["push", "-q", "-u", "origin", "main"]);
  return { work };
}

function fixModel(): ModelProvider {
  return {
    name: "fix", isLocal: true,
    async generate(): Promise<GenerateResult> {
      return {
        text: JSON.stringify({ rationale: "fix", edits: [{ file: "src/calc.ts", search: "a - b", replace: "a + b", intent: "fix" }] }),
        model: "fix", tokensIn: 1, tokensOut: 1,
      };
    },
    async embed(): Promise<Embedding[]> { return []; },
  };
}

const BROKEN = "export function add(a, b) { return a - b; }";

function harness() {
  const { work } = setupRemote("src/calc.ts", `${BROKEN}\n`);
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "r35-spine-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const files: RepoFile[] = [{ path: "src/calc.ts", content: BROKEN }];
  const tree = new InMemoryFileTree({ "src/calc.ts": BROKEN });
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  // Mirror the existing e2e convention (keep_pipeline.test.ts): write the FIXED content into
  // the real worktree so the git diff is non-empty, standing in for a FileTree bound to the
  // worktree. Without it `git commit` fails with nothing staged — which is a defect in the
  // TEST, not the product, and is exactly the kind of red that looks like a finding (Z136).
  execFileSync("bash", ["-c", `printf '%s' 'export function add(a, b) { return a + b; }\n' > ${join(work, "src/calc.ts")}`]);
  return { work, spine, files, tree, runner };
}

const ISSUE: Issue = { id: "R35-OP", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" };

test("R35 REACH: an operator who supplies a registry can REVOKE Keep's solve path", async () => {
  const { work, spine, files, tree, runner } = harness();
  const registry = new IdentityRegistry(spine);

  // The operator constructs the pipeline exactly as they normally would, adding one dep.
  const pipeline = new KeepPipeline({ spine, tree, runner, model: fixModel(), identityRegistry: registry });

  // …then throws the switch, by the exported, documented handle. This is the whole point:
  // the operator needs no reference to anything the pipeline built privately.
  registry.kill(KEEP_SOLVE_IDENTITY_ID, "operator revoked");

  const result = await pipeline.solveIssueToPR(
    ISSUE, files, pinnedGitDependencies(work), { autonomyLevel: "operator" },
  );

  // THE EFFECT (Z108): the fix does not land, and no PR is proposed.
  assert.equal(await tree.read("src/calc.ts"), BROKEN, "a revoked solve path must not change the tree");
  assert.equal(result.solveResult.solved, false, "and must not report a solve");
  assert.equal(result.manifest, undefined, "no PR proposal from a revoked path");
});

test("R35 REACH: the same call SUCCEEDS when the operator has not revoked", async () => {
  // The control. Without it, test 1 shows only that the run failed — not that revocation is why.
  const { work, spine, files, tree, runner } = harness();
  const registry = new IdentityRegistry(spine);
  const pipeline = new KeepPipeline({ spine, tree, runner, model: fixModel(), identityRegistry: registry });

  const result = await pipeline.solveIssueToPR(
    ISSUE, files, pinnedGitDependencies(work), { autonomyLevel: "operator" },
  );

  assert.equal(result.solveResult.solved, true, "an un-revoked path still does ordinary work");
  assert.ok((await tree.read("src/calc.ts"))?.includes("a + b"), "and the fix lands");
});

test("R35 REACH: an operator who supplies NO registry is unaffected", async () => {
  // Requirement 4 at the operator boundary. Arming the switch must not change what happens for
  // every existing caller who has never heard of it.
  const { work, spine, files, tree, runner } = harness();
  const pipeline = new KeepPipeline({ spine, tree, runner, model: fixModel() });

  const result = await pipeline.solveIssueToPR(
    ISSUE, files, pinnedGitDependencies(work), { autonomyLevel: "operator" },
  );

  assert.equal(result.solveResult.solved, true, "omitting the registry leaves behaviour unchanged");
  assert.ok((await tree.read("src/calc.ts"))?.includes("a + b"));
});

test("R35 REACH: the revocation is AUDITED to the spine, not just enforced", async () => {
  // A kill an operator cannot later evidence is a weak control. The registry records the event;
  // this pins that it survives to the spine an auditor reads.
  const { spine } = harness();
  const registry = new IdentityRegistry(spine);
  registry.mint(KEEP_SOLVE_IDENTITY_ID, ["*"]);
  registry.kill(KEEP_SOLVE_IDENTITY_ID, "operator revoked");

  const killed = spine.currentEvents().some(
    (e) => (e.payload as Record<string, unknown>)["event"] === "agent.killed"
      && (e.payload as Record<string, unknown>)["id"] === KEEP_SOLVE_IDENTITY_ID,
  );
  assert.ok(killed, "the kill is recorded to the spine with the identity it revoked");
});
