import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, writeSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const installed = process.env.KEEP_INSTALLED_PACKAGE_ROOT;
if (!installed) throw Error("KEEP_INSTALLED_PACKAGE_ROOT is required; never substitute source imports");
const keep = await import(pathToFileURL(join(installed, "dist/src/index.js")).href);
const here = fileURLToPath(import.meta.url);

if (process.argv[2] === "child") {
  const [mode, dir, attemptId] = process.argv.slice(3);
  const spine = new keep.Spine(new keep.FileSpineStore(join(dir, "spine")), new keep.FileSystemLock(join(dir, "locks")), new keep.SchemaRegistry());
  if (mode === "crash" || mode === "reconcile") {
    const budget = new keep.RecoveryBudget(spine, "crashed-operation", { maxAttempts: 2, maxElapsedMs: 60_000 });
    if (mode === "crash") {
      const permit = await budget.reserve();
      writeSync(1, JSON.stringify(permit));
      process.kill(process.pid, "SIGKILL");
    } else {
      await assert.rejects(budget.reserve(), /unresolved/);
      await assert.rejects(budget.reconcile("wrong", "process-exit-observed"), /does not match/);
      await budget.reconcile(attemptId, "host-observed-prior-process-killed-before-effects");
      const permit = await budget.reserve();
      assert.equal(permit.attempt, 2);
      await budget.finish(permit);
      await assert.rejects(budget.reserve(), /exhausted/);
      process.stdout.write(JSON.stringify({ reconciled: true, attempts: permit.attempt }));
    }
  } else {
    const workspace = new keep.LocalFsWorkspace(join(dir, "workspace"));
    let calls = 0, runs = 0;
    const model = { name: "deterministic-recovery-acceptance", isLocal: true, embed: async () => [], generate: async request => {
      calls++;
      const source = readFileSync(join(dir, "workspace/repo/calc.mjs"), "utf8");
      const expression = ["a + 0", "a + 1", "a + 2", "a + b"][calls - 1];
      if (!expression) throw Error("model call exceeded the shared allowance");
      if (calls === 4) assert.match(JSON.stringify(request), /Diagnosis:/);
      return { text: JSON.stringify({ rationale: "fixture correction", edits: [{ file: "calc.mjs", search: source, replace: `export function add(a, b) { return ${expression}; }\n`, intent: "fix addition" }] }), model: "deterministic-recovery-acceptance", tokensIn: 1, tokensOut: 1 };
    } };
    // Trusted acceptance fixture only. This proves a real repository test process,
    // not arbitrary-code sandboxing or real-model quality (covered separately).
    const solve = keep.buildDefaultSolver({ spine, workspace, model, options: { maxRepairRounds: 3, recoveryMaxElapsedMs: 60_000 }, runnerFor: () => ({ run: async (_repo, options) => {
      runs++;
      const result = spawnSync(process.execPath, ["--input-type=module", "-e", "import assert from 'node:assert/strict'; import {add} from './calc.mjs'; assert.equal(add(2,3),5);"], {
        cwd: join(dir, "workspace/repo"), encoding: "utf8", timeout: Math.max(1, Math.min(5000, options.deadline - Date.now())), env: { PATH: process.env.PATH },
      });
      if (result.error) return { results: [], runnerError: result.error.message, failureKind: "harness" };
      return { results: [{ name: "add(2,3) equals 5", passed: result.status === 0, output: result.stderr }] };
    } }) });
    const result = (await solve({ id: "addition", repoRef: "repo", text: "Fix add() in calc.mjs to add both arguments" }, { recoveryOperationId: "owner-created-run" })).solveResult;
    if (mode === "solve") {
      assert.equal(result.solved, true);
      assert.equal(calls, 4); assert.equal(runs, 4);
      assert.equal(result.repairRounds, 3);
      assert.equal(result.recovery.attempts, 4);
      assert.ok(spine.replay().some(e => e.payload.event === "repair_diagnosis" && e.payload.ownerApprovalRequired === false));
    } else {
      assert.equal(result.solved, false);
      assert.equal(result.recovery.status, "exhausted");
      assert.equal(calls, 0); assert.equal(runs, 0);
    }
    process.stdout.write(JSON.stringify({ solved: result.solved, calls, runs, attempts: result.recovery.attempts }));
  }
} else {
  // Separate owner/tenant storage tracks, not a claim of cross-tenant OS isolation.
  for (const track of ["n1", "enterprise"]) test(`installed ${track}: default solver diagnoses, completes third repair, survives restart and reconciles process loss`, t => {
    const dir = mkdtempSync(join(tmpdir(), `keep-installed-recovery-${track}-`));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    mkdirSync(join(dir, "workspace/repo"), { recursive: true });
    writeFileSync(join(dir, "workspace/repo/calc.mjs"), "export function add(a, b) { return a - b; }\n");
    const child = (mode, attemptId = "") => spawnSync(process.execPath, [here, "child", mode, dir, attemptId], {
      encoding: "utf8", timeout: 20_000, env: { PATH: process.env.PATH, KEEP_INSTALLED_PACKAGE_ROOT: installed }, maxBuffer: 1024 * 1024,
    });
    for (const mode of ["solve", "resume"]) {
      const result = child(mode);
      assert.equal(result.status, 0, `${mode}: ${result.stderr}\n${result.stdout}`);
      assert.equal(JSON.parse(result.stdout).attempts, 4);
    }
    const crashed = child("crash");
    assert.equal(crashed.signal, "SIGKILL");
    const permit = JSON.parse(crashed.stdout);
    const recovered = child("reconcile", permit.id);
    assert.equal(recovered.status, 0, recovered.stderr);
    assert.deepEqual(JSON.parse(recovered.stdout), { reconciled: true, attempts: 2 });
  });
}
