import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock, FileSystemLock } from "../src/lock/lock.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { repairLoop } from "../src/solve/repair_loop.js";
import { validate, type TestRunner } from "../src/solve/validate.js";
import { RecoveryBudget } from "../src/solve/recovery_budget.js";

function fixture(t: TestContext) {
  const dir = mkdtempSync(join(tmpdir(), "keep-bounded-recovery-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  return { spine, tree: new InMemoryFileTree({ "a.ts": "initial" }), ledger: new RollbackLedger(spine) };
}

test("recovery consumes the original failure without another test invocation", async t => {
  const f = fixture(t);
  let runs = 0;
  const runner: TestRunner = { run: async () => { runs++; return { results: [{ name: "network formatting", passed: false, output: "expected one space" }] }; } };
  const first = await validate("repo", runner);
  let replans = 0;
  const result = await repairLoop("feedback", "repo", first, 0, { ...f, runner, replan: async feedback => {
    replans++;
    assert.match(feedback, /expected one space/);
    return { edits: [], rationale: "diagnosis needs another observation" };
  } });
  assert.equal(result.solved, false);
  assert.equal(replans, 1, "the word network must not manufacture transient retries");
  assert.equal(runs, 1, "initial validation is the only test run");
});

test("regression compensation touches only its own repair action", async t => {
  const f = fixture(t);
  const undone: string[] = [];
  f.ledger.record({ id: "initial", artifact: "initial", undo: async () => { undone.push("initial"); } });
  const first = await validate("repo", { run: async () => ({ results: [{ name: "a", passed: true }, { name: "b", passed: true }, { name: "c", passed: false }] }) });
  const runner: TestRunner = { run: async () => ({ results: [{ name: "a", passed: true }, { name: "b", passed: false }, { name: "c", passed: false }] }) };
  const result = await repairLoop("rollback", "repo", first, 2, { ...f, runner,
    replan: async () => ({ edits: [{ file: "a.ts", search: "initial", replace: "bad", intent: "repair" }], rationale: "try" }),
    applyPlan: async () => {
      f.ledger.record({ id: "repair", artifact: "repair", undo: async () => { undone.push("repair"); } });
      return { applied: true, perEdit: [], rollbackId: "repair" };
    },
  });
  assert.equal(result.solved, false);
  assert.deepEqual(undone, ["repair"]);
  assert.equal(f.ledger.pending, 1);
  assert.notEqual(result.validation, first, "old validation cannot certify a restored tree");
});

test("an inverse that throws remains available for reconciliation", async t => {
  const f = fixture(t);
  let fail = true;
  f.ledger.record({ id: "repair", artifact: "repair", undo: async () => { if (fail) throw Error("storage unavailable"); } });
  await assert.rejects(f.ledger.rollback(1, "recover"), /storage unavailable/);
  assert.equal(f.ledger.pending, 1);
  fail = false;
  assert.equal((await f.ledger.rollbackAction("repair", "resolved storage")).rolledBack, true);
});

test("passing tests with refused vetting never report solved", async t => {
  const f = fixture(t);
  const result = await repairLoop("vet", "repo", { testsPassed: true, passedCount: 1, failures: [], vettingCleared: false, detail: "vet refused" }, 1, {
    ...f, runner: { run: async () => { throw Error("must not run"); } },
    replan: async () => { throw Error("must not replan"); },
  });
  assert.equal(result.solved, false);
});

test("two unproductive repairs diagnose and a third evidence-driven correction succeeds autonomously", async t => {
  const f = fixture(t);
  let plans = 0, runs = 0;
  const runner: TestRunner = { run: async () => { runs++; return { results: [{ name: "behavior", passed: await f.tree.read("a.ts") === "fix3" }] }; } };
  const first = await validate("repo", runner);
  const r = await repairLoop("diagnose", "repo", first, 0, { ...f, runner,
    replan: async feedback => {
      plans++;
      if (plans === 3) assert.match(feedback, /Diagnosis:.*two attempts/);
      return { edits: [{ file: "a.ts", search: (await f.tree.read("a.ts"))!, replace: `fix${plans}`, intent: "correct observed behavior" }], rationale: "different correction" };
    },
  });
  assert.equal(r.solved, true);
  assert.equal(r.rounds, 3);
  assert.equal(runs, 4, "one original execution plus one per actual correction");
  const diagnosis = f.spine.replay().filter(e => e.payload["event"] === "repair_diagnosis");
  assert.equal(diagnosis.length, 1);
  assert.equal(diagnosis[0]!.payload["ownerApprovalRequired"], false);
});

test("durable attempts and frozen limits survive a fresh coordinator; concurrent reservation has one winner", async t => {
  const dir = mkdtempSync(join(tmpdir(), "keep-recovery-lock-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const make = (maxAttempts = 2) => new RecoveryBudget(new Spine(new FileSpineStore(join(dir, "spine")), new FileSystemLock(join(dir, "locks")), new SchemaRegistry()), "owner-run", { maxAttempts, maxElapsedMs: 1000 }, () => 100);
  const a = make(), b = make();
  const attempts = await Promise.allSettled([a.reserve(), b.reserve()]);
  assert.equal(attempts.filter(r => r.status === "fulfilled").length, 1);
  const winner = attempts[0]!.status === "fulfilled" ? a : b;
  const permit = attempts.find(r => r.status === "fulfilled") as PromiseFulfilledResult<Awaited<ReturnType<RecoveryBudget["reserve"]>>>;
  await winner.finish(permit.value);
  const next = make();
  const second = await next.reserve();
  assert.equal(second.attempt, 2);
  await next.finish(second);
  await assert.rejects(make().reserve(), /attempt budget exhausted/);
  await assert.rejects(make(3).reserve(), /limits invalid or changed/);
});

test("unresolved work requires exact evidence and reconciliation cannot replenish attempts or time", async t => {
  const f = fixture(t);
  let now = 100;
  const make = () => new RecoveryBudget(f.spine, "crash-run", { maxAttempts: 2, maxElapsedMs: 100 }, () => now);
  const before = make();
  const permit = await before.reserve();
  await before.hold("observed ambiguous adapter completion");
  await before.finish(permit);
  const after = make();
  await assert.rejects(after.reserve(), /ambiguous/);
  await assert.rejects(after.reconcile("wrong", "observed-no-effect"), /does not match/);
  await after.reconcile(permit.id, "trusted-host-observed-quiescent-no-effect");
  const second = await after.reserve();
  await after.reconcile(permit.id, "trusted-host-observed-quiescent-no-effect");
  assert.equal((await after.snapshot()).pendingAttemptId, second.id, "duplicate old evidence cannot clear a newer attempt");
  assert.equal(second.attempt, 2);
  assert.equal(second.deadline, permit.deadline);
  await after.finish(second);
  await assert.rejects(make().reserve(), /attempt budget exhausted/);
  now = 201;
  assert.equal((await make().snapshot()).status, "exhausted");
});

test("clock regression and elapsed deadline fail closed across reconstruction", async t => {
  const f = fixture(t);
  let now = 100;
  const make = () => new RecoveryBudget(f.spine, "clock-run", { maxAttempts: 3, maxElapsedMs: 100 }, () => now);
  const a = make();
  const permit = await a.reserve();
  now = 120; await a.finish(permit);
  now = 119; await assert.rejects(make().reserve(), /backwards/);
  now = 121; await assert.rejects(make().reserve(), /backwards/);
  const elapsed = new RecoveryBudget(f.spine, "elapsed", { maxAttempts: 3, maxElapsedMs: 10 }, () => now);
  const p = await elapsed.reserve(); await elapsed.finish(p);
  now += 11;
  await assert.rejects(elapsed.reserve(), /wall-time/);
});

test("deadline aborts cooperative work, rejects late completion and preserves unresolved debt", async t => {
  const f = fixture(t);
  const budget = new RecoveryBudget(f.spine, "timeout", { maxAttempts: 3, maxElapsedMs: 80 });
  const permit = await budget.reserve();
  let signal: AbortSignal | undefined;
  let complete!: () => void;
  await assert.rejects(budget.during(permit, async s => { signal = s; await new Promise<void>(resolve => { complete = resolve; }); }), /wall-time/);
  assert.equal(signal!.aborted, true);
  complete();
  await budget.finish(permit);
  assert.equal((await budget.snapshot()).pendingAttemptId, permit.id);
  await assert.rejects(budget.reserve(), /wall-time/);
});

test("diagnosis memory persists across coordinators and is not reset by prose changes", async t => {
  const f = fixture(t);
  const make = () => new RecoveryBudget(f.spine, "memory", { maxAttempts: 3, maxElapsedMs: 1000 });
  assert.equal(await make().observeFailures(["b", "a"]), 0);
  assert.equal(await make().observeFailures(["a", "b", "a"]), 1);
  assert.equal(await make().observeFailures(["a", "b"]), 2);
  assert.equal(await make().rememberPlan("a".repeat(64)), true);
  assert.equal(await make().rememberPlan("a".repeat(64)), false);
});

test("a corrected capability resumes the exact diagnosis without owner approval or a budget reset", async t => {
  const f = fixture(t);
  const make = () => new RecoveryBudget(f.spine, "corrected-harness", { maxAttempts: 3, maxElapsedMs: 1000 });
  const a = make();
  const first = await a.reserve();
  await a.hold("test command configuration invalid", "diagnosis");
  await a.finish(first);
  const snapshot = await a.snapshot();
  await assert.rejects(make().reserve(), /configuration invalid/);
  await assert.rejects(make().resumeDiagnosis("wrong", "corrected-command"), /does not match/);
  const b = make();
  await b.resumeDiagnosis(snapshot.diagnosisId!, "trusted-host-verified-command-correction");
  const second = await b.reserve();
  assert.equal(second.attempt, 2);
  assert.equal(second.deadline, first.deadline);
  await b.hold("permission denied", "authority"); await b.finish(second);
  await assert.rejects(make().resumeDiagnosis(snapshot.diagnosisId!, "old-evidence"), /does not match/);
});

test("concurrent compensation has one undo owner and preserves unrelated work", async t => {
  const f = fixture(t);
  let undos = 0;
  f.ledger.record({ id: "initial", artifact: "initial", undo: async () => { throw Error("unrelated inverse must remain"); } });
  f.ledger.record({ id: "repair", artifact: "repair", undo: async () => { undos++; await Promise.resolve(); } });
  const outcomes = await Promise.all([f.ledger.rollback(1, "regression"), f.ledger.rollbackAction("repair", "duplicate delivery")]);
  assert.equal(undos, 1);
  assert.equal(outcomes[1].rolledBack, false);
  assert.equal(f.ledger.pending, 1);
});

test("equal pass counts cannot conceal a newly failing named test", async t => {
  const f = fixture(t);
  const first = await validate("repo", { run: async () => ({ results: [{ name: "existing", passed: true }, { name: "target", passed: false }] }) });
  const result = await repairLoop("named-regression", "repo", first, 1, { ...f,
    runner: { run: async () => ({ results: [{ name: "existing", passed: false }, { name: "target", passed: true }] }) },
    replan: async () => ({ edits: [{ file: "a.ts", search: "initial", replace: "bad", intent: "fix" }], rationale: "try" }),
  });
  assert.equal(result.regressionTripped, true);
  assert.equal(await f.tree.read("a.ts"), "initial");
  assert.equal(result.validation.failureKind, "unknown");
});
