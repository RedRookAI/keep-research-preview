import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { captureGoalWorkDefinition, decodeGoalWork, observeGoalTask, selectGoalWork,
  type GoalWorkDefinition, type GoalWorkDocument, type GoalWorkTask, type GoalTaskAcceptance } from "../src/session/project_goal_work.js";
import { ProjectRuntime } from "../src/session/project_runtime.js";
import { ProjectSessionManager } from "../src/session/project_session_manager.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { FileProjectSessionPersistence } from "../src/session/project_session_persistence.js";
import { SpineProjectJobJournal } from "../src/session/project_job_journal.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { FileSystemLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { encodeProjectCommand } from "../src/session/project_command.js";
import { asProjectId } from "../src/session/project_id.js";
import { projectImplementationDigest } from "../src/autonomy/project_test_stage.js";

const binding = "c".repeat(64), principal = { kind: "human", id: "owner" } as const;
const task = (id: string, extra: Partial<GoalWorkTask> = {}): GoalWorkTask => ({ id, goal: `Implement ${id}`, kind: "goal", dependsOn: [], requires: [], due: "development", acceptance: "tested-proposal", ...extra });
const definition: GoalWorkDefinition = { objective: "Repair retry behavior. Preserve source and deferred release safety obligations.", tasks: [
  task("polish", { kind: "hardening", due: "release" }), task("repair"), task("verify", { dependsOn: ["repair"], requires: ["verification-host"] }),
], maxTaskStarts: 3 };
const document = (extra: Partial<GoalWorkDocument> = {}): GoalWorkDocument => ({ schema: "keep.goal-work/v1", creationId: randomUUID(), binding, principal, definition, phase: "development", active: true, startsUsed: 0, claims: {}, accepted: {}, ...extra });

test("goal-first selection preserves deferred work and holds only its dependent branch", () => {
  const d = document(), selection = selectGoalWork(d, new Set());
  assert.equal(selection.selected, "repair"); assert.deepEqual(selection.deferred, ["polish"]);
  assert.deepEqual(selection.held["verify"], ["dependency:repair", "capability:verification-host"]);
  assert.equal(d.definition.tasks.length, 3);
  assert.equal(selectGoalWork({ ...d, phase: "release" }, new Set()).selected, "polish");
});

test("due safeguards promote their actual prerequisites without promoting unrelated hardening", () => {
  const d = document({ definition: { objective: "Ship safely", maxTaskStarts: 4, tasks: [task("core"), task("guard", { kind: "safeguard", dependsOn: ["prerequisite"] }), task("prerequisite", { due: "release" }), task("later", { kind: "hardening", due: "release" })] } });
  assert.equal(selectGoalWork(d, new Set()).selected, "prerequisite");
  assert.deepEqual(selectGoalWork(d, new Set()).deferred, ["later"]);
});

test("captured contracts retain every task and reject missing/cyclic dependencies and invented acceptance", () => {
  const input = JSON.parse(JSON.stringify(definition)); const captured = captureGoalWorkDefinition(input); input.tasks.pop();
  assert.equal(captured.tasks.length, 3);
  for (const tasks of [[task("a", { dependsOn: ["missing"] })], [task("a", { dependsOn: ["b"] }), task("b", { dependsOn: ["a"] })], [task("a", { acceptance: "model-said-done" as "tested-proposal" })]]) {
    assert.throws(() => captureGoalWorkDefinition({ objective: "goal", tasks, maxTaskStarts: 1 }));
  }
  assert.throws(() => decodeGoalWork(JSON.stringify(document({ startsUsed: 1 }))));
  const d = document({ active: false }); assert.equal(selectGoalWork(d, new Set()).selected, undefined);
});

test("internal task context carries the entire public objective without shrinking its 900 KiB bound", () => {
  const d = captureGoalWorkDefinition({ ...definition, objective: "x".repeat(900 * 1024) });
  encodeProjectCommand({ binding, principal, goal: d.tasks[0]!.goal, goalContext: d.objective }, randomUUID(), asProjectId(`prj_${"a".repeat(32)}`));
});

function fixture(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), "keep-goal-work-")); t.after(() => rmSync(root, { recursive: true, force: true }));
  const manager = new ProjectSessionManager(new ProjectRegistry(new CryptoShredKeyStore()), undefined, id => new FileProjectSessionPersistence(join(root, `${id}.json`)));
  const spine = new Spine(new FileSpineStore(join(root, "spine"), { fsync: true }), new FileSystemLock(join(root, "locks")), new SchemaRegistry());
  return { manager, journal: new SpineProjectJobJournal(spine) };
}
const submission = { keyDigest: "a".repeat(64), requestDigest: "b".repeat(64) };
async function until(predicate: () => boolean): Promise<void> {
  const end = Date.now() + 2000;
  while (!predicate()) { assert.ok(Date.now() < end, "bounded work did not settle"); await new Promise(resolve => setTimeout(resolve, 5)); }
}

test("persisted work restarts, consumes one shared claim and refuses callback-only dependency completion", async t => {
  const { manager, journal } = fixture(t); let calls = 0, proof: GoalTaskAcceptance | undefined;
  const commands = { binding, resource: binding, capabilities: ["verification-host"], validate: () => undefined,
    observe: () => proof, execute: async (command: { goalContext?: string }) => { calls++; assert.equal(command.goalContext, definition.objective); return { completed: true }; } };
  const old = new ProjectRuntime(manager, { aggregateCeiling: 2, perProjectShare: 0.5 }, journal, { commands });
  const id = await old.createGoalWork(submission, definition, principal, true);
  const current = new ProjectRuntime(manager, { aggregateCeiling: 2, perProjectShare: 0.5 }, journal, { commands });
  assert.equal(await current.createGoalWork(submission, definition, principal, true), id);
  await Promise.allSettled([current.advanceGoalWork(id), old.advanceGoalWork(id)]);
  const claim = current.goalWork(id).document.claims["repair"]!; assert.ok(claim.projectId);
  await until(() => current.job(claim.jobId)?.state === "completed");
  const unproven = await current.advanceGoalWork(id);
  assert.equal(calls, 1); assert.equal(unproven.document.startsUsed, 1); assert.deepEqual(unproven.document.accepted, {});
  assert.equal(unproven.tasks.find(row => row.id === "repair")!.status, "acceptance-unproven");
  assert.ok(unproven.selection.held["verify"]!.includes("dependency:repair"));
  proof = { jobId: claim.jobId, projectId: claim.projectId!, checkpointRevision: 9, sourceDigest: binding, validationDigest: binding, kind: "tested-proposal" };
  await current.advanceGoalWork(id);
  const second = current.goalWork(id).document.claims["verify"]!;
  await until(() => current.job(second.jobId)?.state === "completed");
  assert.equal(calls, 2); assert.equal(current.goalWork(id).document.startsUsed, 2);
  assert.deepEqual(current.goalWork(id).selection.deferred, ["polish"]);
});

test("current authority, CAS controls and original budget survive attempted advancement", async t => {
  const { manager, journal } = fixture(t); let permitted = true, calls = 0;
  const runtime = new ProjectRuntime(manager, { aggregateCeiling: 1, perProjectShare: 1 }, journal, { commands: { binding, resource: binding,
    observe: () => undefined, validate: () => { if (!permitted) throw new Error("revoked"); }, execute: async () => { calls++; } } });
  const id = await runtime.createGoalWork(submission, { ...definition, maxTaskStarts: 1 }, principal, true);
  const revision = runtime.goalWork(id).revision; permitted = false;
  await assert.rejects(runtime.advanceGoalWork(id), /revoked/); assert.equal(runtime.goalWork(id).document.startsUsed, 0);
  permitted = true; runtime.setGoalWorkControl(id, revision, false, "release");
  assert.throws(() => runtime.setGoalWorkControl(id, revision, true, "release"));
  assert.throws(() => runtime.setGoalWorkControl(id, runtime.goalWork(id).revision, true, "development"));
  await runtime.advanceGoalWork(id); assert.equal(calls, 0);
  runtime.setGoalWorkControl(id, runtime.goalWork(id).revision, true, "release"); await runtime.advanceGoalWork(id);
  const claim = runtime.goalWork(id).document.claims["polish"]!; await until(() => runtime.job(claim.jobId)?.state === "completed");
  await runtime.advanceGoalWork(id); assert.equal(calls, 1); assert.equal(runtime.goalWork(id).selection.selected, undefined);
});

test("different projects sharing a physical workspace cannot overlap execution", async t => {
  const { manager, journal } = fixture(t); let release!: () => void, calls = 0;
  const held = new Promise<void>(resolve => { release = resolve; }); t.after(release);
  const runtime = new ProjectRuntime(manager, { aggregateCeiling: 2, perProjectShare: 0.5 }, journal, { commands: { binding, resource: binding, observe: () => undefined, validate: () => undefined, execute: async () => { calls++; await held; } } });
  const a = await runtime.createGoalWork(submission, definition, principal, true);
  const b = await runtime.createGoalWork({ ...submission, keyDigest: "d".repeat(64) }, definition, principal, true);
  await runtime.advanceGoalWork(a); await runtime.advanceGoalWork(b); await until(() => calls === 1);
  assert.equal(runtime.goalWork(b).tasks.find(row => row.id === "repair")!.status, "queued");
  release(); await until(() => calls === 2);
  const claims = [runtime.goalWork(a), runtime.goalWork(b)].map(v => v.document.claims["repair"]!);
  await until(() => claims.every(c => runtime.job(c.jobId)?.state === "completed"));
});

test("missing checkpoint evidence is never a tested proposal", () => {
  assert.equal(observeGoalTask(undefined, asProjectId(`prj_${"a".repeat(32)}`), randomUUID(), "goal"), undefined);
});

test("implementation evidence identity survives checkpoint key ordering but not altered source", () => {
  const a = { solve: { tests: true, source: "a" }, task: "repair" };
  const b = { task: "repair", solve: { source: "a", tests: true } };
  assert.equal(projectImplementationDigest(a), projectImplementationDigest(b));
  assert.notEqual(projectImplementationDigest(a), projectImplementationDigest({ ...b, solve: { ...b.solve, source: "b" } }));
});
