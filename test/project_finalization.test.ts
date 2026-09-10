import test from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildAutonomyLoop } from "../src/autonomy/autonomy_loop.js";
import { ProjectFinalizationError, type LoopRunResult } from "../src/autonomy/project_loop.js";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { InMemoryProjectCheckpointStore } from "../src/autonomy/project_checkpoint_store.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { ProjectSessionManager } from "../src/session/project_session_manager.js";
import { FileProjectSessionPersistence } from "../src/session/project_session_persistence.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ProjectRuntime } from "../src/session/project_runtime.js";
import { SpineProjectJobJournal } from "../src/session/project_job_journal.js";

for (const tenant of [undefined, "alpha"]) for (const newer of [false, true]) {
  test(`finalization retains accepted checkpoint winner (${tenant ?? "personal"}, newer=${newer})`, async () => {
    const root = mkdtempSync(join(tmpdir(), "keep-finalization-winner-"));
    const store = new FileProjectSessionPersistence(join(root, "session.json"));
    const registry = new ProjectRegistry(new CryptoShredKeyStore()), checkpoints = new InMemoryProjectCheckpointStore();
    let actual: LoopRunResult | undefined, armed = false, wins = 0, callbacks = 0;
    const port = { load: store.load.bind(store), save: (...args: Parameters<typeof store.save>) => {
      if (armed && actual && args[0].checkpointRef?.revision === actual.state.revision) {
        armed = false; wins++;
        const next = newer ? { ...actual.state, revision: actual.state.revision + 1, note: "newer sibling result" } : actual.state;
        if (newer) checkpoints.save(next, actual.state.revision);
        const sibling = new ProjectSessionManager(registry, undefined, () => store, checkpoints).session(args[0].projectId);
        sibling.checkpoint(next); sibling.append("user", "retained winner history"); sibling.spend(1);
      }
      return store.save(...args);
    } };
    const manager = new ProjectSessionManager(registry, undefined, () => port, checkpoints);
    const project = manager.create({ name: "checkpoint winner", ...(tenant ? { tenant } : {}), budget: { spentTokensToday: 0, dailyTokenCap: 10 } });
    const loop = buildAutonomyLoop({ manager, checkpoints,
      spine: new Spine(new FileSpineStore(join(root, "spine"), { fsync: true }), new InProcessLock(), new SchemaRegistry()),
      solve: async () => { throw new Error("no model or solve test"); },
      runInProjectContext: async (_project, _run, run) => {
        const result = await run(); actual = result as LoopRunResult; callbacks++;
        appendFileSync(join(root, "effects.txt"), "one controlled effect\n"); armed = true; return result;
      },
    });
    const returned = await loop.runManagedProject(project.id, "write and test a local parser", { runId: "winner-run", stepBudget: 1 });
    assert.ok(actual); assert.equal(wins, 1); assert.equal(callbacks, 1); assert.deepEqual(returned, actual);
    assert.equal(readFileSync(join(root, "effects.txt"), "utf8"), "one controlled effect\n");
    const restored = new ProjectSessionManager(registry, undefined, () => store, checkpoints).session(project.id);
    assert.equal(restored.lastCheckpoint()!.revision, actual.state.revision + (newer ? 1 : 0));
    assert.equal(restored.budget.spentTokensToday, 1);
    assert.ok(restored.history().some(entry => entry.text === "retained winner history"));
    assert.match(restored.history().at(-1)!.text, new RegExp(`revision ${actual.state.revision}\\b`));
  });
}

for (const tenant of [undefined, "alpha"]) for (const mode of ["control", "sibling", "save-failure"] as const) {
  test(`managed result survives post-callback ${mode} (${tenant ?? "personal"})`, async () => {
    const root = mkdtempSync(join(tmpdir(), "keep-finalization-"));
    const store = new FileProjectSessionPersistence(join(root, "session.json"));
    const registry = new ProjectRegistry(new CryptoShredKeyStore());
    const checkpoints = new InMemoryProjectCheckpointStore();
    let fail = false, callbacks = 0;
    const port = { load: () => store.load(), save: (...args: Parameters<typeof store.save>) => {
      if (fail) throw new Error("synthetic post-callback save refusal");
      return store.save(...args);
    } };
    const manager = new ProjectSessionManager(registry, undefined, () => port, checkpoints);
    const project = manager.create({ name: "finalization", ...(tenant === undefined ? {} : { tenant }) });
    let actual: LoopRunResult | undefined;
    const loop = buildAutonomyLoop({ manager, checkpoints,
      spine: new Spine(new FileSpineStore(join(root, "spine"), { fsync: true }), new InProcessLock(), new SchemaRegistry()),
      solve: async () => { throw new Error("not a model or solver test"); },
      runInProjectContext: async (_project, _run, run) => {
        const result = await run(); actual = result as LoopRunResult;
        callbacks++; appendFileSync(join(root, "effects.txt"), "actual synthetic effect\n");
        if (mode === "sibling") new ProjectSessionManager(registry, undefined, () => store, checkpoints)
          .session(project.id).append("user", "concurrent retained note");
        fail = mode === "save-failure";
        return result;
      },
    });
    let result: LoopRunResult | undefined, error: unknown;
    try { result = await loop.runManagedProject(project.id, "write and test a local parser", { runId: "owned-run", stepBudget: 1 }); }
    catch (cause) { error = cause; }
    assert.ok(actual); assert.equal(callbacks, 1);
    assert.equal(readFileSync(join(root, "effects.txt"), "utf8"), "actual synthetic effect\n");
    assert.deepEqual(checkpoints.load("owned-run"), actual.state);
    if (mode === "save-failure") {
      assert.ok(error instanceof Error);
      assert.equal(error.name, "ProjectFinalizationError");
      assert.deepEqual((error as Error & { result: LoopRunResult }).result, actual);
      fail = false;
      for (const boundary of ["settle", "hold-write"] as const) {
        const journal = new SpineProjectJobJournal(new Spine(new FileSpineStore(join(root, boundary), { fsync: true }), new InProcessLock(), new SchemaRegistry()));
        if (boundary === "settle") journal.settleActivity = async () => { throw new Error("injected activity settlement refusal"); };
        else {
          const append = journal.append.bind(journal);
          journal.append = intent => { if (intent.state === "reconciliation-required") throw new Error("injected hold persistence refusal"); append(intent); };
        }
        const runtime = new ProjectRuntime(manager, { aggregateCeiling: 1, perProjectShare: 1 }, journal);
        const tracked = runtime.submitTracked(project.id, 1, async () => { throw error; });
        await assert.rejects(tracked.completion, caught => caught === error, "secondary bookkeeping failure must not replace the result-bearing error");
        const held = runtime.job(tracked.jobId)!;
        assert.equal(held.state, "reconciliation-required");
        if (boundary === "settle") assert.equal(held.activeActivityIds?.length, 1, "unconfirmed settlement still consumes capacity");
        else assert.equal(journal.load().find(row => row.id === tracked.jobId)?.state, "running", "local hold is not falsely described as durable");
      }
    } else {
      assert.equal(error, undefined); assert.deepEqual(result, actual);
      const restored = new ProjectSessionManager(registry, undefined, () => store, checkpoints).session(project.id);
      assert.deepEqual(restored.lastCheckpoint(), actual.state);
      if (mode === "sibling") assert.ok(restored.history().some(entry => entry.text === "concurrent retained note"));
    }
  });
}

for (const tenant of [undefined, "alpha"]) test(`runtime and HTTP retain finalization holds for run/resume (${tenant ?? "personal"})`, async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-finalization-http-"));
  const owner = { id: "owner-alpha", tenant: "alpha", kind: "human" as const, role: "owner" as const };
  const configuration = { dataDir, solve: async () => { throw new Error("not a model or solver test"); },
    delegationParentFor: (id: string, scope?: string) => id === owner.id && scope === owner.tenant ? owner : undefined };
  const app = composeKeep(configuration);
  const manager = app.projectManager!, runtime = app.projectRuntime!, loop = app.autonomyLoop!;
  const project = manager.create({ name: "HTTP finalization", ...(tenant === undefined ? {} : { tenant }) });
  let runs = 0, resumes = 0, actual: LoopRunResult | undefined;
  const originalRun = loop.runManagedProject.bind(loop), originalResume = loop.resumeManagedProject.bind(loop);
  // Exercise the runtime/HTTP consumers with a typed post-result failure. The
  // preceding tests exercise actual session save failures at the producer.
  loop.runManagedProject = async (...args) => {
    runs++; actual = await originalRun(...args);
    throw new ProjectFinalizationError(actual, "history", { cause: new Error("private storage path must not be echoed") });
  };
  loop.resumeManagedProject = async (...args) => {
    resumes++; actual = await originalResume(...args);
    throw new ProjectFinalizationError(actual, "history", { cause: new Error("private storage path must not be echoed") });
  };
  const token = "synthetic-finalization-token";
  const security = { token, ...(tenant === undefined ? {} : { principalFor: () => ({ id: "owner-alpha", tenant, kind: "human" as const, role: "owner" as const }) }) };
  const call = (path: string, body: unknown) => handleGatewayRequest(app, { method: "POST", path, query: {},
    headers: { authorization: `Bearer ${token}` }, body: JSON.stringify(body) }, security);
  const first = await call("/project", { projectId: project.id, goal: "write and test a local parser" });
  assert.equal(first.status, 409, first.body); assert.ok(actual, first.body);
  const summary = JSON.parse(first.body);
  assert.equal(summary.status, "reconciliation-required"); assert.equal(summary.taskStatus, actual.state.status);
  assert.equal(summary.runId, actual.state.runId); assert.equal(summary.revision, actual.state.revision);
  assert.deepEqual(summary.finalization, { phase: "history", confirmed: false, replayTask: false });
  assert.equal(first.body.includes("private storage path"), false);
  assert.equal(Object.hasOwn(summary, "artifacts"), false);
  const jobs = runtime.jobs(new Set([project.id]));
  assert.equal(jobs.length, 1); assert.equal(jobs[0]!.state, "reconciliation-required");
  assert.equal(composeKeep(configuration).projectRuntime!.job(jobs[0]!.id)?.state, "reconciliation-required");
  assert.equal(runs, 1); assert.equal(resumes, 0);
  // Exercise resume on a separate, normally checkpointed project. This test does
  // not use another task execution as a way to repair the earlier finalization.
  const resumable = manager.create({ name: "resume finalization", ...(tenant === undefined ? {} : { tenant }) });
  const prepared = await originalRun(resumable.id, "write and test a local parser", { stepBudget: 1 });
  const second = await call("/project/resume", { runId: prepared.state.runId });
  assert.equal(second.status, 409, second.body);
  assert.equal(JSON.parse(second.body).finalization.confirmed, false);
  assert.equal(runs, 1); assert.equal(resumes, 1, "only the explicitly requested resume ran");
});
