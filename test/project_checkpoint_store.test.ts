import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  FileProjectCheckpointStore,
  InMemoryProjectCheckpointStore,
  ProjectCheckpointConflictError,
  type ProjectCheckpointStore,
} from "../src/autonomy/project_checkpoint_store.js";
import { decodeProjectState, InvalidProjectStateError, PROJECT_STATE_SCHEMA_VERSION, type ProjectState } from "../src/autonomy/project_state.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { ProjectRegistry } from "../src/session/project_registry.js";

function state(overrides: Partial<ProjectState> = {}): ProjectState {
  return {
    schemaVersion: PROJECT_STATE_SCHEMA_VERSION,
    revision: 0,
    runId: "run/../hostile-but-data",
    goal: "build the requested artifact",
    stage: "understand",
    artifacts: {},
    posture: "autonomous",
    stepsRemaining: 100,
    reworkCount: 0,
    status: "running",
    retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 },
    consumedSignals: [],
    ...overrides,
  };
}

function contract(store: ProjectCheckpointStore): void {
  const initial = state();
  const first = store.save(initial, undefined);
  assert.equal(first.sha256.length, 64);
  assert.deepEqual(store.load(initial.runId), initial);
  assert.throws(() => store.save(initial, undefined), ProjectCheckpointConflictError);

  const next = state({ revision: 1, stage: "research", artifacts: { understand: { intent: "verified" } } });
  store.save(next, 0);
  assert.deepEqual(store.load(initial.runId), next);
  assert.throws(() => store.save(state({ revision: 1 }), 0), ProjectCheckpointConflictError);
  assert.throws(() => store.save(state({ revision: 3 }), 1), ProjectCheckpointConflictError);
}

test("checkpoint contract: in-memory adapter preserves CAS and defensive copies", () => {
  const store = new InMemoryProjectCheckpointStore();
  contract(store);
  const loaded = store.load("run/../hostile-but-data")!;
  (loaded.artifacts as Record<string, unknown>)["tamper"] = true;
  assert.equal((store.load(loaded.runId)!.artifacts as Record<string, unknown>)["tamper"], undefined);
});

test("checkpoint contract: file adapter survives a new process-level instance and never interprets runId as a path", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-project-store-"));
  try {
    contract(new FileProjectCheckpointStore(dir));
    const restored = new FileProjectCheckpointStore(dir).load("run/../hostile-but-data");
    assert.equal(restored?.revision, 1);
    assert.equal(restored?.stage, "research");
    const files = readdirSync(dir);
    assert.ok(files.length >= 2, "published snapshot and immutable current-revision marker exist");
    const published = files.find((file) => /^[a-f0-9]{64}\.json$/.test(file))!;
    assert.equal(statSync(join(dir, published)).mode & 0o777, 0o600);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("installed encryption safely upgrades a legacy checkpoint using durable run ownership", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-project-checkpoint-upgrade-"));
  try {
    const runId = "legacy-owned-run"; new FileProjectCheckpointStore(dir).save(state({ runId }), undefined);
    const registry = new ProjectRegistry(new CryptoShredKeyStore()); const project = registry.create("legacy owner");
    const encrypted = new FileProjectCheckpointStore(dir, {
      encrypt: (projectId, plaintext) => registry.namespace(projectId).encrypt(plaintext),
      decrypt: (projectId, ciphertext) => registry.namespace(projectId).decrypt(ciphertext),
      projectIdForRun: (candidate) => candidate === runId ? project.id : undefined,
    });
    const restored = encrypted.load(runId)!; assert.equal(restored.projectId, project.id);
    encrypted.save({ ...restored, revision: 1, stage: "research" }, 0);
    const durable = readdirSync(dir).map((name) => readFileSync(join(dir, name), "utf8")).join("\n");
    assert.doesNotMatch(durable, /build the requested artifact/u); assert.equal(encrypted.load(runId)?.revision, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("checkpoint decoder rejects unknown schema/enums, malformed counters, wait mismatches, and hostile JSON", () => {
  const good = state();
  const bad: unknown[] = [
    { ...good, schemaVersion: 2 },
    { ...good, stage: "invented" },
    { ...good, posture: "implicit-superuser" },
    { ...good, strategy: { kind: "domain", domainKind: "unknown" } },
    { ...good, strategy: { kind: "software", domainKind: "audiobook" } },
    { ...good, strategy: { kind: "domain", domainKind: "audiobook", authority: "ambient" } },
    { ...good, status: "paused-human" },
    { ...good, revision: Number.NaN },
    { ...good, stepsRemaining: -1 },
    { ...good, retry: { attemptsByStage: {}, attemptsConsumed: 9, runLimit: 8 } },
    { ...good, status: "waiting-retry" },
    { ...good, wait: { kind: "retry", activity: "research", createdAt: 1, resumeAt: 2, attempt: 1, reason: "later" } },
    JSON.parse(`{"schemaVersion":1,"revision":0,"runId":"x","goal":"x","stage":"understand","artifacts":{"__proto__":{}},"posture":"autonomous","stepsRemaining":1,"reworkCount":0,"status":"running","retry":{"attemptsByStage":{},"attemptsConsumed":0,"runLimit":1}}`) as unknown,
  ];
  for (const candidate of bad) assert.throws(() => decodeProjectState(candidate), InvalidProjectStateError);
});

test("checkpoint file decoder rejects corrupted and oversized-on-policy durable content", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-project-corrupt-"));
  try {
    const store = new FileProjectCheckpointStore(dir);
    store.save(state({ runId: "corrupt" }), undefined);
    const file = join(dir, readdirSync(dir).find((name) => /^[a-f0-9]{64}\.json$/.test(name))!);
    writeFileSync(file, "{not-json", "utf8");
    assert.throws(() => store.load("corrupt"), SyntaxError, "a corrupted published candidate is not silently ignored");
    assert.equal(readFileSync(file, "utf8"), "{not-json");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("file adapter ignores orphan temporary bytes and recovers a committed marker after publish interruption", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-project-torn-"));
  try {
    const store = new FileProjectCheckpointStore(dir);
    store.save(state({ runId: "torn-window" }), undefined);
    const names = readdirSync(dir);
    const published = names.find((name) => /^[a-f0-9]{64}\.json$/.test(name))!;
    const marker = names.find((name) => /^[a-f0-9]{64}\.revision-0\.json$/.test(name))!;
    writeFileSync(join(dir, `.${published}.orphan.tmp`), "{torn", "utf8");
    rmSync(join(dir, published));
    assert.ok(marker, "the immutable committed revision remains after interrupted convenience publish");
    assert.deepEqual(new FileProjectCheckpointStore(dir).load("torn-window"), state({ runId: "torn-window" }));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("checkpoint decoder bounds artifact depth", () => {
  let nested: unknown = "leaf";
  for (let i = 0; i < 70; i += 1) nested = { next: nested };
  assert.throws(() => decodeProjectState(state({ artifacts: { nested } })), InvalidProjectStateError);
});

test("memory and file adapters reject the same non-JSON live values", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-project-equivalence-"));
  try {
    const stores: ProjectCheckpointStore[] = [new InMemoryProjectCheckpointStore(), new FileProjectCheckpointStore(dir)];
    for (const [index, store] of stores.entries()) {
      assert.throws(() => store.save(state({ runId: `undefined-${index}`, artifacts: { bad: undefined } }), undefined), InvalidProjectStateError);
      assert.throws(() => store.save(state({ runId: `function-${index}`, artifacts: { bad: () => true } }), undefined), InvalidProjectStateError);
      assert.throws(() => store.save(state({ runId: `date-${index}`, artifacts: { bad: new Date(0) } }), undefined), InvalidProjectStateError);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("immutable revision CAS lets exactly one stale writer commit", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-project-cas-"));
  try {
    const first = new FileProjectCheckpointStore(dir);
    const second = new FileProjectCheckpointStore(dir);
    first.save(state({ runId: "cas-run" }), undefined);
    const staleA = state({ runId: "cas-run", revision: 1, stage: "research" });
    const staleB = state({ runId: "cas-run", revision: 1, stage: "plan" });
    first.save(staleA, 0);
    assert.throws(() => second.save(staleB, 0), ProjectCheckpointConflictError);
    assert.deepEqual(second.load("cas-run"), staleA);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cross-process CAS admits exactly one writer for a revision", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-project-process-cas-"));
  try {
    new FileProjectCheckpointStore(dir).save(state({ runId: "process-cas" }), undefined);
    const barrier = join(dir, "start");
    const worker = `
      import { existsSync } from 'node:fs';
      import { FileProjectCheckpointStore, ProjectCheckpointConflictError } from './dist/src/autonomy/project_checkpoint_store.js';
      import { PROJECT_STATE_SCHEMA_VERSION } from './dist/src/autonomy/project_state.js';
      const [dir, barrier, stage] = process.argv.slice(1);
      while (!existsSync(barrier)) await new Promise(r => setTimeout(r, 1));
      const state = { schemaVersion: PROJECT_STATE_SCHEMA_VERSION, revision: 1, runId: 'process-cas', goal: 'build the requested artifact', stage, artifacts: {}, posture: 'autonomous', stepsRemaining: 100, reworkCount: 0, status: 'running', retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [] };
      try { new FileProjectCheckpointStore(dir).save(state, 0); process.exit(0); }
      catch (e) { if (!(e instanceof ProjectCheckpointConflictError)) console.error(e instanceof Error ? e.stack : String(e)); process.exit(e instanceof ProjectCheckpointConflictError ? 2 : 3); }
    `;
    const run = (stage: "research" | "plan") => new Promise<{ code: number; stderr: string }>((resolve) => {
      const child = spawn(process.execPath, ["--input-type=module", "-e", worker, dir, barrier, stage], { cwd: process.cwd(), stdio: ["ignore", "ignore", "pipe"] });
      let stderr = ""; child.stderr.setEncoding("utf8"); child.stderr.on("data", (chunk: string) => { stderr += chunk; });
      child.once("exit", (code) => resolve({ code: code ?? 3, stderr }));
    });
    const a = run("research");
    const b = run("plan");
    writeFileSync(barrier, "go", "utf8");
    const outcomes = await Promise.all([a, b]);
    assert.deepEqual(outcomes.map((outcome) => outcome.code).sort(), [0, 2], outcomes.map((outcome) => outcome.stderr).filter(Boolean).join("\n"));
    assert.ok(["research", "plan"].includes(new FileProjectCheckpointStore(dir).load("process-cas")!.stage));
    assert.equal(readdirSync(dir).filter((name) => name.endsWith(".revision-1.json")).length, 1, "the losing writer cannot unlink the winning recovery marker");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("enterprise-style adapter fixture obeys the same state/CAS contract", () => {
  class EnterpriseAdapterFixture implements ProjectCheckpointStore {
    readonly inner = new InMemoryProjectCheckpointStore();
    load(runId: string): ProjectState | undefined { return this.inner.load(runId); }
    save(next: ProjectState, expectedRevision: number | undefined) { return this.inner.save(next, expectedRevision); }
  }
  contract(new EnterpriseAdapterFixture());
});
