import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { composeKeep, type KeepApp } from "../src/compose.js";
import { hashSkill, ManagedSkillRegistry, InMemoryRegistryStore, FileSkillRegistryPersistence, publishSkill, type SkillRegistrySnapshot } from "../src/registry/skill_registry.js";
import { SkillEvaluator } from "../src/loop/skill_evaluator.js";
import { SkillCanary, type CanaryNotice } from "../src/loop/skill_canary.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";

const cases = [-2, -1, 0, 2].map((x, i) => ({ id: `case-${i}`, input: JSON.stringify({ x }) }));
function skill(action = "absolute"): DistilledSkill {
  return { format: "keep.skill/v1", id: "promotion-target", name: "Synthetic absolute value", description: "numeric audit procedure",
    requiredAuthority: [], relevanceKey: "number", provenance: ["synthetic-input"], confidence: "low",
    envelope: { preconditions: ["numeric x"], steps: [{ action, targetPattern: "{arg}" }], postconditions: ["absolute value"], declaredEffects: [] } };
}
const baseline = (c: { input: string }) => JSON.parse(c.input).x === 0;
function execute(s: DistilledSkill, c: { input: string }, offset = 0): boolean {
  const x = JSON.parse(c.input).x as number;
  const actual = s.envelope.steps[0]?.action === "wrong" ? 9 : Math.abs(x) + offset;
  return actual === Math.abs(x);
}
const retrieved = (app: KeepApp) => app.skillRetrieval.retrieve({ taskShape: "number" }).map(row => hashSkill(row.skill));
function restarted(root: string) {
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import {composeKeep} from ${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)};
    import {hashSkill} from ${JSON.stringify(new URL("../src/registry/skill_registry.js", import.meta.url).href)};
    const app=composeKeep({dataDir:process.argv[1]}); console.log(JSON.stringify({
      hashes:app.skillRetrieval.retrieve({taskShape:"number"}).map(row=>hashSkill(row.skill)),
      lifecycle:app.managedSkillRegistry.lifecycle("promotion-target")??null,
      canary:app.skillCanary.state("promotion-target")??null}));
  `, root], { encoding: "utf8", timeout: 15000 });
  assert.equal(child.status, 0, child.stderr);
  return JSON.parse(child.stdout);
}
test("KEEP-07A-001 rejected same-ID revision leaves the admitted incumbent live and durable", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-reject-"));
  const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: execute, runBaseline: baseline } });
  assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "retained");
  assert.equal(app.skillEvaluator!.evaluate(skill("wrong"), cases).verdict, "rejected-degradation");
  assert.deepEqual(retrieved(app), [hashSkill(skill())]);
  assert.deepEqual(restarted(root).hashes, retrieved(app));
});

test("KEEP-07A-001 deterioration of the exact admitted version withdraws it durably", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-incumbent-"));
  let offset = 0;
  const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: (s, c) => execute(s, c, offset), runBaseline: baseline } });
  assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "retained");
  offset = 1;
  assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "rolled-back-degradation");
  assert.deepEqual(retrieved(app), []);
  assert.equal(app.managedSkillRegistry.lifecycle(skill().id)?.retired?.reason, "harmful");
  assert.deepEqual(restarted(root).hashes, []);
});

test("KEEP-07A-002 retired same-content reevaluation and goLive report the actual held state", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-retired-"));
  const notices: CanaryNotice[] = [];
  const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: execute, runBaseline: baseline }, skillCanaryNotifier: { notify: n => notices.push(n) } });
  assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "retained");
  await app.selfImprovementBus.publish({ solveId: "synthetic-failure", taskShape: "number", testsPassed: false,
    mergeVerdict: "pending", activeArtifacts: [skill().id], timestamp: Date.now() });
  const before = notices.length;
  assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "held-retired");
  const repeated = app.skillCanary.goLive(skill().id);
  assert.equal(repeated.state, app.skillCanary.state(skill().id));
  assert.equal(repeated.transition, "unchanged");
  assert.equal(notices.length, before);
  assert.deepEqual(retrieved(app), []);
  assert.deepEqual(restarted(root).hashes, []);
});

test("KEEP-07A-003 real snapshot rename failure leaves no partial promotion; bounded retry succeeds", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-save-"));
  const notices: CanaryNotice[] = [];
  const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: execute, runBaseline: baseline }, skillCanaryNotifier: { notify: n => notices.push(n) } });
  const snapshot = join(root, "skill-registry/default.json");
  mkdirSync(snapshot, { recursive: true }); // Actual fault at an isolated fresh target, not a throwing stub.
  assert.throws(() => app.skillEvaluator!.evaluate(skill(), cases), /EISDIR|directory|commit/i);
  assert.equal(app.registryStore!.get(skill().id), undefined);
  assert.equal(app.managedSkillRegistry.lifecycle(skill().id), undefined);
  assert.equal(app.skillCanary.state(skill().id), undefined);
  assert.deepEqual(retrieved(app), []);
  assert.deepEqual(notices, []);
  assert.equal(JSON.parse(readFileSync(`${snapshot}.tmp`, "utf8")).packages[0].contentHash, hashSkill(skill()));
  renameSync(snapshot, join(root, "preserved-obstruction"));
  assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "retained");
  assert.deepEqual(restarted(root).hashes, [hashSkill(skill())]);
  assert.equal(notices.length, 1);
});

test("KEEP-07A-003 a throwing retained sink never gets a canary or promotion notice", () => {
  const notices: CanaryNotice[] = [];
  const canary = new SkillCanary({ notifier: { notify: n => notices.push(n) } });
  const evaluator = new SkillEvaluator({ runWithSkill: execute, runBaseline: baseline }, canary, undefined,
    { add: () => { throw Error("synthetic retention failure"); } });
  assert.throws(() => evaluator.evaluate(skill(), cases), /retention failure/);
  assert.equal(canary.state(skill().id), undefined);
  assert.deepEqual(notices, []);
});

test("promotion notice observes the committed package and usable retrieval; notifier failure does not undo it", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-notice-"));
  const observed: unknown[] = [];
  const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: execute, runBaseline: baseline },
    skillCanaryNotifier: { notify: () => {
      observed.push({ hash: JSON.parse(readFileSync(join(root, "skill-registry/default.json"), "utf8")).packages[0].contentHash,
        retrieval: retrieved(app), state: app.skillCanary.state(skill().id) });
      throw Error("synthetic notifier failure");
    } } });
  assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "retained");
  assert.deepEqual(observed, [{ hash: hashSkill(skill()), retrieval: [hashSkill(skill())], state: "canary" }]);
  assert.deepEqual(restarted(root).hashes, [hashSkill(skill())]);
});

test("KEEP-07A-003 failed replacement preserves incumbent and reuse counters through two real faults", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-replace-fault-"));
  const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: execute, runBaseline: baseline } });
  assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "retained");
  await app.selfImprovementBus.publish({ solveId: "synthetic-use", taskShape: "number", testsPassed: true,
    mergeVerdict: "merged", activeArtifacts: [skill().id], timestamp: Date.now() });
  const previous = app.managedSkillRegistry.lifecycle(skill().id);
  const snapshot = join(root, "skill-registry/default.json"), preserved = join(root, "preserved-snapshot.json");
  renameSync(snapshot, preserved);
  mkdirSync(snapshot);
  for (const action of ["absolute-v2", "absolute-v3"]) {
    assert.throws(() => app.skillEvaluator!.evaluate(skill(action), cases), /EISDIR|directory|commit/i);
    assert.deepEqual(app.managedSkillRegistry.lifecycle(skill().id), previous);
    assert.deepEqual(retrieved(app), [hashSkill(skill())]);
    assert.equal(JSON.parse(readFileSync(`${snapshot}.tmp`, "utf8")).packages[0].contentHash, hashSkill(skill(action)));
  }
  renameSync(snapshot, join(root, "preserved-obstruction"));
  renameSync(preserved, snapshot);
  assert.deepEqual(restarted(root).hashes, [hashSkill(skill())], "leftover temporary candidate is never restored");
  assert.equal(app.skillEvaluator!.evaluate(skill("absolute-v3"), cases).verdict, "retained");
  assert.deepEqual(restarted(root).hashes, [hashSkill(skill("absolute-v3"))]);
  assert.equal(app.managedSkillRegistry.lifecycle(skill().id)?.uses, 0);
});

test("high-impact retry reruns execution and reuses only the identical failed-retention criticism", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-critic-retry-"));
  let critics = 0, executions = 0;
  const candidate: DistilledSkill = { ...skill(), requiredAuthority: ["workspace:write"] };
  const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: (s, c) => { executions++; return execute(s, c); }, runBaseline: baseline },
    skillCriticism: { builderFamily: "synthetic-builder", critic: { criticize: () => {
      critics++; return { reviewerFamily: "synthetic-critic", verdict: "clear", findings: [] };
    } } } });
  const snapshot = join(root, "skill-registry/default.json");
  mkdirSync(snapshot, { recursive: true });
  assert.throws(() => app.skillEvaluator!.evaluate(candidate, cases), /commit/i);
  renameSync(snapshot, join(root, "preserved-obstruction"));
  assert.equal(app.skillEvaluator!.evaluate(candidate, cases).verdict, "retained");
  assert.equal(critics, 1);
  assert.equal(executions, cases.length * 2);
  assert.deepEqual(restarted(root).hashes, [hashSkill(candidate)]);
  const changed = { ...candidate, description: "different candidate" };
  assert.equal(app.skillEvaluator!.evaluate(changed, cases).verdict, "held-for-criticism", "success consumes the retry allowance; it cannot bless changed content");
});

test("KEEP-07A-002 explicit changed checked revision reactivates after harmful or unused retirement", async () => {
  for (const reason of ["harmful", "unused"] as const) {
    const root = mkdtempSync(join(tmpdir(), `keep-promotion-${reason}-`));
    const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: execute, runBaseline: baseline } });
    assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "retained");
    if (reason === "harmful") {
      await app.selfImprovementBus.publish({ solveId: "synthetic-failure", taskShape: "number", testsPassed: false,
        mergeVerdict: "pending", activeArtifacts: [skill().id], timestamp: Date.now() });
    } else {
      app.managedSkillRegistry.retireUnused(Date.now() + 91 * 24 * 60 * 60 * 1000);
      app.skillCanary.forceRollback(skill().id, "unused");
    }
    assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "held-retired");
    const changed = skill("absolute-revised");
    assert.equal(app.skillEvaluator!.evaluate(changed, cases).verdict, "retained");
    assert.equal(app.skillCanary.state(changed.id), "canary");
    assert.equal(app.skillCanary.revision(changed.id), hashSkill(changed));
    assert.equal(app.managedSkillRegistry.lifecycle(changed.id)?.retired, undefined);
    assert.deepEqual(retrieved(app), [hashSkill(changed)]);
    assert.deepEqual(restarted(root).hashes, [hashSkill(changed)]);
  }
});

test("unbound terminal canary cannot be reinterpreted as a checked replacement", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-unbound-"));
  const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: execute, runBaseline: baseline } });
  app.skillCanary.goLive(skill().id);
  app.skillCanary.forceRollback(skill().id, "synthetic prior terminal state");
  assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "held-retired");
  assert.equal(app.registryStore!.get(skill().id), undefined);
  assert.deepEqual(restarted(root).hashes, []);
});

test("candidate evaluation cannot overwrite a subject changed by a trusted oracle", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-subject-"));
  let change = false;
  const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: (s, c) => {
    if (change) { change = false; app.managedSkillRegistry.trackValidated(skill("absolute-other"), "synthetic-concurrent-check"); }
    return execute(s, c);
  }, runBaseline: baseline } });
  assert.equal(app.skillEvaluator!.evaluate(skill(), cases).verdict, "retained");
  change = true;
  assert.equal(app.skillEvaluator!.evaluate(skill("absolute-proposed"), cases).verdict, "held-state-changed");
  assert.equal(app.registryStore!.get(skill().id)?.contentHash, hashSkill(skill("absolute-other")));
  assert.deepEqual(restarted(root).hashes, [hashSkill(skill("absolute-other"))]);
});

test("registry snapshots are staged deeply, no-op writes are omitted, and reentrant saves are refused", () => {
  const store = new InMemoryRegistryStore();
  let saved: SkillRegistrySnapshot | undefined, saves = 0, reenter = false;
  const registry = new ManagedSkillRegistry({ store, gate: async () => ({ ok: true, verdict: "synthetic-check" }),
    persistence: { load: () => saved, save: value => {
      saves++;
      if (reenter) assert.throws(() => registry.trackValidated(skill("absolute-reentrant"), "test"), /reentrant/);
      saved = value;
    } } });
  registry.trackValidated(skill(), "test", 0);
  registry.retireUnused(0);
  registry.recordOutcome({ solveId: "none", taskShape: "other", testsPassed: true, mergeVerdict: "pending", activeArtifacts: [], timestamp: 1 });
  assert.equal(saves, 1);
  reenter = true;
  registry.recordOutcome({ solveId: "use", taskShape: "number", testsPassed: true, mergeVerdict: "merged", activeArtifacts: [skill().id], timestamp: 2 });
  assert.equal(saves, 2);
  assert.equal(registry.lifecycle(skill().id)?.uses, 1);
  assert.equal(saved?.lifecycle[0]?.uses, 1);
  assert.equal(Object.isFrozen(saved?.packages[0]?.skill.envelope), true);
  assert.equal(store.get(skill().id)?.contentHash, hashSkill(skill()));
});

test("a custom save that commits then throws fences live admission until reconstruction", () => {
  let saved: SkillRegistrySnapshot | undefined, uncertain = false;
  const persistence = { load: () => saved, save: (value: SkillRegistrySnapshot) => {
    saved = value;
    if (uncertain) throw Error("custom uncertain post-save failure");
  } };
  const registry = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), persistence, gate: async () => ({ ok: true, verdict: "synthetic-check" }) });
  registry.trackValidated(skill(), "test", 0);
  uncertain = true;
  assert.throws(() => registry.trackValidated(skill("absolute-revised"), "test", 1), /post-save failure/);
  assert.equal(registry.admissionStatus(skill().id), "reconstruction-required");
  assert.deepEqual(registry.activePackages(), []);
  assert.throws(() => registry.trackValidated(skill(), "test"), /requires reconstruction/);
  const restored = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), persistence, gate: async () => ({ ok: true, verdict: "synthetic-check" }) });
  assert.deepEqual(restored.activePackages().map(p => p.contentHash), [hashSkill(skill("absolute-revised"))]);
});

test("async admission refuses a retirement occurring while its gate is pending", async () => {
  const store = new InMemoryRegistryStore();
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const registry = new ManagedSkillRegistry({ store, gate: async () => { await pending; return { ok: true, verdict: "synthetic-check" }; } });
  registry.trackValidated(skill(), "test", 0);
  const admission = registry.add(publishSkill(skill("absolute-revised"), "test", 1));
  registry.retireUnused(91 * 24 * 60 * 60 * 1000);
  release();
  const result = await admission;
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.detail, /state changed/);
  assert.equal(store.get(skill().id)?.contentHash, hashSkill(skill()));
  assert.equal(registry.lifecycle(skill().id)?.retired?.reason, "unused");
});

test("failed exact withdrawal fences retrieval and reports failure rather than durable success", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-withdraw-fault-"));
  const snapshot = join(root, "registry.json");
  const store = new InMemoryRegistryStore();
  const registry = new ManagedSkillRegistry({ store, persistence: new FileSkillRegistryPersistence(snapshot), gate: async () => ({ ok: true, verdict: "synthetic-check" }) });
  registry.trackValidated(skill(), "test", 0);
  renameSync(snapshot, join(root, "preserved-snapshot.json"));
  mkdirSync(snapshot);
  assert.throws(() => registry.withdrawExact(skill()), /commit/i);
  assert.equal(registry.admissionStatus(skill().id), "reconstruction-required");
  assert.equal(registry.isEligible(skill()), false);
  assert.equal(registry.lifecycle(skill().id)?.retired, undefined, "failed save did not establish durable retirement");
});

test("a draft exception after counter mutation leaves the live lifecycle untouched", () => {
  const registry = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: async () => ({ ok: true, verdict: "synthetic-check" }) });
  registry.trackValidated(skill(), "test", 0);
  const before = registry.lifecycle(skill().id);
  assert.throws(() => registry.recordOutcome({ solveId: "throwing-input", taskShape: "number", testsPassed: true,
    mergeVerdict: "merged", activeArtifacts: [skill().id], get timestamp(): number { throw Error("synthetic timestamp getter failed"); } }), /timestamp getter/);
  assert.deepEqual(registry.lifecycle(skill().id), before);
  assert.equal(registry.isEligible(skill()), true);
});

test("bundle storage failure publishes no prefix and normal retry retains both checked entries", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-promotion-bundle-fault-"));
  const gate = async () => ({ ok: true, verdict: "synthetic-check" });
  const source = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate });
  source.trackValidated(skill(), "test", 0);
  source.trackValidated({ ...skill("absolute-second"), id: "second" }, "test", 0);
  const bundle = source.exportBundle(), store = new InMemoryRegistryStore();
  const snapshot = join(root, "registry.json"), admitted: string[] = [];
  const registry = new ManagedSkillRegistry({ store, gate, persistence: new FileSkillRegistryPersistence(snapshot), onAdmit: s => admitted.push(s.id) });
  mkdirSync(snapshot);
  await assert.rejects(registry.importBundle(bundle), /commit/i);
  assert.deepEqual(store.list(), []);
  assert.deepEqual(registry.activePackages(), []);
  assert.deepEqual(admitted, []);
  assert.equal(JSON.parse(readFileSync(`${snapshot}.tmp`, "utf8")).packages.length, 2);
  renameSync(snapshot, join(root, "preserved-obstruction"));
  assert.deepEqual(await registry.importBundle(bundle), { ok: true, installed: 2, merged: 0 });
  assert.deepEqual(admitted, [skill().id, "second"]);
  const restored = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate, persistence: new FileSkillRegistryPersistence(snapshot) });
  assert.deepEqual(restored.activePackages().map(p => p.contentHash), source.activePackages().map(p => p.contentHash));
});

test("async bundle preflight cannot overwrite an intervening incumbent retirement", async () => {
  const source = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: async () => ({ ok: true, verdict: "synthetic-check" }) });
  source.trackValidated(skill("absolute-revised"), "test", 1);
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const store = new InMemoryRegistryStore();
  const registry = new ManagedSkillRegistry({ store, gate: async () => { await pending; return { ok: true, verdict: "synthetic-check" }; } });
  registry.trackValidated(skill(), "test", 0);
  const admission = registry.importBundle(source.exportBundle());
  registry.retireUnused(91 * 24 * 60 * 60 * 1000);
  release();
  const result = await admission;
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.detail, /state changed/);
  assert.equal(store.get(skill().id)?.contentHash, hashSkill(skill()));
  assert.equal(registry.lifecycle(skill().id)?.retired?.reason, "unused");
});

test("custom catalog publication failure fences partially written live state and reconstructs from committed bytes", () => {
  const backing = new InMemoryRegistryStore();
  let fail = false, saved: SkillRegistrySnapshot | undefined;
  const persistence = { load: () => saved, save: (value: SkillRegistrySnapshot) => { saved = value; } };
  const gate = async () => ({ ok: true, verdict: "synthetic-check" });
  const registry = new ManagedSkillRegistry({ gate, persistence, store: {
    get: id => backing.get(id), list: () => backing.list(), put: pkg => {
      backing.put(pkg);
      if (fail) throw Error("synthetic post-put error");
    },
  } });
  registry.trackValidated(skill(), "test", 0);
  fail = true;
  assert.throws(() => registry.trackValidated(skill("absolute-revised"), "test", 1), /post-put error/);
  assert.equal(backing.get(skill().id)?.contentHash, hashSkill(skill("absolute-revised")), "the custom callback did change its catalog before failing");
  assert.equal(registry.admissionStatus(skill().id), "reconstruction-required");
  assert.deepEqual(registry.activePackages(), []);
  const restored = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate, persistence });
  assert.deepEqual(restored.activePackages().map(p => p.contentHash), [hashSkill(skill("absolute-revised"))]);
});
