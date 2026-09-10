import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { composeKeep, type KeepApp } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { publishSkill, hashSkill, ManagedSkillRegistry, InMemoryRegistryStore, FileSkillRegistryPersistence } from "../src/registry/skill_registry.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";

// Adapted from copied Segment6B public/managed interaction cases. Outcomes are
// explicitly synthetic; retrieval observations never assert task execution.
function skill(id: string, action = "absolute"): DistilledSkill {
  return { format: "keep.skill/v1", id, name: id, description: "Synthetic numeric procedure", relevanceKey: id,
    requiredAuthority: [], confidence: "low", provenance: ["synthetic-input"],
    envelope: { preconditions: ["finite numeric input"], steps: [{ action, targetPattern: "{arg}" }],
      postconditions: ["absolute value"], declaredEffects: [] } };
}
function build(dataDir: string, oracle = false): KeepApp {
  return composeKeep({ dataDir, ...(oracle ? { skillOracle: {
    runWithSkill: (candidate: DistilledSkill) => candidate.envelope.steps[0]?.action === "absolute",
    runBaseline: () => false,
  } } : {}) });
}
const snapshot = (root: string) => join(root, "skill-registry", "default.json");

test("legacy retirement cannot be cleared by revalidation, bundle import or trusted retention", async () => {
  for (const reason of ["harmful", "unused", "redundant"] as const) {
    const root = mkdtempSync(join(tmpdir(), "keep-upgrade-retired-"));
    mkdirSync(join(root, "skill-registry"));
    const pkg = publishSkill(skill(reason), "synthetic-legacy", 10);
    const prior = { skillId: reason, uses: 4, reward: 8, lastUsedAt: 12,
      retired: { reason, at: 13 } };
    writeFileSync(snapshot(root), JSON.stringify({ schemaVersion: 1, packages: [pkg], lifecycle: [prior] }));
    const original = readFileSync(snapshot(root));
    const app = build(root, true);
    for (const candidate of [pkg.skill, { ...pkg.skill, description: "changed metadata does not authorize revival" }]) {
      const rejected = await app.managedSkillRegistry.add(publishSkill(candidate, "synthetic-revalidation"));
      assert.ok(!rejected.ok);
      assert.equal(rejected.reason, "held-legacy-retired");
      assert.equal(app.managedSkillRegistry.trackValidated(candidate, "synthetic-trusted-port").active, false);
      const exporter = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(),
        gate: async () => ({ ok: true, verdict: "synthetic-bundle-fixture-only" }) });
      assert.equal((await exporter.add(publishSkill(skill("unrelated-prefix"), "synthetic-export"))).ok, true);
      assert.equal((await exporter.add(publishSkill(candidate, "synthetic-export"))).ok, true);
      const imported = await app.managedSkillRegistry.importBundle(exporter.exportBundle());
      assert.ok(!imported.ok);
      assert.equal(imported.reason, "held-legacy-retired");
      assert.equal(app.registryStore!.get("unrelated-prefix"), undefined, "refused bundle cannot install its valid prefix");
      const evaluation = app.skillEvaluator!.evaluate(candidate, [{ id: "synthetic-promotion-control", input: "-7" }]);
      assert.equal(evaluation.verdict, "held-retired");
      assert.deepEqual(evaluation.skill, candidate, "a held verdict does not report historical content as the evaluated candidate");
      assert.deepEqual(app.managedSkillRegistry.lifecycle(reason), prior);
      assert.deepEqual(app.registryStore!.get(reason), pkg);
      assert.deepEqual(readFileSync(snapshot(root)), original);
      assert.deepEqual(retrieved(app, reason), []);
    }
    assert.equal(app.managedSkillRegistry.admissionStatus(reason), "retired");
    assert.deepEqual(restart(root).active, []);
    // Explicit static catalog replacement is a different operation: it can change
    // stored bytes, but never clears this retirement or makes either body usable.
    const replacement = { ...pkg.skill, description: "explicit static catalog replacement" };
    await catalogInstall(app, replacement);
    assert.equal((await app.managedSkillRegistry.add(publishSkill(skill("new-anchor"), "fixture"))).ok, true);
    assert.equal(app.registryStore!.get(reason)?.contentHash, hashSkill(replacement));
    assert.deepEqual(retrieved(app, reason), []);
    assert.deepEqual(restart(root).active, ["new-anchor"]);
    assert.equal(build(root).managedSkillRegistry.admissionStatus(reason), "retired");
  }
});

test("retirement during asynchronous validation invalidates the pending admission", async () => {
  const pkg = publishSkill(skill("concurrent-legacy"), "synthetic-legacy", 1);
  let resume!: () => void;
  let entered!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; });
  const wait = new Promise<void>(resolve => { resume = resolve; });
  const store = new InMemoryRegistryStore();
  const registry = new ManagedSkillRegistry({ store,
    persistence: { load: () => ({ schemaVersion: 2, packages: [pkg],
      lifecycle: [{ skillId: pkg.skill.id, admittedHash: pkg.contentHash, uses: 0, reward: 0, lastUsedAt: 1 }] }), save: () => {} },
    gate: async () => { entered(); await wait; return { ok: true, verdict: "synthetic-checked" }; },
  });
  const pending = registry.add(pkg);
  await ready;
  assert.deepEqual(registry.retireUnused(100 * 86400_000), [pkg.skill.id]);
  resume();
  const result = await pending;
  assert.equal(result.ok, false);
  assert.equal(registry.admissionStatus(pkg.skill.id), "retired");
  assert.deepEqual(store.get(pkg.skill.id), pkg);
  assert.deepEqual(registry.activePackages(), []);
});

test("exact retained legacy content can be checked and restored to use; backup restores only its own point in time", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-upgrade-usable-"));
  mkdirSync(join(root, "skill-registry"));
  const good = publishSkill(skill("retained-good"), "synthetic-legacy", 10);
  const bad = publishSkill(skill("retained-bad", "identity"), "synthetic-legacy", 10);
  const lifecycle = [good, bad].map(p => ({ skillId: p.skill.id, uses: 4, reward: 8, lastUsedAt: 12 }));
  writeFileSync(snapshot(root), JSON.stringify({ schemaVersion: 1, packages: [good, bad], lifecycle }));
  const backup = join(root, "private-pre-upgrade.json");
  copyFileSync(snapshot(root), backup);
  const original = readFileSync(backup);
  const unconfigured = build(root);
  assert.equal((await unconfigured.managedSkillRegistry.add(good)).ok, false, "missing oracle is not revalidation");
  assert.deepEqual(readFileSync(snapshot(root)), original);
  const calls: { id: string; input: number; actual: number; expected: number }[] = [];
  const app = composeKeep({ dataDir: root, skillOracle: {
    runWithSkill: (candidate, testCase) => {
      const input = testCase.input.includes("empty-input") ? 0 : testCase.input.includes("large") ? -1000 : -7;
      const actual = candidate.envelope.steps[0]?.action === "absolute" ? Math.abs(input) : input;
      const expected = Math.abs(input);
      calls.push({ id: candidate.id, input, actual, expected });
      return actual === expected;
    },
    runBaseline: () => { throw new Error("validation is not a comparative experiment"); },
  } });
  assert.deepEqual(readFileSync(snapshot(root)), original, "construction must not convert data");
  assert.equal((await app.managedSkillRegistry.add(bad)).ok, false);
  assert.ok(calls.some(c => c.id === bad.skill.id && c.actual !== c.expected));
  assert.deepEqual(readFileSync(snapshot(root)), original, "failed checking preserves data");
  const result = await app.managedSkillRegistry.add(app.registryStore!.get(good.skill.id)!);
  assert.ok(result.ok);
  assert.equal(result.pkg.contentHash, good.contentHash, "the retained bytes themselves passed");
  assert.ok(calls.filter(c => c.id === good.skill.id).length >= 6);
  assert.deepEqual(retrieved(app, good.skill.id), [good.contentHash]);
  assert.equal(app.managedSkillRegistry.lifecycle(good.skill.id)?.uses, 0, "new bound history does not borrow unverifiable old credit");
  assert.deepEqual(app.managedSkillRegistry.lifecycle(bad.skill.id), lifecycle[1]);
  assert.deepEqual(restart(root).active, [good.skill.id]);
  assert.equal((await app.managedSkillRegistry.add(publishSkill(skill("later-work"), "synthetic-new"))).ok, true);
  const upgraded = readFileSync(snapshot(root));
  assert.equal(JSON.parse(upgraded.toString()).schemaVersion, 2);
  const preservedNewer = join(root, "private-upgraded.json");
  copyFileSync(snapshot(root), preservedNewer);
  // Disposable fixture only: never overwrite an operator's live data for this test.
  copyFileSync(backup, snapshot(root));
  assert.deepEqual(readFileSync(snapshot(root)), original);
  const restored = build(root);
  assert.deepEqual(restored.registryStore!.list(), [good, bad]);
  assert.deepEqual(restored.managedSkillRegistry.lifecycle(good.skill.id), lifecycle[0]);
  assert.equal(restored.registryStore!.get("later-work"), undefined, "restoring old backup omits later work");
  assert.deepEqual(readFileSync(preservedNewer), upgraded, "newer state remains separately retained");
  assert.deepEqual(readFileSync(backup), original);
});
const retrieved = (app: KeepApp, id: string) => app.skillRetrieval.retrieve({ taskShape: id }).map(row => hashSkill(row.skill));
const outcome = (app: KeepApp, id: string) => app.selfImprovementBus.publish({
  solveId: "synthetic-anchor-outcome", taskShape: id, testsPassed: true, mergeVerdict: "pending",
  activeArtifacts: [id], timestamp: Date.now(),
});
async function catalogInstall(app: KeepApp, value: DistilledSkill) {
  const r = await handleGatewayRequest(app, { method: "POST", path: "/skill/install", query: {},
    headers: { authorization: "Bearer synthetic-owner" }, body: JSON.stringify({ pkg: publishSkill(value, "fixture") }),
  }, { token: "synthetic-owner" });
  assert.equal(r.status, 200, r.body);
}
function restart(root: string) {
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { composeKeep } from ${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)};
    import { hashSkill } from ${JSON.stringify(new URL("../src/registry/skill_registry.js", import.meta.url).href)};
    const app = composeKeep({dataDir: process.argv[1]});
    console.log(JSON.stringify({catalog: app.registryStore.list().map(p => p.skill.id),
      active: app.managedSkillRegistry.activePackages().map(p => p.skill.id),
      retrieval: Object.fromEntries(app.registryStore.list().map(p => [p.skill.id,
        app.skillRetrieval.retrieve({taskShape:p.skill.relevanceKey}).map(row => hashSkill(row.skill))]))}));
  `, root], { encoding: "utf8", timeout: 15_000, maxBuffer: 128 * 1024 });
  assert.equal(child.status, 0, child.stderr);
  return JSON.parse(child.stdout) as { catalog: string[]; active: string[]; retrieval: Record<string, string[]> };
}

test("KEEP-06B-002 catalog-only package plus managed outcome remains reconstructible and unadmitted", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-registry-new-"));
  const seed = build(root, true);
  assert.equal((await seed.managedSkillRegistry.add(publishSkill(skill("anchor"), "fixture"))).ok, true);
  const app = build(root);
  await catalogInstall(app, skill("unchecked", "wrong"));
  await outcome(app, "anchor");
  const state = restart(root);
  assert.deepEqual(state.catalog.sort(), ["anchor", "unchecked"]);
  assert.deepEqual(state.active, ["anchor"]);
  assert.deepEqual(state.retrieval["anchor"], [hashSkill(skill("anchor"))]);
  assert.deepEqual(state.retrieval["unchecked"], []);
});

test("KEEP-06B-001 changed same-ID catalog content cannot inherit admission live or after restart", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-registry-replace-"));
  const seed = build(root, true);
  for (const id of ["target", "anchor"]) assert.equal((await seed.managedSkillRegistry.add(publishSkill(skill(id), "fixture"))).ok, true);
  const acceptedSnapshot = readFileSync(snapshot(root));
  assert.equal((await seed.managedSkillRegistry.add(publishSkill(skill("target", "wrong"), "fixture"))).ok, false);
  assert.deepEqual(readFileSync(snapshot(root)), acceptedSnapshot, "failed checking preserves the durable incumbent");
  assert.deepEqual(retrieved(seed, "target"), [hashSkill(skill("target"))]);
  const app = build(root);
  assert.deepEqual(retrieved(app, "target"), [hashSkill(skill("target"))]);
  await catalogInstall(app, skill("target", "wrong"));
  await outcome(app, "anchor");
  assert.deepEqual(retrieved(app, "target"), [], "live retrieval must not disagree with current content eligibility");
  assert.equal(app.managedSkillRegistry.admissionStatus("target"), "content-changed");
  const state = restart(root);
  assert.deepEqual(state.active, ["anchor"]);
  assert.deepEqual(state.retrieval["target"], []);
  const checked = build(root, true);
  assert.equal((await checked.managedSkillRegistry.add(publishSkill(skill("target"), "fixture"))).ok, true);
  assert.deepEqual(retrieved(checked, "target"), [hashSkill(skill("target"))]);
  assert.deepEqual(restart(root).retrieval["target"], [hashSkill(skill("target"))]);
});

test("KEEP-06B-003 unused retirement is immediate and agrees with reconstructed retrieval", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-registry-retire-"));
  const app = build(root, true);
  assert.equal((await app.managedSkillRegistry.add(publishSkill(skill("old"), "fixture", Date.now() - 91 * 86400_000))).ok, true);
  assert.equal((await app.managedSkillRegistry.add(publishSkill(skill("healthy"), "fixture"))).ok, true);
  await outcome(app, "healthy");
  assert.equal(app.managedSkillRegistry.lifecycle("old")?.retired?.reason, "unused");
  assert.deepEqual(retrieved(app, "old"), []);
  assert.equal(app.skillCanary.state("old"), "rolled-back");
  assert.deepEqual(retrieved(app, "healthy"), [hashSkill(skill("healthy"))]);
  assert.deepEqual(restart(root).active, ["healthy"]);
});

test("KEEP-06B-002 legacy preview recovery retains data without inventing a checked-content binding", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-registry-legacy-"));
  const initial = build(root, true);
  assert.equal((await initial.managedSkillRegistry.add(publishSkill(skill("legacy"), "fixture"))).ok, true);
  const old = { schemaVersion: 1, packages: [publishSkill(skill("legacy", "wrong"), "fixture"), publishSkill(skill("catalog"), "fixture")],
    lifecycle: [{ skillId: "legacy", uses: 4, reward: 8, lastUsedAt: 123 }] };
  writeFileSync(snapshot(root), JSON.stringify(old));
  const before = readFileSync(snapshot(root));
  const recovered = build(root, true);
  assert.deepEqual(readFileSync(snapshot(root)), before, "loading legacy data is not a silent write");
  assert.equal(recovered.registryStore!.list().length, 2);
  assert.equal(recovered.managedSkillRegistry.lifecycle("legacy")?.uses, 4);
  assert.deepEqual(recovered.managedSkillRegistry.activePackages(), []);
  assert.deepEqual(retrieved(recovered, "legacy"), []);
  assert.equal(recovered.managedSkillRegistry.admissionStatus("legacy"), "legacy-unverified");
  assert.equal(recovered.managedSkillRegistry.admissionStatus("catalog"), "catalog-only");
  // An unrelated managed save must carry unverified history forward, not bind it.
  assert.equal((await recovered.managedSkillRegistry.add(publishSkill(skill("other"), "fixture"))).ok, true);
  assert.deepEqual(restart(root).active, ["other"]);
  assert.equal(build(root).managedSkillRegistry.admissionStatus("legacy"), "legacy-unverified");
  assert.equal((await recovered.managedSkillRegistry.add(publishSkill(skill("legacy"), "fixture"))).ok, true);
  assert.deepEqual(restart(root).active.sort(), ["legacy", "other"]);
  assert.ok(restart(root).catalog.includes("catalog"));
});

test("retirement eligibility is enforced even before a canary notification is propagated", async () => {
  const app = build(mkdtempSync(join(tmpdir(), "keep-registry-direct-retire-")), true);
  const now = Date.now();
  assert.equal((await app.managedSkillRegistry.add(publishSkill(skill("old"), "fixture", now - 91 * 86400_000))).ok, true);
  assert.equal(app.skillCanary.state("old"), "canary");
  assert.deepEqual(app.managedSkillRegistry.retireUnused(now), ["old"]);
  assert.equal(app.skillCanary.state("old"), "canary", "direct registry call does not itself deliver canary notifications");
  assert.equal(app.managedSkillRegistry.admissionStatus("old"), "retired");
  assert.deepEqual(retrieved(app, "old"), []);
});

test("composed equivalent merge offers the merged content immediately and after restart", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-registry-live-merge-"));
  const app = build(root, true);
  const first = skill("canonical");
  assert.equal((await app.managedSkillRegistry.add(publishSkill(first, "fixture"))).ok, true);
  const duplicate = { ...first, id: "duplicate", provenance: ["second-source"] };
  const result = await app.managedSkillRegistry.add(publishSkill(duplicate, "fixture"));
  assert.ok(result.ok);
  assert.equal(result.mergedInto, "canonical");
  const merged = app.registryStore!.get("canonical")!;
  assert.notEqual(merged.contentHash, hashSkill(first));
  assert.deepEqual(retrieved(app, "canonical"), [merged.contentHash]);
  assert.deepEqual(restart(root).retrieval["canonical"], [merged.contentHash]);
});

test("managed checked replacement starts version-specific lifecycle; identical retired content stays retired", async () => {
  const store = new InMemoryRegistryStore();
  const registry = new ManagedSkillRegistry({ store, gate: async (candidate) => ({
    ok: candidate.envelope.steps[0]?.action === "absolute", verdict: "fixture-candidate-checked",
  }) });
  const original = skill("revised");
  assert.equal((await registry.add(publishSkill(original, "fixture", 1))).ok, true);
  registry.recordOutcome({ solveId: "failed", taskShape: "revised", testsPassed: false, mergeVerdict: "pending",
    activeArtifacts: ["revised"], timestamp: 2 });
  const priorHistory = registry.lifecycle("revised");
  assert.equal(priorHistory?.retired?.reason, "harmful");
  assert.equal((await registry.add(publishSkill(original, "fixture", 3))).ok, true);
  assert.deepEqual(registry.lifecycle("revised"), priorHistory);
  assert.equal(registry.admissionStatus("revised"), "retired");
  const revised = { ...original, envelope: { ...original.envelope, postconditions: ["updated synthetic task contract"] } };
  assert.equal((await registry.add(publishSkill(revised, "fixture", 4))).ok, true);
  assert.equal(registry.admissionStatus("revised"), "admitted");
  assert.deepEqual(registry.lifecycle("revised"), { skillId: "revised", uses: 0, reward: 0, lastUsedAt: 4 });
  assert.equal(priorHistory?.retired?.reason, "harmful", "captured prior record is not mutated");
  registry.recordOutcome({ solveId: "second-failure", taskShape: "revised", testsPassed: false, mergeVerdict: "pending",
    activeArtifacts: ["revised"], timestamp: 5 });
  const callerChecked = { ...revised, description: "caller-checked third fixture version" };
  assert.equal(registry.trackValidated(callerChecked, "trusted-fixture", 6).active, true);
  assert.equal(store.get("revised")?.contentHash, hashSkill(callerChecked));
  assert.deepEqual(registry.lifecycle("revised"), { skillId: "revised", uses: 0, reward: 0, lastUsedAt: 6 });
  // Managed admission is not a canary/reactivation claim (KEEP-07A-002 remains open).
});

test("v2 bindings survive JSON key reordering and refuse corrupted or orphaned records without rewriting them", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-registry-bindings-"));
  const app = build(root, true);
  const value = skill("bound");
  assert.equal((await app.managedSkillRegistry.add(publishSkill(value, "fixture"))).ok, true);
  const original = JSON.parse(readFileSync(snapshot(root), "utf8"));
  function reversed(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(reversed);
    if (value === null || typeof value !== "object") return value;
    return Object.fromEntries(Object.entries(value).reverse().map(([k, v]) => [k, reversed(v)]));
  }
  writeFileSync(snapshot(root), JSON.stringify(reversed(original)));
  assert.equal(original.schemaVersion, 2);
  assert.equal(original.lifecycle[0].admittedHash, hashSkill(value));
  assert.deepEqual(restart(root).retrieval["bound"], [hashSkill(value)]);
  for (const edit of [
    (v: typeof original) => { delete v.lifecycle[0].admittedHash; },
    (v: typeof original) => { v.lifecycle[0].admittedHash = "not-a-digest"; },
    (v: typeof original) => { v.lifecycle[0].skillId = "orphan"; },
    (v: typeof original) => { v.lifecycle.push(v.lifecycle[0]); },
    (v: typeof original) => { v.packages[0].skill.name = "changed-without-rehash"; },
  ]) {
    const malformed = structuredClone(original);
    edit(malformed);
    writeFileSync(snapshot(root), JSON.stringify(malformed));
    const before = readFileSync(snapshot(root));
    assert.throws(() => build(root), /invalid persisted skill/);
    assert.deepEqual(readFileSync(snapshot(root)), before);
  }
});

test("equivalence cannot merge distinct typed programs or confer admission on catalog-only content", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-registry-equivalence-"));
  const store = new InMemoryRegistryStore();
  let checks = 0;
  const registry = new ManagedSkillRegistry({ store,
    persistence: new FileSkillRegistryPersistence(join(root, "registry.json")),
    programs: { absolute: (input) => Math.abs(input.n as number), double: (input) => 2 * (input.n as number) },
    // This fixture tests registry/program checking, not generated-case utility.
    gate: async () => { checks++; return { ok: true, verdict: "fixture-envelope-accepted" }; },
  });
  const typed = (id: string, entrypoint: string, expected: number): DistilledSkill => ({ ...skill(id), relevanceKey: "number",
    program: { entrypoint, inputs: { n: "number" }, cases: [{ name: "negative", input: { n: -2 }, expected }] },
  });
  const first = typed("first", "absolute", 2);
  store.put(publishSkill({ ...first, id: "unadmitted" }, "fixture"));
  const a = await registry.add(publishSkill(first, "fixture"));
  const b = await registry.add(publishSkill(typed("second", "double", -4), "fixture"));
  assert.ok(a.ok && b.ok);
  assert.equal(a.mergedInto, undefined);
  assert.equal(b.mergedInto, undefined);
  assert.equal(registry.admissionStatus("unadmitted"), "catalog-only");
  assert.deepEqual(registry.activePackages().map(p => p.skill.id), ["first", "second"]);
  const c = await registry.add(publishSkill({ ...first, id: "same-program", provenance: ["second-trace"] }, "fixture"));
  assert.ok(c.ok);
  assert.equal(c.mergedInto, "first");
  assert.equal(checks, 3);
  assert.equal(registry.admissionStatus("first"), "admitted");
  assert.equal(registry.admissionStatus("same-program"), "retired");
  const restored = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: async () => ({ ok: false, verdict: "unused" }),
    persistence: new FileSkillRegistryPersistence(join(root, "registry.json")) });
  assert.deepEqual(restored.activePackages().map(p => p.contentHash), registry.activePackages().map(p => p.contentHash));
});
