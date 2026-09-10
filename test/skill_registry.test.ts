import { test } from "node:test";
import assert from "node:assert/strict";

import { publishSkill, installSkill, listRegistry, hashSkill, InMemoryRegistryStore, ManagedSkillRegistry, FileSkillRegistryPersistence, type GateVerdict } from "../src/registry/skill_registry.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";
import { SkillValidator } from "../src/loop/skill_validator.js";
import { composeKeep } from "../src/compose.js";

const FORBIDDEN = ["exfil", "external-send", "credential", "escalate-privilege", "delete-external"];

function skill(id: string, effects: readonly string[]): DistilledSkill {
  return {
    format: "keep.skill/v1", requiredAuthority: ["workspace:write"], id, name: `Skill ${id}`, description: "does a thing",
    relevanceKey: "shape:x",
    envelope: { preconditions: ["ready"], steps: [{ action: "edit", targetPattern: "{file}" }], postconditions: ["done"], declaredEffects: effects },
    provenance: ["traj-1"], confidence: "corroborated",
  };
}

function typedSkill(id = "typed:add"): DistilledSkill {
  return {
    ...skill(id, []), requiredAuthority: [],
    program: { entrypoint: "math.add", inputs: { a: "number", b: "number" }, cases: [
      { name: "sum", input: { a: 2, b: 3 }, expected: 5 },
    ] },
  };
}

/** Registry integration fixture: real validator with a small deterministic action interpreter, not a coding study. */
function instrumentedGate(): { gate: (s: DistilledSkill) => Promise<GateVerdict>; calls: DistilledSkill[]; executions: string[] } {
  const calls: DistilledSkill[] = [];
  const executions: string[] = [];
  const validator = new SkillValidator({
    oracle: {
      runWithSkill: (candidate, c) => {
        executions.push(`${candidate.id}:${c.id}`);
        let text = c.input;
        for (const step of candidate.envelope.steps) {
          if (step.action !== "edit" || step.targetPattern !== "{file}") return false;
          text = text.replace("broken", "fixed");
        }
        return text === "fixed";
      },
      runBaseline: (c) => c.input === "fixed",
    },
    generator: { generate: () => [{ id: "replace-broken", input: "broken" }] },
    refiner: () => null,
    safety: { check: (s) => { const bad = s.envelope.declaredEffects.find((e) => FORBIDDEN.includes(e)); return bad ? `forbidden sink '${bad}'` : null; } },
  });
  return {
    calls, executions,
    gate: async (s) => { calls.push(s); const r = validator.validate(s); return { ok: r.verdict === "validated", verdict: r.verdict, reason: r.reason }; },
  };
}

test("REGISTRY: a published skill round-trips (publish → install → retrievable)", async () => {
  const store = new InMemoryRegistryStore();
  const { gate } = instrumentedGate();
  const pkg = publishSkill(skill("s1", ["local-edit"]), "alice@example");
  const r = await installSkill(pkg, { store, gate });
  assert.ok(r.ok, "a safe skill installs");
  assert.equal(listRegistry(store).length, 1);
  assert.equal(store.get("s1")?.origin, "alice@example", "origin is attributed");
});

test("REGISTRY: a poisoned skill (forbidden sink) is REJECTED by the safety gate", async () => {
  const store = new InMemoryRegistryStore();
  const { gate } = instrumentedGate();
  const pkg = publishSkill(skill("evil", ["external-send"]), "attacker@example"); // forbidden sink
  const r = await installSkill(pkg, { store, gate });
  assert.equal(r.ok, false);
  assert.equal((r as { reason: string }).reason, "rejected-unsafe", "the poisoned skill is not admitted");
  assert.equal(listRegistry(store).length, 0, "nothing was installed");
});

test("REGISTRY: a tampered package (content-hash mismatch) is REJECTED before the gate", async () => {
  const store = new InMemoryRegistryStore();
  const { gate, calls } = instrumentedGate();
  const pkg = publishSkill(skill("s2", ["local-edit"]), "alice@example");
  // Tamper: swap in a different skill body while keeping the original hash.
  const tampered = { ...pkg, skill: skill("s2", ["external-send"]) };
  const r = await installSkill(tampered, { store, gate });
  assert.equal(r.ok, false);
  assert.equal((r as { reason: string }).reason, "tampered", "the hash mismatch is caught");
  assert.equal(calls.length, 0, "a tampered package never even reaches the gate");
});

test("REGISTRY: install invokes the validator and executes the candidate in the fixture", async () => {
  const store = new InMemoryRegistryStore();
  const { gate, calls, executions } = instrumentedGate();
  const pkg = publishSkill(skill("s3", ["local-edit"]), "alice@example");
  await installSkill(pkg, { store, gate });
  assert.equal(calls.length, 1, "the gate was actually consulted");
  assert.equal(calls[0]!.id, "s3", "with the pulled skill");
  assert.deepEqual(executions, ["s3:replace-broken"]);
});

test("REGISTRY: the content hash is deterministic and detects any edit", () => {
  const a = hashSkill(skill("h", ["local-edit"]));
  const b = hashSkill(skill("h", ["local-edit"]));
  const c = hashSkill(skill("h", ["local-edit", "extra"]));
  assert.equal(a, b, "stable across calls");
  assert.notEqual(a, c, "any change flips the hash");
});

test("REGISTRY: an executable fixture failure prevents admission", async () => {
  const store = new InMemoryRegistryStore();
  const { gate, executions } = instrumentedGate();
  const broken = skill("broken", ["local-edit"]);
  const result = await installSkill(publishSkill({ ...broken, envelope: { ...broken.envelope, steps: [] } }, "fixture"), { store, gate });
  assert.equal(result.ok, false);
  assert.equal(store.list().length, 0);
  assert.deepEqual(executions, ["broken:replace-broken"]);
});

test("REGISTRY: missing execution evidence is not admitted", async () => {
  const store = new InMemoryRegistryStore();
  const validator = new SkillValidator({
    oracle: { runWithSkill: () => { throw new Error("no cases"); }, runBaseline: () => false },
    generator: { generate: () => [] }, refiner: () => null,
  });
  let observed = "";
  const result = await installSkill(publishSkill(skill("empty", ["local-edit"]), "fixture"), { store, gate: async (candidate) => {
    const r = validator.validate(candidate);
    observed = r.verdict;
    return { ok: r.verdict === "validated", verdict: r.verdict, reason: r.reason };
  } });
  assert.equal(observed, "rejected-no-evidence");
  assert.equal(result.ok, false);
  assert.equal(store.list().length, 0);
});

test("S3: execution outcomes reward reuse and immediately retire a harmful skill", async () => {
  const store = new InMemoryRegistryStore();
  const managed = new ManagedSkillRegistry({ store, gate: instrumentedGate().gate });
  await managed.add(publishSkill(skill("rewarded", ["local-edit"]), "local", 10));
  managed.recordOutcome({ solveId: "ok", taskShape: "shape:x", testsPassed: true, mergeVerdict: "merged", activeArtifacts: ["rewarded"], timestamp: 20 });
  assert.deepEqual(managed.lifecycle("rewarded"), { skillId: "rewarded", uses: 1, reward: 2, lastUsedAt: 20 });
  managed.recordOutcome({ solveId: "bad", taskShape: "shape:x", testsPassed: false, mergeVerdict: "pending", activeArtifacts: ["rewarded"], timestamp: 30 });
  assert.equal(managed.lifecycle("rewarded")?.retired?.reason, "harmful");
  assert.equal(managed.activePackages().length, 0, "retirement is enforced without deleting provenance");
  assert.ok(store.get("rewarded"), "retired skill remains as a tombstone source");
  assert.equal(managed.trackValidated(skill("rewarded", ["local-edit"]), "local", 40).active, false, "identical revalidation cannot silently resurrect a harmful tombstone");
});

test("S3: unused skills retire at the configured age, but used skills remain", async () => {
  const store = new InMemoryRegistryStore();
  const managed = new ManagedSkillRegistry({ store, gate: instrumentedGate().gate, unusedAfterMs: 100 });
  await managed.add(publishSkill(skill("unused", ["local-edit"]), "local", 0));
  await managed.add(publishSkill(skill("used", ["local-test"]), "local", 0));
  managed.recordOutcome({ solveId: "ok", taskShape: "shape:x", testsPassed: true, mergeVerdict: "pending", activeArtifacts: ["used"], timestamp: 50 });
  assert.deepEqual(managed.retireUnused(100), ["unused"]);
  assert.equal(managed.lifecycle("used")?.retired, undefined);
});

test("S3: behaviorally redundant skills merge provenance and retire the duplicate", async () => {
  const store = new InMemoryRegistryStore();
  const managed = new ManagedSkillRegistry({ store, gate: instrumentedGate().gate });
  const first = skill("first", ["local-edit"]);
  const duplicate = { ...skill("duplicate", ["local-edit"]), name: "renamed", provenance: ["traj-2"] } satisfies DistilledSkill;
  await managed.add(publishSkill(first, "local", 1));
  const result = await managed.add(publishSkill(duplicate, "imported", 2));
  assert.equal(result.mergedInto, "first");
  assert.deepEqual(store.get("first")?.skill.provenance, ["traj-1", "traj-2"]);
  assert.equal(store.get("first")?.skill.confidence, "corroborated");
  assert.deepEqual(managed.lifecycle("duplicate")?.retired, { reason: "redundant", at: 2, replacementId: "first" });
});

test("SKILL-07: packages, merged provenance, reuse reward, and retirement survive restart", async () => {
  const path = join(mkdtempSync(join(tmpdir(), "keep-skill-lifecycle-")), "registry.json");
  const persistence = new FileSkillRegistryPersistence(path);
  const first = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: instrumentedGate().gate, persistence, unusedAfterMs: 100 });
  await first.add(publishSkill(skill("kept", ["local-edit"]), "local", 1));
  await first.add(publishSkill({ ...skill("duplicate", ["local-edit"]), provenance: ["traj-2"] }, "local", 2));
  first.recordOutcome({ solveId: "ok", taskShape: "shape:x", testsPassed: true, mergeVerdict: "merged", activeArtifacts: ["kept"], timestamp: 20 });
  await first.add(publishSkill(skill("harmful", ["local-test"]), "local", 3));
  first.recordOutcome({ solveId: "bad", taskShape: "shape:x", testsPassed: false, mergeVerdict: "pending", activeArtifacts: ["harmful"], timestamp: 30 });
  await first.add(publishSkill(skill("unused", ["local-unused"]), "local", 0));
  first.retireUnused(100);

  const restarted = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: instrumentedGate().gate, persistence, unusedAfterMs: 100 });
  assert.deepEqual(restarted.lifecycle("kept"), { skillId: "kept", uses: 1, reward: 2, lastUsedAt: 20 });
  assert.deepEqual(restarted.activePackages().find((pkg) => pkg.skill.id === "kept")?.skill.provenance, ["traj-1", "traj-2"]);
  assert.equal(restarted.lifecycle("duplicate")?.retired?.reason, "redundant");
  assert.equal(restarted.lifecycle("harmful")?.retired?.reason, "harmful");
  assert.equal(restarted.lifecycle("unused")?.retired?.reason, "unused");
});

test("SKILL-07: legacy catalog-only state remains unadmitted while malformed packages fail closed", () => {
  const good = publishSkill(skill("persisted", ["local-edit"]), "local", 1);
  const recovered = new ManagedSkillRegistry({
    store: new InMemoryRegistryStore(), gate: instrumentedGate().gate,
    persistence: { load: () => ({ schemaVersion: 1, packages: [good], lifecycle: [] }), save: () => undefined },
  });
  assert.equal(recovered.admissionStatus("persisted"), "catalog-only");
  assert.deepEqual(recovered.activePackages(), []);
  assert.throws(() => new ManagedSkillRegistry({
    store: new InMemoryRegistryStore(), gate: instrumentedGate().gate,
    persistence: { load: () => ({ schemaVersion: 1, packages: [{ ...good, origin: 7 as never }], lifecycle: [] }), save: () => undefined },
  }), /invalid persisted skill package/);
});

test("S3: registry export/import round-trips through schema, digest, hash, and safety gates", async () => {
  const source = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: instrumentedGate().gate });
  await source.add(publishSkill(skill("portable", ["local-edit"]), "alice", 1));
  const serialized = source.exportBundle();

  const targetStore = new InMemoryRegistryStore();
  const { gate, calls } = instrumentedGate();
  const target = new ManagedSkillRegistry({ store: targetStore, gate });
  assert.deepEqual(await target.importBundle(serialized), { ok: true, installed: 1, merged: 0 });
  assert.equal(targetStore.get("portable")?.origin, "alice");
  assert.equal(calls.length, 1, "imports cannot bypass the normal skill safety gate");

  const tampered = JSON.parse(serialized) as { packages: Array<{ origin: string }> };
  tampered.packages[0]!.origin = "mallory";
  const rejected = await target.importBundle(JSON.stringify(tampered));
  assert.equal(rejected.ok, false);
  assert.equal(rejected.ok ? "" : rejected.reason, "tampered-bundle");
});

test("S3: hostile and oversized imports fail closed before installing anything", async () => {
  const store = new InMemoryRegistryStore();
  const managed = new ManagedSkillRegistry({ store, gate: instrumentedGate().gate, maxImportPackages: 0 });
  assert.equal((await managed.importBundle('{"format":"keep.skill-registry/v1","packages":[],"bundleHash":7}')).ok, false);

  const source = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: instrumentedGate().gate });
  await source.add(publishSkill(skill("one", ["local-edit"]), "alice", 1));
  const tooLarge = await managed.importBundle(source.exportBundle());
  assert.equal(tooLarge.ok, false);
  assert.equal(tooLarge.ok ? "" : tooLarge.reason, "import-too-large");
  assert.equal(store.list().length, 0);
});

test("S3: a poisoned package makes bundle import atomic (no clean prefix is installed)", async () => {
  const sourceStore = new InMemoryRegistryStore();
  const source = new ManagedSkillRegistry({ store: sourceStore, gate: async () => ({ ok: true, verdict: "test-source" }) });
  await source.add(publishSkill(skill("clean", ["local-edit"]), "alice", 1));
  await source.add(publishSkill(skill("poison", ["external-send"]), "mallory", 2));

  const targetStore = new InMemoryRegistryStore();
  const target = new ManagedSkillRegistry({ store: targetStore, gate: instrumentedGate().gate });
  const result = await target.importBundle(source.exportBundle());
  assert.equal(result.ok, false);
  assert.equal(result.ok ? "" : result.reason, "rejected-package");
  assert.equal(targetStore.list().length, 0, "preflight rejects the whole bundle before mutation");
});

test("SKILL-08: exchange rejects excess authority and unavailable typed programs before mutation", async () => {
  const authoritySource = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: instrumentedGate().gate });
  await authoritySource.add(publishSkill(skill("writer", ["local-edit"]), "alice", 1));
  const authorityTarget = new ManagedSkillRegistry({
    store: new InMemoryRegistryStore(), gate: instrumentedGate().gate, allowedImportAuthorities: ["workspace:read"],
  });
  const authorityResult = await authorityTarget.importBundle(authoritySource.exportBundle());
  assert.equal(authorityResult.ok, false);
  assert.match(authorityResult.ok ? "" : authorityResult.detail, /authority is not granted/);
  assert.equal(authorityTarget.activePackages().length, 0);

  const program = { "math.add": (input: Readonly<Record<string, import("../src/loop/skill_distiller.js").SkillJson>>) => Number(input.a) + Number(input.b) };
  const typedSource = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: async () => ({ ok: true, verdict: "source" }), programs: program });
  assert.equal((await typedSource.add(publishSkill(typedSkill(), "alice", 1))).ok, true);
  const typedTarget = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: async () => ({ ok: true, verdict: "permissive" }), programs: {} });
  const typedResult = await typedTarget.importBundle(typedSource.exportBundle());
  assert.equal(typedResult.ok, false);
  assert.match(typedResult.ok ? "" : typedResult.detail, /unavailable program entrypoint/);
  assert.equal(typedTarget.activePackages().length, 0, "a permissive injected gate cannot bypass the registry policy");
});

test("SKILL-08: incompatible versions and corrupted local exports fail closed", async () => {
  const sourceStore = new InMemoryRegistryStore();
  const source = new ManagedSkillRegistry({ store: sourceStore, gate: instrumentedGate().gate });
  await source.add(publishSkill(skill("portable-v1", ["local-edit"]), "alice", 1));
  const incompatible = JSON.parse(source.exportBundle()) as { format: string };
  incompatible.format = "keep.skill-registry/v2";
  const target = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: instrumentedGate().gate });
  const result = await target.importBundle(JSON.stringify(incompatible));
  assert.equal(result.ok, false);
  assert.equal(result.ok ? "" : result.reason, "invalid-bundle");

  const installed = sourceStore.get("portable-v1")!;
  sourceStore.put({ ...installed, origin: 7 as never });
  assert.throws(() => source.exportBundle(), /refusing to export invalid skill package/);
});

test("SKILL-08: composeKeep denies imported authority by default and honors an explicit receiver grant", async () => {
  const source = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: instrumentedGate().gate });
  await source.add(publishSkill(skill("shared-writer", ["local-edit"]), "alice", 1));
  const bundle = source.exportBundle();
  const oracle = { runWithSkill: () => true, runBaseline: () => false };

  const denied = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-exchange-deny-")), skillOracle: oracle });
  const deniedResult = await denied.managedSkillRegistry.importBundle(bundle);
  assert.equal(deniedResult.ok, false);
  assert.match(deniedResult.ok ? "" : deniedResult.detail, /authority is not granted/);

  const allowed = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-exchange-allow-")), skillOracle: oracle,
    skillImportAuthorities: ["workspace:write"],
  });
  assert.deepEqual(await allowed.managedSkillRegistry.importBundle(bundle), { ok: true, installed: 1, merged: 0 });
  assert.equal(allowed.skillRetrieval.retrieve({ taskShape: "shape:x" })[0]?.skill.id, "shared-writer");
});

test("SKILL-08: composed typed import verifies each deterministic example once", async () => {
  const execute = (input: Readonly<Record<string, import("../src/loop/skill_distiller.js").SkillJson>>) => Number(input.a) + Number(input.b);
  const source = new ManagedSkillRegistry({
    store: new InMemoryRegistryStore(), gate: async () => ({ ok: true, verdict: "source" }), programs: { "math.add": execute },
  });
  await source.add(publishSkill(typedSkill("typed:once"), "alice", 1));
  let calls = 0;
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-exchange-program-once-")),
    skillOracle: { runWithSkill: () => true, runBaseline: () => false },
    skillPrograms: { "math.add": (input) => { calls++; return execute(input); } },
  });
  assert.deepEqual(await app.managedSkillRegistry.importBundle(source.exportBundle()), { ok: true, installed: 1, merged: 0 });
  assert.equal(calls, 1, "exchange policy and validator do not repeat the same program verification");
});

test("SKILL-08: a later poisoned package cannot leak a preflighted prefix into live composition state", async () => {
  const source = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: async () => ({ ok: true, verdict: "source" }) });
  await source.add(publishSkill(skill("clean-prefix", ["local-edit"]), "alice", 1));
  await source.add(publishSkill(skill("poison-tail", ["external-send"]), "mallory", 2));
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-exchange-atomic-live-")),
    skillOracle: { runWithSkill: () => true, runBaseline: () => false },
    skillImportAuthorities: ["workspace:write"],
  });
  const result = await app.managedSkillRegistry.importBundle(source.exportBundle());
  assert.equal(result.ok, false);
  assert.equal(app.managedSkillRegistry.activePackages().length, 0);
  assert.equal(app.skillRetrieval.retrieve({ taskShape: "shape:x" }).length, 0);
  assert.equal(app.skillCanary.state("clean-prefix"), undefined, "validation preflight has no activation side effect");
});
