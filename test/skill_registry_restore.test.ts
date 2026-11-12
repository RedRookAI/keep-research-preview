import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { FileSkillRegistryPersistence, InMemoryRegistryStore, ManagedSkillRegistry, SkillRegistryWriteError,
  hashSkill, publishSkill, type GateVerdict, type SkillRegistryPersistence, type SkillRegistrySnapshot } from "../src/registry/skill_registry.js";
import { SkillValidator } from "../src/loop/skill_validator.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";

const skill = (once: boolean): DistilledSkill => ({
  format: "keep.skill/v1", id: "rewrite", name: "Rewrite broken text", description: once ? "fast single rewrite" : "complete rewrite",
  requiredAuthority: ["workspace:write"], relevanceKey: "rewrite", confidence: "corroborated", provenance: [once ? "v2" : "v1"],
  envelope: { preconditions: ["text is available"], postconditions: [once ? "replace one occurrence" : "replace every occurrence"],
    declaredEffects: ["local edit"], steps: [{ action: "edit", targetPattern: "{file}" }] },
});
const v1 = skill(false), v2 = skill(true), h1 = hashSkill(v1), h2 = hashSkill(v2);
const badOutcome = { solveId: "regressed-v2", taskShape: "rewrite", testsPassed: false, mergeVerdict: "rejected" as const,
  rejectReason: "second occurrence remained broken", activeArtifacts: ["rewrite"], timestamp: 3 };

function fixture(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), "keep-skill-restore-")), path = join(root, "registry.json");
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const state = { difficult: false, unavailable: false };
  const activations: string[] = [];
  const validator = new SkillValidator({
    oracle: {
      runWithSkill: (candidate, c) => {
        const result = candidate.envelope.postconditions.includes("replace one occurrence") ? c.input.replace("broken", "fixed") : c.input.replaceAll("broken", "fixed");
        return result === c.input.replaceAll("broken", "fixed");
      }, runBaseline: c => !c.input.includes("broken"),
    },
    generator: { generate: () => [{ id: state.difficult ? "two-occurrences" : "one-occurrence", input: state.difficult ? "broken broken" : "broken" }] },
    refiner: () => null,
  });
  const gate = async (candidate: DistilledSkill): Promise<GateVerdict> => {
    if (state.unavailable) return { ok: false, verdict: "validator-unavailable" };
    const contentHash = hashSkill(candidate), r = validator.validate(candidate);
    return { ok: r.verdict === "validated", verdict: r.verdict, checkedSkill: r.skill,
      executedCases: r.executedCases.filter(c => c.round === 1).map(c => ({ contentHash, caseId: c.testCase.id, passed: c.passed })) };
  };
  const persistence = new FileSkillRegistryPersistence(path);
  const open = (override: { gate?: typeof gate; persistence?: SkillRegistryPersistence; allowedImportAuthorities?: readonly ("workspace:read" | "workspace:write" | "sandbox:execute")[] } = {}) => {
    const store = new InMemoryRegistryStore();
    return { store, registry: new ManagedSkillRegistry({ store, persistence, gate,
      onAdmit: candidate => activations.push(hashSkill(candidate)), ...override }) };
  };
  const initial = open();
  const seed = async () => {
    assert.equal((await initial.registry.add(publishSkill(v1, "fixture", 1))).ok, true);
    const firstToken = initial.registry.subjectToken("rewrite");
    initial.registry.recordOutcome({ solveId: "v1-use", taskShape: "rewrite", testsPassed: true, mergeVerdict: "merged", activeArtifacts: ["rewrite"], timestamp: 1.5 });
    assert.equal((await initial.registry.add(publishSkill(v2, "fixture", 2))).ok, true);
    initial.registry.recordOutcome(badOutcome);
    state.difficult = true;
    return firstToken;
  };
  const request = (registry: ManagedSkillRegistry) => ({ skillId: "rewrite", failedContentHash: h2, previousContentHash: h1, expectedSubjectToken: registry.subjectToken("rewrite") });
  return { ...initial, state, gate, persistence, open, seed, request, root, path, activations };
}

test("restore rechecks exact failed v2 and still-admissible v1, persists history and fences admission ABA", async t => {
  const f = fixture(t), oldV1Token = await f.seed();
  const request = f.request(f.registry), restored = await f.registry.restorePrevious(request);
  assert.ok(restored.ok);
  assert.equal(f.store.get("rewrite")?.contentHash, h1);
  assert.equal(f.registry.isEligible(v1), true);
  assert.notEqual(f.registry.subjectToken("rewrite"), oldV1Token, "returning to identical content cannot restore an invalidated in-flight admission token");
  const history = f.registry.versionHistory("rewrite");
  assert.deepEqual(history.map(v => v.contentHash).sort(), [h1, h2].sort());
  assert.equal(history.find(v => v.contentHash === h1)?.current, true);
  const failed = history.find(v => v.contentHash === h2)!;
  assert.equal(failed.lifecycle.retired?.reason, "harmful");
  assert.deepEqual(failed.feedback.map(v => v.solveId), [badOutcome.solveId]);
  assert.deepEqual(failed.counterexamples, [{ contentHash: h2, caseId: "two-occurrences", passed: false }]);
  assert.ok(!JSON.stringify(history).includes('"envelope"'), "history readback exposes metadata, not stored skill bodies");
  const token = f.registry.subjectToken("rewrite"), reopened = f.open();
  assert.equal(reopened.registry.subjectToken("rewrite"), token);
  assert.equal(reopened.registry.isEligible(v1), true);
  assert.deepEqual(reopened.registry.versionHistory("rewrite"), history);
  assert.equal(reopened.registry.acceptsUnversionedOutcome("rewrite", badOutcome), false);
  const before = readFileSync(f.path, "utf8"); reopened.registry.recordOutcome(badOutcome);
  reopened.registry.recordOutcome({ ...badOutcome, solveId: "unknown-delayed-id-only-result" });
  assert.equal(readFileSync(f.path, "utf8"), before, "ambiguous ID-only feedback cannot target restored v1");
  assert.equal((await reopened.registry.restorePrevious(request)).ok, false);
  assert.equal(f.activations.filter(h => h === h1).length, 2, "one initial admission and one restoration activate v1");
});

test("readable v2 keeps its subject token across restart and an unrelated schema3 save", async t => {
  const f = fixture(t), pkg = publishSkill(v1, "legacy", 1);
  const legacy = JSON.stringify({ schemaVersion: 2, packages: [pkg], lifecycle: [{ skillId: "rewrite", admittedHash: h1, uses: 0, reward: 0, lastUsedAt: 1 }] });
  writeFileSync(f.path, legacy);
  const a = f.open(), token = JSON.stringify([h1, h1, null, false]);
  assert.equal(a.registry.subjectToken("rewrite"), token);
  assert.equal(readFileSync(f.path, "utf8"), legacy, "loading does not mint or persist a new admission instance");
  assert.equal(f.open().registry.subjectToken("rewrite"), token);
  const other = { ...v1, id: "other", envelope: { ...v1.envelope, declaredEffects: ["another effect"] } };
  await a.registry.add(publishSkill(other, "fixture", 2));
  assert.equal(f.open().registry.subjectToken("rewrite"), token);
  assert.equal(JSON.parse(readFileSync(f.path, "utf8")).schemaVersion, 3);
});

test("missing, retired, forgotten or corrupt prior history cannot restore content", async t => {
  const f = fixture(t); await f.seed();
  const original = JSON.parse(readFileSync(f.path, "utf8"));
  const missing = structuredClone(original); missing.versions = missing.versions.filter((v: { pkg: { contentHash: string } }) => v.pkg.contentHash !== h1);
  writeFileSync(f.path, JSON.stringify(missing));
  let reopened = f.open();
  assert.equal((await reopened.registry.restorePrevious(f.request(reopened.registry))).ok, false);
  const retired = structuredClone(original); retired.versions.find((v: { pkg: { contentHash: string } }) => v.pkg.contentHash === h1).lifecycle.retired = { reason: "harmful", at: 0 };
  writeFileSync(f.path, JSON.stringify(retired)); reopened = f.open();
  assert.equal((await reopened.registry.restorePrevious(f.request(reopened.registry))).ok, false);
  assert.equal((await reopened.registry.add(publishSkill(v1, "retired historical body", 20))).ok, false);
  const corrupt = structuredClone(original); corrupt.versions[0].pkg.skill.name = "changed archive without matching hash";
  writeFileSync(f.path, JSON.stringify(corrupt)); const before = readFileSync(f.path, "utf8");
  assert.throws(() => f.open(), /invalid persisted skill version history/);
  assert.equal(readFileSync(f.path, "utf8"), before);
});

test("forget removes a prior body and feedback locally and blocks its exact re-admission across restart", async t => {
  const f = fixture(t); await f.seed();
  assert.equal(f.registry.forgetPreviousVersion({ skillId: "rewrite", contentHash: h2, expectedSubjectToken: f.registry.subjectToken("rewrite") }).ok, false, "current selected body is not a prior-version erasure target");
  const forgotten = f.registry.forgetPreviousVersion({ skillId: "rewrite", contentHash: h1, expectedSubjectToken: f.registry.subjectToken("rewrite") });
  assert.deepEqual(forgotten, { ok: true, forgotten: true });
  const disk = readFileSync(f.path, "utf8");
  assert.ok(!disk.includes('"complete rewrite"') && !disk.includes('"v1-use"'));
  const reopened = f.open();
  assert.deepEqual(reopened.registry.forgottenVersionHashes("rewrite"), [h1]);
  assert.equal((await reopened.registry.restorePrevious(f.request(reopened.registry))).ok, false);
  assert.equal((await reopened.registry.add(publishSkill(v1, "new envelope same content", 20))).ok, false);
  assert.throws(() => reopened.registry.trackValidated(v1, "trusted caller", 20), /forgotten/);
});

test("missing execution evidence, wrong-version evidence and a newly rejected prior remain held", async t => {
  const f = fixture(t); await f.seed();
  f.state.unavailable = true;
  const before = readFileSync(f.path, "utf8");
  assert.equal((await f.registry.restorePrevious(f.request(f.registry))).ok, false);
  assert.equal(readFileSync(f.path, "utf8"), before);
  f.state.unavailable = false;
  const wrongCases = f.open({ gate: async c => ({ ...(await f.gate(c)), executedCases: [{ contentHash: "f".repeat(64), caseId: "foreign", passed: false }] }) });
  assert.equal((await wrongCases.registry.restorePrevious(f.request(wrongCases.registry))).ok, false);
  const restricted = f.open({ allowedImportAuthorities: [] });
  const result = await restricted.registry.restorePrevious(f.request(restricted.registry));
  assert.ok(!result.ok); assert.equal(result.reason, "rejected-prior");
  assert.equal(restricted.store.get("rewrite")?.contentHash, h2);
  assert.deepEqual(restricted.registry.activePackages(), []);
});

test("permission revocation during gate checking prevents restoration before changing selection", async t => {
  const f = fixture(t); await f.seed(); let allowed = true;
  const controlled = f.open({ gate: async c => { const result = await f.gate(c); allowed = false; return result; } });
  await assert.rejects(controlled.registry.restorePrevious(f.request(controlled.registry), () => { if (!allowed) throw new Error("operator authority revoked"); }), /authority revoked/);
  assert.equal(controlled.store.get("rewrite")?.contentHash, h2);
  assert.deepEqual(controlled.registry.activePackages(), []);
});

test("forgetting the prior version while its gate awaits invalidates the pending restoration", async t => {
  const f = fixture(t); await f.seed();
  let release!: () => void, entered!: () => void;
  const ready = new Promise<void>(r => { entered = r; }), wait = new Promise<void>(r => { release = r; });
  const controlled = f.open({ gate: async c => { if (hashSkill(c) === h1) { entered(); await wait; } return f.gate(c); } });
  const pending = controlled.registry.restorePrevious(f.request(controlled.registry)); await ready;
  assert.deepEqual(controlled.registry.forgetPreviousVersion({ skillId: "rewrite", contentHash: h1, expectedSubjectToken: controlled.registry.subjectToken("rewrite") }), { ok: true, forgotten: true });
  release(); const result = await pending;
  assert.ok(!result.ok); assert.equal(result.reason, "changed");
  assert.equal(controlled.store.get("rewrite")?.contentHash, h2);
});

test("failed restoration persistence never activates an uncommitted prior and fences uncertain commits", async t => {
  for (const ambiguous of [false, true]) {
    const f = fixture(t); await f.seed();
    const persistence: SkillRegistryPersistence = {
      load: () => f.persistence.load(),
      save: (snapshot: SkillRegistrySnapshot) => {
        if (snapshot.packages.find(p => p.skill.id === "rewrite")?.contentHash === h1) {
          if (ambiguous) { f.persistence.save(snapshot); throw new Error("save result uncertain"); }
          throw new SkillRegistryWriteError(new Error("before rename"));
        }
        f.persistence.save(snapshot);
      },
    };
    const controlled = f.open({ persistence });
    const beforeActivations = f.activations.length;
    await assert.rejects(controlled.registry.restorePrevious(f.request(controlled.registry)), /uncertain|before rename/);
    assert.equal(f.activations.length, beforeActivations);
    assert.deepEqual(controlled.registry.activePackages(), []);
    assert.equal(controlled.registry.admissionStatus("rewrite"), ambiguous ? "reconstruction-required" : "retired");
    assert.ok(f.open().registry.versionHistory("rewrite").some(v => v.contentHash === h2 && v.counterexamples.length > 0));
  }
});
