import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { SkillValidator, type SkillCase } from "../src/loop/skill_validator.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";
import { publishSkill, hashSkill, installSkill, InMemoryRegistryStore, ManagedSkillRegistry } from "../src/registry/skill_registry.js";

// Numeric inputs and behaviors from the copied Segment6A fixture. These are
// exposed deterministic audit cases, not independent held-out research tasks.
const cases: SkillCase[] = [-3, 0, 2].map((x, i) => ({ id: ["A", "B", "C"][i]!, input: JSON.stringify({ x }) }));
function skill(action = "absolute", id = "audit:absolute"): DistilledSkill {
  return { format: "keep.skill/v1", id, name: "Synthetic absolute value", description: "Return absolute value for finite real numeric input.",
    relevanceKey: "absolute-number", requiredAuthority: [], provenance: ["synthetic-audit-spec"], confidence: "corroborated",
    envelope: { preconditions: ["finite real numeric input x"], steps: [{ action, targetPattern: "{x}" }],
      postconditions: ["output is absolute value of x"], declaredEffects: [] } };
}
function execute(s: DistilledSkill, c: SkillCase): boolean {
  const x = JSON.parse(c.input).x as number;
  const action = s.envelope.steps[0]!.action;
  const actual = action === "identity" ? x : action === "absolute-zero-bug" && x === 0 ? 1 : Math.abs(x);
  return actual === Math.abs(x);
}

test("KEEP-06A-001 exact empty audit batch cannot earn generated execution validation", () => {
  let calls = 0;
  const validator = new SkillValidator({ generator: { generate: () => [] }, refiner: () => null,
    oracle: { runWithSkill: () => { calls++; return false; }, runBaseline: () => { throw Error("not a comparative evaluation"); } } });
  const result = validator.validate(skill("identity"));
  assert.equal(result.verdict, "rejected-no-evidence");
  assert.equal(calls, 0);
  assert.deepEqual(result.executedCases, []);
});

test("KEEP-06A-002 audit A/B/C refinement cannot reintroduce the still-applicable A failure", () => {
  const calls: { action: string; id: string; passed: boolean }[] = [];
  const validator = new SkillValidator({ generator: { generate: (_s, round) => [cases[round - 1]!] },
    refiner: (_s, _c, round) => skill(round === 1 ? "absolute-zero-bug" : "identity"),
    oracle: { runWithSkill: (s, c) => { const passed = execute(s, c); calls.push({ action: s.envelope.steps[0]!.action, id: c.id, passed }); return passed; },
      runBaseline: () => { throw Error("not a comparative evaluation"); } } });
  const result = validator.validate(skill("identity"));
  assert.equal(result.verdict, "abandoned-budget");
  assert.deepEqual(calls, [
    { action: "identity", id: "A", passed: false }, { action: "absolute-zero-bug", id: "A", passed: true },
    { action: "absolute-zero-bug", id: "B", passed: false }, { action: "identity", id: "A", passed: false },
  ]);
  const repaired = new SkillValidator({ generator: { generate: () => cases }, refiner: () => skill(),
    oracle: { runWithSkill: execute, runBaseline: () => false } }).validate(skill("identity"));
  assert.equal(repaired.verdict, "validated");
  assert.ok(cases.every(c => execute(repaired.skill, c)));
});

// Segment6B's configured oracle treats a descriptive exclusion as passing. This
// reproduces the actual audit consumer contract, not proof of safe scope narrowing.
const dimensions: Record<string, number> = { "empty-input": 0, "boundary-large": 1000000, "boundary-small": -1,
  "missing-precondition": -3, "reordered-steps": 2, "unicode-target": -2, "nested-target": -7, "concurrent-context": 4 };
for (const route of ["public", "managed", "bundle"] as const) {
  test(`KEEP-06A-E02 ${route} stores the exact refined candidate, not the submitted original`, async () => {
    const root = mkdtempSync(join(tmpdir(), "keep-refined-identity-"));
    const app = composeKeep({ dataDir: root, skillOracle: {
      runBaseline: () => true,
      runWithSkill: (s, c) => {
        const dimension = c.input.slice(c.input.lastIndexOf(":") + 1);
        assert.ok(dimension in dimensions);
        return dimension !== "concurrent-context" || s.envelope.preconditions.includes("does not apply when: concurrent-context");
      },
    } });
    const original = skill("fails-concurrent");
    const checked = app.skillValidator!.validate(original);
    assert.equal(checked.verdict, "validated");
    assert.notEqual(hashSkill(checked.skill), hashSkill(original));
    const pkg = publishSkill(original, "synthetic-origin");
    if (route === "public") {
      const result = await handleGatewayRequest(app, { method: "POST", path: "/skill/install", query: {},
        headers: { authorization: "Bearer synthetic-owner" }, body: JSON.stringify({ pkg }) }, { token: "synthetic-owner" });
      assert.equal(result.status, 200);
    } else if (route === "managed") {
      assert.equal((await app.managedSkillRegistry.add(pkg)).ok, true);
    } else {
      const source = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: async () => ({ ok: true, verdict: "fixture-source" }) });
      assert.equal((await source.add(pkg)).ok, true);
      assert.equal((await app.managedSkillRegistry.importBundle(source.exportBundle())).ok, true);
    }
    assert.deepEqual(app.registryStore!.get(original.id)?.skill, checked.skill);
    assert.equal(app.registryStore!.get(original.id)?.contentHash, hashSkill(checked.skill));
    if (route === "public") {
      assert.deepEqual(app.skillRetrieval.retrieve({ taskShape: original.relevanceKey }), []);
    } else {
      assert.equal(app.skillRetrieval.retrieve({ taskShape: original.relevanceKey })[0]?.skill.envelope.preconditions.includes("does not apply when: concurrent-context"), true);
      assert.deepEqual(app.skillRetrieval.retrieve({ taskShape: original.relevanceKey, facts: ["concurrent-context"] }), []);
      const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
        import {composeKeep} from ${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)};
        const app=composeKeep({dataDir:process.argv[1]}); console.log(JSON.stringify(app.registryStore.get(process.argv[2])));
      `, root, original.id], { encoding: "utf8", timeout: 15000 });
      assert.equal(child.status, 0, child.stderr);
      assert.deepEqual(JSON.parse(child.stdout).skill, checked.skill);
    }
  });
}

test("KEEP-06A-E01 no-oracle installation reports envelope-only assessment and no managed eligibility", async () => {
  let programCalls = 0;
  const programs = { "audit.absolute": (input: Readonly<Record<string, import("../src/loop/skill_distiller.js").SkillJson>>) => { programCalls++; return Math.abs(input.x as number); } };
  const badTyped: DistilledSkill = { ...skill("identity"), program: { entrypoint: "audit.absolute", inputs: { x: "number" },
    cases: [{ name: "wrong-expected", input: { x: -3 }, expected: 99 }] } };
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-envelope-only-")), skillPrograms: programs });
  const result = await handleGatewayRequest(app, { method: "POST", path: "/skill/install", query: {},
    headers: { authorization: "Bearer synthetic-owner" }, body: JSON.stringify({ pkg: publishSkill(badTyped, "fixture") }) }, { token: "synthetic-owner" });
  assert.equal(result.status, 200);
  assert.equal(JSON.parse(result.body).assessment?.verdict, "envelope-checked");
  assert.equal(app.managedSkillRegistry.admissionStatus("audit:absolute"), "catalog-only");
  assert.deepEqual(app.skillRetrieval.retrieve({ taskShape: "absolute-number" }), []);
  assert.equal(programCalls, 0, "the response must not imply the unchecked typed examples ran");
  const configured = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-envelope-contrast-")), skillPrograms: programs,
    skillOracle: { runWithSkill: () => { throw Error("typed example should refuse first"); }, runBaseline: () => false } });
  const refusal = await handleGatewayRequest(configured, { method: "POST", path: "/skill/install", query: {},
    headers: { authorization: "Bearer synthetic-owner" }, body: JSON.stringify({ pkg: publishSkill(badTyped, "fixture") }) }, { token: "synthetic-owner" });
  assert.equal(refusal.status, 422);
  assert.equal(programCalls, 1);
  assert.equal(configured.registryStore!.list().length, 0);
});

test("a refining gate retains a detached, behaviorally repaired candidate and exact assessment hashes", async () => {
  const original = skill("identity");
  const inputHash = hashSkill(original);
  const repaired = skill();
  const store = new InMemoryRegistryStore();
  let release!: () => void;
  const waiting = new Promise<void>(resolve => { release = resolve; });
  const pending = installSkill(publishSkill(original, "fixture"), { store, gate: async (received) => {
    assert.ok(Object.isFrozen(received.envelope.steps));
    await waiting;
    assert.equal(received.envelope.steps[0]!.action, "identity");
    assert.ok(cases.every(c => execute(repaired, c)));
    return { ok: true, verdict: "sampled-execution-passed", checkedSkill: repaired };
  } });
  (original as { description: string }).description = "caller changed its separate input while waiting";
  release();
  const result = await pending;
  assert.ok(result.ok);
  const acceptedHash = hashSkill(repaired);
  assert.deepEqual(result.assessment, { verdict: "sampled-execution-passed", inputContentHash: inputHash, contentHash: acceptedHash });
  (repaired as { description: string }).description = "caller changed the returned gate object later";
  assert.equal(hashSkill(store.get(original.id)!.skill), acceptedHash);
  assert.ok(cases.every(c => execute(store.get(original.id)!.skill, c)));
  assert.ok(Object.isFrozen(result.pkg.skill.envelope));
});

test("refinement cannot redirect an ID, enlarge receiver authority, or evade typed-program checks", async () => {
  const input = skill();
  const wrongProgram: DistilledSkill = { ...input, program: { entrypoint: "missing", inputs: {}, cases: [{ name: "case", input: {}, expected: true }] } };
  for (const checked of [{ ...input, id: "different-id" }, { ...input, requiredAuthority: ["workspace:write"] as const }, wrongProgram, null as unknown as DistilledSkill]) {
    const store = new InMemoryRegistryStore();
    const registry = new ManagedSkillRegistry({ store, allowedImportAuthorities: [],
      gate: async () => ({ ok: true, verdict: "trusted-fixture-refinement", checkedSkill: checked }) });
    const result = await registry.add(publishSkill(input, "fixture"));
    assert.equal(result.ok, false);
    assert.deepEqual(store.list(), []);
    assert.deepEqual(registry.activePackages(), []);
  }
});

test("bundle preflight keeps the whole prefix uninstalled when a later refined result exceeds receiver authority", async () => {
  const source = new ManagedSkillRegistry({ store: new InMemoryRegistryStore(), gate: async () => ({ ok: true, verdict: "fixture-source" }) });
  for (const id of ["first", "second"]) assert.equal((await source.add(publishSkill({ ...skill("identity", id), relevanceKey: id }, "fixture"))).ok, true);
  const store = new InMemoryRegistryStore();
  const target = new ManagedSkillRegistry({ store, allowedImportAuthorities: [], gate: async (input) => ({
    ok: true, verdict: "fixture-refined", checkedSkill: { ...input, requiredAuthority: input.id === "second" ? ["workspace:write"] : [],
      envelope: { ...input.envelope, steps: [{ action: "absolute", targetPattern: "{x}" }] } },
  }) });
  const result = await target.importBundle(source.exportBundle());
  assert.equal(result.ok, false);
  assert.deepEqual(store.list(), []);
});

test("KEEP-06A-E02 Segment7A same-ID 2/4 then 4/4 scores retain their actual candidate content", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-scored-identity-"));
  const population = [-2, -1, 0, 2].map((x, i) => ({ id: String(i), input: JSON.stringify({ x }) }));
  const reviewedScores: number[] = [];
  const app = composeKeep({ dataDir: root, skillOracle: { runWithSkill: execute, runBaseline: c => JSON.parse(c.input).x === 0 },
    skillCriticism: { builderFamily: "synthetic-builder", critic: { criticize(request) {
      reviewedScores.push(request.execution.candidateScore);
      return { reviewerFamily: "synthetic-other-family", verdict: "clear", findings: [] };
    } } },
  });
  const earlier: DistilledSkill = { ...skill("identity"), requiredAuthority: ["workspace:write"] };
  const later: DistilledSkill = { ...skill("absolute"), requiredAuthority: ["workspace:write"] };
  assert.equal(app.skillEvaluator!.evaluate(earlier, population).withSkill.passed, 2);
  const result = app.skillEvaluator!.evaluate(later, population);
  assert.equal(result.verdict, "retained");
  assert.equal(result.withSkill.passed, 4);
  assert.deepEqual(reviewedScores, [0.5, 1], "each measured score reaches the configured criticism gate");
  assert.equal(result.criticism?.status, "cleared");
  const expected = hashSkill(result.skill);
  assert.equal(app.registryStore!.get(later.id)?.contentHash, expected);
  assert.equal(hashSkill(app.skillRetrieval.retrieve({ taskShape: later.relevanceKey })[0]!.skill), expected);
  (later as { description: string }).description = "later caller mutation does not change retained bytes";
  assert.equal(hashSkill(app.registryStore!.get(later.id)!.skill), expected);
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import {composeKeep} from ${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)};
    const app=composeKeep({dataDir:process.argv[1]}); console.log(JSON.stringify(app.skillRetrieval.retrieve({taskShape:"absolute-number"})[0].skill));
  `, root], { encoding: "utf8", timeout: 15000 });
  assert.equal(child.status, 0, child.stderr);
  const restored = JSON.parse(child.stdout) as DistilledSkill;
  assert.equal(hashSkill(restored), expected);
  assert.ok(population.every(c => execute(restored, c)));
});
