import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OutcomeAdaptation, OutcomeAdaptiveProvider, presentAdaptiveText, type AdaptiveBehavior, type CurrentModelCapability, type OutcomeAdaptationPersistence } from "../src/learning/outcome_adaptation.js";
import { composeKeep } from "../src/compose.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { MemoryStore } from "../src/memory/store.js";
import { ModelGateway, type ModelProvider } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";
import { validatorRunner } from "../src/solve/default_solver.js";

const behavior = (version: string, model = "local-small"): AdaptiveBehavior => ({
  prompt: { version, text: `prompt ${version}` },
  routing: { model, effort: model === "local-small" ? "none" : "graded" },
  voice: { promptFormat: "markdown", verbosity: version === "v1" ? "normal" : "terse" },
});
const policy = { minSamplesPerArm: 4, minQualityGain: 0.1, maxRegressionRate: 0.25, rollbackQualityDrop: 0.15 };
const offline = (initial = behavior("v1")) => new OutcomeAdaptation(initial, policy, { allowUnboundOfflineEvidence: true });
const observeExperiment = (adaptation: OutcomeAdaptation, baselineQuality: number, candidateQuality: number) => {
  let decision: import("../src/learning/outcome_adaptation.js").AdaptationDecision = { kind: "observing", reason: "not started" };
  for (let i = 0; i < policy.minSamplesPerArm * 2; i++) {
    const assignment = adaptation.assign(`subject-${i}`);
    adaptation.expose(assignment.assignmentId);
    decision = adaptation.observe({ assignmentId: assignment.assignmentId, outcomeId: `outcome-${i}`, observedAt: Math.max(Date.now(), assignment.assignedAt), evidence: "observed-product", quality: assignment.arm === "baseline" ? baselineQuality : candidateQuality, regressed: false });
  }
  return decision;
};

test("M6: prompt, routing, and user voice promote only after comparative clean outcomes", () => {
  const adaptation = offline();
  adaptation.propose(behavior("v2", "frontier"));
  for (let i = 0; i < policy.minSamplesPerArm; i++) adaptation.record("baseline", { quality: 0.6, regressed: false });
  let decision;
  for (let i = 0; i < policy.minSamplesPerArm; i++) decision = adaptation.record("candidate", { quality: 0.9, regressed: false });
  assert.equal(decision?.kind, "promoted");
  assert.deepEqual(adaptation.current(), behavior("v2", "frontier"));
});

test("M6: assertion and training-only evidence cannot promote a candidate", () => {
  const adaptation = offline();
  adaptation.propose(behavior("claimed-better"));
  assert.equal(adaptation.current().prompt.version, "v1");
  assert.equal(adaptation.record("candidate", { quality: 1, regressed: false }).kind, "observing");
  assert.equal(adaptation.current().prompt.version, "v1");
});

test("M6: a promoted adaptation automatically rolls back on measured regression", () => {
  const adaptation = offline();
  adaptation.propose(behavior("v2", "frontier"));
  for (let i = 0; i < policy.minSamplesPerArm; i++) adaptation.record("baseline", { quality: 0.5, regressed: false });
  for (let i = 0; i < policy.minSamplesPerArm; i++) adaptation.record("candidate", { quality: 0.9, regressed: false });
  let rolledBack;
  for (let i = 0; i < policy.minSamplesPerArm; i++) rolledBack = adaptation.recordLive({ quality: 0.4, regressed: true });
  assert.equal(rolledBack?.kind, "rolled-back");
  assert.equal(adaptation.current().prompt.version, "v1");
});

test("ADAPT-01: candidate policy, effect, and authority fields are rejected rather than silently stripped", () => {
  const candidate = { ...behavior("v2"), policy: { allow: true }, effect: "publish", autonomy: "delegator" } as unknown as AdaptiveBehavior;
  const adaptation = new OutcomeAdaptation(behavior("v1"), Object.freeze({ ...policy }), { allowUnboundOfflineEvidence: true });
  assert.throws(() => adaptation.propose(candidate), /rejected or missing fields/);
  assert.deepEqual(adaptation.current(), behavior("v1"));
  const nested = { ...behavior("v2"), routing: { ...behavior("v2").routing, effect: "publish" } } as unknown as AdaptiveBehavior;
  assert.throws(() => adaptation.propose(nested), /rejected or missing fields/);
  assert.throws(() => new OutcomeAdaptation(behavior("v1"), { ...policy, minSamplesPerArm: 1 }), /at least 4/);
  assert.throws(() => adaptation.propose({ ...behavior("v1", "frontier"), prompt: { ...behavior("v1").prompt, version: "routing-only" } }), /routing-only advisory/);
});

test("ADAPT-01: composed adaptation promotes only after both measured cohorts improve", () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-adapt-")), outcomeAdaptation: { initial: behavior("v1"), policy } });
  const project = app.projectManager!.create({ name: "adaptation owner" });
  const adaptation = app.outcomeAdaptation?.(project.id);
  assert.ok(adaptation, "configured project-owned adaptation is reachable from the running composition");
  adaptation.propose(behavior("v2", "frontier"));
  assert.throws(() => adaptation.record("candidate", { quality: 0.9, regressed: false }), /assign before observing/, "caller-labelled product evidence is refused");
  const decision = observeExperiment(adaptation, 0.5, 0.9);
  assert.equal(decision.kind, "promoted");
  assert.deepEqual(adaptation.current(), behavior("v2", "frontier"));
  assert.equal(Object.isFrozen(adaptation.current()), true);
  assert.equal(Object.isFrozen(adaptation.current().routing), true);
});

test("ADAPT-01: a non-improving composed candidate is rejected", () => {
  const adaptation = offline();
  adaptation.propose(behavior("v2"));
  for (let i = 0; i < policy.minSamplesPerArm; i++) adaptation.record("baseline", { quality: 0.5, regressed: false });
  let rejected;
  for (let i = 0; i < policy.minSamplesPerArm; i++) rejected = adaptation.record("candidate", { quality: 0.5, regressed: false });
  assert.equal(rejected?.kind, "rejected");
  assert.deepEqual(adaptation.current(), behavior("v1"));
});

test("ADAPT-02: project-owned promoted voice survives independently of the global front door", async () => {
  const local = new LocalProvider();
  const scripted: ModelProvider = {
    name: "scripted-adaptation", isLocal: true,
    generate: async () => ({ text: '{"reply":"The verified total is 42."}', model: "scripted-adaptation", tokensIn: 1, tokensOut: 1 }),
    embed: (texts) => local.embed(texts),
  };
  const memorySpine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-adapt-memory-"))), new InProcessLock(), new SchemaRegistry());
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-adapt-app-")), developmentProvider: scripted,
    frontDoorMemory: new MemoryStore(memorySpine, new ModelGateway(local)),
    outcomeAdaptation: { initial: behavior("v1"), policy },
  });
  const before = await app.frontDoor!.handle("add a login button to the homepage");
  assert.equal(before.driverTurn?.say, "The verified total is 42.");
  const project = app.projectManager!.create({ name: "voice owner" });
  const adaptation = app.outcomeAdaptation!(project.id);
  adaptation.propose({ ...behavior("v2"), voice: { promptFormat: "json", verbosity: "terse" } });
  assert.equal(observeExperiment(adaptation, 0.5, 0.9).kind, "promoted");
  const after = await app.frontDoor!.handle("add a login button to the homepage");
  assert.equal(after.driverTurn!.say, before.driverTurn?.say, "a project adaptation cannot leak into the unscoped front door");
  assert.equal(JSON.parse(presentAdaptiveText(before.driverTurn!.say, adaptation.current().voice).rendered).response, before.driverTurn?.say);
});

test("ADAPT-03: promoted prompt/routing reaches later model calls, re-resolves capabilities, and rolls back", async () => {
  const requests: import("../src/gateway/gateway.js").GenerateRequest[] = [];
  const inner: ModelProvider = {
    name: "observed-solve", isLocal: true,
    generate: async (request) => { requests.push(request); return { text: "ok", model: "observed-solve", tokensIn: 1, tokensOut: 1 }; },
    embed: (texts) => localEmbeddings(texts),
  };
  let current: CurrentModelCapability = { effortKnob: "binary", timeoutClass: "reasoning", asOf: "2026-08-26", freshness: "fresh" };
  let now = 1;
  const adaptation = offline();
  const provider = new OutcomeAdaptiveProvider(inner, adaptation, { current: (_model, observedNow) => { assert.equal(observedNow, now); return current; } }, () => now);
  await provider.generate({ prompt: "solve ticket" });
  assert.match(requests.at(-1)!.prompt, /^prompt v1/);

  adaptation.propose(behavior("v2", "frontier"));
  for (let i = 0; i < policy.minSamplesPerArm; i++) adaptation.record("baseline", { quality: 0.5, regressed: false });
  for (let i = 0; i < policy.minSamplesPerArm; i++) adaptation.record("candidate", { quality: 0.9, regressed: false });
  await provider.generate({ prompt: "solve ticket" });
  assert.match(requests.at(-1)!.prompt, /^prompt v2/);
  assert.equal(requests.at(-1)!.hints?.["preferredModel"], "frontier");
  assert.equal(requests.at(-1)!.hints?.["effortKnob"], "binary", "live capability overrides candidate assumptions");

  now = 2;
  current = { effortKnob: "graded", timeoutClass: "standard", asOf: "2026-08-27", freshness: "stale" };
  await provider.generate({ prompt: "solve ticket" });
  assert.equal(requests.at(-1)!.hints?.["effortKnob"], "graded");
  assert.equal(requests.at(-1)!.hints?.["referenceAsOf"], "2026-08-27", "reference data is read at use time, not frozen at promotion");

  let rollback;
  for (let i = 0; i < policy.minSamplesPerArm; i++) rollback = adaptation.recordLive({ quality: 0.4, regressed: true });
  assert.equal(rollback?.kind, "rolled-back");
  await provider.generate({ prompt: "solve ticket" });
  assert.match(requests.at(-1)!.prompt, /^prompt v1/, "the next call uses the restored safe strategy");
});

function localEmbeddings(texts: readonly string[]) { return new LocalProvider().embed(texts); }

test("ADAPT-04: live evidence requires durable assignment identity and is idempotent", () => {
  let now = 100;
  let serial = 0;
  const adaptation = new OutcomeAdaptation(behavior("v1"), policy, { clock: () => now, id: () => `id-${++serial}`, random: () => 0.25 });
  const experimentId = adaptation.propose(behavior("v2"));
  assert.throws(() => adaptation.propose(behavior("v3")), /already active/);
  const assigned = adaptation.assign("exact subject");
  assert.equal(assigned.experimentId, experimentId);
  assert.throws(() => adaptation.assign("exact subject"), /already assigned/);
  assert.throws(() => adaptation.observe({ assignmentId: "unknown", outcomeId: "o-0", observedAt: now, evidence: "observed-product", quality: 1, regressed: false }), /no assignment/);
  adaptation.expose(assigned.assignmentId);
  assert.throws(() => adaptation.observe({ assignmentId: assigned.assignmentId, outcomeId: "o-1", observedAt: assigned.assignedAt - 1, evidence: "observed-product", quality: 1, regressed: false }), /predates/);
  now++;
  assert.equal(adaptation.observe({ assignmentId: assigned.assignmentId, outcomeId: "o-1", observedAt: now, evidence: "observed-product", quality: 0.5, regressed: false }).kind, "observing");
  assert.throws(() => adaptation.observe({ assignmentId: assigned.assignmentId, outcomeId: "o-2", observedAt: now, evidence: "observed-product", quality: 0.5, regressed: false }), /duplicate/);
});

test("ADAPT-05: experiment state restarts exactly and stale handles cannot overwrite it", () => {
  let durable: { snapshot: unknown; revision: number } | undefined;
  const persistence: OutcomeAdaptationPersistence = {
    load: () => durable === undefined ? undefined : structuredClone(durable),
    save: (snapshot, expectedRevision) => {
      const current = durable?.revision ?? 0;
      if (current !== expectedRevision) throw new Error(`CAS conflict ${expectedRevision}/${current}`);
      durable = { snapshot: structuredClone(snapshot), revision: current + 1 };
      return current + 1;
    },
  };
  let serial = 0;
  const options = { scope: { projectId: "prj_00000000000000000000000000000001", tenant: "tenant-a" }, persistence, clock: () => 10, id: () => `id-${++serial}`, random: () => 0.25 } as const;
  const first = new OutcomeAdaptation(behavior("v1"), policy, options);
  first.propose(behavior("v2"));
  const initial = first.assign("subject-0");
  first.expose(initial.assignmentId);
  first.observe({ assignmentId: initial.assignmentId, outcomeId: "outcome-0", observedAt: 11, evidence: "observed-product", quality: initial.arm === "baseline" ? 0.5 : 0.9, regressed: false });
  const stale = new OutcomeAdaptation(behavior("v1"), policy, options);
  const restarted = new OutcomeAdaptation(behavior("v1"), policy, options);
  for (let index = 1; index < policy.minSamplesPerArm * 2; index++) {
    const assignment = restarted.assign(`subject-${index}`);
    restarted.expose(assignment.assignmentId);
    restarted.observe({ assignmentId: assignment.assignmentId, outcomeId: `outcome-${index}`, observedAt: 11, evidence: "observed-product", quality: assignment.arm === "baseline" ? 0.5 : 0.9, regressed: false });
  }
  assert.equal(restarted.current().prompt.version, "v2", "delayed outcomes complete the same restored experiment");
  assert.throws(() => stale.current(), /document conflict/, "a held stale handle cannot publish or read a superseded revision");
  const final = new OutcomeAdaptation(behavior("v1"), policy, options);
  assert.equal(final.current().prompt.version, "v2", "the promoted behavior survives restart");
  assert.throws(() => new OutcomeAdaptation(behavior("v1"), policy, { ...options, scope: { projectId: options.scope.projectId, tenant: "tenant-b" } }), /binding disagrees/, "persisted evidence cannot cross tenant scope");

  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-adapt-conflict-reload-")), outcomeAdaptation: { initial: behavior("v1"), policy } });
  const project = app.projectManager!.create({ name: "conflict reload" });
  const left = app.outcomeAdaptation!(project.id), right = app.outcomeAdaptation!(project.id);
  left.propose(behavior("v2"));
  assert.throws(() => right.current(), /document conflict/);
  assert.equal(app.outcomeAdaptation!(project.id).current().prompt.version, "v1", "a fresh resolver recovers after a concurrent writer instead of caching a poisoned handle");
});

test("ADAPT-06: fixed-horizon uncertainty rejects a noisy apparent gain", () => {
  const noisyPolicy = { ...policy, minSamplesPerArm: 4 };
  let serial = 0;
  const adaptation = new OutcomeAdaptation(behavior("v1"), noisyPolicy, { clock: () => 10, id: () => `id-${++serial}`, random: () => 0.25 });
  adaptation.propose(behavior("v2"));
  const values = { baseline: [0, 0, 1, 1], candidate: [0, 1, 1, 1] };
  const seen = { baseline: 0, candidate: 0 };
  let decision;
  for (let index = 0; index < 8; index++) {
    const assignment = adaptation.assign(`subject-${index}`);
    adaptation.expose(assignment.assignmentId);
    const quality = values[assignment.arm][seen[assignment.arm]++]!;
    decision = adaptation.observe({ assignmentId: assignment.assignmentId, outcomeId: `outcome-${index}`, observedAt: 10, evidence: "observed-product", quality, regressed: false });
  }
  assert.equal(decision?.kind, "rejected");
  assert.match(decision?.reason ?? "", /lower95/);
  assert.equal(adaptation.current().prompt.version, "v1");
});

test("ADAPT-07: restored evidence is recomputed and malformed or contradictory snapshots fail closed", () => {
  let durable: { snapshot: unknown; revision: number } | undefined;
  const persistence: OutcomeAdaptationPersistence = {
    load: () => durable === undefined ? undefined : structuredClone(durable),
    save: (snapshot, expectedRevision) => {
      assert.equal(expectedRevision, durable?.revision ?? 0);
      durable = { snapshot: structuredClone(snapshot), revision: expectedRevision + 1 };
      return expectedRevision + 1;
    },
  };
  let serial = 0;
  const options = { persistence, clock: () => 20, id: () => `id-${++serial}`, random: () => 0.25 } as const;
  const adaptation = new OutcomeAdaptation(behavior("v1"), policy, options);
  adaptation.propose(behavior("v2"));
  const assignment = adaptation.assign("subject");
  adaptation.expose(assignment.assignmentId);
  adaptation.observe({ assignmentId: assignment.assignmentId, outcomeId: "outcome", observedAt: 21, evidence: "observed-product", quality: 0.5, regressed: false });
  const valid = structuredClone(durable!);
  const contradictory = structuredClone(valid);
  (contradictory.snapshot as { baselineOutcomes: { count: number } }).baselineOutcomes.count += 1;
  durable = contradictory;
  assert.throws(() => new OutcomeAdaptation(behavior("v1"), policy, options), /evidence disagrees/);
  const malformed = structuredClone(valid);
  const assignments = (malformed.snapshot as { assignments: Array<{ outcome: { quality: unknown } }> }).assignments;
  assignments[0]!.outcome.quality = "0.5";
  durable = malformed;
  assert.throws(() => new OutcomeAdaptation(behavior("v1"), policy, options), /invalid persisted assignment outcome/);
  durable = valid;
  assert.doesNotThrow(() => new OutcomeAdaptation(behavior("v1"), policy, options));
});

test("ADAPT-08: an assigned candidate is the behavior actually exposed before its outcome is accepted", async () => {
  let serial = 0;
  const adaptation = new OutcomeAdaptation(behavior("v1"), policy, { clock: () => 100, id: () => `id-${++serial}`, random: () => 0.75 });
  adaptation.propose(behavior("v2", "frontier"));
  const assignment = adaptation.assign("candidate-subject");
  assert.equal(assignment.arm, "candidate");
  assert.throws(() => adaptation.observe({ assignmentId: assignment.assignmentId, outcomeId: "premature", observedAt: 100, evidence: "observed-product", quality: 1, regressed: false }), /before the assigned behavior was exposed/);
  const requests: import("../src/gateway/gateway.js").GenerateRequest[] = [];
  const provider = new OutcomeAdaptiveProvider({
    name: "exposure-probe", isLocal: true,
    generate: async (request) => { requests.push(request); return { text: "ok", model: "probe", tokensIn: 1, tokensOut: 1 }; },
    embed: localEmbeddings,
  }, adaptation, { current: () => ({ effortKnob: "graded", timeoutClass: "reasoning", asOf: "2026-08-29", freshness: "fresh" }) }, () => 100);
  await provider.generate({ prompt: "task", hints: { adaptationAssignmentId: assignment.assignmentId } });
  assert.match(requests[0]!.prompt, /^prompt v2/u);
  assert.equal(requests[0]!.hints?.["preferredModelAdvisory"], true);
  assert.equal(requests[0]!.hints?.["requestedEffort"], "graded");
  assert.equal(adaptation.observe({ assignmentId: assignment.assignmentId, outcomeId: "observed", observedAt: 100, evidence: "observed-product", quality: 1, regressed: false }).kind, "observing");
});

test("ADAPT-09: pre-promotion live reports remain bounded and restartable", () => {
  let durable: { snapshot?: unknown; revision: number } | undefined;
  const persistence: OutcomeAdaptationPersistence = {
    load: () => durable === undefined ? undefined : structuredClone(durable),
    save: (snapshot, expectedRevision) => { assert.equal(expectedRevision, durable?.revision ?? 0); durable = { snapshot: structuredClone(snapshot), revision: expectedRevision + 1 }; return expectedRevision + 1; },
  };
  const first = new OutcomeAdaptation(behavior("v1"), policy, { persistence });
  for (let index = 0; index < 100; index++) assert.equal(first.observeLive({ outcomeId: `live-${index}`, observedAt: index, evidence: "observed-product", quality: 0, regressed: true }).kind, "observing");
  assert.doesNotThrow(() => new OutcomeAdaptation(behavior("v1"), policy, { persistence }));
  assert.equal(JSON.stringify(durable?.snapshot ?? {}).includes("live-99"), false);
});

test("ADAPT-10: failed persistence publishes no in-process mutation", () => {
  let durable: { snapshot?: unknown; revision: number } | undefined;
  let fail = false;
  const persistence: OutcomeAdaptationPersistence = {
    load: () => durable === undefined ? undefined : structuredClone(durable),
    save: (snapshot, expectedRevision) => {
      if (fail) throw new Error("disk full");
      durable = { snapshot: structuredClone(snapshot), revision: expectedRevision + 1 };
      return expectedRevision + 1;
    },
  };
  const adaptation = new OutcomeAdaptation(behavior("v1"), policy, { persistence });
  fail = true;
  assert.throws(() => adaptation.propose(behavior("v2")), /disk full/);
  assert.equal(adaptation.current().prompt.version, "v1");
  fail = false;
  assert.doesNotThrow(() => adaptation.propose(behavior("v2")));

  let promotionDurable: { snapshot?: unknown; revision: number } | undefined;
  let failPromotion = false;
  let serial = 0;
  const promotionPersistence: OutcomeAdaptationPersistence = {
    load: () => promotionDurable === undefined ? undefined : structuredClone(promotionDurable),
    save: (snapshot, expectedRevision) => {
      if (failPromotion) throw new Error("promotion disk full");
      promotionDurable = { snapshot: structuredClone(snapshot), revision: expectedRevision + 1 };
      return expectedRevision + 1;
    },
  };
  const promoting = new OutcomeAdaptation(behavior("v1"), policy, { persistence: promotionPersistence, clock: () => 20, id: () => `promotion-${++serial}`, random: () => 0.25 });
  promoting.propose(behavior("v2"));
  let last: import("../src/learning/outcome_adaptation.js").AdaptationAssignment | undefined;
  for (let index = 0; index < policy.minSamplesPerArm * 2; index++) {
    const assignment = promoting.assign(`promotion-subject-${index}`); promoting.expose(assignment.assignmentId);
    if (index === policy.minSamplesPerArm * 2 - 1) { last = assignment; break; }
    promoting.observe({ assignmentId: assignment.assignmentId, outcomeId: `promotion-outcome-${index}`, observedAt: 20, evidence: "observed-product", quality: assignment.arm === "baseline" ? 0.5 : 0.9, regressed: false });
  }
  failPromotion = true;
  assert.throws(() => promoting.observe({ assignmentId: last!.assignmentId, outcomeId: "promotion-final", observedAt: 20, evidence: "observed-product", quality: last!.arm === "baseline" ? 0.5 : 0.9, regressed: false }), /promotion disk full/);
  assert.equal(promoting.current().prompt.version, "v1", "a failed durable promotion is not live in process");
  failPromotion = false;
  assert.equal(promoting.observe({ assignmentId: last!.assignmentId, outcomeId: "promotion-final", observedAt: 20, evidence: "observed-product", quality: last!.arm === "baseline" ? 0.5 : 0.9, regressed: false }).kind, "promoted");
});

test("ADAPT-11: policy changes abandon an active epoch, tombstones retain CAS revision, and rejected bytes cannot be retried", () => {
  let durable: { snapshot?: unknown; revision: number } | undefined = { revision: 3 };
  const persistence: OutcomeAdaptationPersistence = {
    load: () => structuredClone(durable),
    save: (snapshot, expectedRevision) => { assert.equal(expectedRevision, durable?.revision); durable = { snapshot: structuredClone(snapshot), revision: expectedRevision + 1 }; return expectedRevision + 1; },
  };
  const first = new OutcomeAdaptation(behavior("v1"), policy, { persistence, clock: () => 10 });
  first.propose(behavior("v2"));
  const migrated = new OutcomeAdaptation(behavior("v1"), { ...policy, minSamplesPerArm: 5 }, { persistence, clock: () => 11 });
  assert.equal(migrated.current().prompt.version, "v1");
  assert.throws(() => new OutcomeAdaptation(behavior("different-initial"), { ...policy, minSamplesPerArm: 5 }, { persistence, clock: () => 11 }), /initial behavior disagrees/);
  assert.throws(() => migrated.propose(behavior("v2")), /previously rejected or abandoned/);

  const rejected = offline();
  rejected.propose(behavior("bad"));
  for (let i = 0; i < policy.minSamplesPerArm; i++) rejected.record("baseline", { quality: 0.8, regressed: false });
  for (let i = 0; i < policy.minSamplesPerArm; i++) rejected.record("candidate", { quality: 0.2, regressed: true });
  assert.throws(() => rejected.propose(behavior("bad")), /previously rejected or abandoned/);
});

test("ADAPT-12: the composed managed-project solve exposes its assigned arm to a real model request", async () => {
  const requests: import("../src/gateway/gateway.js").GenerateRequest[] = [];
  const plan = JSON.stringify({ rationale: "fix", edits: [{ file: "src/math.ts", search: "a - b", replace: "a + b", intent: "repair" }] });
  const provider: ModelProvider = {
    name: "composed-exposure", isLocal: true,
    generate: async (request) => { requests.push(request); return { text: plan, model: "composed-exposure", tokensIn: 1, tokensOut: 1 }; },
    embed: localEmbeddings,
  };
  const workspace = new InMemoryWorkspace({ repo: { "src/math.ts": "export const add = (a: number, b: number) => a - b;\n" } });
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-adapt-composed-consumer-")), developmentProvider: provider, workspace, repoRef: "repo",
    projectLocalizer: { async localize() { return { suspects: [{ path: "src/math.ts", score: 1, isTest: false }], stages: ["bm25" as const] }; } },
    solverRunnerFor: (_ref, tree) => validatorRunner(tree, async (candidate) => (await candidate.read("src/math.ts"))?.includes("a + b") ?? false),
    outcomeAdaptation: { initial: behavior("v1"), policy },
  });
  const project = app.projectManager!.create({ name: "installed adaptation consumer" });
  app.outcomeAdaptation!(project.id).propose(behavior("v2", "frontier"));
  await app.autonomyLoop!.runManagedProject(project.id, "fix the subtraction bug", { runId: "adaptation-installed-run", stepBudget: 50 });
  const exposed = requests.find((request) => typeof request.hints?.["adaptationAssignmentId"] === "string");
  assert.ok(exposed, `the installed managed-project solve emitted a model request for its durable assignment: ${JSON.stringify(requests.map((request) => request.hints))}`);
  assert.match(exposed.prompt, new RegExp(`^prompt ${String(exposed.hints?.["adaptationVersion"])}`, "u"));
});

test("ADAPT-13: a full or expired experiment cohort never stops ordinary model service", async () => {
  let now = 100;
  let serial = 0;
  const expiringPolicy = { ...policy, assignmentTtlMs: 10 };
  const adaptation = new OutcomeAdaptation(behavior("v1"), expiringPolicy, { clock: () => now, id: () => `id-${++serial}`, random: () => 0.25 });
  adaptation.propose(behavior("v2"));
  for (let index = 0; index < expiringPolicy.minSamplesPerArm * 2; index++) assert.ok(adaptation.assignOrGet(`subject-${index}`));
  assert.equal(adaptation.assignOrGet("overflow"), undefined, "a full measurement horizon degrades to current behavior");

  const requests: import("../src/gateway/gateway.js").GenerateRequest[] = [];
  const provider = new OutcomeAdaptiveProvider({
    name: "horizon-probe", isLocal: true,
    generate: async (request) => { requests.push(request); return { text: "ok", model: "probe", tokensIn: 1, tokensOut: 1 }; },
    embed: localEmbeddings,
  }, () => ({ adaptation, subjectId: "overflow" }), { current: () => ({ effortKnob: "none", timeoutClass: "standard", asOf: "2026-08-29", freshness: "fresh" }) }, () => now);
  await assert.doesNotReject(() => provider.generate({ prompt: "ordinary request" }));
  assert.match(requests[0]!.prompt, /^prompt v1/u);
  assert.equal(requests[0]!.hints?.["adaptationAssignmentId"], undefined);

  now = 111;
  assert.ok(adaptation.assignOrGet("replacement"), "expired unobserved assignments release bounded cohort capacity");
});

test("ADAPT-14: rollback abandons a newer experiment and remains restartable", () => {
  let durable: { snapshot?: unknown; revision: number } | undefined;
  const persistence: OutcomeAdaptationPersistence = {
    load: () => durable === undefined ? undefined : structuredClone(durable),
    save: (snapshot, expectedRevision) => { assert.equal(expectedRevision, durable?.revision ?? 0); durable = { snapshot: structuredClone(snapshot), revision: expectedRevision + 1 }; return expectedRevision + 1; },
  };
  let serial = 0;
  const adaptation = new OutcomeAdaptation(behavior("v1"), policy, { persistence, clock: () => 100, id: () => `id-${++serial}`, random: () => 0.25 });
  adaptation.propose(behavior("v2"));
  let promoted: import("../src/learning/outcome_adaptation.js").AdaptationDecision | undefined;
  for (let index = 0; index < policy.minSamplesPerArm * 2; index++) {
    const assignment = adaptation.assign(`promotion-${index}`);
    adaptation.expose(assignment.assignmentId);
    promoted = adaptation.observe({ assignmentId: assignment.assignmentId, outcomeId: `promotion-outcome-${index}`, observedAt: 100, evidence: "observed-product", quality: assignment.arm === "baseline" ? 0.5 : 0.9, regressed: false });
  }
  assert.equal(promoted?.kind, "promoted");
  adaptation.propose(behavior("v3"));
  adaptation.assign("new-experiment-subject");
  let decision: import("../src/learning/outcome_adaptation.js").AdaptationDecision | undefined;
  for (let index = 0; index < policy.minSamplesPerArm; index++) decision = adaptation.observeLive({ outcomeId: `regression-${index}`, observedAt: 101 + index, evidence: "observed-product", quality: 0.1, regressed: true });
  assert.equal(decision?.kind, "rolled-back");
  assert.equal(adaptation.current().prompt.version, "v1");
  const restarted = new OutcomeAdaptation(behavior("v1"), policy, { persistence, clock: () => 110 });
  assert.equal(restarted.current().prompt.version, "v1");
  assert.throws(() => restarted.assign("must-not-survive"), /no candidate/, "the newer experiment cannot survive rollback against the old baseline");
});
