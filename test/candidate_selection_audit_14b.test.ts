import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setImmediate as turn } from "node:timers/promises";
import { composeKeep } from "../src/compose.js";
import { selectBestOfN, type CandidateSolver } from "../src/resolve/best_of_n.js";
import { selectBestOfNWithTests } from "../src/resolve/novel_tests.js";
import { resolveCascade, type ResolutionTier } from "../src/resolve/budget_cascade.js";
import { isolateCandidateSolver, SnapshotCandidateWorkspaceFactory, type CandidateWorkspaceFactory } from "../src/resolve/candidate_workspace.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";
import { buildDefaultSolver } from "../src/solve/default_solver.js";
import { candidateDataSha256, captureCandidateData } from "../src/resolve/candidate_snapshot.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import type { SolveResult } from "../src/solve/issue_model.js";

const issue = { id: "candidate-audit", text: "Repair arithmetic addition", repoRef: "repo" };
const good = "function add(a,b) { return a + b; }";
const absolute = "function add(a,b) { return Math.abs(a + b); }";
const base = "function add(a,b) { return a - b; }";
function executes(code: string, negative = false): boolean {
  const r = spawnSync(process.execPath, ["-e", `${code};require('node:assert/strict').equal(add(${negative ? "-9,2" : "2,3"}),${negative ? "-7" : "5"});`], { timeout: 1500, maxBuffer: 16000 });
  assert.equal(r.error, undefined); assert.equal(r.signal, null);
  return r.status === 0;
}
function candidate(code = good): SolveResult {
  const passed = executes(code);
  return { issueId: issue.id, solved: passed, stagesRun: [], repairRounds: 0,
    validation: { testsPassed: passed, passedCount: passed ? 1 : 0, failures: passed ? [] : ["positive"], vettingCleared: passed, detail: "separate Node assertion" },
    prProposal: { title: "Addition", body: "Synthetic candidate", branch: "keep/candidate", testsPassed: passed,
      edits: [{ file: "src/math.mjs", search: base, replace: code, intent: "repair addition" }] } };
}
const noPatch = (): SolveResult => ({ issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0 });
const generator = { generate: async () => [{ id: "negative", description: "negative addition" }] };
const executor = { run: async (_test: unknown, c: SolveResult) => executes(c.prProposal!.edits[0]!.replace, true) ? "pass" as const : "fail" as const };
function deferred() { let resolve!: () => void; const promise = new Promise<void>(r => { resolve = r; }); return { promise, resolve }; }

for (const context of ["personal", "organization-alpha"]) test(`KEEP-14B-001: composed N1 allocates/releases its own snapshot (${context})`, async () => {
  const source = new InMemoryWorkspace({ repo: { "src/math.mjs": base } });
  const factory = new SnapshotCandidateWorkspaceFactory(source);
  let allocations = 0, releases = 0, finishes = 0, generations = 0;
  const wrapped: CandidateWorkspaceFactory = {
    allocate: async (i, e) => { allocations++; assert.ok(e.resolutionId); const lease = await factory.allocate(i, e); return { ...lease, release: async () => { releases++; await lease.release(); } }; },
    finishResolution: id => { finishes++; factory.finishResolution(id); },
  };
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), `keep-14b-${context}-`)),
    candidateWorkspaceFactory: wrapped, bestOfN: { n: 1 },
    candidateSolver: async (i, _index, e) => { assert.ok(e?.workspace); assert.equal(await e.workspace.tree(i.repoRef).read("src/math.mjs"), base); return candidate(); },
    testGenerator: { generate: async () => { generations++; return []; } }, testExecutor: executor });
  const result = await app.resolveWithTests!(issue);
  assert.equal(result.winnerCleared, true); assert.equal(executes(result.winner.prProposal!.edits[0]!.replace, true), true);
  assert.deepEqual([allocations, releases, finishes, generations], [1, 1, 1, 0]);
  assert.equal(await source.tree("repo").read("src/math.mjs"), base);
  // Context-labelled independent factories test shared mechanics, not tenant authentication.
});

test("KEEP-14B-002: awaited executor cannot rewrite the checked winner", async () => {
  const originals = [candidate(), candidate(absolute)]; let tested = 0;
  await assert.rejects(selectBestOfNWithTests({ sample: async (_i, n) => originals[n]!, generator,
    executor: { run: async (t, c) => { const result = await executor.run(t, c); tested++; await turn(); (c.prProposal!.edits[0] as { replace: string }).replace = base; return result; } },
  }, issue, { n: 2 }), /read only|immutable|frozen|candidate.*changed/i);
  assert.equal(tested, 1); assert.equal(originals[0]!.prProposal!.edits[0]!.replace, good);
});

test("KEEP-14B-002: retained sampler alias cannot change earlier scored contents", async () => {
  const first = candidate();
  const result = await selectBestOfNWithTests({ sample: async (_i, n) => {
    if (n === 0) return first;
    (first.prProposal!.edits[0] as { replace: string }).replace = base;
    return candidate(absolute);
  }, generator, executor }, issue, { n: 2 });
  assert.equal(result.winnerCleared, true); assert.equal(executes(result.winner.prProposal!.edits[0]!.replace, true), true);
  assert.equal(first.prProposal!.edits[0]!.replace, base, "caller data remains caller-owned");
});

test("KEEP-14B-002: lease release cannot rewrite candidate before capture", async () => {
  const original = candidate();
  const factory: CandidateWorkspaceFactory = { allocate: async () => ({ workspaceId: "a", repoRef: "a", workspace: new InMemoryWorkspace({ a: {} }),
    release: () => { (original.prProposal!.edits[0] as { replace: string }).replace = base; } }) };
  const result = await selectBestOfN({ sample: isolateCandidateSolver(async () => original, factory) }, issue, { n: 1 });
  assert.equal(result.winnerCleared, true); assert.equal(executes(result.winner.prProposal!.edits[0]!.replace, true), true);
  assert.equal(original.prProposal!.edits[0]!.replace, base);
});

test("KEEP-14B-002: generator cannot mutate nested validation evidence", async () => {
  await assert.rejects(selectBestOfNWithTests({ sample: async () => candidate(), executor,
    generator: { generate: async (_i, cs) => { await turn(); (cs[0]!.validation as { testsPassed: boolean }).testsPassed = false; return []; } },
  }, issue, { n: 2 }), /read only|immutable|frozen|candidate.*changed/i);
});

test("KEEP-14B-002: N1 fidelity evidence owns the meter's arrays", async () => {
  const measurement = { fullCoverage: true, required: ["addition"], covered: ["addition"], missing: [] as string[], extraneous: [] as string[], basis: "synthetic task checker" };
  const result = await selectBestOfN({ sample: async () => candidate(), measureTaskFidelity: () => measurement }, issue, { n: 1 });
  measurement.required.push("changed"); measurement.covered.length = 0;
  measurement.missing.push("addition"); measurement.extraneous.push("other");
  const evidence = result.n1Baseline!.taskFidelity;
  assert.equal(evidence.measured, true);
  if (!evidence.measured) assert.fail("missing configured measurement");
  assert.deepEqual(evidence.value, { fullCoverage: true, required: ["addition"], covered: ["addition"], missing: [], extraneous: [], basis: "synthetic task checker" });
  assert.ok(Object.isFrozen(evidence.value.required));
});

test("KEEP-14B-002: non-inert fidelity output rejects with cleanup", async () => {
  let cleaned = 0, getters = 0;
  const sample: CandidateSolver = async () => candidate();
  sample.finishResolution = () => { cleaned++; };
  await assert.rejects(selectBestOfN({ sample, measureTaskFidelity: () => ({
    get fullCoverage() { getters++; return true; }, required: [], covered: [], missing: [], extraneous: [], basis: "invalid accessor",
  }) }, issue, { n: 1 }), /accessors/);
  assert.deepEqual([cleaned, getters], [1, 0]);
});

test("KEEP-14B-003: failure stops assignment, drains workers, then finishes once", { timeout: 5000 }, async () => {
  const source = new InMemoryWorkspace({ repo: { "state.txt": "old" } }), factory = new SnapshotCandidateWorkspaceFactory(source);
  const entered = deferred(), fail = deferred(), release = deferred(), done = deferred();
  const timeline: string[] = []; const seen: string[] = []; let count = 0; const error = new Error("sample failed");
  const sample: CandidateSolver = async (i, n, e) => {
    timeline.push(`entry${n}`); seen.push((await e!.workspace!.tree(i.repoRef).read("state.txt"))!);
    if (++count === 2) entered.resolve();
    if (n === 0) { await fail.promise; throw error; }
    if (n === 1) { await release.promise; done.resolve(); }
    return noPatch();
  };
  const wrapped: CandidateWorkspaceFactory = {
    allocate: async (i, e) => { const lease = await factory.allocate(i, e); return { ...lease, release: async () => { timeline.push(`release${e.sampleIndex}`); await lease.release(); } }; },
    finishResolution: id => { timeline.push("finish"); factory.finishResolution(id); },
  };
  const selection = selectBestOfN({ sample: isolateCandidateSolver(sample, wrapped) }, issue, { n: 3, concurrency: 2, stopWhenClean: false });
  const outcome = selection.then(() => ({ error: undefined }), error => ({ error }));
  try {
    await entered.promise; fail.resolve(); await turn(); await turn();
    assert.equal(timeline.includes("finish"), false, "finish cannot precede the still-active worker");
    await source.tree("repo").write("state.txt", "new");
  } finally { release.resolve(); await done.promise; await outcome; await turn(); }
  assert.equal((await outcome).error, error); assert.equal(count, 2); assert.deepEqual(seen, ["old", "old"]);
  assert.equal(timeline.at(-1), "finish"); assert.equal(timeline.filter(x => x === "finish").length, 1);
  const next: string[] = [];
  await selectBestOfN({ sample: isolateCandidateSolver(async (i, _n, e) => { next.push((await e!.workspace!.tree(i.repoRef).read("state.txt"))!); return noPatch(); }, factory) }, issue, { n: 1 });
  assert.deepEqual(next, ["new"]);
});

test("KEEP-14B-003: primary and resolution cleanup failures both survive", async () => {
  const primary = new Error("sample failure"), cleanup = new Error("finish failure");
  const sample: CandidateSolver = async () => { throw primary; }; sample.finishResolution = () => { throw cleanup; };
  await assert.rejects(selectBestOfN({ sample }, issue, { n: 1 }), (e: unknown) => e instanceof AggregateError && e.errors.includes(primary) && e.errors.includes(cleanup));
});

for (const missing of ["generator", "executor"] as const) test(`KEEP-14B-004: missing ${missing} refuses before any tier entry`, async () => {
  let entries = 0, budget = 0;
  const tier = (useTests = false): ResolutionTier => ({ name: "tier", n: 2, estCostUsd: 1, useTests, sample: async () => { entries++; return candidate(); } });
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-14b-cascade-")), resolutionTiers: [tier(), tier(true)],
    ...(missing === "generator" ? { testExecutor: executor } : { testGenerator: generator }),
    cascadeBudget: { canAfford: () => { budget++; return true; }, record: () => { budget++; } } });
  await assert.rejects(app.resolveCascade!(issue), /requires.*generator.*executor/i);
  assert.deepEqual([entries, budget], [0, 0]);
});

for (const stop of ["exhausted", "budget", "verified"] as const) test(`KEEP-14B-005: retained fork agrees with winner on ${stop}`, async () => {
  const first: ResolutionTier = { name: "fork", n: 2, useTests: true, estCostUsd: 1, sample: async (_i, n) => candidate(n === 0 ? good : absolute) };
  const second: ResolutionTier = { name: "later", n: 1, estCostUsd: 2, sample: async () => stop === "verified" ? candidate() : noPatch() };
  const result = await resolveCascade({ tiers: [first, second], generator, executor,
    ...(stop === "budget" ? { budget: { canAfford: (cost: number) => cost < 2, record: () => {} } } : {}) }, issue);
  assert.equal(result.stoppedReason, stop); assert.equal(result.winnerCleared, true);
  assert.equal(result.behavioralFork, stop !== "verified"); assert.equal(result.escalateToHuman, stop !== "verified");
  assert.equal(executes(result.winner.prProposal!.edits[0]!.replace, true), true);
});

for (const n of [1, 2]) test(`KEEP-14B: actual native edits and behavioral tests through composed N${n}`, async () => {
  const data = mkdtempSync(join(tmpdir(), "keep-14b-native-"));
  const spine = new Spine(new FileSpineStore(join(data, "native"), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const source = new InMemoryWorkspace({ repo: { "src/math.mjs": base, "unrelated.txt": "retain" } });
  let entries = 0, calls = 0, checks = 0, generated = 0;
  const app = composeKeep({ dataDir: join(data, "app"), candidateWorkspaceFactory: new SnapshotCandidateWorkspaceFactory(source), bestOfN: { n },
    candidateSolver: async (i, index, e) => {
      entries++; assert.ok(e?.workspace);
      const solver = buildDefaultSolver({ spine, workspace: e.workspace,
        model: { name: "synthetic-selection-audit", isLocal: true,
          generate: async () => { calls++; return { text: JSON.stringify({ rationale: "arithmetic repair", edits: [{ file: "src/math.mjs", search: base, replace: index === 0 ? good : absolute, intent: "repair addition" }] }), model: "synthetic-selection-audit", tokensIn: 0, tokensOut: 0 }; },
          embed: async () => { throw new Error("embedding is not part of this fixture"); } },
        runnerFor: (_ref, tree) => ({ run: async () => { checks++; return { results: [{ name: "positive arithmetic", passed: executes((await tree.read("src/math.mjs"))!) }] }; } }), options: { maxRepairRounds: 0 } });
      return (await solver(i)).solveResult;
    }, testGenerator: { generate: async () => { generated++; return generator.generate(); } }, testExecutor: executor });
  const result = await app.resolveWithTests!({ ...issue, text: "Repair add in src/math.mjs for numeric arguments; retain unrelated files." });
  assert.equal(result.winnerCleared, true, JSON.stringify({ result, entries, calls, checks })); assert.equal(executes(result.winner.prProposal!.edits[0]!.replace, true), true);
  assert.equal(result.behavioralFork, n === 2); assert.equal(entries, n); assert.equal(calls, n); assert.equal(checks, n); assert.equal(generated, n === 1 ? 0 : 1);
  assert.equal(result.candidateDigests[result.selectedIndex]!.sha256, candidateDataSha256(result.winner));
  assert.equal(await source.tree("repo").read("src/math.mjs"), base); assert.equal(await source.tree("repo").read("unrelated.txt"), "retain");
});

test("KEEP-14B-002: generated test content cannot drift between candidate cells", async () => {
  const description = { id: "positive", description: "positive", body: "add(2,3)===5" };
  const observed: string[] = [];
  const result = await selectBestOfNWithTests({ sample: async () => candidate(),
    generator: { generate: async () => [description] }, executor: { run: async t => {
      observed.push((t as typeof description).body); await turn(); description.body = "changed after first cell"; return "pass";
    } } }, issue, { n: 2 });
  assert.deepEqual(observed, ["add(2,3)===5", "add(2,3)===5"]);
  assert.equal((result.analysis!.stats[0]!.test as typeof description).body, "add(2,3)===5");
});

test("KEEP-14B-002: inert capture preserves nested optional data without invoking accessors", () => {
  const input = { ...candidate(), optional: undefined, nested: { isolation: ["mount", "network"], receipt: { id: "one" } } };
  const owned = captureCandidateData(input); assert.deepEqual(owned, input); assert.ok(Object.isFrozen(owned.nested.receipt));
  input.nested.receipt.id = "two"; assert.equal(owned.nested.receipt.id, "one");
  let invoked = 0; const accessor = Object.defineProperty({}, "value", { enumerable: true, get: () => { invoked++; return 1; } });
  for (const invalid of [accessor, new Map(), new Date(), new Uint8Array(1), new SharedArrayBuffer(4), new Proxy({}, {}), { f() {} }]) assert.throws(() => captureCandidateData(invalid), /inert|accessor/);
  assert.equal(invoked, 0);
  const cycle: { self?: unknown } = {}; cycle.self = cycle; assert.throws(() => captureCandidateData(cycle), /cycle/);
  assert.throws(() => captureCandidateData([, 1]), /dense/);
  const poison = JSON.parse('{"__proto__":{"key":"owned"}}'); const copy = captureCandidateData(poison);
  assert.equal(Object.getPrototypeOf(copy), Object.prototype); assert.equal(Object.hasOwn(copy, "__proto__"), true);
});

test("KEEP-14B-003: sampler and factory cleanup both run, preserving both failures", async () => {
  const samplerFailure = new Error("sampler finish"), factoryFailure = new Error("factory finish"); const trace: string[] = [];
  const sample: CandidateSolver = async () => noPatch(); sample.finishResolution = () => { trace.push("sampler"); throw samplerFailure; };
  const factory: CandidateWorkspaceFactory = { allocate: async () => ({ workspaceId: "a", workspace: new InMemoryWorkspace({ a: {} }), repoRef: "a", release() {} }),
    finishResolution: () => { trace.push("factory"); throw factoryFailure; } };
  await assert.rejects(selectBestOfN({ sample: isolateCandidateSolver(sample, factory) }, issue, { n: 1 }),
    (e: unknown) => e instanceof AggregateError && e.errors.includes(samplerFailure) && e.errors.includes(factoryFailure));
  assert.deepEqual(trace, ["sampler", "factory"]);
});

test("KEEP-14B-003: undefined rejection is still a failure and cleanup runs", async () => {
  let finished = 0; const sample: CandidateSolver = async () => { throw undefined; }; sample.finishResolution = () => { finished++; };
  let rejected = false;
  await selectBestOfN({ sample }, issue, { n: 3, concurrency: 1, stopWhenClean: false }).catch(error => { assert.equal(error, undefined); rejected = true; });
  assert.equal(rejected, true); assert.equal(finished, 1);
});
