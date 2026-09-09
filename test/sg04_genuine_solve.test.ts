/** Development falsifiers, not installed/real-provider/enterprise qualification. */
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { planEdits, parseEditPlan } from "../src/solve/edit_planner.js";
import { RecoveryBudget } from "../src/solve/recovery_budget.js";
import { SolvePipeline } from "../src/solve/solve_pipeline.js";
import { HierarchicalLocalizer, type LocalizationResult, type RepoFile } from "../src/solve/localize.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import type { ModelProvider } from "../src/gateway/gateway.js";

const issue = { id: "adaptive-observation", repoRef: "owned-fixture", text: "Correct retryLimit in src/retry.ts to use the configured limit." };
const files: RepoFile[] = [
  { path: "src/retry.ts", content: "export const retryLimit = 0;\n" },
  { path: "config/runtime.json", content: '{"configuredRetryLimit":7}\n' },
];
const localized: LocalizationResult = { suspects: [{ path: "src/retry.ts", score: 1, isTest: false }], stages: ["bm25"] };
const read = { action: "read_file", path: "config/runtime.json", startLine: 1, lineCount: 10 };
const proposal = (from = 0, to = 7) => ({ rationale: "Use observed configuration", edits: [
  { file: "src/retry.ts", search: `retryLimit = ${from}`, replace: `retryLimit = ${to}`, intent: "Match configured value" },
] });
function model(reply: (prompt: string, call: number) => unknown | Promise<unknown>) {
  let calls = 0;
  const port: ModelProvider = { name: "scripted-observation-fixture", isLocal: true,
    generate: async req => { const value = await reply(req.prompt, ++calls); return { text: typeof value === "string" ? value : JSON.stringify(value), model: "fixture-v1", tokensIn: 1, tokensOut: 1 }; },
    embed: async () => [],
  };
  return { port, calls: () => calls };
}
function observedConfig(prompt: string): boolean { return prompt.includes('\\"configuredRetryLimit\\":7'); }
function fixture(t: TestContext) {
  const dir = mkdtempSync(join(tmpdir(), "keep-sg04-observation-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const makeSpine = () => new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  return { dir, spine: makeSpine(), makeSpine };
}

test("operator cancellation reaches budgeted provider signal and late completion cannot regain a permit or refund calls", async t => {
  const f = fixture(t), controller = new AbortController(), limits = { maxAttempts: 2, maxElapsedMs: 60_000 };
  const budget = new RecoveryBudget(f.spine, "operator-cancel", limits, Date.now, controller.signal);
  const permit = await budget.reserve();
  assert.equal(await budget.reservePlanningCall(permit, 100), true);
  let release!: () => void, entered!: () => void, signal!: AbortSignal;
  const gate = new Promise<string>(resolve => { release = () => resolve("late output"); });
  const started = new Promise<void>(resolve => { entered = resolve; });
  const work = budget.withinDeadline(() => budget.during(permit, async value => { signal = value; entered(); return gate; }));
  const rejected = assert.rejects(work, /operator cancellation/u);
  await started; controller.abort(); await rejected; assert.equal(signal.aborted, true);
  release(); await new Promise<void>(resolve => setImmediate(resolve));
  await assert.rejects(budget.assertLive(permit), /operator cancellation/u);
  const state = await new RecoveryBudget(f.makeSpine(), "operator-cancel", limits).snapshot();
  assert.equal(state.attempts, 1); assert.equal(state.planningCalls, 1);
  await assert.rejects(new RecoveryBudget(f.makeSpine(), "operator-cancel", limits).reserve(), /operator cancellation/u);
});

test("native planner obtains missing configuration outside initial localization", async () => {
  const events: Readonly<Record<string, unknown>>[] = [];
  const m = model(prompt => observedConfig(prompt) ? proposal() : read);
  const result = await planEdits(issue, localized, files, m.port, { observe: e => events.push(e) });
  assert.deepEqual(result, proposal());
  assert.equal(m.calls(), 2);
  assert.equal(events.filter(e => e["outcome"] === "observation").length, 1);
  assert.equal(JSON.stringify(events).includes("configuredRetryLimit"), false, "new metadata does not leak source");
});

test("withholding the needed observation prevents a proposal, not a guessed pass", async () => {
  const m = model(prompt => observedConfig(prompt) ? proposal() : read);
  const result = await planEdits(issue, localized, files.slice(0, 1), m.port);
  assert.equal(result.edits.length, 0);
  assert.equal(m.calls(), 1);
  assert.match(result.rationale, /unauthorized observation/);
});

test("literal search and paged listing feed subsequent decisions", async () => {
  const m = model((prompt, call) => {
    if (call === 1) return { action: "list_files", prefix: "", offset: 0, limit: 1 };
    if (call === 2) { assert.match(prompt, /"nextOffset":1/); return { action: "search", query: "configuredRetryLimit", offset: 0, limit: 1 }; }
    assert.ok(observedConfig(prompt));
    return proposal();
  });
  assert.equal((await planEdits(issue, localized, files, m.port)).edits.length, 1);
  assert.equal(m.calls(), 3);
});

test("unchanged normalized observations stop at the second request", async () => {
  const m = model((_prompt, call) => call === 1 ? read : { lineCount: 10, startLine: 1, path: read.path, action: "read_file" });
  const result = await planEdits(issue, localized, files, m.port);
  assert.equal(m.calls(), 2);
  assert.match(result.rationale, /duplicate unchanged/);
});

test("adaptive proposals reject the whole mixed or unauthorized message", async () => {
  for (const value of [
    { ...proposal(), ...read },
    { ...proposal(), extra: "ignored?" },
    { ...proposal(), edits: [...proposal().edits, { file: "secret", search: "x", replace: "y" }] },
    { ...proposal(), edits: [null, ...proposal().edits] },
    { action: "execute", command: "touch bad" },
    { ...read, path: "../../outside" },
    "```json\n" + JSON.stringify(read) + "\n```",
    JSON.stringify(proposal()) + JSON.stringify(read),
  ]) {
    const m = model(() => value);
    assert.equal((await planEdits(issue, localized, files, m.port)).edits.length, 0);
    assert.equal(m.calls(), 1);
  }
  assert.equal(parseEditPlan(JSON.stringify({ ...proposal(), edits: [...proposal().edits, { file: "outside", search: "x", replace: "y" }] }), new Set(["src/retry.ts"])).edits.length, 1, "legacy standalone parser contract is unchanged");
  assert.equal((await planEdits(issue, localized, files, model(() => "```json\n" + JSON.stringify(proposal()) + "\n```").port)).edits.length, 1, "single legacy fenced final plan remains compatible");
});

test("observing a file never makes it writable", async () => {
  const m = model((_prompt, call) => call === 1 ? read : { rationale: "change config instead", edits: [{ file: read.path, search: "7", replace: "0" }] });
  assert.equal((await planEdits(issue, localized, files, m.port)).edits.length, 0);
  assert.equal(m.calls(), 2);
});

test("call and UTF-8 byte limits stop before unsafe dispatch or publication", async () => {
  const capped = model(() => read);
  assert.match((await planEdits(issue, localized, files, capped.port, { maxModelCalls: 1 })).rationale, /call budget/);
  assert.equal(capped.calls(), 1);
  const input = model(() => proposal());
  assert.match((await planEdits(issue, localized, files, input.port, { maxPromptBytes: 10 })).rationale, /prompt byte/);
  assert.equal(input.calls(), 0);
  const output = model(() => "é".repeat(60));
  assert.match((await planEdits(issue, localized, files, output.port, { maxResponseBytes: 100 })).rationale, /response byte/);
  const denied = model(() => proposal());
  assert.match((await planEdits(issue, localized, files, denied.port, { reserveCall: async () => false })).rationale, /shared planning budget/);
  assert.equal(denied.calls(), 0);
});

test("failed reservation propagates without dispatch; cancellation discards late proposals", async () => {
  const m = model(() => proposal());
  await assert.rejects(planEdits(issue, localized, files, m.port, { reserveCall: async () => { throw Error("storage failed"); } }), /storage failed/);
  assert.equal(m.calls(), 0);
  const controller = new AbortController();
  const late = model(() => { controller.abort(); return proposal(); });
  assert.equal((await planEdits(issue, localized, files, late.port, { signal: controller.signal })).edits.length, 0);
  await planEdits(issue, localized, files, late.port, { signal: controller.signal });
  assert.equal(late.calls(), 1, "already-aborted dispatch is not sent");
});

test("the captured source snapshot cannot change while a model request awaits", async () => {
  const mutable = files.map(f => ({ ...f }));
  const m = model((prompt, call) => {
    if (call === 1) { mutable[1]!.content = '{"configuredRetryLimit":99}'; return read; }
    assert.ok(observedConfig(prompt));
    assert.equal(prompt.includes("99"), false);
    return proposal();
  });
  assert.equal((await planEdits(issue, localized, mutable, m.port)).edits.length, 1);
});

test("shared planning charges survive fresh coordinators and reject stale permits", async t => {
  const f = fixture(t);
  const limits = { maxAttempts: 3, maxElapsedMs: 60_000, maxPlanningCalls: 2, maxPlanningInputBytes: 100 };
  const first = new RecoveryBudget(f.spine, "durable-planning", limits);
  const p = await first.reserve();
  assert.equal(await first.reservePlanningCall(p, 60), true);
  await first.finish(p);
  await assert.rejects(first.reservePlanningCall(p, 1), /owned and live/);
  const second = new RecoveryBudget(f.makeSpine(), "durable-planning", limits);
  const q = await second.reserve();
  assert.equal(await second.reservePlanningCall(q, 41), false, "remaining bytes, not original allowance");
  assert.equal(await second.reservePlanningCall(q, 40), true);
  assert.equal(await second.reservePlanningCall(q, 1), false);
  await second.finish(q);
  const state = await second.snapshot();
  assert.equal(state.planningCalls, 2);
  assert.equal(state.planningInputBytes, 100);
  assert.equal(state.status, "exhausted", "ordinary planning exhaustion is not an ambiguous effect hold");
});

test("dispatch sees already durable charges; malformed output does not create a sticky hold", async t => {
  const f = fixture(t);
  const limits = { maxAttempts: 2, maxElapsedMs: 60_000 };
  const budget = new RecoveryBudget(f.spine, "predispatch", limits);
  const permit = await budget.reserve();
  const m = model(async () => {
    const state = await new RecoveryBudget(f.makeSpine(), "predispatch", limits).snapshot();
    assert.equal(state.planningCalls, 1);
    assert.ok(state.planningInputBytes > 0);
    return "not JSON";
  });
  const result = await budget.during(permit, signal => planEdits(issue, localized, files, m.port, { signal, reserveCall: bytes => budget.reservePlanningCall(permit, bytes) }));
  assert.equal(result.edits.length, 0);
  await budget.finish(permit);
  assert.equal((await budget.snapshot()).status, "ready");
});

test("legacy or corrupt durable accounting is refused, never reset to zero", async t => {
  const f = fixture(t);
  const id = "legacy-planning";
  const limits = { maxAttempts: 3, maxElapsedMs: 60_000 };
  const budget = new RecoveryBudget(f.spine, id, limits);
  const p = await budget.reserve();
  await budget.reservePlanningCall(p, 10);
  await budget.finish(p);
  const last = f.spine.replay().filter(e => e.actor === "solve.recovery").at(-1)!;
  const state = { ...last.payload["state"] as Record<string, unknown> };
  delete state["planningCalls"];
  f.spine.stage({ type: "identity.action", actor: "solve.recovery", payload: { event: "recovery.state", operation: createHash("sha256").update(id).digest("hex"), state } });
  await f.spine.seal();
  await assert.rejects(new RecoveryBudget(f.makeSpine(), id, limits).reserve(), /stored recovery identity\/limits/);
});

test("actual solver consumes observations, edits and validates; repair retains shared accounting", async t => {
  const f = fixture(t);
  const tree = new InMemoryFileTree(Object.fromEntries(files.map(file => [file.path, file.content])));
  let validations = 0;
  const m = model((prompt, call) => {
    if (call === 1) return proposal(0, 1); // Deliberate near miss; a real repair attempt must own its permit.
    if (call === 2) { assert.match(prompt, /retryLimit = 1/); return read; }
    assert.ok(observedConfig(prompt));
    return proposal(1, 7);
  });
  class FixedLocalizer extends HierarchicalLocalizer { override async localize() { return localized; } }
  const pipeline = new SolvePipeline({ spine: f.spine, ledger: new RollbackLedger(f.spine), tree, model: m.port,
    localizer: new FixedLocalizer(), runner: { run: async () => { validations++; return { results: [
      { name: "configured retry limit", passed: await tree.read("src/retry.ts") === "export const retryLimit = 7;\n", output: "retry limit must be 7" },
    ] }; } },
  });
  const result = await pipeline.run(issue, files);
  assert.equal(result.solved, true, result.gaveUpReason);
  assert.equal(result.repairRounds, 1);
  assert.equal(result.recovery?.attempts, 2);
  assert.equal(result.recovery?.planningCalls, 3);
  assert.equal(validations, 2, "no redundant reacquisition of the first failure");
  assert.equal(m.calls(), 3);
  assert.equal(await tree.read("config/runtime.json"), files[1]!.content);
  await f.spine.seal();
  const dispatches = f.spine.replay().filter(e => e.payload["event"] === "native_planning" && e.payload["outcome"] === "dispatch");
  assert.equal(dispatches.length, 3);
  assert.equal(new Set(dispatches.map(e => e.payload["snapshotId"])).size, 2, "repair observes changed source");
});

test("ordinary composed project uses adaptive preparation inside its original solve budget", async t => {
  const { composeKeep } = await import("../src/compose.js");
  const { InMemoryWorkspace } = await import("../src/solve/workspace.js");
  const f = fixture(t);
  const workspace = new InMemoryWorkspace({ repo: Object.fromEntries(files.map(file => [file.path, file.content])) });
  const m = model(prompt => observedConfig(prompt) ? proposal() : read);
  const app = composeKeep({ dataDir: join(f.dir, "app"), developmentProvider: m.port, workspace, repoRef: "repo",
    projectLocalizer: { localize: async () => localized },
    solverRunnerFor: (_repo, tree) => ({ run: async () => ({ results: [
      { name: "configured retry limit", passed: await tree.read("src/retry.ts") === "export const retryLimit = 7;\n" },
    ] }) }),
  });
  const result = await app.autonomyLoop!.runProject("Fix retryLimit in src/retry.ts to match the configured limit.", { runId: "ordinary-adaptive", stepBudget: 50 });
  assert.equal(result.state.status, "completed", JSON.stringify(result.state));
  const artifact = result.state.artifacts["implement"] as import("../src/solve/project_loop_wiring.js").ProjectImplementationArtifact;
  assert.equal(artifact.solve.recovery?.attempts, 1, "preparation and effect share one attempt");
  assert.equal(artifact.solve.recovery?.planningCalls, 2);
  assert.equal(artifact.solve.projectEditReceipt?.applied, true);
  assert.deepEqual(artifact.admittedEditPrepared?.allowedFiles, ["src/retry.ts"]);
  assert.equal(m.calls(), 2, "no parallel legacy planner or second model plan");
  assert.equal(await workspace.tree("repo").read(read.path), files[1]!.content);
  assert.equal(JSON.stringify(result.state).includes("prepareAdmittedEdit"), false, "ephemeral capability is not durable state");
  const events = app.spine.replay();
  const dispatch = events.findIndex(e => e.payload["event"] === "native_planning" && e.payload["outcome"] === "dispatch");
  const reserved = events.findIndex(e => e.actor === "solve.recovery" && (e.payload["state"] as { planningCalls?: number })?.planningCalls === 1);
  assert.ok(reserved >= 0 && dispatch > reserved, "the initial project model call follows durable reservation");
});

test("exhausted canonical operation does not call deferred project preparation", async t => {
  const f = fixture(t);
  const tree = new InMemoryFileTree(Object.fromEntries(files.map(file => [file.path, file.content])));
  const budget = new RecoveryBudget(f.spine, JSON.stringify([issue.repoRef, "exhausted-project"]), { maxAttempts: 1, maxElapsedMs: 60_000 });
  await budget.finish(await budget.reserve());
  let preparations = 0;
  const pipeline = new SolvePipeline({ spine: f.spine, ledger: new RollbackLedger(f.spine), tree,
    model: model(() => proposal()).port, localizer: new HierarchicalLocalizer(), runner: { run: async () => { throw Error("must not validate"); } },
  }, { maxRepairRounds: 0, recoveryMaxElapsedMs: 60_000 });
  const result = await pipeline.run(issue, files, { recoveryOperationId: "exhausted-project", prepareAdmittedEdit: async () => { preparations++; throw Error("must not prepare"); } });
  assert.equal(result.solved, false);
  assert.equal(preparations, 0);
  assert.equal(result.recovery?.status, "exhausted");
});
