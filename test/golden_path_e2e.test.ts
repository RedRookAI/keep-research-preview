import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ModelGateway, type ModelProvider, type GenerateResult, type Embedding } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { MemoryStore } from "../src/memory/store.js";
import { FrontDoor } from "../src/frontdoor/front_door.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { Issue } from "../src/solve/issue_model.js";
import type { RepoFile } from "../src/solve/localize.js";
import { pinnedGitDependencies } from "./helpers/pinned_git_dependencies.js";
import { KeepPipeline } from "../src/pipeline/keep_pipeline.js";

function newMemory(): MemoryStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-19-mem-"));
  const spine = new Spine(new FileSpineStore(dir, { fsync: true }), new InProcessLock(), new SchemaRegistry());
  return new MemoryStore(spine, new ModelGateway(new LocalProvider()));
}

// ─── the non-engineer onboarding (deterministic, jargon-free, no terminal) ───

test("golden path A: a non-engineer completes onboarding with zero terminal/config, capturing their goal", async () => {
  const memory = newMemory();
  const fd = new FrontDoor(memory);

  const greeting = fd.greeting();
  assert.match(greeting.say, /call you/i); // jargon-free opener
  assert.equal(greeting.source, "deterministic");

  // One short answer at a time — no JSON, no config file, no webhooks.
  await fd.converse("Dana");
  await fd.converse("Keeper");
  const goalTurn = await fd.converse("fix the bug where add() subtracts instead of adds");
  assert.ok(goalTurn.say.length > 0);

  // The goal was captured as a directive (probation memory — must earn trust before configuring anything).
  const directives = fd.capturedDirectives();
  assert.ok(directives.some((d) => /add\(\)|subtracts/i.test(d.text)), "the human's goal is captured as a directive");
  const ctx = fd.context();
  assert.equal(ctx.humanName, "Dana");
  assert.equal(ctx.aiName, "Keeper");
});

test("golden path B: an LLM brain failure never breaks onboarding (degrade, never break)", async () => {
  const memory = newMemory();
  // A brain that always throws — the deterministic line must still drive progress.
  const fd = new FrontDoor(memory, { brain: async () => { throw new Error("brain down"); } });
  fd.greeting();
  const t = await fd.converse("Dana");
  assert.equal(t.source, "deterministic", "brain failure falls back to the deterministic line");
  assert.ok(t.say.length > 0);
});

test("golden path C: an LLM brain warms the phrasing when available (enhance, never gate)", async () => {
  const memory = newMemory();
  const fd = new FrontDoor(memory, { brain: async (line) => `✨ ${line}` });
  fd.greeting();
  const t = await fd.converse("Dana");
  assert.equal(t.source, "llm-warmed");
  assert.match(t.say, /✨/);
});

// ─── front-of-house → back-of-house: the captured goal drives a ticket → human-gated PR ───

function fixModel(search: string, replace: string): ModelProvider {
  return {
    name: "fix", isLocal: true,
    async generate(): Promise<GenerateResult> {
      return { text: JSON.stringify({ rationale: "fix", edits: [{ file: "src/calc.ts", search, replace, intent: "fix" }] }), model: "fix", tokensIn: 1, tokensOut: 1 };
    },
    async embed(): Promise<Embedding[]> { return []; },
  };
}

function setupRemote(seedFile: string, seedContent: string): { work: string; bare: string } {
  const root = mkdtempSync(join(tmpdir(), "keep-19-e2e-"));
  const bare = join(root, "o.git"); const work = join(root, "w");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  execFileSync("git", ["clone", "-q", bare, work]);
  const g = (a: string[]) => execFileSync("git", a, { cwd: work });
  g(["config", "user.email", "t@t"]); g(["config", "user.name", "t"]); g(["checkout", "-qb", "main"]);
  execFileSync("bash", ["-c", `mkdir -p "$(dirname ${join(work, seedFile)})" && printf '%s' ${JSON.stringify(seedContent)} > ${join(work, seedFile)}`]);
  g(["add", "-A"]); g(["commit", "-qm", "init"]); g(["push", "-q", "-u", "origin", "main"]);
  return { work, bare };
}

test("golden path D: the captured goal becomes a ticket that runs the WHOLE spine → human-gated PR", async () => {
  // Front of house: onboarding captures the goal.
  const memory = newMemory();
  const fd = new FrontDoor(memory);
  fd.greeting();
  await fd.converse("Dana");
  await fd.converse("Keeper");
  await fd.converse("add() in calc.ts subtracts instead of adds");
  const goal = fd.context().goal ?? "";
  assert.match(goal, /add\(\)/);

  // Back of house: the goal drives a real ticket through the pipeline to a human-gated PR on a real remote.
  const { work, bare } = setupRemote("src/calc.ts", "export function add(a, b) { return a - b; }\n");
  const dir = mkdtempSync(join(tmpdir(), "keep-19-spine-"));
  const spine = new Spine(new FileSpineStore(dir, { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const files: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
  const tree = new InMemoryFileTree({ "src/calc.ts": "export function add(a, b) { return a - b; }" });
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  const pipeline = new KeepPipeline({ spine, tree, runner, model: fixModel("return a - b;", "return a + b;") });
  execFileSync("bash", ["-c", `mkdir -p "$(dirname ${join(work, "src/calc.ts")})" && printf '%s' 'export function add(a, b) { return a + b; }\n' > ${join(work, "src/calc.ts")}`]);

  // The ticket text comes straight from the non-engineer's captured goal.
  const issue: Issue = { id: "GP-1", text: goal, repoRef: "gp" };
  const result = await pipeline.solveIssueToPR(issue, files, pinnedGitDependencies(work), { autonomyLevel: "operator" });

  assert.equal(result.solveResult.solved, true, "the whole spine ran and solved the non-engineer's goal");
  assert.ok(result.manifest, "a PR manifest was produced");
  assert.equal(result.manifest!.humanApprovalRequired, true, "human merge gate intact — the owner still approves");
  const verify = mkdtempSync(join(tmpdir(), "keep-19-v-"));
  execFileSync("git", ["clone", "-q", bare, verify]);
  assert.match(execFileSync("git", ["branch", "-a"], { cwd: verify }).toString(), /keep\/solve\/GP-1/, "the PR branch reached the real remote");
});

// ─── compose wiring: one canonical memory owner ───

test("golden path E: composeKeep always wires the FrontDoor and accepts an explicit personal memory store", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const without = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-19-c1-")) });
  assert.ok(without.frontDoor, "the zero-configuration n=1 composition exposes the conversational front door");
  assert.match(without.frontDoor!.greeting().say, /call you/i);

  const memory = newMemory();
  const withFd = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-19-c2-")), frontDoorMemory: memory });
  assert.ok(withFd.frontDoor, "an explicit personal memory store remains supported");
  assert.match(withFd.frontDoor!.greeting().say, /call you/i);
});

test("golden path F: composeKeep exposes a working scheduler — grant → enable → tick accrues a proposal (never merged)", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-sched-wire-")) });
  assert.ok(app.scheduler && app.budgetLedger && app.deadLetterQueue, "scheduler cluster is wired onto the app");

  // Operator grants a one-time envelope (the F2 authorization), then toggles the cadence ON.
  await app.budgetLedger.grant({
    id: "envF", projectId: "projF", allowedClasses: ["auto-research"], allowedTiers: [],
    dailyCapUsd: 5, perRunCapUsd: 1, perCallTokenCeiling: 2048,
    expiresAt: Date.now() + 3_600_000, grantedReason: "e2e wire test",
  });
  app.scheduler.enable({ projectId: "projF", enabledClasses: ["auto-research"], envelopeId: "envF" });

  const report = await app.scheduler.tick("projF", [
    { id: "tF", projectId: "projF", cls: "auto-research", run: async () => "PROPOSAL: tidy the README" },
  ]);
  assert.equal(report.halted, false);
  assert.deepEqual(report.proposals.map((p) => p.taskId), ["tF"], "the proposal accrued for human review");

  // Disabled project → nothing runs (autonomy is off by default until the operator toggles it).
  const off = await app.scheduler.tick("projOff", [
    { id: "tOff", projectId: "projOff", cls: "auto-research", run: async () => "should not run" },
  ]);
  assert.equal(off.halted, true, "a project with no cadence toggle runs nothing");
});

test("golden path G: composeKeep exposes a working saga runner — commits on success, unwinds LIFO on partial failure", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-saga-wire-")) });
  assert.ok(app.sagaSequencer && app.nonPersistableRegistry && app.otelEmitter, "saga trio wired onto the app");

  // Happy path: all steps commit.
  const ok = await app.sagaSequencer.run("sagaOK", [
    { name: "a", forward: async () => ({ id: "a", artifact: "A", undo: async () => {} }) },
    { name: "b", forward: async () => ({ id: "b", artifact: "B", undo: async () => {} }) },
  ]);
  assert.equal(ok.committed, true);
  assert.deepEqual(ok.completed, ["a", "b"]);

  // Partial failure: step c throws → completed steps unwind in LIFO (b then a).
  const undone: string[] = [];
  const bad = await app.sagaSequencer.run("sagaBad", [
    { name: "a", forward: async () => ({ id: "a", artifact: "A", undo: async () => { undone.push("a"); } }) },
    { name: "b", forward: async () => ({ id: "b", artifact: "B", undo: async () => { undone.push("b"); } }) },
    { name: "c", forward: async () => { throw new Error("boom"); } },
  ]);
  assert.equal(bad.committed, false);
  assert.equal(bad.failedAt, "c");
  assert.deepEqual(undone, ["b", "a"], "compensation ran in LIFO order");
});

test("golden path H: composeKeep exposes an inert durable project lane without solve and runProject drives the FSM with solve", async () => {
  const { composeKeep } = await import("../src/compose.js");

  // Persistent n=1 capabilities share the durable project substrate. Merely composing it must
  // neither create a project nor start work; executable solve behavior remains opt-in.
  const bare = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-al-0-")) });
  assert.ok(bare.autonomyLoop, "dataDir-only n=1 exposes the durable project lane");
  assert.deepEqual(bare.autonomyLoop!.manager.list(), [], "composition creates no implicit project");
  assert.equal(bare.autonomyLoop!.manager.active(undefined), undefined, "composition activates no project");
  assert.equal(bare.autonomyLoop!.supportsStrategy(), false, "software execution remains unavailable without its seam");

  // With a solve seam: the implement stage delegates to it, and the FSM runs to done.
  let solvedIssue: { readonly text: string; readonly hints?: Readonly<Record<string, unknown>> } | undefined;
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-al-1-")),
    solve: async (issue) => {
      solvedIssue = issue;
      const solveResult = { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } as never;
      return { solveResult } as never;
    },
  });
  assert.ok(app.autonomyLoop, "autonomy loop wired when solve is supplied");
  const run = await app.autonomyLoop!.runProject("add a dark-mode toggle", { runId: "projH", stepBudget: 50 });
  assert.equal(run.state.stage, "done", "the FSM ran through to done");
  assert.equal(run.state.status, "completed", "completed cleanly (not paused/failed)");
  assert.match(solvedIssue?.text ?? "", /Admitted issue context:\nadd a dark-mode toggle(?:\n|$)/, "the exact operator goal remains in the admitted solver context");
  assert.match(solvedIssue?.text ?? "", /Vetted dependency-ordered execution roadmap:/, "the solve seam consumes the vetted task roadmap rather than bypassing decomposition");
  assert.equal(solvedIssue?.hints?.["projectTaskId"], "task-01", "the solve issue is bound to the one admitted root task");
  assert.equal(solvedIssue?.hints?.["planStepId"], "implement", "the solve issue is bound to its vetted plan step");
  assert.ok(run.visited.includes("implement") && run.visited.includes("vet_artifact") && run.visited.includes("learn"),
    "the real-work stages executed");
});

test("golden path H2 (isolation guard now LIVE): checkpoints are deferred while a stage side-effect region is open", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-al-2-")),
    solve: async (issue) => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never),
  });
  // The composed loop uses the composed NonPersistableRegistry — while an executor's region is open, canCheckpoint is false.
  assert.equal(app.nonPersistableRegistry.canCheckpoint(), true, "no region open at rest");
  await app.autonomyLoop!.runProject("refactor the config loader", { runId: "projH2", stepBudget: 50 });
  // After the run, all regions are released (every within() exited) and the guard reports safe again.
  assert.equal(app.nonPersistableRegistry.canCheckpoint(), true, "all stage regions released after the run");
  // The trace shows the loop ran under the isolation guard (regions entered/exited around executors).
  const events = app.spine.currentEvents().map((e) => (e.payload as Record<string, unknown>)["event"]);
  assert.ok(events.includes("nonpersistable_enter") && events.includes("nonpersistable_exit"),
    "the composed loop opened + closed non-persistable regions around its side-effecting stages");
});
