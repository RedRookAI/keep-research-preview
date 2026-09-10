import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { MemoryStore } from "../src/memory/store.js";
import { composeKeep, type KeepApp } from "../src/compose.js";
import { runCli, runGatewayCli, type CliIO, type CliDeps } from "../src/cli/cli_core.js";
import type { GatewayServerHandle } from "../src/gateway/http_gateway.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { GOAL_WORK_DOCUMENT, type GoalWorkDocument } from "../src/session/project_goal_work.js";
import type { PredictionSource } from "../src/frontdoor/front_door.js";
import { priorPosterior, updatePosterior, posteriorMean, type SuccessPosterior } from "../src/routing/uncertainty_router.js";
import type { SolveFn } from "../src/loop/review_intake.js";
import type { PrManifest } from "../src/git/pull_request.js";
import type { Issue } from "../src/solve/issue_model.js";
import type { SolveToPrResult } from "../src/pipeline/keep_pipeline.js";

function newMemory(): MemoryStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-cli-mem-"));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  return new MemoryStore(spine, new ModelGateway(new LocalProvider()));
}
function newApp(): KeepApp {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-cli-")), frontDoorMemory: newMemory() });
}

/** Fake IO: captures all writes, answers prompts from a scripted queue. */
function fakeIO(answers: string[] = []): CliIO & { out: string[]; joined(): string } {
  const out: string[] = [];
  const queue = [...answers];
  return {
    out,
    write: (t) => out.push(t),
    prompt: async () => queue.shift() ?? "",
    joined: () => out.join("\n"),
  };
}

function manifest(id: string): PrManifest {
  return {
    id, title: "Fix tax double-count", body: "…", branch: `keep/solve/${id}`, baseBranch: "main",
    diff: "--- a/calc.ts\n+++ b/calc.ts\n@@\n-total*2\n+total", intent: "totals add tax twice",
    executed: ["edited calc.ts: remove duplicate tax multiply"], checks: [{ name: "unit tests", passed: true } as PrManifest["checks"][number]],
    attribution: "keep-run-1", humanApprovalRequired: true,
    oversight: { band: "low", disposition: "human-approval-required", mode: "notify-async", requiresImmediateAttention: false, reasons: ["reversible, bounded change"] },
  };
}
function solvedResult(id: string): SolveToPrResult {
  return { solveResult: { issueId: id, solved: true, stagesRun: [], repairRounds: 0, prProposal: { title: "t", body: "b", branch: `keep/solve/${id}`, edits: [], testsPassed: true } } as SolveToPrResult["solveResult"], manifest: manifest(id) };
}
const solveOk: SolveFn = async (issue: Issue) => solvedResult(issue.id);

// ─── routing ───

test("dogfood goal overview: projects gateway projects actual durable counts without dispatch", async () => {
  const app = newApp(), parent = app.projectManager!.create({ name: "Keep goal" }), child = app.projectManager!.create({ name: "child task" });
  const jobId = randomUUID();
  const task = (id: string) => ({ id, goal: id, kind: "goal" as const, dependsOn: [], requires: [], due: "development" as const, acceptance: "tested-proposal" as const });
  // This projection fixture represents an already accepted proposal, not live-model evidence.
  const document: GoalWorkDocument = { schema: "keep.goal-work/v1", creationId: randomUUID(), binding: "c".repeat(64), principal: { kind: "human", id: "owner" }, phase: "development", active: true, startsUsed: 1,
    definition: { objective: "private objective must not be copied into list metadata", maxTaskStarts: 3, tasks: [task("repair"), { ...task("verify"), dependsOn: ["repair"], requires: ["release-host"] }, { ...task("polish"), kind: "hardening", due: "release" }] },
    claims: { repair: { jobId, projectId: child.id } }, accepted: { repair: { jobId, projectId: child.id, kind: "tested-proposal", checkpointRevision: 2, sourceDigest: "a".repeat(64), validationDigest: "b".repeat(64) } } };
  const session = app.projectManager!.session(parent.id);
  session.putDocumentVersioned(GOAL_WORK_DOCUMENT, JSON.stringify(document), undefined);
  const before = session.resolveDocumentVersioned(GOAL_WORK_DOCUMENT);
  const response = await handleGatewayRequest(app, { method: "GET", path: "/projects", query: {}, headers: { authorization: "Bearer overview" }, body: "" }, { token: "overview" });
  assert.equal(response.status, 200);
  const rows = JSON.parse(response.body).projects;
  assert.deepEqual(rows.find((row: { id: string }) => row.id === parent.id).goalWork,
    { active: true, phase: "development", totalTasks: 3, acceptedTasks: 1, deferredTasks: 1, heldTasks: 1, nextTaskId: null });
  assert.equal(rows.find((row: { id: string }) => row.id === child.id).goalWork ?? null, null);
  assert.equal(response.body.includes(document.definition.objective), false);
  assert.deepEqual(session.resolveDocumentVersioned(GOAL_WORK_DOCUMENT), before, "listing cannot advance or rewrite work");
  assert.equal(app.projectRuntime!.jobs().length, 0, "listing does not create jobs");
});

test("dogfood goal overview: projects CLI distinguishes tested proposals, deferred work and actionable goal handle", async () => {
  const io = fakeIO(), id = `prj_${"a".repeat(32)}`;
  const response = { projects: [{ id, name: "Keep goal", lifecycle: "active", quarantined: null, runId: null, status: null, proposal: false, decision: null,
    goalWork: { active: true, phase: "development", totalTasks: 3, acceptedTasks: 1, deferredTasks: 1, heldTasks: 1, nextTaskId: null } }], active: null };
  let reads = 0;
  const result = await runGatewayCli(["projects"], io, { gateway: async request => { reads++; assert.equal(request.method, "GET"); assert.equal(request.path, "/projects"); return { status: 200, headers: {}, body: JSON.stringify(response) }; } });
  assert.equal(result.exitCode, 0); assert.equal(reads, 1);
  assert.match(io.joined(), /development/u); assert.match(io.joined(), /1\/3/u);
  assert.match(io.joined(), /tested.proposal/iu); assert.match(io.joined(), /held[^\n]*1|1[^\n]*held/iu); assert.match(io.joined(), /deferred[^\n]*1|1[^\n]*deferred/iu);
  assert.ok(io.joined().includes(`keep project goal show ${id}`));
  assert.doesNotMatch(io.joined(), /goal complete|33\s*%|keep project resume/iu);
});

test("remote project CLI submits and observes exact jobs without a local app", async () => {
  const io = fakeIO(), requests: Array<{ path: string; query: Record<string, string>; body: string }> = [];
  const deps = { gatewayToken: "a".repeat(64), gateway: async (request: { path: string; query: Record<string, string>; body: string }) => { requests.push(request); return { status: request.path === "/project" || request.path === "/project/cancel" ? 202 : 200, headers: {}, body: '{"jobId":"11111111-1111-4111-8111-111111111111"}' }; } };
  assert.equal((await runGatewayCli(["project", "repair task", "--background", "--idempotency-key=stable-operation-key"], io, deps)).exitCode, 0);
  assert.deepEqual(JSON.parse(requests[0]!.body), { goal: "repair task", background: true, idempotencyKey: "stable-operation-key" });
  const id = "11111111-1111-4111-8111-111111111111";
  assert.equal((await runGatewayCli(["project", "job", id], io, deps)).exitCode, 0); assert.equal(requests[1]!.query["jobId"], id);
  assert.equal((await runGatewayCli(["project", "cancel", id], io, deps)).exitCode, 0); assert.deepEqual(JSON.parse(requests[2]!.body), { jobId: id });
  assert.equal((await runGatewayCli(["project", "goal", "--idempotency-key=stable-operation-key"], io, deps)).exitCode, 2); assert.equal(requests.length, 3);
});

test("project memory flags are explicit consent and never become task instructions", async () => {
  const requests: string[] = [];
  const deps = { gateway: async (request: { body: string }) => { requests.push(request.body); return { status: 202, headers: {}, body: '{"status":"accepted"}' }; } };
  const io = fakeIO(), projectId = `prj_${"a".repeat(32)}`;
  const result = await runGatewayCli(["project", "repair config.ts", `--project=${projectId}`, "--memory=project", "--memory-processing=configured-provider"], io, deps);
  assert.equal(result.exitCode, 0);
  assert.deepEqual(JSON.parse(requests[0]!), { goal: "repair config.ts", projectId, memoryContext: { scope: "project", processing: "configured-provider" } });
  for (const args of [["--memory=user"], ["--memory=user", "--memory-processing=local-only"],
    ["--memory=user", "--memory=user", "--memory-processing=configured-provider"], ["--memory-secret=bad"]]) {
    assert.equal((await runGatewayCli(["project", "repair config.ts", ...args], fakeIO(), deps)).exitCode, 2);
  }
  assert.equal(requests.length, 1, "invalid opt-in cannot contact a gateway");
});

test("remote worker stop carries exact worker identity and never infers completion from refusal", async () => {
  const io = fakeIO(); let calls = 0;
  const result = await runGatewayCli(["worker", "stop", "worker-exact"], io, { gateway: async request => {
    calls++; assert.equal(request.path, "/worker/stop"); assert.deepEqual(JSON.parse(request.body), { workerId: "worker-exact" }); return { status: 409, headers: {}, body: '{"error":"active work"}' };
  } });
  assert.equal(result.exitCode, 1); assert.equal(calls, 1);
});

test("help prints usage; version prints version; unknown command exits 2", async () => {
  const io1 = fakeIO(); await runCli(["help"], io1, { app: newApp() }); assert.match(io1.joined(), /Usage: keep/);
  const io2 = fakeIO(); await runCli(["version"], io2, { app: newApp(), version: "9.9" }); assert.match(io2.joined(), /keep 9\.9/);
  const io3 = fakeIO(); const r = await runCli(["frobnicate"], io3, { app: newApp() }); assert.equal(r.exitCode, 2); assert.match(io3.joined(), /Unknown command/);
});

// ─── onboard ───

test("onboard drives the deterministic FrontDoor conversation and captures a directive", async () => {
  const app = newApp();
  const io = fakeIO(["Dana", "Keeper", "fix the bug where totals add tax twice", "web", "no"]);
  const r = await runCli(["onboard"], io, { app });
  assert.equal(r.exitCode, 0);
  assert.match(io.joined(), /call you/i); // greeting rendered
  assert.ok(app.frontDoor, "front door present");
  assert.ok(app.frontDoor!.capturedDirectives().some((d) => /tax twice/i.test(d.text)), "goal captured as a directive");
});

// ─── solve ───

test("solve with no description exits 2 with guidance", async () => {
  const io = fakeIO(); const r = await runCli(["solve"], io, { app: newApp(), solve: solveOk });
  assert.equal(r.exitCode, 2); assert.match(io.joined(), /Tell me what to work on/);
});

test("solve with no solve dep reports honestly (no fake success)", async () => {
  const io = fakeIO(); const r = await runCli(["solve", "do a thing"], io, { app: newApp() });
  assert.equal(r.exitCode, 2); assert.match(io.joined(), /No model\/repository is configured/);
});

test("a successful solve records a review.pending and prints the review hint (never merges)", async () => {
  const app = newApp();
  const io = fakeIO();
  await runCli(["solve", "totals add tax twice"], io, { app, solve: solveOk, clock: () => 1000 });
  assert.match(io.joined(), /Proposed a change \(not merged\)/);
  assert.match(io.joined(), /never merges/i);
  assert.match(io.joined(), /keep review /);
});

test("a solve that doesn't produce a change says so and applies nothing", async () => {
  const app = newApp();
  const failing: SolveFn = async (i) => ({ solveResult: { issueId: i.id, solved: false, stagesRun: [], repairRounds: 0, gaveUpReason: "no confident change" } as SolveToPrResult["solveResult"] });
  const io = fakeIO();
  await runCli(["solve", "unfixable"], io, { app, solve: failing });
  assert.match(io.joined(), /didn't produce a change/i);
});

// ─── status / review / audit round-trip ───

test("status lists a pending review, review approves it, then status is empty and audit shows the trail", async () => {
  const app = newApp();
  // Solve to create a pending review with a fixed id.
  const fixedSolve: SolveFn = async () => solvedResult("KEEP-ABC");
  await runCli(["solve", "totals add tax twice"], fakeIO(), { app, solve: fixedSolve, clock: () => 1000 });

  // status shows it.
  const st1 = fakeIO(); await runCli(["status"], st1, { app });
  assert.match(st1.joined(), /KEEP-ABC/);
  assert.match(st1.joined(), /need your decision/);

  // review renders the decision packet and approves.
  const rv = fakeIO(["approve"]); await runCli(["review", "KEEP-ABC"], rv, { app, clock: () => 2000 });
  assert.match(rv.joined(), /What you asked for/);       // intent
  assert.match(rv.joined(), /What Keep did/);            // executed
  assert.match(rv.joined(), /you're confirming, not catching/); // the verification-first framing
  assert.match(rv.joined(), /Approved KEEP-ABC/);

  // status now empty.
  const st2 = fakeIO(); await runCli(["status"], st2, { app });
  assert.match(st2.joined(), /Nothing is waiting/);

  // audit shows the pending + decision.
  const au = fakeIO(); await runCli(["audit", "KEEP-ABC"], au, { app });
  assert.match(au.joined(), /proposed a change/i);
  assert.match(au.joined(), /you approved the change/i);
});

test("declining records a decline and applies nothing", async () => {
  const app = newApp();
  await runCli(["solve", "x"], fakeIO(), { app, solve: async () => solvedResult("KEEP-DEC"), clock: () => 1 });
  const rv = fakeIO(["decline"]); await runCli(["review", "KEEP-DEC"], rv, { app });
  assert.match(rv.joined(), /Declined KEEP-DEC/);
  assert.match(rv.joined(), /Nothing was applied/);
});

test("re-reviewing a decided change is refused", async () => {
  const app = newApp();
  await runCli(["solve", "x"], fakeIO(), { app, solve: async () => solvedResult("KEEP-ONCE"), clock: () => 1 });
  await runCli(["review", "KEEP-ONCE"], fakeIO(["approve"]), { app });
  const again = fakeIO(["approve"]); await runCli(["review", "KEEP-ONCE"], again, { app });
  assert.match(again.joined(), /already been reviewed/);
});

test("review with an unknown id is a clean error", async () => {
  const io = fakeIO(); const r = await runCli(["review", "NOPE"], io, { app: newApp() });
  assert.equal(r.exitCode, 2); assert.match(io.joined(), /couldn't find a change/);
});

// ─── S0 risk-tier fix: the human is the residual, not the universal vetter ───

function autoApprovedManifest(id: string): PrManifest {
  const m = manifest(id) as unknown as { oversight: Record<string, unknown> };
  m.oversight = { band: "low", disposition: "auto-approved", mode: "silent-auto", requiresImmediateAttention: false, reasons: ["low risk + reversible — verification-cleared"] };
  return m as unknown as PrManifest;
}

test("auto-approved changes do NOT clutter the human decision queue (machine vetting is primary)", async () => {
  const app = newApp();
  // one change that needs a decision, two the machine auto-approved
  await runCli(["solve", "risky"], fakeIO(), { app, solve: async () => solvedResult("KEEP-NEED"), clock: () => 1 });
  await runCli(["solve", "safe1"], fakeIO(), { app, solve: async () => ({ solveResult: solvedResult("KEEP-AUTO1").solveResult, manifest: autoApprovedManifest("KEEP-AUTO1") }), clock: () => 2 });
  await runCli(["solve", "safe2"], fakeIO(), { app, solve: async () => ({ solveResult: solvedResult("KEEP-AUTO2").solveResult, manifest: autoApprovedManifest("KEEP-AUTO2") }), clock: () => 3 });

  const st = fakeIO(); await runCli(["status"], st, { app });
  assert.match(st.joined(), /1 change\(s\) need your decision/);   // only the one that needs it
  assert.match(st.joined(), /KEEP-NEED/);
  assert.doesNotMatch(st.joined().split("need your decision")[1] ?? "", /KEEP-AUTO1/); // auto ones not in the decision list
  assert.match(st.joined(), /2 other change\(s\) were auto-approved/); // batched, not surfaced as decisions
});

test("status --all reveals the auto-approved (verification-cleared) changes for optional spot-check", async () => {
  const app = newApp();
  await runCli(["solve", "safe"], fakeIO(), { app, solve: async () => ({ solveResult: solvedResult("KEEP-AUTO").solveResult, manifest: autoApprovedManifest("KEEP-AUTO") }), clock: () => 1 });
  const st = fakeIO(); await runCli(["status"], st, { app });
  assert.match(st.joined(), /Nothing needs your decision/);
  assert.doesNotMatch(st.joined(), /KEEP-AUTO\b(?![\s\S]*--all)/); // not listed by default
  const all = fakeIO(); await runCli(["status", "--all"], all, { app });
  assert.match(all.joined(), /Auto-approved/);
  assert.match(all.joined(), /KEEP-AUTO/);
});

test("review of an auto-approved change frames it as a spot-check of cleared work, not a required gate", async () => {
  const app = newApp();
  await runCli(["solve", "safe"], fakeIO(), { app, solve: async () => ({ solveResult: solvedResult("KEEP-AUTO").solveResult, manifest: autoApprovedManifest("KEEP-AUTO") }), clock: () => 1 });
  const rv = fakeIO(["approve"]); await runCli(["review", "KEEP-AUTO"], rv, { app });
  assert.match(rv.joined(), /cleared this and auto-approved it/);
  assert.match(rv.joined(), /spot-check/i);
});

test("review with no id defaults to a change that needs a decision, skipping auto-approved ones", async () => {
  const app = newApp();
  await runCli(["solve", "safe"], fakeIO(), { app, solve: async () => ({ solveResult: solvedResult("KEEP-AUTO").solveResult, manifest: autoApprovedManifest("KEEP-AUTO") }), clock: () => 1 });
  await runCli(["solve", "risky"], fakeIO(), { app, solve: async () => solvedResult("KEEP-NEED"), clock: () => 2 });
  const rv = fakeIO(["skip"]); await runCli(["review"], rv, { app }); // no id
  assert.match(rv.joined(), /KEEP-NEED/);       // picked the needs-decision one
  assert.doesNotMatch(rv.joined(), /Review: KEEP-AUTO/);
});


// ─── P2: reachability commands over the gateway ───

function appWithSolve(): KeepApp {
  return composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-cli-p2-")),
    projectPosture: "approval-required",
    frontDoorMemory: newMemory(),
    solve: async (issue: { id: string }) => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never),
  });
}

test("P2: `keep message` prints a real handled reply", async () => {
  const io = fakeIO();
  const r = await runCli(["message", "add a login button to the homepage"], io, { app: newApp() });
  assert.equal(r.exitCode, 0);
  assert.ok(io.joined().length > 0, "a real reply is printed");
});

test("P2: `keep project resume` surfaces run identity and consumes an approval", async () => {
  const app = appWithSolve();
  const started = fakeIO();
  await runCli(["project", "email the whole team the report"], started, { app });
  const runId = /Run: (\S+) @/.exec(started.joined())?.[1];
  const decisionId = /Resume signal: (\S+)/.exec(started.joined())?.[1];
  assert.ok(runId && decisionId);
  const resumed = fakeIO();
  const result = await runCli(["project", "resume", runId!, `--approve=${decisionId}`], resumed, { app });
  assert.equal(result.exitCode, 0);
  assert.match(resumed.joined(), new RegExp(runId!));
});

test("P2: `keep project` starts a project and prints its status", async () => {
  const io = fakeIO();
  const r = await runCli(["project", "email the whole team the report"], io, { app: appWithSolve() });
  assert.equal(r.exitCode, 0);
  assert.match(io.joined(), /Project status:/, "prints the run status");
  assert.match(io.joined(), /needs your go-ahead/, "an external goal is paused for the human (guard live end-to-end)");
});

test("P2: `keep project --domain` reaches a selected domain and rejects unknown selectors", async () => {
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-cli-domain-")),
    domainWorkflows: { worker: async (request) => request.requiredDeliverables.map((name) => ({ name, content: `${request.kind}:${name}` })) },
  });
  const io = fakeIO();
  const result = await runCli(["project", "--domain=chapter-book", "locally write and vet a chapter book"], io, { app });
  assert.equal(result.exitCode, 0);
  assert.match(io.joined(), /completed/u);
  const invalid = fakeIO();
  const rejected = await runCli(["project", "--domain=unknown", "do something"], invalid, { app });
  assert.equal(rejected.exitCode, 2);
  assert.match(invalid.joined(), /Invalid domain/u);
});

test("P2: `keep projects` lists sessions", async () => {
  const app = appWithSolve();
  app.autonomyLoop!.manager.create({ name: "My first project" }); // a real session to list
  const io = fakeIO();
  const r = await runCli(["projects"], io, { app });
  assert.equal(r.exitCode, 0);
  assert.match(io.joined(), /Your projects:/, "lists the sessions");
  assert.match(io.joined(), /My first project/, "reflects the real ProjectSessionManager, not a stub");
});

test("P2: project jobs, quarantine, archive, and crypto-shred are reachable CLI consumers", async () => {
  const app = appWithSolve();
  const project = app.projectManager!.create({ name: "Lifecycle project" });
  const jobs = fakeIO(); assert.equal((await runCli(["project", "jobs", project.id], jobs, { app })).exitCode, 0); assert.match(jobs.joined(), /No durable project jobs/u);
  const quarantine = fakeIO(); assert.equal((await runCli(["project", "quarantine", project.id], quarantine, { app })).exitCode, 0); assert.match(quarantine.joined(), /No matching projects/u);
  const archived = fakeIO(); assert.equal((await runCli(["project", "archive", project.id], archived, { app })).exitCode, 0); assert.match(archived.joined(), /archived and read-only/u);
  const deleted = fakeIO(); assert.equal((await runCli(["project", "delete", project.id], deleted, { app })).exitCode, 0); assert.match(deleted.joined(), /crypto-shredded/u);
  assert.equal(app.projectManager!.list().some((record) => record.id === project.id), false);
});

test("P2: an offer surfaced by `keep message` can be accepted, recording the outcome", async () => {
  // Compose an app whose front door surfaces a proven offer, sharing ONE app across the two CLI calls.
  let proven = priorPosterior(); for (let i = 0; i < 30; i++) proven = updatePosterior(proven, true);
  const persisted: { belief?: SuccessPosterior } = {};
  const source: PredictionSource = {
    candidates: () => [{ id: "pat", description: "open the file you edited yesterday", consequence: "reversible", confidence: proven, utility: 4, interruptionCost: 0.1 }],
    persist: (_id, updated) => { persisted.belief = updated; },
  };
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-cli-offer-")), frontDoorMemory: newMemory(), predictionSource: source });
  const io1 = fakeIO();
  await runCli(["message", "add a login button to the homepage"], io1, { app });
  assert.match(io1.joined(), /open the file you edited yesterday/, "the offer surfaced on the message");
  const io2 = fakeIO();
  await runCli(["offer", "accept"], io2, { app });
  assert.ok(persisted.belief, "accepting the offer recorded the outcome through the gateway");
  assert.ok(posteriorMean(persisted.belief!) >= posteriorMean(proven), "acceptance did not lower the belief");
});


// ─── P9: keep serve --gateway (durable token, safe bind, connect story) ───

function fakeGateway(): { serve: NonNullable<CliDeps["serveGateway"]>; lastOpts: { host?: string; token?: string } } {
  const lastOpts: { host?: string; token?: string } = {};
  const serve = async (_app: KeepApp, opts: { port?: number; host?: string; token?: string }): Promise<GatewayServerHandle> => {
    if (opts.host !== undefined) lastOpts.host = opts.host;
    if (opts.token !== undefined) lastOpts.token = opts.token;
    return { origin: `http://${opts.host ?? "127.0.0.1"}:7788`, port: 7788, token: opts.token ?? "gen", close: async () => {} };
  };
  return { lastOpts, serve };
}
function memTokenStore(initial?: string): { load(): string | undefined; save(t: string): void } {
  let value: string | undefined = initial;
  return { load: () => value, save: (t: string) => { value = t; } };
}

test("P9 SERVE: `keep serve --gateway` starts the gateway and prints the connect story with a token", async () => {
  const io = fakeIO();
  const gw = fakeGateway();
  const r = await runCli(["serve", "--gateway"], io, { app: appWithSolve(), serveGateway: gw.serve, tokenStore: memTokenStore() });
  assert.equal(r.exitCode, 0);
  assert.match(io.joined(), /Keep is running/);
  assert.match(io.joined(), /Token:\s+\S+/, "the connect story includes a token");
  assert.ok(gw.lastOpts.token && gw.lastOpts.token.length > 0, "the gateway was started with a token");
});

test("P9 SERVE: the token PERSISTS across a simulated restart (a paired client stays paired)", async () => {
  const store = memTokenStore();
  const gw1 = fakeGateway();
  await runCli(["serve", "--gateway"], fakeIO(), { app: appWithSolve(), serveGateway: gw1.serve, tokenStore: store });
  const first = gw1.lastOpts.token;
  // "restart": a fresh serve over the SAME token store
  const gw2 = fakeGateway();
  await runCli(["serve", "--gateway"], fakeIO(), { app: appWithSolve(), serveGateway: gw2.serve, tokenStore: store });
  assert.equal(gw2.lastOpts.token, first, "the same token is reused across restarts");
});

test("P9 SERVE: --new-token rotates the token (explicit rotation)", async () => {
  const store = memTokenStore();
  const gw1 = fakeGateway();
  await runCli(["serve", "--gateway"], fakeIO(), { app: appWithSolve(), serveGateway: gw1.serve, tokenStore: store });
  const first = gw1.lastOpts.token;
  const gw2 = fakeGateway();
  await runCli(["serve", "--gateway", "--new-token"], fakeIO(), { app: appWithSolve(), serveGateway: gw2.serve, tokenStore: store });
  assert.notEqual(gw2.lastOpts.token, first, "an explicit rotation changes the token");
});

test("P9 SERVE: the bind defaults to 127.0.0.1 (safe-bind)", async () => {
  const gw = fakeGateway();
  await runCli(["serve", "--gateway"], fakeIO(), { app: appWithSolve(), serveGateway: gw.serve, tokenStore: memTokenStore() });
  assert.equal(gw.lastOpts.host, "127.0.0.1", "safe-bind by default");
});
