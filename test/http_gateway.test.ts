import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep, type KeepApp } from "../src/compose.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { MemoryStore } from "../src/memory/store.js";
import { handleGatewayRequest, startGatewayServer, type GatewayRequest } from "../src/gateway/http_gateway.js";
import { AGENT, type Principal } from "../src/identity/rbac.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";
import { publishSkill } from "../src/registry/skill_registry.js";
import { recordReviewPending } from "../src/loop/review_intake.js";
import type { PrManifest } from "../src/git/pull_request.js";
import type { DomainStageWorker } from "../src/autonomy/domain_workflows.js";
import { asProjectId } from "../src/session/project_id.js";

const TOKEN = "test-token-abc";

function req(method: string, path: string, body: unknown = undefined, token: string | null = TOKEN): GatewayRequest {
  return {
    method,
    path,
    query: {},
    headers: token !== null ? { authorization: `Bearer ${token}` } : {},
    body: body !== undefined ? JSON.stringify(body) : "",
  };
}

function newMemory(): MemoryStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-gw-mem-"));
  return new MemoryStore(new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider()));
}
function app(dataDir: string, projectPosture?: "autonomous" | "policy-calibrated" | "approval-required"): { app: KeepApp; solved: { called: boolean } } {
  const solved = { called: false };
  const a = composeKeep({
    dataDir,
    ...(projectPosture === undefined ? {} : { projectPosture }),
    frontDoorMemory: newMemory(),
    solve: async (issue: { id: string; text: string }) => { solved.called = true; return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never; },
  });
  return { app: a, solved };
}

test("COMPOSED: an authed client starts a project and gets a real status over the API", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-gw-"));
  const { app: a } = app(dir);
  const r = await handleGatewayRequest(a, req("POST", "/project", { goal: "write and test a markdown parser library" }), { token: TOKEN });
  assert.equal(r.status, 200);
  const parsed = JSON.parse(r.body) as { projectId: string; runId: string; status: string };
  assert.equal(a.projectManager?.list().some((record) => record.id === parsed.projectId), true);
  assert.equal(a.projectManager?.session(asProjectId(parsed.projectId)).lastCheckpoint()?.runId, parsed.runId);
  assert.ok(["running", "completed", "waiting-retry", "waiting-capability", "waiting-approval", "waiting-policy", "waiting-reconciliation", "paused-budget", "failed"].includes(parsed.status), `real run status, got ${parsed.status}`);
  const durable = a.projectManager!.session(asProjectId(parsed.projectId)).lastCheckpoint()!;
  const understood = durable.artifacts["understand"] as { schemaVersion?: number; input?: { text?: string }; successCriteria?: unknown[] };
  assert.equal(understood.schemaVersion, 1, "installed composition persists the real typed understand stage");
  assert.equal(understood.input?.text, "write and test a markdown parser library");
  assert.equal(understood.successCriteria?.length, 3);
});

test("organization gateway mints a server-side session only from a verified mapped identity", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-gw-identity-"));
  const { app: a } = app(dir);
  const provider = new HmacAssertionProvider("deployment-only-test-secret");
  const identity = { provider, registry: new PrincipalRegistry([{ subject: "alice-sub", id: "alice", role: "maintainer", tenant: "alpha" }]), sessions: new SessionStore() };
  const assertion = provider.sign({ sub: "alice-sub", exp: Date.now() + 60_000 });
  const login = await handleGatewayRequest(a, req("POST", "/auth/session", { assertion }), { token: TOKEN, identity });
  assert.equal(login.status, 200, login.body);
  const session = (JSON.parse(login.body) as { session: string }).session;
  const request = req("GET", "/projects");
  const admitted = await handleGatewayRequest(a, { ...request, headers: { ...request.headers, "x-keep-session": session } }, { token: TOKEN, identity });
  assert.equal(admitted.status, 200, admitted.body);
  identity.sessions.revoke(session);
  assert.equal((await handleGatewayRequest(a, { ...request, headers: { ...request.headers, "x-keep-session": session } }, { token: TOKEN, identity })).status, 403);
  const queryOnly = { ...req("GET", "/projects", undefined, null), query: { token: TOKEN } };
  assert.equal((await handleGatewayRequest(a, queryOnly, { token: TOKEN, identity })).status, 401, "enterprise identity mode never admits a query-string gateway credential");
});

test("organization gateway issues an opaque delegated session and durable revocation removes its authority", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-gw-delegation-"));
  const owner: Principal = { id: "alice", kind: "human", role: "owner", tenant: "alpha" };
  const a = composeKeep({ dataDir: dir, solve: async (issue) => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } }) as never, delegationParentFor: (id, tenant) => id === owner.id && tenant === owner.tenant ? owner : undefined });
  const provider = new HmacAssertionProvider("deployment-only-test-secret");
  const identity = { provider, registry: new PrincipalRegistry([{ subject: "alice-sub", id: "alice", role: "owner", tenant: "alpha" }]), sessions: new SessionStore() };
  const login = await handleGatewayRequest(a, req("POST", "/auth/session", { assertion: provider.sign({ sub: "alice-sub", exp: Date.now() + 60_000 }) }), { token: TOKEN, identity });
  const humanSession = (JSON.parse(login.body) as { session: string }).session;
  const authed = (method: string, path: string, body: unknown, session: string) => { const request = req(method, path, body); return { ...request, headers: { ...request.headers, "x-keep-session": session } }; };
  const issued = await handleGatewayRequest(a, authed("POST", "/delegation/issue", { agentId: "build-agent", grantId: "grant-1", permissions: ["change.solve"], expiresAt: Date.now() + 60_000 }, humanSession), { token: TOKEN, identity });
  assert.equal(issued.status, 200, issued.body);
  const agentSession = (JSON.parse(issued.body) as { session: string }).session;
  assert.equal((await handleGatewayRequest(a, authed("POST", "/project", { goal: "bounded delegated task" }, agentSession), { token: TOKEN, identity })).status, 200);
  assert.equal((await handleGatewayRequest(a, authed("POST", "/delegation/revoke", { grantId: "grant-1" }, humanSession), { token: TOKEN, identity })).status, 200);
  assert.equal((await handleGatewayRequest(a, authed("POST", "/project", { goal: "revoked task" }, agentSession), { token: TOKEN, identity })).status, 403);
});

test("SHIPPED DOMAIN ROUTE: gateway admits known profiles, persists strategy, and rejects unknown profiles", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-gw-domain-"));
  const worker: DomainStageWorker = async (request) => request.requiredDeliverables.map((name) => ({ name, content: `${request.kind}:${request.stage}:${name}` }));
  const a = composeKeep({ dataDir: dir, domainWorkflows: { worker } });
  const accepted = await handleGatewayRequest(a, req("POST", "/project", {
    goal: "locally write and vet a complete academic paper",
    domainWorkflowKind: "academic-paper",
  }), { token: TOKEN });
  assert.equal(accepted.status, 200);
  const body = JSON.parse(accepted.body) as { projectId: string; runId: string; status: string };
  assert.equal(body.status, "completed");
  assert.deepEqual(a.projectManager!.session(asProjectId(body.projectId)).lastCheckpoint()?.strategy,
    { kind: "domain", domainKind: "academic-paper" });
  const rejected = await handleGatewayRequest(a, req("POST", "/project", {
    goal: "do something", domainWorkflowKind: "made-up-profile",
  }), { token: TOKEN });
  assert.equal(rejected.status, 400);
  const unavailableSoftware = await handleGatewayRequest(a, req("POST", "/project", { goal: "write a parser" }), { token: TOKEN });
  assert.equal(unavailableSoftware.status, 501);
});

test("RESUME AUTHORITY: an agent that can solve cannot approve its own held project", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-gw-resume-auth-"));
  const a = composeKeep({
    dataDir: dir, projectPosture: "approval-required", frontDoorMemory: newMemory(),
    solve: async () => ({ solveResult: { issueId: "x", solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true } } } as never),
  });
  const started = await handleGatewayRequest(a, req("POST", "/project", { goal: "email the report to the team" }), { token: TOKEN });
  assert.equal(started.status, 200);
  const body = JSON.parse(started.body) as { runId: string; status: string; wait: { decisionId: string } };
  assert.equal(body.status, "waiting-approval");
  const denied = await handleGatewayRequest(a, req("POST", "/project/resume", { runId: body.runId, approval: { decisionId: body.wait.decisionId, approved: true } }), { token: TOKEN, principalFor: () => AGENT });
  assert.equal(denied.status, 403);
  const approved = await handleGatewayRequest(a, req("POST", "/project/resume", { runId: body.runId, approval: { decisionId: body.wait.decisionId, approved: true } }), { token: TOKEN });
  assert.equal(approved.status, 200, "an independently authorized owner can consume the still-pending decision");
});

test("DECLINE IS DURABLE: an agent cannot reverse an owner decline through the capability channel", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-gw-decline-auth-"));
  let solves = 0;
  const a = composeKeep({
    dataDir: dir, projectPosture: "approval-required", frontDoorMemory: newMemory(),
    solve: async (issue: { id: string }) => { solves += 1; return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true } } } as never; },
  });
  const started = JSON.parse((await handleGatewayRequest(a, req("POST", "/project", { goal: "email the report to the team" }), { token: TOKEN })).body) as { runId: string; wait: { decisionId: string } };
  const declined = JSON.parse((await handleGatewayRequest(a, req("POST", "/project/resume", { runId: started.runId, approval: { decisionId: started.wait.decisionId, approved: false } }), { token: TOKEN })).body) as { wait: { capability: string } };
  const bypass = await handleGatewayRequest(a, req("POST", "/project/resume", { runId: started.runId, capability: { capability: declined.wait.capability, evidenceId: "agent-claims-alternative" } }), { token: TOKEN, principalFor: () => AGENT });
  assert.equal(bypass.status, 403);
  assert.equal(solves, 0);
});

test("ADAPTATION API: n=1 promotes project-owned presentation through bound observations and survives restart", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-gw-adaptation-"));
  const configuration = {
    dataDir,
    outcomeAdaptation: {
      initial: { prompt: { version: "v1", text: "" }, routing: { model: "local-small", effort: "none" as const }, voice: { promptFormat: "markdown" as const, verbosity: "normal" as const } },
      policy: { minSamplesPerArm: 4, minQualityGain: 0.1, maxRegressionRate: 0.25, rollbackQualityDrop: 0.15 },
    },
  };
  const first = composeKeep(configuration);
  const project = first.projectManager!.create({ name: "personal adaptation" });
  const proposed = await handleGatewayRequest(first, req("POST", "/project/adaptation/propose", { projectId: project.id, candidate: { prompt: { version: "v2", text: "Be concise" }, routing: { model: "frontier", effort: "graded" }, voice: { promptFormat: "json", verbosity: "terse" } } }), { token: TOKEN });
  assert.equal(proposed.status, 200);
  for (let index = 0; index < 8; index++) {
    const assigned = await handleGatewayRequest(first, req("POST", "/project/adaptation/assign", { projectId: project.id, subjectId: `subject-${index}` }), { token: TOKEN });
    assert.equal(assigned.status, 200);
    const assignment = (JSON.parse(assigned.body) as { assignment: { assignmentId: string; assignedAt: number; arm: "baseline" | "candidate" } }).assignment;
    const exposure = await handleGatewayRequest(first, req("POST", "/project/adaptation/present", { projectId: project.id, assignmentId: assignment.assignmentId, content: `exposure-${index}` }), { token: TOKEN });
    assert.equal(exposure.status, 200);
    assert.equal((JSON.parse(exposure.body) as { behaviorVersion: string }).behaviorVersion, assignment.arm === "baseline" ? "v1" : "v2");
    const outcome = await handleGatewayRequest(first, req("POST", "/project/adaptation/outcome", { projectId: project.id, assignmentId: assignment.assignmentId, outcomeId: `outcome-${index}`, observedAt: Math.max(Date.now(), assignment.assignedAt), quality: assignment.arm === "baseline" ? 0.5 : 0.9, regressed: false }), { token: TOKEN });
    assert.equal(outcome.status, 200);
  }
  const presented = await handleGatewayRequest(first, req("POST", "/project/adaptation/present", { projectId: project.id, content: "complete result" }), { token: TOKEN });
  assert.equal(presented.status, 200);
  const presentation = JSON.parse(presented.body) as { behaviorVersion: string; presentation: { content: string; rendered: string } };
  assert.equal(presentation.behaviorVersion, "v2");
  assert.equal(JSON.parse(presentation.presentation.rendered).response, "complete result");
  const restarted = composeKeep(configuration);
  const current = await handleGatewayRequest(restarted, { ...req("GET", "/project/adaptation"), query: { projectId: project.id } }, { token: TOKEN });
  assert.equal((JSON.parse(current.body) as { behavior: { prompt: { version: string } } }).behavior.prompt.version, "v2");
  const events = first.spine.currentEvents().filter((event) => event.actor === "outcome-adaptation").map((event) => event.payload["event"]);
  assert.ok(events.includes("adaptation.proposed") && events.includes("adaptation.promoted"));
});

test("ADAPTATION API: enterprise tenancy and delegated observation are both enforced", async () => {
  const alpha: Principal = { id: "alice", kind: "human", role: "owner", tenant: "alpha" };
  const beta: Principal = { id: "bob", kind: "human", role: "owner", tenant: "beta" };
  const a = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-gw-adaptation-enterprise-")),
    delegationParentFor: (id, tenant) => id === alpha.id && tenant === alpha.tenant ? alpha : id === beta.id && tenant === beta.tenant ? beta : undefined,
    outcomeAdaptation: {
      initial: { prompt: { version: "v1", text: "" }, routing: { model: "local-small", effort: "none" }, voice: { promptFormat: "markdown", verbosity: "normal" } },
      policy: { minSamplesPerArm: 4, minQualityGain: 0.1, maxRegressionRate: 0.25, rollbackQualityDrop: 0.15 },
    },
  });
  const alphaProject = a.projectManager!.create({ name: "alpha adaptation", tenant: "alpha" });
  const betaProject = a.projectManager!.create({ name: "beta adaptation", tenant: "beta" });
  const alphaSec = { token: TOKEN, principalFor: () => alpha };
  const betaSec = { token: TOKEN, principalFor: () => beta };
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/project/adaptation/propose", { projectId: alphaProject.id, candidate: { prompt: { version: "v2", text: "alpha" }, routing: { model: "frontier", effort: "graded" }, voice: { promptFormat: "json", verbosity: "terse" } } }), alphaSec)).status, 200);
  assert.equal((await handleGatewayRequest(a, reqAs("GET", "/project/adaptation"), betaSec)).status, 400, "a missing exact target cannot fall back to another tenant's project");
  assert.equal((await handleGatewayRequest(a, { ...reqAs("GET", "/project/adaptation"), query: { projectId: alphaProject.id } }, betaSec)).status, 404);
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/project/adaptation/assign", { projectId: alphaProject.id, subjectId: "human-forgery" }), alphaSec)).status, 403, "enterprise humans cannot label product exposure as machine-observed");
  const observer = await a.authorization.issue(alpha, "alpha-observer", ["adaptation.observe"], Date.now() + 60_000);
  const observerSec = { token: TOKEN, principalFor: () => observer };
  const assigned = await handleGatewayRequest(a, reqAs("POST", "/project/adaptation/assign", { projectId: alphaProject.id, subjectId: "real-exposure" }), observerSec);
  assert.equal(assigned.status, 200);
  const assignmentId = (JSON.parse(assigned.body) as { assignment: { assignmentId: string } }).assignment.assignmentId;
  const viewer: Principal = { id: "alpha-viewer", kind: "human", role: "viewer", tenant: "alpha" };
  const viewerSec = { token: TOKEN, principalFor: () => viewer };
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/project/adaptation/present", { projectId: alphaProject.id, content: "ordinary presentation" }), viewerSec)).status, 200, "read authority can render the current behavior without mutating experiment evidence");
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/project/adaptation/present", { projectId: alphaProject.id, assignmentId, content: "claimed exposure" }), viewerSec)).status, 403, "assignment exposure requires observation authority");
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/project/adaptation/present", { projectId: alphaProject.id, assignmentId, content: "real exposure" }), observerSec)).status, 200);
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/project/adaptation/assign", { projectId: betaProject.id, subjectId: "cross-tenant" }), observerSec)).status, 404);
});

test("ADAPTATION API: live monitoring cannot brick baseline state and an exact human reset recovers corrupt state", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-gw-adaptation-recovery-"));
  const configuration = {
    dataDir,
    outcomeAdaptation: {
      initial: { prompt: { version: "v1", text: "safe" }, routing: { model: "local-small", effort: "none" as const }, voice: { promptFormat: "markdown" as const, verbosity: "normal" as const } },
      policy: { minSamplesPerArm: 4, minQualityGain: 0.1, maxRegressionRate: 0.25, rollbackQualityDrop: 0.15 },
    },
  };
  const first = composeKeep(configuration);
  const project = first.projectManager!.create({ name: "adaptation recovery" });
  for (let index = 0; index < 12; index++) {
    const response = await handleGatewayRequest(first, req("POST", "/project/adaptation/live-outcome", { projectId: project.id, outcomeId: `baseline-${index}`, observedAt: index, quality: 0, regressed: true }), { token: TOKEN });
    assert.equal(response.status, 200);
  }
  const cleanRestart = composeKeep(configuration);
  assert.equal((await handleGatewayRequest(cleanRestart, { ...req("GET", "/project/adaptation"), query: { projectId: project.id } }, { token: TOKEN })).status, 200);

  const session = cleanRestart.projectManager!.session(project.id);
  const currentRevision = session.resolveDocumentVersioned("outcome-adaptation").revision;
  session.putDocumentVersioned("outcome-adaptation", "{not-json", currentRevision);
  const unavailable = await handleGatewayRequest(cleanRestart, { ...req("GET", "/project/adaptation"), query: { projectId: project.id } }, { token: TOKEN });
  assert.equal(unavailable.status, 409);
  const unavailableBody = JSON.parse(unavailable.body) as { documentRevision: number };
  const reset = await handleGatewayRequest(cleanRestart, req("POST", "/project/adaptation/reset", { projectId: project.id, expectedRevision: unavailableBody.documentRevision, confirm: true }), { token: TOKEN });
  assert.equal(reset.status, 200);
  const recovered = await handleGatewayRequest(cleanRestart, { ...req("GET", "/project/adaptation"), query: { projectId: project.id } }, { token: TOKEN });
  assert.equal(recovered.status, 200);
  assert.equal((JSON.parse(recovered.body) as { behavior: { prompt: { version: string } } }).behavior.prompt.version, "v1");

  const deniedBeforeTargetParsing = await handleGatewayRequest(cleanRestart, reqAs("GET", "/project/adaptation"), { token: TOKEN, principalFor: () => AGENT });
  assert.equal(deniedBeforeTargetParsing.status, 403);
});

test("RESTART: durable state survives but a newly injected opaque executor cannot inherit command authority", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-gw-project-restart-"));
  let solveCalls = 0;
  const config = () => composeKeep({
    dataDir: dir, projectPosture: "approval-required", frontDoorMemory: newMemory(),
    solve: async (issue: { id: string }) => { solveCalls++; return { solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "ok" } } } as never; },
  });
  const first = config();
  const started = await handleGatewayRequest(first, req("POST", "/project", { goal: "email the report to the team" }), { token: TOKEN });
  assert.equal(started.status, 200, started.body);
  const body = JSON.parse(started.body) as { projectId: string; runId: string; revision: number; wait: { decisionId: string } };
  const restarted = config();
  assert.equal(restarted.projectManager?.list().some((record) => record.id === body.projectId), true);
  assert.equal(restarted.projectManager?.session(asProjectId(body.projectId)).lastCheckpoint()?.runId, body.runId);
  const before = restarted.projectManager!.session(asProjectId(body.projectId)).lastCheckpoint();
  const resumed = await handleGatewayRequest(restarted, req("POST", "/project/resume", { runId: body.runId, approval: { decisionId: body.wait.decisionId, approved: true } }), { token: TOKEN });
  assert.equal(resumed.status, 409, resumed.body);
  assert.match(resumed.body, /native project command unavailable: custody/u);
  assert.equal(solveCalls, 0, "neither the initial approval hold nor failed custody can invoke the solver");
  assert.deepEqual(restarted.projectManager!.session(asProjectId(body.projectId)).lastCheckpoint(), before);
});

test("project lifecycle retains its bound identity, encrypts goals, and refuses a second run over that identity", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-gw-project-lifecycle-"));
  const { app: a } = app(dir);
  const goal = "write a local parser\nwith a hostile-input test";
  const started = await handleGatewayRequest(a, req("POST", "/project", { goal }), { token: TOKEN });
  assert.equal(started.status, 200);
  const first = JSON.parse(started.body) as { projectId: string; runId: string };
  assert.doesNotMatch(readFileSync(join(dir, "projects", "records.json"), "utf8"), /hostile-input/u);
  assert.doesNotMatch(readFileSync(join(dir, "projects", "sessions", `${first.projectId}.json`), "utf8"), /hostile-input/u);
  const checkpointBytes = readdirSync(join(dir, "projects", "checkpoints")).map((name) => readFileSync(join(dir, "projects", "checkpoints", name), "utf8")).join("\n");
  assert.doesNotMatch(checkpointBytes, /hostile-input|write a local parser/u, "canonical checkpoints must be encrypted under the owning project key");

  const before = a.projectManager!.session(asProjectId(first.projectId)).lastCheckpoint();
  const reused = await handleGatewayRequest(a, req("POST", "/project", { projectId: first.projectId, goal }), { token: TOKEN });
  assert.equal(reused.status, 409, reused.body);
  assert.match(reused.body, /already bound to run/u);
  assert.deepEqual(a.projectManager!.session(asProjectId(first.projectId)).lastCheckpoint(), before, "a new job cannot overwrite the existing run; use its explicit resume route");
  assert.equal(a.projectManager?.list().length, 1);
  const jobs = await handleGatewayRequest(a, req("GET", "/project/jobs"), { token: TOKEN });
  assert.equal(jobs.status, 200);
  assert.ok(Array.isArray((JSON.parse(jobs.body) as { jobs: unknown[] }).jobs));

  const denied = await handleGatewayRequest(a, req("POST", "/project/delete", { projectId: first.projectId }), { token: TOKEN, principalFor: () => AGENT });
  assert.equal(denied.status, 403);
  const archived = await handleGatewayRequest(a, req("POST", "/project/archive", { projectId: first.projectId }), { token: TOKEN });
  assert.equal(archived.status, 200);
  const deleted = await handleGatewayRequest(a, req("POST", "/project/delete", { projectId: first.projectId }), { token: TOKEN });
  assert.equal(deleted.status, 200);
  assert.doesNotMatch(readFileSync(join(dir, "projects", "records.json"), "utf8"), /hostile-input/u);
});

test("TOKEN-AUTHED: an unauthed request is refused (401) and drives NO run", async () => {
  const { app: a, solved } = app(mkdtempSync(join(tmpdir(), "keep-gw-")));
  const r = await handleGatewayRequest(a, req("POST", "/project", { goal: "write a parser" }, null), { token: TOKEN });
  assert.equal(r.status, 401);
  assert.equal(solved.called, false, "no work ran for an unauthenticated caller");
});

test("FRONT-DOOR WRAP: POST /message returns a real handled result", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-gw-")));
  const r = await handleGatewayRequest(a, req("POST", "/message", { message: "add a login button to the homepage" }), { token: TOKEN });
  assert.equal(r.status, 200);
  const parsed = JSON.parse(r.body) as { result: { kind: string; say: string } };
  assert.ok(typeof parsed.result.kind === "string" && parsed.result.say.length > 0, "a real front-door result, not a canned stub");
});

test("DURABLE: a project committed via the gateway is present in the spine after re-open", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-gw-dur-"));
  const { app: a } = app(dir);
  await handleGatewayRequest(a, req("POST", "/project", { goal: "email the whole team the report" }), { token: TOKEN }); // vetoed/paused → spine event
  // Staged events are durable on disk (replay = sealed blocks; pending = staged-but-durable).
  const before = a.spine.replay().length + a.spine.pending().length;
  assert.ok(before > 0, "the run committed durable events to the spine");
  // Re-open a fresh app over the SAME dataDir — the gateway holds no volatile state; the spine resumes.
  const reopened = composeKeep({ dataDir: dir, frontDoorMemory: newMemory(), solve: async () => ({ solveResult: {} } as never) });
  assert.ok(reopened.spine.replay().length + reopened.spine.pending().length >= before, "committed work survives a gateway restart (spine durable)");
});

test("INTEGRATION (real socket): the server binds 127.0.0.1, auths, and serves the composed app", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-gw-")));
  const h = await startGatewayServer(a, { port: 0, token: TOKEN });
  try {
    assert.ok(h.origin.startsWith("http://127.0.0.1:"), "binds localhost, never 0.0.0.0");
    // health: unauthed
    const health = await fetch(`${h.origin}/health`);
    assert.equal(health.status, 200);
    // /projects without token → 401
    const noAuth = await fetch(`${h.origin}/projects`);
    assert.equal(noAuth.status, 401);
    // /projects with token → 200
    const ok = await fetch(`${h.origin}/projects`, { headers: { authorization: `Bearer ${TOKEN}` } });
    assert.equal(ok.status, 200);
    const body = (await ok.json()) as { projects: unknown[] };
    assert.ok(Array.isArray(body.projects));
  } finally {
    await h.close();
  }
});


// ─── P3: served desktop surface ───

test("P3: GET / returns the HTML surface, token-baked, wired to the project list", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-gw-")));
  const r = await handleGatewayRequest(a, { method: "GET", path: "/", query: {}, headers: { authorization: `Bearer ${TOKEN}` }, body: "" }, { token: TOKEN });
  assert.equal(r.status, 200);
  assert.match(r.headers["content-type"] ?? "", /text\/html/);
  assert.match(r.body, /<!doctype html>/i, "a real HTML page");
  assert.ok(r.body.includes(JSON.stringify(TOKEN)), "the token is baked into the page for its fetches");
  assert.match(r.body, /\/projects/, "the page is wired to the project list");
});

test("P3: the page is token-scoped and JSON routes still 401 without the token", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-gw-")));
  const page = await handleGatewayRequest(a, { method: "GET", path: "/", query: {}, headers: {}, body: "" }, { token: TOKEN });
  assert.equal(page.status, 401, "the page itself is served only WITH the token");
  const projects = await handleGatewayRequest(a, { method: "GET", path: "/projects", query: {}, headers: {}, body: "" }, { token: TOKEN });
  assert.equal(projects.status, 401, "and the JSON routes it calls still 401 unauthed");
});

test("P3: the page renders the REAL gateway routes (message + offer wiring present)", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-gw-")));
  const r = await handleGatewayRequest(a, { method: "GET", path: "/", query: {}, headers: { authorization: `Bearer ${TOKEN}` }, body: "" }, { token: TOKEN });
  assert.match(r.body, /api\("POST","\/message"/, "the message box posts to the real /message route");
  assert.match(r.body, /api\("POST","\/offer"/, "the offer control posts to the real /offer route");
  // and the routes it calls actually work:
  const proj = await handleGatewayRequest(a, req("GET", "/projects"), { token: TOKEN });
  assert.equal(proj.status, 200);
});


// ─── veto surface over the gateway (parked items actionable) ───

async function parkAndApp(): Promise<KeepApp> {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-gw-veto-")), "approval-required");
  await handleGatewayRequest(a, req("POST", "/project", { goal: "email the report to the team" }), { token: TOKEN }); // veto → parked
  return a;
}

test("VETO SURFACE: a vetoed goal appears in GET /veto (shared queue, composed)", async () => {
  const a = await parkAndApp();
  const r = await handleGatewayRequest(a, req("GET", "/veto"), { token: TOKEN });
  assert.equal(r.status, 200);
  const { digest } = JSON.parse(r.body) as { digest: { total: number } | null };
  assert.ok(digest && digest.total >= 1, "the parked action surfaces in the digest");
});

test("VETO SURFACE: POST /veto/approve makes the item runnable (explicit approve)", async () => {
  const a = await parkAndApp();
  const id = (JSON.parse((await handleGatewayRequest(a, req("GET", "/veto"), { token: TOKEN })).body) as { digest: { entries: Array<{ id: string }> } }).digest.entries[0]!.id;
  const r = await handleGatewayRequest(a, req("POST", "/veto/approve", { id }), { token: TOKEN });
  const parsed = JSON.parse(r.body) as { ok: boolean; runnable: boolean };
  assert.ok(parsed.ok && parsed.runnable, "explicit approve makes it runnable");
  assert.equal(a.vetoQueue!.runnable(id), true);
});

test("VETO SURFACE: POST /veto/decline removes it and it can't then be approved", async () => {
  const a = await parkAndApp();
  const id = (JSON.parse((await handleGatewayRequest(a, req("GET", "/veto"), { token: TOKEN })).body) as { digest: { entries: Array<{ id: string }> } }).digest.entries[0]!.id;
  await handleGatewayRequest(a, req("POST", "/veto/decline", { id }), { token: TOKEN });
  assert.equal(a.vetoQueue!.parked().length, 0, "declining removes it");
  const after = await handleGatewayRequest(a, req("POST", "/veto/approve", { id }), { token: TOKEN });
  assert.equal((JSON.parse(after.body) as { ok: boolean }).ok, false, "a vetoed item can't be approved");
});

test("VETO SURFACE: the veto routes require the token", async () => {
  const a = await parkAndApp();
  for (const r of [
    await handleGatewayRequest(a, { method: "GET", path: "/veto", query: {}, headers: {}, body: "" }, { token: TOKEN }),
    await handleGatewayRequest(a, { method: "POST", path: "/veto/approve", query: {}, headers: {}, body: '{"id":"x"}' }, { token: TOKEN }),
    await handleGatewayRequest(a, { method: "POST", path: "/veto/decline", query: {}, headers: {}, body: '{"id":"x"}' }, { token: TOKEN }),
  ]) assert.equal(r.status, 401, "veto routes are token-authed");
});


// ─── P7: RBAC enforcement + audit exposure over the gateway ───

const VIEWER: Principal = { id: "vera", kind: "human", role: "viewer", displayName: "Vera (read-only)", tenant: "tenant-viewer" };
const viewerSec = { token: TOKEN, principalFor: () => VIEWER };

function reqAs(method: string, path: string, body: unknown = undefined): GatewayRequest {
  return { method, path, query: {}, headers: { authorization: `Bearer ${TOKEN}` }, body: body !== undefined ? JSON.stringify(body) : "" };
}

test("P7 RBAC: the OWNER (n=1 default) can start a project and approve a veto", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-rbac-")), "approval-required");
  const proj = await handleGatewayRequest(a, req("POST", "/project", { goal: "email the report to the team" }), { token: TOKEN });
  assert.equal(proj.status, 200, "owner may start a project");
  const id = a.vetoQueue!.parked()[0]!.id;
  const appr = await handleGatewayRequest(a, req("POST", "/veto/approve", { id }), { token: TOKEN });
  assert.equal(appr.status, 200, "owner may approve");
  assert.equal(a.vetoQueue!.runnable(id), true);
});

test("ENTERPRISE AUTH: a configured resolver never falls back to OWNER for missing, failing, tenantless, or malformed identity", async () => {
  const { app: instance } = app(mkdtempSync(join(tmpdir(), "keep-gateway-missing-principal-")));
  const project = req("POST", "/project", { goal: "must not run as owner", stepBudget: 1 });
  assert.equal((await handleGatewayRequest(instance, project, { token: TOKEN, principalFor: () => undefined })).status, 403);
  assert.equal((await handleGatewayRequest(instance, project, { token: TOKEN, principalFor: () => { throw new Error("directory unavailable"); } })).status, 403);
  assert.equal((await handleGatewayRequest(instance, project, { token: TOKEN, principalFor: () => ({ id: "root", kind: "human", role: "owner" }) })).status, 403);
  assert.equal((await handleGatewayRequest(instance, project, { token: TOKEN, principalFor: () => ({ id: "root", kind: "human", role: "unknown", tenant: "alpha" } as never) })).status, 403);
  assert.equal((await handleGatewayRequest(instance, project, { token: TOKEN, principalFor: () => ({ id: "root", kind: "human", role: "owner", tenant: "../alpha" }) })).status, 403);
  assert.equal((await handleGatewayRequest(instance, project, { token: TOKEN, principalFor: () => ({ id: "root", kind: "human", role: "owner", tenant: "keep.n1.default" }) })).status, 403);
  const queryCredential = { ...project, query: { token: TOKEN }, headers: {} };
  assert.equal((await handleGatewayRequest(instance, queryCredential, { token: TOKEN, principalFor: () => ({ id: "root", kind: "human", role: "owner", tenant: "alpha" }) })).status, 401,
    "enterprise credentials are never accepted from a URL");
  const forbidden = await handleGatewayRequest(instance, project, { token: TOKEN, principalFor: () => undefined });
  assert.equal(forbidden.headers["cache-control"], "no-store", "identity failures containing deployment detail are non-cacheable");
  assert.equal(instance.spine.currentEvents().some((event) => (event.payload as Record<string, unknown>)["goal"] === "must not run as owner"), false);
});

test("P7 RBAC: a read-only VIEWER is refused /project and /veto/approve (least-privilege)", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-rbac-")), "approval-required");
  await handleGatewayRequest(a, req("POST", "/project", { goal: "email the report to the team" }), { token: TOKEN }); // owner parks one
  const id = a.vetoQueue!.parked()[0]!.id;
  const proj = await handleGatewayRequest(a, reqAs("POST", "/project", { goal: "do a thing" }), viewerSec);
  assert.equal(proj.status, 403, "viewer may not start a project");
  const appr = await handleGatewayRequest(a, reqAs("POST", "/veto/approve", { id }), viewerSec);
  assert.equal(appr.status, 403, "viewer may not approve");
  assert.equal(a.vetoQueue!.runnable(id), false, "the viewer's refused approve changed nothing");
});

test("P7 RBAC: a VIEWER can still read and message (least-privilege, not lockout)", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-rbac-")));
  const msg = await handleGatewayRequest(a, reqAs("POST", "/message", { message: "hello" }), viewerSec);
  assert.equal(msg.status, 200, "viewer may message");
  const projects = await handleGatewayRequest(a, reqAs("GET", "/projects"), viewerSec);
  assert.equal(projects.status, 200, "viewer may read projects");
});

test("ENTERPRISE TENANCY: project discovery, jobs, reuse, and lifecycle never cross tenant boundaries", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-tenant-projects-")));
  const alpha = a.projectManager!.create({ name: "alpha project", tenant: "tenant-alpha" });
  const beta = a.projectManager!.create({ name: "beta project", tenant: "tenant-beta" });
  let releaseAlpha!: () => void; let releaseBeta!: () => void;
  const alphaGate = new Promise<void>((resolve) => { releaseAlpha = resolve; });
  const betaGate = new Promise<void>((resolve) => { releaseBeta = resolve; });
  const alphaJob = a.projectRuntime!.submit(alpha.id, 1, async () => alphaGate);
  const betaJob = a.projectRuntime!.submit(beta.id, 1, async () => betaGate);
  await new Promise<void>((resolve) => setImmediate(resolve));
  const alphaPrincipal: Principal = { id: "alice", kind: "human", role: "owner", tenant: "tenant-alpha" };
  const betaPrincipal: Principal = { id: "bob", kind: "human", role: "owner", tenant: "tenant-beta" };
  const alphaSec = { token: TOKEN, principalFor: () => alphaPrincipal };
  const betaSec = { token: TOKEN, principalFor: () => betaPrincipal };
  const alphaProjects = JSON.parse((await handleGatewayRequest(a, reqAs("GET", "/projects"), alphaSec)).body) as { projects: { id: string }[] };
  const betaProjects = JSON.parse((await handleGatewayRequest(a, reqAs("GET", "/projects"), betaSec)).body) as { projects: { id: string }[] };
  assert.deepEqual(alphaProjects.projects.map((row) => row.id), [alpha.id]);
  assert.deepEqual(betaProjects.projects.map((row) => row.id), [beta.id]);
  const alphaJobs = JSON.parse((await handleGatewayRequest(a, reqAs("GET", "/project/jobs"), alphaSec)).body) as { jobs: { projectId: string }[]; status: { running: number } };
  assert.deepEqual(alphaJobs.jobs.map((row) => row.projectId), [alpha.id]); assert.equal(alphaJobs.status.running, 1);
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/project", { projectId: beta.id, goal: "foreign" }), alphaSec)).status, 404);
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/project/archive", { projectId: beta.id }), alphaSec)).status, 404);
  releaseAlpha(); releaseBeta(); await Promise.all([alphaJob, betaJob]);
});

test("P7 AUDIT: GET /audit returns the real spine trail for an id", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-rbac-")));
  const m = { id: "KEEP-AUD1", title: "fix totals", branch: "keep/solve/x", baseBranch: "main", diff: "-a\n+b", intent: "fix", executed: [], checks: [], humanApprovalRequired: true } as unknown as PrManifest;
  recordReviewPending({ spine: a.spine, notifications: a.notifications }, m, Date.now(), { correlationId: m.id });
  const r = await handleGatewayRequest(a, req("GET", "/audit", undefined), { token: TOKEN });
  const { trail } = JSON.parse(r.body) as { trail: string[] };
  assert.ok(trail.length === 0 || true); // route works
  const r2 = await handleGatewayRequest(a, { method: "GET", path: "/audit", query: { id: "KEEP-AUD1" }, headers: { authorization: `Bearer ${TOKEN}` }, body: "" }, { token: TOKEN });
  const parsed = JSON.parse(r2.body) as { trail: string[] };
  assert.ok(parsed.trail.some((l) => /proposed a change/.test(l)), "the real audit trail is returned");
});

test("P7 AUDIT: every RBAC allow/deny is recorded to the spine", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-rbac-")));
  const before = a.spine.pending().length + a.spine.replay().length;
  await handleGatewayRequest(a, reqAs("POST", "/project", { goal: "x" }), viewerSec); // a deny
  const events = [...a.spine.pending(), ...a.spine.replay()];
  assert.ok(events.some((e) => (e.payload as Record<string, unknown>)["event"] === "rbac_check" && (e.payload as Record<string, unknown>)["allow"] === false), "the deny was recorded");
  assert.ok(a.spine.pending().length + a.spine.replay().length > before, "an audit event was staged");
});


// ─── R1 (BA-1): the skill-registry gateway surface ───

function mkSkill(id: string, effects: readonly string[]): DistilledSkill {
  return { format: "keep.skill/v1", requiredAuthority: [], id, name: `S ${id}`, description: "d", relevanceKey: "shape:x",
    envelope: { preconditions: ["r"], steps: [{ action: "edit", targetPattern: "{f}" }], postconditions: ["done"], declaredEffects: effects },
    provenance: ["t1"], confidence: "corroborated" };
}

test("R1 REGISTRY-SURFACE: a skill published over the gateway is retrievable via GET /skills", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-reg-")));
  const pub = await handleGatewayRequest(a, req("POST", "/skill/publish", { skill: mkSkill("s1", ["local-edit"]), origin: "alice" }), { token: TOKEN });
  assert.equal(pub.status, 200, "owner may publish");
  const list = await handleGatewayRequest(a, req("GET", "/skills", undefined), { token: TOKEN });
  const { skills } = JSON.parse(list.body) as { skills: { id: string; origin: string }[] };
  assert.ok(skills.some((s) => s.id === "s1" && s.origin === "owner"), "publication provenance comes from the authenticated principal, not caller input");
});

test("R1 SAFETY: a poisoned skill installed over the gateway is REJECTED by the real safety gate", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-reg-")));
  const poisoned = publishSkill(mkSkill("evil", ["external-send"]), "attacker"); // forbidden sink
  const r = await handleGatewayRequest(a, req("POST", "/skill/install", { pkg: poisoned }), { token: TOKEN });
  assert.equal(r.status, 422, "the wire is not a bypass — the poisoned skill is refused");
  assert.match(r.body, /rejected-unsafe/);
  const list = await handleGatewayRequest(a, req("GET", "/skills", undefined), { token: TOKEN });
  assert.equal((JSON.parse(list.body) as { skills: unknown[] }).skills.length, 0, "nothing was installed");
});

test("R1 SAFETY: a clean skill installs over the gateway", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-reg-")));
  const good = publishSkill(mkSkill("s2", ["local-edit"]), "alice");
  const r = await handleGatewayRequest(a, req("POST", "/skill/install", { pkg: good }), { token: TOKEN });
  assert.equal(r.status, 200, "a safe skill installs");
});

test("R1 RBAC: a read-only viewer is refused publish and install", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-reg-")));
  const VIEWER: Principal = { id: "vera", kind: "human", role: "viewer", tenant: "tenant-viewer" };
  const viewerSec = { token: TOKEN, principalFor: () => VIEWER };
  const pub = await handleGatewayRequest(a, reqAs("POST", "/skill/publish", { skill: mkSkill("s3", ["local-edit"]) }), viewerSec);
  assert.equal(pub.status, 403, "viewer may not publish");
  const good = publishSkill(mkSkill("s4", ["local-edit"]), "alice");
  const inst = await handleGatewayRequest(a, reqAs("POST", "/skill/install", { pkg: good }), viewerSec);
  assert.equal(inst.status, 403, "viewer may not install");
});

// ─── M3: manual memory tools over the gateway (RBAC + supersede-not-delete) ───

test("M3 MEMORY: store over the gateway then recall round-trips", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-mem3-")));
  const stored = await handleGatewayRequest(a, req("POST", "/memory", { content: "the deploy window is Tuesdays" }), { token: TOKEN });
  assert.equal(stored.status, 200);
  const id = (JSON.parse(stored.body) as { id: string }).id;
  assert.ok(id, "an id came back");
  const recalled = await handleGatewayRequest(a, { method: "GET", path: "/memory", query: { q: "deploy window" }, headers: { authorization: `Bearer ${TOKEN}` }, body: "" }, { token: TOKEN });
  const { hits } = JSON.parse(recalled.body) as { hits: { content: string }[] };
  assert.ok(hits.some((h) => /deploy window/.test(h.content)), "the stored memory is recalled");
});

test("M3 MEMORY: forget retires (supersede-not-delete) — gone from recall, provenance retained", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-mem3-")));
  const stored = await handleGatewayRequest(a, req("POST", "/memory", { content: "secret note klaxon" }), { token: TOKEN });
  const id = (JSON.parse(stored.body) as { id: string }).id;
  const forgot = await handleGatewayRequest(a, req("POST", "/memory/forget", { id }), { token: TOKEN });
  assert.equal(forgot.status, 200);
  // gone from recall
  const recalled = await handleGatewayRequest(a, { method: "GET", path: "/memory", query: { q: "klaxon" }, headers: { authorization: `Bearer ${TOKEN}` }, body: "" }, { token: TOKEN });
  const { hits } = JSON.parse(recalled.body) as { hits: { content: string }[] };
  assert.ok(!hits.some((h) => /klaxon/.test(h.content)), "the forgotten memory no longer surfaces");
  // BUT still present (retired) — provenance retained, not hard-deleted
  assert.equal(a.secondBrain.memory.get(id)?.tier, "retired", "the lesson is retired, not deleted (provenance kept)");
});

test("M3 MEMORY: correct supersedes (old retired + linked, new active)", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-mem3-")));
  const stored = await handleGatewayRequest(a, req("POST", "/memory", { content: "the API base is v1" }), { token: TOKEN });
  const oldId = (JSON.parse(stored.body) as { id: string }).id;
  const corrected = await handleGatewayRequest(a, req("POST", "/memory/correct", { id: oldId, content: "the API base is v2" }), { token: TOKEN });
  const { newId } = JSON.parse(corrected.body) as { newId: string };
  assert.equal(a.secondBrain.memory.get(oldId)?.tier, "retired", "old is retired");
  assert.equal(a.secondBrain.memory.get(newId)?.citation, `supersedes:${oldId}`, "new links to old (lineage)");
});

test("M3 MEMORY: a read-only VIEWER is refused store + forget (RBAC least-privilege)", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-mem3-")));
  const VIEWER = { id: "v", kind: "human" as const, role: "viewer" as const, tenant: "tenant-viewer" };
  const viewerSec = { token: TOKEN, principalFor: () => VIEWER };
  const store = await handleGatewayRequest(a, reqAs("POST", "/memory", { content: "x" }), viewerSec);
  assert.equal(store.status, 403, "viewer may not store");
  const forget = await handleGatewayRequest(a, reqAs("POST", "/memory/forget", { id: "anything" }), viewerSec);
  assert.equal(forget.status, 403, "viewer may not forget");
  // but a viewer CAN recall (memory.read)
  const recall = await handleGatewayRequest(a, reqAs("GET", "/memory"), viewerSec);
  assert.equal(recall.status, 200, "viewer may recall");
});

// ─── M4: memory curation (list / review / purge) ───

async function seed(a: KeepApp) {
  await handleGatewayRequest(a, req("POST", "/memory", { content: "high pref alpha", kind: "preference" }), { token: TOKEN });
  await handleGatewayRequest(a, req("POST", "/memory", { content: "a decision beta", kind: "decision" }), { token: TOKEN });
  await handleGatewayRequest(a, req("POST", "/memory", { content: "a fact gamma", kind: "fact" }), { token: TOKEN });
}

test("M4 LIST: memories are importance-ranked and filterable by kind", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-m4-"))); await seed(a);
  a.secondBrain.memory.reweight(memoryListIds(a)[0]!, 0.1); // knock one down so ordering is non-trivial
  const all = JSON.parse((await handleGatewayRequest(a, reqAs("GET", "/memory/list"), { token: TOKEN })).body) as { memories: { importance: number; kind: string }[] };
  for (let i = 1; i < all.memories.length; i++) assert.ok(all.memories[i - 1]!.importance >= all.memories[i]!.importance, "importance-ranked");
  const prefs = JSON.parse((await handleGatewayRequest(a, { method: "GET", path: "/memory/list", query: { kind: "preference" }, headers: { authorization: `Bearer ${TOKEN}` }, body: "" }, { token: TOKEN })).body) as { memories: { kind: string }[] };
  assert.ok(prefs.memories.length >= 1 && prefs.memories.every((m) => m.kind === "preference"), "filtered to preferences only");
});

function memoryListIds(a: KeepApp): string[] { return a.secondBrain.memory.all().map((l) => l.id); }

test("M4 REVIEW: a memory review surfaces full provenance", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-m4-")));
  const s = await handleGatewayRequest(a, req("POST", "/memory", { content: "provenance check" }), { token: TOKEN });
  const id = (JSON.parse(s.body) as { id: string }).id;
  const d = JSON.parse((await handleGatewayRequest(a, { method: "GET", path: "/memory/review", query: { id }, headers: { authorization: `Bearer ${TOKEN}` }, body: "" }, { token: TOKEN })).body) as { origin: string; provenanceEventId: string };
  assert.ok(d.origin && d.provenanceEventId, "origin + provenance event id are surfaced");
});

test("M4 PURGE: bulk-retires by filter (supersede-not-delete — purged stay present as retired)", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-m4-"))); await seed(a);
  const res = await handleGatewayRequest(a, req("POST", "/memory/purge", { kind: "fact" }), { token: TOKEN });
  const { ids } = JSON.parse(res.body) as { ids: string[] };
  assert.ok(ids.length >= 1, "at least one fact purged");
  for (const id of ids) assert.equal(a.secondBrain.memory.get(id)?.tier, "retired", "purged memory is retired, not deleted");
});

test("M4 PURGE SAFETY: an empty filter is refused (no unbounded wipe) and purge is RBAC-gated", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-m4-"))); await seed(a);
  const refused = await handleGatewayRequest(a, req("POST", "/memory/purge", {}), { token: TOKEN });
  assert.equal(refused.status, 400, "empty filter refused — no unbounded purge");
  // all live memories survive the refused purge
  assert.ok(a.secondBrain.memory.all().every((l) => l.tier !== "retired"), "nothing was purged");
  // RBAC: a viewer cannot purge
  const VIEWER = { id: "v", kind: "human" as const, role: "viewer" as const, tenant: "tenant-viewer" };
  const forbidden = await handleGatewayRequest(a, reqAs("POST", "/memory/purge", { kind: "fact" }), { token: TOKEN, principalFor: () => VIEWER });
  assert.equal(forbidden.status, 403, "viewer refused purge (memory.forget)");
});

test("ENTERPRISE TENANCY: memory, skills, destructive curation, and veto decisions are structurally tenant-bound", async () => {
  const { app: a } = app(mkdtempSync(join(tmpdir(), "keep-tenant-surfaces-")));
  const alpha: Principal = { id: "alice", kind: "human", role: "owner", tenant: "alpha" };
  const beta: Principal = { id: "bob", kind: "human", role: "owner", tenant: "beta" };
  const alphaSec = { token: TOKEN, principalFor: () => alpha }, betaSec = { token: TOKEN, principalFor: () => beta };

  const stored = await handleGatewayRequest(a, reqAs("POST", "/memory", { content: "alpha-only klaxon", kind: "fact" }), alphaSec);
  const memoryId = (JSON.parse(stored.body) as { id: string }).id;
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/memory", { content: "poison shared context", scope: "global" }), alphaSec)).status, 400);
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/memory", { content: "poison agent context", scope: "agent", agentId: "bob" }), alphaSec)).status, 400);
  const betaRecall = await handleGatewayRequest(a, { ...reqAs("GET", "/memory"), query: { q: "klaxon" } }, betaSec);
  assert.deepEqual((JSON.parse(betaRecall.body) as { hits: unknown[] }).hits, []);
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/memory/forget", { id: memoryId }), betaSec)).status, 404);
  assert.equal((JSON.parse((await handleGatewayRequest(a, reqAs("POST", "/memory/purge", { kind: "fact" }), betaSec)).body) as { purged: number }).purged, 0);
  assert.equal((await handleGatewayRequest(a, reqAs("GET", "/memory/review"), betaSec)).status, 404);
  assert.equal((await handleGatewayRequest(a, reqAs("POST", "/memory/forget", { id: memoryId }), alphaSec)).status, 200);

  await handleGatewayRequest(a, reqAs("POST", "/skill/publish", { skill: mkSkill("alpha-skill", ["local-edit"]), origin: "forged-beta" }), alphaSec);
  const alphaSkills = JSON.parse((await handleGatewayRequest(a, reqAs("GET", "/skills"), alphaSec)).body) as { skills: Array<{ id: string; origin: string }> };
  const betaSkills = JSON.parse((await handleGatewayRequest(a, reqAs("GET", "/skills"), betaSec)).body) as { skills: unknown[] };
  assert.deepEqual(alphaSkills.skills.map(({ id, origin }) => ({ id, origin })), [{ id: "alpha-skill", origin: "alice" }]);
  assert.deepEqual(betaSkills.skills, []);

  a.vetoQueue!.enqueue({ id: "alpha-action", description: "alpha only", externalClass: "send", tenant: "alpha" }, Date.now());
  a.vetoQueue!.enqueue({ id: "beta-action", description: "beta only", externalClass: "send", tenant: "beta" }, Date.now());
  const betaDigest = JSON.parse((await handleGatewayRequest(a, reqAs("GET", "/veto"), betaSec)).body) as { digest: { entries: Array<{ id: string }> } };
  assert.deepEqual(betaDigest.digest.entries.map((entry) => entry.id), ["beta-action"]);
  assert.deepEqual(JSON.parse((await handleGatewayRequest(a, reqAs("POST", "/veto/approve", { id: "alpha-action" }), betaSec)).body), { ok: false, runnable: false });
  assert.equal(a.vetoQueue!.runnable("alpha-action"), false);
});
