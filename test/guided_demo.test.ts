import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBrowserProjectFixture } from "../src/demo/browser_project_fixture.js";
import { SAMPLE_CONTRACT, SAMPLE_GOAL, SAMPLE_NOTICE, SAMPLE_FILE, SAMPLE_CHECK_FILE, SAMPLE_CHECKER, SAMPLE_ORIGINAL, SAMPLE_FIXED, reviewerSampleNotice } from "../src/review/reviewer_sample.js";
import { startGatewayServer } from "../src/gateway/http_gateway.js";
import { handleProjectConsole, type ConsoleApi, type ConsoleSample } from "../src/review/project_console.js";
import { verifyProposalExport } from "../src/audit/proposal_export.js";

const input = (html: string, name: string): string => new RegExp(`name="${name}" value="([^"]+)"`, "u").exec(html)![1]!;
const sample: ConsoleSample = { goal: SAMPLE_GOAL, notice: SAMPLE_NOTICE };

test("the frozen webhook checker exposes the actual duplicate defect and preserves first/distinct behavior", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-webhook-baseline-"));
  try {
    const fixture = createBrowserProjectFixture(root);
    const baseline = spawnSync(process.execPath, ["--test", SAMPLE_CHECK_FILE], { cwd: fixture.source, encoding: "utf8", timeout: 5000, env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: root, TMPDIR: root } });
    assert.equal(baseline.status, 1, baseline.stdout + baseline.stderr); assert.match(baseline.stdout, /# pass 2/); assert.match(baseline.stdout, /# fail 1/);
    assert.match(baseline.stdout, /not ok 2 - duplicate delivery ID is ignored/);
    assert.equal(readFileSync(join(fixture.source, SAMPLE_FILE), "utf8"), SAMPLE_ORIGINAL);
    assert.equal(readFileSync(join(fixture.source, SAMPLE_CHECK_FILE), "utf8"), SAMPLE_CHECKER);
    assert.equal(fixture.generations(), 0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

for (const localAppliance of [false, true]) test(`guided Start → deliberate preparation → real checks → actual approval (${localAppliance ? "workspace-only" : "hosted source landing"})`, async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-guided-approval-")), token = "guided-private-invitation";
  const fixture = createBrowserProjectFixture(root, localAppliance ? { localAppliance: true } : {});
  let server = await startGatewayServer(fixture.app, { port: 0, token, reviewerSample: true });
  try {
    const signIn = await (await fetch(server.origin + "/console")).text();
    assert.match(signIn, /Try Keep on a prepared task/); assert.match(signIn, /Invitation credential/); assert.ok(!signIn.includes(token));
    const signed = await fetch(server.origin + "/console/login", { method: "POST", redirect: "manual", headers: { origin: server.origin }, body: new URLSearchParams({ token }) });
    const cookie = signed.headers.get("set-cookie")!.split(";")[0]!;
    const read = async (path: string) => (await fetch(server.origin + path, { headers: { cookie } })).text();
    const post = (path: string, form: Record<string, string>) => fetch(server.origin + path, { method: "POST", redirect: "manual", headers: { cookie, origin: server.origin }, body: new URLSearchParams(form) });
    const landing = await read("/console");
    assert.match(landing, /Count each delivery once/); assert.match(landing, /Start demo/); assert.doesNotMatch(landing, /Submit a repository goal|<textarea|Retained projects/);
    assert.match(landing, /expected results/); assert.equal(fixture.app.projectManager!.list().length, 0); assert.equal(fixture.generations(), 0);
    const csrf = input(landing, "csrf");
    const submitted = await post("/console/submit", { csrf, goal: SAMPLE_GOAL, idempotencyKey: "guided-start-key-12345" });
    assert.equal(submitted.status, 303); const projectPath = submitted.headers.get("location")!;
    let pending = "";
    for (let i = 0; i < 100; i++) {
      pending = await read(projectPath);
      if (pending.includes('value="approve">Prepare the fix')) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.match(pending, /Ready to prepare the fix/); assert.doesNotMatch(pending, /http-equiv="refresh"/); assert.equal(fixture.generations(), 0);
    const projectId = input(pending, "projectId"), runId = input(pending, "runId"), decisionId = input(pending, "decisionId");
    if (!localAppliance) fixture.app.projectRuntime!.pauseDispatch();
    const prepared = await post("/console/resume", { csrf, projectId, runId, decisionId, action: "approve" });
    assert.equal(prepared.status, 303, "sample preparation returns directly to actual project state"); assert.equal(prepared.headers.get("location"), projectPath);
    if (!localAppliance) {
      const queued = await read(projectPath);
      assert.match(queued, /worker is paused/); assert.doesNotMatch(queued, /http-equiv="refresh"/);
      assert.equal(fixture.generations(), 0, "background approval is durably queued without blocking or generating while paused");
      fixture.app.projectRuntime!.resumeDispatch();
    }
    let review = "";
    for (let i = 0; i < 200; i++) {
      review = await read(projectPath);
      if (review.includes("Review the checked change")) break;
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.match(review, /Review the checked change/); assert.match(review, /Approve this proposal/); assert.match(review, /Veto this proposal/);
    assert.match(review, /Goal check/); assert.doesNotMatch(review, /http-equiv="refresh"/);
    assert.equal(fixture.generations(), 2);
    const checks = (fixture.app.projectManager!.session(fixture.app.projectManager!.list()[0]!.id).inspect().checkpoint!.artifacts["implement"] as { solve: { proposalEvidence: { checks: { passedTests: string[]; testsPassed: boolean } } } }).solve.proposalEvidence.checks;
    assert.deepEqual(checks.passedTests, SAMPLE_CONTRACT.passedTests); assert.equal(checks.testsPassed, true);
    const proposalDigest = input(review, "proposalDigest");
    assert.match(review, localAppliance ? /source repository stays unchanged/ : /synthetic source repository/);
    const approved = await post("/console/merge", { csrf, projectId, runId, proposalDigest, action: "approve" });
    assert.equal(approved.status, 200); const result = await approved.text();
    assert.match(result, localAppliance ? /Change approved in the demo workspace/ : /Change applied to the demo source/);
    assert.match(result, /Download evidence/); assert.match(result, /Technical decision result/);
    assert.equal(readFileSync(join(fixture.source, SAMPLE_FILE), "utf8"), localAppliance ? SAMPLE_ORIGINAL : SAMPLE_FIXED);
    assert.equal(readFileSync(join(fixture.workspaces, "project", SAMPLE_FILE), "utf8"), SAMPLE_FIXED);
    assert.equal(readFileSync(join(fixture.source, SAMPLE_CHECK_FILE), "utf8"), SAMPLE_CHECKER);
    const retained = await read(projectPath);
    assert.match(retained, localAppliance ? /Change approved in the demo workspace/ : /Change applied to the demo source/);
    assert.doesNotMatch(retained, /http-equiv="refresh"/);
    const exported = await read(`/console/export?runId=${runId}&proposalDigest=${proposalDigest}`);
    const bundle = verifyProposalExport(exported);
    assert.deepEqual(bundle.data.proposal.checks.passedTests, SAMPLE_CONTRACT.passedTests);
    assert.equal(bundle.data.delivery.sourceMerge, localAppliance ? "unknown" : "landed");
    assert.equal(fixture.generations(), 2);
    if (localAppliance) {
      await server.close();
      const resumed = createBrowserProjectFixture(root, { localAppliance: true, resume: true });
      server = await startGatewayServer(resumed.app, { port: 0, token, reviewerSample: true });
      const resumedPage = await read(projectPath);
      assert.match(resumedPage, /Change approved in the demo workspace/);
      assert.equal(resumed.generations(), 0); assert.ok(reviewerSampleNotice(resumed.app).includes("source repository unchanged"));
      assert.equal(resumed.app.projectRuntime!.retainedJobs().filter(job => job.id === runId).length, 1);
      assert.equal(readFileSync(join(resumed.source, SAMPLE_FILE), "utf8"), SAMPLE_ORIGINAL);
    }
  } finally { await server.close(); rmSync(root, { recursive: true, force: true }); }
});

test("guided reads show real active, paused, uncertain, failed checks and held outcomes without dispatch or assumed landing", async () => {
  for (const variant of ["active", "resuming", "approval", "paused", "paused-approval", "uncertain", "failed-checks", "held-delivery"]) {
    let writes = 0;
    const api: ConsoleApi = async (method, path) => {
      if (method === "POST") writes++;
      const hasProposal = ["failed-checks", "held-delivery"].includes(variant);
      const data = path === "/projects" ? { runtime: { paused: variant.startsWith("paused") }, projects: [{ id: "p1", runId: "r1" }] }
        : path === "/project/jobs" ? { jobs: [{ id: "j1", label: variant === "resuming" ? "autonomy project resume" : "autonomy project run", state: variant === "uncertain" ? "reconciliation-required" : hasProposal ? "completed" : "running", reason: "Inspect retained work <script>" }] }
        : { projectId: "p1", project: { runId: "r1", stage: "vet_artifact", status: (variant.includes("approval") || variant === "resuming") ? "waiting-approval" : "running", ...((variant.includes("approval") || variant === "resuming") ? { wait: { kind: "approval", decisionId: "d1" } } : {}) },
          proposal: hasProposal ? { diff: "+++ b/webhook.mjs\n+<script>unsafe()</script>", rollback: { patchSha256: "a".repeat(64) }, checks: { testsPassed: false, vettingCleared: false, passedTests: [], failures: [SAMPLE_CONTRACT.passedTests[1]] } } : null,
          decisionHistory: variant === "held-delivery" ? [{ event: "local_merge.failed", reason: "Source delivery outcome is unknown <script>" }] : [] };
      return { status: 200, headers: {}, body: JSON.stringify(data) };
    };
    const response = await handleProjectConsole({ method: "GET", path: "/console/project", query: { projectId: "p1" }, headers: {}, body: "" }, "csrf", api, { approve: true, decline: true }, sample);
    assert.equal(response.status, 200); assert.equal(writes, 0);
    assert.equal(response.body.includes('http-equiv="refresh"'), ["active", "resuming"].includes(variant), variant);
    assert.ok(!response.body.includes("<script>"));
    if (variant === "held-delivery") { assert.match(response.body, /decision needs attention/); assert.doesNotMatch(response.body, /Change applied to the demo source/); }
    if (variant === "failed-checks") { assert.match(response.body, /checks need attention/); assert.match(response.body, />Failed</); }
    if (variant === "uncertain") assert.match(response.body, /needs reconciliation/);
    if (variant.startsWith("paused")) assert.match(response.body, /worker is paused/);
  }
});

test("background preparation exposes held work, refuses duplicate/stale approvals and retains a failed callback", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-guided-failed-resume-")), token = "failed-resume-private-token";
  const fixture = createBrowserProjectFixture(root);
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  fixture.app.autonomyLoop!.resumeManagedProject = async () => { await held; throw new Error("controlled completion failure"); };
  const server = await startGatewayServer(fixture.app, { port: 0, token, reviewerSample: true });
  try {
    const login = await fetch(server.origin + "/console/login", { method: "POST", redirect: "manual", headers: { origin: server.origin }, body: new URLSearchParams({ token }) });
    const cookie = login.headers.get("set-cookie")!.split(";")[0]!;
    const read = async (path: string) => (await fetch(server.origin + path, { headers: { cookie } })).text();
    const post = (path: string, body: Record<string, string>) => fetch(server.origin + path, { method: "POST", redirect: "manual", headers: { cookie, origin: server.origin }, body: new URLSearchParams(body) });
    const start = await read("/console"), csrf = input(start, "csrf");
    const submitted = await post("/console/submit", { csrf, goal: SAMPLE_GOAL, idempotencyKey: "failed-demo-key-12345" });
    const projectPath = submitted.headers.get("location")!;
    let pending = "";
    for (let i = 0; i < 100; i++) { pending = await read(projectPath); if (pending.includes('name="decisionId"')) break; await new Promise(resolve => setTimeout(resolve, 10)); }
    const form = { csrf, projectId: input(pending, "projectId"), runId: input(pending, "runId"), decisionId: input(pending, "decisionId"), action: "approve" };
    assert.equal((await post("/console/resume", { ...form, decisionId: "stale" })).status, 409);
    assert.equal((await post("/console/resume", form)).status, 303, "canonical background202 returns while actual callback is held");
    const active = await read(projectPath); assert.match(active, /Preparing and checking the fix|Checking the change/); assert.match(active, /http-equiv="refresh"/);
    assert.doesNotMatch(active, /value="approve">Prepare the fix/);
    assert.equal((await post("/console/resume", form)).status, 409, "busy approval cannot add a second resume job");
    assert.equal(fixture.app.projectRuntime!.retainedJobs().length, 2); assert.equal(fixture.generations(), 0);
    release();
    let failed = "";
    for (let i = 0; i < 100; i++) { failed = await read(projectPath); if (failed.includes("callback failed")) break; await new Promise(resolve => setTimeout(resolve, 10)); }
    assert.match(failed, /demo needs attention/); assert.match(failed, /callback failed/); assert.doesNotMatch(failed, /http-equiv="refresh"/);
    assert.equal((await post("/console/resume", form)).status, 409, "failed preparation needs explicit owner inspection");
    assert.equal(fixture.app.projectRuntime!.retainedJobs().length, 2); assert.equal(fixture.generations(), 0);
  } finally { release(); await server.close(); rmSync(root, { recursive: true, force: true }); }
});
