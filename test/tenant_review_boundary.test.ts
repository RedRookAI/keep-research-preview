/** Exact tenant joins through real review intake, authenticated browser reads/decisions and durable export. */
import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { recordReviewPending, makeClosedLoopHandler } from "../src/loop/review_intake.js";
import { getPacketInputs, getManifest, listPendingReviews, isDecided, applyReviewDecision, auditTrail, reviewEvents, reviewScopeEvents } from "../src/review/review_core.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";
import { OWNER, type Principal } from "../src/identity/rbac.js";
import { handleReviewRequest, type WebRequest } from "../src/review/review_web.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";
import { exportTenantAudit } from "../src/audit/tenant_audit_export.js";
import { computeMonitor } from "../src/monitor/solve_monitor.js";
import type { PrManifest } from "../src/git/pull_request.js";
import type { SolveToPrResult } from "../src/pipeline/keep_pipeline.js";
import { runCli } from "../src/cli/cli_core.js";
import { admitTenantDeployment } from "../src/team/tenant_deployment_admission.js";

const ORIGIN = "https://review.fixture.invalid", TOKEN = "tenant-review-fixture";
const alpha: Principal = { id: "alice", kind: "human", role: "reviewer", tenant: "alpha" }, beta: Principal = { id: "bob", kind: "human", role: "reviewer", tenant: "beta" };
const viewer: Principal = { id: "viewer", kind: "human", role: "viewer", tenant: "alpha" }, operator: Principal = { id: "operator", kind: "human", role: "operator", tenant: "alpha" };
function manifest(id: string, title: string): PrManifest { return { id, title, body: `${title} body`, branch: "keep/fixture", baseBranch: "main", diff: "", intent: `${title} intent`, executed: [], checks: [], attribution: "keep", humanApprovalRequired: true,
  oversight: { band: "medium", disposition: "human-approval-required", mode: "block-until-approved", requiresImmediateAttention: false, reasons: [] } }; }
function fixture(t: TestContext) {
  const root = mkdtempSync(join(tmpdir(), "keep-tenant-review-")); t.after(() => rmSync(root, { recursive: true, force: true }));
  const humans = [alpha, beta, viewer, operator];
  const app = composeKeep({ dataDir: join(root, "state"), delegationParentFor: (id, tenant) => humans.find(p => p.id === id && p.tenant === tenant) });
  let calibrationEffects = 0; const recordDecision = app.calibrationWire.recordDecision.bind(app.calibrationWire);
  app.calibrationWire.recordDecision = (...args: Parameters<typeof recordDecision>) => { calibrationEffects++; recordDecision(...args); };
  const identity = { provider: new HmacAssertionProvider("synthetic-review-secret"), registry: new PrincipalRegistry(humans.map(p => ({ subject: p.id, id: p.id, tenant: p.tenant!, role: p.role }))), sessions: new SessionStore() };
  const pending = (tenant: string | undefined, id: string, title: string) => recordReviewPending({ spine: app.spine, notifications: app.notifications, ...(tenant === undefined ? {} : { tenant }) }, manifest(id, title), 1);
  const security = { token: TOKEN, origin: ORIGIN, allowedHosts: [new URL(ORIGIN).host], principal: OWNER, identity };
  const browser = (over: Partial<WebRequest>) => handleReviewRequest(app, { method: "GET", path: "/", query: {}, body: "", headers: { host: new URL(ORIGIN).host }, ...over }, security);
  const login = async (person: Principal) => {
    const response = await browser({ method: "POST", path: "/login", headers: { host: new URL(ORIGIN).host, origin: ORIGIN }, body: `assertion=${identity.provider.sign({ sub: person.id, exp: Date.now() + 60000 })}` });
    assert.equal(response.status, 303); const cookie = response.headers["Set-Cookie"]!.split(";")[0]!, session = identity.sessions.get(cookie.split("=")[1]!, Date.now())!;
    return { cookie, session, get: (path: string) => browser({ path, headers: { host: new URL(ORIGIN).host, cookie } }),
      decide: (id: string, action = "approve") => browser({ method: "POST", path: `/review/${id}/decide`, headers: { host: new URL(ORIGIN).host, origin: ORIGIN, cookie }, body: `csrf=${session.csrfToken}&action=${action}` }) };
  };
  return { app, root, identity, pending, login, calibrationEffects: () => calibrationEffects };
}

test("shared review authority joins tenant plus ID before reads, decisions and pending suppression", t => {
  const f = fixture(t); f.pending("beta", "shared", "beta-private"); f.pending("alpha", "shared", "alpha-private"); f.pending(undefined, "shared", "personal-private"); f.pending("beta", "beta-only", "beta-only-secret");
  assert.equal(getPacketInputs(f.app, "shared", "alpha")!.manifest.title, "alpha-private"); assert.equal(getManifest(f.app, "shared", undefined, "beta")!.title, "beta-private");
  assert.equal(getPacketInputs(f.app, "beta-only", "alpha"), undefined); assert.equal(getPacketInputs(f.app, "shared")!.manifest.title, "personal-private");
  const before = f.app.spine.currentEvents().length; assert.deepEqual(applyReviewDecision(f.app, "beta-only", true, 2, alpha), { ok: false, reason: "not-found" }); assert.equal(f.app.spine.currentEvents().length, before); assert.equal(f.calibrationEffects(), 0);
  assert.equal(applyReviewDecision(f.app, "shared", true, 3, alpha).ok, true);
  assert.equal(isDecided(f.app, "shared", "alpha"), true); assert.equal(isDecided(f.app, "shared", "beta"), false); assert.equal(isDecided(f.app, "shared"), false);
  assert.deepEqual(listPendingReviews(f.app, "alpha"), []); assert.deepEqual(listPendingReviews(f.app, "beta").map(p => p.id), ["shared", "beta-only"]);
  assert.equal(applyReviewDecision(f.app, "shared", false, 4, beta).ok, true); assert.equal(applyReviewDecision(f.app, "shared", true, 5).ok, true);
  const decisions = f.app.spine.currentEvents().filter(e => e.payload["event"] === "review.decided").map(e => e.payload);
  assert.deepEqual(decisions.map(p => [p["tenant"], p["by"], p["decision"]]), [["alpha", "alice", "approved"], ["beta", "bob", "declined"], [undefined, "owner", "approved"]]); assert.equal(f.calibrationEffects(), 3);
});

test("authenticated two-tenant browser list/detail/monitor reads cannot join foreign or personal records", async t => {
  const f = fixture(t); f.pending("alpha", "shared", "alpha-private"); f.pending("beta", "shared", "beta-private"); f.pending("beta", "foreign", "foreign-private"); f.pending(undefined, "personal", "personal-private");
  for (const tenant of ["alpha", "beta"]) f.app.spine.stage({ type: "identity.action", actor: "fixture", payload: { event: "trigger.accepted", tenant, issueId: `${tenant}-ticket`, ts: Date.now() } });
  const a = await f.login(alpha), b = await f.login(beta);
  const listA = await a.get("/"), listB = await b.get("/"); assert.equal(listA.status, 200); assert.equal(listB.status, 200);
  assert.match(listA.body, /alpha-private/u); assert.doesNotMatch(listA.body, /beta-private|foreign-private|personal-private/u); assert.match(listB.body, /beta-private/u); assert.doesNotMatch(listB.body, /alpha-private|personal-private/u);
  const detailA = await a.get("/review/shared"); assert.equal(detailA.status, 200); assert.match(detailA.body, /alpha-private intent/u); assert.doesNotMatch(detailA.body, /beta-private/u);
  assert.equal((await a.get("/review/foreign")).status, 404); const before = f.app.spine.currentEvents().length;
  assert.equal((await a.decide("foreign")).status, 404); assert.equal(f.app.spine.currentEvents().length, before); assert.equal(isDecided(f.app, "foreign", "beta"), false);
  const monitor = await a.get("/monitor"); assert.equal(monitor.status, 200); assert.match(monitor.body, /alpha-ticket/u); assert.doesNotMatch(monitor.body, /beta-ticket|foreign|personal/u);
  assert.equal((await a.decide("shared")).status, 303); assert.equal(isDecided(f.app, "shared", "alpha"), true); assert.equal(isDecided(f.app, "shared", "beta"), false);
  assert.equal((await b.decide("shared", "decline")).status, 303); assert.equal(isDecided(f.app, "shared", "beta"), true);
});

test("viewer and operator can inspect own review but only reviewer can decide, with tenant-bound denial evidence", async t => {
  const f = fixture(t); f.pending("alpha", "own", "alpha-private");
  for (const person of [viewer, operator]) { const user = await f.login(person); assert.equal((await user.get("/review/own")).status, 200); assert.equal((await user.decide("own")).status, 403); assert.equal(isDecided(f.app, "own", "alpha"), false); }
  const user = await f.login(alpha); assert.equal((await user.decide("own")).status, 303);
  const denials = f.app.spine.currentEvents().filter(e => e.payload["event"] === "authz.denied"); assert.equal(denials.length, 2); assert.equal(denials.every(e => e.payload["tenant"] === "alpha"), true);
});

test("independent agent grant retains identity and cannot become a human reviewer even through a permissive authorizer", async t => {
  const f = fixture(t); f.pending("alpha", "own", "alpha-private");
  const agent = await f.app.authorization.issue(alpha, "agent", ["review.view", "review.approve"], Date.now() + 60000);
  assert.equal(applyReviewDecision(f.app, "own", true, 2, agent).reason, "forbidden"); assert.equal(isDecided(f.app, "own", "alpha"), false);
  const permissive = { ...f.app, authorization: { ...f.app.authorization, authorize: () => ({ allow: true, reason: "synthetic overbroad policy" }) } } as unknown as typeof f.app;
  assert.equal(applyReviewDecision(permissive, "own", true, 3, { ...agent, role: "owner" }).reason, "forbidden");
  const denials = reviewScopeEvents(f.app, "alpha").filter(e => e.payload["event"] === "authz.denied"); assert.equal(denials.length, 2); assert.equal(denials.every(e => e.payload["who"] === agent.id), true);
  assert.equal(isDecided(f.app, "own", "alpha"), false); assert.equal(applyReviewDecision(f.app, "own", true, 4, alpha).ok, true);
});

test("review audit and monitor filter authority before reused-ID/correlation folds; personal labels stay absent", async t => {
  const f = fixture(t); f.pending(undefined, "shared", "personal-private"); f.pending("alpha", "shared", "alpha-private"); f.pending("beta", "shared", "beta-private");
  f.app.spine.stage({ type: "identity.action", actor: "fixture", payload: { event: "resolve.cascade.tier", tenant: "alpha", issueId: "shared", tier: "fixture", estCostUsd: 1, ts: 2 } });
  f.app.spine.stage({ type: "identity.action", actor: "fixture", payload: { event: "resolve.cascade.tier", tenant: "beta", issueId: "shared", tier: "foreign", estCostUsd: 99, ts: 2 } });
  assert.equal(auditTrail(f.app, "shared", "alpha").length, 1); assert.equal(auditTrail(f.app, "shared", "missing").length, 0);
  assert.equal(computeMonitor(reviewScopeEvents(f.app, "alpha"), Date.now()).totalCostUsd, 1); assert.equal(computeMonitor(reviewScopeEvents(f.app, "beta"), Date.now()).totalCostUsd, 99);
  assert.equal(applyReviewDecision(f.app, "shared", false, 3, beta).ok, true); assert.equal(auditTrail(f.app, "shared", "alpha").length, 1); assert.equal(auditTrail(f.app, "shared", "beta").length, 2); assert.equal(auditTrail(f.app, "shared").length, 1);
  const user = await f.login(alpha); const response = await handleGatewayRequest(f.app, { method: "GET", path: "/audit", query: { id: "shared", tenant: "beta" }, body: "", headers: { authorization: `Bearer ${TOKEN}`, "x-keep-session": user.session.id } }, { token: TOKEN, identity: f.identity });
  assert.equal(response.status, 200); assert.equal(JSON.parse(response.body).trail.length, 1, "query tenant never overrides real session tenant");
  assert.equal(applyReviewDecision(f.app, "shared", true, 4).ok, true); const local = reviewEvents(f.app).find(e => e.event === "review.decided")!; assert.equal(Object.hasOwn(local, "tenant"), false);
});

test("trusted intake binds tenant independently of proposed content and closed-loop issue hints", async t => {
  const f = fixture(t); const proposed = { ...manifest("ingested", "alpha-private"), tenant: "beta" };
  recordReviewPending({ spine: f.app.spine, notifications: f.app.notifications, tenant: "alpha" }, proposed, 1);
  assert.equal(getPacketInputs(f.app, "ingested", "alpha")?.manifest.title, "alpha-private"); assert.equal(getPacketInputs(f.app, "ingested", "beta"), undefined);
  const handler = makeClosedLoopHandler({ spine: f.app.spine, notifications: f.app.notifications, tenant: "alpha" }, async () => ({ manifest: manifest("loop", "trusted-alpha") } as SolveToPrResult));
  await handler({ id: "issue", text: "synthetic", repoRef: ".", hints: { tenant: "beta" } }, { source: "linear", kind: "ticket.created", ticketId: "issue", title: "fixture", body: "", labels: [] }); assert.ok(getPacketInputs(f.app, "loop", "alpha")); assert.equal(getPacketInputs(f.app, "loop", "beta"), undefined);
  const before = f.app.spine.currentEvents().length; for (const tenant of ["../beta", "keep.n1.default", ""]) assert.throws(() => recordReviewPending({ spine: f.app.spine, notifications: f.app.notifications, tenant }, manifest("bad", "refuse"), 1)); assert.equal(f.app.spine.currentEvents().length, before);
});

test("sealed decisions retain tenant and original human through fresh-process readback and scoped exports", async t => {
  const f = fixture(t); f.pending("alpha", "shared", "alpha-private"); f.pending("beta", "shared", "beta-private"); f.pending(undefined, "shared", "personal-private");
  assert.equal(applyReviewDecision(f.app, "shared", true, 2, alpha).ok, true); assert.equal(applyReviewDecision(f.app, "shared", false, 3, beta).ok, true); await f.app.spine.seal();
  const child = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", `
    import {composeKeep} from ${JSON.stringify(new URL("../src/compose.js", import.meta.url).href)};
    import {getPacketInputs,isDecided,reviewEvents} from ${JSON.stringify(new URL("../src/review/review_core.js", import.meta.url).href)};
    import {exportTenantAudit} from ${JSON.stringify(new URL("../src/audit/tenant_audit_export.js", import.meta.url).href)};
    const app=composeKeep({dataDir:process.argv[1]});
    console.log(JSON.stringify({alpha:getPacketInputs(app,'shared','alpha')?.manifest.title,beta:getPacketInputs(app,'shared','beta')?.manifest.title,
      local:getPacketInputs(app,'shared')?.manifest.title,a:isDecided(app,'shared','alpha'),b:isDecided(app,'shared','beta'),personal:isDecided(app,'shared'),
      decisions:reviewEvents(app,'alpha').filter(e=>e.event==='review.decided'),rows:exportTenantAudit(app.spine,'alpha')}));
  `, join(f.root, "state")], { encoding: "utf8", timeout: 10000 }));
  assert.deepEqual([child.alpha, child.beta, child.local, child.a, child.b, child.personal], ["alpha-private", "beta-private", "personal-private", true, true, false]);
  assert.equal(child.rows.every((e: { payload: Record<string, unknown> }) => e.payload["tenant"] === "alpha"), true); assert.equal(JSON.stringify(child.rows).includes("beta-private"), false); assert.equal(JSON.stringify(child.rows).includes("personal-private"), false);
  const decision = child.rows.find((e: { payload: Record<string, unknown> }) => e.payload["event"] === "review.decided"); assert.equal(decision.payload.by, "alice");
  const personal = exportTenantAudit(f.app.spine); assert.ok(personal.some(e => e.payload["tenant"] === "alpha") && personal.some(e => e.payload["tenant"] === "beta"), "n=1 full local audit export remains intact");
});


test("CLI review producer consumes a trusted root-admission receipt independently of proposed tenant content", async t => {
  const f = fixture(t);
  const roots = (tenantId: string) => {
    const base = join(f.root, tenantId), dataRoot = tenantId === "alpha" ? join(f.root, "state") : join(base, "data"), repositoryRoot = join(base, "repository"), workspaceRoot = join(base, "workspace");
    for (const dir of [dataRoot, repositoryRoot, workspaceRoot]) mkdirSync(dir, { recursive: true });
    return { tenantId, dataRoot, repositoryRoot, workspaceRoot };
  };
  const rootAdmission = admitTenantDeployment(roots("alpha"), [roots("beta")]);
  // Test the trusted CLI/intake seam with a real disjoint-root receipt. This does
  // not simulate the separate installed-package/baseline qualification at boot.
  const app = { ...f.app, tenantDeployment: { rootAdmission } } as unknown as typeof f.app;
  const solve = async (issue: { id: string }) => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0 },
    manifest: { ...manifest(`review-${issue.id}`, "admitted-alpha"), tenant: "beta" } } as unknown as SolveToPrResult);
  const result = await runCli(["solve", "synthetic fixture"], { write() {}, prompt: async () => "skip" }, { app, solve }); assert.equal(result.exitCode, 0);
  assert.equal(listPendingReviews(app, "alpha").length, 1); assert.deepEqual(listPendingReviews(app), []); assert.deepEqual(listPendingReviews(app, "beta"), []);
  assert.equal(reviewEvents(app, "alpha").every(event => event.tenant === rootAdmission.tenantId), true);
});
