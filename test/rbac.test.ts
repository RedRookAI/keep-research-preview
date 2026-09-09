import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RbacAuthorizer, OWNER, AGENT, can, ROLE_PERMISSIONS, type Principal, type Role, type Permission, type AuthorizationPort } from "../src/identity/rbac.js";
import { composeKeep } from "../src/compose.js";
import { applyReviewDecision } from "../src/review/review_core.js";

const auth = new RbacAuthorizer();
const P = (role: Role): Principal => ({ id: role, kind: role === "agent" ? "agent" : "human", role });

test("X0 roles: owner holds every permission; viewer is read-only", () => {
  for (const perm of ROLE_PERMISSIONS.owner) assert.equal(can(auth, OWNER, perm), true);
  assert.equal(can(auth, P("viewer"), "review.view"), true);
  assert.equal(can(auth, P("viewer"), "review.approve"), false);
  assert.equal(can(auth, P("viewer"), "config.write"), false);
});

test("X0 SAFETY (I9): the agent may propose but can NEVER approve/decline its own work or admin RBAC", () => {
  assert.equal(can(auth, AGENT, "change.solve"), true);
  assert.equal(can(auth, AGENT, "review.approve"), false);
  assert.equal(can(auth, AGENT, "review.decline"), false);
  assert.equal(can(auth, AGENT, "rbac.admin"), false);
  // structural: the agent role's permission set literally excludes approval
  assert.equal(ROLE_PERMISSIONS.agent.has("review.approve"), false);
});

test("X0 roles: reviewer decides but can't configure; operator runs but can't approve", () => {
  assert.equal(can(auth, P("reviewer"), "review.approve"), true);
  assert.equal(can(auth, P("reviewer"), "config.write"), false);
  assert.equal(can(auth, P("operator"), "change.solve"), true);
  assert.equal(can(auth, P("operator"), "serve"), true);
  assert.equal(can(auth, P("operator"), "review.approve"), false);
});

test("X0 rbac.admin is owner-only — no other role can change who holds what role", () => {
  assert.equal(can(auth, OWNER, "rbac.admin"), true);
  for (const r of ["maintainer", "reviewer", "operator", "viewer", "agent"] as const) assert.equal(can(auth, P(r), "rbac.admin"), false);
});

test("X0 deny-by-default: an unlisted permission for a role is denied", () => {
  const d = auth.authorize(P("viewer"), "calibration.authorize" as Permission);
  assert.equal(d.allow, false);
  assert.match(d.reason, /does not permit/);
});

function appWithReview(id = "pr-1") {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-x0-")) });
  const m = { id, title: "t", body: "", branch: "b", baseBranch: "main", diff: "", intent: "do x", executed: [], checks: [], attribution: "keep", humanApprovalRequired: true, oversight: { band: "medium", disposition: "human-approval-required", mode: "block-until-approved", requiresImmediateAttention: false, reasons: [] } };
  app.spine.stage({ type: "identity.action", actor: "cli", payload: { event: "review.pending", reviewId: id, manifest: m, ts: 1 } });
  return app;
}

test("X0 enforcement: a viewer is refused at the decision path — audited, no review.decided", () => {
  const app = appWithReview();
  const out = applyReviewDecision(app, "pr-1", true, 2, P("viewer"));
  assert.equal(out.ok, false);
  assert.equal(out.reason, "forbidden");
  const events = app.spine.currentEvents().map((e) => e.payload as Record<string, unknown>);
  assert.equal(events.some((p) => p["event"] === "review.decided"), false, "no decision recorded");
  assert.ok(events.find((p) => p["event"] === "authz.denied"), "the denial is audited on the spine");
});

test("X0 enforcement: a permitted principal is allowed and the decider is recorded (accountability)", () => {
  const app = appWithReview();
  const out = applyReviewDecision(app, "pr-1", true, 2, P("reviewer"));
  assert.equal(out.ok, true);
  const decided = app.spine.currentEvents().map((e) => e.payload as Record<string, unknown>).find((p) => p["event"] === "review.decided");
  assert.equal(decided!["by"], "reviewer");
});

test("X0 N=1 default: with no actor the owner acts (zero config), decision recorded as owner", () => {
  const app = appWithReview();
  const out = applyReviewDecision(app, "pr-1", true, 2);
  assert.equal(out.ok, true);
  const decided = app.spine.currentEvents().map((e) => e.payload as Record<string, unknown>).find((p) => p["event"] === "review.decided");
  assert.equal(decided!["by"], "owner");
});

test("X0 port: a custom AuthorizationPort is consulted (the ABAC/ReBAC swap point)", () => {
  const denyAll: AuthorizationPort = { authorize: () => ({ allow: false, reason: "custom deny" }) };
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-x0p-")), authorization: denyAll });
  const m = { id: "pr-2", title: "t", body: "", branch: "b", baseBranch: "main", diff: "", intent: "x", executed: [], checks: [], attribution: "keep", humanApprovalRequired: true, oversight: { band: "low", disposition: "human-approval-required", mode: "notify-async", requiresImmediateAttention: false, reasons: [] } };
  app.spine.stage({ type: "identity.action", actor: "cli", payload: { event: "review.pending", reviewId: "pr-2", manifest: m, ts: 1 } });
  const out = applyReviewDecision(app, "pr-2", true, 2, OWNER); // even the owner is denied by the custom port
  assert.equal(out.ok, false);
  assert.equal(out.reason, "forbidden");
});
