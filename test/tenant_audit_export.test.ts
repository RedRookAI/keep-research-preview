import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { exportTenantAudit } from "../src/audit/tenant_audit_export.js";
import { handleGatewayRequest, type GatewayRequest } from "../src/gateway/http_gateway.js";
import type { Principal } from "../src/identity/rbac.js";

const request: GatewayRequest = { method: "GET", path: "/audit/export", query: {}, headers: { authorization: "Bearer token" }, body: "" };

test("TEAM-02 tenant export contains only explicit same-tenant events while n=1 exports the complete local Spine", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-tenant-audit-")) });
  const bootEventCount = exportTenantAudit(app.spine).length;
  app.spine.stage({ type: "identity.action", actor: "alpha", payload: { event: "private", tenant: "alpha", value: 1 } });
  app.spine.stage({ type: "identity.action", actor: "beta", payload: { event: "private", tenant: "beta", value: 2 } });
  app.spine.stage({ type: "identity.action", actor: "local", payload: { event: "local-only", value: 3 } });
  const alpha = exportTenantAudit(app.spine, "alpha");
  assert.deepEqual(alpha.map((row) => row.actor), ["alpha"]);
  const solo = exportTenantAudit(app.spine);
  assert.equal(solo.length, bootEventCount + 3);
  assert.deepEqual(solo.slice(-3).map((row) => row.actor), ["alpha", "beta", "local"]);
  assert.equal(Object.isFrozen(alpha), true);
  assert.equal(Object.isFrozen(alpha[0]!.payload), true);
  assert.throws(() => exportTenantAudit(app.spine, "../beta"), /safe tenant/);
  for (let index = 0; index < 120; index++) app.spine.stage({ type: "identity.action", actor: "alpha", payload: { tenant: "alpha", index } });
  assert.equal(exportTenantAudit(app.spine, "alpha", { after: 1 }).length, 100, "an after-only page receives the bounded default rather than an invalid unbounded limit");
});

test("TEAM-02 real gateway export binds tenant to the resolved principal and preserves the n=1 full export", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-tenant-audit-gateway-")) });
  app.spine.stage({ type: "identity.action", actor: "alpha", payload: { event: "private", tenant: "alpha" } });
  app.spine.stage({ type: "identity.action", actor: "beta", payload: { event: "private", tenant: "beta" } });
  app.spine.stage({ type: "identity.action", actor: "local", payload: { event: "local-only" } });
  const alpha: Principal = { id: "alice", kind: "human", role: "maintainer", tenant: "alpha" };
  const scoped = await handleGatewayRequest(app, request, { token: "token", principalFor: () => alpha });
  assert.equal(scoped.status, 200);
  const scopedBody = JSON.parse(scoped.body) as { scope: string; completeness: string; rows: Array<{ payload: Record<string, unknown> }> };
  assert.deepEqual({ scope: scopedBody.scope, completeness: scopedBody.completeness }, {
    scope: "explicit-tenant-attribution", completeness: "only-events-carrying-resolved-tenant-attribution",
  });
  const scopedRows = scopedBody.rows;
  assert.ok(scopedRows.length >= 1);
  assert.equal(scopedRows.every((row) => row.payload["tenant"] === "alpha"), true);
  const viewer: Principal = { id: "viewer", kind: "human", role: "viewer", tenant: "alpha" };
  assert.equal((await handleGatewayRequest(app, request, { token: "token", principalFor: () => viewer })).status, 403, "ordinary audit viewing does not grant bulk export");
  const solo = await handleGatewayRequest(app, request, { token: "token" });
  assert.equal(solo.status, 200);
  const soloBody = JSON.parse(solo.body) as { scope: string; completeness: string; rows: Array<{ actor: string }> };
  assert.deepEqual({ scope: soloBody.scope, completeness: soloBody.completeness }, { scope: "complete-local-spine", completeness: "complete" });
  const soloRows = soloBody.rows;
  assert.ok(soloRows.some((row) => row.actor === "alpha") && soloRows.some((row) => row.actor === "beta") && soloRows.some((row) => row.actor === "local"));
});
