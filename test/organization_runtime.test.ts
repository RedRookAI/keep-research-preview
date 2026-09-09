import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { loadInstalledOrganizationRuntime } from "../src/cli/organization_runtime.js";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "keep-org-runtime-"));
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const paths = { jwksPath: join(root, "jwks.json"), principalRosterPath: join(root, "principals.json"), delegationPolicyPath: join(root, "delegation.json"), residencyPolicyPath: join(root, "residency.json"), scannerEnginePath: join(root, "scanner", "effect_sweep.mjs") };
  writeFileSync(paths.jwksPath, JSON.stringify({ keys: [{ ...publicKey.export({ format: "jwk" }), kid: "k1", alg: "RS256", use: "sig" }] }), { mode: 0o600 });
  writeFileSync(paths.principalRosterPath, JSON.stringify({ schema: "keep.principal-roster/v1", tenantId: "alpha", principals: [{ id: "alice", subject: "alice-sub", role: "maintainer" }, { id: "eve", subject: "eve-sub", role: "viewer" }] }), { mode: 0o600 });
  writeFileSync(paths.delegationPolicyPath, JSON.stringify({ schema: "keep.delegation-policy/v1", tenantId: "alpha", parents: ["alice"] }), { mode: 0o600 });
  writeFileSync(paths.residencyPolicyPath, JSON.stringify({ schema: "keep.residency-policy/v1", tenantId: "alpha", allowedPurposes: ["software-development"], allowedRegions: ["external"], egressAllowlist: ["openrouter.ai"] }), { mode: 0o600 });
  return { root, paths };
}

test("installed organization runtime binds protected identity, roster and delegation files to one tenant", () => {
  const { paths } = fixture();
  const runtime = loadInstalledOrganizationRuntime({ tenantId: "alpha", issuer: "https://id.example", audience: "keep", auditScope: "tenant", ...paths });
  assert.equal(runtime.parentFor("alice", "alpha")?.role, "maintainer");
  assert.equal(runtime.parentFor("eve", "alpha"), undefined);
  assert.equal(runtime.parentFor("alice", "beta"), undefined);
  assert.equal(runtime.residency.allowedPurposes?.[0], "software-development");
  assert.equal(runtime.residency.egressAllowlist[0], "openrouter.ai");
});

test("installed organization runtime refuses widened files and cross-tenant policy", () => {
  const { paths } = fixture();
  chmodSync(paths.principalRosterPath, 0o644);
  assert.throws(() => loadInstalledOrganizationRuntime({ tenantId: "alpha", issuer: "https://id.example", audience: "keep", auditScope: "tenant", ...paths }), /mode-0600/u);
  chmodSync(paths.principalRosterPath, 0o600);
  writeFileSync(paths.delegationPolicyPath, JSON.stringify({ schema: "keep.delegation-policy/v1", tenantId: "beta", parents: ["alice"] }), { mode: 0o600 });
  assert.throws(() => loadInstalledOrganizationRuntime({ tenantId: "alpha", issuer: "https://id.example", audience: "keep", auditScope: "tenant", ...paths }), /policy binding/u);
  writeFileSync(paths.delegationPolicyPath, JSON.stringify({ schema: "keep.delegation-policy/v1", tenantId: "alpha", parents: ["alice"] }), { mode: 0o600 });
  writeFileSync(paths.residencyPolicyPath, JSON.stringify({ schema: "keep.residency-policy/v1", tenantId: "beta", allowedPurposes: ["software-development"], allowedRegions: ["external"], egressAllowlist: ["openrouter.ai"] }), { mode: 0o600 });
  assert.throws(() => loadInstalledOrganizationRuntime({ tenantId: "alpha", issuer: "https://id.example", audience: "keep", auditScope: "tenant", ...paths }), /residency policy binding/u);
});
