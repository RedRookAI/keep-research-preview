import { lstatSync, readFileSync } from "node:fs";
import { OidcJwksProvider, type Jwks } from "../identity/oidc_provider.js";
import { PrincipalRegistry, type PrincipalMapping } from "../identity/identity_provider.js";
import { SessionStore } from "../identity/session_store.js";
import type { Principal, Role } from "../identity/rbac.js";
import type { ResidencyPolicy } from "../governance/residency.js";
import type { CapturedRuntimeContract } from "./runtime_config.js";

const MAX = 1024 * 1024;
const SAFE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const ROLES = new Set<Role>(["owner", "maintainer", "reviewer", "operator", "viewer"]);

export interface InstalledOrganizationRuntime {
  readonly identity: { readonly provider: OidcJwksProvider; readonly registry: PrincipalRegistry; readonly sessions: SessionStore };
  readonly parentFor: (id: string, tenant?: string) => Principal | undefined;
  readonly residency: ResidencyPolicy;
}

export function loadInstalledOrganizationRuntime(refs: NonNullable<CapturedRuntimeContract["organization"]>): InstalledOrganizationRuntime {
  if (!SAFE.test(refs.tenantId)) throw new Error("organization tenant id is invalid");
  if (refs.auditScope !== "tenant") throw new Error("installed organization audit scope must be tenant");
  const jwks = protectedJson(refs.jwksPath, "organization JWKS") as { keys?: unknown };
  if (!Array.isArray(jwks.keys) || jwks.keys.length < 1 || jwks.keys.length > 64) throw new Error("organization JWKS requires one bounded key set");
  const roster = protectedJson(refs.principalRosterPath, "organization principal roster") as Record<string, unknown>;
  exact(roster, ["schema", "tenantId", "principals"], "organization principal roster");
  if (roster["schema"] !== "keep.principal-roster/v1" || roster["tenantId"] !== refs.tenantId || !Array.isArray(roster["principals"]) || roster["principals"].length < 1 || roster["principals"].length > 10_000) throw new Error("organization principal roster binding is invalid");
  const mappings = roster["principals"].map((value, index) => principal(value, refs.tenantId, index));
  const policy = protectedJson(refs.delegationPolicyPath, "organization delegation policy") as Record<string, unknown>;
  exact(policy, ["schema", "tenantId", "parents"], "organization delegation policy");
  if (policy["schema"] !== "keep.delegation-policy/v1" || policy["tenantId"] !== refs.tenantId || !Array.isArray(policy["parents"]) || policy["parents"].length < 1 || policy["parents"].length > mappings.length) throw new Error("organization delegation policy binding is invalid");
  const admittedParents = new Set(policy["parents"].map((value) => safeText(value, "delegation parent")));
  const principals = new Map(mappings.map((mapping) => [mapping.id!, { id: mapping.id!, kind: "human" as const, role: mapping.role, tenant: refs.tenantId }]));
  for (const id of admittedParents) if (!principals.has(id)) throw new Error("delegation policy names a principal outside the roster");
  const residency = protectedJson(refs.residencyPolicyPath, "organization residency policy") as Record<string, unknown>;
  exact(residency, ["schema", "tenantId", "allowedPurposes", "allowedRegions", "egressAllowlist"], "organization residency policy");
  if (residency["schema"] !== "keep.residency-policy/v1" || residency["tenantId"] !== refs.tenantId) throw new Error("organization residency policy binding is invalid");
  const allowedPurposes = safeList(residency["allowedPurposes"], "residency purpose");
  const allowedRegions = safeList(residency["allowedRegions"], "residency region");
  const egressAllowlist = hostList(residency["egressAllowlist"]);
  return Object.freeze({
    identity: Object.freeze({ provider: new OidcJwksProvider({ jwks: jwks as Jwks, issuer: refs.issuer, audience: refs.audience }), registry: new PrincipalRegistry(mappings), sessions: new SessionStore() }),
    parentFor: (id: string, tenant?: string) => tenant === refs.tenantId && admittedParents.has(id) ? principals.get(id) : undefined,
    residency: Object.freeze({ allowedPurposes, allowedRegions, egressAllowlist }),
  });
}

function protectedJson(path: string, label: string): unknown {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > MAX || (process.platform !== "win32" && (stat.mode & 0o077) !== 0)) throw new Error(`${label} must be a bounded mode-0600 regular file`);
  try { return JSON.parse(readFileSync(path, "utf8")) as unknown; } catch { throw new Error(`${label} is not valid JSON`); }
}
function principal(value: unknown, tenantId: string, index: number): PrincipalMapping {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`principal ${index} is invalid`);
  const row = value as Record<string, unknown>; exact(row, ["id", "role", "subject"], `principal ${index}`);
  const id = safeText(row["id"], `principal ${index} id`), subject = safeText(row["subject"], `principal ${index} subject`);
  if (typeof row["role"] !== "string" || !ROLES.has(row["role"] as Role)) throw new Error(`principal ${index} role is invalid`);
  return { id, subject, role: row["role"] as Role, tenant: tenantId };
}
function safeText(value: unknown, label: string): string { if (typeof value !== "string" || !SAFE.test(value)) throw new Error(`${label} is invalid`); return value; }
function safeList(value: unknown, label: string): readonly string[] { if (!Array.isArray(value) || value.length < 1 || value.length > 128) throw new Error(`organization ${label} list is invalid`); return Object.freeze([...new Set(value.map((item) => safeText(item, label)))]); }
function hostList(value: unknown): readonly string[] { if (!Array.isArray(value) || value.length < 1 || value.length > 128) throw new Error("organization residency host list is invalid"); return Object.freeze([...new Set(value.map((item) => { const host = safeText(item, "residency host").toLowerCase(); if (host.includes("..")) throw new Error("residency host is invalid"); return host; }))]); }
function exact(row: Record<string, unknown>, keys: readonly string[], label: string): void { if (Object.keys(row).sort().join(",") !== [...keys].sort().join(",")) throw new Error(`${label} contains unknown or missing fields`); }
