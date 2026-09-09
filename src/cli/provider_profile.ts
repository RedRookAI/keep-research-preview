import { closeSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { ProviderAuthority, ProviderLocation } from "./runtime_config.js";

export const PROVIDER_PROFILE_SCHEMA = "keep.provider-profile/v1";
const MAX_PROFILE_BYTES = 64 * 1024;
const PROVIDER_FIELDS = ["KEEP_PROVIDER", "KEEP_PROVIDER_LOCATION", "KEEP_PROVIDER_AUTHORITY", "KEEP_PROVIDER_BASE_URL", "KEEP_PROVIDER_MODEL", "KEEP_PROVIDER_API_KEY", "KEEP_PROVIDER_API_KEY_FILE", "KEEP_PROVIDER_API_KEY_STDIN", "KEEP_REMOTE_PROCESSING_PURPOSE", "KEEP_REMOTE_PROCESSING_REGION", "KEEP_PROVIDER_ROUTE_ALLOWLIST", "KEEP_RELEASE_BUNDLE", "KEEP_RELEASE_TRUST_ROOT"] as const;

type CredentialProfile = { readonly kind: "environment" } | { readonly kind: "file"; readonly path: string } | { readonly kind: "stdin" } | null;
interface OrganizationProfile {
  readonly tenantId: string;
  readonly issuer: string;
  readonly audience: string;
  readonly jwksPath: string;
  readonly principalRosterPath: string;
  readonly delegationPolicyPath: string;
  readonly residencyPolicyPath: string;
  readonly scannerEnginePath: string;
  readonly auditScope: string;
}
export interface ProviderProfile {
  readonly schema: typeof PROVIDER_PROFILE_SCHEMA;
  readonly name: string;
  readonly location: Exclude<ProviderLocation, "offline">;
  readonly authority: ProviderAuthority;
  readonly protocol: "openai-compatible" | "anthropic-compatible";
  readonly endpoint: string;
  readonly model: string;
  readonly purpose: string;
  readonly region: string;
  readonly credential: CredentialProfile;
  readonly routing?: { readonly providers: readonly string[] };
  readonly organization?: OrganizationProfile;
  readonly release?: { readonly bundlePath: string; readonly trustRootPath: string };
}

export function defaultProviderProfilePath(env: NodeJS.ProcessEnv = process.env): string {
  if (process.platform === "win32") return join(env["APPDATA"] ?? join(homedir(), "AppData", "Roaming"), "Keep", "provider.json");
  return join(env["XDG_CONFIG_HOME"] ?? join(homedir(), ".config"), "keep", "provider.json");
}

export function loadProviderProfile(path: string): ProviderProfile {
  return parseProviderProfile(readProtectedProfile(path, "provider profile"));
}

/** Shared bounded, non-secret configuration file boundary. Never loads credentials. */
export function readProtectedProfile(path: string, label: string): unknown {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path`);
  const stat = statSync(path);
  if (!stat.isFile() || stat.size > MAX_PROFILE_BYTES) throw new Error(`${label} must be a regular file no larger than 65536 bytes`);
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) throw new Error(`${label} permits group or other access; require mode 0600 or stricter`);
  let parsed: unknown;
  try { parsed = JSON.parse(readFileSync(path, "utf8")); } catch { throw new Error(`${label} is not valid JSON`); }
  return parsed;
}

export function parseProviderProfile(value: unknown): ProviderProfile {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("provider profile must be an object");
  const raw = value as Record<string, unknown>;
  const allowed = new Set(["schema", "name", "location", "authority", "protocol", "endpoint", "model", "purpose", "region", "credential", "routing", "organization", "release"]);
  for (const key of Object.keys(raw)) if (!allowed.has(key)) throw new Error(`provider profile contains unknown field ${key}`);
  if (raw["schema"] !== PROVIDER_PROFILE_SCHEMA) throw new Error(`provider profile schema must be ${PROVIDER_PROFILE_SCHEMA}`);
  const name = text(raw["name"], "name");
  const location = one(raw["location"], ["local", "external"] as const, "location");
  const authority = one(raw["authority"], ["owner", "organization"] as const, "authority");
  const protocol = one(raw["protocol"], ["openai-compatible", "anthropic-compatible"] as const, "protocol");
  const endpoint = text(raw["endpoint"], "endpoint");
  const model = text(raw["model"], "model");
  const purpose = text(raw["purpose"], "purpose");
  const region = text(raw["region"], "region");
  const credential = credentialProfile(raw["credential"]);
  const routing = raw["routing"] === undefined ? undefined : routingProfile(raw["routing"]);
  const organization = raw["organization"] === undefined ? undefined : organizationProfile(raw["organization"]);
  const release = raw["release"] === undefined ? undefined : releaseProfile(raw["release"]);
  if (authority === "owner" && (organization !== undefined || release !== undefined)) throw new Error("owner profile cannot contain organization or release authority");
  if (authority === "organization" && (organization === undefined || release === undefined)) throw new Error("organization profile requires organization and release references");
  if (credential === null && !(authority === "owner" && location === "local")) throw new Error("only owner/local may omit a credential reference");
  if (routing !== undefined && (protocol !== "openai-compatible" || location !== "external")) throw new Error("provider routing is only valid for external OpenAI-compatible endpoints");
  return Object.freeze({ schema: PROVIDER_PROFILE_SCHEMA, name, location, authority, protocol, endpoint, model, purpose, region, credential, ...(routing ? { routing } : {}), ...(organization ? { organization } : {}), ...(release ? { release } : {}) });
}

export function profileEnvironment(profile: ProviderProfile): Readonly<Record<string, string>> {
  const env: Record<string, string> = {
    KEEP_PROVIDER: profile.protocol,
    KEEP_PROVIDER_LOCATION: profile.location,
    KEEP_PROVIDER_AUTHORITY: profile.authority,
    KEEP_PROVIDER_BASE_URL: profile.endpoint,
    KEEP_PROVIDER_MODEL: profile.model,
    KEEP_REMOTE_PROCESSING_PURPOSE: profile.purpose,
    KEEP_REMOTE_PROCESSING_REGION: profile.region,
  };
  if (profile.credential?.kind === "environment") env["KEEP_PROVIDER_API_KEY"] = "__KEEP_PROFILE_ENV_REFERENCE__";
  if (profile.credential?.kind === "file") env["KEEP_PROVIDER_API_KEY_FILE"] = profile.credential.path;
  if (profile.credential?.kind === "stdin") env["KEEP_PROVIDER_API_KEY_STDIN"] = "1";
  if (profile.routing) env["KEEP_PROVIDER_ROUTE_ALLOWLIST"] = profile.routing.providers.join(",");
  if (profile.release) { env["KEEP_RELEASE_BUNDLE"] = profile.release.bundlePath; env["KEEP_RELEASE_TRUST_ROOT"] = profile.release.trustRootPath; }
  if (profile.organization) {
    env["KEEP_TENANT_ID"] = profile.organization.tenantId;
    env["KEEP_IDENTITY_ISSUER"] = profile.organization.issuer;
    env["KEEP_IDENTITY_AUDIENCE"] = profile.organization.audience;
    env["KEEP_IDENTITY_JWKS"] = profile.organization.jwksPath;
    env["KEEP_PRINCIPAL_ROSTER"] = profile.organization.principalRosterPath;
    env["KEEP_DELEGATION_POLICY"] = profile.organization.delegationPolicyPath;
    env["KEEP_RESIDENCY_POLICY"] = profile.organization.residencyPolicyPath;
    env["KEEP_SCANNER_ENGINE"] = profile.organization.scannerEnginePath;
    env["KEEP_AUDIT_SCOPE"] = profile.organization.auditScope;
  }
  return env;
}

/** Resolve one complete provider layer. Project/test variables remain independent inputs. */
export function applyProviderProfile(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const profilePath = env["KEEP_PROFILE"] ?? defaultProviderProfilePath(env);
  const hasExplicitProvider = env["KEEP_PROVIDER"] !== undefined;
  const hasPartialProvider = PROVIDER_FIELDS.some((field) => !["KEEP_PROVIDER", "KEEP_PROVIDER_API_KEY", "KEEP_PROVIDER_API_KEY_FILE", "KEEP_PROVIDER_API_KEY_STDIN"].includes(field) && env[field] !== undefined);
  if (hasExplicitProvider) return { ...env };
  if (hasPartialProvider) throw new Error("provider environment overrides require KEEP_PROVIDER so one complete layer wins");
  let profile: ProviderProfile;
  try { profile = loadProviderProfile(profilePath); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT" && env["KEEP_PROFILE"] === undefined) return { ...env }; throw error; }
  const materialized = { ...profileEnvironment(profile) };
  if (profile.credential?.kind === "environment") {
    const secret = env["KEEP_PROVIDER_API_KEY"];
    if (!secret) throw new Error("profile selects environment credential but KEEP_PROVIDER_API_KEY is absent");
    materialized["KEEP_PROVIDER_API_KEY"] = secret;
  }
  return { ...env, ...materialized };
}

export function writeProviderProfile(path: string, profile: ProviderProfile): void {
  writeProtectedProfile(path, profile);
}

export function writeProtectedProfile(path: string, profile: unknown): void {
  if (!isAbsolute(path)) throw new Error("provider profile path must be absolute");
  const encoded = `${JSON.stringify(profile, null, 2)}\n`;
  if (Buffer.byteLength(encoded) > MAX_PROFILE_BYTES) throw new Error("profile exceeds 65536 bytes");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  let fd: number | undefined;
  try {
    fd = openSync(temporary, "wx", 0o600);
    writeFileSync(fd, encoded, "utf8");
    closeSync(fd); fd = undefined; renameSync(temporary, path);
  } finally { if (fd !== undefined) closeSync(fd); try { unlinkSync(temporary); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; } }
}

export function profileFromArgs(args: readonly string[], cwd: string): { readonly path: string; readonly profile: ProviderProfile } {
  const fields = new Map<string, string>();
  for (const arg of args) {
    const match = /^--([a-z][a-z-]*)=(.*)$/u.exec(arg);
    if (!match || fields.has(match[1]!)) throw new Error(`invalid or duplicate provider option: ${arg}`);
    fields.set(match[1]!, match[2]!);
  }
  const get = (name: string) => { const value = fields.get(name); if (!value) throw new Error(`--${name}=... is required`); return value; };
  const path = resolve(cwd, fields.get("profile") ?? defaultProviderProfilePath());
  const authority = get("authority");
  const credentialKind = fields.get("credential") ?? (authority === "owner" && fields.get("location") === "local" ? "none" : "environment");
  const credential: CredentialProfile = credentialKind === "none" ? null : credentialKind === "environment" ? { kind: "environment" } : credentialKind === "stdin" ? { kind: "stdin" } : credentialKind === "file" ? { kind: "file", path: get("credential-file") } : (() => { throw new Error("--credential must be none, environment, file, or stdin"); })();
  const organization = authority === "organization" ? {
    tenantId: get("tenant"), issuer: get("issuer"), audience: get("audience"), jwksPath: get("jwks"), principalRosterPath: get("principal-roster"), delegationPolicyPath: get("delegation-policy"), residencyPolicyPath: get("residency-policy"), scannerEnginePath: get("scanner-engine"), auditScope: get("audit-scope"),
  } : undefined;
  const release = authority === "organization" ? { bundlePath: get("release-bundle"), trustRootPath: get("release-trust-root") } : undefined;
  const routing = fields.get("providers") === undefined ? undefined : { providers: fields.get("providers")!.split(",").filter(Boolean) };
  const profile = parseProviderProfile({ schema: PROVIDER_PROFILE_SCHEMA, name: get("name"), location: get("location"), authority, protocol: get("protocol"), endpoint: get("endpoint"), model: get("model"), purpose: get("purpose"), region: get("region"), credential, ...(routing ? { routing } : {}), ...(organization ? { organization } : {}), ...(release ? { release } : {}) });
  return { path, profile };
}

function text(value: unknown, field: string): string { if (typeof value !== "string" || value.length === 0 || value.length > 8_192 || value.includes("\0") || value.trim() !== value) throw new Error(`provider profile ${field} is malformed`); return value; }
function one<const T extends readonly string[]>(value: unknown, values: T, field: string): T[number] { if (typeof value !== "string" || !values.includes(value)) throw new Error(`provider profile ${field} must be ${values.join(" or ")}`); return value as T[number]; }
function credentialProfile(value: unknown): CredentialProfile { if (value === null) return null; if (value === undefined || typeof value !== "object" || Array.isArray(value)) throw new Error("provider profile credential is invalid"); const raw = value as Record<string, unknown>; const kind = one(raw["kind"], ["environment", "file", "stdin"] as const, "credential.kind"); if (kind === "file") return { kind, path: absolute(text(raw["path"], "credential.path"), "credential.path") }; if (Object.keys(raw).some((key) => key !== "kind")) throw new Error("provider profile credential contains unknown fields"); return { kind }; }
function organizationProfile(value: unknown): OrganizationProfile { const raw = object(value, "organization"); return { tenantId: text(raw["tenantId"], "organization.tenantId"), issuer: text(raw["issuer"], "organization.issuer"), audience: text(raw["audience"], "organization.audience"), jwksPath: absolute(text(raw["jwksPath"], "organization.jwksPath"), "organization.jwksPath"), principalRosterPath: absolute(text(raw["principalRosterPath"], "organization.principalRosterPath"), "organization.principalRosterPath"), delegationPolicyPath: absolute(text(raw["delegationPolicyPath"], "organization.delegationPolicyPath"), "organization.delegationPolicyPath"), residencyPolicyPath: absolute(text(raw["residencyPolicyPath"], "organization.residencyPolicyPath"), "organization.residencyPolicyPath"), scannerEnginePath: absolute(text(raw["scannerEnginePath"], "organization.scannerEnginePath"), "organization.scannerEnginePath"), auditScope: text(raw["auditScope"], "organization.auditScope") }; }
function releaseProfile(value: unknown) { const raw = object(value, "release"); return { bundlePath: absolute(text(raw["bundlePath"], "release.bundlePath"), "release.bundlePath"), trustRootPath: absolute(text(raw["trustRootPath"], "release.trustRootPath"), "release.trustRootPath") }; }
function routingProfile(value: unknown) { const raw = object(value, "routing"); if (Object.keys(raw).join(",") !== "providers" || !Array.isArray(raw["providers"]) || raw["providers"].length < 1 || raw["providers"].length > 32) throw new Error("provider profile routing requires one bounded providers list"); return { providers: raw["providers"].map((item) => text(item, "routing.providers")) }; }
function object(value: unknown, field: string): Record<string, unknown> { if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`provider profile ${field} must be an object`); return value as Record<string, unknown>; }
function absolute(value: string, field: string): string { if (!isAbsolute(value)) throw new Error(`provider profile ${field} must be absolute`); return value; }
