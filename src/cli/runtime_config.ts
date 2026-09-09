/**
 * Installed-runtime configuration (A3).
 *
 * One strict resolver owns provider, credential reference, repository and workspace selection. It never
 * guesses remote intent, never falls back from an invalid remote configuration to local mode, and never
 * loads an adapter named by configuration. Only built-in dialect objects can cross this boundary.
 */

import { execFileSync } from "node:child_process";
import { realpathSync, statSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { HttpProvider } from "../gateway/http_provider.js";
import { LocalProvider } from "../gateway/local_provider.js";
import type { ModelProvider } from "../gateway/gateway.js";
import type { RemoteProcessingDeclaration } from "../gateway/governed_remote_provider.js";
import type { ResidencyPolicy } from "../governance/residency.js";
import { anthropicDialect, openAiDialect, openAiDialectWithRouting, type ExternalRoutingPolicy, type WireDialect } from "../gateway/wire_dialect.js";
import { encoderCredentialReference, loadEncoderProfile, type EncoderProfile } from "./encoder_profile.js";

export type ProviderMode = "local" | "openai-compatible" | "anthropic-compatible";
export type ProviderLocation = "offline" | "local" | "external";
export type ProviderAuthority = "owner" | "organization";

export interface ResolvedPath {
  readonly root: string;
  readonly source: "KEEP_REPOSITORY" | "KEEP_WORKSPACE" | "KEEP_WORKSPACE_BASE" | "repository-default";
}

export type CredentialReference =
  | { readonly kind: "environment"; readonly name: "KEEP_PROVIDER_API_KEY" | "KEEP_ENCODER_API_KEY" }
  | { readonly kind: "file"; readonly path: string }
  | { readonly kind: "stdin" };

export interface CapturedTestCommand {
  readonly command: string;
  readonly args: readonly string[];
  readonly timeoutMs: number;
  readonly cpuLimitSec: number;
  readonly maxOutputBytes: number;
  readonly envAllowlist: readonly string[];
}

export interface CapturedInstalledProjectConfig {
  readonly repository: ResolvedPath;
  readonly workspaceBase: ResolvedPath;
  readonly revision: string;
  readonly repoRef: string;
  readonly baseBranch: string;
  readonly testCommand: CapturedTestCommand;
  readonly posture: "autonomous" | "policy-calibrated" | "approval-required";
}

export interface CapturedRuntimeContract {
  readonly encoder?: EncoderProfile;
  readonly encoderCredentialReference?: CredentialReference;
  readonly provider: Omit<Extract<ResolvedProvider, { readonly mode: "openai-compatible" | "anthropic-compatible" }>, "apiKey"> | { readonly mode: "local"; readonly location: "offline"; readonly authority: "owner" };
  readonly credentialReference?: CredentialReference;
  readonly remoteProcessing?: RemoteProcessingDeclaration;
  readonly externalRouting?: ExternalRoutingPolicy;
  readonly residency?: ResidencyPolicy;
  readonly memoryProvider: { readonly mode: "local"; readonly purpose: "credential-free-memory-embedding" };
  readonly installedProject?: CapturedInstalledProjectConfig;
  readonly releaseAdmission?: { readonly bundlePath: string; readonly trustRootPath: string };
  readonly organization?: {
    readonly tenantId: string;
    readonly issuer: string;
    readonly audience: string;
    readonly jwksPath: string;
    readonly principalRosterPath: string;
    readonly delegationPolicyPath: string;
    readonly residencyPolicyPath: string;
    readonly scannerEnginePath: string;
    readonly auditScope: string;
  };
}

export type ResolvedProvider =
  | { readonly mode: "local"; readonly location?: "offline"; readonly authority?: "owner" }
  | {
      readonly mode: "openai-compatible" | "anthropic-compatible";
      readonly baseUrl: string;
      readonly model: string;
      readonly location?: "local" | "external";
      readonly authority?: ProviderAuthority;
      /** A same-process secret until Track A8 moves custody into native D3. Never render or persist it. */
      readonly apiKey: string;
      readonly externalRouting?: ExternalRoutingPolicy;
    };

export interface ResolvedRuntimeConfig {
  readonly provider: ResolvedProvider;
  readonly remoteProcessing?: RemoteProcessingDeclaration;
  readonly residency?: ResidencyPolicy;
  /** Memory embeddings stay credential-free/local until a separately brokered embedding role is configured. */
  readonly memoryProvider: { readonly mode: "local"; readonly purpose: "credential-free-memory-embedding" };
  readonly repository?: ResolvedPath;
  readonly workspace?: ResolvedPath;
}

export interface RuntimeIntent {
  readonly provider: ResolvedProvider;
  readonly remoteProcessing?: RemoteProcessingDeclaration;
  readonly residency?: ResidencyPolicy;
  readonly memoryProvider: { readonly mode: "local"; readonly purpose: "credential-free-memory-embedding" };
}

function externalRoutingFromEnv(env: Readonly<Record<string, string | undefined>>, mode: ProviderMode, location: ProviderLocation): ExternalRoutingPolicy | undefined {
  const raw = env["KEEP_PROVIDER_ROUTE_ALLOWLIST"];
  if (raw === undefined) return undefined;
  if (mode !== "openai-compatible" || location !== "external") throw new RuntimeConfigError("KEEP_PROVIDER_ROUTE_ALLOWLIST", "is only valid for external OpenAI-compatible endpoints");
  const providers = raw.split(",");
  if (providers.length < 1 || providers.length > 32 || providers.some((item) => !/^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$/u.test(item))) throw new RuntimeConfigError("KEEP_PROVIDER_ROUTE_ALLOWLIST", "must be a comma-separated bounded provider allowlist");
  return { zeroDataRetention: true, dataCollection: "deny", allowFallbacks: false, providers };
}

export class RuntimeConfigError extends Error {
  constructor(readonly field: string, message: string) {
    super(`${field}: ${message}`);
    this.name = "RuntimeConfigError";
  }
}

export interface RuntimeConfigContext {
  readonly cwd: string;
  /** False only for an explicitly selected non-repository domain surface. */
  readonly repositoryRequired?: boolean;
  readonly realpath?: (path: string) => string;
  readonly isDirectory?: (path: string) => boolean;
  readonly repositoryRoot?: (path: string) => string;
  readonly resolveCommit?: (repository: string, revision: string) => string;
  readonly validateBranch?: (repository: string, branch: string) => string;
  readonly resolveBranchCommit?: (repository: string, branch: string) => string;
  readonly platform?: NodeJS.Platform;
  readonly processEnv?: NodeJS.ProcessEnv;
}

const REMOTE_ONLY_FIELDS = ["KEEP_PROVIDER_LOCATION", "KEEP_PROVIDER_AUTHORITY", "KEEP_PROVIDER_BASE_URL", "KEEP_PROVIDER_MODEL", "KEEP_PROVIDER_API_KEY", "KEEP_PROVIDER_API_KEY_FILE", "KEEP_PROVIDER_API_KEY_STDIN", "KEEP_REMOTE_PROCESSING_PURPOSE", "KEEP_REMOTE_PROCESSING_REGION", "KEEP_PROVIDER_ROUTE_ALLOWLIST", "KEEP_RELEASE_BUNDLE", "KEEP_RELEASE_TRUST_ROOT"] as const;
const MAX_FIELD = 8_192;
const SAFE_REF = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const EXACT_REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const SAFE_ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const CREDENTIAL_ENV = /(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/iu;
const DEFAULT_TEST_TIMEOUT_MS = 10 * 60_000;
const DEFAULT_TEST_CPU_LIMIT_SEC = 600;
const DEFAULT_TEST_MAX_OUTPUT_BYTES = 8 * 1024 * 1024;

/** Capture immutable installed configuration without loading credentials or creating state. */
export function captureRuntimeContract(
  env: Readonly<Record<string, string | undefined>>,
  context: RuntimeConfigContext,
  options: { readonly projectRequired?: boolean } = {},
): CapturedRuntimeContract {
  const rawMode = required(env, "KEEP_PROVIDER").toLowerCase();
  if (rawMode !== "local" && rawMode !== "openai-compatible" && rawMode !== "anthropic-compatible") {
    throw new RuntimeConfigError("KEEP_PROVIDER", "must name local, openai-compatible, or anthropic-compatible (case-insensitive)");
  }
  let provider: CapturedRuntimeContract["provider"];
  let credentialReference: CredentialReference | undefined;
  let remoteProcessing: RemoteProcessingDeclaration | undefined;
  let externalRouting: ExternalRoutingPolicy | undefined;
  let residency: ResidencyPolicy | undefined;
  let releaseAdmission: CapturedRuntimeContract["releaseAdmission"];
  let organization: CapturedRuntimeContract["organization"];
  if (rawMode === "local") {
    for (const field of REMOTE_ONLY_FIELDS) if (env[field] !== undefined) throw new RuntimeConfigError(field, "is remote-only and must be absent when KEEP_PROVIDER=local");
    provider = { mode: "local", location: "offline", authority: "owner" };
  } else {
    const baseUrl = normalizeBaseUrl(required(env, "KEEP_PROVIDER_BASE_URL"));
    const model = bounded(required(env, "KEEP_PROVIDER_MODEL"), "KEEP_PROVIDER_MODEL");
    const location = providerLocation(env, baseUrl);
    const authority = providerAuthority(env);
    credentialReference = captureCredentialReference(env, context.cwd, authority === "owner" && location === "local" && isLoopbackUrl(baseUrl));
    const purpose = bounded(required(env, "KEEP_REMOTE_PROCESSING_PURPOSE"), "KEEP_REMOTE_PROCESSING_PURPOSE");
    const region = bounded(required(env, "KEEP_REMOTE_PROCESSING_REGION"), "KEEP_REMOTE_PROCESSING_REGION");
    provider = { mode: rawMode, baseUrl, model, location, authority };
    remoteProcessing = { purpose, region };
    residency = { allowedPurposes: [purpose], allowedRegions: [region], egressAllowlist: [new URL(baseUrl).hostname] };
    externalRouting = externalRoutingFromEnv(env, rawMode, location);
    if (authority === "organization") {
      if (env["KEEP_PROVIDER_AUTHORITY"] !== undefined) organization = captureOrganizationReferences(env, context.cwd);
      releaseAdmission = {
      bundlePath: absolutePath(required(env, "KEEP_RELEASE_BUNDLE"), "KEEP_RELEASE_BUNDLE", context.cwd),
      trustRootPath: absolutePath(env["KEEP_RELEASE_TRUST_ROOT"] ?? defaultTrustRoot(context), "KEEP_RELEASE_TRUST_ROOT", context.cwd),
      };
    }
    else if (env["KEEP_RELEASE_BUNDLE"] !== undefined || env["KEEP_RELEASE_TRUST_ROOT"] !== undefined) throw new RuntimeConfigError("KEEP_RELEASE_BUNDLE", "is organization-only; owner authority is explicit configuration admission, not release signing");
  }
  const encoderPath = env["KEEP_ENCODER_PROFILE"];
  if (encoderPath === undefined && env["KEEP_ENCODER_API_KEY"] !== undefined) throw new RuntimeConfigError("KEEP_ENCODER_PROFILE", "is required when an encoder credential is present");
  const encoder = encoderPath === undefined ? undefined : loadEncoderProfile(absolutePath(encoderPath, "KEEP_ENCODER_PROFILE", context.cwd));
  const encoderCredential = encoder === undefined ? undefined : encoderCredentialReference(encoder, env);
  if (encoder !== undefined) {
    if (encoder.authority !== provider.authority || (encoder.authority === "organization" && organization === undefined)) throw new RuntimeConfigError("KEEP_ENCODER_PROFILE", "encoder and runtime must share owner or organization authority; organization identity and independent release references are required");
    if (encoderCredential?.kind === "stdin" && credentialReference?.kind === "stdin") throw new RuntimeConfigError("KEEP_ENCODER_PROFILE", "chat and encoder cannot both consume the same stdin credential stream");
    // Owner configuration is its explicit egress policy. Enterprise composition instead
    // uses the loaded organization policy; encoder configuration never widens that policy.
    if (encoder.authority === "owner") residency = {
      allowedPurposes: [...new Set([...(residency?.allowedPurposes ?? []), encoder.processing.query.purpose, encoder.processing.document.purpose])],
      allowedRegions: [...new Set([...(residency?.allowedRegions ?? []), encoder.processing.query.region, encoder.processing.document.region])],
      egressAllowlist: [...new Set([...(residency?.egressAllowlist ?? []), new URL(encoder.endpoint).hostname])],
    };
  }
  const installedProject = captureInstalledProject(env, context, options.projectRequired === true);
  return Object.freeze({ provider, ...(credentialReference ? { credentialReference } : {}), ...(remoteProcessing ? { remoteProcessing } : {}), ...(residency ? { residency } : {}), ...(externalRouting ? { externalRouting } : {}), memoryProvider: localMemoryProvider(), ...(installedProject ? { installedProject } : {}), ...(releaseAdmission ? { releaseAdmission } : {}), ...(organization ? { organization } : {}), ...(encoder ? { encoder } : {}), ...(encoderCredential ? { encoderCredentialReference: encoderCredential } : {}) });
}

export function resolveRuntimeConfig(
  env: Readonly<Record<string, string | undefined>>,
  context: RuntimeConfigContext,
): ResolvedRuntimeConfig {
  const intent = resolveRuntimeIntent(env, context.repositoryRequired === undefined ? {} : { repositoryRequired: context.repositoryRequired });
  const rawMode = intent.provider.mode;
  const repository = resolveRepository(env["KEEP_REPOSITORY"], context);
  const workspace = resolveWorkspace(env["KEEP_WORKSPACE"], repository, context);

  if (rawMode === "local") return { ...intent, ...(repository ? { repository, workspace: workspace! } : {}) };
  if (!repository || !workspace) {
    if (context.repositoryRequired === false) return intent;
    throw new RuntimeConfigError("KEEP_REPOSITORY", "is required for a remote provider; Keep never guesses a target repository");
  }
  return { ...intent, repository, workspace };
}

/** Pure, bounded configuration capture. It performs no filesystem access and starts no child process. */
export function resolveRuntimeIntent(env: Readonly<Record<string, string | undefined>>, options: { readonly repositoryRequired?: boolean } = {}): RuntimeIntent {
  const rawMode = required(env, "KEEP_PROVIDER").toLowerCase();
  if (rawMode !== "local" && rawMode !== "openai-compatible" && rawMode !== "anthropic-compatible") {
    throw new RuntimeConfigError("KEEP_PROVIDER", "must name local, openai-compatible, or anthropic-compatible (case-insensitive)");
  }

  if (rawMode === "local") {
    for (const field of REMOTE_ONLY_FIELDS) {
      if (env[field] !== undefined) {
        throw new RuntimeConfigError(field, "is remote-only and must be absent when KEEP_PROVIDER=local");
      }
    }
    return { provider: { mode: "local", location: "offline", authority: "owner" }, memoryProvider: localMemoryProvider() };
  }
  if (options.repositoryRequired !== false && (env["KEEP_REPOSITORY"] === undefined || env["KEEP_REPOSITORY"] === "")) {
    throw new RuntimeConfigError("KEEP_REPOSITORY", "is required for a remote provider; Keep never guesses a target repository");
  }
  const baseUrl = normalizeBaseUrl(required(env, "KEEP_PROVIDER_BASE_URL"));
  const model = bounded(required(env, "KEEP_PROVIDER_MODEL"), "KEEP_PROVIDER_MODEL");
  const location = providerLocation(env, baseUrl);
  const authority = providerAuthority(env);
  const optionalCredential = authority === "owner" && location === "local" && isLoopbackUrl(baseUrl);
  const apiKey = env["KEEP_PROVIDER_API_KEY"] === undefined && optionalCredential ? "" : secret(env["KEEP_PROVIDER_API_KEY"]);
  const purpose = bounded(required(env, "KEEP_REMOTE_PROCESSING_PURPOSE"), "KEEP_REMOTE_PROCESSING_PURPOSE");
  const region = bounded(required(env, "KEEP_REMOTE_PROCESSING_REGION"), "KEEP_REMOTE_PROCESSING_REGION");
  const host = new URL(baseUrl).hostname;
  const externalRouting = externalRoutingFromEnv(env, rawMode, location);
  return { provider: { mode: rawMode, baseUrl, model, apiKey, location, authority, ...(externalRouting ? { externalRouting } : {}) }, remoteProcessing: { purpose, region }, residency: { allowedPurposes: [purpose], allowedRegions: [region], egressAllowlist: [host] }, memoryProvider: localMemoryProvider() };
}

export function createConfiguredProvider(config: ResolvedProvider): ModelProvider {
  if (config.mode === "local") return new LocalProvider();
  const dialect: WireDialect = config.mode === "openai-compatible" ? (config.externalRouting ? openAiDialectWithRouting(config.externalRouting) : openAiDialect) : anthropicDialect;
  return new HttpProvider({ baseUrl: config.baseUrl, apiKey: config.apiKey, model: config.model, dialect });
}

export function describeRuntimeConfig(config: ResolvedRuntimeConfig): Readonly<Record<string, string>> {
  return {
    provider: config.provider.mode,
    memoryProvider: config.memoryProvider.mode,
    ...(config.provider.mode === "local" ? {} : { endpointOrigin: new URL(config.provider.baseUrl).origin, model: config.provider.model }),
    ...(config.repository ? { repository: config.repository.root, workspace: config.workspace!.root } : {}),
  };
}

function required(env: Readonly<Record<string, string | undefined>>, field: string): string {
  const value = env[field];
  if (value === undefined || value === "") {
    throw new RuntimeConfigError(field, field === "KEEP_PROVIDER" ? "is required; choose explicit local or remote mode" : "is required");
  }
  return bounded(value, field);
}

function bounded(value: string, field: string): string {
  if (value.length > MAX_FIELD) throw new RuntimeConfigError(field, `exceeds ${MAX_FIELD} bytes`);
  if (value.includes("\0") || value !== value.trim()) throw new RuntimeConfigError(field, "contains NUL or surrounding whitespace");
  return value;
}

function secret(value: string | undefined): string {
  if (value === undefined || value === "") throw new RuntimeConfigError("KEEP_PROVIDER_API_KEY", "is required");
  if (value.length > MAX_FIELD || value.includes("\0") || value !== value.trim()) {
    throw new RuntimeConfigError("KEEP_PROVIDER_API_KEY", "is malformed");
  }
  return value;
}

function captureCredentialReference(env: Readonly<Record<string, string | undefined>>, cwd: string, optional: boolean): CredentialReference | undefined {
  const selected = [env["KEEP_PROVIDER_API_KEY"] !== undefined ? "environment" : undefined, env["KEEP_PROVIDER_API_KEY_FILE"] !== undefined ? "file" : undefined, env["KEEP_PROVIDER_API_KEY_STDIN"] !== undefined ? "stdin" : undefined].filter((value): value is string => value !== undefined);
  if (selected.length === 0 && optional) return undefined;
  if (selected.length !== 1) throw new RuntimeConfigError("KEEP_PROVIDER_API_KEY", "select exactly one credential source: environment, file, or stdin");
  if (selected[0] === "environment") { secret(env["KEEP_PROVIDER_API_KEY"]); return { kind: "environment", name: "KEEP_PROVIDER_API_KEY" }; }
  if (selected[0] === "file") return { kind: "file", path: absolutePath(required(env, "KEEP_PROVIDER_API_KEY_FILE"), "KEEP_PROVIDER_API_KEY_FILE", cwd) };
  if (env["KEEP_PROVIDER_API_KEY_STDIN"] !== "1") throw new RuntimeConfigError("KEEP_PROVIDER_API_KEY_STDIN", "must be exactly 1");
  return { kind: "stdin" };
}

function providerAuthority(env: Readonly<Record<string, string | undefined>>): ProviderAuthority {
  const value = (env["KEEP_PROVIDER_AUTHORITY"] ?? "organization").toLowerCase();
  if (value !== "owner" && value !== "organization") throw new RuntimeConfigError("KEEP_PROVIDER_AUTHORITY", "must be owner or organization");
  return value;
}

function providerLocation(env: Readonly<Record<string, string | undefined>>, baseUrl: string): "local" | "external" {
  const inferred = isLoopbackUrl(baseUrl) ? "local" : "external";
  const value = (env["KEEP_PROVIDER_LOCATION"] ?? inferred).toLowerCase();
  if (value !== "local" && value !== "external") throw new RuntimeConfigError("KEEP_PROVIDER_LOCATION", "must be local or external");
  if (value === "local" && !isLoopbackUrl(baseUrl) && env["KEEP_PROVIDER_LOCATION"] === undefined) throw new RuntimeConfigError("KEEP_PROVIDER_LOCATION", "non-loopback local endpoints require an explicit location declaration");
  return value;
}

function captureOrganizationReferences(env: Readonly<Record<string, string | undefined>>, cwd: string): NonNullable<CapturedRuntimeContract["organization"]> {
  const issuer = bounded(required(env, "KEEP_IDENTITY_ISSUER"), "KEEP_IDENTITY_ISSUER");
  let parsed: URL; try { parsed = new URL(issuer); } catch { throw new RuntimeConfigError("KEEP_IDENTITY_ISSUER", "must be an absolute HTTPS URL"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) throw new RuntimeConfigError("KEEP_IDENTITY_ISSUER", "must be a credential-free HTTPS origin/path");
  return {
    tenantId: bounded(required(env, "KEEP_TENANT_ID"), "KEEP_TENANT_ID"),
    issuer: parsed.toString().replace(/\/+$/u, ""),
    audience: bounded(required(env, "KEEP_IDENTITY_AUDIENCE"), "KEEP_IDENTITY_AUDIENCE"),
    jwksPath: absolutePath(required(env, "KEEP_IDENTITY_JWKS"), "KEEP_IDENTITY_JWKS", cwd),
    principalRosterPath: absolutePath(required(env, "KEEP_PRINCIPAL_ROSTER"), "KEEP_PRINCIPAL_ROSTER", cwd),
    delegationPolicyPath: absolutePath(required(env, "KEEP_DELEGATION_POLICY"), "KEEP_DELEGATION_POLICY", cwd),
    residencyPolicyPath: absolutePath(required(env, "KEEP_RESIDENCY_POLICY"), "KEEP_RESIDENCY_POLICY", cwd),
    scannerEnginePath: absolutePath(required(env, "KEEP_SCANNER_ENGINE"), "KEEP_SCANNER_ENGINE", cwd),
    auditScope: bounded(required(env, "KEEP_AUDIT_SCOPE"), "KEEP_AUDIT_SCOPE"),
  };
}

function isLoopbackUrl(value: string): boolean {
  const hostname = new URL(value).hostname;
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

function captureInstalledProject(env: Readonly<Record<string, string | undefined>>, context: RuntimeConfigContext, requiredProject: boolean): CapturedInstalledProjectConfig | undefined {
  const fields = ["KEEP_REPOSITORY", "KEEP_WORKSPACE_BASE", "KEEP_REVISION", "KEEP_REPO_REF", "KEEP_BASE_BRANCH", "KEEP_TEST_COMMAND"] as const;
  if (!requiredProject && !fields.some((field) => env[field] !== undefined)) return undefined;
  const repository = resolveRepository(required(env, "KEEP_REPOSITORY"), context)!;
  const workspaceBase = resolveWorkspaceBase(required(env, "KEEP_WORKSPACE_BASE"), repository, context);
  const revision = bounded(required(env, "KEEP_REVISION"), "KEEP_REVISION");
  if (!EXACT_REVISION.test(revision)) throw new RuntimeConfigError("KEEP_REVISION", "must be one exact lowercase 40- or 64-hex commit id");
  const observed = (context.resolveCommit ?? ((repositoryRoot, exactRevision) => defaultResolveCommit(repositoryRoot, exactRevision, context)))(repository.root, revision);
  if (observed !== revision) throw new RuntimeConfigError("KEEP_REVISION", "must resolve exactly to itself in KEEP_REPOSITORY");
  const repoRef = bounded(required(env, "KEEP_REPO_REF"), "KEEP_REPO_REF");
  if (!SAFE_REF.test(repoRef)) throw new RuntimeConfigError("KEEP_REPO_REF", "must be a canonical single path component");
  const baseBranch = canonicalBaseBranch(env["KEEP_BASE_BRANCH"] ?? "main", repository.root, context);
  const branchCommit = (context.resolveBranchCommit ?? ((repositoryRoot, branch) => defaultResolveBranchCommit(repositoryRoot, branch, context)))(repository.root, baseBranch);
  if (branchCommit !== revision) throw new RuntimeConfigError("KEEP_BASE_BRANCH", "must name the local branch at exactly KEEP_REVISION");
  const posture = env["KEEP_PROJECT_POSTURE"] ?? "approval-required";
  if (posture !== "autonomous" && posture !== "policy-calibrated" && posture !== "approval-required") throw new RuntimeConfigError("KEEP_PROJECT_POSTURE", "must be autonomous, policy-calibrated, or approval-required");
  return { repository, workspaceBase, revision, repoRef, baseBranch, posture, testCommand: captureTestCommand(env) };
}

function canonicalBaseBranch(value: string, repository: string, context: RuntimeConfigContext): string {
  const branch = bounded(value, "KEEP_BASE_BRANCH");
  if (context.validateBranch) {
    try {
      if (context.validateBranch(repository, branch) !== branch) throw new Error("contextual or normalized branch shorthand");
      return branch;
    } catch { throw new RuntimeConfigError("KEEP_BASE_BRANCH", "must be one canonical Git branch name"); }
  }
  const hardening = gitChildHardening(context.platform ?? process.platform, context.processEnv ?? process.env);
  try {
    const observed = execFileSync("git", [...hardening.configArgs, "-C", repository, "check-ref-format", "--branch", branch], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: hardening.env, timeout: 5_000, maxBuffer: 64 * 1024 }).trim();
    if (observed !== branch) throw new Error("contextual or normalized branch shorthand");
    return branch;
  } catch { throw new RuntimeConfigError("KEEP_BASE_BRANCH", "must be one canonical Git branch name"); }
}

function defaultResolveBranchCommit(repository: string, branch: string, context: RuntimeConfigContext): string {
  const hardening = gitChildHardening(context.platform ?? process.platform, context.processEnv ?? process.env);
  try {
    return execFileSync("git", [...hardening.configArgs, "-C", repository, "rev-parse", "--verify", `refs/heads/${branch}^{commit}`], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: hardening.env, timeout: 5_000, maxBuffer: 64 * 1024 }).trim();
  } catch { throw new RuntimeConfigError("KEEP_BASE_BRANCH", "must name an existing local branch"); }
}

function captureTestCommand(env: Readonly<Record<string, string | undefined>>): CapturedTestCommand {
  const command = bounded(required(env, "KEEP_TEST_COMMAND"), "KEEP_TEST_COMMAND");
  const args = stringArray(env["KEEP_TEST_ARGS_JSON"] ?? "[]", "KEEP_TEST_ARGS_JSON");
  const envAllowlist = (env["KEEP_TEST_ENV_ALLOWLIST"] ?? "").split(",").filter(Boolean).map((name) => bounded(name, "KEEP_TEST_ENV_ALLOWLIST"));
  for (const name of envAllowlist) if (!SAFE_ENV_NAME.test(name) || CREDENTIAL_ENV.test(name)) throw new RuntimeConfigError("KEEP_TEST_ENV_ALLOWLIST", `refuses credential-like or invalid environment name: ${name}`);
  return { command, args, timeoutMs: boundedInteger(env["KEEP_TEST_TIMEOUT_MS"], "KEEP_TEST_TIMEOUT_MS", DEFAULT_TEST_TIMEOUT_MS, 1_000, 60 * 60_000), cpuLimitSec: boundedInteger(env["KEEP_TEST_CPU_LIMIT_SEC"], "KEEP_TEST_CPU_LIMIT_SEC", DEFAULT_TEST_CPU_LIMIT_SEC, 1, 3_600), maxOutputBytes: boundedInteger(env["KEEP_TEST_MAX_OUTPUT_BYTES"], "KEEP_TEST_MAX_OUTPUT_BYTES", DEFAULT_TEST_MAX_OUTPUT_BYTES, 1_024, 64 * 1024 * 1024), envAllowlist: [...new Set(envAllowlist)].sort() };
}

function stringArray(raw: string, field: string): readonly string[] {
  bounded(raw, field);
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new RuntimeConfigError(field, "must be a JSON array of strings"); }
  if (!Array.isArray(value) || value.length > 128 || value.some((item) => typeof item !== "string" || item.length > MAX_FIELD || item.includes("\0"))) throw new RuntimeConfigError(field, "must be a bounded JSON array of strings");
  return value;
}

function boundedInteger(raw: string | undefined, field: string, fallback: number, min: number, max: number): number {
  if (raw === undefined) return fallback;
  if (!/^[0-9]+$/u.test(raw)) throw new RuntimeConfigError(field, "must be a base-10 integer");
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new RuntimeConfigError(field, `must be between ${min} and ${max}`);
  return value;
}

function resolveWorkspaceBase(value: string, repository: ResolvedPath, context: RuntimeConfigContext): ResolvedPath {
  const root = canonicalDirectory(isAbsolute(value) ? value : resolve(context.cwd, value), "KEEP_WORKSPACE_BASE", context);
  if (containsPath(repository.root, root) || containsPath(root, repository.root)) throw new RuntimeConfigError("KEEP_WORKSPACE_BASE", "must be disjoint from the source repository");
  return { root, source: "KEEP_WORKSPACE_BASE" };
}

function containsPath(parent: string, candidate: string): boolean {
  const rel = relative(parent, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

function absolutePath(value: string, field: string, cwd: string): string {
  const checked = bounded(value, field);
  if (!isAbsolute(checked)) throw new RuntimeConfigError(field, "must be an absolute path");
  return resolve(cwd, checked);
}

function defaultTrustRoot(context: RuntimeConfigContext): string {
  if ((context.platform ?? process.platform) !== "win32") return "/etc/keep/release-root.cbor";
  const env = context.processEnv ?? process.env;
  return join(env["ProgramData"] ?? env["PROGRAMDATA"] ?? "C:\\ProgramData", "Keep", "release-root.cbor");
}

function defaultResolveCommit(repository: string, revision: string, context: RuntimeConfigContext): string {
  const hardening = gitChildHardening(context.platform ?? process.platform, context.processEnv ?? process.env);
  try {
    return execFileSync("git", [...hardening.configArgs, "-C", repository, "rev-parse", "--verify", `${revision}^{commit}`], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: hardening.env, timeout: 5_000, maxBuffer: 64 * 1024 }).trim();
  } catch { throw new RuntimeConfigError("KEEP_REVISION", "must identify a commit in KEEP_REPOSITORY"); }
}

function normalizeBaseUrl(value: string): string {
  bounded(value, "KEEP_PROVIDER_BASE_URL");
  let url: URL;
  try { url = new URL(value); }
  catch { throw new RuntimeConfigError("KEEP_PROVIDER_BASE_URL", "must be an absolute URL"); }
  if (url.username || url.password || url.search || url.hash) {
    throw new RuntimeConfigError("KEEP_PROVIDER_BASE_URL", "must not contain credentials, query parameters, or a fragment");
  }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "::1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new RuntimeConfigError("KEEP_PROVIDER_BASE_URL", "must use HTTPS; HTTP is allowed only for an explicit loopback test/local endpoint");
  }
  url.pathname = url.pathname.replace(/\/v1\/?$/u, "");
  return url.toString().replace(/\/+$/, "");
}

function resolveRepository(value: string | undefined, context: RuntimeConfigContext): ResolvedPath | undefined {
  if (value === undefined || value === "") return undefined;
  const input = bounded(value, "KEEP_REPOSITORY");
  const candidate = isAbsolute(input) ? input : resolve(context.cwd, input);
  const root = (context.repositoryRoot ?? defaultRepositoryRoot)(candidate);
  return { root: canonicalDirectory(root, "KEEP_REPOSITORY", context), source: "KEEP_REPOSITORY" };
}

function resolveWorkspace(value: string | undefined, repository: ResolvedPath | undefined, context: RuntimeConfigContext): ResolvedPath | undefined {
  if (!repository) {
    if (value !== undefined && value !== "") throw new RuntimeConfigError("KEEP_WORKSPACE", "cannot be set without KEEP_REPOSITORY");
    return undefined;
  }
  const workspaceInput = value === undefined || value === "" ? undefined : bounded(value, "KEEP_WORKSPACE");
  const candidate = workspaceInput === undefined
    ? repository.root
    : (isAbsolute(workspaceInput) ? workspaceInput : resolve(repository.root, workspaceInput));
  const root = canonicalDirectory(candidate, "KEEP_WORKSPACE", context);
  const rel = relative(repository.root, root);
  if (rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
    throw new RuntimeConfigError("KEEP_WORKSPACE", "must resolve inside the canonical repository root");
  }
  return { root, source: value === undefined || value === "" ? "repository-default" : "KEEP_WORKSPACE" };
}

function canonicalDirectory(path: string, field: string, context: RuntimeConfigContext): string {
  let canonical: string;
  try { canonical = (context.realpath ?? realpathSync)(path); }
  catch { throw new RuntimeConfigError(field, "does not exist or cannot be resolved"); }
  const directory = context.isDirectory ? context.isDirectory(canonical) : statSync(canonical).isDirectory();
  if (!directory) throw new RuntimeConfigError(field, "must resolve to a directory");
  return canonical;
}

function defaultRepositoryRoot(path: string): string {
  const hardening = gitChildHardening(process.platform, process.env);
  try {
    return execFileSync("git", [...hardening.configArgs, "-C", path, "rev-parse", "--path-format=absolute", "--show-toplevel"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: hardening.env,
      timeout: 5_000,
      maxBuffer: 64 * 1024,
    }).trim();
  } catch {
    throw new RuntimeConfigError("KEEP_REPOSITORY", "must be a Git working tree trusted by the current OS user");
  }
}

/** One composed Git-child policy so Windows/POSIX hook and config null devices cannot drift apart. */
export function gitChildHardening(
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
): { readonly configArgs: readonly ["-c", string]; readonly env: NodeJS.ProcessEnv } {
  const nullDevice = platform === "win32" ? "NUL" : "/dev/null";
  // Allowlist only process-launch necessities. In particular, never copy KEEP_PROVIDER_API_KEY (or any other
  // application secret) into the Git discovery child merely because it arrived through process.env.
  const clean: NodeJS.ProcessEnv = {};
  for (const name of ["PATH", "SystemRoot", "WINDIR", "PATHEXT", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL"]) {
    if (env[name] !== undefined) clean[name] = env[name];
  }
  clean["GIT_CONFIG_NOSYSTEM"] = "1";
  clean["GIT_CONFIG_GLOBAL"] = nullDevice;
  clean["GIT_TERMINAL_PROMPT"] = "0";
  clean["HOME"] = platform === "win32" ? `${env["SystemDrive"] ?? "C:"}\\keep-no-home` : "/nonexistent";
  clean["LC_ALL"] = "C";
  return { configArgs: ["-c", `core.hooksPath=${nullDevice}`], env: clean };
}

function localMemoryProvider(): { readonly mode: "local"; readonly purpose: "credential-free-memory-embedding" } {
  return { mode: "local", purpose: "credential-free-memory-embedding" };
}
