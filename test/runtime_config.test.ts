import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { captureRuntimeContract, createConfiguredProvider, describeRuntimeConfig, gitChildHardening, resolveRuntimeConfig, resolveRuntimeIntent, RuntimeConfigError } from "../src/cli/runtime_config.js";
import { HttpProvider } from "../src/gateway/http_provider.js";
import { LocalProvider } from "../src/gateway/local_provider.js";

const REVISION = "a".repeat(40);

const context = {
  cwd: "/repo",
  realpath: (path: string) => path,
  isDirectory: () => true,
  repositoryRoot: () => "/repo",
  validateBranch: (_repository: string, branch: string) => branch,
  resolveBranchCommit: () => REVISION,
};
const REMOTE_PROCESSING = { KEEP_REMOTE_PROCESSING_PURPOSE: "code-assistance", KEEP_REMOTE_PROCESSING_REGION: "eu" } as const;

test("installed contract captures an exact disjoint project target without loading credentials", () => {
  const captured = captureRuntimeContract({
    KEEP_PROVIDER: "openai-compatible",
    KEEP_PROVIDER_BASE_URL: "https://models.example.test",
    KEEP_PROVIDER_MODEL: "frontier-model",
    KEEP_PROVIDER_API_KEY_FILE: "/run/secrets/provider-key",
    KEEP_REMOTE_PROCESSING_PURPOSE: "code-assistance",
    KEEP_REMOTE_PROCESSING_REGION: "eu",
    KEEP_RELEASE_BUNDLE: "/opt/keep/release.cbor",
    KEEP_REPOSITORY: "/repo",
    KEEP_WORKSPACE_BASE: "/workspaces",
    KEEP_REVISION: REVISION,
    KEEP_REPO_REF: "sample-project",
    KEEP_TEST_COMMAND: "npm",
    KEEP_TEST_ARGS_JSON: '["test","--","--runInBand"]',
    KEEP_TEST_ENV_ALLOWLIST: "CI,NODE_ENV,CI",
  }, { ...context, resolveCommit: () => REVISION }, { projectRequired: true });
  assert.deepEqual(captured.credentialReference, { kind: "file", path: "/run/secrets/provider-key" });
  assert.equal("apiKey" in captured.provider, false, "captured provider identity never contains credential bytes");
  assert.equal(captured.installedProject?.workspaceBase.root, "/workspaces");
  assert.equal(captured.installedProject?.revision, REVISION);
  assert.equal(captured.installedProject?.baseBranch, "main");
  assert.deepEqual(captured.installedProject?.testCommand.envAllowlist, ["CI", "NODE_ENV"]);
  assert.deepEqual(captured.releaseAdmission, { bundlePath: "/opt/keep/release.cbor", trustRootPath: "/etc/keep/release-root.cbor" });
});

test("installed contract rejects ambiguous authority, mutable revisions, unsafe test environments and source workspaces", () => {
  const base = { KEEP_PROVIDER: "local", KEEP_REPOSITORY: "/repo", KEEP_WORKSPACE_BASE: "/workspaces", KEEP_REVISION: REVISION, KEEP_REPO_REF: "sample", KEEP_TEST_COMMAND: "npm" };
  const capture = (overlay: Readonly<Record<string, string | undefined>> = {}, overrides = {}) => captureRuntimeContract({ ...base, ...overlay }, { ...context, resolveCommit: () => REVISION, ...overrides }, { projectRequired: true });
  assert.throws(() => capture({ KEEP_REVISION: "main" }), /exact lowercase/u);
  assert.throws(() => capture({}, { resolveCommit: () => "b".repeat(40) }), /resolve exactly to itself/u);
  assert.throws(() => capture({ KEEP_WORKSPACE_BASE: "/repo/work" }), /disjoint/u);
  assert.throws(() => capture({ KEEP_WORKSPACE_BASE: "/" }), /disjoint/u);
  assert.throws(() => capture({ KEEP_TEST_ENV_ALLOWLIST: "CI,PROVIDER_TOKEN" }), /credential-like/u);
  assert.throws(() => capture({ KEEP_TEST_ARGS_JSON: '{"not":"args"}' }), /JSON array/u);
  assert.throws(() => capture({ KEEP_TEST_TIMEOUT_MS: "999" }), /between/u);
  assert.throws(() => capture({ KEEP_BASE_BRANCH: "bad..branch" }, { validateBranch: () => { throw new Error("bad"); } }), /canonical Git branch/u);
  assert.throws(() => capture({ KEEP_BASE_BRANCH: "work/canonical" }, { resolveBranchCommit: () => "b".repeat(40) }), /exactly KEEP_REVISION/u);
  assert.equal(capture({ KEEP_BASE_BRANCH: "work/canonical" }).installedProject?.baseBranch, "work/canonical");
});

test("remote captured credential provenance is exact and mutually exclusive", () => {
  const base = { KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_BASE_URL: "https://models.example.test", KEEP_PROVIDER_MODEL: "m", KEEP_REMOTE_PROCESSING_PURPOSE: "code", KEEP_REMOTE_PROCESSING_REGION: "eu", KEEP_RELEASE_BUNDLE: "/release.cbor" };
  assert.deepEqual(captureRuntimeContract({ ...base, KEEP_PROVIDER_API_KEY_STDIN: "1" }, { ...context, repositoryRequired: false }).credentialReference, { kind: "stdin" });
  assert.throws(() => captureRuntimeContract({ ...base, KEEP_PROVIDER_API_KEY: "secret", KEEP_PROVIDER_API_KEY_STDIN: "1" }, context), /exactly one credential source/u);
  assert.throws(() => captureRuntimeContract({ ...base, KEEP_PROVIDER_API_KEY_STDIN: "yes" }, context), /exactly 1/u);
  assert.throws(() => captureRuntimeContract({ ...base, KEEP_PROVIDER_API_KEY_FILE: "relative" }, context), /absolute path/u);
});

test("A3: provider mode is explicit; absence never silently selects local", () => {
  assert.throws(() => resolveRuntimeConfig({}, context), (err: unknown) =>
    err instanceof RuntimeConfigError && err.field === "KEEP_PROVIDER" && /explicit local or remote/.test(err.message));
});

test("A3: explicit local resolves without a repository and rejects ignored remote authority", () => {
  const resolved = resolveRuntimeConfig({ KEEP_PROVIDER: "local" }, context);
  assert.deepEqual(resolved, {
    provider: { mode: "local", location: "offline", authority: "owner" },
    memoryProvider: { mode: "local", purpose: "credential-free-memory-embedding" },
  });
  assert.ok(createConfiguredProvider(resolved.provider) instanceof LocalProvider);
  assert.throws(() => resolveRuntimeConfig({ KEEP_PROVIDER: "local", KEEP_PROVIDER_API_KEY: "must-not-be-ignored" }, context), /remote-only/);
  assert.throws(() => resolveRuntimeConfig({ KEEP_PROVIDER: "local", KEEP_PROVIDER_API_KEY: "" }, context), /remote-only/);
  assert.equal(resolveRuntimeConfig({ KEEP_PROVIDER: "LOCAL" }, context).provider.mode, "local");
});

test("four-quadrant provider authority keeps owner admission separate from organization release", () => {
  const common = { KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_MODEL: "m", KEEP_REMOTE_PROCESSING_PURPOSE: "code", KEEP_REMOTE_PROCESSING_REGION: "local" };
  const org = { KEEP_TENANT_ID: "alpha", KEEP_IDENTITY_ISSUER: "https://id.example", KEEP_IDENTITY_AUDIENCE: "keep", KEEP_IDENTITY_JWKS: "/jwks", KEEP_PRINCIPAL_ROSTER: "/principals", KEEP_DELEGATION_POLICY: "/delegation", KEEP_RESIDENCY_POLICY: "/residency", KEEP_SCANNER_ENGINE: "/scanner/effect_sweep.mjs", KEEP_AUDIT_SCOPE: "tenant" };
  const ownerLocal = captureRuntimeContract({ ...common, KEEP_PROVIDER_LOCATION: "local", KEEP_PROVIDER_AUTHORITY: "owner", KEEP_PROVIDER_BASE_URL: "http://127.0.0.1:11434" }, { ...context, repositoryRequired: false });
  assert.equal(ownerLocal.provider.mode === "local" ? undefined : ownerLocal.provider.location, "local");
  assert.equal(ownerLocal.credentialReference, undefined);
  assert.equal(ownerLocal.releaseAdmission, undefined);
  const ownerExternal = captureRuntimeContract({ ...common, KEEP_PROVIDER_LOCATION: "external", KEEP_PROVIDER_AUTHORITY: "owner", KEEP_PROVIDER_BASE_URL: "https://openrouter.example", KEEP_PROVIDER_API_KEY_FILE: "/secret" }, { ...context, repositoryRequired: false });
  assert.equal(ownerExternal.releaseAdmission, undefined);
  assert.deepEqual(ownerExternal.credentialReference, { kind: "file", path: "/secret" });
  assert.throws(() => captureRuntimeContract({ ...common, ...org, KEEP_PROVIDER_LOCATION: "external", KEEP_PROVIDER_AUTHORITY: "organization", KEEP_PROVIDER_BASE_URL: "https://models.example", KEEP_PROVIDER_API_KEY: "k" }, { ...context, repositoryRequired: false }), /KEEP_RELEASE_BUNDLE/u);
  const organization = captureRuntimeContract({ ...common, ...org, KEEP_PROVIDER_LOCATION: "external", KEEP_PROVIDER_AUTHORITY: "organization", KEEP_PROVIDER_BASE_URL: "https://models.example", KEEP_PROVIDER_API_KEY: "k", KEEP_RELEASE_BUNDLE: "/bundle" }, { ...context, repositoryRequired: false });
  assert.equal(organization.releaseAdmission?.bundlePath, "/bundle");
  assert.equal(organization.organization?.tenantId, "alpha");
  assert.throws(() => captureRuntimeContract({ ...common, KEEP_PROVIDER_LOCATION: "external", KEEP_PROVIDER_AUTHORITY: "owner", KEEP_PROVIDER_BASE_URL: "https://models.example", KEEP_PROVIDER_API_KEY: "k", KEEP_RELEASE_BUNDLE: "/bundle" }, { ...context, repositoryRequired: false }), /organization-only/u);
});

test("A3: remote intent fails closed on every missing required field", () => {
  const complete = {
    KEEP_PROVIDER: "openai-compatible",
    KEEP_PROVIDER_BASE_URL: "https://models.example.test",
    KEEP_PROVIDER_MODEL: "frontier-model",
    KEEP_PROVIDER_API_KEY: "secret",
    KEEP_REPOSITORY: "/repo",
    ...REMOTE_PROCESSING,
  };
  for (const field of ["KEEP_PROVIDER_BASE_URL", "KEEP_PROVIDER_MODEL", "KEEP_PROVIDER_API_KEY", "KEEP_REPOSITORY", "KEEP_REMOTE_PROCESSING_PURPOSE", "KEEP_REMOTE_PROCESSING_REGION"] as const) {
    const env = { ...complete, [field]: undefined };
    assert.throws(() => resolveRuntimeConfig(env, context), (err: unknown) => err instanceof RuntimeConfigError && err.field === field);
  }
});

test("A3: an explicitly non-repository domain surface may use a remote model without inventing a repository target", () => {
  const env = {
    KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_BASE_URL: "https://models.example.test",
    KEEP_PROVIDER_MODEL: "frontier-model", KEEP_PROVIDER_API_KEY: "secret",
    ...REMOTE_PROCESSING,
  };
  const resolved = resolveRuntimeConfig(env, { ...context, repositoryRequired: false });
  assert.equal(resolved.provider.mode, "openai-compatible");
  assert.equal(resolved.repository, undefined);
  assert.equal(resolved.workspace, undefined);
  assert.throws(() => resolveRuntimeConfig(env, context), /KEEP_REPOSITORY/u, "software/default boot still refuses an unbound target");
});

test("A3: remote resolution is typed, canonical, redacted, and constructs only a built-in provider", () => {
  let repositoryInput = "";
  const resolved = resolveRuntimeConfig({
    KEEP_PROVIDER: "anthropic-compatible",
    KEEP_PROVIDER_BASE_URL: "https://models.example.test/",
    KEEP_PROVIDER_MODEL: "frontier-model",
    KEEP_PROVIDER_API_KEY: "secret-not-for-rendering",
    ...REMOTE_PROCESSING,
    KEEP_REPOSITORY: "/repo/subdir",
    KEEP_WORKSPACE: "packages/app",
  }, { ...context, repositoryRoot: (path) => { repositoryInput = path; return "/repo"; } });
  assert.equal(repositoryInput, "/repo/subdir");
  const provider = resolved.provider;
  assert.ok(provider.mode === "anthropic-compatible");
  assert.equal(provider.baseUrl, "https://models.example.test");
  assert.equal(resolved.repository?.root, "/repo");
  assert.equal(resolved.workspace?.root, "/repo/packages/app");
  assert.ok(createConfiguredProvider(provider) instanceof HttpProvider);
  assert.deepEqual(resolved.memoryProvider, { mode: "local", purpose: "credential-free-memory-embedding" });
  assert.ok(createConfiguredProvider(resolved.memoryProvider) instanceof LocalProvider);
  assert.doesNotMatch(JSON.stringify(describeRuntimeConfig(resolved)), /secret-not-for-rendering/);
});

test("A4: inert remote intent parsing performs no repository discovery before admission", () => {
  const intent = resolveRuntimeIntent({ KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_BASE_URL: "https://models.example.test", KEEP_PROVIDER_MODEL: "m", KEEP_PROVIDER_API_KEY: "k", KEEP_REPOSITORY: "/repo", ...REMOTE_PROCESSING });
  assert.equal(intent.provider.mode, "openai-compatible");
});

test("A3: workspace cannot escape the canonical repository through relative or resolved paths", () => {
  assert.throws(() => resolveRuntimeConfig({ KEEP_PROVIDER: "local", KEEP_REPOSITORY: "/repo", KEEP_WORKSPACE: "../other" }, context), /inside the canonical repository/);
  assert.throws(() => resolveRuntimeConfig({ KEEP_PROVIDER: "local", KEEP_REPOSITORY: "/repo", KEEP_WORKSPACE: "/other" }, context), /inside the canonical repository/);
  assert.throws(() => resolveRuntimeConfig({ KEEP_PROVIDER: "local", KEEP_WORKSPACE: "/repo" }, context), /cannot be set without KEEP_REPOSITORY/);
  assert.throws(() => resolveRuntimeConfig(
    { KEEP_PROVIDER: "local", KEEP_REPOSITORY: "/repo", KEEP_WORKSPACE: "link" },
    { ...context, realpath: (path) => path === "/repo/link" ? "/elsewhere" : path },
  ), /inside the canonical repository/);
});

test("A3: endpoint policy rejects credentials, public plaintext HTTP, and unknown adapter names", () => {
  const base = { KEEP_PROVIDER_MODEL: "m", KEEP_PROVIDER_API_KEY: "k", KEEP_REPOSITORY: "/repo", ...REMOTE_PROCESSING };
  assert.throws(() => resolveRuntimeConfig({ ...base, KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_BASE_URL: "https://user:pass@example.test" }, context), /must not contain credentials/);
  assert.throws(() => resolveRuntimeConfig({ ...base, KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_BASE_URL: "http://example.test" }, context), /must use HTTPS/);
  assert.throws(() => resolveRuntimeConfig({ ...base, KEEP_PROVIDER: "file:evil-adapter", KEEP_PROVIDER_BASE_URL: "https://example.test" }, context), /must name/);
  assert.throws(() => resolveRuntimeConfig({ ...base, KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_BASE_URL: "https://example.test", KEEP_PROVIDER_MODEL: " m" }, context), /surrounding whitespace/);
  assert.throws(() => resolveRuntimeConfig({ ...base, KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_BASE_URL: "https://example.test", KEEP_PROVIDER_MODEL: "m\0hidden" }, context), /NUL/);
  assert.throws(() => resolveRuntimeConfig({ ...base, KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_BASE_URL: "https://example.test", KEEP_PROVIDER_MODEL: "m".repeat(8_193) }, context), /8192 bytes/);
  assert.doesNotThrow(() => resolveRuntimeConfig({ ...base, KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_BASE_URL: "http://127.0.0.1:8080" }, context));
});

test("OpenAI-compatible documented /v1 bases normalize once while retaining earlier path prefixes", () => {
  const base = { KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_MODEL: "m", KEEP_PROVIDER_API_KEY: "k", KEEP_REPOSITORY: "/repo", ...REMOTE_PROCESSING };
  const root = resolveRuntimeConfig({ ...base, KEEP_PROVIDER_BASE_URL: "https://models.example.test/v1/" }, context);
  if (root.provider.mode === "local") assert.fail("expected remote provider");
  assert.equal(root.provider.baseUrl, "https://models.example.test");
  const prefixed = resolveRuntimeConfig({ ...base, KEEP_PROVIDER_BASE_URL: "https://models.example.test/tenant/api/v1" }, context);
  if (prefixed.provider.mode === "local") assert.fail("expected remote provider");
  assert.equal(prefixed.provider.baseUrl, "https://models.example.test/tenant/api");
  const retained = resolveRuntimeConfig({ ...base, KEEP_PROVIDER_BASE_URL: "https://models.example.test/tenant/api" }, context);
  if (retained.provider.mode === "local") assert.fail("expected remote provider");
  assert.equal(retained.provider.baseUrl, "https://models.example.test/tenant/api");
});

test("A3: one Git-child policy binds native hook/config null devices and excludes application secrets", () => {
  const windows = gitChildHardening("win32", { PATH: "bin", KEEP_PROVIDER_API_KEY: "must-not-leak", GIT_DIR: "evil" });
  const linux = gitChildHardening("linux", { PATH: "bin", KEEP_PROVIDER_API_KEY: "must-not-leak", GIT_DIR: "evil" });
  assert.deepEqual(windows.configArgs, ["-c", "core.hooksPath=NUL"]);
  assert.equal(windows.env["GIT_CONFIG_GLOBAL"], "NUL");
  assert.deepEqual(linux.configArgs, ["-c", "core.hooksPath=/dev/null"]);
  assert.equal(linux.env["GIT_CONFIG_GLOBAL"], "/dev/null");
  assert.equal(windows.env["KEEP_PROVIDER_API_KEY"], undefined);
  assert.equal(windows.env["GIT_DIR"], undefined);
});

test("A4 INSTALLED PATH: unsigned remote intent is refused before contacting its configured endpoint", async () => {
  let hits = 0;
  let authorization = "";
  let requestUrl = "";
  let requestBody = "";
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += String(chunk); });
    req.on("end", () => {
      hits++;
      authorization = String(req.headers.authorization ?? "");
      requestUrl = req.url ?? "";
      requestBody = body;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({
        model: "fake-frontier",
        choices: [{ message: { content: '{"reply":"remote-path-ok"}' }, finish_reason: "stop" }],
        usage: { prompt_tokens: 10, completion_tokens: 3 },
      }));
    });
  });
  const repository = makeGitRepository();
  const dataDir = mkdtempSync(join(tmpdir(), "keep-a3-installed-"));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  try {
    const result = await runInstalled(["message", "fix", "the", "login", "button", "now"], {
      KEEP_PROVIDER: "openai-compatible",
      KEEP_PROVIDER_BASE_URL: `http://127.0.0.1:${address.port}`,
      KEEP_PROVIDER_MODEL: "fake-frontier",
      KEEP_PROVIDER_API_KEY: "fake-secret",
      ...REMOTE_PROCESSING,
      KEEP_REPOSITORY: repository,
      KEEP_WORKSPACE: repository,
      KEEP_DATA_DIR: dataDir,
    });
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /KEEP_RELEASE_BUNDLE|installed-release verification|remote provider descriptor/);
    assert.equal(hits, 0, "unsigned remote configuration must not construct or contact transport");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(repository, { recursive: true, force: true });
  }
});

test("OWNER INSTALLED PATH: explicit owner provider reaches the governed built-in transport without organization release signing", async () => {
  let hits = 0;
  const server = createServer((req, res) => {
    let body = ""; req.on("data", (chunk) => { body += String(chunk); }); req.on("end", () => {
      hits++;
      assert.equal(req.headers.authorization, "Bearer owner-secret");
      assert.match(body, /owner-path/u);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ model: "real-wire-fixture", choices: [{ message: { content: "owner-path-ok" }, finish_reason: "stop" }], usage: { prompt_tokens: 2, completion_tokens: 1 } }));
    });
  });
  const repository = makeGitRepository();
  const dataDir = mkdtempSync(join(tmpdir(), "keep-owner-installed-"));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  try {
    const result = await runInstalled(["provider-check", "owner-path"], {
      KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_LOCATION: "local", KEEP_PROVIDER_AUTHORITY: "owner",
      KEEP_PROVIDER_BASE_URL: `http://127.0.0.1:${address.port}`, KEEP_PROVIDER_MODEL: "real-wire-fixture", KEEP_PROVIDER_API_KEY: "owner-secret",
      ...REMOTE_PROCESSING, KEEP_REPOSITORY: repository, KEEP_DATA_DIR: dataDir,
    });
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /owner-path-ok/u);
    assert.equal(hits, 1);
  } finally { await new Promise<void>((resolve) => server.close(() => resolve())); rmSync(dataDir, { recursive: true, force: true }); rmSync(repository, { recursive: true, force: true }); }
});

test("A3 INSTALLED PATH: malformed remote intent exits cleanly before contacting its configured endpoint", async () => {
  const repository = makeGitRepository();
  const dataDir = mkdtempSync(join(tmpdir(), "keep-a3-invalid-"));
  let hits = 0;
  const server = createServer((_req, res) => { hits++; res.end(); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;
  try {
    const result = await runInstalled(["message", "hello"], {
      KEEP_PROVIDER: "openai-compatible",
      KEEP_PROVIDER_BASE_URL: `http://127.0.0.1:${address.port}`,
      KEEP_PROVIDER_MODEL: "m",
      ...REMOTE_PROCESSING,
      KEEP_REPOSITORY: repository,
      KEEP_DATA_DIR: dataDir,
    });
    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /KEEP_PROVIDER_API_KEY: is required/);
    assert.doesNotMatch(result.stderr, /\n\s+at\s/);
    assert.equal(hits, 0);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(repository, { recursive: true, force: true });
  }
});

function makeGitRepository(): string {
  const repository = mkdtempSync(join(tmpdir(), "keep-a3-repository-"));
  const hardening = gitChildHardening(process.platform, process.env);
  try {
    execFileSync("git", [...hardening.configArgs, "init", "--quiet", repository], {
      env: hardening.env,
      stdio: "ignore",
    });
    return repository;
  } catch (err) {
    rmSync(repository, { recursive: true, force: true });
    throw err;
  }
}

async function runInstalled(argv: readonly string[], overlay: Readonly<Record<string, string>>): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("KEEP_")));
  const child = spawn(process.execPath, [join(process.cwd(), "dist/src/main.js"), ...argv], {
    cwd: process.cwd(),
    env: { ...inherited, ...overlay },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8"); child.stdout.on("data", (chunk) => { stdout += String(chunk); });
  child.stderr.setEncoding("utf8"); child.stderr.on("data", (chunk) => { stderr += String(chunk); });
  const code = await new Promise<number | null>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`installed Keep process exceeded 10s; stdout=${stdout}; stderr=${stderr}`));
    }, 10_000);
    child.once("error", (err) => { clearTimeout(timer); reject(err); });
    child.once("close", (value) => { clearTimeout(timer); resolve(value); });
  });
  return { code, stdout, stderr };
}
