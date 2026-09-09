import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { configuredSemanticEncoder, encoderProfileFromArgs, loadEncoderProfile, parseEncoderProfile, writeEncoderProfile } from "../src/cli/encoder_profile.js";
import { captureRuntimeContract } from "../src/cli/runtime_config.js";
import { inspectInstalledReadiness } from "../src/cli/doctor.js";

const profile = {
  schema: "keep.encoder-profile/v1", name: "separate-encoder", authority: "owner", location: "external", protocol: "openai-compatible",
  endpoint: "https://encoder.example/v1", model: "encoder-model", credential: { kind: "environment" },
  contract: { modelRevision: "declared-revision", dimension: 2, queryPrefix: "QUERY: ", documentPrefix: "DOCUMENT: " },
  processing: { query: { purpose: "memory-query", region: "eu" }, document: { purpose: "memory-document", region: "eu" } },
  limits: { requests: 32, inputBytes: 131072, windows: 256 },
} as const;
const chat = { KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_AUTHORITY: "owner", KEEP_PROVIDER_BASE_URL: "https://chat.example/v1", KEEP_PROVIDER_MODEL: "chat-model", KEEP_PROVIDER_API_KEY: "chat-only-secret", KEEP_REMOTE_PROCESSING_PURPOSE: "code", KEEP_REMOTE_PROCESSING_REGION: "eu" };
const organization = { KEEP_PROVIDER_AUTHORITY: "organization", KEEP_RELEASE_BUNDLE: "/chat-release", KEEP_RELEASE_TRUST_ROOT: "/chat-trust", KEEP_TENANT_ID: "alpha", KEEP_IDENTITY_ISSUER: "https://id.example", KEEP_IDENTITY_AUDIENCE: "keep", KEEP_IDENTITY_JWKS: "/jwks", KEEP_PRINCIPAL_ROSTER: "/principals", KEEP_DELEGATION_POLICY: "/delegation", KEEP_RESIDENCY_POLICY: "/residency", KEEP_SCANNER_ENGINE: "/scanner", KEEP_AUDIT_SCOPE: "tenant" };
const context = { cwd: "/repo", realpath: (path: string) => path, isDirectory: () => true, repositoryRoot: () => "/repo", resolveCommit: () => "a".repeat(40), validateBranch: (_: string, branch: string) => branch, resolveBranchCommit: () => "a".repeat(40) };

test("encoder profiles are exact non-secret data with literal prefixes and finite work limits", () => {
  const captured = parseEncoderProfile(profile);
  assert.equal(captured.contract.queryPrefix, "QUERY: ");
  assert.equal(Object.isFrozen(captured.processing.query), true);
  assert.throws(() => parseEncoderProfile({ ...profile, apiKey: "never-store" }), /unknown/u);
  assert.throws(() => parseEncoderProfile({ ...profile, credential: { kind: "file", path: "/key", value: "never-store" } }), /unknown/u);
  assert.throws(() => parseEncoderProfile({ ...profile, contract: { ...profile.contract, dimension: 0 } }), /contract/u);
  assert.throws(() => parseEncoderProfile({ ...profile, limits: { ...profile.limits, requests: Infinity } }), /positive/u);
  assert.throws(() => parseEncoderProfile({ ...profile, protocol: "anthropic-compatible" }), /embedding protocol/u);
  assert.throws(() => parseEncoderProfile({ ...profile, endpoint: "https://secret@encoder.example" }), /credentials/u);
  assert.throws(() => parseEncoderProfile({ ...profile, credential: null }), /loopback/u);
  assert.doesNotThrow(() => parseEncoderProfile({ ...profile, location: "local", endpoint: "http://127.0.0.1:9000", credential: null }));
  let reads = 0; const hostile = { ...profile }; Object.defineProperty(hostile, "name", { enumerable: true, get: () => { reads++; return "hostile"; } });
  assert.throws(() => parseEncoderProfile(hostile), /non-data/u); assert.equal(reads, 0);
});

test("normal runtime captures a dedicated encoder reference and never borrows the chat credential", t => {
  const root = mkdtempSync(join(tmpdir(), "keep-encoder-config-")); t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "encoder.json"); writeEncoderProfile(path, parseEncoderProfile(profile));
  assert.throws(() => captureRuntimeContract({ ...chat, KEEP_ENCODER_PROFILE: path }, context), /chat credentials are not inherited/u);
  const captured = captureRuntimeContract({ ...chat, KEEP_ENCODER_PROFILE: path, KEEP_ENCODER_API_KEY: "encoder-only-secret" }, context);
  assert.deepEqual(captured.credentialReference, { kind: "environment", name: "KEEP_PROVIDER_API_KEY" });
  assert.deepEqual(captured.encoderCredentialReference, { kind: "environment", name: "KEEP_ENCODER_API_KEY" });
  assert.doesNotMatch(JSON.stringify(captured), /chat-only-secret|encoder-only-secret/u);
  assert.deepEqual(captured.residency, { allowedPurposes: ["code", "memory-query", "memory-document"], allowedRegions: ["eu"], egressAllowlist: ["chat.example", "encoder.example"] });
  assert.equal(captureRuntimeContract(chat, context).encoder, undefined);
  assert.throws(() => captureRuntimeContract({ ...chat, KEEP_ENCODER_API_KEY: "unselected" }, context), /KEEP_ENCODER_PROFILE/u);
  const encoder = configuredSemanticEncoder(captured.encoder!, "encoder-only-secret");
  assert.equal(encoder.provider.apiKey, "encoder-only-secret"); assert.equal(encoder.provider.model, "encoder-model");
  assert.throws(() => configuredSemanticEncoder(captured.encoder!, undefined), /credential is empty/u);
  chmodSync(path, 0o644); assert.throws(() => loadEncoderProfile(path), /0600/u);
});

test("file and stdin encoder credentials are explicit and cannot share the chat stdin stream", t => {
  const root = mkdtempSync(join(tmpdir(), "keep-encoder-stream-")); t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "encoder.json"); writeEncoderProfile(path, parseEncoderProfile({ ...profile, credential: { kind: "stdin" } }));
  assert.deepEqual(captureRuntimeContract({ ...chat, KEEP_ENCODER_PROFILE: path }, context).encoderCredentialReference, { kind: "stdin" });
  assert.throws(() => captureRuntimeContract({ ...chat, KEEP_PROVIDER_API_KEY: undefined, KEEP_PROVIDER_API_KEY_STDIN: "1", KEEP_ENCODER_PROFILE: path }, context), /same stdin/u);
  writeEncoderProfile(path, parseEncoderProfile({ ...profile, credential: { kind: "file", path: "/unopened-encoder-key" } }));
  assert.deepEqual(captureRuntimeContract({ ...chat, KEEP_ENCODER_PROFILE: path }, context).encoderCredentialReference, { kind: "file", path: "/unopened-encoder-key" });
  assert.throws(() => captureRuntimeContract({ ...chat, KEEP_ENCODER_PROFILE: path, KEEP_ENCODER_API_KEY: "conflicting" }, context), /conflicts/u);
});

test("organization encoder config keeps its own release and does not widen organization residency", t => {
  const root = mkdtempSync(join(tmpdir(), "keep-encoder-org-")); t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "encoder.json");
  assert.throws(() => parseEncoderProfile({ ...profile, authority: "organization" }), /own release/u);
  const enterprise = parseEncoderProfile({ ...profile, authority: "organization", release: { bundlePath: "/encoder-release", trustRootPath: "/encoder-trust" } });
  writeEncoderProfile(path, enterprise);
  const env = { ...chat, ...organization, KEEP_ENCODER_PROFILE: path, KEEP_ENCODER_API_KEY: "separate-encoder-secret" };
  const captured = captureRuntimeContract(env, context);
  assert.equal(captured.releaseAdmission?.bundlePath, "/chat-release");
  assert.equal(captured.encoder?.release?.bundlePath, "/encoder-release");
  assert.deepEqual(captured.residency?.egressAllowlist, ["chat.example"], "encoder configuration is not enterprise egress authorization");
  assert.throws(() => configuredSemanticEncoder(enterprise, "key"), /own matching release/u);
  assert.throws(() => captureRuntimeContract({ ...chat, KEEP_ENCODER_PROFILE: path, KEEP_ENCODER_API_KEY: "key" }, context), /share owner or organization/u);
  writeEncoderProfile(path, parseEncoderProfile(profile));
  assert.throws(() => captureRuntimeContract(env, context), /share owner or organization/u);
});

test("doctor checks encoder admission independently and reports refusal without a provider call", t => {
  const root = mkdtempSync(join(tmpdir(), "keep-encoder-doctor-")); t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "encoder.json"); writeEncoderProfile(path, parseEncoderProfile({ ...profile, authority: "organization", release: { bundlePath: "/encoder-release", trustRootPath: "/encoder-trust" } }));
  const seen: string[] = [];
  const report = inspectInstalledReadiness({ ...chat, ...organization, KEEP_ENCODER_PROFILE: path, KEEP_ENCODER_API_KEY: "secret", KEEP_REPOSITORY: "/repo", KEEP_WORKSPACE_BASE: "/workspaces", KEEP_REVISION: "a".repeat(40), KEEP_REPO_REF: "sample", KEEP_TEST_COMMAND: process.execPath }, {
    context, packageRoot: root, stdinIsTTY: true, measurePackage: () => "b".repeat(64),
    verifyRelease: contract => { seen.push(contract.releaseAdmission!.bundlePath); if (contract.releaseAdmission!.bundlePath === "/encoder-release") throw new Error("encoder route not admitted"); },
  });
  assert.deepEqual(seen, ["/chat-release", "/encoder-release"]);
  assert.equal(report.ready, false);
  assert.equal(report.checks.find(c => c.name === "release-admission")?.status, "ready");
  assert.equal(report.checks.find(c => c.name === "encoder-release-admission")?.status, "security-refusal");
  assert.match(report.checks.find(c => c.name === "semantic-encoder")!.detail, /not weight-verified/u);
  assert.doesNotMatch(JSON.stringify(report), /"secret"/u);
});

const flags = ["--name=separate", "--authority=owner", "--location=external", "--endpoint=https://encoder.example/v1", "--model=encoder", "--revision=declared-v1", "--dimension=2", "--query-prefix=QUERY: ", "--document-prefix=DOCUMENT: ", "--query-purpose=memory-query", "--document-purpose=memory-document", "--region=eu", "--requests=32", "--input-bytes=131072", "--windows=256", "--credential=environment"];
test("actual compiled CLI configures and shows the protected encoder profile without copying environment secrets", t => {
  const root = mkdtempSync(join(tmpdir(), "keep-encoder-cli-")); t.after(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "encoder.json"), entry = fileURLToPath(new URL("../src/cli/keep.js", import.meta.url));
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("KEEP_"))), KEEP_ENCODER_API_KEY: "never-print-encoder-secret", KEEP_PROVIDER_API_KEY: "never-print-chat-secret" };
  const configured = spawnSync(process.execPath, [entry, "encoder", "configure", `--profile=${path}`, ...flags], { env, encoding: "utf8", timeout: 10000 });
  assert.equal(configured.status, 0, configured.stderr); assert.match(configured.stdout, /Per-command semantic consent/u);
  const shown = spawnSync(process.execPath, [entry, "encoder", "show"], { env: { ...env, KEEP_ENCODER_PROFILE: path }, encoding: "utf8", timeout: 10000 });
  assert.equal(shown.status, 0, shown.stderr); assert.equal(JSON.parse(shown.stdout).contract.queryPrefix, "QUERY: ");
  assert.doesNotMatch(shown.stdout + configured.stdout + readFileSync(path, "utf8"), /never-print/u);
  assert.throws(() => encoderProfileFromArgs([...flags, `--profile=${path}`, "--api-key=never-print"], root), /unknown/u);
  assert.throws(() => encoderProfileFromArgs([...flags, `--profile=${path}`, "--requests=1"], root), /duplicate/u);
  const dataDir = join(root, "must-not-exist");
  const invalid = spawnSync(process.execPath, [entry, "status"], { env: { ...env, KEEP_PROVIDER: "local", KEEP_PROVIDER_API_KEY: undefined, KEEP_ENCODER_PROFILE: "/missing-encoder-profile", KEEP_DATA_DIR: dataDir }, encoding: "utf8", timeout: 10000 });
  assert.notEqual(invalid.status, 0); assert.equal(existsSync(dataDir), false);
});
