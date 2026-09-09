import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyProviderProfile, parseProviderProfile, profileEnvironment, writeProviderProfile } from "../src/cli/provider_profile.js";
import { composeKeep } from "../src/compose.js";

const owner = { schema: "keep.provider-profile/v1", name: "personal", location: "external", authority: "owner", protocol: "openai-compatible", endpoint: "https://openrouter.example/api/v1", model: "m", purpose: "software-development", region: "eu", credential: { kind: "file", path: "/run/secrets/model" }, routing: { providers: ["Example Route"] } } as const;

test("owner profiles materialize one non-secret provider layer", () => {
  const parsed = parseProviderProfile(owner);
  const env = profileEnvironment(parsed);
  assert.equal(env["KEEP_PROVIDER_AUTHORITY"], "owner");
  assert.equal(env["KEEP_PROVIDER_LOCATION"], "external");
  assert.equal(env["KEEP_PROVIDER_API_KEY_FILE"], "/run/secrets/model");
  assert.equal(env["KEEP_PROVIDER_ROUTE_ALLOWLIST"], "Example Route");
  assert.equal(JSON.stringify(parsed).includes("actual-secret"), false);
  assert.throws(() => parseProviderProfile({ ...owner, release: { bundlePath: "/b", trustRootPath: "/r" } }), /owner profile cannot/u);
});

test("only owner-local profiles may omit credentials", () => {
  assert.doesNotThrow(() => parseProviderProfile({ ...owner, location: "local", endpoint: "http://127.0.0.1:11434", credential: null, routing: undefined }));
  assert.throws(() => parseProviderProfile({ ...owner, credential: null }), /only owner\/local/u);
});

test("organization profiles require explicit identity, policy and release references", () => {
  assert.throws(() => parseProviderProfile({ ...owner, authority: "organization" }), /requires organization and release/u);
  const parsed = parseProviderProfile({ ...owner, authority: "organization", organization: { tenantId: "alpha", issuer: "https://id.example", audience: "keep", jwksPath: "/etc/keep/jwks.json", principalRosterPath: "/etc/keep/principals.json", delegationPolicyPath: "/etc/keep/delegation.json", residencyPolicyPath: "/etc/keep/residency.json", scannerEnginePath: "/opt/keep-verifier/effect_sweep.mjs", auditScope: "tenant" }, release: { bundlePath: "/etc/keep/release.cbor", trustRootPath: "/etc/keep/root.cbor" } });
  assert.equal(parsed.organization?.tenantId, "alpha");
  assert.equal(profileEnvironment(parsed)["KEEP_RESIDENCY_POLICY"], "/etc/keep/residency.json");
});

test("profile storage is permission-bounded and environment remains a complete override layer", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-profile-"));
  const path = join(root, "provider.json");
  try {
    const parsed = parseProviderProfile(owner);
    writeProviderProfile(path, parsed);
    assert.equal(JSON.parse(readFileSync(path, "utf8")).credential.path, "/run/secrets/model");
    const applied = applyProviderProfile({ KEEP_PROFILE: path, KEEP_REPOSITORY: "/repo" });
    assert.equal(applied["KEEP_PROVIDER"], "openai-compatible");
    assert.equal(applied["KEEP_REPOSITORY"], "/repo");
    const explicit = applyProviderProfile({ KEEP_PROFILE: path, KEEP_PROVIDER: "local" });
    assert.equal(explicit["KEEP_PROVIDER"], "local");
    chmodSync(path, 0o644);
    assert.throws(() => applyProviderProfile({ KEEP_PROFILE: path }), /group or other access/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("shipped provider configure/show stores and renders references but no credential value", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-profile-cli-"));
  const path = join(root, "provider.json");
  const entry = join(process.cwd(), "dist", "src", "main.js");
  try {
    const configure = spawnSync(process.execPath, [entry, "provider", "configure", `--profile=${path}`, "--name=personal", "--location=external", "--authority=owner", "--protocol=openai-compatible", "--endpoint=https://openrouter.example/api/v1", "--model=m", "--purpose=software-development", "--region=eu", "--credential=file", "--credential-file=/run/secrets/model"], { encoding: "utf8", env: Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("KEEP_"))) });
    assert.equal(configure.status, 0, configure.stderr);
    assert.match(configure.stdout, /no credential value was stored/u);
    const show = spawnSync(process.execPath, [entry, "provider", "show"], { encoding: "utf8", env: { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("KEEP_"))), KEEP_PROFILE: path } });
    assert.equal(show.status, 0, show.stderr);
    assert.match(show.stdout, /"authority": "owner"/u);
    assert.doesNotMatch(`${show.stdout}${readFileSync(path, "utf8")}`, /actual-secret/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("owner provider authority is categorically unavailable to tenant deployment", () => {
  assert.throws(() => composeKeep({
    dataDir: "/unreached",
    ownerProvider: { mode: "openai-compatible", baseUrl: "https://models.example", model: "m", apiKey: "k" },
    tenantDeployment: {} as never,
  }), /owner provider authority is forbidden in tenant deployment/u);
});
