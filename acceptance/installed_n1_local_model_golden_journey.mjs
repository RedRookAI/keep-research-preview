import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const tarball = process.env.KEEP_TARBALL;
const endpoint = process.env.KEEP_LOCAL_MODEL_BASE_URL;
const model = process.env.KEEP_LOCAL_MODEL;
for (const [name, value] of Object.entries({ KEEP_TARBALL: tarball, KEEP_LOCAL_MODEL_BASE_URL: endpoint, KEEP_LOCAL_MODEL: model })) if (!value) throw new Error(`${name} is required`);

const root = mkdtempSync(join(tmpdir(), "keep-installed-n1-local-model-"));
const consumer = join(root, "consumer"); mkdirSync(consumer);
writeFileSync(join(consumer, "package.json"), '{"name":"keep-installed-local-consumer","private":true}\n');
execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], { cwd: consumer, stdio: "pipe" });
const entry = join(consumer, "node_modules", "keep", "dist", "src", "main.js");
const profile = join(root, "provider.json");
const common = { ...process.env, KEEP_PROFILE: profile };
const invoke = (args, env = common, timeout = 600_000) => spawnSync(process.execPath, [entry, ...args], { cwd: consumer, env, encoding: "utf8", timeout, maxBuffer: 16 * 1024 * 1024 });

const configured = invoke(["provider", "configure", `--profile=${profile}`, "--name=installed-owner-local", "--location=local", "--authority=owner", "--protocol=openai-compatible", `--endpoint=${endpoint}`, `--model=${model}`, "--purpose=software-development", "--region=local", "--credential=none"]);
assert.equal(configured.status, 0, configured.stderr);
assert.equal(JSON.parse(readFileSync(profile, "utf8")).credential, null);
const preflight = invoke(["provider-check", "Reply with exactly KEEP_LOCAL_READY"]);
assert.equal(preflight.status, 0, preflight.stderr); assert.match(preflight.stdout, /KEEP_LOCAL_READY/u);
const missingProfile = join(root, "missing-model.json");
assert.equal(invoke(["provider", "configure", `--profile=${missingProfile}`, "--name=missing-local", "--location=local", "--authority=owner", "--protocol=openai-compatible", `--endpoint=${endpoint}`, "--model=keep-model-that-does-not-exist", "--purpose=software-development", "--region=local", "--credential=none"]).status, 0);
const missing = invoke(["provider-check", "This must fail"], { ...common, KEEP_PROFILE: missingProfile });
assert.notEqual(missing.status, 0); assert.match(`${missing.stdout}${missing.stderr}`, /404|not found|does not exist/u);

function repository(name) {
  const source = join(root, name); mkdirSync(source);
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: source });
  execFileSync("git", ["config", "user.name", "Local Owner"], { cwd: source }); execFileSync("git", ["config", "user.email", "owner@example.invalid"], { cwd: source });
  writeFileSync(join(source, "calc.js"), "export function add(a, b) { return a - b; }\n");
  writeFileSync(join(source, "calc.test.js"), "import test from 'node:test'; import assert from 'node:assert/strict'; import { add } from './calc.js'; test('add returns the sum', () => assert.equal(add(2, 3), 5));\n");
  execFileSync("git", ["add", "-A"], { cwd: source }); execFileSync("git", ["commit", "-qm", "failing add implementation"], { cwd: source });
  return source;
}
const git = (repo, ...args) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
const projectEnv = (source, label) => { const workspace = join(root, `workspace-${label}`); mkdirSync(workspace); return ({ ...common, KEEP_DATA_DIR: join(root, `state-${label}`), KEEP_REPOSITORY: source, KEEP_WORKSPACE_BASE: workspace, KEEP_REVISION: git(source, "rev-parse", "HEAD"), KEEP_REPO_REF: "project", KEEP_TEST_COMMAND: process.execPath, KEEP_TEST_ARGS_JSON: '["--test","calc.test.js"]', KEEP_PROJECT_POSTURE: "approval-required" }); };

const source = repository("source-approved"), initial = git(source, "rev-parse", "HEAD"), env = projectEnv(source, "approved");
const proposed = invoke(["project", "In calc.js, fix add so the declared calc.test.js passes without changing the test."], env);
assert.equal(proposed.status, 0, `${proposed.stdout}\n${proposed.stderr}`);
const runId = /Run: ([^\s]+)/u.exec(proposed.stdout)?.[1], digest = /--proposal=([0-9a-f]{64})/u.exec(proposed.stdout)?.[1]; assert.ok(runId && digest, proposed.stdout);
assert.equal(git(source, "rev-parse", "HEAD"), initial);
const stateSnapshot = join(root, "state-proposed-snapshot"), workspaceSnapshot = join(root, "workspace-proposed-snapshot");
cpSync(env.KEEP_DATA_DIR, stateSnapshot, { recursive: true }); cpSync(env.KEEP_WORKSPACE_BASE, workspaceSnapshot, { recursive: true });
chmodSync(join(stateSnapshot, ".locks"), 0o700);
const approved = invoke(["merge", runId, "approve", `--proposal=${digest}`], env);
assert.equal(approved.status, 0, `${approved.stdout}\n${approved.stderr}`); assert.match(readFileSync(join(source, "calc.js"), "utf8"), /a \+ b/u);
execFileSync(process.execPath, ["--test", "calc.test.js"], { cwd: source, stdio: "pipe" });
env.KEEP_REVISION = git(source, "rev-parse", "HEAD");
const reverted = invoke(["revert", runId], env); assert.equal(reverted.status, 0, reverted.stderr); assert.match(readFileSync(join(source, "calc.js"), "utf8"), /a - b/u);
const postRevert = git(source, "rev-parse", "HEAD");
env.KEEP_REVISION = postRevert;

rmSync(env.KEEP_DATA_DIR, { recursive: true }); rmSync(env.KEEP_WORKSPACE_BASE, { recursive: true });
cpSync(stateSnapshot, env.KEEP_DATA_DIR, { recursive: true }); cpSync(workspaceSnapshot, env.KEEP_WORKSPACE_BASE, { recursive: true });
chmodSync(join(env.KEEP_DATA_DIR, ".locks"), 0o700);
const vetoed = invoke(["merge", runId, "veto", `--proposal=${digest}`], env); assert.equal(vetoed.status, 0, vetoed.stderr);
const late = invoke(["merge", runId, "approve", `--proposal=${digest}`], env); assert.equal(late.status, 0, late.stderr); assert.match(late.stdout, /veto is durable/u); assert.equal(git(source, "rev-parse", "HEAD"), postRevert); assert.match(readFileSync(join(source, "calc.js"), "utf8"), /a - b/u);

process.stdout.write(`installed n=1/local-model journey passed at ${root}\n`);
