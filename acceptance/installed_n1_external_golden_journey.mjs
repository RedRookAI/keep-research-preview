import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const tarball = process.env.KEEP_TARBALL;
const apiKey = process.env.LLM_API_KEY;
const configuredBase = process.env.LLM_BASE_URL;
const model = process.env.LLM_MODEL;
const providerRoute = process.env.KEEP_OPENROUTER_PROVIDER_ROUTE;
for (const [name, value] of Object.entries({ KEEP_TARBALL: tarball, LLM_API_KEY: apiKey, LLM_BASE_URL: configuredBase, LLM_MODEL: model, KEEP_OPENROUTER_PROVIDER_ROUTE: providerRoute })) if (!value) throw new Error(`${name} is required`);

const root = mkdtempSync(join(tmpdir(), "keep-installed-n1-external-"));
const consumer = join(root, "consumer"); mkdirSync(consumer);
writeFileSync(join(consumer, "package.json"), '{"name":"keep-installed-consumer","private":true}\n');
execFileSync("npm", ["install", "--no-audit", "--no-fund", tarball], { cwd: consumer, stdio: "pipe" });
const entry = join(consumer, "node_modules", "keep", "dist", "src", "main.js");

const base = new URL(configuredBase);
base.pathname = base.pathname.replace(/\/v1\/?$/u, "");
const profile = join(root, "provider.json");
const common = { ...process.env, KEEP_PROFILE: profile, KEEP_PROVIDER_API_KEY: apiKey };
const invoke = (args, env = common, timeout = 600_000) => spawnSync(process.execPath, [entry, ...args], { cwd: consumer, env, encoding: "utf8", timeout, maxBuffer: 16 * 1024 * 1024 });
const configure = invoke(["provider", "configure", `--profile=${profile}`, "--name=stage2-owner-external", "--location=external", "--authority=owner", "--protocol=openai-compatible", `--endpoint=${base.toString().replace(/\/$/u, "")}`, `--model=${model}`, "--purpose=software-development", "--region=external", "--credential=environment", `--providers=${providerRoute}`]);
assert.equal(configure.status, 0, configure.stderr); assert.doesNotMatch(`${configure.stdout}${readFileSync(profile, "utf8")}`, new RegExp(apiKey.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));
const preflight = invoke(["provider-check", "Reply with exactly KEEP_PROVIDER_READY"]);
assert.equal(preflight.status, 0, preflight.stderr); assert.match(preflight.stdout, /KEEP_PROVIDER_READY/u);

function repository(name) {
  const source = join(root, name); mkdirSync(source);
  execFileSync("git", ["init", "-q", "-b", "main"], { cwd: source });
  execFileSync("git", ["config", "user.name", "Stage Two Owner"], { cwd: source }); execFileSync("git", ["config", "user.email", "owner@example.invalid"], { cwd: source });
  writeFileSync(join(source, "calc.js"), "export function add(a, b) { return a - b; }\n");
  writeFileSync(join(source, "calc.test.js"), "import test from 'node:test'; import assert from 'node:assert/strict'; import { add } from './calc.js'; test('add returns the sum', () => assert.equal(add(2, 3), 5));\n");
  execFileSync("git", ["add", "-A"], { cwd: source }); execFileSync("git", ["commit", "-qm", "failing add implementation"], { cwd: source });
  return source;
}
const git = (repo, ...args) => execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
const projectEnv = (source, dataDir, workspace, revision = git(source, "rev-parse", "HEAD")) => { mkdirSync(workspace, { recursive: true }); return ({ ...common, KEEP_DATA_DIR: dataDir, KEEP_REPOSITORY: source, KEEP_WORKSPACE_BASE: workspace, KEEP_REVISION: revision, KEEP_REPO_REF: "project", KEEP_TEST_COMMAND: process.execPath, KEEP_TEST_ARGS_JSON: '["--test","calc.test.js"]', KEEP_PROJECT_POSTURE: "approval-required" }); };

const source = repository("source-approved"), dataDir = join(root, "state-approved"), workspace = join(root, "workspace-approved"), initial = git(source, "rev-parse", "HEAD"), env = projectEnv(source, dataDir, workspace, initial);
const proposed = invoke(["project", "The add function fails its declared test. Diagnose and fix the implementation without changing the test."], env);
assert.equal(proposed.status, 0, `${proposed.stdout}\n${proposed.stderr}`);
const runId = /Run: ([^\s]+)/u.exec(proposed.stdout)?.[1], digest = /--proposal=([0-9a-f]{64})/u.exec(proposed.stdout)?.[1]; assert.ok(runId && digest, proposed.stdout);
assert.equal(git(source, "rev-parse", "HEAD"), initial); assert.match(readFileSync(join(source, "calc.js"), "utf8"), /a - b/u);
const wrong = invoke(["merge", runId, "approve", `--proposal=${digest}`], { ...env, KEEP_OWNER_TOKEN: "0".repeat(64) });
assert.notEqual(wrong.status, 0); assert.match(`${wrong.stdout}${wrong.stderr}`, /status 401|unauthorized/u); assert.equal(git(source, "rev-parse", "HEAD"), initial);
const merged = invoke(["merge", runId, "approve", `--proposal=${digest}`], env);
assert.equal(merged.status, 0, `${merged.stdout}\n${merged.stderr}`); assert.match(merged.stdout, /Merge merged/u); assert.notEqual(git(source, "rev-parse", "HEAD"), initial); assert.match(readFileSync(join(source, "calc.js"), "utf8"), /a \+ b/u);
execFileSync(process.execPath, ["--test", "calc.test.js"], { cwd: source, stdio: "pipe" });
env.KEEP_REVISION = git(source, "rev-parse", "HEAD");
const reverted = invoke(["revert", runId], env);
assert.equal(reverted.status, 0, `${reverted.stdout}\n${reverted.stderr}`); assert.match(reverted.stdout, /Revert reverted/u); assert.match(readFileSync(join(source, "calc.js"), "utf8"), /a - b/u);

const vetoSource = repository("source-veto"), vetoData = join(root, "state-veto"), vetoWorkspace = join(root, "workspace-veto"), vetoInitial = git(vetoSource, "rev-parse", "HEAD"), vetoEnv = projectEnv(vetoSource, vetoData, vetoWorkspace, vetoInitial);
const vetoProposal = invoke(["project", "The add function fails its declared test. Diagnose and fix the implementation without changing the test."], vetoEnv);
assert.equal(vetoProposal.status, 0, `${vetoProposal.stdout}\n${vetoProposal.stderr}`);
const vetoRun = /Run: ([^\s]+)/u.exec(vetoProposal.stdout)?.[1], vetoDigest = /--proposal=([0-9a-f]{64})/u.exec(vetoProposal.stdout)?.[1]; assert.ok(vetoRun && vetoDigest);
const vetoed = invoke(["merge", vetoRun, "veto", `--proposal=${vetoDigest}`], vetoEnv); assert.equal(vetoed.status, 0, vetoed.stderr); assert.match(vetoed.stdout, /Merge refused:.*vetoed/u);
const lateApproval = invoke(["merge", vetoRun, "approve", `--proposal=${vetoDigest}`], vetoEnv); assert.equal(lateApproval.status, 0, lateApproval.stderr); assert.match(lateApproval.stdout, /veto is durable/u); assert.equal(git(vetoSource, "rev-parse", "HEAD"), vetoInitial);

chmodSync(profile, 0o600);
process.stdout.write(`installed n=1/external journey passed at ${root}\n`);
