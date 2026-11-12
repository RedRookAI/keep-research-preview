import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInstanceCommand } from "../src/cli/instance.js";
import { createHash } from "node:crypto";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { FileSystemLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { readRestrictedClientProfile } from "../src/gateway/restricted_client.js";
import { gitChildHardening } from "../src/cli/runtime_config.js";

async function run(...args: string[]) {
  let output = "";
  const code = await runInstanceCommand(args, text => { output += text; });
  return { code, output };
}

async function stop(directory: string) {
  const stopped = await run("stop", directory);
  assert.equal(stopped.code, 0, stopped.output);
  const worker = JSON.parse(readFileSync(join(directory, "current-worker.json"), "utf8"));
  const receipt = join(directory, "data", "native-workers", `${worker.workerId}.stopped.json`);
  for (let attempt = 0; attempt < 100 && !existsSync(receipt); attempt++) await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(existsSync(receipt), true, "owned worker acknowledged shutdown before fixture cleanup");
}

function fixture(t: { after: (cleanup: () => void) => void }) {
  const root = mkdtempSync(join(tmpdir(), "keep-instance-setup-"));
  const original = { ...process.env };
  for (const name of Object.keys(process.env)) if (name.startsWith("KEEP_")) delete process.env[name];
  process.env.HOME = join(root, "home");
  process.env.CODEX_HOME = join(root, "auth");
  mkdirSync(process.env.HOME); mkdirSync(process.env.CODEX_HOME);
  writeFileSync(join(process.env.CODEX_HOME, "auth.json"), "synthetic-auth-secret", { mode: 0o600 });
  const repository = join(root, "source"), directory = join(root, "instance"), engine = join(root, "fake-codex");
  const calls = join(root, "calls.jsonl"), mode = join(root, "mode");
  mkdirSync(repository);
  const hardening = gitChildHardening(process.platform, process.env);
  const git = (args: string[]) => execFileSync("git", [...hardening.configArgs, ...args], { env: hardening.env, encoding: "utf8" }).trim();
  git(["init", "--quiet", "--initial-branch=main", repository]);
  git(["-C", repository, "-c", "user.name=Keep Test", "-c", "user.email=keep@example.invalid", "commit", "--allow-empty", "-m", "base", "--quiet"]);
  writeFileSync(mode, "ready");
  writeFileSync(engine, `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(calls)}, JSON.stringify(args) + "\\n");
const mode = fs.readFileSync(${JSON.stringify(mode)}, "utf8");
if (mode === "capture") fs.writeFileSync(${JSON.stringify(join(root, "issued-runtime.json"))}, JSON.stringify({ environment: Object.fromEntries(Object.entries(process.env).filter(([name]) => name.startsWith("KEEP_") || ["HOME","CODEX_HOME"].includes(name))), locked: fs.existsSync(${JSON.stringify(join(directory, ".control-lock"))}) }));
if (args.join(" ") === "--version") {
  if (mode === "version-failure") { console.error("synthetic-private-diagnostic"); process.exit(1); }
  console.log(mode === "bad-version" ? "another-engine 1.0" : "codex-cli 0.163.0-keep-generation.2");
} else if (args.join(" ") === "login status") {
  console.error(mode === "logged-out" ? "Not logged in" : "Logged in using ChatGPT");
  process.exitCode = mode === "logged-out" ? 1 : 0;
} else { console.error("generation forbidden in setup fixture"); process.exitCode = 99; }
`, { mode: 0o700 });
  const options = [`--repository=${repository}`, `--test-command=${process.execPath}`, '--test-args=["--version"]'];
  const codex = ["--project-model=codex", "--codex-processing=owner-public-repository", `--codex-executable=${engine}`, "--codex-model=fixture-model",
    "--codex-max-invocations=2", "--codex-max-prompt-bytes=65536", "--codex-max-output-bytes=262144", "--codex-timeout-ms=180000"];
  const profile = () => JSON.parse(readFileSync(join(directory, "instance.json"), "utf8")) as { schema: string; environment: Record<string, string> };
  const probes = () => existsSync(calls) ? readFileSync(calls, "utf8").trim().split("\n").map(line => JSON.parse(line)) : [];
  t.after(() => {
    for (const name of Object.keys(process.env)) if (!(name in original)) delete process.env[name];
    Object.assign(process.env, original);
    rmSync(root, { recursive: true, force: true });
  });
  return { root, repository, directory, engine, mode, options, codex, profile, probes, git };
}

test("init saves explicit Codex setup in the existing private profile with metadata-only probes", async t => {
  const f = fixture(t);
  process.env.KEEP_PROVIDER_API_KEY = "synthetic-provider-secret";
  process.env.KEEP_OWNER_TOKEN = "synthetic-owner-secret";
  const sibling = join(f.root, "sibling.json"); writeFileSync(sibling, "retained sibling state");
  const result = await run("init", f.directory, ...f.options, ...f.codex, "--test-namespace-jail=off");
  assert.equal(result.code, 0, result.output);
  const p = f.profile();
  assert.equal(p.schema, "keep.instance/v1");
  assert.equal(p.environment.KEEP_PROJECT_MODEL, "codex");
  assert.equal(p.environment.KEEP_CODEX_EXECUTABLE, f.engine);
  assert.equal(p.environment.KEEP_CODEX_MODEL, "fixture-model");
  assert.equal(p.environment.KEEP_CODEX_PROCESSING, "owner-public-repository");
  assert.deepEqual([p.environment.KEEP_CODEX_MAX_INVOCATIONS, p.environment.KEEP_CODEX_MAX_PROMPT_BYTES, p.environment.KEEP_CODEX_MAX_OUTPUT_BYTES, p.environment.KEEP_CODEX_TIMEOUT_MS], ["2", "65536", "262144", "180000"]);
  assert.equal(p.environment.KEEP_TEST_NAMESPACE_JAIL, "off");
  assert.equal(p.environment.KEEP_REVISION, f.git(["-C", f.repository, "rev-parse", "HEAD"]));
  assert.deepEqual(f.probes(), [["--version"], ["login", "status"]]);
  assert.doesNotMatch(JSON.stringify(p) + result.output, /synthetic-(?:auth|provider|owner)-secret/);
  assert.equal(readFileSync(sibling, "utf8"), "retained sibling state");
  assert.equal(f.git(["-C", f.repository, "status", "--porcelain"]), "");
  assert.equal(statSync(f.directory).mode & 0o777, 0o700);
  assert.equal(statSync(join(f.directory, "instance.json")).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(f.directory).sort(), ["data", "instance.json", "workspaces"]);
  const coldStatus = await run("status", f.directory);
  assert.equal(coldStatus.code, 0, coldStatus.output);
  assert.match(coldStatus.output, /no acknowledged worker/u);
  assert.match(coldStatus.output, /model=fixture-model/u);
  assert.deepEqual(f.probes(), [["--version"], ["login", "status"]], "status performs no engine invocation");
  assert.equal((await run("init", f.directory, ...f.options, ...f.codex)).code, 1, "existing instance is retained");
  assert.deepEqual(f.profile(), p);
});

test("environment setup remains supported and explicit flags override inherited settings", async t => {
  const f = fixture(t);
  Object.assign(process.env, { KEEP_PROJECT_MODEL: "codex", KEEP_CODEX_PROCESSING: "owner-public-repository", KEEP_CODEX_EXECUTABLE: f.engine,
    KEEP_CODEX_MODEL: "environment-model", KEEP_CODEX_MAX_INVOCATIONS: "3", KEEP_CODEX_MAX_PROMPT_BYTES: "4096", KEEP_CODEX_MAX_OUTPUT_BYTES: "8192", KEEP_CODEX_TIMEOUT_MS: "1000", KEEP_TEST_NAMESPACE_JAIL: "best-effort" });
  const legacy = await run("init", f.directory, ...f.options);
  assert.equal(legacy.code, 0, legacy.output);
  assert.equal(f.profile().environment.KEEP_CODEX_MODEL, "environment-model");
  const second = join(f.root, "second");
  const override = await run("init", second, ...f.options, "--codex-model=explicit-model", "--test-namespace-jail=off");
  assert.equal(override.code, 0, override.output);
  const profile = JSON.parse(readFileSync(join(second, "instance.json"), "utf8"));
  assert.equal(profile.environment.KEEP_CODEX_MODEL, "explicit-model");
  assert.equal(profile.environment.KEEP_CODEX_MAX_INVOCATIONS, "3");
  assert.equal(profile.environment.KEEP_TEST_NAMESPACE_JAIL, "off");
  assert.equal(f.profile().environment.KEEP_TEST_NAMESPACE_JAIL, "best-effort");
});

test("invalid setup explains correction, preserves source, and permits retry at the same path", async t => {
  const f = fixture(t);
  const cases: { replace?: string; value?: string; mode?: string; message: RegExp }[] = [
    { replace: "codex-executable", message: /--codex-executable/u },
    { replace: "codex-executable", value: join(f.root, "absent"), message: /--codex-executable/u },
    { replace: "codex-executable", value: "relative-codex", message: /--codex-executable/u },
    { replace: "codex-model", message: /--codex-model/u },
    { replace: "codex-model", value: "bad model", message: /--codex-model/u },
    { replace: "codex-processing", message: /--codex-processing=owner-public-repository/u },
    { replace: "codex-max-invocations", message: /--codex-max-invocations/u },
    { replace: "codex-max-invocations", value: "0", message: /--codex-max-invocations/u },
    { replace: "codex-max-prompt-bytes", value: "Infinity", message: /--codex-max-prompt-bytes/u },
    { replace: "codex-max-output-bytes", value: "9007199254740992", message: /--codex-max-output-bytes/u },
    { replace: "codex-timeout-ms", value: "2147483648", message: /--codex-timeout-ms/u },
    { replace: "project-model", value: "other", message: /--project-model/u },
    { mode: "logged-out", message: /existing ChatGPT login.*--codex-executable/u },
    { mode: "bad-version", message: /Incompatible Codex version/u },
    { mode: "version-failure", message: /metadata inspection failed.*--codex-executable/u },
  ];
  for (const c of cases) {
    writeFileSync(f.mode, c.mode ?? "ready");
    const flags = f.codex.filter(flag => !flag.startsWith(`--${c.replace}=`));
    if (c.value !== undefined) flags.push(`--${c.replace}=${c.value}`);
    const result = await run("init", f.directory, ...f.options, ...flags);
    assert.equal(result.code, 1, JSON.stringify(c));
    assert.match(result.output, c.message);
    assert.doesNotMatch(result.output, /synthetic-private-diagnostic/u);
    assert.equal(existsSync(f.directory), false, "failed init removes only empty setup directories");
  }
  writeFileSync(f.mode, "ready");
  const retry = await run("init", f.directory, ...f.options, ...f.codex);
  assert.equal(retry.code, 0, retry.output);
  assert.equal(f.git(["-C", f.repository, "status", "--porcelain"]), "");
  assert.ok(f.probes().every(args => JSON.stringify(args) === '["--version"]' || JSON.stringify(args) === '["login","status"]'));
});

test("init refuses unknown/duplicate options and repository overlap including symlinked parents", async t => {
  const f = fixture(t);
  for (const flags of [["--unknown=yes"], ["--codex-model=first", "--codex-model=second"]]) {
    const result = await run("init", f.directory, ...f.options, ...flags);
    assert.equal(result.code, 1); assert.match(result.output, /each documented.*once/u);
    assert.equal(existsSync(f.directory), false);
  }
  const alias = join(f.root, "alias"); symlinkSync(f.repository, alias);
  for (const path of [join(f.repository, "instance"), join(alias, "instance")]) {
    const result = await run("init", path, ...f.options);
    assert.equal(result.code, 1); assert.match(result.output, /choose a new instance directory outside/u);
    assert.equal(existsSync(path), false);
  }
  assert.deepEqual(f.probes(), []);
});

test("required helper selection refuses absent or untrusted bytes without executing it", async t => {
  const f = fixture(t);
  for (const path of [join(f.root, "absent-helper"), f.engine]) {
    const result = await run("init", f.directory, ...f.options, "--test-namespace-jail=required", `--test-jail-executable=${path}`);
    assert.equal(result.code, 1); assert.match(result.output, /absent or untrusted.*--test-namespace-jail=required --test-jail-executable/u);
    assert.equal(existsSync(f.directory), false);
  }
  const wrongMode = await run("init", f.directory, ...f.options, "--test-namespace-jail=off", `--test-jail-executable=${f.engine}`);
  assert.equal(wrongMode.code, 1); assert.match(wrongMode.output, /--test-jail-executable/u);
  assert.deepEqual(f.probes(), [], "helper trust check never executes selected bytes");
});

test("unconfigured saved profile starts paused, survives status and stops through owned lifecycle", async t => {
  const f = fixture(t);
  const initialized = await run("init", f.directory, ...f.options);
  assert.equal(initialized.code, 0, initialized.output);
  assert.match(initialized.output, /dispatch paused/u);
  assert.equal(f.profile().environment.KEEP_PROJECT_MODEL, undefined);
  const started = await run("start", f.directory);
  assert.equal(started.code, 0, started.output);
  try {
    assert.match(started.output, /Dispatch: paused/u);
    const status = await run("status", f.directory);
    assert.equal(status.code, 0, status.output);
    assert.match(status.output, /Dispatch: paused/u);
    assert.match(status.output, /Generation is not configured/u);
    const projects = await run("projects", f.directory);
    assert.equal(projects.code, 0, projects.output);
    assert.deepEqual(f.probes(), []);
  } finally {
    await stop(f.directory);
  }
});

test("fresh workers reuse saved Codex settings and status invokes no engine", async t => {
  const f = fixture(t);
  // Exercise the actual installed CLI dispatch as well as the reusable command handler.
  const initialized = execFileSync(process.execPath, [join(process.cwd(), "dist", "src", "main.js"), "instance", "init", f.directory, ...f.options, ...f.codex], { encoding: "utf8" });
  assert.match(initialized, /Instance saved/u);
  const profile = f.profile();
  let priorWorker: string | undefined;
  for (let restart = 0; restart < 2; restart++) {
    writeFileSync(f.mode, "ready");
    const started = await run("start", f.directory, "--paused");
    assert.equal(started.code, 0, started.output);
    try {
      assert.match(started.output, /Dispatch: paused/u);
      const worker = JSON.parse(readFileSync(join(f.directory, "current-worker.json"), "utf8"));
      assert.notEqual(worker.workerId, priorWorker);
      priorWorker = worker.workerId;
      const callsBeforeStatus = f.probes();
      writeFileSync(f.mode, "version-failure");
      const status = await run("status", f.directory);
      assert.equal(status.code, 0, status.output);
      assert.match(status.output, /model=fixture-model/u);
      assert.match(status.output, /invocations=2; prompt bytes=65536/u);
      assert.deepEqual(f.probes(), callsBeforeStatus, "status does not probe or generate");
      assert.deepEqual(f.profile(), profile, "startup does not rewrite saved setup");
    } finally {
      await stop(f.directory);
    }
  }
  assert.ok(f.probes().every(args => JSON.stringify(args) === '["--version"]' || JSON.stringify(args) === '["login","status"]'), "no generation command was dispatched");
  const stoppedStatus = await run("status", f.directory);
  assert.equal(stoppedStatus.code, 0, stoppedStatus.output);
  assert.match(stoppedStatus.output, /Keep is stopped.*\n.*\nSaved generation setup: Codex selected/u);
});


function clientOptions(f: ReturnType<typeof fixture>) {
  const parent = join(f.root, "private client ; literal"); mkdirSync(parent, { mode: 0o700 });
  const profile = join(parent, "client $(not-a-shell).json"), tokenFile = join(parent, "client-token"), expiry = new Date(Date.now() + 60_000).toISOString();
  return { profile, tokenFile, expiry, args: [`--profile=${profile}`, `--token-file=${tokenFile}`, "--agent-id=saved-instance-client", `--expires-at=${expiry}`] };
}

test("client-issue uses only saved settings, retains charged usage and starts the exact restricted binding", async t => {
  const f = fixture(t), client = clientOptions(f);
  assert.equal((await run("init", f.directory, ...f.options, ...f.codex, "--test-namespace-jail=off")).code, 0);
  const original = f.profile();
  const data = join(f.directory, "data"), retainedClaim = "9c053ffa-239f-417b-8211-f3add9be1bc3";
  const spine = new Spine(new FileSpineStore(data, { fsync: true }), new FileSystemLock(join(data, ".locks")), new SchemaRegistry());
  spine.stage({ type: "identity.action", actor: "codex.project-generation", payload: { event: "claimed", id: retainedClaim, binding: "a".repeat(64) } });
  spine.stage({ type: "identity.action", actor: "codex.project-generation", payload: { event: "uncertain", id: retainedClaim } });
  await spine.seal();
  const retainedUsage = spine.replay().filter(event => event.actor === "codex.project-generation");
  Object.assign(process.env, { KEEP_DATA_DIR: join(f.root, "wrong-data"), KEEP_GATEWAY_URL: "http://foreign.invalid", KEEP_OWNER_TOKEN: "ambient-owner-secret",
    KEEP_PROVIDER_API_KEY: "ambient-provider-secret", KEEP_CODEX_MODEL: "wrong-model", KEEP_CODEX_MAX_INVOCATIONS: "900", KEEP_OPENCLAW_CLIENT_PROFILE: join(f.root, "wrong-client") });
  writeFileSync(f.mode, "capture");
  const issued = spawnSync(process.execPath, [join(process.cwd(), "dist/src/main.js"), "instance", "client-issue", f.directory, ...client.args], { encoding: "utf8" });
  assert.equal(issued.status, 0, issued.stderr + issued.stdout);
  const profile = f.profile(), captured = JSON.parse(readFileSync(join(f.root, "issued-runtime.json"), "utf8"));
  assert.equal(captured.locked, true, "instance control lock remains held during actual issuance child metadata");
  assert.deepEqual(captured.environment, { HOME: process.env.HOME, CODEX_HOME: process.env.CODEX_HOME, ...original.environment });
  assert.deepEqual(profile, { ...original, environment: { ...original.environment, KEEP_OPENCLAW_CLIENT_PROFILE: client.profile } });
  assert.equal(existsSync(join(f.root, "wrong-data")), false, "ambient KEEP_DATA_DIR never selects a different ledger");
  const admission = readRestrictedClientProfile(client.profile), bearer = readFileSync(client.tokenFile, "utf8").trim();
  assert.equal(admission.agentId, "saved-instance-client"); assert.equal(admission.expiresAt, Date.parse(client.expiry));
  assert.equal(admission.bearerSha256, createHash("sha256").update(bearer).digest("hex"));
  assert.equal(statSync(client.profile).mode & 0o777, 0o600); assert.equal(statSync(client.tokenFile).mode & 0o777, 0o600);
  assert.doesNotMatch(JSON.stringify(profile) + issued.stdout + issued.stderr, new RegExp(bearer + "|ambient-owner-secret|ambient-provider-secret|synthetic-auth-secret"));
  assert.deepEqual(spine.replay().filter(event => event.actor === "codex.project-generation"), retainedUsage, "issuance preserves original charged and uncertain invocation records");
  const callsBeforeStatus = f.probes();
  const status = await run("status", f.directory);
  assert.equal(status.code, 0, status.output); assert.ok(status.output.includes(`Restricted client profile: ${client.profile}`));
  assert.deepEqual(f.probes(), callsBeforeStatus, "binding status performs no engine probe");
  const duplicate = await run("client-issue", f.directory, ...client.args);
  assert.equal(duplicate.code, 1); assert.match(duplicate.output, /already has a client profile binding/);
  assert.deepEqual(f.probes(), callsBeforeStatus, "existing binding refuses before issuance metadata or effects");
  const usage = spawnSync(process.execPath, [join(process.cwd(), "dist/src/main.js"), "codex-usage", "status"], { encoding: "utf8", env: { PATH: process.env.PATH, HOME: process.env.HOME, KEEP_DATA_DIR: data } });
  assert.equal(usage.status, 0, usage.stderr); const ledger = JSON.parse(usage.stdout);
  assert.equal(ledger.claimed, 1); assert.deepEqual(ledger.unresolved.map((entry: { id: string; state: string }) => [entry.id, entry.state]), [[retainedClaim, "uncertain"]]);
  const started = await run("start", f.directory, "--paused");
  assert.equal(started.code, 0, started.output);
  try {
    const worker = JSON.parse(readFileSync(join(f.directory, "current-worker.json"), "utf8"));
    const restricted = await fetch(worker.origin + "/project/jobs?jobId=not-a-recorded-job", { headers: { authorization: `Bearer ${bearer}` } });
    assert.equal(restricted.status, 404, "worker accepts exact issued runtime binding/grant then refuses unknown own-work job");
    assert.equal((await fetch(worker.origin + "/projects", { headers: { authorization: `Bearer ${bearer}` } })).status, 403, "issued client cannot list owner projects");
    const before = f.probes(); writeFileSync(f.mode, "version-failure");
    const live = await run("status", f.directory); assert.equal(live.code, 0, live.output);
    assert.ok(live.output.includes(client.profile)); assert.deepEqual(f.probes(), before);
    assert.deepEqual(f.profile(), profile, "start never rewrites original limits, data or client binding");
  } finally { await stop(f.directory); }
  assert.ok(f.probes().every(args => JSON.stringify(args) === '["--version"]' || JSON.stringify(args) === '["login","status"]'), "only scripted metadata commands, no login or generation dispatch");
});

test("client issuance failure saves no reference, suppresses private diagnostics and preserves existing outputs", async t => {
  const f = fixture(t), client = clientOptions(f);
  assert.equal((await run("init", f.directory, ...f.options, ...f.codex)).code, 0);
  const original = readFileSync(join(f.directory, "instance.json"), "utf8");
  writeFileSync(f.mode, "version-failure");
  const failed = await run("client-issue", f.directory, ...client.args);
  assert.equal(failed.code, 1); assert.match(failed.output, /no profile reference was saved/);
  assert.doesNotMatch(failed.output, /synthetic-private-diagnostic|synthetic-auth-secret/);
  assert.equal(readFileSync(join(f.directory, "instance.json"), "utf8"), original);
  assert.equal(existsSync(client.profile), false); assert.equal(existsSync(client.tokenFile), false);
  assert.equal(existsSync(join(f.directory, ".control-lock")), false);
  writeFileSync(f.mode, "ready"); writeFileSync(client.tokenFile, "retain this private existing credential", { mode: 0o600 });
  const collision = await run("client-issue", f.directory, ...client.args);
  assert.equal(collision.code, 1); assert.equal(existsSync(client.profile), false);
  assert.equal(readFileSync(client.tokenFile, "utf8"), "retain this private existing credential");
  assert.equal(readFileSync(join(f.directory, "instance.json"), "utf8"), original);
  assert.ok(f.probes().every(args => JSON.stringify(args) === '["--version"]' || JSON.stringify(args) === '["login","status"]'));
});

test("client issuance refuses startup uncertainty, active ownership, control contention and invalid options before dispatch", async t => {
  const f = fixture(t), client = clientOptions(f);
  assert.equal((await run("init", f.directory, ...f.options, ...f.codex)).code, 0);
  const original = f.profile(), before = f.probes();
  const pending = join(f.directory, "startup-pending.json"); writeFileSync(pending, "{}", { mode: 0o600 });
  const uncertain = await run("client-issue", f.directory, ...client.args);
  assert.equal(uncertain.code, 1); assert.match(uncertain.output, /startup is unresolved/); rmSync(pending);
  const lock = join(f.directory, ".control-lock"); mkdirSync(lock, { mode: 0o700 });
  assert.match((await run("client-issue", f.directory, ...client.args)).output, /control is in progress/); assert.equal(existsSync(lock), true); rmSync(lock, { recursive: true });
  for (const flags of [client.args.slice(0, 3), [...client.args, "--agent-id=duplicate"], [...client.args, "--command=extra"], [...client.args, "--agent-id=contains\0nul"]]) {
    const invalid = await run("client-issue", f.directory, ...flags); assert.equal(invalid.code, 1); assert.match(invalid.output, /documented option|requires --profile/);
  }
  assert.deepEqual(f.probes(), before, "pre-dispatch refusals perform no metadata or grant effects");
  const started = await run("start", f.directory, "--paused"); assert.equal(started.code, 0, started.output);
  try {
    const calls = f.probes();
    const active = await run("client-issue", f.directory, ...client.args);
    assert.equal(active.code, 1); assert.match(active.output, /worker may still be active or unresolved/);
    assert.deepEqual(f.probes(), calls);
  } finally { await stop(f.directory); }
  assert.deepEqual(f.profile(), original); assert.equal(existsSync(client.profile), false); assert.equal(existsSync(client.tokenFile), false);
});


test("client-issue rereads its profile after control admission instead of issuing from a stale pre-lock snapshot", async t => {
  const f = fixture(t), client = clientOptions(f);
  assert.equal((await run("init", f.directory, ...f.options, ...f.codex)).code, 0);
  const probesBefore = f.probes(), priorBinding = join(f.root, "prior-issued-client.json");
  // Only this disposable child patches fs. Simulate a prior controller saving
  // its binding just before this contender acquires the now-free control lock.
  const script = `import fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
const original=fs.mkdirSync; let injected=false;
fs.mkdirSync=function(path,...args){
 if(path===${JSON.stringify(join(f.directory, ".control-lock"))}&&!injected){
  const file=${JSON.stringify(join(f.directory, "instance.json"))}, p=JSON.parse(fs.readFileSync(file,'utf8'));
  p.environment.KEEP_OPENCLAW_CLIENT_PROFILE=${JSON.stringify(priorBinding)};
  fs.writeFileSync(file,JSON.stringify(p)); injected=true;
 }
 return original.call(this,path,...args);
};
syncBuiltinESMExports();
const {runInstanceCommand}=await import(${JSON.stringify(new URL("../src/cli/instance.js", import.meta.url).href)});
let output='';const code=await runInstanceCommand(${JSON.stringify(["client-issue", f.directory, ...client.args])},value=>output+=value);
console.log(JSON.stringify({code,output,injected}));`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
  assert.equal(child.status, 0, child.stderr);
  const result = JSON.parse(child.stdout);
  assert.equal(result.injected, true); assert.equal(result.code, 1);
  assert.match(result.output, /already has a client profile binding/);
  assert.deepEqual(f.probes(), probesBefore, "contender must not issue a second grant after the prior writer saved its binding");
  assert.equal(f.profile().environment.KEEP_OPENCLAW_CLIENT_PROFILE, priorBinding);
  assert.equal(existsSync(client.profile), false); assert.equal(existsSync(client.tokenFile), false);
});
