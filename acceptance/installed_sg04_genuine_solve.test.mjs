/** Installed consumer development evidence. Injected provider, real repository test
 * process and signed enterprise ingress. NOT real-model or full enterprise qualification. */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn, spawnSync, execFile } from "node:child_process";
import { createSign, generateKeyPairSync } from "node:crypto";
import { createServer } from "node:http";

const installed = process.env.KEEP_INSTALLED_PACKAGE_ROOT;
if (!installed) throw Error("KEEP_INSTALLED_PACKAGE_ROOT required; no source import substitution");
const keep = await import(pathToFileURL(join(installed, "dist/src/index.js")).href);
const here = fileURLToPath(import.meta.url);
const goal = "Fix retryLimit in src/retry.mjs to match the configured limit.";
const before = "export const retryLimit = 0;\n";
const after = "export const retryLimit = 7;\n";

function git(cwd, args) {
  const result = spawnSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args], {
    cwd, encoding: "utf8", timeout: 5000, maxBuffer: 256 * 1024,
    env: { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0" },
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

if (process.argv[2] === "dispatch-worker") {
  const root = process.argv[3];
  const module = relative => import(pathToFileURL(join(installed, "dist/src", relative)).href);
  const { Spine } = await module("spine/spine.js"), { FileSpineStore } = await module("spine/store.js");
  const { FileSystemLock } = await module("lock/lock.js"), { SchemaRegistry } = await module("spine/upcaster.js");
  const { SpineProjectJobJournal } = await module("session/project_job_journal.js"), { ProjectRuntime } = await module("session/project_runtime.js");
  const { ProjectRegistry } = await module("session/project_registry.js"), { ProjectSessionManager } = await module("session/project_session_manager.js");
  const { CryptoShredKeyStore } = await module("keystore/keystore.js");
  const spine = new Spine(new FileSpineStore(root, { fsync: true }), new FileSystemLock(join(root, "locks")), new SchemaRegistry());
  const journal = new SpineProjectJobJournal(spine), manager = new ProjectSessionManager(new ProjectRegistry(new CryptoShredKeyStore()));
  const project = manager.create({ name: "independent installed claimant" });
  const runtime = new ProjectRuntime(manager, { aggregateCeiling: 1, perProjectShare: 1 }, journal, { leaseMs: 2000, heartbeatMs: 50 });
  const load = journal.load.bind(journal);
  // Pause each contender after the same pre-admission snapshot, not inside the
  // transaction. This forces the real check/write race instead of hoping for timing.
  journal.load = () => {
    journal.load = load; const snapshot = load(); process.send({ type: "ready" });
    const until = Date.now() + 5000, wait = new Int32Array(new SharedArrayBuffer(4));
    while (!existsSync(join(root, "release-snapshot"))) { if (Date.now() > until) throw Error("snapshot barrier expired"); Atomics.wait(wait, 0, 0, 5); }
    return snapshot;
  };
  let release; const gate = new Promise(resolve => { release = resolve; });
  process.on("message", message => { if (message === "release") release(); });
  const job = runtime.submitTracked(project.id, 1, async context => { process.send({ type: "entered", jobId: context.jobId }); await gate; return "done"; });
  process.send({ type: "submitted", jobId: job.jobId });
  try { await job.completion; await spine.seal(); process.send({ type: "done", jobId: job.jobId }); }
  finally { process.disconnect(); }
} else if (process.argv[2] === "child") {
  const [mode, root, runId] = process.argv.slice(3);
  const source = join(root, "source"), workspaceBase = join(root, "workspaces");
  let calls = 0;
  const model = {
    name: "installed-adaptive-fixture", isLocal: true, embed: async () => [],
    generate: async request => {
      calls++;
      assert.equal(mode === "resume", false, "restart observation must not reacquire a model result");
      assert.equal(request.hints?.taskRole, "repository_edit");
      const seen = request.prompt.includes('\\"configuredRetryLimit\\":7');
      const response = mode === "refuse"
        ? { action: "read_file", path: "../../not-admitted", startLine: 1, lineCount: 1 }
        : seen
          ? { action: "plan", rationale: "Match the observed configuration", edits: [{ file: "src/retry.mjs", search: "retryLimit = 0", replace: "retryLimit = 7", intent: "Correct configured retry behavior" }] }
          : { action: "read_file", path: "config/runtime.json", startLine: 1, lineCount: 10 };
      return { text: JSON.stringify(response), model: "installed-adaptive-fixture", tokensIn: 1, tokensOut: 1 };
    },
  };
  const app = keep.composeKeep({ dataDir: join(root, "state"), developmentProvider: model,
    repositoryMaterialization: { sourceDir: source, workspaceBase, repoRef: "project", commit: git(source, ["rev-parse", "HEAD"]), baseBranch: "main" },
    testCommand: { command: process.execPath, args: ["--test", "--test-reporter=tap", "retry.test.mjs"], timeoutMs: 5000, cpuLimitSec: 2, maxOutputBytes: 16_384 },
  });
  const lines = [];
  if (mode === "resume") {
    assert.equal((await keep.runCli(["projects"], { write: line => lines.push(line), prompt: async () => "" }, { app })).exitCode, 0);
    assert.ok(lines.join("\n").includes(runId));
  } else {
    assert.equal((await keep.runCli(["project", goal], { write: line => lines.push(line), prompt: async () => "" }, { app })).exitCode, 0, lines.join("\n"));
  }
  const selectedRun = runId || /Run: ([^\s]+)/u.exec(lines.join("\n"))?.[1];
  assert.ok(selectedRun, lines.join("\n"));
  const view = await keep.handleGatewayRequest(app, { method: "GET", path: "/project", query: { runId: selectedRun }, headers: { authorization: "Bearer fixture-owner" }, body: "" }, { token: "fixture-owner" });
  assert.equal(view.status, 200, view.body);
  const state = JSON.parse(view.body).project;
  const implementation = state.artifacts.implement;
  assert.ok(implementation?.solve, JSON.stringify(state));
  const solved = implementation.solve;
  assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), before, "proposal does not modify operator source");
  assert.equal(readFileSync(join(workspaceBase, "project/config/runtime.json"), "utf8"), '{"configuredRetryLimit":7}\n');
  if (mode === "refuse") {
    assert.equal(solved.solved, false);
    assert.match(solved.gaveUpReason, /unauthorized observation/);
    assert.equal(solved.recovery.planningCalls, 1);
    assert.equal(solved.recovery.status, "ready", "read-only refusal is not ambiguous effect debt");
    assert.equal(readFileSync(join(workspaceBase, "project/src/retry.mjs"), "utf8"), before);
    assert.equal(solved.projectEditReceipt, undefined);
  } else {
    assert.equal(state.status, "completed", JSON.stringify(state));
    assert.equal(solved.solved, true, solved.gaveUpReason);
    assert.equal(solved.recovery.attempts, 1);
    assert.equal(solved.recovery.planningCalls, 2);
    assert.equal(solved.projectEditReceipt.testsExecuted, true);
    assert.deepEqual(implementation.admittedEditPrepared.allowedFiles, ["src/retry.mjs"]);
    assert.equal(readFileSync(join(workspaceBase, "project/src/retry.mjs"), "utf8"), after);
    if (mode !== "resume") assert.equal(calls, 2);
  }
  await app.spine.seal();
  const events = app.spine.replay();
  const observed = events.filter(e => e.payload.event === "native_planning" && e.payload.outcome === "observation");
  assert.equal(observed.length, mode === "refuse" ? 0 : 1);
  process.stdout.write(JSON.stringify({ runId: selectedRun, status: state.status, calls, planningCalls: solved.recovery.planningCalls, testsExecuted: solved.projectEditReceipt?.testsExecuted ?? false }));
} else {
  test("installed independent worker processes atomically share one dispatch slot", { timeout: 15_000 }, async t => {
    const root = mkdtempSync(join(tmpdir(), "keep-installed-dispatch-")), messages = [], children = [];
    t.after(() => { for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); rmSync(root, { recursive: true, force: true }); });
    const exits = [0, 1].map(index => {
      const child = spawn(process.execPath, [here, "dispatch-worker", root], { cwd: root, env: { KEEP_INSTALLED_PACKAGE_ROOT: installed }, stdio: ["ignore", "ignore", "pipe", "ipc"] });
      children.push(child); let stderr = "";
      child.stderr.on("data", bytes => { stderr += bytes.toString(); });
      child.on("message", message => messages.push({ ...message, index }));
      return new Promise(resolve => child.on("close", (code, signal) => resolve({ code, signal, stderr })));
    });
    const waitFor = async predicate => { const deadline = Date.now() + 5000; while (!predicate()) { assert.ok(Date.now() < deadline, JSON.stringify(messages)); await new Promise(resolve => setTimeout(resolve, 10)); } };
    await waitFor(() => messages.filter(m => m.type === "ready").length === 2);
    writeFileSync(join(root, "release-snapshot"), "ready");
    await waitFor(() => messages.filter(m => m.type === "submitted").length === 2 && messages.some(m => m.type === "entered"));
    await new Promise(resolve => setTimeout(resolve, 100));
    assert.equal(messages.filter(m => m.type === "entered").length, 1, "two stale observations cannot spend the same capacity slot");
    const winner = messages.find(m => m.type === "entered").index;
    children[winner].send("release");
    await waitFor(() => messages.filter(m => m.type === "entered").length === 2);
    children[1 - winner].send("release");
    for (const result of await Promise.all(exits)) assert.equal(result.code, 0, result.stderr);
    assert.equal(messages.filter(m => m.type === "done").length, 2);
    assert.equal(new Set(messages.filter(m => m.type === "entered").map(m => m.jobId)).size, 2);
  });
  for (const mode of ["solve", "refuse"]) test(`installed owner CLI: adaptive ${mode} uses canonical admission and real validation`, t => {
    const root = mkdtempSync(join(tmpdir(), `keep-installed-sg04-${mode}-`));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const source = join(root, "source");
    mkdirSync(join(source, "src"), { recursive: true });
    mkdirSync(join(source, "config"));
    mkdirSync(join(root, "workspaces"));
    writeFileSync(join(source, "src/retry.mjs"), before);
    writeFileSync(join(source, "config/runtime.json"), '{"configuredRetryLimit":7}\n');
    writeFileSync(join(source, "retry.test.mjs"), "import test from 'node:test'; import assert from 'node:assert/strict'; import {retryLimit} from './src/retry.mjs'; test('configured retry behavior', () => assert.equal(retryLimit, 7));\n");
    git(source, ["init", "--quiet", "--initial-branch=main"]);
    git(source, ["add", "src/retry.mjs", "config/runtime.json", "retry.test.mjs"]);
    git(source, ["-c", "user.name=Keep Fixture", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "fixture"]);
    const child = (selected, runId = "") => spawnSync(process.execPath, [here, "child", selected, root, runId], {
      cwd: root, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024,
      env: { PATH: process.env.PATH, KEEP_INSTALLED_PACKAGE_ROOT: installed },
    });
    const first = child(mode);
    assert.equal(first.status, 0, first.stderr + first.stdout);
    const result = JSON.parse(first.stdout);
    assert.equal(result.calls, mode === "solve" ? 2 : 1);
    if (mode === "solve") {
      const restarted = child("resume", result.runId);
      assert.equal(restarted.status, 0, restarted.stderr + restarted.stdout);
      assert.deepEqual(JSON.parse(restarted.stdout), { ...result, calls: 0 });
    }
  });

  for (const execution of ["inline", "detached", "recovery", "goal"]) test(`installed executable CLI ${execution}: configured HTTP provider drives adaptive proposal without an agent installation`, { timeout: 60_000 }, async t => {
    const root = mkdtempSync(join(tmpdir(), "keep-installed-sg04-configured-"));
    let worker, remoteEnv, jobId, workerStart;
    let releaseModel; const modelGate = new Promise(resolve => { releaseModel = resolve; });
    const source = join(root, "source"), workspaceBase = join(root, "workspaces"), profile = join(root, "provider.json");
    mkdirSync(join(source, "src"), { recursive: true }); mkdirSync(join(source, "config")); mkdirSync(workspaceBase);
    writeFileSync(join(source, "src/retry.mjs"), before);
    writeFileSync(join(source, "config/runtime.json"), '{"configuredRetryLimit":7}\n');
    writeFileSync(join(source, "retry.test.mjs"), "import test from 'node:test'; import assert from 'node:assert/strict'; import {retryLimit} from './src/retry.mjs'; test('configured retry behavior', () => assert.equal(retryLimit, 7));\n");
    git(source, ["init", "--quiet", "--initial-branch=main"]);
    git(source, ["add", "."]);
    git(source, ["-c", "user.name=Keep Fixture", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "fixture"]);
    const revision = git(source, ["rev-parse", "HEAD"]);
    const requests = [];
    const server = createServer(async (req, res) => {
      try {
        assert.equal(req.method, "POST"); assert.equal(req.url, "/v1/chat/completions");
        const chunks = []; let bytes = 0;
        for await (const chunk of req) { bytes += chunk.length; assert.ok(bytes <= 65_536); chunks.push(chunk); }
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")); requests.push(body);
        if (execution !== "inline" && requests.length === 1) await modelGate;
        assert.ok(requests.length <= 4, "unexpected repeated provider dispatch");
        assert.equal(body.model, "configured-adaptive-fixture");
        const prompt = body.messages[0].content;
        const response = prompt.includes('\\"configuredRetryLimit\\":7')
          ? { action: "plan", rationale: "Match observed configuration", edits: [{ file: "src/retry.mjs", search: "retryLimit = 0", replace: "retryLimit = 7", intent: "Correct retry behavior" }] }
          : { action: "read_file", path: "config/runtime.json", startLine: 1, lineCount: 10 };
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ model: body.model, choices: [{ message: { content: JSON.stringify(response) }, finish_reason: "stop" }], usage: { prompt_tokens: 10, completion_tokens: 10 } }));
      } catch { res.writeHead(400, { "content-type": "application/json" }); res.end('{"error":"fixture request refused"}'); }
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    const env = { PATH: process.env.PATH, KEEP_PROFILE: profile, KEEP_DATA_DIR: join(root, "state"),
      KEEP_REPOSITORY: source, KEEP_WORKSPACE_BASE: workspaceBase, KEEP_REVISION: revision, KEEP_REPO_REF: "project", KEEP_BASE_BRANCH: "main",
      KEEP_TEST_COMMAND: process.execPath, KEEP_TEST_ARGS_JSON: '["--test","--test-reporter=tap","retry.test.mjs"]',
      KEEP_TEST_TIMEOUT_MS: "5000", KEEP_TEST_CPU_LIMIT_SEC: "2", KEEP_TEST_MAX_OUTPUT_BYTES: "16384", KEEP_PROJECT_POSTURE: "approval-required" };
    const invoke = (args, selectedEnv = env) => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [join(installed, "dist/src/main.js"), ...args], { cwd: root, env: selectedEnv, stdio: ["ignore", "pipe", "pipe"], shell: false });
      let stdout = "", stderr = ""; const timer = setTimeout(() => child.kill("SIGKILL"), 30_000);
      child.stdout.on("data", chunk => { stdout += chunk; if (Buffer.byteLength(stdout) > 1_048_576) child.kill("SIGKILL"); });
      child.stderr.on("data", chunk => { stderr += chunk; if (Buffer.byteLength(stderr) > 1_048_576) child.kill("SIGKILL"); });
      child.once("error", error => { clearTimeout(timer); reject(error); });
      child.once("close", code => { clearTimeout(timer); resolve({ code, stdout, stderr, pid: child.pid }); });
    });
    const processIdentity = pid => { try { const value = readFileSync(`/proc/${pid}/stat`, "utf8"); return value.slice(value.lastIndexOf(")") + 2).split(" ")[19]; } catch { return undefined; } };
    const workerExited = () => { try { const value = readFileSync(`/proc/${worker.pid}/stat`, "utf8"), fields = value.slice(value.lastIndexOf(")") + 2).split(" "); return fields[19] !== workerStart || fields[0] === "Z"; } catch (error) { if (error.code === "ENOENT") return true; throw error; } };
    t.after(async () => {
      releaseModel();
      if (worker && !workerExited() && processIdentity(worker.pid) === workerStart) {
        if (jobId) await invoke(["project", "cancel", jobId], remoteEnv);
        await invoke(["worker", "stop", worker.workerId], remoteEnv);
        if (processIdentity(worker.pid) === workerStart) { try { process.kill(worker.pid, "SIGKILL"); } catch (error) { if (error.code !== "ESRCH") throw error; } }
      }
      server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
      rmSync(root, { recursive: true, force: true });
    });
    const configured = await invoke(["provider", "configure", `--profile=${profile}`, "--name=sg04-configured", "--location=local", "--authority=owner", "--protocol=openai-compatible", `--endpoint=http://127.0.0.1:${server.address().port}`, "--model=configured-adaptive-fixture", "--purpose=software-development", "--region=local", "--credential=none"]);
    assert.equal(configured.code, 0, configured.stderr);
    assert.equal(requests.length, 0, "configuration does not dispatch inference");
    let runId;
    if (execution === "inline") {
      const proposed = await invoke(["project", goal]);
      assert.equal(proposed.code, 0, proposed.stderr + proposed.stdout);
      runId = /Run: ([^\s]+)/u.exec(proposed.stdout)?.[1]; assert.ok(runId, proposed.stdout);
      assert.match(proposed.stdout, /--proposal=[0-9a-f]{64}/u, "real tested proposal must reach the operator");
    } else if (execution === "goal") {
      const launchArgs = ["serve", "--gateway", "--project-worker", "--detach", "--port=0"];
      const launched = await invoke([...launchArgs, "--paused"]); assert.equal(launched.code, 0, launched.stderr + launched.stdout);
      worker = JSON.parse(launched.stdout); workerStart = processIdentity(worker.pid); assert.ok(workerStart);
      remoteEnv = { PATH: process.env.PATH, KEEP_GATEWAY_URL: worker.origin, KEEP_GATEWAY_TOKEN_FILE: worker.tokenFile, KEEP_PROFILE: "/missing/client-profile.json" };
      const spec = join(root, "goal.json"), definition = goalDefinition(); writeFileSync(spec, JSON.stringify(definition));
      const args = ["project", "goal", "create", `--spec=${spec}`, "--idempotency-key=installed-goal-operation", "--activate"];
      const created = await invoke(args, remoteEnv); assert.equal(created.code, 0, created.stderr + created.stdout);
      const parent = JSON.parse(created.stdout); assert.equal(parent.document.startsUsed, 0); assert.equal(parent.selection.selected, "repair");
      const encrypted = readFileSync(join(root, "state", "projects", "sessions", `${parent.projectId}.json.documents`, "native-goal-work-v1.json"), "utf8");
      assert.ok(JSON.parse(encrypted).cipher); assert.equal(encrypted.includes(definition.objective), false); assert.equal(requests.length, 0);
      const stopped = await invoke(["worker", "stop", worker.workerId], remoteEnv); assert.equal(stopped.code, 0, stopped.stdout);
      const deathDeadline = Date.now() + 3000; while (!workerExited()) { assert.ok(Date.now() < deathDeadline); await new Promise(resolve => setTimeout(resolve, 10)); }
      const replacement = await invoke(launchArgs); assert.equal(replacement.code, 0, replacement.stderr + replacement.stdout);
      worker = JSON.parse(replacement.stdout); workerStart = processIdentity(worker.pid); assert.ok(workerStart);
      remoteEnv = { ...remoteEnv, KEEP_GATEWAY_URL: worker.origin, KEEP_GATEWAY_TOKEN_FILE: worker.tokenFile };
      const retry = await invoke(args, remoteEnv); assert.equal(retry.code, 0, retry.stderr + retry.stdout); assert.equal(JSON.parse(retry.stdout).projectId, parent.projectId);
      const readGoal = async () => { const result = await invoke(["project", "goal", "show", parent.projectId], remoteEnv); assert.equal(result.code, 0, result.stderr + result.stdout); return JSON.parse(result.stdout); };
      const deadline = Date.now() + 25_000; let view;
      do { view = await readGoal(); assert.ok(Date.now() < deadline, "restarted worker must select the persisted repair automatically"); if (!view.document.claims.repair) await new Promise(resolve => setTimeout(resolve, 50)); } while (!view.document.claims.repair);
      jobId = view.document.claims.repair.jobId; runId = jobId;
      assert.equal(view.document.claims.polish, undefined); assert.deepEqual(view.selection.deferred, ["polish"]);
      releaseModel();
      do { view = await readGoal(); assert.ok(Date.now() < deadline, JSON.stringify(view.tasks)); if (!view.document.accepted.repair) await new Promise(resolve => setTimeout(resolve, 50)); } while (!view.document.accepted.repair);
      assert.equal(view.document.startsUsed, 1); assert.equal(view.document.accepted.repair.kind, "tested-proposal");
      assert.deepEqual(view.selection.held.verify, ["capability:release-host"]); assert.deepEqual(view.document.definition, definition);
      const listed = await invoke(["projects"], remoteEnv); assert.equal(listed.code, 0, listed.stderr + listed.stdout);
      assert.match(listed.stdout, /1\/3/u); assert.match(listed.stdout, /tested.proposal/iu);
      assert.ok(listed.stdout.includes(`keep project goal show ${parent.projectId}`));
      const controlled = await invoke(["project", "goal", "control", parent.projectId, `--revision=${view.revision}`, "--phase=release", "--active=false"], remoteEnv);
      assert.equal(controlled.code, 0, controlled.stderr + controlled.stdout);
      const due = JSON.parse(controlled.stdout); assert.deepEqual(due.selection.deferred, []); assert.equal(due.document.definition.tasks.length, 3);
      assert.equal(due.tasks.find(task => task.id === "polish").status, "ready");
    } else {
      const launchArgs = ["serve", "--gateway", "--project-worker", "--detach", "--port=0"];
      const launched = await invoke([...launchArgs, "--paused"]);
      assert.equal(launched.code, 0, launched.stderr + launched.stdout);
      worker = JSON.parse(launched.stdout); workerStart = processIdentity(worker.pid);
      assert.ok(workerStart); assert.notEqual(worker.pid, launched.pid, "launching executable has exited, actual worker is separate");
      assert.equal(JSON.parse(readFileSync(worker.receipt, "utf8")).state, "ready");
      remoteEnv = { PATH: process.env.PATH, KEEP_GATEWAY_URL: worker.origin, KEEP_GATEWAY_TOKEN_FILE: worker.tokenFile, KEEP_PROFILE: "/missing/client-must-not-load-provider.json" };
      const args = ["project", goal, "--background", "--idempotency-key=installed-detached-operation"];
      const submitted = await invoke(args, remoteEnv); assert.equal(submitted.code, 0, submitted.stderr + submitted.stdout);
      const accepted = JSON.parse(submitted.stdout); jobId = accepted.jobId; runId = accepted.runId;
      assert.equal(accepted.status, "accepted"); assert.notEqual(submitted.pid, worker.pid);
      const queued = await invoke(["project", "job", jobId], remoteEnv);
      assert.equal(queued.code, 0, queued.stderr + queued.stdout); assert.equal(JSON.parse(queued.stdout).job.state, "queued");
      const originalIntent = JSON.parse(queued.stdout).job;
      const commandAtRest = readFileSync(join(root, "state", "projects", "sessions", `${accepted.projectId}.json.documents`, `job-command-${jobId}.json`), "utf8");
      assert.equal(JSON.parse(commandAtRest).storageRevision, 1); assert.ok(JSON.parse(commandAtRest).cipher);
      assert.equal(commandAtRest.includes(goal), false, "durable command remains encrypted under project custody");
      assert.equal(requests.length, 0, "paused native worker accepts without dispatch");
      if (execution === "recovery") {
        assert.equal(processIdentity(worker.pid), workerStart, "kill only this exact owned worker");
        process.kill(worker.pid, "SIGKILL");
        const deathDeadline = Date.now() + 3000;
        while (!workerExited()) { assert.ok(Date.now() < deathDeadline); await new Promise(resolve => setTimeout(resolve, 10)); }
        const priorWorkerId = worker.workerId;
        const replacement = await invoke(launchArgs); assert.equal(replacement.code, 0, replacement.stderr + replacement.stdout);
        worker = JSON.parse(replacement.stdout); workerStart = processIdentity(worker.pid); assert.ok(workerStart);
        assert.notEqual(worker.workerId, priorWorkerId);
        remoteEnv = { ...remoteEnv, KEEP_GATEWAY_URL: worker.origin, KEEP_GATEWAY_TOKEN_FILE: worker.tokenFile };
      } else {
        const resumed = await invoke(["worker", "resume", worker.workerId], remoteEnv); assert.equal(resumed.code, 0, resumed.stderr + resumed.stdout);
        assert.equal(JSON.parse(resumed.stdout).state, "running");
      }
      const until = Date.now() + (execution === "recovery" ? 42_000 : 5000); while (requests.length === 0) { assert.ok(Date.now() < until, "replacement worker must recover the original queued command"); await new Promise(resolve => setTimeout(resolve, 25)); }
      const observed = await invoke(["project", "job", jobId], remoteEnv); assert.equal(observed.code, 0, observed.stderr + observed.stdout);
      const snapshot = JSON.parse(observed.stdout); assert.equal(snapshot.job.state, "running"); assert.equal(snapshot.job.ownerId, worker.workerId);
      assert.equal(snapshot.job.createdAt, originalIntent.createdAt); assert.equal(snapshot.job.commandDigest, originalIntent.commandDigest);
      assert.ok(snapshot.activities.some(activity => activity.state === "running"));
      const retry = await invoke(args, remoteEnv); assert.equal(retry.code, 0, retry.stderr); assert.equal(JSON.parse(retry.stdout).jobId, jobId); assert.equal(JSON.parse(retry.stdout).replayed, true); assert.equal(requests.length, 1);
      const busy = await invoke(["worker", "stop", worker.workerId], remoteEnv); assert.equal(busy.code, 1); assert.match(busy.stdout, /active requests or owned work/u);
      releaseModel();
      const deadline = Date.now() + 10_000; let state;
      do { const result = await invoke(["project", "job", jobId], remoteEnv); assert.equal(result.code, 0, result.stderr + result.stdout); state = JSON.parse(result.stdout).job.state;
        assert.ok(Date.now() < deadline, state); if (state !== "completed") await new Promise(resolve => setTimeout(resolve, 25));
      } while (state !== "completed");
      if (execution === "recovery") {
        const view = await fetch(`${worker.origin}/project?runId=${runId}`, { headers: { authorization: `Bearer ${readFileSync(worker.tokenFile, "utf8").trim()}` }, signal: AbortSignal.timeout(3000) });
        assert.equal(view.status, 200);
        const project = (await view.json()).project;
        assert.equal(project.artifacts.implement.solve.recovery.attempts, 1);
        assert.equal(project.artifacts.implement.solve.recovery.planningCalls, 2);
      }
    }
    assert.equal(requests.length, 2);
    assert.equal(git(source, ["rev-parse", "HEAD"]), revision);
    assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), before);
    assert.equal(readFileSync(join(workspaceBase, "project/src/retry.mjs"), "utf8"), after);
    const validated = spawnSync(process.execPath, ["--test", "retry.test.mjs"], { cwd: join(workspaceBase, "project"), encoding: "utf8", timeout: 5000, env: { PATH: process.env.PATH } });
    assert.equal(validated.status, 0, validated.stderr + validated.stdout);
    const reopened = await invoke(["projects"], remoteEnv ?? env); assert.equal(reopened.code, 0, reopened.stderr); assert.ok(reopened.stdout.includes(runId));
    assert.equal(requests.length, 2, "fresh executable readback does not call the provider");
    if (worker) {
      const stopped = await invoke(["worker", "stop", worker.workerId], remoteEnv); assert.equal(stopped.code, 0, stopped.stderr + stopped.stdout);
      const receipt = worker.receipt.replace(".ready.json", ".stopped.json"), deadline = Date.now() + 3000;
      while (!existsSync(receipt)) { assert.ok(Date.now() < deadline); await new Promise(resolve => setTimeout(resolve, 10)); }
      assert.equal(JSON.parse(readFileSync(receipt, "utf8")).state, "stopped");
      await assert.rejects(fetch(worker.origin + "/health", { signal: AbortSignal.timeout(1000) }));
      while (!workerExited()) { assert.ok(Date.now() < deadline, "listener closure alone is not process termination"); await new Promise(resolve => setTimeout(resolve, 10)); }
    }
  });

  function goalDefinition() {
    const task = (id, extra = {}) => ({ id, goal, kind: "goal", dependsOn: [], requires: ["software-solver", "repository-tests"], due: "development", acceptance: "tested-proposal", ...extra });
    return { objective: `${goal} Preserve every release safeguard; do not merge the source.`, maxTaskStarts: 3, tasks: [task("polish", { goal: "Polish logging wording before release", kind: "hardening", due: "release" }), task("repair"), task("verify", { dependsOn: ["repair"], requires: ["release-host"] })] };
  }

  async function enterpriseFixture(t, { personal = false, modelGate, directPlan = false, responseFor, testBody } = {}) {
    const root = mkdtempSync(join(tmpdir(), "keep-installed-sg04-enterprise-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const roots = tenantId => {
      const base = join(root, tenantId);
      const row = { tenantId, dataRoot: join(base, "data"), repositoryRoot: join(base, "source"), workspaceRoot: join(base, "workspace") };
      for (const path of [row.dataRoot, row.repositoryRoot, row.workspaceRoot]) mkdirSync(path, { recursive: true });
      return row;
    };
    const alpha = roots("alpha"), beta = roots("beta");
    const candidate = join(alpha.workspaceRoot, "project");
    mkdirSync(join(candidate, "src"), { recursive: true }); mkdirSync(join(candidate, "config"));
    writeFileSync(join(candidate, "src/retry.mjs"), before);
    writeFileSync(join(candidate, "config/runtime.json"), '{"configuredRetryLimit":7}\n');
    writeFileSync(join(candidate, "retry.test.mjs"), testBody ?? "import test from 'node:test'; import assert from 'node:assert/strict'; import {retryLimit} from './src/retry.mjs'; test('tenant retry behavior', () => assert.equal(retryLimit, 7));\n");
    writeFileSync(join(beta.workspaceRoot, "untouched.txt"), "other tenant\n");
    let calls = 0, settled = 0; const signals = [];
    const model = { name: "enterprise-adaptive-fixture", isLocal: true, embed: async () => [], generate: async request => {
      calls++; signals.push(request.signal);
      if (modelGate) await modelGate;
      settled++;
      const response = responseFor ? responseFor(request) : directPlan || request.prompt.includes('\\"configuredRetryLimit\\":7')
        ? { action: "plan", rationale: "Match tenant configuration", edits: [{ file: "src/retry.mjs", search: "retryLimit = 0", replace: "retryLimit = 7", intent: "Correct retry behavior" }] }
        : { action: "read_file", path: "config/runtime.json", startLine: 1, lineCount: 10 };
      return { text: JSON.stringify(response), model: "enterprise-adaptive-fixture", tokensIn: 1, tokensOut: 1 };
    } };
    // Measure this installed owner's startup and health calls, rather than inventing
    // latency numbers. This fixture baseline does NOT qualify release performance.
    let tenantDeployment;
    if (!personal) {
    const started = performance.now();
    const solo = keep.composeKeep({ dataDir: join(root, "solo") });
    const soloServer = await keep.startGatewayServer(solo, { port: 0 });
    const startupMs = Math.ceil(performance.now() - started);
    const timings = [];
    try { for (let i = 0; i < 20; i++) { const at = performance.now(); const res = await fetch(`${soloServer.origin}/health`); assert.equal(res.status, 200); await res.text(); timings.push(performance.now() - at); } }
    finally { await soloServer.close(); }
    timings.sort((a, b) => a - b);
    const current = { startupMs, p95LatencyMs: Math.ceil(timings[18]) };
    const baselinePath = join(alpha.dataRoot, "solo-baseline.json");
    new keep.FileSoloReleaseBaselineStore(baselinePath).pin(keep.captureSoloReleaseBaseline(
      keep.captureCanonicalSoloObservation(current, keep.captureInstalledPackageSubjectDigest(installed)), current,
    ));
    tenantDeployment = { tenantId: "alpha", peers: [beta], soloNonRegression: { baselinePath, current } };
    }
    const owner = { id: "alice", kind: "human", role: "owner", tenant: "alpha" };
    const config = { dataDir: alpha.dataRoot, developmentProvider: model, workspace: new keep.LocalFsWorkspace(alpha.workspaceRoot), repoRef: "project",
      runtimePaths: { repository: alpha.repositoryRoot, workspace: alpha.workspaceRoot },
      ...(tenantDeployment ? { tenantDeployment } : {}),
      delegationParentFor: (id, tenant) => id === owner.id && tenant === owner.tenant ? owner : undefined,
      testCommand: { command: process.execPath, args: ["--test", "--test-reporter=tap", "retry.test.mjs"], timeoutMs: 5000, cpuLimitSec: 2, maxOutputBytes: 16_384 },
    };
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const issuer = "https://sg04-idp.example", audience = "sg04-enterprise";
    const identity = { provider: new keep.OidcJwksProvider({ issuer, audience, jwks: { keys: [{ ...publicKey.export({ format: "jwk" }), kid: "sg04", alg: "RS256", use: "sig" }] } }),
      registry: new keep.PrincipalRegistry([{ subject: "alice", role: "owner", id: "alice", tenant: "alpha" }, { subject: "bob", role: "owner", id: "bob", tenant: "beta" }]), sessions: new keep.SessionStore() };
    let app = keep.composeKeep(config);
    const security = () => ({ port: 0, token: "e".repeat(64), ...(personal ? {} : { identity }) });
    let server = await keep.startGatewayServer(app, security());
    t.after(async () => { await server.close(); });
    const request = async (session, method, path, body) => {
      const res = await fetch(`${server.origin}${path}`, { method, headers: { authorization: `Bearer ${"e".repeat(64)}`, ...(session ? { "x-keep-session": session } : {}), "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      return { status: res.status, body: await res.json() };
    };
    const login = async subject => {
      const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "sg04", typ: "JWT" })).toString("base64url");
      const payload = Buffer.from(JSON.stringify({ sub: subject, iss: issuer, aud: audience, exp: Math.floor(Date.now() / 1000) + 60 })).toString("base64url");
      const signature = createSign("RSA-SHA256").update(`${header}.${payload}`).end().sign(privateKey).toString("base64url");
      return request(undefined, "POST", "/auth/session", { assertion: `${header}.${payload}.${signature}` });
    };
    return { root, alpha, beta, candidate, request, login, origin: () => server.origin, calls: () => calls, settled: () => settled, signals: () => signals, app: () => app,
      restart: async () => { await server.close(); identity.sessions = new keep.SessionStore(); app = keep.composeKeep(config); server = await keep.startGatewayServer(app, security()); },
    };
  }

  for (const personal of [true, false]) test(`installed ${personal ? "owner" : "enterprise"}: lost-response retry observes one operation and survives terminal reconstruction`, { timeout: 10_000 }, async t => {
    let release; const gate = new Promise(resolve => { release = resolve; }); t.after(() => release());
    const f = await enterpriseFixture(t, { personal, modelGate: gate });
    let session;
    if (!personal) { const login = await f.login("alice"); assert.equal(login.status, 200); session = login.body.session; }
    const submission = { goal, background: true, idempotencyKey: "installed-submission-001" };
    const invalid = await f.request(session, "POST", "/project", { ...submission, idempotencyKey: "short" });
    assert.equal(invalid.status, 400); assert.equal(f.calls(), 0);
    const accepted = await f.request(session, "POST", "/project", submission);
    assert.equal(accepted.status, 202); assert.equal(accepted.body.runId, accepted.body.jobId);
    const jobPath = `/project/jobs?jobId=${encodeURIComponent(accepted.body.jobId)}`;
    const deadline = Date.now() + 4000;
    while (f.calls() === 0 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(f.calls(), 1);
    const retried = await f.request(session, "POST", "/project", { idempotencyKey: submission.idempotencyKey, background: true, goal });
    assert.equal(retried.status, 202); assert.equal(retried.body.replayed, true);
    assert.equal(retried.body.jobId, accepted.body.jobId); assert.equal(retried.body.projectId, accepted.body.projectId);
    const conflict = await f.request(session, "POST", "/project", { ...submission, goal: `${goal} changed` });
    assert.equal(conflict.status, 409);
    const projects = await f.request(session, "GET", "/projects"); assert.equal(projects.body.projects.length, 1);
    for (let i = 0; i < 2; i++) {
      const observed = await f.request(session, "GET", jobPath); assert.equal(observed.status, 200); assert.equal(observed.body.job.state, "running");
    }
    assert.equal(f.calls(), 1, "new HTTP observers never redispatch the withheld operation");
    release();
    let terminal;
    do {
      terminal = await f.request(session, "GET", jobPath);
      if (terminal.body.job?.state === "completed") break;
      await new Promise(resolve => setTimeout(resolve, 20));
    } while (Date.now() < deadline);
    assert.equal(terminal.body.job?.state, "completed", JSON.stringify(terminal.body));
    const view = await f.request(session, "GET", `/project?runId=${encodeURIComponent(accepted.body.runId)}`);
    assert.equal(view.status, 200); assert.equal(view.body.project.status, "completed");
    assert.equal(view.body.project.artifacts.implement.solve.projectEditReceipt.testsExecuted, true);
    assert.equal(f.calls(), 2); assert.equal(readFileSync(join(f.candidate, "src/retry.mjs"), "utf8"), after);
    await f.restart();
    if (!personal) { const login = await f.login("alice"); assert.equal(login.status, 200); session = login.body.session; }
    const restored = await f.request(session, "GET", jobPath);
    assert.deepEqual(restored.body.job, terminal.body.job); assert.equal(f.calls(), 2);
    const restartedRetry = await f.request(session, "POST", "/project", submission);
    assert.equal(restartedRetry.status, 202); assert.equal(restartedRetry.body.replayed, true); assert.equal(restartedRetry.body.jobId, accepted.body.jobId);
    assert.equal(f.calls(), 2, "same caller's new authenticated session observes instead of starting another run");
    if (!personal) {
      // The same text key from another authenticated principal is not this owner's
      // reservation. An archived project supplies a no-dispatch admission refusal.
      assert.equal((await f.request(session, "POST", "/project/archive", { projectId: accepted.body.projectId })).status, 200);
      const grant = await f.request(session, "POST", "/delegation/issue", { agentId: "retry-coder", grantId: "retry-grant", expiresAt: Date.now() + 60_000, permissions: ["change.solve"] });
      assert.equal(grant.status, 200);
      const otherSubmission = { ...submission, projectId: accepted.body.projectId };
      const other = await f.request(grant.body.session, "POST", "/project", otherSubmission);
      assert.equal(other.status, 409); assert.equal(other.body.status, "reconciliation-required");
      assert.notEqual(other.body.jobId, accepted.body.jobId, "principal-scoped reservation cannot alias the owner's job");
      const otherRetry = await f.request(grant.body.session, "POST", "/project", otherSubmission);
      assert.equal(otherRetry.status, 409); assert.equal(otherRetry.body.jobId, other.body.jobId);
      assert.equal((await f.request(session, "POST", "/delegation/revoke", { grantId: "retry-grant" })).status, 200);
      assert.equal((await f.request(grant.body.session, "POST", "/project", otherSubmission)).status, 403, "a key never bypasses revoked authority");
      assert.equal(f.calls(), 2);
    }
    const invisible = await f.request(session, "GET", "/project/jobs?jobId=00000000-0000-4000-8000-000000000000"); assert.equal(invisible.status, 404);
  });

  for (const personal of [true, false]) test(`installed ${personal ? "owner" : "enterprise"}: cancellation reaches native provider and rejects a late edit without redispatch`, { timeout: 10_000 }, async t => {
    let release; const gate = new Promise(resolve => { release = resolve; }); t.after(() => release());
    const f = await enterpriseFixture(t, { personal, modelGate: gate, directPlan: true });
    let session;
    if (!personal) { const login = await f.login("alice"); assert.equal(login.status, 200); session = login.body.session; }
    const submission = { goal, background: true, idempotencyKey: "installed-cancel-001" };
    const accepted = await f.request(session, "POST", "/project", submission); assert.equal(accepted.status, 202);
    const deadline = Date.now() + 4000, jobPath = `/project/jobs?jobId=${accepted.body.jobId}`;
    while (f.calls() === 0 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(f.calls(), 1); assert.ok(f.signals()[0]); assert.equal(f.signals()[0].aborted, false);
    assert.equal((await f.request(session, "POST", "/project/cancel", { jobId: "00000000-0000-4000-8000-000000000000" })).status, 404);
    if (!personal) {
      const viewer = await f.request(session, "POST", "/delegation/issue", { agentId: "cancel-viewer", grantId: "cancel-viewer-grant", expiresAt: Date.now() + 60_000, permissions: ["audit.view"] });
      assert.equal(viewer.status, 200);
      assert.equal((await f.request(viewer.body.session, "POST", "/project/cancel", { jobId: accepted.body.jobId })).status, 403);
      assert.equal(f.signals()[0].aborted, false, "read authority cannot cancel another operation");
    }
    const cancelled = await f.request(session, "POST", "/project/cancel", { jobId: accepted.body.jobId });
    assert.equal(cancelled.status, 202); assert.equal(cancelled.body.job.cancellationRequested, true);
    assert.equal(f.signals()[0].aborted, true, "the actual composed native provider receives the operator's signal");
    let stopped;
    do {
      stopped = await f.request(session, "GET", jobPath);
      if (stopped.body.job?.state === "reconciliation-required") break;
      await new Promise(resolve => setTimeout(resolve, 10));
    } while (Date.now() < deadline);
    assert.equal(stopped.body.job?.state, "reconciliation-required", JSON.stringify(stopped.body));
    assert.equal(f.settled(), 0, "an ignoring provider is still live: never report it as confirmed cancelled");
    assert.equal(f.app().projectRuntime.status().running, 1, "unresolved backend retains its original capacity slot after callback settlement");
    const activityView = await f.request(session, "GET", jobPath);
    const pendingModel = activityView.body.activities.find(activity => activity.label === "solve-call" && activity.state === "running");
    assert.ok(pendingModel, "operator sees the exact unresolved child identity");
    await f.restart();
    if (!personal) { const login = await f.login("alice"); assert.equal(login.status, 200); session = login.body.session; }
    assert.equal(f.app().projectRuntime.status().running, 1, "reconstructed runtime still accounts for the original backend");
    const pendingRestored = await f.request(session, "GET", jobPath);
    assert.equal(pendingRestored.body.activities.find(activity => activity.id === pendingModel.id)?.state, "running");
    assert.ok(pendingRestored.body.job.activeActivityIds.includes(pendingModel.id), "parent settlement cannot erase this still-live child");
    assert.equal(readFileSync(join(f.candidate, "src/retry.mjs"), "utf8"), before);
    const repeated = await f.request(session, "POST", "/project/cancel", { jobId: accepted.body.jobId });
    assert.equal(repeated.status, 202);
    release();
    while (f.settled() === 0 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(f.settled(), 1); assert.equal(f.calls(), 1);
    while (f.app().projectRuntime.status().running !== 0 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
    assert.equal(f.app().projectRuntime.status().running, 0, "actual child settlement releases capacity without restarting the operation");
    const settledActivities = await f.request(session, "GET", jobPath);
    assert.ok(settledActivities.body.activities.length > 0 && settledActivities.body.activities.every(activity => activity.state === "settled"));
    assert.equal(readFileSync(join(f.candidate, "src/retry.mjs"), "utf8"), before, "late valid edit plan cannot mutate candidate");
    const project = await f.request(session, "GET", `/project?runId=${accepted.body.runId}`);
    assert.equal(project.body.project.status, "waiting-reconciliation");
    assert.equal(project.body.project.artifacts.implement, undefined, "cancelled stage output cannot become an accepted artifact");
    assert.equal(f.app().spine.currentEvents().filter(e => e.payload.event === "project.job.cancel-requested").length, 1);
    await f.restart();
    if (!personal) { const login = await f.login("alice"); assert.equal(login.status, 200); session = login.body.session; }
    const restored = await f.request(session, "GET", jobPath);
    assert.equal(restored.body.job.state, "reconciliation-required"); assert.equal(restored.body.job.cancellationRequested, true);
    const retry = await f.request(session, "POST", "/project", submission);
    assert.equal(retry.status, 202); assert.equal(retry.body.jobId, accepted.body.jobId); assert.equal(retry.body.replayed, true);
    assert.equal(f.calls(), 1);
  });

  test("installed enterprise: goal work preserves scope, tests its proposal and refuses borrowed or revoked authority", { timeout: 15_000 }, async t => {
    const f = await enterpriseFixture(t), login = await f.login("alice"); assert.equal(login.status, 200);
    const session = login.body.session, definition = goalDefinition();
    const body = { definition, idempotencyKey: "installed-enterprise-goal", active: true };
    const created = await f.request(session, "POST", "/project/goal", body); assert.equal(created.status, 202, JSON.stringify(created.body));
    const id = created.body.projectId;
    assert.equal(created.body.selection.selected, "repair"); assert.equal(f.calls(), 0);
    const issued = await f.request(session, "POST", "/delegation/issue", { agentId: "goal-agent", grantId: "goal-agent-grant", permissions: ["change.solve"], expiresAt: Date.now() + 60_000 });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    assert.equal((await f.request(issued.body.session, "POST", "/project/goal/advance", { projectId: id })).status, 403, "agent must not borrow goal creator authority");
    assert.equal((await f.request(session, "POST", "/project/goal/advance", { projectId: id, accepted: { repair: true } })).status, 400);
    const advanced = await f.request(session, "POST", "/project/goal/advance", { projectId: id }); assert.equal(advanced.status, 202, JSON.stringify(advanced.body));
    const deadline = Date.now() + 7000; let view;
    do {
      const result = await f.request(session, "POST", "/project/goal/advance", { projectId: id }); assert.equal(result.status, 202, JSON.stringify(result.body)); view = result.body;
      if (view.tasks.find(task => task.id === "repair").status === "acceptance-unproven") {
        const saved = await f.request(session, "GET", `/project?runId=${view.document.claims.repair.jobId}`);
        const state = saved.body.project;
        assert.fail(`completed callback lacks accepted evidence: ${JSON.stringify({ status: state.status, stage: state.stage, wait: state.wait, test: state.artifacts.vet_artifact })}`);
      }
      assert.ok(Date.now() < deadline, JSON.stringify(view.tasks)); if (!view.document.accepted.repair) await new Promise(resolve => setTimeout(resolve, 10));
    } while (!view.document.accepted.repair);
    assert.equal(view.document.startsUsed, 1); assert.equal(view.document.accepted.repair.kind, "tested-proposal");
    const saved = await f.request(session, "GET", `/project?runId=${view.document.claims.repair.jobId}`);
    assert.equal(saved.body.project.artifacts.goal_work_context, definition.objective);
    assert.ok(saved.body.project.artifacts.implement.issue.text.includes(definition.objective), "solver receives the complete parent objective, including no-merge constraints");
    assert.deepEqual(view.document.definition, definition); assert.deepEqual(view.selection.held.verify, ["capability:release-host"]);
    assert.deepEqual(view.selection.deferred, ["polish"]); assert.equal(readFileSync(join(f.candidate, "src/retry.mjs"), "utf8"), after);
    const listed = await f.request(session, "GET", "/projects"); assert.equal(listed.status, 200);
    assert.deepEqual(listed.body.projects.find(project => project.id === id).goalWork, { active: true, phase: "development", totalTasks: 3, acceptedTasks: 1, deferredTasks: 1, heldTasks: 1, nextTaskId: null });
    assert.equal(JSON.stringify(listed.body).includes(definition.objective), false);
    const delegated = await f.request(issued.body.session, "POST", "/project/goal", { ...body, active: false, idempotencyKey: "installed-agent-goal" }); assert.equal(delegated.status, 202, JSON.stringify(delegated.body));
    const revoked = await f.request(session, "POST", "/delegation/revoke", { grantId: "goal-agent-grant" }); assert.equal(revoked.status, 200);
    assert.equal((await f.request(issued.body.session, "POST", "/project/goal/advance", { projectId: delegated.body.projectId })).status, 403);
    await f.restart(); const again = await f.login("alice"); assert.equal(again.status, 200);
    const restored = await f.request(again.body.session, "GET", `/project/goal?projectId=${id}`);
    assert.equal(restored.status, 200); assert.deepEqual(restored.body.document.accepted, view.document.accepted); assert.equal(f.calls(), 2);
    const foreign = await f.login("bob"); assert.equal(foreign.status, 403);
    assert.equal(readFileSync(join(f.beta.workspaceRoot, "untouched.txt"), "utf8"), "other tenant\n");
  });

  for (const personal of [true, false]) test(`installed ${personal ? "owner" : "enterprise"}: measured validation retains independent roots and operator limits`, { timeout: 15_000 }, async t => {
    const testBody = "import test from 'node:test'; import assert from 'node:assert/strict'; import {writeFileSync} from 'node:fs'; import {retryLimit} from './src/retry.mjs'; test('tenant retry behavior', () => { writeFileSync('test-generated.txt', 'disposable only'); assert.equal(retryLimit, 7); });\n";
    const f = await enterpriseFixture(t, { personal, directPlan: true, testBody });
    let session;
    if (!personal) { const login = await f.login("alice"); assert.equal(login.status, 200); session = login.body.session; }
    const { ProcessIsolationAdapter } = await import(pathToFileURL(join(installed, "dist/src/infra/process_isolation.js")).href);
    const { computeMicrovmProjectSourceManifestSha256 } = await import(pathToFileURL(join(installed, "dist/src/infra/microvm_boundary.js")).href);
    const originalRun = ProcessIsolationAdapter.prototype.run, executions = [];
    // Observation only: every command still uses the installed adapter and its real
    // child process. Never substitute a runner result or mint a verification receipt.
    t.mock.method(ProcessIsolationAdapter.prototype, "run", async function(command, args, policy) {
      const record = { command, args: [...args], policy: structuredClone(policy),
        manifest: await computeMicrovmProjectSourceManifestSha256(policy.cwd) };
      executions.push(record);
      const result = await originalRun.call(this, command, args, policy);
      Object.assign(record, { code: result.code, durationMs: result.durationMs, timedOut: result.timedOut, degraded: result.degraded ?? [] });
      return result;
    });
    const proposed = await f.request(session, "POST", "/project", { goal });
    assert.equal(proposed.status, 200, JSON.stringify(proposed.body));
    assert.equal(proposed.body.status, "completed", JSON.stringify(proposed.body));
    const view = await f.request(session, "GET", `/project?runId=${proposed.body.runId}`);
    assert.equal(view.status, 200);
    const implementation = view.body.project.artifacts.implement, verification = view.body.project.artifacts.vet_artifact;
    t.diagnostic(JSON.stringify({ track: personal ? "owner" : "enterprise", executions: executions.map(row => ({
      root: row.policy.cwd === f.candidate ? "solver" : "independent-copy", durationMs: row.durationMs,
      maxOutputBytes: row.policy.maxOutputBytes, code: row.code, degraded: row.degraded,
    })) }));
    assert.equal(executions.length, 2, "one repair-feedback run and one independent-copy verification, no extra suite");
    assert.notEqual(executions[0].policy.cwd, f.candidate, "solver feedback also uses independent source, not the mutable candidate");
    assert.notEqual(executions[1].policy.cwd, f.candidate);
    assert.notEqual(executions[0].policy.cwd, executions[1].policy.cwd);
    assert.equal(existsSync(executions[0].policy.cwd), false, "feedback copy was disposed");
    assert.equal(existsSync(executions[1].policy.cwd), false, "verification copy was disposed");
    assert.equal(existsSync(join(f.candidate, "test-generated.txt")), false, "test effects cannot contaminate the candidate");
    for (const row of executions) {
      assert.equal(row.command, process.execPath); assert.deepEqual(row.args, ["--test", "--test-reporter=tap", "retry.test.mjs"]);
      assert.equal(row.manifest, implementation.repositoryExecutionManifestSha256);
      assert.equal(row.manifest, verification.repositoryExecutionManifestSha256);
      assert.equal(row.code, 0); assert.equal(row.timedOut, false);
      assert.equal(row.policy.timeoutMs, 5000); assert.equal(row.policy.cpuLimitSec, 2);
      assert.equal(row.policy.maxOutputBytes, 16_384, "operator output limit applies to both real executions");
      assert.deepEqual(row.policy.envAllowlist ?? [], []);
      assert.equal(row.policy.namespaceJail.projectDir, row.policy.cwd);
    }
    assert.equal(verification.passed, true); assert.equal(f.calls(), 1);
    await f.request(session, "GET", "/projects");
    await f.request(session, "GET", `/project?runId=${proposed.body.runId}`);
    assert.equal(executions.length, 2, "operator readback does not execute validation again");
    assert.equal(readFileSync(join(f.beta.workspaceRoot, "untouched.txt"), "utf8"), "other tenant\n");
  });

  for (const personal of [true, false]) for (const regress of [false, true]) test(`installed ${personal ? "owner" : "enterprise"}: multi-task goal ${regress ? "rejects later regression" : "preserves lineage and dispatches due safeguard"}`, { timeout: 25_000 }, async t => {
    const ready = "export const readiness = true;\n", status = 'export const retryStatus = () => `${retryLimit} attempts`;\n', policy = 'export const releasePolicy = "bounded";\n';
    const responseFor = request => {
      let search = before.trim(), replace = after.trim();
      if (request.prompt.includes("Add the readiness export")) { search = after.trim(); replace = search + "\n" + ready.trim(); }
      else if (request.prompt.includes("Add the retryStatus export")) { search = ready.trim(); replace = search + "\n" + status.trim(); }
      else if (request.prompt.includes("Add the releasePolicy export")) { search = after.trim(); replace = regress ? before.trim() : search + "\n" + policy.trim(); }
      return { action: "plan", rationale: regress ? "Untrusted fixture may introduce a regression" : "Implement the admitted fixture task", edits: [{ file: "src/retry.mjs", search, replace, intent: "Implement current task only" }] };
    };
    const f = await enterpriseFixture(t, { personal, responseFor });
    let session;
    if (!personal) { const login = await f.login("alice"); assert.equal(login.status, 200); session = login.body.session; }
    const task = (id, goal, extra = {}) => ({ id, goal, kind: "goal", dependsOn: [], requires: ["software-solver", "repository-tests"], due: "development", acceptance: "tested-proposal", ...extra });
    const definition = { objective: "Implement retry behavior and its operator metadata while preserving all repository regression tests and release safeguards. No source merge or external publication.", maxTaskStarts: 4, tasks: [
      task("feature", "Add the retryStatus export in src/retry.mjs returning the current retry limit followed by attempts. Preserve all earlier exports.", { dependsOn: ["guard"] }),
      task("release", 'Add the releasePolicy export in src/retry.mjs with value bounded. Preserve earlier retry behavior and exports.', { kind: "safeguard", due: "release", dependsOn: ["feature"] }),
      task("guard", "Add the readiness export in src/retry.mjs with value true. Preserve retry behavior.", { kind: "safeguard", dependsOn: ["repair"] }),
      task("repair", goal, { due: "release" }),
    ] };
    const created = await f.request(session, "POST", "/project/goal", { definition, idempotencyKey: "installed-multi-task-goal", active: true });
    assert.equal(created.status, 202, JSON.stringify(created.body)); const id = created.body.projectId;
    assert.equal(created.body.selection.selected, "repair", "due safeguard promotes its future-labelled prerequisite");
    assert.deepEqual(created.body.selection.deferred, ["release"]);
    const read = async () => { const r = await f.request(session, "GET", `/project/goal?projectId=${id}`); assert.equal(r.status, 200); return r.body; };
    const advance = async () => { const r = await f.request(session, "POST", "/project/goal/advance", { projectId: id }); assert.equal(r.status, 202, JSON.stringify(r.body)); return r.body; };
    const waitTask = async (view, taskId) => {
      const claim = view.document.claims[taskId]; assert.ok(claim?.projectId, JSON.stringify(view.tasks));
      const deadline = Date.now() + 8000;
      for (;;) {
        const r = await f.request(session, "GET", `/project/jobs?jobId=${claim.jobId}`); assert.equal(r.status, 200);
        if (["completed", "failed", "reconciliation-required", "stopped"].includes(r.body.job.state)) break;
        assert.ok(Date.now() < deadline, `task ${taskId} did not settle`); await new Promise(resolve => setTimeout(resolve, 10));
      }
      const r = await f.request(session, "GET", `/project?runId=${claim.jobId}`); assert.equal(r.status, 200);
      return r.body.project;
    };
    let view = await advance(), previous;
    for (const taskId of ["repair", "guard", "feature"]) {
      const state = await waitTask(view, taskId);
      assert.equal(state.status, "completed", JSON.stringify({ taskId, status: state.status, wait: state.wait }));
      if (previous) assert.equal(state.artifacts.plan.localization.repositoryTreeSha256, previous.artifacts.implement.repositoryTreeAfterSha256, "dependent work begins on the prior task's actual candidate");
      assert.equal(state.artifacts.vet_artifact.passed, true);
      previous = state;
      view = await advance();
      assert.ok(view.document.accepted[taskId]);
    }
    assert.deepEqual(Object.keys(view.document.accepted).sort(), ["feature", "guard", "repair"]);
    assert.equal(view.document.startsUsed, 3); assert.equal(f.calls(), 3);
    assert.deepEqual(view.selection.deferred, ["release"]); assert.equal(view.document.claims.release, undefined);
    const beforeRelease = readFileSync(join(f.candidate, "src/retry.mjs"), "utf8");
    assert.equal(beforeRelease, after + ready + status);
    const firstAcceptances = structuredClone(view.document.accepted), firstClaims = structuredClone(view.document.claims);
    const controlled = await f.request(session, "POST", "/project/goal/control", { projectId: id, expectedRevision: view.revision, phase: "release", active: true });
    assert.equal(controlled.status, 200, JSON.stringify(controlled.body));
    view = await advance(); const releaseState = await waitTask(view, "release"); view = await advance();
    assert.equal(view.document.startsUsed, 4); assert.deepEqual(view.document.definition, definition);
    for (const taskId of ["repair", "guard", "feature"]) { assert.deepEqual(view.document.claims[taskId], firstClaims[taskId]); assert.deepEqual(view.document.accepted[taskId], firstAcceptances[taskId]); }
    if (regress) {
      assert.notEqual(releaseState.status, "completed"); assert.equal(view.document.accepted.release, undefined);
      assert.equal(readFileSync(join(f.candidate, "src/retry.mjs"), "utf8"), beforeRelease, "failed later work must restore the earlier accepted candidate exactly");
    } else {
      assert.equal(releaseState.status, "completed"); assert.ok(view.document.accepted.release); assert.equal(f.calls(), 4);
    }
    const checked = spawnSync(process.execPath, ["--input-type=module", "-e", `import assert from 'node:assert/strict'; import * as value from './src/retry.mjs'; assert.equal(value.retryLimit,7); assert.equal(value.readiness,true); assert.equal(value.retryStatus(),'7 attempts'); ${regress ? "assert.equal(value.releasePolicy,undefined);" : "assert.equal(value.releasePolicy,'bounded');"}`], { cwd: f.candidate, encoding: "utf8", timeout: 3000, env: { PATH: process.env.PATH } });
    assert.equal(checked.status, 0, checked.stdout + checked.stderr);
    const finalCalls = f.calls(); assert.ok(finalCalls <= 8, "finite scripted provider work");
    await advance(); assert.equal(f.calls(), finalCalls, "observation never replenishes the four task starts");
    await f.restart(); if (!personal) { const login = await f.login("alice"); assert.equal(login.status, 200); session = login.body.session; }
    const restored = await read(); assert.equal(restored.document.startsUsed, 4); assert.deepEqual(restored.document.accepted, view.document.accepted);
    // This fixture deliberately uses an opaque executable provider seam. Its
    // identity is not restart-stable; do not weaken that hold to claim recovery.
    const refused = await f.request(session, "POST", "/project/goal/advance", { projectId: id });
    assert.equal(refused.status, 409); assert.equal(f.calls(), finalCalls);
    assert.equal(readFileSync(join(f.beta.workspaceRoot, "untouched.txt"), "utf8"), "other tenant\n");
  });

  test("installed enterprise: queued delegated command rechecks revocation before any provider effect", async t => {
    const f = await enterpriseFixture(t), login = await f.login("alice"); assert.equal(login.status, 200);
    const ownerSession = login.body.session;
    f.app().projectRuntime.pauseDispatch();
    const issued = await f.request(ownerSession, "POST", "/delegation/issue", { agentId: "queued-coder", grantId: "queued-grant", expiresAt: Date.now() + 60_000, permissions: ["change.solve"] });
    assert.equal(issued.status, 200);
    const accepted = await f.request(issued.body.session, "POST", "/project", { goal, background: true, idempotencyKey: "installed-queued-delegation" });
    assert.equal(accepted.status, 202, JSON.stringify(accepted.body)); assert.equal(f.calls(), 0);
    assert.equal((await f.request(ownerSession, "POST", "/delegation/revoke", { grantId: "queued-grant" })).status, 200);
    f.app().projectRuntime.resumeDispatch();
    const deadline = Date.now() + 3000; let state;
    do { const result = await f.request(ownerSession, "GET", `/project/jobs?jobId=${accepted.body.jobId}`); state = result.body.job.state;
      assert.ok(Date.now() < deadline, state); if (state !== "failed") await new Promise(resolve => setTimeout(resolve, 10));
    } while (state !== "failed");
    assert.equal(f.calls(), 0, "persisted principal reference cannot retain a revoked grant");
    assert.equal(readFileSync(join(f.candidate, "src/retry.mjs"), "utf8"), before);
  });

  test("installed enterprise: foreign tenant cannot dispatch into the bound workspace", async t => {
    const f = await enterpriseFixture(t);
    const foreignLogin = await f.login("bob");
    if (foreignLogin.status === 200) {
      const denied = await f.request(foreignLogin.body.session, "POST", "/project", { goal });
      assert.equal(denied.status, 403, `foreign tenant reached the bound workspace: ${JSON.stringify(denied.body)}; model calls=${f.calls()}`);
    } else assert.equal(foreignLogin.status, 403);
    assert.equal(f.calls(), 0);
    assert.equal(readFileSync(join(f.candidate, "src/retry.mjs"), "utf8"), before);
    const foreignResolved = await keep.handleGatewayRequest(f.app(), { method: "POST", path: "/project", query: {}, headers: { authorization: "Bearer resolved-fixture" }, body: JSON.stringify({ goal }) }, {
      token: "resolved-fixture", principalFor: () => ({ id: "bob", kind: "human", role: "owner", tenant: "beta" }),
    });
    assert.equal(foreignResolved.status, 403, "cached or custom-resolved principals must match the same deployment");
    // An omitted identity layer cannot turn an admitted tenant process into n=1.
    const local = await keep.handleGatewayRequest(f.app(), { method: "POST", path: "/project", query: {}, headers: { authorization: "Bearer local-fixture" }, body: JSON.stringify({ goal }) }, { token: "local-fixture" });
    assert.equal(local.status, 403, "missing tenant identity must not select the implicit local owner");
    assert.equal(f.calls(), 0);
  });

  test("installed enterprise: signed identity drives adaptive solve, revoked delegation stays refused after restart", async t => {
    const f = await enterpriseFixture(t);
    const login = await f.login("alice"); assert.equal(login.status, 200);
    const ownerSession = login.body.session;
    const issued = await f.request(ownerSession, "POST", "/delegation/issue", { agentId: "coder", grantId: "sg04-coder", expiresAt: Date.now() + 60_000, permissions: ["change.solve"] });
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const proposed = await f.request(issued.body.session, "POST", "/project", { goal });
    assert.equal(proposed.status, 200, JSON.stringify(proposed.body));
    assert.equal(proposed.body.status, "completed", JSON.stringify(proposed.body));
    const runId = proposed.body.runId;
    const view = await f.request(ownerSession, "GET", `/project?runId=${encodeURIComponent(runId)}`);
    assert.equal(view.status, 200);
    const implementation = view.body.project.artifacts.implement;
    assert.equal(implementation.solve.recovery.planningCalls, 2);
    assert.equal(implementation.solve.recovery.attempts, 1);
    assert.equal(implementation.solve.projectEditReceipt.testsExecuted, true);
    assert.equal(f.calls(), 2);
    assert.equal(readFileSync(join(f.candidate, "src/retry.mjs"), "utf8"), after);
    assert.equal(readFileSync(join(f.beta.workspaceRoot, "untouched.txt"), "utf8"), "other tenant\n");
    assert.equal((await f.request(ownerSession, "POST", "/delegation/revoke", { grantId: "sg04-coder" })).status, 200);
    assert.equal((await f.request(issued.body.session, "POST", "/project", { goal })).status, 403);
    await f.restart();
    assert.equal((await f.request(ownerSession, "GET", `/project?runId=${encodeURIComponent(runId)}`)).status, 403, "old identity sessions require fresh login");
    const again = await f.login("alice"); assert.equal(again.status, 200);
    const reopened = await f.request(again.body.session, "GET", `/project?runId=${encodeURIComponent(runId)}`);
    assert.deepEqual(reopened.body.project, view.body.project);
    assert.equal(f.app().authorization.restorePrincipal("sg04-coder"), undefined);
    const tokenFile = join(f.root, "client-token"), sessionFile = join(f.root, "client-session");
    writeFileSync(tokenFile, "e".repeat(64) + "\n", { mode: 0o600 }); writeFileSync(sessionFile, again.body.session + "\n", { mode: 0o600 });
    const client = session => new Promise(resolve => execFile(process.execPath, [join(installed, "dist/src/main.js"), "projects"], {
      cwd: f.root, env: { KEEP_GATEWAY_URL: f.origin(), KEEP_GATEWAY_TOKEN_FILE: tokenFile, ...(session ? { KEEP_GATEWAY_SESSION_FILE: sessionFile } : {}), KEEP_PROFILE: "/missing/enterprise-client-provider.json" }, timeout: 5000, maxBuffer: 65_536,
    }, (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout, stderr })));
    const connected = await client(true); assert.equal(connected.code, 0, connected.stderr + connected.stdout); assert.ok(connected.stdout.includes(runId));
    const missingIdentity = await client(false); assert.notEqual(missingIdentity.code, 0); assert.match(missingIdentity.stdout, /403/u, "gateway token alone cannot become enterprise owner");
    assert.equal(f.calls(), 2, "readback and refused calls do not dispatch another model");
  });
}
