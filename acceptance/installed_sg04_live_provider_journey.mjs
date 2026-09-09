/** Explicit live development evidence; never included in ordinary deterministic tests.
 * The fetch guard is an acceptance observer/spending boundary, NOT shipping cost enforcement.
 * Run with an owned KEEP_LIVE_WORKDIR, KEEP_INSTALLED_PACKAGE_ROOT and KEEP_OPENROUTER_ENV_FILE.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, cpSync, rmSync, openSync, writeSync, fsyncSync, closeSync, statSync, existsSync } from "node:fs";
import { join, isAbsolute } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

// Trusted acceptance command, outside the model-editable repository. Reuses the
// existing compiler/types; no install, download or generated replacement oracle.
if (process.argv[2] === "--dogfood-oracle") {
  const compiler = process.argv[3], typeRoots = process.argv[4];
  assert.ok(compiler && isAbsolute(compiler) && typeRoots && isAbsolute(typeRoots));
  const scratch = mkdtempSync(join(tmpdir(), "keep-dogfood-compiled-"));
  let code = 1;
  try {
    cpSync(join(process.cwd(), "package.json"), join(scratch, "package.json"));
    const compiled = spawnSync(process.execPath, ["--max-old-space-size=1536", compiler, "--target", "ES2022", "--module", "NodeNext", "--moduleResolution", "NodeNext", "--lib", "ES2022", "--strict", "--noUncheckedIndexedAccess", "--exactOptionalPropertyTypes", "--noImplicitOverride", "--noFallthroughCasesInSwitch", "--skipLibCheck", "--esModuleInterop", "--resolveJsonModule", "--typeRoots", typeRoots, "--rootDir", ".", "--outDir", join(scratch, "dist"), "test/cli_core.test.ts"], { cwd: process.cwd(), encoding: "utf8", timeout: 90_000, maxBuffer: 131_072 });
    if (compiled.status !== 0) { process.stdout.write(compiled.stdout ?? ""); process.stderr.write(compiled.stderr ?? ""); }
    else {
      const checked = spawnSync(process.execPath, ["--test", "--test-concurrency=1", "--test-reporter=tap", "--test-name-pattern=dogfood goal overview:", join(scratch, "dist/test/cli_core.test.js")], { cwd: process.cwd(), encoding: "utf8", timeout: 15_000, maxBuffer: 131_072 });
      process.stdout.write(checked.stdout ?? ""); process.stderr.write(checked.stderr ?? ""); code = checked.status ?? 1;
    }
  } finally { rmSync(scratch, { recursive: true, force: true }); }
  process.exit(code);
}

const model = "cohere/north-mini-code:free";
const endpoint = "https://openrouter.ai/api/v1/chat/completions";
const root = process.env.KEEP_LIVE_WORKDIR;
assert.ok(root && isAbsolute(root), "explicit owned KEEP_LIVE_WORKDIR required");
const receiptPath = join(root, "requests.jsonl");
const resumeStep = Number(process.env.KEEP_LIVE_RESUME_STEP ?? "1");
assert.ok(Number.isSafeInteger(resumeStep) && resumeStep >= 1 && resumeStep <= 2, "two explicit recovery observations, no unbounded retry loop");
const resumePrefix = resumeStep === 1 ? "resume" : "resume-2";
const digest = value => createHash("sha256").update(value).digest("hex");
function record(row) {
  const fd = openSync(receiptPath, "a", 0o600);
  try { writeSync(fd, JSON.stringify(row) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
}
const receipts = () => existsSync(receiptPath) ? readFileSync(receiptPath, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse) : [];

if (process.env.KEEP_LIVE_ROLE === "guard") {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    assert.equal(String(url), endpoint, "live guard refuses every other endpoint");
    assert.equal(process.env.KEEP_LIVE_ALLOW_INFERENCE, "1", "configuration/readback must not dispatch inference");
    assert.equal(init?.method, "POST"); assert.equal(typeof init.body, "string");
    const body = JSON.parse(init.body);
    assert.equal(body.model, model); assert.equal(body.stream, false);
    assert.ok(Number.isSafeInteger(body.max_tokens) && body.max_tokens > 0 && body.max_tokens <= 4000);
    assert.ok(Buffer.byteLength(init.body) <= 65_536);
    const attempt = receipts().filter(row => row.kind === "attempt").length + 1;
    assert.ok(attempt <= 4, "one shared four-HTTP-attempt allowance; no retry reset");
    body.provider = { ...(body.provider ?? {}), allow_fallbacks: false, max_price: { prompt: 0, completion: 0 }, data_collection: "deny" };
    const wire = JSON.stringify(body);
    record({ kind: "attempt", attempt, model, inputBytes: Buffer.byteLength(wire), inputSha256: digest(wire), maximumOutputTokens: body.max_tokens, maximumTokenPriceUsd: 0 });
    const response = await originalFetch(url, { ...init, body: wire, redirect: "error" });
    const result = await response.clone().json();
    record({ kind: "response", attempt, status: response.status, id: result.id ?? null, model: result.model ?? null, provider: result.provider ?? null, usage: result.usage ?? null, responseSha256: digest(JSON.stringify(result)), errorCode: result.error?.code ?? null,
      finishReason: result.choices?.[0]?.finish_reason ?? null, contentBytes: typeof result.choices?.[0]?.message?.content === "string" ? Buffer.byteLength(result.choices[0].message.content) : 0 });
    return response;
  };
} else {
  const resuming = process.env.KEEP_LIVE_TASK === "goal-overview-resume";
  if (!resuming) assert.equal(existsSync(receiptPath), false, "use a fresh explicitly owned workdir; preserve prior attempts");
  else assert.ok(existsSync(join(root, "goal-result.json")), "resume requires the original recorded goal");
  const installed = process.env.KEEP_INSTALLED_PACKAGE_ROOT;
  assert.ok(installed && isAbsolute(installed));
  const credentialPath = process.env.KEEP_OPENROUTER_ENV_FILE;
  assert.ok(credentialPath && isAbsolute(credentialPath));
  const credentialStat = statSync(credentialPath);
  assert.ok(credentialStat.isFile() && credentialStat.size <= 8192 && (credentialStat.mode & 0o077) === 0);
  // Parse one named scalar only; never execute/source the environment file or print its contents.
  const matches = [...readFileSync(credentialPath, "utf8").matchAll(/^\s*(?:export\s+)?OPENROUTER_API_KEY\s*=\s*(.*?)\s*$/gm)];
  assert.equal(matches.length, 1, "exactly one OpenRouter credential required");
  const raw = matches[0][1];
  const key = /^(["']).*\1$/u.test(raw) ? raw.slice(1, -1) : raw;
  assert.ok(/^[A-Za-z0-9_-]{20,256}$/u.test(key), "credential must be a plain bounded scalar");
  const catalogResponse = await fetch("https://openrouter.ai/api/v1/models", { signal: AbortSignal.timeout(10_000) });
  assert.equal(catalogResponse.status, 200);
  const selected = (await catalogResponse.json()).data.find(row => row.id === model);
  assert.ok(selected); assert.equal(Number(selected.pricing.prompt), 0); assert.equal(Number(selected.pricing.completion), 0);
  writeFileSync(join(root, resuming ? `catalog-${resumePrefix}.json` : "catalog.json"), JSON.stringify({ model, pricing: selected.pricing, checkedAt: new Date().toISOString() }, null, 2), { flag: "wx", mode: 0o600 });

  if (resuming) { await resumeKeepGoalOverview(installed, key); process.exit(0); }

  if (process.env.KEEP_LIVE_TASK === "goal-overview") {
    await runKeepGoalOverview(installed, key);
    process.exit(0);
  }

  const source = join(root, "source"), workspace = join(root, "workspaces"), profile = join(root, "provider.json");
  mkdirSync(join(source, "src"), { recursive: true }); mkdirSync(join(source, "config")); mkdirSync(workspace);
  const before = "export const retryLimit = 0;\n";
  writeFileSync(join(source, "src/retry.mjs"), before);
  writeFileSync(join(source, "config/runtime.json"), '{"configuredRetryLimit":137}\n');
  writeFileSync(join(source, "retry.test.mjs"), "import test from 'node:test'; import assert from 'node:assert/strict'; import {retryLimit} from './src/retry.mjs'; test('configured retry behavior', () => assert.equal(retryLimit, 137));\n");
  const testBytes = readFileSync(join(source, "retry.test.mjs"), "utf8");
  const safeEnv = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0" };
  const git = args => {
    const result = spawnSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args], { cwd: source, env: safeEnv, encoding: "utf8", timeout: 5000, maxBuffer: 262_144 });
    assert.equal(result.status, 0, result.stderr); return result.stdout.trim();
  };
  git(["init", "--quiet", "--initial-branch=main"]); git(["add", "."]);
  git(["-c", "user.name=Keep Fixture", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "synthetic live fixture"]);
  const revision = git(["rev-parse", "HEAD"]);
  const env = { ...safeEnv, KEEP_LIVE_WORKDIR: root, KEEP_LIVE_ROLE: "guard", KEEP_PROFILE: profile, KEEP_PROVIDER_API_KEY: key,
    KEEP_DATA_DIR: join(root, "state"), KEEP_REPOSITORY: source, KEEP_WORKSPACE_BASE: workspace, KEEP_REVISION: revision, KEEP_BASE_BRANCH: "main", KEEP_REPO_REF: "project",
    KEEP_TEST_COMMAND: process.execPath, KEEP_TEST_ARGS_JSON: '["--test","--test-reporter=tap","retry.test.mjs"]', KEEP_TEST_TIMEOUT_MS: "5000", KEEP_TEST_CPU_LIMIT_SEC: "2", KEEP_TEST_MAX_OUTPUT_BYTES: "16384", KEEP_PROJECT_POSTURE: "approval-required" };
  const invoke = (args, inference = false) => {
    const result = spawnSync(process.execPath, ["--import", fileURLToPath(import.meta.url), join(installed, "dist/src/main.js"), ...args], {
      cwd: root, env: { ...env, KEEP_LIVE_ALLOW_INFERENCE: inference ? "1" : "0" }, encoding: "utf8", timeout: 180_000, maxBuffer: 1_048_576,
    });
    // Only owned synthetic task output; defensive redaction also covers unexpected upstream errors.
    const sanitized = { status: result.status, signal: result.signal, stdout: result.stdout?.replaceAll(key, "[credential]"), stderr: result.stderr?.replaceAll(key, "[credential]") };
    writeFileSync(join(root, `${args[0]}-result.json`), JSON.stringify(sanitized, null, 2), { flag: "wx", mode: 0o600 });
    assert.equal(result.status, 0, JSON.stringify(sanitized)); return result.stdout;
  };
  invoke(["provider", "configure", `--profile=${profile}`, "--name=sg04-live-free", "--location=external", "--authority=owner", "--protocol=openai-compatible", "--endpoint=https://openrouter.ai/api", `--model=${model}`, "--purpose=software-development", "--region=global", "--credential=environment"]);
  const output = invoke(["project", "Fix retryLimit in src/retry.mjs to match the configured limit in config/runtime.json. Do not modify the configuration or tests."], true);
  const runId = /Run: ([^\s]+)/u.exec(output)?.[1]; assert.ok(runId, output);
  assert.match(output, /--proposal=[0-9a-f]{64}/u, "must reach a tested approval-required proposal");
  assert.equal(git(["rev-parse", "HEAD"]), revision); assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), before);
  assert.equal(readFileSync(join(workspace, "project/config/runtime.json"), "utf8"), '{"configuredRetryLimit":137}\n');
  assert.equal(readFileSync(join(workspace, "project/retry.test.mjs"), "utf8"), testBytes, "independent test oracle cannot be edited");
  const validation = spawnSync(process.execPath, ["--test", "retry.test.mjs"], { cwd: join(workspace, "project"), env: safeEnv, encoding: "utf8", timeout: 5000, maxBuffer: 16384 });
  assert.equal(validation.status, 0, validation.stdout + validation.stderr);
  const beforeReadback = receipts().filter(row => row.kind === "attempt").length;
  assert.ok(invoke(["projects"]).includes(runId));
  const rows = receipts(); assert.equal(rows.filter(row => row.kind === "attempt").length, beforeReadback);
  const responses = rows.filter(row => row.kind === "response"); assert.ok(responses.length > 0);
  assert.ok(responses.every(row => row.status === 200 && row.usage && Number.isFinite(row.usage.cost) && row.usage.cost === 0), "explicit zero provider-reported cost required");
  const summary = { status: "PASS", runId, requestedModel: model, responses, actualHttpAttempts: beforeReadback, originalSourceUnchanged: true, independentRepositoryTest: "PASS", readbackRequests: 0, providerReportedCostUsd: 0, evidenceLimit: "One synthetic owner/native configured CLI repair; not enterprise, broad coding ability, optional-agent interoperability or ticket qualification." };
  writeFileSync(join(root, "summary.json"), JSON.stringify(summary, null, 2), { flag: "wx", mode: 0o600 });
  process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
}

async function runKeepGoalOverview(installed, key) {
  const canonical = process.env.KEEP_CANONICAL_PRODUCT_ROOT;
  assert.ok(canonical && isAbsolute(canonical));
  const source = join(root, "source"), workspace = join(root, "workspaces"), profile = join(root, "provider.json");
  mkdirSync(source); mkdirSync(workspace);
  const safeEnv = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0" };
  const command = (executable, args, cwd = source, extra = {}) => spawnSync(executable, args, { cwd, env: safeEnv, encoding: "utf8", timeout: 120_000, maxBuffer: 1_048_576, ...extra });
  const git = args => { const result = command("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args]); assert.equal(result.status, 0, result.stderr); return result.stdout.trim(); };
  const baseResult = command("git", ["rev-parse", "HEAD"], canonical); assert.equal(baseResult.status, 0); const canonicalBase = baseResult.stdout.trim();
  // Canonical production source only, not archived competing implementations or
  // the 890MB historical/evidence tree. This is real Keep code, not an injected bug.
  const archived = command("git", ["archive", canonicalBase, "src", "test", "package.json", "tsconfig.json"], canonical, { encoding: "buffer", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(archived.status, 0);
  const extracted = command("tar", ["-xf", "-"], source, { input: archived.stdout }); assert.equal(extracted.status, 0, extracted.stderr);
  const oracle = readFileSync(join(canonical, "test/cli_core.test.ts"));
  writeFileSync(join(source, "test/cli_core.test.ts"), oracle);
  const compiler = join(canonical, "node_modules/typescript/bin/tsc"), typeRoots = join(canonical, "node_modules/@types");
  const oracleArgs = [fileURLToPath(import.meta.url), "--dogfood-oracle", compiler, typeRoots];
  const baseline = command(process.execPath, oracleArgs);
  writeFileSync(join(root, "baseline.json"), JSON.stringify({ status: baseline.status, stdout: baseline.stdout, stderr: baseline.stderr }), { flag: "wx", mode: 0o600 });
  assert.equal(baseline.status, 1, "the unchanged real product must fail the independent new behavior checks");
  assert.match(baseline.stdout, /# fail 2/u); assert.match(baseline.stdout, /# tests 2/u);
  git(["init", "--quiet", "--initial-branch=main"]); git(["add", "."]);
  git(["-c", "user.name=Keep Dogfood", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "actual Keep source with independent goal overview acceptance"]);
  const revision = git(["rev-parse", "HEAD"]);
  writeFileSync(join(root, "source-identity.json"), JSON.stringify({ canonicalBase, sourceRevision: revision, oracleSha256: digest(oracle), snapshotScope: "canonical src/test/package.json/tsconfig.json; only the predeclared independent test file differs" }), { flag: "wx", mode: 0o600 });
  const env = { ...safeEnv, KEEP_LIVE_WORKDIR: root, KEEP_LIVE_ROLE: "guard", KEEP_PROFILE: profile, KEEP_PROVIDER_API_KEY: key,
    KEEP_DATA_DIR: join(root, "state"), KEEP_REPOSITORY: source, KEEP_WORKSPACE_BASE: workspace, KEEP_REVISION: revision, KEEP_BASE_BRANCH: "main", KEEP_REPO_REF: "project",
    KEEP_TEST_COMMAND: process.execPath, KEEP_TEST_ARGS_JSON: JSON.stringify(oracleArgs), KEEP_TEST_TIMEOUT_MS: "110000", KEEP_TEST_CPU_LIMIT_SEC: "90", KEEP_TEST_MAX_OUTPUT_BYTES: "131072", KEEP_PROJECT_POSTURE: "approval-required" };
  let operation = 0;
  const invoke = (args, inference = false) => {
    const result = command(process.execPath, ["--import", fileURLToPath(import.meta.url), join(installed, "dist/src/main.js"), ...args], root, { env: { ...env, KEEP_LIVE_ALLOW_INFERENCE: inference ? "1" : "0" }, timeout: 240_000 });
    const sanitized = { status: result.status, signal: result.signal, stdout: result.stdout?.replaceAll(key, "[credential]"), stderr: result.stderr?.replaceAll(key, "[credential]") };
    writeFileSync(join(root, `operation-${++operation}.json`), JSON.stringify(sanitized), { flag: "wx", mode: 0o600 });
    assert.equal(result.status, 0, JSON.stringify(sanitized)); return result.stdout;
  };
  invoke(["provider", "configure", `--profile=${profile}`, "--name=keep-dogfood-free", "--location=external", "--authority=owner", "--protocol=openai-compatible", "--endpoint=https://openrouter.ai/api", `--model=${model}`, "--purpose=software-development", "--region=global", "--credential=environment"]);
  const taskGoal = "Implement persisted goal-work visibility in Keep projects listing. Change only src/gateway/http_gateway.ts and src/cli/cli_core.ts. In GET /projects (around line 724), for a non-quarantined session with native-goal-work-v1 document, consume app.projectRuntime.goalWork(id) and return goalWork metadata exactly {active, phase, totalTasks, acceptedTasks, deferredTasks, heldTasks, nextTaskId}. Derive factual counts from definition.tasks, accepted, selection.deferred/held and selected (null if absent). Ordinary projects have no goalWork summary. Do not return the objective, principal, claims or accepted evidence. Keep the existing tenant filtering and audit.view authorization. In cmdProjects (around line 385), render phase, active/paused, accepted/total tested-proposals, held and deferred counts and the command keep project goal show <id>. Never call this goal completion, fabricate a percentage, or offer project resume for a parent goal. Preserve ordinary project rendering and merge/veto hints. Read those two function bodies before proposing a change; tests named dogfood goal overview specify the behavior. Do not edit tests or any other file.";
  const task = (id, goal, extra = {}) => ({ id, goal, kind: "goal", dependsOn: [], requires: ["software-solver", "repository-tests"], due: "development", acceptance: "tested-proposal", ...extra });
  const definition = { objective: "Make real Keep goal work operable for its users. Preserve all full-build and coequal owner/enterprise obligations. This bounded operation proposes one implementation only; no source merge, dependency addition, public action, test-oracle mutation or relaxation of authority/acceptance is allowed.", maxTaskStarts: 1,
    tasks: [task("release-matrix", "Qualify all supported platform goal views", { kind: "hardening", due: "release" }), task("overview", taskGoal), task("platform-check", "Independently exercise the resulting view on supported platforms", { dependsOn: ["overview"], requires: ["qualified-platform-host"] })] };
  const spec = join(root, "goal.json"); writeFileSync(spec, JSON.stringify(definition), { flag: "wx", mode: 0o600 });
  const created = JSON.parse(invoke(["project", "goal", "create", `--spec=${spec}`, "--idempotency-key=keep-real-goal-overview-001", "--activate"]));
  assert.equal(created.selection.selected, "overview"); assert.equal(receipts().length, 0);
  invoke(["project", "goal", "advance", created.projectId], true);
  const view = JSON.parse(invoke(["project", "goal", "advance", created.projectId]));
  writeFileSync(join(root, "goal-result.json"), JSON.stringify(view), { flag: "wx", mode: 0o600 });
  assert.ok(view.document.accepted.overview, JSON.stringify(view.tasks));
  assert.equal(view.document.startsUsed, 1); assert.deepEqual(view.document.definition, definition);
  const candidate = join(workspace, "project");
  assert.equal(git(["rev-parse", "HEAD"]), revision); assert.equal(git(["status", "--porcelain"]), "");
  assert.ok(readFileSync(join(candidate, "test/cli_core.test.ts")).equals(oracle), "independent oracle must remain unchanged");
  const changes = command("git", ["diff", "--name-only"], candidate); assert.equal(changes.status, 0);
  assert.deepEqual(changes.stdout.trim().split("\n").sort(), ["src/cli/cli_core.ts", "src/gateway/http_gateway.ts"]);
  const validation = command(process.execPath, oracleArgs, candidate);
  writeFileSync(join(root, "independent-result.json"), JSON.stringify({ status: validation.status, stdout: validation.stdout, stderr: validation.stderr }), { flag: "wx", mode: 0o600 });
  assert.equal(validation.status, 0, validation.stdout + validation.stderr);
  const responses = receipts().filter(row => row.kind === "response");
  assert.ok(responses.length > 0 && responses.every(row => row.status === 200 && row.usage?.cost === 0));
  const summary = { status: "PASS", canonicalBase, sourceRevision: revision, goalProjectId: created.projectId, task: view.document.accepted.overview, requestedModel: model, responses, actualHttpAttempts: receipts().filter(row => row.kind === "attempt").length, providerReportedCostUsd: 0, originalSourceUnchanged: true, independentOracleUnchanged: true, candidatePaths: changes.stdout.trim().split("\n"), independentRepositoryTest: "PASS", evidenceLimit: "One real Keep operator-view implementation through installed goal/native model execution; independently checked proposal, not canonical merge, enterprise live-model or whole product qualification." };
  writeFileSync(join(root, "summary.json"), JSON.stringify(summary, null, 2), { flag: "wx", mode: 0o600 });
  process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
}

async function resumeKeepGoalOverview(installed, key) {
  const canonical = process.env.KEEP_CANONICAL_PRODUCT_ROOT, evidenceId = process.env.KEEP_LIVE_CORRECTION_EVIDENCE;
  assert.ok(canonical && isAbsolute(canonical)); assert.match(evidenceId ?? "", /^[0-9a-f]{64}$/u);
  const original = JSON.parse(readFileSync(join(root, "goal-result.json"), "utf8")), identity = JSON.parse(readFileSync(join(root, "source-identity.json"), "utf8"));
  assert.equal(original.document.startsUsed, 1); assert.deepEqual(original.document.accepted, {});
  const claim = original.document.claims.overview;
  const { CryptoShredKeyStore } = await import(join(installed, "dist/src/keystore/keystore.js"));
  const { FileWrappedKeyPersistence } = await import(join(installed, "dist/src/keystore/file_wrapped_key_persistence.js"));
  const { ProjectRegistry } = await import(join(installed, "dist/src/session/project_registry.js"));
  const { FileProjectRecordStore } = await import(join(installed, "dist/src/session/project_record_store.js"));
  const { FileProjectCheckpointStore } = await import(join(installed, "dist/src/autonomy/project_checkpoint_store.js"));
  const projectRoot = join(root, "state/projects");
  const registry = new ProjectRegistry(new CryptoShredKeyStore(new FileWrappedKeyPersistence({ masterKeyPath: join(projectRoot, "master.key"), wrappedKeysPath: join(projectRoot, "wrapped-keys.json") })), new FileProjectRecordStore(join(projectRoot, "records.json")));
  const checkpoints = new FileProjectCheckpointStore(join(projectRoot, "checkpoints"), { encrypt: (id, value) => registry.namespace(id).encrypt(value), decrypt: (id, value) => registry.namespace(id).decrypt(value) });
  const before = checkpoints.load(claim.jobId);
  assert.equal(before?.wait?.capability, resumeStep === 1 ? "rework-strategy:ticket" : "solve-recovery:ready");
  assert.equal(before.reworkCount, 3); assert.equal(before.stepsRemaining, resumeStep === 1 ? 86 : 84);
  if (resumeStep === 2) {
    const diagnostic = readFileSync(join(root, "provider-generation-diagnostic.json"));
    assert.equal(digest(diagnostic), evidenceId);
    const observed = JSON.parse(diagnostic);
    assert.equal(observed.data.finish_reason, "error"); assert.equal(observed.data.total_cost, 0);
    assert.equal(observed.data.id, receipts().find(row => row.kind === "response")?.id);
    assert.equal(receipts().filter(row => row.kind === "attempt").length, 1);
  }
  const source = join(root, "source"), workspace = join(root, "workspaces"), candidate = join(workspace, "project");
  const safeEnv = { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0" };
  const oracleArgs = [fileURLToPath(import.meta.url), "--dogfood-oracle", join(canonical, "node_modules/typescript/bin/tsc"), join(canonical, "node_modules/@types")];
  const env = { ...safeEnv, KEEP_LIVE_WORKDIR: root, KEEP_LIVE_ROLE: "guard", KEEP_PROFILE: join(root, "provider.json"), KEEP_PROVIDER_API_KEY: key,
    KEEP_DATA_DIR: join(root, "state"), KEEP_REPOSITORY: source, KEEP_WORKSPACE_BASE: workspace, KEEP_REVISION: identity.sourceRevision, KEEP_BASE_BRANCH: "main", KEEP_REPO_REF: "project",
    KEEP_TEST_COMMAND: process.execPath, KEEP_TEST_ARGS_JSON: JSON.stringify(oracleArgs), KEEP_TEST_TIMEOUT_MS: "110000", KEEP_TEST_CPU_LIMIT_SEC: "90", KEEP_TEST_MAX_OUTPUT_BYTES: "131072", KEEP_PROJECT_POSTURE: "approval-required" };
  let sequence = 0;
  const invoke = (args, inference = false) => {
    const result = spawnSync(process.execPath, ["--import", fileURLToPath(import.meta.url), join(installed, "dist/src/main.js"), ...args], { cwd: root, env: { ...env, KEEP_LIVE_ALLOW_INFERENCE: inference ? "1" : "0" }, encoding: "utf8", timeout: 240_000, maxBuffer: 1_048_576 });
    const sanitized = { status: result.status, signal: result.signal, stdout: result.stdout?.replaceAll(key, "[credential]"), stderr: result.stderr?.replaceAll(key, "[credential]") };
    writeFileSync(join(root, `${resumePrefix}-operation-${++sequence}.json`), JSON.stringify(sanitized), { flag: "wx", mode: 0o600 });
    assert.equal(result.status, 0, JSON.stringify(sanitized)); return result.stdout;
  };
  // Same run/goal/claims and non-replenished budgets. No new project or submission.
  invoke(["project", "resume", claim.jobId, `--capability=${before.wait.capability}`, `--evidence=${evidenceId}`], true);
  const after = checkpoints.load(claim.jobId);
  assert.equal(after.runId, before.runId); assert.equal(after.projectId, before.projectId);
  assert.ok(after.reworkCount >= before.reworkCount && after.stepsRemaining < before.stepsRemaining, "same-run recovery must not replenish budgets");
  writeFileSync(join(root, `${resumePrefix}-budget-observation.json`), JSON.stringify({ runId: after.runId, before: { revision: before.revision, reworkCount: before.reworkCount, stepsRemaining: before.stepsRemaining }, after: { revision: after.revision, reworkCount: after.reworkCount, stepsRemaining: after.stepsRemaining, status: after.status, stage: after.stage } }), { flag: "wx", mode: 0o600 });
  const view = JSON.parse(invoke(["project", "goal", "advance", original.projectId]));
  writeFileSync(join(root, `${resumePrefix}d-goal-result.json`), JSON.stringify(view), { flag: "wx", mode: 0o600 });
  assert.deepEqual(view.document.claims, original.document.claims); assert.equal(view.document.startsUsed, 1);
  assert.ok(view.document.accepted.overview, JSON.stringify(view.tasks));
  const git = (dir, args) => { const r = spawnSync("git", ["-c", "core.hooksPath=/dev/null", ...args], { cwd: dir, env: safeEnv, encoding: "utf8", timeout: 10_000, maxBuffer: 262_144 }); assert.equal(r.status, 0, r.stderr); return r.stdout.trim(); };
  assert.equal(git(source, ["rev-parse", "HEAD"]), identity.sourceRevision); assert.equal(git(source, ["status", "--porcelain"]), "");
  assert.equal(digest(readFileSync(join(candidate, "test/cli_core.test.ts"))), identity.oracleSha256);
  const paths = git(candidate, ["diff", "--name-only"]).split("\n").sort(); assert.deepEqual(paths, ["src/cli/cli_core.ts", "src/gateway/http_gateway.ts"]);
  const validation = spawnSync(process.execPath, oracleArgs, { cwd: candidate, env: safeEnv, encoding: "utf8", timeout: 120_000, maxBuffer: 131_072 });
  writeFileSync(join(root, `independent-${resumePrefix}d-result.json`), JSON.stringify({ status: validation.status, stdout: validation.stdout, stderr: validation.stderr }), { flag: "wx", mode: 0o600 });
  assert.equal(validation.status, 0, validation.stdout + validation.stderr);
  const responses = receipts().filter(row => row.kind === "response"); assert.ok(responses.length > 0 && responses.every(row => row.status === 200 && row.usage?.cost === 0));
  const summary = { status: "PASS", canonicalBase: identity.canonicalBase, sourceRevision: identity.sourceRevision, originalRunId: claim.jobId, goalProjectId: original.projectId, task: view.document.accepted.overview, originalTaskStartsUsed: 1, originalClaimsUnchanged: true, actualHttpAttempts: receipts().filter(row => row.kind === "attempt").length, responses, providerReportedCostUsd: 0, originalSourceUnchanged: true, independentOracleUnchanged: true, candidatePaths: paths, independentRepositoryTest: "PASS", correctionEvidence: evidenceId, evidenceLimit: "Real Keep goal overview proposal after same-run infrastructure recovery; no canonical integration, enterprise live-model or whole product qualification claim." };
  writeFileSync(join(root, `${resumePrefix}d-summary.json`), JSON.stringify(summary, null, 2), { flag: "wx", mode: 0o600 }); process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
}
