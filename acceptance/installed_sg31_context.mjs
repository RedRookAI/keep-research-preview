/** Installed native coding + cited memory, with injected model responses; not live-model qualification. */
import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createSign, generateKeyPairSync } from "node:crypto";
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createServer } from "node:http";

const installed = process.env.KEEP_INSTALLED_PACKAGE_ROOT;
if (!installed) throw new Error("KEEP_INSTALLED_PACKAGE_ROOT required; no source substitute");
const keep = await import(pathToFileURL(join(installed, "dist/src/index.js")).href);
// Deployment/bootstrap helpers are packaged modules, not public barrel exports.
const { remoteProviderIdentityDigest } = await import(pathToFileURL(join(installed, "dist/src/gateway/provider_descriptor.js")).href);
const { captureRuntimeContract } = await import(pathToFileURL(join(installed, "dist/src/cli/runtime_config.js")).href);
const { configuredSemanticEncoder } = await import(pathToFileURL(join(installed, "dist/src/cli/encoder_profile.js")).href);
const here = fileURLToPath(import.meta.url), token = "c".repeat(64);
const issuer = "https://sg31-context.example", audience = "sg31-context";
const content = "The amber orchard retry policy requires retryLimit to be seven.";
const semanticContent = "Raven convention: allowed repetitions are seven.";
const adaptiveContent = "Archive: orchard. " + ".".repeat(1400) + " Allowed repetitions: seven.";
const goal = "Correct retryLimit in src/retry.mjs according to the retained retry policy.";
const billingGoal = "Correct the invoice retry limit in billing.ts according to the retained policy and pending task.";
const billingTask = "Pending task: correct retryLimit in billing.ts using the amber orchard retry policy; preserve the repository tests and unrelated behavior.";
const memoryFreeGoal = "Correct the invoice retry limit in billing.ts to seven; preserve unrelated behavior and repository tests.";
const baseEnv = { PATH: process.env.PATH ?? "/usr/bin:/bin", KEEP_INSTALLED_PACKAGE_ROOT: installed,
  GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0" };
function git(cwd, args) {
  const result = spawnSync("git", ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", ...args],
    { cwd, env: baseEnv, encoding: "utf8", timeout: 5000, maxBuffer: 262144 });
  assert.equal(result.status, 0, result.stderr); return result.stdout.trim();
}

// Independent of editable repository tests and model-authored goal checks. This
// authored integration fixture is not a frontier benchmark or malicious-code proof.
async function sourceOnlyOutcome(projectDir) {
  const { SandboxedCommandRunner } = await import(pathToFileURL(join(installed, "dist/src/solve/sandboxed_runner.js")).href);
  const { ProcessIsolationAdapter } = await import(pathToFileURL(join(installed, "dist/src/infra/process_isolation.js")).href);
  const adapter = new ProcessIsolationAdapter(); let raw;
  const runner = new SandboxedCommandRunner({ command: process.execPath, args: ["--input-type=module", "-e",
    "import assert from 'node:assert/strict'; const m=await import('./billing.ts'); assert.deepEqual(Object.keys(m),['retryLimit']); assert.equal(m.retryLimit,7); process.stdout.write('SOURCE_ONLY_OUTCOME_OK\\n');"],
    projectDir, adapter: { run: async (...args) => { raw = await adapter.run(...args); return raw; } },
    timeoutMs: 5000, cpuLimitSec: 2, maxOutputBytes: 16384, envAllowlist: [], namespaceJail: true, allowNet: false,
    maxFileSizeBytes: 1048576, maxProcesses: 64, maxOpenFiles: 128 });
  const result = await runner.run(".");
  return { accepted: raw?.code === 0 && !raw?.timedOut && !result.runnerError && raw?.stdout === "SOURCE_ONLY_OUTCOME_OK\n", code: raw?.code ?? null };
}

if (process.argv[2] === "installed-cli-namespace") {
  // Host fixture establishes read-only authority boundaries only. All runtime
  // configuration, signature verification and composition remain in packaged main.
  const authority = process.env.KEEP_ENCODER_TEST_AUTHORITY;
  assert.ok(authority && process.env.KEEP_ENCODER_PARENT_MOUNT_NS);
  assert.notEqual(readlinkSync("/proc/self/ns/mnt"), process.env.KEEP_ENCODER_PARENT_MOUNT_NS);
  for (const path of [authority, installed]) for (const args of [["--bind", path, path], ["-o", "remount,bind,ro", path]]) {
    const mounted = spawnSync("mount", args, { encoding: "utf8", timeout: 5000 }); assert.equal(mounted.status, 0, mounted.stderr);
  }
  const entry = join(installed, "dist/src/main.js");
  process.argv = [process.execPath, entry, ...process.argv.slice(3)];
  await import(pathToFileURL(entry).href);
} else if (process.argv[2] === "encoder") {
  const encoder = createServer(async (req, res) => {
    try {
      assert.equal(req.url, "/v1/embeddings"); assert.equal(req.headers.authorization, "Bearer encoder-fixture-only");
      const chunks = []; let bytes = 0;
      for await (const chunk of req) { bytes += chunk.length; assert.ok(bytes <= 65536); chunks.push(chunk); }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      assert.equal(body.model, "separate-encoder-fixture"); assert.ok(Array.isArray(body.input));
      const role = body.input[0]?.startsWith("QUERY: ") ? "query" : "document";
      assert.ok(body.input.every(text => typeof text === "string" && text.startsWith(role === "query" ? "QUERY: " : "DOCUMENT: ")));
      process.send({ observation: "semantic-embedding", role, windows: body.input.length });
      res.end(JSON.stringify({ model: body.model, data: body.input.map((text, index) => ({ index, embedding: role === "query" || text.includes("Raven") ? [1, 0] : [0, 1] })).reverse() }));
    } catch (error) { res.destroy(error); }
  });
  await new Promise(resolve => encoder.listen(0, "127.0.0.1", resolve));
  process.on("message", message => { if (message === "stop") { encoder.closeAllConnections(); encoder.close(() => process.disconnect()); } });
  process.send({ origin: `http://127.0.0.1:${encoder.address().port}` });
} else if (process.argv[2] === "server") {
  const [mode, root, encodedKey, endpoint, dispatch, memoryMode] = process.argv.slice(3);
  const memoryFree = ["memory-free", "authority-withdrawn"].includes(memoryMode);
    const adaptive = ["adaptive", "targeted"].includes(memoryMode);
  const mappings = [
    { subject: "alice", role: "maintainer", id: "alice", tenant: "alpha" },
    { subject: "teammate", role: "maintainer", id: "teammate", tenant: "alpha" },
    { subject: "foreign", role: "maintainer", id: "foreign", tenant: "beta" },
  ];
  let organizationBoot;
  const descriptor = { mode: "openai-compatible", baseUrl: endpoint, model: "installed-cited-memory-fixture", apiKey: "owned-loopback-fixture" };
  if (endpoint && mode !== "owner") {
    const authority = process.env.KEEP_UPGRADE_AUTHORITY;
    if (!authority || !["upgrade", "source-only"].includes(memoryMode) || !process.env.KEEP_UPGRADE_PARENT_MOUNT_NS
      || readlinkSync("/proc/self/ns/mnt") === process.env.KEEP_UPGRADE_PARENT_MOUNT_NS) throw new Error("organization upgrade fixture requires its private mount namespace and release authority");
    for (const path of [authority, installed]) for (const args of [["--bind", path, path], ["-o", "remount,bind,ro", path]]) {
      const mounted = spawnSync("mount", args, { encoding: "utf8", timeout: 5000 }); assert.equal(mounted.status, 0, mounted.stderr);
    }
    const { readReleaseBootBundle, readReleaseTrustRoot } = await import(pathToFileURL(join(installed, "dist/src/graph/release_bundle.js")).href);
    const { verifyInstalledReleaseAtBoot } = await import(pathToFileURL(join(installed, "dist/src/graph/release_boot.js")).href);
    const decoded = readReleaseBootBundle(join(authority, "release.cbor"), readReleaseTrustRoot(join(authority, "trust.cbor")));
    organizationBoot = verifyInstalledReleaseAtBoot({ installedRoot: installed, ...decoded,
      providerDescriptorDigest: remoteProviderIdentityDigest(descriptor), trustedNowMs: () => BigInt(Date.now()),
      scannerEnginePath: join(authority, "scanner/tools/effect_sweep.mjs") });
  }
  const identity = mode === "enterprise" ? {
    provider: new keep.OidcJwksProvider({ issuer, audience, jwks: { keys: [JSON.parse(encodedKey)] } }),
    registry: new keep.PrincipalRegistry(mappings), sessions: new keep.SessionStore(),
  } : undefined;
  let calls = 0;
  const retainedContent = memoryMode === "semantic" ? semanticContent : memoryMode === "outcome" ? content.replace("seven", "nine") : content;
  const source = join(root, "source");
  const encoderConfig = memoryMode !== "semantic" ? undefined : captureRuntimeContract({ KEEP_PROVIDER: "local", KEEP_ENCODER_PROFILE: join(root, "encoder.json"), KEEP_ENCODER_API_KEY: "encoder-fixture-only" }, { cwd: root });
  const app = keep.composeKeep({ dataDir: join(root, "state"), ...(identity ? { identity } : {}),
    ...(encoderConfig === undefined ? {} : {
      semanticEncoder: configuredSemanticEncoder(encoderConfig.encoder, "encoder-fixture-only"),
      residency: encoderConfig.residency,
    }),
    ...(endpoint ? {
      ...(organizationBoot ? { remoteProvider: descriptor, verifiedRelease: organizationBoot } : { ownerProvider: descriptor }),
      remoteProcessing: { purpose: "software-development", region: "local" },
      residency: { allowedPurposes: ["software-development"], allowedRegions: ["local"], egressAllowlist: ["127.0.0.1"] },
      projectRuntimeOwnerId: "context-worker-" + process.pid, projectRuntimePaused: dispatch === "paused",
    } : { developmentProvider: { name: "installed-cited-memory-fixture", isLocal: true,
      embed: async texts => texts.map(() => [1, 0]), generate: async request => {
        calls++;
        if (memoryMode === "authority-withdrawn") process.send({ observation: "native-dispatch", calls });
        if (memoryFree) {
          assert.ok(request.prompt.includes(memoryFreeGoal));
          assert.ok(!request.prompt.includes("QUOTED MEMORY DATA ("));
        }
        if (["billing", "mixed"].includes(memoryMode)) assert.ok(request.prompt.includes(billingTask), "both edit and check consume the actual retained pending task");
        if (request.hints?.taskRole === "goal_test") {
          assert.equal(calls, adaptive ? 4 : 2);
          if (!memoryFree) assert.ok(request.prompt.includes(adaptive ? "Allowed repetitions: seven." : retainedContent));
          assert.ok(!request.prompt.includes('"replace":"retryLimit = 7"'), "check author does not receive the proposed replacement");
          process.send({ observation: "goal-check", calls });
          if (["mixed", "payment"].includes(memoryMode)) {
            assert.ok(request.prompt.includes(memoryMode === "payment" ? "Pay the invoice." : billingGoal + " Then pay the invoice."));
            return { text: JSON.stringify({ unavailable: true }), model: "installed-cited-memory-fixture", tokensIn: 1, tokensOut: 1 };
          }
          return { text: JSON.stringify({ body: `assert.equal((await import('./${memoryMode === "billing" || memoryFree ? "billing.ts" : "src/retry.mjs"}')).retryLimit, ${memoryMode === "outcome" ? 9 : 7});` }),
            model: "installed-cited-memory-fixture", tokensIn: 1, tokensOut: 1 };
        }
        if (memoryMode === "outcome" && calls === 3) {
          assert.match(request.prompt, /goal: requested outcome/u);
          process.send({ observation: "repair-refusal", calls });
          return { text: JSON.stringify({ rationale: "No further edit proposed in this finite adverse fixture", edits: [] }),
            model: "installed-cited-memory-fixture", tokensIn: 1, tokensOut: 1 };
        }
        if (adaptive && calls < 3) {
          const rows = request.prompt.split("\n").filter(line => line.startsWith('{"itemId":')).map(JSON.parse);
          assert.ok(!request.prompt.includes("Allowed repetitions: seven."), "follow-up must recover evidence absent from earlier delivery");
          let action;
          if (calls === 1) { assert.equal(rows.length, 0); action = { action: "search_memory", query: "orchard" }; }
          else {
            assert.equal(rows.length, 1); assert.equal(rows[0].span.startByte, 0); assert.equal(rows[0].span.endByte, 1024);
            action = memoryMode === "targeted" ? { action: "search_memory", query: "allowed repetitions", itemIds: [rows[0].itemId] }
              : { action: "read_memory", itemId: rows[0].itemId, startByte: rows[0].span.endByte, byteLength: 1024 };
          }
          return { text: JSON.stringify(action), model: "installed-cited-memory-fixture", tokensIn: 1, tokensOut: 1 };
        }
        assert.equal(calls, adaptive ? 3 : 1, "bounded native planning calls, no hidden retries");
        if (!memoryFree) {
          assert.ok(request.prompt.includes(adaptive ? "Allowed repetitions: seven." : retainedContent), "actual planner must consume exact retained text");
          assert.match(request.prompt, /"itemId":"[^"]+"/u);
          assert.match(request.prompt, /"authority":"none"/u);
        }
        if (!adaptive) assert.equal(request.prompt.split("QUOTED MEMORY DATA (").length - 1, memoryFree ? 0 : 1);
        else for (const row of request.prompt.split("\n").filter(line => line.startsWith('{"itemId":')).map(JSON.parse)) {
          assert.equal(row.text, Buffer.from(adaptiveContent).subarray(row.span.startByte, row.span.endByte).toString("utf8"));
        }
        process.send({ observation: "native-context", calls, cited: !memoryFree,
          derived: request.prompt.includes('"view":"derived"'), quotedItems: request.prompt.split("\n").filter(line => line.startsWith('{"itemId":')).map(line => JSON.parse(line).itemId) });
        if (memoryMode === "authority-withdrawn") {
          if (mode === "enterprise") mappings[0].role = "viewer";
          else {
            // Owned fixture fault injection: invalidate the original immutable
            // command version while its first model request is in flight.
            const running = app.projectRuntime.jobs(new Set([project.id])).filter(row => row.state === "running");
            assert.equal(running.length, 1);
            const session = app.projectManager.session(project.id), name = "job-command-" + running[0].id;
            const prior = session.resolveDocumentVersioned(name); assert.equal(prior.revision, 1);
            session.putDocumentVersioned(name, prior.value, prior.revision);
          }
        }
        return { text: JSON.stringify({ action: "plan", rationale: "Apply the retained retry policy", edits: [
          { file: memoryFree || ["preparation", "billing", "mixed", "payment"].includes(memoryMode) ? "billing.ts" : "src/retry.mjs", search: "retryLimit = 0", replace: "retryLimit = 7", intent: "Correct retry policy" },
        ] }), model: "installed-cited-memory-fixture", tokensIn: 1, tokensOut: 1 };
      } } }),
    repositoryMaterialization: { sourceDir: source, workspaceBase: join(root, "workspaces"), repoRef: "project", commit: git(source, ["rev-parse", "HEAD"]), baseBranch: "main" },
    ...(memoryMode === "preparation" ? {} : { testCommand: { command: process.execPath, args: ["--test", "--test-reporter=tap", "retry.test.mjs"], timeoutMs: 5000, cpuLimitSec: 2, maxOutputBytes: 16384 } }),
  });
  let project = app.projectManager.list().find(row => row.name === "Installed cited context");
  if (!project) project = app.projectManager.create({ name: "Installed cited context", ...(identity ? { tenant: "alpha" } : {}) });
  const server = await keep.startGatewayServer(app, { port: 0, token, ...(identity ? { identity } : {}) });
  process.on("message", async message => { if (message === "stop") { await server.close(); await app.spine.seal(); process.disconnect(); } });
  process.send({ origin: server.origin, projectId: project.id, pid: process.pid });
} else {
  test("installed embedding transport: durable aggregate batches and uncertain restart", async t => {
    const root = mkdtempSync(join(tmpdir(), "keep-installed-embedding-budget-"));
    const limits = { maxAttempts: 3, maxElapsedMs: 15000, embedding: { requests: 16, inputBytes: 8192, windows: 32 } };
    const make = () => new keep.RecoveryBudget(new keep.Spine(new keep.FileSpineStore(join(root, "application")),
      new keep.FileSystemLock(join(root, "application/.locks")), new keep.SchemaRegistry()), "installed-embedding-job", limits);
    let calls = 0, uncertain = false;
    const reservations = [];
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", chunk => { body += chunk; });
      req.on("end", () => { void (async () => {
        calls++;
        reservations.push((await make().snapshot()).embedding.reserved);
        if (uncertain) { req.socket.destroy(); return; }
        if (calls === 1) { res.writeHead(429, { "retry-after": "0" }); res.end(); return; }
        const { input } = JSON.parse(body);
        res.end(JSON.stringify({ data: input.map((text, index) => ({ index, embedding: [text.length, 1] })).reverse() }));
      })().catch(error => res.destroy(error)); });
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
    const app = keep.composeKeep({ dataDir: join(root, "application"),
      ownerProvider: { mode: "openai-compatible", baseUrl: `http://127.0.0.1:${server.address().port}`, model: "fixture-embedding", apiKey: "fixture-only" },
      remoteProcessing: { purpose: "chat", region: "eu" },
      embeddingProcessing: { query: { purpose: "memory-query-embedding", region: "eu" }, document: { purpose: "memory-document-embedding", region: "eu" } },
      residency: { allowedRegions: ["eu"], egressAllowlist: ["127.0.0.1"], allowedPurposes: ["chat", "memory-query-embedding", "memory-document-embedding"] },
    });
    const provider = app.gateway, budget = new keep.RecoveryBudget(app.spine, "installed-embedding-job", limits), permit = await budget.reserve();
    const result = await provider.embedBounded(["one", "二", "three"], { role: "document", maxBatchWindows: 2, reserve: plan => budget.reserveEmbeddingWork(permit, plan) });
    assert.deepEqual(result.vectors, [[3, 1], [1, 1], [5, 1]]);
    assert.equal(result.reserved.requests, 8); assert.equal(result.dispatched.requests, 3);
    for (const reservation of reservations) assert.deepEqual(reservation, result.reserved);
    await budget.finish(permit);
    uncertain = true;
    const next = await budget.reserve();
    await assert.rejects(provider.embedBounded(["uncertain"], { role: "query", reserve: plan => budget.reserveEmbeddingWork(next, plan) }));
    await budget.finish(next);
    assert.equal(calls, 4, "unknown transport must not consume a blind retry");
    const probe = `import * as keep from ${JSON.stringify(pathToFileURL(join(installed, "dist/src/index.js")).href)};
      const b = new keep.RecoveryBudget(new keep.Spine(new keep.FileSpineStore(${JSON.stringify(join(root, "application"))}),
        new keep.FileSystemLock(${JSON.stringify(join(root, "application/.locks"))}), new keep.SchemaRegistry()), "installed-embedding-job", ${JSON.stringify(limits)});
      let refused = false; try { await b.reserve(); } catch { refused = true; }
      console.log(JSON.stringify({ refused, state: await b.snapshot() }));`;
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", probe], { env: baseEnv, encoding: "utf8", timeout: 5000 });
    assert.equal(child.status, 0, child.stderr);
    const restarted = JSON.parse(child.stdout);
    assert.equal(restarted.refused, true); assert.equal(restarted.state.status, "reconciliation");
    assert.equal(restarted.state.embedding.reserved.requests, 12);
    assert.ok(restarted.state.embedding.pendingWorkId);
    assert.ok(app.spine.replay().some(e => e.type === "effect.intent"));
    t.diagnostic(JSON.stringify({ root, installedPublicApi: true, composedOwnerGateway: true, durableBrokerWitness: true, calls, restarted, ordinarySemanticConsumer: false,
      providerAdmissionQualification: false, learnedModelQualityQualification: false }));
  });
  for (const mode of process.env.KEEP_UPGRADE_RELEASE_FIXTURE_MODULE ? ["owner", "enterprise"] : ["owner"])
  test(`installed ${mode} encoder-profile: ordinary worker and separate HTTP routes repair from retained memory`, { timeout: mode === "enterprise" ? 180000 : 90000 }, async t => {
    const investigation = process.env.KEEP_INSTALLED_MEMORY_INVESTIGATION === "1";
    const repetitionContext = process.env.KEEP_INSTALLED_REPETITION_CONTEXT === "1";
    const expectedChats = repetitionContext ? 1 : investigation ? 4 : 2, expectedDocumentWindows = investigation ? 25 : 13;
    const root = mkdtempSync(join(tmpdir(), "keep-installed-encoder-profile-")), source = join(root, "source"), state = join(root, "state");
    // Explicit host policy and per-write intent retain exact private source.
    // This does not grant disclosure; both encoder roles still transform it.
    const privateEmail = "retained.contact@example.test", privatePhone = "415-555-0100";
    const retainedText = repetitionContext ? "Retry policy value = 7." : semanticContent;
    const privateMemory = retainedText + " Contact " + privatePhone + ". Email " + privateEmail + ".";
    const routedGoal = process.env.KEEP_INSTALLED_RETAINED_HISTORY_ROUTING === "1"
      ? "Correct retryLimit in src/retry.mjs from retained project history and the latest policy." : goal;
    const privateGoal = routedGoal + " Contact " + privatePhone + ". Email " + privateEmail + ".";
    let documentSurrogate, documentEmailSurrogate, retainedUseUntil, retainedAfter, retainedBefore, focusedViewId;
    const companionFact = "Contact retention companion: do not reuse revoked history.";
    const entry = join(installed, "dist/src/main.js");
    mkdirSync(join(source, "src"), { recursive: true }); mkdirSync(join(root, "workspaces"));
    writeFileSync(join(source, "src/retry.mjs"), "export const retryLimit = 0;\n");
    writeFileSync(join(source, "retry.test.mjs"), "import test from 'node:test'; import assert from 'node:assert/strict'; import {retryLimit} from './src/retry.mjs'; test('policy',()=>assert.equal(retryLimit,7));\n");
    git(source, ["init", "--quiet", "--initial-branch=main"]); git(source, ["add", "."]);
    git(source, ["-c", "user.name=Keep Fixture", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "fixture"]);
    const calls = [], errors = []; let chats = 0;
    const model = createServer(async (request, response) => {
      try {
        assert.equal(request.method, "POST");
        let size = 0; const chunks = [];
        for await (const chunk of request) { size += chunk.length; assert.ok(size <= 262144); chunks.push(chunk); }
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")); response.setHeader("content-type", "application/json");
        if (request.url === "/encoder/v1/embeddings") {
          assert.equal(request.headers.authorization, "Bearer encoder-fixture-only"); assert.equal(body.model, "separate-encoder-fixture");
          assert.deepEqual(body.provider, {zdr:true,data_collection:"deny",allow_fallbacks:false,only:["AdmittedEncoder"]}, "encoder routing must reach the actual HTTP body");
          const role = body.input.every(text => text.startsWith("QUERY: ")) ? "query" : "document";
          assert.ok(body.input.every(text => text.startsWith(role === "query" ? "QUERY: " : "DOCUMENT: ")));
          calls.push({ role, windows: body.input.length }); assert.ok(calls.length <= 2);
          assert.ok(!JSON.stringify(body.input).includes(privateEmail), "private email cannot cross the encoder HTTP boundary");
          assert.ok(!JSON.stringify(body.input).includes(privatePhone), "retained private phone cannot cross the encoder HTTP boundary");
          const privateText = body.input.find(text => text.includes("Contact")); assert.ok(privateText, "query and retained document exercise actual transformation");
          const surrogate = privateText.match(/⟦phone#[^⟧]+⟧/u)?.[0]; assert.ok(surrogate);
          const emailSurrogate = privateText.match(/⟦email#[^⟧]+⟧/u)?.[0]; assert.ok(emailSurrogate, "exact retained email is transformed at disclosure, not destroyed during storage");
          if (role === "document") { documentSurrogate = surrogate; documentEmailSurrogate = emailSurrogate; }
          else {
            assert.equal(surrogate, documentSurrogate, "same phone has compatible query/document representation");
            assert.equal(emailSurrogate, documentEmailSurrogate, "same email has compatible query/document representation");
          }
          response.end(JSON.stringify({ data: body.input.map((text, index) => ({ index, embedding: role === "query" || text.includes("Raven") ? [1, 0] : [0, 1] })) })); return;
        }
        assert.equal(request.url, "/chat/v1/chat/completions"); assert.equal(request.headers.authorization, "Bearer chat-fixture-only"); assert.equal(body.model, "chat-fixture");
        const prompt = body.messages[0].content; chats++; assert.ok(chats <= expectedChats + (focusedViewId ? 1 : 0)); assert.ok(prompt.includes(retainedText));
        assert.ok(prompt.includes("QUOTED MEMORY DATA"), "both model roles must receive the cited memory block");
        const quoted = !repetitionContext && chats === expectedChats ? JSON.parse(prompt.split("UNTRUSTED INPUT JSON\n")[1]).memory : prompt;
        assert.ok(quoted.includes('"authority":"none"'), "citation authority is none inside the role's actual wire framing");
        const memoryRows = quoted.split("\n").filter(line => line.startsWith('{"itemId":')).map(line => JSON.parse(line));
        const retainedQuote = memoryRows.find(row => row.text.includes(retainedText)); assert.ok(retainedQuote);
        if (!focusedViewId) {
          assert.equal(retainedQuote.useUntil, new Date(retainedUseUntil).toISOString(), "real custody deadline remains usable at actual chat HTTP");
          assert.equal(retainedQuote.validFrom, retainedQuote.recordedAt);
          const recorded = Date.parse(retainedQuote.recordedAt);
          assert.ok(recorded >= retainedAfter && recorded <= retainedBefore, "record time remains bound to actual storage, not the source's claimed event time");
        }
        assert.ok(!quoted.includes(privateEmail) && !quoted.includes(privatePhone), "formatting timestamps never exempts private source text");
        if (focusedViewId) {
          const view = memoryRows.find(row => row.itemId === focusedViewId);
          assert.ok(view && view.view === "derived" && view.text.includes(companionFact), "restarted ordinary worker consumes the nonprefix exact derived excerpt at chat HTTP");
          assert.equal(view.authority, "none");
          // The preceding job already proves coding. This additional dispatch
          // proves derived-context delivery, not learned understanding of it.
          response.end(JSON.stringify({ model: body.model, choices: [{ message: { content: JSON.stringify({ action: "plan", rationale: "Inspect retained context; no further edit", edits: [] }) }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } }));
          return;
        }
        if (repetitionContext) {
          assert.ok(memoryRows.some(row => row.text.includes("Retry policy value = 9.")), "exact repetitions cannot hide a distinct matching assertion at actual model HTTP");
          // Delivery proof only: this fixture declines to choose a disputed value.
          // It is not a real-model conflict-resolution or safe-abstention claim.
          response.end(JSON.stringify({ model: body.model, choices: [{ message: { content: JSON.stringify({ action: "plan", rationale: "Unresolved competing assertions; no edit proposed", edits: [] }) }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } }));
          return;
        }
        const anchors = investigation && chats <= 2 ? [...new Set(memoryRows.map(row => row.itemId))].slice(0, 4) : [];
        if (investigation && chats <= 2) assert.equal(anchors.length, 4);
        const value = investigation && chats <= 2 ? { action: "search_memory", query: chats === 1 ? "retry policy retained" : "retry policy archive", itemIds: anchors }
          : chats === expectedChats ? { body: "assert.equal((await import('./src/retry.mjs')).retryLimit, 7);" }
          : { action: "plan", rationale: "Apply the retained Raven convention", edits: [{ file: "src/retry.mjs", search: "retryLimit = 0", replace: "retryLimit = 7", intent: "Correct retry policy" }] };
        response.end(JSON.stringify({ model: body.model, choices: [{ message: { content: JSON.stringify(value) }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } }));
      } catch (error) { errors.push(String(error)); response.writeHead(400).end(JSON.stringify({ error: "owned encoder profile fixture refused request" })); }
    });
    await new Promise(resolve => model.listen(0, "127.0.0.1", resolve));
    t.after(async () => { model.closeAllConnections(); await new Promise(resolve => model.close(resolve)); });
    const origin = "http://127.0.0.1:" + model.address().port, profilePath = join(root, "encoder.json");
    const authority = join(root, "authority");
    const spawnCli = (args, env, namespace = false) => spawn(namespace ? "unshare" : process.execPath,
      namespace ? ["-Urm", process.execPath, here, "installed-cli-namespace", ...args] : [entry, ...args],
      { env: { ...env, ...(namespace ? { KEEP_INSTALLED_PACKAGE_ROOT: installed, KEEP_ENCODER_TEST_AUTHORITY: authority, KEEP_ENCODER_PARENT_MOUNT_NS: readlinkSync("/proc/self/ns/mnt") } : {}) }, stdio: ["ignore", "pipe", "pipe"] });
    async function command(args, env, namespace = false) {
      const child = spawnCli(args, env, namespace);
      let stdout = "", stderr = ""; child.stdout.on("data", bytes => { stdout += bytes; }); child.stderr.on("data", bytes => { stderr += bytes; });
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("owned CLI command timed out")); }, namespace ? 45000 : 15000);
        child.once("error", error => { clearTimeout(timer); reject(error); });
        child.once("exit", code => { clearTimeout(timer); code === 0 ? resolve(stdout) : reject(new Error("owned CLI refused: " + stderr + stdout)); });
      });
    }
    let orgEnv = {}, signAssertion;
    if (mode === "enterprise") {
      const support = await import(pathToFileURL(process.env.KEEP_UPGRADE_RELEASE_FIXTURE_MODULE).href), canonical = process.env.KEEP_UPGRADE_CANONICAL_ROOT;
      assert.ok(canonical); const scanner = join(authority, "scanner");
      mkdirSync(join(scanner, "tools"), { recursive: true }); mkdirSync(join(scanner, "node_modules"));
      cpSync(join(canonical, "tools/effect_sweep.mjs"), join(scanner, "tools/effect_sweep.mjs"));
      cpSync(join(canonical, "node_modules/typescript"), join(scanner, "node_modules/typescript"), { recursive: true });
      for (const [role, model] of [["chat", "chat-fixture"], ["encoder", "separate-encoder-fixture"]]) {
        const descriptor = { mode: "openai-compatible", baseUrl: origin + "/" + role, model, apiKey: "not-part-of-descriptor-digest" };
        const release = support.createSignedInstalledReleaseFixture(installed, remoteProviderIdentityDigest(descriptor), BigInt(Date.now()), join(scanner, "tools/effect_sweep.mjs"));
        writeFileSync(join(authority, role + ".cbor"), release.bundle, { mode: 0o600 }); writeFileSync(join(authority, role + "-trust.cbor"), release.trustRoot, { mode: 0o600 });
      }
      const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const protectedJson = (name, value) => writeFileSync(join(authority, name + ".json"), JSON.stringify(value), { mode: 0o600 });
      protectedJson("jwks", { keys: [{ ...publicKey.export({ format: "jwk" }), kid: "encoder-org", alg: "RS256", use: "sig" }] });
      protectedJson("principals", { schema: "keep.principal-roster/v1", tenantId: "alpha", principals: [{ id: "alice", subject: "alice", role: "maintainer" }] });
      protectedJson("delegation", { schema: "keep.delegation-policy/v1", tenantId: "alpha", parents: ["alice"] });
      const residency = { schema: "keep.residency-policy/v1", tenantId: "alpha", allowedPurposes: ["software-development", "memory-query", "memory-document"], allowedRegions: ["local"], egressAllowlist: ["127.0.0.1"] };
      protectedJson("residency", residency); protectedJson("residency-deny-document", { ...residency, allowedPurposes: ["software-development", "memory-query"] });
      orgEnv = { KEEP_TENANT_ID: "alpha", KEEP_IDENTITY_ISSUER: issuer, KEEP_IDENTITY_AUDIENCE: audience, KEEP_IDENTITY_JWKS: join(authority, "jwks.json"), KEEP_PRINCIPAL_ROSTER: join(authority, "principals.json"), KEEP_DELEGATION_POLICY: join(authority, "delegation.json"), KEEP_RESIDENCY_POLICY: join(authority, "residency.json"), KEEP_SCANNER_ENGINE: join(scanner, "tools/effect_sweep.mjs"), KEEP_AUDIT_SCOPE: "tenant", KEEP_RELEASE_BUNDLE: join(authority, "chat.cbor"), KEEP_RELEASE_TRUST_ROOT: join(authority, "chat-trust.cbor") };
      signAssertion = subject => {
        const head = Buffer.from(JSON.stringify({ alg: "RS256", kid: "encoder-org", typ: "JWT" })).toString("base64url");
        const body = Buffer.from(JSON.stringify({ sub: subject, iss: issuer, aud: audience, exp: Math.floor(Date.now() / 1000) + 180 })).toString("base64url");
        const signature = createSign("RSA-SHA256").update(head + "." + body).end().sign(privateKey).toString("base64url"); return head + "." + body + "." + signature;
      };
    }
    // External routing contract exercised by a loopback fixture, not an Internet/provider qualification.
    await command(["encoder", "configure", "--profile=" + profilePath, "--name=ordinary-encoder", "--authority=" + (mode === "enterprise" ? "organization" : "owner"), "--location=external", "--endpoint=" + origin + "/encoder", "--model=separate-encoder-fixture", "--revision=fixture-not-learned", "--dimension=2", "--query-prefix=QUERY: ", "--document-prefix=DOCUMENT: ", "--query-purpose=memory-query", "--document-purpose=memory-document", "--region=local", "--requests=32", "--input-bytes=131072", "--windows=256", "--credential=environment",
      "--providers=AdmittedEncoder", ...(mode === "enterprise" ? ["--release-bundle=" + join(authority, "encoder.cbor"), "--release-trust-root=" + join(authority, "encoder-trust.cbor")] : [])], baseEnv);
    const retentionPath = join(root, "retention.json");
    await command(["memory-retention", "configure", "--profile=" + retentionPath, "--authority=" + (mode === "enterprise" ? "organization" : "owner"), "--purposes=project-context", "--max-use-ms=600000"], baseEnv);
    const env = { ...baseEnv, ...orgEnv, KEEP_MEMORY_RETENTION_PROFILE: retentionPath, KEEP_PROVIDER: "openai-compatible", KEEP_PROVIDER_AUTHORITY: mode === "enterprise" ? "organization" : "owner", KEEP_PROVIDER_LOCATION: "local", KEEP_PROVIDER_BASE_URL: origin + "/chat", KEEP_PROVIDER_MODEL: "chat-fixture", KEEP_PROVIDER_API_KEY: "chat-fixture-only", KEEP_REMOTE_PROCESSING_PURPOSE: "software-development", KEEP_REMOTE_PROCESSING_REGION: "local",
      KEEP_ENCODER_PROFILE: profilePath, KEEP_ENCODER_API_KEY: "encoder-fixture-only", KEEP_REPOSITORY: source, KEEP_WORKSPACE_BASE: join(root, "workspaces"), KEEP_REVISION: git(source, ["rev-parse", "HEAD"]), KEEP_REPO_REF: "project", KEEP_TEST_COMMAND: process.execPath, KEEP_TEST_ARGS_JSON: JSON.stringify(["--test", "--test-reporter=tap", "retry.test.mjs"]), KEEP_TEST_TIMEOUT_MS: "5000", KEEP_TEST_CPU_LIMIT_SEC: "2", KEEP_TEST_MAX_OUTPUT_BYTES: "16384", KEEP_DATA_DIR: state };
    if (mode === "enterprise") {
      const wrong = JSON.parse(readFileSync(profilePath, "utf8")); wrong.release = { bundlePath: orgEnv.KEEP_RELEASE_BUNDLE, trustRootPath: orgEnv.KEEP_RELEASE_TRUST_ROOT };
      const wrongPath = join(root, "wrong-encoder.json"), refusedState = join(root, "must-not-exist"); writeFileSync(wrongPath, JSON.stringify(wrong), { mode: 0o600 });
      await assert.rejects(() => command(["serve", "--gateway", "--project-worker", "--port=0"], { ...env, KEEP_ENCODER_PROFILE: wrongPath, KEEP_DATA_DIR: refusedState }, true), /runtime authority\/provider artifacts are not exactly the ones bound by the release closure/u);
      assert.equal(existsSync(refusedState), false, "wrong encoder release must be refused before mutable app state"); assert.equal(chats + calls.length, 0);
    }
    const doctor = await command(["doctor"], env, mode === "enterprise"); assert.match(doctor, /READY: installed project/u); assert.match(doctor, /encoder-release-admission/u); assert.match(doctor, /private-memory-retention/u); assert.equal(chats + calls.length, 0);
    let worker, workerOrigin, bearer, session;
    let workerEnv = mode === "enterprise" && !repetitionContext ? { ...env, KEEP_RESIDENCY_POLICY: join(authority, "residency-deny-document.json") } : env;
    const authHeaders = () => ({ authorization: "Bearer " + bearer, ...(session ? { "x-keep-session": readFileSync(session, "utf8").trim() } : {}) });
    const start = async () => {
      session = undefined;
      worker = spawnCli(["serve", "--gateway", "--project-worker", "--port=0"], workerEnv, mode === "enterprise");
      let stdout = "", stderr = ""; worker.stderr.on("data", bytes => { stderr += bytes; });
      workerOrigin = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("owned worker readiness timed out: " + stderr)), mode === "enterprise" ? 45000 : 10000);
        worker.stdout.on("data", bytes => { stdout += bytes; const match = /URL:\s+(http:\/\/127\.0\.0\.1:\d+)/u.exec(stdout); if (match) { clearTimeout(timer); resolve(match[1]); } });
        worker.once("error", error => { clearTimeout(timer); reject(error); });
        worker.once("exit", code => { clearTimeout(timer); reject(new Error("owned worker exited before readiness: " + code + ": " + stderr)); });
      });
      bearer = readFileSync(join(state, "gateway-token"), "utf8").trim();
      if (mode === "enterprise") {
        const login = subject => fetch(workerOrigin + "/auth/session", { method: "POST", headers: { authorization: "Bearer " + bearer, "content-type": "application/json" }, body: JSON.stringify({ assertion: signAssertion(subject) }), signal: AbortSignal.timeout(5000) });
        const denied = await login("foreign"); assert.notEqual(denied.status, 200); await denied.text();
        const response = await login("alice"); assert.equal(response.status, 200); const value = await response.json();
        session = join(root, "alice.session"); writeFileSync(session, value.session + "\n", { mode: 0o600 });
      }
    };
    const stop = async () => {
      if (!worker || worker.exitCode !== null) return;
      const child = worker; worker = undefined;
      const exited = new Promise((resolve, reject) => { const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("owned native worker did not stop")); }, 5000); child.once("exit", () => { clearTimeout(timer); resolve(); }); });
      try {
        const status = await fetch(workerOrigin + "/worker/status", { headers: authHeaders(), signal: AbortSignal.timeout(3000) });
        assert.equal(status.status, 200); const value = await status.json();
        const stopped = await fetch(workerOrigin + "/worker/stop", { method: "POST", headers: { ...authHeaders(), "content-type": "application/json" }, body: JSON.stringify({ workerId: value.workerId }), signal: AbortSignal.timeout(3000) });
        assert.equal(stopped.status, 202);
      } catch (error) { child.kill("SIGTERM"); await exited; throw error; }
      await exited;
    };
    t.after(stop); await start();
    const cli = args => command(args, { ...baseEnv, KEEP_GATEWAY_URL: workerOrigin, KEEP_GATEWAY_TOKEN: bearer, ...(session ? { KEEP_GATEWAY_SESSION_FILE: session } : {}) });
    await cli(["memory", "init", "--scope=user", "--retain"]);
    retainedAfter = Date.now(); retainedUseUntil = retainedAfter + 300000;
    const retained = await cli(["memory", "store", privateMemory, "--scope=user", "--durable", "--kind=decision", "--operation-id=retained-raven", "--private-purpose=project-context", "--use-until=" + retainedUseUntil]);
    retainedBefore = Date.now();
    assert.match(retained, /exact-private-source/u);
    const retainedId = retained.match(/Stored\. id=(\S+)/u)?.[1]; assert.ok(retainedId, retained);
    assert.ok((await cli(["memory", "review", retainedId, "--scope=user", "--durable"])).includes(privateEmail));
    if (repetitionContext) {
      for (let i = 0; i < 8; i++) await cli(["memory", "store", i === 7 ? privateMemory.replace("value = 7", "value = 9") : privateMemory, "--scope=user", "--durable", "--kind=decision", "--operation-id=copy-" + i, "--private-purpose=project-context", "--use-until=" + retainedUseUntil]);
      retainedBefore = Date.now();
    } else for (let i = 0; i < 12; i++) await cli(["memory", "store", "Correct retryLimit src retry retained policy: unrelated archive. ".repeat(investigation ? 18 : 6), "--scope=user", "--durable", "--kind=decision", "--operation-id=distractor-" + i]);
    assert.equal(chats + calls.length, 0, "configuration and source-only storage do not grant model egress");
    const runMemoryJob = async (semantic = !repetitionContext) => {
      const dispatchesBefore = chats + calls.length;
      const result = await cli(["project", privateGoal, "--posture=approval-required", "--memory=user", "--memory-processing=configured-provider", ...(semantic ? ["--memory-semantic=configured-encoder"] : [])]);
      const runId = /Run: ([^\s]+)/u.exec(result)?.[1]; assert.ok(runId, result);
      const observe = async () => {
        const response = await fetch(workerOrigin + "/project?runId=" + encodeURIComponent(runId), { headers: authHeaders(), signal: AbortSignal.timeout(5000) });
        assert.equal(response.status, 200); return response.json();
      };
      const initial = await observe();
      assert.equal(initial.project.status, "waiting-approval"); assert.equal(initial.project.stage, "understand");
      assert.equal(chats + calls.length, dispatchesBefore, "approval-required understanding cannot dispatch before its decision");
      await cli(["project", "resume", runId, "--approve=" + initial.project.wait.decisionId]);
      return { result, snapshot: await observe() };
    };
    if (mode === "enterprise" && !repetitionContext) {
      const denied = await runMemoryJob();
      writeFileSync(join(root, "denied-purpose.json"), JSON.stringify(denied, null, 2), { mode: 0o600 });
      assert.equal(denied.snapshot.project.artifacts.implement.solve.solved, false);
      assert.match(denied.snapshot.project.artifacts.implement.solve.gaveUpReason, /selected task memory unavailable: encoder-policy/u);
      assert.equal(chats + calls.length, 0, "an encoder profile cannot widen the organization's document-processing policy");
    }
    await stop(); workerEnv = env; await start();
    const { result, snapshot } = await runMemoryJob();
    writeFileSync(join(root, "outcome.json"), JSON.stringify({ result, snapshot, chats, calls, errors }, null, 2), { mode: 0o600 });
    if (repetitionContext) {
      assert.deepEqual(errors, []); assert.equal(chats, 1); assert.deepEqual(calls, []);
      assert.equal(snapshot.project.artifacts.implement.solve.solved, false);
      assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), "export const retryLimit = 0;\n");
      if (existsSync(join(root, "workspaces/project/src/retry.mjs"))) assert.equal(readFileSync(join(root, "workspaces/project/src/retry.mjs"), "utf8"), "export const retryLimit = 0;\n");
      t.diagnostic(JSON.stringify({ root, mode, ordinaryInstalledMainAndWorker: true, repeatedCopies: 8, competingAssertionsDeliveredAtChatHttp: true,
        privateTextTransformed: true, modelDirectedResolution: false, noEditProposedOrApplied: true, newDependencies: 0 }));
      return;
    }
    if (process.env.KEEP_INSTALLED_RETAINED_HISTORY_ROUTING === "1") {
      assert.equal(snapshot.project.artifacts.research.decision.required, false, "selected retained history is routed to task evidence, not external tri-research");
      assert.equal(snapshot.project.goal, privateGoal, "routing does not rewrite the operator's task");
    }
    assert.deepEqual(errors, []); assert.equal(chats, expectedChats); assert.deepEqual(calls, [{ role: "document", windows: expectedDocumentWindows }, { role: "query", windows: 1 }]);
    assert.equal(snapshot.project.artifacts.implement.solve.solved, true, JSON.stringify(snapshot.project.artifacts.implement.solve));
    assert.equal(snapshot.project.artifacts.implement.solve.recovery.planningCalls, expectedChats);
    assert.equal(snapshot.project.artifacts.implement.solve.recovery.embedding.reserved.requests, 8);
    assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), "export const retryLimit = 0;\n");
    const companionText = "Historical archive. " + "界".repeat(650) + " " + companionFact;
    const companion = await cli(["memory", "store", companionText, "--scope=user", "--durable"]);
    const companionId = companion.match(/Stored\. id=(\S+)/u)?.[1]; assert.ok(companionId);
    const derivedArgs = ["memory", "consolidate", retainedId, companionId, "--scope=user", "--query=Contact retention", "--operation-id=focused-private-view"];
    const derived = await cli(derivedArgs);
    assert.match(derived, /Partial task-focused excerpts/u);
    const derivedId = derived.match(/originals retained\. id=(\S+)/u)?.[1]; assert.ok(derivedId);
    assert.ok((await cli(derivedArgs)).includes(derivedId), "same query and operation replay the same view");
    const reviewedView = await cli(["memory", "review", derivedId, "--scope=user", "--durable"]);
    assert.ok(reviewedView.includes(companionFact) && reviewedView.includes(privateEmail));
    assert.ok((await cli(["memory", "review", companionId, "--scope=user", "--durable"])).includes(companionText), "consolidation preserves the complete Unicode original");
    await stop(); await start(); focusedViewId = derivedId;
    const focusedJob = await runMemoryJob(false);
    writeFileSync(join(root, "focused-outcome.json"), JSON.stringify({ ...focusedJob, chats, calls, errors }, null, 2), { mode: 0o600 });
    assert.deepEqual(errors, []); assert.equal(chats, expectedChats + 1); assert.equal(calls.length, 2);
    assert.equal(focusedJob.snapshot.project.artifacts.implement.solve.solved, false, "delivery-only fixture does not claim another coding success");
    const recallArgs = ["memory", "recall", "Contact", "--scope=user", "--durable", "--operation-id=private-recall"];
    assert.ok((await cli(recallArgs)).includes(privateEmail));
    await assert.rejects(() => cli(["memory", "correct", retainedId, "Contact replacement@example.test.", "--scope=user", "--durable"]));
    await assert.rejects(() => cli(["memory", "correct", retainedId, "Contact AKIA1234567890ABCDEF", "--scope=user", "--durable", "--private-purpose=project-context"]));
    assert.ok((await cli(["memory", "review", retainedId, "--scope=user", "--durable"])).includes(privateEmail), "failed corrections preserve the exact source");
    await stop(); workerEnv = { ...env }; delete workerEnv.KEEP_MEMORY_RETENTION_PROFILE; await start();
    assert.ok(!(await cli(recallArgs)).includes(privateEmail), "old recall receipt cannot replay private text after policy withdrawal");
    for (const id of [retainedId, derivedId]) {
      const review = await cli(["memory", "review", id, "--scope=user", "--durable"]);
      assert.ok(!review.includes(privateEmail)); assert.match(review, /Content withheld/u);
    }
    assert.ok(!(await cli(["memory", "list", "--scope=user", "--durable", "--include-retired"])).includes(retainedId));
    await assert.rejects(() => cli(["memory", "consolidate", retainedId, companionId, "--scope=user"]));
    await stop(); workerEnv = env; await start();
    const corrected = await cli(["memory", "correct", retainedId, "Contact replacement@example.test.", "--scope=user", "--durable", "--private-purpose=project-context"]);
    const successor = corrected.match(/new=(\S+)/u)?.[1]; assert.ok(successor);
    assert.ok((await cli(["memory", "review", successor, "--scope=user", "--durable"])).includes("replacement@example.test"));
    await cli(["memory", "erase", successor, "--scope=user"]);
    assert.ok(!(await cli(["memory", "recall", "Contact", "--scope=user", "--durable"])).includes("replacement@example.test"));
    assert.equal(chats, expectedChats + 1); assert.equal(calls.length, 2, "private memory lifecycle never invokes a model; only the explicit follow-up job adds one chat");
    await stop();
    t.diagnostic(JSON.stringify({ root, mode, ordinaryInstalledMainAndWorker: true, noHostComposition: true, independentCredentialsAndRoutes: true, sourceOnlyRestart: true, chats, calls, nativeReservedRequests: 8, actualRepositoryTest: true, learnedModelQuality: false,
      compatiblePrivateRepresentations: true, privatePhoneAbsentAtEncoderHttp: true, exactPrivateEmailRetainedAndTransformedAtEncoderHttp: true, explicitHostRetentionPolicyAndCommandPurpose: true, encoderRoutingAtHttp: true,
      privatePolicyWithdrawalAndRecallReplayWithheld: true, privateDerivedSourceClosureWithheld: true, safePrivateCorrectionAndErasure: true,
      taskFocusedUnicodeTailExcerptAtNativeChatHttp: true, focusedViewReplayAndRestart: true, originalSourcePreserved: true, focusedDeliveryOnlyChatCalls: 1,
      boundedNativeMemoryInvestigation: investigation, expectedPlanningCalls: expectedChats, learnedInvestigationQuality: false,
      actualCustodyUtcTimesAtChatHttp: true, postPrivacyQuotedRowsParseableInFixture: true, privateTextStillTransformedAtChatHttp: true,
      enterpriseSecondAdmission: mode === "enterprise", syntheticReleaseAuthority: mode === "enterprise", swappedChatAdmissionRefusedBeforeState: mode === "enterprise", documentPolicyDeniedBeforeHttp: mode === "enterprise", authenticatedTenantUserScope: mode === "enterprise" }));
  });
  for (const journey of [...(process.env.KEEP_PREPARATION_PACKAGE_ROOT ? ["upgrade"] : []), "source-only"])
  for (const mode of process.env.KEEP_UPGRADE_RELEASE_FIXTURE_MODULE ? ["owner", "enterprise"] : ["owner"])
  test(journey === "upgrade" ? `installed ${mode} prepared upgrade: ordinary CLI preserves command and budget` : `installed ${mode} source-only: chat-only memory restart and native outcome`, { timeout: 120000 }, async t => {
    const sourceOnly = journey === "source-only";
    const oldInstalled = sourceOnly ? installed : process.env.KEEP_PREPARATION_PACKAGE_ROOT;
    const root = mkdtempSync(join(tmpdir(), "keep-prepared-upgrade-")), source = join(root, "source");
    mkdirSync(source); mkdirSync(join(root, "workspaces"));
    writeFileSync(join(source, "billing.ts"), "export const retryLimit = 0;\n");
    writeFileSync(join(source, "retry.test.mjs"), "import test from 'node:test'; import assert from 'node:assert/strict'; import {retryLimit} from './billing.ts'; test('policy',()=>" + (sourceOnly ? "assert.equal(typeof retryLimit,'number')" : "assert.equal(retryLimit,7)") + ");\n");
    git(source, ["init", "--quiet", "--initial-branch=main"]); git(source, ["add", "."]);
    git(source, ["-c", "user.name=Keep Fixture", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "fixture"]);
    let calls = 0, embeddings = 0; const errors = [];
    const provider = createServer(async (request, response) => {
      try {
        assert.equal(request.headers.authorization, "Bearer owned-loopback-fixture"); assert.equal(request.method, "POST");
        const chunks = []; let bytes = 0;
        for await (const chunk of request) { bytes += chunk.length; assert.ok(bytes <= 262144); chunks.push(chunk); }
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")); response.setHeader("content-type", "application/json");
        if (request.url === "/v1/embeddings") {
          embeddings++; assert.ok(!sourceOnly, "chat-only fixture refuses every embedding request"); assert.ok(embeddings <= 8);
          response.end(JSON.stringify({ data: body.input.map((_, index) => ({ index, embedding: [1, 0] })) })); return;
        }
        assert.equal(request.url, "/v1/chat/completions"); calls++; assert.ok(calls <= (sourceOnly ? 2 : 3));
        const prompt = body.messages[0].content; assert.ok(prompt.includes(content)); assert.ok(prompt.includes(billingTask));
        let value;
        if (calls === (sourceOnly ? 2 : 3)) {
          assert.match(prompt, /Prepare a goal-specific behavioral regression test/u);
          value = { body: "assert.equal((await import('./billing.ts')).retryLimit, 7);" };
        } else {
          assert.ok(prompt.includes("retryLimit = 0"), "fresh original source, not archived prepared bytes");
          value = { action: "plan", rationale: "Bounded code proposal", edits: [
            { file: "billing.ts", search: "retryLimit = 0", replace: "retryLimit = " + (!sourceOnly && calls === 1 ? 9 : 7), intent: "Correct retry policy" },
          ] };
        }
        response.end(JSON.stringify({ model: body.model, choices: [{ message: { content: JSON.stringify(value) }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } }));
      } catch (error) { errors.push(String(error)); response.writeHead(400).end(JSON.stringify({ error: "owned upgrade fixture rejected request" })); }
    });
    await new Promise(resolve => provider.listen(0, "127.0.0.1", resolve));
    t.after(async () => { provider.closeAllConnections(); await new Promise(resolve => provider.close(resolve)); });
    const endpoint = "http://127.0.0.1:" + provider.address().port;
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = { ...publicKey.export({ format: "jwk" }), kid: "sg31", alg: "RS256", use: "sig" };
    const authorities = new Map();
    if (mode === "enterprise") {
      const support = await import(pathToFileURL(process.env.KEEP_UPGRADE_RELEASE_FIXTURE_MODULE).href);
      const canonical = process.env.KEEP_UPGRADE_CANONICAL_ROOT; assert.ok(canonical);
      for (const [label, packageRoot] of sourceOnly ? [["current", installed]] : [["old", oldInstalled], ["current", installed]]) {
        const authority = join(root, "authority", label), scanner = join(authority, "scanner");
        mkdirSync(join(scanner, "tools"), { recursive: true }); mkdirSync(join(scanner, "node_modules"));
        cpSync(join(canonical, "tools/effect_sweep.mjs"), join(scanner, "tools/effect_sweep.mjs"));
        cpSync(join(canonical, "node_modules/typescript"), join(scanner, "node_modules/typescript"), { recursive: true });
        const descriptor = { mode: "openai-compatible", baseUrl: endpoint, model: "installed-cited-memory-fixture", apiKey: "owned-loopback-fixture" };
        const release = support.createSignedInstalledReleaseFixture(packageRoot, remoteProviderIdentityDigest(descriptor), BigInt(Date.now()), join(scanner, "tools/effect_sweep.mjs"));
        writeFileSync(join(authority, "release.cbor"), release.bundle, { mode: 0o600 }); writeFileSync(join(authority, "trust.cbor"), release.trustRoot, { mode: 0o600 });
        authorities.set(packageRoot, authority);
      }
    }
    let child, ready, selected = oldInstalled, session;
    const start = async packageRoot => {
      selected = packageRoot;
      const args = [here, "server", mode, root, JSON.stringify(jwk), endpoint, "running", journey];
      child = spawn(mode === "enterprise" ? "unshare" : process.execPath, mode === "enterprise" ? ["-Urm", process.execPath, ...args] : args, {
        env: { ...baseEnv, KEEP_INSTALLED_PACKAGE_ROOT: selected, ...(mode === "enterprise" ? {
          KEEP_UPGRADE_AUTHORITY: authorities.get(packageRoot), KEEP_UPGRADE_PARENT_MOUNT_NS: readlinkSync("/proc/self/ns/mnt"),
        } : {}) }, stdio: ["ignore", "pipe", "pipe", "ipc"],
      });
      let stderr = ""; child.stderr.on("data", bytes => { stderr = (stderr + bytes).slice(-16384); }); child.stdout.resume();
      ready = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("upgrade readiness timeout: " + stderr)), mode === "enterprise" ? 45000 : 8000);
        child.once("message", message => { clearTimeout(timer); resolve(message); });
        child.once("error", error => { clearTimeout(timer); reject(error); });
        child.once("exit", code => { clearTimeout(timer); reject(new Error("upgrade server exited " + code + ": " + stderr)); });
      });
      if (mode === "enterprise") {
        const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "sg31", typ: "JWT" })).toString("base64url");
        const payload = Buffer.from(JSON.stringify({ sub: "alice", iss: issuer, aud: audience, exp: Math.floor(Date.now() / 1000) + 180 })).toString("base64url");
        const signature = createSign("RSA-SHA256").update(`${header}.${payload}`).end().sign(privateKey).toString("base64url");
        const response = await fetch(ready.origin + "/auth/session", { method: "POST", headers: { authorization: "Bearer " + token, "content-type": "application/json" }, body: JSON.stringify({ assertion: `${header}.${payload}.${signature}` }), signal: AbortSignal.timeout(5000) });
        assert.equal(response.status, 200); const value = (await response.json()).session;
        session = join(root, "upgrade.session"); writeFileSync(session, value + "\n", { mode: 0o600 });
      }
    };
    const stop = async () => {
      if (!child || child.exitCode !== null || child.signalCode !== null) return;
      const owned = child;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { owned.kill("SIGKILL"); reject(new Error("owned upgrade server did not stop")); }, 5000);
        owned.once("exit", () => { clearTimeout(timer); resolve(); }); owned.send("stop");
      });
    };
    t.after(stop);
    const cli = args => new Promise((resolve, reject) => {
      const command = spawn(process.execPath, [join(selected, "dist/src/main.js"), ...args], {
        env: { ...baseEnv, KEEP_GATEWAY_URL: ready.origin, KEEP_GATEWAY_TOKEN: token, ...(session ? { KEEP_GATEWAY_SESSION_FILE: session } : {}) }, stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "", stderr = ""; command.stdout.on("data", bytes => { stdout += bytes; }); command.stderr.on("data", bytes => { stderr += bytes; });
      const timer = setTimeout(() => { command.kill("SIGKILL"); reject(new Error("owned upgrade CLI timed out")); }, 10000);
      command.once("error", error => { clearTimeout(timer); reject(error); });
      command.once("close", code => { clearTimeout(timer); if (code !== 0) reject(new Error(stdout + stderr)); else resolve(stdout); });
    });
    const snapshot = async runId => {
      const response = await fetch(ready.origin + "/project?runId=" + encodeURIComponent(runId), {
        headers: { authorization: "Bearer " + token, ...(session ? { "x-keep-session": readFileSync(session, "utf8").trim() } : {}) }, signal: AbortSignal.timeout(5000),
      });
      assert.equal(response.status, 200); return response.json();
    };
    await start(oldInstalled);
    const memoryScope = mode === "owner" ? "user" : "project", target = ["--scope=" + memoryScope, ...(mode === "enterprise" ? ["--project=" + ready.projectId] : [])];
    await cli(["memory", "init", ...target, "--retain"]);
    const policyOutput = await cli(["memory", "store", sourceOnly ? content.replace("seven", "nine") : content, ...target, "--kind=decision", "--durable", "--operation-id=upgrade-policy"]);
    await cli(["memory", "store", billingTask, ...target, "--kind=decision", "--durable", "--operation-id=upgrade-task"]);
    if (sourceOnly) {
      const oldId = /Stored\. id=([^\s]+)/u.exec(policyOutput)?.[1]; assert.ok(oldId, policyOutput);
      for (const command of [{ action: "store", content: "Malformed mode must not store" },
        { action: "correct", id: oldId, content: "Malformed mode must not retire" }, { action: "recall", query: "retry" }]) {
        const response = await fetch(ready.origin + "/memory/durable", { method: "POST",
          headers: { authorization: "Bearer " + token, "content-type": "application/json", ...(session ? { "x-keep-session": readFileSync(session, "utf8").trim() } : {}) },
          body: JSON.stringify({ target: { scope: memoryScope, ...(mode === "enterprise" ? { projectId: ready.projectId } : {}) },
            operationId: "malformed-mode", command: { ...command, processing: ["source-only"] } }), signal: AbortSignal.timeout(5000) });
        assert.equal(response.status, 409); assert.equal((await response.json()).reason, "invalid-request");
      }
      assert.equal(calls, 0); assert.equal(embeddings, 0, "malformed modes never reach the installed provider");
      const correction = await cli(["memory", "correct", oldId, content, ...target, "--durable", "--operation-id=source-correction"]);
      const id = /superseded by new=([^\s]+)/u.exec(correction)?.[1]; assert.ok(id, correction);
      assert.equal(calls, 0); assert.equal(embeddings, 0);
      const beforePid = ready.pid; await stop(); await start(installed); assert.notEqual(ready.pid, beforePid);
      const review = await cli(["memory", "review", id, ...target, "--durable"]);
      assert.ok(review.includes(content)); assert.match(review, /keep.memory.manual-custody\/v2/u); assert.match(review, /"embeddingProcessing":"none"/u);
      const recalled = await cli(["memory", "recall", "retry", ...target, "--durable", "--k=100"]);
      assert.ok(recalled.includes(content) && recalled.includes(billingTask)); assert.ok(!recalled.includes(content.replace("seven", "nine")));
      const baseline = await sourceOnlyOutcome(source); assert.equal(baseline.accepted, false); assert.equal(baseline.code, 1);
      const text = await cli(["project", billingGoal, "--project=" + ready.projectId, "--memory=" + memoryScope, "--memory-processing=configured-provider"]);
      const runId = /Run: ([^\s]+)/u.exec(text)?.[1]; assert.ok(runId, text);
      const result = await snapshot(runId), solve = result.project.artifacts.implement.solve;
      assert.equal(result.project.goal, billingGoal); assert.equal(result.project.status, "completed", JSON.stringify({ result, errors }));
      assert.equal(solve.solved, true); assert.ok(solve.validation.passedTests.includes("goal: requested outcome"));
      const outcome = await sourceOnlyOutcome(join(root, "workspaces/project")); assert.equal(outcome.accepted, true, JSON.stringify(outcome));
      assert.equal(readFileSync(join(source, "billing.ts"), "utf8"), "export const retryLimit = 0;\n");
      assert.equal(result.project.artifacts.implement.mergeAuthority.verdict, "human-merge");
      const beforeHead = git(join(root, "workspaces/project"), ["rev-parse", "HEAD"]);
      const merge = await fetch(ready.origin + "/project/merge", { method: "POST", headers: { authorization: "Bearer " + token, "content-type": "application/json", ...(session ? { "x-keep-session": readFileSync(session, "utf8").trim() } : {}) },
        body: JSON.stringify({ runId, decision: "approve", proposalDigest: result.proposal.rollback.patchSha256 }), signal: AbortSignal.timeout(5000) });
      assert.equal(merge.status, 200); assert.equal((await merge.json()).status, "refused");
      assert.equal(git(join(root, "workspaces/project"), ["rev-parse", "HEAD"]), beforeHead);
      await cli(["project", "resume", runId]); assert.equal(calls, 2); assert.equal(embeddings, 0); assert.deepEqual(errors, []); await stop();
      t.diagnostic(JSON.stringify({ root, currentInstalled: installed, memoryScope, correctedSourceRecovered: true, distinctServerProcesses: true,
        calls, embeddings, baselineRejected: true, independentOutcomeAccepted: true, sourceUnchanged: true, humanMergeHeld: true,
        signedIdentity: mode === "enterprise", installedOrganizationAdmission: mode === "enterprise", authorityFixtureOnly: mode === "enterprise", liveModel: false }));
      return;
    }
    const firstText = await cli(["project", billingGoal, "--project=" + ready.projectId, "--memory=" + memoryScope, "--memory-processing=configured-provider"]);
    const runId = /Run: ([^\s]+)/u.exec(firstText)?.[1]; assert.ok(runId, firstText);
    const first = await snapshot(runId), original = JSON.parse(await cli(["project", "job", runId])).job;
    assert.equal(first.project.status, "waiting-capability"); assert.equal(calls, 1);
    const prior = first.project.artifacts.implement;
    assert.equal(prior.solve.preparedProposal.plan.edits[0].replace, "retryLimit = 9");
    assert.equal(prior.solve.recovery.planningCalls, 1); assert.equal(existsSync(join(root, "workspaces/project")), false);
    const oldPid = ready.pid; await stop(); await start(installed); assert.notEqual(ready.pid, oldPid);
    await cli(["project", "resume", runId, "--capability=project-execution-admission", "--evidence=generic-approval"]);
    assert.equal((await snapshot(runId)).project.status, "waiting-capability"); assert.equal(calls, 1);
    await cli(["project", "resume", runId]);
    const result = await snapshot(runId), solve = result.project.artifacts.implement.solve;
    assert.equal(result.project.status, "completed", JSON.stringify({ result, errors, calls })); assert.equal(solve.solved, true);
    assert.equal(readFileSync(join(root, "workspaces/project/billing.ts"), "utf8"), "export const retryLimit = 7;\n");
    assert.equal(readFileSync(join(source, "billing.ts"), "utf8"), "export const retryLimit = 0;\n");
    assert.deepEqual(result.project.artifacts.software_prepared_implementation, prior);
    assert.equal(solve.recovery.attempts, 2); assert.equal(solve.recovery.planningCalls, 3);
    assert.equal(solve.recovery.deadline, prior.solve.recovery.deadline); assert.equal(calls, 3); assert.deepEqual(errors, []);
    const after = JSON.parse(await cli(["project", "job", runId])).job;
    assert.equal(after.commandDigest, original.commandDigest); assert.equal(after.createdAt, original.createdAt);
    assert.equal(result.project.artifacts.implement.mergeAuthority.verdict, "human-merge");
    await cli(["project", "resume", runId]); assert.equal(calls, 3); await stop();
    t.diagnostic(JSON.stringify({ root, oldInstalled, currentInstalled: installed, sameCommand: original.commandDigest,
      calls, embeddings, preparedNineNeverApplied: true, completedLocalRepair: true, organizationAdmission: mode === "enterprise",
      authorityFixtureOnly: mode === "enterprise", productionReleaseQualification: false, sharedTenantDeployment: false, liveModel: false }));
  });

  test("installed prepared execution API: fresh admission keeps original durable budget", { timeout: 10000 }, async t => {
    const root = mkdtempSync(join(tmpdir(), "keep-installed-prepared-execution-"));
    mkdirSync(join(root, "repo")); writeFileSync(join(root, "repo/billing.ts"), "export const retryLimit = 0;\n", { flag: "wx" });
    const workspace = new keep.LocalFsWorkspace(root);
    const spineAt = () => new keep.Spine(new keep.FileSpineStore(join(root, "spine")), new keep.InProcessLock(), new keep.SchemaRegistry());
    let spine = spineAt(), calls = 0;
    const checkpointsAt = () => new keep.FileProjectCheckpointStore(join(root, "checkpoints"));
    const model = { name: "installed-prepared-execution", isLocal: true, embed: async () => [], generate: async () => {
      calls++; return { text: JSON.stringify({ action: "plan", rationale: "fresh bounded plan", edits: [
        { file: "billing.ts", search: "retryLimit = 0", replace: "retryLimit = " + (calls === 1 ? 7 : 9), intent: "fresh source admission" },
      ] }), model: "installed-prepared-execution", tokensIn: 1, tokensOut: 1 };
    } };
    const editor = keep.buildModelProjectEditPlanner(model, workspace, "repo");
    const prepare = () => ({ binding: "a".repeat(64), workspace, editor, solve: keep.buildDefaultSolver({ spine, model, workspace }) });
    const firstLoop = keep.buildAutonomyLoop({ spine, checkpoints: checkpointsAt(), repoRef: "repo",
      softwarePreparation: prepare(), solve: async () => { throw new Error("preparation entered execution"); } });
    const first = await firstLoop.runProject("Correct the invoice retry limit in billing.ts.", { runId: "prepared", stepBudget: 50 });
    const prior = first.state.artifacts.implement;
    assert.equal(prior.solve.preparedProposal.disposition, "unexecuted"); assert.equal(prior.solve.recovery.planningCalls, 1);
    assert.equal(readFileSync(join(root, "repo/billing.ts"), "utf8"), "export const retryLimit = 0;\n");
    await spine.seal(); spine = spineAt();
    const secondLoop = keep.buildAutonomyLoop({ spine, checkpoints: checkpointsAt(), repoRef: "repo",
      softwarePreparation: prepare(), softwareOperation: { binding: "b".repeat(64), authorize: () => true },
      projectWorkspace: workspace, projectEditor: editor, solveConsumesAdmittedEdit: true,
      solve: keep.buildDefaultSolver({ spine, model, workspace,
        runnerFor: (_ref, tree) => keep.validatorRunner(tree, async current => (await current.read("billing.ts"))?.includes("retryLimit = 9") === true) }),
    });
    const generic = await secondLoop.resumeProject("prepared", { capability: { capability: "project-execution-admission", evidenceId: "generic-approval" } });
    assert.equal(generic.state.status, "waiting-capability"); assert.equal(calls, 1);
    const result = await secondLoop.resumeProject("prepared"), solve = result.state.artifacts.implement.solve;
    assert.equal(solve.solved, true, JSON.stringify(result.state));
    assert.equal(readFileSync(join(root, "repo/billing.ts"), "utf8"), "export const retryLimit = 9;\n");
    assert.equal(solve.recovery.attempts, 2); assert.equal(solve.recovery.planningCalls, 2);
    assert.equal(solve.recovery.deadline, prior.solve.recovery.deadline);
    assert.deepEqual(result.state.artifacts.software_prepared_implementation, prior);
    assert.equal(result.state.runId, "prepared"); assert.equal(calls, 2);
    await secondLoop.resumeProject("prepared"); assert.equal(calls, 2); await spine.seal();
    t.diagnostic(JSON.stringify({ root, nativeApiOnly: true, durableObjectsReconstructed: true,
      ordinaryCliUpgradeQualified: false, authenticatedTrackQualification: false,
      injectedModelAndValidator: true, liveModel: false, calls }));
  });

  test("installed native preparation API: original billing and mixed goals remain unexecuted", { timeout: 10000 }, async t => {
    const root = mkdtempSync(join(tmpdir(), "keep-installed-preparation-"));
    mkdirSync(join(root, "repo"));
    const original = "export const retryLimit = 0;\n";
    writeFileSync(join(root, "repo/billing.ts"), original, { flag: "wx" });
    const workspace = new keep.LocalFsWorkspace(root);
    const spine = new keep.Spine(new keep.FileSpineStore(join(root, "spine")), new keep.InProcessLock(), new keep.SchemaRegistry());
    let calls = 0, forbidden = 0;
    const fail = () => { forbidden++; throw new Error("preparation reached an effect port"); };
    const model = { name: "installed-preparation-fixture", isLocal: true, embed: async () => [], generate: async request => {
      calls++; assert.ok(request.prompt.includes("billing.ts"));
      return { text: JSON.stringify({ action: "plan", rationale: "Unexecuted repository proposal only", edits: [
        { file: "billing.ts", search: "retryLimit = 0", replace: "retryLimit = 7", intent: "Prepare the code change" },
      ] }), model: "installed-preparation-fixture", tokensIn: 1, tokensOut: 1 };
    } };
    const goals = ["Correct the invoice retry limit in billing.ts according to the retained policy and pending task.",
      "Pay the invoice.", "Correct billing.ts and pay the invoice."];
    for (const [index, exactGoal] of goals.entries()) {
      const state = { schemaVersion: 1, revision: 0, runId: "prepare-" + index, goal: exactGoal,
        stage: "plan", artifacts: {}, posture: "autonomous", stepsRemaining: 10, reworkCount: 0,
        status: "running", retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 }, consumedSignals: [] };
      state.artifacts.project_localization = await keep.localizeProjectRepository(state, workspace, "repo");
      // A host-admitted API fixture, not a forged ordinary project admission. The
      // public editor accepts this persisted plan shape; preparation cannot act on it.
      const task = { id: "task-1", planStepId: "edit-1", objective: exactGoal, dependsOn: [],
        completionCriteria: [{ id: "proposal", statement: exactGoal, evidence: "unexecuted proposal only" }] };
      state.artifacts.plan = { schemaVersion: 1, localization: state.artifacts.project_localization,
        evidence: [{ id: "source-1", kind: "repository-file", sourceId: "billing.ts" }],
        steps: [{ id: task.planStepId, evidenceRefs: ["source-1"] }] };
      const issue = { id: state.runId, repoRef: "repo", text: exactGoal,
        hints: { projectTaskId: task.id, planStepId: task.planStepId } };
      const editor = keep.buildModelProjectEditPlanner(model, workspace, "repo");
      const solve = keep.buildDefaultSolver({ spine, model, workspace: { files: ref => workspace.files(ref), tree: fail },
        runnerFor: fail, proposalEvidenceFor: fail, governance: { spine, vetPatch: fail } });
      const result = (await solve(issue, { executionCeiling: "prepare", recoveryOperationId: state.runId,
        prepareAdmittedEdit: control => editor.prepare(issue, task, state, control) })).solveResult;
      assert.equal(result.preparedProposal?.disposition, "unexecuted", JSON.stringify(result));
      assert.equal(result.preparedProposal.goalFulfilled, false); assert.equal(result.solved, false);
      assert.equal(result.preparedProposal.plan.edits[0].replace, "retryLimit = 7");
      assert.equal(result.admittedEdit, undefined); assert.equal(result.projectEditReceipt, undefined);
      assert.equal(result.validation, undefined); assert.equal(result.prProposal, undefined);
      assert.equal(result.recovery.planningCalls, 1); assert.equal(state.goal, exactGoal);
      assert.equal(readFileSync(join(root, "repo/billing.ts"), "utf8"), original);
    }
    assert.equal(calls, 3); assert.equal(forbidden, 0);
    await spine.seal();
    t.diagnostic(JSON.stringify({ root, nativeApiOnly: true, ordinaryProjectPreflightFixed: false,
      authenticatedTrackQualification: false, liveModel: false, calls, effects: forbidden }));
  });

  for (const mode of ["owner", "enterprise"]) for (const memoryMode of ["original", "derived", "adaptive", "targeted", "preparation", "outcome", "billing", "mixed", "payment", "memory-free", "authority-withdrawn", ...(mode === "owner" ? ["semantic"] : [])]) test(`installed ${mode} ${memoryMode}: native coding with optional consented memory`, { timeout: 40000 }, async t => {
    const root = mkdtempSync(join(tmpdir(), "keep-installed-context-")), source = join(root, "source");
    const memoryFree = ["memory-free", "authority-withdrawn"].includes(memoryMode);
    const adaptive = ["adaptive", "targeted"].includes(memoryMode);
    let encoderChild, encoderEndpoint; const encoderCalls = [];
    if (memoryMode === "semantic") {
      encoderChild = spawn(process.execPath, [here, "encoder"], { env: baseEnv, stdio: ["ignore", "ignore", "pipe", "ipc"] });
      let errors = ""; encoderChild.stderr.on("data", bytes => { errors += bytes; });
      encoderChild.on("message", message => { if (message.observation === "semantic-embedding") encoderCalls.push(message); });
      encoderEndpoint = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("encoder readiness timed out: " + errors)), 5000);
        encoderChild.once("message", message => { clearTimeout(timer); resolve(message.origin); });
        encoderChild.once("error", error => { clearTimeout(timer); reject(error); });
      });
      const configured = spawnSync(process.execPath, [join(installed, "dist/src/cli/keep.js"), "encoder", "configure", "--profile=" + join(root, "encoder.json"),
        "--name=installed-semantic", "--authority=owner", "--location=local", "--endpoint=" + encoderEndpoint, "--model=separate-encoder-fixture",
        "--revision=fixture-v1-not-learned", "--dimension=2", "--query-prefix=QUERY: ", "--document-prefix=DOCUMENT: ",
        "--query-purpose=memory-query-embedding", "--document-purpose=memory-document-embedding", "--region=local", "--requests=32", "--input-bytes=131072", "--windows=256", "--credential=environment"],
        { env: baseEnv, encoding: "utf8", timeout: 10000 });
      assert.equal(configured.status, 0, configured.stderr);
      assert.match(configured.stdout, /Per-command semantic consent/u);
      assert.ok(!readFileSync(join(root, "encoder.json"), "utf8").includes("encoder-fixture-only"));
      t.after(async () => {
        if (encoderChild.exitCode !== null) return;
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => { encoderChild.kill("SIGKILL"); reject(new Error("owned encoder did not stop")); }, 5000);
          encoderChild.once("exit", () => { clearTimeout(timer); resolve(); }); encoderChild.send("stop");
        });
      });
    }
    const activeGoal = memoryFree ? memoryFreeGoal : memoryMode === "payment" ? "Pay the invoice." : memoryMode === "mixed" ? billingGoal + " Then pay the invoice."
      : ["preparation", "billing"].includes(memoryMode) ? billingGoal : goal;
    const sourceFile = memoryFree || ["preparation", "billing", "mixed", "payment"].includes(memoryMode) ? "billing.ts" : "src/retry.mjs";
    mkdirSync(join(source, "src"), { recursive: true }); mkdirSync(join(root, "workspaces"));
    writeFileSync(join(source, sourceFile), "export const retryLimit = 0;\n");
    writeFileSync(join(source, "retry.test.mjs"), `import test from 'node:test'; import assert from 'node:assert/strict'; import {retryLimit} from './${sourceFile}'; test('retained policy',()=>assert.equal(retryLimit,7));\n`);
    git(source, ["init", "--quiet", "--initial-branch=main"]); git(source, ["add", "."]);
    git(source, ["-c", "user.name=Keep Fixture", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "fixture"]);
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = { ...publicKey.export({ format: "jwk" }), kid: "sg31", alg: "RS256", use: "sig" };
    let server, ready; const observations = [], checks = [];
    const start = async () => {
      server = spawn(process.execPath, [here, "server", mode, root, JSON.stringify(jwk), "", "", memoryMode], { env: { ...baseEnv, ...(encoderEndpoint ? { KEEP_SEMANTIC_ENDPOINT: encoderEndpoint } : {}) }, stdio: ["ignore", "pipe", "pipe", "ipc"] });
      let stderr = ""; server.stderr.on("data", bytes => { stderr += bytes; }); server.stdout.resume();
      server.on("message", message => { if (message.observation === "native-context") observations.push(message); else if (message.observation) checks.push(message); });
      ready = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("context server readiness timed out: " + stderr)), 8000);
        server.once("message", message => { clearTimeout(timer); resolve(message); });
        server.once("error", error => { clearTimeout(timer); reject(error); });
        server.once("exit", code => { clearTimeout(timer); reject(new Error("context server exited " + code + ": " + stderr)); });
      });
    };
    const stop = async () => {
      if (!server || server.exitCode !== null) return;
      const child = server;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { child.kill("SIGTERM"); reject(new Error("owned server did not stop")); }, 5000);
        child.once("exit", () => { clearTimeout(timer); resolve(); }); child.send("stop");
      });
    };
    t.after(stop); await start();
    const login = async subject => {
      if (mode === "owner") return undefined;
      const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "sg31", typ: "JWT" })).toString("base64url");
      const payload = Buffer.from(JSON.stringify({ sub: subject, iss: issuer, aud: audience, exp: Math.floor(Date.now() / 1000) + 90 })).toString("base64url");
      const signature = createSign("RSA-SHA256").update(`${header}.${payload}`).end().sign(privateKey).toString("base64url");
      const response = await fetch(ready.origin + "/auth/session", { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ assertion: `${header}.${payload}.${signature}` }), signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, 200); const session = (await response.json()).session;
      const path = join(root, subject + ".session"); writeFileSync(path, session + "\n", { mode: 0o600 }); return path;
    };
    let session = await login("alice");
    const cli = (args, selectedSession = session) => spawnSync(process.execPath, [join(installed, "dist/src/main.js"), ...args,
      ...(memoryMode !== "semantic" && args[0] === "memory" && ["store", "correct", "recall"].includes(args[1]) && args.includes("--durable") ? ["--processing=configured-provider"] : [])], {
      env: { ...baseEnv, KEEP_GATEWAY_URL: ready.origin, KEEP_GATEWAY_TOKEN: token, ...(selectedSession ? { KEEP_GATEWAY_SESSION_FILE: selectedSession } : {}) },
      encoding: "utf8", timeout: 15000, maxBuffer: 1048576,
    });
    const successful = result => { assert.equal(result.status, 0, result.stdout + result.stderr); return result.stdout; };
    const scope = mode === "owner" ? "user" : "project";
    const target = ["--scope=" + scope, ...(scope === "project" ? ["--project=" + ready.projectId] : [])];
    const retainedContent = memoryMode === "semantic" ? semanticContent : memoryMode === "outcome" ? content.replace("seven", "nine") : content;
    let itemId;
    if (!memoryFree) {
      successful(cli(["memory", "init", "--retain", ...target]));
      const stored = successful(cli(["memory", "store", adaptive ? adaptiveContent : retainedContent, "--kind=decision", "--durable", "--operation-id=retained-policy", ...target]));
      itemId = /Stored\. id=([^\s]+)/u.exec(stored)?.[1]; assert.ok(itemId, stored);
      if (memoryMode === "semantic") for (let i = 0; i < 12; i++) successful(cli(["memory", "store", "Correct retryLimit src retry retained policy: unrelated archive. ".repeat(6), "--durable", "--kind=decision", "--operation-id=distractor-" + i, ...target]));
    }
    let viewId, otherId;
    if (["billing", "mixed"].includes(memoryMode)) {
      const pending = successful(cli(["memory", "store", billingTask, "--kind=decision", "--durable", "--operation-id=pending-billing-task", ...target]));
      otherId = /Stored\. id=([^\s]+)/u.exec(pending)?.[1]; assert.ok(otherId, pending);
    }
    if (memoryMode === "derived") {
      const pending = successful(cli(["memory", "store", "Pending task: correct src/retry.mjs according to the retained decision.", "--kind=decision", "--durable", "--operation-id=pending-task", ...target]));
      otherId = /Stored\. id=([^\s]+)/u.exec(pending)?.[1]; assert.ok(otherId, pending);
      const derived = successful(cli(["memory", "consolidate", itemId, otherId, "--operation-id=derived-view", ...target]));
      viewId = /originals retained\. id=([^\s]+)/u.exec(derived)?.[1]; assert.ok(viewId, derived);
      assert.ok(successful(cli(["memory", "consolidate", itemId, otherId, "--operation-id=derived-view", ...target])).includes(viewId));
      if (mode === "enterprise") assert.notEqual(cli(["memory", "consolidate", itemId, otherId, ...target], await login("foreign")).status, 0);
    }
    const projectId = ready.projectId; await stop(); await start(); session = await login("alice");
    assert.equal(ready.projectId, projectId);
    if (!memoryFree) assert.match(successful(cli(["memory", "review", itemId, "--durable", ...target])), memoryMode === "semantic" ? /Raven convention/u : adaptive ? /Allowed repetitions: seven/u : /amber orchard retry policy/u);
    if (viewId) {
      const reviewed = successful(cli(["memory", "review", viewId, "--durable", ...target]));
      assert.match(reviewed, /keep.memory.derived-custody\/v1/u); assert.ok(reviewed.includes(content));
      assert.ok(reviewed.includes(itemId)); assert.ok(reviewed.includes(otherId));
    }
    const flags = ["--project=" + projectId, ...(memoryFree ? [] : ["--memory=" + scope, "--memory-processing=configured-provider"]), ...(memoryMode === "semantic" ? ["--memory-semantic=configured-encoder"] : [])];
    if (!memoryFree) assert.notEqual(cli(["project", activeGoal, "--project=" + projectId, "--memory=" + scope]).status, 0, "missing processing consent cannot dispatch");
    if (mode === "enterprise") assert.notEqual(cli(["project", activeGoal, ...flags], await login("foreign")).status, 0);
    const result = successful(cli(["project", activeGoal, ...flags]));
    if (!memoryFree) assert.match(result, /outside current memory-key erasure/u);
    const runId = /Run: ([^\s]+)/u.exec(result)?.[1]; assert.ok(runId, result);
    if (memoryMode === "payment") {
      assert.match(result, /goal-delivery:assist-only/u);
      assert.equal(observations.length, 0); assert.equal(checks.length, 0);
      assert.equal(existsSync(join(root, "workspaces/project")), false);
      t.diagnostic(JSON.stringify({ root, memoryMode, status: "feasibility-held", calls: 0,
        limitation: "Existing classifier holds payment but incorrectly calls it physical work; no semantic-quality claim." }));
      await stop(); return;
    }
    // Synchronous CLI execution holds this parent's event loop. Await the actual IPC
    // observation, not one setImmediate turn (which may precede pipe delivery).
    if (observations.length === 0) await new Promise((resolve, reject) => {
      const onMessage = message => { if (message.observation === "native-context") { clearTimeout(timer); server.off("message", onMessage); resolve(); } };
      const timer = setTimeout(() => { server.off("message", onMessage); reject(new Error("missing provider observation: " + result)); }, 1000);
      server.on("message", onMessage);
    });
    assert.equal(observations.length, 1, JSON.stringify({ root, result, observations })); assert.equal(observations[0].cited, !memoryFree);
    assert.equal(observations[0].calls, adaptive ? 3 : 1);
    if (memoryMode === "semantic") {
      const response = await fetch(ready.origin + "/project?runId=" + encodeURIComponent(runId), { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, 200); const snapshot = await response.json();
      const recovery = snapshot.project.artifacts.implement.solve.recovery;
      assert.equal(recovery.embedding.reserved.requests, 8, "document batch and one memoized initial query share native recovery accounting");
      assert.equal(recovery.planningCalls, 2);
      assert.deepEqual(encoderCalls.map(row => row.role), ["document", "query"]);
      assert.equal(encoderCalls[0].windows, 13);
      assert.ok(observations[0].quotedItems.includes(itemId));
    }
    if (viewId) { assert.equal(observations[0].derived, true); assert.deepEqual(observations[0].quotedItems, [viewId]); }
    assert.equal(readFileSync(join(source, sourceFile), "utf8"), "export const retryLimit = 0;\n", "proposal does not mutate source repository");
    if (memoryMode === "authority-withdrawn") {
      const response = await fetch(ready.origin + "/project?runId=" + encodeURIComponent(runId), {
        headers: { authorization: `Bearer ${token}`, ...(session ? { "x-keep-session": readFileSync(session, "utf8").trim() } : {}) }, signal: AbortSignal.timeout(5000),
      });
      assert.equal(response.status, 200); const snapshot = await response.json();
      assert.equal(snapshot.project.status, "waiting-capability"); assert.equal(snapshot.proposal, null);
      assert.equal(snapshot.project.artifacts.implement.solve.solved, false);
      assert.equal(snapshot.project.artifacts.implement.solve.recovery.planningCalls, 1);
      assert.equal(snapshot.project.artifacts.implement.solve.recovery.status, "authority");
      assert.equal(readFileSync(join(root, "workspaces/project", sourceFile), "utf8"), "export const retryLimit = 0;\n");
      assert.deepEqual(checks.map(row => row.observation), ["native-dispatch"]);
      const resumed = cli(["project", "resume", runId, "--capability=native-project-command-authority", "--evidence=generic-resume-request"]);
      if (mode === "owner") assert.notEqual(resumed.status, 0);
      else {
        // The existing login session can still submit an observation. Current
        // command authority, not that cached login role, must refuse execution.
        assert.match(successful(resumed), /authority/u);
        const after = await fetch(ready.origin + "/project?runId=" + encodeURIComponent(runId), {
          headers: { authorization: `Bearer ${token}`, "x-keep-session": readFileSync(session, "utf8").trim() }, signal: AbortSignal.timeout(5000),
        });
        assert.equal(after.status, 200); const held = await after.json();
        assert.equal(held.project.status, "waiting-capability"); assert.equal(held.proposal, null);
        assert.equal(held.project.artifacts.implement.solve.recovery.planningCalls, 1);
      }
      await stop();
      assert.deepEqual(checks.map(row => row.observation), ["native-dispatch"]);
      t.diagnostic(JSON.stringify({ root, memoryMode, calls: 1, memoryInitialized: false,
        withdrawal: mode === "enterprise" ? "current principal changed to viewer" : "original command custody version invalidated",
        noEditOrSecondModelDispatch: true, liveModelQualification: false }));
      return;
    }
    if (memoryMode === "preparation") {
      assert.match(result, /prepared but not executed/u);
      assert.equal(existsSync(join(root, "workspaces/project")), false, "preparation never materializes a repository or runs its tests");
      const response = await fetch(ready.origin + "/project?runId=" + encodeURIComponent(runId), {
        headers: { authorization: `Bearer ${token}`, ...(session ? { "x-keep-session": readFileSync(session, "utf8").trim() } : {}) }, signal: AbortSignal.timeout(5000),
      });
      assert.equal(response.status, 200); const snapshot = await response.json();
      assert.equal(snapshot.project.goal, billingGoal); assert.equal(snapshot.project.status, "waiting-capability");
      assert.equal(snapshot.project.artifacts.software_preparation.schemaVersion, 1);
      const implementation = snapshot.project.artifacts.implement;
      assert.equal(implementation.solve.solved, false); assert.equal(implementation.admittedEditPrepared, undefined);
      assert.equal(implementation.solve.preparedProposal.disposition, "unexecuted");
      assert.equal(implementation.solve.preparedProposal.plan.edits[0].replace, "retryLimit = 7");
      assert.equal(implementation.solve.recovery.planningCalls, 1); assert.equal(snapshot.proposal, null);
      const resumed = successful(cli(["project", "resume", runId, "--capability=project-execution-admission", "--evidence=generic-owner-approval"]));
      assert.match(resumed, /remains unexecuted/u);
      assert.equal(existsSync(join(root, "workspaces/project")), false);
    } else if (["mixed", "payment"].includes(memoryMode)) {
      const response = await fetch(ready.origin + "/project?runId=" + encodeURIComponent(runId), {
        headers: { authorization: `Bearer ${token}`, ...(session ? { "x-keep-session": readFileSync(session, "utf8").trim() } : {}) }, signal: AbortSignal.timeout(5000),
      });
      assert.equal(response.status, 200); const snapshot = await response.json();
      assert.equal(snapshot.project.goal, activeGoal); assert.notEqual(snapshot.project.status, "completed");
      assert.equal(snapshot.project.artifacts.implement.solve.solved, false); assert.equal(snapshot.proposal, null);
      assert.equal(readFileSync(join(root, "workspaces/project", sourceFile), "utf8"), "export const retryLimit = 0;\n");
      // This is an explicit unavailable whole-goal oracle, not proof that an arbitrary
      // hostile generated program detects an omitted external clause.
      assert.equal(checks.at(-1)?.calls, 2);
    } else if (memoryMode !== "outcome") {
      assert.equal(readFileSync(join(root, "workspaces/project", sourceFile), "utf8"), "export const retryLimit = 7;\n");
      const verified = spawnSync(process.execPath, ["--test", "retry.test.mjs"], { cwd: join(root, "workspaces/project"), env: baseEnv, encoding: "utf8", timeout: 5000 });
      assert.equal(verified.status, 0, verified.stdout + verified.stderr);
      const response = await fetch(ready.origin + "/project?runId=" + encodeURIComponent(runId), {
        headers: { authorization: `Bearer ${token}`, ...(session ? { "x-keep-session": readFileSync(session, "utf8").trim() } : {}) }, signal: AbortSignal.timeout(5000),
      });
      assert.equal(response.status, 200); const snapshot = await response.json();
      assert.equal(snapshot.project.goal, activeGoal); assert.equal(snapshot.project.status, "completed", JSON.stringify({ root, stage: snapshot.project.stage, wait: snapshot.project.wait, note: snapshot.project.note }));
      assert.equal(snapshot.project.artifacts.software_operation.schemaVersion, 1);
      assert.equal(snapshot.project.artifacts.software_preparation, undefined);
      assert.equal(snapshot.project.artifacts.implement.solve.solved, true);
      assert.ok(snapshot.project.artifacts.implement.solve.validation.passedTests.includes("goal: requested outcome"));
      assert.match(snapshot.project.artifacts.implement.admittedEditPrepared.plan.goalCheck.requestSha256, /^[a-f0-9]{64}$/u);
      if (memoryFree) assert.equal(snapshot.project.artifacts.memory_context_required, undefined);
      if (memoryMode === "billing" || memoryFree) {
        assert.equal(snapshot.project.artifacts.implement.mergeAuthority.verdict, "human-merge");
        const beforeHead = git(join(root, "workspaces/project"), ["rev-parse", "HEAD"]);
        const merge = await fetch(ready.origin + "/project/merge", { method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${token}`, ...(session ? { "x-keep-session": readFileSync(session, "utf8").trim() } : {}) },
          body: JSON.stringify({ runId, decision: "approve", proposalDigest: snapshot.proposal.rollback.patchSha256 }), signal: AbortSignal.timeout(5000),
        });
        assert.equal(merge.status, 200); const held = await merge.json();
        assert.equal(held.status, "refused"); assert.match(held.reason, /merge authority is human-merge/u);
        assert.equal(git(join(root, "workspaces/project"), ["rev-parse", "HEAD"]), beforeHead);
      }
    }
    if (memoryMode === "outcome") {
        // Deliberately stale configured tests accept seven, while current cited policy
        // requires nine. A passing suite cannot establish the requested outcome.
        const response = await fetch(ready.origin + "/project?runId=" + encodeURIComponent(runId), {
          headers: { authorization: `Bearer ${token}`, ...(session ? { "x-keep-session": readFileSync(session, "utf8").trim() } : {}) }, signal: AbortSignal.timeout(5000),
        });
        assert.equal(response.status, 200); const snapshot = await response.json();
        const current = readFileSync(join(root, "workspaces/project/src/retry.mjs"), "utf8");
        const evidence = { root, mode, goal: activeGoal, retainedPolicy: retainedContent,
          requiredRetryLimit: 9, observedRetryLimit: Number(/retryLimit = (\d+)/u.exec(current)?.[1]),
          status: snapshot.project.status, solved: snapshot.project.artifacts.implement?.solve?.solved,
          proposalReturned: snapshot.proposal !== null, nativeCalls: checks.at(-1)?.calls,
          injectedProvider: true, liveModelQualification: false };
        writeFileSync(join(root, "outcome-diagnostic.json"), JSON.stringify(evidence, null, 2) + "\n");
        t.diagnostic(JSON.stringify(evidence));
        assert.notEqual(snapshot.project.status, "completed", "stale tests must not certify a repair that contradicts the current requested policy");
        assert.equal(snapshot.project.artifacts.implement.solve.solved, false);
        assert.equal(snapshot.proposal, null);
        assert.equal(current, "export const retryLimit = 0;\n", "failed requested-outcome check compensates the wrong edit");
        assert.deepEqual(checks.map(row => row.observation), ["goal-check", "repair-refusal"]);
    }
    if (mode === "enterprise") assert.match(cli(["project", "resume", runId], await login("teammate")).stdout, /authority/u);
    if (memoryFree) {
      successful(cli(["project", "resume", runId]));
      assert.equal(observations.length, 1, "completed command observation does not repeat the model");
      await stop(); await start(); session = await login("alice");
      const restored = cli(["project", "resume", runId]);
      assert.notEqual(restored.status, 0); assert.match(restored.stdout, /custody/u);
      await stop();
      t.diagnostic(JSON.stringify({ root, memoryMode, memoryInitialized: false, nativeCalls: 2,
        originalPrincipalOnly: true, opaqueProviderRestartHeld: true, liveModelQualification: false }));
      return;
    }
    successful(cli(["memory", "erase", itemId, "--operation-id=erase-policy", ...target]));
    if (viewId) {
      assert.notEqual(cli(["memory", "review", viewId, "--durable", ...target]).status, 0);
      assert.match(successful(cli(["memory", "review", otherId, "--durable", ...target])), /Pending task/u);
      assert.notEqual(cli(["memory", "consolidate", itemId, otherId, "--operation-id=derived-view", ...target]).status, 0);
    }
    const erasedResume = cli(["project", "resume", runId]);
    assert.notEqual(erasedResume.status, 0); assert.match(erasedResume.stdout, /source-changed/u);
    await stop(); await start(); session = await login("alice");
    // Opaque injected providers deliberately have no restart-stable identity. Do not call
    // this positive command recovery: changed bindings must hold, even after source erasure.
    const restartResume = cli(["project", "resume", runId]);
    assert.notEqual(restartResume.status, 0); assert.match(restartResume.stdout, /custody/u);
    assert.equal(observations.length, 1); await stop();
    if (memoryMode !== "preparation" && memoryMode !== "outcome") assert.equal(checks.filter(row => row.observation === "goal-check").length, 1);
    t.diagnostic(JSON.stringify({ root, scope, memoryMode, nativeCalls: checks.at(-1)?.calls ?? observations[0].calls, injectedProvider: true, signedIdentity: mode === "enterprise", freshMemoryProcess: true,
      ...(memoryMode === "semantic" ? { separateHttpEncoder: true, installedEncoderConfigureAndRuntimeProfileLoader: true, generationStillHostFixture: true, encoderCalls, sourceOnlyStorage: true, nativeBudgetReservedRequests: 8, learnedModelQuality: false } : {}),
      actualRepositoryTest: !["preparation", "mixed", "payment"].includes(memoryMode), preparationOnly: memoryMode === "preparation", erasedSourceResumeDenied: true, opaqueProviderRestartHeld: true, liveModelQualification: false }));
  });

  test("installed owner: original queued memory command recovers through the same configured HTTP provider", { timeout: 65000 }, async t => {
    const root = mkdtempSync(join(tmpdir(), "keep-context-command-recovery-")), source = join(root, "source");
    mkdirSync(join(source, "src"), { recursive: true }); mkdirSync(join(root, "workspaces"));
    writeFileSync(join(source, "src/retry.mjs"), "export const retryLimit = 0;\n");
    writeFileSync(join(source, "retry.test.mjs"), "import test from 'node:test'; import assert from 'node:assert/strict'; import {retryLimit} from './src/retry.mjs'; test('retained policy',()=>assert.equal(retryLimit,7));\n");
    git(source, ["init", "--quiet", "--initial-branch=main"]); git(source, ["add", "."]);
    git(source, ["-c", "user.name=Keep Fixture", "-c", "user.email=keep@example.invalid", "commit", "--quiet", "-m", "fixture"]);
    let calls = 0, embeddings = 0; const errors = [];
    const provider = createServer(async (request, response) => {
      try {
        assert.equal(request.headers.authorization, "Bearer owned-loopback-fixture");
        assert.equal(request.method, "POST"); const chunks = []; let bytes = 0;
        for await (const chunk of request) { bytes += chunk.length; assert.ok(bytes <= 262144); chunks.push(chunk); }
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        response.setHeader("content-type", "application/json");
        if (request.url === "/v1/embeddings") {
          embeddings++; assert.ok(embeddings <= 4);
          response.end(JSON.stringify({ data: body.input.map((_, index) => ({ index, embedding: [1, 0] })) })); return;
        }
        assert.equal(request.url, "/v1/chat/completions"); calls++; assert.ok(calls <= 2);
        const prompt = body.messages[0].content;
        if (calls === 2) {
          assert.match(prompt, /Prepare a goal-specific behavioral regression test/u); assert.ok(prompt.includes(content));
          response.end(JSON.stringify({ model: body.model, choices: [{ message: { content: JSON.stringify({ body: "assert.equal((await import('./src/retry.mjs')).retryLimit, 7);" }) }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } })); return;
        }
        assert.ok(prompt.includes(content)); assert.match(prompt, /"itemId":"[^"]+"/u); assert.match(prompt, /"authority":"none"/u);
        response.end(JSON.stringify({ model: body.model, choices: [{ message: { content: JSON.stringify({ action: "plan", rationale: "Apply retained retry policy", edits: [
          { file: "src/retry.mjs", search: "retryLimit = 0", replace: "retryLimit = 7", intent: "Correct retry policy" },
        ] }) }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } }));
      } catch (error) { errors.push(String(error)); response.writeHead(400).end(JSON.stringify({ error: "fixture rejected request" })); }
    });
    await new Promise(resolve => provider.listen(0, "127.0.0.1", resolve));
    t.after(async () => { provider.closeAllConnections(); await new Promise(resolve => provider.close(resolve)); });
    const endpoint = "http://127.0.0.1:" + provider.address().port;
    let child, ready;
    const start = async dispatch => {
      child = spawn(process.execPath, [here, "server", "owner", root, "{}", endpoint, dispatch], { env: baseEnv, stdio: ["ignore", "pipe", "pipe", "ipc"] });
      let stderr = ""; child.stderr.on("data", bytes => { stderr = (stderr + bytes).slice(-16384); }); child.stdout.resume();
      ready = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("recovery server readiness timeout: " + stderr)), 8000);
        child.once("message", message => { clearTimeout(timer); resolve(message); });
        child.once("error", error => { clearTimeout(timer); reject(error); });
        child.once("exit", code => { clearTimeout(timer); reject(new Error("recovery server exited " + code + ": " + stderr)); });
      });
    };
    const stop = async () => {
      if (!child || child.exitCode !== null || child.signalCode !== null) return;
      const owned = child;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { owned.kill("SIGKILL"); reject(new Error("owned recovery server did not stop")); }, 5000);
        owned.once("exit", () => { clearTimeout(timer); resolve(); }); owned.send("stop");
      });
    };
    t.after(stop); await start("paused");
    const cli = args => new Promise((resolve, reject) => {
      const command = spawn(process.execPath, [join(installed, "dist/src/main.js"), ...args,
        ...(args[0] === "memory" && ["store", "correct", "recall"].includes(args[1]) && args.includes("--durable") ? ["--processing=configured-provider"] : [])], {
        env: { ...baseEnv, KEEP_GATEWAY_URL: ready.origin, KEEP_GATEWAY_TOKEN: token }, stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = "", stderr = ""; command.stdout.on("data", bytes => { stdout += bytes; }); command.stderr.on("data", bytes => { stderr += bytes; });
      const timer = setTimeout(() => { command.kill("SIGKILL"); reject(new Error("owned CLI timed out")); }, 8000);
      command.once("error", error => { clearTimeout(timer); reject(error); });
      command.once("close", code => { clearTimeout(timer); if (code !== 0) reject(new Error(stdout + stderr)); else resolve(stdout); });
    });
    await cli(["memory", "init", "--scope=user", "--retain"]);
    await cli(["memory", "store", content, "--scope=user", "--kind=decision", "--durable", "--operation-id=recovery-policy"]);
    const args = ["project", goal, "--project=" + ready.projectId, "--memory=user", "--memory-processing=configured-provider", "--background", "--idempotency-key=context-recovery-operation"];
    const accepted = JSON.parse(await cli(args)); const jobId = accepted.jobId;
    const original = JSON.parse(await cli(["project", "job", jobId])).job;
    assert.equal(original.state, "queued"); assert.equal(calls, 0); const oldPid = ready.pid;
    // Stop this exact idle-but-queued process abruptly. No other session is targeted.
    const owned = child;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("owned queued server did not exit")), 3000);
      owned.once("exit", () => { clearTimeout(timer); resolve(); }); owned.kill("SIGKILL");
    });
    await start("running"); assert.notEqual(ready.pid, oldPid);
    let observed; const deadline = Date.now() + 45000;
    do {
      assert.ok(Date.now() < deadline, JSON.stringify({ observed, errors, calls }));
      observed = JSON.parse(await cli(["project", "job", jobId])).job;
      assert.notEqual(observed.state, "failed", JSON.stringify({ observed, errors }));
      if (observed.state !== "completed") await new Promise(resolve => setTimeout(resolve, 500));
    } while (observed.state !== "completed");
    assert.deepEqual(errors, []); assert.equal(calls, 2);
    assert.equal(observed.createdAt, original.createdAt); assert.equal(observed.commandDigest, original.commandDigest);
    assert.notEqual(observed.ownerId, original.ownerId);
    const replay = JSON.parse(await cli(args)); assert.equal(replay.jobId, jobId); assert.equal(replay.replayed, true); assert.equal(calls, 2);
    assert.equal(readFileSync(join(root, "workspaces/project/src/retry.mjs"), "utf8"), "export const retryLimit = 7;\n");
    assert.equal(readFileSync(join(source, "src/retry.mjs"), "utf8"), "export const retryLimit = 0;\n");
    await stop();
    t.diagnostic(JSON.stringify({ root, sameCommandRecovered: true, nativeHttpCalls: calls, embeddingCalls: embeddings, originalPrincipal: "owner", organizationAdmission: false, liveModelQualification: false }));
  });
}
