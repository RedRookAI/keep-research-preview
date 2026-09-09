import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { MemoryStore } from "../src/memory/store.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { ModelGateway, type ModelProvider } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { runCli, runGatewayCli, type CliIO } from "../src/cli/cli_core.js";
import { handleGatewayRequest, type GatewayRequest } from "../src/gateway/http_gateway.js";
import type { Principal } from "../src/identity/rbac.js";
import { memoryCorrect, memoryReview, memoryList, executeDurableMemoryMutation, type DurableMemoryMutationResult } from "../src/memory/memory_tools.js";
import { FileMemoryPartition, type MemoryPartitionScope } from "../src/memory/persistence.js";
import { NODE_IO } from "../src/spine/durable_fs.js";
import { InMemoryWorkspace } from "../src/solve/workspace.js";
import { RbacAuthorizer } from "../src/identity/rbac.js";
import { MEMORY_RETENTION_POLICY_SCHEMA } from "../src/memory/retention.js";
import { createTaskMemoryContext } from "../src/memory/task_context.js";

function fixture(t: TestContext, provider: ModelProvider = new LocalProvider()) {
  const root = mkdtempSync(join(tmpdir(), "keep-memory-consumers-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const memory = new MemoryStore(new Spine(new FileSpineStore(join(root, "memory")),
    new InProcessLock(), new SchemaRegistry()), new ModelGateway(provider));
  return { root, memory };
}

test("memory consumers: default composition still provides manual memory", async (t) => {
  const { root } = fixture(t);
  const app = composeKeep({ dataDir: join(root, "app") });
  const item = await app.secondBrain.memory.ingest("Synthetic default-store decision", { origin: "self", kind: "decision" });
  assert.ok(item);
  assert.equal(app.secondBrain.memory.get(item.id)?.content, "Synthetic default-store decision");
});

test("task-memory transport refuses an uncomposed executor before project admission", async (t) => {
  const { root } = fixture(t);
  const app = composeKeep({ dataDir: join(root, "task-app") });
  for (const security of [{ token: "fixture-token" }, { token: "fixture-token", principalFor: () => ({ id: "owner-a", kind: "human" as const, role: "owner" as const, tenant: "tenant-a" }) }]) {
    const response = await handleGatewayRequest(app, { method: "POST", path: "/project", query: {}, headers: { authorization: "Bearer fixture-token" },
      body: JSON.stringify({ goal: "Update retry policy in config.ts", memoryContext: { scope: "user", processing: "configured-provider" } }) }, security);
    assert.equal(response.status, 501, response.body); assert.match(response.body, /selected task memory executor is unavailable/);
    assert.equal(app.projectManager!.list().length, 0, "refuse before project/job admission");
  }
});

for (const track of ["owner", "enterprise"] as const) {
  for (const memoryMode of ["original", "derived"]) test(`${track}: ${memoryMode} memory reaches real native project submission`, async (t) => {
    const { root } = fixture(t), workspace = new InMemoryWorkspace({ repo: { "config.ts": "export const retry = 0;\n" } });
    const principal: Principal = track === "owner" ? { id: "owner", kind: "human", role: "owner" } : { id: "alice", kind: "human", role: "maintainer", tenant: "alpha" };
    let calls = 0; const prompts: string[] = [];
    const app = composeKeep({ dataDir: join(root, "task"), workspace, repoRef: "repo",
      delegationParentFor: (id, tenant) => id === principal.id && tenant === principal.tenant ? principal : undefined,
      developmentProvider: { name: "native-memory-fixture", isLocal: true, embed: async texts => texts.map(() => [1]), generate: async req => {
        prompts.push(req.prompt); calls++; assert.match(req.prompt, /amber orchard retry policy is seven/);
        if (memoryMode === "derived") { assert.match(req.prompt, /"view":"derived"/); assert.match(req.prompt, /"assertion":"derived"/); }
        return { text: JSON.stringify({ rationale: "Meet the retained retry decision", edits: [{ file: "config.ts", search: "retry = 0", replace: "retry = 7", intent: "Apply retry policy" }] }), model: "native-memory-fixture", tokensIn: 1, tokensOut: 1 };
      } }, solverRunnerFor: () => ({ run: async () => ({ results: [{ name: "retry-seven", passed: (await workspace.tree("repo").read("config.ts"))?.includes("retry = 7") === true }] }) }) });
    const project = app.projectManager!.create({ name: "Memory task", ...(principal.tenant === undefined ? {} : { tenant: principal.tenant }) });
    const target = { scope: "project", projectId: project.id };
    const security = { token: "fixture", ...(track === "owner" ? {} : { principalFor: () => principal }) };
    const request = (path: string, body: unknown) => handleGatewayRequest(app, { method: "POST", path, query: {}, headers: { authorization: "Bearer fixture" }, body: JSON.stringify(body) }, security);
    assert.equal((await request("/memory/durable/init", { target, retain: true })).status, 200);
    const stored = await request("/memory/durable", { target, operationId: "decision", command: { action: "store", kind: "decision", content: "amber orchard retry policy is seven" } });
    assert.equal(stored.status, 200, stored.body); const itemId = JSON.parse(stored.body).result.id;
    let viewId: string | undefined, otherId: string | undefined;
    if (memoryMode === "derived") {
      const other = await request("/memory/durable", { target, operationId: "pending", command: { action: "store", kind: "decision", content: "Pending task: correct config.ts according to the retained decision." } });
      assert.equal(other.status, 200, other.body); otherId = JSON.parse(other.body).result.id;
      const derived = await request("/memory/durable", { target, operationId: "view", command: { action: "consolidate", sourceIds: [itemId, otherId] } });
      assert.equal(derived.status, 200, derived.body); viewId = JSON.parse(derived.body).result.id;
      const repeat = await request("/memory/durable", { target, operationId: "view", command: { action: "consolidate", sourceIds: [itemId, otherId] } });
      assert.equal(repeat.status, 200, repeat.body); assert.equal(JSON.parse(repeat.body).result.id, viewId);
    }
    const response = await request("/project", { projectId: project.id, goal: "Correct retry in config.ts according to the retained decision.", memoryContext: { scope: "project", processing: "configured-provider" } });
    assert.equal(response.status, 200, response.body); assert.equal(calls, 1, response.body);
    assert.ok(prompts[0]!.includes(itemId)); assert.equal(await workspace.tree("repo").read("config.ts"), "export const retry = 7;\n");
    if (viewId) { assert.ok(prompts[0]!.includes(viewId)); assert.ok(prompts[0]!.includes(otherId!)); }
    const runId = JSON.parse(response.body).runId;
    const command = app.projectRuntime!.commandForJob(runId, project.id);
    assert.deepEqual(command.memoryContext, { scope: "project", processing: "configured-provider" });
    assert.equal(command.principal.id, principal.id);
    assert.doesNotMatch(JSON.stringify(command), /amber orchard|itemId/);
    assert.equal(app.projectManager!.session(project.id).lastCheckpoint()!.artifacts["memory_context_required"], true);
    assert.match(response.body, /outside current memory-key erasure/);
    const resumed = await request("/project/resume", { runId });
    assert.equal(resumed.status, 200, resumed.body); assert.equal(calls, 1, "no model replay just to observe the capability hold");
    if (track === "enterprise") {
      const foreign = await handleGatewayRequest(app, { method: "POST", path: "/project/resume", query: {}, headers: { authorization: "Bearer fixture" }, body: JSON.stringify({ runId }) },
        { token: "fixture", principalFor: () => ({ ...principal, id: "teammate" }) });
      assert.equal(foreign.status, 409, foreign.body); assert.match(foreign.body, /authority/);
    }
    const erased = await request("/memory/durable", { target, operationId: "erase-context", command: { action: "erase", id: itemId } });
    assert.equal(erased.status, 200, erased.body);
    if (viewId) {
      const partitionScope = { ownerId: `project:${project.id}`, kind: "project" as const, projectId: project.id, ...(principal.tenant === undefined ? {} : { tenantId: principal.tenant }) };
      const remaining = app.memoryCustody.partition(partitionScope).read().entries;
      assert.ok(remaining.some(row => row.lesson.id === otherId));
      assert.ok(!remaining.some(row => row.lesson.id === viewId));
    }
    const before = app.projectRuntime!.jobs().length;
    const stale = await request("/project/resume", { runId });
    assert.equal(stale.status, 409, stale.body); assert.match(stale.body, /source-changed/);
    assert.equal(app.projectRuntime!.jobs().length, before, "refuse before admitting another job");
    assert.equal(calls, 1); assert.equal(await workspace.tree("repo").read("config.ts"), "export const retry = 7;\n", "erasure does not claim to erase generated edits");
  });

  test(`${track}: queued memory command rechecks memory.read before dispatch`, async (t) => {
    const { root } = fixture(t), workspace = new InMemoryWorkspace({ repo: { "config.ts": "export const retry = 0;\n" } });
    const principal: Principal = track === "owner" ? { id: "owner", kind: "human", role: "owner" } : { id: "alice", kind: "human", role: "maintainer", tenant: "alpha" };
    let permitted = true, calls = 0; const rbac = new RbacAuthorizer();
    const app = composeKeep({ dataDir: join(root, "queued"), workspace, repoRef: "repo", projectRuntimePaused: true,
      authorization: { authorize: (actor, permission) => permission === "memory.read" && !permitted ? { allow: false, reason: "revoked" } : rbac.authorize(actor, permission) },
      delegationParentFor: (id, tenant) => id === principal.id && tenant === principal.tenant ? principal : undefined,
      developmentProvider: { name: "queued-memory-fixture", isLocal: true, embed: async texts => texts.map(() => [1]), generate: async () => { calls++; throw new Error("must not dispatch"); } } });
    const project = app.projectManager!.create({ name: "Queued memory", ...(principal.tenant === undefined ? {} : { tenant: principal.tenant }) });
    const target = { scope: "project", projectId: project.id };
    const security = { token: "fixture", ...(track === "owner" ? {} : { principalFor: () => principal }) };
    const request = (path: string, body: unknown) => handleGatewayRequest(app, { method: "POST", path, query: {}, headers: { authorization: "Bearer fixture" }, body: JSON.stringify(body) }, security);
    assert.equal((await request("/memory/durable/init", { target, retain: true })).status, 200);
    const response = await request("/project", { projectId: project.id, goal: "Correct retry in config.ts", background: true, memoryContext: { scope: "project", processing: "configured-provider" } });
    assert.equal(response.status, 202, response.body); const jobId = JSON.parse(response.body).jobId;
    permitted = false; app.projectRuntime!.resumeDispatch();
    for (let i = 0; i < 50 && ["queued", "running"].includes(app.projectRuntime!.job(jobId)!.state); i++) await new Promise(resolve => setTimeout(resolve, 2));
    assert.equal(calls, 0); assert.equal(app.projectRuntime!.job(jobId)!.state, "failed");
  });
}

test("memory consumers: ordinary CLI store and review use the configured conversational memory", async (t) => {
  const { root, memory } = fixture(t);
  const app = composeKeep({ dataDir: join(root, "app"), frontDoorMemory: memory });
  const output: string[] = [];
  const io: CliIO = { write: (text) => output.push(text), prompt: async () => { throw new Error("memory command unexpectedly prompted"); } };
  const stored = await runCli(["memory", "store", "Synthetic shared-memory decision", "--kind=decision"], io, { app });
  assert.equal(stored.exitCode, 0);
  const id = /^Stored\. id=(.+)$/u.exec(output.at(-1) ?? "")?.[1];
  assert.ok(id);
  assert.equal(memory.get(id)?.content, "Synthetic shared-memory decision", "the CLI must not write to a second hidden MemoryStore");
  assert.equal(app.secondBrain.memory, memory);
  output.length = 0;
  assert.equal((await runCli(["memory", "review", id], io, { app })).exitCode, 0);
  assert.match(output.join("\n"), /Synthetic shared-memory decision/u);
});

test("memory consumers: HTTP shares the configured store and retains token and tenant restrictions", async (t) => {
  const { root, memory } = fixture(t);
  const app = composeKeep({ dataDir: join(root, "app"), frontDoorMemory: memory });
  const request: GatewayRequest = { method: "POST", path: "/memory", query: {}, headers: {},
    body: JSON.stringify({ content: "Synthetic scoped-memory decision", kind: "decision" }) };
  const principal: Principal = { id: "owner-a", kind: "human", role: "owner", tenant: "tenant-a" };
  const security = { token: "fixture-token", principalFor: () => principal };
  const denied = await handleGatewayRequest(app, request, security);
  assert.equal(denied.status, 401);
  assert.equal(memory.all().length, 0);
  const authenticated = { ...request, headers: { authorization: "Bearer fixture-token" } };
  const stored = await handleGatewayRequest(app, authenticated, security);
  assert.equal(stored.status, 200, stored.body);
  const id = (JSON.parse(stored.body) as { id: string }).id;
  assert.equal(memory.getForProject("tenant-a", id)?.content, "Synthetic scoped-memory decision");
  assert.equal(memory.getForProject("tenant-b", id), undefined);
  const read: GatewayRequest = { method: "GET", path: "/memory/review", query: { id },
    headers: authenticated.headers, body: "" };
  assert.equal((await handleGatewayRequest(app, read, security)).status, 200);
  const foreign = await handleGatewayRequest(app, read, { ...security, principalFor: () => ({ ...principal, id: "owner-b", tenant: "tenant-b" }) });
  assert.equal(foreign.status, 404);
  const wrongScope = await handleGatewayRequest(app, { ...authenticated,
    body: JSON.stringify({ content: "Synthetic attempted global write", scope: "global" }) }, security);
  assert.equal(wrongScope.status, 400);
  assert.equal(memory.allForProject("tenant-a").length, 1);
});

test("memory preparation: failed embedding does not admit an item or tenant index", async (t) => {
  const provider = new LocalProvider();
  provider.embed = async () => { throw new Error("synthetic embedding failure"); };
  const { memory } = fixture(t, provider);
  await assert.rejects(memory.ingest("Synthetic decision", { origin: "self", projectId: "tenant-a" }), /synthetic embedding failure/u);
  assert.deepEqual(memory.all(), []);
  assert.deepEqual(memory.allForProject("tenant-a"), []);
});

test("memory preparation: missing agent scope is rejected before provider work or publication", async (t) => {
  const provider = new LocalProvider();
  let calls = 0;
  provider.embed = async () => { calls++; return [[1]]; };
  const { memory } = fixture(t, provider);
  await assert.rejects(memory.ingest("Synthetic agent decision", { origin: "self", scope: "agent" }), /agentId/u);
  assert.equal(calls, 0);
  assert.deepEqual(memory.all(), []);
});

test("memory correction: rejected replacement leaves the prior item and validity intact", async (t) => {
  const { memory } = fixture(t);
  const old = await memory.ingest("Synthetic prior decision", { origin: "self", validFrom: 1000 });
  assert.ok(old);
  const before = structuredClone(memory.get(old.id));
  assert.equal(await memoryCorrect(memory, old.id, "SPDX-License-Identifier: GPL-3.0"), null);
  assert.deepEqual(memory.get(old.id), before);
  assert.equal(memory.all().length, 1);
});

test("memory correction: provider failure preserves the original tenant item and no successor", async (t) => {
  const provider = new LocalProvider();
  const { memory } = fixture(t, provider);
  const old = await memory.ingest("Synthetic tenant decision", { origin: "self", projectId: "tenant-a" });
  assert.ok(old);
  const before = structuredClone(memory.getForProject("tenant-a", old.id));
  provider.embed = async () => { throw new Error("synthetic embedding failure"); };
  await assert.rejects(memoryCorrect(memory, old.id, "Synthetic replacement", "tenant-a"), /synthetic embedding failure/u);
  assert.deepEqual(memory.getForProject("tenant-a", old.id), before);
  assert.equal(memory.all().length, 1);
});

test("memory correction: trusted internal correction preserves the original tenant partition", async (t) => {
  const { memory } = fixture(t);
  const old = await memory.ingest("Synthetic tenant decision", { origin: "self", projectId: "tenant-a" });
  assert.ok(old);
  const corrected = await memoryCorrect(memory, old.id, "Synthetic tenant replacement");
  assert.ok(corrected);
  assert.equal(memory.getForProject("tenant-a", corrected.newId)?.citation, `supersedes:${old.id}`);
  assert.equal(memory.getForProject("tenant-b", corrected.newId), undefined);
  assert.equal((await memory.retrieve("Synthetic tenant replacement", 10)).length, 0);
});

test("memory correction: an agent successor retains its isolated retrieval partition", async (t) => {
  const { memory } = fixture(t);
  const old = await memory.ingest("Synthetic agent decision", { origin: "self", scope: "agent", agentId: "agent-a" });
  assert.ok(old);
  const corrected = await memoryCorrect(memory, old.id, "Synthetic agent replacement");
  assert.ok(corrected);
  assert.deepEqual((await memory.retrieve("Synthetic agent replacement", 5, "candidate", "agent-a")).map(h => h.lesson.id), [corrected.newId]);
  assert.deepEqual(await memory.retrieve("Synthetic agent replacement", 5, "candidate", "agent-b"), []);
});

test("memory correction: a concurrent change during preparation is not overwritten", async (t) => {
  const provider = new LocalProvider();
  const { memory } = fixture(t, provider);
  const old = await memory.ingest("Synthetic initial decision", { origin: "self" });
  assert.ok(old);
  const originalEmbed = provider.embed.bind(provider);
  let finish!: () => void;
  const ready = new Promise<void>(resolve => { finish = resolve; });
  t.after(finish);
  provider.embed = async texts => { await ready; return originalEmbed(texts); };
  const pending = memoryCorrect(memory, old.id, "Synthetic stale replacement");
  const changed = memory.reweight(old.id, 0.9);
  finish();
  const result = await pending;
  assert.equal(changed, true, "preparation must not retire the old item early");
  assert.equal(result, null, "a prepared correction must recheck the entire old version");
  assert.equal(memory.get(old.id)?.importance, 0.9);
  assert.equal(memory.get(old.id)?.tier, "candidate");
  assert.equal(memory.get(old.id)?.validTo, undefined);
  assert.equal(memory.all().length, 1);
});

function durableFixture(t: TestContext, scope: MemoryPartitionScope = { ownerId: "owner", kind: "project", projectId: "project" }) {
  const { root } = fixture(t);
  const options = { directory: join(root, "partition"), scope, keyAuthority: { masterKeyPath: join(root, "master.key"), wrappedKeysPath: join(root, "wrapped.json") } };
  writeFileSync(options.keyAuthority.masterKeyPath, randomBytes(32), { mode: 0o600, flag: "wx" });
  const partition = new FileMemoryPartition(options); partition.initialize();
  const spine = new Spine(new FileSpineStore(join(root, "audit"), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const provider = new LocalProvider(); const gateway = new ModelGateway(provider);
  return { root, options, partition, spine, provider, gateway, authorize: () => true };
}
function committed(result: DurableMemoryMutationResult): Extract<DurableMemoryMutationResult, { disposition: "committed" }> {
  assert.equal(result.disposition, "committed", JSON.stringify(result));
  if (result.disposition !== "committed") throw new Error("unreachable");
  return result;
}

for (const enterprise of [false, true]) {
  test(`private source ${enterprise ? "enterprise ordinary operator" : "owner"}: exact custody, restart, current policy, safe correction and erasure`, async t => {
    const { root } = fixture(t), dataDir = join(root, "private-memory"); let modelCalls = 0;
    const provider: ModelProvider = { name: "no-private-ingestion-model", isLocal: true,
      generate: async () => { modelCalls++; throw new Error("unexpected model"); }, embed: async () => { modelCalls++; throw new Error("unexpected embed"); } };
    const policy = { schema: MEMORY_RETENTION_POLICY_SCHEMA as typeof MEMORY_RETENTION_POLICY_SCHEMA, authority: enterprise ? "organization" as const : "owner" as const, purposes: [{ id: "contact-memory", maxUseMs: 60000 }] };
    let app = composeKeep({ dataDir, developmentProvider: provider });
    let principal: Principal | undefined = enterprise ? { id: "alice", kind: "human", role: "operator", tenant: "alpha" } : undefined;
    const output: string[] = [], io: CliIO = { write: line => { output.push(line); }, prompt: async () => "" };
    const cli = (args: string[]) => runGatewayCli(["memory", ...args], io, { gateway: req => handleGatewayRequest(app, req, { token: "fixture", ...(principal ? { principalFor: () => principal! } : {}) }), gatewayToken: "fixture" });
    const run = async (args: string[], code = 0) => { output.length = 0; const result = await cli(args); assert.equal(result.exitCode, code, output.join("\n")); return output.join("\n"); };
    const text = "Contact example@example.invalid. Reference 123-45-6789. Keep exact trailing spaces.  ";
    const flags = ["--durable", "--private-purpose=contact-memory", "--use-until=" + (Date.now() + 30000)];
    await run(["init", "--retain"]);
    await run(["store", text, ...flags], 1);
    app = composeKeep({ dataDir, developmentProvider: provider, memoryRetentionPolicy: policy });
    const stored = await run(["store", text, ...flags, "--operation-id=private"]);
    assert.match(stored, /exact-private-source/u); const id = stored.match(/Stored\. id=(\S+)/u)![1]!;
    const scope: MemoryPartitionScope = { ownerId: principal?.id ?? "owner", kind: "user", ...(enterprise ? { tenantId: "alpha" } : {}) };
    const partition = () => app.memoryCustody.partition(scope);
    const source = partition().read().entries.find(row => row.lesson.id === id)!;
    assert.equal(source.lesson.content, text); assert.equal(source.lesson.custody?.schema, "keep.memory.manual-custody/v3"); assert.equal(source.embedding, undefined);
    const context = () => createTaskMemoryContext({ partition: partition(), scope, selection: { scope: "user", processing: "configured-provider" },
      provider, authorize: () => true, ...(app.memoryRetentionPolicy ? { retentionPolicy: app.memoryRetentionPolicy } : {}) });
    assert.ok(context().select("Contact", provider).prompt.includes("example@example.invalid"));
    assert.ok(!JSON.stringify(partition().admissionEvents()).includes("example@example.invalid"), "audit stores metadata, not private text");
    const defaultStored = await run(["store", "Contact other@example.invalid.", "--durable"]);
    assert.match(defaultStored, /sanitized-source/u); const defaultId = defaultStored.match(/Stored\. id=(\S+)/u)![1]!;
    const derived = await run(["consolidate", id, defaultId]); const derivedId = derived.match(/originals retained\. id=(\S+)/u)![1]!;
    await run(["correct", id, "Contact replacement@example.invalid.", "--durable"], 1);
    await run(["correct", id, "Contact AKIA1234567890ABCDEF", "--durable", "--private-purpose=contact-memory"], 1);
    assert.deepEqual(partition().read().entries.find(row => row.lesson.id === id), source, "failed replacement preserves exact predecessor");
    app = composeKeep({ dataDir, developmentProvider: provider, memoryRetentionPolicy: policy });
    assert.ok((await run(["recall", "Contact", "--durable", "--operation-id=recall-private"])).includes("example@example.invalid"));
    // Host policy removal does not erase data, but use and replay must withhold it.
    app = composeKeep({ dataDir, developmentProvider: provider });
    assert.ok(!(await run(["recall", "Contact", "--durable", "--operation-id=recall-private"])).includes("example@example.invalid"));
    assert.ok(!(await run(["review", id, "--durable"])).includes("example@example.invalid"));
    assert.ok(!(await run(["review", derivedId, "--durable"])).includes("example@example.invalid"));
    assert.ok(!(await run(["list", "--durable", "--include-retired"])).includes(id));
    assert.ok(!context().select("Contact", provider).prompt.includes("example@example.invalid"));
    await run(["consolidate", id, defaultId], 1);
    app = composeKeep({ dataDir, developmentProvider: provider, memoryRetentionPolicy: policy });
    const corrected = await run(["correct", id, "Contact replacement@example.invalid.", "--durable", "--private-purpose=contact-memory"]);
    const next = corrected.match(/new=(\S+)/u)![1]!;
    assert.equal(partition().read().entries.find(row => row.lesson.id === next)?.lesson.content, "Contact replacement@example.invalid.");
    if (principal) principal = { ...principal, role: "maintainer" }; // Erasure uses existing memory.forget, not a new write privilege.
    await run(["erase", next]);
    assert.ok(!(await run(["recall", "Contact", "--durable"])).includes("replacement@example.invalid"));
    assert.equal(modelCalls, 0);
  });

  test(`source-only ${enterprise ? "enterprise resolved gateway" : "owner"}: malformed modes cannot dispatch; failed explicit embedding preserves the source`, async t => {
    const { root } = fixture(t), dataDir = join(root, "mode-authority"); let calls = 0;
    const provider: ModelProvider = { name: "chat-only", isLocal: true,
      generate: async () => { throw new Error("unexpected generation"); },
      embed: async () => { calls++; throw new Error("embedding unavailable"); } };
    let app = composeKeep({ dataDir, developmentProvider: provider });
    const principal: Principal | undefined = enterprise ? { id: "alice", kind: "human", role: "maintainer", tenant: "alpha" } : undefined;
    let route = durableRoute(app, principal); const target = { scope: "user" };
    const post = (operationId: string, command: unknown) => route("POST", "/memory/durable", { target, operationId, command });
    assert.equal((await post("before-consent", { action: "store", content: "Retained policy", processing: "source-only" })).status, 409);
    assert.equal((await route("POST", "/memory/durable/init", { target, retain: true })).status, 200);
    const stored = await post("source", { action: "store", content: "Retry policy contact is example@example.invalid.", processing: "source-only" });
    assert.equal(stored.status, 200, stored.body); const id = JSON.parse(stored.body).result.id as string;
    const scope: MemoryPartitionScope = { ownerId: principal?.id ?? "owner", kind: "user", ...(enterprise ? { tenantId: "alpha" } : {}) };
    const before = app.memoryCustody.partition(scope).read();
    assert.match(before.entries[0]!.lesson.content, /\[REDACTED-PII\]/u);
    assert.ok(!before.entries[0]!.lesson.content.includes("example@example.invalid"));
    for (const processing of [["source-only"], ["configured-provider"], null, {}, true, 0, "automatic"]) {
      for (const command of [{ action: "store", content: "Invalid mode" }, { action: "correct", id, content: "Invalid successor" }, { action: "recall", query: "retry" }]) {
        const response = await post("invalid", { ...command, processing });
        assert.equal(response.status, 409, response.body);
        assert.equal(JSON.parse(response.body).reason, "invalid-request");
      }
    }
    assert.equal(calls, 0, "malformed processing must never select the configured embedding path");
    assert.deepEqual(app.memoryCustody.partition(scope).read(), before, "rejection publishes no access, source, receipt or revision");
    const denied = await post("forged", { action: "correct", id, content: "Forged authority", processing: "source-only", consentEventId: "caller-consent" });
    assert.equal(denied.status, 409);
    const failure = await post("explicit-embedding", { action: "correct", id, content: "Retained updated policy", processing: "configured-provider" });
    assert.equal(failure.status, 409); assert.equal(calls, 1);
    assert.deepEqual(app.memoryCustody.partition(scope).read(), before, "failed explicit embedding cannot retire its source-only predecessor");
    // The same operation cannot change modes after success, including after restart.
    const corrected = await post("correct", { action: "correct", id, content: "Retained retry policy is seven." });
    assert.equal(corrected.status, 200, corrected.body); const newId = JSON.parse(corrected.body).result.newId as string;
    const recall = { action: "recall", query: "retry", processing: "source-only" };
    assert.deepEqual(JSON.parse((await post("recall", recall)).body).result.hits.map((hit: { id: string }) => hit.id), [newId]);
    const after = app.memoryCustody.partition(scope).read();
    app = composeKeep({ dataDir, developmentProvider: provider }); route = durableRoute(app, principal);
    const replay = await post("correct", { action: "correct", id, content: "Retained retry policy is seven." });
    assert.equal(replay.status, 200, replay.body); assert.equal(JSON.parse(replay.body).reconciled, true);
    assert.equal((await post("correct", { action: "correct", id, content: "Retained retry policy is seven.", processing: "configured-provider" })).status, 409);
    assert.deepEqual(app.memoryCustody.partition(scope).read(), after);
    assert.equal((await post("forget", { action: "forget", id: newId })).status, 200);
    assert.deepEqual(JSON.parse((await post("recall", recall)).body).result.hits, [], "replay rechecks current source status");
    assert.equal(calls, 1, "only the explicitly requested configured-provider correction attempted embedding");
  });

  test(`source-only ${enterprise ? "enterprise scoped" : "owner"}: mixed durable custody, literal replay, safe correction and no embedding`, async t => {
    const f = durableFixture(t, { ownerId: "owner", kind: "user", ...(enterprise ? { tenantId: "alpha" } : {}) });
    let at = Date.now(), calls = 0, allowed = true;
    const authority = { admission: { actorId: "owner", actorKind: "human", role: "owner", permission: "memory.write" }, consentEventId: "retention-consent", clock: () => at, authorize: () => allowed };
    const old = committed(await executeDurableMemoryMutation({ ...f, ...authority }, "old", { action: "store", content: "Retry policy uses seven attempts.", useUntil: at + 60000 }));
    const oldId = (old.result as { id: string }).id, oldRow = structuredClone(f.partition.read().entries[0]!);
    assert.equal(oldRow.lesson.custody?.schema, "keep.memory.manual-custody/v1"); assert.ok(oldRow.embedding);
    const provider: ModelProvider = { name: "chat-only", isLocal: true, generate: async () => { throw new Error("no model use in retention"); }, embed: async () => { calls++; throw new Error("embedding unsupported"); } };
    const context = { ...f, ...authority, gateway: new ModelGateway(provider) };
    const command = { action: "store" as const, content: "Retry saturation is capped at six attempts.", processing: "source-only" as const, useUntil: at + 60000 };
    const stored = committed(await executeDurableMemoryMutation(context, "new", command));
    const id = (stored.result as { id: string }).id;
    assert.deepEqual(f.partition.read().entries.find(row => row.lesson.id === oldId), oldRow, "old vector and facts are not rewritten");
    const next = f.partition.read().entries.find(row => row.lesson.id === id)!;
    assert.equal(next.lesson.custody?.schema, "keep.memory.manual-custody/v2"); assert.equal(next.embedding, undefined);
    assert.equal(next.lesson.custody?.dependencies.embeddingProvider, null);
    assert.equal(committed(await executeDurableMemoryMutation(context, "new", command)).reconciled, true);
    assert.equal((await executeDurableMemoryMutation(context, "new", { ...command, processing: "configured-provider" })).disposition, "rejected");
    const recalled = committed(await executeDurableMemoryMutation(context, "recall", { action: "recall", query: "retry", processing: "source-only", k: 100 }));
    assert.deepEqual(new Set((recalled.result as { hits: { id: string }[] }).hits.map(hit => hit.id)), new Set([oldId, id]));
    const vector = committed(await executeDurableMemoryMutation({ ...f, ...authority }, "vector", { action: "recall", query: "retry" }));
    assert.equal((vector.result as { retrieval: { coverageAtSelection: { unrepresentedSources: number } } }).retrieval.coverageAtSelection.unrepresentedSources, 1);
    const derived = committed(await executeDurableMemoryMutation(context, "derived", { action: "consolidate", sourceIds: [oldId, id] }));
    const derivedId = (derived.result as { id: string }).id;
    const corrected = committed(await executeDurableMemoryMutation(context, "correct", { action: "correct", id, content: "Retry saturation is capped at eight attempts." }));
    const successor = (corrected.result as { newId: string }).newId;
    const after = new FileMemoryPartition(f.options).read();
    assert.equal(after.entries.find(row => row.lesson.id === successor)?.lesson.custody?.schema, "keep.memory.manual-custody/v2");
    assert.equal(after.entries.find(row => row.lesson.id === successor)?.lesson.custody?.retention.useUntil, at + 60000);
    const current = committed(await executeDurableMemoryMutation(context, "after", { action: "recall", query: "retry", processing: "source-only" }));
    assert.ok(!(current.result as { hits: { id: string }[] }).hits.some(hit => hit.id === derivedId || hit.id === id));
    const unconsented = await executeDurableMemoryMutation({ ...context, consentEventId: "another-consent" }, "wrong-consent", { action: "correct", id: successor, content: "Synthetic replacement" });
    assert.equal(unconsented.disposition, "rejected");
    allowed = false;
    assert.equal((await executeDurableMemoryMutation(context, "denied", command)).disposition, "rejected");
    allowed = true; at += 60000;
    const expired = committed(await executeDurableMemoryMutation(context, "expired", { action: "recall", query: "retry", processing: "source-only" }));
    assert.deepEqual((expired.result as { hits: unknown[] }).hits, []);
    assert.equal(calls, 0, "source-only operations never probe an embedding API");
    assert.equal((await executeDurableMemoryMutation(context, "legacy-failure", { action: "store", content: "Legacy omitted mode still embeds." })).disposition, "held");
    assert.equal(calls, 1, "legacy failure is not silently retried in source-only mode");
  });

  test(`source-only ${enterprise ? "enterprise resolved gateway" : "owner"}: ordinary CLI defaults survive restart`, async t => {
    const { root } = fixture(t), dataDir = join(root, "source-app"); let calls = 0;
    const provider: ModelProvider = { name: "chat-only", isLocal: true, generate: async () => { throw new Error("unexpected model call"); }, embed: async () => { calls++; throw new Error("no embeddings"); } };
    let app = composeKeep({ dataDir, developmentProvider: provider });
    const principal: Principal | undefined = enterprise ? { id: "alice", kind: "human", role: "maintainer", tenant: "alpha" } : undefined;
    const output: string[] = [], io: CliIO = { write: line => { output.push(line); }, prompt: async () => "" };
    const cli = (args: string[]) => runGatewayCli(["memory", ...args], io, { gateway: req => handleGatewayRequest(app, req, { token: "fixture", ...(principal ? { principalFor: () => principal } : {}) }), gatewayToken: "fixture" });
    assert.equal((await cli(["init", "--retain"])).exitCode, 0);
    assert.equal((await cli(["store", "Retry schedule follows retained policy.", "--durable", "--operation-id=source"])).exitCode, 0, output.join("\n"));
    const id = output.join("\n").match(/Stored\. id=(\S+)/u)![1]!;
    app = composeKeep({ dataDir, developmentProvider: provider });
    assert.equal((await cli(["recall", "retry schedule", "--durable"])).exitCode, 0, output.join("\n"));
    assert.match(output.join("\n"), /Retry schedule follows retained policy/u);
    assert.equal((await cli(["correct", id, "Retry schedule follows corrected policy.", "--durable"])).exitCode, 0, output.join("\n"));
    assert.equal((await cli(["store", "rejected", "--durable", "--processing=source-only", "--processing=configured-provider"])).exitCode, 2);
    assert.equal((await cli(["list", "--durable", "--processing=source-only"])).exitCode, 2);
    assert.equal(calls, 0);
  });
}

for (const enterprise of [false, true]) test(`${enterprise ? "enterprise" : "owner"}: query-focused consolidation persists exact tails with unchanged sources and command-bound intent`, async t => {
  const { root } = fixture(t), dataDir = join(root, "focused"); let modelCalls = 0;
  const provider: ModelProvider = { name: "no-model", isLocal: true,
    embed: async () => { modelCalls++; throw new Error("unexpected embedding"); }, generate: async () => { modelCalls++; throw new Error("unexpected generation"); } };
  let app = composeKeep({ dataDir, developmentProvider: provider });
  const principal: Principal | undefined = enterprise ? { id: "alice", kind: "human", role: "maintainer", tenant: "alpha" } : undefined;
  const scope: MemoryPartitionScope = { ownerId: principal?.id ?? "owner", kind: "user", ...(enterprise ? { tenantId: "alpha" } : {}) };
  const invoke = async (args: string[], expected = 0) => {
    const output: string[] = [];
    const result = await runGatewayCli(["memory", ...args], { write: line => output.push(line), prompt: async () => "" },
      { gateway: req => handleGatewayRequest(app, req, { token: "fixture", ...(principal ? { principalFor: () => principal } : {}) }), gatewayToken: "fixture" });
    assert.equal(result.exitCode, expected, output.join("\n")); return output.join("\n");
  };
  await invoke(["init", "--retain"]);
  const facts = ["Migration retry allowance is three, not seven.", "Current scheduler retry allowance is seven."];
  const ids: string[] = [];
  for (const [i, fact] of facts.entries()) {
    const output = await invoke(["store", "🦉 Background. ".repeat(170) + fact, "--durable", "--operation-id=source-" + i]);
    ids.push(output.match(/Stored\. id=(\S+)/u)![1]!);
  }
  const originals = app.memoryCustody!.partition(scope).read().entries;
  const prefix = await invoke(["consolidate", ...ids, "--operation-id=prefix"]);
  const prefixId = prefix.match(/originals retained\. id=(\S+)/u)![1]!;
  assert.ok(!app.memoryCustody!.partition(scope).read().entries.find(row => row.lesson.id === prefixId)!.lesson.content.includes("allowance"));
  const args = ["consolidate", ...ids, "--operation-id=focused", "--query=migration scheduler retry allowance"];
  const result = await invoke(args), id = result.match(/originals retained\. id=(\S+)/u)![1]!;
  assert.match(result, /Partial task-focused excerpts/u); assert.match(result, /prefixes: 0/u);
  assert.ok((await invoke(args)).includes(id), "exact replay returns the same view");
  await invoke([...args.slice(0, -1), "--query=different request"], 1);
  const beforeRestart = app.memoryCustody!.partition(scope).read();
  assert.deepEqual(beforeRestart.entries.filter(row => ids.includes(row.lesson.id)), originals);
  app = composeKeep({ dataDir, developmentProvider: provider });
  const view = app.memoryCustody!.partition(scope).read().entries.find(row => row.lesson.id === id)!.lesson;
  assert.ok(facts.every(fact => view.content.includes(fact))); assert.equal(view.custody!.authority, "none");
  assert.equal(view.custody!.schema, "keep.memory.derived-custody/v1");
  if (view.custody!.schema !== "keep.memory.derived-custody/v1") throw new Error("wrong view schema");
  assert.ok(view.custody!.sources.every(source => source.startByte > 0 && source.endByte - source.startByte <= 512));
  const memory = createTaskMemoryContext({ partition: app.memoryCustody!.partition(scope), scope,
    selection: { scope: "user", processing: "configured-provider" }, provider, authorize: () => true });
  const slice = memory.select("migration scheduler retry allowance", provider);
  assert.ok(slice.prompt.includes(id)); assert.ok(facts.every(fact => slice.prompt.includes(fact)));
  assert.ok(memory.read!(ids[0]!, 0, 512, provider).prompt.includes("Background"), "view retains access to original omitted material");
  for (const bad of ["--query=", "--query=🦉", "--query=" + "x".repeat(1025), "--query"]) await invoke(["consolidate", ...ids, bad], 2);
  await invoke(["consolidate", ...ids, "--query=a", "--query=b"], 2);
  await invoke(["list", "--durable", "--query=unsupported"], 2);
  const route = durableRoute(app, principal);
  for (const query of [null, 1, {}, [], true, "", "🦉", "x".repeat(1025)]) {
    const rejected = await route("POST", "/memory/durable", { target: { scope: "user" }, operationId: "bad-query", command: { action: "consolidate", sourceIds: ids, query } });
    assert.equal(rejected.status, 409, rejected.body);
  }
  await invoke(["correct", ids[0]!, "Migration retry allowance is five.", "--durable"]);
  assert.throws(() => memory.assertCurrent(provider), /source-changed/u);
  const reviewed = await invoke(["review", id, "--durable"]); assert.ok(!reviewed.includes(facts[0]!));
  assert.equal(modelCalls, 0);
});

test("derived commands: no model work, closed inputs, locked revocation and corrected-source read mediation", async t => {
  const f = durableFixture(t, { ownerId: "owner", kind: "user" }); let embeddings = 0;
  const context = { ...f, gateway: new ModelGateway({ name: "counted", isLocal: true, embed: async texts => { embeddings++; return texts.map(() => [1]); },
    generate: async () => { throw new Error("consolidation must not generate"); } }),
    admission: { actorId: "owner", actorKind: "human", role: "owner", permission: "memory.write" }, consentEventId: "consent" };
  const a = committed(await executeDurableMemoryMutation(context, "a", { action: "store", content: "Retry policy is seven. " + "Background context. ".repeat(60) })).result as { id: string };
  const b = committed(await executeDurableMemoryMutation(context, "b", { action: "store", content: "Pending task: correct retry configuration." })).result as { id: string };
  assert.equal(embeddings, 2);
  for (const command of [{ action: "consolidate", sourceIds: [a.id] }, { action: "consolidate", sourceIds: [a.id, a.id] },
    { action: "consolidate", sourceIds: [a.id, b.id], content: "Invented summary" }, { action: "consolidate", sourceIds: [a.id, "missing"] }]) {
    assert.equal((await executeDurableMemoryMutation(context, "invalid", command as Parameters<typeof executeDurableMemoryMutation>[2])).disposition, "rejected");
  }
  let checks = 0;
  const denied = await executeDurableMemoryMutation({ ...context, authorize: () => ++checks < 3 }, "revoked", { action: "consolidate", sourceIds: [a.id, b.id] });
  assert.equal(denied.disposition, "rejected"); assert.equal(checks, 3, "fresh authority rechecked inside publication lock");
  assert.equal(f.partition.read().entries.length, 2); assert.equal(embeddings, 2);
  const result = committed(await executeDurableMemoryMutation(context, "view", { action: "consolidate", sourceIds: [a.id, b.id] }));
  const id = (result.result as { id: string }).id;
  const repeat = committed(await executeDurableMemoryMutation(context, "view", { action: "consolidate", sourceIds: [a.id, b.id] }));
  assert.equal((repeat.result as { id: string }).id, id); assert.equal(embeddings, 2);
  const snapshot = f.partition.read(), before = MemoryStore.fromPartition(snapshot, f.spine, context.gateway);
  assert.ok(memoryReview(before, id)?.content?.includes("Retry policy is seven."));
  assert.ok(Buffer.byteLength(memoryReview(before, id)!.content!) < Buffer.byteLength(snapshot.entries[0]!.lesson.content));
  assert.ok(!(await before.retrieve("retry", 8)).some(hit => hit.lesson.id === id), "no fake-vector retrieval");
  committed(await executeDurableMemoryMutation(context, "correct-parent", { action: "correct", id: a.id, content: "Retry policy is eight." }));
  const after = MemoryStore.fromPartition(new FileMemoryPartition(f.options).read(), f.spine, context.gateway);
  const reviewed = memoryReview(after, id);
  assert.equal(reviewed?.content, undefined); assert.equal(reviewed?.useStatus, "source-not-current");
  assert.ok(!memoryList(after).some(item => item.id === id));
  assert.ok(memoryList(after, {}, true).some(item => item.id === id), "administrative history survives");
});

test("consolidation gateway requires both read and write authority, not just retention consent", async t => {
  const { root } = fixture(t); const rbac = new RbacAuthorizer(); let deniedPermission = "";
  const app = composeKeep({ dataDir: join(root, "permissions"), authorization: {
    authorize: (actor, permission) => permission === deniedPermission ? { allow: false, reason: "denied" } : rbac.authorize(actor, permission) } });
  const request = (path: string, body: unknown) => handleGatewayRequest(app, { method: "POST", path, query: {}, headers: { authorization: "Bearer fixture" },
    body: JSON.stringify(body) }, { token: "fixture" });
  const target = { scope: "user" };
  assert.equal((await request("/memory/durable/init", { target, retain: true })).status, 200);
  const ids: string[] = [];
  for (const content of ["Retry policy seven.", "Pending retry task."]) {
    const stored = await request("/memory/durable", { target, operationId: content, command: { action: "store", content } });
    assert.equal(stored.status, 200, stored.body); ids.push(JSON.parse(stored.body).result.id);
  }
  for (const permission of ["memory.read", "memory.write"]) {
    deniedPermission = permission;
    const response = await request("/memory/durable", { target, operationId: "derive", command: { action: "consolidate", sourceIds: ids } });
    assert.equal(response.status, 403, response.body);
  }
  deniedPermission = "";
  assert.equal((await request("/memory/durable", { target, operationId: "derive", command: { action: "consolidate", sourceIds: ids } })).status, 200);
});

for (const scope of [
  { ownerId: "owner", kind: "project", projectId: "project" },
  { ownerId: "owner", tenantId: "tenant", kind: "agent", projectId: "project", agentId: "agent" },
] satisfies MemoryPartitionScope[]) {
  test(`durable ${scope.tenantId ? "enterprise" : "n1"} memory: existing store/correction methods commit and a fresh process continues`, async t => {
    const context = durableFixture(t, scope);
    const first = committed(await executeDurableMemoryMutation(context, "first", { action: "store", content: "Synthetic durable source fact", kind: "fact" }));
    assert.equal(first.audit, "delivered");
    const id = (first.result as { id: string }).id;
    const memory = context.partition.read().entries[0]!.lesson;
    const audit = context.spine.currentEvents().find(event => event.payload["memoryEventId"] === memory.provenanceEventId);
    assert.ok(audit); assert.equal(audit.payload["projectId"], scope.projectId);
    assert.equal(audit.payload["tenant"], scope.tenantId);
    const base = new URL("../src/", import.meta.url);
    const source = `
      import { FileMemoryPartition } from ${JSON.stringify(new URL("memory/persistence.js", base).href)};
      import { executeDurableMemoryMutation } from ${JSON.stringify(new URL("memory/memory_tools.js", base).href)};
      import { Spine } from ${JSON.stringify(new URL("spine/spine.js", base).href)};
      import { FileSpineStore } from ${JSON.stringify(new URL("spine/store.js", base).href)};
      import { InProcessLock } from ${JSON.stringify(new URL("lock/lock.js", base).href)};
      import { SchemaRegistry } from ${JSON.stringify(new URL("spine/upcaster.js", base).href)};
      import { ModelGateway } from ${JSON.stringify(new URL("gateway/gateway.js", base).href)};
      import { LocalProvider } from ${JSON.stringify(new URL("gateway/local_provider.js", base).href)};
      const [options, audit, id] = JSON.parse(process.argv[1]);
      const context = { partition: new FileMemoryPartition(options), spine: new Spine(new FileSpineStore(audit, { fsync: true }), new InProcessLock(), new SchemaRegistry()), gateway: new ModelGateway(new LocalProvider()), authorize: () => true };
      process.stdout.write(JSON.stringify(await executeDurableMemoryMutation(context, "correct", { action: "correct", id, content: "Synthetic durable corrected fact" })));
    `;
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", source, JSON.stringify([context.options, join(context.root, "audit"), id])], { encoding: "utf8", timeout: 5000, maxBuffer: 1024 * 1024 });
    assert.equal(child.status, 0, child.stderr);
    const corrected = committed(JSON.parse(child.stdout) as DurableMemoryMutationResult);
    assert.equal(corrected.audit, "delivered");
    const newId = (corrected.result as { newId: string }).newId;
    const view = new FileMemoryPartition(context.options).read();
    assert.equal(view.revision, 2); assert.equal(view.entries.length, 2);
    assert.equal(view.entries.find(row => row.lesson.id === id)?.lesson.tier, "retired");
    assert.equal(view.entries.find(row => row.lesson.id === newId)?.lesson.citation, `supersedes:${id}`);
    assert.equal(view.entries.find(row => row.lesson.id === newId)?.lesson.scope, scope.kind);
    assert.equal(context.spine.currentEvents().filter(event => event.actor === "memory-outbox").length, 2);
  });
}

test("durable commands retain update/forget/purge behavior in one complete selected partition", async t => {
  const context = durableFixture(t);
  const first = committed(await executeDurableMemoryMutation(context, "one", { action: "store", content: "First synthetic decision", kind: "decision" }));
  const second = committed(await executeDurableMemoryMutation(context, "two", { action: "store", content: "Second synthetic decision", kind: "decision" }));
  const id = (first.result as { id: string }).id;
  assert.equal(committed(await executeDurableMemoryMutation(context, "weight", { action: "update", id, importance: 0.9 })).result, true);
  assert.equal(context.partition.read().entries.find(row => row.lesson.id === id)?.lesson.importance, 0.9);
  assert.equal(committed(await executeDurableMemoryMutation(context, "forget", { action: "forget", id })).result, true);
  const purged = committed(await executeDurableMemoryMutation(context, "purge", { action: "purge", filter: { kind: "decision" } }));
  assert.deepEqual(purged.result, { purged: 1, ids: [(second.result as { id: string }).id] });
  assert.ok(context.partition.read().entries.every(row => row.lesson.tier === "retired"));
});

test("durable command ambiguity reconciles the original result without another embedding or successor", async t => {
  const context = durableFixture(t); let calls = 0; const original = context.provider.embed.bind(context.provider);
  context.provider.embed = async texts => { calls++; return original(texts); };
  const writer = new FileMemoryPartition({ ...context.options, fault: point => { if (point === "after-rename") throw new Error("uncertain commit"); } });
  const command = { action: "store", content: "Synthetic ambiguous write" } as const;
  const first = await executeDurableMemoryMutation({ ...context, partition: writer }, "same", command);
  assert.equal(first.disposition, "held"); assert.equal(context.spine.currentEvents().length, 0);
  const id = context.partition.read().entries[0]!.lesson.id;
  const retry = committed(await executeDurableMemoryMutation(context, "same", command));
  assert.equal(retry.reconciled, true); assert.equal(retry.audit, "delivered");
  assert.deepEqual(retry.result, { id }); assert.equal(calls, 1); assert.equal(context.partition.read().revision, 1);
  assert.equal((await executeDurableMemoryMutation(context, "same", { ...command, content: "Changed request" })).disposition, "rejected");
  assert.equal(calls, 1);
});

test("erased retries never embed or re-ingest, while a pending original outbox still delivers once", async t => {
  const context = durableFixture(t); const stage = context.spine.stage.bind(context.spine);
  context.spine.stage = () => { throw new Error("synthetic offline audit"); };
  const command = { action: "store", content: "Synthetic erasable retry" } as const;
  const original = committed(await executeDurableMemoryMutation(context, "original", command));
  assert.equal(original.audit, "pending");
  const id = (original.result as { id: string }).id;
  assert.equal(context.partition.controlCommand("erase", { action: "erase", id }, { actorId: "owner", actorKind: "human", role: "owner", permission: "memory.forget" }).disposition, "committed");
  context.spine.stage = stage; let calls = 0;
  const embed = context.provider.embed.bind(context.provider);
  context.provider.embed = async texts => { calls++; return embed(texts); };
  assert.deepEqual(await executeDurableMemoryMutation(context, "original", command), { disposition: "withheld", operationId: "original", revision: 1, reason: "receipt-erased" });
  assert.equal(calls, 0); assert.equal(context.partition.read().entries.length, 0);
  assert.equal(committed(await executeDurableMemoryMutation(context, "fresh", { action: "store", content: "Synthetic independent memory" })).audit, "delivered");
  const events = context.spine.currentEvents();
  assert.equal(events.filter(event => event.payload["lessonId"] === id).length, 1, "the original admission survives receipt revocation and is delivered once");
  assert.equal(context.partition.read().entries.length, 1);
});

test("audit failure after admission is committed/audit-pending; an uncertain append is deduplicated", async t => {
  const context = durableFixture(t); const stage = context.spine.stage.bind(context.spine);
  context.spine.stage = event => { stage(event); throw new Error("acknowledgment lost after append"); };
  const command = { action: "store", content: "Synthetic audit-pending memory" } as const;
  const first = committed(await executeDurableMemoryMutation(context, "original", command));
  assert.equal(first.audit, "pending"); assert.equal(context.partition.read().revision, 1);
  context.spine.stage = stage;
  context.provider.embed = async () => { throw new Error("reconciliation must not prepare again"); };
  const second = committed(await executeDurableMemoryMutation(context, "original", command));
  assert.equal(second.audit, "delivered"); assert.equal(second.reconciled, true);
  assert.deepEqual(second.result, first.result); assert.equal(context.spine.currentEvents().length, 1);
});

test("failed preparation or prepublication failure emits no accepted audit and leaves no memory mutation", async t => {
  const context = durableFixture(t);
  const writer = new FileMemoryPartition({ ...context.options, fault: point => { if (point === "before-rename") throw new Error("write failed"); } });
  assert.equal((await executeDurableMemoryMutation({ ...context, partition: writer }, "failed", { action: "store", content: "Synthetic failed write" })).disposition, "held");
  assert.equal(context.partition.read().revision, 0); assert.equal(context.spine.currentEvents().length, 0);
  context.provider.embed = async () => { throw new Error("provider preparation failed"); };
  assert.equal((await executeDurableMemoryMutation(context, "failed-preparation", { action: "store", content: "Synthetic failed preparation" })).disposition, "held");
  assert.equal(context.partition.read().entries.length, 0); assert.equal(context.spine.currentEvents().length, 0);
});

test("authorization is checked before data access and again after asynchronous preparation", async t => {
  const context = durableFixture(t); let allowed = false; let calls = 0;
  const original = context.provider.embed.bind(context.provider);
  context.provider.embed = async texts => { calls++; allowed = false; return original(texts); };
  const command = { action: "store", content: "Synthetic gated memory" } as const;
  const guarded = { ...context, authorize: () => allowed };
  assert.deepEqual(await executeDurableMemoryMutation(guarded, "denied", command), { disposition: "rejected", operationId: "denied", reason: "unauthorized" });
  assert.equal(calls, 0); allowed = true;
  assert.deepEqual(await executeDurableMemoryMutation(guarded, "revoked", command), { disposition: "rejected", operationId: "revoked", reason: "unauthorized" });
  assert.equal(calls, 1); assert.equal(context.partition.read().revision, 0); assert.equal(context.spine.currentEvents().length, 0);
});

test("partition working-copy read paths are defensive and preserve real project versus tenant identity", async t => {
  const context = durableFixture(t, { ownerId: "owner", tenantId: "tenant", projectId: "project", kind: "project" });
  const result = committed(await executeDurableMemoryMutation(context, "store", { action: "store", content: "Synthetic scoped fact" }));
  const id = (result.result as { id: string }).id;
  const working = MemoryStore.fromPartition(context.partition.read(), context.spine, context.gateway);
  assert.equal(working.getForProject("tenant", id), undefined);
  assert.equal(working.allForProject("tenant").length, 0);
  const hits = await working.retrieve("Synthetic scoped fact", 5);
  assert.equal(hits.length, 1);
  for (const row of [working.get(id)!, working.getForProject("project", id)!, working.all()[0]!, working.allForProject("project")[0]!, working.validAt(Date.now())[0]!, hits[0]!.lesson]) {
    assert.throws(() => { row.content = "forged mutable escape"; }, TypeError);
  }
  const access = working.accessOf(id)!;
  assert.throws(() => { (access as { count: number }).count = 999; }, TypeError);
  assert.throws(() => working.recordOutcome(id, true, "self-approved"), /independent qualification/u);
  assert.equal(context.partition.read().entries[0]!.access.count, 0, "working-copy retrieval alone is not committed access evidence");
});

test("visible audit bytes with failed fsync remain pending until real carrier confirmation succeeds", async t => {
  const context = durableFixture(t); let failSync = false; let confirmations = 0;
  const spine = new Spine(new FileSpineStore(join(context.root, "injected-audit"), { fsync: true, io: {
    ...NODE_IO, fsyncSync: fd => { if (failSync) throw new Error("synthetic fsync failure"); confirmations++; NODE_IO.fsyncSync(fd); },
  } }), new InProcessLock(), new SchemaRegistry());
  failSync = true;
  const command = { action: "store", content: "Synthetic visible but unconfirmed audit" } as const;
  const first = committed(await executeDurableMemoryMutation({ ...context, spine }, "original", command));
  assert.equal(first.audit, "pending"); assert.equal(spine.currentEvents().length, 1);
  const second = committed(await executeDurableMemoryMutation({ ...context, spine }, "original", command));
  assert.equal(second.audit, "pending", "visible bytes do not establish durable delivery");
  const priorCount = confirmations; failSync = false;
  const third = committed(await executeDurableMemoryMutation({ ...context, spine }, "original", command));
  assert.equal(third.audit, "delivered"); assert.ok(confirmations >= priorCount + 4);
  assert.equal(spine.currentEvents().length, 1, "reconciliation must not append ritual marker events");
  assert.equal(context.partition.read().revision, 1);
});

test("authorization revoked during audit delivery withholds results without claiming rollback", async t => {
  const context = durableFixture(t); let allowed = true;
  const stage = context.spine.stage.bind(context.spine);
  context.spine.stage = event => { const id = stage(event); allowed = false; return id; };
  const result = await executeDurableMemoryMutation({ ...context, authorize: () => allowed }, "original", { action: "store", content: "Synthetic revocation during audit" });
  assert.deepEqual(result, { disposition: "committed-withheld", operationId: "original", revision: 1, audit: "delivered", reason: "authorization-revoked" });
  assert.equal(context.partition.read().entries.length, 1);
  assert.equal("result" in result, false);
});

for (const sameOperation of [false, true]) {
  test(`concurrent preparation ${sameOperation ? "reconciles the same command winner" : "conflicts without publishing a stale command or audit"}`, async t => {
    const context = durableFixture(t); let ready!: () => void; let release!: () => void;
    const started = new Promise<void>(resolve => { ready = resolve; });
    const resumed = new Promise<void>(resolve => { release = resolve; }); t.after(release);
    const waitingProvider = new LocalProvider(); const embed = waitingProvider.embed.bind(waitingProvider);
    waitingProvider.embed = async texts => { ready(); await resumed; return embed(texts); };
    const command = { action: "store", content: "Synthetic concurrent memory" } as const;
    const pending = executeDurableMemoryMutation({ ...context, gateway: new ModelGateway(waitingProvider) }, "original", command);
    await started;
    const winner = committed(await executeDurableMemoryMutation(context, sameOperation ? "original" : "winner", command));
    release(); const late = await pending;
    if (sameOperation) { const replay = committed(late); assert.equal(replay.reconciled, true); assert.deepEqual(replay.result, winner.result); }
    else assert.deepEqual(late, { disposition: "conflict", operationId: "original", revision: 1 });
    assert.equal(context.partition.read().revision, 1); assert.equal(context.partition.read().entries.length, 1);
    assert.equal(context.spine.currentEvents().length, 1);
  });
}

function durableRoute(app: ReturnType<typeof composeKeep>, principal?: Principal) {
  return (method: string, path: string, body?: unknown, query: Record<string, string> = {}) => handleGatewayRequest(app,
    { method, path, body: body === undefined ? "" : JSON.stringify(body), query, headers: { authorization: "Bearer memory-fixture" } },
    { token: "memory-fixture", ...(principal === undefined ? {} : { principalFor: () => principal }) });
}

for (const enterprise of [false, true]) {
  test(`${enterprise ? "enterprise" : "owner"}: real gateway holds refuse erasure; release/restart/replay revoke only the selected item`, async t => {
    const { root } = fixture(t), dataDir = join(root, "app"); const app = composeKeep({ dataDir });
    const principal: Principal | undefined = enterprise ? { id: "alice", kind: "human", role: "maintainer", tenant: "alpha" } : undefined;
    const project = enterprise ? app.projectManager!.create({ name: "Erasure project", tenant: "alpha" }) : undefined;
    const target = project ? { scope: "project", projectId: project.id } : { scope: "user" };
    let route = durableRoute(app, principal);
    assert.equal((await route("POST", "/memory/durable/init", { target, retain: true })).status, 200);
    const store = async (operationId: string, content: string) => {
      const result = await route("POST", "/memory/durable", { target, operationId, command: { action: "store", content } });
      assert.equal(result.status, 200, result.body); return JSON.parse(result.body).result.id as string;
    };
    const id = await store("remove", "Synthetic memory to erase"), survivor = await store("survivor", "Synthetic memory to retain");
    const request = (operationId: string, command: unknown) => route("POST", "/memory/durable", { target, operationId, command });
    const recall = { action: "recall", query: "Synthetic memory", k: 100 };
    assert.ok(JSON.parse((await request("original-read", recall)).body).result.hits.some((hit: { id: string }) => hit.id === id));
    const corrected = await request("correct", { action: "correct", id, content: "Synthetic derived correction" });
    assert.equal(corrected.status, 200, corrected.body); const derivativeId = JSON.parse(corrected.body).result.newId;
    const held = await request("hold", { action: "hold", id: derivativeId, holdId: "matter-a", active: true });
    assert.equal(held.status, 200, held.body);
    if (enterprise) {
      for (const other of [{ ...principal!, id: "foreign", tenant: "beta" }, { ...principal!, id: "viewer", role: "viewer" as const }]) {
        const denied = await durableRoute(app, other)("POST", "/memory/durable", { target, operationId: "hostile-erase", command: { action: "erase", id } });
        assert.equal(denied.status, 403);
      }
    }
    const blocked = await request("erase-original", { action: "erase", id });
    assert.equal(blocked.status, 409); assert.equal(JSON.parse(blocked.body).reason, "legal-hold");
    assert.equal((await route("GET", "/memory/durable", undefined, { ...target, action: "review", id })).status, 200);
    assert.equal((await request("release", { action: "hold", id: derivativeId, holdId: "matter-a", active: false })).status, 200);
    const erased = await request("erase-original", { action: "erase", id }); assert.equal(erased.status, 200, erased.body);
    assert.deepEqual(JSON.parse(erased.body).result, { id, ids: [id, derivativeId], local: "key-revoked", metadataErasure: "receipt-fingerprints-revoked-provenance-pending", outsideCopies: "pending", mediaSanitization: "unproven" });
    route = durableRoute(composeKeep({ dataDir }), principal);
    const replay = await request("erase-original", { action: "erase", id }); assert.equal(replay.status, 200, replay.body);
    assert.equal(JSON.parse(replay.body).reconciled, true);
    const gone = await route("GET", "/memory/durable", undefined, { ...target, action: "review", id });
    assert.equal(gone.status, 410); assert.equal(gone.body.includes("Synthetic memory to erase"), false);
    assert.equal((await route("GET", "/memory/durable", undefined, { ...target, action: "review", id: derivativeId })).status, 410, "erasure reaches an admitted correction derivative");
    assert.equal((await route("GET", "/memory/durable", undefined, { ...target, action: "review", id: survivor })).status, 200);
    for (const [operationId, command] of [["original-read", recall], ["remove", { action: "store", content: "Synthetic memory to erase" }], ["correct", { action: "correct", id, content: "Synthetic derived correction" }]] as const) {
      const withheld = await request(operationId, command); assert.equal(withheld.status, 410, withheld.body);
      assert.equal(JSON.parse(withheld.body).reason, "receipt-erased");
    }
    const recalled = await request("fresh-read", recall); assert.equal(recalled.status, 200, recalled.body);
    assert.deepEqual(JSON.parse(recalled.body).result.hits.map((hit: { id: string }) => hit.id), [survivor]);
    const audit = app.spine.currentEvents();
    assert.equal(audit.filter(event => event.payload["event"] === "memory.erasure.key-revoked").length, 1);
  });
}

for (const enterprise of [false, true]) {
  test(`${enterprise ? "enterprise" : "owner"}: authenticated custody binds consent and immutable assertion/derivative facts through correction`, async t => {
    const { root } = fixture(t); const dataDir = join(root, "app"), app = composeKeep({ dataDir });
    const principal: Principal | undefined = enterprise ? { id: "alice", kind: "human", role: "maintainer", tenant: "alpha" } : undefined;
    const route = durableRoute(app, principal), target = { scope: "user" };
    assert.equal((await route("POST", "/memory/durable/init", { target, retain: true })).status, 200);
    const deadline = Date.now() + 60000;
    const stored = await route("POST", "/memory/durable", { target, operationId: "custody-store", command: { action: "store", content: "Synthetic attributed fact", useUntil: deadline } });
    assert.equal(stored.status, 200, stored.body); const { result: { id }, receiptId } = JSON.parse(stored.body);
    const restarted = composeKeep({ dataDir }), read = durableRoute(restarted, principal);
    const review = await read("GET", "/memory/durable", undefined, { ...target, action: "review", id });
    assert.equal(review.status, 200, review.body); const detail = JSON.parse(review.body).result;
    assert.deepEqual(detail.custody.source, { kind: "authenticated-manual-command", operationId: receiptId, actorId: principal?.id ?? "owner", actorKind: "human" });
    assert.deepEqual(detail.custody.scope, { ownerId: principal?.id ?? "owner", kind: "user", ...(enterprise ? { tenantId: "alpha" } : {}) });
    assert.equal(detail.custody.assertion, "asserted"); assert.equal(detail.custody.uncertainty, "unassessed");
    assert.equal(detail.custody.authority, "none"); assert.equal(detail.tier, "candidate");
    assert.equal(detail.custody.retention.useUntil, deadline);
    assert.equal(detail.custody.residency.region, "unverified"); assert.equal(detail.custody.dependencies.embeddingModel, null);
    assert.deepEqual(detail.custody.derivatives.coEncrypted, ["embedding", "access"]);
    assert.equal(detail.custody.derivatives.outsideCustody, "caller-provider-backup-copies-untracked");
    const partition = restarted.memoryCustody.partition(detail.custody.scope);
    assert.ok(partition.admissionEvents().some(event => event.id === detail.custody.consentEventId && event.payload["event"] === "memory.retention-consented"));
    const corrected = await read("POST", "/memory/durable", { target, operationId: "custody-correct", command: { action: "correct", id, content: "Synthetic corrected attributed fact" } });
    assert.equal(corrected.status, 200, corrected.body); const newId = JSON.parse(corrected.body).result.newId;
    const successor = JSON.parse((await read("GET", "/memory/durable", undefined, { ...target, action: "review", id: newId })).body).result;
    assert.equal(successor.custody.supersedes, id); assert.equal(successor.custody.retention.useUntil, deadline);
    assert.equal(successor.custody.consentEventId, detail.custody.consentEventId);
    assert.notEqual(successor.custody.source.operationId, detail.custody.source.operationId);
    const view = partition.read(); const prior = view.entries.find(row => row.lesson.id === id)!;
    assert.deepEqual(prior.lesson.custody, detail.custody, "correction preserves original custody");
    const tampered = structuredClone(view.entries) as unknown as { lesson: { custody: { authority: string } } }[];
    tampered[0]!.lesson.custody.authority = "owner";
    assert.equal(partition.commit("forge", view.revision, tampered as unknown as Parameters<FileMemoryPartition["commit"]>[2]).disposition, "rejected");
    const changedDeadline = structuredClone(view.entries) as unknown as { lesson: { custody: { retention: { useUntil: number } } } }[];
    changedDeadline[0]!.lesson.custody.retention.useUntil = deadline + 1;
    assert.deepEqual(partition.commit("renew", view.revision, changedDeadline as unknown as Parameters<FileMemoryPartition["commit"]>[2]),
      { disposition: "rejected", operationId: "renew", reason: "immutable-version" });
    const replay = await read("POST", "/memory/durable", { target, operationId: "custody-read", command: { action: "recall", query: "attributed fact" } });
    assert.equal(replay.status, 200, replay.body);
    assert.deepEqual(JSON.parse(replay.body).result.hits.map((hit: { id: string }) => hit.id), [newId]);
  });
}

test("use expiry withholds content across ordinary review/list/recall/replayed recall without claiming erasure", async t => {
  let now = Date.now(); t.mock.method(Date, "now", () => now);
  const { root } = fixture(t); const dataDir = join(root, "app"), app = composeKeep({ dataDir });
  let route = durableRoute(app); const target = { scope: "user" };
  assert.equal((await route("POST", "/memory/durable/init", { target, retain: true })).status, 200);
  const stored = await route("POST", "/memory/durable", { target, operationId: "expiry-store", command: { action: "store", content: "Synthetic expiring knowledge", useUntil: now + 1000 } });
  assert.equal(stored.status, 200, stored.body); const id = JSON.parse(stored.body).result.id;
  const request = { target, operationId: "expiry-read", command: { action: "recall", query: "expiring knowledge" } };
  assert.equal(JSON.parse((await route("POST", "/memory/durable", request)).body).result.hits.length, 1);
  now += 1000; route = durableRoute(composeKeep({ dataDir }));
  const expired = await route("GET", "/memory/durable", undefined, { ...target, action: "review", id });
  assert.equal(expired.status, 200, expired.body); const detail = JSON.parse(expired.body).result;
  assert.equal(detail.content, undefined); assert.equal(detail.useStatus, "expired-pending-erasure");
  assert.equal(expired.body.includes("Synthetic expiring knowledge"), false);
  assert.deepEqual(JSON.parse((await route("GET", "/memory/durable", undefined, { ...target, action: "list" })).body).result, []);
  assert.deepEqual(JSON.parse((await route("POST", "/memory/durable", request)).body).result.hits, []);
  assert.deepEqual(JSON.parse((await route("POST", "/memory/durable", { ...request, operationId: "new-read" })).body).result.hits, []);
  assert.equal((await route("POST", "/memory/durable", { target, operationId: "renew", command: { action: "correct", id, content: "Synthetic attempted renewal" } })).status, 409);
  const retained = app.memoryCustody.partition({ ownerId: "owner", kind: "user" }).read().entries;
  assert.equal(retained.length, 1); assert.equal(retained[0]!.lesson.content, "Synthetic expiring knowledge", "expiry is not a false crypto-erasure claim");
  assert.equal(retained[0]!.access.count, 1);
});

test("forged custody and expiry during preparation cannot publish a partial successor", async t => {
  const context = durableFixture(t); let now = 1000, calls = 0;
  const admission = { actorId: "human", actorKind: "human", role: "owner", permission: "memory.write" };
  const ctx = { ...context, admission, consentEventId: "actual-fixture-consent", clock: () => now };
  const originalEmbed = context.gateway.embed.bind(context.gateway);
  context.gateway.embed = async texts => { calls++; return originalEmbed(texts); };
  const invalid = await executeDurableMemoryMutation(ctx, "forged", { action: "store", content: "Synthetic forgery", custody: { assertion: "observed" } } as unknown as Parameters<typeof executeDurableMemoryMutation>[2]);
  assert.equal(invalid.disposition, "rejected"); assert.equal(calls, 0);
  const first = committed(await executeDurableMemoryMutation(ctx, "first", { action: "store", content: "Synthetic original", useUntil: 2000 }));
  const id = (first.result as { id: string }).id, before = context.partition.read();
  context.gateway.embed = async texts => { now = 2000; return originalEmbed(texts); };
  const result = await executeDurableMemoryMutation(ctx, "late-correct", { action: "correct", id, content: "Synthetic late successor" });
  assert.ok(result.disposition === "rejected" || (result.disposition === "committed" && result.result === null), JSON.stringify(result));
  assert.deepEqual(context.partition.read().entries, before.entries);
  const working = MemoryStore.fromPartition(context.partition.read(), context.spine, context.gateway, () => now);
  assert.equal(memoryReview(working, id)?.content, undefined); assert.deepEqual(memoryList(working), []);
});

test("ordinary durable CLI initializes, stores, recalls and restarts without enabling automatic conversation retention", async t => {
  const { root } = fixture(t); const dataDir = join(root, "app"); const app = composeKeep({ dataDir });
  assert.equal(existsSync(join(dataDir, "memory-custody")), false, "composition must not initialize retained memory");
  const output: string[] = []; const io: CliIO = { write: text => output.push(text), prompt: async () => { throw new Error("unexpected prompt"); } };
  assert.equal((await runCli(["memory", "init"], io, { app })).exitCode, 1);
  assert.equal(existsSync(join(dataDir, "memory-custody")), false, "missing retention consent must not create custody");
  assert.equal((await runCli(["memory", "init", "--retain"], io, { app })).exitCode, 0, output.join("\n"));
  assert.equal((await runCli(["memory", "store", "Synthetic ordinary persistent fact", "--durable", "--kind=fact", "--operation-id=original"], io, { app })).exitCode, 0, output.join("\n"));
  const id = /^Stored\. id=(.+)$/u.exec(output.at(-1) ?? "")?.[1]; assert.ok(id);
  const restarted = composeKeep({ dataDir }); output.length = 0;
  assert.equal((await runCli(["memory", "review", id, "--durable"], io, { app: restarted })).exitCode, 0, output.join("\n"));
  assert.match(output.join("\n"), /Synthetic ordinary persistent fact/u);
  output.length = 0;
  assert.equal((await runCli(["memory", "recall", "persistent fact", "--durable", "--operation-id=read-original"], io, { app: restarted })).exitCode, 0, output.join("\n"));
  assert.match(output.join("\n"), /Synthetic ordinary persistent fact/u);
  const partition = restarted.memoryCustody.partition({ ownerId: "owner", kind: "user" });
  assert.equal(partition.read().entries[0]!.access.count, 1);
  assert.equal((await runCli(["memory", "recall", "persistent fact", "--durable", "--operation-id=read-original"], io, { app: restarted })).exitCode, 0);
  assert.equal(partition.read().entries[0]!.access.count, 1, "same recall command cannot reinforce twice");
  assert.equal(restarted.secondBrain.memory.all().length, 0, "durable manual opt-in does not silently retain all conversational memory");
});

test("shared project memory follows real tenant/project authority and is not owned by the first writer", async t => {
  const { root } = fixture(t); const app = composeKeep({ dataDir: join(root, "app") });
  const project = app.projectManager!.create({ name: "Synthetic shared project", tenant: "tenant-a" });
  const otherProject = app.projectManager!.create({ name: "Synthetic foreign project", tenant: "tenant-b" });
  const principal: Principal = { id: "alice", kind: "human", role: "maintainer", tenant: "tenant-a" };
  const alice = durableRoute(app, principal), bob = durableRoute(app, { ...principal, id: "bob" });
  const target = { scope: "project", projectId: project.id };
  assert.equal((await alice("POST", "/memory/durable/init", { target, retain: true })).status, 200);
  const stored = await alice("POST", "/memory/durable", { target, operationId: "shared", command: { action: "store", content: "Synthetic shared team knowledge" } });
  assert.equal(stored.status, 200, stored.body); const id = JSON.parse(stored.body).result.id as string;
  const review = await bob("GET", "/memory/durable", undefined, { ...target, action: "review", id });
  assert.equal(review.status, 200, review.body); assert.match(review.body, /Synthetic shared team knowledge/u);
  const foreign = durableRoute(app, { ...principal, id: "mallory", tenant: "tenant-b" });
  assert.equal((await foreign("GET", "/memory/durable", undefined, { ...target, action: "review", id })).status, 403);
  assert.equal((await alice("POST", "/memory/durable/init", { target: { scope: "project", projectId: otherProject.id }, retain: true })).status, 403);
  assert.equal((await alice("POST", "/memory/durable/init", { target: { ...target, tenantId: "tenant-b", ownerId: "mallory" }, retain: true })).status, 400);
  const partition = app.memoryCustody.partition({ ownerId: `project:${project.id}`, kind: "project", projectId: project.id, tenantId: "tenant-a" });
  assert.equal(partition.read().entries.length, 1);
  const another = await bob("POST", "/memory/durable", { target, operationId: "shared", command: { action: "store", content: "Synthetic shared team knowledge" } });
  assert.equal(another.status, 200, another.body);
  assert.notEqual(JSON.parse(another.body).result.id, id, "a teammate's operation id cannot borrow another actor's receipt");
  assert.equal(partition.read().entries.length, 2);
  const admissions = partition.admissionEvents().filter(event => event.payload["event"] === "lesson_ingested");
  assert.deepEqual(admissions.map(event => event.payload["actorId"]).sort(), ["alice", "bob"]);
  assert.ok(admissions.every(event => event.payload["permission"] === "memory.write" && event.payload["terminalDisposition"] === "committed"));
});

test("durable gateway permission checks cannot be switched by putting a read command in initialization", async t => {
  const { root } = fixture(t); const dataDir = join(root, "app"); const app = composeKeep({ dataDir });
  const viewer = durableRoute(app, { id: "viewer", kind: "human", role: "viewer", tenant: "tenant" });
  for (const action of ["recall", "forget"]) {
    const result = await viewer("POST", "/memory/durable/init", { target: { scope: "user" }, retain: true, command: { action, query: "synthetic" } });
    assert.equal(result.status, 403);
  }
  assert.equal(existsSync(join(dataDir, "memory-custody")), false);
});

test("remote-only memory CLI uses the same gateway path and cannot fall back to local owner", async t => {
  const { root } = fixture(t); const app = composeKeep({ dataDir: join(root, "app") });
  const principal: Principal = { id: "operator", kind: "human", role: "operator", tenant: "tenant" };
  const output: string[] = []; const io: CliIO = { write: text => output.push(text), prompt: async () => { throw new Error("unexpected prompt"); } };
  let calls = 0;
  const deps = { gatewayToken: "memory-fixture", gateway: (request: GatewayRequest) => { calls++; return handleGatewayRequest(app, request, { token: "memory-fixture", principalFor: () => principal }); } };
  assert.equal((await runGatewayCli(["memory", "init", "--retain"], io, deps)).exitCode, 0, output.join("\n"));
  assert.equal((await runGatewayCli(["memory", "store", "Synthetic remote memory", "--durable", "--operation-id=remote-original"], io, deps)).exitCode, 0, output.join("\n"));
  const id = /^Stored\. id=(.+)$/u.exec(output.at(-1) ?? "")?.[1]; assert.ok(id);
  assert.equal((await runGatewayCli(["memory", "review", id, "--durable"], io, deps)).exitCode, 0);
  assert.equal((await runGatewayCli(["memory", "forget", id, "--durable", "--operation-id=forbidden"], io, deps)).exitCode, 1);
  assert.equal(calls, 4);
  const invalid = await runGatewayCli(["memory", "list", "--durable"], io, { ...deps, gatewayToken: "incorrect" });
  assert.equal(invalid.exitCode, 1);
});

test("archiving or deleting a project revokes durable writes or access through an already-running gateway", async t => {
  const { root } = fixture(t); const app = composeKeep({ dataDir: join(root, "app") }); const route = durableRoute(app);
  const project = app.projectManager!.create({ name: "Synthetic lifecycle project" }); const target = { scope: "project", projectId: project.id };
  assert.equal((await route("POST", "/memory/durable/init", { target, retain: true })).status, 200);
  app.projectManager!.archive(project.id);
  assert.equal((await route("POST", "/memory/durable", { target, operationId: "archived", command: { action: "store", content: "Synthetic refused archived write" } })).status, 403);
  assert.equal((await route("GET", "/memory/durable", undefined, { ...target, action: "list" })).status, 200);
  app.projectManager!.delete(project.id);
  assert.equal((await route("GET", "/memory/durable", undefined, { ...target, action: "list" })).status, 403);
});

test("private user memory is not shared merely because two humans belong to the same tenant", async t => {
  const { root } = fixture(t); const app = composeKeep({ dataDir: join(root, "app") });
  const alice = durableRoute(app, { id: "alice", kind: "human", role: "maintainer", tenant: "team" });
  const bob = durableRoute(app, { id: "bob", kind: "human", role: "maintainer", tenant: "team" });
  const target = { scope: "user" };
  assert.equal((await alice("POST", "/memory/durable/init", { target, retain: true })).status, 200);
  assert.equal((await bob("POST", "/memory/durable/init", { target, retain: true })).status, 200);
  const stored = await alice("POST", "/memory/durable", { target, operationId: "private", command: { action: "store", content: "Synthetic private preference" } });
  const id = JSON.parse(stored.body).result.id as string;
  assert.equal((await bob("GET", "/memory/durable", undefined, { scope: "user", action: "review", id })).status, 404);
});

test("delegated agent memory uses its live parent authority and revocation removes access", async t => {
  const { root } = fixture(t); const parent: Principal = { id: "alice", kind: "human", role: "owner", tenant: "team" };
  const app = composeKeep({ dataDir: join(root, "app"), delegationParentFor: (id, tenant) => id === parent.id && tenant === parent.tenant ? parent : undefined });
  const human = durableRoute(app, parent); const target = { scope: "agent", agentId: "worker" };
  assert.equal((await human("POST", "/memory/durable/init", { target, retain: true })).status, 200);
  const principal = await app.authorization.issue(parent, "worker", ["memory.read", "memory.write"], Date.now() + 60_000);
  const agent = durableRoute(app, principal);
  const stored = await agent("POST", "/memory/durable", { target, operationId: "agent-write", command: { action: "store", content: "Synthetic delegated memory" } });
  assert.equal(stored.status, 200, stored.body);
  assert.equal((await agent("GET", "/memory/durable", undefined, { ...target, action: "list" })).status, 200);
  assert.equal((await agent("GET", "/memory/durable", undefined, { scope: "agent", agentId: "other-agent", action: "list" })).status, 403);
  await app.authorization.revoke(principal.grantId);
  assert.equal((await agent("GET", "/memory/durable", undefined, { ...target, action: "list" })).status, 403);
});
