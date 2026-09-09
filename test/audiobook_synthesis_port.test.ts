import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { audiobookSynthesisRequestSha256, type AudiobookSynthesisRequest, type DomainStageWorker } from "../src/autonomy/domain_workflows.js";
import { composeKeep } from "../src/compose.js";
import type { CapabilityAdapter } from "../src/ecosystem/capability_port.js";

const worker: DomainStageWorker = async (request) => request.requiredDeliverables.map((name) => ({ name, content: `${request.kind}:${request.stage}:${name}` }));

function auth(request: AudiobookSynthesisRequest, capabilityId = "private-tts") {
  return {
    schemaVersion: 1 as const, id: `auth:${request.runId}`, actor: "owner", capabilityId,
    operation: "audio.synthesize" as const, requestSha256: audiobookSynthesisRequestSha256(request),
    idempotencyKey: request.idempotencyKey, notBeforeMs: 1_000, expiresAtMs: 2_000,
  };
}

function app(dataDir: string, authorizationFor: (request: AudiobookSynthesisRequest) => ReturnType<typeof auth> | undefined, synthesisTimeoutMs?: number) {
  return composeKeep({
    dataDir,
    domainWorkflow: {
      kind: "audiobook", worker,
      ...(synthesisTimeoutMs === undefined ? {} : { synthesisTimeoutMs }),
      synthesis: { capabilityId: "private-tts", authorizationFor, verifyAuthorization: (authorization) => authorization.actor === "owner", now: () => 1_500 },
    },
  });
}

function adapter(calls: Array<Record<string, unknown>>, execute: (args: Readonly<Record<string, unknown>>) => Promise<string> | string): CapabilityAdapter {
  return {
    descriptor: { id: "private-tts", kind: "connector", name: "private synthesis", credentialId: "tts", trust: "verified" },
    async invoke(invocation) {
      calls.push(invocation.args as Record<string, unknown>);
      return { ok: true, output: { audioMaster: await execute(invocation.args) } };
    },
  };
}

test("composed audiobook effect uses exact authorization, CapabilityHub mediation, sealed intent and bound receipt", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const composed = app(mkdtempSync(join(tmpdir(), "keep-audio-composed-")), (request) => auth(request));
  composed.infra.capabilities.register(adapter(calls, () => "audio://master"));
  const result = await composed.autonomyLoop!.runProject("locally prepare and vet an audiobook narration package", { runId: "audio-composed", stepBudget: 40 });
  assert.equal(result.state.status, "completed", result.state.note ?? "");
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.["sourceManuscript"], "audiobook:understand:source-manuscript");
  const events = composed.spine.replay();
  assert.ok(events.some((event) => event.type === "effect.intent" && event.payload["kind"] === "audiobook.synthesis.intent"));
  assert.ok(events.some((event) => event.type === "effect.receipt" && event.payload["kind"] === "audiobook.synthesis.receipt"));
  const traffic = events.filter((event) => event.payload["event"] === "capability.traffic");
  assert.ok(traffic.some((event) => event.payload["phase"] === "request"));
  assert.ok(traffic.every((event) => JSON.stringify(event.payload).includes("source-manuscript") === false), "sensitive source bytes stay out of hub audit events");
  assert.ok(traffic.every((event) => /^[0-9a-f]{64}$/u.test(String((event.payload["args"] as Record<string, unknown>)["sha256"]))));
});

test("fleet composition preserves audiobook synthesis through an exact admission permit", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const composed = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-audio-fleet-")),
    fleetLifecycle: { cap: 8, maxPerBasis: 4 },
    domainWorkflow: {
      kind: "audiobook", worker,
      synthesis: { capabilityId: "private-tts", authorizationFor: (request) => auth(request), verifyAuthorization: (authorization) => authorization.actor === "owner", now: () => 1_500 },
    },
  });
  composed.infra.capabilities.register({
    descriptor: {
      id: "private-tts", kind: "connector", name: "private synthesis", credentialId: "tts", trust: "verified",
      fleet: { admissionUnits: 2, resourceDomain: "audiobook", targetArgument: "requestSha256" },
    },
    async invoke(invocation) { calls.push(invocation.args as Record<string, unknown>); return { ok: true, output: { audioMaster: "audio://fleet-master" } }; },
  });

  const result = await composed.autonomyLoop!.runProject("locally prepare and vet an audiobook narration package", { runId: "audio-fleet", stepBudget: 40 });
  assert.equal(result.state.status, "completed", result.state.note ?? "");
  assert.equal(calls.length, 1);
  assert.equal(composed.fleetLifecycle!.active().length, 0, "successful dispatch settles its exact admission");
  assert.equal(composed.fleetLifecycle!.committedTotal(), 2, "server-owned admission units, not caller input, are committed");
  const bypass = await composed.infra.capabilities.invoke(
    { capabilityId: "private-tts", operation: "audio.synthesize", args: { requestSha256: "0".repeat(64) } },
    { requireVerified: true, confirm: true },
  );
  assert.deepEqual({ ok: bypass.ok, held: bypass.held }, { ok: false, held: true }, "the same adapter cannot bypass fleet admission");
});

test("missing or mismatched authorization never calls the adapter and requires approval authority to resume", async () => {
  for (const [id, authorizationFor] of [
    ["missing", (_request: AudiobookSynthesisRequest) => undefined],
    ["mismatch", (request: AudiobookSynthesisRequest) => auth(request, "other-capability")],
  ] as const) {
    const calls: Array<Record<string, unknown>> = [];
    const composed = app(mkdtempSync(join(tmpdir(), `keep-audio-${id}-`)), authorizationFor);
    composed.infra.capabilities.register(adapter(calls, () => "must-not-run"));
    const result = await composed.autonomyLoop!.runProject("locally prepare and vet an audiobook narration package", { runId: `audio-${id}`, stepBudget: 40 });
    assert.equal(result.state.status, "waiting-capability");
    assert.equal(result.state.wait?.kind === "capability" && result.state.wait.resumeAuthority, "approval");
    assert.equal(composed.autonomyLoop!.resumePermission(result.state.runId), "change.solve");
    assert.equal(composed.autonomyLoop!.resumePermission(result.state.runId, { capability: { capability: "audiobook-authorized-synthesis", evidenceId: "new-auth" } }), "review.approve");
    assert.equal(calls.length, 0);
    assert.equal(composed.spine.replay().some((event) => event.type === "effect.intent"), false);
  }
});

test("completed synthesis with an unsealed receipt waits for reconciliation and never auto-retries", async () => {
  const calls: Array<Record<string, unknown>> = [];
  const composed = app(mkdtempSync(join(tmpdir(), "keep-audio-unsealed-")), (request) => auth(request));
  composed.infra.capabilities.register(adapter(calls, () => "audio://paid-master"));
  const seal = composed.spine.seal.bind(composed.spine);
  let effectSeals = 0;
  Object.defineProperty(composed.spine, "seal", { configurable: true, value: async () => {
    effectSeals += 1;
    if (effectSeals === 2) throw new Error("simulated receipt fsync failure");
    return seal();
  } });
  const result = await composed.autonomyLoop!.runProject("locally prepare and vet an audiobook narration package", { runId: "audio-unsealed", stepBudget: 40 });
  assert.equal(result.state.status, "waiting-reconciliation");
  assert.match(result.state.note ?? "", /receipt could not be durably sealed/u);
  assert.equal(calls.length, 1);
  const unchanged = await composed.autonomyLoop!.resumeProject("audio-unsealed");
  assert.equal(unchanged.state.status, "waiting-reconciliation");
  assert.equal(calls.length, 1, "no evidence means no second paid dispatch");
});

test("crash after sealed intent restores as reconciliation and content-bound idempotency prevents a duplicate paid effect", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-audio-crash-"));
  const serviceResults = new Map<string, string>();
  let calls = 0;
  const first = app(dataDir, (request) => auth(request), 100);
  first.infra.capabilities.register(adapter([], async (args) => {
    calls += 1;
    const key = String(args["idempotencyKey"]);
    const existing = serviceResults.get(key);
    if (existing !== undefined) return existing;
    return new Promise<string>(() => {});
  }));
  const abandonedRun = first.autonomyLoop!.runProject("locally prepare and vet an audiobook narration package", { runId: "audio-crash", stepBudget: 40 });
  for (let tries = 0; tries < 100 && !first.spine.replay().some((event) => event.type === "effect.intent"); tries += 1) await new Promise((resolve) => setTimeout(resolve, 2));
  assert.ok(first.spine.replay().some((event) => event.type === "effect.intent"));

  const restored = app(dataDir, (request) => auth(request));
  restored.infra.capabilities.register(adapter([], (args) => {
    calls += 1;
    const key = String(args["idempotencyKey"]);
    const result = serviceResults.get(key) ?? "audio://reconciled-master";
    serviceResults.set(key, result);
    return result;
  }));
  const held = await restored.autonomyLoop!.resumeProject("audio-crash");
  assert.equal(held.state.status, "waiting-reconciliation");
  assert.equal(calls, 1, "restore without reconciliation does not dispatch");
  const effectId = held.state.wait?.kind === "reconciliation" ? held.state.wait.effectId : "";
  const completed = await restored.autonomyLoop!.resumeProject("audio-crash", { reconciliation: { effectId, resolved: true, evidenceId: "service-idempotency-confirmed-absent" } });
  assert.equal(completed.state.status, "completed");
  assert.equal(calls, 2, "one ambiguous first call plus one explicitly reconciled idempotent retry");
  const abandonedOutcome = await abandonedRun;
  assert.equal(abandonedOutcome.state.status, "completed", "the stale process observes the CAS winner rather than overwriting it");
});
