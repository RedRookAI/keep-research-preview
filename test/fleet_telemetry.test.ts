import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest, type GatewayRequest } from "../src/gateway/http_gateway.js";
import { fleetView, localCostTraceView, optimizeProviderPrice, type MeasuredRun } from "../src/observability/fleet_telemetry.js";
import type { CostBreakdown } from "../src/observability/cost_model.js";
import type { Span } from "../src/observability/tracing.js";
import type { Principal } from "../src/identity/rbac.js";

const cost = (totalUsd: number): CostBreakdown => ({ inputUsd: totalUsd, cachedInputUsd: 0, outputUsd: 0, tokenUsd: totalUsd, humanUsd: 0, infraUsd: 0, toolApiUsd: 0, totalUsd });
const request = (query: Record<string, string> = {}): GatewayRequest => ({ method: "GET", path: "/observability/costs", query, headers: { authorization: "Bearer token" }, body: "" });

test("OBS-01 local view attributes measured cost, retains failures, and reports empirical uncertainty", () => {
  const spans: Span[] = Array.from({ length: 5 }, (_, index) => ({
    spanId: `s${index}`, traceId: `tr${index}`, name: "gen_ai", taskId: `task-${index}`,
    provider: index < 3 ? "local" : "remote", agent: "worker", lessonIds: ["lesson-a"],
    cost: cost(index + 1), startTs: index, endTs: index + 1, status: index === 4 ? "llm-error" : "ok",
  }));
  const view = localCostTraceView(spans, { offset: 1, limit: 2 });
  assert.equal(view.totalUsd, 15);
  assert.deepEqual(view.attribution.providers, [{ id: "remote", usd: 9 }, { id: "local", usd: 6 }]);
  assert.deepEqual(view.attribution.lessons, [{ id: "lesson-a", usd: 15 }]);
  assert.deepEqual(view.forecast, { p50: 3, p95: 4.8, sampleSize: 5, credible: true });
  assert.deepEqual(view.page, { offset: 1, limit: 2, total: 5, nextOffset: 3 });
  assert.deepEqual(view.traces.map((trace) => trace.taskId), ["task-1", "task-2"]);
});

test("X5 fleet economics includes failed spend and optimizes cost per pass only above the quality floor", () => {
  const runs: MeasuredRun[] = [
    { taskId: "1", traceId: "a", model: "cheap-flaky", costUsd: 1, passed: true },
    { taskId: "2", traceId: "b", model: "cheap-flaky", costUsd: 1, passed: false },
    { taskId: "3", traceId: "c", model: "steady", costUsd: 3, passed: true },
    { taskId: "4", traceId: "d", model: "steady", costUsd: 3, passed: true },
  ];
  const view = fleetView(runs);
  assert.equal(view.totalUsd, 8);
  assert.equal(view.failedTasks, 1);
  assert.equal(optimizeProviderPrice(view, 0.9)?.model, "steady");
  assert.equal(optimizeProviderPrice(view, 0.5)?.model, "cheap-flaky");
  assert.throws(() => optimizeProviderPrice(view, Number.NaN), /invalid minimum/u);
  assert.throws(() => fleetView([{ ...runs[0]!, costUsd: Number.NaN }]), /invalid measured/u);
});

test("OBS-01 authenticated gateway is complete for n=1 and exact-tenant for enterprise across restart", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-cost-gateway-"));
  const first = composeKeep({ dataDir });
  for (const [tenant, total] of [["alpha", 2], ["beta", 3]] as const) first.observability.recorder.record({
    traceId: `${tenant}-trace`, name: "measured-call", taskId: `${tenant}-task`, tenant,
    provider: `${tenant}-provider`, agent: `${tenant}-agent`, lessonIds: [`${tenant}-lesson`], cost: cost(total), startTs: total, endTs: total + 1,
  });
  first.observability.recorder.record({ traceId: "solo-trace", name: "local-call", taskId: "solo-task", cost: cost(5), startTs: 5, endTs: 6 });
  await first.spine.seal();

  const restarted = composeKeep({ dataDir });
  const solo = JSON.parse((await handleGatewayRequest(restarted, request(), { token: "token" })).body) as ReturnType<typeof localCostTraceView>;
  assert.equal(solo.totalUsd, 10, "n=1 sees the complete local durable trace history");
  assert.equal(solo.traces.length, 3);

  const alpha: Principal = { id: "alice", kind: "human", role: "viewer", tenant: "alpha" };
  const alphaResponse = await handleGatewayRequest(restarted, request(), { token: "token", principalFor: () => alpha });
  assert.equal(alphaResponse.status, 200);
  const alphaView = JSON.parse(alphaResponse.body) as ReturnType<typeof localCostTraceView>;
  assert.equal(alphaView.totalUsd, 2);
  assert.deepEqual(alphaView.traces.map((trace) => trace.taskId), ["alpha-task"]);
  assert.doesNotMatch(alphaResponse.body, /beta|solo/u);

  const scoped = JSON.parse((await handleGatewayRequest(restarted, request({ traceId: "alpha-trace" }), { token: "token", principalFor: () => alpha })).body) as ReturnType<typeof localCostTraceView>;
  assert.equal(scoped.page.total, 1);
  assert.equal((await handleGatewayRequest(restarted, request({ limit: "1001" }), { token: "token", principalFor: () => alpha })).status, 400);
});

test("OBS-02 explicit private export is redacted, durably receipted, fleet-admitted, and never fire-and-forget", async () => {
  let observedUrl = "", observedBody = "", observedAuthorization = "", calls = 0;
  const fetchImpl: typeof fetch = async (input, init) => {
    calls += 1; observedUrl = String(input); observedBody = String(init?.body ?? "");
    observedAuthorization = String((init?.headers as Record<string, string> | undefined)?.["authorization"] ?? "");
    return new Response("", { status: 202 });
  };
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-private-otlp-")), fleetLifecycle: { cap: 5, maxPerBasis: 3 },
    privateTelemetryDestinations: [{ id: "private-ops", purpose: "operations", collectorUrl: "http://127.0.0.1:4318/v1/traces", authorization: "Bearer collector-secret", pseudonymizationKey: "p".repeat(32), maxBatchSpans: 10, fetchImpl }],
  });
  app.observability.recorder.record({ traceId: "customer-secret-trace", name: "contact alice@example.com", taskId: "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN", agent: "Alice Smith", lessonIds: [], cost: cost(2), startTs: 1, endTs: 2 });
  await app.spine.seal();
  const response = await handleGatewayRequest(app, { method: "POST", path: "/observability/export", query: {}, headers: { authorization: "Bearer token" }, body: JSON.stringify({ destinationId: "private-ops", purpose: "operations" }) }, { token: "token" });
  assert.equal(response.status, 200, response.body);
  assert.equal(calls, 1);
  assert.equal(observedUrl, "http://127.0.0.1:4318/v1/traces");
  assert.equal(observedAuthorization, "Bearer collector-secret");
  assert.doesNotMatch(observedBody, /customer-secret|alice@example|ghp_|Alice Smith|collector-secret/u);
  assert.match(observedBody, /\[REDACTED/u);
  assert.equal(app.fleetLifecycle!.committedTotal(), 1);
  assert.equal(app.fleetLifecycle!.active().length, 0);
  const events = app.spine.replay();
  assert.ok(events.some((event) => event.type === "effect.intent" && event.payload["kind"] === "telemetry.export.intent"));
  assert.ok(events.some((event) => event.type === "effect.receipt" && event.payload["kind"] === "telemetry.export.receipt"));
  assert.doesNotMatch(JSON.stringify(events), /collector-secret|alice@example|ghp_/u, "credentials and raw labels never enter the Spine");
  const bypass = await app.infra.capabilities.invoke({ capabilityId: "private-ops", operation: "telemetry.export", args: { destinationDigest: "0".repeat(64) } }, { requireVerified: true, confirm: true });
  assert.deepEqual({ ok: bypass.ok, held: bypass.held }, { ok: false, held: true });
});

test("OBS-02 enterprise destinations are exact-tenant and failed delivery is terminal and visible", async () => {
  const app = composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-private-otlp-tenants-")),
    privateTelemetryDestinations: [
      { id: "ops", tenant: "alpha", purpose: "operations", collectorUrl: "http://127.0.0.1:4318/v1/traces", pseudonymizationKey: "a".repeat(32), fetchImpl: async () => new Response("", { status: 503 }) },
      { id: "ops", tenant: "beta", purpose: "operations", collectorUrl: "http://127.0.0.1:4319/v1/traces", pseudonymizationKey: "b".repeat(32), fetchImpl: async () => new Response("", { status: 202 }) },
    ],
  });
  app.observability.recorder.record({ traceId: "alpha-trace", name: "alpha-call", taskId: "alpha-task", tenant: "alpha", cost: cost(1), startTs: 1, endTs: 2 });
  app.observability.recorder.record({ traceId: "beta-trace", name: "beta-call", taskId: "beta-task", tenant: "beta", cost: cost(1), startTs: 1, endTs: 2 });
  await app.spine.seal();
  const alpha: Principal = { id: "Alice Smith", kind: "human", role: "maintainer", tenant: "alpha" };
  const list = await handleGatewayRequest(app, { method: "GET", path: "/observability/exports", query: {}, headers: { authorization: "Bearer token" }, body: "" }, { token: "token", principalFor: () => alpha });
  assert.equal(list.status, 200);
  assert.equal((JSON.parse(list.body) as { destinations: unknown[] }).destinations.length, 1);
  assert.doesNotMatch(list.body, /4318|4319|beta/u, "collector address, credentials, and foreign destinations are not disclosed");
  const viewer: Principal = { id: "viewer", kind: "human", role: "viewer", tenant: "alpha" };
  assert.equal((await handleGatewayRequest(app, { method: "POST", path: "/observability/export", query: {}, headers: { authorization: "Bearer token" }, body: JSON.stringify({ destinationId: "ops", purpose: "operations" }) }, { token: "token", principalFor: () => viewer })).status, 403);
  const failed = await handleGatewayRequest(app, { method: "POST", path: "/observability/export", query: {}, headers: { authorization: "Bearer token" }, body: JSON.stringify({ destinationId: "ops", purpose: "operations" }) }, { token: "token", principalFor: () => alpha });
  assert.equal(failed.status, 502);
  assert.equal((JSON.parse(failed.body) as { result: { status: string } }).result.status, "failed");
  assert.ok(app.spine.replay().some((event) => event.type === "effect.terminal" && event.payload["kind"] === "telemetry.export.terminal"));
  const beta: Principal = { id: "bob", kind: "human", role: "maintainer", tenant: "beta" };
  assert.equal((await handleGatewayRequest(app, { method: "POST", path: "/observability/export", query: {}, headers: { authorization: "Bearer token" }, body: JSON.stringify({ destinationId: "ops", purpose: "operations" }) }, { token: "token", principalFor: () => beta })).status, 200);
  assert.throws(() => composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-public-otlp-")), privateTelemetryDestinations: [{ id: "bad", purpose: "operations", collectorUrl: "https://collector.example.com/v1/traces", pseudonymizationKey: "x".repeat(32) }] }), /private literal/u);
  assert.throws(() => composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-metadata-otlp-")), privateTelemetryDestinations: [{ id: "bad", purpose: "operations", collectorUrl: "http://169.254.169.254/latest", pseudonymizationKey: "x".repeat(32) }] }), /private literal/u);
});

test("OBS-02 an ambiguous delivery survives restart for explicit reconciliation and is never retried", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-otlp-reconcile-"));
  let calls = 0;
  const destination = { id: "ops", purpose: "operations", collectorUrl: "http://127.0.0.1:4318/v1/traces", pseudonymizationKey: "r".repeat(32), fetchImpl: (async () => { calls += 1; throw new Error("connection reset after write"); }) as typeof fetch };
  const first = composeKeep({ dataDir, privateTelemetryDestinations: [destination] });
  first.observability.recorder.record({ traceId: "trace", name: "call", taskId: "task", cost: cost(1), startTs: 1, endTs: 2 });
  await first.spine.seal();
  const attempted = await handleGatewayRequest(first, { method: "POST", path: "/observability/export", query: {}, headers: { authorization: "Bearer token" }, body: JSON.stringify({ destinationId: "ops", purpose: "operations" }) }, { token: "token" });
  assert.equal(attempted.status, 202);
  assert.equal(calls, 1);
  const exportId = (JSON.parse(attempted.body) as { result: { exportId: string } }).result.exportId;

  const restarted = composeKeep({ dataDir, privateTelemetryDestinations: [destination] });
  const outstanding = await handleGatewayRequest(restarted, { method: "GET", path: "/observability/export/outstanding", query: {}, headers: { authorization: "Bearer token" }, body: "" }, { token: "token" });
  assert.deepEqual((JSON.parse(outstanding.body) as { outstanding: { exportId: string }[] }).outstanding.map((row) => row.exportId), [exportId]);
  assert.equal(calls, 1, "restart and observation never redispatch an ambiguous export");
  const reconciled = await handleGatewayRequest(restarted, { method: "POST", path: "/observability/export/reconcile", query: {}, headers: { authorization: "Bearer token" }, body: JSON.stringify({ exportId, outcome: "delivered", evidenceId: "collector-query-confirmed" }) }, { token: "token" });
  assert.equal(reconciled.status, 200);
  assert.equal(restarted.fleetTelemetry!.outstanding().length, 0);
  assert.equal(calls, 1);
});

test("fleet-composed ambiguous private export retains capacity and does not replay on restart", async () => {
  const dataDir = mkdtempSync(join(tmpdir(), "keep-otlp-fleet-unknown-"));
  let observedEffects = 0;
  const destination = { id: "ops", purpose: "operations", collectorUrl: "http://127.0.0.1:4318/v1/traces", pseudonymizationKey: "r".repeat(32), fetchImpl: (async () => { observedEffects++; throw Error("lost acknowledgment after fixture accepts body"); }) as typeof fetch };
  const config = { dataDir, fleetLifecycle: { cap: 1, maxPerBasis: 3 }, privateTelemetryDestinations: [destination] };
  const first = composeKeep(config);
  first.observability.recorder.record({ traceId: "trace", name: "call", taskId: "task", cost: cost(1), startTs: 1, endTs: 2 });
  await first.spine.seal();
  const response = await handleGatewayRequest(first, { method: "POST", path: "/observability/export", query: {}, headers: { authorization: "Bearer token" }, body: JSON.stringify({ destinationId: "ops", purpose: "operations" }) }, { token: "token" });
  assert.equal(response.status, 202, response.body);
  assert.equal(JSON.parse(response.body).result.status, "unreconciled");
  assert.equal(observedEffects, 1);
  assert.equal(first.fleetLifecycle!.active().length, 1);
  assert.equal(first.fleetLifecycle!.committedTotal(), 0);
  const restarted = composeKeep(config);
  assert.equal(restarted.fleetLifecycle!.active().length, 1);
  assert.equal(restarted.fleetTelemetry!.outstanding().length, 1);
  assert.equal(observedEffects, 1, "neither restart nor status observation initiates another effect");
});
