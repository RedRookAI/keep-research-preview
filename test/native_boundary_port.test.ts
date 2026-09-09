import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { captureNativeBoundaryRequest, encodeNativeBoundaryFrame, NativeBoundaryFrameDecoder, NativeBoundarySession, nativeBoundaryRequestDigest, type NativeBoundaryPort, type NativeBoundaryRequest } from "../src/platform/native_boundary_port.js";

const D = "ab".repeat(32);
const request = (): Extract<NativeBoundaryRequest, { kind: "launch" }> => ({ protocol: "keep.native-boundary", version: 1n, kind: "launch", requestId: "req.1", deploymentId: "deploy.1", bootId: "boot.1", manifestDigest: D, nonce: "nonce.1", sequence: 0n, deadlineMs: 10n, roles: [{ roleId: "net.d3", roleClass: "D3", principalId: "keep-net", artifactDigest: D, credentialDomains: ["provider.openai"], allowedChannelIds: ["d2-net"] }] });

test("A5 native boundary framing is canonical, length-delimited, partial-read safe and fail-stop", () => {
  let proxyTraps = 0;
  const hostileChunk = new Proxy(new Uint8Array([0]), {
    getPrototypeOf(target) { proxyTraps++; return Reflect.getPrototypeOf(target); },
    get(target, property, receiver) { proxyTraps++; return Reflect.get(target, property, receiver); },
  });
  assert.throws(() => new NativeBoundaryFrameDecoder().push(hostileChunk), /Proxy byte chunks/);
  assert.equal(proxyTraps, 0);
  const frame = encodeNativeBoundaryFrame(request()); const decoder = new NativeBoundaryFrameDecoder(); assert.deepEqual(decoder.push(frame.slice(0, 3)), []); assert.deepEqual(decoder.push(frame.slice(3)).length, 1); assert.doesNotThrow(() => decoder.finish()); assert.throws(() => decoder.push(new Uint8Array([1])), /closed/);
  const truncated = new NativeBoundaryFrameDecoder(); truncated.push(frame.slice(0, -1)); assert.throws(() => truncated.finish(), /truncated/);
  const oversized = new Uint8Array(4); new DataView(oversized.buffer).setUint32(0, 1_048_577); assert.throws(() => new NativeBoundaryFrameDecoder().push(oversized), /length is invalid/);
  const trailing = new Uint8Array(frame.length + 1); trailing.set(frame); assert.throws(() => new NativeBoundaryFrameDecoder().push(trailing), /trailing/);
  const noncanonicalPayload = new Uint8Array([0x18, 0x00]); const noncanonical = new Uint8Array(6); new DataView(noncanonical.buffer).setUint32(0, 2); noncanonical.set(noncanonicalPayload, 4); assert.throws(() => new NativeBoundaryFrameDecoder().push(noncanonical), /not canonical/);
});

test("A5 request capture rejects unknown versions/fields, arbitrary commands, bounds, duplicates and hostile objects", () => {
  assert.throws(() => captureNativeBoundaryRequest({ ...request(), version: 2n }), /protocol\/version is unsupported/);
  assert.throws(() => captureNativeBoundaryRequest({ ...request(), command: "/bin/sh" }), /fields are not exact/);
  assert.throws(() => captureNativeBoundaryRequest({ ...request(), roles: [...request().roles, ...request().roles] }), /duplicated/);
  assert.throws(() => captureNativeBoundaryRequest({ ...request(), roles: Array.from({ length: 33 }, (_, i) => ({ ...request().roles[0]!, roleId: `r.${i}` })) }), /bounded array/);
  let traps = 0; const hostile = new Proxy(request(), { getPrototypeOf() { traps++; return Object.prototype; }, ownKeys(target) { traps++; return Reflect.ownKeys(target); } }); assert.throws(() => captureNativeBoundaryRequest(hostile), /not inert canonical data/); assert.equal(traps, 0);
  const sparse = request().roles.slice() as unknown[]; sparse.length = 2; assert.throws(() => captureNativeBoundaryRequest({ ...request(), roles: sparse }), /hole|inert canonical/);
});

test("A5 test-only fake port proves exact request binding; stale/substituted responses fail", async () => {
  const fake = (mutate: (row: Record<string, unknown>) => void = () => {}, exchange?: (req: NativeBoundaryRequest) => Promise<never>): NativeBoundaryPort => ({ async exchange(req) { if (exchange) return exchange(req); const row: Record<string, unknown> = { protocol: "keep.native-boundary", version: 1n, requestId: req.requestId, requestDigest: nativeBoundaryRequestDigest(req), deploymentId: req.deploymentId, bootId: req.bootId, nonce: req.nonce, sequence: req.sequence, helperArtifactDigest: D, helperBuildId: "fake.test-only", kernelBootId: "kernel.test", status: "ok", roleHandles: [{ roleId: "net.d3", roleClass: "D3", handleId: "handle.1", incarnationDigest: D, artifactDigest: D, principalId: "keep-net" }], measurements: [{ measurementId: "m.1", roleHandleId: "handle.1", field: "uid", state: "inconclusive", evidenceDigest: D }], failureCode: "" }; mutate(row); return row as never; }, close() {} });
  const session = (port: NativeBoundaryPort) => new NativeBoundarySession({ port, deploymentId: "deploy.1", bootId: "boot.1", manifestDigest: D, nowMs: () => 0n, maxRequestMs: 100n });
  const result = await session(fake()).exchange(request()); assert.equal(result.status, "ok"); assert.equal(result.measurements[0]?.state, "inconclusive");
  await assert.rejects(session(fake((row) => { row.nonce = "nonce.other"; })).exchange(request()), /not bound/);
  await assert.rejects(session(fake((row) => { row.requestDigest = "cd".repeat(32); })).exchange(request()), /not bound/);
  await assert.rejects(session(fake((row) => { row.extra = true; })).exchange(request()), /fields are not exact/);
  await assert.rejects(session(fake((row) => { row.roleHandles = []; row.measurements = []; })).exchange(request()), /role closure is incomplete/);
  await assert.rejects(session(fake((row) => { (row.roleHandles as Array<Record<string, unknown>>)[0]!.principalId = "substituted"; })).exchange(request()), /substituted/);
  await assert.rejects(session(fake((row) => { row.status = "refused"; row.failureCode = "policy.refused"; })).exchange(request()), /partial success/);
  const twoRoles = { ...request(), roles: [...request().roles, { ...request().roles[0]!, roleId: "storage.d3", principalId: "keep-storage", credentialDomains: ["storage.main"] }] };
  await assert.rejects(session(fake((row) => { const handles = row.roleHandles as Array<Record<string, unknown>>; handles.push({ ...handles[0]!, handleId: "handle.2", incarnationDigest: "cd".repeat(32) }); const measurements = row.measurements as Array<Record<string, unknown>>; measurements.push({ ...measurements[0]!, measurementId: "m.2", roleHandleId: "handle.2" }); })).exchange(twoRoles), /duplicated or omitted/);
});

test("A5 session rejects replay, regression, nonce reuse, concurrency and stalls then stays closed", async () => {
  let closes = 0;
  const response = (req: NativeBoundaryRequest) => ({ protocol: "keep.native-boundary" as const, version: 1n as const, requestId: req.requestId, requestDigest: nativeBoundaryRequestDigest(req), deploymentId: req.deploymentId, bootId: req.bootId, nonce: req.nonce, sequence: req.sequence, helperArtifactDigest: D, helperBuildId: "fake.test-only", kernelBootId: "kernel.test", status: "ok" as const, roleHandles: [{ roleId: "net.d3", roleClass: "D3" as const, handleId: "handle.1", incarnationDigest: D, artifactDigest: D, principalId: "keep-net" }], measurements: [{ measurementId: "m.1", roleHandleId: "handle.1", field: "uid", state: "inconclusive" as const, evidenceDigest: D }], failureCode: "" });
  const immediate: NativeBoundaryPort = { async exchange(req) { return response(req); }, close() { closes++; } };
  const replaySession = new NativeBoundarySession({ port: immediate, deploymentId: "deploy.1", bootId: "boot.1", manifestDigest: D, nowMs: () => 0n, maxRequestMs: 100n }); await replaySession.exchange(request()); await assert.rejects(replaySession.exchange(request()), /replay|regression/); assert.equal(replaySession.closed, true);
  const nonceSession = new NativeBoundarySession({ port: immediate, deploymentId: "deploy.1", bootId: "boot.1", manifestDigest: D, nowMs: () => 0n, maxRequestMs: 100n }); await nonceSession.exchange(request()); await assert.rejects(nonceSession.exchange({ ...request(), requestId: "req.2", sequence: 1n }), /replay|regression/);
  let release!: () => void; const gate = new Promise<void>((resolve) => { release = resolve; }); const delayed: NativeBoundaryPort = { async exchange(req) { await gate; return response(req); }, close() { closes++; } }; const concurrentSession = new NativeBoundarySession({ port: delayed, deploymentId: "deploy.1", bootId: "boot.1", manifestDigest: D, nowMs: () => 0n, maxRequestMs: 100n }); const first = concurrentSession.exchange(request()); await assert.rejects(concurrentSession.exchange({ ...request(), requestId: "req.2", nonce: "nonce.2", sequence: 1n }), /one in-flight/); release(); await assert.rejects(first, /closed while/);
  const stalled: NativeBoundaryPort = { exchange: async () => await new Promise<never>(() => {}), close() { closes++; } }; const timeoutSession = new NativeBoundarySession({ port: stalled, deploymentId: "deploy.1", bootId: "boot.1", manifestDigest: D, nowMs: () => 0n, maxRequestMs: 100n }); await assert.rejects(timeoutSession.exchange({ ...request(), deadlineMs: 1n }), /deadline exceeded/); await assert.rejects(timeoutSession.exchange(request()), /session is closed/); assert.ok(closes >= 3);
  let clockCloses = 0; const clockPort: NativeBoundaryPort = { async exchange(req) { return response(req); }, close() { clockCloses++; } }; const firstThrow = new NativeBoundarySession({ port: clockPort, deploymentId: "deploy.1", bootId: "boot.1", manifestDigest: D, nowMs: () => { throw new Error("clock down"); }, maxRequestMs: 100n }); await assert.rejects(firstThrow.exchange(request()), /trusted clock failed/); await assert.rejects(firstThrow.exchange(request()), /session is closed/); assert.equal(clockCloses, 1);
  let clockReads = 0; const laterThrow = new NativeBoundarySession({ port: clockPort, deploymentId: "deploy.1", bootId: "boot.1", manifestDigest: D, nowMs: () => { if (clockReads++ === 0) return 0n; throw new Error("clock down"); }, maxRequestMs: 100n }); await assert.rejects(laterThrow.exchange(request()), /trusted clock failed/); assert.equal(laterThrow.closed, true); assert.equal(clockCloses, 2);
});

test("A5 fake adapter remains test-only and cannot enter the release package", () => {
  const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { files?: string[] };
  assert.equal(pkg.files?.some((path) => path === "test/" || path.startsWith("test/")), false);
  assert.throws(() => captureNativeBoundaryRequest({ ...request(), roles: [{ ...request().roles[0]!, artifactDigest: "00".repeat(32) }] }), /SHA-256/);
});
