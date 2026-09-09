/** A5: zero-third-party-runtime launch/probe port and strict canonical length-delimited wire contract. */
import { decodeCanonical, eirDigest, encodeCanonical, isCanonical, type CanonicalValue } from "../eir/canonical.js";
import { randomBytes } from "node:crypto";
import { types } from "node:util";

export const NATIVE_BOUNDARY_PROTOCOL = Object.freeze({ name: "keep.native-boundary", version: 1n, maxFrameBytes: 1_048_576, maxRoles: 32, maxChannels: 128, maxMeasurements: 256 } as const);
export type NativeRoleClass = "D1" | "D2" | "D3" | "PROBER";
export interface NativeRoleSpec { readonly roleId: string; readonly roleClass: NativeRoleClass; readonly principalId: string; readonly artifactDigest: string; readonly credentialDomains: readonly string[]; readonly allowedChannelIds: readonly string[]; }
interface RequestBase { readonly protocol: "keep.native-boundary"; readonly version: 1n; readonly requestId: string; readonly deploymentId: string; readonly bootId: string; readonly manifestDigest: string; readonly nonce: string; readonly sequence: bigint; readonly deadlineMs: bigint; }
export type NativeBoundaryRequest =
  | (RequestBase & { readonly kind: "launch"; readonly roles: readonly NativeRoleSpec[] })
  | (RequestBase & { readonly kind: "probe"; readonly roleHandleIds: readonly string[]; readonly challengeNonce: string })
  | (RequestBase & { readonly kind: "cancel"; readonly targetRequestId: string });
export interface NativeRoleHandle { readonly roleId: string; readonly roleClass: NativeRoleClass; readonly handleId: string; readonly incarnationDigest: string; readonly artifactDigest: string; readonly principalId: string; }
export interface NativeMeasurement { readonly measurementId: string; readonly roleHandleId: string; readonly field: string; readonly state: "active" | "inactive" | "unsupported" | "inconclusive"; readonly evidenceDigest: string; }
export interface NativeBoundaryResponse { readonly protocol: "keep.native-boundary"; readonly version: 1n; readonly requestId: string; readonly requestDigest: string; readonly deploymentId: string; readonly bootId: string; readonly nonce: string; readonly sequence: bigint; readonly helperArtifactDigest: string; readonly helperBuildId: string; readonly kernelBootId: string; readonly status: "ok" | "refused" | "failed"; readonly roleHandles: readonly NativeRoleHandle[]; readonly measurements: readonly NativeMeasurement[]; readonly failureCode: string; }
export interface NativeBoundaryPort { exchange(request: NativeBoundaryRequest): Promise<NativeBoundaryResponse>; close(reason: string): void; }
export class NativeBoundaryProtocolError extends Error { constructor(message: string) { super(`native boundary protocol: ${message}`); this.name = "NativeBoundaryProtocolError"; } }

const HEX64 = /^[0-9a-f]{64}$/; const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/;
const plain = (value: unknown, label: string): Record<string, CanonicalValue> => { if (value === null || typeof value !== "object" || Array.isArray(value) || value instanceof Uint8Array || Object.getPrototypeOf(value) !== null) throw new NativeBoundaryProtocolError(`${label} must be an owned canonical map`); return value as Record<string, CanonicalValue>; };
const exact = (row: Record<string, CanonicalValue>, keys: readonly string[], label: string): void => { const actual = Object.keys(row).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new NativeBoundaryProtocolError(`${label} fields are not exact`); };
const text = (value: unknown, label: string): string => { if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new NativeBoundaryProtocolError(`${label} is not a bounded identifier`); return value; };
const digest = (value: unknown, label: string): string => { if (typeof value !== "string" || !HEX64.test(value) || value === "00".repeat(32)) throw new NativeBoundaryProtocolError(`${label} is not a non-placeholder SHA-256 digest`); return value; };
const integer = (value: unknown, label: string): bigint => { if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn) throw new NativeBoundaryProtocolError(`${label} is not a bounded unsigned integer`); return value; };
const list = <T>(value: unknown, maximum: number, label: string, capture: (entry: unknown, index: number) => T): readonly T[] => { if (!Array.isArray(value) || value.length > maximum) throw new NativeBoundaryProtocolError(`${label} is not a bounded array`); return Object.freeze(value.map(capture)); };
const stringList = (value: unknown, maximum: number, label: string): readonly string[] => { const rows = list(value, maximum, label, (entry, index) => text(entry, `${label}[${index}]`)); if (new Set(rows).size !== rows.length) throw new NativeBoundaryProtocolError(`${label} contains duplicates`); return Object.freeze([...rows].sort()); };

function requestCanonical(request: NativeBoundaryRequest): CanonicalValue { return request as unknown as CanonicalValue; }
export function nativeBoundaryRequestDigest(request: NativeBoundaryRequest): string { return eirDigest("keep.native-boundary-request/v1", requestCanonical(captureNativeBoundaryRequest(request))); }

export function captureNativeBoundaryRequest(input: unknown): NativeBoundaryRequest {
  let value: CanonicalValue; try { value = decodeCanonical(encodeCanonical(input as CanonicalValue)); } catch (error) { throw new NativeBoundaryProtocolError(`request is not inert canonical data: ${error instanceof Error ? error.message : String(error)}`); }
  const row = plain(value, "request"); const kind = row.kind; const base = ["protocol", "version", "kind", "requestId", "deploymentId", "bootId", "manifestDigest", "nonce", "sequence", "deadlineMs"];
  if (kind === "launch") exact(row, [...base, "roles"], "launch request"); else if (kind === "probe") exact(row, [...base, "roleHandleIds", "challengeNonce"], "probe request"); else if (kind === "cancel") exact(row, [...base, "targetRequestId"], "cancel request"); else throw new NativeBoundaryProtocolError("request kind/version is unsupported");
  if (row.protocol !== NATIVE_BOUNDARY_PROTOCOL.name || row.version !== NATIVE_BOUNDARY_PROTOCOL.version) throw new NativeBoundaryProtocolError("request protocol/version is unsupported");
  const common = { protocol: NATIVE_BOUNDARY_PROTOCOL.name, version: NATIVE_BOUNDARY_PROTOCOL.version, requestId: text(row.requestId, "requestId"), deploymentId: text(row.deploymentId, "deploymentId"), bootId: text(row.bootId, "bootId"), manifestDigest: digest(row.manifestDigest, "manifestDigest"), nonce: text(row.nonce, "nonce"), sequence: integer(row.sequence, "sequence"), deadlineMs: integer(row.deadlineMs, "deadlineMs") };
  if (kind === "launch") {
    const roles = list(row.roles, NATIVE_BOUNDARY_PROTOCOL.maxRoles, "roles", (entry, index) => {
      const role = plain(entry, `roles[${index}]`); exact(role, ["roleId", "roleClass", "principalId", "artifactDigest", "credentialDomains", "allowedChannelIds"], `roles[${index}]`);
      const roleClass = role.roleClass; if (roleClass !== "D1" && roleClass !== "D2" && roleClass !== "D3" && roleClass !== "PROBER") throw new NativeBoundaryProtocolError(`roles[${index}].roleClass is unsupported`);
      const credentialDomains = stringList(role.credentialDomains, 1, `roles[${index}].credentialDomains`); if (roleClass !== "D3" && credentialDomains.length !== 0) throw new NativeBoundaryProtocolError(`roles[${index}] grants credentials outside D3`);
      return Object.freeze({ roleId: text(role.roleId, `roles[${index}].roleId`), roleClass, principalId: text(role.principalId, `roles[${index}].principalId`), artifactDigest: digest(role.artifactDigest, `roles[${index}].artifactDigest`), credentialDomains, allowedChannelIds: stringList(role.allowedChannelIds, NATIVE_BOUNDARY_PROTOCOL.maxChannels, `roles[${index}].allowedChannelIds`) });
    });
    if (roles.length === 0 || new Set(roles.map((role) => role.roleId)).size !== roles.length || new Set(roles.map((role) => role.principalId)).size !== roles.length) throw new NativeBoundaryProtocolError("launch roles/principals are empty or duplicated");
    return Object.freeze({ kind, ...common, roles });
  }
  if (kind === "probe") { const roleHandleIds = stringList(row.roleHandleIds, NATIVE_BOUNDARY_PROTOCOL.maxRoles, "roleHandleIds"); if (roleHandleIds.length === 0) throw new NativeBoundaryProtocolError("probe roleHandleIds is empty"); return Object.freeze({ kind, ...common, roleHandleIds, challengeNonce: text(row.challengeNonce, "challengeNonce") }); }
  return Object.freeze({ kind, ...common, targetRequestId: text(row.targetRequestId, "targetRequestId") });
}

export function captureNativeBoundaryResponse(input: unknown): NativeBoundaryResponse {
  let value: CanonicalValue; try { value = decodeCanonical(encodeCanonical(input as CanonicalValue)); } catch (error) { throw new NativeBoundaryProtocolError(`response is not inert canonical data: ${error instanceof Error ? error.message : String(error)}`); }
  const row = plain(value, "response"); exact(row, ["protocol", "version", "requestId", "requestDigest", "deploymentId", "bootId", "nonce", "sequence", "helperArtifactDigest", "helperBuildId", "kernelBootId", "status", "roleHandles", "measurements", "failureCode"], "response"); if (row.protocol !== NATIVE_BOUNDARY_PROTOCOL.name || row.version !== NATIVE_BOUNDARY_PROTOCOL.version) throw new NativeBoundaryProtocolError("response protocol/version is unsupported"); const status = row.status; if (status !== "ok" && status !== "refused" && status !== "failed") throw new NativeBoundaryProtocolError("response status is unsupported");
  const roleHandles = list(row.roleHandles, NATIVE_BOUNDARY_PROTOCOL.maxRoles, "roleHandles", (entry, index) => { const handle = plain(entry, `roleHandles[${index}]`); exact(handle, ["roleId", "roleClass", "handleId", "incarnationDigest", "artifactDigest", "principalId"], `roleHandles[${index}]`); const roleClass = handle.roleClass; if (roleClass !== "D1" && roleClass !== "D2" && roleClass !== "D3" && roleClass !== "PROBER") throw new NativeBoundaryProtocolError("response role class is unsupported"); return Object.freeze({ roleId: text(handle.roleId, "roleId"), roleClass, handleId: text(handle.handleId, "handleId"), incarnationDigest: digest(handle.incarnationDigest, "incarnationDigest"), artifactDigest: digest(handle.artifactDigest, "artifactDigest"), principalId: text(handle.principalId, "principalId") }); });
  const measurements = list(row.measurements, NATIVE_BOUNDARY_PROTOCOL.maxMeasurements, "measurements", (entry, index) => { const measurement = plain(entry, `measurements[${index}]`); exact(measurement, ["measurementId", "roleHandleId", "field", "state", "evidenceDigest"], `measurements[${index}]`); const state = measurement.state; if (state !== "active" && state !== "inactive" && state !== "unsupported" && state !== "inconclusive") throw new NativeBoundaryProtocolError("measurement state is unsupported"); return Object.freeze({ measurementId: text(measurement.measurementId, "measurementId"), roleHandleId: text(measurement.roleHandleId, "roleHandleId"), field: text(measurement.field, "field"), state, evidenceDigest: digest(measurement.evidenceDigest, "evidenceDigest") }); });
  if ((status === "ok" && row.failureCode !== "") || (status !== "ok" && (typeof row.failureCode !== "string" || !IDENTIFIER.test(row.failureCode)))) throw new NativeBoundaryProtocolError("response failure code/status mismatch");
  if (new Set(roleHandles.map((handle) => handle.handleId)).size !== roleHandles.length || new Set(measurements.map((measurement) => measurement.measurementId)).size !== measurements.length) throw new NativeBoundaryProtocolError("response handles/measurements are duplicated");
  return Object.freeze({ protocol: NATIVE_BOUNDARY_PROTOCOL.name, version: NATIVE_BOUNDARY_PROTOCOL.version, requestId: text(row.requestId, "requestId"), requestDigest: digest(row.requestDigest, "requestDigest"), deploymentId: text(row.deploymentId, "deploymentId"), bootId: text(row.bootId, "bootId"), nonce: text(row.nonce, "nonce"), sequence: integer(row.sequence, "sequence"), helperArtifactDigest: digest(row.helperArtifactDigest, "helperArtifactDigest"), helperBuildId: text(row.helperBuildId, "helperBuildId"), kernelBootId: text(row.kernelBootId, "kernelBootId"), status, roleHandles, measurements, failureCode: row.failureCode as string });
}

export function encodeNativeBoundaryFrame(value: NativeBoundaryRequest | NativeBoundaryResponse): Uint8Array { const payload = encodeCanonical(value as unknown as CanonicalValue); if (payload.length === 0 || payload.length > NATIVE_BOUNDARY_PROTOCOL.maxFrameBytes) throw new NativeBoundaryProtocolError("frame payload exceeds bound"); const out = new Uint8Array(payload.length + 4); new DataView(out.buffer).setUint32(0, payload.length, false); out.set(payload, 4); return out; }
export class NativeBoundaryFrameDecoder {
  #buffer = new Uint8Array(0); #closed = false;
  push(chunk: Uint8Array): readonly CanonicalValue[] {
    if (this.#closed) throw new NativeBoundaryProtocolError("decoder is closed");
    if (types.isProxy(chunk)) throw new NativeBoundaryProtocolError("Proxy byte chunks are not admitted");
    if (!(chunk instanceof Uint8Array) || chunk.length === 0) return Object.freeze([]);
    if (this.#buffer.length + chunk.length > NATIVE_BOUNDARY_PROTOCOL.maxFrameBytes + 4) throw new NativeBoundaryProtocolError("buffer exceeds one bounded frame");
    const joined = new Uint8Array(this.#buffer.length + chunk.length);
    joined.set(this.#buffer);
    joined.set(chunk, this.#buffer.length);
    this.#buffer = joined;
    if (joined.length < 4) return Object.freeze([]);
    const length = new DataView(joined.buffer, joined.byteOffset, joined.byteLength).getUint32(0, false);
    if (length === 0 || length > NATIVE_BOUNDARY_PROTOCOL.maxFrameBytes) throw new NativeBoundaryProtocolError("frame length is invalid");
    if (joined.length < length + 4) return Object.freeze([]);
    if (joined.length !== length + 4) throw new NativeBoundaryProtocolError("multiple/trailing frames require a fresh decoder");
    const payload = joined.slice(4);
    if (!isCanonical(payload)) throw new NativeBoundaryProtocolError("frame payload is not canonical CBOR");
    this.#buffer = new Uint8Array(0);
    this.#closed = true;
    return Object.freeze([decodeCanonical(payload)]);
  }
  finish(): void { if (!this.#closed || this.#buffer.length !== 0) throw new NativeBoundaryProtocolError("channel ended with a truncated or absent frame"); }
}

function reconcileResponse(request: NativeBoundaryRequest, response: NativeBoundaryResponse): void {
  if (response.requestId !== request.requestId || response.requestDigest !== nativeBoundaryRequestDigest(request) || response.deploymentId !== request.deploymentId || response.bootId !== request.bootId || response.nonce !== request.nonce || response.sequence !== request.sequence) throw new NativeBoundaryProtocolError("response is not bound to the exact request");
  if (response.status !== "ok") { if (response.roleHandles.length !== 0 || response.measurements.length !== 0) throw new NativeBoundaryProtocolError("failed/refused response contains partial success"); return; }
  if (request.kind === "cancel") { if (response.roleHandles.length !== 0 || response.measurements.length !== 0) throw new NativeBoundaryProtocolError("cancel response contains authority-bearing output"); return; }
  if (request.kind === "launch") {
    if (response.roleHandles.length !== request.roles.length) throw new NativeBoundaryProtocolError("launch response role closure is incomplete");
    const requested = new Map(request.roles.map((role) => [role.roleId, role] as const));
    for (const handle of response.roleHandles) { const role = requested.get(handle.roleId); if (role === undefined || handle.roleClass !== role.roleClass || handle.principalId !== role.principalId || handle.artifactDigest !== role.artifactDigest) throw new NativeBoundaryProtocolError("launch response substituted a role identity/artifact"); }
    const handles = new Set(response.roleHandles.map((handle) => handle.handleId)); const returnedRoleIds = new Set(response.roleHandles.map((handle) => handle.roleId)); if (handles.size !== response.roleHandles.length || returnedRoleIds.size !== response.roleHandles.length || returnedRoleIds.size !== requested.size) throw new NativeBoundaryProtocolError("launch response duplicated or omitted a role/handle");
    for (const measurement of response.measurements) if (!handles.has(measurement.roleHandleId)) throw new NativeBoundaryProtocolError("launch measurement references a foreign handle");
    for (const handle of handles) if (!response.measurements.some((measurement) => measurement.roleHandleId === handle)) throw new NativeBoundaryProtocolError("launch response lacks measurement coverage");
    return;
  }
  if (response.roleHandles.length !== 0) throw new NativeBoundaryProtocolError("probe response minted unexpected role handles");
  const requestedHandles = new Set(request.roleHandleIds); for (const measurement of response.measurements) if (!requestedHandles.has(measurement.roleHandleId)) throw new NativeBoundaryProtocolError("probe measurement references an unrequested handle");
  for (const handle of requestedHandles) if (!response.measurements.some((measurement) => measurement.roleHandleId === handle)) throw new NativeBoundaryProtocolError("probe response lacks requested-handle coverage");
}

async function exchangeOnce(port: NativeBoundaryPort, request: NativeBoundaryRequest): Promise<NativeBoundaryResponse> { const response = captureNativeBoundaryResponse(await port.exchange(request)); reconcileResponse(request, response); return response; }

/** Stateful fail-stop client. One channel admits one strictly advancing request at a time and never recovers after error. */
export class NativeBoundarySession {
  readonly #port: NativeBoundaryPort; readonly #deploymentId: string; readonly #bootId: string; readonly #manifestDigest: string; readonly #nowMs: () => bigint; readonly #maxRequestMs: bigint;
  #nextSequence = 0n; #inFlight = false; #closed = false; #lastNowMs: bigint | undefined; readonly #usedIds = new Set<string>(); readonly #usedNonces = new Set<string>();
  constructor(input: { readonly port: NativeBoundaryPort; readonly deploymentId: string; readonly bootId: string; readonly manifestDigest: string; readonly nowMs: () => bigint; readonly maxRequestMs: bigint }) { this.#port = input.port; this.#deploymentId = text(input.deploymentId, "deploymentId"); this.#bootId = text(input.bootId, "bootId"); this.#manifestDigest = digest(input.manifestDigest, "manifestDigest"); if (typeof input.nowMs !== "function" || typeof input.maxRequestMs !== "bigint" || input.maxRequestMs < 1n || input.maxRequestMs > 60_000n) throw new NativeBoundaryProtocolError("session clock/request bound is invalid"); this.#nowMs = input.nowMs; this.#maxRequestMs = input.maxRequestMs; }
  get nextSequence(): bigint { return this.#nextSequence; }
  get closed(): boolean { return this.#closed; }
  #terminate(reason: string): void { if (!this.#closed) { this.#closed = true; try { this.#port.close(reason); } catch { /* already fail-stop */ } } }
  #readClock(floor?: bigint): bigint { let now: unknown; try { now = this.#nowMs(); } catch { this.#terminate("clock-failure"); throw new NativeBoundaryProtocolError("trusted clock failed"); } if (typeof now !== "bigint" || now < 0n || (floor !== undefined && now < floor) || (this.#lastNowMs !== undefined && now < this.#lastNowMs)) { this.#terminate("clock-regression"); throw new NativeBoundaryProtocolError("trusted clock regressed or was malformed"); } this.#lastNowMs = now; return now; }
  async exchange(input: unknown): Promise<NativeBoundaryResponse> {
    if (this.#closed) throw new NativeBoundaryProtocolError("session is closed");
    let request: NativeBoundaryRequest; try { request = captureNativeBoundaryRequest(input); } catch (error) { this.#terminate("malformed-request"); throw error; }
    const now = this.#readClock();
    if (request.deploymentId !== this.#deploymentId || request.bootId !== this.#bootId || request.manifestDigest !== this.#manifestDigest || request.sequence !== this.#nextSequence || this.#usedIds.has(request.requestId) || this.#usedNonces.has(request.nonce) || request.deadlineMs <= now || request.deadlineMs - now > this.#maxRequestMs) { this.#terminate("request-replay-regression-or-scope"); throw new NativeBoundaryProtocolError("request replay, regression, scope, or deadline mismatch"); }
    if (this.#inFlight) { this.#terminate("concurrency-limit"); throw new NativeBoundaryProtocolError("session permits only one in-flight request"); }
    this.#usedIds.add(request.requestId); this.#usedNonces.add(request.nonce); this.#nextSequence++; this.#inFlight = true;
    const delay = Number(request.deadlineMs - now); let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => { timer = setTimeout(() => { this.#terminate("deadline-exceeded"); reject(new NativeBoundaryProtocolError("request deadline exceeded")); }, delay); });
    try { const result = await Promise.race([exchangeOnce(this.#port, request), timeout]); const completedAt = this.#readClock(now); if (completedAt >= request.deadlineMs) { this.#terminate("deadline-exceeded"); throw new NativeBoundaryProtocolError("response arrived after deadline"); } if (this.#closed) throw new NativeBoundaryProtocolError("session closed while request was in flight"); return result; }
    catch (error) { this.#terminate("exchange-failed"); throw error; }
    finally { if (timer !== undefined) clearTimeout(timer); this.#inFlight = false; }
  }
  makeBase(kind: NativeBoundaryRequest["kind"], deadlineMs: bigint): RequestBase & { readonly kind: NativeBoundaryRequest["kind"] } { return Object.freeze({ protocol: NATIVE_BOUNDARY_PROTOCOL.name, version: NATIVE_BOUNDARY_PROTOCOL.version, kind, requestId: `request.${randomBytes(16).toString("hex")}`, deploymentId: this.#deploymentId, bootId: this.#bootId, manifestDigest: this.#manifestDigest, nonce: `nonce.${randomBytes(16).toString("hex")}`, sequence: this.#nextSequence, deadlineMs }); }
}
