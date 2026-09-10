/** Refusal-only packaged A6 transport. No launch, credential, network, profile, evidence, or VMM authority. */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { encodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import {
  captureNativeBoundaryV2Request,
  captureNativeBoundaryV2Response,
  decodeNativeV2Canonical,
  validateNativeBoundaryV2Exchange,
  type NativeBoundaryV2Request,
  type NativeBoundaryV2Response,
} from "./native_boundary_protocol_v2.js";

const CHANNEL_MAX_FRAME_BYTES = 65_536;
const STDERR_MAX_BYTES = 4096;
const MANIFEST_MAX_BYTES = 16_384;
const PACKAGE_DIRECTORY = fileURLToPath(
  new URL("../../native/linux-x64/", import.meta.url),
);

export class NativeBoundaryTransportUnavailableError extends Error {
  constructor(message: string) {
    super(`native boundary transport unavailable: ${message}`);
    this.name = "NativeBoundaryTransportUnavailableError";
  }
}

export class NativeBoundaryTransportError extends Error {
  constructor(message: string) {
    super(`native boundary transport: ${message}`);
    this.name = "NativeBoundaryTransportError";
  }
}

export interface PackagedNativeBoundaryOptions {
  readonly socketPath: string;
  readonly expectedServerUid: number;
  readonly expectedServerGid: number;
  readonly expectedServerSecurityLabel: string;
  readonly timeoutMs?: number;
}

type Artifact = { name: string; bytes: number; sha256: string; mode: number };
type Manifest = {
  schema: string;
  target: string;
  platform: string;
  architecture: string;
  protocolVersion: number;
  channelMaxFrameBytes: number;
  artifacts: Artifact[];
};

function exactObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    throw new NativeBoundaryTransportError(`${label} is not an owned object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index]))
    throw new NativeBoundaryTransportError(`${label} fields are not exact`);
  return value as Record<string, unknown>;
}

function readManifest(): Manifest {
  const path = join(PACKAGE_DIRECTORY, "manifest.json");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size < 1 || before.size > MANIFEST_MAX_BYTES || (before.mode & 0o022) !== 0)
      throw new NativeBoundaryTransportError("package manifest type, size, or mode is unsafe");
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || bytes.length !== before.size)
      throw new NativeBoundaryTransportError("package manifest changed during capture");
    let parsed: unknown;
    try { parsed = JSON.parse(bytes.toString("utf8")); }
    catch { throw new NativeBoundaryTransportError("package manifest is not JSON"); }
    const row = exactObject(parsed, ["schema", "target", "platform", "architecture", "protocolVersion", "channelMaxFrameBytes", "artifacts"], "package manifest");
    if (
      row.schema !== "keep.native-transport-package/v1" ||
      row.target !== "x86_64-unknown-linux-musl" || row.platform !== "linux" ||
      row.architecture !== "x64" || row.protocolVersion !== 2 ||
      row.channelMaxFrameBytes !== CHANNEL_MAX_FRAME_BYTES || !Array.isArray(row.artifacts) ||
      row.artifacts.length !== 2
    ) throw new NativeBoundaryTransportError("package manifest identity is unsupported");
    const artifacts = row.artifacts.map((value, index) => {
      const artifact = exactObject(value, ["name", "bytes", "sha256", "mode"], `artifact[${index}]`);
      if (
        typeof artifact.name !== "string" || !["keep-native-client", "keep-native-supervisor"].includes(artifact.name) ||
        !Number.isSafeInteger(artifact.bytes) || (artifact.bytes as number) < 1 ||
        typeof artifact.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(artifact.sha256) ||
        artifact.mode !== 0o555
      ) throw new NativeBoundaryTransportError(`artifact[${index}] identity is malformed`);
      return artifact as Artifact;
    });
    if (artifacts[0]?.name !== "keep-native-client" || artifacts[1]?.name !== "keep-native-supervisor" || artifacts[0].sha256 === artifacts[1].sha256)
      throw new NativeBoundaryTransportError("package artifact closure is not exact");
    return { ...row, artifacts } as Manifest;
  } finally {
    closeSync(fd);
  }
}

function openVerifiedClient(): number {
  if (process.platform !== "linux" || process.arch !== "x64")
    throw new NativeBoundaryTransportUnavailableError(`no packaged transport for ${process.platform}/${process.arch}`);
  const manifest = readManifest();
  const expected = manifest.artifacts[0]!;
  const path = join(PACKAGE_DIRECTORY, expected.name);
  if (realpathSync(path) !== path)
    throw new NativeBoundaryTransportError("packaged client path is not canonical");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size !== expected.bytes || (before.mode & 0o111) !== 0o111 || (before.mode & 0o022) !== 0)
      throw new NativeBoundaryTransportError("packaged client type, size, or mode mismatch");
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || bytes.length !== before.size)
      throw new NativeBoundaryTransportError("packaged client changed during capture");
    if (createHash("sha256").update(bytes).digest("hex") !== expected.sha256)
      throw new NativeBoundaryTransportError("packaged client digest mismatch");
    return fd;
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function optionInteger(value: number, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum)
    throw new NativeBoundaryTransportError(`${label} is outside its integer range`);
  return value;
}

function requestFrame(request: NativeBoundaryV2Request): Buffer {
  const payload = Buffer.from(encodeCanonical(request as unknown as CanonicalValue));
  if (payload.length < 1 || payload.length > CHANNEL_MAX_FRAME_BYTES)
    throw new NativeBoundaryTransportError("request exceeds development channel bound");
  const frame = Buffer.allocUnsafe(payload.length + 4);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

function responseFromFrame(frame: Buffer, request: NativeBoundaryV2Request): NativeBoundaryV2Response {
  if (frame.length < 5 || frame.length > CHANNEL_MAX_FRAME_BYTES + 4)
    throw new NativeBoundaryTransportError("response frame length is invalid");
  const length = frame.readUInt32BE(0);
  if (length < 1 || length > CHANNEL_MAX_FRAME_BYTES || frame.length !== length + 4)
    throw new NativeBoundaryTransportError("response frame is truncated, oversized, or trailing");
  const canonical = decodeNativeV2Canonical(frame.subarray(4), CHANNEL_MAX_FRAME_BYTES);
  const response = captureNativeBoundaryV2Response(canonical);
  validateNativeBoundaryV2Exchange(request, response);
  return response;
}

/** One packaged, one-shot cancel exchange. The executable is fixed and execute-through-handle. */
export async function exchangePackagedNativeCancel(
  options: PackagedNativeBoundaryOptions,
  input: unknown,
): Promise<NativeBoundaryV2Response> {
  const request = captureNativeBoundaryV2Request(input);
  if (request.kind !== "cancel")
    throw new NativeBoundaryTransportError("refusal-only slice accepts cancel requests only");
  if (!isAbsolute(options.socketPath) || Buffer.byteLength(options.socketPath) > 107 || options.socketPath.includes("\0"))
    throw new NativeBoundaryTransportError("socket path is not an absolute bounded Unix path");
  const uid = optionInteger(options.expectedServerUid, "expectedServerUid", 0xffff_ffff);
  const gid = optionInteger(options.expectedServerGid, "expectedServerGid", 0xffff_ffff);
  const securityLabel = options.expectedServerSecurityLabel;
  if (typeof securityLabel !== "string" || Buffer.byteLength(securityLabel) < 1 || Buffer.byteLength(securityLabel) > 4095 || securityLabel.includes("\0"))
    throw new NativeBoundaryTransportError("expectedServerSecurityLabel is not a bounded non-empty label");
  const timeoutMs = optionInteger(options.timeoutMs ?? 2000, "timeoutMs", 60_000);
  if (timeoutMs < 1) throw new NativeBoundaryTransportError("timeoutMs must be positive");
  const frame = requestFrame(request);
  const clientFd = openVerifiedClient();
  let child;
  try {
    child = spawn(
      "/proc/self/fd/3",
      ["--socket", options.socketPath, "--expected-server-uid", String(uid), "--expected-server-gid", String(gid), "--expected-server-security-label", securityLabel],
      { cwd: "/", env: {}, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe", clientFd] },
    );
  } finally {
    closeSync(clientFd);
  }
  const stdin = child.stdin;
  const stdoutStream = child.stdout;
  const stderrStream = child.stderr;
  if (stdin === null || stdoutStream === null || stderrStream === null) {
    child.kill("SIGKILL");
    throw new NativeBoundaryTransportError("client stdio pipes are unavailable");
  }
  return await new Promise<NativeBoundaryV2Response>((resolve, reject) => {
    let settled = false;
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let stdinFailure: string | undefined;
    const diagnostic = (message: string): NativeBoundaryTransportError => {
      const detail = stderr.toString("utf8").trim().replace(/[\r\n]+/g, " ");
      return new NativeBoundaryTransportError(`${message}${stdinFailure ? `; ${stdinFailure}` : ""}${detail ? `: ${detail}` : ""}`);
    };
    const finish = (error?: Error, response?: NativeBoundaryV2Response): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error !== undefined) reject(error); else resolve(response!);
    };
    const terminate = (message: string): void => {
      if (settled) return;
      child.kill("SIGKILL");
      finish(diagnostic(message));
    };
    const timer = setTimeout(() => terminate("client deadline exceeded"), timeoutMs);
    timer.unref();
    child.on("error", (error) => finish(new NativeBoundaryTransportError(`client spawn failed: ${error.message}`)));
    stdoutStream.on("data", (chunk: Buffer) => {
      if (stdout.length + chunk.length > CHANNEL_MAX_FRAME_BYTES + 4) terminate("client stdout exceeds one bounded frame");
      else stdout = Buffer.concat([stdout, chunk]);
    });
    stderrStream.on("data", (chunk: Buffer) => {
      if (stderr.length < STDERR_MAX_BYTES) stderr = Buffer.concat([stderr, chunk.subarray(0, STDERR_MAX_BYTES - stderr.length)]);
    });
    stdin.on("error", (error) => {
      // An early setup refusal can close stdin before its stderr arrives.
      // Keep the write failure; close drains the diagnostic, while the ORIGINAL
      // deadline still bounds a client that does not exit. Neither this error
      // nor diagnostic prose establishes delivery or absence of a peer effect.
      stdinFailure ??= `client stdin failed: ${error.message}`;
    });
    child.on("close", (code, signal) => {
      if (settled) return;
      if (stdinFailure !== undefined || code !== 0 || signal !== null) {
        finish(diagnostic(`client failed (${signal ?? code})`));
        return;
      }
      try { finish(undefined, responseFromFrame(stdout, request)); }
      catch (error) { finish(error instanceof Error ? error : new NativeBoundaryTransportError(String(error))); }
    });
    stdin.end(frame);
  });
}
