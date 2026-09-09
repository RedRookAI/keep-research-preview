/** One-shot installed native input capture. Returned bytes are data, never effect authority. */
import { spawn } from "node:child_process";
import { createHash, type Hash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync, realpathSync, type BigIntStats } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { types } from "node:util";
import { decodeCanonical, encodeCanonical, type CanonicalValue } from "../eir/canonical.js";
import { parsePolicyJson } from "../policy/json.js";
import { isCanonicalNativeP2RelativePath } from "./native_p2_path.js";

const MIB = 1024 * 1024;
const FRAME = 65_536;
const CHUNK = 32_768;
const PACKAGE_DIRECTORY = fileURLToPath(new URL("../../native/linux-x64/", import.meta.url));
const REQUEST_COMMON = ["schema", "version", "root", "sourceKind", "sourcePath", "overlayPath", "overlayByteDigest", "carrierPath", "carrierByteDigest"];
const HEADER_COMMON = ["record", "schema", "version", "requestDigest", "sourceKind", "sourceRowDigest", "overlayTypedDigest", "carrierTypedDigest", "overlayByteDigest", "carrierByteDigest", "sourceCount", "sourceBytes", "overlayBytes", "carrierBytes"];
// Canonical chunk maps have exactly this key order. Match their small envelope
// against the retained encoder without decoding/re-encoding the 32KiB payload.
const CHUNK_PREFIX = Buffer.concat([Buffer.from([0xa3]), encodeCanonical("bytes")]);
const CHUNK_SUFFIX = Buffer.concat([encodeCanonical("record"), encodeCanonical("chunk"), encodeCanonical("sequence")]);
const CODES = ["MALFORMED", "LIMIT", "PATH", "TYPE", "INTEGRITY", "RACE", "UNSUPPORTED", "IO", "CANCELLED"] as const;
export type NativePatchCaptureCode = typeof CODES[number];

export class NativePatchCaptureError extends Error {
  constructor(readonly code: NativePatchCaptureCode, detail: string) {
    super(`native patch capture: ${code}: ${detail}`);
    this.name = "NativePatchCaptureError";
  }
}
function fail(code: NativePatchCaptureCode, detail: string): never { throw new NativePatchCaptureError(code, detail); }
function wrapped(error: unknown): NativePatchCaptureError {
  return error instanceof NativePatchCaptureError ? error : new NativePatchCaptureError("IO", "capture transport failed");
}

interface RequestCommon {
  readonly schema: "keep.patch-input-capture";
  readonly version: 1n;
  readonly root: string;
  readonly sourcePath: string;
  readonly overlayPath: string;
  readonly overlayByteDigest: string;
  readonly carrierPath: string;
  readonly carrierByteDigest: string;
}
export type NativePatchCaptureRequestV1 = RequestCommon & (
  | { readonly sourceKind: "directory"; readonly expectedSourceRowDigest: string; readonly declaredBaseArchiveDigest: string }
  | { readonly sourceKind: "tar" | "tar-gzip"; readonly sourceStreamDigest: string }
);
export interface NativePatchCaptureOptionsV1 {
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
}
export interface CapturedNativePatchFileV1 {
  readonly path: string;
  readonly mode: number;
  readonly byteLength: number;
  readonly byteDigest: string;
  bytes(): Uint8Array;
}
interface CaptureIdentity {
  readonly requestDigest: string;
  readonly responseDigest: string;
  readonly sourceRowDigest: string;
  readonly sourceBytes: number;
  readonly overlayTypedDigest: string;
  readonly carrierTypedDigest: string;
  readonly overlayByteDigest: string;
  readonly carrierByteDigest: string;
}
export type CapturedNativePatchInputsV1 = CaptureIdentity & (
  | { readonly sourceKind: "directory"; readonly declaredBaseArchiveDigest: string }
  | { readonly sourceKind: "tar" | "tar-gzip"; readonly sourceStreamDigest: string }
) & {
  readonly kind: "CapturedNativePatchInputsV1";
  readonly files: readonly CapturedNativePatchFileV1[];
  overlayBytes(): Uint8Array;
  carrierBytes(): Uint8Array;
  readonly filesystem: false;
  readonly signature: false;
  readonly build: false;
  readonly install: false;
  readonly launch: false;
};

// Inspect descriptors before reading values: no getter, proxy or hidden field can
// acquire input files or affect execution. The returned shallow snapshot is owned.
function object(input: unknown): Record<string, unknown> {
  if (input === null || typeof input !== "object" || types.isProxy(input)) fail("MALFORMED", "expected inert record");
  const prototype = Object.getPrototypeOf(input);
  if ((prototype !== null && prototype !== Object.prototype) || Object.getOwnPropertySymbols(input).length !== 0)
    fail("MALFORMED", "record prototype or symbols refused");
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Object.keys(descriptors).length > 32) fail("LIMIT", "record field bound");
  const result: Record<string, unknown> = Object.create(null);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!("value" in descriptor) || !descriptor.enumerable) fail("MALFORMED", "record accessor or hidden field");
    result[key] = descriptor.value;
  }
  return result;
}
function exact(row: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(row);
  if (actual.length !== keys.length || actual.some(key => !keys.includes(key))) fail("MALFORMED", "record fields are not exact");
}
function digest(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value) || value === "0".repeat(64)) fail("MALFORMED", "digest shape");
  return value;
}
function uint(value: unknown, maximum: number, minimum = 0): number {
  if (typeof value !== "bigint" || value < BigInt(minimum)) fail("MALFORMED", "unsigned integer required");
  if (value > BigInt(maximum)) fail("LIMIT", "integer exceeds bound");
  return Number(value);
}
function relative(value: unknown): string {
  if (typeof value !== "string" || value.length > 4096 || !isCanonicalNativeP2RelativePath(value)) fail("PATH", "input path grammar");
  return value;
}
function requestSnapshot(input: unknown): NativePatchCaptureRequestV1 {
  const row = object(input);
  const directory = row.sourceKind === "directory";
  if (!directory && row.sourceKind !== "tar" && row.sourceKind !== "tar-gzip") fail("MALFORMED", "source kind");
  exact(row, [...REQUEST_COMMON, ...(directory ? ["expectedSourceRowDigest", "declaredBaseArchiveDigest"] : ["sourceStreamDigest"])]);
  if (row.schema !== "keep.patch-input-capture" || row.version !== 1n) fail("MALFORMED", "request schema/version");
  if (typeof row.root !== "string" || row.root.length > 4096 || !row.root.startsWith("/") || !isCanonicalNativeP2RelativePath(row.root.slice(1)))
    fail("PATH", "root must be a canonical absolute path");
  const paths = [relative(row.sourcePath), relative(row.overlayPath), relative(row.carrierPath)].map(path => path.toLowerCase());
  for (let a = 0; a < paths.length; a++) for (let b = a + 1; b < paths.length; b++) {
    if (paths[a] === paths[b] || paths[a]!.startsWith(`${paths[b]}/`) || paths[b]!.startsWith(`${paths[a]}/`))
      fail("PATH", "input paths overlap");
  }
  for (const key of ["overlayByteDigest", "carrierByteDigest", ...(directory ? ["expectedSourceRowDigest", "declaredBaseArchiveDigest"] : ["sourceStreamDigest"])]) digest(row[key]);
  return Object.freeze(row) as unknown as NativePatchCaptureRequestV1;
}

function sameFile(before: BigIntStats, after: BigIntStats): boolean {
  return (["dev", "ino", "mode", "nlink", "uid", "gid", "size", "mtimeNs", "ctimeNs"] as const).every(key => before[key] === after[key]);
}
function readHeld(fd: number, size: number, consume: (chunk: Buffer) => void): void {
  const buffer = Buffer.alloc(Math.min(FRAME, size));
  let offset = 0;
  while (offset < size) {
    const read = readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), null);
    if (read === 0) fail("RACE", "packaged file truncated");
    consume(buffer.subarray(0, read)); offset += read;
  }
  if (readSync(fd, Buffer.alloc(1), 0, 1, null) !== 0) fail("RACE", "packaged file grew");
}
function openPackageFile(name: string): number {
  const path = join(PACKAGE_DIRECTORY, name);
  if (realpathSync(path) !== path) fail("PATH", "packaged artifact path is not canonical");
  return openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
}
function verifiedExecutable(): number {
  if (process.platform !== "linux" || process.arch !== "x64") fail("UNSUPPORTED", "no packaged capture for this platform");
  const manifestFd = openPackageFile("capture-manifest.json");
  let row: Record<string, unknown>;
  try {
    const before = fstatSync(manifestFd, { bigint: true });
    if (!before.isFile() || (before.mode & 0o7777n) !== 0o644n) fail("TYPE", "capture manifest type/mode");
    const bytes = Buffer.alloc(uint(before.size, 16_384, 1));
    let offset = 0;
    readHeld(manifestFd, bytes.length, chunk => { bytes.set(chunk, offset); offset += chunk.length; });
    if (!sameFile(before, fstatSync(manifestFd, { bigint: true }))) fail("RACE", "capture manifest changed");
    try { row = object(parsePolicyJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes))); }
    catch { fail("MALFORMED", "capture manifest JSON"); }
  } finally { closeSync(manifestFd); }
  exact(row, ["schema", "target", "platform", "architecture", "profile", "artifacts"]);
  if (row.schema !== "keep.patch-capture-package/v1" || row.target !== "x86_64-unknown-linux-musl" || row.platform !== "linux" || row.architecture !== "x64" || row.profile !== "keep.patch-input-capture/v1" || !Array.isArray(row.artifacts) || row.artifacts.length !== 1)
    fail("MALFORMED", "capture package identity");
  const artifact = object(row.artifacts[0]);
  exact(artifact, ["name", "bytes", "sha256", "mode"]);
  if (artifact.name !== "keep-native-patch-capture" || artifact.mode !== 0o755n) fail("MALFORMED", "capture executable identity");
  const size = uint(artifact.bytes, 64 * MIB, 1);
  const expected = digest(artifact.sha256);
  const fd = openPackageFile(artifact.name);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || (before.mode & 0o7777n) !== 0o755n) fail("TYPE", "capture executable type/mode");
    if (before.size !== BigInt(size)) fail("INTEGRITY", "capture executable size");
    const hash = createHash("sha256");
    readHeld(fd, size, bytes => { hash.update(bytes); });
    if (!sameFile(before, fstatSync(fd, { bigint: true }))) fail("RACE", "capture executable changed");
    if (hash.digest("hex") !== expected) fail("INTEGRITY", "capture executable hash");
    return fd;
  } catch (error) { closeSync(fd); throw error; }
}

type PendingBody = { bytes: Buffer; offset: number; sequence: number; expected: string; hash: Hash; done: (bytes: Buffer) => void };
class CaptureReceiver {
  private readonly frame = Buffer.alloc(FRAME + 4);
  private used = 0;
  private needed = 4;
  private frames = 0;
  private received = 0;
  private readonly responseHash = createHash("sha256").update("keep.patch-input-response/v1\0", "ascii");
  private readonly rowsHash = createHash("sha256").update("keep.patch-source-rows/v1\0", "ascii");
  private rowPreimageBytes = 0;
  private header: Record<string, unknown> | undefined;
  private body: PendingBody | undefined;
  private files: CapturedNativePatchFileV1[] = [];
  private sourceBytes = 0;
  private readonly namespace = new Map<string, { original: string; file: boolean }>();
  private directories = 0;
  private overlay: Buffer | undefined;
  private carrier: Buffer | undefined;
  private endDigest: string | undefined;
  constructor(private readonly request: NativePatchCaptureRequestV1, private readonly requestDigest: string) {}

  accept(chunk: Buffer): void {
    this.received += chunk.length;
    if (this.received > 320 * MIB) fail("LIMIT", "response byte bound");
    for (let offset = 0; offset < chunk.length;) {
      if (this.endDigest !== undefined) fail("MALFORMED", "data after END");
      const count = Math.min(chunk.length - offset, this.needed - this.used);
      chunk.copy(this.frame, this.used, offset, offset + count);
      this.used += count; offset += count;
      if (this.used !== this.needed) continue;
      if (this.needed === 4) {
        const length = this.frame.readUInt32BE(0);
        if (length === 0) fail("MALFORMED", "empty frame");
        if (length > FRAME || ++this.frames > 32_768) fail("LIMIT", "frame bound");
        this.needed = length + 4;
      } else {
        const payload = this.frame.subarray(4, this.needed);
        if (this.body !== undefined) {
          this.bodyFrame(payload, this.body);
          this.responseHash.update(this.frame.subarray(0, this.needed));
        } else {
          let decoded: CanonicalValue;
          try { decoded = decodeCanonical(payload); }
          catch { fail("MALFORMED", "response is not canonical CBOR"); }
          const row = object(decoded);
          // Closed metadata records admit only primitives; nested maps/arrays
          // never enter the protocol's depth/item profile.
          this.record(row);
          if (row.record !== "end") this.responseHash.update(this.frame.subarray(0, this.needed));
        }
        this.used = 0; this.needed = 4;
      }
    }
  }
  private hashRowPart(bytes: Uint8Array): void {
    this.rowPreimageBytes += bytes.length;
    if (this.rowPreimageBytes > 20 * MIB) fail("LIMIT", "CAPTURE_ROWS encoded bound");
    this.rowsHash.update(bytes);
  }
  private begin(bytes: number, expected: string, done: (bytes: Buffer) => void): void {
    const body: PendingBody = { bytes: Buffer.alloc(bytes), offset: 0, sequence: 0, expected, hash: createHash("sha256"), done };
    this.body = body;
    if (bytes === 0) this.completeBody(body);
  }
  private completeBody(body: PendingBody): void {
    if (body.hash.digest("hex") !== body.expected) fail("INTEGRITY", "captured byte hash");
    this.body = undefined;
    body.done(body.bytes);
  }
  private bodyFrame(payload: Buffer, body: PendingBody): void {
    const size = Math.min(CHUNK, body.bytes.length - body.offset);
    const lengthHead = encodeCanonical(BigInt(size));
    lengthHead[0] = lengthHead[0]! | 0x40; // Same shortest argument, CBOR major 2.
    const sequence = encodeCanonical(BigInt(body.sequence));
    const start = CHUNK_PREFIX.length + lengthHead.length, end = start + size;
    if (payload.length !== end + CHUNK_SUFFIX.length + sequence.length ||
        !payload.subarray(0, CHUNK_PREFIX.length).equals(CHUNK_PREFIX) ||
        !payload.subarray(CHUNK_PREFIX.length, start).equals(lengthHead) ||
        !payload.subarray(end, end + CHUNK_SUFFIX.length).equals(CHUNK_SUFFIX) ||
        !payload.subarray(end + CHUNK_SUFFIX.length).equals(sequence))
      fail("MALFORMED", "chunk is not the exact canonical size/sequence envelope");
    const bytes = payload.subarray(start, end);
    body.bytes.set(bytes, body.offset); body.offset += size; body.sequence++;
    body.hash.update(bytes);
    if (body.offset === body.bytes.length) this.completeBody(body);
  }
  private record(row: Record<string, unknown>): void {
    if (this.header === undefined) {
      const specific = this.request.sourceKind === "directory" ? "declaredBaseArchiveDigest" : "sourceStreamDigest";
      exact(row, [...HEADER_COMMON, specific]);
      if (row.record !== "header" || row.schema !== "keep.patch-input-result" || row.version !== 1n || row.sourceKind !== this.request.sourceKind)
        fail("MALFORMED", "response header identity");
      const base = this.request.sourceKind === "directory" ? this.request.declaredBaseArchiveDigest : this.request.sourceStreamDigest;
      if (row[specific] !== base || row.requestDigest !== this.requestDigest || row.overlayByteDigest !== this.request.overlayByteDigest || row.carrierByteDigest !== this.request.carrierByteDigest)
        fail("INTEGRITY", "request/response join");
      for (const field of ["sourceRowDigest", "overlayTypedDigest", "carrierTypedDigest"]) digest(row[field]);
      if (this.request.sourceKind === "directory" && row.sourceRowDigest !== this.request.expectedSourceRowDigest) fail("INTEGRITY", "declared source rows");
      const count = uint(row.sourceCount, 4096);
      uint(row.sourceBytes, 128 * MIB); uint(row.overlayBytes, MIB, 1); uint(row.carrierBytes, 130 * MIB, 1);
      this.header = row;
      this.hashRowPart(Buffer.from([0xa4])); // canonical 4-field map
      this.hashRowPart(encodeCanonical("files"));
      // Only array counts <=4096 are possible. No bulk metadata/payload encoding.
      this.hashRowPart(Buffer.from(count < 24 ? [0x80 + count] : count <= 255 ? [0x98, count] : [0x99, count >> 8, count & 255]));
      return;
    }
    if (this.files.length < Number(this.header.sourceCount)) {
      exact(row, ["record", "index", "path", "mode", "byteLength", "byteDigest"]);
      if (row.record !== "source-row" || row.index !== BigInt(this.files.length)) fail("MALFORMED", "source row order");
      const path = relative(row.path);
      if (path === ".cargo-checksum.json") fail("PATH", "reserved source path");
      const parts = path.split("/");
      if (parts.length > 32 || parts.some(part => part.length > 255)) fail("LIMIT", "source path components");
      const prior = this.files.at(-1)?.path;
      if (prior !== undefined && prior >= path) fail("PATH", "source rows not strictly sorted");
      let prefix = "";
      for (let index = 0; index < parts.length; index++) {
        prefix += `${index === 0 ? "" : "/"}${parts[index]}`;
        const folded = prefix.toLowerCase(), file = index === parts.length - 1;
        const old = this.namespace.get(folded);
        if (old !== undefined && (old.original !== prefix || old.file || file)) fail("PATH", "source namespace collision");
        if (old === undefined) {
          if (!file && ++this.directories > 8192) fail("LIMIT", "source directory bound");
          this.namespace.set(folded, { original: prefix, file });
        }
      }
      const mode = uint(row.mode, 0xffff_ffff);
      if (mode > 0o777) fail("TYPE", "source mode includes prohibited bits");
      const byteLength = uint(row.byteLength, 16 * MIB);
      const byteDigest = digest(row.byteDigest);
      this.sourceBytes += byteLength;
      if (this.sourceBytes > Number(this.header.sourceBytes)) fail("INTEGRITY", "source byte count");
      this.hashRowPart(encodeCanonical({ path, mode: BigInt(mode), byteLength: BigInt(byteLength), byteDigest }));
      this.begin(byteLength, byteDigest, bytes => { this.files.push(Object.freeze({ path, mode, byteLength, byteDigest, bytes: () => Uint8Array.from(bytes) })); });
      return;
    }
    if (this.overlay === undefined || this.carrier === undefined) {
      exact(row, ["record", "role", "byteLength", "byteDigest"]);
      const role = this.overlay === undefined ? "overlay" : "carrier";
      if (row.record !== "input" || row.role !== role || row.byteLength !== this.header[`${role}Bytes`] || row.byteDigest !== this.request[`${role}ByteDigest`])
        fail("INTEGRITY", "input metadata join/order");
      this.begin(Number(row.byteLength), digest(row.byteDigest), bytes => {
        const domain = role === "overlay" ? "keep.p2-d2-patch-overlay/v1\0" : "keep.p2-d2-patch-byte-carrier-set/v1\0";
        if (createHash("sha256").update(domain, "ascii").update(bytes).digest("hex") !== this.header![`${role}TypedDigest`]) fail("INTEGRITY", "typed input digest");
        // Bulk canonical parsing and the exact overlay/carrier operation join are
        // owned by the verified native executable, before it emits any response.
        // Re-running the legacy JS bulk encoder here would violate the RAM bound.
        if (role === "overlay") this.overlay = bytes; else this.carrier = bytes;
      });
      return;
    }
    exact(row, ["record", "responseDigest"]);
    if (row.record !== "end") fail("MALFORMED", "END required");
    const expected = digest(row.responseDigest);
    if (this.responseHash.digest("hex") !== expected) fail("INTEGRITY", "response digest");
    for (const item of ["schema", "keep.patch-source-rows", "version", 1n, "packageId", "curve25519-dalek@5.0.0"]) this.hashRowPart(encodeCanonical(item));
    if (this.sourceBytes !== Number(this.header.sourceBytes) || this.rowsHash.digest("hex") !== this.header.sourceRowDigest) fail("INTEGRITY", "source rows commitment");
    this.endDigest = expected;
  }
  discard(): void { this.files = []; this.body = undefined; this.overlay = undefined; this.carrier = undefined; this.namespace.clear(); }
  finish(): CapturedNativePatchInputsV1 {
    if (this.used !== 0 || this.endDigest === undefined || this.header === undefined || this.overlay === undefined || this.carrier === undefined || this.body !== undefined)
      fail("MALFORMED", "incomplete response");
    const overlay = this.overlay, carrier = this.carrier;
    const result = Object.freeze({
      kind: "CapturedNativePatchInputsV1" as const,
      ...(this.request.sourceKind === "directory"
        ? { sourceKind: "directory" as const, declaredBaseArchiveDigest: this.request.declaredBaseArchiveDigest }
        : { sourceKind: this.request.sourceKind, sourceStreamDigest: this.request.sourceStreamDigest }),
      requestDigest: this.requestDigest, responseDigest: this.endDigest,
      sourceRowDigest: digest(this.header.sourceRowDigest), sourceBytes: this.sourceBytes,
      overlayTypedDigest: digest(this.header.overlayTypedDigest), carrierTypedDigest: digest(this.header.carrierTypedDigest),
      overlayByteDigest: this.request.overlayByteDigest, carrierByteDigest: this.request.carrierByteDigest,
      files: Object.freeze(this.files), overlayBytes: () => Uint8Array.from(overlay), carrierBytes: () => Uint8Array.from(carrier),
      filesystem: false as const, signature: false as const, build: false as const, install: false as const, launch: false as const,
    });
    this.discard();
    return result;
  }
}

const abortedGetter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")!.get!;

/** Fixed verified-handle execution. No caller executable, environment override, retries or partial output. */
export async function capturePackagedNativePatchInputsV1(input: unknown, options: NativePatchCaptureOptionsV1 = {}): Promise<CapturedNativePatchInputsV1> {
  const started = performance.now();
  const request = requestSnapshot(input);
  const opts = object(options);
  if (Object.keys(opts).some(key => key !== "timeoutMs" && key !== "signal")) fail("MALFORMED", "unknown capture option");
  const timeout = Object.hasOwn(opts, "timeoutMs") ? opts.timeoutMs : 30_000;
  if (typeof timeout !== "number" || !Number.isSafeInteger(timeout) || timeout < 1 || timeout > 60_000) fail("MALFORMED", "timeout must be 1..60000ms");
  let signal: AbortSignal | undefined;
  if (Object.hasOwn(opts, "signal")) {
    if (opts.signal === null || typeof opts.signal !== "object" || types.isProxy(opts.signal) || Object.getPrototypeOf(opts.signal) !== AbortSignal.prototype) fail("MALFORMED", "AbortSignal required");
    signal = opts.signal as AbortSignal;
    try { if (abortedGetter.call(signal)) fail("CANCELLED", "capture aborted before execution"); }
    catch (error) { if (error instanceof NativePatchCaptureError) throw error; fail("MALFORMED", "invalid AbortSignal"); }
  }
  const payload = encodeCanonical(request as unknown as CanonicalValue);
  if (payload.length > FRAME) fail("LIMIT", "request frame bound");
  const frame = Buffer.alloc(payload.length + 4); frame.writeUInt32BE(payload.length); frame.set(payload, 4);
  const requestDigest = createHash("sha256").update("keep.patch-input-request/v1\0", "ascii").update(payload).digest("hex");
  let child;
  try {
    const fd = verifiedExecutable();
    try {
      if (performance.now() - started >= timeout) fail("CANCELLED", "capture deadline exceeded");
      child = spawn("/proc/self/fd/3", [], { cwd: "/", env: {}, shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe", fd] });
    } finally { closeSync(fd); }
  } catch (error) { throw wrapped(error); }
  const receiver = new CaptureReceiver(request, requestDigest);
  return await new Promise<CapturedNativePatchInputsV1>((resolve, reject) => {
    let failure: NativePatchCaptureError | undefined;
    let stdinFailed = false, stdoutEnded = false, stderrEnded = false;
    let stdoutBytes = 0, stderrBytes = 0;
    const stderr = Buffer.alloc(4096);
    const terminate = (error: NativePatchCaptureError): void => {
      failure ??= error;
      receiver.discard();
      child.kill("SIGKILL"); // Wait for close before returning: no abandoned live operation.
    };
    const abort = (): void => terminate(new NativePatchCaptureError("CANCELLED", "capture aborted"));
    const timer = setTimeout(() => terminate(new NativePatchCaptureError("CANCELLED", "capture deadline exceeded")), Math.max(1, timeout - (performance.now() - started)));
    if (signal !== undefined) {
      EventTarget.prototype.addEventListener.call(signal, "abort", abort, { once: true });
      if (abortedGetter.call(signal)) abort();
    }
    child.on("error", () => terminate(new NativePatchCaptureError("IO", "capture process error")));
    child.stdin!.on("error", () => { stdinFailed = true; }); // A terminal typed refusal may precede stdin EOF (EPIPE).
    child.stdout!.on("error", () => terminate(new NativePatchCaptureError("IO", "capture stdout error")));
    child.stderr!.on("error", () => terminate(new NativePatchCaptureError("IO", "capture stderr error")));
    child.stdout!.on("end", () => { stdoutEnded = true; });
    child.stderr!.on("end", () => { stderrEnded = true; });
    child.stdout!.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (failure !== undefined) return;
      if (performance.now() - started >= timeout) { terminate(new NativePatchCaptureError("CANCELLED", "capture deadline exceeded")); return; }
      try { receiver.accept(chunk); } catch (error) { terminate(wrapped(error)); }
    });
    child.stderr!.on("data", (chunk: Buffer) => {
      if (failure !== undefined) return;
      if (stderrBytes + chunk.length > stderr.length) { terminate(new NativePatchCaptureError("LIMIT", "capture stderr bound")); return; }
      stderr.set(chunk, stderrBytes); stderrBytes += chunk.length;
    });
    child.on("close", (code, exitSignal) => {
      clearTimeout(timer);
      if (signal !== undefined) EventTarget.prototype.removeEventListener.call(signal, "abort", abort);
      try {
        if (failure !== undefined) throw failure;
        if (performance.now() - started >= timeout) fail("CANCELLED", "capture deadline exceeded");
        const refusal = stderr.subarray(0, stderrBytes).toString("utf8");
        if (code === 2 && exitSignal === null && stdoutBytes === 0 && CODES.some(value => refusal === `${value}\n`))
          fail(refusal.slice(0, -1) as NativePatchCaptureCode, "native input refused");
        if (code !== 0 || exitSignal !== null || stdinFailed || !stdoutEnded || !stderrEnded || stderrBytes !== 0) fail("IO", "capture did not terminate cleanly");
        resolve(receiver.finish());
      } catch (error) { receiver.discard(); reject(wrapped(error)); }
    });
    child.stdin!.end(frame);
  });
}
