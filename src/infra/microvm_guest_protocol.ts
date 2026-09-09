/**
 * Verifier-owned framing for the Firecracker guest supervisor.
 *
 * The untrusted workload never writes to the serial device. The trusted guest supervisor captures bounded
 * stdout/stderr, then emits this frame. Lengths, digests, and an attempt nonce make payload marker injection
 * inert. This protocol proves receipt of one bounded result for one attempt; it does not make exit zero a
 * semantic proof.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const MICROVM_RESULT_SCHEMA = "keep.microvm-result/v1" as const;
const HEADER = "KEEP_RESULT_V1";
const END = "KEEP_RESULT_END_V1";
const SHA256_RE = /^[0-9a-f]{64}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const DECIMAL_RE = /^(0|[1-9][0-9]{0,9})$/;
const utf8 = new TextDecoder("utf-8", { fatal: true });

export interface MicrovmGuestResult {
  readonly schema: typeof MICROVM_RESULT_SCHEMA;
  readonly attemptNonce: string;
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutSha256: string;
  readonly stderrSha256: string;
}

export interface MicrovmGuestFrameLimits {
  readonly maxStreamBytes: number;
  readonly maxEnvelopeBytes: number;
  readonly maxPreambleBytes: number;
  readonly maxPostambleBytes: number;
}

export const DEFAULT_MICROVM_FRAME_LIMITS: MicrovmGuestFrameLimits = Object.freeze({
  maxStreamBytes: 1024 * 1024,
  maxEnvelopeBytes: 2 * 1024 * 1024 + 4096,
  maxPreambleBytes: 256 * 1024,
  maxPostambleBytes: 64 * 1024,
});

export class MicrovmGuestProtocolError extends Error {
  constructor(message: string) {
    super(`microVM result refused: ${message}`);
    this.name = "MicrovmGuestProtocolError";
  }
}

export function mintMicrovmAttemptNonce(): string {
  return randomBytes(16).toString("hex");
}

/** A fresh per-attempt authentication key, delivered only inside the root-owned guest rootfs. */
export function mintMicrovmResultAuthenticationKey(): Buffer {
  return randomBytes(32);
}

function checkedAuthenticationKey(key: Uint8Array): Buffer {
  const bytes = Buffer.from(key);
  if (bytes.length !== 32) throw new MicrovmGuestProtocolError("result authentication key must be exactly 32 bytes");
  return bytes;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function checkedBound(name: string, value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new MicrovmGuestProtocolError(`${name} is outside 0..${maximum}`);
  }
  return value;
}

function exactDecimal(name: string, text: string, maximum: number): number {
  if (!DECIMAL_RE.test(text)) throw new MicrovmGuestProtocolError(`${name} is not canonical decimal`);
  return checkedBound(name, Number(text), maximum);
}

function validateLimits(limits: MicrovmGuestFrameLimits): void {
  checkedBound("maxStreamBytes", limits.maxStreamBytes, 64 * 1024 * 1024);
  checkedBound("maxEnvelopeBytes", limits.maxEnvelopeBytes, 128 * 1024 * 1024);
  checkedBound("maxPreambleBytes", limits.maxPreambleBytes, 16 * 1024 * 1024);
  checkedBound("maxPostambleBytes", limits.maxPostambleBytes, 16 * 1024 * 1024);
}

/** Test/guest-supervisor construction helper. Production guest code emits byte-for-byte the same grammar. */
export function encodeMicrovmGuestFrame(input: {
  readonly attemptNonce: string;
  readonly exitCode: number;
  readonly stdout: string | Uint8Array;
  readonly stderr: string | Uint8Array;
  readonly authenticationKey: Uint8Array;
}, limits: MicrovmGuestFrameLimits = DEFAULT_MICROVM_FRAME_LIMITS): Buffer {
  validateLimits(limits);
  if (!NONCE_RE.test(input.attemptNonce)) throw new MicrovmGuestProtocolError("attempt nonce must be 16-byte lowercase hex");
  if (!Number.isSafeInteger(input.exitCode) || input.exitCode < 0 || input.exitCode > 255) {
    throw new MicrovmGuestProtocolError("exit code is outside 0..255");
  }
  const stdout = typeof input.stdout === "string" ? Buffer.from(input.stdout, "utf8") : Buffer.from(input.stdout);
  const stderr = typeof input.stderr === "string" ? Buffer.from(input.stderr, "utf8") : Buffer.from(input.stderr);
  checkedBound("stdout length", stdout.length, limits.maxStreamBytes);
  checkedBound("stderr length", stderr.length, limits.maxStreamBytes);
  // Reject non-UTF-8 at construction too; the installed parser repeats this independently.
  try { utf8.decode(stdout); utf8.decode(stderr); } catch { throw new MicrovmGuestProtocolError("stream is not valid UTF-8"); }
  const unsignedHeader = Buffer.from(
    `${HEADER} ${input.attemptNonce} ${input.exitCode} ${stdout.length} ${stderr.length} ${sha256(stdout)} ${sha256(stderr)}\n`,
    "ascii",
  );
  const end = Buffer.from(`\n${END} ${input.attemptNonce}\n`, "ascii");
  const mac = createHmac("sha256", checkedAuthenticationKey(input.authenticationKey))
    .update("keep.microvm-result-auth/v1\0", "utf8")
    .update(unsignedHeader).update(stdout).update(stderr).update(end).digest("hex");
  const header = Buffer.from(`${unsignedHeader.subarray(0, -1).toString("ascii")} ${mac}\n`, "ascii");
  const frame = Buffer.concat([header, stdout, stderr, end]);
  checkedBound("frame length", frame.length, limits.maxEnvelopeBytes);
  return frame;
}

/**
 * Parse one exact nonce-bound frame from bounded Firecracker stdout. A bounded boot preamble/postamble is
 * tolerated, but a second matching frame, malformed length/digest, invalid UTF-8, or ambiguity refuses.
 */
export function parseMicrovmGuestFrame(
  serial: Uint8Array,
  expectedNonce: string,
  authenticationKey: Uint8Array,
  limits: MicrovmGuestFrameLimits = DEFAULT_MICROVM_FRAME_LIMITS,
): MicrovmGuestResult {
  validateLimits(limits);
  if (!NONCE_RE.test(expectedNonce)) throw new MicrovmGuestProtocolError("expected nonce must be 16-byte lowercase hex");
  const bytes = Buffer.from(serial);
  const needle = Buffer.from(`${HEADER} ${expectedNonce} `, "ascii");
  const start = bytes.indexOf(needle);
  if (start < 0) throw new MicrovmGuestProtocolError("expected frame header is absent");
  if (start > limits.maxPreambleBytes) throw new MicrovmGuestProtocolError("serial preamble exceeds bound");
  if (bytes.indexOf(needle, start + 1) >= 0) throw new MicrovmGuestProtocolError("duplicate frame header");
  const lineEnd = bytes.indexOf(0x0a, start);
  if (lineEnd < 0 || lineEnd - start > 512) throw new MicrovmGuestProtocolError("header is missing or oversized");
  let header: string;
  try { header = utf8.decode(bytes.subarray(start, lineEnd)); }
  catch { throw new MicrovmGuestProtocolError("header is not UTF-8"); }
  const fields = header.split(" ");
  if (fields.length !== 8 || fields[0] !== HEADER || fields[1] !== expectedNonce) {
    throw new MicrovmGuestProtocolError("header shape or nonce mismatch");
  }
  const exitCode = exactDecimal("exit code", fields[2]!, 255);
  const stdoutLength = exactDecimal("stdout length", fields[3]!, limits.maxStreamBytes);
  const stderrLength = exactDecimal("stderr length", fields[4]!, limits.maxStreamBytes);
  const stdoutDigest = fields[5]!;
  const stderrDigest = fields[6]!;
  const suppliedMac = fields[7]!;
  if (!SHA256_RE.test(stdoutDigest) || !SHA256_RE.test(stderrDigest) || !SHA256_RE.test(suppliedMac)) {
    throw new MicrovmGuestProtocolError("stream digest or authentication tag is not lowercase SHA-256");
  }
  const payloadStart = lineEnd + 1;
  const payloadLength = stdoutLength + stderrLength;
  const payloadEnd = payloadStart + payloadLength;
  const endBytes = Buffer.from(`\n${END} ${expectedNonce}\n`, "ascii");
  if (!Number.isSafeInteger(payloadEnd) || payloadEnd + endBytes.length > bytes.length) {
    throw new MicrovmGuestProtocolError("frame is truncated");
  }
  checkedBound("frame length", payloadEnd + endBytes.length - start, limits.maxEnvelopeBytes);
  if (!bytes.subarray(payloadEnd, payloadEnd + endBytes.length).equals(endBytes)) {
    throw new MicrovmGuestProtocolError("terminal marker is absent or misplaced");
  }
  const stdoutBytes = bytes.subarray(payloadStart, payloadStart + stdoutLength);
  const stderrBytes = bytes.subarray(payloadStart + stdoutLength, payloadEnd);
  if (sha256(stdoutBytes) !== stdoutDigest || sha256(stderrBytes) !== stderrDigest) {
    throw new MicrovmGuestProtocolError("stream digest mismatch");
  }
  const unsignedHeader = Buffer.from(
    `${HEADER} ${expectedNonce} ${exitCode} ${stdoutLength} ${stderrLength} ${stdoutDigest} ${stderrDigest}\n`,
    "ascii",
  );
  const expectedMac = createHmac("sha256", checkedAuthenticationKey(authenticationKey))
    .update("keep.microvm-result-auth/v1\0", "utf8")
    .update(unsignedHeader).update(stdoutBytes).update(stderrBytes).update(endBytes).digest();
  const suppliedMacBytes = Buffer.from(suppliedMac, "hex");
  if (suppliedMacBytes.length !== expectedMac.length || !timingSafeEqual(suppliedMacBytes, expectedMac)) {
    throw new MicrovmGuestProtocolError("result authentication tag mismatch");
  }
  let stdout: string;
  let stderr: string;
  try { stdout = utf8.decode(stdoutBytes); stderr = utf8.decode(stderrBytes); }
  catch { throw new MicrovmGuestProtocolError("stream is not valid UTF-8"); }
  const postambleStart = payloadEnd + endBytes.length;
  const postambleLength = bytes.length - postambleStart;
  if (postambleLength > limits.maxPostambleBytes) throw new MicrovmGuestProtocolError("serial postamble exceeds bound");
  if (bytes.indexOf(Buffer.from(HEADER, "ascii"), postambleStart) >= 0 || bytes.indexOf(Buffer.from(END, "ascii"), postambleStart) >= 0) {
    throw new MicrovmGuestProtocolError("trailing frame material is ambiguous");
  }
  return {
    schema: MICROVM_RESULT_SCHEMA,
    attemptNonce: expectedNonce,
    exitCode,
    stdout,
    stderr,
    stdoutSha256: stdoutDigest,
    stderrSha256: stderrDigest,
  };
}
