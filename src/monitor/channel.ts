/**
 * Length-prefixed monitor frames with session binding, sequence checks and deadlines.
 * A receiver accepts only the next sequence number. Malformed frames, invalid authentication,
 * wrong sessions or expired deadlines permanently close that receiver.
 *
 * The reference decoder verifies frames with stubSign and a shared secret. Anyone holding verifyKey
 * can produce the same authentication value. Public-key separation requires replacing both signing
 * and verification with a matching asymmetric implementation. The current framing checks alone do
 * not isolate a workload from the monitor or protect the key.
 *
 * A transport must provide ordered delivery and establish a fresh session per connection.
 * Workload confinement, monitor identity and authorization semantics are separate controls.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { stubSign, type Signer } from "../bom/bom_signing.js";

export const CHANNEL_VERSION = 1;
const MAX_PAYLOAD = 1 << 20; // 1 MiB frame payload bound (fail-closed above)
const MAX_SIG = 4096;         // signature length bound (fail-closed above)
const SESSION_ID_LEN = 32;    // sessionId is 64 lowercase hex chars (a 32-byte content digest)

export class ChannelError extends Error { constructor(m: string) { super(`monitor channel: ${m}`); this.name = "ChannelError"; } }

/**
 * Receiver session: a connection identity, key identifier, reference verification key and clock skew.
 * Use fresh nonces for each connection and one MonitorChannel per session. Sequences start at zero
 * and must advance without gaps. Reusing a session can permit replay before a frame's deadline;
 * persisted cross-restart replay protection belongs to the connection lifecycle.
 */
export interface Session {
  readonly sessionId: string;        // 64 lowercase hex chars, bound into every frame
  readonly keyid: string;            // the monitor signing key id expected on frames
  readonly verifyKey: string;        // Shared secret used by the reference decoder.
  readonly clockSkewMs: bigint;      // tolerated clock skew when checking deadlines
}
/** Monitor signing configuration; the reference verifier uses the same secret as its signer. */
export interface MonitorSigner { readonly signer: Signer; readonly keyid: string; readonly verifyKey: string; }

const HEX64 = /^[0-9a-f]{64}$/;
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const sha256hex = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

/**
 * Derive a session identifier from a supplied boot digest and both peers' fresh nonces.
 * bootDigest must be 64-hex and each nonce at least 16 bytes. Length prefixes distinguish nonce
 * boundaries. The identifier binds the inputs; validating the boot measurement is the caller's job.
 */
export function deriveSessionId(bootDigest: string, serverNonce: Uint8Array, clientNonce: Uint8Array): string {
  if (typeof bootDigest !== "string" || !HEX64.test(bootDigest)) throw new ChannelError("bootDigest must be 64 hex");
  if (!(serverNonce instanceof Uint8Array) || serverNonce.length < 16 || serverNonce.length > 0xffff || !(clientNonce instanceof Uint8Array) || clientNonce.length < 16 || clientNonce.length > 0xffff) throw new ChannelError("nonces must be 16..65535 bytes");
  // Length-prefix both nonces so distinct nonce boundaries produce distinct hash inputs.
  return sha256hex(concat(utf8(`keep.monitor.session.v${CHANNEL_VERSION}`), utf8(bootDigest), u16be(serverNonce.length), serverNonce, u16be(clientNonce.length), clientNonce));
}

/** Build the receiver session from the derived identifier and configured verification material. */
export function verifierSession(bootDigest: string, serverNonce: Uint8Array, clientNonce: Uint8Array, monitor: { keyid: string; verifyKey: string }, opts?: { clockSkewMs?: bigint }): Session {
  if (typeof monitor.keyid !== "string" || monitor.keyid.length === 0 || typeof monitor.verifyKey !== "string" || monitor.verifyKey.length === 0) throw new ChannelError("monitor keyid + verifyKey required");
  return { sessionId: deriveSessionId(bootDigest, serverNonce, clientNonce), keyid: monitor.keyid, verifyKey: monitor.verifyKey, clockSkewMs: opts?.clockSkewMs ?? 1000n };
}

// ── wire format (all big-endian; strict, fail-closed) ──
//   BODY: [1] version  [1] sessionId hex len(=64)  [64] sessionId ascii  [8] seq u64  [8] deadlineMs u64
//         [4] payloadLen u32  [payloadLen] payload
//   TRAILER: [2] sig ascii len  [sigLen] signature ascii   (signature = monitor.sign(frameDigest))
const frameDigest = (body: Uint8Array): string => sha256hex(concat(utf8(`keep.monitor.frame.v${CHANNEL_VERSION}\0`), body));
function u64be(v: bigint): Uint8Array { if (v < 0n || v > 0xffffffffffffffffn) throw new ChannelError("u64 out of range"); const b = new Uint8Array(8); let x = v; for (let i = 7; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; }
function readU64be(b: Uint8Array, o: number): bigint { let v = 0n; for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(b[o + i]!); return v; }
function u32be(v: number): Uint8Array { const b = new Uint8Array(4); b[0] = (v >>> 24) & 0xff; b[1] = (v >>> 16) & 0xff; b[2] = (v >>> 8) & 0xff; b[3] = v & 0xff; return b; }
function readU32be(b: Uint8Array, o: number): number { return ((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!) >>> 0; }
function u16be(v: number): Uint8Array { const b = new Uint8Array(2); b[0] = (v >>> 8) & 0xff; b[1] = v & 0xff; return b; }

function encodeBody(sessionId: string, seq: bigint, deadlineMs: bigint, payload: Uint8Array): Uint8Array {
  if (!HEX64.test(sessionId)) throw new ChannelError("bad session id");
  if (!(payload instanceof Uint8Array) || payload.length > MAX_PAYLOAD) throw new ChannelError("payload too large or not bytes");
  const sid = utf8(sessionId);
  const head = new Uint8Array(2); head[0] = CHANNEL_VERSION; head[1] = sid.length;
  return concat(head, sid, u64be(seq), u64be(deadlineMs), u32be(payload.length), payload);
}

/** Encode a frame and obtain its authentication value from the configured signer. */
export function encodeFrame(sessionId: string, monitor: MonitorSigner, seq: bigint, deadlineMs: bigint, payload: Uint8Array): Uint8Array {
  const body = encodeBody(sessionId, seq, deadlineMs, payload);
  const sig = monitor.signer.sign(frameDigest(body));
  if (sig === null || typeof sig !== "object" || sig.keyid !== monitor.keyid || typeof sig.sig !== "string") throw new ChannelError("signer returned a malformed/foreign signature");
  const sigBytes = utf8(sig.sig);
  if (sigBytes.length > MAX_SIG) throw new ChannelError("signature too large");
  return concat(body, u16be(sigBytes.length), sigBytes);
}

export interface DecodedFrame { readonly seq: bigint; readonly deadlineMs: bigint; readonly payload: Uint8Array; }

/** Decode a frame and check its session binding and reference keyed-hash authentication. */
export function decodeFrame(session: Session, bytes: Uint8Array): DecodedFrame {
  if (!(bytes instanceof Uint8Array)) throw new ChannelError("frame must be bytes");
  if (!HEX64.test(session.sessionId)) throw new ChannelError("bad session id");
  const b = bytes.slice(); // owned copy (read-once)
  const minBody = 2 + SESSION_ID_LEN * 2 + 8 + 8 + 4;
  if (b.length < minBody + 2) throw new ChannelError("frame too short");
  if (b[0] !== CHANNEL_VERSION) throw new ChannelError(`unsupported version ${b[0]}`);
  if (b[1] !== SESSION_ID_LEN * 2) throw new ChannelError("bad session-id length");
  let o = 2;
  const sid = new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(o, o + SESSION_ID_LEN * 2)); o += SESSION_ID_LEN * 2;
  if (sid !== session.sessionId) throw new ChannelError("frame is for a different session (cross-session rejected)");
  const seq = readU64be(b, o); o += 8;
  const deadlineMs = readU64be(b, o); o += 8;
  const payloadLen = readU32be(b, o); o += 4;
  if (payloadLen > MAX_PAYLOAD || o + payloadLen + 2 > b.length) throw new ChannelError("payload length out of range");
  const bodyEnd = o + payloadLen;
  const payload = b.slice(o, bodyEnd);
  const sigLen = (b[bodyEnd]! << 8) | b[bodyEnd + 1]!;
  if (sigLen === 0 || sigLen > MAX_SIG) throw new ChannelError("bad signature length");
  if (bodyEnd + 2 + sigLen !== b.length) throw new ChannelError("frame length mismatch (trailing/short bytes)");
  const sig = new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(bodyEnd + 2, bodyEnd + 2 + sigLen));
  // The reference primitive uses the same secret for signing and verification.
  const expected = stubSign(session.verifyKey, session.keyid, frameDigest(b.subarray(0, bodyEnd)));
  const sigB = utf8(sig), expB = utf8(expected.sig);
  if (sigB.length !== expB.length || !timingSafeEqual(sigB, expB)) throw new ChannelError("signature verification failed (forged/altered frame)");
  return { seq, deadlineMs, payload };
}

/**
 * Receive frames in exact sequence, checking their authentication, session and deadline.
 * Any violation permanently closes this receiver. The injected clock returns milliseconds.
 */
export class MonitorChannel {
  readonly #session: Session;
  readonly #now: () => bigint;
  #lastSeq = -1n;
  #failStopped = false;

  constructor(session: Session, now: () => bigint) {
    // Copy each field once and freeze the session so later caller mutations cannot change its binding.
    const snap: Session = Object.freeze({ sessionId: session.sessionId, keyid: session.keyid, verifyKey: session.verifyKey, clockSkewMs: session.clockSkewMs });
    if (!HEX64.test(snap.sessionId) || typeof snap.verifyKey !== "string" || snap.verifyKey.length === 0 || typeof snap.keyid !== "string" || snap.keyid.length === 0) throw new ChannelError("invalid session");
    if (typeof snap.clockSkewMs !== "bigint" || snap.clockSkewMs < 0n) throw new ChannelError("invalid clockSkewMs");
    if (typeof now !== "function") throw new ChannelError("now() must be a function");
    this.#session = snap; this.#now = now;
  }

  get failStopped(): boolean { return this.#failStopped; }

  accept(bytes: Uint8Array): Uint8Array {
    if (this.#failStopped) throw new ChannelError("channel is fail-stopped (a prior violation latched it closed)");
    try {
      const f = decodeFrame(this.#session, bytes); // signature + session binding + framing
      const now = this.#now();
      if (typeof now !== "bigint") throw new ChannelError("clock must return a bigint (ms)");
      if (now > f.deadlineMs + this.#session.clockSkewMs) throw new ChannelError("frame deadline expired (monitor silent / killed / paused)");
      // Ordered delivery requires exactly the next sequence, rejecting replay, reordering and gaps.
      if (f.seq !== this.#lastSeq + 1n) throw new ChannelError(`out-of-order frame (expected seq ${this.#lastSeq + 1n}, got ${f.seq} — reorder/gap/replay rejected)`);
      this.#lastSeq = f.seq;
      return f.payload;
    } catch (e) {
      this.#failStopped = true; // One violation permanently closes this receiver.
      throw e instanceof ChannelError ? e : new ChannelError("channel error");
    }
  }
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0; for (const p of parts) n += p.length;
  const out = new Uint8Array(n); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
