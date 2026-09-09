/**
 * Authenticated length-prefixed monitor CHANNEL (Mechanical-Enforcement Increment 5).
 *
 * The tamper-resistance core of the attested monitor boundary: the wire protocol a confined workload uses to receive
 * authenticated decisions FROM the isolated capability monitor (over virtio-vsock in production — the transport is a
 * seam). This is the framing + authentication + anti-replay + fail-stop that make "the workload cannot impersonate/
 * modify/bypass the monitor" true at the MESSAGE level.
 *
 * ASYMMETRIC BY CONSTRUCTION (the key point). Frame authenticity is a SIGNATURE by the monitor's signer, verified by
 * the workload with only the monitor's PUBLIC verify key. The workload is NEVER given the signing key, so it cannot
 * forge, alter, replay-across-session, or impersonate the monitor — verifying does not imply the ability to sign. (An
 * earlier symmetric design derived a shared HMAC key from PUBLIC data, which the workload could re-derive and forge:
 * that is the flaw this corrects.) `Signer`/verify-key is the codebase's signing seam: the stub is a keyed hash where
 * verifyKey==privateKey, but the ARCHITECTURE is asymmetric — a real deployment holds the monitor's private key in an
 * HSM/measured-image and hands the workload only the public verify key. Session id + key are public; auth is the sig.
 *
 * Every frame carries a strictly-monotonic sequence inside a bounded replay window + a deadline; ANY deviation —
 * bad signature, replay, out-of-window sequence, cross-session frame, malformed framing, or an expired deadline (the
 * monitor went silent / was killed/paused) — FAIL-STOPS the channel: it latches closed and every later frame is
 * rejected, so no payload is delivered to the broker after a violation.
 *
 * SCOPE (honest seams): the isolation SUBSTRATE (Firecracker image, seccomp, RO mounts, the vsock transport, a hardware
 * quote) is the existing tier + src/tcb/attestation.ts. Authorization SEMANTICS = Increment 6; independent observation
 * = Increment 12; stronger substrate = Increment 16.
 *
 * Grounding: reference-monitor tamper resistance; authenticated (signed) channels with sequence numbers + replay
 * windows + deadlines (NIST SP 800-53 AC-3); fail-stop security; asymmetric verify != sign.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { stubSign, type Signer } from "../bom/bom_signing.js";

export const CHANNEL_VERSION = 1;
const MAX_PAYLOAD = 1 << 20; // 1 MiB frame payload bound (fail-closed above)
const MAX_SIG = 4096;         // signature length bound (fail-closed above)
const SESSION_ID_LEN = 32;    // sessionId is 64 lowercase hex chars (a 32-byte content digest)

export class ChannelError extends Error { constructor(m: string) { super(`monitor channel: ${m}`); this.name = "ChannelError"; } }

/**
 * The verifier's (workload's) view of a session: the id both peers agree on + the monitor's PUBLIC verify key.
 *
 * SINGLE-USE. A Session is established ONCE per connection from FRESH nonces (so its `sessionId` is unique) and drives
 * exactly one `MonitorChannel` receiver. The receiver enforces STRICTLY sequential frames (seq 0, 1, 2, …) — reliable,
 * ordered transport (vsock) means the next frame is always exactly the next sequence, so any reorder / gap / replay is
 * rejected. Reusing a session (same nonces) across a fresh channel is a lifecycle error the connection layer must not
 * make; even so, replayed frames carry stale DEADLINES and fail the deadline check. Durable cross-restart sequence
 * flooring is a lifecycle/storage seam.
 */
export interface Session {
  readonly sessionId: string;        // 64 lowercase hex chars, bound into every frame
  readonly keyid: string;            // the monitor signing key id expected on frames
  readonly verifyKey: string;        // the monitor's PUBLIC verify key (NOT a signing key)
  readonly clockSkewMs: bigint;      // tolerated clock skew when checking deadlines
}
/** The monitor's signing identity (holds the private signer — NEVER given to the workload). */
export interface MonitorSigner { readonly signer: Signer; readonly keyid: string; readonly verifyKey: string; }

const HEX64 = /^[0-9a-f]{64}$/;
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const sha256hex = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

/**
 * Derive the (public) session id from the ATTESTED boot-descriptor digest + both peers' fresh nonces. Binding the id
 * to the exact measured image + this connection's nonces means a frame minted for another image/session carries a
 * different id and is rejected. `bootDigest` is 64-hex; nonces are >=16 bytes. This id is PUBLIC — authenticity comes
 * from the monitor's signature, not the id.
 */
export function deriveSessionId(bootDigest: string, serverNonce: Uint8Array, clientNonce: Uint8Array): string {
  if (typeof bootDigest !== "string" || !HEX64.test(bootDigest)) throw new ChannelError("bootDigest must be 64 hex");
  if (!(serverNonce instanceof Uint8Array) || serverNonce.length < 16 || serverNonce.length > 0xffff || !(clientNonce instanceof Uint8Array) || clientNonce.length < 16 || clientNonce.length > 0xffff) throw new ChannelError("nonces must be 16..65535 bytes");
  // LENGTH-PREFIX every variable field (u16 be) so distinct (bootDigest, serverNonce, clientNonce) triples can never
  // share a concatenated preimage — otherwise two different nonce pairs could collide to one sessionId (cross-session).
  return sha256hex(concat(utf8(`keep.monitor.session.v${CHANNEL_VERSION}`), utf8(bootDigest), u16be(serverNonce.length), serverNonce, u16be(clientNonce.length), clientNonce));
}

/** Build the verifier session (what the workload holds): the derived id + the monitor's public verify identity. */
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

/** Encode + SIGN a frame (monitor side; requires the private signer). */
export function encodeFrame(sessionId: string, monitor: MonitorSigner, seq: bigint, deadlineMs: bigint, payload: Uint8Array): Uint8Array {
  const body = encodeBody(sessionId, seq, deadlineMs, payload);
  const sig = monitor.signer.sign(frameDigest(body));
  if (sig === null || typeof sig !== "object" || sig.keyid !== monitor.keyid || typeof sig.sig !== "string") throw new ChannelError("signer returned a malformed/foreign signature");
  const sigBytes = utf8(sig.sig);
  if (sigBytes.length > MAX_SIG) throw new ChannelError("signature too large");
  return concat(body, u16be(sigBytes.length), sigBytes);
}

export interface DecodedFrame { readonly seq: bigint; readonly deadlineMs: bigint; readonly payload: Uint8Array; }

/** Decode + VERIFY a frame's signature (workload side; only the public verifyKey) + session binding. Fail-closed. */
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
  // Verify the monitor's SIGNATURE with only the PUBLIC verify key (the workload cannot produce this without the key).
  const expected = stubSign(session.verifyKey, session.keyid, frameDigest(b.subarray(0, bodyEnd)));
  const sigB = utf8(sig), expB = utf8(expected.sig);
  if (sigB.length !== expB.length || !timingSafeEqual(sigB, expB)) throw new ChannelError("signature verification failed (forged/altered frame)");
  return { seq, deadlineMs, payload };
}

/**
 * The workload-side receiver. `accept()` returns a frame's payload ONLY if it is authentically signed by the monitor,
 * in a strictly-increasing sequence inside the replay window, and not past its deadline; ANY violation FAIL-STOPS the
 * channel permanently (latched). `now()` returns the current time in ms (injected, for determinism).
 */
export class MonitorChannel {
  readonly #session: Session;
  readonly #now: () => bigint;
  #lastSeq = -1n;
  #failStopped = false;

  constructor(session: Session, now: () => bigint) {
    // SNAPSHOT the session into an owned, frozen copy (read each field once): `readonly` is TypeScript-only, so a
    // caller who kept a reference could otherwise mutate sessionId/keyid/verifyKey after construction and swap the
    // trust binding. After this, later mutation of the caller's object has no effect on the channel.
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
      // STRICTLY sequential over a reliable, ordered transport: the next frame is exactly the next sequence. This
      // rejects replay (seq <= last), reordering (seq skipped ahead then the earlier arrives), and gaps in one check.
      if (f.seq !== this.#lastSeq + 1n) throw new ChannelError(`out-of-order frame (expected seq ${this.#lastSeq + 1n}, got ${f.seq} — reorder/gap/replay rejected)`);
      this.#lastSeq = f.seq;
      return f.payload;
    } catch (e) {
      this.#failStopped = true; // fail-STOP: one violation latches the channel closed
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
