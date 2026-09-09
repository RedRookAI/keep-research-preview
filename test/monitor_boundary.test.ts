import { test } from "node:test";
import assert from "node:assert/strict";

import {
  verifierSession, encodeFrame, decodeFrame, MonitorChannel, ChannelError, CHANNEL_VERSION, type Session, type MonitorSigner,
} from "../src/monitor/channel.js";
import {
  compileBootDescriptor, verifyBootDescriptor, measurementDigest, validateMeasurement,
  BoundaryError, type MonitorMeasurement, type BootSigner, type SignedBootDescriptor,
} from "../src/monitor/boundary.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";

// Increment 5 — ATTESTED MONITOR BOUNDARY. Frontier: a workload cannot impersonate/modify/bypass the monitor —
// the image measurement is pinned (alter image => appraisal failure), and every channel frame is authenticated,
// sequence-checked, deadline-bound, session-bound, and FAIL-STOPS on any violation. Proven by disproof:
//   MAC neuter (timingSafeEqual)      => "a tampered frame is REJECTED"
//   seq monotonic neuter               => "a replayed frame is REJECTED + latches"
//   deadline neuter                    => "an expired frame fails closed"
//   appraisal neuter (image match)     => "an altered image fails the appraisal"

const KEYID = "k1", SECRET = "s3cr3t";
const signer: BootSigner = { signer: new StubSigner(SECRET, KEYID), keyid: KEYID, verifyKey: SECRET };
const trust: TrustPolicy = { trustedKeys: new Map([[KEYID, SECRET]]), threshold: 1 };
const NONCE_A = new Uint8Array(16).fill(0xa1);
const NONCE_B = new Uint8Array(16).fill(0xb2);
const MK = "mon-key", MSEC = "monitor-private-secret";
const monitorSigner: MonitorSigner = { signer: new StubSigner(MSEC, MK), keyid: MK, verifyKey: MSEC };

function measurement(over: Partial<MonitorMeasurement> = {}): MonitorMeasurement {
  return validateMeasurement({ rootfsDigest: "1".repeat(64), kernelDigest: "2".repeat(64), cmdline: "console=ttyS0 ro", seccompDigest: "3".repeat(64), configDigest: "4".repeat(64), vsockCid: 3n, ...over });
}
const session = (bootDigest: string): Session => verifierSession(bootDigest, NONCE_A, NONCE_B, { keyid: MK, verifyKey: MSEC }, { clockSkewMs: 0n });

// ── boot descriptor / measured boundary ──
test("boot descriptor: compiles + verifies against the pinned appraisal; returns a bootDigest", () => {
  const m = measurement();
  const d = compileBootDescriptor(m, [signer]);
  const v = verifyBootDescriptor(d, { trust, expectedMeasurementDigest: measurementDigest(m) });
  assert.equal(v.valid, true);
  assert.match((v as { bootDigest: string }).bootDigest, /^[0-9a-f]{64}$/);
});

test("appraisal: an ALTERED monitor image (different measurement) fails verification", () => {
  const m = measurement();
  const d = compileBootDescriptor(m, [signer]);
  // the verifier pins the ORIGINAL measurement; the descriptor now measures a different rootfs
  const altered = compileBootDescriptor(measurement({ rootfsDigest: "9".repeat(64) }), [signer]);
  assert.equal(verifyBootDescriptor(altered, { trust, expectedMeasurementDigest: measurementDigest(m) }).valid, false);
  // and a descriptor whose claimed measurementDigest is forged fails
  const forged: SignedBootDescriptor = { ...d, payload: { ...d.payload, measurementDigest: "0".repeat(64) } };
  assert.equal(verifyBootDescriptor(forged, { trust, expectedMeasurementDigest: measurementDigest(m) }).valid, false);
});

test("boot descriptor verify is total: tampered payload/signature/bad-trust fail closed, never throw", () => {
  const m = measurement();
  const d = compileBootDescriptor(m, [signer]);
  const exp = measurementDigest(m);
  const tamperedCid: SignedBootDescriptor = { ...d, payload: { ...d.payload, measurement: { ...d.payload.measurement, vsockCid: 99n } } };
  assert.equal(verifyBootDescriptor(tamperedCid, { trust, expectedMeasurementDigest: exp }).valid, false);
  assert.equal(verifyBootDescriptor(d, { trust: { trustedKeys: new Map([["other", SECRET]]), threshold: 1 }, expectedMeasurementDigest: exp }).valid, false);
  assert.equal(verifyBootDescriptor(null as unknown as SignedBootDescriptor, { trust, expectedMeasurementDigest: exp }).valid, false);
  assert.throws(() => validateMeasurement({ rootfsDigest: "x", kernelDigest: "2".repeat(64), cmdline: "c", seccompDigest: "3".repeat(64), configDigest: "4".repeat(64), vsockCid: 3n }), BoundaryError);
});

// ── authenticated channel ──
test("channel: an authentic in-order frame is accepted; round-trips its payload", () => {
  const d = compileBootDescriptor(measurement(), [signer]);
  const boot = (verifyBootDescriptor(d, { trust, expectedMeasurementDigest: measurementDigest(measurement()) }) as { bootDigest: string }).bootDigest;
  const s = session(boot);
  const ch = new MonitorChannel(s, () => 1000n);
  const frame = encodeFrame(s.sessionId, monitorSigner, 0n, 5000n, new TextEncoder().encode("allow"));
  assert.deepEqual(decodeFrame(s, frame).payload, new TextEncoder().encode("allow"));
  assert.deepEqual([...ch.accept(frame)], [...new TextEncoder().encode("allow")]);
});

test("channel: a tampered frame (MAC) is REJECTED and fail-stops the channel", () => {
  const s = session("a".repeat(64));
  const ch = new MonitorChannel(s, () => 1000n);
  const frame = encodeFrame(s.sessionId, monitorSigner, 0n, 5000n, new Uint8Array([1, 2, 3]));
  const payloadOff = 2 + 64 + 8 + 8 + 4; // header + sessionId + seq + deadline + payloadLen
  const tampered = frame.slice(); tampered[payloadOff] = (tampered[payloadOff] ?? 0) ^ 0xff; // flip a payload byte
  assert.throws(() => ch.accept(tampered), /signature verification failed/);
  assert.equal(ch.failStopped, true);
  assert.throws(() => ch.accept(frame), /fail-stopped/); // latched closed even for a now-valid frame
});

test("channel: cross-session frames are REJECTED", () => {
  const sA = session("a".repeat(64));
  const sB = verifierSession("b".repeat(64), NONCE_A, NONCE_B, { keyid: MK, verifyKey: MSEC }, { clockSkewMs: 0n });
  const ch = new MonitorChannel(sA, () => 1000n);
  const frameFromB = encodeFrame(sB.sessionId, monitorSigner, 0n, 5000n, new Uint8Array([9]));
  assert.throws(() => ch.accept(frameFromB), (e: unknown) => e instanceof ChannelError);
});

test("channel: replay + out-of-order + out-of-window sequences are REJECTED (anti-replay)", () => {
  const s = session("a".repeat(64));
  let ch = new MonitorChannel(s, () => 1000n);
  ch.accept(encodeFrame(s.sessionId, monitorSigner, 0n, 9000n, new Uint8Array([1])));
  ch.accept(encodeFrame(s.sessionId, monitorSigner, 1n, 9000n, new Uint8Array([1]))); // strictly next: accepted
  assert.throws(() => ch.accept(encodeFrame(s.sessionId, monitorSigner, 1n, 9000n, new Uint8Array([1]))), /out-of-order/); // replay of 1
  ch = new MonitorChannel(s, () => 1000n);
  ch.accept(encodeFrame(s.sessionId, monitorSigner, 0n, 9000n, new Uint8Array([1])));
  assert.throws(() => ch.accept(encodeFrame(s.sessionId, monitorSigner, 0n, 9000n, new Uint8Array([1]))), /out-of-order/); // replay of 0
  ch = new MonitorChannel(s, () => 1000n);
  ch.accept(encodeFrame(s.sessionId, monitorSigner, 0n, 9000n, new Uint8Array([1])));
  assert.throws(() => ch.accept(encodeFrame(s.sessionId, monitorSigner, 2n, 9000n, new Uint8Array([1]))), /out-of-order/); // gap/reorder: 2 before 1
});

test("channel: an expired deadline (monitor silent/killed) fails closed", () => {
  const s = session("a".repeat(64));
  const ch = new MonitorChannel(s, () => 10_000n); // 'now' is past the frame deadline
  assert.throws(() => ch.accept(encodeFrame(s.sessionId, monitorSigner, 0n, 5000n, new Uint8Array([1]))), /deadline expired/);
  assert.equal(ch.failStopped, true);
});

test("channel: malformed framing (short / trailing bytes / bad version) is REJECTED", () => {
  const s = session("a".repeat(64));
  assert.throws(() => decodeFrame(s, new Uint8Array([CHANNEL_VERSION, 1, 2])), /too short/);
  const good = encodeFrame(s.sessionId, monitorSigner, 0n, 5000n, new Uint8Array([1]));
  assert.throws(() => decodeFrame(s, new Uint8Array([...good, 0])), /length mismatch/); // trailing byte
  const badver = good.slice(); badver[0] = 9;
  assert.throws(() => decodeFrame(s, badver), /unsupported version/);
});

test("binding: a channel derived against a DIFFERENT image cannot accept the monitor's frames", () => {
  const sReal = session("a".repeat(64));                 // monitor's real boot digest
  const sImposter = session("f".repeat(64));             // a channel bound to a different image
  const ch = new MonitorChannel(sImposter, () => 1000n);
  const realFrame = encodeFrame(sReal.sessionId, monitorSigner, 0n, 5000n, new Uint8Array([1]));
  assert.throws(() => ch.accept(realFrame), (e: unknown) => e instanceof ChannelError); // different key + sessionId
});
