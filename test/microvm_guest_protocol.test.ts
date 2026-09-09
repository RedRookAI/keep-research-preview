import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import {
  DEFAULT_MICROVM_FRAME_LIMITS,
  encodeMicrovmGuestFrame,
  mintMicrovmAttemptNonce,
  parseMicrovmGuestFrame,
} from "../src/infra/microvm_guest_protocol.js";

const NONCE = "0123456789abcdef0123456789abcdef";
const KEY = Buffer.alloc(32, 0x5a);

test("microVM result frame round-trips arbitrary marker-like UTF-8 payload", () => {
  const stdout = "ok 1 - real\nKEEP_RESULT_END_V1 deadbeef\n☕";
  const stderr = "KEEP_RESULT_V1 forged 0 0 0";
  const frame = encodeMicrovmGuestFrame({ attemptNonce: NONCE, exitCode: 7, stdout, stderr, authenticationKey: KEY });
  const parsed = parseMicrovmGuestFrame(Buffer.concat([Buffer.from("boot\n"), frame, Buffer.from("Power down\n")]), NONCE, KEY);
  assert.equal(parsed.exitCode, 7);
  assert.equal(parsed.stdout, stdout);
  assert.equal(parsed.stderr, stderr);
});

test("microVM result nonce is fresh, exact, and lowercase", () => {
  const a = mintMicrovmAttemptNonce();
  const b = mintMicrovmAttemptNonce();
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.notEqual(a, b);
  assert.throws(() => encodeMicrovmGuestFrame({ attemptNonce: a.toUpperCase(), exitCode: 0, stdout: "", stderr: "", authenticationKey: KEY }), /nonce/);
});

test("microVM parser refuses every single-byte truncation near structural boundaries", () => {
  const frame = encodeMicrovmGuestFrame({ attemptNonce: NONCE, exitCode: 0, stdout: "abc", stderr: "def", authenticationKey: KEY });
  for (let removed = 1; removed <= Math.min(frame.length, 48); removed += 1) {
    assert.throws(() => parseMicrovmGuestFrame(frame.subarray(0, frame.length - removed), NONCE, KEY), /refused/);
  }
});

test("microVM parser refuses wrong nonce, duplicates, digest mutation, and ambiguous trailer", () => {
  const frame = encodeMicrovmGuestFrame({ attemptNonce: NONCE, exitCode: 0, stdout: "abc", stderr: "def", authenticationKey: KEY });
  assert.throws(() => parseMicrovmGuestFrame(frame, "f".repeat(32), KEY), /absent/);
  assert.throws(() => parseMicrovmGuestFrame(Buffer.concat([frame, frame]), NONCE, KEY), /duplicate|ambiguous/);
  const mutated = Buffer.from(frame);
  const payloadIndex = mutated.indexOf(Buffer.from("abc"), mutated.indexOf(0x0a) + 1);
  mutated[payloadIndex] = mutated[payloadIndex]! ^ 1;
  assert.throws(() => parseMicrovmGuestFrame(mutated, NONCE, KEY), /digest mismatch/);
  assert.throws(() => parseMicrovmGuestFrame(Buffer.concat([frame, Buffer.from("KEEP_RESULT_V1")]), NONCE, KEY), /ambiguous/);
  assert.throws(() => parseMicrovmGuestFrame(frame, NONCE, Buffer.alloc(32, 0x5b)), /authentication/);
});

test("microVM parser refuses noncanonical numbers, oversize declarations, and invalid UTF-8", () => {
  const base = encodeMicrovmGuestFrame({ attemptNonce: NONCE, exitCode: 0, stdout: "x", stderr: "", authenticationKey: KEY });
  assert.throws(() => parseMicrovmGuestFrame(Buffer.from(base.toString().replace(` ${NONCE} 0 1 0 `, ` ${NONCE} 00 1 0 `)), NONCE, KEY), /canonical decimal/);
  const tiny = { ...DEFAULT_MICROVM_FRAME_LIMITS, maxStreamBytes: 0 };
  assert.throws(() => parseMicrovmGuestFrame(base, NONCE, KEY, tiny), /outside/);
  const invalid = Buffer.from(base);
  invalid[invalid.indexOf(0x78)] = 0xff;
  // Digest mismatch is deliberately checked before decoding; either condition is an unconditional refusal.
  assert.throws(() => parseMicrovmGuestFrame(invalid, NONCE, KEY), /digest mismatch|UTF-8/);
});

test("microVM frame fuzz: valid bounded payloads round-trip and one-byte payload mutations refuse", () => {
  for (let i = 0; i < 128; i += 1) {
    const stdout = randomBytes(i % 31).toString("base64");
    const stderr = randomBytes((i * 7) % 29).toString("hex");
    const frame = encodeMicrovmGuestFrame({ attemptNonce: NONCE, exitCode: i % 256, stdout, stderr, authenticationKey: KEY });
    assert.deepEqual(
      { ...parseMicrovmGuestFrame(frame, NONCE, KEY), stdoutSha256: undefined, stderrSha256: undefined },
      { schema: "keep.microvm-result/v1", attemptNonce: NONCE, exitCode: i % 256, stdout, stderr, stdoutSha256: undefined, stderrSha256: undefined },
    );
    if (stdout.length + stderr.length > 0) {
      const mutated = Buffer.from(frame);
      const headerEnd = mutated.indexOf(0x0a) + 1;
      const mutationIndex = headerEnd + ((i * 13) % (stdout.length + stderr.length));
      mutated[mutationIndex] = mutated[mutationIndex]! ^ 1;
      assert.throws(() => parseMicrovmGuestFrame(mutated, NONCE, KEY), /refused/);
    }
  }
});
