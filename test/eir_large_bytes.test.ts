import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { decodeCanonical, decodeCanonicalSnapshot, encodeCanonical, isCanonical } from "../src/eir/canonical.js";

test("canonical decoder accepts independent 16MiB wire bytes without property enumeration", () => {
  const wire = new Uint8Array(16 * 1024 * 1024 + 5);
  wire.set([0x5a, 0x01, 0, 0, 0]);
  wire.fill(0x31, 5);
  const digest = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
  const expected = digest(wire.subarray(5));
  const decoded = decodeCanonical(wire);
  assert.ok(decoded instanceof Uint8Array);
  assert.equal(decoded.length, 16 * 1024 * 1024);
  assert.equal(digest(decoded), expected);
  wire.fill(0);
  assert.equal(digest(decoded), expected, "decoded payload owns its bytes");
});

test("canonical snapshot owns independent wire/value bytes and rejects invalid bounds", () => {
  const wire = encodeCanonical({ bytes: new Uint8Array([1, 2]) });
  const expected = Buffer.from(wire);
  const result = decodeCanonicalSnapshot(wire, wire.length);
  wire.fill(0);
  const value = result.value as { bytes: Uint8Array };
  value.bytes[0] = 9;
  assert.deepEqual(Buffer.from(result.bytes), expected);
  result.bytes.fill(0);
  assert.deepEqual(value.bytes, new Uint8Array([9, 2]));
  for (const bound of [0, -1, 1.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1, 1n, "1", null])
    assert.throws(() => decodeCanonicalSnapshot(new Uint8Array([1]), bound as number), /positive safe integer/);
  assert.throws(() => decodeCanonicalSnapshot(new Uint8Array(), 1), /encoded-size bound/);
  assert.throws(() => decodeCanonicalSnapshot(new Uint8Array([0x18, 24]), 1), /encoded-size bound/);
  assert.equal(decodeCanonicalSnapshot(new Uint8Array([1]), 1).value, 1n);
});

test("canonical snapshot ignores shadow getters but rejects proxies and unsafe backing stores", () => {
  const bytes = new Uint8Array([0x18, 24]);
  let calls = 0;
  for (const key of ["length", "byteLength", "buffer", "slice", Symbol.iterator])
    Object.defineProperty(bytes, key, { get() { calls++; throw new Error("hostile getter"); } });
  assert.equal(decodeCanonicalSnapshot(bytes, 2).value, 24n);
  assert.throws(() => decodeCanonicalSnapshot(bytes, 1), /encoded-size bound/);
  assert.equal(calls, 0);
  assert.throws(() => decodeCanonicalSnapshot(new Proxy(bytes, { get() { throw new Error("trap"); } }), 2), /Proxy/);
  assert.throws(() => decodeCanonicalSnapshot([1], 1), /Uint8Array/);
  assert.throws(() => decodeCanonicalSnapshot(new Uint8Array(new SharedArrayBuffer(1)), 1), /SharedArrayBuffer/);
  const detached = new Uint8Array([1]);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  assert.throws(() => decodeCanonicalSnapshot(detached, 1), /detached/);
  const ResizableArrayBuffer = ArrayBuffer as unknown as {
    new (length: number, options: { maxByteLength: number }): ArrayBuffer;
  };
  const rab = new ResizableArrayBuffer(1, { maxByteLength: 2 });
  assert.throws(() => decodeCanonicalSnapshot(new Uint8Array(rab), 1), /resizable/);
  const extra = new Uint8Array([1]);
  Object.defineProperty(extra, "hidden", { value: true });
  assert.throws(() => encodeCanonical(extra), /extra own properties/, "public encoder remains strict");
});

test("streaming re-encode preserves canonical refusals including UTF8 BOM round trips", () => {
  const invalid = [
    [0x18, 0x01], [0x19, 0, 24], [0x5f, 0xff], [0xf6, 0],
    [0x63, 0xef, 0xbb, 0xbf], // decoder strips a BOM: only re-encoding catches this
    [0x61, 0xff], [0x62, 0xc0, 0x80], [0xc0, 1],
    [0xa2, 0x61, 0x62, 1, 0x61, 0x61, 2],
    [0xa2, 0x61, 0x61, 1, 0x61, 0x61, 2],
  ];
  for (const value of invalid) assert.equal(isCanonical(new Uint8Array(value)), false);
  for (const value of [null, true, false, 24n, 256n, 65536n, 4294967296n, -25n, "hi", { a: [1n, false] }]) {
    const wire = encodeCanonical(value);
    assert.deepEqual(decodeCanonicalSnapshot(wire).bytes, wire);
    assert.deepEqual(encodeCanonical(decodeCanonical(wire)), wire);
  }
});
