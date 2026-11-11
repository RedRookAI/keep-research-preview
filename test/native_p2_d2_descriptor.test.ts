import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import { captureNativePatchDescriptorV1 } from "../src/platform/native_p2_d2_carriers.js";

const sha = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const base = "1".repeat(64);
function fixture() {
  const payload = Uint8Array.from([0, 255, 13, 10]);
  const entry = { path: "src/lib.rs", operation: "replace", bytes: payload };
  const operation = { path: entry.path, operation: entry.operation, oldByteDigest: "2".repeat(64), newByteDigest: sha(payload), newByteLength: 4n };
  return {
    overlay: {
      schema: "keep.p2-d2-patch-overlay", version: 1n, packageId: "curve25519-dalek@5.0.0", baseArchiveDigest: base,
      operations: [operation], rationale: "byte-only validation", resultTreeDigest: "3".repeat(64), auditPlanDigest: "4".repeat(64),
    },
    carrier: { schema: "keep.p2-d2-patch-byte-carrier-set", version: 1n, packageId: "curve25519-dalek@5.0.0", entries: [entry] },
  };
}
function corpus(): { name: string; overlay: Uint8Array; carrier: Uint8Array; base: string; valid: boolean }[] {
  const good = fixture();
  const overlay = encodeCanonical(good.overlay), carrier = encodeCanonical(good.carrier);
  const cases = [{ name: "canonical", overlay, carrier, base, valid: true }];
  const add = (name: string, o: CanonicalValue, c: CanonicalValue, valid = false) => cases.push({ name, overlay: encodeCanonical(o), carrier: encodeCanonical(c), base, valid });
  cases.push({ name: "substituted base", overlay, carrier, base: "5".repeat(64), valid: false });
  cases.push({ name: "noncanonical carrier", overlay, carrier: new Uint8Array([0x18, 1]), base, valid: false });
  cases.push({ name: "trailing overlay", overlay: Uint8Array.from([...overlay, 0]), carrier, base, valid: false });
  const wrong = fixture(); wrong.carrier.entries[0]!.bytes[0] = 1;
  add("substituted carrier", wrong.overlay, wrong.carrier);
  const path = fixture(); path.carrier.entries[0]!.path = "../outside";
  add("traversal", path.overlay, path.carrier);
  const unsorted = fixture(); unsorted.carrier.entries.push({ ...unsorted.carrier.entries[0]!, path: "a" });
  add("unordered carriers", unsorted.overlay, unsorted.carrier);
  // Build the large byte string directly; hostile-object encoding intentionally
  // enumerates byte properties and is inappropriate for a 16MiB test fixture.
  const oversized = fixture(); oversized.carrier.entries[0]!.bytes = new Uint8Array();
  const emptyWire = Buffer.from(encodeCanonical(oversized.carrier));
  const marker = Buffer.concat([encodeCanonical("bytes"), Buffer.from([0x40])]);
  const position = emptyWire.indexOf(marker) + marker.length - 1;
  assert.ok(position >= marker.length - 1);
  const payload = new Uint8Array(16 * 1024 * 1024 + 1), head = Buffer.alloc(5);
  head[0] = 0x5a; head.writeUInt32BE(payload.length, 1);
  cases.push({ name: "oversized file", overlay, carrier: Buffer.concat([emptyWire.subarray(0, position), head, payload, emptyWire.subarray(position + 1)]), base, valid: false });
  const deleted = fixture();
  add("delete without carrier", { ...deleted.overlay, operations: [{ path: "build.rs", operation: "delete", oldByteDigest: "2".repeat(64), newByteDigest: null, newByteLength: null }] }, { ...deleted.carrier, entries: [] }, true);
  const empty = fixture();
  add("empty added file", { ...empty.overlay, operations: [{ path: "new", operation: "add", oldByteDigest: null, newByteDigest: sha(new Uint8Array()), newByteLength: 0n }] }, { ...empty.carrier, entries: [{ path: "new", operation: "add", bytes: new Uint8Array() }] }, true);
  return cases;
}

test("byte consumer binds original identities and returns a detached non-authorizing descriptor", () => {
  const f = fixture(), o = encodeCanonical(f.overlay), c = encodeCanonical(f.carrier);
  const descriptor = captureNativePatchDescriptorV1(o, c, base);
  assert.ok(Object.isFrozen(descriptor));
  assert.equal(descriptor.overlayByteDigest, sha(o)); assert.equal(descriptor.carrierByteDigest, sha(c));
  assert.equal(descriptor.operationCount, 1n); assert.equal(descriptor.carrierCount, 1n);
  const canonical = descriptor.canonicalBytes();
  assert.equal(descriptor.descriptorDigest, createHash("sha256").update("keep.p2-d2-patch-descriptor/v1\0").update(canonical).digest("hex"));
  o.fill(0); c.fill(0); descriptor.canonicalBytes().fill(0);
  assert.deepEqual(descriptor.canonicalBytes(), canonical);
  for (const flag of ["filesystem", "build", "admission", "launch"] as const) assert.equal(descriptor[flag], false);
  const changed = fixture(); changed.overlay.auditPlanDigest = "5".repeat(64);
  assert.notEqual(captureNativePatchDescriptorV1(encodeCanonical(changed.overlay), encodeCanonical(changed.carrier), base).descriptorDigest, descriptor.descriptorDigest);
});

test("byte consumer refuses hostile inputs and accepts useful empty/delete controls", () => {
  for (const row of corpus()) {
    const consume = () => captureNativePatchDescriptorV1(row.overlay, row.carrier, row.base);
    if (row.valid) assert.doesNotThrow(consume, row.name); else assert.throws(consume, row.name);
  }
  let traps = 0;
  const proxy = new Proxy(new Uint8Array(), { get() { traps++; return undefined; } });
  assert.throws(() => captureNativePatchDescriptorV1(proxy, new Uint8Array(), base));
  assert.equal(traps, 0);
});

test("TS and safe Rust descriptor consumers agree on canonical, adversarial and bound inputs", () => {
  const oracle = process.env.KEEP_P2_CAPTURE_ORACLE ?? fileURLToPath(new URL("../../native/target/x86_64-unknown-linux-musl/debug/keep-native-p2-d2-overlay-oracle", import.meta.url));
  const cases = corpus();
  const input = cases.map(row => `DESCRIPTOR\t${row.base}\t${Buffer.from(row.overlay).toString("hex")}\t${Buffer.from(row.carrier).toString("hex")}\n`).join("");
  const result = spawnSync(oracle, [], { input, encoding: "utf8", timeout: 60_000, killSignal: "SIGKILL", maxBuffer: 64 * 1024, env: {}, cwd: "/" });
  assert.ifError(result.error); assert.equal(result.status, 0, result.stderr);
  const lines = result.stdout.trim().split("\n"); assert.equal(lines.length, cases.length);
  for (const [index, row] of cases.entries()) {
    if (row.valid) assert.equal(lines[index], `OK\t${captureNativePatchDescriptorV1(row.overlay, row.carrier, row.base).descriptorDigest}`, row.name);
    else assert.match(lines[index]!, /^ERR\t/, row.name);
  }
});
