import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import { captureNativePatchOverlayV1 } from "../src/platform/native_p2_d2_overlay.js";
import {
  captureNativePatchByteCarrierSetV1,
  joinValidatedPatchApplicationInputs,
} from "../src/platform/native_p2_d2_carriers.js";

const oracle = fileURLToPath(new URL("../../native/target/x86_64-unknown-linux-musl/debug/keep-native-p2-d2-overlay-oracle", import.meta.url));
const digest = (bytes: Uint8Array | string): string => createHash("sha256").update(bytes).digest("hex");
const hexDigest = (n: number): string => n.toString(16).padStart(64, "0");
const replacement = Buffer.from("new Cargo manifest\n", "utf8");

function carrier(bytes: Uint8Array = replacement): Record<string, CanonicalValue> {
  return {
    schema: "keep.p2-d2-patch-byte-carrier-set",
    version: 1n,
    packageId: "curve25519-dalek@5.0.0",
    entries: [{ path: "Cargo.toml", operation: "replace", bytes: Uint8Array.from(bytes) }],
  };
}
function overlay(bytes: Uint8Array = replacement): Record<string, CanonicalValue> {
  return {
    schema: "keep.p2-d2-patch-overlay", version: 1n, packageId: "curve25519-dalek@5.0.0",
    baseArchiveDigest: hexDigest(1),
    operations: [{ operation: "replace", path: "Cargo.toml", oldByteDigest: hexDigest(2), newByteDigest: digest(bytes), newByteLength: BigInt(bytes.byteLength) }],
    rationale: "remove build script", resultTreeDigest: hexDigest(3), auditPlanDigest: hexDigest(4),
  };
}
function encoded(value: CanonicalValue): Uint8Array { return encodeCanonical(value); }
function rust(value: CanonicalValue): string {
  const result = spawnSync(oracle, [], {
    input: `CARRIER\t${Buffer.from(encoded(value)).toString("hex")}\n`, encoding: "utf8", maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}
function refuses(value: CanonicalValue): void {
  assert.throws(() => captureNativePatchByteCarrierSetV1(encoded(value)));
  assert.match(rust(value), /^ERR\t/);
}

test("P2-D2 TS and safe Rust capture the same typed byte-carrier identity", () => {
  const capture = captureNativePatchByteCarrierSetV1(encoded(carrier()));
  assert.equal(rust(carrier()), `OK\t${capture.patchByteCarrierSetDigest}`);
  assert.equal(capture.patchByteCarrierSetDigest, "43edab3293cfbfdeb7b1fe5932774339562fd540cb759b8ead7a7e65a793078d", "literal digest pins the carrier domain");
  assert.equal(Buffer.from(capture.canonicalBytes()).toString("hex"), "a466736368656d6178216b6565702e70322d64322d70617463682d627974652d636172726965722d73657467656e747269657381a364706174686a436172676f2e746f6d6c656279746573536e657720436172676f206d616e69666573740a696f7065726174696f6e677265706c6163656776657273696f6e01697061636b616765496476637572766532353531392d64616c656b40352e302e30");
  assert.deepEqual(Buffer.from(capture.entries[0]!.bytes()), replacement);
  const copy = capture.entries[0]!.bytes(); copy[0] = 0;
  assert.deepEqual(Buffer.from(capture.entries[0]!.bytes()), replacement, "carrier bytes are defensively copied");
  assert.notEqual(capture.patchByteCarrierSetDigest, digest(capture.canonicalBytes()));
});

test("P2-D2 carrier exact fields, types, tags, paths, ordering, and case aliases refuse", () => {
  for (const key of Object.keys(carrier())) {
    const value = carrier(); delete value[key]; refuses(value);
    const nulled = carrier(); nulled[key] = null; refuses(nulled);
  }
  const extra = carrier(); extra.extra = 1n; refuses(extra);
  for (const key of ["path", "operation", "bytes"] as const) {
    const missing = carrier(); delete (missing.entries as Record<string, CanonicalValue>[])[0]![key]; refuses(missing);
    const nulled = carrier(); (nulled.entries as Record<string, CanonicalValue>[])[0]![key] = null; refuses(nulled);
  }
  const entryExtra = carrier(); (entryExtra.entries as Record<string, CanonicalValue>[])[0]!.extra = 1n; refuses(entryExtra);
  for (const operation of ["delete", "move"] as const) {
    const value = carrier(); (value.entries as Record<string, CanonicalValue>[])[0]!.operation = operation; refuses(value);
  }
  for (const path of ["", "/abs", "a/../b", "a\\b", "é", ".cargo-checksum.json"] as const) {
    const value = carrier(); (value.entries as Record<string, CanonicalValue>[])[0]!.path = path; refuses(value);
  }
  const unordered = carrier(); unordered.entries = [
    { path: "z", operation: "add", bytes: new Uint8Array() },
    { path: "a", operation: "add", bytes: new Uint8Array() },
  ]; refuses(unordered);
  const alias = carrier(); alias.entries = [
    { path: "A/file", operation: "add", bytes: new Uint8Array() },
    { path: "a/File", operation: "add", bytes: new Uint8Array() },
  ]; refuses(alias);
});

test("P2-D2 carrier joins every and only overlay add/replace byte equation", () => {
  const plan = captureNativePatchOverlayV1(encoded(overlay()));
  const set = captureNativePatchByteCarrierSetV1(encoded(carrier()));
  const joined = joinValidatedPatchApplicationInputs(plan, set);
  assert.deepEqual({ kind: joined.kind, filesystem: joined.filesystem, build: joined.build, admission: joined.admission, launch: joined.launch },
    { kind: "ValidatedPatchApplicationInputs", filesystem: false, build: false, admission: false, launch: false });
  assert.throws(() => joinValidatedPatchApplicationInputs(plan, captureNativePatchByteCarrierSetV1(encoded(carrier(Buffer.from("different\n"))))));
  const empty = carrier(); empty.entries = [];
  assert.throws(() => joinValidatedPatchApplicationInputs(plan, captureNativePatchByteCarrierSetV1(encoded(empty))));
  const wrongPath = carrier(); (wrongPath.entries as Record<string, CanonicalValue>[])[0]!.path = "src/lib.rs";
  assert.throws(() => joinValidatedPatchApplicationInputs(plan, captureNativePatchByteCarrierSetV1(encoded(wrongPath))));
});

test("P2-D2 carrier empty set is canonical for delete-only overlays", () => {
  const value = carrier(); value.entries = [];
  const set = captureNativePatchByteCarrierSetV1(encoded(value));
  const deletion = overlay(); deletion.operations = [{ operation: "delete", path: "build.rs", oldByteDigest: hexDigest(2), newByteDigest: null, newByteLength: null }];
  assert.doesNotThrow(() => joinValidatedPatchApplicationInputs(captureNativePatchOverlayV1(encoded(deletion)), set));
  assert.equal(rust(value), `OK\t${set.patchByteCarrierSetDigest}`);
});

test("P2-D2 carrier file-byte boundary is exact in both language families", () => {
  const maximum = carrier(new Uint8Array(16 * 1024 * 1024));
  const capture = captureNativePatchByteCarrierSetV1(encoded(maximum));
  assert.equal(rust(maximum), `OK\t${capture.patchByteCarrierSetDigest}`);
  assert.throws(() => encoded(carrier(new Uint8Array(16 * 1024 * 1024 + 1))), /Too many properties|file bound/);
});
