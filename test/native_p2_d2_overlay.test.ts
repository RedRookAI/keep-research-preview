import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import {
  captureNativePatchOverlayV1,
  P2_D2_OVERLAY_AUTHORITY_BOUNDARY,
} from "../src/platform/native_p2_d2_overlay.js";
import { captureValidatedPatchOverlayPlan } from "../src/platform/native_authority_schema_v1.js";
import { isCanonicalNativeP2RelativePath } from "../src/platform/native_p2_path.js";
import { resolvedPackageMembers } from "./helpers/native_package_membership.js";

const root = process.cwd();
const oracle = fileURLToPath(new URL("../../native/target/x86_64-unknown-linux-musl/debug/keep-native-p2-d2-overlay-oracle", import.meta.url));
const emptyDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const digest = (n: number): string => n.toString(16).padStart(64, "0");

function fixture(): Record<string, CanonicalValue> {
  return {
    schema: "keep.p2-d2-patch-overlay",
    version: 1n,
    packageId: "curve25519-dalek@5.0.0",
    baseArchiveDigest: digest(1),
    operations: [
      { operation: "delete", path: "build.rs", oldByteDigest: digest(2), newByteDigest: null, newByteLength: null },
      { operation: "add", path: "src/backend/serial/fiat.rs", oldByteDigest: null, newByteDigest: emptyDigest, newByteLength: 0n },
      { operation: "replace", path: "src/lib.rs", oldByteDigest: digest(3), newByteDigest: digest(4), newByteLength: 17n },
    ],
    rationale: "remove build-script authority\nretain audited fiat backend",
    resultTreeDigest: digest(5),
    auditPlanDigest: digest(6),
  };
}

function encoded(value: CanonicalValue = fixture()): Uint8Array {
  return encodeCanonical(value);
}

function rust(bytes: Uint8Array): string {
  const result = spawnSync(oracle, [], {
    input: `${Buffer.from(bytes).toString("hex")}\n`,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function refuses(value: CanonicalValue): void {
  assert.throws(() => captureNativePatchOverlayV1(encoded(value)));
  assert.match(rust(encoded(value)), /^ERR\t/);
}

function accepts(value: CanonicalValue): void {
  const capture = captureNativePatchOverlayV1(encoded(value));
  assert.equal(rust(encoded(value)), `OK\t${capture.patchOverlayDigest}`);
}

test("P2-D2 TS and safe Rust accept identical canonical overlay bytes and digest", () => {
  const bytes = encoded();
  const direct = captureNativePatchOverlayV1(bytes);
  const consumed = captureValidatedPatchOverlayPlan(bytes);
  assert.equal(direct.kind, "ValidatedPatchOverlayPlan");
  assert.equal(consumed.patchOverlayDigest, direct.patchOverlayDigest);
  assert.deepEqual(consumed.canonicalBytes(), bytes);
  const mutableCopy = consumed.canonicalBytes();
  mutableCopy[0] = mutableCopy[0]! ^ 0xff;
  assert.deepEqual(consumed.canonicalBytes(), bytes, "caller mutation cannot alter captured bytes");
  assert.equal(rust(bytes), `OK\t${direct.patchOverlayDigest}`);
  assert.equal(direct.patchOverlayDigest, "4c84a9b5f1b3f0cb403e51f1e4c11c06f97d0be8804d119fce1dfa9103eb19ba", "literal digest pins the domain separator");
  assert.equal(direct.patchOverlayDigest.length, 64);
  assert.notEqual(direct.patchOverlayDigest, Buffer.from(bytes).toString("hex").slice(0, 64));
});

test("P2-D2 canonical key ordering and full golden bytes are literal", () => {
  const bytes = encoded();
  assert.equal(
    Buffer.from(bytes).toString("hex"),
    "a866736368656d6178186b6565702e70322d64322d70617463682d6f7665726c61796776657273696f6e01697061636b616765496476637572766532353531392d64616c656b40352e302e3069726174696f6e616c65783972656d6f7665206275696c642d73637269707420617574686f726974790a72657461696e20617564697465642066696174206261636b656e646a6f7065726174696f6e7383a56470617468686275696c642e7273696f7065726174696f6e6664656c6574656d6e657742797465446967657374f66d6e6577427974654c656e677468f66d6f6c6442797465446967657374784030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303032a56470617468781a7372632f6261636b656e642f73657269616c2f666961742e7273696f7065726174696f6e636164646d6e6577427974654469676573747840653362306334343239386663316331343961666266346338393936666239323432376165343165343634396239333463613439353939316237383532623835356d6e6577427974654c656e677468006d6f6c6442797465446967657374f6a564706174686a7372632f6c69622e7273696f7065726174696f6e677265706c6163656d6e6577427974654469676573747840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030346d6e6577427974654c656e677468116d6f6c64427974654469676573747840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030336f6175646974506c616e44696765737478403030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303670726573756c7454726565446967657374784030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303035716261736541726368697665446967657374784030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303031",
  );
  const textSorted = Object.fromEntries(Object.entries(fixture()).sort(([left], [right]) => left.localeCompare(right))) as CanonicalValue;
  assert.deepEqual(encodeCanonical(textSorted), bytes, "encoder ignores decoded-text insertion order and uses encoded keys");
  const resultTree: CanonicalValue = {
    schema: "keep.p2-d2-result-tree", version: 1n, packageId: "curve25519-dalek@5.0.0",
    files: [
      { path: "Cargo.toml", byteDigest: digest(7), byteLength: 9n },
      { path: "src/lib.rs", byteDigest: digest(8), byteLength: 17n },
    ],
  };
  assert.equal(Buffer.from(encodeCanonical(resultTree)).toString("hex"), "a46566696c657382a364706174686a436172676f2e746f6d6c6a627974654469676573747840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030376a627974654c656e67746809a364706174686a7372632f6c69622e72736a627974654469676573747840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030386a627974654c656e6774681166736368656d61766b6565702e70322d64322d726573756c742d747265656776657273696f6e01697061636b616765496476637572766532353531392d64616c656b40352e302e30");
});

test("P2-D2 exact fields, types, tags, and operation equations refuse in both families", () => {
  for (const key of Object.keys(fixture())) {
    const missing = fixture(); delete missing[key]; refuses(missing);
    const nulled = fixture(); nulled[key] = null; refuses(nulled);
  }
  const extra = fixture(); extra.unknown = 1n; refuses(extra);
  const rootTypeMutants: Partial<Record<string, CanonicalValue>> = {
    schema: 1n, version: "1", packageId: 1n, baseArchiveDigest: 1n,
    operations: "operations", rationale: 1n, resultTreeDigest: 1n, auditPlanDigest: 1n,
  };
  for (const [key, replacement] of Object.entries(rootTypeMutants)) {
    const value = fixture(); value[key] = replacement!; refuses(value);
  }
  for (const key of Object.keys((fixture().operations as Record<string, CanonicalValue>[])[2]!)) {
    const missing = fixture(); delete (missing.operations as Record<string, CanonicalValue>[])[2]![key]; refuses(missing);
    const nulled = fixture(); (nulled.operations as Record<string, CanonicalValue>[])[2]![key] = null; refuses(nulled);
  }
  const operationExtra = fixture(); (operationExtra.operations as Record<string, CanonicalValue>[])[2]!.unknown = 1n; refuses(operationExtra);
  for (const key of ["operation", "path", "oldByteDigest", "newByteDigest", "newByteLength"] as const) {
    const value = fixture();
    (value.operations as Record<string, CanonicalValue>[])[2]![key] = key === "newByteLength" ? "17" : 1n;
    refuses(value);
  }
  const wrongVersion = fixture(); wrongVersion.version = "1"; refuses(wrongVersion);
  const unknown = fixture(); (unknown.operations as Record<string, CanonicalValue>[])[0]!.operation = "move"; refuses(unknown);
  const addOld = fixture(); (addOld.operations as Record<string, CanonicalValue>[])[1]!.oldByteDigest = digest(9); refuses(addOld);
  const deleteNew = fixture(); (deleteNew.operations as Record<string, CanonicalValue>[])[0]!.newByteDigest = digest(9); refuses(deleteNew);
  const replaceNoop = fixture(); (replaceNoop.operations as Record<string, CanonicalValue>[])[2]!.newByteDigest = digest(3); refuses(replaceNoop);
});

test("P2-D2 path traversal, ordering, duplicates, reserved artifact, and ASCII case aliases refuse", () => {
  for (const path of ["", "/abs", ".", "..", "a/../b", "a//b", "a\\b", "a\0b", "é", ".cargo-checksum.json"] as const) {
    const value = fixture();
    (value.operations as Record<string, CanonicalValue>[])[0]!.path = path;
    refuses(value);
  }
  for (const path of ["a", "A-1/b_c.rs", ".hidden", "src/+plus.rs"])
    assert.equal(isCanonicalNativeP2RelativePath(path), true);
  const duplicate = fixture();
  (duplicate.operations as Record<string, CanonicalValue>[])[1]!.path = "build.rs";
  refuses(duplicate);
  const caseAlias = fixture();
  (caseAlias.operations as Record<string, CanonicalValue>[])[0]!.path = "A/file";
  (caseAlias.operations as Record<string, CanonicalValue>[])[1]!.path = "a/File";
  refuses(caseAlias);
  const outOfOrder = fixture();
  (outOfOrder.operations as CanonicalValue[]).reverse();
  refuses(outOfOrder);
});

test("P2-D2 digest and uint64/file equations refuse boundary and semantic substitutions", () => {
  for (const bad of ["0".repeat(64), "A".repeat(64), "1".repeat(63), "g".repeat(64)]) {
    const value = fixture(); value.auditPlanDigest = bad; refuses(value);
  }
  const badEmpty = fixture();
  (badEmpty.operations as Record<string, CanonicalValue>[])[1]!.newByteDigest = digest(8);
  refuses(badEmpty);
  const nonemptyEmptyDigest = fixture();
  (nonemptyEmptyDigest.operations as Record<string, CanonicalValue>[])[2]!.newByteDigest = emptyDigest;
  refuses(nonemptyEmptyDigest);
  for (const length of [2n ** 53n, (2n ** 64n) - 1n, (16n * 1024n * 1024n) + 1n]) {
    const value = fixture();
    (value.operations as Record<string, CanonicalValue>[])[2]!.newByteLength = length;
    refuses(value);
  }
  const swapped = fixture();
  [swapped.baseArchiveDigest, swapped.resultTreeDigest] = [swapped.resultTreeDigest!, swapped.baseArchiveDigest!];
  assert.notEqual(captureNativePatchOverlayV1(encoded(swapped)).patchOverlayDigest, captureNativePatchOverlayV1(encoded()).patchOverlayDigest);
});

test("P2-D2 native profile and encoded-byte bounds refuse before semantic use", () => {
  const nonAscii = fixture(); nonAscii.rationale = "é"; refuses(nonAscii);
  const control = fixture(); control.rationale = "bad\u007f"; refuses(control);
  assert.throws(() => captureNativePatchOverlayV1(new Uint8Array(1024 * 1024 + 1)));
  assert.throws(() => captureNativePatchOverlayV1([]));
  assert.throws(() => captureNativePatchOverlayV1(new Proxy(new Uint8Array([0xf6]), {})));
  let deep: CanonicalValue = "leaf";
  for (let index = 0; index < 17; index += 1) deep = [deep];
  const value = fixture(); value.rationale = deep;
  assert.throws(() => captureNativePatchOverlayV1(encoded(value)));
  for (const hostile of [new Uint8Array([0xbf, 0xff]), new Uint8Array([0x18, 0x01]), new Uint8Array([0xa1, 0x61, 0x62, 0x01, 0xa0])])
    assert.throws(() => captureNativePatchOverlayV1(hostile));
});

test("P2-D2 configured count, text, path, member, and aggregate boundaries are exact", () => {
  const single = fixture();
  single.operations = [{ operation: "add", path: "a".repeat(4096), oldByteDigest: null, newByteDigest: emptyDigest, newByteLength: 0n }];
  single.rationale = "r".repeat(4096);
  accepts(single);
  const longPath = structuredClone(single); (longPath.operations as Record<string, CanonicalValue>[])[0]!.path = "a".repeat(4097); refuses(longPath);
  const longRationale = structuredClone(single); longRationale.rationale = "r".repeat(4097); refuses(longRationale);

  const operations = (count: number, length: bigint): CanonicalValue[] => Array.from({ length: count }, (_, index) => ({
    operation: "add", path: `p${index.toString().padStart(3, "0")}`, oldByteDigest: null,
    newByteDigest: length === 0n ? emptyDigest : digest(10), newByteLength: length,
  }));
  const maxCount = fixture(); maxCount.operations = operations(256, 0n); accepts(maxCount);
  const excessCount = fixture(); excessCount.operations = operations(257, 0n); refuses(excessCount);
  const maxMember = fixture(); maxMember.operations = operations(1, 16n * 1024n * 1024n); accepts(maxMember);
  const maxAggregate = fixture(); maxAggregate.operations = operations(8, 16n * 1024n * 1024n); accepts(maxAggregate);
  const excessAggregate = fixture(); excessAggregate.operations = operations(9, 16n * 1024n * 1024n); refuses(excessAggregate);
});

test("P2-D2 code and introduced mutants prove the byte-only no-effect boundary", () => {
  const ts = readFileSync(`${root}/src/platform/native_p2_d2_overlay.ts`, "utf8");
  const rustLib = readFileSync(`${root}/native/crates/p2-d2-evidence/src/lib.rs`, "utf8");
  const forbiddenTs = /(?:node:(?:fs|child_process|net|http|https|dgram)|\b(?:readFile|spawn|createConnection|fetch)\b)/;
  const forbiddenRust = /std::(?:fs|process|net)/;
  const checkTs = (source: string): void => assert.doesNotMatch(source, forbiddenTs);
  const checkRust = (source: string): void => assert.doesNotMatch(source, forbiddenRust);
  checkTs(ts); checkRust(rustLib);
  assert.throws(() => checkTs(`${ts}\nimport "node:fs";`));
  assert.throws(() => checkTs(`${ts}\nimport { spawn } from "node:child_process";`));
  assert.throws(() => checkTs(`${ts}\nimport "node:net";`));
  assert.throws(() => checkRust(`${rustLib}\nuse std::fs;`));
  assert.throws(() => checkRust(`${rustLib}\nuse std::process;`));
  assert.throws(() => checkRust(`${rustLib}\nuse std::net;`));
  assert.deepEqual(P2_D2_OVERLAY_AUTHORITY_BOUNDARY, {
    filesystem: false, process: false, network: false, signatureVerification: false,
    overlayApplication: false, build: false, admission: false, authorityBrand: false, launch: false,
  });
});

test("P2-D2 workspace/package boundary is exact and cannot import candidate crypto", () => {
  const manifest = readFileSync(`${root}/native/crates/p2-d2-evidence/Cargo.toml`, "utf8");
  assert.match(manifest, /\[dependencies\]\nkeep-native-protocol = \{ path = "\.\.\/protocol" \}/);
  assert.doesNotMatch(manifest, /dalek|vendor-p2|p2-crypto-candidate/);
  const source = readFileSync(`${root}/native/crates/p2-d2-evidence/src/lib.rs`, "utf8");
  assert.doesNotMatch(source, /vendor-p2|p2-crypto-candidate|admissionStatus|VerifiedNativeArtifacts/);
  const members = resolvedPackageMembers(root);
  assert.ok(members.includes("native/crates/p2-d2-evidence/src/lib.rs"));
});
