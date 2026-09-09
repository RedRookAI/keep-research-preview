import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { decodeCanonical, encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import { captureP2S1Canonical, P2_S1_RUST_SCHEMA_NAMES, p2S1EnvelopeDigest, p2S1SignaturePreimage, type P2S1SignedSchema } from "../src/platform/native_authority_schema_v1.js";
import { captureNativePatchOverlayV1 } from "../src/platform/native_p2_d2_overlay.js";
import { captureNativePatchByteCarrierSetV1, joinValidatedPatchApplicationInputs } from "../src/platform/native_p2_d2_carriers.js";
import { deriveNativeResultTreeCandidateV1, validateNativeResultTreeApplicationV1, type CapturedNativeArchiveV1 } from "../src/platform/native_p2_d2_application.js";

const sha = (bytes: Uint8Array | string): string => createHash("sha256").update(bytes).digest("hex");
const digest = (n: number): string => n.toString(16).padStart(64, "0");
const oldManifest = Uint8Array.from(Buffer.from("old manifest\n"));
const newManifest = Uint8Array.from(Buffer.from("new manifest\n"));
const buildScript = Uint8Array.from(Buffer.from("fn main() {}\n"));
const library = Uint8Array.from(Buffer.from("pub fn keep() {}\n"));

function archive(): CapturedNativeArchiveV1 {
  return {
    packageId: "curve25519-dalek@5.0.0", baseArchiveDigest: digest(1),
    files: [
      { path: "Cargo.toml", bytes: Uint8Array.from(oldManifest) },
      { path: "build.rs", bytes: Uint8Array.from(buildScript) },
      { path: "src/lib.rs", bytes: Uint8Array.from(library) },
    ],
  };
}
function carrier(path = "Cargo.toml", operation: "add" | "replace" = "replace", bytes = newManifest): CanonicalValue {
  return { schema: "keep.p2-d2-patch-byte-carrier-set", version: 1n, packageId: "curve25519-dalek@5.0.0", entries: [{ path, operation, bytes }] };
}
function overlay(resultTreeDigest: string, operations: CanonicalValue[] = [
  { operation: "replace", path: "Cargo.toml", oldByteDigest: sha(oldManifest), newByteDigest: sha(newManifest), newByteLength: BigInt(newManifest.byteLength) },
  { operation: "delete", path: "build.rs", oldByteDigest: sha(buildScript), newByteDigest: null, newByteLength: null },
]): CanonicalValue {
  return {
    schema: "keep.p2-d2-patch-overlay", version: 1n, packageId: "curve25519-dalek@5.0.0",
    baseArchiveDigest: digest(1), operations, rationale: "remove build script",
    resultTreeDigest, auditPlanDigest: digest(2),
  };
}
function inputs(resultTreeDigest = digest(3), overlayValue = overlay(resultTreeDigest), carrierValue = carrier()) {
  return joinValidatedPatchApplicationInputs(
    captureNativePatchOverlayV1(encodeCanonical(overlayValue)),
    captureNativePatchByteCarrierSetV1(encodeCanonical(carrierValue)),
  );
}

// Explicit maintainer-only generation; ordinary tests consume frozen bytes and
// never rewrite their expected answers. Both languages read this same fixture.
const fixtureRoot = process.env.KEEP_P2_CAPTURE_SOURCE_ROOT ?? fileURLToPath(new URL("../../", import.meta.url));
const fixturePath = join(fixtureRoot, "test/fixtures/native_p2_canonical_parity_v1.cbor");
const signedSchemaNames: readonly P2S1SignedSchema[] = ["root", "ceremony", "timestamp", "rollback", "recovery", "b3-profile", "b3-receipt", "b3-invalidation", "build-identity", "toolchain", "sbom", "provenance", "reproducibility"];
type SignedInput = { schema: P2S1SignedSchema; canonicalBytes: Uint8Array };
function maximumMetadata(): CanonicalValue {
  const prefix = `${`${"a".repeat(255)}/`.repeat(15)}${"b".repeat(250)}/`;
  const count = 4096n, mode = 0o777n, byteDigest = sha(new Uint8Array());
  const hash = createHash("sha256").update("keep.patch-source-rows/v1\0", "ascii");
  let canonicalLength = 0n;
  const chunk = (bytes: Uint8Array): void => { hash.update(bytes); canonicalLength += BigInt(bytes.length); };
  chunk(Uint8Array.of(0xa4)); chunk(encodeCanonical("files")); chunk(Uint8Array.of(0x99, 0x10, 0x00));
  for (let index = 0; index < Number(count); index++) {
    const path = `${prefix}${String(index).padStart(5, "0")}`; assert.equal(path.length, 4096);
    chunk(encodeCanonical({ path, mode, byteLength: 0n, byteDigest }));
  }
  for (const value of ["schema", "keep.patch-source-rows", "version", 1n, "packageId", "curve25519-dalek@5.0.0"]) chunk(encodeCanonical(value));
  return { prefix, count, mode, byteDigest, byteLength: 0n, canonicalLength, digest: hash.digest("hex") };
}
function canonicalParityFixture(signedInputs?: readonly SignedInput[]): Uint8Array {
  if (!signedInputs) {
    const stored = decodeCanonical(readFileSync(fixturePath)) as Record<string, CanonicalValue>;
    signedInputs = stored.signedSchemas as unknown as SignedInput[];
  }
  assert.deepEqual(signedInputs.map(row => row.schema), [...signedSchemaNames, "root"]);
  const signedSchemas = signedInputs.map(row => {
    const canonicalBytes = captureP2S1Canonical(row.canonicalBytes, row.schema).canonicalBytes;
    const envelope = decodeCanonical(canonicalBytes) as Record<string, CanonicalValue>;
    return { schema: row.schema, rustSchema: P2_S1_RUST_SCHEMA_NAMES[row.schema], canonicalBytes,
      payloadBytes: encodeCanonical(envelope.payload!), envelopeDigest: p2S1EnvelopeDigest(canonicalBytes, row.schema).hex,
      signaturePreimage: p2S1SignaturePreimage(canonicalBytes, row.schema) };
  });
  const source = archive();
  const result = deriveNativeResultTreeCandidateV1(inputs(), source);
  const overlayBytes = encodeCanonical(overlay(result.resultTreeDigest));
  const carrierBytes = encodeCanonical(carrier());
  const rows = (mode: bigint): Uint8Array => encodeCanonical({
    schema: "keep.patch-source-rows", version: 1n, packageId: source.packageId,
    files: source.files.map((file, index) => ({ path: file.path, mode: index === 0 ? mode : 0o644n, byteLength: BigInt(file.bytes.length), byteDigest: sha(file.bytes) })),
  });
  const artifact = (name: string, domain: string, canonicalBytes: Uint8Array): CanonicalValue => ({
    name, domain: Uint8Array.from(Buffer.from(domain, "ascii")), canonicalBytes, digest: createHash("sha256").update(domain, "ascii").update(canonicalBytes).digest("hex"),
  });
  return encodeCanonical({
    schema: "keep.test.native-p2-canonical-parity", version: 1n,
    baseArchiveDigest: source.baseArchiveDigest,
    signedSchemas,
    maximumMetadata: maximumMetadata(),
    source: source.files.map(file => ({ path: file.path, mode: 0o644n, bytes: file.bytes })),
    artifacts: [
      artifact("overlay", "keep.p2-d2-patch-overlay/v1\0", overlayBytes),
      artifact("carrier", "keep.p2-d2-patch-byte-carrier-set/v1\0", carrierBytes),
      artifact("result", "keep.p2-d2-result-tree/v1\0", result.canonicalBytes()),
      artifact("rows", "keep.patch-source-rows/v1\0", rows(0o644n)),
      artifact("rows-mode-mutant", "keep.patch-source-rows/v1\0", rows(0o755n)),
    ],
  });
}
if (process.env.KEEP_C01_GENERATE_FIXTURE === "1") {
  const oracle = process.env.KEEP_C01_PROTOCOL_ORACLE;
  assert.ok(oracle, "explicitly supply the installed-source-built protocol oracle for fixture generation");
  const result = spawnSync(oracle, [], { input: "P2CORPUS\n", encoding: "utf8", env: {}, timeout: 30_000, maxBuffer: 4 * 1024 * 1024 });
  assert.ifError(result.error); assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stdout.startsWith("P2CORPUS\t"));
  const values = new Map(result.stdout.trim().slice("P2CORPUS\t".length).split(";").map(row => {
    const [name, hex] = row.split("|"); assert.ok(name && hex); return [name, Uint8Array.from(Buffer.from(hex, "hex"))];
  }));
  const signedInputs = signedSchemaNames.map(schema => {
    const canonicalBytes = values.get(P2_S1_RUST_SCHEMA_NAMES[schema]); assert.ok(canonicalBytes); return { schema, canonicalBytes };
  });
  const successor = decodeCanonical(signedInputs[0]!.canonicalBytes) as Record<string, CanonicalValue>;
  const payload = successor.payload as Record<string, CanonicalValue>;
  payload.rootEpoch = 1n; payload.predecessorRootEnvelopeDigest = digest(1);
  successor.payloadDigest = sha(encodeCanonical(payload));
  (successor.signatures as Record<string, CanonicalValue>[])[0]!.authorizationRole = "root";
  signedInputs.push({ schema: "root", canonicalBytes: Uint8Array.from(encodeCanonical(successor)) });
  writeFileSync(fixturePath, canonicalParityFixture(signedInputs), { flag: process.argv.includes("--replace-c01-fixture") ? "w" : "wx" });
  process.exit(0);
}
test("P2-D2 shared literal corpus preserves all preimages, domains and mode identity", () => {
  assert.deepEqual(Buffer.from(canonicalParityFixture()), readFileSync(fixturePath));
});

test("P2-D2 pure application derives and then verifies the exact committed result tree", () => {
  const candidate = deriveNativeResultTreeCandidateV1(inputs(), archive());
  assert.equal(candidate.resultTreeDigest, "4e960da8bb98e1f597df4bf41c80ca12c8a6fb949ece7fd22baea1fb0846b000");
  const validated = validateNativeResultTreeApplicationV1(inputs(candidate.resultTreeDigest), archive());
  assert.equal(validated.resultTreeDigest, candidate.resultTreeDigest);
  assert.deepEqual(validated.files.map((row) => row.path), ["Cargo.toml", "src/lib.rs"]);
  assert.deepEqual(Buffer.from(validated.fileBytes("Cargo.toml")), Buffer.from(newManifest));
  assert.throws(() => validated.fileBytes("build.rs"));
  assert.deepEqual(
    { kind: validated.kind, filesystem: validated.filesystem, build: validated.build, admission: validated.admission, launch: validated.launch },
    { kind: "ValidatedNativeResultTreePlan", filesystem: false, build: false, admission: false, launch: false },
  );
  const copy = validated.fileBytes("Cargo.toml"); copy[0] = 0;
  assert.deepEqual(Buffer.from(validated.fileBytes("Cargo.toml")), Buffer.from(newManifest));
  assert.throws(() => validateNativeResultTreeApplicationV1(inputs(digest(9)), archive()));
});

test("P2-D2 pure application refuses base, old-byte, existence, and restored-script mutants", () => {
  const wrongBase = archive(); (wrongBase as { baseArchiveDigest: string }).baseArchiveDigest = digest(8);
  assert.throws(() => deriveNativeResultTreeCandidateV1(inputs(), wrongBase), /different base/);
  const wrongOld = overlay(digest(3));
  ((wrongOld as Record<string, CanonicalValue>).operations as Record<string, CanonicalValue>[])[0]!.oldByteDigest = digest(8);
  assert.throws(() => deriveNativeResultTreeCandidateV1(inputs(digest(3), wrongOld), archive()), /old-byte/);
  const missingDelete = archive(); (missingDelete as { files: CapturedNativeArchiveV1["files"] }).files = missingDelete.files.filter((row) => row.path !== "build.rs");
  assert.throws(() => deriveNativeResultTreeCandidateV1(inputs(), missingDelete), /old-byte/);
  const noDelete = overlay(digest(3), [((overlay(digest(3)) as Record<string, CanonicalValue>).operations as CanonicalValue[])[0]!]);
  const result = deriveNativeResultTreeCandidateV1(inputs(digest(3), noDelete), archive());
  assert.ok(result.files.some((row) => row.path === "build.rs"), "named restore mutant remains observable and must redden a zero-build-script policy");
});

test("P2-D2 pure application refuses base and operation casefold collisions", () => {
  const collidingBase = archive();
  (collidingBase as { files: CapturedNativeArchiveV1["files"] }).files = [
    { path: "A/file", bytes: new Uint8Array() }, { path: "a/File", bytes: new Uint8Array() },
  ];
  assert.throws(() => deriveNativeResultTreeCandidateV1(inputs(), collidingBase), /case folding/);
  const addBytes = Uint8Array.from(Buffer.from("added\n"));
  const addOverlay = overlay(digest(3), [{ operation: "add", path: "SRC/lib.rs", oldByteDigest: null, newByteDigest: sha(addBytes), newByteLength: BigInt(addBytes.byteLength) }]);
  assert.throws(() => deriveNativeResultTreeCandidateV1(inputs(digest(3), addOverlay, carrier("SRC/lib.rs", "add", addBytes)), archive()), /case-collides/);
});

test("P2-D2 pure application refuses reserved/generated metadata in the semantic base tree", () => {
  const value = archive();
  (value as { files: CapturedNativeArchiveV1["files"] }).files = [{ path: ".cargo-checksum.json", bytes: new Uint8Array() }];
  assert.throws(() => deriveNativeResultTreeCandidateV1(inputs(), value), /malformed/);
});
