import test, { after } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";

const installedRoot = process.env.KEEP_INSTALLED_PACKAGE_ROOT;
if (!installedRoot) throw Error("KEEP_INSTALLED_PACKAGE_ROOT is required; no development checkout fallback");
const installedRequire = createRequire(join(installedRoot, "package.json"));
const keep = await import(pathToFileURL(installedRequire.resolve("keep")).href);
// Test fixture encoding comes from the installed source distribution, never the
// development checkout. Operational calls below use the public package-root API.
const { encodeCanonical, decodeCanonical } = await import(pathToFileURL(join(installedRoot, "dist/src/eir/canonical.js")).href);
const sha = bytes => createHash("sha256").update(bytes).digest("hex");
const cbor = value => Buffer.from(encodeCanonical(value));
const refuses = code => error => error instanceof keep.NativePatchCaptureError && error.code === code;

function archive(rows) {
  const parts = [];
  for (const row of rows) {
    const header = Buffer.alloc(512);
    header.write(`curve25519-dalek-5.0.0/${row.path}`, 0, "ascii");
    header.write(`${row.mode.toString(8).padStart(7, "0")}\0`, 100, "ascii");
    header.write(`${row.bytes.length.toString(8).padStart(11, "0")}\0`, 124, "ascii");
    header[156] = 48; header.write("ustar  \0", 257, "ascii"); header.fill(32, 148, 156);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
    parts.push(header, row.bytes, Buffer.alloc((512 - row.bytes.length % 512) % 512));
  }
  return Buffer.concat([...parts, Buffer.alloc(1024)]);
}
function rowsDigest(rows) {
  return createHash("sha256").update("keep.patch-source-rows/v1\0", "ascii").update(cbor({
    schema: "keep.patch-source-rows", version: 1n, packageId: "curve25519-dalek@5.0.0",
    files: [...rows].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0).map(row => ({
      path: row.path, mode: BigInt(row.mode), byteLength: BigInt(row.bytes.length), byteDigest: sha(row.bytes),
    })),
  })).digest("hex");
}

// Normal --extern linking from the installed pure source package. No Cargo
// resolution, path-inclusion, development source, or compiler download fallback.
let compiled;
after(() => { if (compiled) rmSync(compiled.root, { recursive: true }); });
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: installedRoot, env: {}, encoding: "utf8", timeout: 30_000, killSignal: "SIGKILL", maxBuffer: 1024 * 1024, ...options });
  assert.ifError(result.error); assert.equal(result.status, 0, result.stderr); assert.equal(result.signal, null);
  return result.stdout.trim();
}
function installedOracles() {
  if (compiled) return compiled;
  const toolchain = process.env.KEEP_P1_TOOLCHAIN_ROOT;
  assert.ok(toolchain, "KEEP_P1_TOOLCHAIN_ROOT must explicitly locate the pinned compiler");
  const lock = JSON.parse(readFileSync(join(installedRoot, "native/toolchain-lock.json"), "utf8"));
  const rustc = join(toolchain, "bin/rustc"), linker = join(toolchain, "lib/rustlib", lock.host, "bin/rust-lld");
  assert.equal(sha(readFileSync(rustc)), lock.rustcSha256);
  assert.equal(sha(readFileSync(linker)), lock.rustLldSha256);
  const root = mkdtempSync(join(tmpdir(), "keep-installed-c01-rust-"));
  // Register ownership before compilation so even a failed build is cleaned up.
  compiled = { root, protocol: join(root, "protocol-oracle"), evidence: join(root, "evidence-oracle"), parity: join(root, "parity") };
  const protocol = join(root, "libkeep_native_protocol.rlib"), evidence = join(root, "libkeep_native_p2_d2_evidence.rlib");
  const common = ["--edition=2024", "--target", lock.target, "-C", `linker=${linker}`, "-C", "opt-level=1", "-L", `dependency=${root}`];
  const compile = (source, output, args) => run(rustc, [...common, source, "-o", output, ...args]);
  compile(join(installedRoot, "native/crates/protocol/src/lib.rs"), protocol, ["--crate-type=rlib", "--crate-name=keep_native_protocol"]);
  compile(join(installedRoot, "native/crates/p2-d2-evidence/src/lib.rs"), evidence, ["--crate-type=rlib", "--crate-name=keep_native_p2_d2_evidence", "--extern", `keep_native_protocol=${protocol}`]);
  const externs = ["--extern", `keep_native_protocol=${protocol}`, "--extern", `keep_native_p2_d2_evidence=${evidence}`];
  compile(join(installedRoot, "native/crates/protocol/src/main.rs"), compiled.protocol, externs);
  compile(join(installedRoot, "native/crates/p2-d2-evidence/src/main.rs"), compiled.evidence, externs);
  // A fixture-only public-library consumer checks result application and mode
  // identity against the same literal corpus. It has no product runtime role.
  const consumer = join(root, "parity.rs");
  writeFileSync(consumer, String.raw`
#![forbid(unsafe_code)]
use keep_native_protocol::{Value, Limits, decode_canonical, encode_bounded, sha256_hex};
use keep_native_protocol::patch_capture::{SourceRowsBuilder, CaptureError, CAPTURE_ROWS_LIMITS};
use keep_native_p2_d2_evidence::{capture_patch_overlay, capture_patch_byte_carrier_set,
    validate_result_tree_application, CapturedNativeArchiveV1, CapturedNativeArchiveFileV1};
fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    let Value::Map(fields) = v else { panic!("expected map") };
    &fields.iter().find(|(name, _)| name == key).expect("missing field").1
}
fn text(v: &Value) -> &str { let Value::Text(v) = v else { panic!("text") }; v }
fn bytes(v: &Value) -> &[u8] { let Value::Bytes(v) = v else { panic!("bytes") }; v }
fn array(v: &Value) -> &[Value] { let Value::Array(v) = v else { panic!("array") }; v }
fn uint(v: &Value) -> u64 { let Value::Unsigned(v) = v else { panic!("uint") }; *v }
fn main() {
    let raw = std::fs::read(std::env::args().nth(1).expect("fixture path")).unwrap();
    let fixture = decode_canonical(&raw, Limits::EVIDENCE).unwrap();
    assert_eq!(encode_bounded(&fixture, Limits::EVIDENCE).unwrap(), raw);
    let artifacts = array(field(&fixture, "artifacts"));
    let artifact = |name: &str| artifacts.iter().find(|v| text(field(v, "name")) == name).unwrap();
    for row in artifacts {
        let canonical = bytes(field(row, "canonicalBytes"));
        let value = decode_canonical(canonical, Limits::EVIDENCE).unwrap();
        assert_eq!(encode_bounded(&value, Limits::EVIDENCE).unwrap(), canonical);
        let mut preimage = bytes(field(row, "domain")).to_vec();
        preimage.extend_from_slice(canonical);
        assert_eq!(sha256_hex(&preimage), text(field(row, "digest")));
    }
    let overlay = capture_patch_overlay(bytes(field(artifact("overlay"), "canonicalBytes"))).unwrap();
    let carrier = capture_patch_byte_carrier_set(bytes(field(artifact("carrier"), "canonicalBytes"))).unwrap();
    assert_eq!(overlay.patch_overlay_digest(), text(field(artifact("overlay"), "digest")));
    assert_eq!(carrier.patch_byte_carrier_set_digest(), text(field(artifact("carrier"), "digest")));
    let source = array(field(&fixture, "source"));
    let archive = CapturedNativeArchiveV1 {
        package_id: "curve25519-dalek@5.0.0".into(),
        base_archive_digest: text(field(&fixture, "baseArchiveDigest")).into(),
        files: source.iter().map(|v| CapturedNativeArchiveFileV1 {
            path: text(field(v, "path")).into(), bytes: bytes(field(v, "bytes")).to_vec()
        }).collect(),
    };
    let result = validate_result_tree_application(&overlay, &carrier, &archive).unwrap();
    assert_eq!(result.result_tree_digest(), text(field(artifact("result"), "digest")));
    assert_eq!(result.canonical_bytes(), bytes(field(artifact("result"), "canonicalBytes")));
    for (name, first_mode) in [("rows", 0o644), ("rows-mode-mutant", 0o755)] {
        let mut builder = SourceRowsBuilder::new();
        for (index, v) in source.iter().enumerate() {
            builder.push(text(field(v, "path")).into(), if index == 0 { first_mode } else { 0o644 }, bytes(field(v, "bytes")).to_vec()).unwrap();
        }
        assert_eq!(builder.finish().unwrap().row_digest(), text(field(artifact(name), "digest")));
    }
    let maximum = field(&fixture, "maximumMetadata");
    assert_eq!(uint(field(maximum, "count")), 4096);
    assert_eq!(uint(field(maximum, "mode")), 0o777);
    let prefix = text(field(maximum, "prefix"));
    let mut builder = SourceRowsBuilder::new();
    for index in 0..4096 {
        let path = format!("{prefix}{index:05}"); assert_eq!(path.len(), 4096);
        builder.push(path, 0o777, vec![]).unwrap();
    }
    assert_eq!(builder.push("overflow".into(), 0o777, vec![]), Err(CaptureError::Limit));
    assert_eq!(SourceRowsBuilder::new().check_file(&format!("{prefix}000000"), 0o777, 0), Err(CaptureError::Path));
    let rows = builder.finish().unwrap();
    assert_eq!(rows.row_digest(), text(field(maximum, "digest")));
    let metadata = Value::Map(vec![
        ("schema".into(), Value::Text("keep.patch-source-rows".into())),
        ("version".into(), Value::Unsigned(1)),
        ("packageId".into(), Value::Text("curve25519-dalek@5.0.0".into())),
        ("files".into(), Value::Array(rows.files().iter().map(|r| Value::Map(vec![
            ("path".into(), Value::Text(r.path().into())), ("mode".into(), Value::Unsigned(r.mode() as u64)),
            ("byteLength".into(), Value::Unsigned(0)), ("byteDigest".into(), Value::Text(r.byte_digest().into()))
        ])).collect()))
    ]);
    let encoded = encode_bounded(&metadata, CAPTURE_ROWS_LIMITS).unwrap();
    assert_eq!(encoded.len() as u64, uint(field(maximum, "canonicalLength")));
    let mut preimage = b"keep.patch-source-rows/v1\0".to_vec(); preimage.extend(encoded);
    assert_eq!(sha256_hex(&preimage), rows.row_digest());
    println!("PASS shared corpus and maximum metadata with one-over refusals");
}
`);
  compile(consumer, compiled.parity, externs);
  return compiled;
}

for (const track of ["n1", "enterprise"]) {
  test(`SG-02-T001 ${track}: installed C01 standalone Rust and TS consume one literal corpus`, async () => {
    const binaries = installedOracles();
    const fixturePath = join(installedRoot, "test/fixtures/native_p2_canonical_parity_v1.cbor");
    const raw = readFileSync(fixturePath);
    assert.equal(sha(raw), "b1be579bb6a8ab9fbfea12dcf28ca4356fefc3e666db7ae8c1c6ae0c13e91b77");
    const fixture = decodeCanonical(raw);
    assert.deepEqual(cbor(fixture), raw);
    const artifact = name => fixture.artifacts.find(row => row.name === name);
    for (const row of fixture.artifacts) {
      const bytes = Buffer.from(row.canonicalBytes), hex = bytes.toString("hex");
      assert.deepEqual(cbor(decodeCanonical(bytes)), bytes);
      assert.equal(createHash("sha256").update(row.domain, "ascii").update(bytes).digest("hex"), row.digest);
      assert.equal(run(binaries.protocol, [], { input: `VALUE:${hex}\n` }), `OK\tValue\t${sha(bytes)}\t${hex}`);
    }
    const module = name => import(pathToFileURL(join(installedRoot, `dist/src/platform/${name}.js`)).href);
    const { captureNativePatchOverlayV1 } = await module("native_p2_d2_overlay");
    const { captureNativePatchByteCarrierSetV1, joinValidatedPatchApplicationInputs } = await module("native_p2_d2_carriers");
    const { validateNativeResultTreeApplicationV1 } = await module("native_p2_d2_application");
    const overlay = captureNativePatchOverlayV1(artifact("overlay").canonicalBytes);
    const carrier = captureNativePatchByteCarrierSetV1(artifact("carrier").canonicalBytes);
    assert.equal(overlay.patchOverlayDigest, artifact("overlay").digest);
    assert.equal(carrier.patchByteCarrierSetDigest, artifact("carrier").digest);
    assert.equal(run(binaries.evidence, [], { input: `${Buffer.from(artifact("overlay").canonicalBytes).toString("hex")}\n` }), `OK\t${overlay.patchOverlayDigest}`);
    assert.equal(run(binaries.evidence, [], { input: `CARRIER\t${Buffer.from(artifact("carrier").canonicalBytes).toString("hex")}\n` }), `OK\t${carrier.patchByteCarrierSetDigest}`);
    const result = validateNativeResultTreeApplicationV1(joinValidatedPatchApplicationInputs(overlay, carrier), {
      packageId: "curve25519-dalek@5.0.0", baseArchiveDigest: fixture.baseArchiveDigest,
      files: fixture.source.map(row => ({ path: row.path, bytes: row.bytes })),
    });
    assert.equal(result.resultTreeDigest, "4e960da8bb98e1f597df4bf41c80ca12c8a6fb949ece7fd22baea1fb0846b000");
    assert.deepEqual(Buffer.from(result.canonicalBytes()), Buffer.from(artifact("result").canonicalBytes));
    assert.notEqual(artifact("rows").digest, artifact("rows-mode-mutant").digest);
    const authority = await module("native_authority_schema_v1");
    assert.equal(fixture.signedSchemas.length, 14);
    assert.equal(new Set(fixture.signedSchemas.map(row => row.schema)).size, 13);
    for (const row of fixture.signedSchemas) {
      const bytes = Buffer.from(row.canonicalBytes), payload = Buffer.from(row.payloadBytes);
      assert.deepEqual(Buffer.from(authority.captureP2S1Canonical(bytes, row.schema).canonicalBytes), bytes);
      assert.equal(authority.p2S1EnvelopeDigest(bytes, row.schema).hex, row.envelopeDigest);
      assert.deepEqual(Buffer.from(authority.p2S1SignaturePreimage(bytes, row.schema)), Buffer.from(row.signaturePreimage));
      assert.equal(run(binaries.protocol, [], { input: `P2:${row.rustSchema}:${bytes.toString("hex")}\n` }), `P2\t${row.rustSchema}\t${row.envelopeDigest}\t${bytes.toString("hex")}`);
      assert.equal(run(binaries.protocol, [], { input: `P2SIG:${row.rustSchema}:${payload.toString("hex")}\n` }), `P2SIG\t${row.rustSchema}\t${Buffer.from(row.signaturePreimage).toString("hex")}`);
      const changedPayload = change => {
        const envelope = decodeCanonical(bytes), changed = { ...envelope.payload, ...change };
        return cbor({ ...envelope, payload: changed, payloadDigest: sha(cbor(changed)) });
      };
      for (const mutant of [
        Buffer.concat([bytes, Buffer.from([0])]),
        cbor({ ...decodeCanonical(bytes), extra: true }),
        cbor({ ...decodeCanonical(bytes), payloadDigest: "f".repeat(64) }),
        changedPayload({ version: 2n }),
        changedPayload({ schema: "keep.wrong-domain" }),
      ]) {
        assert.throws(() => authority.captureP2S1Canonical(mutant, row.schema));
        assert.match(run(binaries.protocol, [], { input: `P2:${row.rustSchema}:${mutant.toString("hex")}\n` }), /^ERR\t/);
      }
    }
    // A compact frozen expansion recipe represents the 17MiB metadata preimage;
    // hash row encodings incrementally, never a giant source-byte object.
    const maximum = fixture.maximumMetadata;
    assert.equal(maximum.count, 4096n); assert.equal(maximum.mode, 0o777n);
    const hash = createHash("sha256").update("keep.patch-source-rows/v1\0", "ascii");
    let canonicalLength = 0n;
    const chunk = bytes => { hash.update(bytes); canonicalLength += BigInt(bytes.length); };
    chunk(Buffer.from([0xa4])); chunk(cbor("files")); chunk(Buffer.from([0x99, 0x10, 0x00]));
    for (let index = 0; index < 4096; index++) {
      const path = `${maximum.prefix}${String(index).padStart(5, "0")}`; assert.equal(path.length, 4096);
      chunk(cbor({ path, mode: 0o777n, byteLength: 0n, byteDigest: sha(Buffer.alloc(0)) }));
    }
    for (const value of ["schema", "keep.patch-source-rows", "version", 1n, "packageId", "curve25519-dalek@5.0.0"]) chunk(cbor(value));
    assert.equal(canonicalLength, maximum.canonicalLength); assert.equal(hash.digest("hex"), maximum.digest);
    assert.equal(run(binaries.parity, [fixturePath]), "PASS shared corpus and maximum metadata with one-over refusals");
  });
}

// Each track gets its own real source root, distinct data and direct calls. This
// input-capture ticket does not grant tenant/root authorization or execute patches.
for (const track of ["n1", "enterprise"]) {
  test(`SG-02-T001 ${track}: installed C05/C06 exact inert rows across directory/tar/gzip`, async () => {
    const root = mkdtempSync(join(tmpdir(), `keep-installed-capture-${track}-`));
    try {
      assert.equal(typeof keep.capturePackagedNativePatchInputsV1, "function");
      const rows = [
        { path: "empty", mode: 0o644, bytes: Buffer.alloc(0) },
        { path: "src/lib.rs", mode: 0o644, bytes: Buffer.from(`pub fn ${track}_fixture() {}\n`) },
        { path: "tool", mode: 0o755, bytes: Buffer.from(`inert ${track} tool bytes\n`) },
      ];
      mkdirSync(join(root, "directory/src"), { recursive: true });
      for (const row of rows) { writeFileSync(join(root, "directory", row.path), row.bytes); chmodSync(join(root, "directory", row.path), row.mode); }
      const tar = archive(rows), compressed = gzipSync(tar);
      writeFileSync(join(root, "source.tar"), tar); writeFileSync(join(root, "source.tar.gz"), compressed);
      const replacement = Uint8Array.from(Buffer.from(`replacement ${track}\n`));
      const carrier = cbor({ schema: "keep.p2-d2-patch-byte-carrier-set", version: 1n, packageId: "curve25519-dalek@5.0.0", entries: [{ path: "src/lib.rs", operation: "replace", bytes: replacement }] });
      writeFileSync(join(root, "carrier.cbor"), carrier);
      const overlayFor = base => cbor({
        schema: "keep.p2-d2-patch-overlay", version: 1n, packageId: "curve25519-dalek@5.0.0", baseArchiveDigest: base,
        operations: [{ operation: "replace", path: "src/lib.rs", oldByteDigest: sha(rows[1].bytes), newByteDigest: sha(replacement), newByteLength: BigInt(replacement.length) }],
        rationale: `${track} installed capture only`, resultTreeDigest: "2".repeat(64), auditPlanDigest: "3".repeat(64),
      });
      const results = [];
      for (const [sourceKind, sourcePath, stream] of [["directory", "directory", null], ["tar", "source.tar", tar], ["tar-gzip", "source.tar.gz", compressed]]) {
        const base = stream === null ? "1".repeat(64) : sha(stream), overlay = overlayFor(base);
        writeFileSync(join(root, "overlay.cbor"), overlay);
        const request = {
          schema: "keep.patch-input-capture", version: 1n, root, sourceKind, sourcePath,
          overlayPath: "overlay.cbor", overlayByteDigest: sha(overlay), carrierPath: "carrier.cbor", carrierByteDigest: sha(carrier),
          ...(stream === null ? { expectedSourceRowDigest: rowsDigest(rows), declaredBaseArchiveDigest: base } : { sourceStreamDigest: base }),
        };
        const result = await keep.capturePackagedNativePatchInputsV1(request);
        assert.equal(result.sourceRowDigest, rowsDigest(rows)); assert.equal(result.sourceKind, sourceKind);
        assert.deepEqual(Buffer.from(result.overlayBytes()), overlay); assert.deepEqual(Buffer.from(result.carrierBytes()), carrier);
        assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.files));
        for (const flag of ["filesystem", "signature", "build", "install", "launch"]) assert.equal(result[flag], false);
        assert.equal(Object.hasOwn(result, "sourceStreamDigest"), stream !== null);
        assert.equal(Object.hasOwn(result, "declaredBaseArchiveDigest"), stream === null);
        assert.equal(result.files.length, rows.length);
        for (const [index, file] of result.files.entries()) {
          assert.ok(Object.isFrozen(file)); assert.equal(file.path, rows[index].path); assert.equal(file.mode, rows[index].mode);
          const copy = file.bytes(); assert.deepEqual(Buffer.from(copy), rows[index].bytes); copy.fill(0xff);
          assert.deepEqual(Buffer.from(file.bytes()), rows[index].bytes);
        }
        results.push(result);
        await assert.rejects(keep.capturePackagedNativePatchInputsV1({ ...request, sourcePath: "../foreign" }), refuses("PATH"));
        await assert.rejects(keep.capturePackagedNativePatchInputsV1({ ...request, sourcePath: "carrier.cbor" }), refuses("PATH"));
        await assert.rejects(keep.capturePackagedNativePatchInputsV1({ ...request, extra: "authority" }), refuses("MALFORMED"));
        await assert.rejects(keep.capturePackagedNativePatchInputsV1({ ...request, overlayByteDigest: "4".repeat(64) }), refuses("INTEGRITY"));
        if (sourceKind === "tar") {
          const hidden = Buffer.concat([tar, tar]), hiddenOverlay = overlayFor(sha(hidden));
          writeFileSync(join(root, sourcePath), hidden); writeFileSync(join(root, "overlay.cbor"), hiddenOverlay);
          await assert.rejects(keep.capturePackagedNativePatchInputsV1({ ...request, sourceStreamDigest: sha(hidden), overlayByteDigest: sha(hiddenOverlay) }), refuses("MALFORMED"));
        }
        if (sourceKind === "directory") {
          symlinkSync("../carrier.cbor", join(root, "directory/link"));
          await assert.rejects(keep.capturePackagedNativePatchInputsV1(request), refuses("PATH"));
          rmSync(join(root, "directory/link"));
        }
      }
      writeFileSync(join(root, "directory/src/lib.rs"), "changed after capture");
      for (const result of results) assert.deepEqual(Buffer.from(result.files[1].bytes()), rows[1].bytes);
    } finally { rmSync(root, { recursive: true }); }
  });
}
