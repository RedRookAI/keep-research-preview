import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { chmodSync, closeSync, copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { constants, gzipSync } from "node:zlib";
import { encodeCanonical, decodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import { captureNativePatchOverlayV1 } from "../src/platform/native_p2_d2_overlay.js";
import { captureNativePatchByteCarrierSetV1 } from "../src/platform/native_p2_d2_carriers.js";

// Test-only fixture oracle override for isolated builds. The operational SDK must
// resolve only its fixed, verified installed executable, never this environment key.
const oracle = process.env.KEEP_P2_CAPTURE_ORACLE ?? fileURLToPath(new URL("../../native/target/x86_64-unknown-linux-musl/debug/keep-native-p2-d2-overlay-oracle", import.meta.url));
const captureBinary = process.env.KEEP_P2_CAPTURE_BINARY ?? fileURLToPath(new URL("../../native/target/x86_64-unknown-linux-musl/debug/keep-native-patch-capture", import.meta.url));
const captureSourceRoot = process.env.KEEP_P2_CAPTURE_SOURCE_ROOT ?? fileURLToPath(new URL("../../", import.meta.url));
const sha = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
type Row = { path: string; mode: number; bytes: Buffer };
function checksum(header: Buffer): void {
  header.fill(32, 148, 156);
  const sum = header.reduce((n, byte) => n + byte, 0);
  header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
}
function header(row: Row, gnu = true): Buffer {
  const out = Buffer.alloc(512);
  const path = `curve25519-dalek-5.0.0/${row.path}`;
  assert.ok(Buffer.byteLength(path) <= 100, "fixture uses short tar names");
  out.write(path, 0, "utf8");
  out.write(`${row.mode.toString(8).padStart(7, "0")}\0`, 100, "ascii");
  out.write(`${row.bytes.length.toString(8).padStart(11, "0")}\0`, 124, "ascii");
  out[156] = 48;
  out.write(gnu ? "ustar  \0" : "ustar\x0000", 257, "ascii");
  checksum(out);
  return out;
}
function tar(rows: readonly Row[], gnu = true): Buffer {
  return Buffer.concat([...rows.flatMap(row => [header(row, gnu), row.bytes, Buffer.alloc((512 - row.bytes.length % 512) % 512)]), Buffer.alloc(1024)]);
}
function rowDigest(rows: readonly Row[]): string {
  const metadata = {
    schema: "keep.patch-source-rows", version: 1n, packageId: "curve25519-dalek@5.0.0",
    files: [...rows].sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0).map(row => ({
      path: row.path, mode: BigInt(row.mode), byteLength: BigInt(row.bytes.length), byteDigest: sha(row.bytes),
    })),
  };
  return createHash("sha256").update("keep.patch-source-rows/v1\0", "ascii").update(encodeCanonical(metadata)).digest("hex");
}
function runLine(line: string): string {
  const result = spawnSync(oracle, [], { input: `${line}\n`, encoding: "utf8", maxBuffer: 64 * 1024, timeout: 30_000, killSignal: "SIGKILL", env: {}, cwd: "/" });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  return result.stdout.trim();
}
function capture(bytes: Buffer, kind: "TAR" | "TAR_GZIP" = "TAR_GZIP", digest = sha(bytes)): string {
  return runLine(`SOURCE\t${kind}\t${digest}\t${bytes.toString("hex")}`);
}
function expected(rows: readonly Row[]): string {
  return `OK\tSOURCE\t${rowDigest(rows)}\t${rows.length}\t${rows.reduce((n, row) => n + row.bytes.length, 0)}`;
}

test("native archive consumer matches TS identity for actual stored, fixed and dynamic DEFLATE", () => {
  const rows: Row[] = [
    { path: "z", mode: 0o755, bytes: Buffer.from("abc def ghi jkl mno pqr stu vwxyz\n".repeat(2000)) },
    { path: "a/b", mode: 0o644, bytes: Buffer.from("owned inert bytes") },
    { path: "empty", mode: 0, bytes: Buffer.alloc(0) },
  ];
  for (const gnu of [false, true]) {
    const raw = tar(rows, gnu);
    assert.equal(capture(raw, "TAR"), expected(rows));
    for (const [options, blockType] of [[{ level: 0 }, 0], [{ strategy: constants.Z_FIXED }, 1], [{ level: 9 }, 2]] as const) {
      const compressed = gzipSync(raw, options);
      assert.equal((compressed[10]! >> 1) & 3, blockType, "prove the fixture really exercises the claimed first block type");
      assert.equal(capture(compressed), expected(rows));
    }
    const split = 517; // split a file body across gzip members, not a tar boundary
    const concatenated = Buffer.concat([gzipSync(raw.subarray(0, split)), gzipSync(raw.subarray(split))]);
    assert.equal(capture(concatenated), expected(rows));
  }
});

test("compressed hidden second archives, framing corruption and kind/hash confusion refuse", () => {
  const raw = tar([{ path: "a", mode: 0o644, bytes: Buffer.from("data") }]);
  const compressed = gzipSync(raw);
  for (const input of [gzipSync(Buffer.concat([raw, raw])), Buffer.concat([compressed, compressed])]) {
    assert.equal(capture(input), "ERR\tMALFORMED", "a second archive must not be omitted after the first terminator");
  }
  assert.equal(capture(raw), "ERR\tMALFORMED");
  assert.equal(capture(compressed, "TAR"), "ERR\tMALFORMED");
  assert.equal(capture(compressed, "TAR_GZIP", "a".repeat(64)), "ERR\tINTEGRITY");
  for (const offset of [compressed.length - 8, compressed.length - 4]) {
    const bad = Buffer.from(compressed); bad[offset] = bad[offset]! ^ 1;
    assert.equal(capture(bad), "ERR\tINTEGRITY");
  }
  for (const input of [compressed.subarray(0, compressed.length - 1), Buffer.concat([compressed, Buffer.from([0])])]) {
    assert.equal(capture(input), "ERR\tMALFORMED");
  }
  assert.equal(runLine("SOURCE\tTAR\tbad\t0é0"), "ERR\tinvalid hex", "Unicode cannot panic the fixture oracle's hex reader");
  assert.equal(runLine("SOURCE\tTAR\ta\t00\textra"), "ERR\tMALFORMED");
});

test("native consumer admits 4096 files and refuses file 4097 before body allocation", () => {
  const rows: Row[] = Array.from({ length: 4096 }, (_, index) => ({ path: `f${index}`, mode: 0o644, bytes: Buffer.alloc(0) }));
  assert.equal(capture(gzipSync(tar(rows))), expected(rows));
  rows.push({ path: "excess", mode: 0o644, bytes: Buffer.alloc(0) });
  assert.equal(capture(gzipSync(tar(rows))), "ERR\tLIMIT");
});

test("native consumer admits 16MiB files and 128MiB aggregate, refuses one-over declarations", () => {
  const file = Buffer.alloc(16 * 1024 * 1024);
  const rows: Row[] = Array.from({ length: 8 }, (_, index) => ({ path: `f${index}`, mode: 0o644, bytes: file }));
  const compressed = gzipSync(tar(rows));
  assert.equal(capture(compressed), expected(rows));
  rows.push({ path: "excess", mode: 0o644, bytes: Buffer.from([1]) });
  assert.equal(capture(gzipSync(tar(rows))), "ERR\tLIMIT");
  const tooLarge = header({ path: "excess", mode: 0o644, bytes: Buffer.alloc(0) });
  tooLarge.write(`${(file.length + 1).toString(8).padStart(11, "0")}\0`, 124, "ascii");
  checksum(tooLarge);
  assert.equal(capture(gzipSync(tooLarge)), "ERR\tLIMIT", "no oversized body supplied or allocated");
});

test("native gzip expansion admits 144MiB and refuses the next block without a ratio exemption", () => {
  const zeros = Buffer.alloc(144 * 1024 * 1024);
  assert.equal(capture(gzipSync(zeros)), expected([]), "complete zero blocks after the two terminators are valid");
  const over = Buffer.concat([gzipSync(zeros), gzipSync(Buffer.alloc(512))]);
  assert.equal(capture(over), "ERR\tLIMIT");
});

function frame(payload: Uint8Array): Buffer {
  const length = Buffer.alloc(4); length.writeUInt32BE(payload.length);
  return Buffer.concat([length, payload]);
}
function invokeCapture(input: Buffer, args: string[] = []) {
  const result = spawnSync(captureBinary, args, { input, maxBuffer: 2 * 1024 * 1024, timeout: 30_000, killSignal: "SIGKILL", env: {}, cwd: "/" });
  assert.ifError(result.error);
  return result;
}
type CaptureFixture = { root: string; request: Record<string, CanonicalValue>; rows: Row[]; overlay: Buffer; carrier: Buffer };
function createCaptureFixture(kind: "directory" | "tar" | "tar-gzip"): CaptureFixture {
  const root = mkdtempSync(join(tmpdir(), "keep-framed-capture-"));
  try {
    const rows: Row[] = [
      { path: "a", mode: 0o644, bytes: Buffer.from("original\n".repeat(8000)) },
      { path: "empty", mode: 0o644, bytes: Buffer.alloc(0) },
    ];
    const archive = kind === "tar-gzip" ? gzipSync(tar(rows)) : tar(rows);
    const base = kind === "directory" ? "1".repeat(64) : sha(archive);
    const replacement = Buffer.from("replacement\n".repeat(4000));
    const overlay = Buffer.from(encodeCanonical({
      schema: "keep.p2-d2-patch-overlay", version: 1n, packageId: "curve25519-dalek@5.0.0",
      baseArchiveDigest: base,
      operations: [{ operation: "replace", path: "a", oldByteDigest: sha(rows[0]!.bytes), newByteDigest: sha(replacement), newByteLength: BigInt(replacement.length) }],
      rationale: "capture fixture only", resultTreeDigest: "2".repeat(64), auditPlanDigest: "3".repeat(64),
    }));
    const carrier = Buffer.from(encodeCanonical({
      schema: "keep.p2-d2-patch-byte-carrier-set", version: 1n, packageId: "curve25519-dalek@5.0.0",
      entries: [{ path: "a", operation: "replace", bytes: Uint8Array.from(replacement) }],
    }));
    writeFileSync(join(root, "overlay.cbor"), overlay);
    writeFileSync(join(root, "carrier.cbor"), carrier);
    if (kind === "directory") {
      mkdirSync(join(root, "source"));
      for (const row of rows) { writeFileSync(join(root, "source", row.path), row.bytes); chmodSync(join(root, "source", row.path), row.mode); }
    } else { writeFileSync(join(root, "source"), archive); }
    const request: Record<string, CanonicalValue> = {
      schema: "keep.patch-input-capture", version: 1n, root, sourceKind: kind, sourcePath: "source",
      overlayPath: "overlay.cbor", overlayByteDigest: sha(overlay), carrierPath: "carrier.cbor", carrierByteDigest: sha(carrier),
      ...(kind === "directory" ? { expectedSourceRowDigest: rowDigest(rows), declaredBaseArchiveDigest: base } : { sourceStreamDigest: base }),
    };
    return { root, request, rows, overlay, carrier };
  } catch (error) {
    rmSync(root, { recursive: true });
    throw error;
  }
}
function withCaptureFixture(kind: "directory" | "tar" | "tar-gzip", body: (fixture: CaptureFixture) => void): void {
  const fixture = createCaptureFixture(kind);
  try { body(fixture); } finally { rmSync(fixture.root, { recursive: true }); }
}
function decodedFrames(output: Buffer): { start: number; value: Record<string, CanonicalValue> }[] {
  const result: { start: number; value: Record<string, CanonicalValue> }[] = [];
  for (let at = 0; at < output.length;) {
    const start = at;
    assert.ok(at + 4 <= output.length);
    const length = output.readUInt32BE(at); at += 4;
    assert.ok(length > 0 && length <= 65_536 && at + length <= output.length);
    const value = decodeCanonical(output.subarray(at, at + length));
    assert.ok(value && typeof value === "object" && !Array.isArray(value) && !(value instanceof Uint8Array));
    result.push({ start, value: { ...value as Record<string, CanonicalValue> } });
    at += length;
  }
  return result;
}

test("framed capture joins all three real source routes and emits exact independently checked records", () => {
  for (const kind of ["directory", "tar", "tar-gzip"] as const) withCaptureFixture(kind, fixture => {
    const requestBytes = encodeCanonical(fixture.request);
    const result = invokeCapture(frame(requestBytes));
    assert.equal(result.status, 0, result.stderr.toString());
    assert.equal(result.stderr.length, 0);
    const frames = decodedFrames(result.stdout);
    const requestDigest = createHash("sha256").update("keep.patch-input-request/v1\0").update(requestBytes).digest("hex");
    assert.deepEqual(frames[0]!.value, {
      record: "header", schema: "keep.patch-input-result", version: 1n, requestDigest,
      sourceKind: kind, sourceRowDigest: rowDigest(fixture.rows),
      sourceCount: BigInt(fixture.rows.length), sourceBytes: BigInt(fixture.rows.reduce((n, row) => n + row.bytes.length, 0)),
      overlayBytes: BigInt(fixture.overlay.length), carrierBytes: BigInt(fixture.carrier.length),
      overlayTypedDigest: captureNativePatchOverlayV1(Uint8Array.from(fixture.overlay)).patchOverlayDigest,
      carrierTypedDigest: captureNativePatchByteCarrierSetV1(Uint8Array.from(fixture.carrier)).patchByteCarrierSetDigest,
      overlayByteDigest: sha(fixture.overlay), carrierByteDigest: sha(fixture.carrier),
      ...(kind === "directory" ? { declaredBaseArchiveDigest: fixture.request.declaredBaseArchiveDigest } : { sourceStreamDigest: fixture.request.sourceStreamDigest }),
    });
    let at = 1;
    function chunks(bytes: Buffer): void {
      for (let offset = 0, sequence = 0; offset < bytes.length; offset += 32768, sequence++) {
        const value = frames[at++]!.value;
        assert.deepEqual(Object.keys(value).sort(), ["bytes", "record", "sequence"]);
        assert.equal(value.record, "chunk"); assert.equal(value.sequence, BigInt(sequence));
        assert.ok(value.bytes instanceof Uint8Array);
        assert.deepEqual(Buffer.from(value.bytes), bytes.subarray(offset, offset + 32768));
      }
    }
    fixture.rows.forEach((row, index) => {
      assert.deepEqual(frames[at++]!.value, { record: "source-row", index: BigInt(index), path: row.path, mode: BigInt(row.mode), byteLength: BigInt(row.bytes.length), byteDigest: sha(row.bytes) });
      chunks(row.bytes);
    });
    for (const [role, bytes] of [["overlay", fixture.overlay], ["carrier", fixture.carrier]] as const) {
      assert.deepEqual(frames[at++]!.value, { record: "input", role, byteLength: BigInt(bytes.length), byteDigest: sha(bytes) });
      chunks(bytes);
    }
    assert.equal(at, frames.length - 1);
    const last = frames[at]!;
    assert.deepEqual(last.value, { record: "end", responseDigest: createHash("sha256").update("keep.patch-input-response/v1\0").update(result.stdout.subarray(0, last.start)).digest("hex") });
  });
});

test("framed capture denies malformed envelopes and aliases before emitting data", () => {
  withCaptureFixture("directory", fixture => {
    const valid = frame(encodeCanonical(fixture.request));
    const oversized = Buffer.alloc(4); oversized.writeUInt32BE(65537);
    for (const [input, code] of [[Buffer.alloc(0), "MALFORMED"], [Buffer.alloc(4), "MALFORMED"], [oversized, "LIMIT"], [valid.subarray(0, valid.length - 1), "MALFORMED"], [Buffer.concat([valid, Buffer.from([0])]), "MALFORMED"], [Buffer.concat([valid, valid]), "MALFORMED"]] as const) {
      const result = invokeCapture(input);
      assert.equal(result.status, 2); assert.equal(result.stdout.length, 0); assert.equal(result.stderr.toString(), `${code}\n`);
    }
    for (const [change, code] of [
      [{ extra: true }, "MALFORMED"], [{ version: 2n }, "MALFORMED"], [{ sourceDigest: "a".repeat(64) }, "MALFORMED"],
      [{ sourceStreamDigest: "a".repeat(64) }, "MALFORMED"], [{ sourcePath: "overlay.cbor" }, "PATH"],
      [{ overlayPath: "source/nested" }, "PATH"], [{ carrierPath: "OVERLAY.cbor" }, "PATH"],
      [{ overlayByteDigest: "0".repeat(64) }, "MALFORMED"],
    ] as const) {
      const result = invokeCapture(frame(encodeCanonical({ ...fixture.request, ...change })));
      assert.equal(result.status, 2); assert.equal(result.stdout.length, 0); assert.equal(result.stderr.toString(), `${code}\n`);
    }
    // Argument refusal precedes reading stdin. Do not race a needless payload
    // write against that early exit (spawnSync can report EPIPE instead).
    const result = invokeCapture(Buffer.alloc(0), ["--unlisted"]);
    assert.equal(result.status, 2); assert.equal(result.stdout.length, 0); assert.equal(result.stderr.toString(), "MALFORMED\n");
  });
});

test("framed capture emits no success bytes for raw, typed-join or source commitment mismatches", () => {
  withCaptureFixture("directory", fixture => {
    for (const change of [{ overlayByteDigest: "a".repeat(64) }, { carrierByteDigest: "a".repeat(64) }, { declaredBaseArchiveDigest: "a".repeat(64) }, { expectedSourceRowDigest: "a".repeat(64) }]) {
      const result = invokeCapture(frame(encodeCanonical({ ...fixture.request, ...change })));
      assert.equal(result.status, 2); assert.equal(result.stdout.length, 0); assert.equal(result.stderr.toString(), "INTEGRITY\n");
    }
    const mismatched = Buffer.from(encodeCanonical({ schema: "keep.p2-d2-patch-byte-carrier-set", version: 1n, packageId: "curve25519-dalek@5.0.0", entries: [{ path: "a", operation: "replace", bytes: Uint8Array.from(Buffer.from("different")) }] }));
    writeFileSync(join(fixture.root, "carrier.cbor"), mismatched);
    const result = invokeCapture(frame(encodeCanonical({ ...fixture.request, carrierByteDigest: sha(mismatched) })));
    assert.equal(result.status, 2); assert.equal(result.stdout.length, 0); assert.equal(result.stderr.toString(), "INTEGRITY\n", "valid raw carrier hash must not bypass the typed overlay join");
  });
});

test("framed capture operates as an unprivileged child without changing source permissions", () => {
  withCaptureFixture("directory", fixture => {
    // The out-of-tree build directory can be root-private. Copy the exact built
    // executable into this synthetic fixture; this is not package qualification.
    const binary = join(fixture.root, "capture-helper");
    copyFileSync(captureBinary, binary); chmodSync(binary, 0o555);
    chmodSync(fixture.root, 0o755);
    const input = frame(encodeCanonical(fixture.request));
    const result = spawnSync(binary, [], {
      input, maxBuffer: 2 * 1024 * 1024, timeout: 30_000, killSignal: "SIGKILL", env: {}, cwd: "/",
      ...(process.getuid?.() === 0 ? { uid: 65534, gid: 65534 } : {}),
    });
    assert.ifError(result.error); assert.equal(result.status, 0, result.stderr.toString());
    assert.equal(result.stderr.length, 0);
    assert.equal(decodedFrames(result.stdout)[0]!.value.sourceRowDigest, rowDigest(fixture.rows));
  });
});

type CaptureSdk = typeof import("../src/platform/native_patch_capture.js");
// Deploy the actual compiled receiver and its existing pure imports in an isolated
// package-shaped fixture. This is receiver integration, NOT npm/tarball qualification.
async function sdkFixture(root: string, executable: Buffer = readFileSync(captureBinary)) {
  const deployed = join(root, "sdk");
  for (const relative of ["platform/native_patch_capture.js", "platform/native_p2_path.js", "eir/canonical.js", "policy/json.js"]) {
    const target = join(deployed, "src", relative); mkdirSync(dirname(target), { recursive: true });
    copyFileSync(fileURLToPath(new URL(`../src/${relative}`, import.meta.url)), target);
  }
  writeFileSync(join(deployed, "package.json"), '{"type":"module"}');
  const native = join(deployed, "native", "linux-x64"); mkdirSync(native, { recursive: true });
  const artifact = join(native, "keep-native-patch-capture");
  writeFileSync(artifact, executable); chmodSync(artifact, 0o755);
  const manifest = {
    schema: "keep.patch-capture-package/v1", target: "x86_64-unknown-linux-musl", platform: "linux", architecture: "x64",
    profile: "keep.patch-input-capture/v1", artifacts: [{ name: "keep-native-patch-capture", bytes: executable.length, sha256: sha(executable), mode: 0o755 }],
  };
  const manifestPath = join(native, "capture-manifest.json");
  writeFileSync(manifestPath, JSON.stringify(manifest)); chmodSync(manifestPath, 0o644);
  return { sdk: await import(pathToFileURL(join(deployed, "src/platform/native_patch_capture.js")).href) as CaptureSdk, artifact, manifest, manifestPath };
}
function codeIs(code: string): (error: unknown) => boolean {
  return error => !!error && typeof error === "object" && "code" in error && error.code === code;
}
function responseBytes(rows: readonly Record<string, CanonicalValue>[]): Buffer {
  const preceding = Buffer.concat(rows.filter(row => row.record !== "end").map(row => frame(encodeCanonical(row))));
  const responseDigest = createHash("sha256").update("keep.patch-input-response/v1\0", "ascii").update(preceding).digest("hex");
  return Buffer.concat([preceding, frame(encodeCanonical({ record: "end", responseDigest }))]);
}
function emitter(root: string, extra = ""): Buffer {
  // Explicit protocol adversary, never a product test mode or positive native proof.
  // Uses only the existing Node executable and synthetic files in this fixture.
  return Buffer.from(`#!${process.execPath}\nimport('node:fs').then(fs => {
fs.writeFileSync(${JSON.stringify(join(root, "emitter.pid"))}, String(process.pid));
process.stdin.resume(); process.stdin.on('end', () => {
  const bytes = fs.readFileSync(${JSON.stringify(join(root, "response.bin"))});
  let offset = 0; const emit = () => {
    if (offset === bytes.length) { ${extra} return; }
    const next = Math.min(bytes.length, offset + (offset < 12 ? 1 : 7919));
    const ready = process.stdout.write(bytes.subarray(offset, next)); offset = next;
    if (ready) setImmediate(emit); else process.stdout.once('drain', emit);
  }; emit();
}); });\n`);
}

test("capture SDK returns exact immutable owned data from all three actual native routes", async () => {
  for (const kind of ["directory", "tar", "tar-gzip"] as const) {
    const fixture = createCaptureFixture(kind);
    try {
      const { sdk } = await sdkFixture(fixture.root);
      const pending = sdk.capturePackagedNativePatchInputsV1(fixture.request);
      fixture.request.root = "/changed-after-call"; // Must not change the captured request.
      const result = await pending;
      assert.equal(result.sourceKind, kind); assert.equal(result.sourceRowDigest, rowDigest(fixture.rows));
      assert.equal(result.files.length, fixture.rows.length);
      assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.files));
      for (const [index, file] of result.files.entries()) {
        assert.ok(Object.isFrozen(file)); assert.equal(file.path, fixture.rows[index]!.path);
        assert.equal(file.mode, fixture.rows[index]!.mode); assert.equal(file.byteDigest, sha(fixture.rows[index]!.bytes));
        const copy = file.bytes(); assert.deepEqual(Buffer.from(copy), fixture.rows[index]!.bytes);
        copy.fill(42); assert.deepEqual(Buffer.from(file.bytes()), fixture.rows[index]!.bytes);
      }
      for (const [read, expected] of [[() => result.overlayBytes(), fixture.overlay], [() => result.carrierBytes(), fixture.carrier]] as const) {
        const copy = read(); assert.deepEqual(Buffer.from(copy), expected); copy.fill(0); assert.deepEqual(Buffer.from(read()), expected);
      }
      for (const flag of ["filesystem", "signature", "build", "install", "launch"] as const) assert.equal(result[flag], false);
      assert.equal(Object.hasOwn(result, "sourceStreamDigest"), kind !== "directory");
      assert.equal(Object.hasOwn(result, "declaredBaseArchiveDigest"), kind === "directory");
      assert.equal(result.overlayTypedDigest, captureNativePatchOverlayV1(fixture.overlay).patchOverlayDigest);
      assert.equal(result.carrierTypedDigest, captureNativePatchByteCarrierSetV1(fixture.carrier).patchByteCarrierSetDigest);
    } finally { rmSync(fixture.root, { recursive: true }); }
  }
});

test("capture SDK refuses inert-shape/path/options violations before touching the package", async () => {
  const fixture = createCaptureFixture("directory");
  try {
    const { sdk, manifestPath } = await sdkFixture(fixture.root);
    rmSync(manifestPath); // Any accidental acquisition would produce IO, not the expected admission error.
    let getterCalls = 0;
    const accessor = { ...fixture.request }; Object.defineProperty(accessor, "root", { enumerable: true, get: () => { getterCalls++; return fixture.root; } });
    for (const request of [accessor, new Proxy(fixture.request, {}), { ...fixture.request, extra: true }, { ...fixture.request, version: 1 }, { ...fixture.request, sourceStreamDigest: "1".repeat(64) }, { ...fixture.request, overlayByteDigest: "0".repeat(64) }])
      await assert.rejects(sdk.capturePackagedNativePatchInputsV1(request), codeIs("MALFORMED"));
    assert.equal(getterCalls, 0);
    for (const patch of [{ root: "/" }, { sourcePath: "../escape" }, { sourcePath: "source/" }, { overlayPath: "source/inside" }, { sourcePath: "OVERLAY.CBOR" }, { carrierPath: "overlay.cbor/nested" }])
      await assert.rejects(sdk.capturePackagedNativePatchInputsV1({ ...fixture.request, ...patch }), codeIs("PATH"));
    for (const options of [{ timeoutMs: 0 }, { timeoutMs: 60_001 }, { timeoutMs: NaN }, { timeoutMs: undefined }, { signal: {} }, { executable: captureBinary }])
      await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request, options as never), codeIs("MALFORMED"));
    const controller = new AbortController(); controller.abort();
    await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request, { signal: controller.signal }), codeIs("CANCELLED"));
  } finally { rmSync(fixture.root, { recursive: true }); }
});

test("capture SDK verifies manifest uniqueness, fixed artifact identity, mode and symlink refusal", async () => {
  const fixture = createCaptureFixture("directory");
  try {
    const { sdk, artifact, manifest, manifestPath } = await sdkFixture(fixture.root);
    const replaceManifest = (text: string): void => {
      writeFileSync(manifestPath, text);
    };
    for (const patch of [{ profile: "wrong" }, { artifacts: [...manifest.artifacts, ...manifest.artifacts] }, { artifacts: [{ ...manifest.artifacts[0], name: "other" }] }]) {
      replaceManifest(JSON.stringify({ ...manifest, ...patch }));
      await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request), codeIs("MALFORMED"));
    }
    replaceManifest(JSON.stringify(manifest).replace('{"schema":', '{"schema":"duplicate","schema":'));
    await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request), codeIs("MALFORMED"));
    replaceManifest(" ".repeat(16_385));
    await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request), codeIs("LIMIT"));
    replaceManifest(JSON.stringify({ ...manifest, artifacts: [{ ...manifest.artifacts[0], bytes: 64 * 1024 * 1024 + 1 }] }));
    await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request), codeIs("LIMIT"));
    replaceManifest(JSON.stringify({ ...manifest, artifacts: [{ ...manifest.artifacts[0], sha256: "1".repeat(64) }] }));
    await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request), codeIs("INTEGRITY"));
    replaceManifest(JSON.stringify(manifest));
    for (const mode of [0o555, 0o775, 0o777, 0o4755]) {
      chmodSync(artifact, mode);
      await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request), codeIs("TYPE"));
    }
    rmSync(artifact); symlinkSync(captureBinary, artifact);
    await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request), codeIs("PATH"));
  } finally { rmSync(fixture.root, { recursive: true }); }
});

test("capture SDK rejects independently framed corruption and only accepts complete clean exchanges", async () => {
  const fixture = createCaptureFixture("directory");
  try {
    const result = invokeCapture(frame(encodeCanonical(fixture.request))); assert.equal(result.status, 0);
    const rows = decodedFrames(result.stdout).map(row => row.value);
    const responsePath = join(fixture.root, "response.bin");
    writeFileSync(responsePath, result.stdout);
    const { sdk } = await sdkFixture(fixture.root, emitter(fixture.root));
    const captured = await sdk.capturePackagedNativePatchInputsV1(fixture.request);
    assert.equal(captured.sourceRowDigest, rowDigest(fixture.rows), "arbitrarily fragmented framing must be accepted");
    const mutant = (index: number, patch: Record<string, CanonicalValue>): Buffer => responseBytes(rows.map((row, i) => i === index ? { ...row, ...patch } : row));
    const chunkIndex = rows.findIndex(row => row.record === "chunk");
    const inputIndex = rows.findIndex(row => row.record === "input");
    const variants: [string, Buffer, string?][] = [
      ["request hash", mutant(0, { requestDigest: "1".repeat(64) })],
      ["unknown header field", mutant(0, { unexpected: true })],
      ["wrong kind-specific field", mutant(0, { sourceStreamDigest: "1".repeat(64) })],
      ["typed/raw domain confusion", mutant(0, { overlayTypedDigest: fixture.request.overlayByteDigest! })],
      ["source commitment", mutant(0, { sourceRowDigest: "1".repeat(64) })],
      ["source count", mutant(0, { sourceCount: 4097n }), "LIMIT"],
      ["aggregate source bytes", mutant(0, { sourceBytes: 128n * 1024n * 1024n + 1n })],
      ["row index", mutant(1, { index: 1n })],
      ["special mode", mutant(1, { mode: 0o4644n })],
      ["per-file size", mutant(1, { byteLength: 16n * 1024n * 1024n + 1n })],
      ["path traversal", mutant(1, { path: "../outside" })],
      ["path one over", mutant(1, { path: "a".repeat(4097) }), "PATH"],
      ["component one over", mutant(1, { path: "a".repeat(256) }), "LIMIT"],
      ["depth one over", mutant(1, { path: Array(33).fill("a").join("/") }), "LIMIT"],
      ["chunk gap", mutant(chunkIndex, { sequence: 1n })],
      ["short chunk", mutant(chunkIndex, { bytes: new Uint8Array([1]) })],
      ["byte hash", mutant(chunkIndex, { bytes: new Uint8Array(32768) })],
      ["input order", mutant(inputIndex, { role: "carrier" })],
      ["extra END byte", Buffer.concat([result.stdout, Buffer.from([0])])],
      ["truncation", result.stdout.subarray(0, result.stdout.length - 1)],
      ["missing END", result.stdout.subarray(0, decodedFrames(result.stdout).at(-1)!.start)],
      ["frame bound", Buffer.from([0, 1, 0, 1])],
      ["zero frame", Buffer.alloc(4)],
    ];
    for (const [name, bytes, expectedCode] of variants) {
      writeFileSync(responsePath, bytes);
      await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request), error => {
        assert.ok(error instanceof sdk.NativePatchCaptureError, name);
        if (expectedCode !== undefined) assert.equal(error.code, expectedCode, name);
        return true;
      }, name);
    }
  } finally { rmSync(fixture.root, { recursive: true }); }
});

test("capture SDK withholds complete responses on nonzero exit, stderr, timeout and cancellation", async () => {
  for (const scenario of ["nonzero", "stderr", "timeout", "abort"] as const) {
    const fixture = createCaptureFixture("directory");
    try {
      const native = invokeCapture(frame(encodeCanonical(fixture.request))); assert.equal(native.status, 0);
      writeFileSync(join(fixture.root, "response.bin"), native.stdout);
      const extra = scenario === "nonzero" ? "process.exitCode = 2;" : scenario === "stderr" ? "process.stderr.write('unexpected');" : "setInterval(() => {}, 1000);";
      const { sdk } = await sdkFixture(fixture.root, emitter(fixture.root, extra));
      const controller = new AbortController();
      const promise = sdk.capturePackagedNativePatchInputsV1(fixture.request, { timeoutMs: scenario === "timeout" ? 500 : 5000, signal: controller.signal });
      // Attach rejection handling immediately, then cancel only this known fixture child.
      const checked = assert.rejects(promise, codeIs(scenario === "abort" || scenario === "timeout" ? "CANCELLED" : "IO"));
      if (scenario === "abort") {
        const deadline = performance.now() + 2000;
        while (!existsSync(join(fixture.root, "emitter.pid")) && performance.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
        assert.ok(existsSync(join(fixture.root, "emitter.pid"))); controller.abort();
      }
      await checked;
      const pid = Number(readFileSync(join(fixture.root, "emitter.pid"), "utf8"));
      assert.throws(() => process.kill(pid, 0), { code: "ESRCH" }, "rejection must follow child termination, not abandon it");
    } finally { rmSync(fixture.root, { recursive: true }); }
  }
});

test("capture SDK preserves real native refusal codes without returning any rows", async () => {
  const fixture = createCaptureFixture("directory");
  try {
    const { sdk } = await sdkFixture(fixture.root);
    await assert.rejects(sdk.capturePackagedNativePatchInputsV1({ ...fixture.request, expectedSourceRowDigest: "2".repeat(64) }), codeIs("INTEGRITY"));
    rmSync(join(fixture.root, "source", "a")); symlinkSync("/etc/passwd", join(fixture.root, "source", "a"));
    await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request), codeIs("PATH"));
  } finally { rmSync(fixture.root, { recursive: true }); }
});

test("capture SDK accepts only exact zero-output refusal codes, including an early closed stdin", async () => {
  for (const [stderr, expected] of [["PATH\n", "PATH"], ["PATH\nextra", "IO"], ["\u00d0ATH\n", "IO"], ["unknown\n", "IO"], ["X".repeat(4097), "LIMIT"]] as const) {
    const fixture = createCaptureFixture("directory");
    try {
      const script = Buffer.from(`#!${process.execPath}\nprocess.stderr.write(${JSON.stringify(stderr)}, () => process.exit(2));\n`);
      const { sdk } = await sdkFixture(fixture.root, script);
      await assert.rejects(sdk.capturePackagedNativePatchInputsV1(fixture.request), codeIs(expected));
    } finally { rmSync(fixture.root, { recursive: true }); }
  }
});

test("capture SDK survives actual offline npm pack/install without install scripts or mode repair", async () => {
  const fixture = createCaptureFixture("directory");
  try {
    await sdkFixture(fixture.root);
    const staged = join(fixture.root, "sdk");
    writeFileSync(join(staged, "package.json"), JSON.stringify({
      name: "keep-capture-receiver-fixture", version: "0.0.0", type: "module", private: true,
      files: ["src", "native"], exports: "./src/platform/native_patch_capture.js",
      // This npm version runs prepare even with --ignore-scripts during packing.
      // Source artifacts are already built here; only installation must be script-free.
      scripts: { install: "node -e 'process.exit(89)'" },
    }));
    const consumer = join(fixture.root, "consumer"); mkdirSync(consumer);
    writeFileSync(join(consumer, "package.json"), '{"name":"capture-consumer","version":"0.0.0","private":true,"type":"module"}');
    const userConfig = join(fixture.root, "user.npmrc"), globalConfig = join(fixture.root, "global.npmrc");
    writeFileSync(userConfig, ""); writeFileSync(globalConfig, "");
    const npm = (args: string[], cwd: string) => {
      const result = spawnSync("npm", [...args, "--offline", "--ignore-scripts", "--no-audit", "--no-fund", `--cache=${join(fixture.root, "npm-cache")}`, `--userconfig=${userConfig}`, `--globalconfig=${globalConfig}`], {
        cwd, env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LANG: "C", LC_ALL: "C" }, encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 30_000, killSignal: "SIGKILL",
      });
      assert.ifError(result.error); assert.equal(result.status, 0, result.stderr); return result.stdout;
    };
    const packed = JSON.parse(npm(["pack", "--json", `--pack-destination=${fixture.root}`], staged)) as { filename: string }[];
    assert.equal(packed.length, 1);
    const tarball = join(fixture.root, packed[0]!.filename);
    npm(["install", "--package-lock=false", tarball], consumer);
    const installed = join(consumer, "node_modules", "keep-capture-receiver-fixture");
    const artifact = join(installed, "native/linux-x64/keep-native-patch-capture");
    assert.equal(statSync(artifact).mode & 0o7777, 0o755);
    assert.equal(statSync(join(installed, "native/linux-x64/capture-manifest.json")).mode & 0o7777, 0o644);
    assert.equal(sha(readFileSync(artifact)), sha(readFileSync(captureBinary)));
    const sdk = await import(pathToFileURL(join(installed, "src/platform/native_patch_capture.js")).href) as CaptureSdk;
    const result = await sdk.capturePackagedNativePatchInputsV1(fixture.request);
    assert.equal(result.sourceRowDigest, rowDigest(fixture.rows));
    assert.deepEqual(Buffer.from(result.files[0]!.bytes()), fixture.rows[0]!.bytes);
    // This proves the real packaging/mode seam only. The complete Keep package,
    // root export and paired C01-C11 installed journeys remain separate evidence.
  } finally { rmSync(fixture.root, { recursive: true }); }
});

test("capture SDK admits the composed 128MiB source plus 128MiB carrier at the default deadline", async t => {
  const root = mkdtempSync(join(tmpdir(), "keep-capture-maximum-"));
  try {
    const source = join(root, "source"); mkdirSync(source);
    const before = Buffer.alloc(16 * 1024 * 1024, 0x31), after = Buffer.alloc(before.length, 0x32);
    const beforeDigest = sha(before), afterDigest = sha(after);
    const rows: Row[] = Array.from({ length: 8 }, (_, index) => ({ path: `file${index}`, mode: 0o644, bytes: before }));
    for (const row of rows) { writeFileSync(join(source, row.path), row.bytes); chmodSync(join(source, row.path), row.mode); }
    const overlay = Buffer.from(encodeCanonical({
      schema: "keep.p2-d2-patch-overlay", version: 1n, packageId: "curve25519-dalek@5.0.0", baseArchiveDigest: "1".repeat(64),
      operations: rows.map(row => ({ operation: "replace", path: row.path, oldByteDigest: beforeDigest, newByteDigest: afterDigest, newByteLength: BigInt(after.length) })),
      rationale: "full composed source and carrier bound", resultTreeDigest: "2".repeat(64), auditPlanDigest: "3".repeat(64),
    }));
    writeFileSync(join(root, "overlay.cbor"), overlay);
    // Stream the fixed-schema fixture; don't make the legacy JS encoder allocate
    // a giant number array just to manufacture the input for this separate API.
    const fd = openSync(join(root, "carrier.cbor"), "wx", 0o644);
    const carrierHash = createHash("sha256");
    const write = (bytes: Uint8Array): void => {
      let offset = 0;
      while (offset < bytes.length) { const written = writeSync(fd, bytes, offset); assert.ok(written > 0); offset += written; }
      carrierHash.update(bytes);
    };
    const scalar = (value: CanonicalValue): void => write(encodeCanonical(value));
    try {
      write(Buffer.from([0xa4])); scalar("schema"); scalar("keep.p2-d2-patch-byte-carrier-set");
      scalar("entries"); write(Buffer.from([0x88]));
      for (const row of rows) {
        write(Buffer.from([0xa3])); scalar("path"); scalar(row.path); scalar("bytes");
        write(Buffer.from([0x5a, 0x01, 0, 0, 0])); write(after); // bytestring length 16MiB
        scalar("operation"); scalar("replace");
      }
      scalar("version"); scalar(1n); scalar("packageId"); scalar("curve25519-dalek@5.0.0");
    } finally { closeSync(fd); }
    const expectedCarrierDigest = carrierHash.digest("hex");
    const emptyCarrier = encodeCanonical({ schema: "keep.p2-d2-patch-byte-carrier-set", version: 1n, packageId: "curve25519-dalek@5.0.0", entries: rows.map(row => ({ path: row.path, operation: "replace", bytes: new Uint8Array() })) });
    // A 16MiB byte-string length takes five bytes, versus one for the empty string.
    assert.equal(statSync(join(root, "carrier.cbor")).size, 128 * 1024 * 1024 + emptyCarrier.length + 8 * 4);
    const { sdk } = await sdkFixture(root);
    const start = performance.now();
    const result = await sdk.capturePackagedNativePatchInputsV1({
      schema: "keep.patch-input-capture", version: 1n, root, sourceKind: "directory", sourcePath: "source",
      expectedSourceRowDigest: rowDigest(rows), declaredBaseArchiveDigest: "1".repeat(64),
      overlayPath: "overlay.cbor", overlayByteDigest: sha(overlay), carrierPath: "carrier.cbor", carrierByteDigest: expectedCarrierDigest,
    }); // No timeout override: prove the default, not only the 60s escape ceiling.
    const captureMs = performance.now() - start;
    assert.equal(result.sourceBytes, 128 * 1024 * 1024); assert.equal(result.files.length, 8);
    for (const file of result.files) { assert.equal(file.byteLength, before.length); assert.equal(sha(file.bytes()), beforeDigest); }
    assert.equal(sha(result.carrierBytes()), expectedCarrierDigest);
    const cgroup = readFileSync("/proc/self/cgroup", "utf8").split("\n").find(line => line.startsWith("0::"))?.slice(3);
    // Read only our own scope; never inspect the protected project's cgroup/processes.
    const peakPath = cgroup && /^\/[A-Za-z0-9_.\/-]+$/.test(cgroup) && !cgroup.split("/").includes("..") ? `/sys/fs/cgroup${cgroup}/memory.peak` : undefined;
    const peakBytes = peakPath && existsSync(peakPath) ? Number(readFileSync(peakPath, "utf8").trim()) : null;
    t.diagnostic(JSON.stringify({ sourceBytes: result.sourceBytes, carrierPayloadBytes: 128 * 1024 * 1024, captureMs, cgroupPeakBytes: peakBytes, defaultTimeoutMs: 30_000 }));
    assert.ok(captureMs < 30_000);
    if (peakBytes !== null) assert.ok(peakBytes <= 2 * 1024 * 1024 * 1024, "composed scope memory bound");
  } finally { rmSync(root, { recursive: true }); }
});

test("capture build gate still refuses an extra unsafe site and an undeclared auto-discovered target", () => {
  const root = mkdtempSync(join(tmpdir(), "keep-capture-gate-"));
  try {
    mkdirSync(join(root, "tools"));
    copyFileSync(join(captureSourceRoot, "tools/native_toolchain_inventory.mjs"), join(root, "tools/native_toolchain_inventory.mjs"));
    copyFileSync(join(captureSourceRoot, "rust-toolchain.toml"), join(root, "rust-toolchain.toml"));
    const native = join(captureSourceRoot, "native");
    cpSync(native, join(root, "native"), { recursive: true, filter: path => !["target", "vendor-p2", "p2-crypto-candidate"].some(name => path === join(native, name) || path.startsWith(`${join(native, name)}/`)) });
    const run = () => spawnSync(process.execPath, [join(captureSourceRoot, "tools/native_p1_gate.mjs"), root], {
      cwd: root, env: { PATH: process.env.PATH ?? "/usr/bin:/bin", ...(process.env.KEEP_P1_TOOLCHAIN_ROOT ? { KEEP_P1_TOOLCHAIN_ROOT: process.env.KEEP_P1_TOOLCHAIN_ROOT } : {}) },
      encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 30_000, killSignal: "SIGKILL",
    });
    const abi = join(root, "native/crates/linux-abi/src/lib.rs"), original = readFileSync(abi, "utf8");
    writeFileSync(abi, `${original}\n// SAFETY: deliberate inventory mutant, never compiled or executed.\nfn extra_site() { unsafe {} }\n`);
    const unsafeResult = run(); assert.ifError(unsafeResult.error); assert.notEqual(unsafeResult.status, 0);
    assert.match(unsafeResult.stderr, /exact fifty-six documented/);
    writeFileSync(abi, original);
    writeFileSync(join(root, "native/crates/p2-d2-supervisor/src/bin/undeclared-capture-target.rs"), "#![forbid(unsafe_code)]\nfn main() {}\n");
    const targetResult = run(); assert.ifError(targetResult.error); assert.notEqual(targetResult.status, 0);
    assert.match(targetResult.stderr, /metadata targets are not exact/); assert.match(targetResult.stderr, /undeclared-capture-target/);
  } finally { rmSync(root, { recursive: true }); }
});
