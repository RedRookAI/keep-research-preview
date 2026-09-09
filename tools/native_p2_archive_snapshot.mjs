#!/usr/bin/env node
/** Single-capture authenticated .crate reader for the non-authorizing P2 evidence gate. */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const TAR_PATH = "/usr/bin/tar";
const TAR_SHA256 = "3ee2c3c0b4dd9aacebfd2f0fbae44bad36348203acff78a44888dd58c05f811c";
const DEFAULT_MAX_ARCHIVE_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const HEX = /^[0-9a-f]{64}$/u;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function sameStat(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function verifyTarIdentity() {
  const status = lstatSync(TAR_PATH, { bigint: true });
  if (!status.isFile() || status.isSymbolicLink())
    throw new Error("P2 archive tool is not a no-follow regular file");
  const digest = sha256(readFileSync(TAR_PATH));
  if (digest !== TAR_SHA256)
    throw new Error(`P2 archive tool identity mismatch: ${digest}`);
}

export function captureAuthenticatedCrateArchive(
  archivePath,
  expectedSha256,
  { maxArchiveBytes = DEFAULT_MAX_ARCHIVE_BYTES } = {},
) {
  if (!HEX.test(expectedSha256) || /^0+$/u.test(expectedSha256))
    throw new Error("P2 expected archive digest is malformed");
  if (!Number.isSafeInteger(maxArchiveBytes) || maxArchiveBytes < 1)
    throw new Error("P2 archive byte bound is malformed");
  verifyTarIdentity();
  const descriptor = openSync(archivePath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
  let before;
  let carrier;
  try {
    before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.size < 1n || before.size > BigInt(maxArchiveBytes))
      throw new Error("P2 archive is not a bounded regular file");
    carrier = Buffer.from(readFileSync(descriptor));
    const after = fstatSync(descriptor, { bigint: true });
    if (!sameStat(before, after) || carrier.byteLength !== Number(before.size))
      throw new Error("P2 archive changed during its single capture");
  } finally {
    closeSync(descriptor);
  }
  const carrierDigest = sha256(carrier);
  if (carrierDigest !== expectedSha256)
    throw new Error("P2 authenticated crate archive checksum mismatch");

  const runTar = (args, { maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES } = {}) => {
    if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1)
      throw new Error("P2 tar output bound is malformed");
    if (sha256(carrier) !== carrierDigest)
      throw new Error("P2 private archive capture mutated before inspection");
    verifyTarIdentity();
    const result = spawnSync(TAR_PATH, args, {
      input: carrier,
      env: { LANG: "C", LC_ALL: "C", TZ: "UTC" },
      encoding: null,
      maxBuffer: maxOutputBytes,
      stdio: ["pipe", "pipe", "pipe"],
    });
    if (sha256(carrier) !== carrierDigest)
      throw new Error("P2 private archive capture mutated during inspection");
    if (result.error || result.signal !== null || result.status !== 0)
      throw new Error(`P2 archive tool failed closed: ${result.error?.message ?? result.signal ?? result.status}`);
    if ((result.stderr?.byteLength ?? 0) !== 0)
      throw new Error("P2 archive tool emitted a diagnostic");
    if (!Buffer.isBuffer(result.stdout) || result.stdout.byteLength > maxOutputBytes)
      throw new Error("P2 archive tool output violated its bound");
    return Buffer.from(result.stdout);
  };

  return Object.freeze({
    sha256: carrierDigest,
    byteLength: carrier.byteLength,
    list: () => runTar(["--gzip", "--list", "--file=-"]),
    listVerbose: () => runTar(["--gzip", "--list", "--verbose", "--file=-"]),
    readMember: (member, maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES) => {
      if (typeof member !== "string" || member.length < 1 || member.includes("\0"))
        throw new Error("P2 archive member operand is malformed");
      return runTar(
        ["--gzip", "--extract", "--to-stdout", "--file=-", "--", member],
        { maxOutputBytes },
      );
    },
  });
}

function selfTest() {
  const scratch = mkdtempSync(join(tmpdir(), "keep-p2-archive-snapshot-"));
  try {
    const firstRoot = join(scratch, "first");
    const secondRoot = join(scratch, "second");
    const mkdir = (path) => {
      const result = spawnSync("/usr/bin/mkdir", ["-p", path], { env: { LANG: "C", LC_ALL: "C" } });
      if (result.status !== 0) throw new Error("self-test mkdir failed");
    };
    mkdir(join(firstRoot, "sample-1.0.0"));
    mkdir(join(secondRoot, "sample-1.0.0"));
    writeFileSync(join(firstRoot, "sample-1.0.0/value"), "captured\n");
    writeFileSync(join(secondRoot, "sample-1.0.0/value"), "replacement\n");
    const firstArchive = join(scratch, "sample.crate");
    const secondArchive = join(scratch, "replacement.crate");
    for (const [root, archive] of [[firstRoot, firstArchive], [secondRoot, secondArchive]]) {
      const result = spawnSync(TAR_PATH, ["--create", "--gzip", "--file", archive, "sample-1.0.0"], {
        cwd: root,
        env: { LANG: "C", LC_ALL: "C", TZ: "UTC" },
      });
      if (result.status !== 0) throw new Error("self-test archive creation failed");
    }
    const firstBytes = readFileSync(firstArchive);
    const capture = captureAuthenticatedCrateArchive(firstArchive, sha256(firstBytes));
    renameSync(secondArchive, firstArchive);
    if (capture.readMember("sample-1.0.0/value").toString("utf8") !== "captured\n")
      throw new Error("pathname replacement changed captured member bytes");
    if (!capture.list().toString("utf8").includes("sample-1.0.0/value"))
      throw new Error("captured inventory lost its member");
    let refused = false;
    try {
      captureAuthenticatedCrateArchive(firstArchive, sha256(firstBytes));
    } catch {
      refused = true;
    }
    if (!refused) throw new Error("wrong post-replacement carrier digest was accepted");
    console.log("[native-p2-archive-snapshot] OK — single capture survives pathname replacement");
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1] && process.argv.includes("--self-test"))
  selfTest();
