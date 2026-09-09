#!/usr/bin/env node
/** Build the gated native workspace binaries and stage packaged transport peers. */
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { homedir, tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const nativeRoot = join(root, "native");
const lock = JSON.parse(readFileSync(join(nativeRoot, "toolchain-lock.json"), "utf8"));
const rustupHome = process.env.RUSTUP_HOME ?? join(homedir(), ".rustup");
const toolchainRoot = realpathSync(
  process.env.KEEP_P1_TOOLCHAIN_ROOT ?? join(rustupHome, "toolchains", lock.toolchain),
);
const cargo = join(toolchainRoot, "bin", "cargo");
const rustc = join(toolchainRoot, "bin", "rustc");
const rustdoc = join(toolchainRoot, "bin", "rustdoc");
const rustfmt = join(toolchainRoot, "bin", "rustfmt");
const rustLld = join(toolchainRoot, "lib/rustlib", lock.host, "bin/rust-lld");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

for (const [name, path, digest] of [
  ["cargo", cargo, lock.cargoSha256],
  ["rustc", rustc, lock.rustcSha256],
  ["rustdoc", rustdoc, lock.rustdocSha256],
  ["rustfmt", rustfmt, lock.rustfmtSha256],
  ["rust-lld", rustLld, lock.rustLldSha256],
]) {
  const status = lstatSync(path);
  if (!status.isFile() || status.isSymbolicLink() || realpathSync(path) !== path)
    throw new Error(`native transport build: ${name} is not a canonical regular file`);
  if (sha256(readFileSync(path)) !== digest)
    throw new Error(`native transport build: ${name} identity mismatch`);
}

const gateOutput = execFileSync(process.execPath, [join(root, "tools/native_p1_gate.mjs")], {
  cwd: root,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"],
  env: {
    PATH: "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C",
    RUSTUP_HOME: rustupHome,
    KEEP_P1_TOOLCHAIN_ROOT: toolchainRoot,
  },
});
process.stderr.write(gateOutput);

const cargoHome = mkdtempSync(join(tmpdir(), "keep-native-package-cargo-"));
try {
  execFileSync(
    cargo,
    [
      "build", "--release", "--locked", "--offline", "--frozen",
      "--target", lock.target, "-p", "keep-native-transport", "-p", "keep-native-p2-d2-supervisor", "-p", "keep-native-production-resolver", "--bins",
    ],
    {
      cwd: nativeRoot,
      stdio: "inherit",
      env: {
        PATH: `${join(toolchainRoot, "bin")}:${dirname(rustLld)}:/usr/bin:/bin`,
        LANG: "C",
        LC_ALL: "C",
        CARGO_HOME: cargoHome,
        CARGO_NET_OFFLINE: "true",
        CARGO_INCREMENTAL: "0",
        CARGO_BUILD_JOBS: "1",
        RUSTC: rustc,
        RUSTDOC: rustdoc,
        RUSTFMT: rustfmt,
        RUSTUP_HOME: rustupHome,
        RUSTUP_TOOLCHAIN: lock.toolchain,
        RUSTFLAGS: `--remap-path-prefix=${root}=/keep/source`,
        SOURCE_DATE_EPOCH: "0",
      },
    },
  );
} finally {
  rmSync(cargoHome, { recursive: true, force: true });
}

function assertStaticPieX64(bytes, name) {
  if (
    bytes.length < 64 || bytes[0] !== 0x7f || bytes[1] !== 0x45 ||
    bytes[2] !== 0x4c || bytes[3] !== 0x46 || bytes[4] !== 2 || bytes[5] !== 1
  ) throw new Error(`native transport build: ${name} is not ELF64 little-endian`);
  if (bytes.readUInt16LE(16) !== 3 || bytes.readUInt16LE(18) !== 62)
    throw new Error(`native transport build: ${name} is not x86-64 PIE`);
  const programOffset = Number(bytes.readBigUInt64LE(32));
  const programEntryBytes = bytes.readUInt16LE(54);
  const programEntries = bytes.readUInt16LE(56);
  if (programEntryBytes < 56 || programOffset + programEntryBytes * programEntries > bytes.length)
    throw new Error(`native transport build: ${name} program headers are malformed`);
  for (let index = 0; index < programEntries; index += 1)
    if (bytes.readUInt32LE(programOffset + index * programEntryBytes) === 3)
      throw new Error(`native transport build: ${name} has a dynamic interpreter`);
}

const output = join(root, "dist/native/linux-x64");
mkdirSync(output, { recursive: true, mode: 0o755 });
chmodSync(output, 0o755);
function stageOwnedArtifact(destination, bytes, mode) {
  if (existsSync(destination)) {
    const prior = lstatSync(destination);
    if (!prior.isFile() || prior.isSymbolicLink()) throw new Error(`native transport build: staged destination is not an owned regular file: ${basename(destination)}`);
  }
  const temporary = join(output, `.${basename(destination)}.${process.pid}.${randomUUID()}.tmp`);
  let fd;
  try {
    fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    fchmodSync(fd, mode);
    closeSync(fd); fd = undefined;
    renameSync(temporary, destination);
    const directory = openSync(output, constants.O_RDONLY);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } finally {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(temporary); } catch (error) { if (error?.code !== "ENOENT") throw error; }
  }
}
const artifacts = [];
for (const name of ["keep-native-client", "keep-native-supervisor", "keep-native-patch-capture"]) {
  const source = join(nativeRoot, "target", lock.target, "release", name);
  const status = lstatSync(source);
  if (!status.isFile() || status.isSymbolicLink())
    throw new Error(`native transport build: ${name} output is not a regular file`);
  const bytes = readFileSync(source);
  if (bytes.length === 0 || bytes.length > 64 * 1024 * 1024)
    throw new Error(`native transport build: ${name} exceeds the packaged executable bound`);
  assertStaticPieX64(bytes, name);
  const destination = join(output, name);
  // npm portable packing adds owner read/write. The capture manifest describes
  // exact installed modes; A6 retains its existing staging/manifest contract.
  const mode = name === "keep-native-patch-capture" ? 0o755 : 0o555;
  stageOwnedArtifact(destination, bytes, mode);
  artifacts.push({ name, bytes: bytes.length, sha256: sha256(bytes), mode });
}
if (new Set(artifacts.map(artifact => artifact.sha256)).size !== artifacts.length)
  throw new Error("native transport build: packaged executable artifacts alias");
stageOwnedArtifact(join(output, "keep-native-supervisor.sha256"), Buffer.from(`${artifacts[1].sha256}\n`, "ascii"), 0o444);
const manifest = {
  schema: "keep.native-transport-package/v1",
  target: lock.target,
  platform: "linux",
  architecture: "x64",
  protocolVersion: 2,
  channelMaxFrameBytes: 65536,
  artifacts: artifacts.slice(0, 2),
};
stageOwnedArtifact(join(output, "manifest.json"), Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8"), 0o444);
const captureManifest = {
  schema: "keep.patch-capture-package/v1",
  target: lock.target,
  platform: "linux",
  architecture: "x64",
  profile: "keep.patch-input-capture/v1",
  artifacts: [artifacts[2]],
};
stageOwnedArtifact(join(output, "capture-manifest.json"), Buffer.from(`${JSON.stringify(captureManifest, null, 2)}\n`, "utf8"), 0o644);
chmodSync(output, 0o555);
console.error(`[native-transport-package] staged ${artifacts.length} static PIE artifacts`);
