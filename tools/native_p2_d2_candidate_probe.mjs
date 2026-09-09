#!/usr/bin/env node
/** Non-authorizing real-Cargo probe for carrier + overlay = patched result-root mechanics. */
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { captureAuthenticatedCrateArchive } from "./native_p2_archive_snapshot.mjs";
import { encodeCanonical } from "../dist/src/eir/canonical.js";
import { captureNativePatchOverlayV1 } from "../dist/src/platform/native_p2_d2_overlay.js";
import {
  captureNativePatchByteCarrierSetV1,
  joinValidatedPatchApplicationInputs,
} from "../dist/src/platform/native_p2_d2_carriers.js";
import { deriveNativeResultTreeCandidateV1 } from "../dist/src/platform/native_p2_d2_application.js";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

function regularFilePaths(root, relative = "") {
  const rows = [];
  for (const name of readdirSync(join(root, relative)).sort()) {
    const path = relative === "" ? name : `${relative}/${name}`;
    const stat = lstatSync(join(root, path));
    if (stat.isSymbolicLink()) throw new Error(`immutable input contains symlink: ${path}`);
    if (stat.isDirectory()) rows.push(...regularFilePaths(root, path));
    else if (stat.isFile()) rows.push(path);
    else throw new Error(`immutable input contains special node: ${path}`);
  }
  return rows;
}

function verifyExactFiles(root, expected, label) {
  const paths = regularFilePaths(root).sort();
  const expectedPaths = [...expected.keys()].sort();
  if (JSON.stringify(paths) !== JSON.stringify(expectedPaths))
    throw new Error(`${label} path inventory changed`);
  for (const path of paths) {
    const bytes = readFileSync(join(root, path));
    const row = expected.get(path);
    if (bytes.length !== row.size || sha(bytes) !== row.sha256)
      throw new Error(`${label} bytes changed: ${path}`);
  }
}

function vendorInventory() {
  const inventory = JSON.parse(readFileSync(join(repositoryRoot, "native/p2-crypto-vendor-inventory.json")));
  return new Map(inventory.entries.map((row) => [row.path, row]));
}

function toolchainInventory() {
  const inventory = JSON.parse(readFileSync(join(repositoryRoot, "native/toolchain-inventory.json")));
  return new Map(inventory.entries.map((row) => [row.path, row]));
}

function writeSnapshotManifest(scratch, name, expected) {
  const bytes = Buffer.from([...expected.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([path, row]) => `${row.sha256} ${row.size} ${path}\n`).join(""), "ascii");
  const path = join(scratch, `${name}.snapshot-manifest`);
  writeFileSync(path, bytes, { flag: "wx", mode: 0o400 });
  return { path, digest: sha(bytes) };
}
const BASE_DIGEST = "b5eed333089e2e1c1ac8c6c0398e5e2497b4c9926ca6d0365ed1e099afa5bc23";
const PACKAGE_ID = "curve25519-dalek@5.0.0";
const PREFIX = "curve25519-dalek-5.0.0/";
const toolchain = "1.97.1-x86_64-unknown-linux-gnu";
const rustupHome = "/root/.keep-build/rustup";
const toolchainRoot = realpathSync(join(rustupHome, "toolchains", toolchain));
const cargo = join(toolchainRoot, "bin/cargo");
const buildCell = join(repositoryRoot, "native/target/x86_64-unknown-linux-musl/release/keep-native-p2-d2-build-cell");
const nativeSupervisor = join(repositoryRoot, "native/target/x86_64-unknown-linux-musl/release/keep-native-p2-d2-supervisor");
const bwrap = "/usr/bin/bwrap";
const BWRAP_DIGEST = "52231e1caf55bcbc667b269f49c63599a6f7db4767ae6a039580d0ff853db712";
const systemdRun = "/usr/bin/systemd-run";
const SYSTEMD_RUN_DIGEST = "dbc8b988a849d5c9d7ef2de7068a6f107021bc6c11e0d7864c73f373eef726a7";
const TOOLCHAIN_INVENTORY_DIGEST = "ba2e351f3f279a4cbc17cba1e3f74ba9b185275c5802c575e81c630c7cd57dc0";

function capturedArchive() {
  const capture = captureAuthenticatedCrateArchive(
    join(repositoryRoot, "native/p2-crypto-crates/curve25519-dalek-5.0.0.crate"),
    BASE_DIGEST,
  );
  const paths = capture.list().toString("utf8").split("\n").filter((path) => path && !path.endsWith("/"))
    .map((path) => {
      if (!path.startsWith(PREFIX)) throw new Error(`P2-D2 probe archive prefix mismatch: ${path}`);
      return path.slice(PREFIX.length);
    })
    .sort((left, right) => Buffer.compare(Buffer.from(left, "ascii"), Buffer.from(right, "ascii")));
  return {
    packageId: PACKAGE_ID,
    baseArchiveDigest: BASE_DIGEST,
    files: paths.map((path) => ({
      path,
      bytes: new Uint8Array(capture.readMember(`${PREFIX}${path}`, 16 * 1024 * 1024 + 1)),
    })),
  };
}

function proposal(archive) {
  const manifest = archive.files.find((row) => row.path === "Cargo.toml");
  const buildScript = archive.files.find((row) => row.path === "build.rs");
  if (!manifest || !buildScript) throw new Error("P2-D2 probe base members are missing");
  let source = Buffer.from(manifest.bytes).toString("utf8");
  const buildDeclaration = 'build = "build.rs"\n';
  const buildDependency = '\n[build-dependencies.rustc_version]\nversion = "0.4.0"\n';
  if (source.split(buildDeclaration).length !== 2 || source.split(buildDependency).length !== 2)
    throw new Error("P2-D2 probe manifest transformation precondition changed");
  source = source.replace(buildDeclaration, "").replace(buildDependency, "\n");
  const manifestBytes = new Uint8Array(Buffer.from(source, "utf8"));
  const operations = [
    {
      operation: "replace", path: "Cargo.toml", oldByteDigest: sha(manifest.bytes),
      newByteDigest: sha(manifestBytes), newByteLength: BigInt(manifestBytes.byteLength),
    },
    {
      operation: "delete", path: "build.rs", oldByteDigest: sha(buildScript.bytes),
      newByteDigest: null, newByteLength: null,
    },
  ];
  const carrierValue = {
    schema: "keep.p2-d2-patch-byte-carrier-set", version: 1n, packageId: PACKAGE_ID,
    entries: [{ path: "Cargo.toml", operation: "replace", bytes: manifestBytes }],
  };
  const overlayValue = {
    schema: "keep.p2-d2-patch-overlay", version: 1n, packageId: PACKAGE_ID,
    baseArchiveDigest: BASE_DIGEST, operations,
    rationale: "remove custom-build source and manifest declaration; bind fiat/64 cfg in the final cell",
    resultTreeDigest: "3".repeat(64),
    // Probe-only sentinel: a real D2 overlay is not emitted until AuditPlanV1 and its off-host registry resolve.
    auditPlanDigest: "2".repeat(64),
  };
  const carrierBytes = encodeCanonical(carrierValue);
  const carrierSet = captureNativePatchByteCarrierSetV1(carrierBytes);
  const provisional = captureNativePatchOverlayV1(encodeCanonical(overlayValue));
  const result = deriveNativeResultTreeCandidateV1(
    joinValidatedPatchApplicationInputs(provisional, carrierSet),
    archive,
  );
  return { operations, carrierBytes, carrierSet, result };
}

function materialize(result, root) {
  mkdirSync(root, { recursive: false, mode: 0o700 });
  for (const row of result.files) {
    const target = join(root, row.path);
    mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    writeFileSync(target, result.fileBytes(row.path), { flag: "wx", mode: 0o400 });
  }
  const checksumValue = {
    files: Object.fromEntries(result.files.map((row) => [row.path, row.byteDigest])),
    package: null,
  };
  const checksumBytes = Buffer.from(`${JSON.stringify(checksumValue)}\n`, "utf8");
  writeFileSync(join(root, ".cargo-checksum.json"), checksumBytes, { flag: "wx", mode: 0o400 });
  const directories = new Set([root]);
  for (const row of result.files) {
    let current = dirname(join(root, row.path));
    while (current.startsWith(`${root}/`)) { directories.add(current); current = dirname(current); }
  }
  for (const directory of [...directories].sort((left, right) => right.length - left.length)) chmodSync(directory, 0o500);
  return checksumBytes;
}

function writeCandidateWorkspace(root, resultRoot, vendorRoot) {
  mkdirSync(root, { mode: 0o700 });
  mkdirSync(join(root, "src"), { mode: 0o700 });
  mkdirSync(join(root, ".cargo"), { mode: 0o700 });
  for (const relativePath of ["Cargo.toml", "Cargo.lock", "src/lib.rs"])
    writeFileSync(join(root, relativePath), readFileSync(join(repositoryRoot, "native/p2-crypto-candidate", relativePath)), { flag: "wx", mode: 0o600 });
  const config = `[build]\ntarget = "x86_64-unknown-linux-musl"\n\n[target.x86_64-unknown-linux-musl]\nlinker = "rust-lld"\n\n[net]\noffline = true\n\n[source.crates-io]\nreplace-with = "vendored-p2"\n\n[source.vendored-p2]\ndirectory = "${vendorRoot}"\n\n[patch.crates-io]\ncurve25519-dalek = { path = "${resultRoot}" }\n`;
  const bytes = Buffer.from(config, "utf8");
  writeFileSync(join(root, ".cargo/config.toml"), bytes, { flag: "wx", mode: 0o600 });
  return bytes;
}

function confinedRunner(scratch, workspace, resultRoot, snapshotManifests) {
  if (sha(readFileSync(bwrap)) !== BWRAP_DIGEST)
    throw new Error("P2-D2 probe bubblewrap identity changed");
  if (sha(readFileSync(systemdRun)) !== SYSTEMD_RUN_DIGEST)
    throw new Error("P2-D2 probe systemd-run identity changed");
  const cargoHome = join(workspace, ".cargo-home");
  const target = join(workspace, "target");
  const home = join(workspace, ".home");
  for (const directory of [cargoHome, target, home]) mkdirSync(directory, { mode: 0o700 });
  const capturedBuildCell = join(scratch, "captured-build-cell");
  const buildCellBytes = readFileSync(buildCell);
  writeFileSync(capturedBuildCell, buildCellBytes, { flag: "wx", mode: 0o500 });
  if (sha(readFileSync(capturedBuildCell)) !== sha(buildCellBytes))
    throw new Error("P2-D2 build-cell private capture changed");
  const capturedSupervisor = join(scratch, "captured-supervisor");
  const supervisorBytes = readFileSync(nativeSupervisor);
  writeFileSync(capturedSupervisor, supervisorBytes, { flag: "wx", mode: 0o500 });
  const supervisorDescriptor = openSync(capturedSupervisor, "r");
  const supervisorFdPath = `/proc/${process.pid}/fd/${supervisorDescriptor}`;
  if (sha(readFileSync(supervisorFdPath)) !== sha(supervisorBytes))
    throw new Error("P2-D2 supervisor private descriptor capture changed");
  let unitSequence = 0;
  const invoke = (operation, extra = []) => {
    unitSequence += 1;
    const unit = `keep-objective3-${process.pid}-${unitSequence}`;
    const restored = join(workspace, ".keep-snapshot-restored");
    if (operation === "probe-snapshot-race") {
      const helper = `
        const fs = require("node:fs");
        const ready = process.argv[1], ack = process.argv[2], target = process.argv[3];
        const cgroup = process.argv[4], restored = process.argv[5];
        const pause = () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
        for (let n = 0; n < 3000 && !fs.existsSync(ready); n++) pause();
        if (!fs.existsSync(ready)) process.exit(91);
        const original = fs.readFileSync(target);
        fs.chmodSync(target, 0o600); fs.writeFileSync(target, "transient hostile replacement\\n");
        fs.writeFileSync(ack, "mutated\\n", { flag: "wx", mode: 0o600 });
        while (fs.existsSync(cgroup)) pause();
        fs.writeFileSync(target, original); fs.chmodSync(target, 0o400);
        fs.writeFileSync(restored, "restored\\n", { flag: "wx", mode: 0o600 });
      `;
      spawn(process.execPath, ["-e", helper,
        join(workspace, ".keep-snapshot-ready"), join(workspace, ".keep-snapshot-mutated"),
        join(resultRoot, "Cargo.toml"), `/sys/fs/cgroup/system.slice/${unit}.service`, restored,
      ], { stdio: "ignore" });
    }
    const invocation = spawnSync(systemdRun, [
      "--quiet", "--wait", "--collect", "--pipe", `--unit=${unit}`,
      "--property=Delegate=yes", "--property=MemoryMax=2147483648", "--property=MemorySwapMax=0",
      "--property=TasksMax=256", "--property=CPUQuota=400%",
      "--property=RuntimeMaxSec=240", "--property=TimeoutStopSec=10",
      "--property=KillMode=mixed",
      "--property=LimitNOFILE=4096",
      `--property=IOReadBandwidthMax=${workspace} 268435456`,
      `--property=IOWriteBandwidthMax=${workspace} 268435456`,
      `--property=IOReadIOPSMax=${workspace} 4096`,
      `--property=IOWriteIOPSMax=${workspace} 4096`,
      supervisorFdPath, `${unit}.service`, workspace,
      toolchainRoot, snapshotManifests.toolchain.path, snapshotManifests.toolchain.digest,
      capturedBuildCell,
      join(repositoryRoot, "native/vendor-p2"), snapshotManifests.vendor.path, snapshotManifests.vendor.digest,
      resultRoot, snapshotManifests.result.path, snapshotManifests.result.digest,
      operation, ...extra,
    ], {
      cwd: scratch, env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", TZ: "UTC" },
      encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 300_000, killSignal: "SIGKILL",
    });
    const cgroup = `/sys/fs/cgroup/system.slice/${unit}.service`;
    if (existsSync(cgroup)) {
      for (const command of [["kill", "--kill-whom=all", unit], ["stop", unit], ["reset-failed", unit]])
        spawnSync("/usr/bin/systemctl", command, { encoding: "utf8", timeout: 15_000 });
    }
    if (existsSync(cgroup)) throw new Error(`P2-D2 transient cgroup was not collected: ${unit}`);
    if (operation === "probe-snapshot-race") {
      const pause = () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
      for (let n = 0; n < 1000 && !existsSync(restored); n++) pause();
      if (!existsSync(restored)) throw new Error("P2-D2 hostile mutation helper did not restore input");
    }
    return invocation;
  };
  const execute = (operation, receiptMode) => {
    const result = invoke(operation);
    if (result.error) throw result.error;
    if (result.signal || result.status !== 0)
      throw new Error(`P2-D2 confined process failed (${result.signal ?? result.status}): ${result.stderr}`);
    if (receiptMode !== undefined) {
      const prefix = `[keep-p2-d2-cell] mode=${receiptMode} landlockAbi=`;
      const markers = result.stderr.split("\n").filter((line) => line.startsWith(prefix));
      const match = markers[0]?.match(/ landlockAbi=([0-9]+) noNewPrivs=1 seccomp=2 capabilities=zero$/u);
      if (markers.length !== 1 || match === null || match === undefined || Number(match[1]) < 4)
        throw new Error(`P2-D2 confined activation receipt missing or ambiguous: ${result.stderr}`);
    }
    return result.stdout;
  };
  const refuse = (operation, extra, expected) => {
    const result = invoke(operation, extra);
    if (result.error) throw result.error;
    if (result.signal || result.status !== 125 || !result.stderr.includes(expected))
      throw new Error(`P2-D2 supervisor did not refuse ${operation}: ${result.stderr}`);
  };
  refuse("arbitrary-command", [], "operation is outside the closed supervisor set");
  refuse("check", ["--bind", "/", "/outside"], "extra supervisor arguments are forbidden");
  const hostNetworkNamespace = readlinkSync("/proc/self/ns/net");
  const sandboxNetworkNamespace = execute("probe-namespace").trim();
  if (sandboxNetworkNamespace === hostNetworkNamespace)
    throw new Error("P2-D2 probe did not enter a distinct network namespace");
  execute("probe-network", "probe-network");
  return {
    runCargo: (mode) => execute(mode, mode),
    runSnapshotRace: () => execute("probe-snapshot-race", "check"),
    sandboxNetworkNamespace,
    closeSupervisorCapture: () => {
      if (sha(readFileSync(supervisorFdPath)) !== sha(supervisorBytes))
        throw new Error("P2-D2 supervisor descriptor capture changed during execution");
      closeSync(supervisorDescriptor);
    },
  };
}

function verifyToolchainClosure() {
  const inventoryPath = join(repositoryRoot, "native/toolchain-inventory.json");
  if (sha(readFileSync(inventoryPath)) !== TOOLCHAIN_INVENTORY_DIGEST)
    throw new Error("P2-D2 probe toolchain inventory carrier changed");
  execFileSync(process.execPath, [join(repositoryRoot, "tools/native_toolchain_inventory.mjs")], {
    cwd: repositoryRoot, encoding: "utf8", maxBuffer: 1024 * 1024,
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", RUSTUP_HOME: rustupHome, KEEP_P1_TOOLCHAIN_ROOT: toolchainRoot },
  });
}

function main() {
  verifyToolchainClosure();
  const frozenToolchainInventory = toolchainInventory();
  const frozenVendorInventory = vendorInventory();
  verifyExactFiles(join(repositoryRoot, "native/vendor-p2"), frozenVendorInventory, "vendor closure");
  const archive = capturedArchive();
  const { operations, carrierBytes, carrierSet, result } = proposal(archive);
  const scratch = mkdtempSync(join(tmpdir(), "keep-p2-d2-candidate-probe-"));
  try {
    const resultRoot = join(scratch, "result-root");
    const workspace = join(scratch, "candidate");
    const checksumBytes = materialize(result, resultRoot);
    const frozenResultInventory = new Map(result.files.map((row) => [row.path, {
      size: Number(row.byteLength), sha256: row.byteDigest,
    }]));
    frozenResultInventory.set(".cargo-checksum.json", {
      size: checksumBytes.length, sha256: sha(checksumBytes),
    });
    verifyExactFiles(resultRoot, frozenResultInventory, "captured result root");
    const snapshotManifests = {
      toolchain: writeSnapshotManifest(scratch, "toolchain", frozenToolchainInventory),
      vendor: writeSnapshotManifest(scratch, "vendor", frozenVendorInventory),
      result: writeSnapshotManifest(scratch, "result", frozenResultInventory),
    };
    const configBytes = writeCandidateWorkspace(workspace, "/keep/result", "/keep/vendor");
    const { runCargo: run, runSnapshotRace, sandboxNetworkNamespace, closeSupervisorCapture } = confinedRunner(
      scratch, workspace, resultRoot, snapshotManifests,
    );
    const metadata = JSON.parse(run("metadata-unlocked"));
    const derivedLockBytes = readFileSync(join(workspace, "Cargo.lock"));
    const lockedMetadata = JSON.parse(run("metadata-locked"));
    if (JSON.stringify(metadata) !== JSON.stringify(lockedMetadata))
      throw new Error("P2-D2 derived locked metadata changed after capture");
    const curve = metadata.packages.filter((pkg) => pkg.name === "curve25519-dalek");
    if (curve.length !== 1 || curve[0].source !== null || curve[0].manifest_path !== "/keep/result/Cargo.toml")
      throw new Error("P2-D2 Cargo did not resolve the captured patch result root");
    if (metadata.packages.some((pkg) => pkg.name === "rustc_version" || pkg.name === "semver"))
      throw new Error("P2-D2 derived graph retained removed build dependencies");
    if (curve[0].targets.some((target) => target.kind.includes("custom-build")))
      throw new Error("P2-D2 derived curve package retained a custom-build target");
    const messages = run("check")
      .trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
    if (messages.some((row) => row.reason === "build-script-executed" ||
        (row.reason === "compiler-artifact" && row.target?.kind?.includes("custom-build"))))
      throw new Error("P2-D2 compiler executed a custom-build unit or build-script event");
    runSnapshotRace();
    verifyToolchainClosure();
    verifyExactFiles(join(repositoryRoot, "native/vendor-p2"), frozenVendorInventory, "vendor closure");
    verifyExactFiles(resultRoot, frozenResultInventory, "captured result root");
    closeSupervisorCapture();
    if (messages.some((row) => row.reason === "compiler-artifact" && row.target?.kind?.includes("proc-macro")))
      throw new Error("P2-D2 compiler executed a proc-macro unit");
    console.log(JSON.stringify({
      schema: "keep.p2-d2-candidate-probe-receipt", version: 1, authorizing: false,
      status: "confined-mechanics-only-audit-plan-and-authoritative-evidence-not-yet-resolved",
      baseArchiveDigest: BASE_DIGEST,
      operationCount: operations.length,
      patchByteCarrierSetDigest: carrierSet.patchByteCarrierSetDigest,
      resultTreeDigest: result.resultTreeDigest,
      resultFileCount: result.files.length,
      resultByteLength: result.files.reduce((sum, row) => sum + Number(row.byteLength), 0),
      cargoChecksumArtifactDigest: sha(Buffer.concat([Buffer.from("keep.p2-d2-cargo-checksum-artifact/v1\0", "ascii"), checksumBytes])),
      cargoPatchConfigDigest: sha(configBytes),
      derivedCargoLockDigest: sha(derivedLockBytes),
      curveManifestPath: "$CAPTURED_RESULT_ROOT/Cargo.toml",
      curveSource: null,
      removedPackages: ["rustc_version@0.4.1", "semver@1.0.28"],
      customBuildUnits: 0,
      procMacroUnits: 0,
      toolchainInventoryDigest: TOOLCHAIN_INVENTORY_DIGEST,
      nativeBuildCellDigest: sha(readFileSync(buildCell)),
      nativeSupervisorDigest: sha(readFileSync(nativeSupervisor)),
      sealedSnapshotManifestDigests: {
        toolchain: snapshotManifests.toolchain.digest,
        vendor: snapshotManifests.vendor.digest,
        result: snapshotManifests.result.digest,
      },
      sandbox: {
        mechanism: "bubblewrap-user-mount-pid-ipc-uts-cgroup-network-namespaces",
        executableDigest: BWRAP_DIGEST,
        systemdRunDigest: SYSTEMD_RUN_DIGEST,
        cgroup: {
          memoryMax: 2147483648, memorySwapMax: 0, pidsMax: 256, cpuMax: "400000 100000",
          ioReadBytesPerSecondMax: 268435456, ioWriteBytesPerSecondMax: 268435456,
          ioReadOperationsPerSecondMax: 4096, ioWriteOperationsPerSecondMax: 4096,
          openFileSoftAndHardMax: 4096,
        },
        capabilities: "all-five-sets-zero",
        nestedUserNamespaces: "disabled",
        networkNamespace: sandboxNetworkNamespace,
        networkRoutes: 0,
        immutableInputInventories: "authenticated-per-file-sealed-memfd-snapshot-plus-exact-before-and-after",
        hostileDescendantMutation: "transient-replacement-cannot-change-consumed-bytes",
        visibleInputs: ["read-only-system-runtime", "sealed-toolchain", "sealed-vendor-mirror", "sealed-result-root"],
        writableRoots: ["candidate-workspace", "private-tmpfs"],
      },
    }, null, 2));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

main();
