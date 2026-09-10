#!/usr/bin/env node
/** Freeze/verify the non-authorizing A6 P2 Ed25519 dependency and build closure. */
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { captureAuthenticatedCrateArchive } from "./native_p2_archive_snapshot.mjs";
import { orderCompilationUnits } from "./native_compilation_units.mjs";

const repositoryRoot = resolve(
  process.argv.find((arg, index) => index > 1 && !arg.startsWith("--")) ??
    fileURLToPath(new URL("..", import.meta.url)),
);
const candidate = join(repositoryRoot, "native/p2-crypto-candidate");
const vendor = realpathSync(join(repositoryRoot, "native/vendor-p2"));
const target = join(repositoryRoot, "native/p2-crypto-vendor-inventory.json");
const attributionTarget = join(repositoryRoot, "native/p2-crypto-THIRD_PARTY_LICENSES.txt");
const crateArchiveRoot = realpathSync(join(repositoryRoot, "native/p2-crypto-crates"));
const tarTool = realpathSync("/usr/bin/tar");
const collectorPath = realpathSync(fileURLToPath(import.meta.url));
const archiveSnapshotHelperPath = realpathSync(
  fileURLToPath(new URL("native_p2_archive_snapshot.mjs", import.meta.url)),
);
const write = process.argv.includes("--write");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

for (const key of Object.keys(process.env)) {
  if (
    key === "CARGO" ||
    key === "RUSTC" ||
    key === "RUSTDOC" ||
    key === "RUSTFLAGS" ||
    key === "RUSTC_WRAPPER" ||
    key === "RUSTC_WORKSPACE_WRAPPER" ||
    key === "CARGO_ENCODED_RUSTFLAGS" ||
    /^CARGO_TARGET_.*_(?:RUNNER|LINKER|RUSTFLAGS)$/.test(key)
  )
    throw new Error(`P2 ambient build injection variable refused: ${key}`);
}

function walkRegular(root, ignored = new Set()) {
  const files = [];
  const walk = (directory) => {
    for (const name of readdirSync(directory).sort()) {
      if (ignored.has(name)) continue;
      const path = join(directory, name);
      const status = lstatSync(path);
      if (status.isSymbolicLink()) throw new Error(`P2 symlink refused: ${path}`);
      if (status.isDirectory()) walk(path);
      else if (status.isFile()) files.push(path);
      else throw new Error(`P2 special file refused: ${path}`);
    }
  };
  walk(root);
  return files;
}
function inventory(root, paths) {
  return paths.map((path) => {
    const bytes = readFileSync(path);
    return { path: relative(root, path), size: bytes.byteLength, sha256: sha(bytes) };
  });
}

const entries = inventory(vendor, walkRegular(vendor));
const rootHash = createHash("sha256");
for (const row of entries)
  rootHash.update(`${row.path}\0${row.size}\0${row.sha256}\n`);
const candidateEntries = inventory(
  candidate,
  walkRegular(candidate, new Set(["target"])),
);
const manifests = entries
  .filter((row) => row.path.endsWith("Cargo.toml") && !row.path.includes("/tests/"))
  .map((row) => row.path);
const packages = manifests
  .map((path) => {
    const source = readFileSync(join(vendor, path), "utf8");
    const name = /^name = "([^"]+)"/m.exec(source)?.[1];
    const version = /^version = "([^"]+)"/m.exec(source)?.[1];
    const license = /^license = "([^"]+)"/m.exec(source)?.[1];
    if (!name || !version || !license)
      throw new Error(`P2 vendor package metadata incomplete: ${path}`);
    return { name, version, license };
  })
  .sort((a, b) => a.name.localeCompare(b.name));
const acceptedLicenseExpressions = new Set([
  "Apache-2.0 OR MIT",
  "BSD-3-Clause",
  "MIT OR Apache-2.0",
  "MIT OR Apache-2.0 OR BSD-1-Clause",
  "MIT/Apache-2.0",
  "(MIT OR Apache-2.0) AND Unicode-3.0",
]);
for (const pkg of packages)
  if (!acceptedLicenseExpressions.has(pkg.license))
    throw new Error(`P2 unreviewed license expression refused: ${pkg.name}`);
const presentBuildScripts = entries
  .filter((row) => /(^|\/)build\.rs$/.test(row.path))
  .map((row) => row.path);
const procMacros = manifests.filter((path) =>
  /^proc-macro = true$/m.test(readFileSync(join(vendor, path), "utf8")),
);
const unsafeFiles = entries
  .filter(
    (row) =>
      row.path.endsWith(".rs") &&
      /\bunsafe\b/.test(readFileSync(join(vendor, row.path), "utf8")),
  )
  .map((row) => ({
    path: row.path,
    sha256: row.sha256,
    occurrences: (readFileSync(join(vendor, row.path), "utf8").match(/\bunsafe\b/g) ?? [])
      .length,
    status: "candidate-pending-independent-semantic-audit",
  }));
const licenseFiles = entries.filter((row) =>
  /(^|\/)(?:LICENSE|COPYING|NOTICE)(?:[-_.].*)?$/i.test(row.path),
);
const packageIdentities = new Set();
const lockSource = readFileSync(join(candidate, "Cargo.lock"), "utf8");
const lockedPackages = new Map(
  lockSource
    .split("[[package]]")
    .slice(1)
    .map((block) => {
      const name = /^name = "([^"]+)"/m.exec(block)?.[1];
      const version = /^version = "([^"]+)"/m.exec(block)?.[1];
      const source = /^source = "([^"]+)"/m.exec(block)?.[1];
      const checksum = /^checksum = "([0-9a-f]{64})"/m.exec(block)?.[1];
      return name && version && source && checksum
        ? [`${name}@${version}`, { source, checksum }]
        : undefined;
    })
    .filter(Boolean),
);
if (lockedPackages.size !== packages.length)
  throw new Error("P2 Cargo.lock external package cardinality mismatch");
if (lockedPackages.size > 64)
  throw new Error("P2 crate archive cardinality exceeds frozen bound");
const expectedArchiveRows = [...lockedPackages.entries()]
  .map(([identity, locked]) => ({ identity, locked, path: `${identity.replace("@", "-")}.crate` }))
  .sort((left, right) => left.path.localeCompare(right.path));
const crateArchivePaths = walkRegular(crateArchiveRoot);
if (
  crateArchivePaths.length !== expectedArchiveRows.length ||
  crateArchivePaths.some((path, index) => relative(crateArchiveRoot, path) !== expectedArchiveRows[index].path)
)
  throw new Error("P2 crate archive directory is not the exact Cargo.lock carrier set");
const archiveCaptures = new Map();
const crateArchiveEntries = crateArchivePaths.map((path, index) => {
  const expected = expectedArchiveRows[index];
  if (!expected) throw new Error("P2 crate archive expectation is missing");
  const capture = captureAuthenticatedCrateArchive(path, expected.locked.checksum);
  archiveCaptures.set(expected.identity, capture);
  return { path: expected.path, size: capture.byteLength, sha256: capture.sha256 };
});
if (
  crateArchiveEntries.some((row) => row.size > 16 * 1024 * 1024) ||
  crateArchiveEntries.reduce((sum, row) => sum + row.size, 0) > 128 * 1024 * 1024
)
  throw new Error("P2 compressed crate archive bounds exceeded");
const crateArchiveRootHash = createHash("sha256");
for (const row of crateArchiveEntries)
  crateArchiveRootHash.update(`${row.path}\0${row.size}\0${row.sha256}\n`);
const archiveInventory = [];
const licensePolicy = packages.map((pkg) => {
  const identity = `${pkg.name}@${pkg.version}`;
  if (packageIdentities.has(identity))
    throw new Error(`P2 duplicate package identity refused: ${identity}`);
  packageIdentities.add(identity);
  const checksumRecord = JSON.parse(
    readFileSync(join(vendor, pkg.name, ".cargo-checksum.json"), "utf8"),
  );
  if (!/^[0-9a-f]{64}$/.test(checksumRecord.package ?? ""))
    throw new Error(`P2 package checksum missing: ${identity}`);
  const locked = lockedPackages.get(identity);
  if (
    !locked ||
    locked.source !== "registry+https://github.com/rust-lang/crates.io-index" ||
    locked.checksum !== checksumRecord.package
  )
    throw new Error(`P2 Cargo.lock/vendor checksum join failed: ${identity}`);
  const archivePath = join(crateArchiveRoot, `${pkg.name}-${pkg.version}.crate`);
  const archiveCapture = archiveCaptures.get(identity);
  if (!archiveCapture || archiveCapture.sha256 !== locked.checksum)
    throw new Error(`P2 authenticated crate archive capture missing: ${identity}`);
  const prefix = `${pkg.name}-${pkg.version}/`;
  const members = archiveCapture.list().toString("utf8")
    .split("\n")
    .filter(Boolean);
  if (new Set(members).size !== members.length)
    throw new Error(`P2 duplicate crate archive member refused: ${identity}`);
  if (members.length > 4096)
    throw new Error(`P2 crate archive member bound exceeded: ${identity}`);
  for (const member of members) {
    if (!member.startsWith(prefix))
      throw new Error(`P2 crate archive root mismatch: ${identity}:${member}`);
    const path = member.slice(prefix.length).replace(/\/$/, "");
    if (
      path !== "" &&
      (!/^[A-Za-z0-9._+@/-]+$/.test(path) ||
        path.split("/").some((part) => part === "" || part === "." || part === ".."))
    )
      throw new Error(`P2 hostile crate archive path refused: ${identity}:${path}`);
  }
  const verboseMembers = archiveCapture.listVerbose().toString("utf8")
    .split("\n")
    .filter(Boolean);
  if (
    verboseMembers.length !== members.length ||
    verboseMembers.some((line) => line[0] !== "-" && line[0] !== "d")
  )
    throw new Error(`P2 crate archive link/special member refused: ${identity}`);
  const archiveFiles = members
    .filter((member) => !member.endsWith("/"))
    .map((member) => {
      if (!member.startsWith(prefix))
        throw new Error(`P2 crate archive root mismatch: ${identity}:${member}`);
      const path = member.slice(prefix.length);
      if (
        !/^[A-Za-z0-9._+@/-]+$/.test(path) ||
        path.split("/").some((part) => part === "" || part === "." || part === "..")
      )
        throw new Error(`P2 hostile crate archive path refused: ${identity}:${path}`);
      const bytes = archiveCapture.readMember(member, 16 * 1024 * 1024 + 1);
      if (bytes.byteLength > 16 * 1024 * 1024)
        throw new Error(`P2 expanded crate member bound exceeded: ${identity}:${path}`);
      return { path, size: bytes.byteLength, sha256: sha(bytes) };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
  if (archiveFiles.reduce((sum, row) => sum + row.size, 0) > 128 * 1024 * 1024)
    throw new Error(`P2 expanded crate archive bound exceeded: ${identity}`);
  const checksumFiles = Object.entries(checksumRecord.files ?? {})
    .map(([path, digest]) => ({ path, sha256: digest }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const checksumPaths = new Set(checksumFiles.map((row) => row.path));
  const archiveTrackedFiles = archiveFiles.filter((row) => checksumPaths.has(row.path));
  const archivePackagingOnlyFiles = archiveFiles.filter((row) => !checksumPaths.has(row.path));
  if (
    archivePackagingOnlyFiles.some(
      (row) => ![".gitignore", ".gitattributes"].includes(row.path.split("/").at(-1)),
    ) ||
    checksumFiles.length !== archiveTrackedFiles.length ||
    archiveTrackedFiles.some(
      (row, index) =>
        row.path !== checksumFiles[index].path || row.sha256 !== checksumFiles[index].sha256,
    )
  )
    throw new Error(`P2 crate archive/checksum file-set reconciliation failed: ${identity}`);
  const vendorRows = entries
    .filter((row) => row.path.startsWith(`${pkg.name}/`))
    .map((row) => ({ ...row, path: row.path.slice(pkg.name.length + 1) }))
    .filter((row) => row.path !== ".cargo-checksum.json")
    .sort((a, b) => a.path.localeCompare(b.path));
  if (
    vendorRows.length !== archiveTrackedFiles.length ||
    archiveTrackedFiles.some(
      (row, index) =>
        row.path !== vendorRows[index].path ||
        row.size !== vendorRows[index].size ||
        row.sha256 !== vendorRows[index].sha256,
    )
  )
    throw new Error(`P2 authenticated crate archive/vendor byte reconciliation failed: ${identity}`);
  archiveInventory.push({
    name: pkg.name,
    version: pkg.version,
    source: locked.source,
    path: relative(repositoryRoot, archivePath),
    size: archiveCapture.byteLength,
    sha256: locked.checksum,
    memberCount: archiveFiles.length,
    packagingOnlyMembers: archivePackagingOnlyFiles,
  });
  const selected =
    pkg.license === "BSD-3-Clause"
      ? [{ spdx: "BSD-3-Clause", file: "LICENSE" }]
      : pkg.license === "(MIT OR Apache-2.0) AND Unicode-3.0"
        ? [
            { spdx: "MIT", file: "LICENSE-MIT" },
            { spdx: "Unicode-3.0", file: "LICENSE-UNICODE" },
          ]
        : [{ spdx: "MIT", file: "LICENSE-MIT" }];
  const files = selected.map((choice) => {
    const path = `${pkg.name}/${choice.file}`;
    const row = licenseFiles.find((candidate) => candidate.path === path);
    if (!row) throw new Error(`P2 selected license file missing: ${identity}:${path}`);
    const text = readFileSync(join(vendor, path), "utf8");
    if (!/copyright/i.test(text))
      throw new Error(`P2 selected license lacks preserved copyright text: ${identity}:${path}`);
    return { ...choice, path, size: row.size, sha256: row.sha256 };
  });
  return {
    name: pkg.name,
    version: pkg.version,
    cargoLockSource: locked.source,
    cargoPackageChecksum: checksumRecord.package,
    declaredExpression: pkg.license,
    obligations: ["preserve-selected-license-and-copyright-text-in-binary-distribution"],
    files,
  };
});
const attributionBytes = Buffer.from(
  [
    "Keep P2 crypto candidate — third-party license attribution",
    "Generated from the exact non-authorizing vendored closure; admission remains blocked.",
    "",
    ...licensePolicy.flatMap((pkg) => [
      `===== ${pkg.name} ${pkg.version} | ${pkg.declaredExpression} | selected ${pkg.files.map((row) => row.spdx).join(" AND ")} =====`,
      ...pkg.files.flatMap((row) => [
        `----- ${row.path} | sha256 ${row.sha256} -----`,
        readFileSync(join(vendor, row.path), "utf8").replace(/\s+$/, ""),
        "",
      ]),
    ]),
  ].join("\n"),
  "utf8",
);

const rustupHome = process.env.RUSTUP_HOME ?? "/root/.keep-build/rustup";
const toolchain = "1.97.1-x86_64-unknown-linux-gnu";
const toolchainRoot = realpathSync(join(rustupHome, "toolchains", toolchain));
execFileSync(
  process.execPath,
  [fileURLToPath(new URL("native_toolchain_inventory.mjs", import.meta.url)), repositoryRoot],
  {
    cwd: repositoryRoot,
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
      RUSTUP_HOME: rustupHome,
      KEEP_P1_TOOLCHAIN_ROOT: toolchainRoot,
    },
    encoding: "utf8",
  },
);
const cargo = join(toolchainRoot, "bin/cargo");
const hostLinker = realpathSync("/usr/bin/gcc");
const tracer = realpathSync("/usr/bin/strace");
const toolchainInventoryBytes = readFileSync(
  join(repositoryRoot, "native/toolchain-inventory.json"),
);
const toolchainInventory = JSON.parse(toolchainInventoryBytes);
const scratch = mkdtempSync(join(tmpdir(), "keep-p2-dependency-gate-"));
const cargoHome = join(scratch, "cargo-home");
const buildTarget = join(scratch, "target");
const env = {
  PATH: `${join(toolchainRoot, "bin")}:${join(toolchainRoot, "lib/rustlib/x86_64-unknown-linux-gnu/bin")}:/usr/bin:/bin`,
  LANG: "C",
  LC_ALL: "C",
  TZ: "UTC",
  SOURCE_DATE_EPOCH: "0",
  RUSTUP_HOME: rustupHome,
  RUSTUP_TOOLCHAIN: toolchain,
  CARGO_HOME: cargoHome,
  CARGO_NET_OFFLINE: "true",
  CARGO_INCREMENTAL: "0",
  CARGO_TARGET_DIR: buildTarget,
  RUSTC: join(toolchainRoot, "bin/rustc"),
  RUSTDOC: join(toolchainRoot, "bin/rustdoc"),
  RUSTFLAGS: `--cfg=curve25519_dalek_backend="fiat" --remap-path-prefix=${repositoryRoot}=/keep/source --remap-path-prefix=${scratch}=/keep/build`,
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER: hostLinker,
};

function graph(metadata) {
  const byId = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  return metadata.resolve.nodes
    .map((node) => {
      const pkg = byId.get(node.id);
      return {
        id: node.id.replaceAll(candidate, "$CANDIDATE"),
        name: pkg.name,
        version: pkg.version,
        source: pkg.source,
        features: [...node.features].sort(),
        targets: pkg.targets
          .map((target) => ({
            name: target.name,
            kind: [...target.kind].sort(),
            crateTypes: [...target.crate_types].sort(),
          }))
          .sort((a, b) => a.name.localeCompare(b.name)),
        dependencies: node.deps
          .map((dep) => ({
            name: dep.name,
            packageId: dep.pkg.replaceAll(candidate, "$CANDIDATE"),
            kinds: dep.dep_kinds
              .map((kind) => ({ kind: kind.kind, target: kind.target }))
              .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
          }))
          .sort((a, b) => `${a.name}:${a.packageId}`.localeCompare(`${b.name}:${b.packageId}`)),
      };
    })
    .sort((a, b) => a.id.localeCompare(b.id));
}

try {
  const run = (args, overrides = {}) =>
    execFileSync(cargo, args, {
      cwd: candidate,
      env: { ...env, ...overrides },
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
  const metadata = JSON.parse(
    run(["metadata", "--locked", "--offline", "--format-version", "1"]),
  );
  const hostMetadata = JSON.parse(
    run([
      "metadata",
      "--locked",
      "--offline",
      "--format-version",
      "1",
      "--filter-platform",
      "x86_64-unknown-linux-gnu",
    ]),
  );
  const targetMetadata = JSON.parse(
    run([
      "metadata",
      "--locked",
      "--offline",
      "--format-version",
      "1",
      "--filter-platform",
      "x86_64-unknown-linux-musl",
    ]),
  );
  const targetNodes = new Map(targetMetadata.resolve.nodes.map((node) => [node.id, node]));
  const candidateId = targetMetadata.packages.find(
    (pkg) => pkg.name === "keep-p2-crypto-candidate",
  )?.id;
  if (!candidateId) throw new Error("P2 candidate package absent from target graph");
  const dependencyIds = (packageId, acceptedKinds) =>
    (targetNodes.get(packageId)?.deps ?? [])
      .filter((dep) =>
        dep.dep_kinds.some((row) => acceptedKinds.has(row.kind ?? "normal")),
      )
      .map((dep) => dep.pkg);
  const packageClosure = (seeds, acceptedKinds) => {
    const seen = new Set();
    const pending = [...seeds];
    while (pending.length > 0) {
      const packageId = pending.pop();
      if (seen.has(packageId)) continue;
      seen.add(packageId);
      pending.push(...dependencyIds(packageId, acceptedKinds));
    }
    return seen;
  };
  const directRuntime = dependencyIds(candidateId, new Set(["normal"]));
  const targetRuntime = packageClosure(directRuntime, new Set(["normal"]));
  const directTest = dependencyIds(candidateId, new Set(["dev"]));
  const testClosure = packageClosure(directTest, new Set(["normal"]));
  const buildSeeds = [...targetRuntime].flatMap((id) =>
    dependencyIds(id, new Set(["build"])),
  );
  const hostBuild = packageClosure(buildSeeds, new Set(["normal", "build"]));
  const activeIds = new Set([candidateId, ...targetRuntime, ...testClosure, ...hostBuild]);
  const compilationRoles = targetMetadata.packages
    .map((pkg) => {
      const roles = [];
      if (pkg.id === candidateId) roles.push("candidate");
      if (targetRuntime.has(pkg.id)) roles.push("target-runtime");
      if (testClosure.has(pkg.id)) roles.push("test-closure");
      if (directTest.includes(pkg.id)) roles.push("test-direct");
      if (hostBuild.has(pkg.id)) roles.push("host-build");
      if (activeIds.has(pkg.id) && pkg.targets.some((target) => target.kind.includes("custom-build")))
        roles.push("host-build-script-owner");
      return { packageId: pkg.id.replaceAll(candidate, "$CANDIDATE"), name: pkg.name, roles };
    })
    .concat(
      metadata.packages
        .filter((pkg) => !activeIds.has(pkg.id))
        .map((pkg) => ({
          packageId: pkg.id.replaceAll(candidate, "$CANDIDATE"),
          name: pkg.name,
          roles: ["resolved-dormant"],
        })),
    )
    .sort((a, b) => a.packageId.localeCompare(b.packageId));
  const messages = run([
    "check",
    "--locked",
    "--offline",
    "--frozen",
    "--all-targets",
    "--message-format=json",
  ])
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const normalizeBuildPath = (path) =>
    path.replaceAll(scratch, "$SCRATCH").replaceAll(repositoryRoot, "$REPOSITORY");
  const compiledUnits = messages
    .filter((row) => row.reason === "compiler-artifact")
    .map((row) => ({
      packageId: row.package_id.replaceAll(candidate, "$CANDIDATE"),
      targetName: row.target.name,
      targetKinds: [...row.target.kind].sort(),
      crateTypes: [...row.target.crate_types].sort(),
      features: [...row.features].sort(),
      profile: {
        optLevel: row.profile.opt_level,
        debuginfo: row.profile.debuginfo,
        debugAssertions: row.profile.debug_assertions,
        overflowChecks: row.profile.overflow_checks,
        test: row.profile.test,
      },
      outputs: row.filenames
        .map((path) => ({
          path: normalizeBuildPath(path),
          sha256: sha(readFileSync(path)),
          size: readFileSync(path).byteLength,
        }))
        .sort((a, b) => a.path.localeCompare(b.path)),
    }))
    .sort((a, b) =>
      `${a.packageId}:${a.targetName}:${a.targetKinds.join(",")}`.localeCompare(
        `${b.packageId}:${b.targetName}:${b.targetKinds.join(",")}`,
      ),
    );
  const rolesByPackage = new Map(compilationRoles.map((row) => [row.packageId, row.roles]));
  const normalizedCandidateId = candidateId.replaceAll(candidate, "$CANDIDATE");
  const unitIds = new Set();
  for (const unit of compiledUnits) {
    const hostCell = unit.outputs.every((row) =>
      row.path.startsWith("$SCRATCH/target/debug/"),
    );
    unit.executionCell = hostCell ? "host-build" : "x86_64-unknown-linux-musl";
    if (hostCell)
      unit.outputs = unit.outputs.map((row) => ({
        path: row.path,
        rootBound: true,
        status: "byte-identity-intentionally-unfrozen-pending-hermetic-host-build",
      }));
    unit.unitRole = unit.profile.test
      ? "test-unit"
      : unit.targetKinds.includes("custom-build")
        ? "host-build-script"
        : hostCell
          ? "host-build-dependency"
          : unit.packageId === normalizedCandidateId
            ? "candidate-wrapper-library"
            : "target-runtime-library";
    unit.unitId = [
      unit.packageId,
      unit.targetName,
      unit.targetKinds.join(","),
      unit.executionCell,
      unit.profile.test ? "test" : "non-test",
    ].join("|");
    if (unitIds.has(unit.unitId)) throw new Error(`P2 duplicate compilation unit: ${unit.unitId}`);
    unitIds.add(unit.unitId);
    if (
      unit.targetKinds.includes("custom-build") !== (unit.unitRole === "host-build-script") ||
      unit.profile.test !== (unit.unitRole === "test-unit")
    )
      throw new Error(`P2 compilation unit kind/role equation failed: ${unit.unitId}`);
    const packageRoles = rolesByPackage.get(unit.packageId) ?? [];
    if (
      (unit.unitRole === "host-build-script" &&
        (unit.executionCell !== "host-build" || !packageRoles.includes("host-build-script-owner"))) ||
      (unit.unitRole === "host-build-dependency" &&
        (unit.executionCell !== "host-build" || !packageRoles.includes("host-build"))) ||
      (unit.unitRole === "test-unit" &&
        (unit.executionCell !== "x86_64-unknown-linux-musl" || unit.packageId !== normalizedCandidateId)) ||
      (unit.unitRole === "candidate-wrapper-library" &&
        (unit.executionCell !== "x86_64-unknown-linux-musl" || unit.packageId !== normalizedCandidateId)) ||
      (unit.unitRole === "target-runtime-library" &&
        (unit.executionCell !== "x86_64-unknown-linux-musl" || !packageRoles.includes("target-runtime"))) ||
      ![
        "host-build-script",
        "host-build-dependency",
        "test-unit",
        "candidate-wrapper-library",
        "target-runtime-library",
      ].includes(unit.unitRole)
    )
      throw new Error(`P2 compilation unit/role mismatch: ${unit.unitId}`);
  }
  const compiledPackageIds = new Set(compiledUnits.map((row) => row.packageId));
  for (const unit of compiledUnits) {
    const roles = rolesByPackage.get(unit.packageId) ?? [];
    if (roles.length === 0 || roles.includes("resolved-dormant"))
      throw new Error(`P2 compiled unit lacks an active compilation role: ${unit.packageId}`);
  }
  for (const row of compilationRoles) {
    if (row.roles.includes("resolved-dormant") === compiledPackageIds.has(row.packageId))
      throw new Error(`P2 compilation role/unit partition mismatch: ${row.packageId}`);
  }
  const activeProcMacros = compiledUnits
    .filter((row) => row.targetKinds.includes("proc-macro"))
    .map((row) => `${row.packageId}:${row.targetName}`)
    .sort();
  const unsafeMessages = run(
    ["check", "--locked", "--offline", "--frozen", "--all-targets", "--message-format=json"],
    {
      CARGO_TARGET_DIR: join(scratch, "unsafe-target"),
      RUSTFLAGS: `${env.RUSTFLAGS} --force-warn unsafe-code`,
    },
  )
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const rawActiveUnsafeDiagnostics = unsafeMessages
    .filter(
      (row) =>
        row.reason === "compiler-message" &&
        row.message?.code?.code === "unsafe_code" &&
        row.message?.level === "warning",
    )
    .flatMap((row) =>
      row.message.spans
        .filter((span) => span.is_primary)
        .map((span) => {
          const observedFile = span.file_name
            .replace(/^\/keep\/source(?=\/|$)/, repositoryRoot)
            .replace(/^\/keep\/build(?=\/|$)/, scratch);
          const realFile = realpathSync(observedFile);
          const path = relative(vendor, realFile);
          if (path.startsWith("..") || path === "")
            throw new Error(`P2 active unsafe site escaped vendor closure: ${span.file_name}`);
          const source = readFileSync(realFile, "utf8").split("\n")[span.line_start - 1];
          if (source === undefined)
            throw new Error(`P2 active unsafe source line missing: ${path}:${span.line_start}`);
          const targetKinds = [...row.target.kind].sort();
          const matchingUnits = compiledUnits.filter(
            (unit) =>
              unit.packageId === row.package_id &&
              unit.targetName === row.target.name &&
              JSON.stringify(unit.targetKinds) === JSON.stringify(targetKinds),
          );
          if (matchingUnits.length !== 1)
            throw new Error(`P2 unsafe diagnostic unit binding is not exact: ${row.package_id}:${path}`);
          return {
            packageId: row.package_id,
            targetName: row.target.name,
            targetKinds,
            unitId: matchingUnits[0].unitId,
            path,
            line: span.line_start,
            column: span.column_start,
            lineEnd: span.line_end,
            columnEnd: span.column_end,
            kind: row.message.message,
            sourceLineSha256: sha(Buffer.from(source, "utf8")),
            status: "candidate-pending-independent-semantic-audit",
          };
        }),
    )
    .sort((a, b) =>
      `${a.packageId}:${a.path}:${String(a.line).padStart(8, "0")}:${String(a.column).padStart(8, "0")}:${a.kind}`.localeCompare(
        `${b.packageId}:${b.path}:${String(b.line).padStart(8, "0")}:${String(b.column).padStart(8, "0")}:${b.kind}`,
      ),
    );
  const activeUnsafeByKey = new Map();
  for (const row of rawActiveUnsafeDiagnostics) {
    const key = `${row.unitId}:${row.path}:${row.line}:${row.column}:${row.lineEnd}:${row.columnEnd}:${row.kind}`;
    const prior = activeUnsafeByKey.get(key);
    activeUnsafeByKey.set(key, prior ? { ...prior, observationCount: prior.observationCount + 1 } : {
      ...row,
      observationCount: 1,
    });
  }
  const activeUnsafeDiagnostics = [...activeUnsafeByKey.values()];
  if (activeUnsafeDiagnostics.length === 0)
    throw new Error("P2 forced unsafe diagnostic inventory was vacuously empty");
  for (const row of activeUnsafeDiagnostics) {
    if (!compiledPackageIds.has(row.packageId))
      throw new Error(`P2 unsafe diagnostic lacks a compiled unit: ${row.packageId}`);
    if (!Number.isSafeInteger(row.observationCount) || row.observationCount < 1)
      throw new Error(`P2 unsafe diagnostic multiplicity invalid: ${row.packageId}:${row.path}`);
  }
  if (
    !activeUnsafeDiagnostics.some(
      (row) => row.path === "block-buffer/src/read.rs" && row.line === 26,
    ) ||
    !activeUnsafeDiagnostics.some(
      (row) => row.path === "hybrid-array/src/flatten.rs" && row.line === 32,
    )
  )
    throw new Error("P2 known-active unsafe positive controls were not diagnosed");
  const tracePath = join(scratch, "build.trace");
  const traceTarget = join(scratch, "trace-target");
  const traced = spawnSync(
    tracer,
    [
      "-f",
      "-qq",
      "-s",
      "4096",
      "-e",
      "trace=execve,connect,bind,openat,chdir",
      "-o",
      tracePath,
      cargo,
      "check",
      "--locked",
      "--offline",
      "--frozen",
      "--all-targets",
    ],
    {
      cwd: candidate,
      env: { ...env, CARGO_TARGET_DIR: traceTarget },
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    },
  );
  if (traced.status !== 0)
    throw new Error(`P2 traced build failed: ${traced.stderr}`);
  const traceLines = readFileSync(tracePath, "utf8")
    .split("\n")
    .filter(Boolean);
  const normalizeTrace = (line) =>
    line
      .replace(/^\d+\s+/, "")
      .replaceAll(scratch, "$SCRATCH")
      .replaceAll(repositoryRoot, "$REPOSITORY")
      .replace(/(\$SCRATCH\/trace-target(?:\/x86_64-unknown-linux-musl)?)[A-Za-z0-9]{6}(?=\/CACHEDIR\.TAG)/g, "$1RANDOM")
      .replace(/\/tmp\/cc[A-Za-z0-9]+/g, "/tmp/ccRANDOM")
      .replace(/\/(?:rmeta|rustc)[A-Za-z0-9]{6}(?=\/|\")/g, "/RUSTC-RANDOM")
      .replace(/\/\.tmp[A-Za-z0-9]{6}\.temp-archive(?=\/|\")/g, "/.tmpRANDOM.temp-archive")
      .replace(/0x[0-9a-f]+ \/\* \d+ vars \*\//g, "$ENV")
      .replace(/\s+= -?\d+(?: <[^>]+>)?$/, "")
      .replace(/\s+<unfinished \.\.\.>$/, "");
  const networkAttempts = traceLines
    .filter((line) => /\b(?:connect|bind)\(/.test(line))
    .map(normalizeTrace)
    .sort();
  if (networkAttempts.length !== 0)
    throw new Error(`P2 offline build attempted network/socket authority: ${networkAttempts[0]}`);
  const execveRows = [...new Set(
    traceLines
      .filter((line) => /\bexecve\(/.test(line))
      .map(normalizeTrace)
      .map((line) => {
        const match = /execve\((.*\])/.exec(line);
        return match ? `execve(${match[1]})` : line;
      }),
  )].sort();
  if (
    !execveRows.some(
      (line) =>
        line.includes('"--crate-name", "curve25519_dalek"') &&
        line.includes('--cfg=curve25519_dalek_backend=\\"fiat\\"') &&
        line.includes('curve25519_dalek_bits=\\"64\\"') &&
        line.includes('"--extern", "fiat_crypto='),
    )
  )
    throw new Error("P2 traced curve invocation did not prove fiat/64/external linkage");
  if (
    execveRows.some(
      (line) =>
        line.includes("curve25519_dalek_backend=\\\"simd\\\"") ||
        line.includes("curve25519_dalek_backend=\\\"avx512\\\"") ||
        line.includes("curve25519_dalek_derive"),
    )
  )
    throw new Error("P2 traced build admitted SIMD/derive authority");
  const fileAccessSet = [...new Set(
    traceLines.flatMap((raw) => {
      const line = normalizeTrace(raw);
      const open = /openat\([^,]+, "((?:\\.|[^"])*)", ([A-Z0-9_|]+)/.exec(line);
      if (open) return [`openat:${open[1]}:${open[2]}`];
      const directory = /chdir\("((?:\\.|[^"])*)"/.exec(line);
      return directory ? [`chdir:${directory[1]}`] : [];
    }),
  )].sort();
  if (fileAccessSet.length === 0 || execveRows.length === 0)
    throw new Error("P2 build trace was vacuously empty");
  const verificationTestOutput = run([
    "test",
    "--locked",
    "--offline",
    "--frozen",
    "--lib",
  ]);
  if (!/test result: ok\. 6 passed; 0 failed;/.test(verificationTestOutput))
    throw new Error("P2 strict-wrapper hostile corpus did not run to completion");
  const verificationTestEvidence = verificationTestOutput
    .split("\n")
    .filter((line) => line.startsWith("test ") || line.startsWith("test result:"))
    .map((line) => line.replace(/; finished in .*$/, ""))
    .sort()
    .join("\n");
  const byId = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const activePackages = new Set(graph(targetMetadata).map((row) => row.name));
  const packageLevelUnsafeCandidates = unsafeFiles.filter((row) =>
    activePackages.has(row.path.split("/")[0]),
  );
  const buildTranscript = messages
    .filter((row) => row.reason === "build-script-executed")
    .map((row) => {
      const pkg = byId.get(row.package_id);
      return {
        name: pkg?.name,
        version: pkg?.version,
        cfgs: [...(row.cfgs ?? [])].sort(),
        env: [...(row.env ?? [])].sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
        linkedLibs: [...(row.linked_libs ?? [])].sort(),
        linkedPaths: [...(row.linked_paths ?? [])].sort(),
      };
    })
    .sort((a, b) => String(a.name).localeCompare(String(b.name)));
  const executedBuildScripts = buildTranscript.map((row) => `${row.name}@${row.version}`);
  const depInfo = walkRegular(buildTarget)
    .filter((path) => path.endsWith(".d"))
    .map((path) => {
      const observed = readFileSync(path, "utf8");
      const sourcePaths = [...new Set(
        observed
          .split(/\s+/)
          .map((token) => token.replace(/[:\\]+$/, ""))
          .filter((token) => token.endsWith(".rs"))
          .map((token) => {
            try {
              const real = realpathSync(token);
              const rel = relative(vendor, real);
              return rel.startsWith("..") || rel === "" ? undefined : rel;
            } catch {
              return undefined;
            }
          })
          .filter(Boolean),
      )].sort();
      const normalized = observed
        .replaceAll(scratch, "$SCRATCH")
        .replaceAll(repositoryRoot, "$REPOSITORY");
      return {
        path: normalizeBuildPath(path).replace(
          /(^|\/)([^/]+)-[0-9a-f]{16}(?=\.d$|\/)/g,
          "$1$2-BUILDHASH",
        ),
        normalizedSha256: sha(Buffer.from(normalized, "utf8")),
        sourcePaths,
      };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
  const curveDepInfo = depInfo.find(
    (row) =>
      row.path.includes("/deps/curve25519_dalek-") &&
      row.sourcePaths.includes("curve25519-dalek/src/backend/serial/fiat_u64.rs"),
  );
  if (!curveDepInfo)
    throw new Error("P2 fiat curve dep-info proof was not observed");
  if (
    !curveDepInfo.sourcePaths.includes("curve25519-dalek/src/backend/serial/fiat_u64/field.rs") ||
    curveDepInfo.sourcePaths.some(
      (path) => path.includes("/backend/vector/") || path.startsWith("curve25519-dalek-derive/"),
    )
  )
    throw new Error("P2 curve dep-info did not prove exact fiat/non-SIMD source closure");
  const buildArtifactPaths = walkRegular(buildTarget).filter((path) => {
      const rel = relative(buildTarget, path);
      return /(^|\/)build\/[^/]+\/(?:output|stderr|root-output)$/.test(rel) ||
        /(^|\/)build\/[^/]+\/out\//.test(rel);
    });
  const buildArtifacts = buildArtifactPaths.map((path) => {
    const observed = readFileSync(path);
    const normalized = path.endsWith("/root-output")
      ? Buffer.from(
          observed
            .toString("utf8")
            .replaceAll(scratch, "$SCRATCH")
            .replaceAll(repositoryRoot, "$REPOSITORY"),
          "utf8",
        )
      : observed;
    return {
      path: relative(buildTarget, path).replace(
        /(^|\/build\/[^/]+)-[0-9a-f]{16}(\/)/,
        (_match, prefix, suffix) => `${prefix}-BUILDHASH${suffix}`,
      ),
      size: normalized.byteLength,
      sha256: sha(normalized),
    };
  });
  const closure = {
    schema: "keep.native-p2-dependency-closure",
    version: 1,
    authorizing: false,
    admissionStatus: "candidate-pending-independent-unsafe-and-host-tool-audit",
    collectorIdentity: {
      path: "tools/native_p2_dependency_gate.mjs",
      sha256: sha(readFileSync(collectorPath)),
    },
    archiveSnapshotHelperIdentity: {
      path: "tools/native_p2_archive_snapshot.mjs",
      sha256: sha(readFileSync(archiveSnapshotHelperPath)),
    },
    compilationOrderHelperIdentity: {
      path: "tools/native_compilation_units.mjs",
      sha256: sha(readFileSync(fileURLToPath(new URL("native_compilation_units.mjs", import.meta.url)))),
    },
    toolchain,
    target: "x86_64-unknown-linux-musl",
    curveBackend: "fiat",
    toolInputs: {
      toolchainRootDigest: toolchainInventory.rootDigest,
      toolchainInventoryDigest: sha(toolchainInventoryBytes),
      hostLinkerPath: hostLinker,
      hostLinkerSha256: sha(readFileSync(hostLinker)),
      hostLinkerTcb: "OS-provisioned GCC/glibc/binutils development-only closure",
    },
    candidateEntries,
    crateArchiveTool: { path: tarTool, sha256: sha(readFileSync(tarTool)) },
    crateArchiveRootDigest: crateArchiveRootHash.digest("hex"),
    crateArchiveEntries,
    crateArchives: archiveInventory,
    vendorRootDigest: rootHash.digest("hex"),
    entries,
    packages,
    licenseFiles,
    acceptedLicenseExpressions: [...acceptedLicenseExpressions].sort(),
    licensePolicy,
    distributionAttribution: {
      path: relative(repositoryRoot, attributionTarget),
      size: attributionBytes.byteLength,
      sha256: sha(attributionBytes),
    },
    presentBuildScripts,
    executedBuildScripts,
    procMacros,
    activeProcMacros,
    packageResolutionRoles: compilationRoles,
    compiledUnits: orderCompilationUnits(compiledUnits),
    unsafeFiles,
    packageLevelUnsafeCandidates,
    activeUnsafeDiagnostics,
    buildObservation: {
      observationKind: "untrusted-raw-whole-build-observation-not-build-script-policy/v1",
      tracer: {
        path: tracer,
        sha256: sha(readFileSync(tracer)),
      },
      startingEnvironment: Object.entries(env)
        .map(([key, value]) => [key, normalizeBuildPath(value)])
        .sort((a, b) => a[0].localeCompare(b[0])),
      execveRows,
      networkAttempts,
      limitations: [
        "whole-cargo-tree-not-attributed-to-build-script",
        "pid-parentage-and-child-environments-not-retained",
        "relative-openat-not-resolved-to-byte-identities",
        "raw-file-access-rows-not-frozen-because-ancestor-probes-are-source-root-dependent",
        "syscall-results-not-authority-evidence",
      ],
      status: "untrusted-observation-only-candidate-pending-attributable-trace-audit",
    },
    graphs: {
      all: graph(metadata),
      host: graph(hostMetadata),
      target: graph(targetMetadata),
    },
    buildTranscript,
    depInfo,
    backendProof: {
      requestedBackend: "fiat",
      requestedBits: "64",
      curveDepInfoPath: curveDepInfo.path,
      fiatSourcePaths: curveDepInfo.sourcePaths.filter((path) => path.includes("/fiat_u64")),
      vectorSourcePaths: curveDepInfo.sourcePaths.filter((path) => path.includes("/backend/vector/")),
      activeDeriveSourcePaths: curveDepInfo.sourcePaths.filter((path) =>
        path.startsWith("curve25519-dalek-derive/"),
      ),
    },
    buildArtifacts,
    verificationTests: {
      policy: "rfc8032-canonical-key-nonweak-verify-strict/v1",
      passed: 6,
      failed: 0,
      outputSha256: sha(Buffer.from(verificationTestEvidence, "utf8")),
    },
  };
  if (write) {
    writeFileSync(attributionTarget, attributionBytes, { mode: 0o644 });
    writeFileSync(target, `${JSON.stringify(closure, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o644,
    });
    console.log(
      `[native-p2-dependency-gate] wrote ${entries.length} files / ${packages.length} packages`,
    );
  } else {
    const observedAttribution = readFileSync(attributionTarget);
    if (!observedAttribution.equals(attributionBytes))
      throw new Error("P2 distribution attribution differs from selected license closure");
    const expected = JSON.parse(readFileSync(target, "utf8"));
    if (JSON.stringify(expected) !== JSON.stringify(closure))
      throw new Error("P2 dependency/build closure differs from frozen inventory");
    console.log(
      `[native-p2-dependency-gate] OK — ${entries.length} files / ${packages.length} packages; non-authorizing candidate`,
    );
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
