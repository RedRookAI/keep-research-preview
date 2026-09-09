#!/usr/bin/env node
/** A6 P1 mechanical TCB gate and sanitized development-only build runner. */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  chmodSync,
  copyFileSync,
  fsyncSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { homedir, tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(
  process.argv.find((arg, index) => index > 1 && !arg.startsWith("--")) ??
    fileURLToPath(new URL("..", import.meta.url)),
);
const verify = process.argv.includes("--verify");
const nativeRoot = join(repositoryRoot, "native");
const fail = (reason) => {
  throw new Error(`native P1 gate: ${reason}`);
};
const read = (path) => readFileSync(path, "utf8");
const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const verifyInstalledShim = (path, expected) => {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o555)
    fail("installed shim metadata is not exact");
  if (sha256(path) !== expected) fail("installed shim digest is not joined to launcher measurement");
};
for (const key of Object.keys(process.env)) {
  if (
    key === "CARGO" ||
    key === "RUSTC" ||
    key === "RUSTDOC" ||
    key === "RUSTFMT" ||
    key === "RUSTFLAGS" ||
    key === "RUSTC_WRAPPER" ||
    key === "RUSTC_WORKSPACE_WRAPPER" ||
    key === "CARGO_ENCODED_RUSTFLAGS" ||
    /^CARGO_TARGET_.*_(?:RUNNER|LINKER|RUSTFLAGS)$/.test(key)
  )
    fail(`ambient build injection variable ${key} is forbidden`);
}
const exact = (path, expected) => {
  if (read(path) !== expected)
    fail(`${relative(repositoryRoot, path)} differs from frozen bytes`);
};
const CONFIG =
  '[build]\ntarget = "x86_64-unknown-linux-musl"\n\n[target.x86_64-unknown-linux-musl]\nlinker = "rust-lld"\n\n[net]\noffline = true\n\n[source.crates-io]\nreplace-with = "vendored-transport"\n\n[source.vendored-transport]\ndirectory = "vendor-transport"\n';
const WORKSPACE =
  '[workspace]\nresolver = "3"\nmembers = ["crates/protocol", "crates/transport", "crates/p2-d2-evidence", "crates/linux-abi", "crates/p2-d2-supervisor", "crates/production-resolver", "crates/prober-launcher", "crates/prober-vmm-shim"]\n\n[workspace.package]\nedition = "2024"\nlicense = "MIT"\nrust-version = "1.97.1"\n\n[workspace.dependencies]\nnix = { version = "=0.31.3", default-features = false, features = ["fs", "poll", "socket", "uio", "user"] }\nrustix = { version = "=1.1.4", default-features = false, features = ["net", "std"] }\nlibc = "=0.2.189"\n\n[profile.dev]\npanic = "abort"\n\n[profile.release]\npanic = "abort"\ncodegen-units = 1\nlto = "fat"\nstrip = "none"\n';
const PROTOCOL_CRATE =
  '[package]\nname = "keep-native-protocol"\nversion = "0.1.0"\nedition.workspace = true\nlicense.workspace = true\nrust-version.workspace = true\npublish = false\n\n[[bin]]\nname = "keep-native-protocol-oracle"\npath = "src/main.rs"\n';
const TRANSPORT_CRATE =
  '[package]\nname = "keep-native-transport"\nversion = "0.1.0"\nedition.workspace = true\nlicense.workspace = true\nrust-version.workspace = true\npublish = false\n\n[dependencies]\nkeep-native-protocol = { path = "../protocol" }\nnix.workspace = true\nrustix.workspace = true\n';
const P2_D2_EVIDENCE_CRATE =
  '[package]\nname = "keep-native-p2-d2-evidence"\nversion = "0.1.0"\nedition.workspace = true\nlicense.workspace = true\nrust-version.workspace = true\npublish = false\n\n[dependencies]\nkeep-native-protocol = { path = "../protocol" }\n\n[[bin]]\nname = "keep-native-p2-d2-overlay-oracle"\npath = "src/main.rs"\n';
const LINUX_ABI_CRATE =
  '[package]\nname = "keep-native-linux-abi"\nversion = "0.1.0"\nedition.workspace = true\nlicense.workspace = true\nrust-version.workspace = true\npublish = false\n\n[dependencies]\nlibc.workspace = true\n';
const P2_D2_SUPERVISOR_CRATE =
  '[package]\nname = "keep-native-p2-d2-supervisor"\nversion = "0.1.0"\nedition.workspace = true\nlicense.workspace = true\nrust-version.workspace = true\npublish = false\n\n[dependencies]\nkeep-native-linux-abi = { path = "../linux-abi" }\nkeep-native-protocol = { path = "../protocol" }\n\n[[bin]]\nname = "keep-native-p2-d2-build-cell"\npath = "src/main.rs"\n\n[[bin]]\nname = "keep-native-p2-d2-supervisor"\npath = "src/supervisor.rs"\n';
const PRODUCTION_RESOLVER_CRATE =
  '[package]\nname = "keep-native-production-resolver"\nversion = "0.1.0"\nedition.workspace = true\nlicense.workspace = true\nrust-version.workspace = true\npublish = false\n\n[dependencies]\nkeep-native-linux-abi = { path = "../linux-abi" }\nkeep-native-protocol = { path = "../protocol" }\n\n[[bin]]\nname = "keep-native-production-resolver-probe"\npath = "src/main.rs"\n';
const PROBER_LAUNCHER_CRATE =
  '[package]\nname = "keep-native-prober-launcher"\nversion = "0.1.0"\nedition.workspace = true\nlicense.workspace = true\nrust-version.workspace = true\npublish = false\n\n[features]\ncandidate-probe = []\n\n[dependencies]\nkeep-native-linux-abi = { path = "../linux-abi" }\nkeep-native-protocol = { path = "../protocol" }\n\n[[bin]]\nname = "keep-native-prober-launch-candidate"\npath = "src/main.rs"\nrequired-features = ["candidate-probe"]\n';
const PROBER_VMM_SHIM_CRATE =
  '[package]\nname = "keep-native-prober-vmm-shim"\nversion = "0.1.0"\nedition.workspace = true\nlicense.workspace = true\nrust-version.workspace = true\npublish = false\n\n[dependencies]\nkeep-native-linux-abi = { path = "../linux-abi" }\n\n[[bin]]\nname = "keep-native-prober-vmm-shim"\npath = "src/main.rs"\n';
exact(join(nativeRoot, ".cargo/config.toml"), CONFIG);
exact(join(nativeRoot, "Cargo.toml"), WORKSPACE);
exact(join(nativeRoot, "crates/protocol/Cargo.toml"), PROTOCOL_CRATE);
exact(join(nativeRoot, "crates/transport/Cargo.toml"), TRANSPORT_CRATE);
exact(join(nativeRoot, "crates/p2-d2-evidence/Cargo.toml"), P2_D2_EVIDENCE_CRATE);
exact(join(nativeRoot, "crates/linux-abi/Cargo.toml"), LINUX_ABI_CRATE);
exact(join(nativeRoot, "crates/p2-d2-supervisor/Cargo.toml"), P2_D2_SUPERVISOR_CRATE);
exact(join(nativeRoot, "crates/production-resolver/Cargo.toml"), PRODUCTION_RESOLVER_CRATE);
exact(join(nativeRoot, "crates/prober-launcher/Cargo.toml"), PROBER_LAUNCHER_CRATE);
exact(join(nativeRoot, "crates/prober-vmm-shim/Cargo.toml"), PROBER_VMM_SHIM_CRATE);
const toolchain = read(join(repositoryRoot, "rust-toolchain.toml"));
if (
  toolchain !==
  '[toolchain]\nchannel = "1.97.1"\nprofile = "minimal"\ncomponents = ["rustfmt"]\ntargets = ["x86_64-unknown-linux-musl"]\n'
)
  fail("toolchain/components/target are not exact");
const lock = JSON.parse(read(join(nativeRoot, "toolchain-lock.json")));
const rustupHome = process.env.RUSTUP_HOME ?? join(homedir(), ".rustup");
const toolchainRoot = realpathSync(
  process.env.KEEP_P1_TOOLCHAIN_ROOT ??
    join(rustupHome, "toolchains", lock.toolchain),
);
execFileSync(
  process.execPath,
  [join(repositoryRoot, "tools/native_toolchain_inventory.mjs")],
  {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
      RUSTUP_HOME: rustupHome,
      KEEP_P1_TOOLCHAIN_ROOT: toolchainRoot,
    },
  },
);
const tools = {
  cargo: [join(toolchainRoot, "bin/cargo"), lock.cargoSha256],
  rustc: [join(toolchainRoot, "bin/rustc"), lock.rustcSha256],
  rustdoc: [join(toolchainRoot, "bin/rustdoc"), lock.rustdocSha256],
  rustfmt: [join(toolchainRoot, "bin/rustfmt"), lock.rustfmtSha256],
  rustLld: [
    join(toolchainRoot, "lib/rustlib", lock.host, "bin/rust-lld"),
    lock.rustLldSha256,
  ],
};
for (const [name, [path, digest]] of Object.entries(tools)) {
  const canonical = realpathSync(path);
  if (canonical !== path || !lstatSync(path).isFile())
    fail(`${name} is not a canonical regular file`);
  const observed = createHash("sha256")
    .update(readFileSync(path))
    .digest("hex");
  if (observed !== digest) fail(`${name} identity mismatch`);
}
const files = [];
const walk = (directory) => {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) {
      if (
        path !== join(nativeRoot, "target") &&
        path !== join(nativeRoot, "vendor-transport") &&
        path !== join(nativeRoot, "vendor-p2") &&
        path !== join(nativeRoot, "p2-crypto-candidate")
      )
        walk(path);
    } else files.push(path);
  }
};
walk(nativeRoot);
const manifests = files
  .filter((path) => path.endsWith("Cargo.toml"))
  .map((path) => relative(nativeRoot, path))
  .sort();
if (
  JSON.stringify(manifests) !==
  JSON.stringify([
    "Cargo.toml",
    "crates/linux-abi/Cargo.toml",
    "crates/p2-d2-evidence/Cargo.toml",
    "crates/p2-d2-supervisor/Cargo.toml",
    "crates/prober-launcher/Cargo.toml",
    "crates/prober-vmm-shim/Cargo.toml",
    "crates/production-resolver/Cargo.toml",
    "crates/protocol/Cargo.toml",
    "crates/transport/Cargo.toml",
  ])
)
  fail(`unexpected manifests: ${manifests.join(",")}`);
const cargoLock = read(join(nativeRoot, "Cargo.lock"));
const packages = [...cargoLock.matchAll(/^name = "([^"]+)"$/gm)].map(
  (match) => match[1],
);
if (
  JSON.stringify(packages) !== JSON.stringify([
    "autocfg",
    "bitflags",
    "cfg-if",
    "cfg_aliases",
    "errno",
    "keep-native-linux-abi",
    "keep-native-p2-d2-evidence",
    "keep-native-p2-d2-supervisor",
    "keep-native-prober-launcher",
    "keep-native-prober-vmm-shim",
    "keep-native-production-resolver",
    "keep-native-protocol",
    "keep-native-transport",
    "libc",
    "linux-raw-sys",
    "memoffset",
    "nix",
    "rustix",
    "windows-link",
    "windows-sys",
  ]) ||
  [...cargoLock.matchAll(/^source = /gm)].length !== 12 ||
  [...cargoLock.matchAll(/^checksum = /gm)].length !== 12
)
  fail(`unexpected dependency lock: ${packages.join(",")}`);
const vendorPackages = readdirSync(join(nativeRoot, "vendor-transport"))
  .filter((name) => statSync(join(nativeRoot, "vendor-transport", name)).isDirectory())
  .sort();
if (JSON.stringify(vendorPackages) !== JSON.stringify([
  "autocfg-1.5.1", "bitflags-2.13.1", "cfg-if-1.0.4", "cfg_aliases-0.2.2",
  "errno-0.3.14", "libc-0.2.189", "linux-raw-sys-0.12.1", "memoffset-0.9.1",
  "nix-0.31.3", "rustix-1.1.4", "windows-link-0.2.1", "windows-sys-0.61.2",
])) fail(`unexpected transport vendor closure: ${vendorPackages.join(",")}`);
if (files.some((path) => path.endsWith("build.rs")))
  fail("Keep application build script entered workspace");
for (const path of files.filter((entry) => entry.endsWith(".rs"))) {
  const source = read(path);
  if (path === join(nativeRoot, "crates/linux-abi/src/lib.rs")) {
    if ((source.match(/\bunsafe\s*\{/g) ?? []).length !== 56 ||
        (source.match(/\/\/ SAFETY:/g) ?? []).length !== 56 ||
        /unsafe\s+(?:fn|trait|impl)/.test(source))
      fail("linux-abi unsafe boundary differs from its exact fifty-six documented syscall/FD ownership sites");
    continue;
  }
  if (!source.includes("#![forbid(unsafe_code)]"))
    fail(`${relative(nativeRoot, path)} does not forbid unsafe`);
  if (/\bunsafe\s*(?:\{|fn\b|trait\b|impl\b|extern\b)/.test(source))
    fail(`${relative(nativeRoot, path)} contains unsafe`);
}
if (existsSync(join(repositoryRoot, ".git")) && existsSync(join(nativeRoot, "target"))) {
  const tracked = execFileSync("git", ["ls-files", "--", "native/target"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
  }).trim();
  if (tracked) fail("native/target contains tracked build output");
}
const cargoHome = mkdtempSync(join(tmpdir(), "keep-p1-cargo-home-"));
const cleanEnv = {
  PATH: `${join(toolchainRoot, "bin")}:${dirname(tools.rustLld[0])}:/usr/bin:/bin`,
  LANG: "C",
  LC_ALL: "C",
  CARGO_HOME: cargoHome,
  CARGO_NET_OFFLINE: "true",
  CARGO_INCREMENTAL: "0",
  RUSTC: tools.rustc[0],
  RUSTDOC: tools.rustdoc[0],
  RUSTFMT: tools.rustfmt[0],
  RUSTUP_HOME: rustupHome,
  RUSTUP_TOOLCHAIN: lock.toolchain,
  RUSTFLAGS: `--remap-path-prefix=${repositoryRoot}=/keep/source`,
  SOURCE_DATE_EPOCH: "0",
};
try {
  const run = (args, stdio = "pipe") =>
    execFileSync(tools.cargo[0], args, {
      cwd: nativeRoot,
      encoding: "utf8",
      env: cleanEnv,
      stdio,
    });
  const metadata = JSON.parse(
    run([
      "metadata",
      "--locked",
      "--offline",
      "--no-deps",
      "--format-version",
      "1",
    ]),
  );
  if (metadata.workspace_members.length !== 8 || metadata.packages.length !== 8)
    fail("workspace membership is not exact");
  const protocol = metadata.packages.find((row) => row.name === "keep-native-protocol");
  const transport = metadata.packages.find((row) => row.name === "keep-native-transport");
  const evidence = metadata.packages.find((row) => row.name === "keep-native-p2-d2-evidence");
  const linuxAbi = metadata.packages.find((row) => row.name === "keep-native-linux-abi");
  const p2Supervisor = metadata.packages.find((row) => row.name === "keep-native-p2-d2-supervisor");
  const productionResolver = metadata.packages.find((row) => row.name === "keep-native-production-resolver");
  const proberLauncher = metadata.packages.find((row) => row.name === "keep-native-prober-launcher");
  const proberVmmShim = metadata.packages.find((row) => row.name === "keep-native-prober-vmm-shim");
  if (
    protocol === undefined || transport === undefined || evidence === undefined || linuxAbi === undefined || p2Supervisor === undefined || productionResolver === undefined || proberLauncher === undefined || proberVmmShim === undefined ||
    protocol.dependencies.length !== 0 ||
    Object.keys(protocol.features ?? {}).length !== 0 ||
    Object.keys(transport.features ?? {}).length !== 0 ||
    Object.keys(evidence.features ?? {}).length !== 0 ||
    Object.keys(linuxAbi.features ?? {}).length !== 0 ||
    Object.keys(p2Supervisor.features ?? {}).length !== 0 ||
    Object.keys(productionResolver.features ?? {}).length !== 0 ||
    Object.keys(proberVmmShim.features ?? {}).length !== 0 ||
    JSON.stringify(proberLauncher.features ?? {}) !== JSON.stringify({ "candidate-probe": [] })
  )
    fail("metadata dependency/feature graph is not exact");
  const dependencies = transport.dependencies.map((dependency) => ({
    name: dependency.name,
    req: dependency.req,
    source: dependency.source,
    usesDefaultFeatures: dependency.uses_default_features,
    features: dependency.features,
  }));
  if (JSON.stringify(dependencies) !== JSON.stringify([
    { name: "keep-native-protocol", req: "*", source: null, usesDefaultFeatures: true, features: [] },
    { name: "nix", req: "=0.31.3", source: "registry+https://github.com/rust-lang/crates.io-index", usesDefaultFeatures: false, features: ["fs", "poll", "socket", "uio", "user"] },
    { name: "rustix", req: "=1.1.4", source: "registry+https://github.com/rust-lang/crates.io-index", usesDefaultFeatures: false, features: ["net", "std"] },
  ])) fail(`metadata dependencies are not exact: ${JSON.stringify(dependencies)}`);
  const evidenceDependencies = evidence.dependencies.map((dependency) => ({
    name: dependency.name,
    req: dependency.req,
    source: dependency.source,
    usesDefaultFeatures: dependency.uses_default_features,
    features: dependency.features,
  }));
  if (JSON.stringify(evidenceDependencies) !== JSON.stringify([
    { name: "keep-native-protocol", req: "*", source: null, usesDefaultFeatures: true, features: [] },
  ])) fail(`P2-D2 evidence dependencies are not exact: ${JSON.stringify(evidenceDependencies)}`);
  const linuxAbiDependencies = linuxAbi.dependencies.map((dependency) => ({
    name: dependency.name,
    req: dependency.req,
    source: dependency.source,
    usesDefaultFeatures: dependency.uses_default_features,
    features: dependency.features,
  }));
  if (JSON.stringify(linuxAbiDependencies) !== JSON.stringify([
    { name: "libc", req: "=0.2.189", source: "registry+https://github.com/rust-lang/crates.io-index", usesDefaultFeatures: true, features: [] },
  ])) fail(`linux-abi dependencies are not exact: ${JSON.stringify(linuxAbiDependencies)}`);
  const p2SupervisorDependencies = p2Supervisor.dependencies.map((dependency) => ({
    name: dependency.name,
    req: dependency.req,
    source: dependency.source,
    usesDefaultFeatures: dependency.uses_default_features,
    features: dependency.features,
  }));
  if (JSON.stringify(p2SupervisorDependencies) !== JSON.stringify([
    { name: "keep-native-linux-abi", req: "*", source: null, usesDefaultFeatures: true, features: [] },
    { name: "keep-native-protocol", req: "*", source: null, usesDefaultFeatures: true, features: [] },
  ])) fail(`P2-D2 supervisor dependencies are not exact: ${JSON.stringify(p2SupervisorDependencies)}`);
  const productionResolverDependencies = productionResolver.dependencies.map((dependency) => ({
    name: dependency.name,
    req: dependency.req,
    source: dependency.source,
    usesDefaultFeatures: dependency.uses_default_features,
    features: dependency.features,
  }));
  if (JSON.stringify(productionResolverDependencies) !== JSON.stringify([
    { name: "keep-native-linux-abi", req: "*", source: null, usesDefaultFeatures: true, features: [] },
    { name: "keep-native-protocol", req: "*", source: null, usesDefaultFeatures: true, features: [] },
  ])) fail(`production resolver dependencies are not exact: ${JSON.stringify(productionResolverDependencies)}`);
  const proberLauncherDependencies = proberLauncher.dependencies.map((dependency) => ({
    name: dependency.name,
    req: dependency.req,
    source: dependency.source,
    usesDefaultFeatures: dependency.uses_default_features,
    features: dependency.features,
  }));
  if (JSON.stringify(proberLauncherDependencies) !== JSON.stringify([
    { name: "keep-native-linux-abi", req: "*", source: null, usesDefaultFeatures: true, features: [] },
    { name: "keep-native-protocol", req: "*", source: null, usesDefaultFeatures: true, features: [] },
  ])) fail(`PROBER launcher dependencies are not exact: ${JSON.stringify(proberLauncherDependencies)}`);
  const proberVmmShimDependencies = proberVmmShim.dependencies.map((dependency) => ({
    name: dependency.name,
    req: dependency.req,
    source: dependency.source,
    usesDefaultFeatures: dependency.uses_default_features,
    features: dependency.features,
  }));
  if (JSON.stringify(proberVmmShimDependencies) !== JSON.stringify([
    { name: "keep-native-linux-abi", req: "*", source: null, usesDefaultFeatures: true, features: [] },
  ])) fail(`PROBER VMM shim dependencies are not exact: ${JSON.stringify(proberVmmShimDependencies)}`);
  const targets = [...protocol.targets, ...transport.targets, ...evidence.targets, ...linuxAbi.targets, ...p2Supervisor.targets, ...productionResolver.targets, ...proberLauncher.targets, ...proberVmmShim.targets].map((target) => ({
    name: target.name,
    kind: target.kind,
    crate_types: target.crate_types,
  }));
  if (
    JSON.stringify(targets) !==
    JSON.stringify([
      { name: "keep_native_protocol", kind: ["lib"], crate_types: ["lib"] },
      {
        name: "keep-native-protocol-oracle",
        kind: ["bin"],
        crate_types: ["bin"],
      },
      { name: "keep_native_transport", kind: ["lib"], crate_types: ["lib"] },
      { name: "keep-native-client", kind: ["bin"], crate_types: ["bin"] },
      { name: "keep-native-supervisor", kind: ["bin"], crate_types: ["bin"] },
      { name: "refusal_exchange", kind: ["test"], crate_types: ["bin"] },
      { name: "keep_native_p2_d2_evidence", kind: ["lib"], crate_types: ["lib"] },
      { name: "keep-native-p2-d2-overlay-oracle", kind: ["bin"], crate_types: ["bin"] },
      { name: "keep_native_linux_abi", kind: ["lib"], crate_types: ["lib"] },
      { name: "landlock", kind: ["test"], crate_types: ["bin"] },
      { name: "seccomp", kind: ["test"], crate_types: ["bin"] },
      { name: "keep_native_p2_d2_supervisor", kind: ["lib"], crate_types: ["lib"] },
      { name: "keep-native-p2-d2-build-cell", kind: ["bin"], crate_types: ["bin"] },
      { name: "keep-native-p2-d2-supervisor", kind: ["bin"], crate_types: ["bin"] },
      { name: "keep-native-patch-capture", kind: ["bin"], crate_types: ["bin"] },
      { name: "keep_native_production_resolver", kind: ["lib"], crate_types: ["lib"] },
      { name: "keep-native-production-resolver-probe", kind: ["bin"], crate_types: ["bin"] },
      { name: "keep_native_prober_launcher", kind: ["lib"], crate_types: ["lib"] },
      { name: "keep-native-prober-launch-candidate", kind: ["bin"], crate_types: ["bin"] },
      { name: "keep_native_prober_vmm_shim", kind: ["lib"], crate_types: ["lib"] },
      { name: "keep-native-prober-vmm-shim", kind: ["bin"], crate_types: ["bin"] },
    ])
  )
    fail(`metadata targets are not exact: ${JSON.stringify(targets)}`);
  if (verify) {
    // Force Cargo's authenticated vendor traversal before any content-derived
    // artifact check so an altered vendored byte is diagnosed at its source.
    run(
      [
        "build", "--locked", "--offline", "--frozen", "--target", lock.target,
        "-p", "keep-native-transport", "--lib",
      ],
      "inherit",
    );
    run(
      [
        "build", "--locked", "--offline", "--frozen", "--target", lock.target,
        "-p", "keep-native-prober-vmm-shim", "--bin", "keep-native-prober-vmm-shim",
      ],
      "inherit",
    );
    const builtShim = join(nativeRoot, "target", lock.target, "debug", "keep-native-prober-vmm-shim");
    const installedShim = `${builtShim}.installed`;
    const temporaryShim = `${installedShim}.new`;
    rmSync(temporaryShim, { force: true });
    copyFileSync(builtShim, temporaryShim, constants.COPYFILE_EXCL);
    chmodSync(temporaryShim, 0o555);
    const temporaryFd = openSync(temporaryShim, constants.O_RDONLY | constants.O_NOFOLLOW);
    fsyncSync(temporaryFd);
    closeSync(temporaryFd);
    renameSync(temporaryShim, installedShim);
    const installedDirectoryFd = openSync(dirname(installedShim), constants.O_RDONLY | constants.O_DIRECTORY);
    fsyncSync(installedDirectoryFd);
    closeSync(installedDirectoryFd);
    const launcherSource = read(join(nativeRoot, "crates/prober-launcher/src/lib.rs"));
    const expectedMatch = launcherSource.match(/keep-native-prober-vmm-shim\.installed"[\s\S]{0,300}?"([0-9a-f]{64})"/);
    if (!expectedMatch) fail("launcher installed-shim measurement is absent or ambiguous");
    verifyInstalledShim(installedShim, expectedMatch[1]);
    const mutant = `${installedShim}.mutant`;
    copyFileSync(installedShim, mutant, constants.COPYFILE_EXCL);
    chmodSync(mutant, 0o555);
    const mutantBytes = readFileSync(mutant);
    mutantBytes[0] ^= 1;
    writeFileSync(mutant, mutantBytes);
    let mutantRefused = false;
    try { verifyInstalledShim(mutant, expectedMatch[1]); } catch { mutantRefused = true; }
    rmSync(mutant, { force: true });
    if (!mutantRefused) fail("installed-shim substitution mutant was accepted");
    run(
      [
        "build", "--locked", "--offline", "--frozen", "--target", lock.target,
        "-p", "keep-native-prober-launcher", "--features", "candidate-probe",
        "--bin", "keep-native-prober-launch-candidate",
      ],
      "inherit",
    );
    run(
      ["test", "--locked", "--offline", "--frozen", "--target", lock.target],
      "inherit",
    );
    run(
      [
        "test", "--locked", "--offline", "--frozen", "--target", lock.target,
        "-p", "keep-native-prober-launcher", "--features", "candidate-probe", "--lib",
      ],
      "inherit",
    );
    run(
      [
        "build",
        "--locked",
        "--offline",
        "--frozen",
        "--target",
        lock.target,
        "--bin",
        "keep-native-protocol-oracle",
      ],
      "inherit",
    );
    run(
      [
        "build",
        "--locked",
        "--offline",
        "--frozen",
        "--target",
        lock.target,
        "--bin",
        "keep-native-p2-d2-overlay-oracle",
      ],
      "inherit",
    );
    run(
      [
        "build", "--release", "--locked", "--offline", "--frozen",
        "--target", lock.target, "-p", "keep-native-transport", "--bins",
      ],
      "inherit",
    );
  }
} finally {
  rmSync(cargoHome, { recursive: true, force: true });
}
console.log(
  `[native-p1-gate] OK — pinned ${lock.toolchain} identities; exact protocol+transport+P2-D2 evidence+Linux ABI+production resolver+non-authorizing PROBER launch-candidate config/metadata/vendor graph; separately gated P2 candidate excluded; sanitized build env; unsafe code confined to fifty-six documented linux-abi ownership/syscall sites; all other Keep crates forbid unsafe/build scripts; dependency unsafe/build machinery remains explicitly non-admitted${verify ? "; tests+oracles+release transport binaries and candidate refusal probe built" : ""}`,
);
