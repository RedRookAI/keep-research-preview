import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createPublicKey, verify } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const gate = fileURLToPath(new URL("../../tools/native_p2_dependency_gate.mjs", import.meta.url));
const archiveSnapshotHelper = fileURLToPath(new URL("../../tools/native_p2_archive_snapshot.mjs", import.meta.url));

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), "keep-p2-dependency-neuter-"));
  mkdirSync(join(root, "native"), { recursive: true });
  for (const name of [
    "vendor-p2",
    "p2-crypto-crates",
    "p2-crypto-candidate",
    "p2-crypto-THIRD_PARTY_LICENSES.txt",
    "p2-crypto-vendor-inventory.json",
    "toolchain-inventory.json",
  ])
    cpSync(join(repositoryRoot, "native", name), join(root, "native", name), {
      recursive: true,
    });
  return root;
}

function run(root: string, extra: NodeJS.ProcessEnv = {}, write = false) {
  return spawnSync(process.execPath, [gate, root, ...(write ? ["--write"] : [])], {
    encoding: "utf8",
    env: { ...process.env, ...extra },
  });
}

test("A6 P2 dependency closure rejects vendor, candidate, transcript, and ambient build neuters", () => {
  const mutations = [
    (root: string) => {
      const path = join(root, "native/vendor-p2/ed25519-dalek/src/verifying.rs");
      writeFileSync(path, `${readFileSync(path, "utf8")}\n// neuter\n`);
    },
    (root: string) => {
      const path = join(root, "native/p2-crypto-candidate/Cargo.toml");
      writeFileSync(path, `${readFileSync(path, "utf8")}\n# graph neuter\n`);
    },
    (root: string) => {
      const path = join(root, "native/p2-crypto-candidate/src/lib.rs");
      writeFileSync(path, `${readFileSync(path, "utf8")}\npub fn authorizing() {}\n`);
    },
    (root: string) => {
      const path = join(root, "native/p2-crypto-vendor-inventory.json");
      const before = readFileSync(path, "utf8");
      const value = JSON.parse(before);
      value.buildTranscript = value.buildTranscript.filter(
        (row: { name: string }) => row.name !== "curve25519-dalek",
      );
      const after = `${JSON.stringify(value, null, 2)}\n`;
      assert.notEqual(after, before, "build-transcript neuter must change the fixture");
      writeFileSync(path, after);
    },
    (root: string) => {
      const path = join(root, "native/p2-crypto-vendor-inventory.json");
      const before = readFileSync(path, "utf8");
      const value = JSON.parse(before);
      assert.deepEqual(value.activeProcMacros, [], "fiat baseline has no active proc macro");
      value.activeProcMacros = ["curve25519-dalek-derive-0.1.1/src/lib.rs"];
      const after = `${JSON.stringify(value, null, 2)}\n`;
      assert.notEqual(after, before, "active-proc-macro neuter must change the fixture");
      writeFileSync(path, after);
    },
    (root: string) => {
      const path = join(root, "native/p2-crypto-vendor-inventory.json");
      const before = readFileSync(path, "utf8");
      const value = JSON.parse(before);
      assert.ok(value.activeUnsafeDiagnostics.length > 0, "unsafe baseline must be nonempty");
      value.activeUnsafeDiagnostics = value.activeUnsafeDiagnostics.slice(1);
      const after = `${JSON.stringify(value, null, 2)}\n`;
      assert.notEqual(after, before, "active-unsafe neuter must change the fixture");
      writeFileSync(path, after);
    },
    (root: string) => {
      const path = join(root, "native/p2-crypto-vendor-inventory.json");
      const value = JSON.parse(readFileSync(path, "utf8"));
      assert.ok(value.packageResolutionRoles.length > 0, "role baseline must be nonempty");
      value.packageResolutionRoles = value.packageResolutionRoles.slice(1);
      writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
    },
    (root: string) => {
      const path = join(root, "native/p2-crypto-vendor-inventory.json");
      const value = JSON.parse(readFileSync(path, "utf8"));
      assert.equal(value.backendProof.requestedBackend, "fiat");
      value.backendProof.requestedBackend = "serial";
      writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
    },
    (root: string) => {
      const path = join(root, "native/p2-crypto-vendor-inventory.json");
      const value = JSON.parse(readFileSync(path, "utf8"));
      assert.ok(value.buildObservation.execveRows.length > 0, "trace baseline must be nonempty");
      value.buildObservation.execveRows = value.buildObservation.execveRows.slice(1);
      writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
    },
    (root: string) => {
      const path = join(root, "native/p2-crypto-THIRD_PARTY_LICENSES.txt");
      writeFileSync(path, `${readFileSync(path, "utf8")}\nattribution neuter\n`);
    },
  ];
  // All mutation fixtures are byte-for-byte copies produced by fixture(). Prove that common baseline once;
  // rerunning the same expensive Rust/toolchain campaign before every mutation adds no independent signal.
  const control = fixture();
  try {
    const baseline = run(control);
    assert.equal(baseline.status, 0, baseline.stderr);
    assert.match(baseline.stdout, /non-authorizing/);
  } finally {
    rmSync(control, { recursive: true, force: true });
  }
  for (const [index, mutate] of mutations.entries()) {
    const root = fixture();
    try {
      mutate(root);
      const result = run(root);
      assert.notEqual(result.status, 0, `gate accepted dependency mutation ${index}`);
      assert.match(
        `${result.stdout}\n${result.stderr}`,
        /dependency\/build closure differs from frozen inventory|distribution attribution differs|listed checksum[\s\S]*has changed|authenticated crate archive(?: checksum mismatch|\/vendor byte reconciliation failed)/,
        `mutation ${index} did not reach the frozen-inventory comparison`,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
  const root = fixture();
  try {
    const baseline = run(root);
    assert.equal(baseline.status, 0, baseline.stderr);
    const result = run(root, { RUSTC_WRAPPER: "/tmp/evil" });
    assert.notEqual(result.status, 0, "gate accepted ambient build wrapper");
    assert.match(result.stderr, /ambient build injection variable refused: RUSTC_WRAPPER/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("A6 P2 authenticated crate carrier set is exact and closed", () => {
  const root = fixture();
  const archives = join(root, "native/p2-crypto-crates");
  const reset = () => {
    rmSync(archives, { recursive: true, force: true });
    cpSync(join(repositoryRoot, "native/p2-crypto-crates"), archives, { recursive: true });
  };
  try {
    const baseline = run(root);
    assert.equal(baseline.status, 0, baseline.stderr);
    const variants = [
      () => writeFileSync(join(archives, "extra-0.0.0.crate"), "extra"),
      () => rmSync(join(archives, "ed25519-dalek-3.0.0.crate")),
      () => {
        rmSync(join(archives, "ed25519-dalek-3.0.0.crate"));
        symlinkSync(
          join(repositoryRoot, "native/p2-crypto-crates/ed25519-dalek-3.0.0.crate"),
          join(archives, "ed25519-dalek-3.0.0.crate"),
        );
      },
      () => {
        const result = spawnSync("mkfifo", [join(archives, "special-0.0.0.crate")]);
        assert.equal(result.status, 0, result.stderr?.toString());
      },
      () => {
        const path = join(archives, "ed25519-dalek-3.0.0.crate");
        const bytes = readFileSync(path);
        assert.ok(bytes.length > 0);
        bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
        writeFileSync(path, bytes);
      },
    ];
    for (const [index, mutate] of variants.entries()) {
      reset();
      mutate();
      const result = run(root);
      assert.notEqual(result.status, 0, `carrier mutation ${index} remained green`);
      assert.match(
        result.stderr,
        /crate archive directory is not the exact|symlink refused|special file refused|authenticated crate archive checksum mismatch/,
      );
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("A6 npm package ships declared native runtime and inspection inputs, never experimental builds or vendor trees", () => {
  const result = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    timeout: 30000,
    env: { ...process.env, npm_config_offline: "true", npm_config_update_notifier: "false" },
  });
  assert.equal(result.status, 0, result.stderr);
  const rows = JSON.parse(result.stdout) as { files: { path: string }[] }[];
  const paths = rows[0]?.files.map((row) => row.path) ?? [];
  // Runtime inspection needs the protocol/evidence sources and frozen inventories.
  // This is the binary npm distribution, not the complete source-preview snapshot.
  assert.deepEqual(paths.filter((path) => path.startsWith("native/")).sort(), [
    "native/Cargo.lock",
    "native/Cargo.toml",
    "native/crates/p2-d2-evidence/Cargo.toml",
    "native/crates/p2-d2-evidence/src/audit_plan.rs",
    "native/crates/p2-d2-evidence/src/lib.rs",
    "native/crates/p2-d2-evidence/src/main.rs",
    "native/crates/protocol/Cargo.toml",
    "native/crates/protocol/src/gzip.rs",
    "native/crates/protocol/src/lib.rs",
    "native/crates/protocol/src/main.rs",
    "native/crates/protocol/src/p2_d2.rs",
    "native/crates/protocol/src/p2_schema.rs",
    "native/crates/protocol/src/p2_schema_specs.rs",
    "native/crates/protocol/src/patch_capture.rs",
    "native/licenses/README.md",
    "native/licenses/rust-1.97.1-COPYRIGHT-library.html",
    "native/licenses/musl-1.2.5-COPYRIGHT.txt",
    "native/licenses/compiler-builtins-LICENSE.txt",
    "native/licenses/libm-LICENSE.txt",
    "native/licenses/compiler-rt-LICENSE.txt",
    "native/licenses/compiler-rt-CREDITS.txt",
    "native/licenses/libunwind-LICENSE.txt",
    "native/toolchain-inventory.json",
    "native/toolchain-lock.json",
  ].sort());
  for (const path of paths)
    assert.doesNotMatch(path, /(?:^|\/)(?:vendor-p2|vendor-transport|p2-crypto-candidate|p2-crypto-crates|target)(?:\/|$)/u);
  assert.deepEqual(
    paths.filter((path) => path.startsWith("dist/native/")).sort(),
    [
      "dist/native/linux-x64/capture-manifest.json",
      "dist/native/linux-x64/keep-native-client",
      "dist/native/linux-x64/keep-native-patch-capture",
      "dist/native/linux-x64/keep-native-supervisor",
      "dist/native/linux-x64/keep-native-supervisor.sha256",
      "dist/native/linux-x64/manifest.json",
    ],
  );
  for (const path of ["LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.txt", "docs/licensing.md"])
    assert.ok(paths.includes(path), `distribution missing required attribution entry ${path}`);
});

test("A6 P2 producer-side unsafe, role, and backend neuters redden named controls", () => {
  const original = readFileSync(gate, "utf8");
  const variants = [
    {
      from: 'row.reason === "compiler-message" &&',
      to: 'false && row.reason === "compiler-message" &&',
      reason: /forced unsafe diagnostic inventory was vacuously empty/,
    },
    {
      from: 'if (pkg.id === candidateId) roles.push("candidate");',
      to: 'if (pkg.id === candidateId) roles.push("resolved-dormant");',
      reason: /compiled unit lacks an active compilation role|compilation unit\/role mismatch/,
    },
    {
      from: '? "host-build-script"',
      to: '? "target-runtime-library"',
      reason: /compilation unit kind\/role equation failed/,
    },
    {
      from: '? "test-unit"',
      to: '? "target-runtime-library"',
      reason: /compilation unit kind\/role equation failed/,
    },
    {
      from: "const hostCell = unit.outputs.every",
      to: "const hostCell = false && unit.outputs.every",
      reason: /compilation unit\/role mismatch/,
    },
    {
      from: "const hostCell = unit.outputs.every",
      to: "const hostCell = unit.profile.test || unit.outputs.every",
      reason: /compilation unit\/role mismatch/,
    },
    {
      from: 'unit.packageId === normalizedCandidateId',
      to: "false",
      reason: /compilation unit\/role mismatch/,
    },
    {
      from: '--cfg=curve25519_dalek_backend="fiat"',
      to: '--cfg=curve25519_dalek_backend="serial"',
      reason: /fiat curve dep-info proof was not observed|did not prove exact fiat|traced curve invocation did not prove fiat/,
    },
  ];
  for (const [index, variant] of variants.entries()) {
    // Keep mutation fixtures outside the checkout. A verifier may snapshot the
    // worktree while this test is running, so even correctly cleaned temporary
    // files under tools/ would make the tested tree appear to drift.
    const directory = mkdtempSync(join(tmpdir(), "keep-native-p2-producer-neuter-"));
    const path = join(directory, "gate.mjs");
    try {
      const source = original
        .replace(
          'fileURLToPath(new URL("native_toolchain_inventory.mjs", import.meta.url))',
          JSON.stringify(join(repositoryRoot, "tools/native_toolchain_inventory.mjs")),
        )
        .replace(variant.from, variant.to);
      assert.notEqual(source, original, `producer neuter ${index} must change source`);
      writeFileSync(path, source);
      writeFileSync(
        join(directory, "native_p2_archive_snapshot.mjs"),
        readFileSync(archiveSnapshotHelper),
      );
      const result = spawnSync(process.execPath, [path, repositoryRoot], {
        encoding: "utf8",
        env: process.env,
      });
      assert.notEqual(result.status, 0, `producer neuter ${index} remained green`);
      assert.match(result.stderr, variant.reason);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("A6 P2 RFC 8032 positives have an independent Node/OpenSSL signal", () => {
  const vectors = [
    {
      key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      message: "",
      signature:
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
      key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      message: "72",
      signature:
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
      key: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      message: "af82",
      signature:
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
  ];
  for (const row of vectors) {
    const publicKey = createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        Buffer.from(row.key, "hex"),
      ]),
      format: "der",
      type: "spki",
    });
    const message = Buffer.from(row.message, "hex");
    const signature = Buffer.from(row.signature, "hex");
    assert.equal(verify(null, message, publicKey, signature), true);
    signature[0]! ^= 1;
    assert.equal(verify(null, message, publicKey, signature), false);
  }
});
