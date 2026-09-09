import { test } from "node:test";
import assert from "node:assert/strict";
import {
  copyFileSync,
  cpSync,
  linkSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const gate = fileURLToPath(
  new URL("../../tools/native_p1_gate.mjs", import.meta.url),
);
const inventoryTool = fileURLToPath(
  new URL("../../tools/native_toolchain_inventory.mjs", import.meta.url),
);
function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), "keep-native-gate-"));
  mkdirSync(join(root, "tools"), { recursive: true });
  copyFileSync(
    join(repositoryRoot, "tools/native_toolchain_inventory.mjs"),
    join(root, "tools/native_toolchain_inventory.mjs"),
  );
  cpSync(
    join(repositoryRoot, "rust-toolchain.toml"),
    join(root, "rust-toolchain.toml"),
  );
  cpSync(join(repositoryRoot, "native"), join(root, "native"), {
    recursive: true,
    filter: (source) =>
      !source.includes(`${join(repositoryRoot, "native", "target")}`) &&
      !source.includes(`${join(repositoryRoot, "native", "vendor-p2")}`) &&
      !source.includes(
        `${join(repositoryRoot, "native", "p2-crypto-candidate")}`,
      ),
  });
  return root;
}
function run(root: string, extra: NodeJS.ProcessEnv = {}) {
  return spawnSync(process.execPath, [gate, root], {
    encoding: "utf8",
    env: { ...process.env, ...extra },
  });
}

test("A6 native workspace gate rejects dependency, build, proc-macro, and hidden-member neuters", () => {
  const mutations = [
    (root: string) =>
      writeFileSync(
        join(root, "native/crates/transport/Cargo.toml"),
        readFileSync(join(root, "native/crates/transport/Cargo.toml"), "utf8") +
          '\nserde = "1"\n',
      ),
    (root: string) =>
      writeFileSync(
        join(root, "native/crates/protocol/Cargo.toml"),
        readFileSync(join(root, "native/crates/protocol/Cargo.toml"), "utf8") +
          "\n[dependencies]\n",
      ),
    (root: string) =>
      writeFileSync(
        join(root, "native/crates/protocol/Cargo.toml"),
        readFileSync(join(root, "native/crates/protocol/Cargo.toml"), "utf8") +
          '\nbuild = "build.rs"\n',
      ),
    (root: string) =>
      writeFileSync(
        join(root, "native/crates/protocol/Cargo.toml"),
        readFileSync(join(root, "native/crates/protocol/Cargo.toml"), "utf8") +
          "\nproc-macro = true\n",
      ),
    (root: string) => {
      mkdirSync(join(root, "native/crates/hidden/src"), { recursive: true });
      writeFileSync(
        join(root, "native/crates/hidden/Cargo.toml"),
        '[package]\nname="hidden"\nversion="0.1.0"\nedition="2024"\n',
      );
      writeFileSync(
        join(root, "native/crates/hidden/src/lib.rs"),
        "pub unsafe fn hidden() {}\n",
      );
    },
    (root: string) =>
      writeFileSync(
        join(root, "native/.cargo/config.toml"),
        readFileSync(join(root, "native/.cargo/config.toml"), "utf8") +
          '\n[build]\nrustc-wrapper="/tmp/evil"\n',
      ),
    (root: string) =>
      writeFileSync(
        join(root, "native/.cargo/config.toml"),
        readFileSync(join(root, "native/.cargo/config.toml"), "utf8") +
          '\n[target.x86_64-unknown-linux-musl]\nrustflags=["-Clinker=/tmp/evil"]\n',
      ),
    (root: string) =>
      writeFileSync(
        join(root, "native/.cargo/config.toml"),
        readFileSync(join(root, "native/.cargo/config.toml"), "utf8") +
          '\n[target.x86_64-unknown-linux-musl]\nrunner="/tmp/evil"\n',
      ),
    (root: string) =>
      writeFileSync(
        join(root, "native/.cargo/config.toml"),
        readFileSync(join(root, "native/.cargo/config.toml"), "utf8") +
          '\n[source.crates-io]\nreplace-with="evil"\n',
      ),
  ];
  for (const [index, mutate] of mutations.entries()) {
    const root = fixture();
    try {
      mutate(root);
      const result = run(root);
      assert.notEqual(result.status, 0, `gate accepted mutation ${index}`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
  for (const [key, value] of [
    ["RUSTC_WRAPPER", "/tmp/evil"],
    ["RUSTFLAGS", "-Clinker=/tmp/evil"],
    ["CARGO", "/tmp/evil"],
  ] as const) {
    const root = fixture();
    try {
      assert.notEqual(
        run(root, { [key]: value }).status,
        0,
        `gate accepted ambient ${key}`,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test("A6 native workspace gate authenticates every vendored transport source byte", () => {
  const root = fixture();
  try {
    const victim = join(root, "native/vendor-transport/nix-0.31.3/src/lib.rs");
    writeFileSync(victim, readFileSync(victim, "utf8") + "\n// hostile mutation\n");
    const result = spawnSync(process.execPath, [gate, root, "--verify"], {
      encoding: "utf8",
      env: process.env,
    });
    assert.notEqual(result.status, 0, "mutated vendored source passed frozen build");
    assert.match(result.stderr, /checksum|failed to calculate checksum/i);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("A6 P1 toolchain closure inventory detects a mutated rustlib before Cargo can run", () => {
  const rustupHome = process.env.RUSTUP_HOME ?? join(homedir(), ".rustup");
  const inventory = JSON.parse(
    readFileSync(
      join(repositoryRoot, "native/toolchain-inventory.json"),
      "utf8",
    ),
  ) as { toolchain: string; entries: { path: string; sha256: string }[] };
  const source = process.env.KEEP_P1_TOOLCHAIN_ROOT ?? join(rustupHome, "toolchains", inventory.toolchain);
  const root = mkdtempSync(join(tmpdir(), "keep-native-toolchain-neuter-"));
  try {
    for (const entry of inventory.entries) {
      const destination = join(root, entry.path);
      mkdirSync(join(destination, ".."), { recursive: true });
      linkSync(join(source, entry.path), destination);
    }
    const victim = inventory.entries.find((entry) =>
      entry.path.endsWith(".rlib"),
    );
    assert.ok(victim, "inventory contains a Rust library");
    const victimPath = join(root, victim.path);
    const privateCopy = `${victimPath}.copy`;
    copyFileSync(victimPath, privateCopy);
    rmSync(victimPath);
    copyFileSync(privateCopy, victimPath);
    rmSync(privateCopy);
    const bytes = readFileSync(victimPath);
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
    writeFileSync(victimPath, bytes);
    const result = spawnSync(process.execPath, [inventoryTool], {
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
        RUSTUP_HOME: rustupHome,
        KEEP_P1_TOOLCHAIN_ROOT: root,
      },
    });
    assert.notEqual(
      result.status,
      0,
      "mutated rustlib passed the complete toolchain inventory before Cargo",
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("A6 P1 toolchain perimeter excludes rustup installation history but retains every executed library", () => {
  const rustupHome = process.env.RUSTUP_HOME ?? join(homedir(), ".rustup");
  const inventory = JSON.parse(
    readFileSync(join(repositoryRoot, "native/toolchain-inventory.json"), "utf8"),
  ) as { toolchain: string; perimeter: string; entries: { path: string }[] };
  assert.equal(inventory.perimeter, "direct-build-executables-compiler-runtime-host-and-target-libraries");
  assert.equal(inventory.entries.some((entry) => entry.path === "lib/rustlib/components"), false);
  assert.equal(inventory.entries.some((entry) => entry.path === "lib/rustlib/multirust-config.toml"), false);
  const source = process.env.KEEP_P1_TOOLCHAIN_ROOT ?? join(rustupHome, "toolchains", inventory.toolchain);
  const root = mkdtempSync(join(tmpdir(), "keep-native-toolchain-metadata-"));
  try {
    for (const entry of inventory.entries) {
      const destination = join(root, entry.path);
      mkdirSync(join(destination, ".."), { recursive: true });
      linkSync(join(source, entry.path), destination);
    }
    mkdirSync(join(root, "lib/rustlib"), { recursive: true });
    writeFileSync(join(root, "lib/rustlib/components"), "arbitrary install ordering\n");
    writeFileSync(join(root, "lib/rustlib/multirust-config.toml"), "install_history = true\n");
    const result = spawnSync(process.execPath, [inventoryTool], {
      encoding: "utf8",
      env: { PATH: "/usr/bin:/bin", RUSTUP_HOME: rustupHome, KEEP_P1_TOOLCHAIN_ROOT: root },
    });
    assert.equal(result.status, 0, result.stderr);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("A6 P1 toolchain location honors explicit root and rustup root without falling back on error", () => {
  const inventory = JSON.parse(readFileSync(join(repositoryRoot, "native/toolchain-inventory.json"), "utf8")) as { toolchain: string; rootDigest: string };
  const configuredRustup = process.env.RUSTUP_HOME ?? join(homedir(), ".rustup");
  const source = realpathSync(process.env.KEEP_P1_TOOLCHAIN_ROOT ?? join(configuredRustup, "toolchains", inventory.toolchain));
  const root = mkdtempSync(join(tmpdir(), "keep-toolchain-location-"));
  try {
    const locatedRustup = join(root, "caller-rustup");
    mkdirSync(join(locatedRustup, "toolchains"), { recursive: true });
    symlinkSync(source, join(locatedRustup, "toolchains", inventory.toolchain), "dir");
    const invoke = (env: NodeJS.ProcessEnv) => spawnSync(process.execPath, [inventoryTool], {
      encoding: "utf8", timeout: 20_000, env: { PATH: "/usr/bin:/bin", ...env },
    });
    const explicit = invoke({ RUSTUP_HOME: join(root, "absent-rustup"), KEEP_P1_TOOLCHAIN_ROOT: source });
    assert.equal(explicit.status, 0, explicit.stderr);
    assert.ok(explicit.stdout.includes(inventory.rootDigest), "selected root must pass the exact inventory, not just exist");
    const located = invoke({ RUSTUP_HOME: locatedRustup });
    assert.equal(located.status, 0, located.stderr);
    assert.ok(located.stdout.includes(inventory.rootDigest));
    const invalidOverride = invoke({ RUSTUP_HOME: locatedRustup, KEEP_P1_TOOLCHAIN_ROOT: join(root, "absent-toolchain") });
    assert.notEqual(invalidOverride.status, 0, "invalid explicit root must not silently fall back to a valid rustup root");
    assert.match(invalidOverride.stderr, /absent-toolchain/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
