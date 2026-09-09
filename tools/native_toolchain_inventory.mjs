#!/usr/bin/env node
/** Generate/verify the A6 P1 development toolchain closure inventory. */
import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(
  process.argv.find((arg, index) => index > 1 && !arg.startsWith("--")) ??
    fileURLToPath(new URL("..", import.meta.url)),
);
const rustupHome = process.env.RUSTUP_HOME ?? join(homedir(), ".rustup");
const toolchain = "1.97.1-x86_64-unknown-linux-gnu";
const host = "x86_64-unknown-linux-gnu";
const root = realpathSync(
  process.env.KEEP_P1_TOOLCHAIN_ROOT ??
    join(rustupHome, "toolchains", toolchain),
);
// Authenticate the executed build perimeter, not rustup's mutable installation
// history. The root rustlib metadata (components, manifests, multirust config) and
// debugger helpers are neither executed nor read by Keep's direct cargo/rustc/lld
// invocation. Including them made identical official toolchains differ by install
// order and extension bookkeeping while every executable/library byte matched.
const selected = [];
for (const name of ["cargo", "rustc", "rustdoc", "rustfmt"])
  selected.push(join(root, "bin", name));
const walk = (directory) => {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    const status = lstatSync(path);
    if (status.isSymbolicLink())
      throw new Error(`toolchain symlink refused: ${path}`);
    if (status.isDirectory()) walk(path);
    else if (status.isFile()) selected.push(path);
    else throw new Error(`special toolchain entry refused: ${path}`);
  }
};
for (const name of readdirSync(join(root, "lib"))) {
  const path = join(root, "lib", name);
  const status = lstatSync(path);
  if (status.isFile()) selected.push(path);
  else if (status.isSymbolicLink()) throw new Error(`toolchain symlink refused: ${path}`);
}
for (const directory of [
  join(root, "lib/rustlib", host, "bin"),
  join(root, "lib/rustlib", host, "lib"),
  join(root, "lib/rustlib", "x86_64-unknown-linux-musl", "lib"),
])
  walk(directory);
const unique = [...new Set(selected.map((path) => realpathSync(path)))].sort();
const entries = unique.map((path) => {
  if (!path.startsWith(`${root}/`) || !statSync(path).isFile())
    throw new Error(`toolchain containment/type refused: ${path}`);
  const bytes = readFileSync(path);
  return {
    path: relative(root, path),
    size: bytes.byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
});
const rootHash = createHash("sha256");
for (const entry of entries)
  rootHash.update(`${entry.path}\0${entry.size}\0${entry.sha256}\n`);
const inventory = {
  schema: "keep.native-p1-toolchain-inventory",
  version: 2,
  toolchain,
  host,
  target: "x86_64-unknown-linux-musl",
  perimeter: "direct-build-executables-compiler-runtime-host-and-target-libraries",
  rootDigest: rootHash.digest("hex"),
  entries,
};
const target = join(repositoryRoot, "native/toolchain-inventory.json");
if (process.argv.includes("--write")) {
  writeFileSync(target, `${JSON.stringify(inventory, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o644,
  });
  console.log(
    `[native-toolchain-inventory] wrote ${entries.length} files, ${inventory.rootDigest}`,
  );
} else {
  const expected = JSON.parse(readFileSync(target, "utf8"));
  if (JSON.stringify(expected) !== JSON.stringify(inventory))
    throw new Error("native P1 toolchain closure inventory mismatch");
  console.log(
    `[native-toolchain-inventory] OK — ${entries.length} files, ${inventory.rootDigest}`,
  );
}
