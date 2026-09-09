#!/usr/bin/env node
import assert from "node:assert/strict";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function removeReadOnlyTree(path) {
  if (!existsSync(path)) return;
  const status = lstatSync(path);
  if (status.isSymbolicLink()) {
    rmSync(path, { force: true });
    return;
  }
  if (status.isDirectory()) {
    chmodSync(path, status.mode | 0o700);
    for (const name of readdirSync(path)) removeReadOnlyTree(join(path, name));
  } else if (status.isFile()) chmodSync(path, status.mode | 0o600);
  else throw new Error(`clean refused special filesystem entry: ${path}`);
  rmSync(path, { force: true, recursive: status.isDirectory() });
}

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--self-test")) {
    const fixture = mkdtempSync(join(tmpdir(), "keep-clean-readonly-"));
    const outside = join(fixture, "outside"), target = join(fixture, "dist");
    mkdirSync(join(target, "native"), { recursive: true });
    writeFileSync(outside, "preserve\n");
    writeFileSync(join(target, "native", "artifact"), "binary\n", { mode: 0o444 });
    symlinkSync(outside, join(target, "outside-link"));
    chmodSync(join(target, "native"), 0o555); chmodSync(target, 0o555);
    removeReadOnlyTree(target);
    assert.equal(existsSync(target), false);
    assert.equal(existsSync(outside), true);
    rmSync(fixture, { recursive: true, force: true });
    console.log("clean: self-test OK");
  } else removeReadOnlyTree(join(repositoryRoot, "dist"));
}
