import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The deliberately distributed reference data/source/notices, not executable test ports.
export const NATIVE_REFERENCE_MEMBERS = [
  "test/fixtures/native_p2_canonical_parity_v1.cbor",
  "native/Cargo.toml", "native/Cargo.lock", "native/toolchain-inventory.json", "native/toolchain-lock.json",
  "native/crates/protocol/Cargo.toml", "native/crates/p2-d2-evidence/Cargo.toml",
  ...["gzip.rs", "lib.rs", "main.rs", "p2_d2.rs", "p2_schema_specs.rs", "p2_schema.rs", "patch_capture.rs"]
    .map(name => "native/crates/protocol/src/" + name),
  ...["audit_plan.rs", "lib.rs", "main.rs"].map(name => "native/crates/p2-d2-evidence/src/" + name),
  ...["README.md", "rust-1.97.1-COPYRIGHT-library.html", "musl-1.2.5-COPYRIGHT.txt",
    "compiler-builtins-LICENSE.txt", "libm-LICENSE.txt", "compiler-rt-LICENSE.txt",
    "compiler-rt-CREDITS.txt", "libunwind-LICENSE.txt"].map(name => "native/licenses/" + name),
].sort();

export function assertNativeReferenceMembers(paths: readonly string[]): void {
  assert.ok(paths.length > 0, "package membership is empty");
  assert.equal(new Set(paths).size, paths.length, "duplicate package members");
  for (const path of paths) {
    assert.equal(typeof path, "string");
    assert.ok(!path.includes("\\") && !path.includes("\0") &&
      path.split("/").every(part => part !== "" && part !== "." && part !== ".."), "invalid package member");
  }
  const actual = paths.filter(path => /^(?:test|native|dist\/test)\//u.test(path)).sort();
  assert.deepEqual(actual, NATIVE_REFERENCE_MEMBERS, "native/reference package boundary differs");
}

/** Let npm resolve its own files rules. This is not a prepack or installed-artifact test. */
export function resolvedPackageMembers(root: string): string[] {
  const scratch = mkdtempSync(join(tmpdir(), "keep-native-packlist-"));
  try {
    for (const name of ["user.npmrc", "global.npmrc"]) writeFileSync(join(scratch, name), "");
    const output = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts", "--offline", "--no-audit", "--no-fund"], {
      cwd: root, encoding: "utf8", timeout: 30000, maxBuffer: 4 * 1024 * 1024,
      env: { PATH: process.env.PATH, LANG: "C", npm_config_cache: join(scratch, "cache"),
        npm_config_userconfig: join(scratch, "user.npmrc"), npm_config_globalconfig: join(scratch, "global.npmrc") },
    });
    const rows: unknown = JSON.parse(output);
    assert.ok(Array.isArray(rows) && rows.length === 1 && rows[0] && Array.isArray(rows[0].files), "invalid npm pack record");
    const paths = rows[0].files.map((row: { path?: unknown }) => {
      assert.ok(row && typeof row.path === "string", "invalid npm pack file record"); return row.path;
    });
    assertNativeReferenceMembers(paths);
    return paths;
  } finally { rmSync(scratch, { recursive: true, force: true }); }
}
