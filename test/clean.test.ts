import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

test("portable clean removes immutable package output without following symlinks", () => {
  const result = spawnSync(process.execPath, [join(process.cwd(), "tools", "clean.mjs"), "--self-test"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /self-test OK/u);
});
