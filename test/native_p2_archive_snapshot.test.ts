import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const helper = fileURLToPath(new URL("../../tools/native_p2_archive_snapshot.mjs", import.meta.url));

test("P2-D2 archive snapshot remains bound after hostile pathname replacement", () => {
  const result = spawnSync(process.execPath, [helper, "--self-test"], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", TZ: "UTC" },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /single capture survives pathname replacement/);
});

test("P2-D2 archive helper has no pathname-based tar inspection seam", () => {
  const source = readFileSync(helper, "utf8");
  assert.match(source, /O_NOFOLLOW/);
  assert.match(source, /input: carrier/);
  assert.match(source, /"--file=-"/);
  assert.doesNotMatch(source, /execFileSync\(TAR_PATH/);
  assert.doesNotMatch(source, /\["-[tlx][^"\]]*zf",\s*archivePath/);
  const check = (candidate: string): void => {
    assert.match(candidate, /O_NOFOLLOW/);
    assert.match(candidate, /input: carrier/);
    assert.match(candidate, /"--file=-"/);
  };
  for (const mutant of [
    source.replaceAll('input: carrier,', 'input: readFileSync(archivePath),'),
    source.replaceAll('"--file=-"', 'archivePath'),
    source.replaceAll('constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC', 'constants.O_RDONLY'),
  ]) assert.throws(() => check(mutant));
});
