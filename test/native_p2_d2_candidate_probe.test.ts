import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(process.cwd());
const probe = resolve(repositoryRoot, "tools/native_p2_d2_candidate_probe.mjs");

test("P2-D2 candidate probe confines the real offline Cargo build without granting authority", () => {
  const receipt = JSON.parse(execFileSync(process.execPath, [probe], {
    cwd: repositoryRoot,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  })) as Record<string, unknown>;
  assert.equal(receipt.schema, "keep.p2-d2-candidate-probe-receipt");
  assert.equal(receipt.authorizing, false);
  assert.equal(receipt.resultTreeDigest, "bdcfb687650efcd803e0f4123ab7476b5002a83ec8ebc4aaacc4303cd927a065");
  assert.equal(receipt.derivedCargoLockDigest, "68acd90035f8032cfde4c611ba696eecc569323024721b4a1520275ba3d45fe3");
  assert.equal(receipt.customBuildUnits, 0);
  assert.equal(receipt.procMacroUnits, 0);
  assert.equal(receipt.toolchainInventoryDigest, "ba2e351f3f279a4cbc17cba1e3f74ba9b185275c5802c575e81c630c7cd57dc0");
  const sandbox = receipt.sandbox as Record<string, unknown>;
  assert.equal(sandbox.networkRoutes, 0);
  assert.deepEqual(sandbox.writableRoots, ["candidate-workspace", "private-tmpfs"]);
});

test("P2-D2 candidate probe keeps the sandbox and non-authority assertions fail closed", () => {
  const source = readFileSync(probe, "utf8");
  const supervisor = readFileSync(resolve(repositoryRoot, "native/crates/p2-d2-supervisor/src/supervisor.rs"), "utf8");
  const buildCell = readFileSync(resolve(repositoryRoot, "native/crates/p2-d2-supervisor/src/main.rs"), "utf8");
  for (const required of [
    '"--unshare-all"', '"--clearenv"', '"--ro-bind"', '"--bind"',
    "test ! -e /root", "! touch /outside", "/proc/net/route",
  ]) assert.ok(supervisor.includes(required), `missing native-supervisor fail-closed assertion: ${required}`);
  for (const required of ['"--offline"', '"--frozen"'])
    assert.ok(buildCell.includes(required), `missing build-cell fail-closed assertion: ${required}`);
  for (const required of [
    'authorizing: false', "BWRAP_DIGEST", "TOOLCHAIN_INVENTORY_DIGEST",
    'row.reason === "build-script-executed"', 'target?.kind?.includes("proc-macro")',
  ]) assert.ok(source.includes(required), `missing fail-closed probe assertion: ${required}`);
  assert.ok(!source.includes("process.env.RUSTUP_HOME"), "ambient RUSTUP_HOME still redirects the pinned toolchain");
});
