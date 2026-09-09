import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { nativeProductionResolutionTranscriptDigest } from "../src/platform/native_production_resolution_observation.js";

const observation = () => ({
  authorityRoot: { device: 1n, inode: 2n, mountId: 3n, filesystemType: 4n, uid: 0n, gid: 0n, permissions: 0o555n, readOnly: true },
  payloadRoot: { device: 5n, inode: 6n, mountId: 7n, filesystemType: 8n, uid: 0n, gid: 0n, permissions: 0o555n, readOnly: true },
  manifestLeaf: { device: 1n, inode: 9n, uid: 0n, gid: 0n, mode: 0o100444n, size: 10n },
  deploymentId: "deploy.1", manifestDigest: "ab".repeat(32),
  artifacts: [
    { artifactId: "helper", kind: "helper" as const, digest: "11".repeat(32), leaf: { device: 5n, inode: 11n, uid: 0n, gid: 0n, mode: 0o100555n, links: 1n, size: 1n }, byteLength: 1n },
    { artifactId: "prober", kind: "prober" as const, digest: "22".repeat(32), leaf: { device: 5n, inode: 12n, uid: 0n, gid: 0n, mode: 0o100555n, links: 1n, size: 2n }, byteLength: 2n },
    { artifactId: "provisioner.net", kind: "provisioner" as const, digest: "33".repeat(32), leaf: { device: 5n, inode: 13n, uid: 0n, gid: 0n, mode: 0o100555n, links: 1n, size: 3n }, byteLength: 3n },
    { artifactId: "roles/net", kind: "role" as const, digest: "44".repeat(32), leaf: { device: 5n, inode: 14n, uid: 0n, gid: 0n, mode: 0o100555n, links: 1n, size: 4n }, byteLength: 4n },
    { artifactId: "trampoline", kind: "trampoline" as const, digest: "55".repeat(32), leaf: { device: 5n, inode: 15n, uid: 0n, gid: 0n, mode: 0o100555n, links: 1n, size: 5n }, byteLength: 5n },
  ],
});

test("production observation transcript is total, typed, and mutation-sensitive", () => {
  const original = observation();
  const baseline = nativeProductionResolutionTranscriptDigest(original);
  assert.match(baseline, /^[0-9a-f]{64}$/);
  for (const mutant of [
    { ...original, authorityRoot: { ...original.authorityRoot, mountId: 4n } },
    { ...original, manifestLeaf: { ...original.manifestLeaf, inode: 10n } },
    { ...original, deploymentId: "deploy.2" },
    { ...original, manifestDigest: "cd".repeat(32) },
    { ...original, artifacts: original.artifacts.map((row, index) => index === 0 ? { ...row, byteLength: 2n } : row) },
  ]) assert.notEqual(nativeProductionResolutionTranscriptDigest(mutant), baseline);
  assert.throws(() => nativeProductionResolutionTranscriptDigest({ ...original, artifacts: [...original.artifacts].reverse() }), /artifact projection/);
  assert.throws(() => nativeProductionResolutionTranscriptDigest({ ...original, manifestDigest: "AB".repeat(32) }), /digest/);
  assert.throws(() => nativeProductionResolutionTranscriptDigest({ ...original, artifacts: original.artifacts.map((row, index) => index === 0 ? { ...row, artifactId: ".helper" } : row) }), /artifact identifier/);
  assert.match(nativeProductionResolutionTranscriptDigest({ ...original, artifacts: original.artifacts.map((row, index) => index === 3 ? { ...row, artifactId: "roles//net" } : row) }), /^[0-9a-f]{64}$/);
});

test("native production resolver observes a real read-only mounted PROBER graph", () => {
  const repository = process.cwd();
  const result = spawnSync(
    "/usr/bin/unshare",
    ["--mount", "--propagation", "private", process.execPath, "tools/native_production_resolver_probe.mjs"],
    { cwd: repository, encoding: "utf8", env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" } },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^\[native-production-resolver-probe\] OK — [0-9a-f]{64}\n$/);
});

for (const attack of ["writable-root", "manifest-mode", "manifest-trailing", "manifest-oversize", "manifest-address",
  "development-trust", "duplicate-artifact", "extra-artifact", "artifact-mode", "artifact-symlink", "artifact-digest",
  "artifact-hardlink", "deployment-id", "request-traversal", "root-alias", "root-bind-alias", "root-mount-substitution",
  "ancestor-symlink", "ancestor-mount", "descendant-mount", "authority-descendant-mount"]) {
  test(`native production resolver categorically refuses ${attack}`, () => {
    const result = spawnSync(
      "/usr/bin/unshare",
      ["--mount", "--propagation", "private", process.execPath, "tools/native_production_resolver_probe.mjs"],
      { cwd: process.cwd(), encoding: "utf8", env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", KEEP_RESOLVER_ATTACK: attack } },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `[native-production-resolver-probe] REFUSED — ${attack}\n`);
  });
}
