import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureInstalledBackup, verifyInstalledBackup } from "../src/backup/installed_backup_capture.js";
import { composeLifecycle } from "../src/lifecycle/compose_lifecycle.js";

function fixture(): { product: string; state: string } {
  const base = mkdtempSync(join(tmpdir(), "keep-capture-"));
  const product = join(base, "installed"), state = join(base, "state");
  mkdirSync(product); mkdirSync(state);
  writeFileSync(join(product, "keep.js"), "installed product");
  writeFileSync(join(state, "chain.jsonl"), "durable state");
  return { product, state };
}

test("OPS-04 captures installed product and owned state with a verified deterministic inventory", async () => {
  const { product, state } = fixture();
  const capture = await captureInstalledBackup({ installedRoot: product, stateRoot: state, nowMs: 10 });
  assert.equal(capture.verified, true);
  assert.equal(verifyInstalledBackup(capture), true);
  assert.deepEqual(capture.files.map((file) => `${file.scope}:${file.path}`), ["product:keep.js", "state:chain.jsonl"]);
  assert.equal((await captureInstalledBackup({ installedRoot: product, stateRoot: state, nowMs: 20 })).id, capture.id, "time does not change the content address");
  assert.equal(composeLifecycle().captureInstalledBackup, captureInstalledBackup, "capture is reachable through the existing lifecycle surface");
});

test("OPS-04 excludes credentials, git control data, and nested unrelated repositories with an inventory record", async () => {
  const { product, state } = fixture();
  writeFileSync(join(state, ".env"), "TOKEN=raw-secret");
  writeFileSync(join(state, "notes.txt"), "ghp_abcdefghijklmnopqrstuvwxyz123456");
  mkdirSync(join(product, ".git")); writeFileSync(join(product, ".git", "config"), "remote secret");
  const nested = join(state, "foreign-project"); mkdirSync(nested); mkdirSync(join(nested, ".git")); writeFileSync(join(nested, "work.txt"), "user repository");
  const capture = await captureInstalledBackup({ installedRoot: product, stateRoot: state });
  assert.equal(verifyInstalledBackup(capture), true);
  assert.deepEqual(capture.exclusions.map((entry) => `${entry.scope}:${entry.path}:${entry.reason}`), [
    "product:.git:git-control", "state:.env:credential-path", "state:foreign-project:nested-repository", "state:notes.txt:credential-content",
  ]);
  assert.ok(!capture.files.some((file) => file.path.includes("foreign-project") || file.path === ".env" || file.path === "notes.txt"));
});

test("OPS-04 refuses ambiguous roots and symlink escape paths", async () => {
  const { product, state } = fixture();
  await assert.rejects(captureInstalledBackup({ installedRoot: product, stateRoot: product }), /disjoint/);
  symlinkSync("/etc/passwd", join(state, "escape"));
  await assert.rejects(captureInstalledBackup({ installedRoot: product, stateRoot: state }), /symbolic link/);
});

test("OPS-04 transported capture verification detects content or inventory tampering", async () => {
  const { product, state } = fixture();
  const capture = await captureInstalledBackup({ installedRoot: product, stateRoot: state });
  const files = capture.files.map((file, index) => index === 0 ? { ...file, contentBase64: Buffer.from("tampered").toString("base64") } : file);
  assert.equal(verifyInstalledBackup({ ...capture, files }), false);
  assert.equal(verifyInstalledBackup({ ...capture, exclusions: [...capture.exclusions, { scope: "state", path: "x", reason: "credential-path" }] }), false);
  assert.equal(verifyInstalledBackup({ ...capture, exclusions: [{ scope: "state", path: "../escape", reason: "credential-path" }] }), false);
});
