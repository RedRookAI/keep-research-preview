import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";

// WIRING PROOF (P0 finish): the lifecycle/backup/integrity bundle is reachable on the composed app.

function app() {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-life-")) });
}

test("composeKeep exposes the lifecycle bundle", () => {
  const l = app().lifecycle;
  assert.equal(typeof l.verifyBackupRestore, "function");
  assert.equal(typeof l.uninstall, "function");
  assert.equal(typeof l.verifyTcb, "function");
});

test("off-machine backup options are FREE-first (never lose your work)", () => {
  const opts = app().lifecycle.offMachineBackupOptions;
  assert.ok(opts.length > 0, "backup targets are offered");
  assert.ok(opts.some((o) => o.free), "at least one free option (e.g. a private git repo)");
  const firstPaidIdx = opts.findIndex((o) => !o.free);
  const firstFreeIdx = opts.findIndex((o) => o.free);
  assert.ok(firstFreeIdx !== -1 && (firstPaidIdx === -1 || firstFreeIdx < firstPaidIdx), "free options are listed before paid ones");
});

test("TCB verification reports drift, never silently passes a mismatch", () => {
  const l = app().lifecycle;
  const good = l.measureModule("export const x = 1;");
  const manifest = { modules: [{ path: "m", pinnedHash: good.hash, allowedDeps: [] }] };
  const drifted = new Map([["m", l.measureModule("export const x = 2; // tampered")]]);
  const v = l.verifyTcb(manifest, drifted);
  assert.equal(v.verified, false, "a drifted module fails verification");
  if (!v.verified) assert.ok(v.drifts.length >= 1);
});
