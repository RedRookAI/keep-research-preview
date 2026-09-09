import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileSystemLock } from "../src/lock/lock.js";

const lockPath = (dir: string, key: string) => join(dir, `${createHash("sha256").update("keep.lock/v1\0").update(key).digest("hex")}.lock`);

test("filesystem lock serializes separate lock instances over one directory", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-fs-lock-"));
  const first = new FileSystemLock(dir, 2_000, 2);
  const second = new FileSystemLock(dir, 2_000, 2);
  let active = 0; let maximum = 0;
  const work = async (lock: FileSystemLock) => lock.withLock("spine.sealer", async () => {
    active++; maximum = Math.max(maximum, active);
    await new Promise((resolve) => setTimeout(resolve, 20));
    active--;
  });
  await Promise.all([work(first), work(second)]);
  assert.equal(maximum, 1);
  assert.equal(existsSync(lockPath(dir, "spine.sealer")), false);
});

test("filesystem lock quarantines a complete dead-owner carrier before proceeding", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-fs-lock-stale-"));
  const path = lockPath(dir, "spine.sealer");
  writeFileSync(path, `${JSON.stringify({ schema: "keep.filesystem-lock/v1", pid: 2_147_483_647, token: "dead" })}\n`, { mode: 0o600 });
  const lock = new FileSystemLock(dir, 1_000, 2);
  let ran = false;
  await lock.withLock("spine.sealer", async () => { ran = true; });
  assert.equal(ran, true);
  assert.equal(existsSync(path), false);
});

test("filesystem lock preserves the primary failure when release also fails", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-fs-lock-dual-failure-"));
  const key = "publication.coordinator";
  const lock = new FileSystemLock(dir, 1_000, 2);
  await assert.rejects(
    () => lock.withLock(key, async () => {
      unlinkSync(lockPath(dir, key));
      throw new Error("primary publication failure");
    }),
    (error: unknown) => error instanceof AggregateError
      && error.errors.some((entry) => entry instanceof Error && entry.message === "primary publication failure")
      && error.errors.some((entry) => entry instanceof Error && /disappeared/.test(entry.message)),
  );
});

test("filesystem lock refuses a permissive carrier immediately instead of timing out then stealing it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-fs-lock-hostile-mode-"));
  const key = "hostile";
  writeFileSync(lockPath(dir, key), `${JSON.stringify({ schema: "keep.filesystem-lock/v1", pid: process.pid, processStart: "x", token: "x" })}\n`, { mode: 0o644 });
  const lock = new FileSystemLock(dir, 2_000, 10);
  const started = Date.now();
  await assert.rejects(() => lock.withLock(key, async () => undefined), /kind\/mode refused/);
  assert.ok(Date.now() - started < 500, "hostile carrier refusal must not wait for the stale timeout");
});
