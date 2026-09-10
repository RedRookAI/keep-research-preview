import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import fsDefault from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { withLogicalAppendLock } from "../src/spine/logical_append_lock.js";
import { FileSpineStore } from "../src/spine/store.js";
import { NODE_IO } from "../src/spine/durable_fs.js";

if (process.argv[2] === "--lock-child") {
  const target = process.argv[3]!;
  try {
    for (let i = 0; i < Number(process.argv[4]); i++) withLogicalAppendLock(target, () => fs.appendFileSync(`${target}.entries`, "entered\n"), { waitMs: 30 });
    console.log("acquired");
  } catch (error) { console.log((error as Error).message); process.exitCode = 3; }
} else {
  const fixture = () => join(fs.mkdtempSync(join(tmpdir(), "keep-append-lock-")), "data");
  const child = (target: string, count = 1) => spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--lock-child", target, String(count)], { encoding: "utf8", timeout: 10000 });

  test("logical append repeated normal release does not consume generations", () => {
    const target = fixture();
    for (let i = 0; i < 1000; i++) withLogicalAppendLock(target, () => {});
    for (let i = 0; i < 8; i++) assert.equal(child(target, 10).status, 0);
    assert.deepEqual(fs.readdirSync(`${target}.append-lock`), []);
    assert.equal(fs.readFileSync(`${target}.entries`, "utf8").trim().split("\n").length, 80);
  });

  test("live owner is not skipped by retirement or an unproven high floor hint", () => {
    const target = fixture(), dir = `${target}.append-lock`;
    withLogicalAppendLock(target, () => {
      const owner = fs.readFileSync(join(dir, "owner-0"));
      fs.writeFileSync(join(dir, "retired-0"), "");
      fs.writeFileSync(join(dir, "floor"), "999\n");
      const result = child(target);
      assert.equal(result.status, 3); assert.match(result.stdout, /contention deadline/);
      assert.equal(fs.existsSync(`${target}.entries`), false);
      assert.equal(fs.readFileSync(join(dir, "owner-0")).equals(owner), true);
      assert.equal(fs.existsSync(join(dir, "drained-0")), false);
    });
    assert.equal(child(target).status, 0);
    assert.equal(fs.existsSync(join(dir, "drained-0")), true);
    assert.equal(fs.readFileSync(join(dir, "floor"), "utf8"), "0\n");
  });

  test("boot identity distinguishes an old owner even if PID and start match now", () => {
    const target = fixture(), dir = `${target}.append-lock`;
    let owner: Record<string, unknown> = {};
    withLogicalAppendLock(target, () => { owner = JSON.parse(fs.readFileSync(join(dir, "owner-0"), "utf8")); });
    assert.equal(typeof owner.boot, "string", "this reboot test qualifies Linux boot identity only");
    owner.boot = "00000000-0000-0000-0000-000000000000";
    fs.writeFileSync(join(dir, "owner-0"), JSON.stringify(owner), { mode: 0o600 });
    assert.equal(child(target).status, 0);
    assert.equal(fs.existsSync(join(dir, "retired-0")), true);
    assert.equal(fs.existsSync(join(dir, "owner-0")), true, "reaper never deletes dead owner");
  });

  test("same-process reentrancy refuses without removing the original owner", () => {
    const target = fixture();
    withLogicalAppendLock(target, () => {
      assert.throws(() => withLogicalAppendLock(target, () => assert.fail("must not enter")), /reentrant/);
      assert.equal(fs.existsSync(`${target}.append-lock/owner-0`), true);
    });
    assert.equal(withLogicalAppendLock(target, () => 42), 42);
  });

  test("foreign-domain owner is retained, not treated as dead", () => {
    const target = fixture(), dir = `${target}.append-lock`; let owner: Record<string, unknown> = {};
    withLogicalAppendLock(target, () => { owner = JSON.parse(fs.readFileSync(join(dir, "owner-0"), "utf8")); });
    owner.namespace = "pid:[0]";
    fs.writeFileSync(join(dir, "owner-0"), JSON.stringify(owner), { mode: 0o600 });
    assert.throws(() => withLogicalAppendLock(target, () => {}), /domain/);
    assert.equal(fs.existsSync(join(dir, "retired-0")), false);
  });

  test("malformed private owner has a recovery diagnostic distinct from contention", () => {
    const target = fixture(), dir = `${target}.append-lock`;
    fs.mkdirSync(dir); fs.writeFileSync(join(dir, "owner-0"), "{broken}", { mode: 0o600 });
    assert.throws(() => withLogicalAppendLock(target, () => {}), { code: "KEEP_LOGICAL_APPEND_RECOVERY_REQUIRED", message: "logical append owner identity JSON is malformed" });
    assert.equal(fs.readFileSync(join(dir, "owner-0"), "utf8"), "{broken}");
    assert.equal(fs.existsSync(join(dir, "retired-0")), false);
  });

  test("malformed boot identity cannot masquerade as positive death of a live owner", () => {
    const target = fixture(), dir = `${target}.append-lock`; let owner: Record<string, unknown> = {};
    withLogicalAppendLock(target, () => { owner = JSON.parse(fs.readFileSync(join(dir, "owner-0"), "utf8")); });
    owner.boot = "";
    fs.writeFileSync(join(dir, "owner-0"), JSON.stringify(owner), { mode: 0o600 });
    assert.throws(() => withLogicalAppendLock(target, () => assert.fail("must not enter")), { code: "KEEP_LOGICAL_APPEND_RECOVERY_REQUIRED" });
    assert.equal(fs.existsSync(join(dir, "retired-0")), false);
  });

  test("retired-generation scanning has a separate deadline and retains useful progress", () => {
    const target = fixture(), dir = `${target}.append-lock`; fs.mkdirSync(dir);
    for (let i = 0; i < 20; i++) { fs.writeFileSync(join(dir, `retired-${i}`), ""); fs.writeFileSync(join(dir, `drained-${i}`), ""); }
    fs.writeFileSync(join(dir, "floor"), "0\n");
    assert.throws(() => withLogicalAppendLock(target, () => assert.fail("zero-budget scan must not reach the head"), { waitMs: 0 }), { code: "KEEP_LOGICAL_APPEND_SCAN_LIMIT" });
    assert.ok(Number(fs.readFileSync(join(dir, "floor"), "utf8")) > 0);
    assert.equal(withLogicalAppendLock(target, () => 42), 42);
    assert.equal(fs.readFileSync(join(dir, "floor"), "utf8"), "19\n");
    // A stale advisory hint affects work, not authority; it may not skip a live
    // generation and is advanced again from permanent drained certificates.
    fs.writeFileSync(join(dir, "floor"), "2\n");
    assert.equal(withLogicalAppendLock(target, () => 43), 43);
    assert.equal(fs.readFileSync(join(dir, "floor"), "utf8"), "19\n");
  });

  test("fsync:false suppresses actual synchronization, including append lock sidecars", () => {
    const target = fixture(), original = fsDefault.fsyncSync, originalIO = NODE_IO.fsyncSync;
    let syncs = 0;
    const measured = (fd: number): void => { syncs++; original(fd); };
    try {
      fsDefault.fsyncSync = measured; NODE_IO.fsyncSync = measured; syncBuiltinESMExports();
      const store = new FileSpineStore(`${target}.store`, { fsync: false });
      store.appendStaged({ id: "ordinary", schemaVersion: 1, type: "generic", ts: 1, actor: "owner", payload: {} });
      store.prepareForSeal();
      assert.equal(syncs, 0, "count actual built-in calls, not only injected IO calls");
    } finally { fsDefault.fsyncSync = original; NODE_IO.fsyncSync = originalIO; syncBuiltinESMExports(); }
  });
}
