import { test } from "node:test";
import assert from "node:assert/strict";
import { InProcessLock } from "../src/lock/lock.js";

const retained = (lock: InProcessLock): number =>
  (lock as unknown as { tails: ReadonlyMap<string, unknown> }).tails.size;
function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

test("completed unique lock keys and rejected bodies leave no idle entries", async () => {
  const lock = new InProcessLock();
  await Promise.all(Array.from({ length: 2_000 }, (_, i) => lock.withLock(`unique-${i}`, async () => i)));
  assert.equal(retained(lock), 0);
  await assert.rejects(lock.withLock("throws", async () => { throw new Error("body failed"); }), /body failed/);
  assert.equal(retained(lock), 0);
  assert.equal(await lock.withLock("throws", async () => "reused"), "reused");
  assert.equal(retained(lock), 0);
});

test("finishing a holder preserves its queued tail and FIFO exclusion", { timeout: 2_000 }, async () => {
  const lock = new InProcessLock(), firstGate = gate(), secondGate = gate(), secondEntered = gate();
  const order: string[] = []; let active = 0, maximum = 0;
  const enter = (name: string) => { order.push(name); active++; maximum = Math.max(maximum, active); };
  const first = lock.withLock("shared", async () => { enter("first"); await firstGate.promise; active--; });
  const second = lock.withLock("shared", async () => { enter("second"); secondEntered.release(); await secondGate.promise; active--; });
  firstGate.release(); await first; await secondEntered.promise;
  assert.equal(retained(lock), 1, "later holder remains owned");
  const third = lock.withLock("shared", async () => { enter("third"); active--; });
  await Promise.resolve(); assert.deepEqual(order, ["first", "second"]);
  secondGate.release(); await Promise.all([second, third]);
  assert.deepEqual(order, ["first", "second", "third"]); assert.equal(maximum, 1); assert.equal(retained(lock), 0);
});

test("same key reused immediately after each completion stays exclusive", async () => {
  const lock = new InProcessLock(); let active = 0, maximum = 0;
  for (let i = 0; i < 100; i++) {
    await Promise.all(Array.from({ length: 8 }, () => lock.withLock("reused", async () => {
      active++; maximum = Math.max(maximum, active); await Promise.resolve(); active--;
    })));
    assert.equal(retained(lock), 0);
  }
  assert.equal(maximum, 1);
});
