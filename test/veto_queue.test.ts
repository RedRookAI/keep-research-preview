import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { VetoQueue, type ParkedAction } from "../src/scheduler/veto_queue.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-veto-"))), new InProcessLock(), new SchemaRegistry());
}
function mk(runSpy: { ran: string[] }, windowMs = 1000): VetoQueue {
  return new VetoQueue({ spine: newSpine(), run: (a: ParkedAction) => runSpy.ran.push(a.id), defaultWindowMs: windowMs });
}
const send = (id: string) => ({ id, description: `email report ${id}`, externalClass: "send" as const });

test("ENQUEUE parks a vetoed action — it does NOT run", () => {
  const spy = { ran: [] as string[] };
  const q = mk(spy);
  const item = q.enqueue(send("a"), 0);
  assert.equal(item.status, "parked");
  assert.deepEqual(spy.ran, [], "enqueue never runs the action");
  assert.equal(q.runnable("a"), false);
});

test("NEVER-AUTO-EXECUTE: window elapsing does NOT make an item runnable or run it", () => {
  const spy = { ran: [] as string[] };
  const q = mk(spy, 1000);
  q.enqueue(send("a"), 0);
  // Advance well past the window without any approval.
  assert.equal(q.windowOpen("a", 5000), false, "the veto window has closed");
  assert.equal(q.runnable("a"), false, "a closed window is NOT an approval — still not runnable");
  assert.deepEqual(spy.ran, [], "nothing ran on elapse");
  assert.equal(q.parked().length, 1, "the item is still parked, awaiting explicit approval");
});

test("APPROVE is the ONLY run path (explicit human OK)", () => {
  const spy = { ran: [] as string[] };
  const q = mk(spy);
  q.enqueue(send("a"), 0);
  const approved = q.approve("a");
  assert.equal(approved?.status, "approved");
  assert.deepEqual(spy.ran, ["a"], "approve runs the action");
  assert.equal(q.runnable("a"), true);
});

test("REVERSIBLE-WHILE-PARKED: a veto removes the item; a vetoed item can never be approved", () => {
  const spy = { ran: [] as string[] };
  const q = mk(spy);
  q.enqueue(send("a"), 0);
  assert.equal(q.veto("a", 100), true, "vetoing a parked item succeeds");
  assert.equal(q.parked().length, 0, "a vetoed item is no longer parked");
  assert.equal(q.approve("a"), null, "a vetoed item cannot be approved");
  assert.deepEqual(spy.ran, [], "it never runs");
});

test("LOW-FRICTION: N parked items batch into ONE digest, not N interruptions", () => {
  const spy = { ran: [] as string[] };
  const q = mk(spy);
  q.enqueue(send("a"), 0);
  q.enqueue(send("b"), 0);
  q.enqueue(send("c"), 0);
  const d = q.digest(10);
  assert.equal(d.total, 3, "all three are in one digest");
  assert.equal(d.entries.length, 3);
  assert.ok(/3 actions awaiting/.test(d.summary), "one summary across the batch");
});
