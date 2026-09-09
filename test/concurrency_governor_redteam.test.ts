import { test } from "node:test";
import assert from "node:assert/strict";

import { concurrencyGovernor, finiteNonNegative, type RunningEntry, type ConcurrencyPolicy } from "../src/autonomy/project_loop.js";

const policy: ConcurrencyPolicy = { aggregateCeiling: 10, perProjectShare: 1.0 };

test("GOVERNOR-HARDEN (a): a NaN weight is DENIED, never admitted (the confirmed fail-open)", () => {
  // NaN > ceiling is false, so an unguarded governor admits this past the ceiling. The fuse must deny it.
  const r = concurrencyGovernor([], { project: "X", weight: NaN }, policy);
  assert.equal(r.verdict, "denied");
  assert.notEqual(r.verdict, "admitted", "a NaN weight must never be admitted");
});

test("GOVERNOR-HARDEN (b): a negative weight is rejected, not summed into the aggregate", () => {
  const r = concurrencyGovernor([], { project: "X", weight: -100 }, policy);
  assert.equal(r.verdict, "denied");
  // and a negative weight already IN the running-set is caught (can't fabricate spare capacity)
  const poisoned = concurrencyGovernor([{ project: "A", weight: -100 }], { project: "B", weight: 5 }, policy);
  assert.equal(poisoned.verdict, "denied", "a poisoned running-set fails closed, never admits on fabricated capacity");
});

test("GOVERNOR-HARDEN (c): an Infinity weight never poisons the aggregate (denied)", () => {
  const reqInf = concurrencyGovernor([], { project: "X", weight: Infinity }, policy);
  assert.equal(reqInf.verdict, "denied");
  const runInf = concurrencyGovernor([{ project: "A", weight: Infinity }], { project: "B", weight: 1 }, policy);
  assert.equal(runInf.verdict, "denied", "an Infinity in the running-set is caught before it queues everyone forever");
});

test("GOVERNOR-HARDEN (d): a malformed policy fails closed (non-finite ceiling / share outside [0,1])", () => {
  assert.equal(concurrencyGovernor([], { project: "X", weight: 1 }, { aggregateCeiling: NaN, perProjectShare: 1 }).verdict, "denied");
  assert.equal(concurrencyGovernor([], { project: "X", weight: 1 }, { aggregateCeiling: Infinity, perProjectShare: 1 }).verdict, "denied");
  assert.equal(concurrencyGovernor([], { project: "X", weight: 1 }, { aggregateCeiling: 10, perProjectShare: 2 }).verdict, "denied");
  assert.equal(concurrencyGovernor([], { project: "X", weight: 1 }, { aggregateCeiling: 10, perProjectShare: -0.5 }).verdict, "denied");
});

test("GOVERNOR-HARDEN (e): well-formed behavior is unchanged and deterministic (fuses don't over-block)", () => {
  const p: ConcurrencyPolicy = { aggregateCeiling: 10, perProjectShare: 0.6 };
  const admit = concurrencyGovernor([{ project: "A", weight: 4 }], { project: "B", weight: 3 }, p);
  assert.equal(admit.verdict, "admitted", "a legitimate within-ceiling request still admits");
  const queue = concurrencyGovernor([{ project: "A", weight: 6 }], { project: "A", weight: 1 }, p);
  assert.equal(queue.verdict, "queued", "fair-share still queues");
  const deny = concurrencyGovernor([], { project: "X", weight: 11 }, p);
  assert.equal(deny.verdict, "denied", "infeasible still denies");
  // deterministic
  const a = concurrencyGovernor([{ project: "A", weight: 4 }], { project: "B", weight: 3 }, p);
  assert.deepEqual(a, admit);
});

test("GOVERNOR-HARDEN (fuse): finiteNonNegative is a correct, reusable input fuse", () => {
  assert.equal(finiteNonNegative(0), true);
  assert.equal(finiteNonNegative(5.5), true);
  assert.equal(finiteNonNegative(NaN), false);
  assert.equal(finiteNonNegative(Infinity), false);
  assert.equal(finiteNonNegative(-Infinity), false);
  assert.equal(finiteNonNegative(-1), false);
});
