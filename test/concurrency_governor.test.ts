import { test } from "node:test";
import assert from "node:assert/strict";

import { concurrencyGovernor, type RunningEntry, type ConcurrencyPolicy } from "../src/autonomy/project_loop.js";

// ceiling 10; a project may hold at most 60% = 6.
const policy: ConcurrencyPolicy = { aggregateCeiling: 10, perProjectShare: 0.6 };

test("CONCURRENCY-GOVERNOR (a): a run within the aggregate ceiling is admitted; one that would exceed it is queued", () => {
  const running: RunningEntry[] = [{ project: "A", weight: 4 }]; // used 4/10
  const ok = concurrencyGovernor(running, { project: "B", weight: 3 }, policy);
  assert.equal(ok.verdict, "admitted"); // 4+3=7 <= 10
  const over = concurrencyGovernor([{ project: "A", weight: 4 }, { project: "C", weight: 4 }], { project: "B", weight: 4 }, policy);
  assert.equal(over.verdict, "queued", "8+4=12 > 10 — queued, not admitted");
});

test("CONCURRENCY-GOVERNOR (b): the aggregate ceiling is HARD — never admits past it (no silent over-admission)", () => {
  const running: RunningEntry[] = [{ project: "A", weight: 5 }, { project: "B", weight: 5 }]; // exactly at 10
  const d = concurrencyGovernor(running, { project: "C", weight: 1 }, policy);
  assert.notEqual(d.verdict, "admitted", "at the ceiling, one more unit is never admitted");
  assert.equal(d.verdict, "queued");
  assert.ok(d.aggregateUsed + 1 > d.aggregateCeiling, "the decision reflects real over-ceiling arithmetic");
});

test("CONCURRENCY-GOVERNOR (c): fair-share — a project cannot monopolize; others are not starved", () => {
  // A already holds its full 60% share (6). A asks for more → queued (cannot monopolize).
  const running: RunningEntry[] = [{ project: "A", weight: 6 }];
  const aMore = concurrencyGovernor(running, { project: "A", weight: 1 }, policy);
  assert.equal(aMore.verdict, "queued", "A is at its fair-share cap — queued");
  // meanwhile B (a different project) still fits within the aggregate → not starved
  const bFits = concurrencyGovernor(running, { project: "B", weight: 3 }, policy);
  assert.equal(bFits.verdict, "admitted", "B is not starved by A holding its share");
});

test("CONCURRENCY-GOVERNOR (d): reflects only the real running-set + weights; OS enforcement is honestly a seam", () => {
  const running: RunningEntry[] = [{ project: "A", weight: 4 }, { project: "A", weight: 2 }];
  const d = concurrencyGovernor(running, { project: "A", weight: 1 }, policy);
  assert.equal(d.aggregateUsed, 6, "aggregateUsed is the real sum, not fabricated");
  assert.equal(d.projectUsed, 6, "projectUsed is A's real total");
  assert.equal(d.enforcement, "admission-decision-only", "OS-level resource cap is a named seam, not claimed here");
  // a request too large to EVER fit is denied, not queued
  assert.equal(concurrencyGovernor([], { project: "X", weight: 11 }, policy).verdict, "denied");
});

test("CONCURRENCY-GOVERNOR (e): deterministic admission decision; changes no unrelated gate", () => {
  const running: RunningEntry[] = [{ project: "A", weight: 3 }];
  const req = { project: "B", weight: 2 };
  const a = concurrencyGovernor(running, req, policy);
  const b = concurrencyGovernor(running, req, policy);
  assert.equal(a.changesGate, false, "changes no unrelated gate");
  assert.deepEqual(a, b, "same running-set + request → same verdict");
});

test("CONCURRENCY-GOVERNOR (both-tracks): n=1 one project can use the whole box; org N projects fair-shared", () => {
  const solo: ConcurrencyPolicy = { aggregateCeiling: 10, perProjectShare: 1.0 }; // n=1: one project may use all
  assert.equal(concurrencyGovernor([], { project: "solo", weight: 9 }, solo).verdict, "admitted");
  // org: two projects each capped at 60%; the box can't be monopolized
  const org = concurrencyGovernor([{ project: "A", weight: 6 }], { project: "A", weight: 2 }, policy);
  assert.equal(org.verdict, "queued", "org: A held to its fair share");
});
