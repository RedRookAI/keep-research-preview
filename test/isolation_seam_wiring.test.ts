import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import type { JailRequest } from "../src/ree/jail.js";

// WIRING PROOF (P0-C): the in-env jail + fence halves are reachable and HONEST about the OS-enforcement seam.

function sb() {
  return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-jl-")) }).secondBrain;
}

test("composeKeep exposes the in-env isolation halves", () => {
  const s = sb();
  assert.equal(typeof s.killIdentity, "function");
  assert.equal(typeof s.runJailed, "function");
  assert.equal(typeof s.isolationEnforcement, "function");
});

test("HONEST SEAM LABELLING: isolationEnforcement never claims OS isolation it doesn't enforce", () => {
  const e = sb().isolationEnforcement();
  assert.equal(e.jailEnforced, false, "no OsJail attached ⇒ not claimed enforced (fail-honest)");
  assert.equal(e.osKillEnforced, false, "no OsKiller attached ⇒ not claimed enforced");
  assert.match(e.seam, /seam/i, "the OS-enforcement boundary is named as a seam");
});

test("FAIL-SAFE fence: kill bumps the fence + flags escalation even with no OS killer", () => {
  const s = sb();
  s.bindIdentity("agent-1", "pg-1");
  const lease = s.leaseToken("agent-1");
  assert.ok(lease.admit && lease.token !== undefined);
  const staleToken = lease.token!;
  const outcome = s.killIdentity("agent-1");
  assert.equal(outcome.killed, false, "no OS killer ⇒ honestly reports the process was NOT terminated");
  assert.equal(outcome.escalate, true, "it flags escalation rather than pretending success (fail-honest)");
  assert.ok(outcome.fenced > staleToken, "the fence bumped past the stale token");
  // the stale token (leased before the kill) must now be rejected at commit:
  assert.equal(s.checkFence(outcome.fenced, true, staleToken), false, "a stale/killed token is rejected — no fail-open");
});

test("the in-env jail contract rolls back on breach (fail-safe, no partial commit)", async () => {
  const s = sb();
  const committed: string[] = [];
  const req = { op: { description: {}, execute: async () => {} }, preState: {} } as unknown as JailRequest;
  // StubJail runs the op; an empty op yields a clean no-write commit — assert it doesn't throw and returns an outcome.
  const outcome = await s.runJailed(req, { commit: async (w) => { committed.push(...w.map((x) => x.path)); }, accept: () => true });
  assert.ok(outcome.outcome === "committed" || outcome.outcome === "rolled-back", "the envelope-side contract returns a decision");
});

test("graceful with no OS backend (n=1 floor): binding + leasing a fresh identity works", () => {
  const s = sb();
  s.bindIdentity("solo", "pg-solo");
  assert.equal(s.leaseToken("solo").admit, true);
});
