import { test } from "node:test";
import assert from "node:assert/strict";

import { FencedKillRegistry, fenceDecision, type OsKiller } from "../src/identity/process_kill.js";

// R35 — process-kill fencing conformance. Proves the ENVELOPE-SIDE fencing logic: a killed or
// stale-lease agent's effect is rejected at the COMMIT egress even if the gate passed. The real OS
// cgroup.kill is the SEAM. Verify by disproof.

function recordingKiller(result = { killed: true } as { killed: boolean; reason?: string }) {
  const calls: string[] = [];
  const killer: OsKiller = { kill: (pg) => { calls.push(pg); return result; } };
  return { killer, calls };
}

test("R35: a current-token effect is admitted at commit", () => {
  const reg = new FencedKillRegistry();
  reg.bind("agent-1", "pg-1");
  const lease = reg.lease("agent-1");
  assert.equal(lease.admit, true);
  if (lease.admit) assert.equal(reg.admitAtCommit("agent-1", lease.token).admit, true);
});

test("R35: after kill, the SAME (now stale) token is REJECTED at commit — the kill-mid-flight fence", () => {
  const { killer } = recordingKiller();
  const reg = new FencedKillRegistry(killer);
  reg.bind("agent-1", "pg-1");
  const lease = reg.lease("agent-1");
  assert.equal(lease.admit, true);
  const token = lease.admit ? lease.token : -1;
  // the effect passed the gate and holds `token`; now the agent is killed mid-flight.
  reg.kill("agent-1", "compromised");
  const admit = reg.admitAtCommit("agent-1", token);
  assert.equal(admit.admit, false, "the in-flight effect's token is fenced out at commit");
  if (!admit.admit) assert.ok(admit.reason.startsWith("killed-identity") || admit.reason.startsWith("stale-fence-token"));
});

test("R35: kill bumps the fence, marks killed, AND invokes the OS killer seam", () => {
  const { killer, calls } = recordingKiller();
  const reg = new FencedKillRegistry(killer);
  reg.bind("agent-1", "pg-42");
  const out = reg.kill("agent-1");
  assert.equal(reg.isKilled("agent-1"), true);
  assert.equal(out.fenced, 2, "fence bumped from 1 to 2");
  assert.deepEqual(calls, ["pg-42"], "the OS killer was invoked with the bound process group");
  assert.equal(out.killed, true);
  assert.equal(out.escalate, false);
});

test("R35: a FAILED OS kill still fences (fail-safe) and flags escalation", () => {
  const { killer } = recordingKiller({ killed: false, reason: "cgroup-busy" });
  const reg = new FencedKillRegistry(killer);
  reg.bind("agent-1", "pg-1");
  const lease = reg.lease("agent-1");
  const token = lease.admit ? lease.token : -1;
  const out = reg.kill("agent-1");
  assert.equal(out.killed, false, "OS kill reported failure");
  assert.equal(out.escalate, true, "escalation flagged");
  // …but the fence still rejects the revoked agent's commit — the safety does not depend on the OS kill.
  assert.equal(reg.admitAtCommit("agent-1", token).admit, false, "fence fails safe even when OS kill failed");
});

test("R35: with NO OS killer wired (the SEAM absent), the fence still fails safe and escalates", () => {
  const reg = new FencedKillRegistry(); // no killer
  reg.bind("agent-1", "pg-1");
  const lease = reg.lease("agent-1");
  const token = lease.admit ? lease.token : -1;
  const out = reg.kill("agent-1");
  assert.equal(out.escalate, true);
  assert.equal(reg.admitAtCommit("agent-1", token).admit, false, "fence rejects the commit with no OS killer");
});

test("R35: the fence is monotonic — a killed identity never un-kills, stale never resurrects", () => {
  const { killer } = recordingKiller();
  const reg = new FencedKillRegistry(killer);
  reg.bind("agent-1", "pg-1");
  const old = reg.lease("agent-1");
  const oldToken = old.admit ? old.token : -1;
  reg.kill("agent-1");
  assert.equal(reg.lease("agent-1").admit, false, "a killed identity cannot lease a new token");
  assert.equal(reg.admitAtCommit("agent-1", oldToken).admit, false, "the old token stays fenced out");
});

test("R35: a stale token after a lease RENEWAL is fenced out even though the identity is ALIVE (isolates the fence)", () => {
  const reg = new FencedKillRegistry();
  reg.bind("agent-1", "pg-1");
  const first = reg.lease("agent-1");
  const staleToken = first.admit ? first.token : -1;
  const renewed = reg.renew("agent-1"); // heartbeat/handoff → fence bumps, identity NOT killed
  assert.equal(renewed.admit, true);
  assert.equal(reg.isKilled("agent-1"), false, "the identity is alive — only the fence rejects");
  const admit = reg.admitAtCommit("agent-1", staleToken);
  assert.equal(admit.admit, false, "the pre-renewal token is stale and fenced out");
  if (!admit.admit) assert.ok(admit.reason.startsWith("stale-fence-token"));
  // the renewed token is admitted.
  if (renewed.admit) assert.equal(reg.admitAtCommit("agent-1", renewed.token).admit, true);
});

test("R35: fenceDecision is pure — killed or below-fence is rejected, at-or-above is admitted", () => {
  assert.equal(fenceDecision(5, false, 5), true);
  assert.equal(fenceDecision(5, false, 6), true);
  assert.equal(fenceDecision(5, false, 4), false); // stale
  assert.equal(fenceDecision(5, true, 9), false); // killed overrides a fresh token
});
