import { test } from "node:test";
import assert from "node:assert/strict";
import { SessionStore } from "../src/identity/session_store.js";
import type { Principal } from "../src/identity/rbac.js";

const principals: Principal[] = [
  { id: "owner", kind: "human", role: "maintainer" },
  { id: "member", kind: "human", role: "reviewer", tenant: "tenant-a" },
];
const retained = (s: SessionStore) => (s as unknown as { sessions: ReadonlyMap<string, unknown> }).sessions;

test("create reclaims thousands of untouched expired sessions", () => {
  const s = new SessionStore({ idleMs: 100, absoluteMs: 500 });
  for (let i = 0; i < 2_000; i++) s.create(principals[i % 2]!, 0);
  assert.equal(retained(s).size, 2_000);
  const fresh = s.create(principals[0]!, 1_000);
  assert.equal(retained(s).size, 1);
  assert.ok(retained(s).has(fresh.id));
});

test("active count independently reclaims untouched records with the same clock", (t) => {
  let now = 0; t.mock.method(Date, "now", () => now);
  const s = new SessionStore({ idleMs: 100, absoluteMs: 500 });
  for (const principal of principals) s.create(principal, now);
  now = 101;
  assert.equal(s.activeCount(), 0);
  assert.equal(retained(s).size, 0);
  assert.equal(s.activeCount(), 0, "repeated sweep stays empty");
});

test("maintenance preserves inclusive idle and absolute boundaries and live touches", (t) => {
  let now = 0; t.mock.method(Date, "now", () => now);
  const s = new SessionStore({ idleMs: 100, absoluteMs: 500 });
  const absolute = s.create(principals[0]!, now), idle = s.create(principals[1]!, now);
  for (now = 100; now <= 400; now += 100) assert.ok(s.get(absolute.id, now));
  now = 450; const live = s.create(principals[1]!, now);
  assert.equal(retained(s).has(idle.id), false, "untouched idle-expired session removed");
  now = 500;
  assert.ok(s.get(absolute.id, now), "exact absolute boundary remains live");
  assert.ok(s.get(live.id, now)); assert.equal(s.activeCount(), 2);
  now = 501; assert.equal(s.activeCount(), 1);
  assert.equal(retained(s).has(absolute.id), false); assert.ok(s.get(live.id, now));
  now = 601; assert.equal(s.activeCount(), 1, "exact idle boundary remains live");
  now = 602; assert.equal(s.activeCount(), 0); assert.equal(retained(s).size, 0);
});
