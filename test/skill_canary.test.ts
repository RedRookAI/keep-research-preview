import { test } from "node:test";
import assert from "node:assert/strict";
import { SkillCanary, type CanaryNotice, type CanaryNotifier } from "../src/loop/skill_canary.js";
import type { OutcomeSignal } from "../src/loop/self_improvement_bus.js";

function sig(over: Partial<OutcomeSignal> = {}): OutcomeSignal {
  return { solveId: "s", taskShape: "build", testsPassed: true, mergeVerdict: "merged", timestamp: Date.now(), ...over };
}
function recorder(): CanaryNotifier & { notices: CanaryNotice[] } {
  const notices: CanaryNotice[] = [];
  return { notices, notify: (n) => notices.push(n) };
}

// ─── goes live instantly ───

test("a validated skill goes live instantly as a canary (no shadow wait)", () => {
  const c = new SkillCanary();
  const r = c.goLive("skill-1");
  assert.equal(r.state, "canary");
  assert.equal(r.transition, "went-live");
  assert.ok(c.liveSkills().includes("skill-1"));
});

test("SKILL-06: provisional promotion notifies through the canary port", () => {
  const notifier = recorder();
  new SkillCanary({ notifier }).goLive("skill-1");
  assert.equal(notifier.notices.length, 1);
  assert.equal(notifier.notices[0]?.tier, "log");
  assert.match(notifier.notices[0]?.message ?? "", /promoted provisionally/);
});

test("SKILL-06: notification failure cannot split provisional promotion", () => {
  const canary = new SkillCanary({ notifier: { notify: () => { throw new Error("channel down"); } } });
  assert.doesNotThrow(() => canary.goLive("skill-1"));
  assert.equal(canary.state("skill-1"), "canary");
});

// ─── graduation after exactly the floor ───

test("graduates to full trust after exactly 3 clean uses (K1 floor), not before", () => {
  const c = new SkillCanary({ graduateFloor: 3 });
  c.goLive("s");
  assert.equal(c.recordUse("s", sig()).state, "canary"); // 1
  assert.equal(c.recordUse("s", sig()).state, "canary"); // 2
  const third = c.recordUse("s", sig());                 // 3 → graduate
  assert.equal(third.state, "graduated");
  assert.equal(third.transition, "graduated");
});

test("graduation emits a SILENT log-tier notice (K5)", () => {
  const n = recorder();
  const c = new SkillCanary({ graduateFloor: 2, notifier: n });
  c.goLive("s");
  c.recordUse("s", sig());
  c.recordUse("s", sig()); // graduate
  const grad = n.notices.find((x) => x.message.includes("graduated"));
  assert.equal(grad?.tier, "log"); // silent
});

// ─── instant demote on a single regression (no 3-strikes) ───

test("INSTANT-demotes on a single failed-test regression (no 3 strikes)", () => {
  const c = new SkillCanary();
  c.goLive("s");
  c.recordUse("s", sig({ testsPassed: true })); // 1 clean
  const bad = c.recordUse("s", sig({ testsPassed: false, mergeVerdict: "pending" })); // regression
  assert.equal(bad.state, "rolled-back");
  assert.equal(bad.transition, "rolled-back");
  assert.ok(!c.liveSkills().includes("s"));
});

test("INSTANT-demotes on a human reject too", () => {
  const c = new SkillCanary();
  c.goLive("s");
  const bad = c.recordUse("s", sig({ testsPassed: true, mergeVerdict: "rejected", rejectReason: "wrong approach" }));
  assert.equal(bad.state, "rolled-back");
});

test("a reversible rollback emits a quiet TICKET (not a Page) — K5", () => {
  const n = recorder();
  const c = new SkillCanary({ notifier: n });
  c.goLive("s"); // reversible by default
  c.recordUse("s", sig({ testsPassed: false, mergeVerdict: "pending" }));
  const rb = n.notices.find((x) => x.message.includes("underperformed"));
  assert.equal(rb?.tier, "ticket");
  assert.match(rb?.message ?? "", /nothing to do/);
});

test("an IRREVERSIBLE skill's rollback PAGES (needs review) — K5", () => {
  const n = recorder();
  const c = new SkillCanary({ notifier: n });
  c.goLive("s", { irreversible: true });
  c.recordUse("s", sig({ testsPassed: false, mergeVerdict: "pending" }));
  const rb = n.notices.find((x) => x.tier === "page");
  assert.ok(rb, "irreversible rollback should page");
  assert.match(rb!.message, /IRREVERSIBLE/);
});

// ─── neutral use is not clean ───

test("a human reject regresses a canary (merge gate authoritative), even with passing tests", () => {
  // Corrected design: the human reject means a PR they won't merge → a regression for retention, even though
  // reuseSignal net-reward is 0 (the Goodhart guard keeps it out of graduation CREDIT, but retention demotes).
  const c = new SkillCanary({ graduateFloor: 1 });
  c.goLive("s");
  const r = c.recordUse("s", sig({ testsPassed: true, mergeVerdict: "rejected" }));
  assert.equal(r.state, "rolled-back");
});

// ─── graduated skill can still be demoted ───

test("a graduated skill is still monitored and can be demoted by a later regression", () => {
  const c = new SkillCanary({ graduateFloor: 2 });
  c.goLive("s");
  c.recordUse("s", sig());
  assert.equal(c.recordUse("s", sig()).state, "graduated");
  const demoted = c.recordUse("s", sig({ testsPassed: false, mergeVerdict: "pending" }));
  assert.equal(demoted.state, "rolled-back");
});

// ─── forceRollback (drift/reuse-decline external trigger) ───

test("forceRollback demotes a live skill (drift/reuse-decline trigger) with a ticket", () => {
  const n = recorder();
  const c = new SkillCanary({ notifier: n });
  c.goLive("s");
  const r = c.forceRollback("s", "drift safe-mode");
  assert.equal(r.state, "rolled-back");
  const rollback = n.notices.find((notice) => notice.message.includes("drift safe-mode"));
  assert.equal(rollback?.tier, "ticket");
  assert.match(rollback?.message ?? "", /drift safe-mode/);
});

test("ceiling: a skill with only pending human verdicts stays live and advances cleanly", () => {
  // A "pending" verdict with passing tests is a clean use (reward +1) — the human hasn't reviewed yet.
  // With a high floor, a few clean uses keep it a live canary until it graduates.
  const c = new SkillCanary({ graduateFloor: 10, ceiling: 10 });
  c.goLive("s");
  for (let i = 0; i < 5; i++) c.recordUse("s", sig({ testsPassed: true, mergeVerdict: "pending" }));
  assert.equal(c.state("s"), "canary"); // 5 clean uses < floor 10 → still a live canary
  assert.ok(c.liveSkills().includes("s"));
});
