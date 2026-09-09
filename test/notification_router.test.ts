import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { NotificationRouter, CollectingChannel } from "../src/notify/notification_router.js";
import type { PrManifest } from "../src/git/pull_request.js";
import type { CalibrationWire } from "../src/oversight/calibration_wire.js";

function mk(id: string, oversight: Partial<{ band: "low" | "medium" | "high"; disposition: string; mode: string; requiresImmediateAttention: boolean; reasons: string[] }>): PrManifest {
  return { id, title: `change ${id}`, oversight: { band: "low", disposition: "auto-approved", mode: "silent-auto", requiresImmediateAttention: false, reasons: [], ...oversight } } as unknown as PrManifest;
}

test("W2: auto-approved low-risk work is SUPPRESSED — never a per-PR interrupt (anti-rubber-stamping)", () => {
  const ch = new CollectingChannel();
  const r = new NotificationRouter({ channel: ch });
  assert.equal(r.notify(mk("A", { band: "low", disposition: "auto-approved", mode: "silent-auto" })), "suppress");
  assert.equal(ch.sent.length, 0, "no notification delivered for routine auto-approved work");
});

test("W2: auto-approved medium → digest (batched, not interrupting)", () => {
  const ch = new CollectingChannel();
  const r = new NotificationRouter({ channel: ch });
  assert.equal(r.notify(mk("B", { band: "medium", disposition: "auto-approved", mode: "notify-async" })), "digest");
  assert.equal(ch.sent.length, 0, "digest is buffered, not sent immediately");
  assert.equal(r.pendingDigestCount(), 1);
});

test("W2: a change that needs a decision → notify (async, non-interrupting)", () => {
  const ch = new CollectingChannel();
  const r = new NotificationRouter({ channel: ch });
  assert.equal(r.notify(mk("C", { band: "medium", disposition: "human-approval-required", mode: "block-until-approved" })), "notify");
  assert.equal(ch.sent[0]?.tier, "notify");
});

test("W2: blocked or requires-immediate-attention → URGENT (interrupt)", () => {
  const ch = new CollectingChannel();
  const r = new NotificationRouter({ channel: ch });
  assert.equal(r.notify(mk("D", { band: "high", disposition: "blocked" })), "urgent");
  assert.equal(r.notify(mk("E", { band: "medium", disposition: "human-approval-required", requiresImmediateAttention: true })), "urgent");
  assert.equal(ch.sent.filter((n) => n.tier === "urgent").length, 2);
});

test("W2 (F2 calibration): a class with an active reduced-escalation policy is SUPPRESSED even if it'd digest", () => {
  const calibration = { activePolicyGates: () => new Set(["medium"]) } as unknown as CalibrationWire;
  const ch = new CollectingChannel();
  const r = new NotificationRouter({ channel: ch, calibration });
  assert.equal(r.notify(mk("F", { band: "medium", disposition: "auto-approved", mode: "notify-async" })), "suppress");
});

test("W2: a dead-lettered ticket always interrupts (urgent)", () => {
  const ch = new CollectingChannel();
  const r = new NotificationRouter({ channel: ch });
  r.notifyDeadLetter("GITEA-9", "handler failed 3 times");
  assert.equal(ch.sent[0]?.tier, "urgent");
  assert.equal(ch.sent[0]?.kind, "dead-letter");
});

test("W2: the routine is flushed as ONE digest (nothing lost, no per-item interrupt)", () => {
  const ch = new CollectingChannel();
  const r = new NotificationRouter({ channel: ch });
  r.notify(mk("G", { band: "medium", disposition: "auto-approved", mode: "notify-async" }));
  r.notify(mk("H", { band: "medium", disposition: "auto-approved", mode: "notify-async" }));
  const digest = r.flushDigest();
  assert.equal(digest?.total, 2);
  assert.equal(ch.sent.filter((n) => n.kind === "digest").length, 1, "one digest, not two interrupts");
  assert.equal(r.pendingDigestCount(), 0, "buffer cleared after flush");
});

test("W2 fatigue ceiling: too many urgents records an overload HEALTH signal but NEVER drops an alert", () => {
  const ch = new CollectingChannel();
  const r = new NotificationRouter({ channel: ch, maxUrgentPerWindow: 1 });
  r.notify(mk("I", { disposition: "blocked", band: "high" }));
  r.notify(mk("J", { disposition: "blocked", band: "high" })); // exceeds the ceiling
  assert.equal(ch.sent.filter((n) => n.tier === "urgent").length, 2, "both dangerous alerts still delivered (safety over fatigue)");
});

test("W2 CORE: across a batch, ONLY the dangerous few interrupt; the routine produces zero notifications", () => {
  const ch = new CollectingChannel();
  const r = new NotificationRouter({ channel: ch });
  for (let i = 0; i < 20; i++) r.notify(mk(`auto${i}`, { band: "low", disposition: "auto-approved", mode: "silent-auto" }));
  r.notify(mk("dec1", { band: "medium", disposition: "human-approval-required" }));
  r.notify(mk("dec2", { band: "medium", disposition: "human-approval-required" }));
  r.notify(mk("block1", { band: "high", disposition: "blocked" }));
  assert.equal(ch.sent.filter((n) => n.tier === "urgent").length, 1, "only the 1 blocked change interrupts");
  assert.equal(ch.sent.filter((n) => n.tier === "notify").length, 2, "the 2 decisions are async notifications");
  assert.equal(ch.sent.length, 3, "the 20 routine auto-approved changes produced NO notifications at all");
});

test("W2: composeKeep exposes notifications; routing works through the composed app", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-w2-")) });
  assert.ok(app.notifications);
  assert.equal(app.notifications.notify(mk("Z", { band: "low", disposition: "auto-approved", mode: "silent-auto" })), "suppress");
});
