import { test } from "node:test";
import assert from "node:assert/strict";

import { autonomyScorecard, type RunEvent, type HoldKind } from "../src/frontdoor/autonomy_profile.js";

const act = (inEnvelope = true): RunEvent => ({ kind: "action", inEnvelope });
const hold = (holdKind: HoldKind): RunEvent => ({ kind: "hold", holdKind });

test("AUTONOMY-MEASURE (a): a run with no human hold reads as unattended-complete; one with a hold does not", () => {
  const clean = autonomyScorecard({ events: [act(), act(), act()], completed: true });
  assert.equal(clean.unattendedComplete, true);
  const held = autonomyScorecard({ events: [act(), hold("consequence-gated"), act()], completed: true });
  assert.equal(held.unattendedComplete, false, "a hold means it was not unattended");
  // completed:false is never unattended-complete
  assert.equal(autonomyScorecard({ events: [act()], completed: false }).unattendedComplete, false);
});

test("AUTONOMY-MEASURE (b): the touchpoint burden reflects the real count and kind of holds", () => {
  const s = autonomyScorecard({ events: [hold("consequence-gated"), hold("consequence-gated"), hold("confidence-escalation")], completed: true });
  assert.equal(s.humanTouchpoints, 3);
  assert.equal(s.touchpointsByKind["consequence-gated"], 2, "planned holds counted");
  assert.equal(s.touchpointsByKind["confidence-escalation"], 1, "unplanned escalations counted separately");
  assert.equal(s.touchpointsByKind["resource-limit"], 0);
});

test("AUTONOMY-MEASURE (c): envelope adherence is HARD — one out-of-envelope action is a breach, never averaged", () => {
  // 9 in-envelope, 1 out — a naive average would call this 90% "mostly adherent"; the invariant says BREACH.
  const events: RunEvent[] = [...Array(9).fill(0).map(() => act(true)), act(false)];
  const s = autonomyScorecard({ events, completed: true });
  assert.equal(s.envelopeAdherence, false, "a single breach makes adherence false");
  assert.equal(s.outOfEnvelopeCount, 1);
  assert.match(s.summary, /ENVELOPE BREACH/);
  // all-in-envelope is adherent
  assert.equal(autonomyScorecard({ events: [act(true), act(true)], completed: true }).envelopeAdherence, true);
});

test("AUTONOMY-MEASURE (d): autonomy is measured SEPARATELY from correctness (unattended ≠ correct)", () => {
  const s = autonomyScorecard({ events: [act(), act()], completed: true });
  assert.equal(s.unattendedComplete, true);
  assert.equal(s.measures, "autonomy-not-correctness", "explicitly labeled: not a correctness claim");
  assert.match(s.summary, /not correctness/);
  // @ts-expect-error — the scorecard NEVER asserts correctness/success
  assert.equal(s.correct, undefined);
});

test("AUTONOMY-MEASURE (e): report-only + deterministic (changes no gate; same events → same scorecard)", () => {
  const input = { events: [act(), hold("resource-limit" as const), act(false)], completed: true };
  const a = autonomyScorecard(input);
  const b = autonomyScorecard(input);
  assert.equal(a.changesGate, false, "changes no gate");
  assert.deepEqual(a, b, "deterministic");
  assert.deepEqual(JSON.parse(JSON.stringify(a)), a, "serializable");
});

test("AUTONOMY-MEASURE (both-tracks): n=1 personal readout; org sees the breach surfaced, never smoothed", () => {
  const personal = autonomyScorecard({ events: [act(), act()], completed: true });
  assert.equal(personal.unattendedComplete, true);
  // org SLO: even a mostly-good run with one breach is reported as a breach (not smoothed to green)
  const org = autonomyScorecard({ events: [...Array(50).fill(0).map(() => act(true)), act(false)], completed: true });
  assert.equal(org.envelopeAdherence, false, "50/51 in-envelope is still a breach — never smoothed");
});
