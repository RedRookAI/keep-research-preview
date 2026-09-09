import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { computeMonitor, renderMonitor } from "../src/monitor/solve_monitor.js";
import { handleReviewRequest, type WebRequest, type WebSecurity } from "../src/review/review_web.js";
import { runCli } from "../src/cli/cli_core.js";
import { composeKeep, type KeepApp } from "../src/compose.js";
import { OWNER } from "../src/identity/rbac.js";

function app(): KeepApp { return composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-s4-")) }); }
const stage = (a: KeepApp, payload: Record<string, unknown>) => a.spine.stage({ type: "identity.action", actor: "t", payload });
const snap = (a: KeepApp, now: number, stalenessMs?: number) => computeMonitor(a.spine.currentEvents(), now, stalenessMs !== undefined ? { stalenessMs } : {});

test("S4: folds a ticket lifecycle solving → awaiting-review → decided", () => {
  const a = app();
  stage(a, { event: "trigger.accepted", issueId: "ENG-1", source: "linear", ticketId: "ENG-1", ts: 100 });
  let s = snap(a, 200, 10_000);
  assert.equal(s.tickets[0]!.phase, "solving");

  stage(a, { event: "review.pending", reviewId: "pr-ENG-1", correlationId: "ENG-1", ts: 300 });
  s = snap(a, 400, 10_000);
  assert.equal(s.tickets[0]!.phase, "awaiting-review");
  assert.equal(s.tickets[0]!.needsAttention, true);

  stage(a, { event: "review.decided", reviewId: "pr-ENG-1", decision: "approved", ts: 500 });
  s = snap(a, 600, 10_000);
  assert.equal(s.tickets[0]!.phase, "decided", "review.decided stitched to the ticket via the reviewId→issueId map");
  assert.equal(s.tickets[0]!.needsAttention, false);
});

test("S4: closed-loop correlation — the review folds onto the ORIGINATING trigger, one ticket not two", () => {
  const a = app();
  stage(a, { event: "trigger.accepted", issueId: "ENG-2", ts: 1 });
  stage(a, { event: "review.pending", reviewId: "pr-2", correlationId: "ENG-2", ts: 2 });
  const s = snap(a, 3, 10_000);
  assert.equal(s.tickets.length, 1, "trigger + review are the same ticket");
  assert.equal(s.tickets[0]!.issueId, "ENG-2");
});

test("S4: a non-terminal ticket idle past the staleness threshold is STUCK (and needs attention)", () => {
  const a = app();
  stage(a, { event: "trigger.accepted", issueId: "ENG-3", ts: 0 });
  const s = snap(a, 20 * 60_000, 15 * 60_000); // 20 min later, 15 min threshold
  assert.equal(s.tickets[0]!.stuck, true);
  assert.equal(s.tickets[0]!.needsAttention, true);
  assert.equal(s.counts.stuck, 1);
});

test("S4: a terminal ticket (completed) is never stuck", () => {
  const a = app();
  stage(a, { event: "trigger.accepted", issueId: "ENG-4", ts: 0 });
  stage(a, { event: "trigger.completed", issueId: "ENG-4", ts: 1 });
  const s = snap(a, 999 * 60_000, 1);
  assert.equal(s.tickets[0]!.phase, "completed");
  assert.equal(s.tickets[0]!.stuck, false);
});

test("S4: needs-attention tickets are surfaced FIRST (action-first)", () => {
  const a = app();
  stage(a, { event: "trigger.accepted", issueId: "healthy", ts: 100 });      // solving, fresh
  stage(a, { event: "trigger.accepted", issueId: "decideme", ts: 90 });
  stage(a, { event: "review.pending", reviewId: "pr-d", correlationId: "decideme", ts: 95 });
  const s = snap(a, 120, 10_000);
  assert.equal(s.tickets[0]!.issueId, "decideme", "the ticket needing a decision is first");
  assert.equal(s.needsAttention.length, 1);
});

test("S4: cost + escalations are aggregated from the cascade trail; dead-letter is surfaced", () => {
  const a = app();
  stage(a, { event: "trigger.accepted", issueId: "ENG-5", ts: 0 });
  stage(a, { event: "resolve.cascade.tier", issueId: "ENG-5", tier: "cheap", estCostUsd: 1.5, ts: 1 });
  stage(a, { event: "resolve.cascade.escalate", issueId: "ENG-5", ts: 2 });
  stage(a, { event: "resolve.cascade.tier", issueId: "ENG-5", tier: "strong", estCostUsd: 4, ts: 3 });
  stage(a, { event: "trigger.dead-lettered", issueId: "ENG-5", reason: "boom", ts: 4 });
  const s = snap(a, 5, 10_000);
  assert.equal(s.tickets[0]!.phase, "dead-lettered");
  assert.equal(s.tickets[0]!.needsAttention, true);
  assert.equal(s.tickets[0]!.costUsd, 5.5);
  assert.equal(s.tickets[0]!.escalations, 1);
  assert.deepEqual(s.tickets[0]!.tiersUsed, ["cheap", "strong"]);
});

test("S4: the monitor is READ-ONLY — computing a snapshot stages no new events", () => {
  const a = app();
  stage(a, { event: "trigger.accepted", issueId: "ENG-6", ts: 0 });
  const before = a.spine.currentEvents().length;
  computeMonitor(a.spine.currentEvents(), 100);
  renderMonitor(computeMonitor(a.spine.currentEvents(), 100), 100);
  assert.equal(a.spine.currentEvents().length, before, "the monitor observes; it never writes");
});

test("S4 end-to-end: `keep monitor` renders the in-flight view from the real spine", async () => {
  const a = app();
  stage(a, { event: "trigger.accepted", issueId: "ENG-7", source: "jira", ts: Date.now() - 60_000 });
  stage(a, { event: "review.pending", reviewId: "pr-7", correlationId: "ENG-7", ts: Date.now() });
  const out: string[] = [];
  await runCli(["monitor"], { write: (s: string) => out.push(s), prompt: async () => "" }, { app: a });
  const text = out.join("\n");
  assert.match(text, /Needs your attention/);
  assert.match(text, /ENG-7/);
  assert.match(text, /NEEDS DECISION/);
});

test("S4 web: the /monitor route renders and requires view access", async () => {
  const a = app();
  stage(a, { event: "trigger.accepted", issueId: "ENG-8", ts: Date.now() });
  const sec: WebSecurity = { token: "T", origin: "http://127.0.0.1:7", allowedHosts: ["127.0.0.1:7"], principal: OWNER };
  const req: WebRequest = { method: "GET", path: "/monitor", query: {}, headers: { host: "127.0.0.1:7", cookie: "keep_token=T" }, body: "" };
  const r = await handleReviewRequest(a, req, sec);
  assert.equal(r.status, 200);
  assert.match(r.body, /Work in flight/);
  assert.match(r.body, /ENG-8/);
});
