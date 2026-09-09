import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { TriggerRouter } from "../src/ecosystem/integrations.js";
import { registerAllTrackers } from "../src/infra/tracker_adapters.js";
import { WebhookVerifier } from "../src/ingress/webhook_verifier.js";
import { TriggerIngress, type TriggerHandler } from "../src/ingress/trigger_ingress.js";
import { PollingSource } from "../src/ingress/polling_source.js";
import type { Issue } from "../src/solve/issue_model.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-w0-"))), new InProcessLock(), new SchemaRegistry());
}
const SECRET = "shh-signing-secret";
function hmacHex(secret: string, body: string): string { return createHmac("sha256", secret).update(body, "utf8").digest("hex"); }
function makeIngress(handler?: TriggerHandler) {
  const spine = newSpine();
  const router = new TriggerRouter();
  registerAllTrackers(router);
  const ingress = new TriggerIngress({ verifier: new WebhookVerifier(), router, spine, secretFor: () => SECRET, ...(handler ? { handler } : {}) });
  return { spine, router, ingress };
}
function linearBody(id: string, title: string, tsMs = Date.now()): string {
  return JSON.stringify({ type: "Issue", action: "create", webhookTimestamp: tsMs, data: { identifier: id, title, description: "please fix" } });
}
function linearHeaders(body: string, secret = SECRET): Record<string, string> { return { "Linear-Signature": hmacHex(secret, body) }; }

test("W0: a correctly-signed Linear webhook is accepted → Issue created, handler called once, audited", async () => {
  const seen: Issue[] = [];
  const { spine, ingress } = makeIngress(async (issue) => { seen.push(issue); });
  const body = linearBody("ENG-1", "add() subtracts");
  const r = await ingress.receive({ source: "linear", rawBody: body, headers: linearHeaders(body) });
  assert.equal(r.status, "accepted");
  assert.equal(seen.length, 1);
  assert.equal(seen[0]!.id, "linear:ENG-1");
  await spine.seal();
  assert.ok(spine.replay().some((e) => (e.payload as Record<string, unknown>)["event"] === "trigger.accepted"), "accept audited");
});

test("W0 SECURITY: a tampered body does not match its signature → REJECTED, handler never called", async () => {
  let called = 0;
  const { ingress } = makeIngress(async () => { called++; });
  const original = linearBody("ENG-2", "legit change");
  const sig = linearHeaders(original); // signature bound to the original bytes
  const tampered = linearBody("ENG-2", "MALICIOUS injected instruction");
  const r = await ingress.receive({ source: "linear", rawBody: tampered, headers: sig });
  assert.equal(r.status, "rejected");
  assert.equal(called, 0, "a forged/tampered payload never reaches the handler");
});

test("W0 SECURITY: a wrong-secret signature is rejected", async () => {
  const { ingress } = makeIngress();
  const body = linearBody("ENG-3", "x");
  const r = await ingress.receive({ source: "linear", rawBody: body, headers: linearHeaders(body, "attacker-secret") });
  assert.equal(r.status, "rejected");
});

test("W0 SECURITY: a missing signature header is rejected (fail-closed)", async () => {
  const { ingress } = makeIngress();
  const body = linearBody("ENG-4", "x");
  const r = await ingress.receive({ source: "linear", rawBody: body, headers: {} });
  assert.equal(r.status, "rejected");
});

test("W0 IDEMPOTENCY: replaying the exact same delivery → duplicate; handler runs exactly once", async () => {
  let called = 0;
  const { ingress } = makeIngress(async () => { called++; });
  const body = linearBody("ENG-5", "dedupe me");
  const h = linearHeaders(body);
  const r1 = await ingress.receive({ source: "linear", rawBody: body, headers: h });
  const r2 = await ingress.receive({ source: "linear", rawBody: body, headers: h });
  assert.equal(r1.status, "accepted");
  assert.equal(r2.status, "duplicate");
  assert.equal(called, 1, "the same logical event is processed exactly once");
});

test("W0 IDEMPOTENCY (cross-transport): a poll of the same ticket state a webhook already accepted is deduped", async () => {
  let called = 0;
  const { router, ingress } = makeIngress(async () => { called++; });
  const body = linearBody("ENG-6", "cross transport");
  await ingress.receive({ source: "linear", rawBody: body, headers: linearHeaders(body) }); // via webhook
  const native = JSON.parse(body) as Record<string, unknown>;
  const poll = new PollingSource("linear", router, ingress, async () => [native]); // same state via polling
  const res = await poll.poll();
  assert.equal(res.duplicates, 1, "the poll dedups against the webhook — one mechanism");
  assert.equal(called, 1, "not double-processed across transports");
});

test("W0: polling accepts a genuinely new ticket and dedups on re-poll", async () => {
  let called = 0;
  const { router, ingress } = makeIngress(async () => { called++; });
  const native = JSON.parse(linearBody("ENG-9", "polled-in")) as Record<string, unknown>;
  const poll = new PollingSource("linear", router, ingress, async () => [native]);
  assert.equal((await poll.poll()).accepted, 1);
  assert.equal((await poll.poll()).duplicates, 1, "re-poll is idempotent");
  assert.equal(called, 1);
});

test("W0 SECURITY: a stale timestamp (replay window exceeded) is rejected (generic scheme)", () => {
  const v = new WebhookVerifier();
  const body = JSON.stringify({ hello: "world" });
  const staleTs = Math.floor(Date.now() / 1000) - 10_000; // far outside 300s
  const sig = "sha256=" + hmacHex(SECRET, `${staleTs}.${body}`);
  const r = v.verify({ source: "generic", rawBody: body, secret: SECRET, headers: { "x-webhook-signature": sig, "x-webhook-timestamp": String(staleTs) } });
  assert.equal(r.ok, false);
});

test("W0: GitHub sha256= signature verifies and carries the delivery id", () => {
  const v = new WebhookVerifier();
  const body = JSON.stringify({ action: "opened", issue: { number: 7, title: "t", body: "b" } });
  const r = v.verify({ source: "github-issues", rawBody: body, secret: SECRET, headers: { "x-hub-signature-256": "sha256=" + hmacHex(SECRET, body), "x-github-delivery": "abc-123" } });
  assert.ok(r.ok && r.deliveryId === "github:abc-123");
});

test("W0: GitLab token equality verifies; a wrong token is rejected", () => {
  const v = new WebhookVerifier();
  const body = JSON.stringify({ object_kind: "issue" });
  assert.ok(v.verify({ source: "gitlab", rawBody: body, secret: SECRET, headers: { "x-gitlab-token": SECRET, "x-gitlab-event-uuid": "u1" } }).ok);
  assert.equal(v.verify({ source: "gitlab", rawBody: body, secret: SECRET, headers: { "x-gitlab-token": "nope", "x-gitlab-event-uuid": "u1" } }).ok, false);
});

test("W0 SAFETY (I5/I6): the ingress has NO merge surface — the front door can never auto-merge", async () => {
  const { ingress } = makeIngress(async () => {});
  assert.equal(typeof (ingress as unknown as { merge?: unknown }).merge, "undefined");
  assert.equal(typeof (ingress as unknown as { publish?: unknown }).publish, "undefined");
  const body = linearBody("ENG-7", "x");
  const r = await ingress.receive({ source: "linear", rawBody: body, headers: linearHeaders(body) });
  assert.equal(r.status, "accepted"); // produces an Issue for the human-gated pipeline; nothing merged
});

test("W0: the zero-dep HTTP listener accepts a signed request over a real socket (202), dedups a replay (200), rejects a forgery (401)", async () => {
  const { ingress } = makeIngress(async () => {});
  const { startHttpIngress } = await import("../src/ingress/http_ingress.js");
  const h = await startHttpIngress(ingress, { host: "127.0.0.1" });
  try {
    const body = linearBody("ENG-8", "over http");
    const sig = hmacHex(SECRET, body);
    const post = async (signature: string) =>
      (await fetch(`http://127.0.0.1:${h.port}/webhook/linear`, { method: "POST", headers: { "Linear-Signature": signature, "content-type": "application/json" }, body })).status;
    assert.equal(await post(sig), 202, "signed request accepted");
    assert.equal(await post(sig), 200, "replay deduped (idempotent ack)");
    assert.equal(await post("deadbeef"), 401, "forged signature rejected at the socket");
  } finally {
    await h.close();
  }
});

test("W0: composeKeep exposes triggerIngress, and with NO secret configured a webhook is fail-closed (rejected)", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-w0-c-")) });
  assert.ok(app.triggerIngress, "triggerIngress exposed on the composed app");
  const body = linearBody("ENG-10", "no secret configured");
  const r = await app.triggerIngress.receive({ source: "linear", rawBody: body, headers: linearHeaders(body) });
  assert.equal(r.status, "rejected", "unconfigured source is fail-closed by default (safe)");
});

// ─── Red-team fixes: provider-agnosticism, retryable handler failure, reachable no-webhook path ───

test("RED-TEAM F1 (provider-agnostic): a GENERIC-envelope payload from a non-Linear tracker normalizes + ingests", async () => {
  let seen = 0;
  const { ingress } = makeIngress(async () => { seen++; });
  // A homegrown/Gitea/Bugzilla tracker posts a simple envelope — no bespoke adapter needed.
  const native = { key: "GITEA-42", summary: "flaky test on CI", description: "fails intermittently", labels: ["bug"], action: "created" };
  const r = await ingress.ingestNative("generic", native);
  assert.equal(r.status, "accepted");
  assert.equal(seen, 1);
});

test("RED-TEAM F2 (self-healing): a handler failure does NOT drop the ticket — a redelivery retries and can succeed", async () => {
  let attempts = 0;
  const { ingress } = makeIngress(async () => { attempts++; if (attempts === 1) throw new Error("transient solve failure"); });
  const body = linearBody("ENG-RT", "retry me");
  const h = linearHeaders(body);
  const first = await ingress.receive({ source: "linear", rawBody: body, headers: h });
  assert.equal(first.status, "error", "handler failure surfaces as a retryable error, not a silent accept");
  const retry = await ingress.receive({ source: "linear", rawBody: body, headers: h });
  assert.equal(retry.status, "accepted", "the redelivery RE-RUNS (not deduped) and succeeds");
  assert.equal(attempts, 2, "the ticket was retried, never dropped");
  const third = await ingress.receive({ source: "linear", rawBody: body, headers: h });
  assert.equal(third.status, "duplicate", "once succeeded, further redeliveries dedup");
});

test("RED-TEAM F4 (stability): dedup survives a restart — a fresh ingress seeded from the spine still dedups", async () => {
  const spine = newSpine();
  const router = new TriggerRouter(); registerAllTrackers(router);
  const mk = () => new TriggerIngress({ verifier: new WebhookVerifier(), router, spine, secretFor: () => SECRET, handler: async () => {} });
  const body = linearBody("ENG-RESTART", "persist dedup");
  const r1 = await mk().receive({ source: "linear", rawBody: body, headers: linearHeaders(body) });
  assert.equal(r1.status, "accepted");
  // a NEW ingress instance (simulating a restart) seeded from the same spine must still dedup
  const r2 = await mk().receive({ source: "linear", rawBody: body, headers: linearHeaders(body) });
  assert.equal(r2.status, "duplicate", "dedup index rebuilt from the durable spine");
});

test("RED-TEAM F6 (N=1 reachable): `keep ingest generic <file>` routes payloads through the deduped ingress", async () => {
  const { composeKeep } = await import("../src/compose.js");
  const { runCli } = await import("../src/cli/cli_core.js");
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-ingest-")) });
  const payloads = [{ id: "A-1", title: "first", action: "created" }, { id: "A-2", title: "second" }];
  const out: string[] = [];
  const io = { write: (s: string) => out.push(s), prompt: async () => "" };
  await runCli(["ingest", "generic", "/tmp/whatever.json"], io, { app, readFile: () => JSON.stringify(payloads) });
  assert.match(out.join("\n"), /2 accepted/);
});

// ─── Runaway audit: a PERMANENT handler failure must be BOUNDED (dead-lettered), not retried forever ───

test("RUNAWAY: a permanently-failing handler is retried a BOUNDED number of times then dead-lettered (no storm)", async () => {
  let calls = 0;
  const spine = newSpine();
  const router = new TriggerRouter(); registerAllTrackers(router);
  const ingress = new TriggerIngress({
    verifier: new WebhookVerifier(), router, spine, secretFor: () => SECRET,
    handler: async () => { calls++; throw new Error("permanent failure"); },
    maxHandlerRetries: 2,
  });
  const body = linearBody("ENG-DL", "always fails");
  const h = linearHeaders(body);
  const r1 = await ingress.receive({ source: "linear", rawBody: body, headers: h });
  assert.equal(r1.status, "error", "attempt 1 → retryable error");
  const r2 = await ingress.receive({ source: "linear", rawBody: body, headers: h });
  assert.equal(r2.status, "dead-letter", "attempt 2 hits the cap → dead-lettered (retries stopped)");
  // Any further redeliveries are terminal duplicates — the handler is NOT called again (no runaway).
  const r3 = await ingress.receive({ source: "linear", rawBody: body, headers: h });
  assert.equal(r3.status, "duplicate");
  const r4 = await ingress.receive({ source: "linear", rawBody: body, headers: h });
  assert.equal(r4.status, "duplicate");
  assert.equal(calls, 2, "handler ran exactly maxHandlerRetries times — bounded, no storm");
  await spine.seal();
  assert.ok(spine.replay().some((e) => (e.payload as Record<string, unknown>)["event"] === "trigger.dead-lettered"), "dead-letter surfaced for a human");
});

test("RUNAWAY: dead-letter is durable — a restart does NOT resurrect a dead-lettered ticket", async () => {
  const spine = newSpine();
  const router = new TriggerRouter(); registerAllTrackers(router);
  const mk = () => new TriggerIngress({ verifier: new WebhookVerifier(), router, spine, secretFor: () => SECRET, handler: async () => { throw new Error("permanent"); }, maxHandlerRetries: 1 });
  const body = linearBody("ENG-DL2", "always fails");
  const h = linearHeaders(body);
  assert.equal((await mk().receive({ source: "linear", rawBody: body, headers: h })).status, "dead-letter");
  // fresh instance (restart) seeded from the spine must treat it as terminal, not retry it
  assert.equal((await mk().receive({ source: "linear", rawBody: body, headers: h })).status, "duplicate");
});

test("W2 wiring: a dead-lettered ticket fires an URGENT notification via the onDeadLetter hook", async () => {
  const { NotificationRouter, CollectingChannel } = await import("../src/notify/notification_router.js");
  const ch = new CollectingChannel();
  const notifications = new NotificationRouter({ channel: ch });
  const spine = newSpine();
  const router = new TriggerRouter(); registerAllTrackers(router);
  const ingress = new TriggerIngress({
    verifier: new WebhookVerifier(), router, spine, secretFor: () => SECRET,
    handler: async () => { throw new Error("permanent"); },
    maxHandlerRetries: 1,
    onDeadLetter: (id, reason) => notifications.notifyDeadLetter(id, reason),
  });
  const body = linearBody("ENG-W2", "will dead-letter");
  const r = await ingress.receive({ source: "linear", rawBody: body, headers: linearHeaders(body) });
  assert.equal(r.status, "dead-letter");
  assert.equal(ch.sent.length, 1);
  assert.equal(ch.sent[0]?.tier, "urgent");
  assert.equal(ch.sent[0]?.kind, "dead-letter");
});

test("W0 ALLOWLIST: a direct-peer IP allowlist admits an allowed IP, denies others, and fails CLOSED when empty", async () => {
  const { startHttpIngress, normalizeIp } = await import("../src/ingress/http_ingress.js");
  const body = linearBody("ENG-9", "allowlist");
  const sig = hmacHex(SECRET, body);
  const post = async (port: number) =>
    (await fetch(`http://127.0.0.1:${port}/webhook/linear`, { method: "POST", headers: { "Linear-Signature": sig, "content-type": "application/json" }, body })).status;

  // 1) 127.0.0.1 allowed → the signed request is processed (202).
  {
    const { ingress } = makeIngress(async () => {});
    const h = await startHttpIngress(ingress, { host: "127.0.0.1", allowedIps: ["127.0.0.1"] });
    try { assert.equal(await post(h.port), 202, "an allowlisted peer is admitted"); } finally { await h.close(); }
  }
  // 2) allowlist that excludes localhost → the real localhost request is denied at the socket (403), before verification.
  {
    const { ingress } = makeIngress(async () => {});
    const h = await startHttpIngress(ingress, { host: "127.0.0.1", allowedIps: ["10.0.0.5"] });
    try { assert.equal(await post(h.port), 403, "a non-allowlisted peer is refused"); } finally { await h.close(); }
  }
  // 3) FAIL CLOSED: an explicitly empty allowlist denies everything (never fails open — the 2026 CVE class).
  {
    const { ingress } = makeIngress(async () => {});
    const h = await startHttpIngress(ingress, { host: "127.0.0.1", allowedIps: [] });
    try { assert.equal(await post(h.port), 403, "an empty allowlist fails closed"); } finally { await h.close(); }
  }
  // 4) IPv4-mapped IPv6 normalizes so ::ffff:127.0.0.1 and 127.0.0.1 compare equal.
  assert.equal(normalizeIp("::ffff:127.0.0.1"), "127.0.0.1");
  assert.equal(normalizeIp("127.0.0.1"), "127.0.0.1");
});

test("W0 ALLOWLIST: X-Forwarded-For is NOT trusted for the allowlist (spoof attempt is still denied)", async () => {
  const { startHttpIngress } = await import("../src/ingress/http_ingress.js");
  const { ingress } = makeIngress(async () => {});
  const h = await startHttpIngress(ingress, { host: "127.0.0.1", allowedIps: ["10.0.0.5"] });
  try {
    const body = linearBody("ENG-11", "xff spoof");
    const status = (await fetch(`http://127.0.0.1:${h.port}/webhook/linear`, {
      method: "POST",
      headers: { "Linear-Signature": hmacHex(SECRET, body), "content-type": "application/json", "x-forwarded-for": "10.0.0.5" },
      body,
    })).status;
    assert.equal(status, 403, "spoofing X-Forwarded-For to an allowlisted IP does NOT bypass the direct-peer check");
  } finally { await h.close(); }
});
