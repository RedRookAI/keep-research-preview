import { test } from "node:test";
import assert from "node:assert/strict";
import { get } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleReviewRequest, type WebRequest, type WebSecurity } from "../src/review/review_web.js";
import { startReviewServer } from "../src/review/review_server.js";
import type { PrManifest } from "../src/git/pull_request.js";
import { OWNER, type Principal } from "../src/identity/rbac.js";

const TOKEN = "test-token-abc";
const SEC: WebSecurity = { token: TOKEN, origin: "http://127.0.0.1:7777", allowedHosts: ["127.0.0.1:7777", "localhost:7777"], principal: OWNER };
const secAs = (principal: Principal): WebSecurity => ({ ...SEC, principal });
const PERSUASIVE = [/you should approve/i, /we recommend/i, /keep recommends/i, /looks good/i, /safe to approve/i, /go ahead and approve/i];

function appWith(manifest: Record<string, unknown>) {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-s2-")) });
  app.spine.stage({ type: "identity.action", actor: "cli", payload: { event: "review.pending", reviewId: String(manifest["id"]), manifest, ts: Date.now() } });
  return app;
}
function decisionManifest(id: string, title = "Change password hashing"): Record<string, unknown> {
  return { id, title, body: "", branch: "keep/x", baseBranch: "main", diff: "", intent: "Upgrade password hashing to argon2", executed: [], checks: [], attribution: "keep", humanApprovalRequired: true, oversight: { band: "medium", disposition: "human-approval-required", mode: "block-until-approved", requiresImmediateAttention: false, reasons: ["touches auth"] } };
}
function req(over: Partial<WebRequest>): WebRequest {
  return { method: "GET", path: "/", query: {}, headers: { host: "127.0.0.1:7777" }, body: "", ...over };
}
const authed = (over: Partial<WebRequest>): WebRequest => req({ ...over, headers: { host: "127.0.0.1:7777", cookie: `keep_token=${TOKEN}`, ...(over.headers ?? {}) } });

test("S2 security: a wrong Host header is refused (DNS-rebinding guard, CVE-2025-66414 class)", async () => {
  const app = appWith(decisionManifest("pr-1"));
  const r = await handleReviewRequest(app, req({ headers: { host: "evil.example.com", cookie: `keep_token=${TOKEN}` } }), SEC);
  assert.equal(r.status, 403);
});

test("S2 security: no token → 401", async () => {
  const app = appWith(decisionManifest("pr-1"));
  assert.equal((await handleReviewRequest(app, req({}), SEC)).status, 401);
});

test("S2 security: a token in the URL bootstraps a SameSite=Strict, HttpOnly cookie then redirects", async () => {
  const app = appWith(decisionManifest("pr-1"));
  const r = await handleReviewRequest(app, req({ query: { token: TOKEN } }), SEC);
  assert.equal(r.status, 303);
  const cookie = r.headers["Set-Cookie"] ?? "";
  assert.match(cookie, /keep_token=/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
});

test("S2 security: POST decide without a CSRF token → 403 (no decision recorded)", async () => {
  const app = appWith(decisionManifest("pr-1"));
  const r = await handleReviewRequest(app, authed({ method: "POST", path: "/review/pr-1/decide", headers: { origin: SEC.origin }, body: "action=approve" }), SEC);
  assert.equal(r.status, 403);
  assert.equal(app.spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "review.decided"), false);
});

test("S2 security: POST decide from a foreign Origin → 403", async () => {
  const app = appWith(decisionManifest("pr-1"));
  const r = await handleReviewRequest(app, authed({ method: "POST", path: "/review/pr-1/decide", headers: { origin: "http://evil.example.com" }, body: `action=approve&csrf=${TOKEN}` }), SEC);
  assert.equal(r.status, 403);
});

test("S2 decision routes through the SHARED path: a valid POST approve records review.decided", async () => {
  const app = appWith(decisionManifest("pr-1"));
  const r = await handleReviewRequest(app, authed({ method: "POST", path: "/review/pr-1/decide", headers: { origin: SEC.origin }, body: `action=approve&csrf=${TOKEN}` }), SEC);
  assert.equal(r.status, 303, "redirects back to the list");
  const decided = app.spine.currentEvents().map((e) => e.payload as Record<string, unknown>).find((p) => p["event"] === "review.decided");
  assert.ok(decided, "a review.decided event was recorded");
  assert.equal(decided!["decision"], "approved");
});

test("S2 rendering: the detail page states the disposition, is non-persuasive, and carries a CSRF token", async () => {
  const app = appWith(decisionManifest("pr-1"));
  const r = await handleReviewRequest(app, authed({ path: "/review/pr-1" }), SEC);
  assert.equal(r.status, 200);
  assert.match(r.body, /needs your decision/i);
  assert.match(r.body, /not recommending either way/);
  for (const rx of PERSUASIVE) assert.doesNotMatch(r.body, rx);
  assert.match(r.body, new RegExp(`name="csrf" value="${TOKEN}"`));
  assert.match(r.body, /name="action" value="approve"/);
});

test("S2 rendering: a malicious title/intent is HTML-escaped (no XSS)", async () => {
  const m = { ...decisionManifest("pr-x"), intent: '<script>alert(1)</script>' };
  const app = appWith(m);
  const r = await handleReviewRequest(app, authed({ path: "/review/pr-x" }), SEC);
  assert.doesNotMatch(r.body, /<script>alert\(1\)<\/script>/);
  assert.match(r.body, /&lt;script&gt;/);
});

test("S2 list: pending changes are grouped into decisions vs auto-approved", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-s2l-")) });
  app.spine.stage({ type: "identity.action", actor: "cli", payload: { event: "review.pending", reviewId: "d1", manifest: decisionManifest("d1", "Auth change"), ts: Date.now() } });
  const auto = { ...decisionManifest("a1", "Typo fix"), oversight: { band: "low", disposition: "auto-approved", mode: "silent-auto", requiresImmediateAttention: false, reasons: [] } };
  app.spine.stage({ type: "identity.action", actor: "cli", payload: { event: "review.pending", reviewId: "a1", manifest: auto, ts: Date.now() } });
  const r = await handleReviewRequest(app, authed({ path: "/" }), SEC);
  assert.match(r.body, /Needs your decision/);
  assert.match(r.body, /Auto-approved/);
});

test("S2 wiring: `keep serve` starts the UI via the injected seam and prints the token URL", async () => {
  const { runCli } = await import("../src/cli/cli_core.js");
  const app = appWith(decisionManifest("pr-1"));
  const out: string[] = [];
  let started = false;
  const fakeServe = async (_app: unknown, opts: { port?: number }) => { started = true; return { url: "http://127.0.0.1:9999/?token=XYZ", origin: "http://127.0.0.1:9999", port: opts.port ?? 9999, token: "XYZ", close: async () => {} }; };
  await runCli(["serve", "--port=0"], { write: (s: string) => out.push(s), prompt: async () => "" }, { app, serveReviews: fakeServe });
  assert.equal(started, true);
  assert.match(out.join("\n"), /http:\/\/127\.0\.0\.1:9999\/\?token=XYZ/);
  assert.match(out.join("\n"), /127\.0\.0\.1/);
});

test("X0 web: a viewer principal is refused at POST decide (403, no decision recorded)", async () => {
  const app = appWith(decisionManifest("pr-1"));
  const r = await handleReviewRequest(app, authed({ method: "POST", path: "/review/pr-1/decide", headers: { origin: SEC.origin }, body: `action=approve&csrf=${TOKEN}` }), secAs({ id: "v", kind: "human", role: "viewer" }));
  assert.equal(r.status, 403);
  assert.equal(app.spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "review.decided"), false);
});

test("X0 web: a viewer sees a view-only notice instead of Approve/Decline controls", async () => {
  const app = appWith(decisionManifest("pr-1"));
  const r = await handleReviewRequest(app, authed({ path: "/review/pr-1" }), secAs({ id: "v", kind: "human", role: "viewer" }));
  assert.match(r.body, /view-only access/);
  assert.doesNotMatch(r.body, /name="action" value="approve"/);
});

test("S2 integration (real socket): the server binds localhost, requires the token, and serves", async () => {
  const app = appWith(decisionManifest("pr-1"));
  const handle = await startReviewServer(app, { port: 0, token: TOKEN });
  try {
    assert.match(handle.url, /^http:\/\/127\.0\.0\.1:\d+\/\?token=/);
    const body: string = await new Promise((resolve, reject) => {
      get(`${handle.origin}/?token=${TOKEN}`, (res) => {
        // 303 bootstrap redirect (sets cookie) — that's the authenticated happy path
        assert.equal(res.statusCode, 303);
        let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => resolve(d));
      }).on("error", reject);
    });
    assert.equal(typeof body, "string");
    // no token → unauthorized
    const status: number = await new Promise((resolve, reject) => {
      get(`${handle.origin}/`, (res) => { res.resume(); resolve(res.statusCode ?? 0); }).on("error", reject);
    });
    assert.equal(status, 401);
  } finally {
    await handle.close();
  }
});
