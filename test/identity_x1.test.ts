import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { SessionStore } from "../src/identity/session_store.js";
import { composeKeep } from "../src/compose.js";
import { handleReviewRequest, type WebRequest, type WebSecurity, type IdentityLayer } from "../src/review/review_web.js";
import { OWNER } from "../src/identity/rbac.js";

// ─── identity provider ───

test("X1 provider: a validly signed, unexpired assertion verifies; tampered/expired/garbage do not", async () => {
  const p = new HmacAssertionProvider("s3cret");
  const good = p.sign({ sub: "u1", email: "a@b.com", name: "Ada", exp: 1000 });
  assert.deepEqual(await p.verify(good, 500), { subject: "u1", email: "a@b.com", displayName: "Ada" });
  assert.equal(await p.verify(good, 2000), null, "expired → null");
  assert.equal(await p.verify(good.slice(0, -2) + "00", 500), null, "tampered signature → null");
  assert.equal(await p.verify("not-an-assertion", 500), null);
  const otherSigner = new HmacAssertionProvider("different");
  assert.equal(await p.verify(otherSigner.sign({ sub: "u1", exp: 1000 }), 500), null, "wrong signing key → null");
});

// ─── principal registry ───

test("X1 registry: resolves by subject and by email (case-insensitive); unknown → null (deny-by-default)", () => {
  const reg = new PrincipalRegistry([
    { subject: "sub-rev", role: "reviewer", id: "rev", tenant: "alpha" },
    { email: "boss@x.com", role: "maintainer", id: "boss" },
  ]);
  assert.equal(reg.resolve({ subject: "sub-rev" })?.role, "reviewer");
  assert.equal(reg.resolve({ subject: "sub-rev" })?.tenant, "alpha", "a verified enterprise identity retains its explicit tenant boundary");
  assert.equal(reg.resolve({ subject: "z", email: "BOSS@X.com" })?.role, "maintainer");
  assert.equal(reg.resolve({ subject: "nobody", email: "no@x.com" }), null);
});

// ─── session store ───

test("X1 sessions: create→get works; idle + absolute timeouts expire and destroy; revoke works", () => {
  const s = new SessionStore({ idleMs: 100, absoluteMs: 1000 });
  const sess = s.create({ id: "u", kind: "human", role: "reviewer" }, 0);
  assert.equal(s.get(sess.id, 50)?.principal.id, "u");
  assert.equal(s.get(sess.id, 50 + 101), null, "idle timeout (no activity for >idleMs) expires");
  assert.equal(s.activeCount(), 0, "expired session destroyed server-side");
  const s2 = new SessionStore({ idleMs: 10_000, absoluteMs: 500 });
  const a = s2.create({ id: "u", kind: "human", role: "reviewer" }, 0);
  s2.get(a.id, 400); // active, but...
  assert.equal(s2.get(a.id, 600), null, "absolute cap expires even with activity");
  const s3 = new SessionStore();
  const b = s3.create({ id: "u", kind: "human", role: "reviewer" }, 0);
  s3.revoke(b.id);
  assert.equal(s3.get(b.id, 1), null, "revoked session is gone");
});

// ─── the full multi-user web flow ───

const TOKEN = "srv-token";
function idLayer() {
  const provider = new HmacAssertionProvider("idp-secret");
  const registry = new PrincipalRegistry([
    { email: "rev@x.com", role: "reviewer", id: "rev", displayName: "Reviewer" },
    { subject: "sub-view", role: "viewer", id: "vw" },
  ]);
  const sessions = new SessionStore();
  return { provider, registry, sessions } satisfies IdentityLayer;
}
function appWithReview(id = "pr-1") {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-x1-")) });
  const m = { id, title: "t", body: "", branch: "b", baseBranch: "main", diff: "", intent: "do x", executed: [], checks: [], attribution: "keep", humanApprovalRequired: true, oversight: { band: "medium", disposition: "human-approval-required", mode: "block-until-approved", requiresImmediateAttention: false, reasons: [] } };
  app.spine.stage({ type: "identity.action", actor: "cli", payload: { event: "review.pending", reviewId: id, manifest: m, ts: 1 } });
  return app;
}
const sec = (identity: IdentityLayer, over: Partial<WebSecurity> = {}): WebSecurity => ({ token: TOKEN, origin: "http://127.0.0.1:9", allowedHosts: ["127.0.0.1:9"], principal: OWNER, identity, now: 1000, ...over });
const rq = (over: Partial<WebRequest>): WebRequest => ({ method: "GET", path: "/", query: {}, headers: { host: "127.0.0.1:9" }, body: "", ...over });
function cookieFrom(res: { headers: Readonly<Record<string, string>> }): string {
  const sc = res.headers["Set-Cookie"] ?? "";
  return sc.split(";")[0] ?? "";
}

test("X1 web: no session → GET / redirects to /login", async () => {
  const id = idLayer();
  const r = await handleReviewRequest(appWithReview(), rq({ path: "/" }), sec(id));
  assert.equal(r.status, 303);
  assert.equal(r.headers["Location"], "/login");
});

test("X1 web: login with a valid assertion issues a session; that session can view and (as reviewer) decide", async () => {
  const id = idLayer();
  const app = appWithReview();
  const assertion = id.provider.sign({ sub: "sub-rev", email: "rev@x.com", name: "Reviewer", exp: 5000 });
  const login = await handleReviewRequest(app, rq({ method: "POST", path: "/login", headers: { host: "127.0.0.1:9", origin: "http://127.0.0.1:9" }, body: `assertion=${encodeURIComponent(assertion)}` }), sec(id));
  assert.equal(login.status, 303);
  assert.equal(login.headers["Location"], "/");
  const cookie = cookieFrom(login);
  assert.match(cookie, /keep_session=/);
  const sid = cookie.split("=")[1]!;

  // signed-in list page
  const list = await handleReviewRequest(app, rq({ path: "/", headers: { host: "127.0.0.1:9", cookie } }), sec(id));
  assert.equal(list.status, 200);
  assert.match(list.body, /Signed in as/);

  // decide as the reviewer (needs the session's own CSRF token)
  const csrf = id.sessions.get(sid, 1000)!.csrfToken;
  const decide = await handleReviewRequest(app, rq({ method: "POST", path: "/review/pr-1/decide", headers: { host: "127.0.0.1:9", cookie, origin: "http://127.0.0.1:9" }, body: `action=approve&csrf=${csrf}` }), sec(id));
  assert.equal(decide.status, 303);
  const decided = app.spine.currentEvents().map((e) => e.payload as Record<string, unknown>).find((p) => p["event"] === "review.decided");
  assert.equal(decided!["by"], "rev", "the decision is attributed to the signed-in reviewer");
});

test("X1 web: an unknown identity is refused a session (403) and the denial is audited", async () => {
  const id = idLayer();
  const app = appWithReview();
  const assertion = id.provider.sign({ sub: "stranger", email: "no@x.com", exp: 5000 });
  const r = await handleReviewRequest(app, rq({ method: "POST", path: "/login", headers: { host: "127.0.0.1:9", origin: "http://127.0.0.1:9" }, body: `assertion=${encodeURIComponent(assertion)}` }), sec(id));
  assert.equal(r.status, 403);
  assert.equal(id.sessions.activeCount(), 0, "no session issued");
  assert.ok(app.spine.currentEvents().map((e) => e.payload as Record<string, unknown>).find((p) => p["event"] === "authz.denied" && p["action"] === "login"));
});

test("X1 web: a tampered assertion is rejected (401, no session)", async () => {
  const id = idLayer();
  const assertion = id.provider.sign({ sub: "sub-rev", email: "rev@x.com", exp: 5000 }).slice(0, -2) + "zz";
  const r = await handleReviewRequest(appWithReview(), rq({ method: "POST", path: "/login", headers: { host: "127.0.0.1:9", origin: "http://127.0.0.1:9" }, body: `assertion=${encodeURIComponent(assertion)}` }), sec(id));
  assert.equal(r.status, 401);
  assert.equal(id.sessions.activeCount(), 0);
});

test("X1 web: RBAC still enforced per session — a viewer session cannot decide (403)", async () => {
  const id = idLayer();
  const app = appWithReview();
  const viewer = id.sessions.create({ id: "vw", kind: "human", role: "viewer" }, 1000);
  const decide = await handleReviewRequest(app, rq({ method: "POST", path: "/review/pr-1/decide", headers: { host: "127.0.0.1:9", cookie: `keep_session=${viewer.id}`, origin: "http://127.0.0.1:9" }, body: `action=approve&csrf=${viewer.csrfToken}` }), sec(id));
  assert.equal(decide.status, 403);
  assert.equal(app.spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "review.decided"), false);
});

test("X1 web: logout destroys the session server-side (next request → /login)", async () => {
  const id = idLayer();
  const app = appWithReview();
  const s = id.sessions.create({ id: "rev", kind: "human", role: "reviewer" }, 1000);
  const out = await handleReviewRequest(app, rq({ method: "POST", path: "/logout", headers: { host: "127.0.0.1:9", cookie: `keep_session=${s.id}`, origin: "http://127.0.0.1:9" } }), sec(id));
  assert.equal(out.status, 303);
  assert.equal(id.sessions.get(s.id, 1000), null, "session destroyed server-side");
  const after = await handleReviewRequest(app, rq({ path: "/", headers: { host: "127.0.0.1:9", cookie: `keep_session=${s.id}` } }), sec(id));
  assert.equal(after.headers["Location"], "/login");
});

test("X1 N=1 preserved: with no identity layer, single-owner token mode is unchanged", async () => {
  const app = appWithReview();
  const single: WebSecurity = { token: TOKEN, origin: "http://127.0.0.1:9", allowedHosts: ["127.0.0.1:9"], principal: OWNER };
  const r = await handleReviewRequest(app, rq({ path: "/", headers: { host: "127.0.0.1:9", cookie: `keep_token=${TOKEN}` } }), single);
  assert.equal(r.status, 200);
  assert.doesNotMatch(r.body, /Signed in as/, "no session header in single-owner mode");
});
