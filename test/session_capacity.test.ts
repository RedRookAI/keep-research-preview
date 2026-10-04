import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SessionStore, SessionCapacityError } from "../src/identity/session_store.js";
import { HmacAssertionProvider, PrincipalRegistry } from "../src/identity/identity_provider.js";
import { OWNER, type Principal } from "../src/identity/rbac.js";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest, type GatewayRequest } from "../src/gateway/http_gateway.js";
import { handleReviewRequest } from "../src/review/review_web.js";

const human: Principal = { id: "alice", kind: "human", role: "maintainer", tenant: "acme" };
const state = (s: SessionStore) => s as unknown as { sessions: ReadonlyMap<string, unknown>; reservations?: ReadonlySet<symbol> };
const occupied = (s: SessionStore) => state(s).sessions.size + (state(s).reservations?.size ?? 0);

test("finite global session capacity preserves live owner and organization sessions", () => {
  const s = new SessionStore({ ...{ maxSessions: 2 }, idleMs: 100, absoluteMs: 500 });
  const owner = s.create(OWNER, 0), member = s.create(human, 0);
  assert.throws(() => s.create(human, 1), /capacity/i);
  assert.equal(occupied(s), 2); assert.ok(s.get(owner.id, 50)); assert.ok(s.get(member.id, 50));
  const replacement = s.create(human, 151); assert.equal(occupied(s), 1); assert.ok(s.get(replacement.id, 151));
});

test("invalid global capacity is rejected before serving sessions", () => {
  for (const maxSessions of [0, -1, NaN, Infinity, -Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => new SessionStore({ ...{ maxSessions }, idleMs: 100 }), /maxSessions|capacity/i);
  }
});

function fixture(maxSessions = 1) {
  const root = mkdtempSync(join(tmpdir(), "keep-session-capacity-"));
  const provider = new HmacAssertionProvider("owned-fixture-key");
  const administrator: Principal = { ...human, role: "owner" };
  const registry = new PrincipalRegistry([{ subject: "alice", id: "alice", role: "owner", tenant: "acme" }]);
  const sessions = new SessionStore({ ...{ maxSessions }, idleMs: 30 * 60_000 });
  const app = composeKeep({ dataDir: root, delegationParentFor: (id, tenant) => id === administrator.id && tenant === administrator.tenant ? administrator : undefined });
  const now = Date.now(), identity = { provider, registry, sessions };
  const login = sessions.create(administrator, now);
  const assertion = provider.sign({ sub: "alice", exp: now + 60_000 });
  const request = (path: string, body: unknown): GatewayRequest => ({ method: "POST", path, query: {}, headers: { authorization: "Bearer fixture", "x-keep-session": login.id }, body: JSON.stringify(body) });
  const issueRequest = (grantId = "grant-cap") => request("/delegation/issue", { agentId: "agent-cap", grantId, expiresAt: now + 60_000, permissions: ["memory.read"] });
  return { root, provider, sessions, app, identity, login, assertion, now, request, issueRequest, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("full store refuses verified gateway login with typed 503 and preserves authentication denials", async () => {
  const f = fixture();
  try {
    const sec = { token: "fixture", identity: f.identity };
    const response = await handleGatewayRequest(f.app, f.request("/auth/session", { assertion: f.assertion }), sec);
    assert.equal(response.status, 503); assert.equal(JSON.parse(response.body).code, "session-capacity");
    assert.equal(occupied(f.sessions), 1); assert.ok(f.sessions.get(f.login.id, Date.now()));
    assert.equal((await handleGatewayRequest(f.app, f.request("/auth/session", { assertion: "invalid" }), sec)).status, 401);
    const unknown = f.provider.sign({ sub: "unknown", exp: f.now + 60_000 });
    assert.equal((await handleGatewayRequest(f.app, f.request("/auth/session", { assertion: unknown }), sec)).status, 403);
  } finally { f.cleanup(); }
});

test("full store refuses verified review login without a session cookie", async () => {
  const f = fixture();
  try {
    const response = await handleReviewRequest(f.app, { method: "POST", path: "/login", query: {}, headers: { host: "127.0.0.1:9", origin: "http://127.0.0.1:9" }, body: `assertion=${encodeURIComponent(f.assertion)}` },
      { token: "fixture", origin: "http://127.0.0.1:9", allowedHosts: ["127.0.0.1:9"], principal: OWNER, identity: f.identity, now: f.now });
    assert.equal(response.status, 503); assert.match(response.body, /session capacity/i);
    assert.equal(response.headers["Set-Cookie"], undefined); assert.equal(occupied(f.sessions), 1);
    assert.ok(f.sessions.get(f.login.id, f.now));
  } finally { f.cleanup(); }
});

test("full store refuses delegation before issue and leaves its durable grant projection unchanged", async () => {
  const f = fixture();
  try {
    let issued = 0; const original = f.app.authorization.issue.bind(f.app.authorization);
    f.app.authorization.issue = async (...args) => { issued++; return original(...args); };
    const before = f.app.spine.replay().filter(e => (e.payload as { event?: string }).event?.startsWith("delegation."));
    const response = await handleGatewayRequest(f.app, f.issueRequest(), { token: "fixture", identity: f.identity });
    assert.equal(response.status, 503); assert.equal(JSON.parse(response.body).code, "session-capacity");
    assert.equal(issued, 0); assert.equal(occupied(f.sessions), 1);
    assert.equal(f.app.authorization.restorePrincipal("grant-cap"), undefined);
    assert.deepEqual(f.app.spine.replay().filter(e => (e.payload as { event?: string }).event?.startsWith("delegation.")), before);
  } finally { f.cleanup(); }
});

test("reservation consumption is one-shot and unused release is idempotent", () => {
  const s = new SessionStore({ maxSessions: 1 });
  const slot = s.reserve(0); assert.equal(occupied(s), 1);
  assert.throws(() => s.create(OWNER, 0), /capacity/i);
  const session = slot.create(OWNER, 0); assert.equal(occupied(s), 1);
  assert.throws(() => slot.create(human, 0), /reservation/i);
  slot.release(); slot.release(); assert.ok(s.get(session.id, 1));
  s.revoke(session.id); const unused = s.reserve(1);
  unused.release(); unused.release(); assert.equal(occupied(s), 0);
  assert.throws(() => unused.create(OWNER, 1), /reservation/i);
});

function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

for (const outcome of ["success", "before-issue-failure", "after-issue-failure"] as const) {
  test(`delegation owns the final slot across await: ${outcome}`, { timeout: 5_000 }, async () => {
    const f = fixture(2), entered = gate(), proceed = gate();
    const original = f.app.authorization.issue.bind(f.app.authorization);
    f.app.authorization.issue = async (...args) => {
      entered.release(); await proceed.promise;
      if (outcome === "before-issue-failure") throw new Error("owned pre-issue refusal");
      const agent = await original(...args);
      // The same error class from an effectful issuer is not a proven pre-issue capacity refusal.
      if (outcome === "after-issue-failure") throw new SessionCapacityError();
      return agent;
    };
    const sec = { token: "fixture", identity: f.identity };
    const pending = handleGatewayRequest(f.app, f.issueRequest(), sec);
    try {
      await entered.promise;
      assert.equal(state(f.sessions).sessions.size, 1); assert.equal(occupied(f.sessions), 2);
      assert.equal(f.app.authorization.restorePrincipal("grant-cap"), undefined);
      const competitor = await handleGatewayRequest(f.app, f.request("/auth/session", { assertion: f.assertion }), sec);
      assert.equal(competitor.status, 503); assert.equal(occupied(f.sessions), 2);
      proceed.release(); const response = await pending;
      assert.equal(state(f.sessions).reservations?.size, 0);
      assert.equal(occupied(f.sessions), outcome === "success" ? 2 : 1);
      assert.ok(f.sessions.get(f.login.id, Date.now()), "existing administrator session stays usable");
      const grant = f.app.authorization.restorePrincipal("grant-cap");
      if (outcome === "success") {
        assert.equal(response.status, 200);
        const body = JSON.parse(response.body) as { session: string };
        assert.equal(f.sessions.get(body.session, Date.now())?.principal.kind, "agent");
        assert.ok(grant, "actual sealed grant projection exists");
      } else {
        assert.equal(response.status, 400);
        assert.equal(grant !== undefined, outcome === "after-issue-failure", "an exception can follow a durable grant effect");
        assert.equal((await handleGatewayRequest(f.app, f.request("/auth/session", { assertion: f.assertion }), sec)).status, 200);
        assert.equal(occupied(f.sessions), 2, "proven unused slot can be admitted again");
      }
    } finally { proceed.release(); await pending; f.cleanup(); }
  });
}

test("default capacity admits exactly 10000 live sessions and measures bounded sweep", { timeout: 20_000 }, (t) => {
  const s = new SessionStore(), start = performance.now();
  for (let i = 0; i < 10_000; i++) {
    s.create(i % 2 === 0 ? OWNER : human, 0);
    assert.equal(occupied(s), i + 1);
  }
  const admissionMs = performance.now() - start;
  assert.throws(() => s.create(OWNER, 0), /capacity/i);
  assert.equal(occupied(s), 10_000);
  const sweepStart = performance.now(); assert.equal(s.activeCount(3_000_000), 0);
  t.diagnostic(JSON.stringify({ capacity: 10_000, admissionMs, sweepMs: performance.now() - sweepStart, retainedAfterExpiry: occupied(s) }));
});
