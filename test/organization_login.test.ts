/** Local transport/RSA/browser fixtures; no real issuer, deployment or credential-custody qualification. */
import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { request as httpRequest } from "node:http";
import { chmodSync, linkSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureOidcLoginConfig, OidcCodeFlow, type OidcLoginConfig } from "../src/identity/oidc_code_flow.js";
import { OidcJwksProvider, type Jwks } from "../src/identity/oidc_provider.js";
import { loadInstalledOrganizationRuntime } from "../src/cli/organization_runtime.js";
import { captureRuntimeContract } from "../src/cli/runtime_config.js";
import { parseProviderProfile, profileEnvironment } from "../src/cli/provider_profile.js";
import { SessionStore } from "../src/identity/session_store.js";
import { OWNER } from "../src/identity/rbac.js";
import { handleReviewRequest, type WebRequest } from "../src/review/review_web.js";
import { handleGatewayRequest, startGatewayServer } from "../src/gateway/http_gateway.js";
import { composeKeep } from "../src/compose.js";

const ISSUER = "https://issuer.fixture.invalid/tenant/", CLIENT = "keep-org-fixture", ORIGIN = "https://keep.fixture.invalid";
const NOW = Math.floor(Date.now() / 1000) * 1000;
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...keys.publicKey.export({ format: "jwk" }), kty: "RSA", kid: "fixture-k1", alg: "RS256", use: "sig" };
const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
function sign(claims: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: "fixture-k1", typ: "JWT" }, payloadJson?: string) {
  const h = b64(header), p = payloadJson === undefined ? b64(claims) : Buffer.from(payloadJson).toString("base64url");
  return `${h}.${p}.${createSign("RSA-SHA256").update(`${h}.${p}`).end().sign(keys.privateKey).toString("base64url")}`;
}
function fixture(t: TestContext, overrides: Partial<OidcLoginConfig> = {}) {
  const root = mkdtempSync(join(tmpdir(), "keep-org-login-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const secretFile = join(root, "client-secret"); writeFileSync(secretFile, "synthetic-client-secret\n", { mode: 0o600 });
  const config = captureOidcLoginConfig({ clientId: CLIENT, authorizationEndpoint: `${ISSUER}authorize`, tokenEndpoint: `${ISSUER}token`, jwksUri: `${ISSUER}keys`, publicOrigin: ORIGIN,
    redirectUri: `${ORIGIN}/auth/oidc/callback`, clientSecretFile: secretFile, transactionTtlMs: 60_000, maxTransactions: 4, requestTimeoutMs: 1000, maxResponseBytes: 32768,
    leewaySec: 5, sessionIdleMs: 60_000, sessionAbsoluteMs: 120_000, maxSessions: 4, ...overrides }, CLIENT);
  const refs = { tenantId: "alpha", issuer: ISSUER, audience: CLIENT, auditScope: "tenant", login: config,
    jwksPath: join(root, "jwks.json"), principalRosterPath: join(root, "principals.json"), delegationPolicyPath: join(root, "delegation.json"), residencyPolicyPath: join(root, "residency.json"), scannerEnginePath: join(root, "unused-scanner.mjs") };
  const write = (path: string, value: unknown) => writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
  write(refs.jwksPath, { keys: [jwk] });
  write(refs.principalRosterPath, { schema: "keep.principal-roster/v1", tenantId: "alpha", principals: [{ subject: "auth0|alice", id: "alice", role: "maintainer" }, { subject: "eve", id: "eve", role: "viewer" }] });
  write(refs.delegationPolicyPath, { schema: "keep.delegation-policy/v1", tenantId: "alpha", parents: ["alice"] });
  write(refs.residencyPolicyPath, { schema: "keep.residency-policy/v1", tenantId: "alpha", allowedPurposes: ["software-development"], allowedRegions: ["local"], egressAllowlist: ["models.fixture.invalid"] });
  let now = NOW, exchanges = 0;
  let respond: ((input: Parameters<typeof fetch>[0], init?: RequestInit) => Promise<Response>) | undefined;
  const codes = new Map<string, { nonce: string; challenge: string; claims: Record<string, unknown> }>();
  const transport: typeof fetch = async (input, init) => {
    exchanges++;
    assert.equal(String(input), config.tokenEndpoint); assert.equal(init?.method, "POST"); assert.equal(init?.redirect, "error");
    assert.equal(new Headers(init?.headers).get("authorization"), `Basic ${Buffer.from(`${CLIENT}:synthetic-client-secret`).toString("base64")}`);
    if (respond) return respond(input, init);
    const body = new URLSearchParams(String(init?.body));
    assert.equal(body.get("redirect_uri"), config.redirectUri); assert.equal(body.get("grant_type"), "authorization_code");
    const issued = codes.get(body.get("code") ?? "");
    assert.ok(issued); codes.delete(body.get("code")!);
    const verifier = body.get("code_verifier")!;
    assert.match(verifier, /^[A-Za-z0-9_-]{43}$/u); assert.equal(createHash("sha256").update(verifier).digest("base64url"), issued.challenge);
    return Response.json({ id_token: sign({ iss: ISSUER, aud: CLIENT, sub: "auth0|alice", nonce: issued.nonce, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 60, ...issued.claims }), token_type: "Bearer" });
  };
  const runtime = () => loadInstalledOrganizationRuntime(refs, { fetch: transport, now: () => now });
  const identity = runtime().identity;
  const app = composeKeep({ dataDir: join(root, "app"), identity });
  const authorize = (authorizationUrl: string, claims: Record<string, unknown> = {}) => {
    const url = new URL(authorizationUrl); assert.equal(url.origin + url.pathname, config.authorizationEndpoint);
    assert.equal(url.searchParams.get("scope"), "openid"); assert.equal(url.searchParams.get("response_type"), "code"); assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    const code = `fixture-code-${codes.size}-${exchanges}`;
    codes.set(code, { nonce: url.searchParams.get("nonce")!, challenge: url.searchParams.get("code_challenge")!, claims });
    return { state: url.searchParams.get("state")!, code };
  };
  const browser = (request: Partial<WebRequest> = {}) => handleReviewRequest(app, { method: "GET", path: "/login", query: {}, headers: { host: new URL(ORIGIN).host }, body: "", ...request },
    { token: "fixture-gateway", origin: ORIGIN, allowedHosts: [new URL(ORIGIN).host], principal: OWNER, identity, now });
  const start = async (claims: Record<string, unknown> = {}) => {
    const response = await browser({ path: "/auth/oidc/start" }); assert.equal(response.status, 303);
    const cookie = response.headers["Set-Cookie"]!.split(";")[0]!;
    return { query: authorize(response.headers.Location!, claims), cookie };
  };
  const callback = (login: { query: Record<string, string>; cookie: string }) => browser({ path: "/auth/oidc/callback", query: login.query, headers: { host: new URL(ORIGIN).host, cookie: login.cookie } });
  return { root, refs, config, identity, app, runtime, authorize, browser, start, callback, transport, exchanges: () => exchanges, time: (value: number) => { now = value; }, respond: (value: typeof respond) => { respond = value; } };
}

test("rostered code/PKCE login mints one tenant-bound session; viewer and logout retain permission/CSRF boundaries", async t => {
  const f = fixture(t); f.app.projectManager!.create({ name: "alpha project", tenant: "alpha" }); f.app.projectManager!.create({ name: "beta project", tenant: "beta" });
  const login = await f.start(), response = await f.callback(login);
  assert.equal(response.status, 303); assert.equal(response.headers.Location, "/console"); assert.match(response.headers["Set-Cookie"]!, /HttpOnly; Secure; SameSite=Strict/u);
  const cookie = response.headers["Set-Cookie"]!.split(";")[0]!, sid = cookie.split("=")[1]!;
  const session = f.identity.sessions.get(sid, NOW)!;
  assert.deepEqual(session.authentication, { issuer: ISSUER, subject: "auth0|alice", tenantId: "alpha" });
  const api = (method: string, path: string, id = sid) => handleGatewayRequest(f.app, { method, path, query: {}, body: "{}", headers: { authorization: "Bearer fixture-gateway", "x-keep-session": id } }, { token: "fixture-gateway", identity: f.identity });
  const projects = await api("GET", "/projects"); assert.equal(projects.status, 200); assert.match(projects.body, /alpha project/u); assert.doesNotMatch(projects.body, /beta project/u);
  const denied = await f.callback(await f.start({ sub: "eve" })); const viewerId = denied.headers["Set-Cookie"]!.split(";")[0]!.split("=")[1]!;
  assert.equal((await api("POST", "/project", viewerId)).status, 403);
  const logout = (origin: string, csrf: string) => f.browser({ method: "POST", path: "/logout", headers: { host: new URL(ORIGIN).host, origin, cookie }, body: `csrf=${csrf}` });
  assert.equal((await logout("https://other.fixture.invalid", session.csrfToken)).status, 403);
  assert.equal((await logout(ORIGIN, "wrong")).status, 403); assert.ok(f.identity.sessions.get(sid, NOW));
  assert.equal((await logout(ORIGIN, session.csrfToken)).status, 303); assert.equal(f.identity.sessions.get(sid, NOW), null);
  const signIn = await f.browser(); assert.match(signIn.body, /Sign in with your organization/u);
  assert.doesNotMatch(signIn.body + projects.body + response.body + JSON.stringify(f.app.spine.currentEvents()), /synthetic-client-secret|fixture-code-|eyJhbGci/u);
});

test("state/browser/nonce/issuer/audience/time/roster failures and concurrent callback replay cannot create a session", async t => {
  const f = fixture(t);
  const first = await f.start();
  assert.equal((await f.callback({ ...first, query: { ...first.query, state: "wrong-state" } })).status, 401);
  assert.equal((await f.callback({ ...first, cookie: "__Host-keep_oidc=wrong-browser" })).status, 401); assert.equal(f.exchanges(), 0);
  const concurrent = await Promise.all([f.callback(first), f.callback(first)]);
  assert.deepEqual(concurrent.map(row => row.status).sort(), [303, 401]); assert.equal(f.exchanges(), 1);
  f.identity.sessions.revokeAllFor("alice");
  for (const claims of [{ nonce: "wrong" }, { iss: ISSUER.slice(0, -1) }, { aud: "other-client" }, { exp: NOW / 1000 - 100 }, { iat: NOW / 1000 + 100 }, { sub: "unrostered" }, { aud: [CLIENT, "untrusted"] }, { azp: "other-client" }]) {
    const login = await f.start(claims); assert.equal((await f.callback(login)).status, 401); assert.equal((await f.callback(login)).status, 401);
    assert.equal(f.identity.sessions.activeCount(NOW), 0);
  }
  const expired = await f.start(); f.time(NOW + f.config.transactionTtlMs); const before = f.exchanges(); assert.equal((await f.callback(expired)).status, 401); assert.equal(f.exchanges(), before);
});

test("code mode disables assertion shortcuts and protects Host/origin while personal mode remains usable", async t => {
  const f = fixture(t);
  assert.equal((await f.browser({ method: "POST", path: "/login", body: "assertion=unused" })).status, 405);
  assert.equal((await handleGatewayRequest(f.app, { method: "POST", path: "/auth/session", query: {}, body: '{"assertion":"unused"}', headers: { authorization: "Bearer fixture-gateway" } }, { token: "fixture-gateway", identity: f.identity })).status, 405);
  assert.equal((await f.browser({ path: "/auth/oidc/start", headers: { host: "wrong.invalid" } })).status, 403); assert.equal(f.exchanges(), 0);
  const unconfigured = await handleGatewayRequest(f.app, { method: "GET", path: "/projects", query: {}, body: "", headers: { authorization: "Bearer fixture-gateway" } }, { token: "fixture-gateway" });
  assert.equal(unconfigured.status, 403, "configured organization must never fall back to owner when its security layer is omitted");
  const personalApp = composeKeep({ dataDir: join(f.root, "personal-app") });
  const personal = await handleReviewRequest(personalApp, { method: "GET", path: "/console", query: {}, body: "", headers: { host: "127.0.0.1:1" } },
    { token: "personal", origin: "http://127.0.0.1:1", allowedHosts: ["127.0.0.1:1"], principal: OWNER, projectConsole: async () => ({ status: 200, headers: {}, body: "personal console" }) });
  assert.equal(personal.status, 200); assert.equal(f.exchanges(), 0);
});

test("unrelated percent cookie leaves login usable and malformed actual binding refuses before exchange", async t => {
  const f = fixture(t), host = new URL(ORIGIN).host;
  const begun = await f.browser({ path: "/auth/oidc/start", headers: { host, cookie: "unrelated=literal%" } });
  assert.equal(begun.status, 303);
  const query = f.authorize(begun.headers.Location!), cookie = begun.headers["Set-Cookie"]!.split(";")[0]!;
  assert.equal((await f.callback({ query, cookie: "unrelated=literal%; __Host-keep_oidc=bad%" })).status, 401);
  assert.equal(f.exchanges(), 0);
  const valid = await f.callback({ query, cookie: `unrelated=literal%; ${cookie}` });
  assert.equal(valid.status, 303); assert.equal(f.exchanges(), 1);
});

test("strict code-flow verification rejects ambiguous JSON, key selection and malformed clocks without changing legacy semantics", async () => {
  const transaction = { nonce: "fixture-nonce", issuedAt: NOW, expiresAt: NOW + 60000 };
  const claims = { iss: ISSUER, aud: CLIENT, sub: "alice", nonce: transaction.nonce, iat: NOW / 1000, exp: NOW / 1000 + 60 };
  const provider = (keyset: Jwks = { keys: [jwk] }) => new OidcJwksProvider({ jwks: keyset, issuer: ISSUER, audience: CLIENT, leewaySec: 5 });
  assert.ok(await provider().verifyCodeFlow(sign(claims), NOW, transaction));
  for (const header of [{ alg: "RS256" }, { alg: "none", kid: jwk.kid }, { alg: "RS256", kid: jwk.kid, b64: false }, { alg: "RS256", kid: jwk.kid, crit: ["unknown"] }]) assert.equal(await provider().verifyCodeFlow(sign(claims, header), NOW, transaction), null);
  for (const keyset of [{ keys: [jwk, jwk] }, { keys: [{ ...jwk, use: "enc" }] }, { keys: [{ ...jwk, d: "private" }] }, { keys: [{ ...jwk, key_ops: ["sign"] }] }]) assert.equal(await provider(keyset).verifyCodeFlow(sign(claims), NOW, transaction), null);
  for (const value of [{ ...claims, iat: undefined }, { ...claims, iat: "bad" }, { ...claims, iat: NOW / 1000 - 60 }, { ...claims, nonce: undefined }]) assert.equal(await provider().verifyCodeFlow(sign(value), NOW, transaction), null);
  assert.equal(await provider().verifyCodeFlow(sign(claims), NaN, transaction), null);
  const duplicate = JSON.stringify(claims).replace('"sub":"alice"', '"sub":"alice","sub":"other"');
  assert.equal(await provider().verifyCodeFlow(sign(claims, undefined, duplicate), NOW, transaction), null);
  assert.equal(await provider().verifyCodeFlow(sign(claims) + "=", NOW, transaction), null);
  assert.ok(await provider().verify(sign({ ...claims, iat: undefined, nbf: NOW / 1000 - 0.5 }), NOW), "legacy fixture profile still admits its documented fractional times");
});

test("uncertain exchange is terminal with no automatic retry; session capacity is reserved before network effects", async t => {
  const f = fixture(t, { maxSessions: 1, requestTimeoutMs: 20 });
  const login = await f.start();
  f.respond(async () => { throw new Error("private diagnostic and token must not escape"); });
  const failure = await f.callback(login); assert.equal(failure.status, 401); assert.doesNotMatch(failure.body, /private diagnostic/u);
  assert.equal((await f.callback(login)).status, 401); assert.equal(f.exchanges(), 1);
  f.respond(async () => new Promise(() => undefined));
  const timeout = await f.callback(await f.start()); assert.equal(timeout.status, 401); assert.equal(f.identity.sessions.activeCount(NOW), 0);
  f.respond(undefined);
  const good = await f.callback(await f.start()); assert.equal(good.status, 303);
  const before = f.exchanges(), full = await f.callback(await f.start()); assert.equal(full.status, 503); assert.equal(f.exchanges(), before);
});

test("transaction capacity, issuer errors and restart cannot reuse acquisition state", async t => {
  const f = fixture(t, { maxTransactions: 1 });
  const first = await f.start();
  assert.equal((await f.browser({ path: "/auth/oidc/start" })).status, 503);
  assert.equal((await f.callback({ ...first, query: { state: first.query.state, error: "access_denied" } })).status, 401);
  assert.equal((await f.callback(first)).status, 401); assert.equal(f.exchanges(), 0);
  const second = await f.start();
  const binding = second.cookie.split("=")[1]!;
  await assert.rejects(f.runtime().identity.codeFlow!.complete(second.query.state, binding, second.query.code), /could not be completed/u);
  f.time(NOW + f.config.transactionTtlMs);
  assert.equal((await f.browser({ path: "/auth/oidc/start" })).status, 303, "expired transactions release capacity");
  assert.equal(f.exchanges(), 0);
});

test("deferred verifier crossing transaction or token expiry cannot mint a session or retain its slot", async t => {
  for (const boundary of ["transaction", "token"] as const) {
    const f = fixture(t, { requestTimeoutMs: 120000 });
    const sessions = new SessionStore({ maxSessions: 1 });
    const provider = new OidcJwksProvider({ jwks: { keys: [jwk] }, issuer: ISSUER, audience: CLIENT, leewaySec: f.config.leewaySec });
    let now = NOW, entered!: () => void, release!: () => void, signal: AbortSignal | undefined;
    const started = new Promise<void>(resolve => { entered = resolve; }), deferred = new Promise<void>(resolve => { release = resolve; });
    const flow = new OidcCodeFlow(f.config, ISSUER, "alpha", sessions, { fetch: f.transport, now: () => now,
      verify: async (assertion, verifiedAt, transaction, cancellation) => { signal = cancellation; const identity = await provider.verifyCodeFlow(assertion, verifiedAt, transaction); entered(); await deferred; return identity; },
      principal: () => ({ id: "alice", kind: "human", role: "maintainer", tenant: "alpha" }),
    });
    const begun = flow.start(), query = f.authorize(begun.authorizationUrl, boundary === "token" ? { exp: NOW / 1000 + 1 } : {});
    const completion = flow.complete(query.state, begun.browserBinding, query.code);
    const rejected = assert.rejects(completion, /could not be completed/u);
    await started;
    assert.throws(() => sessions.create(OWNER, NOW), /capacity/u, "verification still owns its reserved slot");
    now = NOW + (boundary === "transaction" ? f.config.transactionTtlMs : 7000); f.time(now); release();
    await rejected;
    assert.equal(signal?.aborted, true); assert.equal(sessions.activeCount(now), 0);
    const unused = sessions.reserve(now); unused.release();
    await assert.rejects(flow.complete(query.state, begun.browserBinding, query.code), /could not be completed/u);
    assert.equal(f.exchanges(), 1, "expired asynchronous verification never retries acquisition");
  }
});

test("protected credential and bounded token response refusals retain no session and invoke no other endpoints", async t => {
  const f = fixture(t);
  chmodSync(f.config.clientSecretFile, 0o644);
  assert.equal((await f.callback(await f.start())).status, 401); assert.equal(f.exchanges(), 0);
  chmodSync(f.config.clientSecretFile, 0o600);
  const original = join(f.root, "original-secret"); writeFileSync(original, "synthetic-client-secret", { mode: 0o600 });
  rmSync(f.config.clientSecretFile); symlinkSync(original, f.config.clientSecretFile);
  assert.equal((await f.callback(await f.start())).status, 401); assert.equal(f.exchanges(), 0);
  rmSync(f.config.clientSecretFile); linkSync(original, f.config.clientSecretFile);
  assert.equal((await f.callback(await f.start())).status, 401); assert.equal(f.exchanges(), 0);
  rmSync(f.config.clientSecretFile); writeFileSync(f.config.clientSecretFile, "synthetic-client-secret", { mode: 0o600 });
  for (const reply of [() => new Response("redirect", { status: 302 }), () => Response.json({ id_token: "a".repeat(f.config.maxResponseBytes + 1) }), () => new Response('{"id_token":"x","id_token":"y"}', { headers: { "content-type": "application/json" } })]) {
    f.respond(async () => reply()); assert.equal((await f.callback(await f.start())).status, 401); assert.equal(f.identity.sessions.activeCount(NOW), 0);
  }
});

test("profile/runtime preserve exact issuer and secret references; duplicate subjects and unsupported configuration refuse", t => {
  const f = fixture(t);
  const profile = parseProviderProfile({ schema: "keep.provider-profile/v1", name: "org", authority: "organization", location: "external", protocol: "openai-compatible", endpoint: "https://models.fixture.invalid", model: "fixture", purpose: "software", region: "local", credential: { kind: "environment" }, organization: f.refs, release: { bundlePath: "/fixture/release", trustRootPath: "/fixture/root" } });
  const env = profileEnvironment(profile);
  const captured = captureRuntimeContract(env, { cwd: f.root });
  assert.equal(captured.organization?.issuer, ISSUER); assert.equal(captured.organization?.login?.clientSecretFile, f.config.clientSecretFile);
  assert.doesNotMatch(JSON.stringify(profile) + JSON.stringify(captured), /synthetic-client-secret/u);
  assert.throws(() => captureRuntimeContract({ KEEP_PROVIDER: "local", KEEP_IDENTITY_LOGIN_JSON: JSON.stringify(f.config) }, { cwd: f.root }), /requires explicit organization/u);
  for (const change of [{ publicOrigin: "http://insecure.invalid" }, { clientId: "other" }, { maxTransactions: 0 }, { requestTimeoutMs: Infinity }, { redirectUri: "https://other.invalid/auth/oidc/callback" }]) assert.throws(() => captureOidcLoginConfig({ ...f.config, ...change }, CLIENT));
  writeFileSync(f.refs.principalRosterPath, JSON.stringify({ schema: "keep.principal-roster/v1", tenantId: "alpha", principals: [{ subject: "same", id: "alice", role: "maintainer" }, { subject: "same", id: "eve", role: "viewer" }] }));
  assert.throws(() => f.runtime(), /unique subjects/u);
});

test("gateway socket routes actual callback/public Host and rejects duplicate callback parameters before exchange", async t => {
  const f = fixture(t), server = await startGatewayServer(f.app, { port: 0, token: "fixture-gateway" });
  t.after(() => server.close());
  const get = (path: string, cookie?: string, host = new URL(ORIGIN).host) => new Promise<{ status: number; headers: import("node:http").IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const request = httpRequest(`${server.origin}${path}`, { headers: { host, ...(cookie ? { cookie } : {}) } }, response => {
      let body = ""; response.setEncoding("utf8"); response.on("data", value => { body += value; }); response.on("end", () => resolve({ status: response.statusCode!, headers: response.headers, body }));
    }); request.once("error", reject); request.end();
  });
  assert.equal((await get("/auth/oidc/start", undefined, "wrong.invalid")).status, 403);
  const started = await get("/auth/oidc/start"); assert.equal(started.status, 303); assert.match(started.headers["set-cookie"]![0]!, /Secure; SameSite=Lax/u);
  const query = f.authorize(started.headers.location!), cookie = started.headers["set-cookie"]![0]!.split(";")[0]!;
  assert.equal((await get(`/auth/oidc/callback?${new URLSearchParams(query)}&state=duplicate`, cookie)).status, 400); assert.equal(f.exchanges(), 0);
  const complete = await get(`/auth/oidc/callback?${new URLSearchParams(query)}`, cookie); assert.equal(complete.status, 303); assert.equal(complete.headers.location, "/console");
  const fresh = f.runtime();
  const sessionId = complete.headers["set-cookie"]![0]!.split(";")[0]!.split("=")[1]!;
  assert.equal(fresh.identity.sessions.get(sessionId, NOW), null, "restart has no retained session or token");
  assert.doesNotMatch(complete.body, /fixture-code-|synthetic-client-secret/u);
});

test("code-flow rotation requires origin/CSRF, changes opaque credentials and forwards only trusted session reference into console", async t => {
  const f = fixture(t), logged = await f.callback(await f.start()), cookie = logged.headers["Set-Cookie"]!.split(";")[0]!, sid = cookie.split("=")[1]!;
  const prior = f.identity.sessions.get(sid, NOW)!;
  const rotate = (origin: string, csrf: string) => f.browser({ method: "POST", path: "/auth/oidc/rotate", headers: { host: new URL(ORIGIN).host, origin, cookie }, body: `csrf=${csrf}` });
  assert.equal((await rotate("https://other.fixture.invalid", prior.csrfToken)).status, 403);
  assert.equal((await rotate(ORIGIN, "wrong")).status, 403);
  const response = await rotate(ORIGIN, prior.csrfToken); assert.equal(response.status, 303); assert.match(response.headers["Set-Cookie"]!, /HttpOnly; Secure; SameSite=Strict/u);
  const nextCookie = response.headers["Set-Cookie"]!.split(";")[0]!, next = f.identity.sessions.get(nextCookie.split("=")[1]!, NOW)!;
  assert.equal(f.identity.sessions.get(sid, NOW), null); assert.notEqual(next.csrfToken, prior.csrfToken); assert.equal(next.createdAt, prior.createdAt);
  assert.throws(() => f.identity.sessions.assertAuthority(prior.authority, prior.principal, NOW)); f.identity.sessions.assertAuthority(next.authority, next.principal, NOW);
  let bridged: unknown;
  const view = await handleReviewRequest(f.app, { method: "GET", path: "/console", query: {}, body: "", headers: { host: new URL(ORIGIN).host, cookie: nextCookie } },
    { token: "fixture", origin: ORIGIN, allowedHosts: [new URL(ORIGIN).host], principal: OWNER, identity: f.identity, now: NOW,
      projectConsole: async (_req, _principal, _csrf, ref) => { bridged = ref; return { status: 200, headers: {}, body: "console" }; } });
  assert.equal(view.status, 200); assert.deepEqual(bridged, next.authority); assert.doesNotMatch(JSON.stringify(bridged), new RegExp(`${next.id}|${next.csrfToken}`));
});


test("code-flow browser effect routes are held before console or review handlers; permitted console remains available", async t => {
  const f = fixture(t), logged = await f.callback(await f.start()), cookie = logged.headers["Set-Cookie"]!.split(";")[0]!, current = f.identity.sessions.get(cookie.split("=")[1]!, NOW)!;
  let dispatches = 0;
  const security = { token: "fixture", origin: ORIGIN, allowedHosts: [new URL(ORIGIN).host], principal: OWNER, identity: f.identity, now: NOW,
    projectConsole: async () => { dispatches++; return { status: 200, headers: {}, body: "observed" }; } };
  const request = (method: string, path: string) => handleReviewRequest(f.app, { method, path, query: {}, body: `csrf=${current.csrfToken}&action=approve`, headers: { host: new URL(ORIGIN).host, origin: ORIGIN, cookie } }, security);
  for (const [method, path] of [["POST", "/console/merge"], ["POST", "/console/cancel"], ["POST", "/review/fixture/decide"], ["GET", "/console/future-effect"]]) {
    const response = await request(method!, path!); assert.equal(response.status, 409, response.body); assert.match(response.body, /route is held/u);
  }
  assert.equal(dispatches, 0); assert.equal(f.app.spine.currentEvents().some(event => event.payload["event"] === "review.decided"), false);
  assert.equal((await request("GET", "/console")).status, 200); assert.equal(dispatches, 1);
});
