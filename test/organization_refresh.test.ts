/** Synthetic issuer/key transport only; no live deployment or account qualification. */
import test from "node:test";
import assert from "node:assert/strict";
import { createSign, generateKeyPairSync } from "node:crypto";
import { OidcIssuerKeySource, captureOidcKeyRefreshPolicy } from "../src/identity/oidc_key_source.js";
import type { OidcLoginConfig } from "../src/identity/oidc_code_flow.js";
import { SessionStore } from "../src/identity/session_store.js";
import { HttpProvider, ProviderError } from "../src/gateway/http_provider.js";
import { anthropicDialect, openAiDialect } from "../src/gateway/wire_dialect.js";
import { buildDefaultBrokeredEgress } from "../src/gateway/brokered_egress.js";

const issuer = "https://issuer.fixture.invalid/", initial = 1800000000000;
const config = { clientId: "keep-fixture", authorizationEndpoint: `${issuer}authorize`, tokenEndpoint: `${issuer}token`, jwksUri: `${issuer}keys`, leewaySec: 0 } as OidcLoginConfig;
const policy = captureOidcKeyRefreshPolicy({ metadataUrl: `${issuer}metadata`, ttlMs: 1000, cooldownMs: 100, timeoutMs: 200, maxResponseBytes: 8192, maxKeys: 4, maxRetiredKeys: 4 });
const metadata = { issuer, authorization_endpoint: config.authorizationEndpoint, token_endpoint: config.tokenEndpoint, jwks_uri: config.jwksUri,
  response_types_supported: ["code"], id_token_signing_alg_values_supported: ["RS256"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["client_secret_basic"] };
const keys = ["one", "two", "three"].map(kid => { const pair = generateKeyPairSync("rsa", { modulusLength: 2048 }); return { ...pair, jwk: { ...pair.publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" } }; });
const transaction = { nonce: "nonce-fixture", issuedAt: initial, expiresAt: initial + 60000 };
function assertion(index: number, kid = keys[index]!.jwk.kid) {
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const h = b64({ alg: "RS256", kid }), p = b64({ iss: issuer, aud: config.clientId, sub: "alice", nonce: transaction.nonce, iat: initial / 1000, exp: initial / 1000 + 60 });
  return `${h}.${p}.${createSign("RSA-SHA256").update(`${h}.${p}`).end().sign(keys[index]!.privateKey).toString("base64url")}`;
}
function fixture(override = policy) {
  let now = initial, active: unknown[] = [keys[0]!.jwk], meta: unknown = metadata, calls = 0, failure = false;
  let deferred: (() => Promise<void>) | undefined;
  const transport: typeof fetch = async input => { calls++; if (deferred) await deferred(); if (failure) throw Error("synthetic unavailable"); return Response.json(String(input) === policy.metadataUrl ? meta : { keys: active }); };
  const source = new OidcIssuerKeySource(issuer, config, override, transport, () => now);
  return { verify: (index: number, kid?: string, signal = new AbortController().signal) => source.verify(assertion(index, kid), now, transaction, signal),
    advance: (ms: number) => { now += ms; }, set: (set: unknown[]) => { active = set; }, meta: (v: unknown) => { meta = v; }, fail: () => { failure = true; },
    defer: (fn: (() => Promise<void>) | undefined) => { deferred = fn; }, calls: () => calls };
}

test("refresh coalesces first callers, bounds kid storms, atomically rotates and permanently refuses retired material in this process", async () => {
  const f = fixture(); let release!: () => void; const wait = new Promise<void>(r => { release = r; }); f.defer(() => wait);
  const first = f.verify(0), second = f.verify(0); assert.equal(f.calls(), 1); release(); assert.ok(await first); assert.ok(await second); assert.equal(f.calls(), 2); f.defer(undefined);
  for (let i = 0; i < 12; i++) assert.equal(await f.verify(1, `unknown-${i}`), null);
  assert.equal(f.calls(), 2); f.advance(101); f.set([keys[1]!.jwk]); assert.ok(await f.verify(1)); assert.equal(await f.verify(0), null);
  f.advance(101); f.set([keys[1]!.jwk, { ...keys[0]!.jwk, kid: "resurrected" }]); assert.equal(await f.verify(0, "resurrected"), null);
  assert.ok(await f.verify(1)); f.advance(101); f.set([keys[0]!.jwk]); assert.equal(await f.verify(0), null); assert.ok(await f.verify(1));
});

test("failed refresh preserves only an unexpired admitted snapshot and cannot extend its TTL", async () => {
  const f = fixture(); assert.ok(await f.verify(0)); f.advance(101); f.fail(); assert.equal(await f.verify(1), null); assert.ok(await f.verify(0));
  f.advance(900); assert.equal(await f.verify(0), null); const count = f.calls(); assert.equal(await f.verify(0), null); assert.equal(f.calls(), count);
});

test("wrong pinned metadata, duplicate/private/oversized keys and changed kid material never replace admitted keys", async () => {
  for (const invalid of [{ ...metadata, issuer: `${issuer}other` }, { ...metadata, token_endpoint: `${issuer}other` }, { ...metadata, jwks_uri: "https://attacker.invalid/keys" }]) {
    const f = fixture(); f.meta(invalid); assert.equal(await f.verify(0), null); assert.equal(f.calls(), 1);
  }
  for (const invalid of [[keys[0]!.jwk, keys[0]!.jwk], [keys[0]!.jwk, { ...keys[0]!.jwk, kid: "alias" }], [{ ...keys[0]!.jwk, n: Buffer.concat([Buffer.from([0]), Buffer.from(keys[0]!.jwk.n!, "base64url")]).toString("base64url") }], [{ ...keys[0]!.jwk, d: "private" }], [{ ...keys[1]!.jwk, kid: "one" }], [{ ...keys[0]!.jwk, kid: "x".repeat(9000) }]]) {
    const f = fixture(); assert.ok(await f.verify(0)); f.advance(101); f.set(invalid); assert.equal(await f.verify(2), null); assert.ok(await f.verify(0));
  }
});

test("cancelled waiter does not cancel another caller; timed out late transport cannot admit a snapshot", async () => {
  const f = fixture(); let release!: () => void; const wait = new Promise<void>(r => { release = r; }); f.defer(() => wait);
  const controller = new AbortController(), first = f.verify(0, undefined, controller.signal), second = f.verify(0); controller.abort(); assert.equal(await first, null); release(); assert.ok(await second);
  const late = fixture({ ...policy, timeoutMs: 10 }); let finish!: () => void; const delayed = new Promise<void>(r => { finish = r; }); late.defer(() => delayed);
  assert.equal(await late.verify(0), null); finish(); await new Promise<void>(r => setImmediate(r)); assert.equal(await late.verify(0), null);
});

const principal = { id: "alice", kind: "human" as const, role: "maintainer" as const, tenant: "alpha" };
const auth = { issuer, subject: "oidc|alice", tenantId: "alpha" };
function sessionFixture() { const store = new SessionStore({ idleMs: 100, absoluteMs: 250 }); const slot = store.reserve(initial); const session = slot.create(principal, initial, auth); return { store, session }; }
test("dispatch checks never renew idle lifetime; session references cannot authenticate, cross subjects or cross boots", () => {
  const { store, session } = sessionFixture(); store.assertAuthority(session.authority, principal, initial + 90); assert.equal(session.lastSeen, initial);
  assert.throws(() => store.assertAuthority(session.authority, principal, initial + 101)); assert.equal(store.get(session.authority!.authorityId, initial), null);
  assert.throws(() => store.assertAuthority(session.authority, { ...principal, id: "other" }, initial));
  assert.throws(() => new SessionStore().assertAuthority(session.authority, principal, initial));
  assert.throws(() => store.assertAuthority({ ...session.authority!, subject: "other" }, principal, initial));
});
test("rotation, logout and fresh login revoke old admission without replenishing absolute lifetime", () => {
  const { store, session } = sessionFixture(); store.get(session.id, initial + 90); const rotated = store.rotate(session.id, initial + 180);
  assert.notEqual(rotated.id, session.id); assert.notEqual(rotated.csrfToken, session.csrfToken); assert.equal(rotated.createdAt, initial);
  assert.throws(() => store.assertAuthority(session.authority, principal, initial + 180)); store.assertAuthority(rotated.authority, principal, initial + 180);
  store.get(rotated.id, initial + 240); assert.throws(() => store.assertAuthority(rotated.authority, principal, initial + 251));
  store.revoke(rotated.id); const next = store.reserve(initial + 251).create(principal, initial + 251, auth); store.assertAuthority(next.authority, principal, initial + 251);
  assert.throws(() => store.assertAuthority(rotated.authority, principal, initial + 251));
});

for (const dialect of [openAiDialect, anthropicDialect]) test(`${dialect.name}: revocation after an observed first HTTP refusal prevents a second wire attempt`, async () => {
  let active = true, calls = 0;
  const provider = new HttpProvider({ baseUrl: "https://models.fixture.invalid", apiKey: "synthetic", model: "fixture", dialect,
    fetchImpl: async () => { calls++; return Response.json({}, { status: 503 }); }, sleep: async () => { active = false; } });
  await assert.rejects(provider.generate({ prompt: "fixture", assertAuthority: () => { if (!active) throw Error("revoked"); } }), (e: unknown) => e instanceof ProviderError && e.permanent);
  assert.equal(calls, 1); await assert.rejects(provider.generateStream({ prompt: "fixture", assertAuthority: () => { throw Error("revoked"); } }), /authority unavailable/); assert.equal(calls, 1);
});
test("broker host preserves live authority across its asynchronous witness and HTTP retry boundary", async () => {
  let active = true, calls = 0, checks = 0;
  const inner = new HttpProvider({ baseUrl: "https://models.fixture.invalid", apiKey: "synthetic", model: "fixture", dialect: openAiDialect,
    fetchImpl: async () => { calls++; return Response.json({}, { status: 503 }); }, sleep: async () => { active = false; } });
  const provider = buildDefaultBrokeredEgress(inner, { write() {} }, { transportClass: "remote", ownerAuthority: true });
  await assert.rejects(provider.generate({ prompt: "fixture", assertAuthority: () => { checks++; if (!active) throw Error("revoked"); } }));
  assert.equal(calls, 1); assert.ok(checks >= 3);
});
