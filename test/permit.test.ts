import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";

import {
  mintRoot, attenuate, verify, permitId, claimsDigest, caveatDigest, PermitError,
  type PermitClaims, type PermitKey, type Permit, type Caveat, type RedeemContext, type PermitVerdict,
} from "../src/permit/permit.js";
import { RedemptionLedger, redeem } from "../src/permit/ledger.js";

// Recompute the caveat-layer tag the way permit.ts does (HMAC over the domain + caveat digest), to forge a chain.
function macFold(prevTag: string, caveat: object): string {
  return createHmac("sha256", prevTag).update("keep.permit.caveat-tag/v1").update("|").update(caveatDigest(caveat)).digest("hex");
}

// Mechanical-Enforcement Increment 7 — UNFORGEABLE OBJECT-CAPABILITY PERMITS. Frontier property: authority flows ONLY
// via an unforgeable, object-bound permit that a holder can narrow + delegate WITHOUT a key but can neither forge,
// amplify, detach a restriction from, move across sessions/subjects, nor multiply its redemptions by branching. Proven
// by disproof — neutering a check in src/permit/permit.ts (or ledger.ts) reddens a named test:
//   tag recompute (unforgeable, HMAC)  => "a forged / tampered permit is rejected"
//   monotone narrowing (no amplify)    => "a caveat can only narrow — amplification is impossible"
//   strict-narrowing (anti-launder)    => "a no-op (non-narrowing) caveat is rejected"
//   caveat-chain integrity             => "detaching a caveat (parent) is rejected"
//   subject / session binding          => "a permit is bound to its subject and session"
//   object / effect binding            => "a permit is bound to its exact object and effect"
//   epoch fence (revocation)           => "a permit from a superseded epoch is rejected"
//   validity interval                  => "a permit outside its validity interval is rejected"
//   audience / right                   => "audience and required-right are enforced"
//   per-permit + per-ROOT budget       => "redemptions cannot be multiplied by branching the chain"
//   exact-key / symbol rejection       => "unknown / symbol fields are rejected (every field is bound)"

const ISSUER = "monitor-key-1";
const ROOT_KEY = "root-secret-K";
const key: PermitKey = { issuer: ISSUER, rootKey: ROOT_KEY };
const trust = key;

function baseClaims(over: Partial<PermitClaims> = {}): PermitClaims {
  return {
    issuer: ISSUER, subject: "agent", session: "sess-1", effectId: "eff-post", objectId: "https://api.example/v1",
    rights: ["read", "write"], guardDigest: "a".repeat(64), epoch: 3n,
    notBefore: 1000n, notAfter: 2000n, nonce: "nonce-abc", maxRedemptions: 1n, audience: ["broker-http"],
    ...over,
  };
}
function ctx(over: Partial<RedeemContext> = {}): RedeemContext {
  return { now: 1500n, currentEpoch: 3n, subject: "agent", session: "sess-1", effectId: "eff-post", audience: "broker-http", objectId: "https://api.example/v1", right: "read", ...over };
}
const why = (v: PermitVerdict): string => (v.valid ? "<unexpectedly-valid>" : v.reason);

test("happy path: mint → verify → redeem once succeeds, and reflects the granted authority", () => {
  const p = mintRoot(baseClaims(), key);
  const v = verify(p, trust, ctx());
  assert.equal(v.valid, true);
  if (v.valid) {
    assert.deepEqual(v.effective.rights, ["read", "write"]);
    assert.equal(v.effective.maxRedemptions, 1n);
    assert.equal(v.permitId, permitId(p));
    assert.equal(v.rootId, claimsDigest(p.claims));
  }
  assert.equal(redeem(p, trust, ctx(), new RedemptionLedger()).valid, true);
});

test("a forged / tampered permit is rejected (unforgeable without the root key)", () => {
  const p = mintRoot(baseClaims(), key);
  assert.equal(verify(p, { issuer: ISSUER, rootKey: "not-the-key" }, ctx()).valid, false); // wrong key
  const tampered: Permit = { ...p, claims: { ...p.claims, rights: ["read", "write", "admin"] } };
  assert.match(why(verify(tampered, trust, ctx({ right: "admin" }))), /tag-mismatch/);      // tampered claims, old tag
  assert.equal(verify({ ...p, tag: "f".repeat(64) }, trust, ctx()).valid, false);           // fabricated tag
  assert.equal(verify(p, { issuer: "other", rootKey: ROOT_KEY }, ctx()).valid, false);       // untrusted issuer
});

test("a caveat can only narrow — amplification is impossible", () => {
  const p = mintRoot(baseClaims({ rights: ["read", "write"], audience: ["broker-http", "broker-mail"] }), key);
  const child = attenuate(p, { rights: ["read"], audience: ["broker-http"] });
  const v = verify(child, trust, ctx({ right: "read" }));
  assert.equal(v.valid, true);
  if (v.valid) { assert.deepEqual(v.effective.rights, ["read"]); assert.deepEqual(v.effective.audience, ["broker-http"]); }
  assert.equal(verify(child, trust, ctx({ right: "write" })).valid, false);       // narrowed-away right is gone
  // a caveat naming a right the parent never had cannot grant it (intersection empties it).
  const sneaky = attenuate(p, { rights: ["admin"] });
  assert.equal(verify(sneaky, trust, ctx({ right: "admin" })).valid, false);
  // hand-editing a child's caveat to widen it breaks the tag chain AND is a non-narrowing caveat.
  const forgedWiden: Permit = { ...child, caveats: [{ rights: ["read", "write"], audience: ["broker-http"] }] };
  assert.equal(verify(forgedWiden, trust, ctx()).valid, false);
});

test("a no-op (non-narrowing) caveat is rejected (anti-laundering)", () => {
  const p = mintRoot(baseClaims({ audience: ["broker-http"] }), key);
  // a caveat whose extra audience member is intersected away narrows nothing — rejected at attenuation.
  assert.throws(() => attenuate(p, { audience: ["broker-http", "filler"] }), PermitError);
  // rights superset: no-op → rejected.
  assert.throws(() => attenuate(p, { rights: ["read", "write"] }), PermitError);
  // a looser validity bound narrows nothing → rejected.
  assert.throws(() => attenuate(p, { notAfter: 3000n }), PermitError);   // 3000 > root's 2000
  assert.throws(() => attenuate(p, { maxRedemptions: 5n }), PermitError); // 5 > root's 1
  // and a hand-crafted permit carrying a valid tag over a no-op caveat is still rejected at verify.
  const noop = { rights: ["read", "write"] };
  const forged: Permit = { claims: p.claims, caveats: [noop], tag: macFold(p.tag, noop) };
  assert.match(why(verify(forged, trust, ctx())), /non-narrowing-caveat/);
});

test("detaching a caveat (parent) is rejected — the caveat chain is tamper-evident", () => {
  const p = mintRoot(baseClaims(), key);
  const c1 = attenuate(p, { rights: ["read"] });
  const c2 = attenuate(c1, { notAfter: 1600n });
  assert.equal(verify(c2, trust, ctx({ right: "read", now: 1500n })).valid, true);
  const detached: Permit = { claims: c2.claims, caveats: [{ rights: ["read"] }], tag: c2.tag };
  assert.equal(verify(detached, trust, ctx({ right: "read" })).valid, false);
  const reordered: Permit = { claims: c2.claims, caveats: [{ notAfter: 1600n }, { rights: ["read"] }], tag: c2.tag };
  assert.equal(verify(reordered, trust, ctx({ right: "read" })).valid, false);
});

test("a permit is bound to its subject and session (non-transferable)", () => {
  const p = mintRoot(baseClaims({ subject: "agent", session: "sess-1" }), key);
  assert.equal(verify(p, trust, ctx()).valid, true);
  assert.match(why(verify(p, trust, ctx({ subject: "mallory" }))), /subject-mismatch/);
  assert.match(why(verify(p, trust, ctx({ session: "sess-2" }))), /session-mismatch/);
});

test("a permit is bound to its exact object and effect", () => {
  const p = mintRoot(baseClaims({ objectId: "obj-A", effectId: "eff-post" }), key);
  assert.equal(verify(p, trust, ctx({ objectId: "obj-A", effectId: "eff-post" })).valid, true);
  assert.match(why(verify(p, trust, ctx({ objectId: "obj-B" }))), /object-mismatch/);
  assert.match(why(verify(p, trust, ctx({ effectId: "eff-other" }))), /effect-mismatch/);
});

test("a permit from a superseded epoch is rejected (monotonic revocation)", () => {
  const p = mintRoot(baseClaims({ epoch: 3n }), key);
  assert.equal(verify(p, trust, ctx({ currentEpoch: 3n })).valid, true);
  assert.match(why(verify(p, trust, ctx({ currentEpoch: 4n }))), /stale-epoch/);
});

test("a permit outside its validity interval is rejected", () => {
  const p = mintRoot(baseClaims({ notBefore: 1000n, notAfter: 2000n }), key);
  assert.equal(verify(p, trust, ctx({ now: 1000n })).valid, true);
  assert.equal(verify(p, trust, ctx({ now: 2000n })).valid, true);
  assert.match(why(verify(p, trust, ctx({ now: 999n }))), /not-yet-valid/);
  assert.match(why(verify(p, trust, ctx({ now: 2001n }))), /expired/);
  const short = attenuate(p, { notAfter: 1500n });
  assert.match(why(verify(short, trust, ctx({ now: 1600n }))), /expired/);
});

test("audience and required-right are enforced", () => {
  const p = mintRoot(baseClaims({ audience: ["broker-http"], rights: ["read"] }), key);
  assert.match(why(verify(p, trust, ctx({ audience: "broker-mail" }))), /audience-mismatch/);
  assert.match(why(verify(p, trust, ctx({ right: "write" }))), /right-not-granted/);
});

test("redemptions cannot be multiplied by branching the chain (per-permit + per-ROOT budget)", () => {
  const led = new RedemptionLedger();
  // a single-use root: redeem once, then denied — AND branching into narrowed children does not add budget.
  const root = mintRoot(baseClaims({ maxRedemptions: 1n, notAfter: 2000n }), key);
  // ten genuinely-narrowed children (descending notAfter, all still > now): the ROOT budget caps TOTAL redemptions to 1.
  const children = Array.from({ length: 10 }, (_, i) => attenuate(root, { notAfter: 1990n - BigInt(i) }));
  let redeemed = 0;
  for (const c of children) if (redeem(c, trust, ctx({ now: 1500n }), led).valid) redeemed++;
  assert.equal(redeemed, 1, "the whole subtree shares the root's single-redemption budget");
  assert.equal(redeem(root, trust, ctx(), led).valid, false, "the root itself is also spent");
  assert.equal(led.consumedRoot(claimsDigest(root.claims)), 1n);

  // a root minted for 3 redemptions: exactly 3 across the subtree, then denied.
  const led2 = new RedemptionLedger();
  const root3 = mintRoot(baseClaims({ nonce: "n3", maxRedemptions: 3n }), key);
  const kids = Array.from({ length: 6 }, (_, i) => attenuate(root3, { notAfter: 1990n - BigInt(i) }));
  let ok = 0;
  for (const c of kids) if (redeem(c, trust, ctx({ now: 1500n }), led2).valid) ok++;
  assert.equal(ok, 3, "total redemptions across the subtree == root budget");

  // per-permit cap is also enforced: a child capped at 1 is single-use even if the root has budget left.
  const led3 = new RedemptionLedger();
  const root5 = mintRoot(baseClaims({ nonce: "n5", maxRedemptions: 5n }), key);
  const oneShot = attenuate(root5, { maxRedemptions: 1n });
  assert.equal(redeem(oneShot, trust, ctx(), led3).valid, true);
  assert.equal(redeem(oneShot, trust, ctx(), led3).valid, false, "child's own cap is 1");
  assert.equal(led3.consumedRoot(claimsDigest(root5.claims)), 1n, "root still has 4 left, but this child is spent");
});

test("the ledger rejects a duplicate-id budget list (no double-count of one counter)", () => {
  const led = new RedemptionLedger();
  const id = "00".repeat(32);
  assert.equal(led.tryConsume([{ id, cap: 1n }, { id, cap: 1n }]), false);
  assert.equal(led.consumed(id), 0n, "a duplicate-id list consumes nothing");
  // a single valid budget still consumes.
  assert.equal(led.tryConsume([{ id, cap: 1n }]), true);
  assert.equal(led.consumed(id), 1n);
  assert.equal(led.tryConsume([{ id, cap: 1n }]), false);
});

test("an intermediate delegated cap cannot be multiplied by branching BELOW it (per-prefix budget)", () => {
  // GPT-5.6 r4 SEV0: root budget 100, delegate P (cap 1), then fork P into siblings. Each sibling has a distinct leaf
  // id but they all share P's PREFIX budget (cap 1), so the WHOLE subtree below P redeems at most once — the delegated
  // cap-1 cannot be amplified up to the root budget.
  const led = new RedemptionLedger();
  const root = mintRoot(baseClaims({ maxRedemptions: 100n, notAfter: 5000n }), key);
  const P = attenuate(root, { maxRedemptions: 1n }); // delegated cap 1
  const siblings = Array.from({ length: 8 }, (_, i) => attenuate(P, { notAfter: 4990n - BigInt(i) }));
  let redeemed = 0;
  for (const s of siblings) if (redeem(s, trust, ctx({ now: 1500n }), led).valid) redeemed++;
  // also try redeeming P itself and the root — still bounded by P's prefix (1) for the P-subtree.
  if (redeem(P, trust, ctx({ now: 1500n }), led).valid) redeemed++;
  assert.equal(redeemed, 1, "P's whole subtree shares its delegated cap of 1 — branching cannot multiply it");
  // the root still has budget for a DIFFERENT delegation path (a sibling of P under the root, not under P).
  const Q = attenuate(root, { maxRedemptions: 1n, notAfter: 4000n }); // a distinct prefix under the root
  assert.equal(redeem(Q, trust, ctx({ now: 1500n }), led).valid, true, "an independent delegation under the root still works");
});

test("unknown / symbol fields are rejected (every field is cryptographically bound)", () => {
  // an extra own field on claims is rejected at mint (it would otherwise be an unsigned channel).
  const withExtra = { ...baseClaims(), admin: true } as unknown as PermitClaims;
  assert.throws(() => mintRoot(withExtra, key), PermitError);
  // a symbol key on claims is rejected.
  const symClaims = { ...baseClaims() } as Record<string | symbol, unknown>;
  symClaims[Symbol.for("x")] = 1;
  assert.throws(() => mintRoot(symClaims as unknown as PermitClaims, key), PermitError);
  // an extra field on the presented envelope is rejected at verify.
  const p = mintRoot(baseClaims(), key);
  assert.equal(verify({ ...p, dispatchTarget: "evil" } as unknown as Permit, trust, ctx()).valid, false);
  // a caveat with an unknown field is rejected.
  assert.equal(verify({ ...p, caveats: [{ rights: ["read"], bogus: 1 }] } as unknown as Permit, trust, ctx()).valid, false);
});

test("a hostile own Array.map cannot bypass caveat validation or vary the permit identity", () => {
  // GPT-5.6 r2 SEV1: p.caveats.map(...) would dispatch through the caller's overridable .map. The fix validates via
  // INDEXED access into a fresh snapshot, so a hostile .map is never invoked and the identity stays authenticated.
  const led = new RedemptionLedger();
  const root = mintRoot(baseClaims({ maxRedemptions: 5n }), key);
  const delegated = attenuate(root, { maxRedemptions: 1n }); // per-permit cap 1
  const realCaveat = delegated.caveats[0]!;
  const hostile = [realCaveat] as Caveat[];
  (hostile as unknown as { map: unknown }).map = () => [{ maxRedemptions: 1n }, { rights: ["read"] }]; // would corrupt id if used
  const env: Permit = { claims: delegated.claims, caveats: hostile, tag: delegated.tag };
  // indexed access reads the REAL element, so the tag verifies and the id is stable → the cap-1 holds across redemptions.
  assert.equal(redeem(env, trust, ctx(), led).valid, true);
  assert.equal(redeem(env, trust, ctx(), led).valid, false, "per-permit cap of 1 holds despite the hostile .map");
  // an array whose real content does not fold to the tag is a tag-mismatch regardless of a hostile .map.
  const wrongLen = [] as Caveat[];
  (wrongLen as unknown as { map: unknown }).map = () => [realCaveat];
  assert.equal(verify({ claims: delegated.claims, caveats: wrongLen, tag: delegated.tag }, trust, ctx()).valid, false);
});

test("read-once field capture: a divergent caveat getter cannot store an unvalidated/larger value", () => {
  // Fable r3 latent-TOCTOU: fields are read EXACTLY once. A getter returning a valid 1n on the (single) validation read
  // cannot then store a larger 5n — the stored cap is the validated value, so the child stays single-use.
  const led = new RedemptionLedger();
  const root = mintRoot(baseClaims({ maxRedemptions: 10n }), key);
  let reads = 0;
  const caveat = { get maxRedemptions() { reads++; return reads <= 1 ? 1n : 5n; } } as unknown as Caveat;
  const child = attenuate(root, caveat);
  assert.equal(redeem(child, trust, ctx(), led).valid, true);
  assert.equal(redeem(child, trust, ctx(), led).valid, false, "the single validated read (cap 1) was stored, not a later 5");
});

test("attenuate is total against hostile input (normalizes to PermitError)", () => {
  const p = mintRoot(baseClaims(), key);
  // a Proxy-wrapped array (Array.isArray still true) whose length access throws.
  const hostileCaveats = new Proxy([] as Caveat[], { get(t, k, r) { if (k === "length") throw new Error("boom"); return Reflect.get(t, k, r); } });
  assert.throws(() => attenuate({ claims: p.claims, caveats: hostileCaveats, tag: p.tag }, { rights: ["read"] }), PermitError);
  // a non-hex tag is rejected as an HMAC key.
  assert.throws(() => attenuate({ claims: p.claims, caveats: [], tag: "not-hex" }, { rights: ["read"] }), PermitError);
});

test("verify is total: malformed permits/contexts fail closed without throwing", () => {
  const p = mintRoot(baseClaims(), key);
  for (const bad of [null, undefined, 42, "x", {}, { claims: p.claims, caveats: p.caveats }, { ...p, caveats: "no" }]) {
    assert.equal(verify(bad, trust, ctx()).valid, false);
  }
  // a thrown value whose .message getter itself throws must not escape (totality of the catch handler).
  const hostile = new Proxy({}, { get(_t, k) { if (k === "claims") throw new Proxy({}, { get() { throw new Error("boom"); } }); return undefined; } });
  assert.equal(verify(hostile, trust, ctx()).valid, false);
  assert.equal(verify(p, trust, { ...ctx(), currentEpoch: "x" as unknown as bigint }).valid, false);
  assert.equal(verify(p, trust, ctx({ subject: "" })).valid, false);
});

test("mint / attenuate reject malformed input (fail closed at issuance)", () => {
  assert.throws(() => mintRoot(baseClaims({ rights: [] }), key), PermitError);
  assert.throws(() => mintRoot(baseClaims({ notAfter: 500n, notBefore: 1000n }), key), PermitError);
  assert.throws(() => mintRoot(baseClaims({ maxRedemptions: 0n }), key), PermitError);
  assert.throws(() => mintRoot(baseClaims({ guardDigest: "short" }), key), PermitError);
  assert.throws(() => mintRoot(baseClaims({ epoch: -1n }), key), PermitError);
  assert.throws(() => mintRoot(baseClaims(), { issuer: "wrong", rootKey: ROOT_KEY }), PermitError); // issuer≠key.issuer
  assert.throws(() => mintRoot(baseClaims({ rights: Array.from({ length: 65 }, (_, i) => `r${i}`) }), key), PermitError); // over MAX_SET
});
