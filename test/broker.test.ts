import { test } from "node:test";
import assert from "node:assert/strict";

import { compilePolicy, type SignedBundle, type CompilerSigner } from "../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";
import type { JsonValue } from "../src/policy/json.js";
import { validateEffectDecl, type EffectFamily } from "../src/effect/effect.js";
import { compileEffectManifest, type EffectManifestSigner } from "../src/effect/effect_manifest.js";
import { mintRoot, type Permit, type PermitClaims, type PermitKey } from "../src/permit/permit.js";
import { RedemptionLedger } from "../src/permit/ledger.js";
import { EffectBroker, BrokerError, MapIdempotencyStore, type IdempotencyStore, type InFlight, type Executor, type AuditSink, type BrokerRequest, type FamilyBinding, type Authorized } from "../src/broker/broker.js";
import type { CanonicalValue } from "../src/eir/canonical.js";

// Mechanical-Enforcement Increment 9 — EFFECT BROKER KERNEL. Frontier property: an effect runs ONLY as the second half
// of an atomic redeem→dispatch transaction — the requested OPERATION maps to the RIGHT it requires (sealed allowlist),
// a permit bound to this subject/session/effect/object + that right + this family's audience is single-use redeemed on
// a SHARED ledger, then the ONE closed-world executor gets the AUTHORIZED (effect,object,operation,right); all audited
// fail-closed; no escape hatch. Proven by disproof — neutering a check in src/broker/broker.ts reddens a named test:
//   operation→right binding          => "an operation cannot exceed the right its permit grants"
//   redeem-before-dispatch           => "an invalid permit is denied and NOTHING is dispatched"
//   single-use (shared ledger)       => "a permit cannot be redeemed twice"
//   audience binds family            => "a permit for one family cannot drive another"
//   closed-world executor/operation  => "an undeclared family/operation is denied"
//   single-flight idempotency        => "concurrent + repeated identical ops dispatch exactly once"
//   fail-closed audit                => "a failing audit sink aborts before any effect"
//   cancellation                     => "an aborted dispatch is a fail-closed error"
//   result sanitization + freeze     => "a non-canonical result is rejected; outputs are frozen"

const KEYID = "k1", SECRET = "s3cr3t";
const psigner: CompilerSigner = { signer: new StubSigner(SECRET, KEYID), keyid: KEYID, verifyKey: SECRET };
const ptrust: TrustPolicy = { trustedKeys: new Map([[KEYID, SECRET]]), threshold: 1 };
const EK = "ek1", ESEC = "effect-secret";
const esigner: EffectManifestSigner = { signer: new StubSigner(ESEC, EK), keyid: EK, verifyKey: ESEC };
const etrust: TrustPolicy = { trustedKeys: new Map([[EK, ESEC]]), threshold: 1 };
const SEAMS = { artifactGraphDigest: "a".repeat(64), scannerToolDigest: "b".repeat(64) };
const permitKey: PermitKey = { issuer: "monitor", rootKey: "root-K" };

function policyBundle(): SignedBundle {
  const p: JsonValue = {
    version: 1n, combiningAlgorithm: "deny-overrides",
    principals: [{ name: "agent", labels: [] }],
    effects: [{ id: "e", effectType: "fs.read", resourceSelector: "/x" }],
    guards: [],
    rules: [{ id: "r", decision: "permit", subjects: ["agent"], entryPoints: ["*"], effect: "e" }],
  };
  return compilePolicy(p, [psigner]);
}

interface Canary { calls: Authorized[]; }
interface Built { broker: EffectBroker; audit: { records: CanonicalValue[] }; canary: Canary; effectId: string; ledger: RedemptionLedger; }
function build(opts: { exec?: Executor; operations?: Map<string, string>; sink?: AuditSink; idem?: IdempotencyStore } = {}): Built {
  const bundle = policyBundle();
  const effectId = bundle.payload.effects[0]!.id;
  const fsDecl = validateEffectDecl({ family: "fs", owner: "src/fs/owner.ts" });
  const manifest = compileEffectManifest([fsDecl], bundle, SEAMS, [esigner]);
  const canary: Canary = { calls: [] };
  const executor: Executor = opts.exec ?? ((authz) => { canary.calls.push(authz); return { ok: true }; });
  const audit = { records: [] as CanonicalValue[] };
  const sink: AuditSink = opts.sink ?? { write(r) { audit.records.push(r); } };
  const operations = opts.operations ?? new Map([["read", "read"], ["write", "write"]]);
  const ledger = new RedemptionLedger();
  const bindings = new Map<EffectFamily, FamilyBinding>([["fs", { executor, audience: "broker-fs", operations }]]);
  const broker = new EffectBroker(manifest, bundle, { manifestTrust: etrust, policyTrust: ptrust }, permitKey, ledger, opts.idem ?? new MapIdempotencyStore(), bindings, sink, "broker-nonce-1");
  return { broker, audit, canary, effectId, ledger };
}

function permit(effectId: string, over: Partial<PermitClaims> = {}): Permit {
  const claims: PermitClaims = {
    issuer: "monitor", subject: "agent", session: "req-1", effectId, objectId: "obj-1",
    rights: ["read", "write"], guardDigest: "a".repeat(64), epoch: 0n,
    notBefore: 0n, notAfter: 1000n, nonce: "req-1", maxRedemptions: 1n, audience: ["broker-fs"],
    ...over,
  };
  return mintRoot(claims, permitKey);
}
function req(effectId: string, p: Permit, over: Partial<BrokerRequest> = {}): BrokerRequest {
  return { permit: p, subject: "agent", session: "req-1", effectId, objectId: "obj-1", family: "fs", operation: "read", args: { path: "/x" }, idempotencyKey: "idem-1", ...over };
}
const kinds = (recs: CanonicalValue[]): string[] => recs.map((r) => (r as { kind: string }).kind);

test("happy path: an admitted permit is redeemed and dispatched exactly once, fully audited", async () => {
  const { broker, audit, canary, effectId } = build();
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, true);
  if (r.ok) assert.equal((r.output as { ok: boolean }).ok, true);
  assert.equal(canary.calls.length, 1);
  assert.deepEqual({ op: canary.calls[0]!.operation, right: canary.calls[0]!.right, obj: canary.calls[0]!.objectId }, { op: "read", right: "read", obj: "obj-1" });
  const ks = kinds(audit.records);
  assert.ok(["intent", "redeemed", "dispatch", "result"].every((k) => ks.includes(k)), `audit had ${ks.join(",")}`);
});

test("an operation cannot exceed the right its permit grants (operation→right binding — the keystone)", async () => {
  // ops: 'delete' requires the 'delete' right. The permit grants only ['read'] -> the DERIVED right 'delete' is not
  // granted -> redemption fails -> the delete executor never runs. A read permit cannot drive a delete.
  const { broker, canary, effectId } = build({ operations: new Map([["read", "read"], ["delete", "delete"]]) });
  const readOnly = permit(effectId, { rights: ["read"] });
  const r = await broker.dispatch(req(effectId, readOnly, { operation: "delete" }), 100n, 0n);
  assert.equal(r.ok, false);
  assert.equal(canary.calls.length, 0, "a read-only permit must not drive a delete");
  // and a permit that DOES grant delete can invoke it.
  const full = permit(effectId, { rights: ["read", "delete"], nonce: "req-2", session: "req-2" });
  const r2 = await broker.dispatch(req(effectId, full, { operation: "delete", session: "req-2", idempotencyKey: "k2" }), 100n, 0n);
  assert.equal(r2.ok, true);
  assert.equal(canary.calls.length, 1);
  assert.equal(canary.calls[0]!.right, "delete");
});

test("an invalid permit is denied and NOTHING is dispatched (redeem before dispatch)", async () => {
  const { broker, canary, audit, effectId } = build();
  const r = await broker.dispatch(req(effectId, permit(effectId), { session: "other" }), 100n, 0n); // session-mismatch
  assert.equal(r.ok, false);
  assert.equal(canary.calls.length, 0);
  assert.ok(kinds(audit.records).includes("denied") || kinds(audit.records).includes("intent"));
});

test("a permit cannot be redeemed twice (single-use, shared ledger)", async () => {
  const { broker, canary, effectId } = build();
  const p = permit(effectId);
  assert.equal((await broker.dispatch(req(effectId, p, { idempotencyKey: "k1" }), 100n, 0n)).ok, true);
  const r2 = await broker.dispatch(req(effectId, p, { idempotencyKey: "k2" }), 100n, 0n); // same permit, new idem key
  assert.equal(r2.ok, false);
  assert.equal(canary.calls.length, 1);
});

test("a permit for one family cannot drive another (audience binding)", async () => {
  const { broker, canary, effectId } = build();
  const p = permit(effectId, { audience: ["broker-net"] });
  const r = await broker.dispatch(req(effectId, p), 100n, 0n);
  assert.equal(r.ok, false);
  assert.equal(canary.calls.length, 0);
});

test("an undeclared family / operation is denied (closed-world, no escape hatch)", async () => {
  const { broker, canary, effectId } = build();
  assert.equal((await broker.dispatch(req(effectId, permit(effectId), { family: "net" as EffectFamily }), 100n, 0n)).ok, false);
  assert.equal((await broker.dispatch(req(effectId, permit(effectId), { operation: "exec-anything" }), 100n, 0n)).ok, false);
  assert.equal(canary.calls.length, 0);
});

test("concurrent + repeated identical ops dispatch exactly once (single-flight idempotency)", async () => {
  let started = 0;
  const slow: Executor = async () => { started++; await Promise.resolve(); return { ok: true }; };
  const { broker, canary, effectId } = build({ exec: slow });
  void canary;
  // two CONCURRENT identical requests (distinct permits) -> exactly one dispatch.
  const [a, b] = await Promise.all([
    broker.dispatch(req(effectId, permit(effectId), { idempotencyKey: "same" }), 100n, 0n),
    broker.dispatch(req(effectId, permit(effectId, { nonce: "p2" }), { idempotencyKey: "same" }), 100n, 0n),
  ]);
  assert.equal(a.ok && b.ok, true);
  assert.equal(started, 1, "single-flight: the executor ran exactly once");
  // a later repeat replays without re-dispatching.
  const c = await broker.dispatch(req(effectId, permit(effectId, { nonce: "p3" }), { idempotencyKey: "same" }), 100n, 0n);
  assert.equal(c.ok, true);
  if (c.ok) assert.equal(c.replayed, true);
  assert.equal(started, 1);
});

test("a failing audit sink aborts before any effect (fail-closed audit)", async () => {
  const canary: Authorized[] = [];
  const exec: Executor = (a) => { canary.push(a); return { ok: true }; };
  const badSink: AuditSink = { write() { throw new Error("audit down"); } };
  const { broker, effectId } = build({ exec, sink: badSink });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /audit unavailable/);
  assert.equal(canary.length, 0, "no effect runs when the audit sink is down");
});

test("an aborted dispatch is a fail-closed error", async () => {
  const hang: Executor = () => new Promise(() => { /* never settles */ });
  const { broker, effectId } = build({ exec: hang });
  const ac = new AbortController();
  const pr = broker.dispatch(req(effectId, permit(effectId)), 100n, 0n, ac.signal);
  ac.abort();
  const r = await pr;
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /abort|timed out/);
});

test("a non-canonical executor result is rejected; outputs are frozen", async () => {
  const bad: Executor = () => (() => 0) as unknown as CanonicalValue;
  assert.equal((await build({ exec: bad }).broker.dispatch(req("x".repeat(64), permit("x".repeat(64)), {}), 100n, 0n)).ok, false);
  // a valid output is returned frozen (cache-poisoning resistant).
  const { broker, effectId } = build({ exec: () => ({ n: 1n, list: [1n, 2n] }) });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, true);
  if (r.ok) { assert.equal(Object.isFrozen(r.output), true); assert.throws(() => { (r.output as { n: bigint }).n = 9n; }, TypeError); }
});

test("totality: malformed requests fail closed without throwing; the broker exposes only dispatch", async () => {
  const { broker, canary, effectId } = build();
  for (const bad of [null, 42, "x", {}, req(effectId, permit(effectId), { operation: "" }), req(effectId, permit(effectId), { subject: "" })]) {
    assert.equal((await broker.dispatch(bad as unknown as BrokerRequest, 100n, 0n)).ok, false);
  }
  assert.equal((await broker.dispatch(req(effectId, permit(effectId), { args: (() => 0) as unknown as CanonicalValue }), 100n, 0n)).ok, false);
  assert.equal(canary.calls.length, 0);
  assert.deepEqual(Object.getOwnPropertyNames(Object.getPrototypeOf(broker)).filter((m) => m !== "constructor").sort(), ["dispatch"]);
});

test("a pre-aborted signal denies WITHOUT running the effect or spending the permit", async () => {
  let ran = 0;
  const exec: Executor = () => { ran++; return { ok: true }; }; // synchronous effect owner
  const { broker, effectId } = build({ exec });
  const ac = new AbortController(); ac.abort(); // aborted BEFORE the call
  const p = permit(effectId);
  const r = await broker.dispatch(req(effectId, p), 100n, 0n, ac.signal);
  assert.equal(r.ok, false);
  assert.equal(ran, 0, "the synchronous executor must NOT run under a pre-aborted signal");
  // the permit was not spent — a fresh (un-aborted) dispatch of the SAME permit still succeeds.
  const r2 = await broker.dispatch(req(effectId, p, { idempotencyKey: "k2" }), 100n, 0n);
  assert.equal(r2.ok, true);
});

test("the returned/cached result wrapper is deeply frozen (no cache poisoning)", async () => {
  const { broker, effectId } = build();
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, true);
  assert.equal(Object.isFrozen(r), true);
  assert.throws(() => { (r as unknown as { ok: boolean }).ok = false; }, TypeError);
  assert.throws(() => { (r as unknown as { auditId: string }).auditId = "forged"; }, TypeError);
});

test("a hostile request Proxy is a fail-closed deny, not a throw (totality)", async () => {
  const { broker } = build();
  const hostile = new Proxy({}, { get() { throw new Error("boom"); } });
  const r = await broker.dispatch(hostile as unknown as BrokerRequest, 100n, 0n);
  assert.equal(r.ok, false); // must resolve, not reject
});

test("a result-audit failure is surfaced explicitly (resultAudited:false), not silent success", async () => {
  // a sink that throws ONLY on the post-effect 'result' record.
  const seenKinds: string[] = [];
  const sink: AuditSink = { write(rec) { const k = (rec as { kind: string }).kind; seenKinds.push(k); if (k === "result") throw new Error("result write failed"); } };
  const { broker, effectId } = build({ sink });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, true); // the effect happened
  if (r.ok) assert.equal(r.resultAudited, false); // but the result record failed — surfaced, not hidden
  assert.ok(seenKinds.includes("intent") && seenKinds.includes("dispatch"));
});

test("replay requires a valid permit for the operation (no cross-caller output disclosure)", async () => {
  const { broker, canary, effectId } = build();
  const first = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(first.ok, true);
  // a party who knows the (guessable) request fields but presents a BOGUS permit is denied — NOT served the output.
  const bogus = { ...permit(effectId), tag: "f".repeat(64) } as Permit;
  const r2 = await broker.dispatch(req(effectId, bogus), 100n, 0n);
  assert.equal(r2.ok, false);
  assert.match((r2 as { reason: string }).reason, /valid permit/);
  assert.equal(canary.calls.length, 1);
  // a holder of a VALID permit for the same op does replay (idempotent, authorized).
  const r3 = await broker.dispatch(req(effectId, permit(effectId, { nonce: "p3" })), 100n, 0n);
  assert.equal(r3.ok, true);
  if (r3.ok) assert.equal(r3.replayed, true);
  assert.equal(canary.calls.length, 1);
});

test("a hostile abort signal is a fail-closed deny, not a throw", async () => {
  const { broker, effectId } = build();
  const hostile = { get aborted(): boolean { throw new Error("boom"); } } as unknown as AbortSignal;
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n, hostile); // must resolve, not reject
  assert.equal(r.ok, false);
});

test("a malformed abort signal fails closed WITHOUT running the effect", async () => {
  let ran = 0;
  const { broker, effectId } = build({ exec: () => { ran++; return { ok: true }; } });
  const malformed = { aborted: false } as unknown as AbortSignal; // no addEventListener
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n, malformed);
  assert.equal(r.ok, false);
  assert.equal(ran, 0, "the executor must not run when the abort signal is malformed");
});

test("a shared idempotency store gives single-flight across broker instances", async () => {
  // two broker instances sharing ONE ledger + ONE idem store: the same op dispatches exactly once across both.
  const bundle = policyBundle();
  const effectId = bundle.payload.effects[0]!.id;
  const fsDecl = validateEffectDecl({ family: "fs", owner: "src/fs/owner.ts" });
  const manifest = compileEffectManifest([fsDecl], bundle, SEAMS, [esigner]);
  let runs = 0;
  const exec: Executor = async () => { runs++; await Promise.resolve(); return { ok: true }; };
  const ledger = new RedemptionLedger();
  const idem = new MapIdempotencyStore(); // ONE shared store across both instances
  const mk = (): EffectBroker => new EffectBroker(manifest, bundle, { manifestTrust: etrust, policyTrust: ptrust }, permitKey, ledger, idem, new Map<EffectFamily, FamilyBinding>([["fs", { executor: exec, audience: "broker-fs", operations: new Map([["read", "read"]]) }]]), { write() {} }, "n1");
  const a = mk(), b = mk();
  const [ra, rb] = await Promise.all([
    a.dispatch(req(effectId, permit(effectId), { idempotencyKey: "shared" }), 100n, 0n),
    b.dispatch(req(effectId, permit(effectId, { nonce: "p2" }), { idempotencyKey: "shared" }), 100n, 0n),
  ]);
  assert.equal(ra.ok && rb.ok, true);
  assert.equal(runs, 1, "single-flight across instances via the shared idem store");
});

test("a fake (non-AbortSignal) signal is a fail-closed deny without running the effect", async () => {
  let ran = 0;
  const { broker, effectId } = build({ exec: () => { ran++; return { ok: true }; } });
  const fake = { aborted: false, addEventListener() {}, removeEventListener() {} } as unknown as AbortSignal; // no-op listeners
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n, fake);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /malformed abort signal/);
  assert.equal(ran, 0, "a non-AbortSignal must not run the effect");
});

test("a Proxy whose getPrototypeOf trap throws is a fail-closed deny, not a throw (brand-check totality)", async () => {
  // `instanceof AbortSignal` THROWS for this object; isRealAbortSignal must swallow it and deny (dispatch must resolve).
  const { broker, effectId } = build();
  const hostile = new Proxy({}, { getPrototypeOf() { throw new Error("boom"); } }) as unknown as AbortSignal;
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n, hostile);
  assert.equal(r.ok, false);
});

test("a genuine pre-aborted signal cannot hide behind a lying own 'aborted' property (captured getter)", async () => {
  // A real AbortSignal instance (passes the brand check) with an OWN data property `aborted:false` shadowing the
  // prototype getter. abortedSafe reads the CAPTURED platform getter, so the true aborted state is seen -> pre-abort deny.
  let ran = 0;
  const { broker, effectId } = build({ exec: () => { ran++; return { ok: true }; } });
  const ac = new AbortController(); ac.abort();
  const sig = ac.signal;
  Object.defineProperty(sig, "aborted", { value: false, configurable: true }); // lie
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n, sig);
  assert.equal(r.ok, false);
  assert.equal(ran, 0, "the captured getter must see the TRUE aborted state despite the lying own property");
});

test("a genuine signal cannot evade the deadline by shadowing addEventListener (captured intrinsics)", { timeout: 3000 }, async () => {
  // A real AbortSignal with an OWN no-op addEventListener/removeEventListener + lying aborted:false. The broker installs
  // its abort listener via the CAPTURED EventTarget.prototype.addEventListener, so the abort is still delivered and a
  // never-settling executor is bounded {ok:false} — the own-property shadow cannot swallow the abort wiring.
  const hang: Executor = () => new Promise(() => { /* never settles on its own */ });
  const { broker, effectId } = build({ exec: hang });
  const ac = new AbortController();
  const sig = ac.signal;
  Object.defineProperty(sig, "addEventListener", { value() { /* swallow */ }, configurable: true });
  Object.defineProperty(sig, "removeEventListener", { value() {}, configurable: true });
  Object.defineProperty(sig, "aborted", { value: false, configurable: true });
  const pr = broker.dispatch(req(effectId, permit(effectId)), 100n, 0n, sig);
  ac.abort();
  const r = await pr;
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /abort|timed out/);
});

test("a replay disclosure is audited fail-closed (no cached output served if the replay record can't be written)", async () => {
  // The replay-served record is an information-disclosure audit: if the sink cannot write it, the cached output is NOT
  // served (deny), so "every path is audited fail-closed" holds for the replay-read path too.
  let mode = "normal";
  const sink: AuditSink = { write(rec) { if (mode === "fail" && (rec as { kind: string }).kind === "replay-served") throw new Error("audit down"); } };
  const { broker, effectId } = build({ sink });
  const first = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(first.ok, true);
  mode = "fail";
  // a DIFFERENT holder of a valid permit for the same op would replay — but the disclosure record now fails to write.
  const r = await broker.dispatch(req(effectId, permit(effectId, { nonce: "p2" })), 100n, 0n);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /audit unavailable \(replay\)/);
  if (!r.ok) { /* no output field exists on a fail result — nothing disclosed */ }
});

test("an idempotency-store operational failure is fail-closed, not a rejected dispatch (reserve throws)", async () => {
  // a durable IdempotencyStore whose CAS/read throws (DB/transport down) must not make dispatch REJECT — it denies.
  const throwing: IdempotencyStore = { reserve() { throw new Error("db down"); }, release() { /* unused */ } };
  const { broker, effectId } = build({ idem: throwing });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n); // must resolve, not reject
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /idempotency store unavailable/);
});

test("a release() failure never strands the dispatch (settle before release, guarded)", async () => {
  // A retryable (pre-effect) failure triggers release(); if release throws, the dispatch must STILL resolve (waiters are
  // settled first). Force a retryable failure via a sink that throws on the 'intent' write.
  const store = new MapIdempotencyStore();
  const throwingRelease: IdempotencyStore = { reserve: (k, c) => store.reserve(k, c), release: () => { throw new Error("release boom"); } };
  const badSink: AuditSink = { write() { throw new Error("audit down"); } }; // intent write fails -> pre-effect retryable
  const { broker, effectId } = build({ idem: throwingRelease, sink: badSink });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n); // must resolve despite release throwing
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /audit unavailable/);
});

test("a reserve() that installs then throws settles the broker-owned entry and releases it (no strand)", async () => {
  // A durable store that COMMITS the reservation (installs the broker-owned entry) and THEN throws — e.g. a post-commit
  // ack/transport failure. The broker must settle its own entry (so a concurrent waiter that got it resolves, never
  // hangs) AND release the key (so a retry proceeds), then deny.
  const m = new Map<string, InFlight>();
  let installed: InFlight | undefined;
  const store: IdempotencyStore = {
    reserve(key, entry) {
      const ex = m.get(key); if (ex !== undefined) return { entry: ex, fresh: false };
      m.set(key, entry); installed = entry;               // COMMIT
      throw new Error("ack failed after commit");         // ...then fail
    },
    release(key, entry) { if (m.get(key) === entry) m.delete(key); },
  };
  const { broker, effectId } = build({ idem: store });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /idempotency store unavailable/);
  assert.ok(installed, "the store committed a broker-owned entry");
  // the committed entry must be SETTLED (awaiting it resolves, not hangs) — proves no waiter is stranded.
  const outcome = await Promise.race([installed!.then(() => "settled"), new Promise((res) => setTimeout(() => res("pending"), 150))]);
  assert.equal(outcome, "settled", "the broker-owned reservation entry must be settled on the reserve-throw path");
  assert.equal(m.size, 0, "the possibly-installed reservation was released so a retry can proceed");
});

test("a reservation that resolves to a malformed (non-BrokerResult) value is denied, never passed through", async () => {
  // A trusted-but-buggy store returns fresh:false with a thenable resolving to garbage. The broker must DENY, not return
  // the raw value as an output.
  const store: IdempotencyStore = {
    reserve() { return { entry: Promise.resolve(42) as unknown as InFlight, fresh: false }; },
    release() { /* unused */ },
  };
  const { broker, effectId } = build({ idem: store });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /malformed result/);
});

test("a reservation with a FORGED replay binding is denied, never disclosed (authenticated replay — no cross-key disclosure)", async () => {
  // A Byzantine store returns fresh:false with a valid-SHAPED success (carrying attacker 'loot') and a forged bind. The
  // broker re-derives the binding under its own key and constant-time-compares -> mismatch -> DENY, loot never disclosed.
  const forged = Promise.resolve({ result: { ok: true, output: { loot: 1n }, auditId: "x", replayed: false, resultAudited: true }, bind: "0".repeat(64) }) as unknown as InFlight;
  const store: IdempotencyStore = { reserve() { return { entry: forged, fresh: false }; }, release() { /* unused */ } };
  const { broker, effectId } = build({ idem: store });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false, "a forged replay binding must never disclose the cached output");
  assert.match((r as { reason: string }).reason, /binding mismatch/);
});

test("a store that returns NOT-fresh with the broker's OWN entry is denied (no self-strand)", { timeout: 3000 }, async () => {
  // If the store hands our own never-installed deferred back as if it pre-existed, awaiting it would hang forever. The
  // ownership invariant fresh⟺(entry===mine) rejects it -> fail-closed deny, not a hang.
  const store: IdempotencyStore = { reserve(_key, entry) { return { entry, fresh: false }; }, release() { /* unused */ } };
  const { broker, canary, effectId } = build({ idem: store });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /idempotency store unavailable/);
  assert.equal(canary.calls.length, 0);
});

test("the not-fresh path settles + releases the broker's OWN entry so a lying store cannot strand waiters", { timeout: 3000 }, async () => {
  // A Byzantine store INSTALLS the broker-owned `mine` but reports not-fresh with a (never-settling) alien entry. A later
  // caller could receive the secretly-installed `mine`; the broker must settle it (so that waiter resolves) and release it.
  const m = new Map<string, InFlight>();
  let captured: InFlight | undefined;
  const alien = new Promise<never>(() => { /* never settles */ }) as unknown as InFlight;
  const store: IdempotencyStore = {
    reserve(key, entry) { m.set(key, entry); captured = entry; return { entry: alien, fresh: false }; },
    release(key, entry) { if (m.get(key) === entry) m.delete(key); },
  };
  const { broker, effectId } = build({ idem: store });
  const ac = new AbortController();
  const pr = broker.dispatch(req(effectId, permit(effectId)), 100n, 0n, ac.signal);
  ac.abort(); // the current caller is bounded by its signal while awaiting the never-settling alien
  const r = await pr;
  assert.equal(r.ok, false);
  assert.ok(captured, "the store installed the broker-owned entry");
  const outcome = await Promise.race([captured!.then(() => "settled"), new Promise((res) => setTimeout(() => res("pending"), 150))]);
  assert.equal(outcome, "settled", "the broker-owned entry must be settled on the not-fresh path (no strand)");
  assert.equal(m.size, 0, "the installed entry was released");
});

test("a store that returns FRESH with an ALIEN entry is denied (ownership invariant)", async () => {
  const alien = Promise.resolve({ result: { ok: false as const, reason: "x", auditId: "" }, bind: "0".repeat(64) }) as unknown as InFlight;
  const store: IdempotencyStore = { reserve() { return { entry: alien, fresh: true }; }, release() { /* unused */ } };
  const { broker, canary, effectId } = build({ idem: store });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /idempotency store unavailable/);
  assert.equal(canary.calls.length, 0, "the effect must not run when the reservation ownership invariant is violated");
});

test("a reservation object with a throwing getter is denied, not a rejected dispatch", async () => {
  const store: IdempotencyStore = {
    reserve() { return new Proxy({}, { get(_t, p) { if (p === "fresh") throw new Error("boom"); return undefined; } }) as unknown as { entry: InFlight; fresh: boolean }; },
    release() { /* unused */ },
  };
  const { broker, effectId } = build({ idem: store });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n); // must resolve, not reject
  assert.equal(r.ok, false);
});

test("a reservation resolving to a malformed SUCCESS (missing output/resultAudited) is denied", async () => {
  const store: IdempotencyStore = {
    reserve() { return { entry: Promise.resolve({ ok: true, auditId: "x" } as unknown as Awaited<InFlight>), fresh: false }; },
    release() { /* unused */ },
  };
  const { broker, effectId } = build({ idem: store });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /malformed result/);
});

test("executor cancellation survives a replaced global AbortController (captured controller)", async () => {
  const realAC = globalThis.AbortController;
  let execSignalAborted = false;
  // the executor resolves ONLY when the broker cancels IT via the signal the broker passed in.
  const exec: Executor = (_a, _args, sig) => new Promise((resolve) => {
    sig.addEventListener("abort", () => { execSignalAborted = true; resolve({ ok: true }); }, { once: true });
  });
  const { broker, effectId } = build({ exec });
  // sabotage: after module load, replace the global AbortController with one whose abort() is a no-op.
  class NoAbortController { readonly signal = new realAC().signal; abort(): void { /* swallow */ } }
  (globalThis as unknown as { AbortController: unknown }).AbortController = NoAbortController;
  try {
    const ac = new realAC();
    const pr = broker.dispatch(req(effectId, permit(effectId)), 100n, 0n, ac.signal);
    ac.abort();
    const r = await pr;
    assert.equal(r.ok, false); // caller aborted -> dispatch fails closed
    assert.equal(execSignalAborted, true, "the broker must cancel the executor via a CAPTURED AbortController, not the replaced global");
  } finally { (globalThis as unknown as { AbortController: unknown }).AbortController = realAC; }
});

test("closed-world construction: bindings must cover the declared families with unique audiences", () => {
  const bundle = policyBundle();
  const fsDecl = validateEffectDecl({ family: "fs", owner: "src/fs/owner.ts" });
  const manifest = compileEffectManifest([fsDecl], bundle, SEAMS, [esigner]);
  const sink: AuditSink = { write() { /* noop */ } };
  const ex: Executor = () => null;
  const led = new RedemptionLedger();
  const ops = new Map([["read", "read"]]);
  // missing the declared fs family -> reject.
  assert.throws(() => new EffectBroker(manifest, bundle, { manifestTrust: etrust, policyTrust: ptrust }, permitKey, led, new MapIdempotencyStore(), new Map(), sink, "n"), BrokerError);
  // a binding for an UNDECLARED family (net) -> reject.
  assert.throws(() => new EffectBroker(manifest, bundle, { manifestTrust: etrust, policyTrust: ptrust }, permitKey, led, new MapIdempotencyStore(), new Map<EffectFamily, FamilyBinding>([["fs", { executor: ex, audience: "broker-fs", operations: ops }], ["net", { executor: ex, audience: "broker-net", operations: ops }]]), sink, "n"), BrokerError);
  // a non-IdempotencyStore (a bare Map, or missing reserve/release) -> reject.
  assert.throws(() => new EffectBroker(manifest, bundle, { manifestTrust: etrust, policyTrust: ptrust }, permitKey, led, new Map() as never, new Map<EffectFamily, FamilyBinding>([["fs", { executor: ex, audience: "broker-fs", operations: ops }]]), sink, "n"), BrokerError);
});
