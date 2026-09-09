import { test } from "node:test";
import assert from "node:assert/strict";

import { compilePolicy, type SignedBundle, type CompilerSigner } from "../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";
import type { JsonValue } from "../src/policy/json.js";
import { makeAddress } from "../src/ingress/address.js";
import { validateDecl, type IngressDecl } from "../src/ingress/ingress.js";
import type { WireSchema } from "../src/ingress/schema.js";
import { compileManifest, type ManifestSigner } from "../src/ingress/ingress_manifest.js";
import { DecisionKernel } from "../src/kernel/decision.js";
import { verify as verifyPermit, type Permit, type PermitKey } from "../src/permit/permit.js";
import {
  AdmissionGate, AdmissionError, MAX_BODY_BYTES, MAX_VALIDITY_MS, permitMinter, type ChannelAuthenticator, type AdmissionPolicy,
  type AdmissionHandler, type AdmissionView, type IngressEvent,
} from "../src/admission/admission.js";

// Mechanical-Enforcement Increment 8 — INGRESS ADMISSION GATE. Frontier property: no handler obtains authority until the
// request is admitted (channel-authenticated FOR THIS ingress, bounded, schema-decoded, kernel-authorized, permit-minted);
// authority is the unforgeable request-bound single-use permit in the delivered view. Proven by disproof — neutering a
// check in src/admission/admission.ts reddens a named test:
//   closed-world seal                => "an undeclared ingress address is rejected"
//   channel authentication           => "an unauthenticated channel is rejected"
//   channel bound to the ingress     => "a credential valid for one ingress cannot be cross-routed to another"
//   decision-before-handler          => "a denied decision rejects before the handler runs"
//   per-request + per-gate uniqueness => "each admission mints a distinct request-bound permit" / "...across gates"
//   body read-once                    => "the body is read exactly once (size == decoded == committed)"
//   validity cap                      => "an over-cap validity is rejected at registration"
//   handler-throw is post-admission  => "a handler exception is reported admitted:true"
//   schema / bounds / phase          => "malformed / oversized / pre-active requests are rejected"

const KEYID = "k1", SECRET = "s3cr3t";
const psigner: CompilerSigner = { signer: new StubSigner(SECRET, KEYID), keyid: KEYID, verifyKey: SECRET };
const ptrust: TrustPolicy = { trustedKeys: new Map([[KEYID, SECRET]]), threshold: 1 };
const MK = "mk1", MSECRET = "manifest-secret";
const msigner: ManifestSigner = { signer: new StubSigner(MSECRET, MK), keyid: MK, verifyKey: MSECRET };
const mtrust: TrustPolicy = { trustedKeys: new Map([[MK, MSECRET]]), threshold: 1 };
const SEAMS = { artifactGraphDigest: "a".repeat(64), scannerToolDigest: "b".repeat(64) };
const minterKey: PermitKey = { issuer: "monitor-key", rootKey: "root-K" };
const minter = permitMinter(minterKey);

const HTTP = makeAddress("http", "orders.create");
const TIMER = makeAddress("timer", "nightly");
const BLOB = makeAddress("http", "blob");
const intRec: WireSchema = { t: "record", fields: [{ name: "amount", schema: { t: "int" }, optional: false }] };
const httpDecl: IngressDecl = validateDecl({ address: HTTP, abiVersion: 1n, input: intRec, output: { t: "null" }, error: { t: "str" }, cardinality: "single" });
const timerDecl: IngressDecl = validateDecl({ address: TIMER, abiVersion: 1n, input: { t: "null" }, output: { t: "null" }, error: { t: "str" }, cardinality: "single" });
const blobDecl: IngressDecl = validateDecl({ address: BLOB, abiVersion: 1n, input: { t: "str" }, output: { t: "null" }, error: { t: "str" }, cardinality: "single" });

// A channel authenticator that binds each credential to a SPECIFIC ingress address (a stand-in for a verified webhook
// signature / mTLS peer scoped to an endpoint). A credential presented to the wrong ingress authenticates to null.
const authBound = (creds: Record<string, { principal: string; channelId: string; forAddress: string }>): ChannelAuthenticator => ({
  authenticate(channel, decl) {
    const c = channel as { cred?: string };
    const a = c && typeof c.cred === "string" ? creds[c.cred] : undefined;
    if (!a || a.forAddress !== decl.address) return null;
    return { principal: a.principal, channelId: a.channelId };
  },
});

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

interface Built { gate: AdmissionGate; ran: { at: string[] }; effectId: string; }
function build(auth: ChannelAuthenticator, decls: IngressDecl[] = [httpDecl], gateNonce = "gate-nonce-1"): Built {
  const bundle = policyBundle();
  const effectId = bundle.payload.effects[0]!.id;
  const kernel = new DecisionKernel(bundle, ptrust);
  const policy: AdmissionPolicy = (decl) => ({
    effectId, entryPoint: decl.address, objectId: `obj:${decl.address}`, rights: ["read"], audience: ["broker-fs"],
    validityMs: 1000n, contextOf: () => new Map(),
  });
  const ran = { at: [] as string[] };
  const gate = new AdmissionGate(kernel, auth, minter, policy, gateNonce);
  const handler: (addr: string) => AdmissionHandler = (addr) => (view: AdmissionView) => { ran.at.push(addr); return { echoed: view.input, by: view.principal, permit: view.permit }; };
  for (const d of decls) gate.register(d, handler(d.address));
  gate.seal(compileManifest(decls, bundle, SEAMS, [msigner]), bundle, { manifestTrust: mtrust, policyTrust: ptrust });
  gate.activate();
  return { gate, ran, effectId };
}

const agentHttp = authBound({ good: { principal: "agent", channelId: "chan-1", forAddress: HTTP } });

test("happy path: an admitted request runs the handler and delivers a genuine request-bound permit", async () => {
  const { gate, ran } = build(agentHttp);
  const r = await gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 7n } }, 100n);
  assert.equal(r.admitted, true);
  assert.deepEqual(ran.at, [HTTP]);
  if (r.admitted) {
    const out = r.output as { echoed: unknown; by: string; permit: Permit };
    assert.deepEqual(out.echoed, { amount: 7n });
    assert.equal(out.by, "agent");
    const v = verifyPermit(out.permit, minterKey, { now: 200n, currentEpoch: 0n, subject: "agent", session: r.requestId, effectId: out.permit.claims.effectId, audience: "broker-fs", objectId: out.permit.claims.objectId, right: "read" });
    assert.equal(v.valid, true);
    assert.equal(out.permit.claims.session, r.requestId);
  }
});

test("an undeclared ingress address is rejected (closed-world deny-by-default)", async () => {
  const { gate, ran } = build(agentHttp);
  const r = await gate.admit({ address: makeAddress("http", "ghost"), channel: { cred: "good" }, body: { amount: 1n } }, 100n);
  assert.equal(r.admitted, false);
  assert.equal(ran.at.length, 0);
});

test("an unauthenticated channel is rejected (handler never runs)", async () => {
  const { gate, ran } = build(agentHttp);
  const r = await gate.admit({ address: HTTP, channel: { cred: "unknown" }, body: { amount: 1n } }, 100n);
  assert.equal(r.admitted, false);
  assert.match((r as { reason: string }).reason, /channel authentication failed/);
  assert.equal(ran.at.length, 0);
});

test("a credential valid for one ingress cannot be cross-routed to another", async () => {
  const auth = authBound({ good: { principal: "agent", channelId: "c", forAddress: HTTP } });
  const { gate, ran } = build(auth, [httpDecl, timerDecl]);
  const r = await gate.admit({ address: TIMER, channel: { cred: "good" }, body: null }, 100n);
  assert.equal(r.admitted, false);
  assert.equal(ran.at.length, 0);
});

test("the subject is the authenticated principal, not body-asserted (a denied principal is rejected)", async () => {
  const auth = authBound({ good: { principal: "stranger", channelId: "c", forAddress: HTTP } });
  const { gate, ran } = build(auth);
  const r = await gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 1n } }, 100n);
  assert.equal(r.admitted, false);
  assert.match((r as { reason: string }).reason, /denied by the decision kernel/);
  assert.equal(ran.at.length, 0);
});

test("a denied decision rejects before the handler runs; the permit is bound to the decided subject and effect", async () => {
  const bundle = policyBundle();
  const effectId = bundle.payload.effects[0]!.id;
  const kernel = new DecisionKernel(bundle, ptrust);
  const ran = { at: [] as string[] };
  const gate = new AdmissionGate(kernel, agentHttp, minter, (d) => ({ effectId, entryPoint: d.address, objectId: "o", rights: ["read"], audience: ["b"], validityMs: 10n, contextOf: () => new Map() }), "gn");
  gate.register(httpDecl, (v: AdmissionView) => { ran.at.push("x"); return v; });
  gate.seal(compileManifest([httpDecl], bundle, SEAMS, [msigner]), bundle, { manifestTrust: mtrust, policyTrust: ptrust });
  gate.activate();
  const ok = await gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 1n } }, 100n);
  assert.equal(ok.admitted, true);
  if (ok.admitted) assert.equal((ok.output as AdmissionView).permit.claims.effectId, effectId);
  kernel.revoke({ effect: effectId });
  ran.at.length = 0;
  const r = await gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 1n } }, 100n);
  assert.equal(r.admitted, false);
  assert.equal(ran.at.length, 0);
});

test("each admission mints a distinct request-bound permit (no cross-request replay)", async () => {
  const { gate } = build(agentHttp);
  const r1 = await gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 5n } }, 100n);
  const r2 = await gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 5n } }, 100n);
  assert.equal(r1.admitted && r2.admitted, true);
  if (r1.admitted && r2.admitted) {
    assert.notEqual(r1.requestId, r2.requestId);
    const p1 = (r1.output as { permit: Permit }).permit, p2 = (r2.output as { permit: Permit }).permit;
    assert.notEqual(p1.claims.session, p2.claims.session);
    assert.notEqual(p1.tag, p2.tag);
    assert.equal(verifyPermit(p1, minterKey, { now: 150n, currentEpoch: 0n, subject: "agent", session: r2.requestId, effectId: p1.claims.effectId, audience: "broker-fs", objectId: p1.claims.objectId, right: "read" }).valid, false);
  }
});

test("request ids are distinct across gate instances/restarts (per-gate nonce)", async () => {
  const a = build(agentHttp, [httpDecl], "gate-A");
  const b = build(agentHttp, [httpDecl], "gate-B");
  const ra = await a.gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 9n } }, 100n);
  const rb = await b.gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 9n } }, 100n);
  assert.equal(ra.admitted && rb.admitted, true);
  if (ra.admitted && rb.admitted) assert.notEqual(ra.requestId, rb.requestId);
});

test("the body is read exactly once (size == decoded == committed value)", async () => {
  const auth = authBound({ goodBlob: { principal: "agent", channelId: "c", forAddress: BLOB } });
  const g = build(auth, [blobDecl]);
  let reads = 0;
  const event: IngressEvent = { address: BLOB, channel: { cred: "goodBlob" }, get body() { reads++; return reads === 1 ? "hello" : "a".repeat(MAX_BODY_BYTES + 100); } };
  const r = await g.gate.admit(event, 100n);
  assert.equal(reads, 1, "event.body is read exactly once");
  assert.equal(r.admitted, true);
  if (r.admitted) assert.equal((r.output as { echoed: unknown }).echoed, "hello");
});

test("an over-cap validity is rejected at registration (no effectively-permanent permit)", () => {
  const bundle = policyBundle();
  const effectId = bundle.payload.effects[0]!.id;
  const gate = new AdmissionGate(new DecisionKernel(bundle, ptrust), agentHttp, minter, (d) => ({ effectId, entryPoint: d.address, objectId: "o", rights: ["r"], audience: ["b"], validityMs: MAX_VALIDITY_MS + 1n, contextOf: () => new Map() }), "gn");
  assert.throws(() => gate.register(httpDecl, () => null), AdmissionError);
});

test("a handler exception is reported admitted:true (the request was admitted; not a re-mintable denial)", async () => {
  const bundle = policyBundle();
  const effectId = bundle.payload.effects[0]!.id;
  const gate = new AdmissionGate(new DecisionKernel(bundle, ptrust), agentHttp, minter, (d) => ({ effectId, entryPoint: d.address, objectId: "o", rights: ["r"], audience: ["b"], validityMs: 10n, contextOf: () => new Map() }), "gn");
  gate.register(httpDecl, () => { throw { get message() { throw new Error("hostile"); } }; });
  gate.seal(compileManifest([httpDecl], bundle, SEAMS, [msigner]), bundle, { manifestTrust: mtrust, policyTrust: ptrust });
  gate.activate();
  const r = await gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 1n } }, 100n);
  assert.equal(r.admitted, true);
  if (r.admitted) assert.equal(typeof r.handlerError, "string");
});

test("an oversized body is rejected before the decision (bounds)", async () => {
  const auth = authBound({ goodBlob: { principal: "agent", channelId: "c", forAddress: BLOB } });
  const { gate, ran } = build(auth, [blobDecl]);
  const r = await gate.admit({ address: BLOB, channel: { cred: "goodBlob" }, body: "a".repeat(MAX_BODY_BYTES + 100) }, 100n);
  assert.equal(r.admitted, false);
  assert.match((r as { reason: string }).reason, /exceeds/);
  assert.equal(ran.at.length, 0);
});

test("malformed / oversized / pre-active requests are rejected (fail closed, total)", async () => {
  const { gate, ran } = build(agentHttp);
  assert.equal((await gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: "seven" } as unknown as JsonValue }, 100n)).admitted, false);
  assert.equal((await gate.admit({ address: HTTP, channel: { cred: "good" }, body: (() => 0) as unknown as JsonValue }, 100n)).admitted, false);
  for (const bad of [null, 42, "x", {}]) assert.equal((await gate.admit(bad as unknown as IngressEvent, 100n)).admitted, false);
  assert.equal((await gate.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 1n } }, -1n)).admitted, false);
  const hostile = new Proxy({}, { get(_t, k) { if (k === "address") throw { get message() { throw 1; } }; return undefined; } });
  assert.equal((await gate.admit(hostile as unknown as IngressEvent, 100n)).admitted, false);
  assert.equal(ran.at.length, 0);

  const bundle = policyBundle();
  const effectId = bundle.payload.effects[0]!.id;
  const g2 = new AdmissionGate(new DecisionKernel(bundle, ptrust), agentHttp, minter, (d) => ({ effectId, entryPoint: d.address, objectId: "o", rights: ["r"], audience: ["b"], validityMs: 10n, contextOf: () => new Map() }), "gn");
  g2.register(httpDecl, () => null);
  g2.seal(compileManifest([httpDecl], bundle, SEAMS, [msigner]), bundle, { manifestTrust: mtrust, policyTrust: ptrust });
  assert.equal((await g2.admit({ address: HTTP, channel: { cred: "good" }, body: { amount: 1n } }, 100n)).admitted, false);
});

test("boot closure: sealing a collected set that differs from the manifest is rejected", () => {
  const bundle = policyBundle();
  const effectId = bundle.payload.effects[0]!.id;
  const gate = new AdmissionGate(new DecisionKernel(bundle, ptrust), agentHttp, minter, (d) => ({ effectId, entryPoint: d.address, objectId: "o", rights: ["r"], audience: ["b"], validityMs: 10n, contextOf: () => new Map() }), "gn");
  gate.register(httpDecl, () => null);
  const manifest = compileManifest([httpDecl, timerDecl], bundle, SEAMS, [msigner]);
  assert.throws(() => gate.seal(manifest, bundle, { manifestTrust: mtrust, policyTrust: ptrust }), AdmissionError);
});

test("a timer (scheduled) ingress is admitted like any other — no unadmitted timer path", async () => {
  const auth = authBound({ tick: { principal: "agent", channelId: "c", forAddress: TIMER } });
  const { gate, ran } = build(auth, [httpDecl, timerDecl]);
  const r = await gate.admit({ address: TIMER, channel: { cred: "tick" }, body: null }, 100n);
  assert.equal(r.admitted, true);
  assert.deepEqual(ran.at, [TIMER]);
});
