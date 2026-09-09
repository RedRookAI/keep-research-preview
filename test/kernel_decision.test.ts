import { test } from "node:test";
import assert from "node:assert/strict";

import { compilePolicy, ALGORITHM, type SignedBundle, type CompilerSigner } from "../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";
import type { JsonValue } from "../src/policy/json.js";
import { DecisionKernel, KernelError, decisionDigest, nextEpoch, MAX_INT_MAG, type DecisionRequest, type Verdict, type DecisionReason } from "../src/kernel/decision.js";
import { parsePredicate, evalPredicate, evalAtom, type ContextValue } from "../src/kernel/predicate.js";

// Mechanical-Enforcement Increment 6 — TOTAL DECISION KERNEL. Frontier property: the kernel is the SOLE producer of an
// allow/deny decision for an EIR request, and every path resolves to DENY except a current-epoch, un-revoked, in-bound
// request that a real permit DEFINITELY grants and no deny even POSSIBLY fires against. Proven by disproof — neutering a
// rule in src/kernel/decision.ts (or predicate.ts) reddens a named test:
//   deny-overrides (denies before permits) => "prod deny overrides an otherwise-valid permit"
//   deny fires on Kleene U (fail-closed)    => "an unknown deny atom still fires the deny (U denies)"
//   permit needs T, not U (fail-closed)     => "an unknown permit atom never grants (U never permits)"
//   unknown effect => deny-by-default       => "a request for an unknown effect is denied"
//   epoch fence                             => "a request at a stale epoch is denied"
//   monotonic revocation                    => "a revoked effect/subject is denied"
//   bounded evaluation                      => "a zero-budget evaluation is denied"
//   decision commitment (digest over all)   => "decision digests match the frozen reference vectors"
//   predicate theory (typed 3-valued eval)  => the predicate.* unit tests

const KEYID = "k1", SECRET = "s3cr3t";
const signer: CompilerSigner = { signer: new StubSigner(SECRET, KEYID), keyid: KEYID, verifyKey: SECRET };
const trust: TrustPolicy = { trustedKeys: new Map([[KEYID, SECRET]]), threshold: 1 };

// A conformance policy whose guard predicates are in the kernel's typed grammar (predicate.ts). Two effects:
//   post (http.post, external): permitted for agent/cli when port∈{443,8443} ∧ path startsWith "/srv"; denied in prod.
//   del  (fs.delete, destructive): permitted for operator/cli when path startsWith "/srv"; denied in prod.
function policy(): JsonValue {
  return {
    version: 1n,
    combiningAlgorithm: ALGORITHM,
    principals: [{ name: "agent", labels: ["untrusted"] }, { name: "operator", labels: [] }],
    effects: [
      { id: "post", effectType: "http.post", resourceSelector: "https://*" },
      { id: "del", effectType: "fs.delete", resourceSelector: "/srv/*" },
    ],
    guards: [
      { id: "gPort", predicate: "net.port in [443, 8443]" },
      { id: "gPath", predicate: "path startsWith \"/srv\"" },
      { id: "gProd", predicate: "env == \"prod\"" },
      { id: "gSafePost", allOf: ["gPort", "gPath"] },
    ],
    rules: [
      { id: "r-post-ok", decision: "permit", subjects: ["agent"], entryPoints: ["cli"], effect: "post", guard: "gSafePost" },
      { id: "r-post-deny-prod", decision: "deny", subjects: ["*"], entryPoints: ["*"], effect: "post", guard: "gProd" },
      { id: "r-del-deny-prod", decision: "deny", subjects: ["*"], entryPoints: ["*"], effect: "del", guard: "gProd" },
      { id: "r-del-op", decision: "permit", subjects: ["operator"], entryPoints: ["cli"], effect: "del", guard: "gPath" },
    ],
  };
}

function build(): { kernel: () => DecisionKernel; bundle: SignedBundle; effId: (t: string) => string } {
  const bundle = compilePolicy(policy(), [signer]);
  const effId = (effectType: string): string => {
    const e = bundle.payload.effects.find((x) => x.effectType === effectType);
    if (e === undefined) throw new Error(`no effect for ${effectType}`);
    return e.id;
  };
  return { kernel: () => new DecisionKernel(bundle, trust), bundle, effId };
}

const ctx = (o: Record<string, ContextValue>): Map<string, ContextValue> => new Map(Object.entries(o));

interface Vec { name: string; subject: string; entry: string; effect: "http.post" | "fs.delete" | "__bogus__"; context: Map<string, ContextValue>; verdict: Verdict; reason: DecisionReason; }

// Epoch-0 stateless vectors — the semantic oracle (verdict + reason) AND the frozen decision-digest reference.
const VECTORS: readonly Vec[] = [
  { name: "post allowed for agent in dev with good port+path", subject: "agent", entry: "cli", effect: "http.post", context: ctx({ env: "dev", "net.port": 443n, path: "/srv/app" }), verdict: "allow", reason: "matched-permit" },
  { name: "prod deny overrides an otherwise-valid permit", subject: "agent", entry: "cli", effect: "http.post", context: ctx({ env: "prod", "net.port": 443n, path: "/srv/app" }), verdict: "deny", reason: "matched-deny" },
  { name: "wrong port yields no applicable permit", subject: "agent", entry: "cli", effect: "http.post", context: ctx({ env: "dev", "net.port": 22n, path: "/srv/app" }), verdict: "deny", reason: "no-applicable-permit" },
  { name: "an unknown permit atom never grants (U never permits)", subject: "agent", entry: "cli", effect: "http.post", context: ctx({ env: "dev", path: "/srv/app" }), verdict: "deny", reason: "no-applicable-permit" },
  { name: "an unknown deny atom still fires the deny (U denies)", subject: "agent", entry: "cli", effect: "http.post", context: ctx({ "net.port": 443n, path: "/srv/app" }), verdict: "deny", reason: "matched-deny" },
  { name: "an undeclared subject matches no specific permit", subject: "stranger", entry: "cli", effect: "http.post", context: ctx({ env: "dev", "net.port": 443n, path: "/srv/app" }), verdict: "deny", reason: "no-applicable-permit" },
  { name: "a request for an unknown effect is denied", subject: "agent", entry: "cli", effect: "__bogus__", context: ctx({ env: "dev" }), verdict: "deny", reason: "unknown-effect" },
  { name: "del permitted for operator in dev under /srv", subject: "operator", entry: "cli", effect: "fs.delete", context: ctx({ env: "dev", path: "/srv/x" }), verdict: "allow", reason: "matched-permit" },
  { name: "del denied for agent (no operator permit applies)", subject: "agent", entry: "cli", effect: "fs.delete", context: ctx({ env: "dev", path: "/srv/x" }), verdict: "deny", reason: "no-applicable-permit" },
];

const BOGUS = "0".repeat(64);
function reqFor(v: Vec, effId: (t: string) => string, epoch = 0n): DecisionRequest {
  return { atEpoch: epoch, subject: v.subject, entryPoint: v.entry, effectId: v.effect === "__bogus__" ? BOGUS : effId(v.effect), context: v.context };
}

// FROZEN reference decision digests (the reference-vector oracle). Any change to decision semantics, canonical form,
// or the proof shape changes these — so a neuter that flips a verdict diverges from the frozen bytes. Captured from a
// known-good run; regenerate deliberately (never blindly) if the decision schema legitimately changes.
const REF_DIGESTS: Record<string, string> = {
  "post allowed for agent in dev with good port+path": "d5ac5f2c244cc0c65f8b4ad672f2d4e5ee00cebe65fdced77cd0994db7474aac",
  "prod deny overrides an otherwise-valid permit": "0156056c2c6c469db7109ad76dcdfd354238f7fdddee06f1f1c0369e3fd44eed",
  "wrong port yields no applicable permit": "eba9e27a9a35bd2c6de55b2f1714f15316386e143c387be7fe4ed8633670c17a",
  "an unknown permit atom never grants (U never permits)": "dd3454a9c59f929caa4bb9da5eb73a03f9779b8942cd36421b4397481cd35d7e",
  "an unknown deny atom still fires the deny (U denies)": "8d14467ea4940cad4f16a4789283cb2f192a00ba72bc4671fbf1f4b041edf5d4",
  "an undeclared subject matches no specific permit": "72376447c609c2248e516c37317cb8bcf411973dd97daf3f0f94107071d62386",
  "a request for an unknown effect is denied": "a5dbd6e1c74b300f12b46f68589ee16125bac9b95e67d43ed423b86275fc15de",
  "del permitted for operator in dev under /srv": "a912ba66e977997ea308afe7456905bf69dd11e7775301219f3151495f328366",
  "del denied for agent (no operator permit applies)": "73d8b545c27960d9d44ab4c3bfbe6e2b4c87374387a9888a53dc83b5b1118a6c",
};

test("semantic oracle: each conformance vector yields the expected verdict + reason", () => {
  const { kernel, effId } = build();
  const k = kernel();
  for (const v of VECTORS) {
    const d = k.decide(reqFor(v, effId));
    assert.equal(d.verdict, v.verdict, `${v.name}: verdict`);
    assert.equal(d.reason, v.reason, `${v.name}: reason`);
    // the committed digest must re-derive from the returned decision's own fields (verifier recomputes, never trusts).
    assert.equal(decisionDigest(d), d.digest, `${v.name}: digest self-consistency`);
    // allow ⇔ matched-permit is the ONLY allow reason.
    assert.equal(d.verdict === "allow", d.reason === "matched-permit", `${v.name}: allow-iff-matched-permit`);
  }
});

test("decision digests match the frozen reference vectors", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const captured: Record<string, string> = {};
  for (const v of VECTORS) captured[v.name] = k.decide(reqFor(v, effId)).digest;
  if (process.env.CAPTURE_KERNEL_DIGESTS === "1") { console.log(JSON.stringify(captured, null, 2)); return; }
  for (const v of VECTORS) assert.equal(captured[v.name], REF_DIGESTS[v.name], `${v.name}: frozen decision digest`);
});

test("determinism: an independent kernel over an independently-compiled bundle yields identical decision digests", () => {
  const a = build(); const b = build();
  assert.equal(a.bundle.payloadDigest, b.bundle.payloadDigest, "same policy compiles to the same bundle digest");
  const ka = a.kernel(); const kb = b.kernel();
  for (const v of VECTORS) assert.equal(ka.decide(reqFor(v, a.effId)).digest, kb.decide(reqFor(v, b.effId)).digest, `${v.name}: cross-instance digest`);
});

test("a request for an unknown effect is denied (deny-by-default, no decision root)", () => {
  const { kernel, effId } = build();
  const d = kernel().decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: BOGUS, context: ctx({}) });
  assert.equal(d.verdict, "deny");
  assert.equal(d.reason, "unknown-effect");
  assert.equal(effId("http.post") === BOGUS, false);
});

test("a request at a stale epoch is denied (epoch fence)", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const post = effId("http.post");
  const good: DecisionRequest = { atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ env: "dev", "net.port": 443n, path: "/srv/app" }) };
  assert.equal(k.decide(good).verdict, "allow"); // baseline at current epoch
  const newEpoch = k.revoke({ subject: "nobody" }); // advances the epoch monotonically
  assert.equal(newEpoch, 1n);
  assert.equal(k.epoch, 1n);
  // the same request, still minted at epoch 0, is now stale ⇒ deny (a replayed pre-revocation request cannot pass).
  const stale = k.decide(good);
  assert.equal(stale.verdict, "deny");
  assert.equal(stale.reason, "stale-epoch");
  // re-minted at the current epoch it passes again (revocation of an unrelated subject didn't remove this authority).
  assert.equal(k.decide({ ...good, atEpoch: 1n }).verdict, "allow");
  // a future/forged epoch is also stale.
  assert.equal(k.decide({ ...good, atEpoch: 99n }).reason, "stale-epoch");
});

test("a revoked effect/subject is denied (monotonic revocation)", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const del = effId("fs.delete");
  const opDel: DecisionRequest = { atEpoch: 0n, subject: "operator", entryPoint: "cli", effectId: del, context: ctx({ env: "dev", path: "/srv/x" }) };
  assert.equal(k.decide(opDel).verdict, "allow");
  const e1 = k.revoke({ subject: "operator" });
  assert.equal(e1, 1n);
  const afterSubj = k.decide({ ...opDel, atEpoch: 1n });
  assert.equal(afterSubj.verdict, "deny");
  assert.equal(afterSubj.reason, "revoked-subject");
  // revoking is monotonic + idempotent: re-revoking the same target does not advance the epoch.
  assert.equal(k.revoke({ subject: "operator" }), 1n);
  // revoke the effect too — now even a different (would-be) principal is denied on that effect.
  const e2 = k.revoke({ effect: del });
  assert.equal(e2, 2n);
  const afterEff = k.decide({ ...opDel, atEpoch: 2n, subject: "operator" });
  assert.equal(afterEff.reason, "revoked-effect"); // effect check precedes subject
});

test("epoch advance seals at the encodable ceiling (2^64) instead of overflowing the committed epoch", () => {
  // The kernel's own epoch is committed in every decision, so it must stay < 2^64 (the CBOR argument ceiling); after
  // that many revocations the kernel seals (permanent fail-closed) rather than let #seal throw. 2^64 real revocations
  // are unreachable in a test, so the boundary is proven on the pure advance function that revoke() uses.
  assert.deepEqual(nextEpoch(0n), { epoch: 1n, sealed: false });
  assert.deepEqual(nextEpoch(MAX_INT_MAG - 2n), { epoch: MAX_INT_MAG - 1n, sealed: false }); // last safe advance
  assert.deepEqual(nextEpoch(MAX_INT_MAG - 1n), { epoch: MAX_INT_MAG - 1n, sealed: true });   // advancing would hit 2^64 ⇒ seal, epoch held
  // the sealed epoch (MAX_INT_MAG - 1) is still strictly encodable, so a decision at it can be sealed without throwing.
  assert.equal(MAX_INT_MAG - 1n < MAX_INT_MAG, true);
});

test("a zero-budget evaluation is denied (bounded evaluation)", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const post = effId("http.post");
  // budget 0 cannot afford to evaluate any applicable rule's guard ⇒ fail-closed deny.
  const d = k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ env: "dev", "net.port": 443n, path: "/srv/app" }), budget: 0 });
  assert.equal(d.verdict, "deny");
  assert.equal(d.reason, "eval-bound-exceeded");
  // a generous budget on the same request allows (the bound, not the policy, caused the deny above).
  assert.equal(k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ env: "dev", "net.port": 443n, path: "/srv/app" }), budget: 1_000 }).verdict, "allow");
});

test("malformed requests fail closed without throwing (total)", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const post = effId("http.post");
  // wrong types / empty fields / bad context values all become a malformed-request deny.
  const bad: DecisionRequest[] = [
    { atEpoch: 0 as unknown as bigint, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({}) },
    { atEpoch: 0n, subject: "", entryPoint: "cli", effectId: post, context: ctx({}) },
    { atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: [] as unknown as Map<string, ContextValue> },
    { atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: new Map([["k", { bad: 1 } as unknown as ContextValue]]) },
    { atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({}), budget: -1 },
  ];
  for (const r of bad) {
    const d = k.decide(r);
    assert.equal(d.verdict, "deny");
    assert.equal(d.reason, "malformed-request");
  }
  assert.equal(k.decide(null as unknown as DecisionRequest).reason, "malformed-request");
  // ill-formed (lone-surrogate) strings in a field are a CLEAN malformed-request deny — not an internal-error — so the
  // gate rejects them before they can collide under the canonical encoder (cross-family review, Fable SEV1).
  const ctxKey = new Map<string, ContextValue>(); ctxKey.set("a\uD800", 1n);
  const ctxVal = new Map<string, ContextValue>(); ctxVal.set("k", "v\uD800");
  const surrogates: DecisionRequest[] = [
    { atEpoch: 0n, subject: "agent\uD800", entryPoint: "cli", effectId: post, context: ctx({}) },
    { atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctxKey },
    { atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctxVal },
  ];
  for (const r of surrogates) assert.equal(k.decide(r).reason, "malformed-request");
});

test("proof trace names the deciding rules (audit commitment)", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const post = effId("http.post");
  // allow: names the granting permit.
  const allow = k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ env: "dev", "net.port": 443n, path: "/srv/app" }) });
  assert.equal(allow.proof.grantingPermit?.ruleId, "r-post-ok");
  assert.equal(allow.proof.firedDenies.length, 0);
  // deny: names the fired deny + the guard's three-valued outcome.
  const deny = k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ env: "prod", "net.port": 443n, path: "/srv/app" }) });
  assert.equal(deny.proof.grantingPermit, null);
  assert.equal(deny.proof.firedDenies.length, 1);
  assert.equal(deny.proof.firedDenies[0]!.ruleId, "r-post-deny-prod");
  assert.equal(deny.proof.firedDenies[0]!.guardValue, "T");
  // the U-fires-deny case records guardValue "U" in the proof.
  const denyU = k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ "net.port": 443n, path: "/srv/app" }) });
  assert.equal(denyU.proof.firedDenies[0]!.guardValue, "U");
});

test("construction fails closed on an unverifiable bundle (no policy ⇒ no permit)", () => {
  const { bundle } = build();
  const wrongTrust: TrustPolicy = { trustedKeys: new Map([[KEYID, "not-the-key"]]), threshold: 1 };
  assert.throws(() => new DecisionKernel(bundle, wrongTrust), KernelError);
  // a tampered payload also cannot construct a kernel.
  const tampered = { ...bundle, payloadDigest: "f".repeat(64) } as SignedBundle;
  assert.throws(() => new DecisionKernel(tampered, trust), KernelError);
});

// ── cross-family review hardening (GPT-5.6 + Fable, both NO-GO on the first cut) ──

test("a hostile context Map cannot split iteration from lookup (committed context == evaluated context)", () => {
  const { kernel, effId } = build();
  const post = effId("http.post");
  // EvilMap: iterator yields NOTHING, but .get() would return a FULLY permit-granting context (good port + path +
  // non-prod env, so no deny fires either). After the fix the kernel captures the context ONCE via iteration and
  // evaluates the owned (empty) copy — .get() is never consulted — so the guards are unknown and the request denies.
  // (Evaluating the caller's object instead would ALLOW: this is the fail-open the fix closes.)
  const grant: Record<string, ContextValue> = { "net.port": 443n, path: "/srv/app", env: "dev" };
  class EvilMap extends Map<string, ContextValue> {
    override get(k: string): ContextValue | undefined { return k in grant ? grant[k] : super.get(k); }
  }
  const evil = new EvilMap(); // iterator empty
  const d = kernel().decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: evil });
  assert.equal(d.verdict, "deny");
  // the committed context digest is the digest of the EMPTY (iterated) context — i.e. it binds what was evaluated.
  const emptyCtxDecision = kernel().decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({}) });
  assert.equal(d.contextDigest, emptyCtxDecision.contextDigest, "digest binds the iterated (owned) context, not .get()");
});

test("a reentrant context that revokes mid-evaluation cannot escape the epoch fence (fail-closed)", () => {
  const { kernel, effId } = build();
  const post = effId("http.post");
  const k = kernel();
  // A Map subclass that tries to revoke during traversal. Because the kernel touches the context exactly once (the
  // capture) BEFORE the epoch/revocation checks, any such mutation is observed by those checks ⇒ deny, never allow.
  class ReentrantMap extends Map<string, ContextValue> {
    fired = false;
    override [Symbol.iterator](): MapIterator<[string, ContextValue]> {
      if (!this.fired) { this.fired = true; k.revoke({ subject: "agent" }); }
      return super[Symbol.iterator]();
    }
  }
  const m = new ReentrantMap([["net.port", 443n], ["path", "/srv/app"], ["env", "dev"]]);
  const d = k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: m });
  assert.equal(d.verdict, "deny");
  // it revoked at epoch 0 → kernel is now epoch 1 → the epoch-0 request is stale (or the subject is revoked); either
  // way it is NOT an allow, and the decision never falsely reports a current-epoch grant.
  assert.notEqual(d.reason, "matched-permit");
  assert.equal(k.epoch, 1n);
});

test("a type-mismatched permit atom never grants; a type-mismatched deny still fires (fail-closed at the decision)", () => {
  // Custom policy: a permit gated on `net.port notin ["blocked"]` (allow-unless-blocklisted idiom, string list) and a
  // deny gated on `path == "/etc"`. Supplying an int where a string is expected must not launder either.
  const p: JsonValue = {
    version: 1n, combiningAlgorithm: ALGORITHM,
    principals: [{ name: "agent", labels: [] }],
    effects: [{ id: "post", effectType: "http.post", resourceSelector: "https://*" }],
    guards: [{ id: "notBlocked", predicate: "net.port notin [\"blocked\"]" }, { id: "isEtc", predicate: "path == \"/etc\"" }],
    rules: [
      { id: "r-permit", decision: "permit", subjects: ["agent"], entryPoints: ["cli"], effect: "post", guard: "notBlocked" },
      { id: "r-deny", decision: "deny", subjects: ["*"], entryPoints: ["*"], effect: "post", guard: "isEtc" },
    ],
  };
  const b = compilePolicy(p, [signer]);
  const post = b.payload.effects.find((e) => e.effectType === "http.post")!.id;
  const k = new DecisionKernel(b, trust);
  // int where a string was expected: `443n notin ["blocked"]` ⇒ U (not T) ⇒ permit does NOT grant.
  const d1 = k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ "net.port": 443n, path: "/srv" }) });
  assert.equal(d1.verdict, "deny", "type-mismatched notin must be U, not a grant");
  // well-typed string that is not blocked ⇒ permit grants.
  const d2 = k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ "net.port": "open", path: "/srv" }) });
  assert.equal(d2.verdict, "allow");
  // deny `path == "/etc"` with an int path ⇒ U ⇒ the deny still FIRES (fail-closed), overriding the grant.
  const d3 = k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ "net.port": "open", path: 5n }) });
  assert.equal(d3.verdict, "deny", "type-mismatched deny atom must be U and still fire");
  assert.equal(d3.reason, "matched-deny");
});

test("the returned Decision is deeply frozen (immutable audit record)", () => {
  const { kernel, effId } = build();
  const d = kernel().decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: effId("http.post"), context: ctx({ env: "prod", "net.port": 443n, path: "/srv/app" }) });
  assert.equal(Object.isFrozen(d), true);
  assert.equal(Object.isFrozen(d.proof), true);
  assert.equal(Object.isFrozen(d.proof.firedDenies), true);
  assert.equal(Object.isFrozen(d.proof.firedDenies[0]), true);
  assert.equal(Object.isFrozen(d.kernel), true);
  assert.throws(() => { (d as unknown as { verdict: string }).verdict = "allow"; }, TypeError);
});

test("the resolved budget is part of the decision commitment (injective over the request)", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const post = effId("http.post");
  const base = { atEpoch: 0n as bigint, subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ env: "dev", "net.port": 443n, path: "/srv/app" }) };
  const dA = k.decide({ ...base, budget: 500 });
  const dB = k.decide({ ...base, budget: 501 });
  assert.equal(dA.verdict, "allow");
  assert.equal(dB.verdict, "allow");
  assert.notEqual(dA.digest, dB.digest, "different budgets ⇒ different decision digests");
  // -0 is normalized to +0 so the committed budget is canonical (no -0/0 field-vs-digest disagreement).
  const dZero = k.decide({ ...base, budget: 0 });
  const dNegZero = k.decide({ ...base, budget: -0 });
  assert.equal(Object.is(dNegZero.budget, -0), false, "committed budget is +0, never -0");
  assert.equal(dZero.digest, dNegZero.digest, "0 and -0 budgets commit identically");
});

test("an out-of-range epoch/budget/context-int is a malformed request and NEVER throws (encoder-aligned bound)", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const post = effId("http.post");
  const base = { subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ env: "dev", "net.port": 443n, path: "/srv/app" }) };
  // The canonical CBOR encoder throws above 2^64-1; the kernel's bound is aligned to it, so 2^64 is the exact cliff.
  // Every over-range value must be a CLEAN deny with NO exception escaping decide() (totality is the increment's name).
  assert.doesNotThrow(() => {
    assert.equal(k.decide({ ...base, atEpoch: 1n << 64n }).reason, "malformed-request");   // == 2^64: over the cliff
    assert.equal(k.decide({ ...base, atEpoch: -1n }).reason, "malformed-request");          // negative epoch
    assert.equal(k.decide({ ...base, atEpoch: (1n << 64n) - 1n }).reason, "stale-epoch");   // 2^64-1: in range, processed
    assert.equal(k.decide({ ...base, atEpoch: 0n, budget: 2 ** 64 }).reason, "malformed-request"); // budget over range
    assert.equal(k.decide({ ...base, atEpoch: 0n, budget: Number.MAX_SAFE_INTEGER }).verdict, "allow"); // huge but in-range
    // a context integer in [2^64, 2^2048) must be malformed-request (a clean deny), NOT an internal-error collision.
    const bigInt = new Map<string, ContextValue>(); bigInt.set("net.port", 1n << 64n);
    assert.equal(k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: bigInt }).reason, "malformed-request");
  });
});

test("an over-cap context is a malformed request (bounds pre-evaluation work)", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const post = effId("http.post");
  const big = new Map<string, ContextValue>();
  for (let i = 0; i < 300; i++) big.set(`a${i}`, BigInt(i)); // > MAX_CONTEXT_ATTRS (256)
  assert.equal(k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: big }).reason, "malformed-request");
  // an oversized string value (> MAX_TEXT_LEN) is rejected BEFORE it is normalized/hashed.
  const hugeStr = new Map<string, ContextValue>([["x", "a".repeat((1 << 16) + 1)]]);
  assert.equal(k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: hugeStr }).reason, "malformed-request");
  // an oversized list (> MAX_CONTEXT_LIST_LEN) is rejected.
  const hugeList = new Map<string, ContextValue>([["x", Array.from({ length: 2000 }, (_, i) => BigInt(i))]]);
  assert.equal(k.decide({ atEpoch: 0n, subject: "agent", entryPoint: "cli", effectId: post, context: hugeList }).reason, "malformed-request");
});

test("the presented epoch is committed (two distinct stale requests do not collide)", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const post = effId("http.post");
  k.revoke({ subject: "nobody" }); k.revoke({ subject: "nobody2" }); // advance to epoch 2
  assert.equal(k.epoch, 2n);
  const base = { subject: "agent", entryPoint: "cli", effectId: post, context: ctx({ env: "dev", "net.port": 443n, path: "/srv/app" }) };
  const s8 = k.decide({ ...base, atEpoch: 0n });
  const s9 = k.decide({ ...base, atEpoch: 1n });
  assert.equal(s8.reason, "stale-epoch");
  assert.equal(s9.reason, "stale-epoch");
  assert.notEqual(s8.digest, s9.digest, "different presented epochs ⇒ different decision digests");
  assert.equal(s8.requestedEpoch, 0n);
  assert.equal(s8.epoch, 2n); // the fence epoch is the kernel's current epoch
});

test("a context array's hostile own iterator is never consulted (indexed reads keep decide() total)", () => {
  const { kernel, effId } = build();
  const k = kernel();
  const del = effId("fs.delete");
  // An array whose Symbol.iterator throws, but whose indexed elements are valid. The kernel must read it by index
  // (not via the poisoned iterator), so an UNREFERENCED extra context attribute cannot turn a valid request into an
  // internal-error. (Pre-fix `for..of` would throw ⇒ internal-error deny; the operator del would be lost.)
  const evilArr = [1n, 2n]; // bigint[] (a valid scalar list)
  Object.defineProperty(evilArr, Symbol.iterator, { value: function* () { throw new Error("boom"); } });
  const context = new Map<string, ContextValue>();
  context.set("path", "/srv/x"); context.set("env", "dev"); context.set("tags", evilArr);
  const d = k.decide({ atEpoch: 0n, subject: "operator", entryPoint: "cli", effectId: del, context });
  assert.equal(d.verdict, "allow", "the poisoned iterator was not consulted; the request evaluated normally");
  assert.equal(d.reason, "matched-permit");
});

// ── predicate theory (predicate.ts) — the typed, three-valued atom semantics deferred from Increment 2 ──
test("predicate theory: typed three-valued evaluation", () => {
  const c = ctx({ "net.port": 443n, path: "/srv/app", env: "dev", "principal.labels": ["prod", "eu"] as unknown as ContextValue });
  assert.equal(evalAtom("net.port == 443", c), "T");
  assert.equal(evalAtom("net.port == 80", c), "F");
  assert.equal(evalAtom("net.port in [80, 443]", c), "T");
  assert.equal(evalAtom("net.port notin [80, 443]", c), "F");
  assert.equal(evalAtom("net.port < 1024", c), "T");
  assert.equal(evalAtom("net.port >= 8443", c), "F");
  assert.equal(evalAtom("path startsWith \"/srv\"", c), "T");
  assert.equal(evalAtom("path endsWith \".tmp\"", c), "F");
  assert.equal(evalAtom("env == \"prod\"", c), "F");
  assert.equal(evalAtom("principal.labels has \"prod\"", c), "T");
  assert.equal(evalAtom("principal.labels has \"us\"", c), "F");
  // fail-closed unknowns:
  assert.equal(evalAtom("missing.attr == 1", c), "U", "absent attribute ⇒ U");
  assert.equal(evalAtom("path < 5", c), "U", "ordering on a string ⇒ U (no silent byte-compare)");
  assert.equal(evalAtom("net.port startsWith \"4\"", c), "U", "affix on an int ⇒ U");
  assert.equal(evalAtom("net.port has 4", c), "U", "has on a scalar ⇒ U");
  // TYPE-MISMATCH is a type error ⇒ U (Indeterminate), never a definite verdict — else not(U) could launder a grant
  // and a mistyped deny could be suppressed (both reviews, SEV0). ==, !=, in/notin, has must all be conservative.
  assert.equal(evalAtom("env == 5", c), "U", "cross-type == ⇒ U (not definite F)");
  assert.equal(evalAtom("env != 5", c), "U", "cross-type != ⇒ U");
  assert.equal(evalAtom("net.port in [\"443\"]", c), "U", "int attr vs string list ⇒ U (not a definite non-member)");
  assert.equal(evalAtom("net.port notin [\"443\"]", c), "U", "notin of a type-mismatch ⇒ U (never a grant)");
  assert.equal(evalAtom("net.port in [443, \"x\"]", c), "T", "a definite int match still wins over a mistyped element");
  assert.equal(evalAtom("principal.labels has 5", c), "U", "string list vs int ⇒ U");
  // uninterpretable predicates ⇒ constant U (never an exception, never a silent T):
  for (const junk of ["path.within-root", "", "port ==", "== 5", "a & b", "port = 5", "port in []", "net.port in [1,]"]) {
    assert.equal(parsePredicate(junk), null, `unparseable: ${JSON.stringify(junk)}`);
    assert.equal(evalAtom(junk, c), "U", `uninterpretable ⇒ U: ${JSON.stringify(junk)}`);
  }
  // parse/eval split is consistent.
  const p = parsePredicate("net.port in [443, 8443]");
  assert.notEqual(p, null);
  assert.equal(evalPredicate(p!, c), "T");
});
