import { test } from "node:test";
import assert from "node:assert/strict";

import { compilePolicy, type SignedBundle, type CompilerSigner } from "../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";
import type { JsonValue } from "../src/policy/json.js";
import { makeAddress } from "../src/ingress/address.js";
import { validateDecl, type IngressDecl } from "../src/ingress/ingress.js";
import type { WireSchema } from "../src/ingress/schema.js";
import { compileManifest, verifyManifest, coverageProblem, ManifestError, type ManifestSigner, type SignedManifest } from "../src/ingress/ingress_manifest.js";
import { IngressRegistry, RegistryError } from "../src/ingress/ingress_registry.js";

// Increment 3 (step B) — SEALED REGISTRY + signed MANIFEST + E_M=E_P coverage. Frontier property: no ingress
// dispatches unless it is in the sealed, signed, policy-addressable manifest; the set is immutable after seal.
// Proven by disproof — neutering an enforcement reddens its test:
//   coverage (stale/uncovered)       => "coverage: dangling/un-addressable REJECTED"
//   boot closure (set equality)      => "seal REJECTS a collected set != manifest"
//   temporal closure (monotonic)     => "register after seal is REJECTED"
//   fail-closed dispatch             => "dispatch of an unknown/pre-active/mistyped request is REJECTED"

const KEYID = "k1", SECRET = "s3cr3t";
const psigner: CompilerSigner = { signer: new StubSigner(SECRET, KEYID), keyid: KEYID, verifyKey: SECRET };
const ptrust: TrustPolicy = { trustedKeys: new Map([[KEYID, SECRET]]), threshold: 1 };
const MK = "mk1", MSECRET = "manifest-secret";
const msigner: ManifestSigner = { signer: new StubSigner(MSECRET, MK), keyid: MK, verifyKey: MSECRET };
const mtrust: TrustPolicy = { trustedKeys: new Map([[MK, MSECRET]]), threshold: 1 };
const SEAMS = { artifactGraphDigest: "a".repeat(64), scannerToolDigest: "b".repeat(64) };

const ADDR = makeAddress("http", "orders.create");
const intSchema: WireSchema = { t: "record", fields: [{ name: "amount", schema: { t: "int" }, optional: false }] };
const theDecl: IngressDecl = validateDecl({ address: ADDR, abiVersion: 1n, input: intSchema, output: { t: "null" }, error: { t: "str" }, cardinality: "single" });

function policyWith(entryPoints: string[]): SignedBundle {
  const p: JsonValue = {
    version: 1n, combiningAlgorithm: "deny-overrides",
    principals: [{ name: "agent", labels: [] }],
    effects: [{ id: "e", effectType: "fs.read", resourceSelector: "/x" }],
    guards: [],
    rules: [{ id: "r", decision: "permit", subjects: ["agent"], entryPoints, effect: "e" }],
  };
  return compilePolicy(p, [psigner]);
}

test("happy path: compile manifest, seal registry against it, activate, dispatch a typed request", async () => {
  const bundle = policyWith([ADDR]);
  const manifest = compileManifest([theDecl], bundle, SEAMS, [msigner]);
  assert.equal(verifyManifest(manifest, bundle, { manifestTrust: mtrust, policyTrust: ptrust }).valid, true);

  const reg = new IngressRegistry();
  reg.register(theDecl, (input) => { void input; return null; });
  reg.seal(manifest, bundle, { manifestTrust: mtrust, policyTrust: ptrust });
  assert.equal(reg.phase(), "sealed");
  reg.activate();
  assert.equal(await reg.dispatch(ADDR, { amount: 7n }), null);
});

test("coverage: a stale policy token (entryPoint with no ingress) is REJECTED", () => {
  const bundle = policyWith([makeAddress("http", "ghost")]); // policy addresses an ingress we won't declare
  assert.throws(() => compileManifest([theDecl], bundle, SEAMS, [msigner]), (e: unknown) => e instanceof ManifestError && /stale policy token/.test((e as Error).message));
});

test("coverage: a declared-but-un-addressable ingress is REJECTED (no rule addresses it, no wildcard)", () => {
  const bundle = policyWith([ADDR]);
  const extra = validateDecl({ ...theDecl, address: makeAddress("timer", "nightly") });
  assert.equal(coverageProblem([theDecl, extra], bundle) !== null, true);
  assert.throws(() => compileManifest([theDecl, extra], bundle, SEAMS, [msigner]), /un-addressable/);
});

test("coverage: a wildcard ('*') policy rule addresses all declared ingresses", () => {
  const bundle = policyWith(["*"]);
  const extra = validateDecl({ ...theDecl, address: makeAddress("timer", "nightly") });
  assert.equal(coverageProblem([theDecl, extra], bundle), null);
  assert.doesNotThrow(() => compileManifest([theDecl, extra], bundle, SEAMS, [msigner]));
});

test("boot closure: sealing a collected set that differs from the manifest is REJECTED", () => {
  const bundle = policyWith([ADDR]);
  const manifest = compileManifest([theDecl], bundle, SEAMS, [msigner]);
  // register a DIFFERENT ABI at the same address -> different declId -> boot-closure mismatch
  const reg = new IngressRegistry();
  const altDecl = validateDecl({ ...theDecl, input: { t: "null" } });
  reg.register(altDecl, () => null);
  assert.throws(() => reg.seal(manifest, bundle, { manifestTrust: mtrust }), (e: unknown) => e instanceof RegistryError && /boot closure/.test((e as Error).message));
});

test("temporal closure: registering after seal is REJECTED (monotonic, no unseal)", () => {
  const bundle = policyWith([ADDR]);
  const manifest = compileManifest([theDecl], bundle, SEAMS, [msigner]);
  const reg = new IngressRegistry();
  reg.register(theDecl, () => null);
  reg.seal(manifest, bundle, { manifestTrust: mtrust });
  assert.throws(() => reg.register(theDecl, () => null), /sealed/);
});

test("fail-closed dispatch: unknown address, pre-active, and mistyped input all REJECTED", async () => {
  const bundle = policyWith([ADDR]);
  const manifest = compileManifest([theDecl], bundle, SEAMS, [msigner]);
  const reg = new IngressRegistry();
  reg.register(theDecl, () => null);
  reg.seal(manifest, bundle, { manifestTrust: mtrust });
  // pre-active dispatch
  await assert.rejects(reg.dispatch(ADDR, { amount: 1n }), /not active/);
  reg.activate();
  // unknown address
  await assert.rejects(reg.dispatch(makeAddress("http", "nope"), { amount: 1n }), /deny-by-default/);
  // mistyped input (amount must be a bigint int)
  await assert.rejects(reg.dispatch(ADDR, { amount: 1 }), /expected int/);
  // handler violating its output contract fails closed
  const reg2 = new IngressRegistry();
  reg2.register(theDecl, () => "not-null" as unknown);
  reg2.seal(manifest, bundle, { manifestTrust: mtrust });
  reg2.activate();
  await assert.rejects(reg2.dispatch(ADDR, { amount: 1n }), /expected null/);
});

test("TOCTOU: verifyManifest reads the caller payload once and returns an owned frozen snapshot", () => {
  const bundle = policyWith([ADDR]);
  const good = compileManifest([theDecl], bundle, SEAMS, [msigner]);
  let reads = 0;
  const spy = { payloadDigest: good.payloadDigest, signatures: good.signatures, get payload() { reads++; return good.payload; } } as unknown as SignedManifest;
  const v = verifyManifest(spy, bundle, { manifestTrust: mtrust });
  assert.equal(v.valid, true);
  assert.equal(reads, 1, "payload getter must be read exactly once (capture-once, TOCTOU-safe)");
  assert.ok(Object.isFrozen((v as { manifest: SignedManifest }).manifest.payload), "returned snapshot is frozen + owned");
});

test("runtime encapsulation: the sealed dispatch table is not reachable or mutable via reflection", async () => {
  const bundle = policyWith([ADDR]);
  const manifest = compileManifest([theDecl], bundle, SEAMS, [msigner]);
  const reg = new IngressRegistry();
  reg.register(theDecl, () => null);
  reg.seal(manifest, bundle, { manifestTrust: mtrust });
  reg.activate();
  // ES #private state is unreachable; there is no `table`/`collecting`/`phaseState` own property to tamper with.
  assert.equal((reg as unknown as { table?: unknown }).table, undefined);
  assert.equal((reg as unknown as { collecting?: unknown }).collecting, undefined);
  assert.deepEqual(Object.keys(reg), []);
  // injecting an address onto the instance does NOT create a dispatchable ingress
  (reg as unknown as Record<string, unknown>)[makeAddress("http", "evil")] = { decl: theDecl, handler: () => "pwned" };
  await assert.rejects(reg.dispatch(makeAddress("http", "evil"), { amount: 1n }), /deny-by-default/);
});

test("manifest verify: tampering the declaration set or bound policy digest fails closed", () => {
  const bundle = policyWith([ADDR]);
  const manifest = compileManifest([theDecl], bundle, SEAMS, [msigner]);
  const tampered: SignedManifest = { ...manifest, payload: { ...manifest.payload, policyBundleDigest: "0".repeat(64) } };
  assert.equal(verifyManifest(tampered, bundle, { manifestTrust: mtrust }).valid, false);
  const wrongBundle = policyWith(["*"]);
  assert.equal(verifyManifest(manifest, wrongBundle, { manifestTrust: mtrust }).valid, false); // binds a different bundle
  assert.equal(verifyManifest(null as unknown as SignedManifest, bundle, { manifestTrust: mtrust }).valid, false);
  // Fable-caught: a policy bundle whose CLAIMED payloadDigest doesn't match its payload must fail, even without policyTrust
  const forgedDigest: SignedBundle = { ...bundle, payloadDigest: "0".repeat(64) };
  assert.equal(verifyManifest(manifest, forgedDigest, { manifestTrust: mtrust }).valid, false);
});
