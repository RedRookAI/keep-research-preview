import { test } from "node:test";
import assert from "node:assert/strict";

import { validateEffectDecl, effectDeclId, EFFECT_FAMILIES, EffectError, type EffectDecl } from "../src/effect/effect.js";
import {
  compileEffectManifest, verifyEffectManifest, familyForEffectType, ownersOf,
  EffectManifestError, type EffectManifestSigner, type SignedEffectManifest,
} from "../src/effect/effect_manifest.js";
import { compilePolicy, type SignedBundle, type CompilerSigner } from "../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";
import type { JsonValue } from "../src/policy/json.js";

// Increment 4 — CLOSED-WORLD EFFECT INVENTORY. Frontier: every policy effect classifies into a DECLARED, OWNED family;
// exactly one broker owner per family; bound to the exact Incr-2 policy bundle; verify total + capture-once.

const KEYID = "k1", SECRET = "s";
const psigner: CompilerSigner = { signer: new StubSigner(SECRET, KEYID), keyid: KEYID, verifyKey: SECRET };
const MK = "mk", MSECRET = "ms";
const msigner: EffectManifestSigner = { signer: new StubSigner(MSECRET, MK), keyid: MK, verifyKey: MSECRET };
const mtrust: TrustPolicy = { trustedKeys: new Map([[MK, MSECRET]]), threshold: 1 };
const SEAMS = { artifactGraphDigest: "a".repeat(64), scannerToolDigest: "b".repeat(64) };
const OWNER = (fam: string): EffectDecl => validateEffectDecl({ family: fam, owner: `src/broker/${fam}_broker.ts` });

// a policy touching fs.read (recoverable), email.send (external), fs.delete (destructive) -> families fs + net
function policy(): SignedBundle {
  const p: JsonValue = {
    version: 1n, combiningAlgorithm: "deny-overrides",
    principals: [{ name: "agent", labels: [] }],
    effects: [
      { id: "read", effectType: "fs.read", resourceSelector: "/x" },
      { id: "mail", effectType: "email.send", resourceSelector: "*" },
      { id: "del", effectType: "fs.delete", resourceSelector: "/y" },
    ],
    guards: [],
    rules: [
      { id: "r1", decision: "permit", subjects: ["agent"], entryPoints: ["*"], effect: "read" },
      { id: "r2", decision: "deny", subjects: ["agent"], entryPoints: ["*"], effect: "mail" },
      { id: "r3", decision: "deny", subjects: ["agent"], entryPoints: ["*"], effect: "del" },
    ],
  };
  return compilePolicy(p, [psigner]);
}

test("effect family classification maps effectTypes by first segment; unclassifiable -> null", () => {
  assert.equal(familyForEffectType("fs.read"), "fs");
  assert.equal(familyForEffectType("email.send"), "net");
  assert.equal(familyForEffectType("fs.delete"), "fs");
  assert.equal(familyForEffectType("db.drop"), "persistence");
  assert.equal(familyForEffectType("mystery.thing"), null);
  assert.equal(EFFECT_FAMILIES.length, 14);
});

test("declaration validates; unknown field/family/owner path rejected; content id derived", () => {
  const d = OWNER("fs");
  assert.match(effectDeclId(d), /^[0-9a-f]{64}$/);
  assert.throws(() => validateEffectDecl({ family: "fs", owner: "src/x.ts", extra: 1 }), /unknown field/);
  assert.throws(() => validateEffectDecl({ family: "nope", owner: "src/x.ts" }), /unknown effect family/);
  assert.throws(() => validateEffectDecl({ family: "fs", owner: "/abs/x.ts" }), /repo-relative/);
  assert.throws(() => validateEffectDecl({ family: "fs", owner: "../x.ts" }), /repo-relative/);
});

test("manifest: compiles + verifies when every policy effect's family is declared/owned", () => {
  const bundle = policy();
  const m = compileEffectManifest([OWNER("fs"), OWNER("net")], bundle, SEAMS, [msigner]);
  assert.equal(verifyEffectManifest(m, bundle, { manifestTrust: mtrust }).valid, true);
  assert.deepEqual([...ownersOf(m).keys()].sort(), ["fs", "net"]);
});

test("coverage: an un-owned policy-effect family is REJECTED", () => {
  const bundle = policy(); // needs fs + net
  assert.throws(() => compileEffectManifest([OWNER("fs")], bundle, SEAMS, [msigner]), (e: unknown) => e instanceof EffectManifestError && /net.*not declared\/owned/.test((e as Error).message));
});

test("one broker ownership: declaring a family twice is REJECTED", () => {
  const bundle = policy();
  assert.throws(() => compileEffectManifest([OWNER("fs"), OWNER("net"), validateEffectDecl({ family: "fs", owner: "src/broker/other.ts" })], bundle, SEAMS, [msigner]), /declared more than once/);
});

test("manifest verify: tamper the bound policy digest / forged bundle digest fails closed", () => {
  const bundle = policy();
  const m = compileEffectManifest([OWNER("fs"), OWNER("net")], bundle, SEAMS, [msigner]);
  const tampered: SignedEffectManifest = { ...m, payload: { ...m.payload, policyBundleDigest: "0".repeat(64) } };
  assert.equal(verifyEffectManifest(tampered, bundle, { manifestTrust: mtrust }).valid, false);
  const forged: SignedBundle = { ...bundle, payloadDigest: "0".repeat(64) };
  assert.equal(verifyEffectManifest(m, forged, { manifestTrust: mtrust }).valid, false);
  assert.equal(verifyEffectManifest(null as unknown as SignedEffectManifest, bundle, { manifestTrust: mtrust }).valid, false);
});
