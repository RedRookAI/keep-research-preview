import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { compilePolicy, type SignedBundle, type CompilerSigner } from "../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";
import type { JsonValue } from "../src/policy/json.js";
import { validateEffectDecl, type EffectFamily } from "../src/effect/effect.js";
import { compileEffectManifest, type EffectManifestSigner, type SignedEffectManifest } from "../src/effect/effect_manifest.js";
import { scanEffects } from "../src/effect/effect_scan_port.js";
import { compileWaiver, defaultEnginePath, scannerRuntimeDigest, verifyAuthorityClosure, type WaiverEntry, type WaiverSigner, type SignedWaiver } from "../src/effect/authority_gate.js";

// Mechanical-Enforcement Increment 10a — ARTIFACT-BOUND CLOSED-WORLD AUTHORITY GATE. Frontier property: the gate RE-scans
// the DEPLOYED tree with the SIGNED manifest owner map, binds the scan's graph digest to the manifest's signed
// artifactGraphDigest, and admits an unowned effect only as a KNOWN legacy one within a generation-chained, only-shrinking
// signed waiver. Proven by disproof — neutering a check in src/effect/authority_gate.ts reddens a named test:
//   artifact binding (deployed==signed)   => "a swapped/tampered deployed tree is rejected (scan-then-swap)"
//   signed owner map (no poisoning)       => "an unowned effect not in the SIGNED owner map fails closed"
//   waiver coverage + per-site count      => "a NEW / EXTRA unowned effect fails closed"
//   monotone shrink (chain)               => "a GROWN waiver / bad chain is rejected"

const PK = "pk1", PS = "policy-secret";
const psigner: CompilerSigner = { signer: new StubSigner(PS, PK), keyid: PK, verifyKey: PS };
const ptrust: TrustPolicy = { trustedKeys: new Map([[PK, PS]]), threshold: 1 };
const EK = "ek1", ES = "effect-secret";
const esigner: EffectManifestSigner = { signer: new StubSigner(ES, EK), keyid: EK, verifyKey: ES };
const etrust: TrustPolicy = { trustedKeys: new Map([[EK, ES]]), threshold: 1 };
const WK = "wk1", WS = "waiver-secret";
const wsigners: WaiverSigner[] = [{ signer: new StubSigner(WS, WK), keyid: WK, verifyKey: WS }];
const wtrust: TrustPolicy = { trustedKeys: new Map([[WK, WS]]), threshold: 1 };
const trust = { manifestTrust: etrust, policyTrust: ptrust };
// The gate verifies the running engine's bytes against the manifest's scannerToolDigest — bind the REAL engine digest.
const SCANNER = scannerRuntimeDigest();

function policyBundle(): SignedBundle {
  const p: JsonValue = {
    version: 1n, combiningAlgorithm: "deny-overrides",
    principals: [{ name: "agent", labels: [] }],
    effects: [{ id: "e", effectType: "fs.read", resourceSelector: "/x" }],
    guards: [], rules: [{ id: "r", decision: "permit", subjects: ["agent"], entryPoints: ["*"], effect: "e" }],
  };
  return compilePolicy(p, [psigner]);
}
const bundle = policyBundle();

let tmp: string;
function fixtureTree(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "keep-authority-"));
  for (const [rel, content] of Object.entries(files)) { const full = join(dir, rel); mkdirSync(join(full, ".."), { recursive: true }); writeFileSync(full, content); }
  return dir;
}
/** Compile a manifest binding the REAL graph digest of `root` under owner map `owners`. The policy references fs.read, so
 * the fs family is always declared (owner "fs_owner.ts") to satisfy manifest coverage — harmless for fs-free trees. */
function manifestFor(root: string, owners: Map<EffectFamily, string>): { manifest: SignedEffectManifest; graphDigest: string } {
  const fullOwners = new Map<EffectFamily, string>([["fs", "fs_owner.ts"], ...owners]);
  const scan = scanEffects({ root, owners: fullOwners });
  const decls = [...fullOwners].map(([family, owner]) => validateEffectDecl({ family, owner }));
  const manifest = compileEffectManifest(decls, bundle, { artifactGraphDigest: scan.graphDigest, scannerToolDigest: SCANNER }, [esigner]);
  return { manifest, graphDigest: scan.graphDigest };
}
const entry = (file: string, family: string, construct: string, count = 1): WaiverEntry => ({ file, family, construct, count, reason: "legacy debt" });
function genesisWaiver(entries: WaiverEntry[]): SignedWaiver { return compileWaiver({ generation: 0, predecessorDigest: "" }, entries, wsigners); }

const CLEAN = "export const x = 1;\n";
const FS_OWNER = "import { readFileSync } from 'node:fs';\nexport const r = () => readFileSync('/x');\n";
const LEAKY = "export async function go(){ return fetch('http://evil'); }\n";

test.afterEach(() => { if (tmp) { try { rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } } });

test("happy path: deployed tree matches the signed manifest, the one unowned effect is waived within the chain", () => {
  tmp = fixtureTree({ "clean.ts": CLEAN, "fs_owner.ts": FS_OWNER, "leaky.ts": LEAKY });
  const { manifest } = manifestFor(tmp, new Map([["fs" as EffectFamily, "fs_owner.ts"]]));
  const w = genesisWaiver([entry("leaky.ts", "net", "fetch")]);
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: w, baseline: w, boundWaiverDigest: w.payloadDigest, previousReleaseHead: "", waiverTrust: wtrust });
  assert.equal(v.valid, true, (v as { reason?: string }).reason);
});

test("scanner subprocess inherits no dynamic-loader or Node injection environment", () => {
  tmp = fixtureTree({ "clean.ts": CLEAN });
  const engine = join(tmp, "env_probe.mjs");
  writeFileSync(engine, `const poisoned = Object.keys(process.env).some(k => /^(LD_|DYLD_|NODE_|PATH$)/i.test(k));\nconsole.log(JSON.stringify({ok:!poisoned,sentinel:!poisoned?'EFFECT-SWEEP-OK':'POISONED',scanned:0,owners:[],findings:[],graphDigest:'${"a".repeat(64)}'}));\n`);
  const previous = process.env.LD_PRELOAD; process.env.LD_PRELOAD = "/definitely/not/a/real/preload.so";
  try { assert.equal(scanEffects({ root: tmp, enginePath: engine }).graphDigest, "a".repeat(64)); }
  finally { if (previous === undefined) delete process.env.LD_PRELOAD; else process.env.LD_PRELOAD = previous; }
});

test("scanner runtime identity follows a symlink to and hashes the canonical target", () => {
  tmp = fixtureTree({ "placeholder": "x" }); const link = join(tmp, "scanner-link.mjs"); symlinkSync(defaultEnginePath(), link);
  assert.equal(scannerRuntimeDigest(link), scannerRuntimeDigest(defaultEnginePath()));
});

test("a swapped/tampered deployed tree is rejected (scan-then-swap / artifact binding — the keystone)", () => {
  tmp = fixtureTree({ "clean.ts": CLEAN, "fs_owner.ts": FS_OWNER, "leaky.ts": LEAKY });
  const { manifest } = manifestFor(tmp, new Map([["fs" as EffectFamily, "fs_owner.ts"]]));
  const w = genesisWaiver([entry("leaky.ts", "net", "fetch")]);
  // deploy-time swap: change a file AFTER the manifest was signed -> the gate's fresh scan digest no longer matches.
  writeFileSync(join(tmp, "clean.ts"), CLEAN + "// tampered\n");
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: w, baseline: w, boundWaiverDigest: w.payloadDigest, previousReleaseHead: "", waiverTrust: wtrust });
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /artifact mismatch|scan-then-swap/);
});

test("an unowned effect not in the SIGNED owner map fails closed (no owner-map poisoning)", () => {
  // The gate derives owners from the SIGNED manifest; there is NO owner-map parameter to poison. leaky.ts's fetch is
  // unowned under the signed manifest (fs owner only) and NOT waived -> reject. (A caller cannot declare leaky.ts an owner
  // without the effect-manifest signing key.)
  tmp = fixtureTree({ "fs_owner.ts": FS_OWNER, "leaky.ts": LEAKY });
  const { manifest } = manifestFor(tmp, new Map([["fs" as EffectFamily, "fs_owner.ts"]]));
  const emptyWaiver = genesisWaiver([]);
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: emptyWaiver, baseline: emptyWaiver, boundWaiverDigest: emptyWaiver.payloadDigest, previousReleaseHead: "", waiverTrust: wtrust });
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /unowned effect/);
});

test("a NEW / EXTRA unowned effect fails closed (per-site count coverage)", () => {
  // two fetches in one file: the site count is 2, but the waiver permits 1 -> the extra occurrence is a new site -> reject.
  tmp = fixtureTree({ "leaky.ts": "export const a = () => fetch('a');\nexport const b = () => fetch('b');\n" });
  const { manifest } = manifestFor(tmp, new Map());
  const w = genesisWaiver([entry("leaky.ts", "net", "fetch", 1)]);
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: w, baseline: w, boundWaiverDigest: w.payloadDigest, previousReleaseHead: "", waiverTrust: wtrust });
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /unowned effect/);
  // ...but waiving count 2 verifies (the debt is honestly enumerated).
  const w2 = genesisWaiver([entry("leaky.ts", "net", "fetch", 2)]);
  const v2 = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: w2, baseline: w2, boundWaiverDigest: w2.payloadDigest, previousReleaseHead: "", waiverTrust: wtrust });
  assert.equal(v2.valid, true, (v2 as { reason?: string }).reason);
});

test("a GROWN waiver is rejected; a SHRUNK waiver in a valid chain is accepted (monotone chain)", () => {
  tmp = fixtureTree({ "leaky.ts": LEAKY });
  const { manifest } = manifestFor(tmp, new Map());
  const baseline = genesisWaiver([entry("leaky.ts", "net", "fetch", 1), entry("old.ts", "clock", "Date.now", 3)]);
  // GROW: a successor that adds a NEW site not in the baseline -> reject.
  const grown = compileWaiver({ generation: 1, predecessorDigest: baseline.payloadDigest }, [entry("leaky.ts", "net", "fetch", 1), entry("new.ts", "net", "fetch", 1)], wsigners);
  const vg = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: grown, baseline, boundWaiverDigest: grown.payloadDigest, previousReleaseHead: baseline.payloadDigest, waiverTrust: wtrust });
  assert.equal(vg.valid, false);
  assert.match((vg as { reason: string }).reason, /waiver grew/);
  // SHRINK: a successor that drops old.ts (paid down) -> valid chain (generation+1, correct predecessor).
  const shrunk = compileWaiver({ generation: 1, predecessorDigest: baseline.payloadDigest }, [entry("leaky.ts", "net", "fetch", 1)], wsigners);
  const vs = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: shrunk, baseline, boundWaiverDigest: shrunk.payloadDigest, previousReleaseHead: baseline.payloadDigest, waiverTrust: wtrust });
  assert.equal(vs.valid, true, (vs as { reason?: string }).reason);
});

test("a substituted baseline (not the named predecessor) is rejected (chain anchoring)", () => {
  tmp = fixtureTree({ "leaky.ts": LEAKY });
  const { manifest } = manifestFor(tmp, new Map());
  const realBaseline = genesisWaiver([entry("leaky.ts", "net", "fetch", 1)]);
  const current = compileWaiver({ generation: 1, predecessorDigest: realBaseline.payloadDigest }, [entry("leaky.ts", "net", "fetch", 1)], wsigners);
  // attacker supplies a DIFFERENT (larger, correctly-signed) baseline than the one `current` names.
  const fakeBaseline = genesisWaiver([entry("leaky.ts", "net", "fetch", 1), entry("evil.ts", "net", "fetch", 9)]);
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: current, baseline: fakeBaseline, boundWaiverDigest: current.payloadDigest, previousReleaseHead: realBaseline.payloadDigest, waiverTrust: wtrust });
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /TRUSTED previous release head/);
});

test("a current waiver not pinned by boundWaiverDigest is rejected", () => {
  tmp = fixtureTree({ "leaky.ts": LEAKY });
  const { manifest } = manifestFor(tmp, new Map());
  const w = genesisWaiver([entry("leaky.ts", "net", "fetch", 1)]);
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: w, baseline: w, boundWaiverDigest: "0".repeat(64), previousReleaseHead: "", waiverTrust: wtrust });
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /pinned by boundWaiverDigest/);
});

test("an unverifiable manifest (wrong trust) is rejected before any scan", () => {
  tmp = fixtureTree({ "leaky.ts": LEAKY });
  const { manifest } = manifestFor(tmp, new Map());
  const w = genesisWaiver([entry("leaky.ts", "net", "fetch", 1)]);
  const badTrust = { manifestTrust: { trustedKeys: new Map([["ek1", "WRONG"]]), threshold: 1 } as TrustPolicy };
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust: badTrust, waiver: w, baseline: w, boundWaiverDigest: w.payloadDigest, previousReleaseHead: "", waiverTrust: wtrust });
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /manifest does not verify/);
});

test("a forged/untrusted waiver or baseline is rejected", () => {
  tmp = fixtureTree({ "leaky.ts": LEAKY });
  const { manifest } = manifestFor(tmp, new Map());
  const evil: WaiverSigner[] = [{ signer: new StubSigner("evil", "evil"), keyid: "evil", verifyKey: "evil" }];
  const forged = compileWaiver({ generation: 0, predecessorDigest: "" }, [entry("leaky.ts", "net", "fetch", 1)], evil);
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: forged, baseline: forged, boundWaiverDigest: forged.payloadDigest, previousReleaseHead: "", waiverTrust: wtrust });
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /waiver does not verify/);
});

test("a fresh genesis cannot re-open debt once a release head exists (cross-release ratchet — previousReleaseHead)", () => {
  tmp = fixtureTree({ "leaky.ts": LEAKY });
  const { manifest } = manifestFor(tmp, new Map());
  const priorHead = genesisWaiver([entry("leaky.ts", "net", "fetch", 1)]); // release N (small, trusted head)
  // attacker crafts a NEW generation-0 genesis re-adding debt, self-baselined -> internally consistent, but the
  // deployment's release state already names priorHead as the previous head, so a genesis (predecessor "") is rejected.
  const freshGenesis = genesisWaiver([entry("leaky.ts", "net", "fetch", 1), entry("evil.ts", "net", "fetch", 9)]);
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: freshGenesis, baseline: freshGenesis, boundWaiverDigest: freshGenesis.payloadDigest, previousReleaseHead: priorHead.payloadDigest, waiverTrust: wtrust });
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /previous release head/);
});

test("a manifest pinning the WRONG scanner engine digest is rejected (engine pin — scannerToolDigest)", () => {
  tmp = fixtureTree({ "fs_owner.ts": FS_OWNER, "leaky.ts": LEAKY });
  const scan = scanEffects({ root: tmp, owners: new Map([["fs" as EffectFamily, "fs_owner.ts"]]) });
  const decls = [validateEffectDecl({ family: "fs", owner: "fs_owner.ts" })];
  // bind a BOGUS scannerToolDigest (not the real engine's bytes) -> the gate's engine-pin check must reject.
  const manifest = compileEffectManifest(decls, bundle, { artifactGraphDigest: scan.graphDigest, scannerToolDigest: "c".repeat(64) }, [esigner]);
  const w = genesisWaiver([entry("leaky.ts", "net", "fetch", 1)]);
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: w, baseline: w, boundWaiverDigest: w.payloadDigest, previousReleaseHead: "", waiverTrust: wtrust });
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /scanner engine mismatch/);
});

test("a waiver entry with no matching occurrence is rejected (no dormant allowance / exact coverage)", () => {
  tmp = fixtureTree({ "fs_owner.ts": FS_OWNER, "leaky.ts": LEAKY }); // only leaky net fetch ×1
  const { manifest } = manifestFor(tmp, new Map([["fs" as EffectFamily, "fs_owner.ts"]]));
  // the waiver claims a site (old.ts Date.now) that does NOT occur -> a dormant allowance that could later regrow -> reject.
  const w = genesisWaiver([entry("leaky.ts", "net", "fetch", 1), entry("old.ts", "clock", "Date.now", 1)]);
  const v = verifyAuthorityClosure({ root: tmp, manifest, policyBundle: bundle, trust, waiver: w, baseline: w, boundWaiverDigest: w.payloadDigest, previousReleaseHead: "", waiverTrust: wtrust });
  assert.equal(v.valid, false);
  assert.match((v as { reason: string }).reason, /stale waiver entry/);
});

test("totality: malformed root/manifest/waiver/digest fail closed, never throw", () => {
  tmp = fixtureTree({ "leaky.ts": LEAKY });
  const { manifest } = manifestFor(tmp, new Map());
  const w = genesisWaiver([entry("leaky.ts", "net", "fetch", 1)]);
  const base = { root: tmp, manifest, policyBundle: bundle, trust, waiver: w, baseline: w, boundWaiverDigest: w.payloadDigest, previousReleaseHead: "", waiverTrust: wtrust };
  assert.equal(verifyAuthorityClosure({ ...base, root: "" }).valid, false);
  assert.equal(verifyAuthorityClosure({ ...base, boundWaiverDigest: "nothex" }).valid, false);
  assert.equal(verifyAuthorityClosure({ ...base, waiver: null }).valid, false);
  assert.equal(verifyAuthorityClosure({ ...base, baseline: 42 as unknown }).valid, false);
  assert.equal(verifyAuthorityClosure({ ...base, manifest: {} as unknown as SignedEffectManifest }).valid, false);
});
