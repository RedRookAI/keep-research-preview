/**
 * Signed EFFECT MANIFEST + effect-to-policy coverage (Mechanical-Enforcement Increment 4).
 *
 * The sealed, signed, content-addressed inventory of every effect FAMILY and its single broker OWNER. It binds the exact declaration set, the exact Increment-2 policy bundle, and (as honest seams enforced by
 * later increments) the scanned artifact-graph digest + scanner-tool identity. `verifyEffectManifest` re-derives
 * everything and fails closed on any mismatch. Structure mirrors the GO'd ingress manifest (Increment 3).
 *
 * EFFECT-TO-POLICY COVERAGE. Every effect the policy references (each `effectType`) is classified into a family; the
 * manifest must DECLARE + OWN that family. So a policy effect with no owned family is fatal — the outbound surface is
 * closed. The consequence KIND is a per-effect property of the policy (Increment 2), not the family. Each family is
 * declared AT MOST ONCE (exactly one broker ownership). Runtime execution mediation is Increment 9.
 *
 * Grounding: capability-safe module discipline; deny-by-default syscall ownership; SLSA-style signed manifest binding;
 * content-addressed identity (Increment 1); domain separation.
 */
import { eirDigest, type CanonicalValue } from "../eir/canonical.js";
import { stubSign, type Signature, type Signer, type TrustPolicy } from "../bom/bom_signing.js";
import { validateEffectDecl, effectDeclToCanonical, effectDeclId, isEffectFamily, type EffectDecl, type EffectFamily } from "./effect.js";
import { verifyBundle, captureBundle, bundlePayloadDigest, type SignedBundle } from "../policy/compiler.js";

export const EFFECT_MANIFEST = { name: "keep.effect.manifest", version: "4.0.0" } as const;
const HEX64 = /^[0-9a-f]{64}$/;

export class EffectManifestError extends Error { constructor(m: string) { super(`effect manifest: ${m}`); this.name = "EffectManifestError"; } }
function safeMsg(e: unknown): string { try { return String((e as { message?: unknown })?.message ?? e); } catch { return "unknown"; } }

/** Classify a policy effectType into an effect family by its first dotted segment (closed, enumerated map). */
const FAMILY_OF_PREFIX: Readonly<Record<string, EffectFamily>> = {
  fs: "fs", file: "fs",
  net: "net", http: "net", https: "net", email: "net", webhook: "net", payment: "net", deploy: "net", release: "net",
  dns: "dns", tls: "tls", dgram: "dgram", udp: "dgram",
  subprocess: "subprocess", exec: "subprocess", spawn: "subprocess", proc: "subprocess",
  worker: "worker", thread: "worker",
  require: "module-load", import: "module-load", module: "module-load", addon: "module-load",
  env: "env", secret: "env", secrets: "env",
  clock: "clock", time: "clock", date: "clock",
  random: "random", rand: "random", entropy: "random",
  host: "hostinfo", os: "hostinfo", metadata: "hostinfo",
  db: "persistence", prod: "persistence", preference: "persistence", note: "persistence", plan: "persistence", memory: "persistence", store: "persistence",
  audit: "audit-out", log: "audit-out",
};
/** The effect family of a policy effectType, or null if it cannot be classified (fail-closed at the caller). */
export function familyForEffectType(effectType: string): EffectFamily | null {
  const seg = effectType.split(".")[0]?.trim().toLowerCase() ?? "";
  return FAMILY_OF_PREFIX[seg] ?? null;
}

export interface EffectManifestPayload {
  readonly manifestVersion: 1;
  readonly builder: { readonly name: string; readonly version: string };
  readonly declarations: readonly EffectDecl[];   // one per family (family->owner), sorted by family
  readonly declarationSetDigest: string;
  readonly policyBundleDigest: string;
  readonly artifactGraphDigest: string;           // SEAM (Incr 5)
  readonly scannerToolDigest: string;             // SEAM
}
export interface SignedEffectManifest {
  readonly payload: EffectManifestPayload;
  readonly payloadDigest: string;
  readonly signatures: readonly Signature[];
}
export interface EffectManifestSigner { readonly signer: Signer; readonly keyid: string; readonly verifyKey: string; }
export type EffectManifestVerdict = { readonly valid: true; readonly signerCount: number; readonly manifest: SignedEffectManifest } | { readonly valid: false; readonly reason: string };

const payloadDigestOf = (p: EffectManifestPayload): string => eirDigest("keep.effect-manifest.v1", payloadCanonical(p));
const signPreimageOf = (payloadDigest: string): string => eirDigest("keep.effect-manifest.signature-preimage/v1", { payloadDigest });
const declSetDigestOf = (decls: readonly EffectDecl[]): string => eirDigest("keep.effect.declset.v1", decls.map(effectDeclId).sort());

/** The distinct effectTypes the policy references (the effect surface the manifest must own). */
function policyEffectTypes(bundle: SignedBundle): Set<string> {
  const s = new Set<string>();
  for (const e of bundle.payload.effects) s.add(e.effectType);
  return s;
}

/** The coverage problem, or null: every policy effect classifies into a DECLARED (owned) family. Kind lives in the policy. */
function coverageOf(declByFamily: Map<EffectFamily, EffectDecl>, effectTypes: Set<string>): string | null {
  for (const effectType of effectTypes) {
    const fam = familyForEffectType(effectType);
    if (fam === null) return `policy effect "${effectType}" cannot be classified into an effect family (unclassifiable)`;
    if (!declByFamily.has(fam)) return `policy effect "${effectType}" needs family "${fam}" which is not declared/owned`;
  }
  return null;
}

/** Compile a signed effect manifest. Fails unless declarations are valid + one-per-family, coverage holds, self-verifies. */
export function compileEffectManifest(
  declarations: readonly EffectDecl[],
  policyBundle: SignedBundle,
  seams: { readonly artifactGraphDigest: string; readonly scannerToolDigest: string },
  signers: readonly EffectManifestSigner[],
  threshold = signers.length,
): SignedEffectManifest {
  if (signers.length === 0) throw new EffectManifestError("at least one signer is required");
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > signers.length) throw new EffectManifestError(`threshold must be in [1, ${signers.length}]`);
  const keyids = new Set<string>();
  for (const s of signers) { if (keyids.has(s.keyid)) throw new EffectManifestError(`duplicate signer keyid "${s.keyid}"`); keyids.add(s.keyid); }
  for (const d of [seams.artifactGraphDigest, seams.scannerToolDigest]) if (!HEX64.test(d)) throw new EffectManifestError("seam digests must be 64-hex");

  const decls = [...declarations.map(validateEffectDecl)].sort((a, b) => (a.family < b.family ? -1 : a.family > b.family ? 1 : 0));
  const byFamily = new Map<EffectFamily, EffectDecl>();
  for (const d of decls) { if (byFamily.has(d.family)) throw new EffectManifestError(`family "${d.family}" declared more than once (exactly one broker ownership)`); byFamily.set(d.family, d); }
  const cover = coverageOf(byFamily, policyEffectTypes(policyBundle));
  if (cover !== null) throw new EffectManifestError(`coverage: ${cover}`);

  const payload: EffectManifestPayload = {
    manifestVersion: 1, builder: { name: EFFECT_MANIFEST.name, version: EFFECT_MANIFEST.version },
    declarations: decls, declarationSetDigest: declSetDigestOf(decls),
    policyBundleDigest: bundlePayloadDigest(policyBundle),
    artifactGraphDigest: seams.artifactGraphDigest, scannerToolDigest: seams.scannerToolDigest,
  };
  const payloadDigest = payloadDigestOf(payload);
  const preimage = signPreimageOf(payloadDigest);
  const signatures = signers.map((s) => {
    const sig = s.signer.sign(preimage);
    if (sig === null || typeof sig !== "object" || sig.keyid !== s.keyid || typeof sig.sig !== "string") throw new EffectManifestError(`signer for "${s.keyid}" returned a malformed/foreign signature`);
    if (sig.sig !== stubSign(s.verifyKey, s.keyid, preimage).sig) throw new EffectManifestError(`signer for "${s.keyid}" produced an invalid signature`);
    return { keyid: sig.keyid, sig: sig.sig };
  }).sort((a, b) => (a.keyid < b.keyid ? -1 : a.keyid > b.keyid ? 1 : 0));
  const manifest: SignedEffectManifest = { payload, payloadDigest, signatures };
  const trust: TrustPolicy = { trustedKeys: new Map(signers.map((s) => [s.keyid, s.verifyKey] as const)), threshold };
  const v = verifyEffectManifest(manifest, policyBundle, { manifestTrust: trust });
  if (!v.valid) throw new EffectManifestError(`compiler produced a manifest that does not verify: ${v.reason}`);
  return manifest;
}

const exactKeys = (o: unknown, allowed: readonly string[]): boolean =>
  o !== null && typeof o === "object" && !Array.isArray(o) && (() => { const k = Object.keys(o).sort(); const a = [...allowed].sort(); return k.length === a.length && k.every((x, i) => x === a[i]); })();
const PAYLOAD_KEYS = ["manifestVersion", "builder", "declarations", "declarationSetDigest", "policyBundleDigest", "artifactGraphDigest", "scannerToolDigest"];

/** Capture the caller's manifest into an OWNED, read-once snapshot (TOCTOU-safe). */
export function captureEffectManifest(signed: unknown): SignedEffectManifest {
  if (signed === null || typeof signed !== "object") throw new EffectManifestError("manifest must be an object");
  const s = signed as Record<string, unknown>;
  if (!exactKeys(s, ["payload", "payloadDigest", "signatures"])) throw new EffectManifestError("malformed manifest envelope");
  const payloadDigest = s.payloadDigest;
  if (typeof payloadDigest !== "string") throw new EffectManifestError("payloadDigest must be a string");
  const sigRaw = s.signatures;
  if (!Array.isArray(sigRaw) || sigRaw.length === 0) throw new EffectManifestError("signatures must be a non-empty array");
  const signatures = sigRaw.map((x) => {
    if (!exactKeys(x, ["keyid", "sig"])) throw new EffectManifestError("malformed signature entry");
    const so = x as Record<string, unknown>;
    if (typeof so.keyid !== "string" || typeof so.sig !== "string") throw new EffectManifestError("malformed signature entry");
    return Object.freeze({ keyid: so.keyid, sig: so.sig });
  });
  const p = s.payload;
  if (!exactKeys(p, PAYLOAD_KEYS)) throw new EffectManifestError("payload has unexpected or missing fields");
  const po = p as Record<string, unknown>;
  if (!exactKeys(po.builder, ["name", "version"])) throw new EffectManifestError("builder has unexpected fields");
  const bo = po.builder as Record<string, unknown>;
  if (!Array.isArray(po.declarations)) throw new EffectManifestError("declarations must be an array");
  const declarations = po.declarations.map((d) => Object.freeze(validateEffectDecl(d)));
  const payload: EffectManifestPayload = Object.freeze({
    manifestVersion: po.manifestVersion as 1,
    builder: Object.freeze({ name: bo.name as string, version: bo.version as string }),
    declarations: Object.freeze(declarations),
    declarationSetDigest: po.declarationSetDigest as string,
    policyBundleDigest: po.policyBundleDigest as string,
    artifactGraphDigest: po.artifactGraphDigest as string,
    scannerToolDigest: po.scannerToolDigest as string,
  });
  return Object.freeze({ payload, payloadDigest, signatures });
}

function structuralProblem(p: EffectManifestPayload, pol: { digest: string; effects: Set<string> }): string | null {
  if (p.manifestVersion !== 1) return `unsupported manifestVersion ${String(p.manifestVersion)}`;
  if (p.builder.name !== EFFECT_MANIFEST.name || p.builder.version !== EFFECT_MANIFEST.version) return "unsupported builder identity";
  for (const d of [p.declarationSetDigest, p.policyBundleDigest, p.artifactGraphDigest, p.scannerToolDigest]) if (typeof d !== "string" || !HEX64.test(d)) return "a bound digest is not 64-hex";
  let prev = "";
  const byFamily = new Map<EffectFamily, EffectDecl>();
  for (const d of p.declarations) {
    if (!isEffectFamily(d.family)) return "unknown effect family";
    if (d.family < prev) return "declarations are not canonically sorted by family";
    prev = d.family;
    if (byFamily.has(d.family)) return `family "${d.family}" declared more than once`;
    byFamily.set(d.family, d);
  }
  if (declSetDigestOf(p.declarations) !== p.declarationSetDigest) return "declarationSetDigest does not match the declarations";
  if (p.policyBundleDigest !== pol.digest) return "manifest binds a different policy bundle than the one supplied";
  const cover = coverageOf(byFamily, pol.effects);
  if (cover !== null) return `coverage: ${cover}`;
  return null;
}

/** Verify a signed effect manifest END TO END against the policy bundle it binds. TOTAL + fail-safe; returns an owned snapshot. */
export function verifyEffectManifest(signed: SignedEffectManifest, policyBundle: SignedBundle, opts: { manifestTrust: TrustPolicy; policyTrust?: TrustPolicy }): EffectManifestVerdict {
  try {
    const trust = opts.manifestTrust;
    const rawKeys = trust?.trustedKeys; if (!(rawKeys instanceof Map)) return { valid: false, reason: "manifestTrust.trustedKeys must be a Map" };
    const trustedKeys = new Map(rawKeys); const threshold = trust.threshold; // capture map ONCE before clone (TOCTOU-safe)
    if (!Number.isInteger(threshold) || threshold < 1) return { valid: false, reason: "invalid-threshold" };
    let snap: SignedEffectManifest;
    try { snap = captureEffectManifest(signed); } catch (e) { return { valid: false, reason: safeMsg(e) }; }
    if (snap.signatures.some((s, i) => i > 0 && s.keyid <= snap.signatures[i - 1]!.keyid)) return { valid: false, reason: "signatures not canonically sorted / duplicate keyid" };
    let polBundle: SignedBundle;
    let polDigest: string;
    try { polBundle = captureBundle(policyBundle); polDigest = bundlePayloadDigest(polBundle); }
    catch (e) { return { valid: false, reason: `policy bundle malformed: ${safeMsg(e)}` }; }
    if (polBundle.payloadDigest !== polDigest) return { valid: false, reason: "policy bundle claimed payloadDigest does not match its payload" };
    if (opts.policyTrust) { const pv = verifyBundle(polBundle, opts.policyTrust); if (!pv.valid) return { valid: false, reason: `bound policy bundle does not verify: ${pv.reason}` }; }
    const pol = { digest: polDigest, effects: policyEffectTypes(polBundle) };

    const structural = structuralProblem(snap.payload, pol);
    if (structural !== null) return { valid: false, reason: `structural: ${structural}` };
    const recomputed = payloadDigestOf(snap.payload);
    if (recomputed !== snap.payloadDigest) return { valid: false, reason: "payload digest mismatch" };
    const preimage = signPreimageOf(recomputed);
    let valid = 0;
    const seen = new Set<string>();
    for (const s of snap.signatures) {
      const key = trustedKeys.get(s.keyid);
      if (key === undefined || seen.has(s.keyid)) continue;
      if (s.sig === stubSign(key, s.keyid, preimage).sig) { seen.add(s.keyid); valid++; }
    }
    if (valid < threshold) return { valid: false, reason: `threshold-not-met:${valid}<${threshold}` };
    return { valid: true, signerCount: valid, manifest: snap };
  } catch (e) {
    return { valid: false, reason: `verify error: ${safeMsg(e)}` };
  }
}

/** The declared owner path for each family (from a verified manifest snapshot) — the scanner's owner map. */
export function ownersOf(manifest: SignedEffectManifest): Map<EffectFamily, string> {
  const m = new Map<EffectFamily, string>();
  for (const d of manifest.payload.declarations) m.set(d.family, d.owner);
  return m;
}

function payloadCanonical(p: EffectManifestPayload): CanonicalValue {
  return {
    manifestVersion: BigInt(p.manifestVersion),
    builder: { name: p.builder.name, version: p.builder.version },
    declarations: p.declarations.map(effectDeclToCanonical),
    declarationSetDigest: p.declarationSetDigest,
    policyBundleDigest: p.policyBundleDigest,
    artifactGraphDigest: p.artifactGraphDigest,
    scannerToolDigest: p.scannerToolDigest,
  };
}
