/**
 * Signed INGRESS MANIFEST + policy-addressability coverage (Mechanical-Enforcement Increment 3, the binding to Incr 2).
 *
 * The manifest is the sealed, signed, content-addressed inventory of every declared ingress. It binds three things
 * cryptographically: the exact declaration set, the exact Increment-2 policy bundle it was compiled against, and (as
 * honest SEAMS whose enforcement is owned by later increments) the scanned artifact-graph digest + scanner-tool
 * identity. `verifyManifest` re-derives everything and fails closed on any mismatch.
 *
 * POLICY-ADDRESSABILITY (the E_M = E_P relation). Let A = the set of declared ingress addresses and, over the compiled
 * policy's rules, let the referenced entryPoint tokens be split into concrete tokens and the "*" wildcard. Coverage is
 * exact set-equality between A and the policy's addressed set (with "*" expanded to all of A):
 *   - SOUNDNESS (no dangling policy token): every concrete entryPoint a rule references is a declared address.
 *   - COMPLETENESS (every ingress is policy-addressable): every declared address is referenced by some rule, or a
 *     wildcard ("*") rule exists that addresses all of them.
 * So a stale policy token (points at a non-existent ingress) and an un-addressable ingress (declared but no policy
 * path) are BOTH fatal. This does not evaluate permits or establish principals (Increment 8) — denied-only ingresses
 * are valid inventory; it only proves address coverage.
 *
 * Grounding: SLSA/in-toto signed manifest binding; deny-by-default registration; canonical content-addressed identity
 * (Increment 1); domain separation (never reuse the policy-bundle or generic EIR domain).
 */
import { eirDigest, type CanonicalValue } from "../eir/canonical.js";
import { stubSign, type Signature, type Signer, type TrustPolicy } from "../bom/bom_signing.js";
import { validateDecl, declToCanonical, declId, type IngressDecl } from "./ingress.js";
import { parseAddress } from "./address.js";
import { verifyBundle, captureBundle, bundlePayloadDigest, type SignedBundle } from "../policy/compiler.js";

export const MANIFEST = { name: "keep.ingress.manifest", version: "3.0.0" } as const;
const HEX64 = /^[0-9a-f]{64}$/;

export class ManifestError extends Error { constructor(m: string) { super(`ingress manifest: ${m}`); this.name = "ManifestError"; } }

/** Extract an error message without letting an adversarial thrown value (e.g. a Proxy with a throwing getter) escape. */
function safeMsg(e: unknown): string { try { return String((e as { message?: unknown })?.message ?? e); } catch { return "unknown"; } }

export interface ManifestPayload {
  readonly manifestVersion: 1;
  readonly builder: { readonly name: string; readonly version: string };
  readonly declarations: readonly IngressDecl[];    // canonical, sorted by address, unique
  readonly declarationSetDigest: string;             // digest of the sorted declaration ids
  readonly policyBundleDigest: string;               // the exact Increment-2 bundle payload digest this binds
  readonly artifactGraphDigest: string;              // SEAM (Incr 5): the scanned/deployed artifact identity
  readonly scannerToolDigest: string;                // SEAM: the closed-world scanner engine identity
}
export interface SignedManifest {
  readonly payload: ManifestPayload;
  readonly payloadDigest: string;
  readonly signatures: readonly Signature[];
}
export interface ManifestSigner { readonly signer: Signer; readonly keyid: string; readonly verifyKey: string; }
/** On success, `manifest` is an OWNED, immutable snapshot verified end-to-end — use THIS, never the caller's object. */
export type ManifestVerdict = { readonly valid: true; readonly signerCount: number; readonly manifest: SignedManifest } | { readonly valid: false; readonly reason: string };

// ── domain-separated digests (never the policy-bundle or generic EIR domain) ──
const payloadDigestOf = (p: ManifestPayload): string => eirDigest("keep.ingress-manifest.v1", payloadCanonical(p));
const signPreimageOf = (payloadDigest: string): string => eirDigest("keep.ingress-manifest.signature-preimage/v1", { payloadDigest });
const declSetDigestOf = (decls: readonly IngressDecl[]): string => eirDigest("keep.ingress.declset.v1", decls.map(declId).sort());

/** The distinct declared ingress addresses (E_M), validated. */
export function manifestAddresses(decls: readonly IngressDecl[]): string[] {
  return decls.map((d) => validateDecl(d).address);
}

/** The policy's addressed entryPoint universe over a compiled bundle: {concrete tokens} and whether a "*" rule exists. */
function policyEntryPoints(bundle: SignedBundle): { concrete: Set<string>; wildcard: boolean } {
  const concrete = new Set<string>();
  let wildcard = false;
  for (const r of bundle.payload.rules) for (const ep of r.entryPoints) { if (ep === "*") wildcard = true; else concrete.add(ep); }
  return { concrete, wildcard };
}

/** The coverage problem over already-snapshotted sets, or null if E_M = E_P holds. */
function coverageOf(A: ReadonlySet<string>, concrete: ReadonlySet<string>, wildcard: boolean): string | null {
  for (const t of concrete) if (!A.has(t)) return `policy references entryPoint "${t}" that is not a declared ingress (stale policy token)`;
  if (!wildcard) for (const a of A) if (!concrete.has(a)) return `ingress "${a}" is declared but no policy rule addresses it (un-addressable)`;
  return null;
}

/** The coverage problem, or null if E_M = E_P holds. Pure; used by compile + tests (reads the bundle once). */
export function coverageProblem(decls: readonly IngressDecl[], bundle: SignedBundle): string | null {
  const { concrete, wildcard } = policyEntryPoints(bundle);
  return coverageOf(new Set(manifestAddresses(decls)), concrete, wildcard);
}

/**
 * Compile a signed manifest from declarations + the policy bundle it binds. Fails unless declarations are valid +
 * uniquely addressed, coverage holds, and the result self-verifies. `seams` carries the artifact/scanner digests whose
 * *enforcement* is a later increment; they are bound here so the binding points exist.
 */
export function compileManifest(
  declarations: readonly IngressDecl[],
  policyBundle: SignedBundle,
  seams: { readonly artifactGraphDigest: string; readonly scannerToolDigest: string },
  signers: readonly ManifestSigner[],
  threshold = signers.length,
): SignedManifest {
  if (signers.length === 0) throw new ManifestError("at least one signer is required (an unsigned manifest is never emitted)");
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > signers.length) throw new ManifestError(`threshold must be in [1, ${signers.length}]`);
  const keyids = new Set<string>();
  for (const s of signers) { if (keyids.has(s.keyid)) throw new ManifestError(`duplicate signer keyid "${s.keyid}"`); keyids.add(s.keyid); }
  for (const d of seams ? [seams.artifactGraphDigest, seams.scannerToolDigest] : []) if (!HEX64.test(d)) throw new ManifestError("seam digests must be 64-hex");

  const decls = [...declarations.map(validateDecl)].sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
  const addrs = new Set<string>();
  for (const d of decls) { if (addrs.has(d.address)) throw new ManifestError(`duplicate ingress address "${d.address}"`); addrs.add(d.address); }
  const cover = coverageProblem(decls, policyBundle);
  if (cover !== null) throw new ManifestError(`coverage: ${cover}`);

  const payload: ManifestPayload = {
    manifestVersion: 1, builder: { name: MANIFEST.name, version: MANIFEST.version },
    declarations: decls, declarationSetDigest: declSetDigestOf(decls),
    policyBundleDigest: policyBundle.payloadDigest,
    artifactGraphDigest: seams.artifactGraphDigest, scannerToolDigest: seams.scannerToolDigest,
  };
  const payloadDigest = payloadDigestOf(payload);
  const preimage = signPreimageOf(payloadDigest);
  const signatures = signers.map((s) => {
    const sig = s.signer.sign(preimage);
    if (sig === null || typeof sig !== "object" || sig.keyid !== s.keyid || typeof sig.sig !== "string") throw new ManifestError(`signer for "${s.keyid}" returned a malformed/foreign signature`);
    if (sig.sig !== stubSign(s.verifyKey, s.keyid, preimage).sig) throw new ManifestError(`signer for "${s.keyid}" produced an invalid signature`);
    return { keyid: sig.keyid, sig: sig.sig };
  }).sort((a, b) => (a.keyid < b.keyid ? -1 : a.keyid > b.keyid ? 1 : 0));
  const manifest: SignedManifest = { payload, payloadDigest, signatures };
  const trust: TrustPolicy = { trustedKeys: new Map(signers.map((s) => [s.keyid, s.verifyKey] as const)), threshold };
  const v = verifyManifest(manifest, policyBundle, { manifestTrust: trust });
  if (!v.valid) throw new ManifestError(`compiler produced a manifest that does not verify: ${v.reason}`);
  return manifest;
}

const exactKeys = (o: unknown, allowed: readonly string[]): boolean =>
  o !== null && typeof o === "object" && !Array.isArray(o) && (() => { const k = Object.keys(o).sort(); const a = [...allowed].sort(); return k.length === a.length && k.every((x, i) => x === a[i]); })();
const PAYLOAD_KEYS = ["manifestVersion", "builder", "declarations", "declarationSetDigest", "policyBundleDigest", "artifactGraphDigest", "scannerToolDigest"];

/**
 * Capture the caller's manifest into an OWNED, immutable snapshot, reading every (possibly getter/Proxy-backed) field
 * EXACTLY ONCE. All verification + sealing then use this snapshot — never the caller's object — so a stateful getter
 * cannot present the signed payload to verification and a different one to boot-closure/table construction (TOCTOU).
 */
function captureManifest(signed: unknown): SignedManifest {
  if (signed === null || typeof signed !== "object") throw new ManifestError("manifest must be an object");
  const s = signed as Record<string, unknown>;
  if (!exactKeys(s, ["payload", "payloadDigest", "signatures"])) throw new ManifestError("malformed manifest envelope");
  const payloadDigest = s.payloadDigest;
  if (typeof payloadDigest !== "string") throw new ManifestError("payloadDigest must be a string");
  const sigRaw = s.signatures;
  if (!Array.isArray(sigRaw) || sigRaw.length === 0) throw new ManifestError("signatures must be a non-empty array");
  const signatures = sigRaw.map((x) => {
    if (!exactKeys(x, ["keyid", "sig"])) throw new ManifestError("malformed signature entry");
    const so = x as Record<string, unknown>;
    if (typeof so.keyid !== "string" || typeof so.sig !== "string") throw new ManifestError("malformed signature entry");
    return Object.freeze({ keyid: so.keyid, sig: so.sig });
  });
  const p = s.payload;
  if (!exactKeys(p, PAYLOAD_KEYS)) throw new ManifestError("payload has unexpected or missing fields");
  const po = p as Record<string, unknown>;
  const b = po.builder;
  if (!exactKeys(b, ["name", "version"])) throw new ManifestError("builder has unexpected fields");
  const bo = b as Record<string, unknown>;
  const declsRaw = po.declarations;
  if (!Array.isArray(declsRaw)) throw new ManifestError("declarations must be an array");
  const declarations = declsRaw.map((d) => Object.freeze(validateDecl(d))); // validateDecl returns an owned copy
  const payload: ManifestPayload = Object.freeze({
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

/** Re-derive the OWNED snapshot's structural invariants against the (once-snapshotted) policy. Null if sound. */
function structuralProblem(p: ManifestPayload, pol: { digest: string; concrete: ReadonlySet<string>; wildcard: boolean }): string | null {
  if (p.manifestVersion !== 1) return `unsupported manifestVersion ${String(p.manifestVersion)}`;
  if (p.builder.name !== MANIFEST.name || p.builder.version !== MANIFEST.version) return "unsupported builder identity";
  for (const d of [p.declarationSetDigest, p.policyBundleDigest, p.artifactGraphDigest, p.scannerToolDigest]) if (typeof d !== "string" || !HEX64.test(d)) return "a bound digest is not 64-hex";
  let prev = "";
  const addrs = new Set<string>();
  for (const vd of p.declarations) {
    if (vd.address < prev) return "declarations are not canonically sorted by address";
    prev = vd.address;
    if (addrs.has(vd.address)) return `duplicate ingress address "${vd.address}"`;
    addrs.add(vd.address);
  }
  if (declSetDigestOf(p.declarations) !== p.declarationSetDigest) return "declarationSetDigest does not match the declarations";
  if (p.policyBundleDigest !== pol.digest) return "manifest binds a different policy bundle than the one supplied";
  const cover = coverageOf(addrs, pol.concrete, pol.wildcard);
  if (cover !== null) return `coverage: ${cover}`;
  return null;
}

/**
 * Verify a signed manifest END TO END against the policy bundle it binds. TOTAL + fail-safe. On success returns an
 * OWNED, immutable snapshot (`manifest`) that callers (e.g. registry.seal) MUST use instead of the passed object.
 * `opts.policyTrust`, if given, additionally re-verifies the policy bundle itself (recommended).
 */
export function verifyManifest(signed: SignedManifest, policyBundle: SignedBundle, opts: { manifestTrust: TrustPolicy; policyTrust?: TrustPolicy }): ManifestVerdict {
  try {
    const trust = opts.manifestTrust;
    const rawKeys = trust?.trustedKeys; if (!(rawKeys instanceof Map)) return { valid: false, reason: "manifestTrust.trustedKeys must be a Map" };
    const trustedKeys = new Map(rawKeys); const threshold = trust.threshold; // capture map ONCE before clone (TOCTOU-safe)
    if (!Number.isInteger(threshold) || threshold < 1) return { valid: false, reason: "invalid-threshold" };
    let snap: SignedManifest;
    try { snap = captureManifest(signed); } catch (e) { return { valid: false, reason: safeMsg(e) }; }
    if (snap.signatures.some((s, i) => i > 0 && s.keyid <= snap.signatures[i - 1]!.keyid)) return { valid: false, reason: "signatures not canonically sorted / duplicate keyid" };
    // Capture the policy bundle ONCE into an owned snapshot, then derive coverage/digest AND (if policyTrust) verify
    // signatures all from that SAME snapshot — so coverage can never be checked against a different view than is
    // verified (a getter-backed policy bundle presenting policy A for coverage, policy B for signatures).
    let polBundle: SignedBundle;
    let polDigest: string;
    try {
      polBundle = captureBundle(policyBundle);
      // ALWAYS recompute the bundle's digest from its own payload — never trust the claimed `payloadDigest` field
      // (even without policyTrust): a forged (payload, claimed-digest) pair must not pass the binding/coverage checks.
      polDigest = bundlePayloadDigest(polBundle);
    } catch (e) { return { valid: false, reason: `policy bundle malformed: ${safeMsg(e)}` }; }
    if (polBundle.payloadDigest !== polDigest) return { valid: false, reason: "policy bundle claimed payloadDigest does not match its payload" };
    if (opts.policyTrust) { const pv = verifyBundle(polBundle, opts.policyTrust); if (!pv.valid) return { valid: false, reason: `bound policy bundle does not verify: ${pv.reason}` }; }
    const pol = { digest: polDigest, ...policyEntryPoints(polBundle) };

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

/** Canonical value of the manifest payload — explicit field mapping. */
function payloadCanonical(p: ManifestPayload): CanonicalValue {
  return {
    manifestVersion: BigInt(p.manifestVersion),
    builder: { name: p.builder.name, version: p.builder.version },
    declarations: p.declarations.map(declToCanonical),
    declarationSetDigest: p.declarationSetDigest,
    policyBundleDigest: p.policyBundleDigest,
    artifactGraphDigest: p.artifactGraphDigest,
    scannerToolDigest: p.scannerToolDigest,
  };
}
