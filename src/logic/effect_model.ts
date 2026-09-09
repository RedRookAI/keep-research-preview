/**
 * Effect-model INTEGRITY GATE (closes R41's core) + the smallest execution-monitoring primitive.
 *
 * The state-simulation hard critic (`stateSimulation`) is sound only w.r.t. the declared EFFECT-MODEL
 * (what each step establishes/deletes/requires). R41: a wrong or TAMPERED model still simulates to a pass —
 * the honest residual. The premium pattern (ComplianceTwin/ATA, LLM-Modulo): confine the LLM to OFFLINE model
 * ingestion, VALIDATE + SIGN the model, and make runtime verification deterministic. So the model's CONTENT
 * stays a SEAM (acquired offline), but its INTEGRITY is gated in-env: the simulation refuses to trust a model
 * that is not signed by a trusted key. A model the agent forged or edited fails signature verification —
 * exactly as R34 does for the AI-BOM (the agent, data-plane, cannot reach the control-plane signing key).
 *
 * This reuses the R34 DSSE verify pattern (trusted keys + threshold + fail-safe) rather than inventing one.
 *
 * BUILT vs SEAM: BUILT + proven in-env is the VERIFY side — recompute the model digest, verify signatures
 * against trusted keys, require a threshold, fail safe (absent/unsigned/tampered/untrusted-key ⇒ reject) —
 * plus the `divergence` execution-monitor primitive. SEAM: the model's CONTENT (acquired offline) and the
 * real signer (HSM/KMS/TEE, key unreachable by the agent). The signing key must be UNREACHABLE by the
 * plan generator, or the gate is theatre.
 */

/** The effect-model: per step-kind, the facts it requires / establishes / deletes. Content = SEAM. */
export interface EffectModel {
  /** step-kind id → its effect schema. */
  readonly schema: ReadonlyMap<string, { readonly requires: readonly string[]; readonly establishes: readonly string[]; readonly deletes: readonly string[] }>;
  /** A version/domain tag bound into the signed content. */
  readonly version: string;
}

export interface ModelSignature {
  readonly keyid: string;
  readonly sig: string;
}

/** DSSE-style envelope: the effect-model + its signature(s). */
export interface SignedEffectModel {
  readonly payload: EffectModel;
  readonly signatures: readonly ModelSignature[];
}

export interface ModelTrustPolicy {
  /** keyid → verify key. The generator's own key MUST NOT be here. */
  readonly trustedKeys: ReadonlyMap<string, string>;
  readonly threshold: number; // k-of-n; 1 for a single trusted signer
}

export type ModelVerification =
  | { readonly verified: true; readonly model: EffectModel; readonly signerCount: number }
  | { readonly verified: false; readonly reason: string };

/** A tiny, deterministic digest over the model content (order-independent over the schema map). */
function modelDigest(m: EffectModel): string {
  const entries: string[] = [];
  for (const [kind, s] of m.schema) {
    entries.push(`${kind}:R[${[...s.requires].sort().join(",")}]E[${[...s.establishes].sort().join(",")}]D[${[...s.deletes].sort().join(",")}]`);
  }
  entries.sort();
  return `${m.version}#${entries.join("|")}`;
}

/** The content that is signed. */
export function modelSignedContent(m: EffectModel): string {
  return modelDigest(m);
}

/** Stub signature (stands in for the HSM/KMS signature — the SEAM), mirroring R34's stubSign. */
export function stubSignModel(privateKey: string, keyid: string, content: string): ModelSignature {
  // a simple deterministic MAC over key|content; the real signer is the SEAM.
  let h = 2166136261 >>> 0;
  const s = `${privateKey}|${content}`;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return { keyid, sig: `${h.toString(16)}` };
}

/**
 * Verify a signed effect-model. Total + fail-safe. Recompute the digest, count signatures that are BOTH from
 * a TRUSTED key AND valid over the content, require the threshold; any shortfall ⇒ unverifiable (reject).
 */
export function verifiedEffectModel(env: SignedEffectModel | undefined, policy: ModelTrustPolicy): ModelVerification {
  if (env === undefined) return { verified: false, reason: "no-signed-model" }; // absent ⇒ reject
  if (env.signatures.length === 0) return { verified: false, reason: "no-signatures" };
  const content = modelSignedContent(env.payload);
  let valid = 0;
  const seen = new Set<string>();
  for (const s of env.signatures) {
    const key = policy.trustedKeys.get(s.keyid);
    if (key === undefined) continue; // untrusted key (incl. the agent's own) does not count
    const expected = stubSignModel(key, s.keyid, content).sig;
    if (s.sig === expected && !seen.has(s.keyid)) {
      seen.add(s.keyid);
      valid++;
    }
  }
  if (valid < policy.threshold) return { verified: false, reason: `threshold-not-met:${valid}<${policy.threshold}` };
  return { verified: true, model: env.payload, signerCount: valid };
}

/**
 * The smallest EXECUTION-MONITORING primitive (the "after"): compare a step's SIMULATED predicted outcome to
 * its ACTUAL outcome; a mismatch means the world diverged from the model ⇒ replan. Pure + fail-safe (an
 * unknown/undefined actual ⇒ replan — we cannot confirm the prediction held). The monitor's WIRING (feeding
 * actual outcomes from execution) is the SEAM; the divergence decision is in-env.
 */
export function divergence(
  predicted: readonly string[],
  actual: readonly string[] | undefined,
): { readonly replan: boolean; readonly reason: string } {
  if (actual === undefined) return { replan: true, reason: "unknown-actual-outcome" }; // fail-safe
  const a = new Set(actual);
  const missing = predicted.filter((p) => !a.has(p));
  const extra = actual.filter((x) => !predicted.includes(x));
  if (missing.length > 0 || extra.length > 0) {
    return { replan: true, reason: `divergence:missing[${missing.join(",")}]extra[${extra.join(",")}]` };
  }
  return { replan: false, reason: "outcome-matches-prediction" };
}
