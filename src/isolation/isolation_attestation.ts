/**
 * IsolationAttestation (BUILD-ORDER 1.7 — BIND-EXECUTOR-TIER-ATTESTATION) — the tier that buys the
 * autonomy ceiling becomes a SIGNED, CHECKABLE attestation the oversight router VERIFIES, not the
 * executor's word.
 *
 * Round 43 (`weakerTier`) took the minimum of the DECLARED tier and the executor's `.tier` property —
 * but `.tier` is STILL only the executor's word (a class field). A mislabelled executor, a config
 * mismatch, or a supply-chain swap that constructs `BoundaryExecutor("microvm", …)` over the process
 * floor asserts "microvm" and buys the `full` ceiling with nothing enforcing it. That is the Z156/Z193
 * confused-deputy shape at its last isolation-stack instance: an authority (autonomy) derived from the
 * thing it is supposed to govern (isolation), on a claim nothing checked.
 *
 * THE ONE THING: the executor EMITS a signed attestation `{tier, evidence, projectDir, ts, mechanism}`
 * of the tier it really ran; the router VERIFIES it before the tier grants a ceiling. Verification is
 * TWO independent checks, both required:
 *   1. SIGNATURE valid — HMAC over the canonical claim with the run-local key (integrity + provenance:
 *      a tampered attestation, or one not produced by this run's attestor, fails).
 *   2. EVIDENCE recomputes to AT LEAST the claimed tier — `recomputeTierFromEvidence` derives, from the
 *      measured evidence alone, the strongest tier that evidence PROVES; the claim is capped at it.
 * Forged / unsigned / tampered / absent → the weakest tier ("none"), NO autonomy. A validly-signed claim
 * of a stronger tier than the evidence backs is capped DOWN to the proven tier (never honoured up).
 *
 * SOTA basis (2026-08-16): remote attestation appraises EVIDENCE, not a stamped label (RFC 9683; EAT
 * Entity Attestation Tokens; SEV-SNP/TDX signed reports). THE DISCONFIRMING CASE the literature keeps
 * proving (v3→v4 SEV-SNP report parser breaks; the 2026 VCEK-seed-extraction attack): a signature is
 * only as good as the key custody, so the verifier must RECOMPUTE the claim from evidence — "a signature
 * over a lie is still a lie." A real hardware attestation (SEV-SNP/TDX) is the unforgeable-evidence
 * upgrade and is a LABELLED VERIFIED-SEAM behind the same port (`TeeVerifier`); in-env there is no TEE,
 * so this is the HMAC run-key form, labelled — a `tee-*` mechanism claim with no live TEE verifier
 * verifies as the HMAC tier, NEVER a false TEE claim. Zero new deps (node:crypto HMAC).
 *
 * Sibling to `../tcb/attestation.ts` (R37): that attests the LOADED BINARY (measurement digest match);
 * this attests the EXECUTION TIER (evidence recompute). Same fail-safe posture; the tier recompute is
 * the check R37's digest-match does not need.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { TIER_STRENGTH, weakerTier, type IsolationTier } from "./isolation_tier.js";
import { consumeVerifiedMicrovmRunReceiptDigest } from "../infra/microvm_boundary.js";

/**
 * The MEASURED evidence an executor attests to — the fields the verifier RECOMPUTES the tier from. Each
 * is a fact a probe measured (or a VERIFIED-SEAM host reports), never a tier label. The tier is DERIVED
 * from these, so falsifying the tier alone (the common confused-deputy case) cannot survive recompute.
 */
export interface IsolationEvidence {
  /** `process.platform` where the run happened. */
  readonly platform: string;
  /** The concrete boundary mechanism: "process" | "windows-job-object" | "docker"|"podman"|"containerd" |
   *  "runsc"|"gvisor" | "firecracker"|"cloud-hypervisor". The tier is recomputed FROM this + the flags. */
  readonly runtimeKind: string;
  /** `/dev/kvm` present as a real char device (required, with a VMM, for the microvm tier). */
  readonly kvmPresent: boolean;
  /** The tier's run images exist on disk (guest kernel+rootfs for microvm; a toolchain image for a container). */
  readonly imagesPresent: boolean;
  /** A Win32 Job Object can really be created+assigned (the win32 process-tier backing). */
  readonly jobObjectSupport: boolean;
  /** Honest degradations measured at run time (e.g. "net-deny not enforceable", "no-measured-evidence"). */
  readonly degraded: readonly string[];
  /** One-time verifier-owned real-run receipt. Required for `microvm`; absent for every weaker tier. */
  readonly completedRunReceiptDigest?: string;
  readonly completedRunExecutionSpecDigest?: string;
  readonly completedRunGuestExecutionRequestDigest?: string;
  readonly completedRunProjectManifestDigest?: string;
  readonly completedRunResultDigest?: string;
  readonly completedRunMeasurementPolicyDigest?: string;
}

/** The attestation mechanism. `hmac-run-key` is the in-env zero-dep form; `tee-*` are VERIFIED-SEAMs (real
 *  hardware attestation reports) honoured ONLY when a live `TeeVerifier` confirms the report. */
export type AttestationMechanism = "hmac-run-key" | "tee-sev-snp" | "tee-tdx";

/** The unsigned claim: the tier the executor says it ran, with the evidence + provenance. */
export interface IsolationClaim {
  readonly tier: IsolationTier;
  readonly evidence: IsolationEvidence;
  readonly projectDir: string;
  readonly ts: number;
  readonly mechanism: AttestationMechanism;
}

/** A signed attestation: the claim + an HMAC over its canonical form. */
export interface IsolationAttestation {
  readonly claim: IsolationClaim;
  readonly signature: string;
}

/** Concrete runtime kinds grouped by the tier they back. A kind outside these backs at most the process floor. */
const VMM_KINDS = new Set(["firecracker", "cloud-hypervisor", "qemu-kvm", "microvm"]);

/**
 * RECOMPUTE the tier the evidence PROVES — the DISCONFIRMING core (a signature over a lie is still a lie).
 * Independent of the claimed tier: derives the STRONGEST tier the measured evidence actually backs and
 * nothing more. The verifier caps the claim at this, so stamping a stronger tier over honest weaker
 * evidence (the process floor mislabelled `microvm`) recomputes to the weaker tier and buys only its
 * ceiling. Total + deterministic.
 */
export function recomputeTierFromEvidence(e: IsolationEvidence): IsolationTier {
  // microvm needs HARDWARE virt evidence: KVM + a VMM runtime + the guest images to actually boot.
  if (e.kvmPresent && e.imagesPresent && VMM_KINDS.has(e.runtimeKind) && /^[0-9a-f]{64}$/.test(e.completedRunReceiptDigest ?? "")) return "microvm";
  // No shared-kernel strong tier earns authority from a runtime label or image preflight. A future
  // gVisor/container implementation must introduce the same completed-transaction receipt discipline.
  // process floor: the POSIX scoped-process backend is always backable; win32 is backed by a Job Object.
  if (e.runtimeKind === "process") return "process";
  if (e.platform === "win32" && e.jobObjectSupport && e.runtimeKind === "windows-job-object") return "process";
  return "none";
}

/** Deterministic serialization over ALL claim fields — any field change invalidates the signature. */
function canonicalClaim(c: IsolationClaim): string {
  return JSON.stringify({
    tier: c.tier,
    mechanism: c.mechanism,
    projectDir: c.projectDir,
    ts: c.ts,
    evidence: {
      platform: c.evidence.platform,
      runtimeKind: c.evidence.runtimeKind,
      kvmPresent: c.evidence.kvmPresent,
      imagesPresent: c.evidence.imagesPresent,
      jobObjectSupport: c.evidence.jobObjectSupport,
      degraded: [...c.evidence.degraded],
      completedRunReceiptDigest: c.evidence.completedRunReceiptDigest ?? null,
      completedRunExecutionSpecDigest: c.evidence.completedRunExecutionSpecDigest ?? null,
      completedRunGuestExecutionRequestDigest: c.evidence.completedRunGuestExecutionRequestDigest ?? null,
      completedRunProjectManifestDigest: c.evidence.completedRunProjectManifestDigest ?? null,
      completedRunResultDigest: c.evidence.completedRunResultDigest ?? null,
      completedRunMeasurementPolicyDigest: c.evidence.completedRunMeasurementPolicyDigest ?? null,
    },
  });
}

/** HMAC-SHA256 over the canonical claim with the run-local key (hex). The zero-dep signing primitive. */
export function signIsolationClaim(key: Buffer, claim: IsolationClaim): string {
  return createHmac("sha256", key).update(canonicalClaim(claim)).digest("hex");
}

/** Constant-time signature check — a length mismatch or any byte difference → false. */
function signatureValid(key: Buffer, att: IsolationAttestation): boolean {
  const expected = Buffer.from(signIsolationClaim(key, att.claim), "hex");
  let actual: Buffer;
  try { actual = Buffer.from(att.signature, "hex"); } catch { return false; }
  if (actual.length !== expected.length || expected.length === 0) return false;
  return timingSafeEqual(actual, expected);
}

/** The attestation port — the EXECUTOR emits. Given a run attestor, signs its measured tier+evidence. */
export interface IsolationAttestor {
  attest(claim: IsolationClaim): IsolationAttestation;
}

/** The result the router acts on. `verifiedTier` is what may buy a ceiling (never above the evidence). */
export interface AttestationVerification {
  /** The tier the router may grant a ceiling for — "none" on any failure; else min(claim, proven). */
  readonly verifiedTier: IsolationTier;
  /** True iff signature valid AND the claim was fully backed by evidence (claim <= proven). */
  readonly ok: boolean;
  /** The mechanism that ACTUALLY verified — NEVER `tee-*` unless a live TeeVerifier confirmed the report. */
  readonly verifiedMechanism: AttestationMechanism;
  readonly reason: string;
  /**
   * BUILD-ORDER 2.3 (REVISIT-ISOLATION-GATING) — the honest degradations the APPRAISED evidence measured
   * (the evidence's `degraded[]`, surfaced from the same claim the tier was recomputed from). Non-empty ⇒
   * the run PROVED LESS containment than `verifiedTier` nominally guarantees, so the autonomy-ceiling
   * decision (`isolationCeilingFromEvidence`) must not grant that tier's clean ceiling. Empty on an absent
   * or bad-signature attestation (nothing was appraised — the tier already fell to "none"). This keeps the
   * ceiling a function of what was MEASURED, not the tier label alone.
   */
  readonly measuredDegradations: readonly string[];
  /** Verifier-owned identities from the consumed completed microVM transaction. They are surfaced
   * only after signature, measurement-policy, and one-time receipt verification all succeed. */
  readonly verifiedRunReceiptDigest?: string;
  readonly verifiedExecutionSpecDigest?: string;
  readonly verifiedGuestExecutionRequestDigest?: string;
  readonly verifiedProjectManifestDigest?: string;
  readonly verifiedResultDigest?: string;
  readonly verifiedMeasurementPolicyDigest?: string;
  /** Opaque, verifier-owned, single-use authority for one exact completed execution subject. Plain
   * objects and copied verification fields cannot substitute for this capability. */
  readonly executionSubjectAuthority?: VerifiedExecutionSubjectAuthority;
}

const EXECUTION_SUBJECT_AUTHORITIES = new WeakMap<object, { readonly projectDir: string; readonly projectManifestDigest: string }>();
declare const EXECUTION_SUBJECT_AUTHORITY_TYPE: unique symbol;
export interface VerifiedExecutionSubjectAuthority { readonly [EXECUTION_SUBJECT_AUTHORITY_TYPE]: true }

function mintExecutionSubjectAuthority(projectDir: string, projectManifestDigest: string): VerifiedExecutionSubjectAuthority {
  const authority = Object.freeze(Object.create(null)) as VerifiedExecutionSubjectAuthority;
  EXECUTION_SUBJECT_AUTHORITIES.set(authority as object, { projectDir, projectManifestDigest });
  return authority;
}

/** Consume exactly once and only for the exact project/manifest measured by the completed run. */
export function consumeVerifiedExecutionSubjectAuthority(
  authority: VerifiedExecutionSubjectAuthority | undefined,
  projectDir: string,
  projectManifestDigest: string,
): boolean {
  if (!authority || (typeof authority !== "object" && typeof authority !== "function")) return false;
  const row = EXECUTION_SUBJECT_AUTHORITIES.get(authority as object);
  if (!row || row.projectDir !== projectDir || row.projectManifestDigest !== projectManifestDigest) return false;
  EXECUTION_SUBJECT_AUTHORITIES.delete(authority as object);
  return true;
}

/** The attestation port — the ROUTER verifies. */
export interface IsolationVerifier {
  verify(att: IsolationAttestation | undefined): AttestationVerification;
}

/**
 * VERIFIED-SEAM: a real hardware attestation report verifier (SEV-SNP / TDX). A live implementation
 * appraises the signed TEE report bound to the claim and returns the confirmed `tee-*` mechanism. Absent
 * in-env (no TEE) → `tee-*` claims verify as the HMAC form, never a false TEE status.
 */
export interface TeeVerifier {
  verifyTee(att: IsolationAttestation): AttestationMechanism | undefined;
}

class HmacAttestor implements IsolationAttestor {
  constructor(private readonly key: Buffer) {}
  attest(claim: IsolationClaim): IsolationAttestation {
    return { claim, signature: signIsolationClaim(this.key, claim) };
  }
}

class HmacVerifier implements IsolationVerifier {
  constructor(private readonly key: Buffer, private readonly teeVerifier?: TeeVerifier, private readonly trustedMicrovmMeasurementPolicyDigests: ReadonlySet<string> = new Set()) {}

  verify(att: IsolationAttestation | undefined): AttestationVerification {
    // (d) ABSENT → fail-closed to the weakest tier, NO autonomy. Never the declared/last-known tier.
    if (att === undefined) {
      return { verifiedTier: "none", ok: false, verifiedMechanism: "hmac-run-key", reason: "absent-attestation", measuredDegradations: [] };
    }
    // (c) SIGNATURE must be valid — a tampered attestation, or one not produced by this run's attestor,
    // → weakest tier. Checked BEFORE the tier is read, so a forged envelope earns nothing.
    if (!signatureValid(this.key, att)) {
      return { verifiedTier: "none", ok: false, verifiedMechanism: "hmac-run-key", reason: "bad-signature", measuredDegradations: [] };
    }
    // (e) SEAM-HONESTY: a `tee-*` mechanism is honoured as a TEE claim ONLY if a live TeeVerifier confirms
    // the hardware report. With no TEE verifier (the in-env case) it DOWNGRADES to the HMAC run-key form —
    // never a false TEE status. The tier is recomputed from the ordinary evidence regardless.
    let verifiedMechanism: AttestationMechanism = "hmac-run-key";
    if (att.claim.mechanism !== "hmac-run-key") {
      verifiedMechanism = this.teeVerifier?.verifyTee(att) ?? "hmac-run-key";
    }
    // (a) the DISCONFIRMING recompute — cap the claim at what the EVIDENCE proves. `weakerTier` never lets
    // the claim exceed the recomputed tier, so a forged-up tier over honest evidence buys only the proven
    // ceiling. (b) an honest strong claim whose evidence backs it is NOT demoted.
    const proven = recomputeTierFromEvidence(att.claim.evidence);
    const backed = TIER_STRENGTH[att.claim.tier] <= TIER_STRENGTH[proven];
    const verifiedTier = weakerTier(att.claim.tier, proven);
    // Appraise the signed claim first. Only a structurally backed microVM claim may consume its one-time
    // receipt, preventing malformed claims from burning a legitimate receipt.
    if (att.claim.tier === "microvm") {
      const e = att.claim.evidence;
      if (!backed || !e.completedRunReceiptDigest || !e.completedRunExecutionSpecDigest || !e.completedRunGuestExecutionRequestDigest ||
          !e.completedRunProjectManifestDigest || !e.completedRunResultDigest || !e.completedRunMeasurementPolicyDigest ||
          !this.trustedMicrovmMeasurementPolicyDigests.has(e.completedRunMeasurementPolicyDigest) ||
          !consumeVerifiedMicrovmRunReceiptDigest(e.completedRunReceiptDigest, att.claim.projectDir,
            e.completedRunExecutionSpecDigest, e.completedRunGuestExecutionRequestDigest, e.completedRunProjectManifestDigest, e.completedRunResultDigest)) {
        return { verifiedTier: "none", ok: false, verifiedMechanism: "hmac-run-key", reason: "missing-replayed-result-or-project-mismatched-microvm-run-receipt", measuredDegradations: [] };
      }
    }
    const completed = att.claim.tier === "microvm" && backed ? att.claim.evidence : undefined;
    const executionSubjectAuthority = completed?.completedRunProjectManifestDigest
      ? mintExecutionSubjectAuthority(att.claim.projectDir, completed.completedRunProjectManifestDigest)
      : undefined;
    return {
      verifiedTier,
      ok: backed,
      verifiedMechanism,
      reason: backed ? "verified" : `evidence-insufficient: claim=${att.claim.tier} proven=${proven}`,
      // BUILD-ORDER 2.3 — surface the degradations the appraised evidence measured, so the ceiling
      // decision reflects a degraded boundary (net-deny unenforceable, Job Object degraded) and cannot
      // grant the tier's clean ceiling on a proven-but-degraded run.
      measuredDegradations: [...att.claim.evidence.degraded],
      ...(completed?.completedRunReceiptDigest ? { verifiedRunReceiptDigest: completed.completedRunReceiptDigest } : {}),
      ...(completed?.completedRunExecutionSpecDigest ? { verifiedExecutionSpecDigest: completed.completedRunExecutionSpecDigest } : {}),
      ...(completed?.completedRunGuestExecutionRequestDigest ? { verifiedGuestExecutionRequestDigest: completed.completedRunGuestExecutionRequestDigest } : {}),
      ...(completed?.completedRunProjectManifestDigest ? { verifiedProjectManifestDigest: completed.completedRunProjectManifestDigest } : {}),
      ...(completed?.completedRunResultDigest ? { verifiedResultDigest: completed.completedRunResultDigest } : {}),
      ...(completed?.completedRunMeasurementPolicyDigest ? { verifiedMeasurementPolicyDigest: completed.completedRunMeasurementPolicyDigest } : {}),
      ...(executionSubjectAuthority ? { executionSubjectAuthority } : {}),
    };
  }
}

/**
 * Create the ONE run-local attestation channel: an attestor (executor emits) and a verifier (router
 * checks), sharing a fresh ephemeral HMAC key generated per run. The key never persists and never leaves
 * the process — it binds an attestation to THIS run so a fabricated/replayed one (a different key) fails
 * the signature check. A real `TeeVerifier` plugs in behind the same port for hardware attestation.
 */
export function createRunAttestationChannel(opts: { teeVerifier?: TeeVerifier; trustedMicrovmMeasurementPolicyDigests?: readonly string[] } = {}): {
  readonly attestor: IsolationAttestor;
  readonly verifier: IsolationVerifier;
} {
  const key = randomBytes(32);
  return {
    attestor: new HmacAttestor(key),
    verifier: new HmacVerifier(key, opts.teeVerifier, new Set(opts.trustedMicrovmMeasurementPolicyDigests ?? [])),
  };
}

/** Test/VERIFIED-SEAM helpers to construct an attestor/verifier over an EXPLICIT key (e.g. to forge a
 *  cross-run signature, or stand in for a host). Not used on the default path (that uses the run channel). */
export function attestorWithKey(key: Buffer): IsolationAttestor { return new HmacAttestor(key); }
export function verifierWithKey(key: Buffer, teeVerifier?: TeeVerifier): IsolationVerifier { return new HmacVerifier(key, teeVerifier); }

/**
 * The honest evidence a real host of `tier` would MEASURE — for the process floor and for VERIFIED-SEAM
 * stand-ins (a test/host that genuinely represents a stronger tier declares the evidence it would report).
 * It is NOT a way to fake a tier: it is only ever legitimate where the caller truly backs that tier
 * (the probe-measured default path builds its evidence from the real `detect*` probes, not this).
 */
export function processFloorEvidence(platform: string = process.platform): IsolationEvidence {
  return { platform, runtimeKind: "process", kvmPresent: false, imagesPresent: false, jobObjectSupport: false, degraded: [] };
}

/**
 * The VERIFIED-SEAM evidence a host that GENUINELY runs `tier` would MEASURE — for an explicitly-wired
 * host boundary (`selectExecutor`'s `boundaryRun`/`windowsBoundaryRun`) or a test standing in for that
 * host. Honest ONLY where the caller truly backs the tier (the operator vouches by wiring a real
 * boundary; the confused-not-compromised threat model). It is NOT a bypass: the default probe path builds
 * its evidence from the real `detect*` measurements, never this; a strong claim with no real backing
 * defaults to the process floor and recomputes DOWN.
 */
export function seamEvidenceForTier(tier: IsolationTier, platform: string = process.platform): IsolationEvidence {
  switch (tier) {
    case "microvm":
    case "gvisor":
    case "container": return { platform, runtimeKind: "declared-seam", kvmPresent: false, imagesPresent: false, jobObjectSupport: false, degraded: ["no-completed-transaction-receipt"] };
    case "process": return processFloorEvidence(platform);
    case "none": return { platform, runtimeKind: "none", kvmPresent: false, imagesPresent: false, jobObjectSupport: false, degraded: ["no-isolation"] };
  }
}
