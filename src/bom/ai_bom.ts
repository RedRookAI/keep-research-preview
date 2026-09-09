/**
 * Signed AI-BOM (Core Addition B) — a verifiable, tamper-evident manifest of WHAT produced a
 * decision/run: model identity + version, prompt/policy hashes, tool set, the gate-barrier verdicts,
 * and code/config hashes. It answers "what exactly produced this effect, and can we prove it wasn't
 * tampered with."
 *
 * DISCIPLINE (research, 2026-08-09): in-toto / SLSA provenance — a manifest in CANONICAL JSON binding
 * the inputs by digest, whose SHA-256 is the anchor (Kettle: "connect a specific artifact with its
 * inputs without requiring bit-for-bit reproducibility"). Tamper-evidence is by RECOMPUTATION: if a
 * field is modified after recording, the recomputed digest no longer matches the one sealed in the
 * chain — "the provenance will not match." Verifiable, not asserted. Cross-industry: airworthiness
 * tags / pharma chain-of-custody — the manifest travels with the artifact and is checked at each
 * handoff; a missing or failed tag quarantines (fails closed).
 *
 * BUILT vs SEAM: BUILT is the in-env manifest + canonical digest + spine hash-chain tamper-evidence +
 * verification. The real CRYPTOGRAPHIC SIGNING AUTHORITY — a DSSE envelope signed by a key held only
 * by a trusted domain, not reachable by the agent (SLSA L2/L3) — is a SEAM, shared with R25 (key
 * custody). In-env the tamper-evidence is the append-only hash chain (a bad actor can forge a manifest
 * but cannot alter the digest already sealed in the chain without breaking it).
 *
 * DENY-CAPABLE: an unverifiable BOM (missing or digest-mismatched) is a deny-capable gate signal — if
 * you cannot prove what produced an effect, you do not auto-proceed. The BOM never LOOSENS anything.
 *
 * WHAT WOULD CHANGE IT: a richer material set (per-file code digests, resolved dependency lockfile)
 * extends the manifest; real signing upgrades tamper-evidence to authenticity. Neither lets a
 * mismatched manifest verify.
 */

import { createHash } from "node:crypto";
import { canonicalize } from "../spine/event.js";
import type { Spine } from "../spine/spine.js";

/** The gate-barrier verdicts as they stood for this decision (whichever were assessed). */
export interface BarrierVerdicts {
  readonly floor?: string;
  readonly budget?: string;
  readonly actionTier?: string;
  readonly ownerPresent?: boolean;
  readonly provenance?: string;
  readonly twin?: string;
}

/** The manifest. Every field is a decidable fact about the run; the digest binds them together. */
export interface AiBom {
  /** What this BOM attests — a decision/run id and (optionally) the effect's digest. */
  readonly subject: string;
  readonly modelId?: string;
  readonly modelVersion?: string;
  readonly promptHash?: string;
  readonly policyHash?: string;
  readonly toolSet?: readonly string[];
  readonly barriers?: BarrierVerdicts;
  readonly codeHash?: string;
  readonly configHash?: string;
  readonly timestamp: number;
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** The canonical digest of a BOM — deterministic (sorted keys) so it recomputes bit-for-bit. */
export function bomDigest(bom: AiBom): string {
  return sha256Hex(canonicalize(bom));
}

/**
 * Record a BOM to the spine: stage its digest into the append-only hash chain. The manifest travels
 * with the decision; the sealed digest is the tamper-evidence anchor. Returns the digest + event id.
 */
export function recordBom(spine: Spine, bom: AiBom, actor = "ai-bom"): { digest: string; eventId: string } {
  const digest = bomDigest(bom);
  const eventId = spine.stage({
    type: "identity.action",
    actor,
    payload: { event: "ai_bom_recorded", subject: bom.subject, digest },
  });
  return { digest, eventId };
}

export type BomVerification =
  | { readonly verified: true }
  | { readonly verified: false; readonly reason: string };

/**
 * Verify a BOM against the digest that was recorded for it. Recompute the canonical digest and
 * compare. Fails safe: a missing BOM, a missing recorded digest, or a mismatch ⇒ unverifiable.
 */
export function verifyBom(bom: AiBom | undefined, recordedDigest: string | undefined): BomVerification {
  if (bom === undefined) return { verified: false, reason: "no-bom" };
  if (recordedDigest === undefined || recordedDigest === "") return { verified: false, reason: "no-recorded-digest" };
  const recomputed = bomDigest(bom);
  if (recomputed !== recordedDigest) return { verified: false, reason: `digest-mismatch:${recomputed.slice(0, 8)}!=${recordedDigest.slice(0, 8)}` };
  return { verified: true };
}
