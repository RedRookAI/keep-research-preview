/**
 * Signed evidence pack + compliance export (Phase 5, #30 + #36).
 *
 * Generates a regime-versioned evidence pack from the governance trail:
 *  - CRYPTOGRAPHICALLY SIGNED + OFFLINE-VERIFIABLE (2026 sharpening — evidence packs
 *    are signed and offline-verifiable, e.g. Proofpane). We sign over the canonical
 *    content; a verifier needs only the pack + key, no live service.
 *  - AUDIT-READY, NOT CERTIFIED — labeled explicitly. Keep's USER is the legal
 *    "provider" under the AI Act (they place/substantially-modify the system); Keep
 *    makes them audit-ready, it is not itself certified.
 *  - Framework CROSSWALKS (EU AI Act <-> NIST AI RMF <-> ISO 42001) — map once,
 *    comply across (~60% less duplicate work).
 *  - Cites legal basis + date + regime version (the regime is versioned; a further
 *    Omnibus package is expected, so packs stay basis-cited).
 */

import { createHmac } from "node:crypto";
import type { GovernanceRecord } from "./decision_record.js";
import { canonicalize } from "../spine/event.js";

export type ComplianceStatus = "Full" | "Partial" | "Reference";

export interface ControlCoverage {
  readonly control: string;
  readonly status: ComplianceStatus;
  readonly evidence: string;
  /** Crosswalk: the equivalent controls in other frameworks. */
  readonly crosswalk: { readonly nistAiRmf?: string; readonly iso42001?: string };
}

export interface EvidencePack {
  readonly regimeVersion: string;
  readonly legalBasis: string;
  readonly generatedTs: number;
  /** ALWAYS present — the honesty label. */
  readonly disclaimer: string;
  readonly decisionCount: number;
  /** Summary of enforcement outcomes over the trail. */
  readonly outcomeSummary: Record<string, number>;
  readonly controls: readonly ControlCoverage[];
  /** Hash-chain anchor from the governance trail (tamper-evidence reference). */
  readonly trailDigest: string;
}

export interface SignedEvidencePack {
  readonly pack: EvidencePack;
  /** HMAC-SHA256 over the canonical pack; offline-verifiable with the key. */
  readonly signature: string;
  readonly algorithm: "HMAC-SHA256";
}

const DISCLAIMER =
  "AUDIT-READY, NOT CERTIFIED. This pack is machine-generated evidence retained in the " +
  "operator's trust boundary. Under the EU AI Act, the operator who places or substantially " +
  "modifies the system is the 'provider' and is responsible for conformity; Keep is not a " +
  "certified system and this pack is not a certificate.";

/** The default control crosswalk Keep's architecture evidences. */
export function defaultControls(): ControlCoverage[] {
  return [
    {
      control: "EU AI Act Art. 12 — record-keeping / logging",
      status: "Full",
      evidence: "Hash-chained event spine records every decision with provenance.",
      crosswalk: { nistAiRmf: "MEASURE 2.x (traceability)", iso42001: "A.6.2.8 (event logging)" },
    },
    {
      control: "EU AI Act Art. 14 — human oversight",
      status: "Full",
      evidence: "Human merge/approval gate is a boot-level invariant; irreversible actions require approval.",
      crosswalk: { nistAiRmf: "MANAGE 2.x (oversight)", iso42001: "A.9.2 (human oversight)" },
    },
    {
      control: "EU AI Act Art. 15 — accuracy/robustness/security",
      status: "Partial",
      evidence: "Heterogeneous review + security verifier + two-gate memory; kill-switch + rollback.",
      crosswalk: { nistAiRmf: "MEASURE 2.7 (security/resilience)", iso42001: "A.8.3 (system integrity)" },
    },
    {
      control: "EU AI Act Art. 10 — data governance",
      status: "Partial",
      evidence: "Ingestion gate (PII/secret redaction, copyleft rejection); crypto-shred erasure.",
      crosswalk: { nistAiRmf: "MAP 2.x (data)", iso42001: "A.7.x (data for AI systems)" },
    },
    {
      control: "EU AI Act Art. 9 — risk management",
      status: "Partial",
      evidence: "Reversibility×blast-radius tiering; confidence-gated escalation; shadow-mode.",
      crosswalk: { nistAiRmf: "GOVERN/MAP/MEASURE/MANAGE", iso42001: "Clause 6.1 (risk)" },
    },
  ];
}

export class ComplianceExporter {
  constructor(
    private readonly regimeVersion: string,
    private readonly legalBasis: string,
    /** Signing key (from the Phase 0 keystore in a real deploy). */
    private readonly signingKey: Buffer,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  /** Build a (regime-versioned, honesty-labeled) evidence pack from the trail. */
  buildPack(trail: readonly GovernanceRecord[], controls: readonly ControlCoverage[] = defaultControls()): EvidencePack {
    const outcomeSummary: Record<string, number> = {};
    for (const r of trail) outcomeSummary[r.outcome] = (outcomeSummary[r.outcome] ?? 0) + 1;
    return {
      regimeVersion: this.regimeVersion,
      legalBasis: this.legalBasis,
      generatedTs: this.clock(),
      disclaimer: DISCLAIMER,
      decisionCount: trail.length,
      outcomeSummary,
      controls,
      trailDigest: digestTrail(trail),
    };
  }

  /** Sign a pack (HMAC-SHA256 over canonical content) for offline verification. */
  sign(pack: EvidencePack): SignedEvidencePack {
    const signature = createHmac("sha256", this.signingKey).update(canonicalize(pack), "utf8").digest("hex");
    return { pack, signature, algorithm: "HMAC-SHA256" };
  }

  /** Verify a signed pack offline (needs only the pack + key). */
  static verify(signed: SignedEvidencePack, key: Buffer): boolean {
    const expected = createHmac("sha256", key).update(canonicalize(signed.pack), "utf8").digest("hex");
    // Constant-time-ish compare.
    if (expected.length !== signed.signature.length) return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signed.signature.charCodeAt(i);
    return diff === 0;
  }
}

function digestTrail(trail: readonly GovernanceRecord[]): string {
  return createHmac("sha256", "trail-digest").update(canonicalize(trail.map((r) => r.spineEventId)), "utf8").digest("hex");
}
