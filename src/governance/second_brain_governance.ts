/**
 * SECOND-BRAIN GOVERNANCE & COMPLIANCE EVIDENCE — Teams/Enterprise arc, T4.
 *
 * Enterprise adoption gates on data governance: DSAR (data-subject access requests), ROPA (record of processing),
 * retention, and DATA RESIDENCY (an enterprise dealbreaker — EU/in-country). Keep has these primitives for the
 * code-build side, but they were never wired over the second brain's NEW stores (memory + CI vault + portability).
 * This module closes that: a DSAR/ROPA evidence capability over the second brain, with residency enforcement and
 * evidenced (crypto-shred) erasure.
 *
 * The load-bearing property is COMPLETENESS: an evidence pack must enumerate the subject's holdings across EVERY
 * store — a missing store is a compliance failure, not a rounding error.
 *
 * STANDING PRINCIPLE — two tracks sharing ONE mechanism, never collapse to N=1:
 *   - N=1 FLOOR: the sole owner's self-serve data receipt — their holdings + their own export/erase (R8), zero org
 *     setup, no compliance officer required.
 *   - org CEILING: a compliance officer's evidence pack across users (DSAR fulfilment, residency, evidenced erase).
 * Same underlying mechanism (enumerate across stores → residency check → evidenced erase), two surfaces.
 *
 * BUILT + proven in-env: completeness (over every store) + residency enforcement + evidenced erasure. SEAM: the
 * regulator-format / org-directory source (a datum's region and subject association).
 */

import { ResidencyEnforcer, type ResidencyPolicy } from "./residency.js";
import { erase, type Receipt } from "../portability/portability.js";
import type { MemoryStore } from "../memory/store.js";
import type { SensitiveContextVault } from "../privacy/contextual_integrity.js";
import type { CryptoShredKeyStore } from "../keystore/keystore.js";

/** One datum the second brain holds about a subject (for the DSAR record). */
export interface HeldRecord {
  readonly store: "memory" | "vault";
  readonly id: string;
  readonly summary: string; // WHAT is held (metadata; not the raw special-category content)
  readonly region: string;
}

export interface SecondBrainEvidence {
  readonly subject: string;
  readonly records: readonly HeldRecord[];
  readonly residencyOk: boolean;
  readonly residencyViolations: readonly string[]; // ids of records in a disallowed region
}

export interface EvidenceDeps {
  readonly memory: MemoryStore;
  readonly vault: SensitiveContextVault;
  readonly residency: ResidencyPolicy;
  /** SEAM: a datum's region (default "eu"). */
  readonly regionOf?: ((store: "memory" | "vault", id: string) => string) | undefined;
  /** SEAM: which memories belong to the subject (default: all memories are the subject's — single-owner brain). */
  readonly subjectOf?: ((lessonId: string) => string) | undefined;
}

/**
 * Enumerate what the second brain holds about `subject` across BOTH stores (memory + vault) — a COMPLETE DSAR
 * record — and flag any record whose region violates the required residency.
 */
export function secondBrainEvidence(subject: string, deps: EvidenceDeps): SecondBrainEvidence {
  const regionOf = deps.regionOf ?? ((): string => "eu");
  const subjectOf = deps.subjectOf ?? ((): string => subject);
  const enforcer = new ResidencyEnforcer(deps.residency);
  const records: HeldRecord[] = [];

  // memory store — the subject's non-retired lessons
  for (const l of deps.memory.all()) {
    if (l.tier === "retired") continue;
    if (subjectOf(l.id) !== subject) continue;
    records.push({ store: "memory", id: l.id, summary: `memory:${l.tier}:${l.scope}`, region: regionOf("memory", l.id) });
  }

  // CI vault — the subject's special-category disclosures (metadata only)
  for (const rec of deps.vault.revealToSubject(subject)) {
    records.push({ store: "vault", id: rec.entry.id, summary: `vault:${rec.entry.informationType}`, region: regionOf("vault", rec.entry.id) });
  }

  const residencyViolations: string[] = [];
  for (const r of records) {
    if (!enforcer.checkRegion(r.region).allowed) residencyViolations.push(r.id);
  }

  return { subject, records, residencyOk: residencyViolations.length === 0, residencyViolations };
}

export interface ErasureEvidence {
  readonly receipt: Receipt;
  readonly unreadable: boolean; // the subject's vaulted context is unreadable after erasure
}

export interface ErasureDeps {
  readonly keystore: CryptoShredKeyStore;
  readonly vault: SensitiveContextVault;
  /** The vault's key subject (the ProjectId whose crypto-shred makes the vault unreadable). */
  readonly projectKeySubject: string;
}

/**
 * Evidenced erasure: compose R8's crypto-shred `erase` and return a verifiable receipt, then confirm the subject's
 * vaulted context is unreadable (a soft-delete that leaves it readable is a compliance failure).
 */
export function secondBrainErase(subject: string, deps: ErasureDeps): ErasureEvidence {
  const receipt = erase(deps.keystore, deps.projectKeySubject); // crypto-shred the vault's project key
  let unreadable = false;
  try {
    deps.vault.revealToSubject(subject); // should now throw (key shredded)
  } catch {
    unreadable = true;
  }
  return { receipt, unreadable };
}
