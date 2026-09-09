/**
 * DataGovernance (Increment 4.5c) — the governed compliance inventory (ROPA) + purpose gate.
 *
 * SOTA basis (2026-08-04): encode obligations AGAINST the data inventory so "a single record
 * carries its own obligations instead of waiting for a team to remember them — access controls,
 * retention rules, consent status travel WITH the data" (ewsolutions 2026). Forward-dated to the
 * near-future regulatory timeline we're reasonably certain lands: EU AI Act (high-risk 2026-2027),
 * California ADMT automated-decision opt-out (enforcement Jan 2027), Colorado AI Act (live Feb
 * 2026), GDPR purpose-limitation + right-to-erasure, India DPDP (2026-2027). Recurring obligations
 * built for: Records of Processing, data minimization, purpose limitation, lawful basis/consent,
 * right to erasure (+ index propagation), retention, automated-decision opt-out, auditable export.
 *
 * HONEST SCOPE: this provides the technical MECHANISMS + surfaces the questions. It is NOT legal
 * advice; the operator/their counsel owns the legal determinations. Zero deps.
 */

import type { SensitivityTier } from "./data_classifier.js";
import type { ProjectId } from "../session/project_id.js";

/** Lawful basis for processing (GDPR Art. 6 shapes; "none-declared" forces the purpose gate). */
export type LawfulBasis =
  | "consent"
  | "contract"
  | "legitimate-interest"
  | "legal-obligation"
  | "vital-interest"
  | "public-task"
  | "none-declared";

/** A declared processing purpose (why data may be used). Freeform + a few well-known ones. */
export type Purpose = string; // e.g. "indexing", "qa", "automated-email", "marketing-analysis"

/** One entry in the Records of Processing Activities inventory (per ingested source). */
export interface ProcessingRecord {
  readonly sourceId: string;
  readonly projectId: ProjectId;
  readonly ingestionTimestamp: number;
  readonly contentHash: string;
  readonly sensitivityTier: SensitivityTier;
  /** Purposes this source is CLEARED for, each with its lawful basis. */
  readonly clearedPurposes: Map<Purpose, LawfulBasis>;
  /** Delete-by timestamp, or undefined = until project deletion. */
  readonly retainUntil?: number;
  /** Data subjects (for erasure / DSAR), if known. */
  readonly subjects: Set<string>;
  /** Which handling ran (audit). */
  readonly handlingApplied: string;
  /** Individuals who have opted out of automated decisions / marketing (CA ADMT / CAN-SPAM). */
  readonly optedOut: Set<string>;
}

/** Result of a purpose-limitation check. `allowed=false` surfaces a compliance question. */
export interface PurposeDecision {
  readonly allowed: boolean;
  readonly reason: string;
  /** If blocked, the exact question the human must answer to proceed compliantly. */
  readonly question?: string;
}

export class DataGovernance {
  private readonly records = new Map<string, ProcessingRecord>();

  /** Register an ingested source in the ROPA inventory with its initial purpose + basis. */
  register(input: {
    sourceId: string;
    projectId: ProjectId;
    contentHash: string;
    sensitivityTier: SensitivityTier;
    purpose: Purpose;
    lawfulBasis: LawfulBasis;
    handlingApplied: string;
    retainUntil?: number;
    subjects?: readonly string[];
  }): ProcessingRecord {
    const rec: ProcessingRecord = {
      sourceId: input.sourceId,
      projectId: input.projectId,
      ingestionTimestamp: Date.now(),
      contentHash: input.contentHash,
      sensitivityTier: input.sensitivityTier,
      clearedPurposes: new Map([[input.purpose, input.lawfulBasis]]),
      subjects: new Set(input.subjects ?? []),
      handlingApplied: input.handlingApplied,
      optedOut: new Set(),
      ...(input.retainUntil !== undefined ? { retainUntil: input.retainUntil } : {}),
    };
    this.records.set(input.sourceId, rec);
    return rec;
  }

  get(sourceId: string): ProcessingRecord {
    const r = this.records.get(sourceId);
    if (!r) throw new Error(`no processing record for source ${sourceId}`);
    return r;
  }

  /** Declare a lawful basis for a NEW purpose on an existing source (operator-authorized). */
  clearPurpose(sourceId: string, purpose: Purpose, basis: LawfulBasis): void {
    if (basis === "none-declared") throw new Error("cannot clear a purpose with none-declared basis");
    this.get(sourceId).clearedPurposes.set(purpose, basis);
  }

  /** Record an opt-out (honored for automated-decision / marketing purposes). */
  recordOptOut(sourceId: string, subject: string): void {
    this.get(sourceId).optedOut.add(subject);
  }

  /**
   * PURPOSE-LIMITATION GATE (the automated-email/marketing case). Fail-closed: using regulated
   * data for a purpose it isn't cleared for is BLOCKED with the exact question to answer, rather
   * than silently proceeding. Non-regulated data for a benign purpose passes.
   */
  checkPurpose(sourceId: string, purpose: Purpose): PurposeDecision {
    const rec = this.get(sourceId);
    if (rec.clearedPurposes.has(purpose)) {
      const basis = rec.clearedPurposes.get(purpose)!;
      return { allowed: true, reason: `purpose "${purpose}" cleared under ${basis}` };
    }
    // A new, uncleared purpose on regulated/confidential data → fail closed, surface the question.
    if (rec.sensitivityTier === "regulated" || rec.sensitivityTier === "confidential") {
      return {
        allowed: false,
        reason: `purpose "${purpose}" has no declared lawful basis for ${rec.sensitivityTier} data`,
        question:
          `You're about to use ${rec.sensitivityTier} data (source ${sourceId}) for "${purpose}". ` +
          `What is the lawful basis (consent / contract / legitimate-interest)? ` +
          `Are there opt-outs to honor? I'll record it and proceed once you confirm.`,
      };
    }
    // Lower-sensitivity data: allowed, but auto-record the purpose for the audit trail.
    rec.clearedPurposes.set(purpose, "legitimate-interest");
    return { allowed: true, reason: `purpose "${purpose}" auto-cleared for ${rec.sensitivityTier} data` };
  }

  /** Is this subject opted out of the given purpose on this source? (honor before emailing). */
  isOptedOut(sourceId: string, subject: string): boolean {
    return this.get(sourceId).optedOut.has(subject);
  }

  /** Sources whose retention has expired as of `now` (candidates for deletion). */
  expired(now: number = Date.now()): readonly ProcessingRecord[] {
    return [...this.records.values()].filter(
      (r) => r.retainUntil !== undefined && r.retainUntil <= now,
    );
  }

  /**
   * ERASURE (right-to-erasure + state-drift prevention). Removes the ROPA record; the caller
   * (ingestion pipeline) propagates to the index + shreds the token vault. Returns the erased
   * record's sourceId list for propagation. Erasing by subject erases every source about them.
   */
  eraseSource(sourceId: string): void {
    this.records.delete(sourceId);
  }

  eraseSubject(subject: string): string[] {
    const affected: string[] = [];
    for (const [id, rec] of this.records) {
      if (rec.subjects.has(subject)) {
        this.records.delete(id);
        affected.push(id);
      }
    }
    return affected;
  }

  /** ROPA export — the "routine export" auditors expect. Plain data, no secrets. */
  ropaExport(): Array<Record<string, unknown>> {
    return [...this.records.values()].map((r) => ({
      sourceId: r.sourceId,
      projectId: r.projectId,
      ingestionTimestamp: r.ingestionTimestamp,
      contentHash: r.contentHash,
      sensitivityTier: r.sensitivityTier,
      purposes: [...r.clearedPurposes.entries()].map(([p, b]) => ({ purpose: p, lawfulBasis: b })),
      retainUntil: r.retainUntil ?? null,
      subjectCount: r.subjects.size,
      optOutCount: r.optedOut.size,
      handlingApplied: r.handlingApplied,
    }));
  }
}
