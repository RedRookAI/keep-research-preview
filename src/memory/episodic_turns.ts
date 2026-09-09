/**
 * EPISODIC-TURN TRACK (M1) — the raw Track-1 ground truth for the learning loop.
 *
 * The rolling-memory research (2026 SOTA + Multiple Trace / Trace Transformation Theory) is clear on two things:
 * lossy in-band compaction is the most-hated frontier behavior (it drops the exact numbers and decisions agents
 * need), and the brain keeps BOTH a detailed episodic trace and a distilled semantic gist rather than overwriting
 * one with the other. Keep already has the semantic track (Lessons, trust tiers, consolidation/supersede). What it
 * lacked was the raw episodic track: a persistent, append-only record of interaction turns (goal + action +
 * outcome) that retains the exact detail, so retrieval can later blend precise recall with generalized gist.
 *
 * This is that track. It COMPOSES the existing substrate rather than re-inventing it:
 *   - append-only + hash-chained (tamper-evidence, OWASP ASI06 memory-poisoning integrity) — reusing the spine's
 *     `canonicalize` and `ZERO_HASH` so the chain math matches the audit spine.
 *   - per-subject crypto-shred (GDPR Art.17 erasure on an immutable log) — reusing `CryptoShredKeyStore`: the
 *     payload is stored as ciphertext, erasure destroys the subject key, and the chain still verifies (it hashes
 *     over the ciphertext, which remains).
 *   - write-boundary validate/sanitize (poison + secret + copyleft defense) — reusing `scanIngestion`: no raw
 *     untrusted content is persisted; copyleft is rejected, secrets/PII are redacted before encryption.
 *   - provenance + trust on every record — reusing `Origin` / `TrustTier`: untrusted-source turns can NEVER be
 *     written confirmed (poison-dampener; confirmation is earned downstream, never asserted at the write boundary).
 *
 * BUILT + proven in-env: the append-only hash-chained turn store with crypto-shred erasure, write-boundary scan,
 * and provenance/trust capping. SEAM: the similarity/embedding index for relevance retrieval lives in M2 (the
 * context assembler); this module provides addressable recall by key + the full ordered track for M2 to draw from.
 */

import { createHash } from "node:crypto";
import { canonicalize } from "../spine/event.js";
import { ZERO_HASH } from "../spine/hashchain.js";
import { CryptoShredKeyStore, type Ciphertext, type SubjectId } from "../keystore/keystore.js";
import { scanIngestion, type IngestionResult } from "./ingestion.js";
import type { Origin, TrustTier, MemoryScope } from "./model.js";

/** The plaintext content of one interaction turn (before write-boundary scan + encryption). */
export interface TurnContent {
  /** The user/agent goal or instruction for this turn. */
  readonly goal: string;
  /** What Keep did (a short summary), if known at record time. */
  readonly action?: string;
  /** The observed outcome, if known at record time. */
  readonly outcome?: string;
}

/** Provenance + trust inputs for a turn (the security-relevant metadata). */
export interface RecordTurnInput {
  readonly scope: MemoryScope;
  /** The crypto-shred subject (user/tenant) — the unit of isolation and erasure. */
  readonly subject: SubjectId;
  /** Where this turn came from (self = Keep's own loop; external = imported/tool/pasted). */
  readonly origin: Origin;
  readonly content: TurnContent;
  /**
   * Whether the SOURCE is trusted. Self-observed turns are trusted (→ probation); anything from an untrusted
   * source (external doc, tool result, pasted content) is untrusted (→ candidate, the lowest live tier). Neither
   * is ever written `confirmed` — that must be earned by corroborating outcomes downstream (poison-dampener).
   */
  readonly trusted: boolean;
}

/** An append-only, hash-chained episodic-turn record. Payload is ciphertext — never plaintext. */
export interface TurnRecord {
  /** Addressable key (unique within the log). */
  readonly id: string;
  readonly seq: number;
  readonly ts: number;
  readonly scope: MemoryScope;
  readonly subject: SubjectId;
  readonly origin: Origin;
  /** Capped trust: never `confirmed` at the write boundary. */
  readonly trust: TrustTier;
  /** What the write-boundary scan flagged (redacted secrets / PII), for auditability. */
  readonly ingestFindings: readonly string[];
  /** Encrypted, write-boundary-sanitized content. Decryptable only while the subject key lives. */
  readonly payload: Ciphertext;
  readonly prevHash: string;
  readonly hash: string;
}

export type RecordDecision =
  | { readonly status: "recorded"; readonly record: TurnRecord }
  | { readonly status: "rejected"; readonly reason: string; readonly findings: readonly string[] };

export type ReadResult =
  | { readonly status: "ok"; readonly content: TurnContent; readonly meta: TurnRecord }
  | { readonly status: "erased"; readonly meta: TurnRecord }
  | { readonly status: "not-found" };

export interface VerifyResult {
  readonly ok: boolean;
  /** The seq of the first broken link, if any. */
  readonly brokenAt?: number;
}

/** Injectable write-boundary scanner (default = scanIngestion); kept injectable for testing/deployment. */
export type WriteScan = (content: string) => IngestionResult;

/**
 * The episodic-turn log. Append-only: the ONLY mutation is `record`; there is no update or delete. Erasure is
 * crypto-shred (destroy the subject key), which leaves the chain intact and verifiable.
 */
export class EpisodicTurnLog {
  private readonly records: TurnRecord[] = [];
  private seqCounter = 0;

  constructor(
    private readonly keys: CryptoShredKeyStore,
    private readonly clock: () => number = () => Date.now(),
    private readonly scan: WriteScan = scanIngestion,
  ) {}

  /**
   * Derive the write-time trust tier. SECURITY INVARIANT: untrusted sources cap at `candidate`, trusted at
   * `probation` — NEVER `confirmed`. This is the poison-dampener; neutering it (returning `confirmed`) is the
   * disproof for the trust-cap property.
   */
  private deriveTrust(trusted: boolean): TrustTier {
    return trusted ? "probation" : "candidate";
  }

  /**
   * Record one turn. Runs the write-boundary scan (reject copyleft, redact secrets/PII), attaches provenance +
   * capped trust, encrypts the SANITIZED content under the subject key, and hash-chains the record. Append-only.
   */
  record(input: RecordTurnInput): RecordDecision {
    const joined = [input.content.goal, input.content.action ?? "", input.content.outcome ?? ""].join("\n");

    // 1. Write boundary: no raw untrusted content is persisted.
    const scanned = this.scan(joined);
    if (scanned.decision === "reject") {
      return { status: "rejected", reason: "ingestion-reject", findings: scanned.findings };
    }

    // 2. Provenance + capped trust (never confirmed on write).
    const trust = this.deriveTrust(input.trusted);

    // 3. Encrypt the sanitized content under the subject's crypto-shred key.
    this.keys.ensureKey(input.subject);
    const sanitizedContent: TurnContent = reparse(scanned.sanitized, input.content);
    const payload = this.keys.encrypt(input.subject, JSON.stringify(sanitizedContent));

    // 4. Hash-chain the record (over the ciphertext + metadata, so crypto-shred leaves the chain intact).
    const seq = this.seqCounter++;
    const prevHash = this.records.length === 0 ? ZERO_HASH : this.records[this.records.length - 1]!.hash;
    const id = `turn-${seq}`;
    const base = {
      id,
      seq,
      ts: this.clock(),
      scope: input.scope,
      subject: input.subject,
      origin: input.origin,
      trust,
      ingestFindings: scanned.findings,
      payload,
      prevHash,
    };
    const hash = createHash("sha256").update(prevHash + "|" + canonicalize(base)).digest("hex");
    const record: TurnRecord = { ...base, hash };
    this.records.push(record);
    return { status: "recorded", record };
  }

  /** Addressable recall: fetch a specific prior turn's metadata by key. */
  getTurn(id: string): TurnRecord | undefined {
    return this.records.find((r) => r.id === id);
  }

  /**
   * Read a turn's decrypted content. Returns `erased` (not a throw) if the subject has been crypto-shredded —
   * so callers can distinguish "gone by erasure" from "never existed".
   */
  read(id: string): ReadResult {
    const rec = this.getTurn(id);
    if (!rec) return { status: "not-found" };
    if (!this.keys.hasKey(rec.subject)) return { status: "erased", meta: rec };
    try {
      const content = JSON.parse(this.keys.decrypt(rec.subject, rec.payload)) as TurnContent;
      return { status: "ok", content, meta: rec };
    } catch {
      return { status: "erased", meta: rec };
    }
  }

  /** The full ordered track (metadata; addressable). Returns a copy — the internal log is append-only. */
  all(): readonly TurnRecord[] {
    return this.records.slice();
  }

  /** Number of records. */
  size(): number {
    return this.records.length;
  }

  /**
   * Crypto-shred erasure for a subject (GDPR Art.17). Delegates to the key store's two-phase audited destroy;
   * the subject's turn payloads become unrecoverable while their records — and the chain — remain and verify.
   */
  eraseSubject(subject: SubjectId): boolean {
    return this.keys.shred(subject);
  }

  /**
   * Re-walk the hash-chain to detect tampering. Any mutation of a historical record changes its hash and breaks
   * every subsequent link. Returns the first broken seq if any.
   */
  verifyChain(): VerifyResult {
    let prev = ZERO_HASH;
    for (const rec of this.records) {
      if (rec.prevHash !== prev) return { ok: false, brokenAt: rec.seq };
      const { hash: _h, ...base } = rec;
      const expected = createHash("sha256").update(prev + "|" + canonicalize(base)).digest("hex");
      if (expected !== rec.hash) return { ok: false, brokenAt: rec.seq };
      prev = rec.hash;
    }
    return { ok: true };
  }
}

/**
 * Rebuild a structured TurnContent from the write-boundary-sanitized joined string. The scan may have redacted
 * secrets, so we keep the sanitized text as the goal-line-and-beyond; the original structure is best-effort
 * reconstructed by splitting on the join boundaries, defaulting to a single sanitized goal when redaction changed
 * the shape. This keeps the STORED content sanitized (the security property) without over-engineering structure.
 */
function reparse(sanitized: string, original: TurnContent): TurnContent {
  const parts = sanitized.split("\n");
  const goal = parts[0] ?? "";
  const out: { goal: string; action?: string; outcome?: string } = { goal };
  if (original.action !== undefined) out.action = parts[1] ?? "";
  if (original.outcome !== undefined) out.outcome = parts[2] ?? "";
  return out;
}
