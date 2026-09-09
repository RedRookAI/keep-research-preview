/**
 * Crypto-shred key store (Round 15) — GDPR-endorsed erasure on an immutable log.
 *
 * The paradox: the spine is immutable (tamper-evidence), but GDPR Art. 17 requires
 * erasure. Resolution (explicitly endorsed by 2026 guidance): encrypt sensitive
 * data per-subject; store only ciphertext + a hash in the chain. Erasure destroys
 * the subject's key -> the ciphertext becomes unrecoverable noise, while the chain
 * is untouched and still verifies.
 *
 * This store is Phase 0 foundation: backup encryption (R17) and cryptographic
 * per-tenant namespaces (R19) reuse these keys.
 *
 * Node's crypto only (AES-256-GCM). In-memory key registry for the zero-dependency
 * tier; a KMS/Vault-backed impl drops in behind the same shape later.
 */

import { randomBytes, createCipheriv, createDecipheriv, createHash, createHmac } from "node:crypto";

export type SubjectId = string;

export interface Ciphertext {
  /** AES-256-GCM: iv | authTag | data, all hex. */
  readonly iv: string;
  readonly authTag: string;
  readonly data: string;
  /** Optional transient content identity. Never persist it with secret-bearing ciphertext. */
  readonly plaintextHash?: string;
}

export type ErasurePhase = "requested" | "confirmed";

/** Recorder hook so every key-destruction is auditable in the spine (two-phase). */
export type ErasureAuditor = (subject: SubjectId, phase: ErasurePhase) => void;

const ALGO = "aes-256-gcm";

/** Durable storage seam for raw subject keys. Implementations must persist them protected at rest. */
export interface KeyPersistence {
  load(): ReadonlyMap<SubjectId, Buffer>;
  save(subject: SubjectId, key: Buffer): void;
  delete(subject: SubjectId): void;
}

export class CryptoShredKeyStore {
  /** subject -> 32-byte key. Deleting the entry is the crypto-shred. */
  private readonly keys = new Map<SubjectId, Buffer>();
  private readonly auditors: ErasureAuditor[] = [];

  constructor(private readonly persistence?: KeyPersistence) {
    for (const [subject, key] of persistence?.load() ?? []) {
      if (typeof subject !== "string" || subject.length === 0 || key.length !== 32) {
        throw new Error(`invalid persisted key for subject ${JSON.stringify(subject)}`);
      }
      this.keys.set(subject, Buffer.from(key));
    }
  }

  /** Register an auditor (e.g. one that appends key_shredded events to the spine). */
  onErasure(a: ErasureAuditor): void {
    this.auditors.push(a);
  }

  /** Ensure a subject has a key, creating one if absent. Returns whether it was created. */
  ensureKey(subject: SubjectId): boolean {
    if (this.keys.has(subject)) return false;
    const key = randomBytes(32);
    this.persistence?.save(subject, key);
    this.keys.set(subject, key);
    return true;
  }

  hasKey(subject: SubjectId): boolean {
    return this.keys.has(subject);
  }

  /** Reconcile a long-lived process with durable key authority changed by another process. */
  refresh(): void {
    if (this.persistence === undefined) return;
    const durable = this.persistence.load();
    for (const subject of [...this.keys.keys()]) if (!durable.has(subject)) this.keys.delete(subject);
    for (const [subject, key] of durable) {
      if (typeof subject !== "string" || subject.length === 0 || key.length !== 32) throw new Error(`invalid persisted key for subject ${JSON.stringify(subject)}`);
      this.keys.set(subject, Buffer.from(key));
    }
  }

  encrypt(subject: SubjectId, plaintext: string): Ciphertext {
    const key = this.keys.get(subject);
    if (!key) throw new Error(`no key for subject ${subject} (create with ensureKey first)`);
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGO, key, iv);
    const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return {
      iv: iv.toString("hex"),
      authTag: authTag.toString("hex"),
      data: enc.toString("hex"),
      plaintextHash: createHash("sha256").update(plaintext, "utf8").digest("hex"),
    };
  }

  /**
   * Decrypt. Throws if the subject's key has been shredded — which is the whole
   * point: post-erasure the data is unrecoverable.
   */
  decrypt(subject: SubjectId, c: Ciphertext): string {
    const key = this.keys.get(subject);
    if (!key) throw new Error(`subject ${subject} has been erased (key shredded)`);
    const decipher = createDecipheriv(ALGO, key, Buffer.from(c.iv, "hex"));
    decipher.setAuthTag(Buffer.from(c.authTag, "hex"));
    const dec = Buffer.concat([decipher.update(Buffer.from(c.data, "hex")), decipher.final()]);
    return dec.toString("utf8");
  }

  /** Stable project/subject-local pseudonym. Destroying the subject key destroys future linkability. */
  pseudonym(subject: SubjectId, domain: string, value: string): string {
    const key = this.keys.get(subject);
    if (!key) throw new Error(`no key for subject ${subject}`);
    return createHmac("sha256", key).update(domain).update("\0").update(value).digest("hex");
  }

  /**
   * Crypto-shred: destroy the subject's key. Irreversible. Two-phase audit
   * (requested -> confirmed) per the Aug-2026 SOTA refinement, since key
   * destruction is irreversible and the audit trail must survive it.
   *
   * NOTE: a production deployment adds a deferred cooling-off window (CNIL ~30d,
   * cancellable) before this is called; here we expose the atomic destroy + audit.
   */
  shred(subject: SubjectId): boolean {
    if (!this.keys.has(subject)) return false;
    for (const a of this.auditors) a(subject, "requested");
    this.persistence?.delete(subject);
    this.keys.delete(subject);
    for (const a of this.auditors) a(subject, "confirmed");
    return true;
  }
}
