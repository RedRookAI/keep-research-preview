import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import {
  chmodSync,
  constants,
  closeSync,
  existsSync,
  fsyncSync,
  fstatSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";

import { ensureDurableDir, fsyncDir, NODE_IO } from "../spine/durable_fs.js";
import type { KeyPersistence, SubjectId } from "./keystore.js";
import { withSyncFileMutationLock } from "../spine/sync_file_mutation_lock.js";

interface WrappedKey { readonly iv: string; readonly authTag: string; readonly ciphertext: string; }
interface WrappedKeyFile { readonly version: 1; readonly keys: Record<string, WrappedKey>; }

export interface FileWrappedKeyPersistenceOptions {
  readonly masterKeyPath: string;
  readonly wrappedKeysPath: string;
  /** Established custody must never silently initialize a replacement master key. */
  readonly requireExistingMasterKey?: boolean;
  readonly allowStaleTakeover?: boolean;
}

const ALGO = "aes-256-gcm";
const MAX_KEYS = 100_000;
const MAX_KEY_FILE_BYTES = 64 * 1024 * 1024;

function validSubject(subject: string): boolean {
  return subject.length > 0 && Buffer.byteLength(subject, "utf8") <= 4_096 && !/[\u0000-\u001f\u007f]/u.test(subject);
}

function validateWrapped(value: unknown, subject: string): WrappedKey {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`invalid wrapped key for ${subject}`);
  const row = value as Record<string, unknown>;
  if (Object.keys(row).sort().join(",") !== "authTag,ciphertext,iv") throw new Error(`invalid wrapped key fields for ${subject}`);
  if (typeof row.iv !== "string" || !/^[0-9a-f]{24}$/iu.test(row.iv)
    || typeof row.authTag !== "string" || !/^[0-9a-f]{32}$/iu.test(row.authTag)
    || typeof row.ciphertext !== "string" || !/^[0-9a-f]{64}$/iu.test(row.ciphertext)) {
    throw new Error(`invalid wrapped key encoding for ${subject}`);
  }
  return { iv: row.iv, authTag: row.authTag, ciphertext: row.ciphertext };
}

export class FileWrappedKeyPersistence implements KeyPersistence {
  private readonly masterKey: Buffer;

  constructor(private readonly options: FileWrappedKeyPersistenceOptions) {
    if (options.masterKeyPath === options.wrappedKeysPath) throw new Error("master key and wrapped-key file must be distinct");
    this.masterKey = this.readOrCreateMasterKey();
  }

  load(): ReadonlyMap<SubjectId, Buffer> {
    const keys = new Map<SubjectId, Buffer>();
    for (const [subject, wrapped] of Object.entries(this.readRecords())) {
      try {
        const decipher = createDecipheriv(ALGO, this.masterKey, Buffer.from(wrapped.iv, "hex"));
        decipher.setAAD(Buffer.from(subject, "utf8"));
        decipher.setAuthTag(Buffer.from(wrapped.authTag, "hex"));
        const key = Buffer.concat([decipher.update(Buffer.from(wrapped.ciphertext, "hex")), decipher.final()]);
        if (key.length !== 32) throw new Error("invalid key length");
        keys.set(subject, key);
      } catch (cause) {
        throw new Error(`cannot authenticate persisted key for subject ${subject}`, { cause });
      }
    }
    return keys;
  }

  save(subject: SubjectId, key: Buffer): void {
    if (!validSubject(subject)) throw new Error("invalid key subject");
    if (key.length !== 32) throw new Error("project keys must be 32 bytes");
    withSyncFileMutationLock(this.options.wrappedKeysPath, () => {
      const prior = this.readRecords();
      if (!(subject in prior) && Object.keys(prior).length >= MAX_KEYS) throw new Error(`wrapped-key store exceeds ${MAX_KEYS} subjects`);
      const iv = randomBytes(12);
      const cipher = createCipheriv(ALGO, this.masterKey, iv);
      cipher.setAAD(Buffer.from(subject, "utf8"));
      const ciphertext = Buffer.concat([cipher.update(key), cipher.final()]);
      const next = Object.assign(Object.create(null) as Record<string, WrappedKey>, prior, {
        [subject]: { iv: iv.toString("hex"), authTag: cipher.getAuthTag().toString("hex"), ciphertext: ciphertext.toString("hex") },
      });
      this.writeRecords(next);
    }, { ...(this.options.allowStaleTakeover === undefined ? {} : { allowStaleTakeover: this.options.allowStaleTakeover }) });
  }

  delete(subject: SubjectId): void {
    this.deleteMany([subject]);
  }

  /** One durable key-map replacement for an admitted memory derivative closure. */
  deleteMany(subjects: readonly SubjectId[]): void {
    if (subjects.length > MAX_KEYS || subjects.some(subject => !validSubject(subject))) throw new Error("invalid deletion subjects");
    const captured = [...new Set(subjects)];
    withSyncFileMutationLock(this.options.wrappedKeysPath, () => {
      const prior = this.readRecords();
      // Re-publish even an already-absent key: absence after an uncertain rename is
      // not durable erasure evidence until the map and directory are synced.
      const next = Object.assign(Object.create(null) as Record<string, WrappedKey>, prior);
      for (const subject of captured) delete next[subject];
      this.writeRecords(next);
    }, { ...(this.options.allowStaleTakeover === undefined ? {} : { allowStaleTakeover: this.options.allowStaleTakeover }) });
  }

  private readOrCreateMasterKey(): Buffer {
    if (this.options.requireExistingMasterKey) {
      const fd = openSync(this.options.masterKeyPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        const stat = fstatSync(fd);
        if (!stat.isFile() || stat.size !== 32 || (stat.mode & 0o077) !== 0) throw new Error("established master key must be a private 32-byte regular file");
        const key = readFileSync(fd);
        if (key.length !== 32) throw new Error("established master key changed while reading");
        return key;
      } finally { closeSync(fd); }
    }
    const dir = dirname(this.options.masterKeyPath);
    ensureDurableDir(NODE_IO, dir);
    let created = false;
    if (!existsSync(this.options.masterKeyPath)) {
      const key = randomBytes(32);
      let fd: number | undefined;
      try {
        fd = openSync(this.options.masterKeyPath, "wx", 0o600);
        for (let offset = 0; offset < key.length;) {
          const written = writeSync(fd, key, offset, key.length - offset);
          if (written <= 0) throw new Error("master-key write made no progress");
          offset += written;
        }
        fsyncSync(fd);
        created = true;
      } catch (cause) {
        if (!existsSync(this.options.masterKeyPath)) throw cause;
      } finally { if (fd !== undefined) closeSync(fd); }
    }
    if (created) fsyncDir(NODE_IO, dir);
    const key = readFileSync(this.options.masterKeyPath);
    if (key.length !== 32 || !statSync(this.options.masterKeyPath).isFile()) throw new Error("local master key must be a 32-byte regular file");
    chmodSync(this.options.masterKeyPath, 0o600);
    return key;
  }

  private readRecords(): Record<string, WrappedKey> {
    if (!existsSync(this.options.wrappedKeysPath)) return Object.create(null) as Record<string, WrappedKey>;
    if (statSync(this.options.wrappedKeysPath).size > MAX_KEY_FILE_BYTES) throw new Error("wrapped-key file is oversized");
    try {
      const parsed = JSON.parse(readFileSync(this.options.wrappedKeysPath, "utf8")) as Partial<WrappedKeyFile>;
      if (parsed.version !== 1 || typeof parsed.keys !== "object" || parsed.keys === null || Array.isArray(parsed.keys)) throw new Error("invalid wrapped-key file format");
      const entries = Object.entries(parsed.keys);
      if (entries.length > MAX_KEYS) throw new Error("wrapped-key file has too many subjects");
      const records = Object.create(null) as Record<string, WrappedKey>;
      for (const [subject, value] of entries) {
        if (!validSubject(subject)) throw new Error("invalid wrapped-key subject");
        records[subject] = validateWrapped(value, subject);
      }
      return records;
    } catch (cause) { throw new Error("cannot read wrapped-key file", { cause }); }
  }

  private writeRecords(records: Record<string, WrappedKey>): void {
    const bytes = Buffer.from(JSON.stringify({ version: 1, keys: records }), "utf8");
    if (bytes.byteLength > MAX_KEY_FILE_BYTES) throw new Error("wrapped-key file is oversized");
    const dir = dirname(this.options.wrappedKeysPath);
    ensureDurableDir(NODE_IO, dir);
    const temporaryPath = `${this.options.wrappedKeysPath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    let fd: number | undefined;
    try {
      fd = openSync(temporaryPath, "wx", 0o600);
      for (let offset = 0; offset < bytes.length;) {
        const written = writeSync(fd, bytes, offset, bytes.length - offset);
        if (written <= 0) throw new Error("wrapped-key write made no progress");
        offset += written;
      }
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      renameSync(temporaryPath, this.options.wrappedKeysPath);
      chmodSync(this.options.wrappedKeysPath, 0o600);
      fsyncDir(NODE_IO, dir);
    } catch (error) {
      if (fd !== undefined) { try { closeSync(fd); } catch { /* preserve original failure */ } }
      try { unlinkSync(temporaryPath); } catch { /* absent or already renamed */ }
      throw error;
    }
  }
}
