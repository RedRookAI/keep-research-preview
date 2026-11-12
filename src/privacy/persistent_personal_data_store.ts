import { randomUUID } from "node:crypto";
import {
  closeSync,
  chmodSync,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

import { CryptoShredKeyStore, type Ciphertext, type SubjectId } from "../keystore/keystore.js";
import { ensureDurableDir, fsyncDir, NODE_IO } from "../spine/durable_fs.js";

export type PersonalDataKind = "surrogate" | "cue" | "preference";

export interface PersonalDataItem {
  readonly id: string;
  readonly kind: PersonalDataKind;
  readonly label: string;
  readonly value: string;
  readonly createdAt: number;
  readonly correctedAt?: number;
}

interface EncryptedItem extends Omit<PersonalDataItem, "label" | "value"> {
  readonly label: Ciphertext;
  readonly value: Ciphertext;
}

interface StoreFile {
  readonly schema: "keep.personal-data/v2" | "keep.personal-data/v3";
  readonly subject: SubjectId;
  readonly items: readonly EncryptedItem[];
}

export interface PersistentPersonalDataStoreOptions {
  /** Persistence is disabled unless the operator explicitly opts in. */
  readonly enabled: boolean;
  readonly path: string;
  /** A dedicated key subject is recommended so shredding this store does not erase unrelated project data. */
  readonly subject: SubjectId;
  readonly keys: CryptoShredKeyStore;
}

/**
 * Opt-in encrypted-at-rest storage for reversible PII surrogates and user-visible
 * behavioral cues/preferences. The file contains ciphertext and metadata only.
 */
export class PersistentPersonalDataStore {
  private items: EncryptedItem[] = [];
  private writeFailed = false;

  constructor(private readonly options: PersistentPersonalDataStoreOptions) {
    if (!options.enabled) return;
    if (options.subject.trim() === "") throw new Error("personal data subject is required");
    const existed = existsSync(options.path);
    if (!existed) options.keys.ensureKey(options.subject);
    if (existed && !options.keys.hasKey(options.subject)) {
      throw new Error(`subject ${options.subject} has been erased (key shredded)`);
    }
    const loaded = this.load();
    this.items = loaded.items;
    // Authenticate every record before exposing a writable store. Neither a
    // wrong key nor a partial migration may overwrite the recoverable original.
    try {
      for (const item of this.items) {
        options.keys.decrypt(options.subject, item.label);
        options.keys.decrypt(options.subject, item.value);
      }
      if (loaded.migrate) this.persist(this.items);
    } catch (cause) {
      if (loaded.migrate) {
        throw new Error("personal data migration incomplete; retain the store and reopen with its authorized key", { cause });
      }
      throw cause;
    }
  }

  put(kind: PersonalDataKind, label: string, value: string, now = Date.now()): PersonalDataItem {
    this.assertEnabled();
    if (label.trim() === "" || value === "") throw new Error("label and value are required");
    const plain: PersonalDataItem = { id: randomUUID(), kind, label, value, createdAt: now };
    const next = [...this.items, {
      id: plain.id,
      kind: plain.kind,
      label: this.options.keys.encrypt(this.options.subject, label),
      value: this.options.keys.encrypt(this.options.subject, value),
      createdAt: plain.createdAt,
    }];
    this.persist(next);
    this.items = next;
    return plain;
  }

  list(kind?: PersonalDataKind): PersonalDataItem[] {
    this.assertEnabled();
    return this.items
      .filter((item) => kind === undefined || item.kind === kind)
      .map((item) => ({
        ...item,
        label: this.options.keys.decrypt(this.options.subject, item.label),
        value: this.options.keys.decrypt(this.options.subject, item.value),
      }));
  }

  correct(id: string, value: string, now = Date.now()): PersonalDataItem {
    this.assertEnabled();
    if (value === "") throw new Error("value is required");
    const index = this.items.findIndex((item) => item.id === id);
    if (index < 0) throw new Error(`no such personal data item: ${id}`);
    const prior = this.items[index]!;
    const next: EncryptedItem = {
      ...prior,
      value: this.options.keys.encrypt(this.options.subject, value),
      correctedAt: now,
    };
    const items = this.items.slice();
    items[index] = next;
    this.persist(items);
    this.items = items;
    return { ...next, label: this.options.keys.decrypt(this.options.subject, next.label), value };
  }

  /** Visible, portable plaintext export initiated by the operator. */
  export(): { readonly schema: "keep.personal-data-export/v1"; readonly subject: SubjectId; readonly items: PersonalDataItem[] } {
    return { schema: "keep.personal-data-export/v1", subject: this.options.subject, items: this.list() };
  }

  /** Erase one record from the live persistent file. */
  erase(id: string): boolean {
    this.assertEnabled();
    const before = this.items.length;
    const items = this.items.filter((item) => item.id !== id);
    if (items.length === before) return false;
    this.persist(items);
    this.items = items;
    return true;
  }

  /** Irreversibly destroy the store key; retained ciphertext becomes unreadable. */
  cryptoShred(): boolean {
    this.assertEnabled(true);
    const shredded = this.options.keys.shred(this.options.subject);
    this.items = [];
    return shredded;
  }

  private assertEnabled(allowHeldErasure = false): void {
    if (!this.options.enabled) throw new Error("persistent personal data store is not opted in");
    if (this.writeFailed && !allowHeldErasure) throw new Error("personal data store is held after a failed write; reopen to reconcile its retained file");
  }

  private load(): { items: EncryptedItem[]; migrate: boolean } {
    if (!existsSync(this.options.path)) return { items: [], migrate: false };
    const decoded = JSON.parse(readFileSync(this.options.path, "utf8")) as Partial<StoreFile>;
    if (!["keep.personal-data/v2", "keep.personal-data/v3"].includes(String(decoded.schema)) || decoded.subject !== this.options.subject || !Array.isArray(decoded.items)) {
      throw new Error("invalid or foreign persistent personal data store");
    }
    let migrate = decoded.schema === "keep.personal-data/v2";
    const items = decoded.items.map((raw): EncryptedItem => {
      const item = raw as Partial<EncryptedItem>;
      if (
        typeof item.id !== "string" || item.id === "" ||
        !(["surrogate", "cue", "preference"] as const).includes(item.kind as PersonalDataKind) ||
        !isCiphertext(item.label) || !isCiphertext(item.value) ||
        typeof item.createdAt !== "number" || !Number.isFinite(item.createdAt) ||
        (item.correctedAt !== undefined && (typeof item.correctedAt !== "number" || !Number.isFinite(item.correctedAt)))
      ) {
        throw new Error("invalid encrypted personal data item");
      }
      migrate ||= item.label.plaintextHash !== undefined || item.value.plaintextHash !== undefined;
      return {
        id: item.id,
        kind: item.kind as PersonalDataKind,
        label: protectedCiphertext(item.label),
        value: protectedCiphertext(item.value),
        createdAt: item.createdAt,
        ...(item.correctedAt === undefined ? {} : { correctedAt: item.correctedAt }),
      };
    });
    chmodSync(this.options.path, 0o600);
    return { items, migrate };
  }

  private persist(items: readonly EncryptedItem[]): void {
    ensureDurableDir(NODE_IO, dirname(this.options.path));
    const temp = `${this.options.path}.${process.pid}.${randomUUID()}.tmp`;
    const data: StoreFile = { schema: "keep.personal-data/v3", subject: this.options.subject, items };
    let fd: number | undefined;
    try {
      fd = openSync(temp, "wx", 0o600);
      writeFileSync(fd, `${JSON.stringify(data)}\n`, "utf8");
      fsyncSync(fd);
      closeSync(fd);
      fd = undefined;
      renameSync(temp, this.options.path);
      fsyncDir(NODE_IO, dirname(this.options.path));
    } catch (error) {
      // A failure after rename leaves a valid new file, but its durability is
      // uncertain. Fence this instance rather than continue with stale state.
      this.writeFailed = true;
      throw error;
    } finally {
      if (fd !== undefined) closeSync(fd);
      try { unlinkSync(temp); } catch { /* absent or already renamed */ }
    }
  }
}

function isCiphertext(value: unknown): value is Ciphertext {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const c = value as Partial<Ciphertext>;
  return typeof c.iv === "string" && /^[a-f0-9]{24}$/iu.test(c.iv)
    && typeof c.authTag === "string" && /^[a-f0-9]{32}$/iu.test(c.authTag)
    && typeof c.data === "string" && /^(?:[a-f0-9]{2})*$/iu.test(c.data)
    && (c.plaintextHash === undefined || typeof c.plaintextHash === "string");
}

function protectedCiphertext(value: Ciphertext): Ciphertext {
  return { iv: value.iv, authTag: value.authTag, data: value.data };
}

