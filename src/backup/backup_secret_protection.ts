import { createCipheriv, createDecipheriv, createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import type { BackupCredentialProtector, BackupScope } from "./installed_backup_capture.js";

export interface BackupCredentialOpener {
  readonly protectorId: string;
  /** Authenticate the envelope and its exact scope/path binding before returning plaintext. */
  open(scope: BackupScope, path: string, sealedBase64: string, expectedContentBinding?: string): Promise<Buffer> | Buffer;
}

/**
 * Portable n=1 adapter. The recovery secret is never serialized into the backup. Enterprise deployments can
 * implement the same small protector/opener boundary with KMS, HSM, or split-custody key services.
 */
export class PassphraseBackupCredentialProtector implements BackupCredentialProtector, BackupCredentialOpener {
  readonly #bindingKey: Buffer;
  constructor(readonly protectorId: string, private readonly recoverySecret: string, bindingSaltBase64: string) {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(protectorId)) throw new Error("backup protector id must be a bounded canonical token");
    if (Buffer.byteLength(recoverySecret, "utf8") < 20) throw new Error("backup recovery secret must contain at least 20 UTF-8 bytes");
    const bindingSalt = canonicalBytes(bindingSaltBase64, 16);
    this.#bindingKey = scryptSync(this.recoverySecret, Buffer.concat([Buffer.from("keep.installed-backup.content-binding/v1\0"), bindingSalt]), 32,
      { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  }
  static generateBindingSalt(): string { return randomBytes(16).toString("base64"); }

  seal(scope: BackupScope, path: string, plaintext: Buffer): { readonly sealedBase64: string; readonly contentBinding: string } {
    const salt = randomBytes(16), iv = randomBytes(12);
    const key = scryptSync(this.recoverySecret, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(aad(this.protectorId, scope, path));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const envelope = { v: 1, kdf: "scrypt-32768-8-1", cipher: "aes-256-gcm", salt: salt.toString("base64"), iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") };
    const sealedBase64 = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64");
    const contentBinding = createHmac("sha256", this.#bindingKey).update(aad(this.protectorId, scope, path)).update(plaintext).digest("hex");
    return Object.freeze({ sealedBase64, contentBinding });
  }

  open(scope: BackupScope, path: string, sealedBase64: string, expectedContentBinding?: string): Buffer {
    try {
      const raw = Buffer.from(sealedBase64, "base64");
      if (raw.toString("base64") !== sealedBase64 || raw.length > 128 * 1024 * 1024) throw new Error("non-canonical or oversized envelope");
      const value = JSON.parse(raw.toString("utf8")) as Record<string, unknown>;
      if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["cipher", "ciphertext", "iv", "kdf", "salt", "tag", "v"]) || value.v !== 1 ||
          value.kdf !== "scrypt-32768-8-1" || value.cipher !== "aes-256-gcm") throw new Error("unsupported envelope");
      const salt = canonicalBytes(value.salt, 16), iv = canonicalBytes(value.iv, 12), tag = canonicalBytes(value.tag, 16);
      const ciphertext = canonicalBytes(value.ciphertext);
      const key = scryptSync(this.recoverySecret, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
      const decipher = createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAAD(aad(this.protectorId, scope, path)); decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      if (expectedContentBinding !== undefined) {
        const actual = createHmac("sha256", this.#bindingKey).update(aad(this.protectorId, scope, path)).update(plaintext).digest();
        const expected = Buffer.from(expectedContentBinding, "hex");
        if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw new Error("content binding mismatch");
      }
      return plaintext;
    } catch (cause) {
      throw new Error(`protected backup credential could not be authenticated for ${scope}:${path}`, { cause });
    }
  }
}

function aad(protectorId: string, scope: BackupScope, path: string): Buffer {
  return Buffer.from(`keep.installed-backup.credential/v1\0${protectorId}\0${scope}\0${path}`, "utf8");
}
function canonicalBytes(value: unknown, exactLength?: number): Buffer {
  if (typeof value !== "string") throw new Error("envelope field is not a string");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || (exactLength !== undefined && bytes.length !== exactLength)) throw new Error("non-canonical envelope field");
  return bytes;
}
