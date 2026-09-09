/**
 * Tokenizer + HandlingPolicy (Increment 4.5b) — tag-driven, context-preserving.
 *
 * SOTA basis (2026-08-04):
 *  - Tokenize, don't blank: "blanking a name destroys the semantic value the model needs —
 *    replace with tokens that preserve meaning/format" (Protecto). Deterministic mapping so the
 *    same value → the same token every time, keeping joins/analytics valid (firstsource).
 *  - Masking (irreversible) = anonymized, out of GDPR scope; tokenization (reversible via a vault)
 *    = pseudonymized, still regulated (pctechmag). Keep offers both; regulated data defaults to
 *    tokenization via the project's CryptoShred vault so it can be re-identified under authority.
 *  - Ingestion behavior changes automatically by sensitivity tag (Atlan; AI-Business-Solutions).
 *
 * Zero deps beyond the session-layer vault (node:crypto under the hood).
 */

import type { PiiFinding, SensitivityTier } from "./data_classifier.js";
import type { ProjectNamespace } from "../session/project_registry.js";
import type { Ciphertext } from "../keystore/keystore.js";

/** How a field is handled. */
export type HandlingAction = "keep" | "tokenize" | "mask" | "block";

/** A reversible token map entry: token → the ENCRYPTED original (under the project key). */
export interface TokenVaultEntry {
  readonly token: string;
  readonly cipher: Ciphertext;
  readonly category: string;
}

/**
 * Reversible, deterministic, format-aware tokenizer backed by the project's encryption vault.
 * The same plaintext value always yields the same token (so pseudonymized data still joins);
 * the original is recoverable only by decrypting under the project key (authority-gated).
 */
export class Tokenizer {
  /** value → token (deterministic within a session run). */
  private readonly forward = new Map<string, string>();
  /** token → encrypted original (the vault). */
  private readonly vault = new Map<string, TokenVaultEntry>();
  private counter = 0;

  constructor(private readonly ns: ProjectNamespace) {}

  /** Tokenize a single value under a category, returning a stable, format-hinted token. */
  tokenize(value: string, category: string): string {
    const existing = this.forward.get(value);
    if (existing) return existing;
    const token = `«${category}_${this.counter++}»`;
    this.forward.set(value, token);
    this.vault.set(token, { token, cipher: this.ns.encrypt(value), category });
    return token;
  }

  /** Recover the original value for a token (decrypts under the project key). Throws post-shred. */
  detokenize(token: string): string {
    const entry = this.vault.get(token);
    if (!entry) throw new Error(`unknown token: ${token}`);
    return this.ns.decrypt(entry.cipher);
  }

  /** The vault entries (encrypted originals) — for audit/erasure, never plaintext. */
  entries(): readonly TokenVaultEntry[] {
    return [...this.vault.values()];
  }
}

/** Irreversible mask: replace with a category placeholder (anonymized, out of GDPR scope). */
export function mask(category: string): string {
  return `«${category}_REDACTED»`;
}

/** Per-tier handling rules (the SOTA tiered pattern). Configurable per project. */
export interface HandlingRules {
  readonly tokenizeRegulated: boolean; // regulated PII → reversible tokens (default true)
  readonly allowSharedGlobal: SensitivityTier; // max tier permitted into shared/global scope
  readonly defaultRetentionDays?: number; // regulated default retention (SOTA: ~30d for tier-3)
}

export const DEFAULT_HANDLING: HandlingRules = {
  tokenizeRegulated: true,
  allowSharedGlobal: "internal", // confidential/regulated never leave the private project index
  defaultRetentionDays: 30,
};

/** The outcome of applying handling to a piece of text. */
export interface HandledText {
  readonly text: string; // safe-to-index form (tokenized/masked as policy dictates)
  readonly action: HandlingAction;
  readonly tokensCreated: number;
}

export class HandlingPolicy {
  constructor(
    private readonly tokenizer: Tokenizer,
    private readonly rules: HandlingRules = DEFAULT_HANDLING,
  ) {}

  /** May a record of this tier be placed into a shared/global (cross-project) index? */
  allowsSharedGlobal(tier: SensitivityTier): boolean {
    const order: Record<SensitivityTier, number> = {
      public: 0,
      internal: 1,
      confidential: 2,
      regulated: 3,
    };
    return order[tier] <= order[this.rules.allowSharedGlobal];
  }

  /**
   * Produce the safe-to-index form of `text` given its tier and detected findings. Regulated
   * findings are tokenized (or masked) in-place; the surrounding text is preserved for utility.
   */
  apply(text: string, tier: SensitivityTier, findings: readonly PiiFinding[]): HandledText {
    if (tier === "public" || findings.length === 0) {
      return { text, action: "keep", tokensCreated: 0 };
    }
    // Replace findings from the end so indices stay valid as we splice.
    const ordered = [...findings].sort((a, b) => b.start - a.start);
    let out = text;
    let tokens = 0;
    for (const f of ordered) {
      const replacement = this.rules.tokenizeRegulated
        ? this.tokenizer.tokenize(f.value, f.category)
        : mask(f.category);
      if (this.rules.tokenizeRegulated) tokens++;
      out = out.slice(0, f.start) + replacement + out.slice(f.end);
    }
    return {
      text: out,
      action: this.rules.tokenizeRegulated ? "tokenize" : "mask",
      tokensCreated: tokens,
    };
  }
}
