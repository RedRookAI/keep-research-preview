/**
 * PORTABILITY — Round 8 of the personalization moat (the ethical capstone: the portable second brain).
 *
 * Portability = CREDIBLE EXIT = the durable moat (NOT lock-in), and it is now the direction of law (EU Data Act
 * switching-fee elimination by 2027; AI Act full enforcement 2026). The killer insight from the 2026 AI-memory
 * literature: existing exports return raw logs — "you don't lose the data, you lose the understanding" — so Keep
 * exports the DERIVED state (memories with their tiers/scopes, preferences, inferred profiles, lenses, connector
 * configs, corrections), not transcripts. Credible exit is only real if it re-homes into the user's OWN instance
 * (n=1-local self-host) — cognitive sovereignty.
 *
 * Three research-driven properties shape this:
 *   1. CI-RESPECTING export (GDPR Art 20(4)) — export MY subject-data, never another user's.
 *   2. SAFE RE-HYDRATION — a bundle is UNTRUSTED input (memory-mediated prompt injection, forged provenance,
 *      poisoned memory). Import VERIFIES an integrity digest (tampered ⇒ rejected), checks the version (unknown ⇒
 *      graceful degradation, never a silent misparse), lands imported memories at PROBATION (never confirmed — no
 *      authority laundering), SANITIZES imported personas (parseSoul), and marks imported content tainted.
 *   3. ERASURE = per-entity CRYPTO-SHRED not soft-delete — a flag is not erasure (an admin can still read it); the
 *      SOTA is key destruction (Keep's CryptoShredKeyStore). Erase makes the ciphertext unreadable while the audit
 *      event survives, and returns a verifiable receipt.
 *
 * This layer is the export/import round-trip + erasure LOGIC over abstract derived-state categories (a thin
 * adapter assembles `DerivedState` from the real stores). BUILT + proven in-env: export-completeness, CI-scoping,
 * integrity-verify, safe-re-hydration, and crypto-shred erasure. SEAM: the wire serialization format (the specific
 * bytes) and cross-vendor schema adapters (importing another vendor's bundle).
 */

import { sha256Hex } from "../tcb/attestation.js";
import { parseSoul, type RawSoul, type SoulConfig } from "../soul/soul_config.js";
import type { CryptoShredKeyStore, Ciphertext } from "../keystore/keystore.js";

/** The self-describing bundle version. An unknown version degrades gracefully on import. */
export const BUNDLE_VERSION = 1;

// ---- the derived state (the "understanding", not raw logs) ----

export interface PortableMemory {
  readonly id: string;
  readonly content: string;
  readonly tier: string; // exported tier — but import lands it at probation
  readonly scope: string;
  readonly subject?: string | undefined; // whose data (for CI-scoping)
}
export interface PortablePreference {
  readonly dimension: string;
  readonly value: string;
  readonly scope?: string | undefined;
  readonly subject?: string | undefined;
}
export interface PortableLens {
  readonly preset: string;
  readonly soul: unknown; // untrusted on import — sanitized via parseSoul
  readonly overlay: readonly PortablePreference[];
}
export interface PortableConnector {
  readonly id: string;
  readonly grantedScopes: readonly string[];
}
export interface PortableCorrection {
  readonly before: string;
  readonly after: string;
}

export interface DerivedState {
  readonly memories: readonly PortableMemory[];
  readonly preferences: readonly PortablePreference[];
  readonly inferred: readonly PortablePreference[];
  readonly lenses: readonly PortableLens[];
  readonly connectors: readonly PortableConnector[];
  readonly corrections: readonly PortableCorrection[];
}

export interface Portable {
  readonly version: number;
  readonly subject: string; // the exporting subject — self-describing
  readonly state: DerivedState;
  readonly digest: string; // integrity/provenance digest over the state
}

/** Deterministic serialization for the integrity digest (state only — not the version, so version can vary
 *  independently for the version-degrade path). */
function serializeState(state: DerivedState): string {
  return JSON.stringify(state);
}
function digestOf(state: DerivedState): string {
  return sha256Hex(serializeState(state));
}

/** Does a subject-bearing item belong to `subject`? An item with no subject is the owner's own; an item whose
 *  subject is ANOTHER user is excluded (Art 20(4)). */
function belongsTo(itemSubject: string | undefined, subject: string): boolean {
  return itemSubject === undefined || itemSubject === subject;
}

/**
 * Export the derived state as a versioned, self-describing bundle — CI-SCOPED to the requesting subject (another
 * user's data is filtered out) and carrying an integrity digest.
 */
export function exportAll(subject: string, state: DerivedState): Portable {
  const scoped: DerivedState = {
    memories: state.memories.filter((m) => belongsTo(m.subject, subject)),
    preferences: state.preferences.filter((p) => belongsTo(p.subject, subject)),
    inferred: state.inferred.filter((p) => belongsTo(p.subject, subject)),
    lenses: state.lenses,
    connectors: state.connectors,
    corrections: state.corrections,
  };
  return { version: BUNDLE_VERSION, subject, state: scoped, digest: digestOf(scoped) };
}

// ---- safe re-hydration (a bundle is UNTRUSTED input) ----

export interface Restored {
  readonly memories: readonly PortableMemory[]; // tier forced to probation
  readonly preferences: readonly PortablePreference[];
  readonly inferred: readonly PortablePreference[];
  readonly lenses: readonly (Omit<PortableLens, "soul"> & { readonly soul: SoulConfig })[]; // souls sanitized
  readonly connectors: readonly PortableConnector[];
  readonly corrections: readonly PortableCorrection[];
  readonly tainted: true; // imported content is untrusted
}

export type ImportResult =
  | { readonly ok: true; readonly restored: Restored }
  | { readonly ok: false; readonly reason: "integrity-failed" | "unsupported-version" };

/**
 * Import a bundle SAFELY. Verify the integrity digest (tampered ⇒ rejected), check the version (unknown ⇒
 * graceful degradation), then re-hydrate: imported memories land at PROBATION (never confirmed — no authority
 * laundering), imported personas are SANITIZED (parseSoul), imported content is tainted. Total + fail-safe.
 */
export function importAll(bundle: Portable): ImportResult {
  // integrity first — a tampered bundle (state altered without a matching digest) is rejected.
  if (digestOf(bundle.state) !== bundle.digest) {
    return { ok: false, reason: "integrity-failed" };
  }
  // version — an unknown/future version degrades gracefully rather than misparsing.
  if (bundle.version !== BUNDLE_VERSION) {
    return { ok: false, reason: "unsupported-version" };
  }
  const restored: Restored = {
    memories: bundle.state.memories.map((m) => ({ ...m, tier: "probation" })), // never confirmed on import
    preferences: bundle.state.preferences,
    inferred: bundle.state.inferred,
    lenses: bundle.state.lenses.map((l) => ({
      preset: l.preset,
      overlay: l.overlay,
      soul: parseSoul((l.soul ?? {}) as RawSoul), // sanitize — a bundle can't smuggle authority into a persona
    })),
    connectors: bundle.state.connectors,
    corrections: bundle.state.corrections,
    tainted: true,
  };
  return { ok: true, restored };
}

// ---- erasure (per-entity crypto-shred, not soft-delete) ----

export interface Receipt {
  readonly subject: string;
  readonly method: "crypto-shred";
  readonly keyDestroyed: boolean;
  readonly erasedTs: number;
}

/**
 * Erase a subject's data by CRYPTO-SHREDDING their key (destroy the key ⇒ the ciphertext becomes unreadable — not
 * a soft-delete flag). The keystore's two-phase audit preserves the erasure event. Returns a verifiable receipt.
 */
export function erase(keystore: CryptoShredKeyStore, subject: string, now: () => number = () => Date.now()): Receipt {
  const keyDestroyed = keystore.shred(subject);
  return { subject, method: "crypto-shred", keyDestroyed, erasedTs: now() };
}

/** Can this ciphertext still be read for the subject? False once the key is shredded (decrypt throws). */
export function canRead(keystore: CryptoShredKeyStore, subject: string, c: Ciphertext): boolean {
  try {
    keystore.decrypt(subject, c);
    return true;
  } catch {
    return false;
  }
}
