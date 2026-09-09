/**
 * F1 — Secret-safe message intake (the chat security floor).
 *
 * Non-experts paste API keys and logins straight into chat. The 2026 consensus
 * (TruffleHog, PII-Shield, the Hermes-agent secrets issue) is unambiguous: a secret
 * must be caught and removed BEFORE it enters LLM context or session logs, and the
 * right primitive is DETERMINISTIC TOKENIZATION (a stable placeholder), not masking.
 *
 * So: every inbound message is scanned; any secret is CAPTURED into the crypto-shred
 * keystore (F0's mechanism) and replaced with a placeholder like {{secret:cred_1}}
 * that maps back to the stored value. The brain and the spine only ever see the
 * placeholder; Keep can still USE the credential by resolving it from the keystore.
 * It NEVER errors on a pasted secret — the human gets a warm, jargon-free note.
 */

import type { CryptoShredKeyStore } from "../keystore/keystore.js";
import { scanIngestion } from "../memory/ingestion.js";
import { detectProviderKind } from "./brain_port.js";

export interface CapturedSecret {
  readonly placeholder: string; // e.g. "{{secret:cred_1}}"
  readonly subject: string; // keystore subject
  readonly providerLabel: string; // "Anthropic (Claude)", "a login/password", etc.
  readonly kind: "api-key" | "login" | "high-entropy";
}

export interface IntakeResult {
  /** The message with every secret replaced by a placeholder — safe for the brain + spine. */
  readonly safeText: string;
  /** Secrets captured this message (values are NOT here — they're in the keystore). */
  readonly captured: readonly CapturedSecret[];
  /** A warm, jargon-free line to show the human if anything was captured (else empty). */
  readonly acknowledgment: string;
}

/** Extract candidate secret substrings from text (pattern + high-entropy tokens). */
function findSecretTokens(text: string): string[] {
  const tokens = new Set<string>();
  // Known API-key shapes (sk-..., gsk_, nvapi-, AIza..., long hex/base64 blobs).
  const patterns = [
    /\bsk-[A-Za-z0-9-]{16,}\b/g,
    /\bgsk_[A-Za-z0-9]{16,}\b/g,
    /\bnvapi-[A-Za-z0-9_-]{16,}\b/g,
    /\bAIza[A-Za-z0-9_-]{20,}\b/g,
    /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
    /\b[0-9]{6,}:[A-Za-z0-9_-]{30,}\b/g, // Telegram bot token shape
    /\bghp_[A-Za-z0-9]{30,}\b/g, // GitHub PAT
    /\bAKIA[0-9A-Z]{16}\b/g, // AWS access key id
    /\b[a-z]+:\/\/[^\s:@/]+:[^\s@/]+@[^\s]+/g, // connection string with inline creds
  ];
  for (const rx of patterns) {
    for (const m of text.matchAll(rx)) tokens.add(m[0]);
  }
  // Contextual labels: a human writing "password is X" / "pwd: X" / "pin 1234" /
  // "token = X" — capture the value REGARDLESS of entropy, to catch the low-entropy
  // human secrets (weak passwords, PINs) that entropy detection misses. But only when
  // the following token actually LOOKS like a value (has a digit, symbol, mixed case,
  // or is long) — so "the token bucket algorithm" / "the api key thing" are NOT caught.
  const labelled = /\b(?:password|passwd|pwd|passphrase|pin|secret|token|api[\s_-]?key|access[\s_-]?key|bearer|auth(?:orization)?)\b\s*(?:is|:|=|->)?\s*["']?([^\s"',;]{3,})/gi;
  for (const m of text.matchAll(labelled)) {
    const val = m[1];
    if (val && looksLikeSecretValue(val)) tokens.add(val);
  }
  // High-entropy standalone tokens the ingestion gate would flag.
  for (const word of text.split(/\s+/)) {
    if (word.length >= 20 && scanIngestion(word).findings.some((f) => f.startsWith("secret:"))) {
      tokens.add(word.replace(/[.,;:]+$/, ""));
    }
  }
  return [...tokens];
}

/**
 * A token following a secret-label looks like an actual value (not a dictionary
 * word) if it has a digit, a symbol, mixed case, or is long. This keeps "the token
 * bucket algorithm" and "the api key thing" from being falsely captured, while still
 * catching weak passwords like "MyDog2024", "Summer2024!", or a bare PIN "4823".
 */
function looksLikeSecretValue(v: string): boolean {
  if (/[0-9]/.test(v) || /[^A-Za-z0-9]/.test(v)) return true; // has a digit or symbol
  if (/[a-z]/.test(v) && /[A-Z]/.test(v)) return true; // mixed case
  if (v.length >= 16) return true; // long enough to be a token
  return false; // plain lowercase word like "bucket" / "thing" -> not a secret
}

function classify(token: string): { providerLabel: string; kind: CapturedSecret["kind"] } {
  const d = detectProviderKind(token);
  if (d.id !== "unknown") return { providerLabel: d.label, kind: "api-key" };
  if (/^xox|:.*[A-Za-z0-9_-]{30,}$|^ghp_/.test(token)) return { providerLabel: "a service token", kind: "api-key" };
  return { providerLabel: "a secret value", kind: "high-entropy" };
}

export class SecretSafeIntake {
  private counter = 0;

  constructor(private readonly keystore: CryptoShredKeyStore) {}

  /**
   * Process an inbound message: capture any secrets to the keystore, replace them
   * with placeholders, and return brain/spine-safe text plus a warm acknowledgment.
   */
  process(message: string): IntakeResult {
    const tokens = findSecretTokens(message);
    if (tokens.length === 0) {
      return { safeText: message, captured: [], acknowledgment: "" };
    }
    let safeText = message;
    const captured: CapturedSecret[] = [];
    for (const token of tokens) {
      const subject = `chat-secret:cred_${++this.counter}`;
      const placeholder = `{{secret:cred_${this.counter}}}`;
      // Store crypto-shredded; the value never leaves the keystore.
      this.keystore.ensureKey(subject);
      // We store by keeping the ciphertext in the keystore-adjacent map via encrypt;
      // for a single value we hold it here only long enough to encrypt, then drop it.
      const ciphertext = this.keystore.encrypt(subject, token);
      this.store.set(subject, ciphertext);
      const { providerLabel, kind } = classify(token);
      captured.push({ placeholder, subject, providerLabel, kind });
      // Replace ALL occurrences of the raw token with the placeholder.
      safeText = safeText.split(token).join(placeholder);
    }
    return { safeText, captured, acknowledgment: buildAck(captured) };
  }

  /** Resolve a captured secret's real value (e.g. to build a live adapter). */
  resolve(subject: string): string | undefined {
    const ct = this.store.get(subject);
    if (!ct) return undefined;
    return this.keystore.decrypt(subject, ct);
  }

  /** Forget a captured secret (crypto-shred): unrecoverable. */
  forget(subject: string): void {
    this.keystore.shred(subject);
    this.store.delete(subject);
  }

  /** subject -> ciphertext (the key lives in the keystore; deleting it shreds the value). */
  private readonly store = new Map<string, import("../keystore/keystore.js").Ciphertext>();
}

function buildAck(captured: readonly CapturedSecret[]): string {
  if (captured.length === 1) {
    return `Got it — I've saved ${captured[0]!.providerLabel} securely and removed it from our chat so it can't be seen again. You don't need to do anything else with it.`;
  }
  const labels = captured.map((c) => c.providerLabel).join(", ");
  return `Got it — I've securely saved what you shared (${labels}) and removed those values from our chat so they can't be seen again. Nothing more to do.`;
}
