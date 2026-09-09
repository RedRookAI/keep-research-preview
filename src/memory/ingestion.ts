/**
 * Ingestion gate (Phase 1) — Round 15 (PII/secret) + Round 20 (license/SCA).
 *
 * OWASP ASI06 layer: input moderation + memory sanitization at the INGESTION
 * boundary, before anything is stored or distilled into a lesson. Two checks:
 *   - Secret/PII detection (entropy + known patterns): reject or redact.
 *   - License/SCA: copyleft (GPL/AGPL/LGPL) content is a stop-the-line flag,
 *     never distilled into a proprietary lesson/skill (anti-laundering).
 */

export type IngestionDecision = "accept" | "redact" | "reject";

export interface IngestionResult {
  readonly decision: IngestionDecision;
  /** The (possibly redacted) content safe to store. Empty if rejected. */
  readonly sanitized: string;
  readonly findings: readonly string[];
}

/** Known secret patterns (a representative git-secrets/trufflehog-class set). */
const SECRET_PATTERNS: readonly { rx: RegExp; label: string }[] = [
  { rx: /\bAKIA[0-9A-Z]{16}\b/, label: "aws-access-key" },
  { rx: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, label: "github-token" },
  { rx: /\bsk-[A-Za-z0-9]{20,}\b/, label: "api-secret-key" },
  { rx: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, label: "private-key" },
  { rx: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, label: "slack-token" },
];

/** PII patterns (conservative; email + common national-id shapes). */
const PII_PATTERNS: readonly { rx: RegExp; label: string }[] = [
  { rx: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, label: "email" },
  { rx: /\b\d{3}-\d{2}-\d{4}\b/, label: "ssn-like" },
];

/** Copyleft license markers — stop-the-line (Round 20 anti-laundering). */
const COPYLEFT_PATTERNS: readonly { rx: RegExp; label: string }[] = [
  { rx: /\b(GNU\s+)?(GPL|General Public License)(\s*v?[23])?\b/i, label: "GPL" },
  { rx: /\bAGPL\b/i, label: "AGPL" },
  { rx: /\bLGPL\b/i, label: "LGPL" },
  { rx: /SPDX-License-Identifier:\s*(A?GPL|LGPL)/i, label: "SPDX-copyleft" },
];

/** Shannon entropy, used to catch high-entropy secret-like tokens. */
function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** True if a token looks like a high-entropy secret (long + high entropy). */
function looksLikeSecret(token: string): boolean {
  return token.length >= 24 && shannonEntropy(token) >= 4.0 && /[A-Za-z]/.test(token) && /[0-9]/.test(token);
}

export function scanIngestion(content: string): IngestionResult {
  const findings: string[] = [];

  // 1. Copyleft = hard reject (never launder copyleft into a lesson).
  for (const c of COPYLEFT_PATTERNS) {
    if (c.rx.test(content)) {
      findings.push(`copyleft:${c.label}`);
      return { decision: "reject", sanitized: "", findings };
    }
  }

  // 2. Secrets = redact (keep the surrounding lesson, remove the secret).
  let sanitized = content;
  let hadSecret = false;
  for (const s of SECRET_PATTERNS) {
    if (s.rx.test(sanitized)) {
      findings.push(`secret:${s.label}`);
      sanitized = sanitized.replace(new RegExp(s.rx, "g"), "[REDACTED-SECRET]");
      hadSecret = true;
    }
  }
  // Entropy-based catch for secrets not matching a known pattern.
  sanitized = sanitized
    .split(/(\s+)/)
    .map((tok) => {
      if (looksLikeSecret(tok)) {
        findings.push("secret:high-entropy");
        hadSecret = true;
        return "[REDACTED-SECRET]";
      }
      return tok;
    })
    .join("");

  // 3. PII = redact.
  let hadPii = false;
  for (const p of PII_PATTERNS) {
    if (p.rx.test(sanitized)) {
      findings.push(`pii:${p.label}`);
      sanitized = sanitized.replace(new RegExp(p.rx, "g"), "[REDACTED-PII]");
      hadPii = true;
    }
  }

  const decision: IngestionDecision = hadSecret || hadPii ? "redact" : "accept";
  return { decision, sanitized, findings };
}
