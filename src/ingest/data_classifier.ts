/**
 * DataClassifier (Increment 4.5a) — deterministic, zero-dep sensitivity classification.
 *
 * SOTA basis (2026-08-04): secure ingestion classifies BEFORE indexing; the decisive layer is
 * deterministic regex for structured identifiers — "fast, local, auditable, requires no external
 * data processor... the PII firewall before content reaches an LLM" (openredaction; pctechmag).
 * NER (unstructured names/orgs) is a heavier ML seam → a PORT here, not a built-in. Detection is
 * imperfect (F1~0.97 on known entities, drops out-of-distribution — GLiNER2), so this classifier
 * is HONEST: it flags what it finds, and callers default to safe (regulated) handling when a NER
 * recognizer is absent and uncertainty is possible. No model in the classification path.
 *
 * Zero deps (regex only).
 */

/** Sensitivity tiers, least → most restricted. `regulated` = contains PII/PHI/financial IDs. */
export type SensitivityTier = "public" | "internal" | "confidential" | "regulated";

/** Categories of personally-identifiable / regulated data the deterministic layer detects. */
export type PiiCategory =
  | "email"
  | "phone"
  | "ssn"
  | "credit_card"
  | "iban"
  | "ip_address"
  | "gov_id"
  | "name" // only via the NER port
  | "org"; // only via the NER port

/** A single detected PII span. `confidence` is honest: 1 = deterministic match, <1 = probabilistic. */
export interface PiiFinding {
  readonly category: PiiCategory;
  readonly start: number;
  readonly end: number;
  readonly value: string;
  readonly confidence: number;
  readonly source: "regex" | "ner";
}

/** Result of classifying one piece of text. */
export interface Classification {
  readonly tier: SensitivityTier;
  readonly findings: readonly PiiFinding[];
  /** True if a NER pass could still surface unstructured PII this deterministic pass can't see. */
  readonly unstructuredPiiPossible: boolean;
}

/** A pluggable named-entity recognizer for unstructured PII (names/orgs). Injected; optional. */
export type NerRecognizer = (text: string) => readonly PiiFinding[];

/** Luhn check for credit-card validation (rejects random 16-digit numbers). */
function luhnValid(digits: string): boolean {
  const d = digits.replace(/\D/g, "");
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** Deterministic recognizers. Each returns spans with confidence 1 (exact pattern match). */
const RECOGNIZERS: ReadonlyArray<{
  category: PiiCategory;
  rx: RegExp;
  validate?: (m: string) => boolean;
}> = [
  { category: "email", rx: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  // SSN before generic phone so 3-2-4 grouping isn't mis-tagged.
  { category: "ssn", rx: /\b\d{3}-\d{2}-\d{4}\b/g },
  { category: "credit_card", rx: /\b(?:\d[ -]?){13,19}\b/g, validate: luhnValid },
  { category: "iban", rx: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/g },
  { category: "ip_address", rx: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  { category: "phone", rx: /(?<!\d)(?:\+?\d{1,3}[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?!\d)/g },
  // A conservative government-ID shape (e.g., passport-like alphanumerics). Low confidence.
  { category: "gov_id", rx: /\b[A-Z]{1,2}\d{6,9}\b/g },
];

export class DataClassifier {
  constructor(private readonly ner?: NerRecognizer) {}

  /** Detect PII findings in text using the deterministic recognizers (+ NER port if present). */
  detect(text: string): PiiFinding[] {
    const findings: PiiFinding[] = [];
    const claimed: Array<[number, number]> = [];
    const overlaps = (s: number, e: number): boolean =>
      claimed.some(([cs, ce]) => s < ce && e > cs);

    for (const rec of RECOGNIZERS) {
      rec.rx.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = rec.rx.exec(text)) !== null) {
        const value = m[0];
        const start = m.index;
        const end = start + value.length;
        if (overlaps(start, end)) continue; // first (more specific) recognizer wins the span
        if (rec.validate && !rec.validate(value)) continue;
        // gov_id shape is ambiguous → lower confidence than the exact-format recognizers
        const confidence = rec.category === "gov_id" ? 0.6 : 1;
        findings.push({ category: rec.category, start, end, value, confidence, source: "regex" });
        claimed.push([start, end]);
      }
    }

    if (this.ner) {
      for (const f of this.ner(text)) {
        if (!overlaps(f.start, f.end)) {
          findings.push(f);
          claimed.push([f.start, f.end]);
        }
      }
    }

    return findings.sort((a, b) => a.start - b.start);
  }

  /**
   * Classify text into a SensitivityTier. Any regulated identifier (email/phone/ssn/card/iban/
   * gov_id) → `regulated`. A `baseTier` lets callers set the floor (e.g. company financials are
   * at least `confidential` even without detected PII).
   */
  classify(text: string, baseTier: SensitivityTier = "internal"): Classification {
    const findings = this.detect(text);
    const hasRegulated = findings.some(
      (f) => f.category !== "name" && f.category !== "org" && f.confidence >= 0.6,
    );
    const tier: SensitivityTier = hasRegulated
      ? "regulated"
      : tierMax(baseTier, findings.length ? "confidential" : baseTier);
    // Honest: if no NER is wired, unstructured PII (freeform names) could still be present.
    const unstructuredPiiPossible = !this.ner;
    return { tier, findings, unstructuredPiiPossible };
  }
}

const TIER_ORDER: Record<SensitivityTier, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  regulated: 3,
};

/** The more-restrictive of two tiers. */
export function tierMax(a: SensitivityTier, b: SensitivityTier): SensitivityTier {
  return TIER_ORDER[a] >= TIER_ORDER[b] ? a : b;
}
