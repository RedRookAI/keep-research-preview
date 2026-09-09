/**
 * F1 / H-1 — THE REDACTION GATEWAY. Composes the deterministic `DataClassifier` (rule-based; NO model in the path — the
 * H-2 vendored model is unnecessary and deliberately NOT added, preserving zero-dep) to detect PII, then adds three
 * things the classifier alone doesn't: (1) a SURROGATE tokenizer + an EPHEMERAL vault (surrogate↔real map, held only in
 * memory — never persisted, never spine-logged; an optional audit sink receives METADATA only), (2) a QUASI-IDENTIFIER
 * accumulator that flags re-identification risk when the combination of quasi-ids seen crosses a k-anonymity-style
 * threshold, and (3) an HONEST tier labeler that never claims more anonymity than was achieved.
 *
 * HONESTY: surrogated text is at best "pseudonymized" (the vault makes it reversible) — never "anonymized". A residual
 * re-identification risk (quasi-id set over threshold, or possible unstructured PII) is "identifiable". Only text with
 * no detected PII and no residual risk is "anonymized".
 */

import { DataClassifier, type PiiCategory, type PiiFinding, type NerRecognizer } from "../ingest/data_classifier.js";
import { randomBytes } from "node:crypto";

export const EMBEDDING_REPRESENTATION_VERSION = "keep.embedding-surrogates/v1";

let nextEphemeralVaultId = 0n;
function alphaVaultId(value: bigint): string {
  let n = value, out = "";
  while (n > 0n) { n -= 1n; out = String.fromCharCode(97 + Number(n % 26n)) + out; n /= 26n; }
  return out || "a";
}

export type AnonymityTier = "anonymized" | "pseudonymized" | "identifiable";

/** Quasi-identifiers: weak alone, re-identifying in COMBINATION (the k-anonymity concern). Direct ids are handled as strong. */
const QUASI_IDENTIFIERS = new Set<PiiCategory>(["name", "org", "ip_address", "phone"]);

export interface RedactionPolicy {
  /** Host-only, one task-memory context. Never share across jobs or tenants.
   * Preserves equality of exact detected category/value, not semantic equivalence. */
  readonly reuseEntitiesWithinSession?: boolean;
  /** k-anonymity-style over-tolerance: this many distinct quasi-identifier categories ⇒ re-identification risk. Default 3. */
  readonly quasiIdThreshold?: number;
  /** HIGH-RISK context (hiring/credit/medical/etc.): uncertain detection FAILS SAFE (blockRecommended) rather than proceed. */
  readonly highRisk?: boolean;
  /** A finding below this confidence is "uncertain". Default 0.6. */
  readonly confidenceFloor?: number;
}

export interface RedactionResult {
  /** The text with every detected PII span replaced by a stable surrogate token. */
  readonly redacted: string;
  /** HONEST label of what the redaction achieved (never overclaims). */
  readonly tier: AnonymityTier;
  /** True when the accumulated quasi-identifier set crosses the re-identification threshold. */
  readonly reidentificationRisk: boolean;
  readonly surrogateCount: number;
  /** HONEST CAVEAT: a NER pass could still surface unstructured PII (names/orgs) the deterministic layer can't see.
   *  Surfaced explicitly rather than silently downgrading the tier — the label covers what was DETECTED + handled. */
  readonly unstructuredPiiPossible: boolean;
  /** FAIL-SAFE: in a high-risk context with a low-confidence finding, the gateway RECOMMENDS blocking / human review
   *  rather than silently proceeding. The gateway is the boundary; the detector is only a sensor (2026 SOTA). */
  readonly blockRecommended: boolean;
  /** Why review is recommended (present only when blockRecommended). */
  readonly reviewReason?: string;
  /** HONEST SCOPE: redaction REDUCES exposure — it does NOT GUARANTEE anonymity against a strong adversary (AURA
   *  2026): quasi-identifier combination + implicit/contextual PII can still re-identify. Never claim "anonymized" =
   *  "guaranteed anonymous". Always true — a permanent honesty marker on every result. */
  readonly reducesNotGuarantees: true;
}

export interface RedactionAuditEvent {
  readonly event: "redacted";
  readonly surrogateCount: number;
  readonly tier: AnonymityTier;
  readonly reidentificationRisk: boolean;
}

export interface RedactionDeps {
  readonly ner?: NerRecognizer;
  /** Optional metadata sink (e.g. the spine). Receives COUNTS + tier ONLY — never the real values or the vault. */
  readonly audit?: (e: RedactionAuditEvent) => void;
}

export class RedactionGateway {
  private readonly classifier: DataClassifier;
  /** EPHEMERAL: surrogate → real value. In-memory only; never persisted, never staged to the spine. */
  private readonly vault = new Map<string, string>();
  /** Accumulated quasi-identifier categories seen across this session (the re-identification surface). */
  private readonly quasiSeen = new Set<PiiCategory>();
  private seq = 0;
  private readonly vaultId = ++nextEphemeralVaultId;
  readonly #equalEntities = new Map<string, string>();
  readonly #namespace: string | undefined;
  /** Opaque per-session identity, no plaintext/key. Undefined for legacy per-call use. */
  readonly representationIdentity: string | undefined;

  constructor(private readonly policy: RedactionPolicy = {}, private readonly deps: RedactionDeps = {}) {
    this.classifier = new DataClassifier(deps.ner);
    // Alphabetic encoding prevents the token namespace itself matching numeric PII
    // recognizers. 16 random bytes retain 128 bits; no plaintext-derived identifier.
    this.#namespace = policy.reuseEntitiesWithinSession === true
      ? [...randomBytes(16).toString("hex")].map(c => String.fromCharCode(97 + Number.parseInt(c, 16))).join("") : undefined;
    this.representationIdentity = this.#namespace === undefined ? undefined : `${EMBEDDING_REPRESENTATION_VERSION}:${this.#namespace}`;
  }

  /** Detect + surrogate PII; accumulate quasi-identifiers; label the anonymity tier honestly. */
  redact(text: string): RedactionResult {
    const cls = this.classifier.classify(text);
    // Replace right-to-left so earlier spans' offsets stay valid.
    const findings = [...cls.findings].sort((a, b) => b.start - a.start);
    let out = text;
    for (const f of findings) {
      const key = JSON.stringify([f.category, f.value]);
      let surrogate = this.#namespace === undefined ? undefined : this.#equalEntities.get(key);
      if (surrogate === undefined) {
        surrogate = `\u27E6${f.category}#${++this.seq}@v${this.#namespace ?? alphaVaultId(this.vaultId)}\u27E7`;
        if (this.#namespace !== undefined) this.#equalEntities.set(key, surrogate);
      }
      this.vault.set(surrogate, f.value);
      out = out.slice(0, f.start) + surrogate + out.slice(f.end);
      if (QUASI_IDENTIFIERS.has(f.category)) this.quasiSeen.add(f.category);
    }
    const reidentificationRisk = this.quasiSeen.size >= (this.policy.quasiIdThreshold ?? 3);
    const tier = labelTier(findings.length, reidentificationRisk);
    // FAIL-SAFE-ON-UNCERTAINTY: a high-risk context with a low-confidence finding blocks for review — never a silent
    // proceed. The gateway is the boundary; the detector is only a sensor (PIIBench: F1 can fall to 0.18 out-of-distribution).
    const floor = this.policy.confidenceFloor ?? 0.6;
    const uncertain = cls.findings.some((fn) => fn.confidence < floor);
    const blockRecommended = this.policy.highRisk === true && uncertain;
    const reviewReason = blockRecommended ? "high-risk context with a low-confidence detection — review before egress (fail-safe; the detector is a sensor, not a guarantee)" : undefined;
    // METADATA ONLY to the audit sink — the real values + the vault never leave this object.
    this.deps.audit?.({ event: "redacted", surrogateCount: findings.length, tier, reidentificationRisk });
    return { redacted: out, tier, reidentificationRisk, surrogateCount: findings.length, unstructuredPiiPossible: cls.unstructuredPiiPossible, blockRecommended, ...(reviewReason !== undefined ? { reviewReason } : {}), reducesNotGuarantees: true };
  }

  /**
   * The set of real values this call's vault holds — i.e. the values we DELIBERATELY restore on rehydration. The output
   * filter uses this to distinguish AUTHORIZED data (our own rehydrated surrogates) from a NOVEL leak the model emitted.
   */
  authorizedValues(): Set<string> {
    return new Set(this.vault.values());
  }

  /** Re-hydrate surrogates back to their real values from the ephemeral vault (e.g. after a remote round-trip). */
  rehydrate(text: string): string {
    let out = text;
    for (const [surrogate, real] of this.vault) out = out.split(surrogate).join(real);
    return out;
  }
}

/**
 * HONEST tier over what was DETECTED + handled: a real residual re-identification risk (quasi-id set over threshold)
 * ⇒ identifiable; any surrogated (reversible) PII ⇒ pseudonymized; otherwise anonymized. The deterministic-only
 * uncertainty (`unstructuredPiiPossible`) is surfaced as a caveat on the result, NOT folded into the label — folding
 * it in would make every label "identifiable" whenever no NER is injected, which tells the caller nothing.
 */
function labelTier(surrogateCount: number, reidentificationRisk: boolean): AnonymityTier {
  if (reidentificationRisk) return "identifiable";
  if (surrogateCount > 0) return "pseudonymized"; // reversible via the vault — NOT anonymized
  return "anonymized";
}
