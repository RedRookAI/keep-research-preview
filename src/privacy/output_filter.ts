/**
 * LLM06-OUTFILTER — output-side sensitive-information-disclosure control (OWASP "Sensitive Information Disclosure";
 * numbered LLM06 in DeepInspect's 2026 mapping / LLM02 in the data-disclosure framing — cite the control, the edition
 * number drifts). The egress interceptor redacts the OUTBOUND prompt and rehydrates OUR surrogates on the way back; but
 * a model can also EMIT a secret it was never given — a hallucinated or in-context-leaked API key, credential, or another
 * tenant's identifier (DeepInspect 2026: "the model emits data the application or user is not authorized to receive").
 * Network DLP can't catch this — it needs application-level output filtering (PipeLab 2026). This scans the RESPONSE
 * (after rehydration) and flags/blocks a NOVEL secret — one that did NOT come from our vault.
 *
 * COMPOSED: reuses the DataClassifier for PII + a compact deterministic credential recognizer for key formats the PII
 * detectors don't cover; reuses the interceptor's metadata-only audit. NO new detector engine.
 * HONEST: our own rehydrated (authorized) values are NEVER flagged. Flags VALUES, not descriptions — the intent-family
 * exclusion (a request that DESCRIBES a secret is not a secret value; dev.to red-team 2026).
 * SAFE: a novel-secret hit is FLAGGED always; under a high-assurance policy it BLOCKS the response (fail-safe), never
 * silently delivered.
 */

import { DataClassifier } from "../ingest/data_classifier.js";

/** Compact, conservative credential VALUE formats (the output-specific concern the PII classifier doesn't cover). */
const CREDENTIAL_PATTERNS: ReadonlyArray<{ readonly category: string; readonly rx: RegExp }> = [
  { category: "aws_access_key", rx: /\bAKIA[0-9A-Z]{16}\b/g },
  { category: "github_token", rx: /\bghp_[A-Za-z0-9]{36}\b/g },
  { category: "api_key", rx: /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b/g }, // OpenAI/Anthropic-style
  { category: "slack_token", rx: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { category: "private_key", rx: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/g },
];

export interface OutputFilterPolicy {
  /** High-assurance: a novel-secret hit BLOCKS the response (fail-safe) instead of only flagging it. */
  readonly blockOnNovelSecret?: boolean;
}

export interface OutputFilterDeps {
  readonly classifier: DataClassifier;
  /** Values we deliberately restored (our vault) — AUTHORIZED; never counted as a novel leak. */
  readonly authorizedValues: ReadonlySet<string>;
  /** Metadata-only audit sink (inbound direction, per-category counts — never the real values). */
  readonly audit?: (e: { readonly direction: "inbound"; readonly perCategory: Readonly<Record<string, number>>; readonly blocked: boolean }) => void;
}

export interface OutputScan {
  /** A novel (non-vault) secret/identifier was found in the response. */
  readonly flagged: boolean;
  /** Under a high-assurance policy, the response should be BLOCKED rather than delivered. */
  readonly blockRecommended: boolean;
  /** Per-category counts of the NOVEL findings only (metadata — no values). */
  readonly novelByCategory: Readonly<Record<string, number>>;
  readonly reason?: string;
}

/** Scan a model response for NOVEL secrets (not from our vault). Flags always; blocks under a high-assurance policy. */
export function scanOutput(response: string, deps: OutputFilterDeps, policy: OutputFilterPolicy = {}): OutputScan {
  // (1) PII the model emitted (reuse the classifier's deterministic detectors).
  const pii = deps.classifier.detect(response).map((f) => ({ category: f.category as string, value: f.value }));
  // (2) credential/key VALUES the PII detectors don't cover (output-specific).
  const creds: { category: string; value: string }[] = [];
  for (const p of CREDENTIAL_PATTERNS) {
    p.rx.lastIndex = 0;
    for (const m of response.matchAll(p.rx)) creds.push({ category: p.category, value: m[0] });
  }
  // (3) NOVEL = not one of our authorized (rehydrated) values.
  const novel = [...pii, ...creds].filter((f) => !deps.authorizedValues.has(f.value));

  const novelByCategory: Record<string, number> = {};
  for (const f of novel) novelByCategory[f.category] = (novelByCategory[f.category] ?? 0) + 1;

  const flagged = novel.length > 0;
  const blockRecommended = flagged && policy.blockOnNovelSecret === true;
  deps.audit?.({ direction: "inbound", perCategory: novelByCategory, blocked: blockRecommended });

  return {
    flagged,
    blockRecommended,
    novelByCategory,
    ...(flagged ? { reason: `output discloses ${novel.length} novel secret/identifier value(s) not authorized by this call — ${blockRecommended ? "BLOCKED (high-assurance)" : "flagged for review"}` } : {}),
  };
}
