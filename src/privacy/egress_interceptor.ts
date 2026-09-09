/**
 * R-EGRESS — THE EGRESS REDACTION INTERCEPTOR. The "anonymize -> LLM -> deanonymize sandwich" (Topic 6): a deterministic
 * redaction stage that is the LAST hop before a prompt leaves the machine and the FIRST hop on the way back. It runs the
 * seven-boundary pipeline (minimize -> detect -> classify -> transform -> call -> inspect -> selectively restore) and
 * composes the built pieces — DataClassifier (detect PII + proprietary), RedactionGateway (reversible surrogate + ephemeral
 * vault), the provider isLocal flag, and the compiled per-model cache mechanics — with NO new detector/redactor.
 *
 * SAFE (cardinal): LOCAL provider -> skip (nothing egresses); REMOTE -> redact BEFORE send, over a PER-CALL ephemeral
 * vault, failing SAFE on uncertain detection in a high-risk path (never silent fail-open). Real values never leave the
 * process except as surrogates and never hit the audit sink. FAITHFUL: reversible round-trip; the stable (cacheable)
 * prefix is kept byte-identical so prompt-cache hits survive; a rewrite that drops task-necessary content is rejected.
 * HONEST: this REDUCES exposure — it does NOT guarantee anonymity against a strong adversary (AURA, Topic 6); a forced
 * stable-prefix redaction (safety > cost) surfaces the cache-miss trade.
 */

import { DataClassifier } from "../ingest/data_classifier.js";
import { deslopPass, SURROGATE_TOKEN, type DeslopTransform } from "./deslop.js";
import { scanOutput, type OutputScan, type OutputFilterPolicy } from "./output_filter.js";
import type { RedactionGateway } from "./redaction_gateway.js";
import type { CacheMechanics } from "../prompt/harness_compiler.js";
import type { Purpose } from "../ingest/data_governance.js";

export interface EgressFlowContext {
  readonly purpose: Purpose;
  readonly region: string;
  readonly host?: string;
  readonly sourceIds?: readonly string[];
  readonly recipient?: string;
  readonly contextEntryIds?: readonly string[];
}

/** The prompt split into its cacheable stable prefix (system/context) and its volatile user-content tail. */
export interface EgressPrompt {
  readonly stablePrefix: string;
  readonly volatile: string;
  readonly flow?: EgressFlowContext;
}

export interface EgressPolicy {
  /** High-risk workflow: uncertain detection BLOCKS (fail-safe), never egresses. */
  readonly highRisk?: boolean;
  /** Detection below this confidence is "uncertain". Default 0.6. */
  readonly confidenceFloor?: number;
  /** Task-necessary substrings a rewrite MUST preserve; a rewrite that drops any is rejected. */
  readonly requiredContent?: readonly string[];
}

export interface EgressAuditEvent {
  readonly direction: "outbound" | "inbound";
  readonly policyVersion: string;
  /** Per-entity counts (metadata only — never the real values). */
  readonly perCategory: Readonly<Record<string, number>>;
  readonly cacheMissForced: boolean;
}

export interface EgressDeps {
  readonly classifier: DataClassifier;
  /** A fresh RedactionGateway per call — the per-call ephemeral vault (surrogate<->real, discarded after). */
  readonly session: () => RedactionGateway;
  /** The compiled per-model cache mechanics (from harnessCompiler.compile) — informs prefix/breakpoint handling. */
  readonly cache?: CacheMechanics;
  /** Drop fields the model doesn't need (data minimization). Default identity. */
  readonly minimize?: (volatile: string) => string;
  /** Optional model-assisted rewrite (metaprompt). Default identity. Rejected if it drops requiredContent. */
  readonly rewrite?: (text: string) => string;
  /** Metadata-only audit sink (per-entity, per-direction). Never receives real values. */
  readonly audit?: (e: EgressAuditEvent) => void;
  /** Optional prose de-slop transform, applied to the REDACTED response BEFORE rehydration (surrogates protected). Default off. */
  readonly deslop?: DeslopTransform;
  readonly checkPurpose?: (sourceId: string, purpose: Purpose) => { readonly allowed: boolean; readonly reason: string };
  readonly checkResidency?: (region: string, host: string | undefined) => { readonly allowed: boolean; readonly reason?: string };
  readonly checkContextFlow?: (entryId: string, recipient: string, purpose: Purpose) => boolean;
}

export interface EgressResult {
  /** Optional trusted composition identity for a compatible job-local embedding
   * transformation. Not a model-supplied declaration or an egress permission. */
  readonly representationIdentity?: string;
  readonly skipped: boolean; // true for LOCAL providers (no egress)
  readonly blocked: boolean; // true when fail-safe blocked egress
  readonly reason?: string;
  readonly outbound: string; // the redacted+rewritten prompt to send ("" when blocked)
  readonly rehydrate: (response: string) => string; // restore surrogates in the response (this call's vault)
  /** LLM06 output filter: scan the (rehydrated) response for a NOVEL secret the model emitted — not one of our own
   *  authorized vault values. Flags always; blocks under a high-assurance policy. */
  readonly inspect: (response: string, outPolicy?: OutputFilterPolicy) => OutputScan;
  readonly cacheMissForced: boolean; // the stable prefix had to be redacted (safety > cost)
  readonly surrogateCount: number;
}

export const EGRESS_POLICY_VERSION = "2026-08-14";

/**
 * Intercept an outbound model call: local -> skip; remote -> minimize + detect + redact (volatile-first, cache-preserving)
 * + optional rewrite + metadata-only audit, returning the outbound prompt and a rehydrate closure for the response.
 */
export function interceptEgress(
  prompt: EgressPrompt,
  provider: { readonly isLocal: boolean },
  deps: EgressDeps,
  policy: EgressPolicy = {},
): EgressResult {
  const identity = (s: string): string => s;

  const blocked = (reason: string): EgressResult => ({ skipped: false, blocked: true, reason, outbound: "", rehydrate: identity, inspect: () => ({ flagged: false, blockRecommended: false, novelByCategory: {} }), cacheMissForced: false, surrogateCount: 0 });
  if (prompt.flow) {
    const flow = prompt.flow;
    if (!deps.checkResidency) return blocked("residency enforcement unavailable for governed flow");
    const residency = deps.checkResidency(flow.region, provider.isLocal ? undefined : flow.host);
    if (!residency.allowed) return blocked(residency.reason ?? "residency policy denied governed flow");
    for (const sourceId of flow.sourceIds ?? []) {
      if (!deps.checkPurpose) return blocked("purpose enforcement unavailable for governed source");
      const purpose = deps.checkPurpose(sourceId, flow.purpose);
      if (!purpose.allowed) return blocked(purpose.reason);
    }
    for (const entryId of flow.contextEntryIds ?? []) {
      if (!flow.recipient) return blocked("contextual-integrity flow has no recipient");
      if (!deps.checkContextFlow) return blocked("contextual-integrity enforcement unavailable for governed context");
      if (!deps.checkContextFlow(entryId, flow.recipient, flow.purpose)) return blocked(`contextual-integrity policy denied entry ${entryId}`);
    }
  }

  // (1) LOCAL -> SKIP: nothing leaves the machine, so there is nothing to redact.
  if (provider.isLocal) {
    const inputValues = new Set(deps.classifier.detect(prompt.stablePrefix + prompt.volatile).map((finding) => finding.value));
    const localInspect = (response: string, outPolicy: OutputFilterPolicy = {}): OutputScan =>
      scanOutput(response, { classifier: deps.classifier, authorizedValues: inputValues, ...(deps.audit ? { audit: (e) => deps.audit!({ direction: "inbound", policyVersion: EGRESS_POLICY_VERSION, perCategory: e.perCategory, cacheMissForced: false }) } : {}) }, outPolicy);
    return { skipped: true, blocked: false, outbound: prompt.stablePrefix + prompt.volatile, rehydrate: identity, inspect: localInspect, cacheMissForced: false, surrogateCount: 0 };
  }

  // (2) REMOTE. PER-CALL ephemeral session (fresh vault, discarded when this result is dropped).
  const session = deps.session();

  // MINIMIZE the volatile portion (drop fields the model doesn't need).
  const minimized = (deps.minimize ?? identity)(prompt.volatile);

  // DETECT/CLASSIFY. FAIL-SAFE-ON-UNCERTAINTY: a high-risk path with a low-confidence finding BLOCKS (never fail-open).
  const floor = policy.confidenceFloor ?? 0.6;
  const volClass = deps.classifier.classify(minimized);
  if (policy.highRisk && volClass.findings.some((f) => f.confidence < floor)) {
    return { skipped: false, blocked: true, reason: "high-risk path: low-confidence PII detection — blocked for review (fail-safe, no egress)", outbound: "", rehydrate: identity, inspect: () => ({ flagged: false, blockRecommended: false, novelByCategory: {} }), cacheMissForced: false, surrogateCount: 0 };
  }

  // REDACT the VOLATILE portion over the per-call vault.
  const volRed = session.redact(minimized);
  let vol = volRed.redacted;

  // CACHE-PRESERVING: keep the stable prefix byte-identical UNLESS it itself carries PII/proprietary (then safety > cost).
  let outboundPrefix = prompt.stablePrefix;
  let cacheMissForced = false;
  const prefixClass = deps.classifier.classify(prompt.stablePrefix);
  if (prefixClass.findings.length > 0) {
    outboundPrefix = session.redact(prompt.stablePrefix).redacted;
    cacheMissForced = true; // surfaced honestly — we chose safety over a cache hit
  }

  // Optional REWRITE (metaprompt) applied ONLY to the volatile portion — never the stable prefix (cache). Reject a
  // rewrite that drops task-necessary content.
  if (deps.rewrite) {
    const rewritten = deps.rewrite(vol);
    const preserved = (policy.requiredContent ?? []).every((r) => rewritten.includes(r));
    if (preserved) vol = rewritten; // else keep the un-rewritten redacted volatile (reject the drop)
  }

  const outbound = outboundPrefix + vol;

  // AUDIT: per-entity, per-direction, metadata ONLY (counts + tier + policy version) — never the real values.
  const perCategory: Record<string, number> = {};
  for (const f of volClass.findings) perCategory[f.category] = (perCategory[f.category] ?? 0) + 1;
  deps.audit?.({ direction: "outbound", policyVersion: EGRESS_POLICY_VERSION, perCategory, cacheMissForced });

  // INSPECT + SELECTIVELY RESTORE on the way back — this call's vault rehydrates the response.
  const rehydrate = (response: string): string => {
    // DESLOP runs BEFORE rehydration, on the still-redacted text: prose-only, byte-verified, surrogate tokens protected.
    const cleaned = deps.deslop ? deslopPass({ text: response, transform: deps.deslop, surrogatePattern: SURROGATE_TOKEN }).output : response;
    return session.rehydrate(cleaned);
  };
  // OUTPUT FILTER (LLM06): our own rehydrated values are AUTHORIZED (excluded); a novel secret the model emitted is flagged.
  const inspect = (response: string, outPolicy: OutputFilterPolicy = {}): OutputScan =>
    scanOutput(response, { classifier: deps.classifier, authorizedValues: session.authorizedValues(), ...(deps.audit ? { audit: (e) => deps.audit!({ direction: "inbound", policyVersion: EGRESS_POLICY_VERSION, perCategory: e.perCategory, cacheMissForced: false }) } : {}) }, outPolicy);

  return { skipped: false, blocked: false, outbound, rehydrate, inspect, cacheMissForced, surrogateCount: volRed.surrogateCount };
}
