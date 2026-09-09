/**
 * CONTEXTUAL-INTEGRITY SENSITIVE-CONTEXT VAULT — Round 1 of the personalization moat.
 *
 * Privacy is not secrecy; it is APPROPRIATE INFORMATION FLOW (Nissenbaum 2004). A disclosure is governed by five
 * parameters — sender, recipient, information-subject, information-type, transmission-principle — and a violation
 * is accurate/available-but-INAPPROPRIATE flow (right data, wrong recipient/purpose/consent). Persistent memory is
 * the specific risk (CIMemories 2025): a health disclosure a user made to get help is in-context for that help,
 * and out-of-context for a teammate, another project, or a marketing purpose.
 *
 * The structured-PII firewall (`data_classifier`) catches identifiers (SSN, email) but NOT special-category
 * FREE-TEXT ("I was diagnosed with cancer" — GDPR Art. 9: health/sexuality/religion/politics/biometric). This
 * vault closes that gap and adds CI flow-control on top of the existing PII stack:
 *   - `classifySpecialCategory` — a conservative, HIGH-PRECISION detector (the SEAM; a full NER/ML detector is the
 *     estimator). Conservative on purpose: over-detection tokenizes everything and destroys utility.
 *   - `capture` — DATA-MINIMIZATION: only special-category data enters the vault; everything else is ignored. The
 *     datum is wrapped in a default-RESTRICTIVE `CIContext` (recipient = the subject only; purpose = assisting the
 *     subject) and stored ENCRYPTED under the per-project key (reusing the crypto namespace), keyed by subject.
 *   - `mayFlow` — the deterministic default-DENY egress gate: a flow is permitted only if the recipient is
 *     permitted AND the purpose is permitted. This governs CROSS-context egress, not the subject's own use.
 *   - `revealToSubject` — the information-subject can always read their own context (accessible every round,
 *     protected like an env from everyone else); another user reading the same project's vault gets nothing.
 *
 * BUILT + proven in-env: the CI flow-control + user-scoping + reveal. SEAM: the special-category detector and the
 * persistent store. Deterministic, below the model — flow decisions are never delegated to an LLM.
 */

import type { ProjectNamespace } from "../session/project_registry.js";
import type { Ciphertext } from "../keystore/keystore.js";
import type { Purpose } from "../ingest/data_governance.js";

/** GDPR Art. 9 special categories the vault governs (free-text, beyond the structured-PII firewall). */
export type SpecialCategory = "health" | "sexuality" | "religion" | "politics" | "biometric";

/** Nissenbaum's five CI parameters (sender is implicit — the user disclosing). Default-restrictive. */
export interface CIContext {
  readonly subject: string; // information-subject: whose data this is (a user id)
  readonly informationType: SpecialCategory;
  readonly permittedRecipients: readonly string[]; // who may receive it (default: [subject])
  readonly permittedPurposes: readonly Purpose[]; // for what (default: assist the subject)
  readonly transmissionPrinciple: string; // under what condition it was shared
}

export interface VaultEntry {
  readonly id: string;
  readonly subject: string;
  readonly informationType: SpecialCategory;
  readonly ci: CIContext;
}

export interface FlowRequest {
  readonly recipient: string;
  readonly purpose: Purpose;
}

export interface CaptureOptions {
  readonly permittedRecipients?: readonly string[] | undefined;
  readonly permittedPurposes?: readonly Purpose[] | undefined;
  readonly transmissionPrinciple?: string | undefined;
}

/**
 * Conservative, high-precision special-category detector (SEAM). Matches explicit disclosure patterns only — it
 * would rather MISS an oblique mention than over-tag benign text (the privacy-utility trade-off). A production
 * deployment injects a NER/ML detector; this deterministic core is the honest seam boundary + a safe default.
 */
export function classifySpecialCategory(text: string): SpecialCategory | undefined {
  const t = text.toLowerCase();
  // health: an explicit diagnosis / condition statement.
  if (/\b(i\s+(?:have|was diagnosed with|am living with)|diagnosed with|my)\s+[\w\s]*\b(cancer|diabetes|hiv|aids|depression|anxiety|bipolar|schizophreni|epilep|leukemia|lupus|chemo(?:therapy)?|tumou?r|pregnan)/.test(t))
    return "health";
  // sexuality: an explicit orientation statement.
  if (/\bi(?:'m| am)\s+(?:gay|lesbian|bisexual|transgender|trans|queer|asexual|nonbinary|non-binary)\b/.test(t))
    return "sexuality";
  // religion: an explicit faith statement.
  if (/\bi(?:'m| am)\s+(?:a\s+)?(?:muslim|christian|jewish|jew|hindu|buddhist|catholic|atheist|agnostic|sikh|mormon)\b/.test(t))
    return "religion";
  // politics: an explicit affiliation statement.
  if (/\bi(?:'m| am)\s+(?:a\s+)?(?:democrat|republican|liberal|conservative|socialist|libertarian|communist|green party)\b/.test(t))
    return "politics";
  // biometric: explicit biometric identifiers.
  if (/\b(fingerprint|retina scan|iris scan|facial recognition|dna (?:sample|profile|sequence)|genome)\b/.test(t))
    return "biometric";
  return undefined;
}

/**
 * The vault. Stores ONLY special-category data (data-minimization), encrypted at rest under the per-project key,
 * keyed by information-subject. The persistent store is the SEAM (here an in-memory list); the CI logic is BUILT.
 */
export class SensitiveContextVault {
  private readonly store = new Map<string, { subject: string; type: SpecialCategory; ci: CIContext; enc: Ciphertext }>();
  private seq = 0;

  constructor(private readonly ns: ProjectNamespace) {}

  /**
   * Capture a disclosure. Returns undefined (no capture) unless the text is special-category — the vault never
   * hoards general text. A captured datum gets a default-RESTRICTIVE CIContext (only the subject may receive it,
   * only for assisting the subject) unless the caller widens it explicitly, and is stored encrypted + subject-keyed.
   */
  capture(subject: string, content: string, opts?: CaptureOptions): VaultEntry | undefined {
    const type = classifySpecialCategory(content);
    if (type === undefined) return undefined; // data-minimization: not special-category ⇒ not vaulted
    const ci: CIContext = {
      subject,
      informationType: type,
      permittedRecipients: opts?.permittedRecipients ?? [subject],
      permittedPurposes: opts?.permittedPurposes ?? ["assist-subject"],
      transmissionPrinciple: opts?.transmissionPrinciple ?? "confidence",
    };
    const id = `ci:${this.ns.projectId}:${subject}:${this.seq++}`;
    this.store.set(id, { subject, type, ci, enc: this.ns.encrypt(content) }); // encrypted at rest under project key
    return { id, subject, informationType: type, ci };
  }

  /**
   * The deterministic default-DENY egress gate (the heart of CI flow-control). A flow is permitted ONLY if the
   * recipient is on the permitted list AND the purpose is on the permitted list. Everything else is denied — even
   * accurate, available data. This governs cross-context egress; the subject's own use is permitted via `capture`
   * defaults (recipient = subject).
   */
  mayFlow(entry: VaultEntry, request: FlowRequest): boolean {
    const recipientOk = entry.ci.permittedRecipients.includes(request.recipient);
    const purposeOk = entry.ci.permittedPurposes.includes(request.purpose);
    return recipientOk && purposeOk; // default-deny: both must hold
  }

  /**
   * The information-subject can always read their OWN context (accessible every round, protected like an env from
   * everyone else). A different user — even in the same project — gets nothing: reveal is scoped by subject.
   */
  revealToSubject(requester: string): readonly { entry: VaultEntry; content: string }[] {
    const out: { entry: VaultEntry; content: string }[] = [];
    for (const [id, rec] of this.store) {
      if (rec.subject !== requester) continue; // user-scoping: only the subject's own data
      out.push({
        entry: { id, subject: rec.subject, informationType: rec.type, ci: rec.ci },
        content: this.ns.decrypt(rec.enc),
      });
    }
    return out;
  }

  /** Look up a stored entry by id (for a flow decision) — subject-independent handle; flow is gated by mayFlow. */
  get(id: string): VaultEntry | undefined {
    const rec = this.store.get(id);
    return rec === undefined ? undefined : { id, subject: rec.subject, informationType: rec.type, ci: rec.ci };
  }
}
