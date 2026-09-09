/**
 * Setup-phase composition — the first-run/onboarding surface for a non-engineer on a fresh, possibly account-less
 * install. Assembles three built-ahead pieces from primitives so the composition root has one call to make:
 *   • BrainResolver (F0)  — default to a LOCAL model; else accept a bring-your-own key (stored crypto-shredded).
 *   • capability audit    — an honest "what works right now" report that surfaces free/local paths FIRST.
 *   • applyDirective (F2) — translate → validate → gate → apply a config directive, never widening scope unapproved.
 *
 * SOTA basis (2026): the ecosystem default is "assume an OpenAI key + a credit card; local is a footnote" — Keep
 * inverts that (local-first, key optional, free path surfaced first), which is the privacy/sovereignty posture the
 * self-hosted-agent guidance converges on. The hybrid pattern (local for routine, a stronger model for the hard
 * minority) is exactly what the capability audit's needsStrongReasoning flag + the cost-cascade router express.
 */

import { CryptoShredKeyStore } from "../keystore/keystore.js";
import { PlanExecuteGate, type AdversarialReviewer } from "./plan_execute_gate.js";
import { PolicyEngine } from "../governance/policy_engine.js";
import { RevisionStore } from "./revision_store.js";
import { BrainResolver, type LocalProbe, type ResolveOutcome } from "./brain_resolver.js";
import { auditCapabilities, type AuditEnv, type AuditReport, type Capability } from "./capability_audit.js";
import { applyDirective, type ApplyResult, type ApplyOptions } from "./config_applier.js";
import { brainBackedReviewer } from "./working_phase.js";
import type { BrainCall } from "./conversation_driver.js";
import type { Spine } from "../spine/spine.js";

export interface SetupPhaseConfig {
  readonly spine: Spine;
  /** Model seam for the config gate's adversarial reviewer (fail-closed on outage). */
  readonly brainCall: BrainCall;
  /** Detect a local OpenAI-compatible runtime (Ollama/LM Studio/Jan); null → ask for a key. */
  readonly probeLocal: LocalProbe;
  /** The environment the capability audit reports against. */
  readonly env: AuditEnv;
  /** Shared keystore (brain credential + message secrets under one crypto-shred boundary). Default: fresh. */
  readonly keystore?: CryptoShredKeyStore;
  /** Shared revision store for config items. Default: fresh (spine-backed). */
  readonly revisions?: RevisionStore;
  readonly policyVersion?: string;
  readonly reviewer?: AdversarialReviewer;
  readonly capabilities?: readonly Capability[];
}

export interface SetupPhaseDeps {
  readonly resolver: BrainResolver;
  /** The honest capability report for the current environment (free/local paths first). */
  readonly audit: () => AuditReport;
  /** Apply a config directive through the gate (scope-widening → human tap; unresolved → clarify). */
  readonly applyDirective: (directiveText: string, opts?: ApplyOptions) => Promise<ApplyResult>;
}

/** Assemble the setup-phase deps for the FrontDoor's first-run flow. */
export function buildSetupPhase(cfg: SetupPhaseConfig): SetupPhaseDeps {
  const keystore = cfg.keystore ?? new CryptoShredKeyStore();
  const revisions = cfg.revisions ?? new RevisionStore(cfg.spine);
  const policy = new PolicyEngine(cfg.policyVersion ?? "frontdoor-setup-v1");
  const reviewer = cfg.reviewer ?? brainBackedReviewer(cfg.brainCall);
  const gate = new PlanExecuteGate(cfg.spine, policy, reviewer);
  const resolver = new BrainResolver(cfg.spine, keystore, cfg.probeLocal);
  return {
    resolver,
    audit: () => auditCapabilities(cfg.env, cfg.capabilities),
    applyDirective: (directiveText, opts) => applyDirective(directiveText, { spine: cfg.spine, gate, revisions }, opts ?? {}),
  };
}

export type { ResolveOutcome };
