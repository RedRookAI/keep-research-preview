/**
 * LoRA local-adapter tier (Increment 10a) — adapter model + versioning + ENTRY gates.
 *
 * This is the most gated capability in Keep: opt-in, OFF by default, and it NEVER trains weights
 * itself — it ORCHESTRATES and GATES an external sandboxed trainer. Gradient-free learning (item 6)
 * stays the default and the safe floor.
 *
 * SOTA basis (2026-08-04, re-verified): LoRA is NOT automatically safe. "LoRA efficiently undoes
 * safety training" (Lermen; Shadow Alignment) — a few bad examples subvert alignment while preserving
 * helpfulness, so preserved helpfulness is NOT evidence of safety. NEW 2026 finding (arXiv 2605.30189):
 * LoRA adapters can be reliably BACKDOORED via training-data poisoning at ~4.2% poison ratio while
 * retaining baseline task performance — so a capability eval alone cannot catch a backdoored adapter;
 * the training DATA must be provenance-gated + poison-screened. RLVR is the one safety-preserving
 * family but only when rewards are genuinely verifiable (unit tests/compilers/exact-match) and can
 * still be weaponized (HarmRLVR) — so verifiable-reward-only is necessary, not sufficient.
 *
 * This module: the adapter model + registry + the ENTRY gates (authorization, sandbox, data
 * provenance/poison screen, verifiable-reward-only). The eval + composition gates are 10b; the deploy
 * orchestrator is 10c. Zero deps.
 */

import type { Spine } from "../spine/spine.js";

export type AdapterStatus = "candidate" | "canary" | "active" | "rejected" | "retired";

/** The reward signal an adapter was trained against — must be verifiable for the tier to consider it. */
export type RewardKind = "unit-tests" | "compiler" | "exact-match" | "cited-facts" | "human-preference" | "model-judge";

/** Whether a reward kind is genuinely VERIFIABLE (RLVR-eligible) vs a soft signal. */
export function isVerifiableReward(kind: RewardKind): boolean {
  return kind === "unit-tests" || kind === "compiler" || kind === "exact-match" || kind === "cited-facts";
}

/** Provenance + poison-screen metadata for an adapter's training data (the 2026 backdoor finding). */
export interface TrainingDataProvenance {
  /** Number of training examples. */
  readonly exampleCount: number;
  /** Fraction of examples from an untrusted/unverified source (the poison-ratio proxy). */
  readonly untrustedFraction: number;
  /** Whether every example passed the ingestion/sanitization gate (scanIngestion-style). */
  readonly allScreened: boolean;
  /** Whether a behavioral backdoor probe was run on the trained adapter. */
  readonly backdoorProbed: boolean;
}

/** A versioned LoRA adapter (metadata only — the weights live in the sandbox, not in Keep's process). */
export interface LoraAdapter {
  readonly id: string;
  readonly version: number;
  /** What capability it targets (a specific measured failure mode, from item 8). */
  readonly targetSignature: string;
  readonly rewardKind: RewardKind;
  readonly provenance: TrainingDataProvenance;
  /** Opaque handle to the sandboxed weights (never loaded into Keep's process). */
  readonly weightsRef: string;
  status: AdapterStatus;
  readonly createdTs: number;
}

/** Per-session human authorization — this tier is NEVER covered by a scheduled envelope. */
export interface SessionAuthorization {
  readonly sessionId: string;
  readonly operator: string;
  /** Explicit, fresh authorization for THIS adapter deploy (not a standing grant). */
  readonly authorizedAdapterId: string;
  readonly grantedTs: number;
  /** Short TTL — a session authorization is not a standing envelope. */
  readonly expiresTs: number;
}

export interface EntryGateOptions {
  /** Max untrusted fraction allowed in training data. Default 0.042 (the 2026 poison threshold). */
  readonly maxUntrustedFraction?: number;
}

export interface EntryGateResult {
  readonly passed: boolean;
  readonly gate: string;
  readonly reason: string;
}

/** The registry of adapters + whether the whole tier is even enabled (ships OFF). */
export class AdapterRegistry {
  private readonly adapters = new Map<string, LoraAdapter>();
  private tierEnabled = false;

  constructor(private readonly spine: Spine) {}

  /** Power-user opt-in. The tier does nothing until this is explicitly called. */
  enableTier(operator: string, justification: string): void {
    this.tierEnabled = true;
    this.spine.stage({ type: "identity.action", actor: "lora", payload: { event: "tier_enabled", operator, justification } });
  }

  disableTier(operator: string): void {
    this.tierEnabled = false;
    this.spine.stage({ type: "identity.action", actor: "lora", payload: { event: "tier_disabled", operator } });
  }

  get isEnabled(): boolean {
    return this.tierEnabled;
  }

  register(adapter: LoraAdapter): void {
    this.adapters.set(adapter.id, adapter);
    this.spine.stage({ type: "identity.action", actor: "lora", payload: { event: "adapter_registered", id: adapter.id, version: adapter.version, target: adapter.targetSignature } });
  }

  get(id: string): LoraAdapter | undefined {
    return this.adapters.get(id);
  }

  /** Currently loaded adapters — active and canary — that every new adapter must be composed against. */
  activeAdapters(): LoraAdapter[] {
    return [...this.adapters.values()].filter((a) => a.status === "active" || a.status === "canary");
  }

  setStatus(id: string, status: AdapterStatus): void {
    const a = this.adapters.get(id);
    if (a) { a.status = status; this.spine.stage({ type: "identity.action", actor: "lora", payload: { event: "adapter_status", id, status } }); }
  }
}

/**
 * The ENTRY gates — all must hold before an adapter is even eligible for eval. Ordered, fail-closed:
 * tier-enabled → session authorization (fresh, matching, unexpired) → sandbox asserted → verifiable
 * reward → training-data provenance/poison screen. Returns the first failing gate, or a pass.
 */
export function checkEntryGates(
  registry: AdapterRegistry,
  adapter: LoraAdapter,
  auth: SessionAuthorization | undefined,
  sandboxed: boolean,
  now: number,
  opts: EntryGateOptions = {},
): EntryGateResult {
  const maxUntrusted = opts.maxUntrustedFraction ?? 0.042;

  if (!registry.isEnabled) {
    return { passed: false, gate: "tier-enabled", reason: "LoRA tier is OFF (opt-in power-user feature); gradient-free learning is the default" };
  }
  // Per-session human authorization — never envelope-covered.
  if (!auth) {
    return { passed: false, gate: "session-authorization", reason: "no per-session human authorization (this tier is never covered by a scheduled envelope)" };
  }
  if (auth.authorizedAdapterId !== adapter.id) {
    return { passed: false, gate: "session-authorization", reason: `authorization is for ${auth.authorizedAdapterId}, not ${adapter.id}` };
  }
  if (now > auth.expiresTs) {
    return { passed: false, gate: "session-authorization", reason: "session authorization expired (fresh per-deploy auth required)" };
  }
  // Sandbox — asserted, never assumed.
  if (!sandboxed) {
    return { passed: false, gate: "sandbox", reason: "training/deploy must run sandboxed/isolated — refused (never assume isolation)" };
  }
  // Verifiable reward only.
  if (!isVerifiableReward(adapter.rewardKind)) {
    return { passed: false, gate: "verifiable-reward", reason: `reward '${adapter.rewardKind}' is not genuinely verifiable; only unit-tests/compiler/exact-match/cited-facts are RLVR-eligible` };
  }
  // Training-data provenance + poison screen (the 2026 backdoor finding).
  if (!adapter.provenance.allScreened) {
    return { passed: false, gate: "data-provenance", reason: "not all training examples passed the ingestion/sanitization screen" };
  }
  if (adapter.provenance.untrustedFraction > maxUntrusted) {
    return { passed: false, gate: "poison-screen", reason: `untrusted-data fraction ${(adapter.provenance.untrustedFraction * 100).toFixed(1)}% > ${(maxUntrusted * 100).toFixed(1)}% (LoRA backdoors saturate ~4.2%)` };
  }
  if (!adapter.provenance.backdoorProbed) {
    return { passed: false, gate: "backdoor-probe", reason: "no behavioral backdoor probe run (a backdoored adapter retains baseline task performance, so a capability eval cannot catch it)" };
  }
  return { passed: true, gate: "entry", reason: "all entry gates passed" };
}
