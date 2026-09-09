/**
 * ReferenceRegistry + dated seeds (Increment 3.6b) — the perishable categories.
 *
 * Registers each shelf-life category as a ReferenceSet with an HONEST dated seed (as of today,
 * 2026-08-04) and a per-category TTL (pricing changes often → short; endpoints rarely → long).
 * Pre-seeded so Keep works fully OFFLINE on day one; the ReferenceRefresher (3.6c) keeps it
 * current when a connected env exists. Provider-agnostic: an unknown model family isn't an error —
 * it falls through to the model-blind default (the invariant that Keep serves ANY model).
 *
 * Zero deps.
 */

import { ReferenceSet, type FreshnessPolicy } from "./reference_set.js";

/** Seed date — the honest "as of" for every category below. */
export const SEED_AS_OF = "2026-08-04";
const SEED_MS = Date.parse(SEED_AS_OF + "T00:00:00Z");

// ── Category shapes ──────────────────────────────────────────────────────────

/** How a model family exposes its reasoning-effort knob (capability-detected, never assumed). */
export type EffortKnob = "graded" | "binary" | "none";

/** A known model family + its quirks. Unknown families → the model-blind default. */
export interface ModelFamily {
  readonly family: string;
  readonly effortKnob: EffortKnob;
  readonly timeoutClass: "standard" | "reasoning"; // reasoning models need 120s+
  readonly notes: string;
}

/** A provider endpoint (base URL + auth shape). */
export interface ProviderEndpoint {
  readonly id: string;
  readonly label: string;
  readonly baseURL: string;
  readonly openAICompatible: boolean;
}

/** Per-model pricing (USD per 1M tokens). Fed to the GroundedEstimator as FALLBACK only. */
export interface ReferencePricing {
  readonly model: string;
  readonly inputPerM: number;
  readonly outputPerM: number;
}

/** Capability defaults that drift over time. */
export interface CapabilityDefaults {
  readonly defaultContextTokens: number;
  readonly cacheDiscountFraction: number; // typical input-cache discount
  readonly batchDiscountFraction: number; // typical batch-tier discount
}

// ── Dated seeds (as of 2026-08-04) — honest, fallback-not-truth for verifiable facts ──

const MODEL_FAMILY_SEED: ModelFamily[] = [
  { family: "gpt", effortKnob: "graded", timeoutClass: "reasoning", notes: "graded reasoning_effort (low/med/high)" },
  { family: "gemini", effortKnob: "graded", timeoutClass: "reasoning", notes: "graded thinking levels" },
  { family: "claude", effortKnob: "graded", timeoutClass: "reasoning", notes: "adaptive/extended thinking" },
  { family: "deepseek", effortKnob: "graded", timeoutClass: "reasoning", notes: "Non-Think / Think-High / Think-Max modes" },
  { family: "kimi", effortKnob: "binary", timeoutClass: "reasoning", notes: "binary thinking toggle" },
  { family: "qwen", effortKnob: "binary", timeoutClass: "reasoning", notes: "binary thinking toggle" },
  { family: "grok", effortKnob: "none", timeoutClass: "reasoning", notes: "no effort/temperature knob" },
  { family: "llama", effortKnob: "none", timeoutClass: "standard", notes: "open-weights; no built-in effort knob" },
];

/** The model-blind default for ANY unrecognized family (provider-agnostic invariant). */
export const UNKNOWN_FAMILY_DEFAULT: ModelFamily = {
  family: "<unknown>",
  effortKnob: "none",
  timeoutClass: "reasoning", // safe: allow more time; don't assume a fast model
  notes: "unrecognized family — capability-detect at runtime; do not assume knobs exist",
};

const ENDPOINT_SEED: ProviderEndpoint[] = [
  { id: "openai", label: "OpenAI (or OpenAI-compatible)", baseURL: "https://api.openai.com/v1", openAICompatible: true },
  { id: "anthropic", label: "Anthropic (Claude)", baseURL: "https://api.anthropic.com/v1", openAICompatible: true },
  { id: "gemini", label: "Google Gemini", baseURL: "https://generativelanguage.googleapis.com/v1beta/openai", openAICompatible: true },
  { id: "openrouter", label: "OpenRouter", baseURL: "https://openrouter.ai/api/v1", openAICompatible: true },
  { id: "groq", label: "Groq", baseURL: "https://api.groq.com/openai/v1", openAICompatible: true },
  { id: "deepseek", label: "DeepSeek", baseURL: "https://api.deepseek.com/v1", openAICompatible: true },
  { id: "ollama", label: "Ollama (local)", baseURL: "http://localhost:11434/v1", openAICompatible: true },
];

const PRICING_SEED: ReferencePricing[] = [
  // Honest as-of seed; the GroundedEstimator STILL prefers a live same-day rate and treats
  // these as fallback, never quoting a dollar figure from a stale seed without saying so.
  { model: "deepseek-v4-flash", inputPerM: 0.14, outputPerM: 0.28 },
  { model: "gemini-3-flash", inputPerM: 0.5, outputPerM: 3.0 },
  { model: "gpt-5.4-nano", inputPerM: 0.2, outputPerM: 1.25 },
  { model: "gpt-5.4-mini", inputPerM: 0.75, outputPerM: 4.5 },
];

const CAPABILITY_SEED: CapabilityDefaults = {
  defaultContextTokens: 128_000,
  cacheDiscountFraction: 0.9, // input-cache hits are typically ~10% of full input price
  batchDiscountFraction: 0.5, // batch tier ~50% off
};

// ── Per-category TTLs (SOTA: don't use one TTL for all data types) ──
const DAY = 86_400_000;
const POLICIES = {
  pricing: { freshMs: 1 * DAY, graceMs: 2 * DAY, jitter: 0.15 } as FreshnessPolicy, // volatile
  modelFamilies: { freshMs: 7 * DAY, graceMs: 21 * DAY, jitter: 0.1 } as FreshnessPolicy,
  endpoints: { freshMs: 30 * DAY, graceMs: 60 * DAY, jitter: 0.1 } as FreshnessPolicy, // stable
  capabilities: { freshMs: 30 * DAY, graceMs: 60 * DAY, jitter: 0.1 } as FreshnessPolicy,
};

/**
 * The registry of perishable reference categories. Each is a self-refreshing ReferenceSet with an
 * honest dated seed. Consumers read via the typed getters, which surface freshness state.
 */
export class ReferenceRegistry {
  readonly modelFamilies: ReferenceSet<ModelFamily[]>;
  readonly endpoints: ReferenceSet<ProviderEndpoint[]>;
  readonly pricing: ReferenceSet<ReferencePricing[]>;
  readonly capabilities: ReferenceSet<CapabilityDefaults>;

  constructor(asOfMs: number = SEED_MS) {
    this.modelFamilies = new ReferenceSet({ seed: MODEL_FAMILY_SEED, policy: POLICIES.modelFamilies, asOfMs });
    this.endpoints = new ReferenceSet({ seed: ENDPOINT_SEED, policy: POLICIES.endpoints, asOfMs });
    this.pricing = new ReferenceSet({ seed: PRICING_SEED, policy: POLICIES.pricing, asOfMs });
    this.capabilities = new ReferenceSet({ seed: CAPABILITY_SEED, policy: POLICIES.capabilities, asOfMs });
  }

  /**
   * Look up a model family by name (case-insensitive substring match on the family key).
   * Provider-agnostic: an unrecognized family returns UNKNOWN_FAMILY_DEFAULT, never throws —
   * so Keep serves ANY model, and capability is detected at runtime rather than assumed.
   */
  familyFor(modelOrFamily: string, now: number = Date.now()): ModelFamily {
    const key = modelOrFamily.toLowerCase();
    const families = this.modelFamilies.get(now).value;
    return families.find((f) => key.includes(f.family)) ?? UNKNOWN_FAMILY_DEFAULT;
  }

  /** Pricing for a model, or undefined (the estimator then declines to quote from a stale seed). */
  pricingFor(model: string, now: number = Date.now()): ReferencePricing | undefined {
    return this.pricing.get(now).value.find((p) => p.model === model);
  }
}

// ── Capability effect classification (BUILD-ORDER 8.44B — CAPABILITY-NOT-PROSE) ──
//
// External-effect / destructiveness must be decided by the RESOLVED capability identity actually being invoked
// (the callee), NOT by re-parsing a prose description of it. Prose is attacker-controlled and unbounded — "gently
// tidy the remote" hides a `delete production`; a novel tool a wordlist never enumerated reads as inert. The SET
// OF TOOLS, by contrast, is finite and known. This is the object-capability / least-authority invariant: authority
// rides the resolved capability, and anything not explicitly enumerated as recoverable is deny-by-default. Unlike
// familyFor()'s permissive UNKNOWN_FAMILY_DEFAULT (serving ANY model is safe), an UNKNOWN capability here is
// FAIL-CLOSED — it must be held for review, never waved through as recoverable.

/** The externally-visible effect class of a resolved capability identity. */
export type CapabilityEffect = "recoverable" | "external" | "destructive";

/** A resolved capability/tool identity → its effect class (one allowlist entry). */
export interface CapabilityEffectRecord {
  /** The RESOLVED callee id, lowercased and EXACT-matched (e.g. "fs.write-draft"). */
  readonly id: string;
  readonly effect: CapabilityEffect;
  readonly note: string;
}

/**
 * The known-capability allowlist. ENUMERATED, not pattern-matched: an id is classified ONLY if it appears here
 * verbatim. Everything absent is UNKNOWN and MUST fail closed at the caller (hold/deny), never be treated as
 * recoverable. Extended by a deployment's real tool registry — the seam named in the estimator.
 */
const CAPABILITY_EFFECT_SEED: readonly CapabilityEffectRecord[] = [
  // Recoverable — local, revert-safe, no reach outside the workspace.
  { id: "fs.read", effect: "recoverable", note: "local read — no mutation, no external reach" },
  { id: "fs.write-draft", effect: "recoverable", note: "writes a draft/local file — revert-safe" },
  { id: "preference.set", effect: "recoverable", note: "sets a stored preference — additive, restorable" },
  { id: "note.capture", effect: "recoverable", note: "captures a note/goal — additive" },
  { id: "plan.edit", effect: "recoverable", note: "edits a plan/directive — previous version kept" },
  // External — reaches outside the workspace; can't be unsent.
  { id: "email.send", effect: "external", note: "sends mail to the outside world — unsendable" },
  { id: "http.post", effect: "external", note: "posts to a remote endpoint — external effect" },
  { id: "payment.charge", effect: "external", note: "moves money — external, irreversible" },
  { id: "deploy.release", effect: "external", note: "ships to production — external, high blast radius" },
  { id: "audio.synthesize", effect: "external", note: "submits source material to a synthesis service and may incur cost" },
  { id: "telemetry.export", effect: "external", note: "exports minimized observability data to an explicitly configured collector" },
  { id: "client.sign", effect: "external", note: "uses an explicitly configured private-development signing authority" },
  // Destructive — destroys/overwrites real work; no automatic undo.
  { id: "fs.delete", effect: "destructive", note: "deletes files — no automatic undo" },
  { id: "db.drop", effect: "destructive", note: "drops a datastore — irreversible" },
  { id: "prod.reset", effect: "destructive", note: "resets production state — irreversible" },
];

/** A resolved capability identity: a bare callee id, or a callee namespace + operation (combined as `id.operation`). */
export type CapabilityIdentity = string | { readonly id: string; readonly operation?: string };

export interface CapabilityEffectResolution {
  /** The resolved identity key this verdict was derived from (named, for the audit trail). */
  readonly id: string;
  /** true only if `id` matched an enumerated allowlist entry (else the caller MUST fail closed). */
  readonly known: boolean;
  /** The enumerated effect, or "unknown" when unmatched (deny-by-default). */
  readonly effect: CapabilityEffect | "unknown";
  readonly note: string;
}

/**
 * Resolve a capability identity to its effect class by EXACT (case-insensitive) id match against the enumerated
 * allowlist — NOT a substring/pattern match (that would be a denylist smell). An unmatched id resolves to
 * `unknown`, whose caller MUST fail closed (hold/deny), never treat it as recoverable. Deterministic, offline.
 */
export function resolveCapabilityEffect(identity: CapabilityIdentity): CapabilityEffectResolution {
  const raw = typeof identity === "string"
    ? identity
    : identity.operation !== undefined && identity.operation !== ""
      ? `${identity.id}.${identity.operation}`
      : identity.id;
  const id = raw.trim().toLowerCase();
  const rec = CAPABILITY_EFFECT_SEED.find((r) => r.id === id);
  if (rec) return { id, known: true, effect: rec.effect, note: rec.note };
  return {
    id: id || "<unresolved>",
    known: false,
    effect: "unknown",
    note: "unrecognized capability — not in the known-recoverable allowlist; hold for review (deny-by-default)",
  };
}
