/**
 * F1.6 — Capability-adaptive tiering (works for everyone, adapts to what's there).
 *
 * The moat: the same product serves a frontier multi-model stack AND the person with
 * one cheap/local model on an old laptop. The capability/cost gap between those is
 * ~100x (Aug 2026: DeepSeek V4 ~$0.44/M vs GPT-5.5-pro $30/$180), so adapting to the
 * available brain isn't a nicety — it's what makes the product usable at all.
 *
 * SOTA basis: task-complexity tiering is the established pattern — simple tasks
 * (classification, extraction, slot-filling, constrained generation) run well even on
 * 1-3B models, while ambiguous hard reasoning needs frontier. Onboarding is MOSTLY the
 * simple kind, which is why a weak model can still drive it. The real risk is the
 * "silent quality regression": a flow calibrated for a strong model produces
 * structurally different output on a weak one and breaks downstream parsing. So on
 * weaker tiers we DON'T ask for rich free-form reasoning and hope — we lean hard on
 * the typed F1.5 action schema and degrade ambition, not correctness.
 *
 * Tiers are ABSTRACT (not model names) so the mapping survives model swaps (the
 * RouteLLM result: a strong/weak router held up when the underlying models changed).
 *
 * SAFETY INVARIANT (non-negotiable): a weaker brain NEVER gets weaker safety. The
 * external-confidence bar RISES on weak tiers and adversarial vetting never drops
 * below a floor — a weak model's proposals are LESS trustworthy, not more. Capability
 * adaptation changes ambition and cost, never the safety envelope.
 */

import type { BrainDescriptor } from "./brain_port.js";

export type CapabilityTier = "rich" | "standard" | "lean" | "minimal";

/** Signals we can probe about a brain without a network round-trip. */
export interface CapabilitySignals {
  /** Advertised context window in tokens, if known. */
  readonly contextWindow?: number;
  /** Rough input cost per million tokens (USD), if known. Lower can imply a smaller model. */
  readonly costPerMTokUSD?: number;
  /** A measured quality score in [0,1] from prior runs, if we have one (best signal). */
  readonly measuredQuality?: number;
  /** True if the human explicitly flagged a low-resource / offline environment. */
  readonly lowResourceDeclared?: boolean;
}

export interface AdaptiveProfile {
  readonly tier: CapabilityTier;
  /** Max tokens of context to assemble for a turn (keeps weak/small models reliable). */
  readonly contextTokenBudget: number;
  /** Max output tokens to request per turn. */
  readonly maxOutputTokens: number;
  /** How the conversation should shape its asks. */
  readonly conversationStyle: "adaptive-freeform" | "guided" | "structured-only";
  /** If true, the conversation driver falls back to the deterministic F1 state machine. */
  readonly useDeterministicFallback: boolean;
  /** Gate knobs for this tier (merged into GateConfig). Safety only tightens on weak tiers. */
  readonly gate: { externalConfidenceThreshold: number; adversarialRounds: number };
  /** A plain-language note the UI can show about how we've adapted. */
  readonly note: string;
}

/**
 * Classify a brain into a capability tier from its descriptor + any probed signals.
 * Precedence: a measured quality score wins; else declared low-resource; else infer
 * from context window / cost / local-vs-hosted. Unknown => 'standard' (safe middle),
 * never 'rich' (don't assume more capability than proven).
 */
export function classifyCapability(brain: BrainDescriptor, signals: CapabilitySignals = {}): CapabilityTier {
  if (signals.lowResourceDeclared) return "minimal";

  if (typeof signals.measuredQuality === "number") {
    const q = signals.measuredQuality;
    if (q >= 0.85) return "rich";
    if (q >= 0.65) return "standard";
    if (q >= 0.4) return "lean";
    return "minimal";
  }

  // Local runtimes on consumer hardware: assume lean unless a big context says otherwise.
  if (brain.kind === "local") {
    if ((signals.contextWindow ?? 0) >= 128_000) return "standard";
    return "lean";
  }

  // Hosted: infer from context window + cost when we have them.
  const ctx = signals.contextWindow ?? 0;
  const cost = signals.costPerMTokUSD;
  if (ctx >= 400_000 || (cost !== undefined && cost >= 5)) return "rich";
  if (ctx >= 128_000 || (cost !== undefined && cost >= 1)) return "standard";
  if (cost !== undefined && cost > 0 && cost < 1) return "lean"; // cheap hosted model
  return "standard"; // unknown hosted -> safe middle
}

const PROFILES: Record<CapabilityTier, Omit<AdaptiveProfile, "tier">> = {
  rich: {
    contextTokenBudget: 200_000,
    maxOutputTokens: 4_000,
    conversationStyle: "adaptive-freeform",
    useDeterministicFallback: false,
    gate: { externalConfidenceThreshold: 0.75, adversarialRounds: 3 },
    note: "You've got a powerful model connected — I can handle rich, open-ended conversations and deeper research.",
  },
  standard: {
    contextTokenBudget: 32_000,
    maxOutputTokens: 2_000,
    conversationStyle: "guided",
    useDeterministicFallback: false,
    gate: { externalConfidenceThreshold: 0.78, adversarialRounds: 3 },
    note: "Your model is a solid all-rounder — I'll keep things focused and check in when it matters.",
  },
  lean: {
    contextTokenBudget: 8_000,
    maxOutputTokens: 1_000,
    conversationStyle: "structured-only",
    useDeterministicFallback: false,
    // Weaker model => LESS trustworthy proposals => HIGHER confidence bar, not lower.
    gate: { externalConfidenceThreshold: 0.85, adversarialRounds: 3 },
    note: "I'm working with a lighter model, so I'll keep questions short and simple and lean on clear yes/no steps. Everything still gets the same safety checks.",
  },
  minimal: {
    contextTokenBudget: 3_000,
    maxOutputTokens: 500,
    conversationStyle: "structured-only",
    useDeterministicFallback: true, // degrade to the deterministic F1 flow — never break
    gate: { externalConfidenceThreshold: 0.9, adversarialRounds: 3 },
    note: "I'm running in a lightweight mode that works even on modest hardware or a single small model. It's simpler, but it works — and it's just as careful about safety.",
  },
};

/** Build the adaptive profile for a brain + signals. */
export function adaptiveProfileFor(brain: BrainDescriptor, signals: CapabilitySignals = {}): AdaptiveProfile {
  const tier = classifyCapability(brain, signals);
  return { tier, ...PROFILES[tier] };
}

/**
 * The floor of the safety envelope — the minimum any tier may use. Used to ASSERT that
 * no profile ever weakens safety below this, regardless of capability.
 */
export const SAFETY_FLOOR = { minExternalConfidenceThreshold: 0.75, minAdversarialRounds: 3 } as const;

/** True if a profile respects the safety floor (weaker capability never means weaker safety). */
export function profileRespectsSafetyFloor(p: AdaptiveProfile): boolean {
  return (
    p.gate.externalConfidenceThreshold >= SAFETY_FLOOR.minExternalConfidenceThreshold &&
    p.gate.adversarialRounds >= SAFETY_FLOOR.minAdversarialRounds
  );
}
