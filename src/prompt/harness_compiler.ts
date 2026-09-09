/**
 * F2 / H-3 (REVET 2026-08) — THE PER-MODEL HARNESS COMPILER. Turns a target model id + a detected capability tier into
 * the `ModelProfile` the `AdaptivePromptLayer` consumes, plus the model's real reasoning-effort control KIND and its
 * prompt-cache mechanics. It produces a profile; it does not re-implement assembly.
 *
 *   • KNOWN model id → a TUNED harness (real tier / effort-control kind / timeout / cache mechanics).
 *   • UNKNOWN model id → a SAFE natural-language DEFAULT (conservative; nothing model-specific is fabricated).
 *   • The detected CAPABILITY tier CAPS the rung (SAFE-DEGRADING): never richer than the host supports.
 *
 * HONEST: unknown → default (never fabricated); the effort knob is reported as a CEILING not a floor where the model
 * treats it that way (e.g. GPT-5.6 may emit zero reasoning tokens even at high effort); the roster is SEEDED + DATED,
 * not evergreen. STALENESS-RESISTANT: an operator config override replaces/extends the seeded table (this domain moves
 * monthly). BOTH-TRACKS: zero-config seeded default n=1; config override + per-model tuning + cache mechanics for an org.
 *
 * NOTE (seeded 2026-08-14 from KEEP_SOTA_AUDIT_2026-08.md Topics 1 & 5): the entries below are a dated snapshot. Model
 * ids, effort APIs, and cache economics change monthly — override via config rather than trusting this table blindly.
 */

import type { CapabilityTier } from "../frontdoor/capability_adaptive.js";
import type { ModelProfile } from "../prompt/prompt_strategy.js";
import type { EffortKnob } from "../reference/reference_registry.js";
import type { AdaptivePromptLayer, PromptRequest, AssembledPrompt } from "../prompt/adaptive_prompt_layer.js";

/** Least -> most capable. Used to CAP the model's tuned rung at the host's detected capability. */
const TIER_RANK: Record<CapabilityTier, number> = { minimal: 0, lean: 1, standard: 2, rich: 3 };

/** The REAL 2026 reasoning-effort control kinds (Topic 1). Distinct from the legacy graded|binary|none EffortKnob. */
export type EffortControlKind =
  | "mode+effort" // OpenAI GPT-5.6: reasoning.mode (standard|pro) + reasoning.effort (low|med|high|max); max tier-gated
  | "adaptive" // Anthropic Opus/Fable: adaptive thinking, effort scales automatically
  | "budget_tokens" // Anthropic Sonnet / Bedrock reasoning_tokens
  | "thinking_level" // Google Gemini: thinking level
  | "thinking_mode" // DeepSeek: thinking mode (on/off-ish)
  | "none"; // no reasoning-effort control surface

export interface EffortControl {
  readonly kind: EffortControlKind;
  /** True when the model treats effort as a CEILING not a floor (may do zero reasoning on easy prompts even at high). */
  readonly ceilingNotFloor: boolean;
  /** True when the top effort level is gated to a specific tier (e.g. OpenAI `max` is Sol-only). */
  readonly maxTierGated?: boolean;
}

export type CacheStyle = "explicit-breakpoint" | "explicit-cache_control" | "implicit" | "disk-backed" | "none";
export type TtlClass = "30min" | "5min" | "hourly-storage" | "none";

/** Per-model prompt-cache mechanics (Topic 5) — consumed by R-EGRESS's cache-preserving rewrite. */
export interface CacheMechanics {
  readonly minCacheablePrefixTokens: number;
  readonly cacheStyle: CacheStyle;
  readonly breakpointBudget: number; // <= 4
  readonly lookback: number; // 50 GPT-5.6 / 20 Claude / 0 implicit
  readonly ttlClass: TtlClass;
  readonly writePremium: number; // 1.25 where applicable, else 1
}

export interface ModelTuning {
  readonly tier: CapabilityTier;
  readonly effortControl: EffortControl;
  readonly timeoutClass: "standard" | "reasoning";
  readonly cache: CacheMechanics;
}

// Cache-mechanics presets by family (dated 2026-08).
const OPENAI_CACHE: CacheMechanics = { minCacheablePrefixTokens: 1024, cacheStyle: "explicit-breakpoint", breakpointBudget: 4, lookback: 50, ttlClass: "30min", writePremium: 1.25 };
const CLAUDE_CACHE_512: CacheMechanics = { minCacheablePrefixTokens: 512, cacheStyle: "explicit-cache_control", breakpointBudget: 4, lookback: 20, ttlClass: "5min", writePremium: 1.25 };
const CLAUDE_CACHE_1024: CacheMechanics = { minCacheablePrefixTokens: 1024, cacheStyle: "explicit-cache_control", breakpointBudget: 4, lookback: 20, ttlClass: "5min", writePremium: 1.25 };
const GEMINI_CACHE: CacheMechanics = { minCacheablePrefixTokens: 0, cacheStyle: "implicit", breakpointBudget: 0, lookback: 0, ttlClass: "hourly-storage", writePremium: 1 };
const DEEPSEEK_CACHE: CacheMechanics = { minCacheablePrefixTokens: 0, cacheStyle: "disk-backed", breakpointBudget: 0, lookback: 0, ttlClass: "none", writePremium: 1 };
const NO_CACHE: CacheMechanics = { minCacheablePrefixTokens: 0, cacheStyle: "none", breakpointBudget: 0, lookback: 0, ttlClass: "none", writePremium: 1 };

const CEILING = (maxTierGated?: boolean): EffortControl => ({ kind: "mode+effort", ceilingNotFloor: true, ...(maxTierGated ? { maxTierGated: true } : {}) });
const ADAPTIVE: EffortControl = { kind: "adaptive", ceilingNotFloor: false };
const BUDGET: EffortControl = { kind: "budget_tokens", ceilingNotFloor: false };
const THINK_LEVEL: EffortControl = { kind: "thinking_level", ceilingNotFloor: false };
const THINK_MODE: EffortControl = { kind: "thinking_mode", ceilingNotFloor: false };
const NO_EFFORT: EffortControl = { kind: "none", ceilingNotFloor: false };

/**
 * Seeded, DATED known-model roster (2026-08-14, from Topics 1 & 5). Entries marked (seed) have an unconfirmed effort
 * knob and use a conservative kind -- override via config for exactness. Qwen's current-gen id is unconfirmed (TODO).
 */
const KNOWN_MODELS: Readonly<Record<string, ModelTuning>> = {
  // OpenAI GPT-5.6 (Sol/Terra/Luna): two-axis mode+effort; `max` Sol-only; effort is a CEILING; explicit-breakpoint cache.
  "gpt-5.6-sol": { tier: "rich", effortControl: CEILING(true), timeoutClass: "reasoning", cache: OPENAI_CACHE },
  "gpt-5.6-terra": { tier: "standard", effortControl: CEILING(false), timeoutClass: "reasoning", cache: OPENAI_CACHE },
  "gpt-5.6-luna": { tier: "lean", effortControl: CEILING(false), timeoutClass: "standard", cache: OPENAI_CACHE },
  // Anthropic: Opus/Fable adaptive thinking; Sonnet budget_tokens; Opus-5 cache min halved to 512.
  "claude-opus-5": { tier: "rich", effortControl: ADAPTIVE, timeoutClass: "reasoning", cache: CLAUDE_CACHE_512 },
  "claude-fable-5": { tier: "rich", effortControl: ADAPTIVE, timeoutClass: "reasoning", cache: CLAUDE_CACHE_512 },
  "claude-opus-4.8": { tier: "rich", effortControl: ADAPTIVE, timeoutClass: "reasoning", cache: CLAUDE_CACHE_1024 },
  "claude-sonnet-4.6": { tier: "standard", effortControl: BUDGET, timeoutClass: "reasoning", cache: CLAUDE_CACHE_1024 },
  // Google Gemini 3.x: thinking_level; implicit caching on by default.
  "gemini-3.1-pro": { tier: "rich", effortControl: THINK_LEVEL, timeoutClass: "reasoning", cache: GEMINI_CACHE },
  "gemini-3.5-flash": { tier: "standard", effortControl: THINK_LEVEL, timeoutClass: "standard", cache: GEMINI_CACHE },
  "gemini-3.6-flash": { tier: "standard", effortControl: THINK_LEVEL, timeoutClass: "standard", cache: GEMINI_CACHE },
  // Open-weight / other (self-hostable -- the provider-agnostic local path).
  "grok-4.5": { tier: "rich", effortControl: THINK_LEVEL, timeoutClass: "reasoning", cache: NO_CACHE }, // (seed)
  "deepseek-v4": { tier: "standard", effortControl: THINK_MODE, timeoutClass: "reasoning", cache: DEEPSEEK_CACHE },
  "kimi-k3": { tier: "standard", effortControl: THINK_LEVEL, timeoutClass: "reasoning", cache: NO_CACHE }, // (seed)
  "glm-5.2": { tier: "standard", effortControl: THINK_LEVEL, timeoutClass: "reasoning", cache: NO_CACHE }, // (seed)
  "command-a-plus": { tier: "standard", effortControl: NO_EFFORT, timeoutClass: "standard", cache: NO_CACHE },
  "mistral-medium-3.5": { tier: "standard", effortControl: NO_EFFORT, timeoutClass: "standard", cache: NO_CACHE },
  "mistral-small-4": { tier: "lean", effortControl: NO_EFFORT, timeoutClass: "standard", cache: NO_CACHE },
  "llama-4": { tier: "standard", effortControl: NO_EFFORT, timeoutClass: "standard", cache: NO_CACHE },
  // TODO(qwen): current Qwen generation id unconfirmed as of 2026-08 -- add once verified.
};

/** The safe fallback for an unknown model: a conservative NL harness that assumes nothing model-specific. */
const SAFE_NL_DEFAULT: ModelTuning = { tier: "standard", effortControl: NO_EFFORT, timeoutClass: "standard", cache: NO_CACHE };

/** Map a real effort-control KIND down to the legacy EffortKnob (graded|binary|none) so selectStrategy stays green. */
function legacyEffortKnob(kind: EffortControlKind): EffortKnob {
  switch (kind) {
    case "mode+effort":
    case "adaptive":
    case "budget_tokens":
    case "thinking_level":
      return "graded"; // a continuous/graded effort surface
    case "thinking_mode":
      return "binary"; // on/off
    case "none":
      return "none";
  }
}

/** Operator override: replace or extend the seeded roster (staleness resistance) and/or the default tuning. */
export interface HarnessOverrides {
  readonly models?: Readonly<Record<string, ModelTuning>>;
  readonly defaultTuning?: ModelTuning;
}

export interface CompiledHarness {
  readonly model: string;
  readonly known: boolean;
  /** The profile the AdaptivePromptLayer consumes (tier = the chosen rung after capping; effortKnob = mapped legacy). */
  readonly profile: ModelProfile;
  readonly rung: CapabilityTier;
  /** The real 2026 effort-control kind for this model (ceiling-not-floor surfaced honestly). */
  readonly effortControl: EffortControl;
  /** The model's prompt-cache mechanics (consumed by R-EGRESS's cache-preserving rewrite). */
  readonly cache: CacheMechanics;
  /** HONEST: which rung was chosen and why (known-vs-unknown + cap + ceiling-not-floor). */
  readonly reason: string;
}

/**
 * Compile a harness for a target model at a detected capability tier, with optional operator overrides. Known -> tuned;
 * unknown -> safe NL default; the capability tier caps the rung (safe-degrading). Reports rung + reason + ceiling-not-floor.
 */
export function compileHarness(model: string, capabilities: CapabilityTier, overrides?: HarnessOverrides): CompiledHarness {
  // Override replaces/extends the seeded table (staleness resistance): an override entry wins over the built-in.
  const table: Readonly<Record<string, ModelTuning>> = { ...KNOWN_MODELS, ...(overrides?.models ?? {}) };
  const tuning = table[model];
  const known = tuning !== undefined;
  const base = tuning ?? overrides?.defaultTuning ?? SAFE_NL_DEFAULT;
  // Cap the rung at the host's detected capability -- never assemble a harness richer than the host can run.
  const capped = TIER_RANK[base.tier] <= TIER_RANK[capabilities];
  const rung: CapabilityTier = capped ? base.tier : capabilities;
  const profile: ModelProfile = { tier: rung, effortKnob: legacyEffortKnob(base.effortControl.kind), timeoutClass: base.timeoutClass };
  const ceilingNote = base.effortControl.ceilingNotFloor ? "; effort is a CEILING not a floor" : "";
  const reason = known
    ? `known model '${model}' -> tuned harness (base ${base.tier}, effort '${base.effortControl.kind}'${ceilingNote}); capability '${capabilities}' -> rung '${rung}'${capped ? "" : " (capability-capped)"}`
    : `unknown model '${model}' -> safe NL default (base ${base.tier}, no fabricated tuning); capability '${capabilities}' -> rung '${rung}'${capped ? "" : " (capability-capped)"}`;
  return { model, known, profile, rung, effortControl: base.effortControl, cache: base.cache, reason };
}

/**
 * Assemble a prompt through the compiled harness -- composes the AdaptivePromptLayer with the compiled profile. No
 * parallel prompt path: the harness only supplies the profile; the layer does the actual assembly.
 */
export function harnessAssemble(
  harness: CompiledHarness,
  layer: AdaptivePromptLayer,
  req: Omit<PromptRequest, "profile">,
): AssembledPrompt {
  return layer.assemble({ ...req, profile: harness.profile });
}
