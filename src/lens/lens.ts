/**
 * LENSES — Round 5 of the personalization moat. A lens is PERSONALITY + CLAMPED PREFERENCES, nothing more — so it
 * is safe by construction.
 *
 * SoulConfig's load-bearing rule is SEPARATE PERSONALITY FROM POLICY: a soul shapes voice/tone/stance and can
 * NEVER touch the gate/floor/autonomy (persona-encoded rules break on 20-30% of adversarial prompts; souls are
 * untrusted input, sanitized by `parseSoul`). A lens's preference overlay is written THROUGH the personalization
 * envelope, so the CLAMP guarantees a lens can only ever move CONVENIENCE within policy bounds — it can never
 * widen autonomy or relax a floor. Overlay composition falls out of the spine's supersede + CP-net scope: lens
 * prefs are LOW-precedence (global/unscoped), the user's explicit (scoped) prefs supersede them; "none" =
 * DEFAULT_SOUL + no overlay; "custom" = author your own (sanitized). The companion lens — the confidant-trap
 * surface — carries Round 2's anti-dependence guards.
 *
 * BUILT + proven in-env: the lens abstraction, the four presets, overlay composition (precedence), and the
 * clamped application. SEAM: the prewired capability modules themselves (video/content creation, etc.).
 */

import { SoulConfig, DEFAULT_SOUL, parseSoul, type RawSoul } from "../soul/soul_config.js";
import { putScopedPreference, resolveScopedProfile } from "../personalize/scoped_preferences.js";
import type { PreferenceDimension, PolicyBounds, PersonalizeContext, EffectiveProfile } from "../personalize/personalize.js";
import type { RevisionStore } from "../frontdoor/revision_store.js";
import type { ProjectNamespace } from "../session/project_registry.js";

export type LensPreset = "companion" | "researcher" | "marketer" | "content-creator" | "none" | "custom";

export interface LensPreference {
  readonly dimension: PreferenceDimension;
  readonly value: string;
}

export interface Lens {
  readonly preset: LensPreset;
  readonly soul: SoulConfig; // voice only — separated from policy
  readonly preferenceOverlay: readonly LensPreference[]; // convenience prefs, clamped at resolve
  readonly modules?: readonly string[] | undefined; // SEAM: prewired capability modules
  readonly guards?: readonly string[] | undefined; // e.g. ["anti-dependence"] for the companion lens
}

// ---- the presets ----

/** No lens: the friendly all-rounder default, no overlay. */
export const NONE_LENS: Lens = { preset: "none", soul: DEFAULT_SOUL, preferenceOverlay: [] };

/** Companion: warm, conversational — and it INHERITS Round 2's anti-dependence guards (the confidant-trap surface). */
export const COMPANION_LENS: Lens = {
  preset: "companion",
  soul: { name: "Keep", tagline: "a steady companion", tone: "warm, plain-language, unhurried", decisionStyle: "listens first, offers gently" },
  preferenceOverlay: [{ dimension: "verbosity", value: "detailed" }],
  guards: ["anti-dependence"],
};

/** Researcher: precise, source-oriented. */
export const RESEARCHER_LENS: Lens = {
  preset: "researcher",
  soul: { name: "Keep", tagline: "a rigorous research partner", tone: "precise, neutral, cites sources", decisionStyle: "lays out evidence, flags uncertainty" },
  preferenceOverlay: [{ dimension: "verbosity", value: "detailed" }, { dimension: "promptFormat", value: "markdown" }],
};

/** Marketer: persuasive, audience-aware. */
export const MARKETER_LENS: Lens = {
  preset: "marketer",
  soul: { name: "Keep", tagline: "a sharp marketing partner", tone: "punchy, audience-first, benefit-led", decisionStyle: "leads with the hook" },
  preferenceOverlay: [{ dimension: "promptFormat", value: "markdown" }],
};

/** Content creator: creative, format-fluent. Ships with prewired content modules (the SEAM). */
export const CONTENT_CREATOR_LENS: Lens = {
  preset: "content-creator",
  soul: { name: "Keep", tagline: "a versatile content partner", tone: "creative, vivid, format-fluent", decisionStyle: "offers several angles" },
  preferenceOverlay: [{ dimension: "verbosity", value: "detailed" }],
  modules: ["content-creation", "video-creation"],
};

/** Build a CUSTOM lens from untrusted raw soul input — SANITIZED via parseSoul so it can't smuggle authority into
 *  the persona (persona-jailbreak-proof). */
export function makeCustomLens(rawSoul: RawSoul, overlay: readonly LensPreference[], modules?: readonly string[]): Lens {
  return {
    preset: "custom",
    soul: parseSoul(rawSoul), // strips any authority-encoding fields into rejectedDirectives
    preferenceOverlay: overlay,
    ...(modules !== undefined ? { modules } : {}),
  };
}

/** The anti-dependence (and other) guards a lens carries — the caller applies these (e.g. wellbeing guardrails). */
export function lensGuards(lens: Lens): readonly string[] {
  return lens.guards ?? [];
}

export interface AppliedLens {
  readonly soul: SoulConfig;
  readonly effectiveProfile: EffectiveProfile; // CLAMPED — the lens can never relax a floor
}

/**
 * Apply a lens: set the voice-only soul and write the overlay preferences THROUGH the envelope at LOW precedence
 * (global/unscoped) so a user's scoped preference supersedes. Returns the sanitized soul + the CLAMPED effective
 * profile (a lens overlay requesting a relaxed floor is neutralized by the envelope's clamp at resolve).
 */
export function applyLens(
  lens: Lens,
  store: RevisionStore,
  ns: ProjectNamespace,
  ctx: PersonalizeContext,
  bounds: PolicyBounds,
): AppliedLens {
  for (const p of lens.preferenceOverlay) {
    putScopedPreference(store, ns, p.dimension, p.value); // GLOBAL (no scope) ⇒ low precedence; user scoped prefs win
  }
  const effectiveProfile = resolveScopedProfile(store, ns, ctx, bounds); // CLAMPED resolution
  return { soul: lens.soul, effectiveProfile };
}
