/**
 * PERSONALIZATION as convenience within a SAFETY ENVELOPE (theme 2's payoff over the revision spine).
 *
 * The vetted thesis: the personalization SOTA (learn preferences from interaction; condition generation on a
 * retrieved persona) is a SAFETY ANTI-PATTERN for an orchestrator — it converges stored-injection ("stored
 * XSS": a stored preference carrying an instruction that fires when read), sycophancy-amplification (the system
 * *preferred* into being less safe), preference-poisoning, and persona-jailbreak, plus classic cold-start /
 * filter-bubble / drift. Two 2026 results force the structural design: LLMs measurably OVER-APPLY preferences
 * as global rules and stronger adherence makes it WORSE (SCALE @ ICML 2026), and DETERMINISTIC version-aware
 * resolution beats LLM-mediated resolution by +10–21pp ("Don't Ask the LLM to Track Freshness"). So Keep builds
 * the SAFE INVERSION:
 *   (1) EXPLICIT, not learned — preferences come only from the operator via the spine (learned inference is a
 *       deferred, clamped, consequence-gated follow-up — NOT done here).
 *   (2) DATA, not instructions — a preference VALUE is inert data validated against an enum/range and applied
 *       by deterministic code; it is NEVER text conditioning a prompt or an instruction the model obeys.
 *   (3) CONVENIENCE, never a safety lever — the CLAMP: a preference may only move WITHIN policy bounds; it can
 *       never relax a safety floor, widen autonomy past the backstop, or exceed the operator's model ceiling
 *       (monotone-toward-caution, reusing the raise-only / autonomy-backstop pattern).
 *   (4) CURRENT-VIEW, auditable, reversible — reads the spine's current (non-superseded) versions; the operator
 *       supersedes to change or revert (drift + agency handled structurally).
 *   (5) SCOPED, not blanket — CP-net-style conditional preferences (ceteris paribus): a preference carries the
 *       scope it applies to and is used ONLY when the current context matches; most-specific wins; no match ⇒
 *       not applied (fail-safe narrow — the structural answer to the over-application failure).
 *
 * BUILT + proven in-env: resolution + scope-match + clamp + validation. SEAM: the preference VALUES (operator
 * input via the spine). This module reads `RevisionStore.allCurrent("preference")`; it modifies nothing else.
 */

import type { RevisionStore, Version } from "../frontdoor/revision_store.js";
import { atLeastAsAutonomous, type AutonomyLevel } from "../frontdoor/autonomy_profile.js";

export type PromptFormat = "xml" | "markdown" | "terse" | "json";
export type Verbosity = "terse" | "normal" | "detailed";

/** The dimensions an operator preference may name. Cosmetic ones are enum-validated; the safety-touching ones
 *  (minReliability / autonomy / modelTier) are what the CLAMP bounds — a preference can request them but can
 *  only ever move toward caution / within policy. */
export type PreferenceDimension = "promptFormat" | "verbosity" | "minReliability" | "autonomy" | "modelTier";

const COSMETIC_ENUM: Record<"promptFormat" | "verbosity", readonly string[]> = {
  promptFormat: ["xml", "markdown", "terse", "json"],
  verbosity: ["terse", "normal", "detailed"],
};
const AUTONOMY_VALUES: readonly AutonomyLevel[] = ["observer", "approver", "collaborator", "operator", "delegator"];

/** Safe defaults used when a dimension has no (valid, in-scope) preference. */
export interface EffectiveProfile {
  readonly promptFormat: PromptFormat;
  readonly verbosity: Verbosity;
  readonly minReliability: number; // effective reliability floor (>= the policy floor after clamp)
  readonly autonomy: AutonomyLevel; // effective autonomy (<= the policy backstop after clamp)
  readonly modelTier: number; // effective model tier (<= the operator ceiling after clamp)
}

/** Policy bounds the clamp enforces — the safety envelope. */
export interface PolicyBounds {
  readonly reliabilityFloor: number; // a preference may RAISE this, never lower it
  readonly autonomyBackstop: AutonomyLevel; // a preference may LOWER autonomy, never exceed this
  readonly modelCeilingTier: number; // a preference may pick lower, never exceed this
  readonly defaultPromptFormat: PromptFormat;
  readonly defaultVerbosity: Verbosity;
}

/** The current context a scoped preference is matched against (CP-net antecedent). */
export interface PersonalizeContext {
  readonly scope?: string | undefined; // e.g. "project:alpha"; undefined = no particular scope
}

interface ParsedPref {
  readonly dimension: PreferenceDimension;
  readonly scope?: string | undefined; // absent ⇒ global (applies unless a scoped one overrides)
  readonly value: string;
}

/** Parse a preference Version's itemKey ("pref:<dim>" or "pref:<dim>@<scope>") + content into a typed pref.
 *  Returns undefined for anything that isn't a well-formed, KNOWN dimension — unknown keys are ignored (data,
 *  not instructions: we never act on an unrecognized preference). */
function parsePref(v: Version): ParsedPref | undefined {
  if (!v.itemKey.startsWith("pref:")) return undefined;
  const body = v.itemKey.slice(5);
  const [dimRaw, scope] = body.split("@", 2) as [string, string | undefined];
  if (!isDimension(dimRaw)) return undefined; // unknown dimension ⇒ ignored
  return { dimension: dimRaw, scope, value: v.content };
}

function isDimension(s: string): s is PreferenceDimension {
  return s === "promptFormat" || s === "verbosity" || s === "minReliability" || s === "autonomy" || s === "modelTier";
}

/** Validate a preference VALUE as data. Cosmetic ⇒ must be in the enum. Numeric/level ⇒ must parse in range.
 *  Anything else is REJECTED (returns undefined) — never obeyed. */
export function validate(dim: PreferenceDimension, value: string): string | number | undefined {
  if (dim === "promptFormat" || dim === "verbosity") {
    return COSMETIC_ENUM[dim].includes(value) ? value : undefined; // data-not-instructions: enum only
  }
  if (dim === "autonomy") return (AUTONOMY_VALUES as readonly string[]).includes(value) ? value : undefined;
  if (dim === "minReliability") {
    const n = Number(value);
    return Number.isFinite(n) && n >= 0 && n <= 1 ? n : undefined;
  }
  // modelTier
  const n = Number(value);
  return Number.isInteger(n) && n >= 0 ? n : undefined;
}

const READ_KIND = "preference" as const;

/** Read the CURRENT (non-superseded) preference versions from the spine. Isolated so the current-view
 *  dependency is explicit and testable. */
function readCurrentPreferences(store: RevisionStore): Version[] {
  return store.allCurrent(READ_KIND); // spine excludes superseded ⇒ drift handled structurally
}

/** CP-net scope resolution: among valid parsed prefs for a dimension, the most-specific match wins — a pref
 *  scoped to the current context beats a global (unscoped) one; a pref scoped to a DIFFERENT context does not
 *  apply at all (fail-safe narrow). Returns the winning raw value, or undefined if none applies. */
function resolveDimension(prefs: readonly ParsedPref[], dim: PreferenceDimension, ctx: PersonalizeContext): string | number | undefined {
  let globalWin: string | number | undefined;
  let scopedWin: string | number | undefined;
  for (const p of prefs) {
    if (p.dimension !== dim) continue;
    const v = validate(dim, p.value);
    if (v === undefined) continue; // invalid ⇒ rejected as data
    if (p.scope === undefined) globalWin = v; // applies unless a scoped one overrides
    else if (ctx.scope !== undefined && p.scope === ctx.scope) scopedWin = v; // in-scope match
    // a pref scoped to a non-matching context is intentionally skipped (no overgeneralization)
  }
  return scopedWin !== undefined ? scopedWin : globalWin; // most-specific wins
}

/** Resolve the operator's current preferences into a RAW (pre-clamp) profile, scope-matched to `ctx`. */
export function resolveProfile(store: RevisionStore, ctx: PersonalizeContext, bounds: PolicyBounds): EffectiveProfile {
  const prefs = readCurrentPreferences(store).map(parsePref).filter((p): p is ParsedPref => p !== undefined);
  const raw = {
    promptFormat: resolveDimension(prefs, "promptFormat", ctx) as PromptFormat | undefined,
    verbosity: resolveDimension(prefs, "verbosity", ctx) as Verbosity | undefined,
    minReliability: resolveDimension(prefs, "minReliability", ctx) as number | undefined,
    autonomy: resolveDimension(prefs, "autonomy", ctx) as AutonomyLevel | undefined,
    modelTier: resolveDimension(prefs, "modelTier", ctx) as number | undefined,
  };
  return applyWithinPolicy(raw, bounds);
}

interface RawProfile {
  readonly promptFormat?: PromptFormat | undefined;
  readonly verbosity?: Verbosity | undefined;
  readonly minReliability?: number | undefined;
  readonly autonomy?: AutonomyLevel | undefined;
  readonly modelTier?: number | undefined;
}

/**
 * THE CLAMP — personalization is convenience, never a safety lever. Cosmetic dimensions pass through (or fall
 * to the safe default). Safety-touching dimensions may only move TOWARD caution / within policy:
 *   - minReliability: the effective floor is max(requested, policyFloor) — a preference can RAISE the floor,
 *     never lower it below the policy floor.
 *   - autonomy: the effective level is the LESS autonomous of (requested, backstop) — a preference can reduce
 *     autonomy, never exceed the backstop (reuses `atLeastAsAutonomous`).
 *   - modelTier: min(requested, ceiling) — a preference can pick cheaper, never exceed the operator ceiling.
 */
export function applyWithinPolicy(raw: RawProfile, bounds: PolicyBounds): EffectiveProfile {
  const minReliability = Math.max(raw.minReliability ?? bounds.reliabilityFloor, bounds.reliabilityFloor); // never below floor
  const reqAut = raw.autonomy ?? bounds.autonomyBackstop;
  const autonomy = atLeastAsAutonomous(reqAut, bounds.autonomyBackstop) ? bounds.autonomyBackstop : reqAut; // never above backstop
  const modelTier = Math.min(raw.modelTier ?? bounds.modelCeilingTier, bounds.modelCeilingTier); // never above ceiling
  return {
    promptFormat: raw.promptFormat ?? bounds.defaultPromptFormat,
    verbosity: raw.verbosity ?? bounds.defaultVerbosity,
    minReliability,
    autonomy,
    modelTier,
  };
}

export { readCurrentPreferences, resolveDimension };
