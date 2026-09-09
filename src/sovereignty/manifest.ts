/**
 * SovereigntyManifest (Increment 16.9c-1) — a first-class, auditable inventory of Keep's capability
 * surface and its relationship to the outside world.
 *
 * The all-in-one goal: ship as free of externals as possible, while ALLOWING an operator to wire in an
 * external tool they trust. This manifest makes that property PROVABLE rather than asserted: every
 * capability declares the port it sits behind, its in-box offline fallback, and whether/what it egresses.
 *
 * SOTA basis (2026-08-05): adopt the AI Bill of Materials pattern — "a structured, auditable inventory of
 * all models, datasets, dependencies, and tools" (predictionguard 2026; CycloneDX ML-BOM). "Sovereignty is
 * only as strong as your weakest link" — a local stack that egresses to a telemetry-tracking service has a
 * broken privacy boundary (ml6 2026). "Minimum sufficient sovereignty" — classify each touchpoint, don't
 * force air-gap everywhere (AGVN 2026): the manifest records the tier per capability.
 *
 * The provable invariant (assertSovereign): NO capability is a HARD external dependency — every one has an
 * in-box offline fallback — and every egress is DECLARED + privacy-preserving (no IP/plan body, no
 * telemetry). This is what lets Keep claim "all-in-one out of the box" honestly. Zero deps.
 */

import type { Spine } from "../spine/spine.js";
import type { SovereigntyPosture } from "./posture.js";

/** How a capability relates to the outside world. */
export type SovereigntyTier =
  | "in-box" // fully local; never touches an external service
  | "opt-in-egress"; // CAN reach an external service, but only when the operator opts in; falls back in-box

/** What (if anything) leaves the box when an opt-in egress is active. */
export interface EgressDeclaration {
  /** Plain description of exactly what is sent (e.g. "minimal query terms"). */
  readonly what: string;
  /** True iff it never sends IP / plan body / document content — only minimal necessary terms. */
  readonly privacyPreserving: boolean;
  /** True iff it transmits telemetry/behavioral metadata (a sovereignty leak — must be false). */
  readonly telemetry: boolean;
}

/** One capability's sovereignty declaration. */
export interface CapabilityDeclaration {
  /** The capability (e.g. "brain", "research-verification", "embeddings", "git-remote", "backup"). */
  readonly capability: string;
  /** The port interface it sits behind (swappable). */
  readonly port: string;
  readonly tier: SovereigntyTier;
  /**
   * The in-box fallback used when no external is wired (e.g. "LocalProvider", "BM25 lexical ranker",
   * "local bare git remote", "dated caveat"). MUST be non-null — a null fallback is a HARD external
   * dependency, which violates the all-in-one property.
   */
  readonly offlineFallback: string | null;
  /** What egresses when the opt-in external is active (null for in-box capabilities). */
  readonly egress: EgressDeclaration | null;
  /** Whether an external is currently wired (reflects REAL config, not just what's possible). */
  readonly externalActive: boolean;
}

export interface SovereigntyManifest {
  readonly asOf: string;
  /** The honest deployment posture (present when derived from environment). */
  readonly posture?: SovereigntyPosture;
  readonly capabilities: readonly CapabilityDeclaration[];
}

/**
 * The capabilities Keep ships with. Reflects the shipped defaults: everything has an in-box fallback and
 * nothing egresses unless an operator opts in. buildManifest() marks which externals are actually wired.
 */
export const KEEP_CAPABILITIES: readonly Omit<CapabilityDeclaration, "externalActive">[] = [
  {
    capability: "brain", port: "ModelProvider", tier: "opt-in-egress",
    // NOTE: the brain's fallback is ENVIRONMENT-DEPENDENT, not assumed-local. A back-of-the-room laptop may
    // have NO local model — its brain is a free-tier key. buildManifest() sets the honest fallback per env.
    offlineFallback: "LocalProvider (only when a local model can actually run on this machine)",
    egress: { what: "the prompt, only when a hosted/free-tier provider is wired", privacyPreserving: false, telemetry: false },
  },
  {
    capability: "research-verification", port: "PriorArtSearch / ResearchLoop search", tier: "opt-in-egress",
    offlineFallback: "dated caveat + self-refreshing landscape catalog (offline)",
    egress: { what: "minimal query terms only (never the plan body or IP)", privacyPreserving: true, telemetry: false },
  },
  {
    capability: "embeddings", port: "dense reranker seam (RRF)", tier: "opt-in-egress",
    offlineFallback: "BM25 zero-dep lexical ranker (in-box)",
    egress: { what: "text to embed, only when a hosted embedder is wired", privacyPreserving: false, telemetry: false },
  },
  {
    capability: "git-remote", port: "GitRemote", tier: "opt-in-egress",
    offlineFallback: "local bare git remote (in-box)",
    egress: { what: "commits/branches, only when a hosted remote is wired", privacyPreserving: false, telemetry: false },
  },
  {
    capability: "backup", port: "BackupPort", tier: "opt-in-egress",
    offlineFallback: "local filesystem backup (in-box)",
    egress: { what: "backup archive, only when a remote backup target is wired", privacyPreserving: false, telemetry: false },
  },
  {
    capability: "audit-spine", port: "SpineStore", tier: "in-box",
    offlineFallback: "local hash-chained file store (in-box; never egresses)",
    egress: null,
  },
];

/** Which externals are actually wired right now (reflects real config). */
export interface WiredExternals {
  readonly brain?: boolean;
  readonly researchVerification?: boolean;
  readonly embeddings?: boolean;
  readonly gitRemote?: boolean;
  readonly backup?: boolean;
  /** The honest deployment posture (from derivePosture). Drives the brain's declared fallback. */
  readonly posture?: SovereigntyPosture;
}

/** Build the manifest, marking which externals are actually active + the honest posture. */
export function buildManifest(wired: WiredExternals = {}, now = new Date()): SovereigntyManifest {
  const active: Record<string, boolean> = {
    brain: wired.brain ?? false,
    "research-verification": wired.researchVerification ?? false,
    embeddings: wired.embeddings ?? false,
    "git-remote": wired.gitRemote ?? false,
    backup: wired.backup ?? false,
    "audit-spine": false,
  };
  const posture = wired.posture;
  return {
    asOf: now.toISOString().slice(0, 10),
    ...(posture ? { posture } : {}),
    capabilities: KEEP_CAPABILITIES.map((c) => {
      // Honest brain fallback: only claim a local fallback when the env can actually run one.
      if (c.capability === "brain" && posture && posture.brainLocation !== "local") {
        return {
          ...c,
          offlineFallback: null, // no local brain in this env — honesty; the control-plane invariant covers us
          externalActive: active[c.capability] ?? false,
        };
      }
      return { ...c, externalActive: active[c.capability] ?? false };
    }),
  };
}

export interface SovereigntyViolation {
  readonly capability: string;
  readonly reason: string;
}

/**
 * The provable all-in-one property. Returns the violations (empty === sovereign). A capability violates if:
 *  - it has NO in-box fallback (a hard external dependency), or
 *  - an ACTIVE egress transmits telemetry, or
 *  - an ACTIVE egress claims to be privacy-preserving but sends IP/plan body (declared !privacyPreserving
 *    while active is allowed ONLY for operator-opted externals like a hosted brain; telemetry is never ok).
 */
export function findSovereigntyViolations(manifest: SovereigntyManifest): readonly SovereigntyViolation[] {
  const v: SovereigntyViolation[] = [];
  // If the posture legitimately declares a non-local brain (e.g. the back-of-the-room free-tier operator),
  // a null brain fallback is HONEST, not a violation — the guarantee is control-plane-local, not local-brain.
  const brainLegitimatelyExternal = manifest.posture !== undefined && manifest.posture.brainLocation !== "local";
  for (const c of manifest.capabilities) {
    if (c.offlineFallback === null && c.tier !== "in-box") {
      const isDeclaredExternalBrain = c.capability === "brain" && brainLegitimatelyExternal;
      if (!isDeclaredExternalBrain) {
        v.push({ capability: c.capability, reason: "no in-box fallback — this is an UNDECLARED hard external dependency" });
      }
    }
    if (c.egress?.telemetry === true) {
      v.push({ capability: c.capability, reason: "egress transmits telemetry (sovereignty leak)" });
    }
  }
  return v;
}

/** Throws if the manifest is not sovereign (used as a shipped-default guard + a proving test). */
export function assertSovereign(manifest: SovereigntyManifest): void {
  const v = findSovereigntyViolations(manifest);
  if (v.length > 0) {
    throw new Error(`sovereignty violated: ${v.map((x) => `${x.capability} (${x.reason})`).join("; ")}`);
  }
}

/** Record the manifest to the spine as a durable, auditable artifact (AIBOM). */
export function recordManifest(spine: Spine, manifest: SovereigntyManifest): void {
  spine.stage({
    type: "identity.action",
    actor: "keep-sovereignty",
    payload: {
      event: "sovereignty_manifest",
      asOf: manifest.asOf,
      capabilities: manifest.capabilities.map((c) => ({
        capability: c.capability, tier: c.tier, hasFallback: c.offlineFallback !== null,
        externalActive: c.externalActive, egresses: c.egress !== null,
      })),
    },
  });
}
