/**
 * SovereigntyPosture (Increment 16.9d) — sovereignty as an environment-adaptive SPECTRUM.
 *
 * The earlier manifest assumed the brain always has an in-box fallback (LocalProvider). But a back-of-the-
 * room operator (a laptop, an OpenRouter key mostly on the FREE TIER) may not be able to run a local model
 * at all — their only brain is an external, rate-limited free tier. Claiming a local fallback that can't
 * run is dishonest. Sovereignty is a spectrum matched to environment, and the invariant that holds at
 * EVERY point on it is: the CONTROL PLANE (audit spine + governance + deterministic safety floors) stays
 * LOCAL and never egresses. Only the COMPUTE PLANE (the brain) varies by environment.
 *
 * SOTA basis (2026-08-05): "minimum sufficient sovereignty" — classify the deployment, be honest about its
 * tier, don't force air-gap (AGVN 2026). "You are not pretending the system is whole" — report the honest
 * posture, never a false air-gap claim (buildmvpfast 2026).
 *
 * hosted-dependent (free-tier-only, NO local model) is a FIRST-CLASS supported posture — not a downgrade to
 * be warned away from. Zero deps.
 */

/** Where the brain (compute plane) runs. Declared per deployment; not assumed. */
export type BrainLocation =
  | "local" // a local model runs on this machine
  | "hosted" // a hosted API key (may be paid)
  | "free-tier" // a hosted key used mostly on a rate-limited free tier (the back-of-the-room operator)
  | "none"; // no brain wired yet (deterministic floors still operate)

export type SovereigntyPostureName =
  | "air-gapped" // brain local, zero egress (Tier 3)
  | "local-first" // brain local by default, optional research egress (Tier 2+)
  | "hybrid" // brain may be hosted/free-tier; control plane local (Tier 2)
  | "hosted-dependent"; // brain is a hosted/free-tier key, NO local model; control plane local (still Tier 2)

export interface EnvironmentFacts {
  /** Can this machine actually run a local model? (Not assumed — declared/detected.) */
  readonly localModelAvailable: boolean;
  /** Where the brain actually runs in this deployment. */
  readonly brainLocation: BrainLocation;
  /** Is there any network egress at all (research, hosted brain, remote git)? */
  readonly hasEgress: boolean;
  /** Is the operator primarily on a free/rate-limited tier? (drives resilience defaults) */
  readonly freeTierConstrained: boolean;
}

export interface SovereigntyPosture {
  readonly name: SovereigntyPostureName;
  readonly brainLocation: BrainLocation;
  readonly tier: 2 | 3; // 3 = air-gapped; 2 = minimum sufficient sovereignty (control plane local)
  readonly freeTierConstrained: boolean;
  /** Honest one-line description of what is and isn't local. */
  readonly summary: string;
}

/** Derive the honest posture from environment facts. Never claims more sovereignty than the env affords. */
export function derivePosture(env: EnvironmentFacts): SovereigntyPosture {
  if (env.brainLocation === "local" && !env.hasEgress) {
    return { name: "air-gapped", brainLocation: "local", tier: 3, freeTierConstrained: false,
      summary: "Fully local: brain runs on-device, nothing egresses. Air-gapped (Tier 3)." };
  }
  if (env.brainLocation === "local") {
    return { name: "local-first", brainLocation: "local", tier: 2, freeTierConstrained: env.freeTierConstrained,
      summary: "Brain runs locally by default; optional egress for research only. Control plane local (Tier 2)." };
  }
  if (!env.localModelAvailable && (env.brainLocation === "hosted" || env.brainLocation === "free-tier")) {
    return { name: "hosted-dependent", brainLocation: env.brainLocation, tier: 2, freeTierConstrained: env.freeTierConstrained,
      summary: `No local model available; brain is a ${env.brainLocation} key. Control plane (audit + governance + safety floors) stays local (Tier 2). Fully supported.` };
  }
  // A local model COULD run but a hosted/free brain is wired → hybrid.
  return { name: "hybrid", brainLocation: env.brainLocation, tier: 2, freeTierConstrained: env.freeTierConstrained,
    summary: "Brain may be hosted/free-tier; a local fallback exists. Control plane local (Tier 2)." };
}

/**
 * The control plane MUST be local in every posture — this is the invariant that makes Keep sovereign
 * regardless of where the brain runs. These capabilities never egress:
 */
export const CONTROL_PLANE_CAPABILITIES: readonly string[] = [
  "audit-spine", // hash-chained audit trail
  "governance", // policy decisions + records
  "deterministic-floors", // consequence analysis, patch verification, trajectory, forecast, currency
];

export interface ControlPlaneStatus {
  readonly capability: string;
  readonly local: boolean;
}

/**
 * Assert the control-plane-local invariant: audit, governance, and the deterministic safety floors are all
 * local in this deployment. This is what we actually guarantee — NOT that a local brain exists. Throws if
 * any control-plane capability is reported non-local. Holds in air-gapped, local-first, hybrid, AND
 * hosted-dependent postures.
 */
export function assertControlPlaneLocal(status: readonly ControlPlaneStatus[]): void {
  const nonLocal = status.filter((s) => !s.local);
  if (nonLocal.length > 0) {
    throw new Error(`sovereignty violated: control-plane capability not local: ${nonLocal.map((s) => s.capability).join(", ")}`);
  }
  // Every required control-plane capability must be present + local.
  for (const cap of CONTROL_PLANE_CAPABILITIES) {
    const found = status.find((s) => s.capability === cap);
    if (!found) throw new Error(`sovereignty violated: control-plane capability "${cap}" not declared`);
    if (!found.local) throw new Error(`sovereignty violated: "${cap}" is not local`);
  }
}

/** The default control-plane status for a normally-composed Keep (all local — always true by construction). */
export function defaultControlPlaneStatus(): readonly ControlPlaneStatus[] {
  return CONTROL_PLANE_CAPABILITIES.map((capability) => ({ capability, local: true }));
}
