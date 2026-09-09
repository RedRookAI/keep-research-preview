/**
 * IsolationTier (Increment 17) — the honest, environment-adaptive isolation ladder for executing AI-
 * generated code (the solve pipeline runs the project's tests on a patch Keep just wrote — untrusted).
 *
 * Tiers by strength: microvm > gvisor > container > process > none. selectTier() picks the STRONGEST
 * AVAILABLE from detected capabilities and declares it HONESTLY — a back-of-house laptop with no KVM gets
 * process isolation, truthfully labeled, never a false microVM claim (mirrors the sovereignty posture).
 *
 * The key second/third-order move: isolation STRENGTH feeds the autonomy ceiling. A bad patch executing
 * under weak isolation has a larger blast radius on escape, so weaker isolation → a LOWER auto-approve
 * ceiling (more human review). This wires isolation into the oversight/consequence layer.
 *
 * SOTA basis (2026-08-05): isolation hierarchy microVM (dedicated kernel, HW-enforced) > gVisor (user-space
 * kernel) > hardened container > bare process; STANDARD DOCKER IS NOT SUFFICIENT for untrusted AI code
 * (northflank/zylos/bunnyshell/vietanh 2026; ~90% incident reduction, zylos). microVMs need Linux+KVM —
 * cannot run on macOS/Windows/a constrained laptop (bunnyshell 2026) → environment-adaptive honest tier.
 * "Start strong, relax only when the threat model justifies it" (northflank). Isolation strength feeds
 * autonomy: "maintain deterministic safety alongside autonomous flexibility" (vietanh). Zero deps.
 */

/** Isolation strength tiers (strongest → weakest). */
export type IsolationTier = "microvm" | "gvisor" | "container" | "process" | "none";

/** Strength ordering (higher = stronger). */
export const TIER_STRENGTH: Record<IsolationTier, number> = {
  microvm: 4, gvisor: 3, container: 2, process: 1, none: 0,
};

/**
 * ROUND 43 — the WEAKER of a declared tier and the tier that will actually run.
 *
 * A declaration is not evidence. `KeepPipelineDeps.isolationTier` is a claim the operator makes,
 * and `KeepPipelineDeps.isolationExecutor` is what actually executes; the two are independent
 * inputs and nothing compared them. Measured: declaring `microvm` while
 * `ProcessIsolationExecutor` ran the tests granted the `full` autonomy ceiling — auto-approval,
 * and therefore **no decision brief** — on the strength of the claim alone.
 *
 * Note the direction of the reward: declaring a STRONGER tier made Keep LESS careful. An
 * unverified claim that buys autonomy is the confused-deputy shape this project already named
 * once (Z156) — an authority derived from the thing it is supposed to govern.
 *
 * Taking the minimum is the fail-safe composition: a claim can only ever LOWER the ceiling
 * relative to what is actually enforced, never raise it.
 */
export function weakerTier(a: IsolationTier, b: IsolationTier): IsolationTier {
  return TIER_STRENGTH[a] <= TIER_STRENGTH[b] ? a : b;
}

/** Detected/declared capabilities of the host environment. */
export interface IsolationCapabilities {
  /** Linux + KVM present (required for Firecracker/Kata microVMs). */
  readonly kvmAvailable: boolean;
  /** gVisor (runsc) available. */
  readonly gvisorAvailable: boolean;
  /** A container runtime (docker/podman/containerd) available. */
  readonly containerRuntime: boolean;
  /** Can scope the working dir to the project (never home) + resource-limit a child process. */
  readonly canScopeProcess: boolean;
}

export interface IsolationSelection {
  readonly tier: IsolationTier;
  /** Honest one-line description of what isolation this deployment actually has. */
  readonly summary: string;
  /** True if this is the strongest tier the environment could support (nothing stronger was available). */
  readonly strongestAvailable: true;
}

/**
 * Select the STRONGEST AVAILABLE isolation tier and declare it honestly. Never claims a tier the
 * environment can't provide. A back-of-house laptop (no KVM, no gVisor, no container) → process isolation
 * if it can scope a child; otherwise "none".
 */
export function selectTier(caps: IsolationCapabilities): IsolationSelection {
  if (caps.kvmAvailable) {
    return { tier: "microvm", strongestAvailable: true, summary: "microVM (dedicated kernel, hardware-enforced) — strongest; front-of-house Hetzner/KVM." };
  }
  if (caps.gvisorAvailable) {
    return { tier: "gvisor", strongestAvailable: true, summary: "gVisor (user-space kernel, syscall interception) — strong; no KVM present." };
  }
  if (caps.containerRuntime) {
    return { tier: "container", strongestAvailable: true, summary: "hardened container (shared kernel) — moderate; no microVM/gVisor. Autonomy is reduced accordingly." };
  }
  if (caps.canScopeProcess) {
    return { tier: "process", strongestAvailable: true, summary: "scoped process (project-dir only, resource-limited) — back-of-house floor; no container/VM. Autonomy is reduced accordingly." };
  }
  return { tier: "none", strongestAvailable: true, summary: "NO isolation available — risky execution will be refused, not silently run." };
}

/**
 * The autonomy CEILING for a given isolation tier (the second/third-order feedback). The weaker the
 * isolation, the lower the ceiling — because a bad patch that escapes under weak isolation has a larger
 * blast radius, so more should route to a human. Values align with the oversight router's bands.
 */
export type AutonomyCeiling = "full" | "reduced" | "minimal" | "refuse-risky";
export function isolationAutonomyCeiling(tier: IsolationTier): AutonomyCeiling {
  switch (tier) {
    case "microvm": return "full"; // strongest isolation → the oversight router's normal ceiling applies
    case "gvisor": return "full";
    case "container": return "reduced"; // shared kernel → escape possible → gate more
    case "process": return "minimal"; // only process scoping → gate most; auto-approve only trivial-reversible
    case "none": return "refuse-risky"; // no isolation → refuse to execute anything risky
  }
}

/** Ceiling strength ordering (higher = more autonomy). The weakest is `refuse-risky` (the floor). */
const CEILING_BY_RANK: readonly AutonomyCeiling[] = ["refuse-risky", "minimal", "reduced", "full"];
const CEILING_RANK: Record<AutonomyCeiling, number> = { "refuse-risky": 0, minimal: 1, reduced: 2, full: 3 };

/** Drop an autonomy ceiling by ONE rung (never below the `refuse-risky` floor). Deterministic. */
export function weakenCeiling(c: AutonomyCeiling): AutonomyCeiling {
  return CEILING_BY_RANK[Math.max(0, CEILING_RANK[c] - 1)] ?? "refuse-risky";
}

/**
 * The MEASURED containment a run's attestation PROVED — the input to the evidence-bound ceiling. Both fields
 * come from the BUILD-ORDER 1.7 verifier's output (`AttestationVerification`): `verifiedTier` is the tier the
 * evidence backs (already capped DOWN from any forged-up claim), and `measuredDegradations` are the honest
 * degradations that evidence carried. This is the ONE thing the ceiling reads — never the raw tier label.
 */
export interface MeasuredContainment {
  readonly verifiedTier: IsolationTier;
  readonly measuredDegradations: readonly string[];
}

/**
 * BUILD-ORDER 2.3 (REVISIT-ISOLATION-GATING) — the autonomy ceiling RE-DERIVED from what the run's
 * attestation PROVED, not from the tier LABEL alone (Z187). Round 43 gated only `refuse-risky` because it
 * MEASURED that the default process floor did not confine an in-process runner; 1.3/1.5 built a namespace+
 * rlimit jail and a Job Object, so the harness asked whether the ceiling should now rise. Re-measured THIS
 * round: those are CAPABILITIES, not the default wiring (`buildEnforcingRunner` is called by no src file),
 * so the default path's evidence still recomputes to a bare `process` (degraded []) and its ceiling stays
 * `minimal` — CONFIRMED by evidence, not asserted from a stale table. What CHANGES is that the ceiling is
 * now a FUNCTION OF EVIDENCE:
 *   - the nominal ceiling is taken from `verifiedTier` (the 1.7-verified, evidence-capped tier), so a
 *     forged-up label that already capped DOWN buys only the proven tier's ceiling;
 *   - a DEGRADED measurement (net-deny unenforceable, Job Object degraded) drops the ceiling ONE rung, so
 *     the gate EXTENDS to the real, weaker boundary rather than granting the tier's clean ceiling;
 *   - a CLEAN measurement (no degradations) keeps the nominal ceiling — no false demotion of an honest tier.
 * Bounded by what the tier PROVABLY prevents (the SOTA disconfirming case: a namespace escape / shared-kernel
 * LPE is still in scope), so this never RAISES a ceiling above `isolationAutonomyCeiling(verifiedTier)`.
 */
export function isolationCeilingFromEvidence(m: MeasuredContainment): AutonomyCeiling {
  const nominal = isolationAutonomyCeiling(m.verifiedTier);
  // A degraded measurement proved LESS containment than the tier nominally guarantees → weaken the ceiling.
  // A degraded/insufficient measurement can only ever LOWER the ceiling, never raise it (the honest floor).
  return m.measuredDegradations.length > 0 ? weakenCeiling(nominal) : nominal;
}

/**
 * Whether a patch with a given risk should be ALLOWED to execute under this isolation tier at all. Under
 * "none", risky execution is refused (not silently run). Under weaker tiers, high-risk execution requires
 * the stronger tiers. Deterministic.
 */
export function executionAllowed(tier: IsolationTier, patchRisk: "low" | "medium" | "high"): { allowed: boolean; reason: string } {
  if (tier === "none") {
    return patchRisk === "low"
      ? { allowed: true, reason: "no isolation, but a low-risk patch may execute" }
      : { allowed: false, reason: `no isolation available — refusing to execute a ${patchRisk}-risk patch (would run untrusted code on the bare host)` };
  }
  if (tier === "process" && patchRisk === "high") {
    return { allowed: false, reason: "high-risk patch requires container/VM isolation; process scoping is insufficient — routing instead of executing" };
  }
  return { allowed: true, reason: `execution permitted under ${tier} isolation for ${patchRisk}-risk patch` };
}
