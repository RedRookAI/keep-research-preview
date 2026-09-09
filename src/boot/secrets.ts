/**
 * Boot secret-requirement policy (Phase 0.5) — fixes coupling-bug #3.
 *
 * Original bug: `REQUIRED_SECRETS=["LINEAR_API_KEY","GH_TOKEN"]` raised FATAL at
 * boot, contradicting the agnostic connector layer — the PROVIDER_LOCAL zero-dep
 * default became dead code for anyone without Linear.
 *
 * Fix: separate TRUE security invariants (fail-closed — boot MUST abort if absent)
 * from OPTIONAL infra (fail-soft — the feature is simply unavailable, boot
 * continues). A connector's secret is required only if that connector is BOUND in
 * policy. Conflating the two was the bug.
 */

export type SecretClass = "security-invariant" | "optional-infra";

export interface SecretRequirement {
  readonly name: string;
  readonly klass: SecretClass;
  /** For optional-infra: the connector/feature this unlocks (for the report). */
  readonly unlocks?: string;
  /** For optional-infra: only required if this connector is bound in policy. */
  readonly requiredIfBound?: string;
}

export interface BootPolicy {
  /** Connector ids the operator has chosen to bind (e.g. ["github"]). */
  readonly boundConnectors: readonly string[];
}

export interface BootCheckResult {
  readonly ok: boolean;
  /** Missing security invariants — these abort boot (fail-closed). */
  readonly fatalMissing: readonly string[];
  /** Missing optional infra — these degrade gracefully (fail-soft). */
  readonly degraded: readonly { secret: string; unlocks: string }[];
}

/**
 * Evaluate boot requirements against the available secrets.
 * `has(name)` reports whether a secret is present (env, vault, etc.).
 */
export function checkBootSecrets(
  requirements: readonly SecretRequirement[],
  policy: BootPolicy,
  has: (name: string) => boolean,
): BootCheckResult {
  const fatalMissing: string[] = [];
  const degraded: { secret: string; unlocks: string }[] = [];
  const bound = new Set(policy.boundConnectors);

  for (const req of requirements) {
    const present = has(req.name);
    if (req.klass === "security-invariant") {
      // Fail-closed: a true invariant must be present.
      if (!present) fatalMissing.push(req.name);
    } else {
      // Optional infra: only required if its connector is bound.
      const needed = req.requiredIfBound ? bound.has(req.requiredIfBound) : false;
      if (needed && !present) {
        // Bound but missing its secret -> still fail-soft (feature disabled), but reported.
        degraded.push({ secret: req.name, unlocks: req.unlocks ?? req.name });
      } else if (!present) {
        // Not bound and absent -> simply unavailable, no problem at all.
        degraded.push({ secret: req.name, unlocks: req.unlocks ?? req.name });
      }
    }
  }

  return { ok: fatalMissing.length === 0, fatalMissing, degraded };
}
