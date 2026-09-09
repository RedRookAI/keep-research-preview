/**
 * Turns concrete external/system failure observations into narrow runtime defenses.
 *
 * This is deliberately not a research loop. Callers supply an observation, a proposed
 * defense, and deterministic probes. Admission requires executable evidence that the
 * failure exists, that the defense blocks it, and that declared safe behavior remains.
 */

export interface FailureObservation {
  readonly id: string;
  readonly source: "competitor" | "keep" | "dependency" | "operator";
  readonly mechanism: string;
  readonly evidence: readonly string[];
  readonly observedAtMs: number;
}

export interface DefenseProbe {
  readonly id: string;
  /** True means the protected operation was allowed to complete. */
  run(guard: DefenseGuard | undefined): boolean;
}

export type DefenseContext = Readonly<Record<string, string | number | boolean>>;
export type DefenseDecision = { readonly allowed: true } | { readonly allowed: false; readonly reason: string };
export type DefenseGuard = (context: DefenseContext) => DefenseDecision;

/** A bounded, deterministic restriction. Admitted defenses never retain caller-supplied code. */
export interface DefenseRule {
  readonly field: string;
  readonly operator: "equals";
  readonly value: string | number | boolean;
  readonly effect: "deny";
  readonly reason: string;
}

export interface DefenseCandidate {
  readonly id: string;
  readonly observationId: string;
  readonly mechanism: string;
  /** Exact product operations protected by this defense. Wildcards are forbidden. */
  readonly protectedOperations: readonly string[];
  /** Declarative so behavior cannot mutate after admission without being reprobed. */
  readonly rule: DefenseRule;
  readonly failureProbe: DefenseProbe;
  readonly collateralProbes: readonly DefenseProbe[];
  readonly expiresAtMs: number;
}

export interface AdmittedDefense {
  readonly id: string;
  readonly observationId: string;
  readonly mechanism: string;
  readonly protectedOperations: readonly string[];
  /** Immutable runtime restriction, exposed so operators can inspect what was actually admitted. */
  readonly rule: DefenseRule;
  readonly admittedAtMs: number;
  readonly expiresAtMs: number;
  readonly evidence: readonly string[];
}

export type DefenseAdmission =
  | { readonly admitted: true; readonly defense: AdmittedDefense }
  | { readonly admitted: false; readonly reason: string };

export interface ObservedFailureDefenseOptions {
  readonly nowMs?: () => number;
  readonly maxActiveDefenses?: number;
  readonly maxLifetimeMs?: number;
  readonly maxOperationsPerDefense?: number;
}

const TOKEN = /^[a-z0-9][a-z0-9._:-]{0,127}$/;

export class ObservedFailureDefenseRegistry {
  private readonly nowMs: () => number;
  private readonly maxActive: number;
  private readonly maxLifetimeMs: number;
  private readonly maxOperations: number;
  private readonly active = new Map<string, { readonly defense: AdmittedDefense; readonly guard: DefenseGuard }>();

  constructor(options: ObservedFailureDefenseOptions = {}) {
    this.nowMs = options.nowMs ?? Date.now;
    this.maxActive = boundedPositive(options.maxActiveDefenses, 32, "maxActiveDefenses");
    this.maxLifetimeMs = boundedPositive(options.maxLifetimeMs, 90 * 24 * 60 * 60 * 1_000, "maxLifetimeMs");
    this.maxOperations = boundedPositive(options.maxOperationsPerDefense, 4, "maxOperationsPerDefense");
  }

  admit(observation: FailureObservation, candidate: DefenseCandidate): DefenseAdmission {
    const now = this.nowMs();
    this.pruneExpired(now);

    if (!validToken(observation.id) || !validToken(candidate.id)) return deny("ids must be bounded canonical tokens");
    if (candidate.observationId !== observation.id) return deny("candidate is not bound to the observation");
    if (observation.mechanism.trim() === "" || candidate.mechanism !== observation.mechanism)
      return deny("candidate must target the observed mechanism exactly");
    if (observation.evidence.length === 0 || observation.evidence.some((item) => item.trim() === "" || item.length > 512))
      return deny("observation requires bounded concrete evidence");
    if (!Number.isSafeInteger(observation.observedAtMs) || observation.observedAtMs > now)
      return deny("observation timestamp is invalid or in the future");
    if (!Number.isSafeInteger(candidate.expiresAtMs) || candidate.expiresAtMs <= now || candidate.expiresAtMs - now > this.maxLifetimeMs)
      return deny("defense expiry exceeds the bounded lifetime");
    if (candidate.protectedOperations.length === 0 || candidate.protectedOperations.length > this.maxOperations)
      return deny("defense operation scope is empty or too broad");
    if (new Set(candidate.protectedOperations).size !== candidate.protectedOperations.length ||
        candidate.protectedOperations.some((operation) => !validToken(operation) || operation.includes("*")))
      return deny("defense operations must be unique exact tokens without wildcards");
    if (candidate.collateralProbes.length === 0) return deny("at least one collateral probe is required");
    const ruleError = validateRule(candidate.rule);
    if (ruleError) return deny(ruleError);
    if (this.active.has(candidate.id)) return deny("defense id is already active");
    if (this.active.size >= this.maxActive) return deny("active defense capacity reached");

    const guard = compileGuard(candidate.rule);
    try {
      // The observed failure must be reproduced without the defense and prevented with it.
      if (candidate.failureProbe.run(undefined)) return deny("failure probe did not reproduce the observed failure");
      if (!candidate.failureProbe.run(guard)) return deny("candidate did not prevent the observed failure");
      for (const probe of candidate.collateralProbes) {
        if (!validToken(probe.id) || !probe.run(undefined) || !probe.run(guard))
          return deny(`collateral probe ${probe.id || "<invalid>"} did not preserve safe behavior`);
      }
    } catch {
      return deny("defense probe threw instead of producing deterministic evidence");
    }

    const defense: AdmittedDefense = Object.freeze({
      id: candidate.id,
      observationId: observation.id,
      mechanism: candidate.mechanism,
      protectedOperations: Object.freeze([...candidate.protectedOperations]),
      rule: Object.freeze({ ...candidate.rule }),
      admittedAtMs: now,
      expiresAtMs: candidate.expiresAtMs,
      evidence: Object.freeze([...observation.evidence]),
    });
    this.active.set(defense.id, { defense, guard });
    return { admitted: true, defense };
  }

  /** Runtime lookup only; expiry is automatic and does not schedule research or audits. */
  protects(defenseId: string, operation: string): boolean {
    this.pruneExpired(this.nowMs());
    return this.active.get(defenseId)?.defense.protectedOperations.includes(operation) ?? false;
  }

  /** Apply every active guard scoped to this exact operation. Guard failure denies; no defense means unchanged allow. */
  evaluate(operation: string, context: DefenseContext = {}): DefenseDecision & { readonly appliedDefenseIds: readonly string[] } {
    this.pruneExpired(this.nowMs());
    const applied: string[] = [];
    const inertContext = Object.freeze({ ...context });
    for (const { defense, guard } of this.active.values()) {
      if (!defense.protectedOperations.includes(operation)) continue;
      applied.push(defense.id);
      try {
        const decision = guard(inertContext);
        if (!decision.allowed) return { ...decision, appliedDefenseIds: Object.freeze(applied) };
      } catch {
        return { allowed: false, reason: `observed-failure defense ${defense.id} threw — operation denied fail-closed`, appliedDefenseIds: Object.freeze(applied) };
      }
    }
    return { allowed: true, appliedDefenseIds: Object.freeze(applied) };
  }

  list(): readonly AdmittedDefense[] {
    this.pruneExpired(this.nowMs());
    return [...this.active.values()].map((entry) => entry.defense);
  }

  private pruneExpired(now: number): void {
    for (const [id, entry] of this.active) if (entry.defense.expiresAtMs <= now) this.active.delete(id);
  }
}

function validToken(value: string): boolean { return TOKEN.test(value); }
function validateRule(rule: DefenseRule): string | undefined {
  if (!validToken(rule.field)) return "defense rule field must be a bounded canonical token";
  if (rule.operator !== "equals") return "defense rule operator is unsupported";
  if (rule.effect !== "deny") return "defense rule effect must deny";
  if (typeof rule.value === "number" && !Number.isFinite(rule.value)) return "defense rule value must be finite";
  if (typeof rule.value === "string" && rule.value.length > 256) return "defense rule value is too long";
  if (rule.reason.trim() === "" || rule.reason.length > 256) return "defense rule requires a bounded reason";
  return undefined;
}
function compileGuard(rule: DefenseRule): DefenseGuard {
  const frozen = Object.freeze({ ...rule });
  return (context) => {
    const matches = context[frozen.field] === frozen.value;
    return matches ? { allowed: false, reason: frozen.reason } : { allowed: true };
  };
}
function deny(reason: string): DefenseAdmission { return { admitted: false, reason }; }
function boundedPositive(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) throw new Error(`${name} must be a positive safe integer`);
  return resolved;
}
