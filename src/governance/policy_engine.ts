/**
 * Policy-as-code engine (Phase 5, #35) — the shared governance engine.
 *
 * Deterministic DENY/WARN/ALLOW, NOT model-based. The 2026 consensus (MLflow, OPA):
 * "model-based enforcement introduces the exact unpredictability you are trying to
 * govern; a rules engine that produces the same decision" is the right tool. This is
 * OPA/Rego-shaped but zero-dependency; a real OPA/Rego adapter plugs in behind the
 * same evaluate() contract.
 *
 * FAIL-CLOSED: the engine sits in the request path (a SPOF), so ANY evaluation error
 * results in DENY — never fail-open. Every evaluation yields exactly one decision,
 * which the governance record links to its enforcement outcome.
 *
 * Version-controlled rules; conditions over model/provider/data_residency/
 * action_tier/content flags. Encodes the EU AI Act Article 5 hard-DENY set
 * (CSAM / non-consensual intimate imagery) as non-overridable.
 */

export type Effect = "deny" | "warn" | "allow";

export interface PolicyContext {
  readonly model?: string;
  readonly provider?: string;
  readonly dataResidency?: string; // e.g. "eu", "us"
  readonly actionTier?: string; // from Phase 2 action_tier
  readonly ipIndemnificationRequired?: boolean;
  /** Content-safety flags raised upstream (e.g. by a classifier). */
  readonly contentFlags?: readonly string[];
  /** Arbitrary extra attributes rules may reference. */
  readonly attributes?: Readonly<Record<string, string | number | boolean>>;
}

export interface PolicyRule {
  readonly id: string;
  readonly effect: Effect;
  readonly description: string;
  /** The predicate; true => this rule applies. Must be pure and total. */
  readonly when: (ctx: PolicyContext) => boolean;
  /** Non-overridable rules (e.g. Article 5) always win over allow/warn. */
  readonly nonOverridable?: boolean;
}

export interface PolicyDecision {
  readonly effect: Effect;
  /** The rule id that determined the effect (or "fail-closed"/"default-allow"). */
  readonly ruleId: string;
  readonly reason: string;
  /** All rules that matched, for the evidence trail. */
  readonly matchedRuleIds: readonly string[];
  readonly policyVersion: string;
}

/** The Article 5 hard-DENY set — always present, non-overridable. */
export const ARTICLE_5_RULES: readonly PolicyRule[] = [
  {
    id: "article5.csam",
    effect: "deny",
    description: "EU AI Act Article 5: CSAM is prohibited.",
    when: (ctx) => (ctx.contentFlags ?? []).includes("csam"),
    nonOverridable: true,
  },
  {
    id: "article5.ncii",
    effect: "deny",
    description: "EU AI Act Article 5: non-consensual intimate imagery is prohibited.",
    when: (ctx) => (ctx.contentFlags ?? []).includes("ncii"),
    nonOverridable: true,
  },
];

export class PolicyEngine {
  private readonly rules: PolicyRule[];

  constructor(
    private readonly policyVersion: string,
    rules: readonly PolicyRule[] = [],
    /** If true (default), the Article 5 hard-DENY set is always included. */
    includeArticle5 = true,
  ) {
    this.rules = includeArticle5 ? [...ARTICLE_5_RULES, ...rules] : [...rules];
  }

  /**
   * Evaluate the context. Deterministic precedence:
   *   1. any matched non-overridable DENY wins (Article 5),
   *   2. else any matched DENY wins,
   *   3. else any matched WARN,
   *   4. else ALLOW (default).
   * FAIL-CLOSED: if any rule predicate throws, the whole evaluation returns DENY.
   */
  evaluate(ctx: PolicyContext): PolicyDecision {
    const matched: PolicyRule[] = [];
    try {
      for (const r of this.rules) {
        if (r.when(ctx)) matched.push(r);
      }
    } catch (err) {
      // Predicate error in the request path -> fail closed.
      return {
        effect: "deny",
        ruleId: "fail-closed",
        reason: `policy engine error (fail-closed): ${(err as Error).message}`,
        matchedRuleIds: matched.map((m) => m.id),
        policyVersion: this.policyVersion,
      };
    }

    const matchedIds = matched.map((m) => m.id);
    const nonOverridableDeny = matched.find((m) => m.nonOverridable && m.effect === "deny");
    if (nonOverridableDeny) {
      return decision("deny", nonOverridableDeny, matchedIds, this.policyVersion);
    }
    const anyDeny = matched.find((m) => m.effect === "deny");
    if (anyDeny) return decision("deny", anyDeny, matchedIds, this.policyVersion);
    const anyWarn = matched.find((m) => m.effect === "warn");
    if (anyWarn) return decision("warn", anyWarn, matchedIds, this.policyVersion);

    return {
      effect: "allow",
      ruleId: "default-allow",
      reason: "no deny/warn rule matched",
      matchedRuleIds: matchedIds,
      policyVersion: this.policyVersion,
    };
  }

  get version(): string {
    return this.policyVersion;
  }

  ruleCount(): number {
    return this.rules.length;
  }
}

function decision(effect: Effect, rule: PolicyRule, matchedIds: string[], version: string): PolicyDecision {
  return { effect, ruleId: rule.id, reason: rule.description, matchedRuleIds: matchedIds, policyVersion: version };
}
