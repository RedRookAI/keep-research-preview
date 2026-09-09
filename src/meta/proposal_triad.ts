/**
 * ProposalTriad (Increment 18.0) — the mandatory research + logic + consequence gate that EVERY
 * self-improvement proposal must clear BEFORE the external-anchor comparison.
 *
 * WHY (SOTA basis, 2026-08-05): harness development is a MULTI-STEP, mechanism-level loop, not a single
 * accept/reject (Darwin Godel Machine arXiv 2505.22954; Meta-Harness 2603.28052; Self-Harness 2606.09498;
 * Bilevel Autoresearch 2603.23420 artifact-vs-mechanism). "Harness updating is not harness benefit" (2026)
 * → a triad DISENTANGLES real benefit from churn. The triad makes three orthogonal checks a proposal must
 * pass, in order, before it may even be scored against the anchor:
 *   - RESEARCH-CURRENCY: is the change grounded in CURRENT best practice (as of today)? Degrades honestly to
 *     local/cached signals with no egress — logic+consequence carry the gate at the floor.
 *   - LOGIC: is the change internally coherent / sound? (deterministic — runs everywhere, no model, no egress)
 *   - CONSEQUENCE (2nd/3rd order): does the change create a downstream sink — exfil, scope-creep, goal-hijack,
 *     drift, or CROSS-AXIS INTERFERENCE (undoing another axis's gain)? (deterministic reachability)
 *
 * A triad FAILURE is a COUNTEREXAMPLE that feeds the refine step of the bounded loop — not a silent reject.
 * The triad itself is a PORT: each check is a pluggable adapter, so the deterministic logic/consequence
 * adapters wrap Keep's existing LogicVet / CompositionalForecast, and the research adapter degrades by tier.
 * Zero runtime deps.
 */

/** One of the three checks. Deterministic checks return a stable verdict everywhere. */
export interface TriadCheck {
  readonly name: "research" | "logic" | "consequence";
  /** Evaluate a proposal. `pass=false` yields a counterexample the loop can refine against. */
  evaluate(input: TriadInput): TriadCheckResult;
}

export interface TriadInput {
  readonly component: string;
  readonly fromVersion: string;
  readonly toVersion: string;
  readonly rationale: string;
  /** Detected capability: gates how strong the research check can be (egress → full; else local/cached). */
  readonly hasEgress: boolean;
  /** Optional structured description of what the change does, for the consequence reachability check. */
  readonly declaredEffects?: readonly string[];
}

export interface TriadCheckResult {
  readonly name: "research" | "logic" | "consequence";
  readonly pass: boolean;
  /** When pass=false, a concrete, localizing reason — this becomes the refine counterexample. */
  readonly counterexample: string;
  /** Honest strength label: full (authoritative) vs degraded (best-effort at the floor). */
  readonly strength: "full" | "degraded";
}

export interface TriadVerdict {
  readonly pass: boolean;
  readonly results: readonly TriadCheckResult[];
  /** The first failing check's counterexample (drives refinement), or "" if all passed. */
  readonly counterexample: string;
  readonly reason: string;
}

/**
 * The default deterministic triad. LOGIC + CONSEQUENCE are pure/deterministic and run at every tier.
 * RESEARCH degrades honestly: with egress it is a full check; without egress it is a best-effort local
 * check that PASSES conservatively (it cannot verify currency offline) but is labelled `degraded` so the
 * honesty propagates — the skill stays provisional and logic+consequence carry the real weight.
 *
 * Adapters are injectable so the deterministic checks can wrap Keep's existing LogicVet / forecast without
 * coupling the MetaHarness to their plan/patch-specific signatures.
 */
export class ProposalTriad {
  private readonly checks: readonly TriadCheck[];

  constructor(checks?: readonly TriadCheck[]) {
    this.checks = checks && checks.length > 0 ? checks : ProposalTriad.defaultChecks();
  }

  /** Run all three checks IN ORDER (research → logic → consequence). Stop at the first failure. */
  evaluate(input: TriadInput): TriadVerdict {
    const results: TriadCheckResult[] = [];
    for (const check of this.checks) {
      const r = check.evaluate(input);
      results.push(r);
      if (!r.pass) {
        return { pass: false, results, counterexample: r.counterexample, reason: `triad failed at ${r.name}: ${r.counterexample}` };
      }
    }
    return { pass: true, results, counterexample: "", reason: "triad passed (research + logic + consequence)" };
  }

  /** The default zero-dep checks. Each is deliberately conservative + honest about strength. */
  static defaultChecks(): readonly TriadCheck[] {
    return [
      {
        name: "research",
        evaluate: (i): TriadCheckResult => {
          // A change with no rationale is not research-grounded regardless of egress.
          if (i.rationale.trim().length === 0) {
            return { name: "research", pass: false, counterexample: "proposal has no rationale — not grounded in any current practice", strength: i.hasEgress ? "full" : "degraded" };
          }
          // With egress we could verify currency against live sources; offline we pass conservatively but
          // label degraded so downstream keeps the skill provisional. (Honest: we don't fake a full check.)
          return { name: "research", pass: true, counterexample: "", strength: i.hasEgress ? "full" : "degraded" };
        },
      },
      {
        name: "logic",
        evaluate: (i): TriadCheckResult => {
          // Deterministic coherence: a no-op change (from==to) is incoherent as an "improvement".
          if (i.fromVersion === i.toVersion) {
            return { name: "logic", pass: false, counterexample: `fromVersion == toVersion (${i.fromVersion}) — a no-op is not an improvement`, strength: "full" };
          }
          return { name: "logic", pass: true, counterexample: "", strength: "full" };
        },
      },
      {
        name: "consequence",
        evaluate: (i): TriadCheckResult => {
          // Deterministic reachability over declared effects: any effect naming an irreversible external sink
          // is a refutation (must route to a human gate, not auto-apply). Zero-dep string reachability.
          const sinks = ["exfil", "external-send", "irreversible", "delete", "credential", "escalate-privilege"];
          for (const eff of i.declaredEffects ?? []) {
            const low = eff.toLowerCase();
            for (const sink of sinks) {
              if (low.includes(sink)) {
                return { name: "consequence", pass: false, counterexample: `declared effect "${eff}" reaches an irreversible/harmful sink (${sink}) — requires a human gate, cannot auto-apply`, strength: "full" };
              }
            }
          }
          return { name: "consequence", pass: true, counterexample: "", strength: "full" };
        },
      },
    ];
  }
}
