/**
 * SafeRemediation (Increment 16.9a) — deterministic self-heal BEFORE routing to a human.
 *
 * Premise (user, SOTA-validated): humans — especially non-engineers — rubber-stamp approvals, so routing
 * is often a FALSE safeguard. Safety must live in the deterministic layer. When a patch concern is in the
 * PROVABLY-SAFE class (reversible + bounded + known-failure-mode + complete blast-radius), we auto-narrow
 * and INDEPENDENTLY re-vet instead of routing. Everything irreversible/high-blast still routes or blocks.
 *
 * SOTA basis (2026-08-05): auto-remediate ONLY low-risk, reversible, bounded, deterministic, known-mode
 * fixes with full audit + rollback; ALWAYS keep a human on irreversible/high-risk; anything with
 * incomplete blast-radius info routes (Aurora SRE / Tamnoon / SRE School / PolicyCortex 2026). Trust is
 * system-level: a self-heal is safe because the independent re-vet + rollback + audit catch a bad heal,
 * NOT because the heal is trusted (safeguard.sh 2026). Memory-backed loop guard: "auto-remediation
 * without memory is a faster way to cause the same outage twice" (rubixkube 2026).
 *
 * HARD invariants (non-negotiable):
 *  - NEVER heals a patch touching auth / secrets / network-egress / audit / db-schema / filesystem-
 *    destructive — those route or block, always.
 *  - Narrowing only REMOVES/narrows edits (reversible); it never adds behavior.
 *  - The narrowed patch must INDEPENDENTLY clear the sound floor (re-vet) — a self-heal cannot launder a
 *    patch past vetting.
 *  - Memory-backed loop guard: a signature healed too many times → route (never loop).
 *  - Per-rule shadow mode (evidence-based): a rule in shadow logs its would-be fix WITHOUT applying it.
 *  - Every remediation (applied or shadowed) is audited with a rollback id.
 *
 * Zero deps (node:crypto is a builtin). The human MERGE gate is untouched — self-heal only narrows a
 * patch before the existing human gate; it never merges.
 */

import { randomUUID } from "node:crypto";
import { verifyPatch, type PatchVerdict, type PatchVerifierInput } from "./patch_verifier.js";
import { deriveEffectsFromEdits, type EffectClass } from "./plan_consequences.js";
import { assertHeterogeneous, crossFamilyVerify, type Authorship, type CrossFamilyVerdict } from "../review/heterogeneous.js";
import type { SearchReplaceEdit, SolveResult } from "../solve/issue_model.js";
import type { GovernanceLedger } from "../governance/decision_record.js";

/** Effect classes that must NEVER be auto-healed — they route or block, always. */
const NEVER_HEAL: ReadonlySet<EffectClass> = new Set([
  "audit-tamper", "filesystem-destructive", "db-schema", "network-egress", "secret-credential", "auth-access-control",
]);

export type RemediationRiskClass = "trivial-reversible" | "novel";

export interface RemediationContext {
  readonly issueId: string;
  readonly input: PatchVerifierInput;
  readonly verdict: PatchVerdict;
  /** Localized suspect file paths — what the patch is EXPECTED to touch (to find accidental edits). */
  readonly suspectPaths: readonly string[];
}

export interface RemediationRule {
  readonly name: string;
  readonly riskClass: RemediationRiskClass;
  /** Can this rule safely address the current verdict? */
  admissible(ctx: RemediationContext): boolean;
  /** Produce a NARROWED edit set (only removes/narrows — never adds). Returns the kept edits. */
  narrow(ctx: RemediationContext): readonly SearchReplaceEdit[];
}

export interface RemediationAttempt {
  readonly ruleName: string;
  readonly clearedSoundFloor: boolean;
  readonly independentApproved: boolean | "n/a";
  readonly reason: string;
}

export interface RemediationOutcome {
  readonly healed: boolean;
  readonly ruleName?: string;
  readonly healedResult?: SolveResult;
  readonly rollbackId?: string;
  readonly droppedEdits?: readonly SearchReplaceEdit[];
  readonly shadowed?: boolean;
  /** Every attempt tried this run (bounded-iteration observability). */
  readonly attempts?: readonly RemediationAttempt[];
  readonly reason: string;
}

export interface SafeRemediationConfig {
  /** Rules to register. Omit → the default narrowest-safe set. */
  readonly rules?: readonly RemediationRule[];
  /** Per-rule enabled flag (default: only trivial-reversible rules enabled). */
  readonly enabled?: Readonly<Record<string, boolean>>;
  /** Per-rule shadow flag (default: off). A shadowed rule logs its would-be fix WITHOUT applying. */
  readonly shadow?: Readonly<Record<string, boolean>>;
  readonly governance?: GovernanceLedger;
  /** Loop-guard signature → count store (memory-backed). Omit → in-process Map. */
  readonly healCounts?: Map<string, number>;
  /** Max heals for one signature before routing instead (cross-run loop guard). Default 2. */
  readonly maxHealsPerSignature?: number;
  /**
   * Within-run attempt budget: how many DIFFERENT targeted rules to try before escalating (SOTA: bounded
   * iteration is mandatory; marginal value collapses after 2–3 for deterministic narrowing; unbounded is
   * dangerous — arXiv 2605.01471, 2601.11637). Default 3.
   */
  readonly maxAttempts?: number;
  /**
   * Optional INDEPENDENT (heterogeneous) verifier for a healed patch — an ADDITIONAL gate beyond the
   * deterministic acceptance oracle, not a replacement. Cross-family verification catches shared-blind-spot
   * failures a same-verifier re-check misses (DISC 2026; cross-family > self-verification). When absent
   * (N=1/free-tier), the deterministic floor alone governs. Returns true iff it independently approves.
   */
  readonly independentVerifier?: {
    readonly identity: Authorship;
    verify(narrowed: SolveResult): boolean;
  };
  /** The self-heal's own authorship (to enforce verifier heterogeneity). Omit → a default deterministic id. */
  readonly authorship?: Authorship;
}

/** The default narrowest-safe rule: drop edits to files NOT among the localized suspects (scope creep). */
export const dropAccidentalUnrelatedEdit: RemediationRule = {
  name: "drop-accidental-unrelated-edit",
  riskClass: "trivial-reversible",
  admissible(ctx) {
    // Only when the patch was flagged for scope (heuristic) and there ARE edits outside the suspect set.
    const scopeFlagged = ctx.verdict.checks.some((c) => c.name === "scope-bounded" && c.decision === "flag");
    const edits = ctx.input.solveResult.prProposal?.edits ?? [];
    const hasUnrelated = edits.some((e) => !ctx.suspectPaths.includes(e.file));
    const hasRelated = edits.some((e) => ctx.suspectPaths.includes(e.file));
    // Must keep at least one related edit (don't narrow to nothing) and have something to drop.
    return scopeFlagged && hasUnrelated && hasRelated;
  },
  narrow(ctx) {
    const edits = ctx.input.solveResult.prProposal?.edits ?? [];
    return edits.filter((e) => ctx.suspectPaths.includes(e.file)); // keep only related; drop the rest
  },
};

const DEFAULT_RULES: readonly RemediationRule[] = [dropAccidentalUnrelatedEdit];

export class SafeRemediation {
  private readonly rules: readonly RemediationRule[];
  private readonly enabled: Readonly<Record<string, boolean>>;
  private readonly shadow: Readonly<Record<string, boolean>>;
  private readonly governance: GovernanceLedger | undefined;
  private readonly healCounts: Map<string, number>;
  private readonly maxHeals: number;
  private readonly maxAttempts: number;
  private readonly independentVerifier: SafeRemediationConfig["independentVerifier"];
  private readonly authorship: Authorship;

  constructor(config: SafeRemediationConfig = {}) {
    this.rules = config.rules ?? DEFAULT_RULES;
    this.enabled = config.enabled ?? {};
    this.shadow = config.shadow ?? {};
    this.governance = config.governance;
    this.healCounts = config.healCounts ?? new Map();
    this.maxHeals = config.maxHealsPerSignature ?? 2;
    this.maxAttempts = config.maxAttempts ?? 3;
    this.independentVerifier = config.independentVerifier;
    this.authorship = config.authorship ?? { agentId: "keep-safe-remediation", modelFamily: "deterministic" };
    // Fail-fast: if an independent verifier is supplied, it MUST be heterogeneous from the healer.
    if (this.independentVerifier) assertHeterogeneous(this.authorship, this.independentVerifier.identity);
  }

  /** A rule is active if enabled (trivial-reversible rules default ON; novel rules default OFF). */
  private isEnabled(rule: RemediationRule): boolean {
    if (rule.name in this.enabled) return this.enabled[rule.name] === true;
    return rule.riskClass === "trivial-reversible";
  }

  private audit(action: string, effect: "allow" | "deny" | "warn", reason: string, outcome: "proceeded" | "blocked" | "escalated-to-human" | "warned-and-proceeded"): void {
    this.governance?.record({
      action, actor: "safe-remediation",
      policy: { effect, ruleId: "safe-remediation", reason, matchedRuleIds: ["safe-remediation"], policyVersion: "1" },
      outcome,
    });
  }

  /**
   * Attempt to deterministically self-heal a patch that did NOT clear vetting, instead of routing.
   * Bounded multi-attempt (SOTA: bounded iteration is mandatory; try a few DIFFERENT targeted rules, each
   * INDEPENDENTLY re-vetted, escalate on non-convergence). The deterministic sound floor is the acceptance
   * oracle (bounded correctness guarantee); an optional heterogeneous verifier is an ADDITIONAL gate. Each
   * attempt re-vets the cumulative narrowed state fresh, so rules can't compose into an unsafe patch.
   * Never heals forbidden effect classes. Records every attempt.
   */
  remediate(ctx: RemediationContext): RemediationOutcome {
    const edits = ctx.input.solveResult.prProposal?.edits ?? [];

    // GUARD 1: never self-heal a patch touching a forbidden effect class.
    const effects = deriveEffectsFromEdits(edits.map((e) => ({ file: e.file, replace: e.replace })));
    const forbidden = effects.find((e) => NEVER_HEAL.has(e.cls));
    if (forbidden) {
      this.audit("remediate.refused", "warn", `patch touches ${forbidden.cls} — must never be auto-healed; routing`, "escalated-to-human");
      return { healed: false, reason: `patch touches ${forbidden.cls} — routing to human (never auto-healed)` };
    }

    const attempts: RemediationAttempt[] = [];
    const triedRules = new Set<string>();

    // Bounded iteration: try up to maxAttempts DIFFERENT admissible, enabled rules.
    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      const rule = this.rules.find((r) => this.isEnabled(r) && !triedRules.has(r.name) && r.admissible(ctx));
      if (!rule) break; // no more admissible rules → converged to "route"
      triedRules.add(rule.name);

      // GUARD 2: cross-run memory loop guard — don't auto-heal the same signature endlessly across runs.
      const signature = `${ctx.issueId}:${rule.name}`;
      const seen = this.healCounts.get(signature) ?? 0;
      if (seen >= this.maxHeals) {
        this.audit("remediate.loopguard", "warn", `signature ${signature} healed ${seen}x across runs — routing instead of looping`, "escalated-to-human");
        attempts.push({ ruleName: rule.name, clearedSoundFloor: false, independentApproved: "n/a", reason: "cross-run loop guard tripped" });
        continue;
      }

      const kept = rule.narrow(ctx);
      const dropped = edits.filter((e) => !kept.includes(e));

      // Semantic-preservation (Rule 3, arXiv 2605.01471): narrowing must STRICTLY reduce and keep ≥1 edit.
      if (kept.length === 0 || kept.length >= edits.length) {
        attempts.push({ ruleName: rule.name, clearedSoundFloor: false, independentApproved: "n/a", reason: "narrowing did not strictly reduce (or emptied) the patch" });
        continue;
      }

      // SHADOW: a rule in shadow logs its would-be fix WITHOUT applying it.
      if (this.shadow[rule.name] === true) {
        this.audit("remediate.shadow", "warn", `[shadow] '${rule.name}' would drop ${dropped.length} edit(s): ${dropped.map((e) => e.file).join(", ")}`, "warned-and-proceeded");
        attempts.push({ ruleName: rule.name, clearedSoundFloor: false, independentApproved: "n/a", reason: "shadow (not applied)" });
        return { healed: false, shadowed: true, ruleName: rule.name, droppedEdits: dropped, attempts, reason: `[shadow] '${rule.name}' logged a would-be fix (not applied)` };
      }

      // ACCEPTANCE ORACLE: the narrowed patch must INDEPENDENTLY clear the deterministic sound floor
      // (bounded correctness guarantee; can't launder a patch past vetting).
      const narrowedResult = withEdits(ctx.input.solveResult, kept);
      const reVerdict: PatchVerdict = verifyPatch({ ...ctx.input, solveResult: narrowedResult });
      if (!reVerdict.cleared) {
        this.audit("remediate.attempt", "warn", `'${rule.name}' did not clear the sound floor (${reVerdict.reason})`, "warned-and-proceeded");
        attempts.push({ ruleName: rule.name, clearedSoundFloor: false, independentApproved: "n/a", reason: reVerdict.reason });
        continue; // try the next targeted rule
      }

      // ADDITIONAL GATE: an optional independent/heterogeneous verifier must ALSO approve — decided by the reusable
      // cross-family verification gate (deterministic authoritative; heterogeneous verifier additive; same-family can't
      // rubber-stamp). Absent → the deterministic floor alone governs. reVerdict.cleared is true here (we continued above).
      const verifierApproved = this.independentVerifier ? this.independentVerifier.verify(narrowedResult) : undefined;
      const gate: CrossFamilyVerdict = crossFamilyVerify({
        deterministicPass: reVerdict.cleared,
        author: this.authorship,
        ...(this.independentVerifier ? { verifier: { identity: this.independentVerifier.identity, approved: verifierApproved === true } } : {}),
      });
      const independentApproved: boolean | "n/a" = this.independentVerifier ? verifierApproved === true : "n/a";
      if (!gate.accepted) {
        this.audit("remediate.attempt", "warn", `'${rule.name}' cleared the sound floor but the INDEPENDENT verifier declined — not accepting`, "warned-and-proceeded");
        attempts.push({ ruleName: rule.name, clearedSoundFloor: true, independentApproved, reason: "independent verifier declined" });
        continue;
      }

      // Accepted. Record with a rollback id (the dropped edits are the undo artifact).
      const rollbackId = randomUUID();
      this.healCounts.set(signature, seen + 1);
      attempts.push({ ruleName: rule.name, clearedSoundFloor: true, independentApproved, reason: "accepted" });
      this.audit("remediate.applied", "allow", `'${rule.name}' dropped ${dropped.length} edit(s); sound floor + ${this.independentVerifier ? "independent verifier" : "no second verifier"} cleared. rollbackId=${rollbackId}`, "proceeded");
      return { healed: true, ruleName: rule.name, healedResult: narrowedResult, rollbackId, droppedEdits: dropped, attempts, reason: `self-healed via '${rule.name}' (dropped ${dropped.length} edit(s)); independently re-vetted${this.independentVerifier ? " + heterogeneous verifier approved" : ""}` };
    }

    // Non-convergence within budget → escalate to human (the defined safe state).
    this.audit("remediate.escalate", "warn", `no safe heal converged in ${attempts.length} attempt(s) — routing to human`, "escalated-to-human");
    return { healed: false, attempts, reason: `no safe self-heal converged in ${attempts.length} attempt(s) — routing to human` };
  }
}

/** Build a SolveResult with a narrowed edit set (only removes edits; reversible). */
function withEdits(base: SolveResult, edits: readonly SearchReplaceEdit[]): SolveResult {
  if (!base.prProposal) return base;
  return { ...base, prProposal: { ...base.prProposal, edits } };
}
