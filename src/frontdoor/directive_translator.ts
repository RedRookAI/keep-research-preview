/**
 * F2 — Directive translator (natural language -> typed config intermediate representation).
 *
 * Closes the loop from "the human said it" to "the system is configured for it". The
 * 2026 consensus (firewall-config, NLAC, LACE, LMN) is unanimous on the architecture:
 * the LLM is an ASSISTIVE PARSER that emits a typed intermediate representation, while
 * "compilation and enforcement remain deterministic" and "intent translation is
 * intentionally separated from authorization and configuration updating to manage the
 * risk of incorrect LLM outputs." Accuracy also degrades sharply at scale (NLACBench:
 * >96% small, <20% for some models as complexity grows) — so translation is NEVER
 * trusted blindly; it is validated, and scope-widening requires a human tap.
 *
 * This module produces a typed ConfigProposal; the F2 validator + F1.5 gate decide
 * whether it may auto-apply or needs the operator. The safety-critical scope-escalation
 * check is DETERMINISTIC (not model-trusted), matching Keep's posture throughout.
 */

import type { ProposedAction } from "./action_schema.js";

/** A single typed config directive derived from a human directive. */
export type ConfigDirectiveKind =
  | "set_preference" // a soft preference (tone, verbosity, working style)
  | "add_policy_rule" // a policy rule the PolicyEngine will enforce
  | "set_scope_limit" // a constraint that NARROWS what the agent may do
  | "grant_scope"; // a directive that WIDENS what the agent may do (dangerous)

export interface ConfigDirective {
  readonly kind: ConfigDirectiveKind;
  /** Human-readable statement of what this directive does. */
  readonly statement: string;
  /** For add_policy_rule: the effect the rule should have. */
  readonly effect?: "deny" | "warn" | "allow";
  /** Structured key/value the directive sets (e.g. { tone: "brief" }). */
  readonly settings?: Readonly<Record<string, string | number | boolean>>;
  /** Whether this directive widens the agent's own scope/permissions. */
  readonly widensScope: boolean;
}

export interface ConfigProposal {
  readonly directives: readonly ConfigDirective[];
  /** True if ANY directive widens scope (the whole proposal needs a human tap). */
  readonly widensScope: boolean;
  /** Entities the translator couldn't resolve (trigger a clarify, not a guess). */
  readonly unresolved: readonly string[];
  /** Plain-language summary shown back to the human for one-tap confirmation. */
  readonly summary: string;
}

/**
 * Phrases that WIDEN the agent's scope/permissions — pinned to a human tap.
 *
 * Red-teamed: approval-removal phrasing ("never/stop/without asking", "auto-approve")
 * ONLY widens scope when tied to a genuinely dangerous action (spend real money, deploy,
 * delete, send external, grant access). A general "don't ask me about small stuff / just
 * handle it" is a REASONABLE friction-reduction request, not a scope grant, and must not
 * be flagged (false positives bury the human in taps and ban reasonable directives).
 *
 * Note: normal LLM inference is NEVER a "spend_money" action — it's ordinary operation
 * that never touches this gate. "spend money" here means spending the USER'S money in
 * the world (ads, purchases, paid services), not the cost of running the model.
 */
const DANGER = "(spend|deploy|delete|drop|send|pay|purchase|email|wire|transfer|grant|publish|post|buy|charge|money|production|prod\\b)";
const SCOPE_WIDENING_RX = new RegExp(
  [
    `allow (it|you|the agent|yourself) to ${DANGER}`,
    `give (it|you|yourself) (access|permission)`,
    `\\bgrant (it|you|yourself|me|the)`,
    `enable .* to ${DANGER}`,
    `let (it|you) ${DANGER}`,
    `can now ${DANGER}`,
    `permission to ${DANGER}`,
    `full access`,
    `admin access`,
    // Approval-removal ONLY when tied to a dangerous action:
    `(auto[- ]?approve|without (asking|approval|confirmation|checking)|never (ask|check|confirm|verify)|stop asking|do(n'?t| not) (ask|check|confirm|verify))[^.]{0,40}${DANGER}`,
    `${DANGER}[^.]{0,40}(without (asking|approval|confirmation|checking(\\s+with\\s+me)?)|auto[- ]?approve)`,
    // BLANKET/unbounded approval-removal is dangerous by itself — it removes oversight
    // from ALL actions, including dangerous ones (distinct from scoped friction-reduction):
    `(auto[- ]?approve|approve) (everything|all|anything|it all)`,
    `never ask (me )?(for anything|again about anything|to confirm anything)`,
    `stop asking,? auto[- ]?approve`,
  ].join("|"),
  "i",
);

/** Phrases that NARROW scope — always safe (least-privilege friendly). */
const SCOPE_NARROWING_RX =
  /\b(never|don'?t (ever )?(allow|let|spend|deploy|send|delete|access)|only (allow|permit)|restrict|limit|require (approval|confirmation)|always ask|read[- ]?only|forbid|block)\b/i;

/** Preference-style directives (soft, reversible). */
const PREFERENCE_RX = /\b(prefer|keep it|be (brief|concise|detailed|formal|casual)|tone|style|verbose|short(er)?|long(er)?|use (bullet|prose)|call me)\b/i;

/**
 * Translate a confirmed directive into a typed ConfigProposal. `resolve` optionally
 * grounds org-specific entities (like NLAC's knowledge base); anything it can't
 * resolve is surfaced as unresolved rather than guessed.
 */
export function translateDirective(
  directiveText: string,
  resolve: (entity: string) => string | null = () => null,
): ConfigProposal {
  const text = directiveText.trim();
  const directives: ConfigDirective[] = [];
  const unresolved: string[] = [];

  const widening = SCOPE_WIDENING_RX.test(text);
  const narrowing = SCOPE_NARROWING_RX.test(text);
  const isPreference = PREFERENCE_RX.test(text) && !widening && !narrowing;

  if (widening) {
    // A scope-widening directive: emit a grant_scope directive (will be gated).
    directives.push({
      kind: "grant_scope",
      statement: `Widen what I'm allowed to do: "${text}"`,
      widensScope: true,
    });
  } else if (narrowing) {
    // A narrowing directive: a scope limit or a deny rule — always safe.
    directives.push({
      kind: text.match(/\b(never|don'?t|forbid|block)\b/i) ? "add_policy_rule" : "set_scope_limit",
      statement: `Constrain behavior: "${text}"`,
      ...(text.match(/\b(never|don'?t|forbid|block)\b/i) ? { effect: "deny" as const } : {}),
      widensScope: false,
    });
  } else if (isPreference) {
    directives.push({
      kind: "set_preference",
      statement: `Preference: "${text}"`,
      settings: extractPreferenceSettings(text),
      widensScope: false,
    });
  } else {
    // A general directive that isn't clearly a preference/limit/grant: record it as a
    // soft preference-style config, but flag any unresolved entities for a clarify.
    const entities = extractCandidateEntities(text);
    for (const e of entities) {
      if (resolve(e) === null) unresolved.push(e);
    }
    directives.push({
      kind: "set_preference",
      statement: `Directive: "${text}"`,
      widensScope: false,
    });
  }

  const widensScope = directives.some((d) => d.widensScope);
  return {
    directives,
    widensScope,
    unresolved,
    summary: buildSummary(directives, widensScope, unresolved),
  };
}

/**
 * Map a ConfigProposal to a ProposedAction for the F1.5 gate. Scope-widening ->
 * grant_broad_scope (irreversible -> human tap). Otherwise a reversible set_preference.
 */
export function proposalToAction(proposal: ConfigProposal, directiveText: string): ProposedAction {
  if (proposal.widensScope) {
    return {
      kind: "grant_broad_scope",
      args: { directive: directiveText, directives: proposal.directives.length },
      rationale: "This directive would widen what I'm allowed to do, so it needs your explicit approval.",
    };
  }
  return {
    kind: "set_preference",
    args: { directive: directiveText, directives: proposal.directives.length },
    rationale: "This directive constrains or configures behavior without widening scope — safe and reversible.",
  };
}

function extractPreferenceSettings(text: string): Record<string, string | number | boolean> {
  const s: Record<string, string | number | boolean> = {};
  if (/\bbrief|concise|short/i.test(text)) s["verbosity"] = "brief";
  if (/\bdetailed|verbose|long/i.test(text)) s["verbosity"] = "detailed";
  if (/\bformal/i.test(text)) s["tone"] = "formal";
  if (/\bcasual/i.test(text)) s["tone"] = "casual";
  return s;
}

function extractCandidateEntities(text: string): string[] {
  // Quoted phrases or capitalized multi-word names are candidate org entities.
  const quoted = [...text.matchAll(/"([^"]+)"/g)].map((m) => m[1]!).filter(Boolean);
  return quoted;
}

function buildSummary(directives: readonly ConfigDirective[], widensScope: boolean, unresolved: readonly string[]): string {
  const parts: string[] = [];
  if (widensScope) {
    parts.push("This would give me broader permissions, so I'll ask you to confirm before it takes effect.");
  } else {
    parts.push(`I'll set this up (${directives.map((d) => d.kind.replace(/_/g, " ")).join(", ")}) and keep the previous version so you can change it back.`);
  }
  if (unresolved.length > 0) {
    parts.push(`I wasn't sure what you meant by ${unresolved.map((u) => `"${u}"`).join(", ")} — can you clarify?`);
  }
  return parts.join(" ");
}
