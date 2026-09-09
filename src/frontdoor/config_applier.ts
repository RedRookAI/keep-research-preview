/**
 * F2 — Config applier (deterministic validate -> gate -> apply).
 *
 * The stage that actually CHANGES the running system from a directive — safely. Per
 * the 2026 consensus, the LLM never touches enforcement: a directive is translated to
 * a typed proposal, validated deterministically, routed through the F1.5 gate, and
 * only THEN — if approved — applied (config stored revisably; enforceable rules emitted
 * for the PolicyEngine). Scope-widening always requires the operator's tap, so a spoken
 * directive can't silently self-grant dangerous scope.
 */

import type { Spine } from "../spine/spine.js";
import type { PlanExecuteGate, GateDecision } from "./plan_execute_gate.js";
import type { RevisionStore } from "./revision_store.js";
import type { PolicyRule } from "../governance/policy_engine.js";
import { translateDirective, proposalToAction, type ConfigProposal } from "./directive_translator.js";

export type ApplyOutcome = "applied" | "needs-approval" | "needs-clarification" | "blocked";

export interface ApplyResult {
  readonly outcome: ApplyOutcome;
  readonly proposal: ConfigProposal;
  readonly gateDecision?: GateDecision;
  /** Enforceable rules emitted (only for applied scope-narrowing/deny directives). */
  readonly emittedRules: readonly PolicyRule[];
  /** The config item key in the RevisionStore (only when applied). */
  readonly configKey?: string;
  /** Plain-language message for the human. */
  readonly say: string;
}

export interface ApplyOptions {
  /** Ground org-specific entities (like NLAC's knowledge base); default: none. */
  readonly resolve?: (entity: string) => string | null;
  /** Confidence for the gate (external/irreversible still can't auto-proceed). */
  readonly calibratedConfidence?: number;
  readonly now?: number;
}

/**
 * Translate + validate + gate + apply a directive. Never applies a scope-widening
 * directive without the operator's approval; never guesses an unresolved entity.
 */
export async function applyDirective(
  directiveText: string,
  deps: { spine: Spine; gate: PlanExecuteGate; revisions: RevisionStore },
  opts: ApplyOptions = {},
): Promise<ApplyResult> {
  const resolve = opts.resolve ?? (() => null);
  const proposal = translateDirective(directiveText, resolve);

  // Log the translation for audit (the LLM's proposed IR is recorded, not enforced).
  deps.spine.stage({
    type: "identity.action",
    actor: "directive-translator",
    payload: {
      event: "directive.translated",
      directives: proposal.directives.length,
      widensScope: proposal.widensScope,
      unresolved: proposal.unresolved.length,
    },
  });

  // 1. Unresolved entities -> clarify, never guess.
  if (proposal.unresolved.length > 0) {
    return { outcome: "needs-clarification", proposal, emittedRules: [], say: proposal.summary };
  }

  // 2. Route through the F1.5 gate. Scope-widening -> grant_broad_scope -> human tap.
  const action = proposalToAction(proposal, directiveText);
  const decision = await deps.gate.decide(action, opts.calibratedConfidence ?? 0);

  if (decision.disposition === "blocked") {
    return { outcome: "blocked", proposal, gateDecision: decision, emittedRules: [], say: decision.reason };
  }
  if (decision.disposition === "human-approval-required") {
    return { outcome: "needs-approval", proposal, gateDecision: decision, emittedRules: [], say: proposal.summary };
  }

  // 3. Approved (auto) -> apply. Store config revisably + emit enforceable rules.
  const configKey = `config:${hash(directiveText)}`;
  const content = JSON.stringify(proposal.directives);
  if (deps.revisions.current(configKey)) {
    deps.revisions.revise(configKey, content, "directive updated", opts.now);
  } else {
    deps.revisions.create(configKey, "directive", content, opts.now);
  }

  const emittedRules = emitRules(proposal, configKey);

  deps.spine.stage({
    type: "identity.action",
    actor: "directive-translator",
    payload: { event: "directive.applied", configKey, rules: emittedRules.length },
  });

  return {
    outcome: "applied",
    proposal,
    gateDecision: decision,
    emittedRules,
    configKey,
    say: proposal.summary,
  };
}

/** Emit deterministic, enforceable PolicyRules from narrowing/deny directives. */
function emitRules(proposal: ConfigProposal, configKey: string): PolicyRule[] {
  const rules: PolicyRule[] = [];
  let i = 0;
  for (const d of proposal.directives) {
    if (d.kind === "add_policy_rule" && d.effect === "deny") {
      const ruleId = `${configKey}:rule:${i++}`;
      // A deny rule derived from a "never/don't" directive. The `when` is a
      // conservative matcher keyed on an attribute the caller can set; deterministic.
      rules.push({
        id: ruleId,
        effect: "deny",
        description: d.statement,
        when: (ctx) => ctx.attributes?.["directiveTag"] === ruleId,
      });
    }
  }
  return rules;
}

function hash(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
}
