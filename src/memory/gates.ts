/**
 * The two-gate promotion defense (Phase 1) — poisoning resistance.
 *
 * A poisoned belief can pass a FUNCTIONAL check (the code it endorses compiles and
 * the tests pass) while carrying a backdoor — a MemoryGraft-class attack (2025/26).
 * A functional gate alone would grade it Clean-Resolved and PROMOTE the poison. So
 * the defense is TWO complementary gates at the promotion boundary; a memory must
 * pass BOTH to graduate from probation to confirmed:
 *
 *   1. FUNCTIONAL gate — verified it works and wasn't gamed: >= minCleanContexts
 *      distinct contexts clean-resolved, and no net-negative outcome trend.
 *   2. SEMANTIC / INTENT gate — the belief itself passes security & objective
 *      policy, INDEPENDENT of execution success: no exfiltration/backdoor/secret-
 *      leaking/authority-escalating content, no trigger-phrase patterns.
 *
 * They are different checks against different threats (gaming vs. belief-poisoning).
 */

import type { Lesson } from "./model.js";
import { distinctCleanContexts, outcomeTally } from "./model.js";

export interface GateResult {
  readonly pass: boolean;
  readonly reason: string;
}

export interface FunctionalGateConfig {
  /** Distinct clean-resolved contexts required (cross-context proof it isn't overfit). */
  readonly minCleanContexts: number;
  /** Maximum tolerated failure ratio before the lesson is not promotable. */
  readonly maxFailureRatio: number;
}

export const DEFAULT_FUNCTIONAL_CONFIG: FunctionalGateConfig = {
  minCleanContexts: 2,
  maxFailureRatio: 0.2,
};

/** Gate 1: did it actually work, across enough distinct contexts, without gaming? */
export function functionalGate(lesson: Lesson, config: FunctionalGateConfig = DEFAULT_FUNCTIONAL_CONFIG): GateResult {
  const contexts = distinctCleanContexts(lesson);
  if (contexts < config.minCleanContexts) {
    return { pass: false, reason: `needs ${config.minCleanContexts} distinct clean contexts, has ${contexts}` };
  }
  const { clean, failed } = outcomeTally(lesson);
  const total = clean + failed;
  if (total === 0) return { pass: false, reason: "no outcome evidence" };
  const failureRatio = failed / total;
  if (failureRatio > config.maxFailureRatio) {
    return { pass: false, reason: `failure ratio ${failureRatio.toFixed(2)} exceeds ${config.maxFailureRatio}` };
  }
  return { pass: true, reason: "functionally verified across contexts" };
}

/**
 * Patterns that indicate a poisoned/malicious BELIEF regardless of whether the
 * code it endorses passes tests. This is the independent intent check. Deliberately
 * conservative: it flags authority-escalation, exfiltration, secret-leaking, and
 * sleeper trigger-phrase constructions. Extensible; a semantic classifier plugs in
 * behind the same interface later.
 */
const INTENT_RED_FLAGS: readonly { rx: RegExp; label: string }[] = [
  { rx: /\b(exfiltrat|leak|send).{0,30}(secret|token|credential|api[_-]?key|password)/i, label: "exfiltration/secret-leak" },
  { rx: /\b(disable|bypass|skip|ignore).{0,30}(review|audit|verification|gate|check|security)/i, label: "control-bypass" },
  { rx: /\b(curl|wget|fetch|http).{0,40}(\|\s*(sh|bash)|--data|POST)/i, label: "network-exfil-command" },
  { rx: /\b(grant|escalate|elevate).{0,20}(admin|root|privilege|scope)/i, label: "authority-escalation" },
  { rx: /\bwhen (you see|the (word|phrase|trigger))\b.{0,40}\b(then|always|silently)\b/i, label: "sleeper-trigger" },
  { rx: /\b(base64|eval|exec)\s*\(/i, label: "obfuscated-execution" },
];

/** Gate 2: does the belief itself pass security/objective policy, independent of execution? */
export function semanticGate(lesson: Lesson): GateResult {
  for (const flag of INTENT_RED_FLAGS) {
    if (flag.rx.test(lesson.content)) {
      return { pass: false, reason: `intent red-flag: ${flag.label}` };
    }
  }
  return { pass: true, reason: "belief passes security/objective policy" };
}

export interface PromotionDecision {
  readonly promotable: boolean;
  readonly functional: GateResult;
  readonly semantic: GateResult;
}

/** A lesson is promotable to `confirmed` ONLY if it passes BOTH gates. */
export function evaluatePromotion(
  lesson: Lesson,
  functionalConfig: FunctionalGateConfig = DEFAULT_FUNCTIONAL_CONFIG,
): PromotionDecision {
  const functional = functionalGate(lesson, functionalConfig);
  const semantic = semanticGate(lesson);
  return { promotable: functional.pass && semantic.pass, functional, semantic };
}
