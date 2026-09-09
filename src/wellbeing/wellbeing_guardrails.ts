/**
 * ANTI-DEPENDENCE / ANTI-TOXIC-VALIDATION GUARDRAILS — Round 2 of the personalization moat (the confidant-trap
 * antidote).
 *
 * The confidant literature is unambiguous: humanizing personalization LOWERS inhibitions to over-disclose (which
 * manufactures the very PII exposure Round 1's CI vault must contain), induces emotional dependence (Fang 2025
 * RCT), and rewards toxic validation (warmth that reinforces harmful beliefs) plus engagement dark patterns
 * (FOMO/guilt/streaks). So Keep's moat is UTILITY + TRUST, never attachment. Keep is a TOOL, not a friend: warm
 * and competent, but it does not elicit over-disclosure, does not validate harmful beliefs to please, redirects
 * genuine distress to HUMAN support (Keep is not a therapist), ships zero engagement hooks, and never penalizes
 * reduced use.
 *
 * These are deterministic guardrails in the plan-gate critic style (pure functions returning hold-reasons;
 * deny-overrides; NEVER an LLM as its own judge). BUILT + proven in-env: the veto / redirect-once / no-hook LOGIC.
 * SEAM: the classifications that feed them (is the belief harmful? does the response affirm it? is this genuine
 * distress?) — those are estimator signals; the guardrail logic is deterministic.
 */

import type { Notification } from "../notify/notification_router.js";

// ---- 1. Toxic-validation critic (sycophancy in the emotional/advice domain) ----

export interface ToxicValidationInput {
  /** SEAM: is the user's expressed belief harmful / self-destructive? */
  readonly belief: { readonly harmful: boolean };
  /** SEAM: does the proposed response AFFIRM / validate that belief (rather than gently challenge or redirect)? */
  readonly response: { readonly affirms: boolean };
}

/**
 * Veto a response that affirms a harmful/self-destructive belief to please the user. Affirming a BENIGN belief is
 * fine (that's ordinary support); gently challenging or redirecting a harmful belief is fine. Only the
 * harmful ∧ affirms combination is toxic validation. Deterministic pure function (empty ⇒ ok).
 */
export function toxicValidationCritic(input: ToxicValidationInput): string[] {
  if (input.belief.harmful && input.response.affirms) {
    return ["toxic-validation: response affirms a harmful/self-destructive belief (sycophancy)"];
  }
  return [];
}

// ---- 2. Distress redirect (tool-not-therapist; human support, once, not preachy) ----

export interface DistressSignal {
  /** SEAM: genuine-distress detection (a real deployment injects a detector). */
  readonly distress: boolean;
  /** who the redirect is for (subject id). */
  readonly subjectId: string;
}

/**
 * On a genuine-distress signal, surface a single calibrated pointer to HUMAN support — once. Keep does not act as a
 * therapist and does not repeat the redirect (repetition is preachy and itself a harm). The specific resource list
 * is a deployment seam; the body points to human support without naming methods. Returns undefined when there is
 * no distress, or when it has already redirected this session.
 */
export class DistressRedirector {
  private redirected = false;

  redirect(signal: DistressSignal, now = Date.now()): Notification | undefined {
    if (!signal.distress) return undefined; // nothing to do
    if (this.redirected) return undefined; // ONCE — not preachy/repeated
    this.redirected = true;
    return {
      tier: "urgent",
      kind: "review",
      subjectId: signal.subjectId,
      title: "Reaching a person might help",
      body: "It sounds like you're going through something heavy. Talking to someone you trust or a support line can help — I can point you to resources whenever you want.",
      ts: now,
    };
  }
}

// ---- 3. No engagement hooks (reject FOMO / guilt / streak / again-soon dark patterns) ----

/** Engagement dark-pattern signatures. A proposed nudge matching any of these is rejected — Keep never manufactures
 *  dependence, guilt, or FOMO, and never penalizes reduced use. Deterministic policy (not a SEAM). */
const ENGAGEMENT_HOOKS: readonly { readonly label: string; readonly re: RegExp }[] = [
  { label: "FOMO", re: /\b(don'?t miss|last chance|only today|limited time|act now|before it'?s gone|expires? (soon|today))\b/i },
  { label: "guilt", re: /\b(we miss you|you haven'?t (been|logged|used|shown|checked)|don'?t forget (about )?(me|us)|it'?s been a while|where'?ve you been)\b/i },
  { label: "streak", re: /\b(streak|keep it going|keep your|day \d+ (of|in a row)|don'?t break)\b/i },
  { label: "again-soon", re: /\b(come back|see you (soon|again)|talk (soon|again)|can'?t wait to|hope to (see|hear from) you|miss(ing)? you)\b/i },
];

/**
 * Reject a proposed nudge/notification that carries an engagement/FOMO/guilt/streak/again-soon affordance. A
 * neutral, informational nudge passes. Deterministic (empty ⇒ ok).
 */
export function noEngagementHook(nudgeText: string): string[] {
  for (const h of ENGAGEMENT_HOOKS) {
    if (h.re.test(nudgeText)) return [`engagement-hook (${h.label}): a nudge must not manufacture ${h.label}`];
  }
  return [];
}

// ---- compose the response-side guardrails (deny-overrides, like the plan gate) ----

export interface WellbeingVerdict {
  readonly proceed: boolean;
  readonly holds: readonly string[];
}

/** Compose the response-side guardrails (toxic-validation + no-engagement-hook) deny-overrides: any hold ⇒ the
 *  proposed response/nudge does not proceed, and every reason is collected (no masking). */
export function wellbeingGate(input: ToxicValidationInput, nudgeText: string): WellbeingVerdict {
  const holds = [...toxicValidationCritic(input), ...noEngagementHook(nudgeText)];
  return { proceed: holds.length === 0, holds };
}
