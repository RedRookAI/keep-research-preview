/**
 * F1.7 — Conversation driver (THE KEYSTONE: the whole front door as one loop).
 *
 * This is the orchestration layer, and per the 2026 consensus "production failures
 * stem mostly from orchestration, not model quality" — so this loop's robustness IS
 * the product's reliability. It ties together every front-door piece:
 *
 *   human message
 *     -> SecretSafeIntake (F1)      secrets captured before the brain/spine ever see them
 *     -> BrainCall (F1.8/F1.9 seam) role-routed + fallback-protected + budget-capped
 *     -> parseProposal (F1.7)       validate; retry-with-clarification on malformed output
 *     -> PlanExecuteGate (F1.5)     auto-approve reversible / human-gate destructive
 *     -> deterministic fallback (F1) whenever the brain is unavailable / over-budget /
 *                                    repeatedly malformed, or the profile demands it
 *
 * Degrade, never break: if the LLM path can't produce a valid action, the driver hands
 * the turn to the deterministic OnboardingConversation so onboarding always progresses.
 * Bounded by maxRetries. Never throws.
 */

import { SecretSafeIntake } from "./secret_intake.js";
import { parseProposal } from "./proposal_parser.js";
import { PlanExecuteGate, type GateDecision } from "./plan_execute_gate.js";
import { OnboardingConversation, type Turn } from "./onboarding_conversation.js";
import type { AdaptiveProfile } from "./capability_adaptive.js";

/**
 * The brain call seam. In production this is wired to the role-router (planning role)
 * + fallback chain + capability budget; here it's injected so the driver is testable
 * offline. Returns the model's raw text, or null if the brain is unavailable (total
 * fallback-chain exhaustion) — which the driver treats as "use the deterministic path".
 */
export interface BrainCall {
  (prompt: string, opts: { maxOutputTokens: number }): Promise<string | null>;
}

export type DriverSource = "llm" | "deterministic" | "llm-fallback-to-deterministic";

export interface DriverTurn {
  /** What to say to the human (jargon-free). */
  readonly say: string;
  /** A warm acknowledgment if a secret was captured this turn (else empty). */
  readonly secretAck: string;
  /** The gate decision, if the turn produced an action. */
  readonly gateDecision?: GateDecision;
  /** Whether this turn was produced by the LLM, the deterministic flow, or a fallback. */
  readonly source: DriverSource;
  readonly done: boolean;
}

export interface DriverConfig {
  readonly maxRetries: number; // retry-with-clarification attempts before falling back
  /** Presentation-only transform. It receives completed content after parsing and authorization. */
  readonly present?: (content: string) => string;
}

const DEFAULT_CONFIG: DriverConfig = { maxRetries: 2 };

export class ConversationDriver {
  private readonly config: DriverConfig;

  constructor(
    private readonly intake: SecretSafeIntake,
    private readonly gate: PlanExecuteGate,
    private readonly fallback: OnboardingConversation,
    private readonly profile: AdaptiveProfile,
    private readonly brainCall: BrainCall,
    config: Partial<DriverConfig> = {},
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /** The opening line (delegates to the deterministic script's greeting). */
  greeting(): Turn {
    const turn = this.fallback.greeting();
    return { ...turn, say: this.present(turn.say) };
  }

  /**
   * Drive one turn. `calibratedConfidence` feeds the gate for external actions.
   */
  async turn(humanMessage: string, calibratedConfidence = 0): Promise<DriverTurn> {
    // 1. Secrets never reach the brain or the spine.
    const safe = this.intake.process(humanMessage);
    const secretAck = safe.acknowledgment;

    // 2. If the profile demands the deterministic path (minimal tier), use it.
    if (this.profile.useDeterministicFallback) {
      return this.deterministicTurn(safe.safeText, secretAck, "deterministic");
    }

    // 3. LLM path with retry-with-clarification.
    let prompt = this.buildPrompt(safe.safeText);
    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      let raw: string | null;
      try {
        raw = await this.brainCall(prompt, { maxOutputTokens: this.profile.maxOutputTokens });
      } catch {
        raw = null; // brain error -> treat as unavailable
      }
      if (raw === null) {
        // Brain unavailable (fallback chain exhausted) -> deterministic path.
        return this.deterministicTurn(safe.safeText, secretAck, "llm-fallback-to-deterministic");
      }

      const outcome = parseProposal(raw);
      if (outcome.kind === "reply") {
        return { say: this.present(outcome.text), secretAck, source: "llm", done: false };
      }
      if (outcome.kind === "action") {
        const decision = await this.gate.decide(outcome.action, calibratedConfidence);
        return { say: this.present(decision.reason), secretAck, gateDecision: decision, source: "llm", done: false };
      }
      // invalid -> feed the clarification back and retry.
      prompt = `${prompt}\n\nYour last reply couldn't be used: ${outcome.clarification}\nPlease try again.`;
    }

    // 4. Exhausted retries without a valid proposal -> deterministic path (never break).
    return this.deterministicTurn(safe.safeText, secretAck, "llm-fallback-to-deterministic");
  }

  private async deterministicTurn(safeText: string, secretAck: string, source: DriverSource): Promise<DriverTurn> {
    const t = await this.fallback.next(safeText);
    return { say: this.present(t.say), secretAck, source, done: t.done };
  }

  private present(content: string): string { return this.config.present?.(content) ?? content; }

  /** Build the per-turn prompt within the capability profile's shape + budget. */
  private buildPrompt(safeText: string): string {
    const style =
      this.profile.conversationStyle === "structured-only"
        ? "Reply with ONLY a single JSON object (an action or a reply). Keep it short."
        : "Reply with a single JSON object: an action to take, or a reply to the user.";
    // The context budget caps how much we'd assemble; here the message is the context.
    const budgetNote = `(keep within ~${this.profile.contextTokenBudget} tokens of context)`;
    return `${style} ${budgetNote}\nUser: ${safeText}`;
  }
}
