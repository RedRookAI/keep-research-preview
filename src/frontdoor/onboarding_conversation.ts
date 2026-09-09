/**
 * F1 — Onboarding conversation (deterministic, jargon-free cold start).
 *
 * "Human says what they want; AI asks clarifying questions that don't overwhelm or
 * expect engineering knowledge, and translates that into what needs to happen
 * (through a full vetting process)."
 *
 * Design (SOTA, Aug 2026): conversation-first, intent-adaptive, PROGRESSIVE
 * DISCLOSURE — one short question at a time (~40 words, mobile-first), recognize
 * intent from vague phrasing, let the human self-select rather than facing a menu,
 * and NEVER loop on the same question (brittle re-clarification is the top failure).
 *
 * Safety: this is a deterministic state machine, not the LLM freewheeling, so it is
 * testable and can't be talked into skipping steps. Each human directive is captured
 * as a PROBATION memory item (external origin) — it must earn trust before it
 * configures anything (F2 translates confirmed directives into real system changes).
 */

import type { MemoryStore } from "../memory/store.js";

export type Step =
  | "ask-human-name"
  | "ask-ai-name"
  | "ask-goal"
  | "clarify-goal"
  | "ask-channel"
  | "ask-email"
  | "done";

export interface OnboardingContext {
  humanName?: string;
  aiName?: string;
  goal?: string;
  goalDetail?: string;
  desiredChannel?: string; // "slack" | "telegram" | "web" | "other" | "none"
  wantsEmail?: boolean;
}

export interface Turn {
  /** What the AI says to the human this turn (short, jargon-free). */
  readonly say: string;
  /** The step we're now waiting on the human to answer. */
  readonly awaiting: Step;
  /** True when onboarding is complete. */
  readonly done: boolean;
}

/** Directives captured during onboarding, each stored on probation in memory. */
export interface CapturedDirective {
  readonly text: string;
  readonly lessonId?: string;
}

export class OnboardingConversation {
  private step: Step = "ask-human-name";
  private readonly ctx: OnboardingContext = {};
  private readonly directives: CapturedDirective[] = [];

  constructor(private readonly memory: Pick<MemoryStore, "ingest">) {}

  get context(): Readonly<OnboardingContext> {
    return this.ctx;
  }
  get capturedDirectives(): readonly CapturedDirective[] {
    return this.directives;
  }
  get currentStep(): Step {
    return this.step;
  }

  /** The opening line (before the human has said anything). */
  greeting(): Turn {
    return { say: "Hi! What can I call you?", awaiting: "ask-human-name", done: false };
  }

  /**
   * Advance the conversation with the human's (already secret-safe) reply. Returns
   * the AI's next short line + the step we now await. Captures context + directives.
   */
  async next(reply: string): Promise<Turn> {
    const answer = reply.trim();
    switch (this.step) {
      case "ask-human-name": {
        this.ctx.humanName = extractName(answer) || answer || "there";
        this.step = "ask-ai-name";
        return { say: `Nice to meet you, ${this.ctx.humanName}. What would you like to call me?`, awaiting: "ask-ai-name", done: false };
      }
      case "ask-ai-name": {
        this.ctx.aiName = extractName(answer) || answer || "Keep";
        this.step = "ask-goal";
        return { say: `Great — I'm ${this.ctx.aiName}. What do you want to work on today?`, awaiting: "ask-goal", done: false };
      }
      case "ask-goal": {
        this.ctx.goal = answer;
        await this.captureDirective(`Goal: ${answer}`);
        // Intent-adaptive: if the goal is vague, ask ONE clarifying question; else move on.
        if (isVague(answer)) {
          this.step = "clarify-goal";
          return { say: clarifyingQuestionFor(answer), awaiting: "clarify-goal", done: false };
        }
        this.step = "ask-channel";
        return { say: channelQuestion(), awaiting: "ask-channel", done: false };
      }
      case "clarify-goal": {
        this.ctx.goalDetail = answer;
        await this.captureDirective(`Goal detail: ${answer}`);
        this.step = "ask-channel";
        return { say: channelQuestion(), awaiting: "ask-channel", done: false };
      }
      case "ask-channel": {
        this.ctx.desiredChannel = normalizeChannel(answer);
        if (this.ctx.desiredChannel !== "none") {
          await this.captureDirective(`Reach me on: ${this.ctx.desiredChannel}`);
        }
        this.step = "ask-email";
        return {
          say: "Do you want me to be able to use email? I'd suggest a fresh address just for me, so your personal inbox stays separate and secure. Yes or no is fine.",
          awaiting: "ask-email",
          done: false,
        };
      }
      case "ask-email": {
        this.ctx.wantsEmail = isYes(answer);
        if (this.ctx.wantsEmail) await this.captureDirective("Set up a dedicated email for the assistant");
        this.step = "done";
        return { say: this.closingLine(), awaiting: "done", done: true };
      }
      case "done":
      default:
        return { say: "We're all set — tell me what you'd like to do next.", awaiting: "done", done: true };
    }
  }

  private closingLine(): string {
    const name = this.ctx.humanName ?? "there";
    const goal = this.ctx.goal ? ` on "${truncate(this.ctx.goal)}"` : "";
    return `Perfect, ${name}. I'll start getting up to speed${goal} in the background and check in as I go. You can change any of this any time — just tell me.`;
  }

  /** Store a directive as a probation memory item (external origin, project scope). */
  private async captureDirective(text: string): Promise<void> {
    const lesson = await this.memory.ingest(`[directive] ${text}`, { origin: "external", scope: "project" });
    this.directives.push({ text, ...(lesson ? { lessonId: lesson.id } : {}) });
  }
}

// --- small, dependency-free language helpers (deterministic + testable) ---

function extractName(s: string): string | undefined {
  // "I'm Alex" / "call me Alex" / "call you Ada" / "name is Alex" / "it's Ada" / "Alex"
  const m = s.match(/(?:i['’]?m|i am|call me|call you|you['’]?re|name is|it['’]?s|name you)\s+([A-Za-z][\w'-]{0,30})/i);
  if (m) return capitalize(m[1]!);
  const single = s.trim().match(/^([A-Za-z][\w'-]{0,30})$/);
  return single ? capitalize(single[1]!) : undefined;
}

function isVague(goal: string): boolean {
  const g = goal.toLowerCase().trim();
  if (g.split(/\s+/).length <= 3) return true;
  return /\b(stuff|things|everything|help|build something|a project|my app|my site)\b/.test(g) && g.split(/\s+/).length < 8;
}

function clarifyingQuestionFor(goal: string): string {
  const g = goal.toLowerCase();
  if (/\b(app|site|website|product)\b/.test(g)) {
    return "Nice. Is this a brand-new thing, or improving something that already exists? Either is fine.";
  }
  if (/\b(bug|fix|broken|error)\b/.test(g)) {
    return "Got it. What's the one thing that's most broken right now — where should I look first?";
  }
  return "Tell me a little more — what would a great result look like for you?";
}

function channelQuestion(): string {
  return "Where's easiest to reach you — Slack, Telegram, right here on the web, or somewhere else? We can set it up now or later.";
}

function normalizeChannel(s: string): string {
  const t = s.toLowerCase();
  if (t.includes("slack")) return "slack";
  if (t.includes("telegram")) return "telegram";
  if (t.includes("web") || t.includes("here") || t.includes("this")) return "web";
  if (t.includes("later") || t.includes("no") || t.includes("skip")) return "none";
  return "other";
}

function isYes(s: string): boolean {
  return /\b(yes|yeah|yep|sure|ok|okay|please|sounds good|do it)\b/i.test(s);
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function truncate(s: string, n = 60): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}
