/**
 * Intent-shape router — routes a human message by its SHAPE to the right handler.
 *
 * The 2026 consensus is a LAYERED CASCADE ordered cheapest->most-expensive: a
 * high-precision rule tier, then (seam) an LLM classifier for genuine ambiguity, then
 * a CLARIFYING-QUESTION fallback. The key warning (RECAP, 2026): rigid fixed-schema
 * classification "forces inputs into rigid categories that don't reflect actual
 * goals" — so this router NEVER guesses a bucket it isn't confident about; ambiguity
 * falls through to a single clarifying question.
 *
 * Shapes:
 *   - artifact-drop   : files/attachments present            -> F3a ingestion
 *   - revision        : "change/rebuild/actually..." verbs    -> F3b revise/rebuild
 *   - open-ended-goal : a vague aspiration ("run my marketing")-> clarify + research
 *   - concrete-task   : a specific actionable request          -> propose an action
 *   - ambiguous       : not confidently any of the above       -> ask ONE question
 *
 * The rule tier is structural (not model-trusted). The LLM classifier is an injected
 * seam used only when rules are unsure. What would change it: an embedding/prototype
 * tier slots between rules and LLM behind the same interface once a local embedding
 * backend exists.
 */

export type IntentShape = "artifact-drop" | "revision" | "open-ended-goal" | "concrete-task" | "ambiguous";

export interface RouteInput {
  readonly text: string;
  /** True if the turn carried file attachments / a dropped archive. */
  readonly hasAttachments?: boolean;
  /** Number of attached items, if known. */
  readonly attachmentCount?: number;
}

export interface RouteResult {
  readonly shape: IntentShape;
  /** 0..1 confidence in the shape. */
  readonly confidence: number;
  /** How the decision was reached. */
  readonly via: "rule" | "llm" | "clarify-fallback";
  /** The clarifying question to ask, when shape === "ambiguous". */
  readonly clarifyingQuestion?: string;
  /** Plain-language note about what will happen next. */
  readonly note: string;
}

/** Injected LLM classifier seam — used only when the rule tier is unsure. */
export interface LlmShapeClassifier {
  (text: string): Promise<{ shape: IntentShape; confidence: number } | null>;
}

const REVISION_RX = /\b(change|revise|update|rebuild|redo|rethink|instead|actually|scrap|start over|different (approach|plan|direction)|changed my mind|go back|undo|restore)\b/i;
const OPEN_ENDED_RX = /\b(run|handle|manage|grow|help me with|take care of|do (my|the)|figure out|improve|make (money|sales)|marketing|strategy|business|somehow|everything)\b/i;
const CONCRETE_TASK_RX = /\b(add|fix|create|write|implement|build (a|the)|refactor|rename|delete the|deploy|set up|configure|connect|integrate|generate|remove the|send|email|publish|post|pay|purchase|submit)\b/i;

const AUTO_THRESHOLD = 0.8; // >= route automatically
const ESCALATE_FLOOR = 0.5; // < escalate to LLM / clarify

/**
 * Deterministic (rule-only, no LLM) intent-shape classification — the same precedence the router's rule tier uses, as a
 * pure function so cheap callers (e.g. skill-application keying) can classify a prompt without a model round-trip.
 */
export function intentShapeByRule(text: string, hasAttachments = false): IntentShape {
  if (hasAttachments) return "artifact-drop";
  const t = text.trim();
  const isRevision = REVISION_RX.test(t);
  const isConcrete = CONCRETE_TASK_RX.test(t);
  const isOpenEnded = OPEN_ENDED_RX.test(t);
  const wordCount = t.split(/\s+/).filter(Boolean).length;
  if (isRevision && !isConcrete) return "revision";
  if (isConcrete && wordCount >= 3 && !isOpenEnded) return "concrete-task";
  if (isOpenEnded && !isConcrete) return "open-ended-goal";
  return isRevision ? "revision" : isConcrete ? "concrete-task" : isOpenEnded ? "open-ended-goal" : "ambiguous";
}

export class IntentShapeRouter {
  constructor(private readonly llm?: LlmShapeClassifier) {}

  async route(input: RouteInput): Promise<RouteResult> {
    // Tier 1: high-precision rules.
    const ruled = this.ruleTier(input);
    if (ruled.confidence >= AUTO_THRESHOLD) return ruled;

    // Tier 2 (seam): LLM classifier, only when rules are unsure.
    if (this.llm) {
      let llmRes: { shape: IntentShape; confidence: number } | null = null;
      try {
        llmRes = await this.llm(input.text);
      } catch {
        llmRes = null;
      }
      if (llmRes && llmRes.confidence >= AUTO_THRESHOLD) {
        return { shape: llmRes.shape, confidence: llmRes.confidence, via: "llm", note: noteFor(llmRes.shape) };
      }
    }

    // Tier 3: never guess — ask one clarifying question.
    return {
      shape: "ambiguous",
      confidence: ruled.confidence,
      via: "clarify-fallback",
      clarifyingQuestion: clarifyingQuestion(input),
      note: "I want to make sure I help the right way, so I'll ask a quick question first.",
    };
  }

  /** The deterministic rule tier. High-precision signals only. */
  private ruleTier(input: RouteInput): RouteResult {
    const text = input.text.trim();

    // Strongest signal: an actual artifact was dropped.
    if (input.hasAttachments || (input.attachmentCount ?? 0) > 0) {
      return { shape: "artifact-drop", confidence: 0.95, via: "rule", note: noteFor("artifact-drop") };
    }

    const isRevision = REVISION_RX.test(text);
    const isConcrete = CONCRETE_TASK_RX.test(text);
    const isOpenEnded = OPEN_ENDED_RX.test(text);
    const wordCount = text.split(/\s+/).filter(Boolean).length;

    // Revision verbs are a strong, explicit signal.
    if (isRevision && !isConcrete) {
      return { shape: "revision", confidence: 0.85, via: "rule", note: noteFor("revision") };
    }

    // A concrete actionable verb, reasonably specific.
    if (isConcrete && wordCount >= 3 && !isOpenEnded) {
      return { shape: "concrete-task", confidence: 0.82, via: "rule", note: noteFor("concrete-task") };
    }

    // An open-ended aspiration (vague, delegatory).
    if (isOpenEnded && !isConcrete) {
      return { shape: "open-ended-goal", confidence: 0.8, via: "rule", note: noteFor("open-ended-goal") };
    }

    // Mixed or weak signals -> low confidence, will escalate/clarify.
    const best = isRevision ? "revision" : isConcrete ? "concrete-task" : isOpenEnded ? "open-ended-goal" : "ambiguous";
    return { shape: best as IntentShape, confidence: best === "ambiguous" ? 0.3 : 0.6, via: "rule", note: noteFor(best as IntentShape) };
  }
}

function clarifyingQuestion(input: RouteInput): string {
  const t = input.text.toLowerCase();
  if (/\b(project|app|site|code|build)\b/.test(t)) {
    return "Happy to dig in — are you starting something new, continuing an existing project, or changing something we've already set up?";
  }
  return "I can take this a few different ways — do you want me to just get started on it, or would it help to talk through what you're aiming for first?";
}

function noteFor(shape: IntentShape): string {
  switch (shape) {
    case "artifact-drop":
      return "I'll read through what you've shared, safely, and tell you what I understand before doing anything.";
    case "revision":
      return "I'll treat this as a change to what we have — I'll keep the previous version so we can go back.";
    case "open-ended-goal":
      return "I'll ask a couple of quick questions and start building up what I need in the background.";
    case "concrete-task":
      return "I'll get started on this and check with you before anything that can't be undone.";
    case "ambiguous":
      return "Let me ask a quick question so I help the right way.";
  }
}

export { AUTO_THRESHOLD, ESCALATE_FLOOR };
