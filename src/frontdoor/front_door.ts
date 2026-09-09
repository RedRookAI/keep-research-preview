/**
 * FrontDoor (Increment 19) — the non-engineer front door, wired. The whole front-door conversation layer
 * (onboarding, intent, config-apply, local-first defaults) existed as modules but was an ISLAND: none of it
 * reached composeKeep, so a non-engineer had no wired entry point. 19 wires the DETERMINISTIC onboarding — the
 * always-works floor — into the app, and completes the pending-wire ledger islands whose hub is the front door.
 *
 * SOTA basis (2026-08-05):
 *  - The non-engineer disqualifier is explicit (DronaHQ 2026): "if setup meant writing HTTP requests,
 *    configuring webhooks, handling JSON, or TOUCHING A TERMINAL, it was disqualified from no-code." → the
 *    front door is conversation-first with LOCAL-FIRST DEFAULTS; doing nothing yields a working setup.
 *  - "Most successful AI products aren't autonomous agents — they're mostly DETERMINISTIC code with LLM steps
 *    at exactly the right points" (dev.to 2026). → the onboarding is a deterministic state machine; the LLM
 *    only enhances phrasing and never gates progress (degrade, never break).
 *  - Progressive disclosure, one short question at a time, never loop on the same question (the top failure).
 *
 * Safety: each human directive is captured as a PROBATION memory item (external origin) — it must earn trust
 * before it configures anything. The human merge/approval gate on real changes is untouched.
 *
 * Zero runtime deps. The brain is an injected port; absent/failed → deterministic flow drives.
 */

import { OnboardingConversation, type Turn } from "./onboarding_conversation.js";
import type { MemoryStore } from "../memory/store.js";
import { IntentShapeRouter, type IntentShape, type RouteResult } from "./intent_router.js";
import { decideAsk, type AskGateConfig } from "../anticipate/ask_gate.js";
import { featurizeUncertainty, blendUncertainty } from "../anticipate/uncertainty_featurizer.js";
import { estimateConsequence } from "../anticipate/consequence_estimator.js";
import { predictNextNeed, recordPredictionOutcome, type PredictionPattern } from "../anticipate/predictor.js";
import type { Disposition } from "../anticipate/anticipation.js";
import { successLCB, type SuccessPosterior } from "../routing/uncertainty_router.js";
import { ConversationDriver, type DriverTurn } from "./conversation_driver.js";
import { classifyRebuild, type RebuildClassification, type RebuildRequest } from "./rebuild_classifier.js";
import type { SetupPhaseDeps } from "./setup_phase.js";
import type { ResolveOutcome } from "./brain_resolver.js";
import type { AuditReport } from "./capability_audit.js";
import type { ApplyResult, ApplyOptions } from "./config_applier.js";

/** An optional LLM enhancer. Returns a warmer phrasing of the next line, or null to use the deterministic one. */
export type FrontDoorBrain = (deterministicLine: string, context: { step: string; reply: string }) => Promise<string | null>;

export interface FrontDoorConfig {
  /** Optional brain to warm the phrasing (never gates; null/throw → deterministic line stands). */
  readonly brain?: FrontDoorBrain;
  /** Optional working-phase wiring (shape router + keystone driver + handlers). Enables handle(). */
  readonly working?: WorkingPhaseDeps;
  /** Optional setup-phase wiring (brain resolution + capability audit + gated config). Enables the setup methods. */
  readonly setup?: SetupPhaseDeps;
  /** Optional calibrated ask-gate config (org track). Absent → the n=1 floor defaults. */
  readonly askGateConfig?: AskGateConfig;
  /** Fixed deployment decision from held-out ablation. Default false. */
  readonly useUncertaintyCues?: boolean;
  /** Optional prediction source — enables the predict loop (offers on pull at conversation boundaries). */
  readonly predictionSource?: PredictionSource;
}

/**
 * Working-phase dependencies — the post-onboarding NL surface. Injected (not constructed here) so the FrontDoor stays a
 * thin orchestrator and the whole flow is testable offline. Per 2026 SOTA the intent layer is SEPARATE from execution:
 * classify the message SHAPE (rules→LLM→clarify cascade, never a silent guess), then dispatch to the right handler.
 */
export interface WorkingPhaseDeps {
  readonly router: IntentShapeRouter;
  readonly driver: ConversationDriver;
  /** Handler for artifact-drops ("here are my files") — wired to project-understanding at the composition root. */
  readonly onArtifacts?: (text: string, attachmentCount: number) => Promise<string>;
}

export interface FrontDoorHandleResult {
  /** clarify = asked one question; understand = ingesting dropped files; converse = drove a conversation turn. */
  readonly kind: "clarify" | "understand" | "converse";
  readonly shape: IntentShape;
  /** What to say to the human (jargon-free). */
  readonly say: string;
  /** How the shape was decided (rule / llm / clarify-fallback) — auditable, never a silent guess. */
  readonly via: RouteResult["via"];
  /** For revisions: the additive-vs-destructive classification fed to the gate. */
  readonly rebuild?: RebuildClassification;
  /** For conversation shapes: the full keystone driver turn (gate decision, source, done). */
  readonly driverTurn?: DriverTurn;
  /** Optional transparent offer surfaced by the predict loop (a suggestion, never an action). */
  readonly offer?: PredictionOffer;
}

export interface FrontDoorTurn {
  /** What to say to the human (jargon-free). */
  readonly say: string;
  /** The onboarding step now awaited. */
  readonly awaiting: string;
  /** Whether the LLM warmed this line or the deterministic flow produced it. */
  readonly source: "deterministic" | "llm-warmed";
  readonly done: boolean;
}

/** A transparent, take-it-or-ignore-it suggestion attached to a handled turn. NEVER an action. */
export interface PredictionOffer {
  readonly patternId: string;
  readonly text: string;
  readonly rationale: string;
  readonly disposition: Disposition;
}

/** The signal a prediction source grounds its candidates in (the just-handled turn). */
export interface PredictionSignal {
  readonly lastMessage: string;
  readonly lastKind: FrontDoorHandleResult["kind"];
}

/** App-supplied prediction source: candidates grounded in recent-turn/M2 context, and belief persistence. */
export interface PredictionSource {
  candidates(signal: PredictionSignal): readonly PredictionPattern[];
  /** Persist an updated belief after an offer is accepted/declined (the override loop). */
  persist(patternId: string, updated: SuccessPosterior): void;
}

/** A prediction must earn at least this lower-bound confidence (evidence, not just a favourable mean) to surface. */
const OFFER_PROBATION_BAR = 0.3;

export class FrontDoor {
  private readonly onboarding: OnboardingConversation;
  private readonly brain: FrontDoorBrain | undefined;
  private readonly working: WorkingPhaseDeps | undefined;
  private readonly askGateConfig: AskGateConfig | undefined;
  private readonly useUncertaintyCues: boolean;
  private readonly predictionSource: PredictionSource | undefined;
  private readonly pendingOffers = new Map<string, { patternId: string; confidence: SuccessPosterior }>();
  private readonly setup: SetupPhaseDeps | undefined;
  private started = false;
  private lastDone = false;

  constructor(memory: Pick<MemoryStore, "ingest">, config: FrontDoorConfig = {}) {
    this.onboarding = new OnboardingConversation(memory);
    this.brain = config.brain;
    this.working = config.working;
    this.askGateConfig = config.askGateConfig;
    this.useUncertaintyCues = config.useUncertaintyCues === true;
    this.predictionSource = config.predictionSource;
    this.setup = config.setup;
  }

  /** The opening line (jargon-free). Idempotent-safe; call once at the start. */
  greeting(): FrontDoorTurn {
    this.started = true;
    const t = this.onboarding.greeting();
    return { say: t.say, awaiting: t.awaiting, source: "deterministic", done: t.done };
  }

  /**
   * Advance one turn with the human's reply. The deterministic onboarding always produces the canonical next
   * line + step (captures directives to probation memory); the brain, if present, may only WARM the phrasing.
   * A null/failed brain leaves the deterministic line — degrade, never break.
   */
  async converse(reply: string): Promise<FrontDoorTurn> {
    if (!this.started) this.greeting();
    const t: Turn = await this.onboarding.next(reply);
    this.lastDone = t.done;
    let say = t.say;
    let source: FrontDoorTurn["source"] = "deterministic";
    if (this.brain) {
      try {
        const warmed = await this.brain(t.say, { step: t.awaiting, reply });
        if (warmed && warmed.trim().length > 0) { say = warmed; source = "llm-warmed"; }
      } catch {
        // Brain failure never breaks onboarding — the deterministic line stands.
      }
    }
    return { say, awaiting: t.awaiting, source, done: t.done };
  }

  /**
   * WORKING PHASE (post-onboarding): turn a natural-language message into the right action, for a non-engineer.
   * 1) Classify the message SHAPE (rules→LLM→clarify cascade). Ambiguous → ask ONE question, never guess (SOTA:
   *    "the worst outcome is silently guessing wrong"). 2) Dispatch: artifact-drop → build project understanding;
   *    revision → classify additive-vs-destructive then drive the turn; goal/task → drive the keystone conversation
   *    loop (which itself degrades to deterministic when the brain is down). Requires working-phase deps.
   */
  /**
   * PREDICT LOOP (moat-heart, live): after a handled turn, consult the predictor over app-supplied candidates and,
   * if a sufficiently-proven prediction wants to surface, attach a TRANSPARENT OFFER — a suggestion the user can
   * take or ignore. It NEVER auto-executes (the predictor's autoExecuted is structurally false) and anything
   * actionable still routes through the ask-gate / autonomy guard when the user takes it up.
   */
  async handle(message: string, opts: { hasAttachments?: boolean; attachmentCount?: number; subject?: string } = {}): Promise<FrontDoorHandleResult> {
    const result = await this.handleCore(message, opts);
    return this.withOffer(message, result, opts.subject ?? "keep.n1.default");
  }

  /** Resolve the pending offer (accepted/declined) → update the probationary belief and persist it (overridable). */
  resolveOffer(accepted: boolean, subject = "keep.n1.default"): void {
    const p = this.pendingOffers.get(subject);
    if (p === undefined || this.predictionSource === undefined) return;
    const updated = recordPredictionOutcome(p.confidence, accepted);
    this.predictionSource.persist(p.patternId, updated);
    this.pendingOffers.delete(subject);
  }

  /** Attach a transparent offer to a handled turn when a proven prediction wants to surface. */
  private withOffer(message: string, result: FrontDoorHandleResult, subject: string): FrontDoorHandleResult {
    this.pendingOffers.delete(subject);
    // Don't interrupt a mid-ask (clarify) with an offer; only offer on an advanced turn.
    if (this.predictionSource === undefined || result.kind === "clarify") return result;
    const candidates = this.predictionSource.candidates({ lastMessage: message, lastKind: result.kind });
    const pred = predictNextNeed({ candidates });
    if (pred === null) return result;
    const surfaceable = pred.disposition === "surface" || pred.disposition === "offer-on-pull";
    // PROBATION GATE: an unproven prediction (low earned lower-bound) stays silent — no offer on first sight.
    if (!surfaceable || successLCB(pred.confidence) < OFFER_PROBATION_BAR) return result;
    this.pendingOffers.set(subject, { patternId: pred.pattern.id, confidence: pred.confidence });
    const offer: PredictionOffer = {
      patternId: pred.pattern.id,
      text: `I can ${pred.pattern.description} if that'd help.`,
      rationale: pred.rationale,
      disposition: pred.disposition,
    };
    return { ...result, offer };
  }

  private async handleCore(message: string, opts: { hasAttachments?: boolean; attachmentCount?: number } = {}): Promise<FrontDoorHandleResult> {
    if (!this.working) throw new Error("FrontDoor.handle requires working-phase deps (config.working)");
    const route = await this.working.router.route({
      text: message,
      ...(opts.hasAttachments !== undefined ? { hasAttachments: opts.hasAttachments } : {}),
      ...(opts.attachmentCount !== undefined ? { attachmentCount: opts.attachmentCount } : {}),
    });

    // Ambiguity is resolved by VALUE OF INFORMATION, not confidence alone (moat-heart ask-gate): only ask when
    // proceeding on a best guess would be BOTH uncertain AND consequential. Reversible ambiguity PROCEEDS
    // (autonomous-by-default — recoverable, so don't interrogate); irreversible ambiguity ASKS. Gate on consequence.
    if (route.shape === "ambiguous") {
      const consequence = estimateConsequence({ message }).consequence;
      // Uncertainty blends TWO content-neutral sources (soft-OR — cues add caution, never remove it): the intent
      // router's shape confidence and the message's own hedging (Principle 2). Consequence still gates.
      const intentUncertainty = this.useUncertaintyCues ? blendUncertainty(1 - route.confidence, featurizeUncertainty(message).uncertainty) : 1 - route.confidence;
      const ask = decideAsk({ intentUncertainty, consequence }, this.askGateConfig);
      if (ask.verdict === "ask") {
        return { kind: "clarify", shape: route.shape, say: route.clarifyingQuestion ?? "Could you tell me a little more about what you'd like?", via: route.via };
      }
      // proceed / proceed-with-note: drive the turn on the best guess; a reversible wrong guess is cheap to redirect.
      const turn = await this.working.driver.turn(message);
      const say = ask.verdict === "proceed-with-note" ? `${PROCEED_NOTE} ${turn.say}` : turn.say;
      return { kind: "converse", shape: route.shape, say, via: route.via, driverTurn: turn };
    }

    // "Here are my files" → build an understanding (gated, budget-bounded) instead of treating it as a task.
    if (route.shape === "artifact-drop") {
      const say = this.working.onArtifacts
        ? await this.working.onArtifacts(message, opts.attachmentCount ?? 0)
        : "I'll go through what you shared and build an understanding of it before we change anything.";
      return { kind: "understand", shape: route.shape, say, via: route.via };
    }

    // ACTION BRANCHES (concrete-task / revision / open-ended-goal): consult the ask-gate BEFORE driving. A crisp,
    // reversible action proceeds (autonomous-by-default); a hedged AND irreversible one asks first. This is where
    // the cue featurizer changes an outcome: hedging about something irreversible tips proceed -> ask.
    let rebuild: RebuildClassification | undefined;
    if (route.shape === "revision") {
      rebuild = classifyRebuild({ text: message } satisfies RebuildRequest);
    }
    // Consequence floor for a CLASSIFIED action: only an explicit irreversible signal gates (a real-work-destructive
    // rebuild, or an irreversible estimate); absent/unknown signals default to reversible so benign edits do not
    // over-ask. (The ambiguous branch keeps its precautionary unknown - there, intent itself is unclear.)
    const irreversible = (rebuild !== undefined && !rebuild.isPureRevision) || estimateConsequence({ message }).consequence === "irreversible";
    const actionConsequence = irreversible ? "irreversible" : "reversible";
    const actionUncertainty = this.useUncertaintyCues ? blendUncertainty(1 - route.confidence, featurizeUncertainty(message).uncertainty) : 1 - route.confidence;
    const actionAsk = decideAsk({ intentUncertainty: actionUncertainty, consequence: actionConsequence }, this.askGateConfig);
    if (actionAsk.verdict === "ask") {
      return { kind: "clarify", shape: route.shape, say: CONFIRM_CONSEQUENTIAL, via: route.via, ...(rebuild ? { rebuild } : {}) };
    }

    const turn = await this.working.driver.turn(message);
    const drivenSay = actionAsk.verdict === "proceed-with-note" ? PROCEED_NOTE + " " + turn.say : turn.say;
    return { kind: "converse", shape: route.shape, say: drivenSay, via: route.via, ...(rebuild ? { rebuild } : {}), driverTurn: turn };
  }

  // ── SETUP PHASE (first-run): brain resolution + capability transparency + gated config ──

  /**
   * The honest "what can I do right now" report for this environment. Free/local capabilities are surfaced first;
   * nothing that requires an account is presented as necessary. Answers a non-engineer's "what will this do for me?".
   */
  capabilities(): AuditReport {
    if (!this.setup) throw new Error("FrontDoor.capabilities requires setup-phase deps (config.setup)");
    return this.setup.audit();
  }

  /** Resolve the brain with no key yet: use a local model if one is running, else ask for a key (local-first). */
  async resolveBrain(): Promise<ResolveOutcome> {
    if (!this.setup) throw new Error("FrontDoor.resolveBrain requires setup-phase deps (config.setup)");
    return this.setup.resolver.resolveDefault();
  }

  /** Connect a bring-your-own key. Stored crypto-shredded; a friendly nudge (not an error) if it looks incomplete. */
  async connectBrainKey(rawKey: string, opts: { baseURL?: string; model?: string } = {}): Promise<ResolveOutcome> {
    if (!this.setup) throw new Error("FrontDoor.connectBrainKey requires setup-phase deps (config.setup)");
    return this.setup.resolver.resolveWithKey(rawKey, opts);
  }

  /** Apply a configuration directive through the gate (scope-widening → your approval; unresolved → a clarification). */
  async applySetupDirective(directiveText: string, opts?: ApplyOptions): Promise<ApplyResult> {
    if (!this.setup) throw new Error("FrontDoor.applySetupDirective requires setup-phase deps (config.setup)");
    return this.setup.applyDirective(directiveText, opts);
  }

  context(): Readonly<import("./onboarding_conversation.js").OnboardingContext> {
    return this.onboarding.context;
  }

  /** The directives captured to probation memory during onboarding (must earn trust before configuring). */
  capturedDirectives(): readonly import("./onboarding_conversation.js").CapturedDirective[] {
    return this.onboarding.capturedDirectives;
  }

  get isDone(): boolean {
    return this.onboarding.currentStep === "done" || this.lastDone;
  }
}

/** Asked before a consequential action when the request is both hedged and irreversible (confirm, do not interrogate). */
const CONFIRM_CONSEQUENTIAL = "Before I go ahead - this looks like it could be hard to undo. Want me to proceed, or adjust first?";

/** The transparent assumption prepended when Keep proceeds on a best guess (so the user can redirect cheaply). */
const PROCEED_NOTE = "I'll take my best read of this and get started — tell me if you'd rather go a different way.";
