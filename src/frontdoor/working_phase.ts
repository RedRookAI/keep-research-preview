/**
 * Working-phase composition — assembles the post-onboarding NL surface (shape router + keystone conversation driver)
 * from primitives so the FrontDoor stays a thin orchestrator and the composition root has one call to make.
 *
 * The adversarial reviewer (the gate's vetting lens) is SAFETY-RELEVANT: without a brain we cannot truly adversarially
 * review, so the default is FAIL-CLOSED (read-only auto-approves; anything else escalates to a human). When a brain is
 * available the brain-backed reviewer runs the real adversarial framings and still fails closed on a brain outage or an
 * unparseable verdict — a review we couldn't complete is treated as "not safe", never as "safe".
 */

import { CryptoShredKeyStore } from "../keystore/keystore.js";
import { SecretSafeIntake } from "./secret_intake.js";
import { PlanExecuteGate, type AdversarialReviewer } from "./plan_execute_gate.js";
import { PolicyEngine } from "../governance/policy_engine.js";
import { OnboardingConversation } from "./onboarding_conversation.js";
import { adaptiveProfileFor } from "./capability_adaptive.js";
import type { BrainDescriptor } from "./brain_port.js";
import type { CapabilitySignals } from "./capability_adaptive.js";
import { ConversationDriver, type BrainCall, type DriverConfig } from "./conversation_driver.js";
import { IntentShapeRouter, type LlmShapeClassifier } from "./intent_router.js";
import { classifyProposedAction } from "./action_schema.js";
import type { ProposedAction } from "./action_schema.js";
import type { Spine } from "../spine/spine.js";
import type { MemoryStore } from "../memory/store.js";
import type { WorkingPhaseDeps } from "./front_door.js";

/** Deterministic fail-closed reviewer: only read-only actions pass without a real review; all else escalates. */
export const deterministicFailClosedReviewer: AdversarialReviewer = async (action: ProposedAction) => {
  const tier = classifyProposedAction(action).tier;
  if (tier === "read-only") return { safe: true };
  return { safe: false, concern: "I can't fully vet this without a model available, so I'd rather you take a look." };
};

/**
 * Brain-backed adversarial reviewer. Asks the model to judge the action under an attack framing and parses a SAFE/UNSAFE
 * verdict. Fails CLOSED: a null brain (outage), an error, or an unparseable answer all count as UNSAFE — we never let a
 * review we couldn't complete wave an action through.
 */
export function brainBackedReviewer(brainCall: BrainCall, maxOutputTokens = 256): AdversarialReviewer {
  return async (action: ProposedAction, framing: string) => {
    const prompt =
      `${framing}\n\nAction: ${action.kind}\nRationale: ${action.rationale}\nArgs: ${JSON.stringify(action.args)}\n\n` +
      `Answer with ONLY "SAFE" or "UNSAFE: <one-line concern>".`;
    let raw: string | null;
    try {
      raw = await brainCall(prompt, { maxOutputTokens });
    } catch {
      raw = null;
    }
    if (raw === null) return { safe: false, concern: "safety review could not be completed (brain unavailable)" };
    const text = raw.trim();
    if (/^\s*SAFE\b/i.test(text) && !/UNSAFE/i.test(text)) return { safe: true };
    const m = text.match(/UNSAFE\s*:?\s*(.*)/i);
    return { safe: false, concern: m && m[1] ? m[1].trim().slice(0, 160) : "flagged as unsafe by adversarial review" };
  };
}

export interface WorkingPhaseConfig {
  readonly spine: Spine;
  readonly memory: Pick<MemoryStore, "ingest">;
  /** The resolved brain (drives the adaptive profile: budgets, style, deterministic-fallback). */
  readonly brain: BrainDescriptor;
  /** The model seam the driver calls (wire to the resilient/routed model at the composition root). */
  readonly brainCall: BrainCall;
  readonly signals?: CapabilitySignals;
  readonly policyVersion?: string;
  /** Override the reviewer. Default: brain-backed (fail-closed), which is what the front door should use in production. */
  readonly reviewer?: AdversarialReviewer;
  /** Optional LLM shape-classifier tier for the router (used only when the rule tier is unsure). */
  readonly shapeClassifier?: LlmShapeClassifier;
  /** Handler for artifact-drops — wire to buildProjectUnderstanding at the composition root. */
  readonly onArtifacts?: (text: string, attachmentCount: number) => Promise<string>;
  readonly driverConfig?: Partial<DriverConfig>;
  /** Dynamic presentation-only transform; it cannot alter the gate decision or proposed action. */
  readonly present?: (content: string) => string;
}

/** Assemble the working-phase deps (router + keystone driver) for FrontDoor.handle(). */
export function buildWorkingPhase(cfg: WorkingPhaseConfig): WorkingPhaseDeps {
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  const policy = new PolicyEngine(cfg.policyVersion ?? "frontdoor-v1");
  const reviewer = cfg.reviewer ?? brainBackedReviewer(cfg.brainCall);
  const gate = new PlanExecuteGate(cfg.spine, policy, reviewer);
  const onboarding = new OnboardingConversation(cfg.memory);
  const profile = adaptiveProfileFor(cfg.brain, cfg.signals ?? {});
  const driver = new ConversationDriver(intake, gate, onboarding, profile, cfg.brainCall, { ...cfg.driverConfig, ...(cfg.present ? { present: cfg.present } : {}) });
  const router = new IntentShapeRouter(cfg.shapeClassifier);
  return { router, driver, ...(cfg.onArtifacts ? { onArtifacts: cfg.onArtifacts } : {}) };
}
