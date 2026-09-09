/**
 * Vetting-gates composition — routes plan-vetting and patch-vetting through ONE deterministic-floor-first cascade.
 *
 * Each gate's Tier-0 is the EXISTING deterministic check (analyzeConsequences for plans, verifyPatch for patches),
 * wrapped as a sound floor. Above it sits the shared, capability-adaptive harness: an optional single-brain verifier,
 * then a heterogeneous second brain, then human — escalated only when the floor cannot decide (ConfidenceEscalationPolicy).
 *
 * SOTA basis (2026): the production pattern is a cascade — run the deterministic floor first, escalate to a judge only
 * on borderline cases; "deterministic evaluators are the floor for safety, model judges the ceiling for intelligence."
 * The crown-jewel property is SOUNDNESS DOMINANCE: a sound floor verdict is authoritative and a probabilistic model tier
 * can never overturn it ("you can't audit a grader that hallucinates"). This factory composes exactly that, adding
 * model-tier scrutiny ABOVE the deterministic floor the pipeline already runs — value the deterministic-only vetter lacks.
 */

import { buildUnifiedGate, type FloorAdapter } from "./unified_gate.js";
import { buildHarness, type BrainCapability } from "./verification_harness.js";
import type { SingleBrainVerifier, ExternalBrainReviewer } from "./tier_adapters.js";
import type { Authorship } from "../review/heterogeneous.js";
import type { CascadeOutcome, VerificationItem } from "./verification_cascade.js";
import { analyzeConsequences } from "../pipeline/plan_consequences.js";
import { verifyPatch, type PatchVerifierInput } from "../pipeline/patch_verifier.js";
import { ResearchProvenanceFloorTier, type ResearchVetPayload, type CitationFetchPort } from "../research/provenance_floor.js";
import { RagGroundingFloorTier, type RagVetPayload } from "../research/rag_grounding_floor.js";
import { evaluateResearchTriple, type TripleEvalContext, type TripleVerdict } from "../research/research_loop.js";
import type { ResearchTriple } from "../research/research_need.js";
import type { Issue } from "../solve/issue_model.js";
import type { SuspectFile } from "../solve/localize.js";

export interface ConsequenceVetPayload {
  readonly issue: Issue;
  readonly suspects?: readonly SuspectFile[];
}
export type PatchVetPayload = PatchVerifierInput;

/** Payload for the research-triple gate: the three-axis source set + the build-domain/currency context. */
export interface ResearchTripleVetPayload {
  readonly triple: ResearchTriple;
  readonly context: TripleEvalContext;
}

export interface VettingGatesConfig {
  /** The operator's brain capability: rich (front-of-house), lean, or none (deterministic floor only). */
  readonly capability: BrainCapability;
  /** Optional model-tier verifier for plans (Tier-1). Absent → floor-only for plans. */
  readonly planSingleBrain?: SingleBrainVerifier<ConsequenceVetPayload>;
  /** Optional model-tier verifier for patches (Tier-1). Absent → floor-only for patches. */
  readonly patchSingleBrain?: SingleBrainVerifier<PatchVetPayload>;
  /** Optional model-tier verifier for research claims (Tier-1). Absent → floor-only. */
  readonly researchSingleBrain?: SingleBrainVerifier<ResearchVetPayload>;
  /** Optional model-tier verifier for RAG answers (Tier-1). Absent → floor-only. */
  readonly ragSingleBrain?: SingleBrainVerifier<RagVetPayload>;
  /**
   * Optional fail-honest URL-fetch port for SOUND verbatim citation verification (enterprise egress on).
   * Injected into every research-claim vet so an agent-produced Citation whose quoted text is reachable-
   * but-absent is caught as a sound fabrication. Absent → offline: verdicts stay `unverifiable`, never a
   * silent pass. A per-call `payload.options.fetch` takes precedence.
   */
  readonly researchFetch?: CitationFetchPort;
  readonly singleBrainAuthorship?: Authorship;
  readonly planSecondBrain?: { reviewer: ExternalBrainReviewer<ConsequenceVetPayload>; identity: Authorship };
  readonly patchSecondBrain?: { reviewer: ExternalBrainReviewer<PatchVetPayload>; identity: Authorship };
  /** Audit sink for each tier result. */
  readonly logger?: (tierResult: unknown, itemId: string) => void;
}

export interface VettingGates {
  /** Vet a plan through the cascade (deterministic consequence floor → model tiers → human). */
  vetPlan(payload: ConsequenceVetPayload, itemId?: string): Promise<CascadeOutcome>;
  /** Vet a patch through the cascade (deterministic patch-verifier floor → model tiers → human). NOTE: a `finalDecision`
   *  of `escalate-human` is a verification-CONFIDENCE signal ("automated tiers couldn't clear it"), NOT a consequence
   *  signal — consume it via `mergeVerificationFromCascade` + `decideMergeAuthority` so a REVERSIBLE change resolves
   *  autonomously and only a genuinely consequential one reaches a person. Never treat it as a direct human interrupt. */
  vetPatch(payload: PatchVetPayload, itemId?: string): Promise<CascadeOutcome>;
  /** Vet research claims through the provenance floor (fabricated/absent citations = sound fail → climb faithfulness). */
  vetResearchClaim(payload: ResearchVetPayload, itemId?: string): Promise<CascadeOutcome>;
  /** Vet a RAG answer through the grounding floor (insufficient retrieval → abstain; ungrounded → fabrication fail). */
  vetRagAnswer(payload: RagVetPayload, itemId?: string): Promise<CascadeOutcome>;
  /**
   * Vet a research TRIPLE through the tri-formula predicate — three axes, three DISTINCT machine checks
   * (TODAY fetched+fresh+receipt / HISTORICAL fails-recency / CROSS-DISC foreign-domain+mapping). A claim
   * that fills only one or two slots is REJECTED (a same-day-only search is a third of the picture); an
   * offline TODAY seam is honest (`honestSeam`), not a silent pass. Sound + deterministic; no brain tier.
   */
  vetResearchTriple(payload: ResearchTripleVetPayload): TripleVerdict;
}

export function buildVettingGates(cfg: VettingGatesConfig): VettingGates {
  const planFloor: FloorAdapter<ConsequenceVetPayload> = {
    name: "plan-consequences",
    evaluate: (p) => {
      const v = analyzeConsequences(p.issue, p.suspects ?? []);
      // Sound floor: only a cleared plan passes; block/escalate are a sound floor FAIL (authoritative).
      return { decision: v.cleared ? "pass" : "fail", reason: v.reason };
    },
  };
  const patchFloor: FloorAdapter<PatchVetPayload> = {
    name: "patch-verifier",
    evaluate: (p) => {
      const v = verifyPatch(p);
      // 3-valued → cascade: a sound check failure is an authoritative FAIL; a clean patch PASSES; a heuristic concern
      // (escalate-human — scope-creep / unintended control flow) is UNDECIDED, so it climbs to a model tier or human
      // rather than silently clearing the floor. This preserves verifyPatch's 3-valued safety semantics in the cascade.
      const decision = v.outcome === "fail" ? "fail" : v.outcome === "escalate-human" ? "undecided" : "pass";
      return { decision, reason: v.reason };
    },
  };

  const planGate = buildUnifiedGate<ConsequenceVetPayload>(planFloor, {
    capability: cfg.capability,
    ...(cfg.planSingleBrain ? { singleBrain: cfg.planSingleBrain } : {}),
    ...(cfg.singleBrainAuthorship ? { singleBrainAuthorship: cfg.singleBrainAuthorship } : {}),
    ...(cfg.planSecondBrain ? { secondBrain: cfg.planSecondBrain } : {}),
    ...(cfg.logger ? { logger: cfg.logger as (r: import("./verification_cascade.js").TierResult, id: string) => void } : {}),
  });
  const patchGate = buildUnifiedGate<PatchVetPayload>(patchFloor, {
    capability: cfg.capability,
    ...(cfg.patchSingleBrain ? { singleBrain: cfg.patchSingleBrain } : {}),
    ...(cfg.singleBrainAuthorship ? { singleBrainAuthorship: cfg.singleBrainAuthorship } : {}),
    ...(cfg.patchSecondBrain ? { secondBrain: cfg.patchSecondBrain } : {}),
    ...(cfg.logger ? { logger: cfg.logger as (r: import("./verification_cascade.js").TierResult, id: string) => void } : {}),
  });

  // Research grounding gates: the floors are already sound VerificationTiers, so they go straight into buildHarness
  // (no FloorAdapter wrapper). Provenance floor: absent/unresolvable citations are an authoritative fail; the
  // faithfulness residual climbs. RAG floor: insufficient retrieval abstains, ungrounded answers fail as fabrication.
  // NB (SOTA residuals, model-tier / future — NOT sound-floor concerns): refuted/contradicting evidence needs NLI
  // (the model tier's job, per SURE-RAG's three-way Supported/Refuted/Insufficient); deceptive grounding (right-doc,
  // wrong-entity) needs entity-attribution verification (arXiv 2607.09349); temporal staleness is handled at corpus
  // ingestion. The floors stay deterministic and correctly scoped.
  const researchCascade = buildHarness<ResearchVetPayload>({
    floor: new ResearchProvenanceFloorTier(),
    capability: cfg.capability,
    ...(cfg.researchSingleBrain ? { singleBrain: cfg.researchSingleBrain } : {}),
    ...(cfg.singleBrainAuthorship ? { singleBrainAuthorship: cfg.singleBrainAuthorship } : {}),
    ...(cfg.logger ? { logger: cfg.logger as (r: unknown, id: string) => void } : {}),
  });
  const ragCascade = buildHarness<RagVetPayload>({
    floor: new RagGroundingFloorTier(),
    capability: cfg.capability,
    ...(cfg.ragSingleBrain ? { singleBrain: cfg.ragSingleBrain } : {}),
    ...(cfg.singleBrainAuthorship ? { singleBrainAuthorship: cfg.singleBrainAuthorship } : {}),
    ...(cfg.logger ? { logger: cfg.logger as (r: unknown, id: string) => void } : {}),
  });

  return {
    vetPlan: (payload, itemId = "plan") => planGate({ id: itemId, kind: "plan", payload }),
    vetPatch: (payload, itemId = "patch") => patchGate({ id: itemId, kind: "artifact", payload }),
    vetResearchClaim: (payload, itemId = "research-claim") => {
      // WIRING: route the gate-level fetch port into the floor's provenance options so a fabricated
      // (reachable-but-absent) verbatim citation is caught end-to-end. A per-call options.fetch wins if set.
      const merged: ResearchVetPayload = cfg.researchFetch
        ? { ...payload, options: { ...(payload.options ?? {}), fetch: payload.options?.fetch ?? cfg.researchFetch } }
        : payload;
      return researchCascade.run({ id: itemId, kind: "research-claim", payload: merged });
    },
    vetRagAnswer: (payload, itemId = "rag-answer") => ragCascade.run({ id: itemId, kind: "rag-answer", payload }),
    // The tri-formula gate is a pure sound predicate (no brain tier): the three axes carry distinct
    // machine checks and compose over the currency recency logic + the spine-sealed fetch receipt.
    vetResearchTriple: (payload) => evaluateResearchTriple(payload.triple, payload.context),
  };
}
