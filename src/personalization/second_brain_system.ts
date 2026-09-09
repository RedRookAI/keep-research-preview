/**
 * SECOND-BRAIN COMPOSITION ROOT — the wiring that integrates the personalization + teams/enterprise capabilities
 * into ONE reachable subsystem.
 *
 * The moat (8 rounds), hardening (4), and teams/enterprise (T1-T2) rounds each built and test-proved a capability,
 * but none was wired into `composeKeep` — the whole second brain was reachable only by tests. `assembleSecondBrain`
 * fixes that: it assembles the capabilities into a single `SecondBrainSystem` and is invoked by `composeKeep`, so
 * the second brain is part of the running Keep, not an island.
 *
 * It genuinely consumes each capability module (real calls, not stubs):
 *   - memory store + CI vault (per-project crypto namespace) + safe-parsing registry;
 *   - `ingest` — the H4 end-to-end path (parse → upkeep + vault → land in the store);
 *   - `anticipate` — R4 need anticipation;
 *   - `authorize` — T1 `may()` over the personalization surfaces (owner + ReBAC resolvers);
 *   - `promote` / `retract` — T2 governed team commons;
 *   - `exportBundle` / `importBundle` / `erase` — H2 portability round-trip + crypto-shred;
 *   - connector policy (`mayConnectorAct`), lens catalog + guards, inferred-preference proposal/admission.
 */

import type { Spine } from "../spine/spine.js";
import type { ModelGateway } from "../gateway/gateway.js";
import { MemoryStore } from "../memory/store.js";
import { SensitiveContextVault } from "../privacy/contextual_integrity.js";
import { ProjectRegistry } from "../session/project_registry.js";
import { CryptoShredKeyStore } from "../keystore/keystore.js";
import { ParserRegistry } from "../intake/parser_registry.js";
import { ingestToSecondBrain, type IngestOutcome } from "../pipeline/second_brain.js";
import { anticipate, type CandidateNeed, type Decision as AnticipateDecision, type AnticipateOptions } from "../anticipate/anticipation.js";
import { may, ownerResolver, type AuthzPrincipal, type AuthzResolver, type AuthzAction, type Resource, type Decision as AuthzDecision } from "../authz/authorization.js";
import { promoteToShared, retractFromShared, type PromotionRequest, type PromotionResult, type RetractionResult } from "../memory/team_commons.js";
import { assembleDerived, applyRestored } from "../portability/store_io.js";
import { exportAll, importAll, erase, type Portable, type ImportResult, type Receipt } from "../portability/portability.js";
import { registerConnector, mayAct, type ConnectorDescriptor, type ConnectorPolicy, type Registration, type ActDecision, type Consequence } from "../connect/connector.js";
import { lensGuards, NONE_LENS, COMPANION_LENS, RESEARCHER_LENS, MARKETER_LENS, CONTENT_CREATOR_LENS, type Lens } from "../lens/lens.js";
import { proposeInferred, admitInferred, type InferredTarget, type CandidatePreference, type AdmitPolicy } from "../personalize/inferred.js";
import { resolvePolicy, type PolicyRequest, type PolicyLayer, type PolicyDecision } from "../governance/personalization_policy.js";
import { secondBrainEvidence, secondBrainErase, type SecondBrainEvidence, type ErasureEvidence } from "../governance/second_brain_governance.js";
import type { ResidencyPolicy } from "../governance/residency.js";
import { wellbeingGate, DistressRedirector, type ToxicValidationInput, type WellbeingVerdict, type DistressSignal } from "../wellbeing/wellbeing_guardrails.js";
import type { Notification } from "../notify/notification_router.js";
import { estimateComplexity, chooseModel, type TaskSignal, type ModelProfile, type RouterPolicy, type RouteChoice } from "../routing/cost_of_pass_router.js";
import { calibratedFloorByConsequence, type CalibrationRecord, type CalibrationConfig } from "../routing/floor_calibration.js";
import { measuredSavings } from "../observability/routing.js";
import { monitorExecution, type ObservedOutcome, type MonitorResult } from "../logic/execution_monitor.js";
import { GroundedEstimator, type EstimateRequest, type GroundedEstimate } from "../autonomy/grounded_estimator.js";
import type { Plan } from "../logic/plan_gate.js";
import { resolveLocalFirstDefaults, endpointsAsOf, type EndpointProbe, type LocalFirstPlan } from "../frontdoor/local_first_defaults.js";
import { seedStarterCorpus } from "../memory/starter_corpus.js";
import type { Lesson } from "../memory/model.js";
import { renderSoulPrompt, describeSoul, soulChangeToProposal } from "../soul/soul_render.js";
import { DEFAULT_SOUL, type SoulConfig } from "../soul/soul_config.js";
import type { ConfigProposal } from "../frontdoor/directive_translator.js";
import { priorArtCheck, type PriorArtInput, type PriorArtReport, type PriorArtSearch } from "../currency/prior_art.js";
import { LandscapeCatalog } from "../currency/landscape_catalog.js";
import { buildTemporalContext } from "../currency/temporal_context.js";
import { buildBatchDigest, type PrReviewItem, type BatchDigest } from "../review/batch_digest.js";
import { jailedAttempt, StubJail, type JailRequest, type JailedAttemptDeps, type JailedOutcome } from "../ree/jail.js";
import { FencedKillRegistry, fenceDecision, type KillOutcome, type CommitAdmission, type FenceToken } from "../identity/process_kill.js";
import { fleetAdmit, type FleetChecks, type FleetAdmission } from "../fleet/fleet_gate.js";
import type { IntakeItem } from "../intake/intake.js";
import type { Labeled } from "../provenance/taint_tracer.js";

export interface SecondBrainConfig {
  readonly spine: Spine;
  readonly gateway: ModelGateway;
  /** Reuse the composition root's admitted store across all memory consumers. */
  readonly memory?: MemoryStore;
  readonly ownerId?: string; // the N=1 owner principal id (default "owner")
  readonly projectName?: string;
}

/** The assembled, reachable second-brain subsystem. */
export interface SecondBrainSystem {
  readonly memory: MemoryStore;
  readonly vault: SensitiveContextVault;
  readonly parsers: ParserRegistry;
  readonly ownerResolver: AuthzResolver;
  readonly lenses: Readonly<Record<string, Lens>>;

  /** Ingest an item end-to-end (parse → upkeep + vault → land in the store). */
  ingest(item: IntakeItem, existing?: Parameters<typeof ingestToSecondBrain>[2], key?: string): Promise<IngestOutcome>;
  /** Anticipate whether a latent need should surface (reads through the vault when sensitive). */
  anticipateNeed(candidate: CandidateNeed, opts?: AnticipateOptions): AnticipateDecision;
  /** Authorize an action on a personalization surface (T1). Defaults to the owner resolver (N=1). */
  authorize(who: AuthzPrincipal, action: AuthzAction, resource: Resource, resolver?: AuthzResolver): AuthzDecision;
  /** Promote a personal lesson into the shared/team commons (T2, governed). */
  promote(req: PromotionRequest, who: AuthzPrincipal, resolver?: AuthzResolver): Promise<PromotionResult>;
  /** Retract (contain) a shared entry. */
  retract(sharedId: string, reason?: string): RetractionResult;
  /** Export the subject's derived state as a portable bundle (H2 + CI-scoped). */
  exportBundle(subject: string): Portable;
  /** Import a bundle into a destination store at probation (H2). */
  importBundle(bundle: Portable, into: MemoryStore): Promise<ImportResult>;
  /** Crypto-shred the subject's key (portability erase) — makes the vaulted context unreadable. */
  erase(subject: string): Receipt;
  /** Register a connector under a policy (R6). */
  registerConnector(desc: ConnectorDescriptor, policy: ConnectorPolicy): Registration;
  /** May a connector-sourced, tainted input drive an action of this consequence? (R6 trifecta break) */
  mayConnectorAct(consequence: Consequence, inputs: readonly Labeled<unknown>[]): ActDecision;
  /** Propose an inferred preference from observations (R-inferred). */
  inferPreference(target: InferredTarget, observations: readonly boolean[]): CandidatePreference;
  /** Admit an inferred preference under a policy (cosmetic-only, incumbent-respecting). */
  admitPreference(candidate: CandidatePreference, incumbent: string | undefined, policy: AdmitPolicy): boolean;
  /** The guard tags a given lens imposes. */
  guardsFor(lens: Lens): readonly string[];
  /** Resolve a personalization request against the nested org-policy layers (T3, PBAC/subsidiarity). */
  resolvePolicy(request: PolicyRequest, layers: readonly PolicyLayer[]): PolicyDecision;
  /** A DSAR/ROPA evidence pack over the second brain (T4): what is held about a subject + residency. */
  evidenceFor(subject: string, residency: ResidencyPolicy): SecondBrainEvidence;
  /** Evidenced erasure (T4): crypto-shred the subject key + confirm the vaulted context is unreadable. */
  eraseWithEvidence(subject: string): ErasureEvidence;
  /** R2 anti-dependence gate: veto a proposed response/nudge that is toxic validation or an engagement hook. */
  checkWellbeing(input: ToxicValidationInput, nudgeText: string): WellbeingVerdict;
  /** R2 distress redirect: on genuine distress, point to HUMAN support once (never preachy/repeated). */
  redirectOnDistress(signal: DistressSignal): Notification | undefined;
  /** Budget/routing lever: estimate complexity → apply the calibrated consequence-scaled floor → min cost-of-pass. */
  route(task: TaskSignal, profiles: readonly ModelProfile[], policy: RouterPolicy, calibration?: { records: readonly CalibrationRecord[]; config: CalibrationConfig }): RouteChoice;
  /** Measured routing savings vs a baseline (cost governance). */
  routingSavings(baselineUsd: number, routedUsd: number): { savedUsd: number; pct: number };
  /** AFTER-execution vetting: walk a plan against observed outcomes; HALT + replan at the first divergence. */
  monitorPlan(plan: Plan, observed: readonly ObservedOutcome[]): MonitorResult;
  /** Grounded before-estimate (cost/time) — never fabricates; honest "not enough data" when unmeasured. */
  estimateWork(req: EstimateRequest): Promise<GroundedEstimate>;
  /** n=1 no-account boot: probe for a local model; never demands an account (the back-of-house floor). */
  resolveLocalFirst(probe: EndpointProbe): Promise<LocalFirstPlan>;
  /** Seed the research starter corpus into memory at PROBATION (borrowed/unverified; no authority laundering). */
  seedStarter(): Promise<Lesson[]>;
  /** Staleness note for the known-local-endpoints list (surface the cold-start data freshness). */
  localEndpointsAsOf(): string;
  /** Render the soul into VOICE (name/tone/style). Shapes how the system sounds — never what it may do. */
  renderSoul(soul?: SoulConfig): string;
  /** Plain-language description of the current soul (onboarding confirmation). */
  describeSoul(soul?: SoulConfig): string;
  /** A soul change becomes a gated config PROPOSAL (routed through the config gate, never applied directly). */
  proposeSoulChange(changeText: string): ConfigProposal;
  /** Anti-reinvention: surface existing tools/approaches for a goal (advisory, free/open first, never auto-adopted). */
  checkPriorArt(input: PriorArtInput, search?: PriorArtSearch): Promise<PriorArtReport>;
  /** Batch low-consequence reviews into ONE triaged digest (blockers surface first) — cuts rubber-stamping. */
  reviewDigest(items: readonly PrReviewItem[]): BatchDigest;
  /** In-env jail contract (R27): run a confined attempt; any breach/failed-accept ⇒ rolled-back (fail-safe). */
  runJailed(req: JailRequest, deps: JailedAttemptDeps): Promise<JailedOutcome>;
  /** Bind an identity to its process group + open its fence (R35). */
  bindIdentity(id: string, processGroup: string): void;
  /** Kill an identity: bump the fence (fail-safe even if the OS kill is unavailable), flag escalation. */
  killIdentity(id: string, reason?: string): KillOutcome;
  /** Lease the current fence token to a live identity. */
  leaseToken(id: string): CommitAdmission;
  /** Pure fencing decision: reject a killed identity or a stale token. */
  checkFence(currentFence: FenceToken, killed: boolean, presentedToken: FenceToken): boolean;
  /** HONEST seam labelling: reports that OS jail (R27) + process-group kill (R35) are deployment seams — never claims isolation it does not enforce. */
  isolationEnforcement(): { readonly jailEnforced: boolean; readonly osKillEnforced: boolean; readonly seam: string };
  /** Fleet admission (deny-overrides): proceed iff the per-decision gate allows AND every fleet barrier clears. */
  admitFleetAction(gateAutoProceed: boolean, checks: FleetChecks): FleetAdmission;
}

/**
 * Assemble the second-brain subsystem. Invoked by `composeKeep` so the personalization + teams capabilities are
 * part of the running system rather than test-only islands.
 */
export function assembleSecondBrain(config: SecondBrainConfig): SecondBrainSystem {
  const ownerId = config.ownerId ?? "owner";
  const memory = config.memory ?? new MemoryStore(config.spine, config.gateway);

  // per-project crypto namespace for the CI vault (silo-grade primitive on shared infra)
  const keystore = new CryptoShredKeyStore();
  const registry = new ProjectRegistry(keystore);
  const project = registry.create(config.projectName ?? "second-brain");
  const vault = new SensitiveContextVault(registry.namespace(project.id));

  const parsers = new ParserRegistry();
  const distress = new DistressRedirector(); // R2 — redirects to human support once per session
  const jail = new StubJail(); // in-env envelope contract; the OS-enforced OsJail (R27) is the SEAM
  const fence = new FencedKillRegistry(); // in-env monotonic fence; the OS process-group kill (R35) is the SEAM
  const landscape = new LandscapeCatalog(); // seeded with OpenClaw/Hermes/ElevenLabs/… (anti-reinvention)
  const temporal = buildTemporalContext(); // canVerify=false by default ⇒ honest staleness caveat
  const estimator = new GroundedEstimator(async () => null); // rates feed is the SEAM ⇒ honest ungrounded by default
  const owner = ownerResolver(ownerId);
  const lenses: Readonly<Record<string, Lens>> = {
    none: NONE_LENS,
    companion: COMPANION_LENS,
    researcher: RESEARCHER_LENS,
    marketer: MARKETER_LENS,
    contentCreator: CONTENT_CREATOR_LENS,
  };

  return {
    memory,
    vault,
    parsers,
    ownerResolver: owner,
    lenses,

    ingest(item, existing, key) {
      return ingestToSecondBrain(item, { store: memory, vault, registry: parsers }, existing, key);
    },
    anticipateNeed(candidate, opts) {
      return anticipate(candidate, opts);
    },
    authorize(who, action, resource, resolver) {
      return may(who, action, resource, resolver ?? owner);
    },
    promote(req, who, resolver) {
      return promoteToShared(req, who, { resolver: resolver ?? owner, store: memory });
    },
    retract(sharedId, reason) {
      return retractFromShared(sharedId, { store: memory }, reason);
    },
    exportBundle(subject) {
      return exportAll(subject, assembleDerived(subject, { memoryStore: memory }));
    },
    async importBundle(bundle, into) {
      const result = importAll(bundle);
      if (result.ok) await applyRestored(result.restored, { memoryStore: into });
      return result;
    },
    erase(subject) {
      return erase(keystore, subject);
    },
    registerConnector(desc, policy) {
      return registerConnector(desc, policy);
    },
    mayConnectorAct(consequence, inputs) {
      return mayAct(consequence, inputs);
    },
    inferPreference(target, observations) {
      return proposeInferred(target, observations);
    },
    admitPreference(candidate, incumbent, policy) {
      return admitInferred(candidate, incumbent, policy);
    },
    guardsFor(lens) {
      return lensGuards(lens);
    },
    resolvePolicy(request, layers) {
      return resolvePolicy(request, layers);
    },
    evidenceFor(subject, residency) {
      return secondBrainEvidence(subject, { memory, vault, residency });
    },
    eraseWithEvidence(subject) {
      return secondBrainErase(subject, { keystore, vault, projectKeySubject: project.id as unknown as string });
    },
    checkWellbeing(input, nudgeText) {
      return wellbeingGate(input, nudgeText);
    },
    redirectOnDistress(signal) {
      return distress.redirect(signal);
    },
    route(task, profiles, policy, calibration) {
      const band = estimateComplexity(task);
      let effectivePolicy = policy;
      if (calibration !== undefined) {
        const floorByConseq = calibratedFloorByConsequence(calibration.records, calibration.config);
        const floor = floorByConseq[task.reversibilityClass];
        effectivePolicy = { ...policy, minSuccess: Math.max(policy.minSuccess, floor) }; // never below the calibrated floor
      }
      return chooseModel(band, profiles, effectivePolicy);
    },
    routingSavings(baselineUsd, routedUsd) {
      return measuredSavings(baselineUsd, routedUsd);
    },
    monitorPlan(plan, observed) {
      return monitorExecution(plan, observed);
    },
    estimateWork(req) {
      return estimator.estimate(req);
    },
    resolveLocalFirst(probe) {
      return resolveLocalFirstDefaults(probe);
    },
    seedStarter() {
      return seedStarterCorpus(memory);
    },
    localEndpointsAsOf() {
      return endpointsAsOf();
    },
    renderSoul(soul) {
      return renderSoulPrompt(soul ?? DEFAULT_SOUL);
    },
    describeSoul(soul) {
      return describeSoul(soul ?? DEFAULT_SOUL);
    },
    proposeSoulChange(changeText) {
      return soulChangeToProposal(changeText);
    },
    checkPriorArt(input, search) {
      return priorArtCheck(input, { spine: config.spine, catalog: landscape, temporal, ...(search !== undefined ? { search } : {}) });
    },
    reviewDigest(items) {
      return buildBatchDigest(items);
    },
    runJailed(req, deps) {
      return jailedAttempt(jail, req, deps);
    },
    bindIdentity(id, processGroup) {
      fence.bind(id, processGroup);
    },
    killIdentity(id, reason) {
      return fence.kill(id, reason ?? "revoked");
    },
    leaseToken(id) {
      return fence.lease(id);
    },
    checkFence(currentFence, killed, presentedToken) {
      return fenceDecision(currentFence, killed, presentedToken);
    },
    isolationEnforcement() {
      return { jailEnforced: false, osKillEnforced: false, seam: "OS jail (R27) + process-group kill (R35) are deployment seams; in-env provides the envelope-side contract + monotonic fence only" };
    },
    admitFleetAction(gateAutoProceed, checks) {
      return fleetAdmit(gateAutoProceed, checks);
    },
  };
}
