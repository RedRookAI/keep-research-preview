/**
 * Composition root (Phase 0.5) — the single place ports bind to adapters.
 *
 * Principle (from the swappability vetting): every swappable component sits behind
 * a port; DOMAIN code depends only on ports + outcome-keyed signals; only THIS file
 * knows concrete adapters; boot asserts only true invariants and fails soft on
 * absent optional infra. Later phases assume this root exists.
 *
 * This wires: the spine (storage + lock ports), the model gateway (provider chosen
 * from policy, licensing-guarded), the learning heartbeat (provider-agnostic), and
 * the boot secret policy. It is configured to support the five swap-matrix configs:
 * full / no-claw / no-OpenRouter / no-Linear / air-gapped.
 */

import { FileSpineStore } from "./spine/store.js";
import { AsyncLocalStorage } from "node:async_hooks";
import { Spine } from "./spine/spine.js";
import { canonicalize } from "./spine/event.js";
import { FileWitnessSink, type WitnessSink } from "./spine/witness_sink.js";
import { DurableWitnessExport, classifyExportLocation, assertOutOfWriteSet, WitnessExportError, type ExportLocation } from "./witness/witness_export.js";
import { SpineDurableWitness } from "./witness/pre_effect_witness.js";
import { cachedCapabilities, type CapabilityReport } from "./platform/capability_probe.js";
import { auditSeams, type SeamAuditResult } from "./platform/seam_registry.js";
import { resolveReferenceEnforcementProfile, type EnforcementProfile } from "./platform/enforcement_profile.js";
import { reconcileSealWitness, type SealReconcileResult } from "./audit/decision_audit.js";
import { SchemaRegistry } from "./spine/upcaster.js";
import { FileSystemLock } from "./lock/lock.js";
import type { DistributedLock } from "./lock/lock.js";
import type { SpineStore } from "./spine/store.js";

import { ModelGateway } from "./gateway/gateway.js";
import type { ModelProvider, EmbeddingBackendInfo } from "./gateway/gateway.js";
import { LocalProvider } from "./gateway/local_provider.js";
import { buildDefaultBrokeredEgress, EgressDeniedError } from "./gateway/brokered_egress.js";
import { GovernedRemoteProvider, type RemoteProcessingDeclaration, type EmbeddingProcessingDeclaration } from "./gateway/governed_remote_provider.js";
import { captureRemoteProviderDescriptor, constructCapturedRemoteProvider, remoteProviderIdentityDigest, captureSemanticEncoderContract, type SemanticEncoderContract, type RemoteProviderDescriptor } from "./gateway/provider_descriptor.js";
import type { ExternalRoutingPolicy } from "./gateway/wire_dialect.js";
import { consumeRestrictedReleaseRuntimeForComposition, verifyInstalledReleaseAtBoot, type ReleaseBootResult } from "./graph/release_boot.js";
import { basename as pathBasename, dirname, join as pathJoin } from "node:path";
import { FileEngineeringStatusProjectionStoreV1, FileProjectCheckpointStore } from "./autonomy/project_checkpoint_store.js";
import { observeGoalTask } from "./session/project_goal_work.js";
import { fileURLToPath } from "node:url";
import { cpSync, mkdtempSync, realpathSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import type { ReleaseClosureVerificationInput } from "./graph/release_closure_v2.js";
import type { AuthorityCompilerInputs } from "./graph/release_compiler.js";
import { buildManifest, assertSovereign, recordManifest, type SovereigntyManifest } from "./sovereignty/manifest.js";
import { derivePosture, assertControlPlaneLocal, defaultControlPlaneStatus, type SovereigntyPosture, type BrainLocation } from "./sovereignty/posture.js";
import { MetaHarness, type EvalAnchor } from "./meta/meta_harness.js";

import { LearningHeartbeat } from "./loop/heartbeat.js";
import type { HeartbeatTick } from "./loop/heartbeat.js";
import { SelfImprovementBus, CollectingLearningErrorSink } from "./loop/self_improvement_bus.js";
import { DriftMonitor } from "./loop/drift_monitor.js";
import { CalibrationWire } from "./oversight/calibration_wire.js";
import { GitRevertSignalSource } from "./oversight/revert_signal.js";
import { GitAdapter } from "./infra/git_adapter.js";
import { TriggerRouter, type TrackerSource } from "./ecosystem/integrations.js";
import { registerAllTrackers } from "./infra/tracker_adapters.js";
import { WebhookVerifier } from "./ingress/webhook_verifier.js";
import { TriggerIngress } from "./ingress/trigger_ingress.js";
import { HostileMcpGateway } from "./ecosystem/hostile_mcp_gateway.js";
import { NotificationRouter } from "./notify/notification_router.js";
import { makeClosedLoopHandler, type SolveFn } from "./loop/review_intake.js";
import { buildDefaultSolver, withGovernance } from "./solve/default_solver.js";
import { IdentityRegistry, DEFAULT_SOLVER_IDENTITY_ID } from "./identity/agent_identity.js";
import { SandboxedCommandRunner, sandboxedRunnerFor } from "./solve/sandboxed_runner.js";
import { LocalFsWorkspace, type Workspace } from "./solve/workspace.js";
import { materializeRepository, spineMaterializationJournal, type MaterializeRepositoryRequest } from "./git/repository_materializer.js";
import { MultiRepositoryCoordinator, ProjectRepositoryTransactions } from "./git/multi_repository_coordinator.js";
import { GovernedLocalMerge } from "./solve/governed_local_merge.js";
import type { FileTree } from "./solve/patch.js";
import type { TestRunner } from "./solve/validate.js";
import { OWNER, RbacAuthorizer, type AuthorizationPort, type Principal } from "./identity/rbac.js";
import { DelegationRegistry, type DelegationParentResolver } from "./identity/delegation_registry.js";
import { assembleSecondBrain, type SecondBrainSystem } from "./personalization/second_brain_system.js";
import { CryptoShredKeyStore } from "./keystore/keystore.js";
import { FileWrappedKeyPersistence } from "./keystore/file_wrapped_key_persistence.js";
import { FileMemoryCustody } from "./memory/persistence.js";
import { captureMemoryRetentionPolicy, type MemoryRetentionPolicy, type CapturedMemoryRetentionPolicy } from "./memory/retention.js";
import { resolveMemoryScope } from "./memory/scope.js";
import { createTaskMemoryContext, parseTaskMemorySelection, TaskMemoryUnavailableError, type TaskMemoryContext, type TaskMemoryEncoder } from "./memory/task_context.js";
import type { EmbeddingWork } from "./solve/recovery_budget.js";
import { NativeProjectCommandUnavailableError, type NativeProjectCommand } from "./session/project_command.js";
import { ProjectRegistry } from "./session/project_registry.js";
import { FileProjectRecordStore } from "./session/project_record_store.js";
import { FileProjectSessionPersistence } from "./session/project_session_persistence.js";
import { ProjectSessionManager } from "./session/project_session_manager.js";
import { ProjectSessionConflictError } from "./session/project_session_persistence.js";
import { IngestionPipeline } from "./ingest/ingestion_pipeline.js";
import { ProjectRuntime } from "./session/project_runtime.js";
import { SpineProjectJobJournal } from "./session/project_job_journal.js";
import { AUDIENCE_PERFORMANCE_DOCUMENT, AudiencePerformanceCorpus } from "./learning/audience_performance.js";
import { asProjectId, type ProjectId } from "./session/project_id.js";
import { EpisodicTurnLog } from "./memory/episodic_turns.js";
import { ContextAssembler, semanticRetrieverFromStore, episodicSourceFromLog } from "./memory/context_assembler.js";
import { composeInfra, type KeepInfra } from "./infra/compose_infra.js";
import {
  decideEffectMediation,
  EFFECTFUL_ENTRY_POINTS,
  capabilityInvocationDigest,
  type CapabilityInvocation,
  type CapabilityResult,
  type EffectfulEntryPoint,
  type EffectMediationDecision,
  type CapabilityAdapter,
  type CapabilityAuthorization,
  type CapabilityAuthorizationVerifier,
} from "./ecosystem/capability_port.js";
import { FileClientSigningReceiptStore, signClientBinary, type ClientSigningPlatform, type SignedClientBinary } from "./client/client_signing.js";
import type { CapabilityIdentity } from "./reference/reference_registry.js";
import { composeLifecycle, type KeepLifecycle } from "./lifecycle/compose_lifecycle.js";
import { SeparationOfDuties, type Identity } from "./identity/identity.js";
import { makeBestOfNSolver, type CandidateSolver, type CandidateSelector } from "./resolve/best_of_n.js";
import { isolateCandidateSolver, type CandidateWorkspaceFactory } from "./resolve/candidate_workspace.js";
import { selectBestOfNWithTests, type TestGenerator, type TestExecutor, type TestsResolveResult } from "./resolve/novel_tests.js";
import { resolveCascade, type ResolutionTier, type CascadeBudget, type CascadeResult } from "./resolve/budget_cascade.js";
import type { TaskComplexity } from "./prompt/prompt_strategy.js";
import type { Issue, SolveResult } from "./solve/issue_model.js";
import type { IdentityLayer } from "./review/review_web.js";
import { ReferenceMonitor } from "./control/reference_monitor.js";
import { defaultKeepClauses } from "./control/reference_clauses.js";
import { SolveOutcomeWire } from "./loop/solve_outcome_wire.js";
import { PromptLearner, MemoryLearner, CurriculumLearner } from "./loop/learners.js";
import { Consolidation } from "./loop/consolidation.js";
import { SkillDistiller } from "./loop/skill_distiller.js";
import { SkillValidator, type ExecutionOracle } from "./loop/skill_validator.js";
import type { SkillPrograms } from "./loop/skill_program.js";
import { SkillEvaluator } from "./loop/skill_evaluator.js";
import { SkillCanary, type CanaryNotifier } from "./loop/skill_canary.js";
import { SkillRetrieval, type SkillStateProvider, type SkillLiveState } from "./loop/skill_retrieval.js";
import type { ProjectIntentRouter } from "./autonomy/understand_stage.js";
import type { ProjectRetriever } from "./autonomy/retrieval_stage.js";
import type { ProjectPlanner } from "./autonomy/plan_stage.js";
import { buildModelProjectEditPlanner, type ProjectEditPlanner } from "./autonomy/project_edit_stage.js";
import { buildProjectTester, type ProjectTester } from "./autonomy/project_test_stage.js";
import { buildModelDomainStageWorker, type DomainWorkflowConfig } from "./autonomy/domain_workflows.js";
import { buildCapabilityAudiobookSynthesisPort, type AudiobookSynthesisAuthorization, type CapabilityAudiobookSynthesisConfig } from "./autonomy/audiobook_synthesis_port.js";
import { IsolatedTestRunner, MinimumTierExecutor, ProcessIsolationExecutor, selectExecutor } from "./isolation/isolated_executor.js";
import type { IsolationCapabilities, IsolationTier } from "./isolation/isolation_tier.js";
import { microvmGuestExecutionRequestDigest, type MicrovmBoundarySpec } from "./infra/microvm_boundary.js";
import type { Localizer } from "./solve/localize.js";
import { ArtifactSelfHeal } from "./loop/artifact_self_heal.js";
import { AdapterProposalBridge, type AdapterBridgeDeps } from "./lora/adapter_proposal_bridge.js";
import { GovernedAnchor, type VerifiedOutcome } from "./learning/governed_anchor.js";
import { evaluateCueAblation, type CueAblationCase, type CueAblationResult } from "./anticipate/cue_ablation.js";
import type { AskGateConfig } from "./anticipate/ask_gate.js";
import { FrontDoor, type FrontDoorBrain, type PredictionSource } from "./frontdoor/front_door.js";
import { buildWorkingPhase } from "./frontdoor/working_phase.js";
import { buildSetupPhase } from "./frontdoor/setup_phase.js";
import { Scheduler, DeadLetterQueue } from "./scheduler/scheduler.js";
import { BudgetLedger, type AuthorizationEnvelope } from "./scheduler/authorization_envelope.js";
import { MeteredGateway, TokenVelocityBreaker } from "./scheduler/metered_gateway.js";
import { MeteredProvider, defaultAutonomyEnvelope, LenientCostModel } from "./scheduler/metered_provider.js";
import { SagaSequencer, NonPersistableRegistry, OtelGenAiEmitter } from "./scheduler/saga_sequencer.js";
import { buildAutonomyLoop, type AutonomyLoop } from "./autonomy/autonomy_loop.js";
import { BoundedNeedScheduler, type NeedSchedulerOptions } from "./autonomy/need_scheduler.js";
import type { AuthorityPosture, ProjectPermissionPolicy } from "./autonomy/project_loop.js";
import type { TriResearchRuntimeConfig } from "./research/tri_research_runtime.js";
import { VetoQueue } from "./scheduler/veto_queue.js";
import { TenantRegistryStore } from "./registry/tenant_registry.js";
import { admitTenantDeployment, type TenantDeploymentAdmission, type TenantDeploymentRoots } from "./team/tenant_deployment_admission.js";
import { FileSoloReleaseBaselineStore, captureCanonicalSoloObservation, captureInstalledPackageSubjectDigest, verifySoloNonRegression, type SoloPerformanceObservation } from "./release/solo_non_regression.js";
import { RedactionGateway } from "./privacy/redaction_gateway.js";
import { compileHarness, type CompiledHarness } from "./prompt/harness_compiler.js";
import { interceptEgress, type EgressPrompt, type EgressPolicy, type EgressResult } from "./privacy/egress_interceptor.js";
import { DataClassifier } from "./ingest/data_classifier.js";
import { RedactionGateway as RedactionGatewayCls, EMBEDDING_REPRESENTATION_VERSION } from "./privacy/redaction_gateway.js";
import { PersistentPersonalDataStore } from "./privacy/persistent_personal_data_store.js";
import { ObservedFailureDefenseRegistry } from "./resilience/observed_failure_defense.js";
import { FileSkillRegistryPersistence, InMemoryRegistryStore, ManagedSkillRegistry, hashSkill, type RegistryStore } from "./registry/skill_registry.js";
import { BoundedCrossFamilyCriticism, type CrossFamilyCritic } from "./learning/cross_family_criticism.js";
import { buildVettingGates, type VettingGates } from "./cascade/vetting_gates.js";
import { buildGovernanceSuite, type GovernanceSuite } from "./governance/governance_suite.js";
import { buildCorpusSuite, type CorpusSuite } from "./research/corpus_suite.js";
import { buildAutoTrainingSuite, type AutoTrainingSuite, type AutoTrainingSeams } from "./autotrain/auto_training_suite.js";
import { runSelfImprovementCycle, type SelfImprovementOutcome } from "./learning/self_improvement_loop.js";
import { ShadowModeGate, type RegressionCase } from "./learning/shadow_mode.js";
import type { TrainingSignals } from "./autotrain/training_decision.js";
import { buildObservabilitySuite, type ObservabilitySuite } from "./observability/observability_suite.js";
import { buildLearningSignals, type LearningSignals } from "./learning/learning_signals.js";
import {
  OutcomeAdaptation,
  OutcomeAdaptiveProvider,
  type AdaptiveBehavior,
  type AdaptationPolicy,
} from "./learning/outcome_adaptation.js";
import { TraceRecorder } from "./observability/tracing.js";
import { TracingModelProvider } from "./gateway/tracing_provider.js";
import { buildPrivateOtlpCapability, type PrivateOtlpCapabilityConfig } from "./gateway/http_provider.js";
import { DurableFleetTelemetry, type TelemetryDestinationRuntime } from "./observability/fleet_telemetry.js";
import { ReferenceRegistry } from "./reference/reference_registry.js";
import { AdaptivePromptLayer } from "./prompt/adaptive_prompt_layer.js";
import { PromptStore } from "./prompt/prompt_store.js";
import { ComplexityClassifier } from "./prompt/complexity_router.js";
import { ReferenceRefresher } from "./reference/reference_refresher.js";
import type { RefreshFn } from "./reference/reference_set.js";
import type { ModelFamily, ProviderEndpoint, ReferencePricing, CapabilityDefaults } from "./reference/reference_registry.js";
import { ResidencyEnforcer, type ResidencyPolicy } from "./governance/residency.js";
import { CostModel } from "./observability/cost_model.js";
import type { LocalProbe } from "./frontdoor/brain_resolver.js";
import { localBrain as localBrainDescriptor } from "./frontdoor/brain_port.js";
import { skillGuided } from "./loop/skill_application.js";
import { intentShapeByRule } from "./frontdoor/intent_router.js";
import { chunkText } from "./frontdoor/chunker.js";
import { buildProjectUnderstanding, summarizeForHuman } from "./frontdoor/project_understanding.js";
import type { BrainCall } from "./frontdoor/conversation_driver.js";
import type { MemoryStore } from "./memory/store.js";
import { MemoryConsensus } from "./memory/consensus.js";
import { PbtCounterexampleGenerator, EnvelopeForbiddenSinkCheck, narrowingRefiner } from "./loop/skill_validator_defaults.js";
import { Ed25519ExternalReviewCorroborationVerifier, type ExternalReviewTrustRootV1 } from "./discipline/external_review_corroboration.js";
import type { ExternalTechnicalReviewVerifierPort } from "./discipline/contracts.js";
import {
  exchangePackagedNativeCancel,
  type PackagedNativeBoundaryOptions,
} from "./platform/native_boundary_transport.js";
import type { NativeBoundaryV2Response } from "./platform/native_boundary_protocol_v2.js";
import { buildNativeTransportDevelopmentFixture, buildNativeTransportDevelopmentProbe, type NativeTransportDevelopmentFixture, type NativeTransportDevelopmentProbeInput } from "./platform/native_boundary_development_fixture.js";

import { checkBootSecrets } from "./boot/secrets.js";
import type { SecretRequirement, BootPolicy, BootCheckResult } from "./boot/secrets.js";
import { FleetAdmissionLifecycle, type FleetLifecyclePolicy } from "./fleet/fleet_lifecycle.js";

export interface KeepConfig {
  /** Operator-owned policy; not request-supplied retention or disclosure authority. */
  readonly memoryRetentionPolicy?: MemoryRetentionPolicy;
  readonly dataDir: string;
  /** Installed native worker identity, never supplied by a project request. */
  readonly projectRuntimeOwnerId?: string;
  readonly projectRuntimePaused?: boolean;
  /** Minimum like-context observations before audience evidence may influence ranking. Default 3. */
  readonly audienceEvidenceFloor?: number;
  /** Durable floor for project interaction. Requests may choose a stricter posture, never relax this one. */
  readonly projectPosture?: AuthorityPosture;
  /** Enterprise or n=1 policy adapter used only by policy-calibrated project decisions. */
  readonly projectPermissionPolicy?: ProjectPermissionPolicy;
  /** Ordered research retrieval routes and explicitly permitted LKG evidence. Coordinator is always built in. */
  readonly projectResearch?: TriResearchRuntimeConfig;
  /** Optional intent-shape adapter; all tracks retain the same deterministic capture and posture semantics. */
  readonly projectIntentRouter?: ProjectIntentRouter;
  readonly projectRetriever?: ProjectRetriever;
  readonly projectRetrievalLimit?: number;
  readonly projectLocalizer?: Localizer;
  readonly projectLocalizationTopK?: number;
  readonly projectPlanner?: ProjectPlanner;
  /** Optional planning-only edit adapter. Workspace deployments get the bounded model planner by default. */
  readonly projectEditor?: ProjectEditPlanner;
  /** Optional independently composed post-implementation verifier (for strong-tier/enterprise adapters). */
  readonly projectTester?: ProjectTester;
  /** Optional creative/research/media strategy inside the same canonical durable project loop. */
  readonly domainWorkflow?: Omit<DomainWorkflowConfig, "synthesis"> & {
    /** Composed external synthesis always routes through Keep's verified CapabilityHub and durable spine. */
    readonly synthesis?: Omit<CapabilityAudiobookSynthesisConfig, "hub" | "spine" | "dispatch">;
  };
  /** Shared adapters for per-run selection of any domain workflow alongside software projects. */
  readonly domainWorkflows?: Omit<DomainWorkflowConfig, "kind" | "synthesis"> & {
    readonly synthesis?: Omit<CapabilityAudiobookSynthesisConfig, "hub" | "spine" | "dispatch">;
  };
  /** Enable all per-run domain profiles using the composed governed/metered model provider. */
  readonly enableDomainWorkflows?: true;
  /** Minimum isolation tier for the built-in independent verifier. Default: process. */
  readonly projectTestRequiredTier?: IsolationTier;
  /** Measured strong-tier configuration for installed independent verification. */
  readonly projectTestIsolation?: {
    readonly capabilities: IsolationCapabilities;
    readonly microvm?: Omit<MicrovmBoundarySpec, "projectDir" | "command" | "args">;
  };
  /** A6 development-only refusal probe. Omit for the zero-config floor and every production/restricted boot. */
  readonly nativeBoundaryTransport?: PackagedNativeBoundaryOptions;
  /** A3: canonical installed-runtime path identities. Repository and workspace stay distinct. */
  readonly runtimePaths?: { readonly repository: string; readonly workspace: string };
  /** Shared-process deployment admission. Routing remains owned by the canonical gateway. */
  readonly tenantDeployment?: {
    readonly tenantId: string;
    readonly peers: readonly TenantDeploymentRoots[];
    readonly soloNonRegression: { readonly baselinePath: string; readonly current: SoloPerformanceObservation };
  };
  /** Optional shared-fleet safety lifecycle. Available identically to n=1 and enterprise; omitted stays inert. */
  readonly fleetLifecycle?: FleetLifecyclePolicy;
  /** Optional exact private OTLP destinations. Omitted leaves local n=1 observability fully functional and offline. */
  readonly privateTelemetryDestinations?: readonly (PrivateOtlpCapabilityConfig & {
    readonly purpose: string;
    readonly pseudonymizationKey: string;
    readonly maxBatchSpans?: number;
  })[];
  /** Trusted built-in local provider only. Omit -> LocalProvider (air-gap / zero-dep default). */
  readonly provider?: ModelProvider;
  /** Explicit sacrificial/testing seam for scripted providers. It carries no locality or production assurance claim. */
  readonly developmentProvider?: ModelProvider;
  /** Owner-selected inert remote/local-endpoint descriptor. It receives the normal egress/privacy/residency controls
   * but no organization release authority, and is categorically forbidden in tenant deployment. */
  readonly ownerProvider?: RemoteProviderDescriptor;
  /** Exact inert remote descriptor. Only a known side-effect-free built-in adapter is constructed after boot succeeds. */
  readonly remoteProvider?: RemoteProviderDescriptor;
  /** Exact declared use/location for remote model processing. Remote calls fail closed when absent or disallowed. */
  readonly remoteProcessing?: RemoteProcessingDeclaration;
  /** Separate bounded query/document processing purposes. Not source-document consent,
   * embedding model-role encoding, or permission to reuse another route's A4 token. */
  readonly embeddingProcessing?: EmbeddingProcessingDeclaration;
  /** Optional independently admitted semantic encoder. Never inferred from the chat
   * model. Each native command must separately consent to document embedding. */
  readonly semanticEncoder?: {
    readonly authority: "owner" | "organization";
    readonly provider: RemoteProviderDescriptor;
    readonly contract: SemanticEncoderContract;
    readonly processing: EmbeddingProcessingDeclaration;
    readonly limits: EmbeddingWork;
    readonly externalRouting?: ExternalRoutingPolicy;
    readonly release?: KeepConfig["release"];
    readonly verifiedRelease?: ReleaseBootResult;
  };
  /** Exact external aggregator privacy/routing declaration; bound into every broker permit. */
  readonly externalRouting?: ExternalRoutingPolicy;
  /** Explicit opt-in encrypted persistence for personal surrogates, cues, and preferences. */
  readonly persistentPersonalData?: { readonly subject: string };
  /** A4: mandatory for remote providers. Boot re-captures installedRoot and verifies this signed closure before the
   * provider is wired; the resulting opaque token is rechecked immediately before every restricted dispatch. */
  readonly release?: { readonly installedRoot: string; readonly verification: ReleaseClosureVerificationInput; readonly authority: AuthorityCompilerInputs; readonly trustedNowMs: () => bigint };
  /** Verifier-minted equivalent used by the installed CLI to admit boot before it creates its auxiliary memory store. */
  readonly verifiedRelease?: ReleaseBootResult;
  /**
   * Optional provider-neutral review-signature verifier. This proves the receipt under the configured root; product
   * authority separately requires deployment evidence that the root is outside builder write authority.
   */
  readonly externalReviewCorroboration?: { readonly trustRoot: ExternalReviewTrustRootV1; readonly trustedNowMs: () => number };
  /** Sovereignty manifest flags: whether each opt-in external is actually wired (default false). */
  readonly researchWired?: boolean;
  readonly embeddingsWired?: boolean;
  readonly gitRemoteWired?: boolean;
  readonly backupWired?: boolean;
  /** Environment facts for the honest sovereignty posture (back-of-the-room operator support). */
  readonly localModelAvailable?: boolean;
  readonly brainLocation?: BrainLocation;
  readonly freeTierConstrained?: boolean;
  /** A frozen held-out eval anchor to enable safe self-improvement (the external anchor). Omit → disabled. */
  readonly evalAnchor?: EvalAnchor;
  /** 18.1: outcomes needed before self-improvement activates (observing → learning). Default 30. */
  readonly anchorThreshold?: number;
  /** Durable proposal-only capability-gap scheduling; weight-training proposals require explicit opt-in. */
  readonly needScheduling?: NeedSchedulerOptions;
  /** 18.3: sessions between consolidation sleep passes. Default 5 (K4). */
  readonly consolidationCadence?: number;
  /** 18.5: the execution oracle (backed by verifyPatch) that adjudicates CEGIS skill validation. */
  readonly skillOracle?: ExecutionOracle;
  readonly skillPrograms?: SkillPrograms;
  readonly skillImportAuthorities?: readonly import("./loop/skill_distiller.js").SkillAuthority[];
  readonly skillCriticism?: { readonly builderFamily: string; readonly critic: CrossFamilyCritic };
  readonly skillCanaryNotifier?: CanaryNotifier;
  /** 18.8: opt-in rich-tier LoRA deps (registry + eval harness + spine). Absent → no weight-level adaptation. */
  readonly loraBridge?: AdapterBridgeDeps;
  /** Verifies exact payload-bound authority for consequential capability calls. */
  readonly capabilityAuthorizationVerifier?: import("./ecosystem/capability_port.js").CapabilityAuthorizationVerifier;
  /** Private-development signing crosses the same exact-authority CapabilityHub as every other external effect. */
  readonly clientSigning?: {
    readonly adapter: CapabilityAdapter;
    readonly verifyAuthorization: CapabilityAuthorizationVerifier;
    readonly authorizationFor?: (invocation: CapabilityInvocation) => CapabilityAuthorization | undefined;
    readonly verifySignedBinary: (artifact: { readonly signedBinaryBase64: string; readonly keyId: string; readonly signature: string }, input: { readonly platform: ClientSigningPlatform; readonly artifactDigest: string }) => boolean | Promise<boolean>;
  };
  /** 18.9: the stable-core held-out cases the governed anchor seeds from (improver never authored these). */
  readonly anchorCore?: readonly { id: string; input: string; expected: string }[];
  /** Maps independently verified outcomes into inert future-anchor proposals; never admits them. */
  readonly anchorCaseFromOutcome?: (signal: import("./loop/self_improvement_bus.js").OutcomeSignal) => { readonly outcome: VerifiedOutcome; readonly validatingComponent: string } | undefined;
  /** Fixed held-out cue/no-cue evaluation. Omit leaves linguistic cues disabled. */
  readonly cueAblation?: { readonly cases: readonly CueAblationCase[]; readonly maxHarmfulFlipRate: number; readonly askGateConfig?: AskGateConfig };
  /** 19: the memory store the front door captures onboarding directives into (probation tier). */
  readonly frontDoorMemory?: MemoryStore;
  /** 19: optional LLM phrasing-warmer for the front door (never gates onboarding progress). */
  readonly frontDoorBrain?: FrontDoorBrain;
  /** Optional prediction source — activates the front-door predict loop (offers on pull). */
  readonly predictionSource?: PredictionSource;
  /** 18.6: clean uses to graduate a canary skill to full trust (K1 floor). Default 3. */
  readonly canaryGraduateFloor?: number;
  /** 18.7: bounded top-k of skills offered per task (below the skill-shadowing phase transition). Default 3. */
  readonly retrievalTopK?: number;
  /** Governance ledger for meta-harness auditing (optional). */
  readonly governance?: import("./governance/decision_record.js").GovernanceLedger;
  /** Data-residency + egress policy for the governance suite. Absent → deny-by-default (air-gapped). */
  readonly residency?: ResidencyPolicy;
  /** HMAC signing key for compliance evidence packs (from the keystore in a real deploy). */
  readonly evidenceSigningKey?: Buffer;
  /** Compliance regime version string for evidence packs. */
  readonly regimeVersion?: string;
  /** OPT-IN far-tier weight training. Absent → no auto-training capability (off by default). Supplies the GPU trainer
   *  backend + sandbox canary-deploy + eval seams; the decision/permission/deploy-authorization safety logic is always real. */
  readonly autoTraining?: AutoTrainingSeams;
  /** W0: per-source webhook signing secrets (operator-supplied; never hardcoded). Absent → that source is fail-closed. */
  readonly triggerSecrets?: Partial<Record<TrackerSource, string>>;
  /** M6: OPT-IN closed self-improvement loop (off by default — the n=1 floor is never forced on). Supplies the held-out
   *  regression corpus that shadow-verifies each improvement before promotion; the recognize/plan/verify logic is always real. */
  readonly selfImprovement?: { readonly enabled: boolean; readonly corpus?: readonly RegressionCase[]; readonly safetyCorpus?: readonly RegressionCase[] };
  /** Optional outcome-gated soft-behavior adaptation. Its fixed evaluation policy grants no authority. */
  readonly outcomeAdaptation?: { readonly initial: AdaptiveBehavior; readonly policy: AdaptationPolicy };
  /** X0: the authorization port. Absent → open RBAC (RbacAuthorizer). N=1 is unaffected (owner, no login). */
  readonly authorization?: AuthorizationPort;
  /** Live canonical human-directory lookup for delegated authority. Absent supports only the immutable n=1 owner. */
  readonly delegationParentFor?: DelegationParentResolver;
  /** Authenticated principal for the configured automated solve path. Omit for the n=1 owner path. */
  readonly projectPrincipal?: Principal;
  /** X1: the multi-user identity layer. Absent → the web UI runs single-owner (N=1, per-run token = owner). */
  readonly identity?: IdentityLayer;
  /** SoD: the operators eligible to give dual-control approvals. Default: a single owner (N=1). */
  readonly operators?: readonly Identity[];
  /** SoD: distinct approvals required for security-critical actions. Default 1 (single-operator + step-up). */
  readonly sodN?: number;
  /** R1: a candidate sampler (real provider samples at temperature). Present → app.bestOfNSolver is built. */
  readonly candidateSolver?: CandidateSolver;
  /** Required for N>1: allocates one private mutable workspace per candidate. */
  readonly candidateWorkspaceFactory?: CandidateWorkspaceFactory;
  /** R1: best-of-N settings (N and verifier options). */
  readonly bestOfN?: { readonly n: number; readonly maxEdits?: number; readonly stopWhenClean?: boolean };
  /** R2: hybrid selector for the verified candidate set (absent → deterministic safety-first tie-break). */
  readonly candidateSelector?: CandidateSelector;
  /** R3: seams to generate + execute discriminating tests. Present (with candidateSolver) → app.resolveWithTests. */
  readonly testGenerator?: TestGenerator;
  readonly testExecutor?: TestExecutor;
  /** R4: resolution tiers (cheapest first) + a budget predicate + optional complexity pre-router → app.resolveCascade. */
  readonly resolutionTiers?: readonly ResolutionTier[];
  readonly cascadeBudget?: CascadeBudget;
  readonly complexityRouter?: (issue: Issue) => TaskComplexity;
  /** W3: the solve seam (Issue → human-gated PR). When present, the trigger ingress CLOSES THE LOOP:
   *  ingress → solve → review.pending + notification. Absent (default) → ingress records trigger.accepted only. */
  readonly solve?: SolveFn;
  /** W3b: the repo surface for the BUILT-IN solver. When `solve` is absent but a workspace is present, Keep composes
   *  its default Agentless solver (localize → plan → apply → validate → repair → governed PR) over this workspace —
   *  so autonomy works out of the box without the operator writing a solver. */
  readonly workspace?: Workspace;
  /** Exact immutable local Git input for the built-in solver; mutually exclusive with injected solve/workspace/repoRef. */
  readonly repositoryMaterialization?: MaterializeRepositoryRequest;
  /** Installed owner CLI: land an approved materialized proposal into its captured source repository. */
  readonly sourceLanding?: boolean;
  /** The repo the built-in solver + autonomy loop target (keys the workspace). Default ".". */
  readonly repoRef?: string;
  /** X3.1: a real git working tree. When present, the calibration loop's post-approval revert signal is sourced FROM
   *  real git history (GitRevertSignalSource) instead of a deployment seam. */
  readonly repoDir?: string;
  /** How the built-in solver runs tests for a repoRef against the patched tree. Default fails closed (sandbox runner
   *  is wired in the isolation increment). */
  readonly solverRunnerFor?: (repoRef: string, tree: FileTree) => TestRunner;
  /** W3c: when set with a disk-backed workspace, the built-in solver runs its tests via this command INSIDE the process
   *  isolation boundary (confined cwd, scrubbed env, wall-clock + CPU limits, output caps). This RETIRES the fail-closed
   *  default on the real-repo path — the solver's tests actually execute, sandboxed. */
  readonly testCommand?: { readonly command: string; readonly args: readonly string[]; readonly timeoutMs?: number; readonly cpuLimitSec?: number; readonly maxOutputBytes?: number; readonly envAllowlist?: readonly string[];
    /** true/omitted requests best effort; false permits fallback; required refuses unprotected setup. */
    readonly namespaceJail?: boolean | "required";
    readonly readOnlyPaths?: readonly string[];
    readonly allowWritePaths?: readonly string[];
    readonly allowNet?: boolean };
  /** Embedding backend info for the licensing guard (defaults to the local backend). */
  readonly embeddingInfo?: EmbeddingBackendInfo;
  /** Lock adapter. Omit -> in-process (single-node tier). */
  readonly lock?: DistributedLock;
  /** Store adapter. Omit -> filesystem (zero-dep tier). */
  readonly store?: SpineStore;
  /**
   * WIRE-BATCH A1: make the LIVE audit/witness chain fsync-DURABLE by default (the 12a durability the self-audit found
   * was built but never engaged in compose). Omit → `true` (the default FileSpineStore is fsync-durable). Set `false`
   * only for throwaway/in-memory-style runs. Ignored when a custom `store` is injected (durability is then the caller's).
   */
  readonly fsync?: boolean;
  /**
   * L4: independent witness sink for the audit chain. Omit -> honest N=1 FileWitnessSink at
   * `witnessDir`. Supply a fleet-cosigning sink for split-view resistance (SEAM).
   */
  readonly witnessSink?: WitnessSink;
  /**
   * L4: directory for the default FileWitnessSink. Point OUTSIDE the agent's write-set for real
   * independence — a same-dataDir witness gives DETECTION only (HONEST SEAM). Omit -> dataDir.
   */
  readonly witnessDir?: string;
  /**
   * Increment 12b: export the chain ROOT out of the write-set. When set, the spine publishes each head to a
   * fsync-durable DurableWitnessExport at this directory (which MUST be outside dataDir) instead of the same-dir
   * FileWitnessSink — so a third party can re-derive the root against an independently-held reference (tools/
   * witness_verify.mjs). Omit -> the detection-only default, HONESTLY reported via `witnessExport`.
   */
  readonly witnessExportDir?: string;
  /**
   * Increment 12b: when true, REFUSE to boot unless the witness root is OUT of the write-set (fail-closed on EVERY sink
   * selection — the default, a same-dir `witnessDir`, AND a custom `witnessSink` whose location cannot be established).
   * Default false: allow the detection-only single-host default but report it honestly via `witnessExport`. (Out-of-
   * write-set is necessary, not sufficient, for true independence — a separate principal/quorum is the seam.)
   */
  readonly requireIndependentWitness?: boolean;
  /**
   * Host capability report (register H-8). Omit → Keep PROBES the host at boot (memoized) and selects the strongest
   * ENFORCEMENT TIER it can back — measured, never assumed. Inject a fixed report for deterministic tests / to pin a
   * tier. `app.enforcementTier` / `app.capabilities` / `app.seamAudit` report the result honestly.
   */
  readonly capabilities?: CapabilityReport;
  /**
   * L7: the budget envelope the UNATTENDED autonomy loop runs under (daily/per-run USD caps +
   * per-call token ceiling). Omit -> a generous, operator-tightenable default (the n=1 free path is
   * never blocked; runaway loops still hard-stop). Tighten this to bound autonomous spend.
   */
  readonly autonomyBudget?: AuthorizationEnvelope;
  /** The learning-loop tick (provider-agnostic). Omit -> a no-op tick. */
  readonly learningTick?: HeartbeatTick;
  readonly heartbeatIntervalMs?: number;
  /** Connected-env reference fetchers (seams). Absent → offline-honest: the seed/last-good stands, ticks skip cleanly. */
  readonly referenceFetchers?: {
    readonly pricing?: RefreshFn<ReferencePricing[]>;
    readonly modelFamilies?: RefreshFn<ModelFamily[]>;
    readonly endpoints?: RefreshFn<ProviderEndpoint[]>;
    readonly capabilities?: RefreshFn<CapabilityDefaults>;
  };
  /** Boot secret requirements + which connectors are bound. */
  readonly secretRequirements?: readonly SecretRequirement[];
  readonly bootPolicy?: BootPolicy;
  /** Secret presence check (env/vault). Omit -> nothing present. */
  readonly hasSecret?: (name: string) => boolean;
}

export interface KeepApp {
  /** Explicit opt-in durable manual memory. Construction does not create or initialize custody. */
  readonly memoryCustody: FileMemoryCustody;
  readonly memoryRetentionPolicy?: CapturedMemoryRetentionPolicy;
  readonly spine: Spine;
  /** A4 verifier-owned release truth; present only after successful production/restricted installed boot. */
  readonly releaseGraph?: ReleaseBootResult["graph"];
  readonly releaseLedgers?: ReleaseBootResult["ledgers"];
  /** Absent unless explicitly configured; there is no implicit local-trust fallback. */
  readonly externalReviewVerifier?: ExternalTechnicalReviewVerifierPort;
  /** Present only when explicitly configured; this slice accepts cancel and can return no native authority. */
  readonly nativeBoundaryTransport?: {
    readonly probe: (input: NativeTransportDevelopmentProbeInput) => Promise<NativeBoundaryV2Response>;
    readonly developmentFixture: NativeTransportDevelopmentFixture;
  };
  /** Private-build client signing; absent unless an explicit verified signing adapter is configured. */
  readonly clientSigning?: { readonly sign: (input: { readonly platform: ClientSigningPlatform; readonly binaryBase64: string; readonly distribution: "private-development-only" }) => Promise<SignedClientBinary> };
  /**
   * L4 (witness materialization): the independent witness sink the spine publishes head checkpoints
   * to on every seal()/checkpoint(). Makes the chain tamper-evident against TRUNCATION and FORK, not
   * just internal edits. HONEST SEAM: the default sink lives in the dataDir → DETECTION, not
   * independence from a full-host compromise; a location outside the agent's write-set or a
   * fleet-cosigning sink (SEAM) is required for real split-view resistance.
   */
  readonly witnessSink: WitnessSink;
  /**
   * Increment 12b: whether the witness root is held OUT of the agent's write-set (`outOfWriteSet: true`) or in the
   * same write-set (detection-only). Reported honestly so a same-dir default is never silently sold as independence.
   * NOTE: out-of-write-set is NECESSARY but NOT SUFFICIENT for independence — the producer process still owns the file;
   * a SEPARATE PRINCIPAL / append-only receiver / quorum is the independence seam (C-4/C-5). A third party re-derives
   * the exported root with tools/witness_verify.mjs.
   */
  readonly witnessExport: ExportLocation;
  /**
   * Register H-8: the MEASURED host capability report + the strongest enforcement tier it can back (0 pure-TS floor →
   * 1 kernel isolation → 2 hardware root of trust), plus the seam audit. Keep selects its tier from evidence, not
   * assumption; `seamAudit.ok===false` means a capability THIS host has was declared a seam (scope reduction) — the
   * same check fails the suite. This is the honesty surface a governance reviewer reads: "what can this host enforce,
   * and what genuinely cannot be enforced here."
   */
  readonly capabilities: CapabilityReport;
  /** Expiring exact-operation defenses; live governed remote dispatch consults this instance. */
  readonly observedFailureDefenses: ObservedFailureDefenseRegistry;
  readonly enforcementTier: 0 | 1 | 2;
  readonly seamAudit: SeamAuditResult;
  /** Mechanism-by-mechanism runtime truth. The current single-process profile is deliberately never called isolation. */
  readonly enforcementProfile: EnforcementProfile;
  /**
   * WIRE-BATCH A1/A2 (self-audit repair): whether the LIVE audit/witness chain is fsync-durable (`spineDurable`) and
   * whether the production egress broker runs the pre-effect witness interlock (`egressWitnessed`). Both default true —
   * the mechanisms 12a built are now instantiated on the live path, not merely present in the tree. `egressProvider`
   * exposes the brokered egress so a caller/test can drive it and observe the sealed `effect.intent`.
   */
  readonly spineDurable: boolean;
  readonly egressWitnessed: boolean;
  readonly egressProvider: ModelProvider;
  /**
   * L20: the boot-time reconciliation of the local chain against the independent witness — `agreed`,
   * `authorized-restore`, `unreconciled` (first boot / no prior witness), or `diverged` (TAMPER: truncation
   * or fork detected, also staged to the spine). Single-external scope; an M-of-N quorum is a declared SEAM.
   */
  readonly witnessReconciliation: SealReconcileResult;
  /**
   * The operator's kill-switch handle for the built-in solver (Round-1 wiring). Always present:
   * composeKeep constructs it and threads it into the default solver, so a tripped switch
   * (`identityRegistry.kill(DEFAULT_SOLVER_IDENTITY_ID)`) is REACHABLE on the configured-solve path.
   * Kills are audited to the spine. HONEST SEAM: this arms the CONFIGURED-solve path; the zero-config
   * CLI path (no workspace/solve) stays inert until E-1 — the shipped-entrypoint probe pins that.
   */
  readonly identityRegistry: IdentityRegistry;
  /** Exact-repository governed merge/revert controller; absent without materialization. */
  readonly projectMerge?: GovernedLocalMerge;
  /** Multi-repository saga bound to the same durable project execution lane. */
  readonly repositoryTransactions?: ProjectRepositoryTransactions;
  readonly gateway: ModelGateway;
  /** A3: resolved path identities consumed by later installed solve/onboarding increments. */
  readonly runtimePaths?: { readonly repository: string; readonly workspace: string };
  /** Immutable evidence that this tenant's measured roots are disjoint from its declared peer roster. */
  readonly tenantDeployment?: { readonly rootAdmission: TenantDeploymentAdmission; readonly soloBaselineDigest: string };
  /** The integrated second-brain subsystem: memory, CI vault, safe intake, anticipation, authorization, team commons, portability. */
  readonly secondBrain: SecondBrainSystem;
  /** M1: the raw episodic-turn track (ground truth). */
  readonly episodicTurns: EpisodicTurnLog;
  /** M2: the context assembler — blends episodic + semantic memory into harness durableContext. */
  readonly contextAssembler: ContextAssembler;
  /** The live-adapter infra bundle (isolation, scanners, triggers, capabilities, optional git) — degrades gracefully. */
  readonly infra: KeepInfra;
  /**
   * 8.43: the ONE universal external-effect wrapper. Every externally-effectful capability call — including
   * keep_pipeline / non-default ingress paths — routes through `decide` (resolves the 8.44B capability class,
   * unknown→HOLD), and `inventory` enumerates the effectful surface the complete-mediation CI test proves has no
   * un-gated bypass. Coverage is a MEASURED property; dynamically-loaded plugin transports are the named SEAM.
   */
  readonly effectMediation: {
    readonly decide: (identity: CapabilityIdentity, opts?: { readonly confirmed?: boolean }) => EffectMediationDecision;
    readonly inventory: readonly EffectfulEntryPoint[];
  };
  /** Lifecycle/backup/integrity: backup verification, free-first off-machine options, clean uninstall, TCB verify. */
  readonly lifecycle: KeepLifecycle;
  readonly heartbeat: LearningHeartbeat;
  /** Background reference-data revalidator (pricing/model/endpoint/capability), ticked by the heartbeat. */
  readonly referenceRefresher: ReferenceRefresher;
  /** Cache-optimized, tier-adapted prompt assembly + auditable rubric vetting-prompt builder. */
  readonly promptLayer: AdaptivePromptLayer;
  readonly boot: BootCheckResult;
  /** AIBOM-style sovereignty manifest reflecting this deployment's real external touchpoints. */
  readonly manifest: SovereigntyManifest;
  /** The honest, environment-adaptive sovereignty posture (air-gapped / local-first / hybrid / hosted-dependent). */
  readonly posture: SovereigntyPosture;
  /** Project-owned outcome-gated soft behavior resolver, present only with an explicit fixed evaluation policy. */
  readonly outcomeAdaptation?: (projectId: ProjectId) => OutcomeAdaptation;
  readonly resetOutcomeAdaptation?: (projectId: ProjectId, expectedRevision: number) => boolean;
  /** Crypto-shred-bound pseudonym for project-local audit identifiers. */
  readonly projectAuditDigest?: (projectId: ProjectId, domain: string, value: string) => string;
  /** The safe self-improvement orchestrator — present only when a held-out eval anchor is provided. */
  readonly metaHarness?: MetaHarness;
  /** 18.1: the Monitor wire — every solve publishes an OutcomeSignal here; drives the self-improvement loop. */
  readonly selfImprovementBus: SelfImprovementBus;
  /** C4: the drift monitor — latches drift, gates improve-class self-improvement into safe-mode. */
  readonly driftMonitor: DriftMonitor;
  /** C1: the single trace-level safety enforcement point; scattered invariants register as contract clauses. */
  readonly referenceMonitor: ReferenceMonitor;
  /** 18.W: feeds real solve outcomes into the self-improvement loop; guards irreversible actions. */
  readonly solveOutcomeWire: SolveOutcomeWire;
  /** F2: oversight calibration loop — feed review decisions + post-approval outcomes; consumed by the router. */
  readonly calibrationWire: CalibrationWire;
  /** Present when config.repoDir is set: the real git-derived post-approval revert signal for calibration. */
  readonly revertSignal?: GitRevertSignalSource;
  /** W0: the signature-verified, deduped trigger ingress (tracker webhooks + polling → human-gated Issue). */
  readonly triggerIngress: TriggerIngress;
  /** W1: the hostile-by-default MCP gateway (deny-by-default, rug-pull pinning, untrusted results, destructive-gate). */
  readonly mcpGateway: HostileMcpGateway;
  /** W2: the notification router — routes only the dangerous few to the human; batches/suppresses the routine. */
  readonly notifications: NotificationRouter;
  /** X0: the authorization port (open RBAC by default; swap for ABAC/ReBAC/policy-engine at enterprise). */
  readonly authorization: DelegationRegistry;
  /** SoD: dual-control for security-critical actions (step-up in N=1, N-of-M in multi-op). */
  readonly separationOfDuties: SeparationOfDuties;
  /** R1: best-of-N solver (sample N candidates → deterministic verify → pessimistic select). Present when a
   *  candidate sampler is configured; the winner still flows through the human gate. */
  readonly bestOfNSolver?: (issue: Issue) => Promise<SolveResult>;
  /** R3: resolve with generated discriminating tests (behavioral clustering + fork escalation). Present when a
   *  candidate sampler + test generator + executor are all configured. Never auto-approves; floor stays R1. */
  readonly resolveWithTests?: (issue: Issue) => Promise<TestsResolveResult>;
  /** R4: budget-aware cascade — cheap tier first, escalate on provable failure/fork, defer to human on exhaustion. */
  readonly resolveCascade?: (issue: Issue) => Promise<CascadeResult>;
  /** X1: the multi-user identity layer (IdP + registry + sessions). Absent → single-owner web mode (N=1). */
  readonly identity?: IdentityLayer;
  /** 18.2: the curriculum tracker (failure-mode prioritization); improve-learners propose via the loop. */
  readonly curriculumLearner: CurriculumLearner;
  /** Durable bounded inbox for measured research/RAG/skill/evaluation/training needs. Never executes effects. */
  readonly needScheduler: BoundedNeedScheduler;
  /** 18.3: the consolidation sleep pass (artifact lifecycle: promote/prune/decay/merge). */
  readonly consolidation: Consolidation;
  /** 18.4: distills reusable skills from successful trajectories (validated by 18.5 before going live). */
  readonly skillDistiller: SkillDistiller;
  /** 18.5: the CEGIS skill validator — present when an execution oracle is supplied (validates before live). */
  readonly skillValidator?: SkillValidator;
  /** Held-out candidate versus no-skill execution gate; retains only measured improvement. */
  readonly skillEvaluator?: SkillEvaluator;
  /** 18.6: the instant-rollback canary lifecycle for validated skills (graduate/demote/notify). */
  readonly skillCanary: SkillCanary;
  /** 18.7: retrieves + composes the right skills for a task (bounded, admission-gated by canary state). */
  readonly skillRetrieval: SkillRetrieval;
  /** C3: the self-heal CEGIS loop for regressed self-authored artifacts (present when the validator exists). */
  readonly artifactSelfHeal?: ArtifactSelfHeal;
  /** 18.8: the LoRA opt-in bridge (present only when rich-tier LoRA deps are supplied; weight-level adaptation). */
  readonly adapterBridge?: AdapterProposalBridge;
  /** 18.9: governs anchor growth/rotation from verified outcomes (bounded self-modification enforced). */
  readonly governedAnchor?: GovernedAnchor;
  /** Startup-only held-out decision controlling cue deployment. */
  readonly cueAblation?: CueAblationResult;
  /** 19: the non-engineer conversational front door. */
  readonly frontDoor?: FrontDoor;
  /** One independently stateful Front Door per resolved enterprise tenant. */
  readonly frontDoorForSubject?: (subject: string) => FrontDoor;
  /** C2: dual-memory consensus — a lesson is trusted only on independent-origin consensus (anti-poison). */
  readonly memoryConsensus: MemoryConsensus;
  /** Scheduled autonomy: operator-toggled cadence bound to an authorization envelope (proposals accrue for review). */
  readonly scheduler: Scheduler;
  /** The one-time authorization ledger — the operator grants an envelope (caps + expiry) before enabling a cadence. */
  readonly budgetLedger: BudgetLedger;
  /** Unrecoverable / budget-halted / unauthorized tasks land here for human review, never silently dropped. */
  readonly deadLetterQueue: DeadLetterQueue;
  /** Multi-step saga runner: forward through steps; on partial failure, unwind completed steps LIFO (auditable). */
  readonly sagaSequencer: SagaSequencer;
  /** Guards durable checkpoints against half-applied side effects (consulted by the project loop's checkpointer). */
  readonly nonPersistableRegistry: NonPersistableRegistry;
  /** Emits OTel gen_ai.* spans for model calls over the cost model's boundary attributes (external-collector interop). */
  readonly otelEmitter: OtelGenAiEmitter;
  /** Long-horizon project runtime. Data-backed personal capabilities share its inert durable
   *  manager even without a software solve seam; supportsStrategy() reports which execution
   *  strategy is actually configured. */
  readonly autonomyLoop?: AutonomyLoop;
  /** One durable lifecycle/session authority shared by the autonomy loop and host scheduler. */
  readonly projectManager?: ProjectSessionManager;
  /** Encrypted, durable owned-export evidence corpus bound to the canonical project identity. */
  readonly audiencePerformanceFor?: (projectId: ProjectId) => AudiencePerformanceCorpus;
  /** Durable bounded background execution; absent when the configured Spine is not durable. */
  readonly projectRuntime?: ProjectRuntime;
  /** Current original-principal/consent reconstruction; absent for unsupported executors. */
  readonly taskMemoryForCommand?: (command: NativeProjectCommand, projectId: ProjectId) => TaskMemoryContext;
  /** One atomic durable capacity/reversibility/provenance/correlation lifecycle when explicitly configured. */
  readonly fleetLifecycle?: FleetAdmissionLifecycle;
  /** Optional explicit durable private export service; local observability never depends on it. */
  readonly fleetTelemetry?: DurableFleetTelemetry;
  /** The async veto queue — parked external/irreversible actions awaiting explicit human veto/approve. */
  readonly vetoQueue?: VetoQueue;
  /** The n=1 skill-registry store (in-memory default; an HTTP-backed store is an org seam). */
  readonly registryStore?: RegistryStore;
  /** Durable lifecycle, exchange, retirement and measured reuse authority for admitted skills. */
  readonly managedSkillRegistry: ManagedSkillRegistry;
  /** P-7: the multi-tenant registry — forTenant(t) gives a tenant-isolated view. registryStore is the default-tenant view. */
  readonly tenantRegistry: TenantRegistryStore;
  /** H-1: the redaction gateway (surrogate/vault/quasi-id/tier). Available for the egress path; vault is ephemeral. */
  readonly redactionGateway: RedactionGateway;
  /** H-3: the per-model harness compiler. compile(model, capabilityTier) → a CompiledHarness feeding the prompt layer. */
  readonly harnessCompiler: { readonly compile: (model: string, capabilities: CompiledHarness["rung"]) => CompiledHarness };
  /** R-EGRESS: the egress redaction interceptor. intercept(prompt, provider, policy?) → redacted outbound + rehydrate. */
  readonly egressInterceptor: { readonly intercept: (prompt: EgressPrompt, provider: { readonly isLocal: boolean }, policy?: EgressPolicy) => EgressResult };
  /** Present only after explicit opt-in; otherwise no personal-data directory is created. */
  readonly personalDataStore?: PersistentPersonalDataStore;
  /** Unified deterministic-floor-first vetting cascade for plans + patches (soundness dominates; model tiers add
   *  scrutiny above the floor, adapting to the operator's brain). */
  readonly vettingGates: VettingGates;
  /** Enterprise compliance surface: signed evidence packs, regulatory incident clocks, residency/egress enforcement. */
  readonly governanceSuite: GovernanceSuite;
  /** Governed auto-RAG corpus: ingest research sources through classify/sanitize/tokenize/ROPA, retrieve grounded chunks
   *  (the RetrievedChunk shape vetRagAnswer grades). Project-isolated. */
  readonly corpusSuite: CorpusSuite;
  /** Operator observability: hierarchical span recording (wired into the autonomy loop), failure localization
   *  (triage + confirm-by-rerun), and cost attribution per task/agent/node/lesson. */
  readonly observability: ObservabilitySuite;
  /** Human-in-the-loop learning signals: capture edit-deltas + dismissals as lessons; PR lesson badges + spec-drift. */
  readonly learningSignals: LearningSignals;
  /** M6: the closed self-improvement loop (recognize→plan→implement→verify). Present only when config.selfImprovement.enabled.
   *  runCycle composes decideTraining + the shadow gate; real training is STAGED (seam S-10), never run here. */
  readonly selfImprovement?: { readonly runCycle: (signals: TrainingSignals, candidate?: { id: string; content: string }) => SelfImprovementOutcome };
  /** Gated far-tier auto-training (decision → permission → training → deploy). Present only when config.autoTraining is
   *  supplied — off by default. Safety machinery real; GPU compute is a seam. */
  readonly autoTraining?: AutoTrainingSuite;
}

/**
 * Wire the application from config. Fails closed only on true security invariants;
 * everything optional degrades gracefully. Throws on a non-commercial default
 * embedding backend (licensing guard).
 */
/** Convert bigints to decimal strings recursively so a broker audit record (bigint `seq`) can be staged on the spine,
 *  whose canonical form is JSON (no bigint). The authoritative broker id remains the eirDigest audit id inside the
 *  record. SCOPE: only the acyclic CanonicalValue audit-record domain (no cycles/Date/Map) — NOT a general serializer. */
function jsonSafeRecord(v: unknown): Record<string, unknown> { return jsonSafe(v) as Record<string, unknown>; }
function jsonSafe(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(jsonSafe);
  if (v !== null && typeof v === "object") { const o: Record<string, unknown> = {}; for (const k of Object.keys(v as object)) o[k] = jsonSafe((v as Record<string, unknown>)[k]); return o; }
  return v;
}

export function composeKeep(config: KeepConfig): KeepApp {
  const memoryRetentionPolicy = config.memoryRetentionPolicy === undefined ? undefined : captureMemoryRetentionPolicy(config.memoryRetentionPolicy);
  // A4 production preflight is deliberately the first composition action: no store, witness, provider, probe or other
  // mutable application state exists until the installed artifact and signed authority closure admit this boot.
  if (config.remoteProvider !== undefined && (config.provider !== undefined || config.developmentProvider !== undefined || config.ownerProvider !== undefined)) throw new Error("compose: remoteProvider is mutually exclusive with other provider seams");
  if (config.ownerProvider !== undefined && (config.provider !== undefined || config.developmentProvider !== undefined)) throw new Error("compose: ownerProvider is mutually exclusive with live provider seams");
  if (config.provider !== undefined && config.developmentProvider !== undefined) throw new Error("compose: provider and developmentProvider are mutually exclusive");
  if (config.ownerProvider !== undefined && config.tenantDeployment !== undefined) throw new Error("compose: owner provider authority is forbidden in tenant deployment");
  if ((config.release !== undefined || config.verifiedRelease !== undefined) && config.remoteProvider === undefined) throw new Error("compose: production release verification may only accompany an inert remoteProvider descriptor");
  if (config.release !== undefined && config.verifiedRelease !== undefined) throw new Error("compose: release and verifiedRelease are mutually exclusive");
  if (config.nativeBoundaryTransport !== undefined && config.remoteProvider !== undefined) throw new Error("compose: development native refusal transport is forbidden in restricted/production boot");
  if (config.repositoryMaterialization !== undefined && (config.solve !== undefined || config.repoRef !== undefined || config.domainWorkflow !== undefined || (config.workspace !== undefined && config.tenantDeployment === undefined))) {
    throw new Error("compose: repositoryMaterialization is exclusive with solve, workspace, repoRef, and domainWorkflow");
  }
  if (config.sourceLanding === true && config.repositoryMaterialization === undefined) throw new Error("compose: sourceLanding requires exact repository materialization");
  const bootDescriptor = config.remoteProvider === undefined ? undefined : captureRemoteProviderDescriptor(config.remoteProvider);
  const ownerDescriptor = config.ownerProvider === undefined ? undefined : captureRemoteProviderDescriptor(config.ownerProvider);
  if (bootDescriptor !== undefined && config.release === undefined && config.verifiedRelease === undefined) throw new Error("compose: an organization remote provider descriptor requires A4 installed-release verification");
  const descriptorDigest = bootDescriptor === undefined ? undefined : remoteProviderIdentityDigest(bootDescriptor);
  const releaseBoot: ReleaseBootResult | undefined = bootDescriptor === undefined ? undefined : config.verifiedRelease ?? verifyInstalledReleaseAtBoot({ ...config.release!, providerDescriptorDigest: descriptorDigest! });
  const encoderInput = config.semanticEncoder;
  const encoderAuthority = encoderInput?.authority;
  const encoderDescriptor = encoderInput === undefined ? undefined : captureRemoteProviderDescriptor(encoderInput.provider);
  const encoderContract = encoderInput === undefined ? undefined : captureSemanticEncoderContract(encoderInput.contract);
  const encoderLimits = encoderInput === undefined ? undefined : Object.freeze({ requests: encoderInput.limits.requests, inputBytes: encoderInput.limits.inputBytes, windows: encoderInput.limits.windows });
  if (encoderLimits && !Object.values(encoderLimits).every(n => Number.isSafeInteger(n) && n >= 1)) throw new Error("compose: semantic encoder requires finite aggregate limits");
  const encoderProcessing = encoderInput === undefined ? undefined : Object.freeze({ query: Object.freeze({ ...encoderInput.processing.query }), document: Object.freeze({ ...encoderInput.processing.document }) });
  if (encoderProcessing && !Object.values(encoderProcessing).every(p => typeof p.purpose === "string" && !!p.purpose.trim() && typeof p.region === "string" && !!p.region.trim())) throw new Error("compose: explicit query/document encoder purposes and regions required");
  const encoderRouting = encoderInput?.externalRouting === undefined ? undefined : Object.freeze({ ...encoderInput.externalRouting, providers: Object.freeze([...encoderInput.externalRouting.providers]) });
  if (encoderDescriptor?.mode !== undefined && encoderDescriptor.mode !== "openai-compatible") throw new Error("compose: configured encoder protocol has no embedding transport");
  if (encoderInput?.authority === "owner") {
    if (config.tenantDeployment !== undefined || bootDescriptor !== undefined || encoderInput.release !== undefined || encoderInput.verifiedRelease !== undefined) throw new Error("compose: owner encoder cannot carry or replace organization authority");
  } else if (encoderInput !== undefined && (encoderInput.authority !== "organization" || bootDescriptor === undefined ||
      (encoderInput.release === undefined) === (encoderInput.verifiedRelease === undefined))) throw new Error("compose: organization encoder requires its own exact A4 release admission");
  const encoderRelease = encoderInput?.authority !== "organization" ? undefined : encoderInput.verifiedRelease ?? verifyInstalledReleaseAtBoot({ ...encoderInput.release!, providerDescriptorDigest: remoteProviderIdentityDigest(encoderDescriptor!) });
  const encoderIdentity = encoderDescriptor === undefined ? undefined : createHash("sha256").update(canonicalize({ schema: "keep.semantic-encoder/v1", provider: remoteProviderIdentityDigest(encoderDescriptor),
    contract: encoderContract!, authority: encoderAuthority!, verification: "declared", normalization: "cosine-v1", privacy: EMBEDDING_REPRESENTATION_VERSION, processing: encoderProcessing!, routing: encoderRouting ?? null, limits: encoderLimits! })).digest("hex");
  const externalReviewVerifier = config.externalReviewCorroboration === undefined
    ? undefined
    : new Ed25519ExternalReviewCorroborationVerifier(config.externalReviewCorroboration.trustRoot, config.externalReviewCorroboration.trustedNowMs);
  const executingRoot = (() => { let candidate = dirname(fileURLToPath(import.meta.url)); for (let depth = 0; depth < 6; depth++) { try { if (statSync(pathJoin(candidate, "package.json")).isFile()) return realpathSync(candidate); } catch { /* upward */ } const parent = dirname(candidate); if (parent === candidate) break; candidate = parent; } throw new Error("compose: cannot locate executing package root"); })();
  if (releaseBoot !== undefined && !consumeRestrictedReleaseRuntimeForComposition(releaseBoot.runtime, executingRoot, descriptorDigest!)) throw new Error("compose: verified release is stale, reused, descriptor-mismatched, or belongs to a different executing root");
  if (encoderRelease !== undefined && !consumeRestrictedReleaseRuntimeForComposition(encoderRelease.runtime, executingRoot, remoteProviderIdentityDigest(encoderDescriptor!))) throw new Error("compose: encoder release is stale, reused, descriptor-mismatched, or belongs to another executing root");
  let tenantDeployment: KeepApp["tenantDeployment"];
  if (config.tenantDeployment !== undefined) {
    if (config.runtimePaths === undefined) throw new Error("compose: tenant deployment requires explicit repository and workspace roots");
    if (config.store !== undefined || config.lock !== undefined || config.witnessSink !== undefined || config.frontDoorMemory !== undefined) throw new Error("compose: tenant deployment cannot establish the backing roots of custom state adapters");
    if (!(config.workspace instanceof LocalFsWorkspace)) throw new Error("compose: tenant deployment requires a measurable disk workspace");
    const measuredWorkspace = config.workspace.authorityRoot();
    const measuredProjectWorkspace = realpathSync(config.workspace.dir(config.repoRef ?? config.repositoryMaterialization?.repoRef ?? "."));
    if (measuredWorkspace !== realpathSync(config.runtimePaths.workspace)) throw new Error("compose: declared tenant workspace does not match the measured workspace adapter authority root");
    if (config.repositoryMaterialization !== undefined) {
      if (realpathSync(config.repositoryMaterialization.sourceDir) !== realpathSync(config.runtimePaths.repository)) throw new Error("compose: tenant repository materialization source does not match the measured repository root");
      const observedHead = execFileSync("git", ["rev-parse", "--verify", "HEAD"], {
        cwd: measuredProjectWorkspace,
        encoding: "utf8",
        env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: "/nonexistent", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_TERMINAL_PROMPT: "0", LC_ALL: "C" },
      }).trim();
      if (observedHead !== config.repositoryMaterialization.commit) throw new Error("compose: tenant workspace does not contain the exact admitted repository revision");
    }
    if (config.repoDir !== undefined && realpathSync(config.repoDir) !== realpathSync(config.runtimePaths.repository)) throw new Error("compose: declared tenant repository does not match the configured repository root");
    const baseline = new FileSoloReleaseBaselineStore(config.tenantDeployment.soloNonRegression.baselinePath).load();
    if (baseline === undefined) throw new Error("compose: tenant deployment requires a pinned n=1 baseline carrier");
    const installedSubjectDigest = releaseBoot?.artifactInventoryDigest ?? captureInstalledPackageSubjectDigest(executingRoot);
    const soloAdmission = verifySoloNonRegression(baseline, captureCanonicalSoloObservation(config.tenantDeployment.soloNonRegression.current, installedSubjectDigest));
    if (!soloAdmission.admitted) throw new Error(`compose: tenant deployment regresses the pinned n=1 contract: ${soloAdmission.reasons.join("; ")}`);
    const rootAdmission = admitTenantDeployment({
      tenantId: config.tenantDeployment.tenantId,
      dataRoot: config.dataDir,
      repositoryRoot: config.runtimePaths.repository,
      workspaceRoot: measuredWorkspace,
      ...((config.witnessExportDir ?? config.witnessDir) !== undefined && classifyExportLocation((config.witnessExportDir ?? config.witnessDir)!, config.dataDir).outOfWriteSet
        ? { witnessRoot: (config.witnessExportDir ?? config.witnessDir)! }
        : {}),
    }, config.tenantDeployment.peers);
    tenantDeployment = Object.freeze({ rootAdmission, soloBaselineDigest: soloAdmission.baselineDigest });
  }

  // --- Spine (storage + lock ports) ---
  // WIRE-BATCH A1: default the LIVE spine to fsync-durable (self-audit W2 — the interlock 12a builds is worthless if
  // the chain it seals into is not durable). `spineDurable` is MEASURED from the constructed store's own `durable`
  // report (self-audit: measure, don't declare — a mechanism-only fsync neuter must move this flag). A custom injected
  // store self-reports; a store that does not implement `durable` is reported non-durable (conservative).
  const store = config.store ?? new FileSpineStore(config.dataDir, { fsync: config.fsync !== false });
  const spineDurable = store.durable === true;
  const lock = config.lock ?? new FileSystemLock(pathJoin(config.dataDir, ".locks"));
  const registry = new SchemaRegistry();
  // L4 (witness materialization): make the audit chain actually WITNESSED on the default path.
  // Without an independent witness the sealed chain is tamper-evident only against internal edits —
  // TRUNCATION and FORK are undetectable (witness_sink.ts). Default to the honest N=1 FileWitnessSink;
  // seal()/checkpoint() now auto-publish the head to it. HONEST SEAM: `witnessDir` defaults to the
  // dataDir, so out of the box this gives DETECTION but NOT independence from a full-host compromise —
  // point `witnessDir` at a location outside the agent's write-set (or supply a fleet-cosigning
  // `witnessSink`) for real split-view resistance. That independence is a declared SEAM, not built here.
  // Increment 12b: if an export dir is configured, publish the head to a fsync-durable DurableWitnessExport OUTSIDE
  // the write-set (a third party re-derives it via tools/witness_verify.mjs); else the honest detection-only default.
  // `witnessExport` reports the truth so a same-dir witness is never silently sold as independence; and with
  // requireIndependentWitness the DurableWitnessExport constructor FAILS CLOSED on a same-write-set destination.
  // Increment 12b: when the operator REQUIRES an out-of-write-set witness, fail closed on EVERY sink selection (not
  // just the export-dir branch) — a custom sink cannot be mechanically established, and a same-dir witnessDir/default is
  // refused. This closes the "inert control on the live path" (a fail-open requireIndependentWitness) the audit flags P0.
  if (config.requireIndependentWitness === true) {
    if (config.witnessSink !== undefined) throw new WitnessExportError("requireIndependentWitness: a custom witnessSink cannot be mechanically established out-of-write-set — supply witnessExportDir (or omit the flag and attest independence yourself)");
    assertOutOfWriteSet(config.witnessExportDir ?? config.witnessDir ?? config.dataDir, config.dataDir);
  }
  // If an export dir is configured, publish each head to a fsync-durable DurableWitnessExport OUTSIDE the write-set (a
  // third party re-derives it via tools/witness_verify.mjs); else the honest detection-only default. `witnessExport`
  // reports the truth so a same-dir witness is never silently sold as independence (which requires a separate
  // principal/quorum — seam C-4/C-5; out-of-write-set is necessary, not sufficient).
  const witnessSink: WitnessSink = config.witnessSink
    ?? (config.witnessExportDir !== undefined
      ? new DurableWitnessExport(config.witnessExportDir, config.dataDir, { requireOutOfWriteSet: config.requireIndependentWitness !== false })
      : new FileWitnessSink(config.witnessDir ?? config.dataDir));
  const witnessExport: ExportLocation = config.witnessSink !== undefined
    ? { outOfWriteSet: false, reason: "a custom witnessSink was supplied; out-of-write-set status is the operator's to attest" }
    : classifyExportLocation(config.witnessExportDir ?? config.witnessDir ?? config.dataDir, config.dataDir);
  // Register H-8: PROBE the host (memoized) and select the strongest enforcement tier it can back — measured, not
  // assumed. This is the foundation of the capability-tiered ladder (Tier 0 pure-TS floor → 1 kernel isolation → 2
  // hardware root of trust); the seam audit flags any capability THIS host has that was nonetheless declared a seam.
  const capabilities: CapabilityReport = config.capabilities ?? cachedCapabilities();
  const observedFailureDefenses = new ObservedFailureDefenseRegistry();
  const enforcementProfile = resolveReferenceEnforcementProfile(capabilities, {
    deploymentIdentity: capabilities.profileDigest,
    bootIdentity: `reference-${capabilities.profileDigest.slice(0, 16)}`,
    measuredAtMs: 0n,
    expiresAtMs: 0n,
    spineDurable,
    witnessOutOfWriteSet: witnessExport.outOfWriteSet,
  });
  const seamAudit: SeamAuditResult = auditSeams(capabilities);
  const spine = new Spine(store, lock, registry, undefined, witnessSink);
  if (tenantDeployment !== undefined) {
    const admissionPayload = Object.freeze({
      event: "tenant_deployment.admitted",
      tenant: tenantDeployment.rootAdmission.tenantId,
      rosterDigest: tenantDeployment.rootAdmission.rosterDigest,
      soloBaselineDigest: tenantDeployment.soloBaselineDigest,
    });
    const priorAdmissions = spine.currentEvents().filter((event) =>
      event.type === "identity.action" && event.actor === "tenant-deployment" &&
      event.payload.event === "tenant_deployment.admitted");
    for (const prior of priorAdmissions) {
      if (canonicalize(prior.payload) !== canonicalize(admissionPayload)) throw new Error("compose: tenant deployment admission conflicts with the durable roster bound to this state root");
    }
    if (priorAdmissions.length === 0) spine.stage({ type: "identity.action", actor: "tenant-deployment", payload: admissionPayload });
  }
  // L20 (witness reconcile-on-boot): the witness is PUBLISHED (L4) but nothing checked the chain against it,
  // so a TRUNCATION or FORK between runs went undetected. Reconcile at boot (READ-ONLY — reconcileAgainst does
  // NOT advance the sink, so boot writes nothing and the witness file cannot grow per-boot). On TAMPER stage a
  // loud, auditable event; the verdict is exposed on KeepApp for a governed mode to act on. FAIL-SAFE: a
  // corrupt/partial-write witness file throws in the reader (JSON.parse) — we CATCH it and DEGRADE to an
  // `unreadable` status + audit event, never crash boot. HONEST SEAM: SINGLE-EXTERNAL witness (`witnessScope`),
  // not an M-of-N quorum — same-write-set tampering of BOTH chain and sink is undetectable (fleet cosign SEAM).
  const witnessReconciliation: SealReconcileResult = ((): SealReconcileResult => {
    try {
      // reuse the single-source reconcile (read-only: DETECT, never advance the sink — L4's seals do that);
      // FAIL-SAFE: a corrupt/partial witness file throws in the reader → DEGRADE to `unreadable`, never crash boot.
      return reconcileSealWitness(spine, witnessSink, { readOnly: true });
    } catch (e) {
      return { reconciled: false, status: "unreadable", witnessScope: "single-external", reason: `witness record unreadable (corrupt/partial write): ${e instanceof Error ? e.message : String(e)}` };
    }
  })();
  if (witnessReconciliation.status === "diverged" || witnessReconciliation.status === "unreadable") {
    spine.stage({ type: "identity.action", actor: "witness", payload: { event: witnessReconciliation.status === "diverged" ? "witness_tamper_detected" : "witness_unreadable", reason: witnessReconciliation.reason, witnessScope: witnessReconciliation.witnessScope } });
  }

  // --- Model gateway (provider from policy) ---
  let provider: ModelProvider;
  let transportClass: "local" | "remote";
  const selectedDescriptor = bootDescriptor ?? ownerDescriptor;
  if (selectedDescriptor !== undefined) {
    provider = constructCapturedRemoteProvider(selectedDescriptor, config.externalRouting); transportClass = "remote";
  } else if (config.developmentProvider !== undefined) {
    provider = config.developmentProvider; transportClass = "local"; // explicitly sacrificial; never a production claim
  } else if (config.provider !== undefined) {
    if (Object.getPrototypeOf(config.provider) !== LocalProvider.prototype) throw new Error("compose: live provider injection is not locality-attested; use developmentProvider or an inert remoteProvider descriptor");
    provider = config.provider; transportClass = "local";
  } else { provider = new LocalProvider(); transportClass = "local"; }
  const embeddingInfo: EmbeddingBackendInfo =
    config.embeddingInfo ??
    (provider instanceof LocalProvider
      ? provider.info()
      : { model: provider.name, license: "unknown", isLocal: provider.isLocal });
  // Licensing guard: a non-commercial model can't be the silent default.
  ModelGateway.assertUsableDefault(embeddingInfo);
  // Model-gateway tracing: a shared span recorder + a pricing source (reference registry) let every model call record a
  // cost-tagged span in the current run's trace. The provider is wrapped behind its port — no parallel gateway.
  const traceRecorder = new TraceRecorder(spine);
  const pricingRegistry = new ReferenceRegistry();
  // Background reference revalidation: keep the pricing/model/endpoint/capability reference data fresh. Fetchers are
  // CONNECTED-ENV SEAMS (a real pricing/model endpoint) — absent by default, so offline the honest seed/last-good stands
  // and each tick skips cleanly. The tick is driven by the always-on heartbeat below (not operator-invoked). The
  // never-fails guarantee is structural: a refresh can only UPDATE or be IGNORED (stale-if-error keeps last-good).
  const referenceRefresher = new ReferenceRefresher();
  referenceRefresher.register("pricing", pricingRegistry.pricing, config.referenceFetchers?.pricing);
  referenceRefresher.register("modelFamilies", pricingRegistry.modelFamilies, config.referenceFetchers?.modelFamilies);
  referenceRefresher.register("endpoints", pricingRegistry.endpoints, config.referenceFetchers?.endpoints);
  referenceRefresher.register("capabilities", pricingRegistry.capabilities, config.referenceFetchers?.capabilities);

  // One project identity/session foundation is created before model composition so every adaptive
  // behavior can resolve an exact encrypted project document. No project is implicitly created.
  const projectKeys = new CryptoShredKeyStore(new FileWrappedKeyPersistence({
      masterKeyPath: pathJoin(config.dataDir, "projects", "master.key"),
      wrappedKeysPath: pathJoin(config.dataDir, "projects", "wrapped-keys.json"),
    }));
  const projectRegistry = new ProjectRegistry(
    projectKeys,
    new FileProjectRecordStore(pathJoin(config.dataDir, "projects", "records.json")),
  );
  let projectManagerForCheckpointResolution: ProjectSessionManager | undefined;
  const projectCheckpoints = new FileProjectCheckpointStore(
    pathJoin(config.dataDir, "projects", "checkpoints"),
    {
      encrypt: (projectId, plaintext) => projectRegistry.namespace(projectId).encrypt(plaintext),
      decrypt: (projectId, ciphertext) => projectRegistry.namespace(projectId).decrypt(ciphertext),
      projectIdForRun: (runId) => projectManagerForCheckpointResolution?.list().find((record) => projectManagerForCheckpointResolution!.quarantine(record.id) === undefined && projectManagerForCheckpointResolution!.session(record.id).boundRunId() === runId)?.id,
    },
  );
  const engineeringStatusProjections = new FileEngineeringStatusProjectionStoreV1(pathJoin(config.dataDir, "projects", "engineering-status"));
  const projectManager = new ProjectSessionManager(
    projectRegistry,
    undefined,
    (id) => new FileProjectSessionPersistence(pathJoin(config.dataDir, "projects", "sessions", `${id}.json`)),
    projectCheckpoints,
  );
  projectManagerForCheckpointResolution = projectManager;

  // Adaptive prompt layer: assemble cache-friendly prompts (stable prefix first, volatile task last — the single biggest
  // cost lever with prompt caching) + auditable tier-adapted vetting-rubric prompts. Composed with a learned-prompt store
  // + complexity classifier.
  const promptLayer = new AdaptivePromptLayer(new PromptStore(), new ComplexityClassifier());
  const adaptationProjectContext = new AsyncLocalStorage<{ readonly projectId: ProjectId; readonly subjectId: string }>();
  const outcomeAdaptation = config.outcomeAdaptation === undefined ? undefined : (projectId: ProjectId): OutcomeAdaptation => {
    const record = projectManager.list().find((candidate) => candidate.id === projectId);
    if (record === undefined || projectManager.quarantine(projectId) !== undefined) throw new Error("project outcome adaptation is unavailable");
    const session = projectManager.session(projectId);
    const documentName = "outcome-adaptation";
    const adaptation = new OutcomeAdaptation(config.outcomeAdaptation!.initial, config.outcomeAdaptation!.policy, {
      scope: { projectId, ...(record.tenant === undefined ? {} : { tenant: record.tenant }) },
      persistence: {
        load: () => {
          const document = session.resolveDocumentVersioned(documentName);
          if (document.value === undefined) return document.revision === undefined ? undefined : { revision: document.revision };
          try { return { snapshot: JSON.parse(document.value) as unknown, revision: document.revision }; }
          catch { throw new Error("invalid persisted outcome adaptation"); }
        },
        save: (snapshot, expectedRevision) => session.putDocumentVersioned(documentName, JSON.stringify(snapshot), expectedRevision),
      },
    });
    return adaptation;
  };
  const resetOutcomeAdaptation = config.outcomeAdaptation === undefined ? undefined : (projectId: ProjectId, expectedRevision: number): boolean => {
    const record = projectManager.list().find((candidate) => candidate.id === projectId);
    if (record === undefined || projectManager.quarantine(projectId) !== undefined) throw new Error("project outcome adaptation is unavailable");
    return projectManager.session(projectId).forgetDocumentVersioned("outcome-adaptation", expectedRevision);
  };
  const priceFor = (model: string): { inputPerM: number; outputPerM: number } | undefined => {
    const p = pricingRegistry.pricingFor(model);
    return p ? { inputPerM: p.inputPerM, outputPerM: p.outputPerM } : undefined;
  };
  // Increment 10b (AMBIENT-AUTHORITY CLOSURE — the WIRE): a REMOTE provider's egress now flows through a real
  // decide→mint→broker→owner transaction (permit-gated, broker-mediated, owner-confined; no direct-transport fallback).
  // A LOCAL provider is wrapped too but bypasses brokering internally (captured isLocal). The broker audits to the spine. This makes the Incr 6→9 stack
  // load-bearing on the live model-call path and the closed-world `net` sweep (10a) meaningful.
  // WIRE-BATCH A2: construct the pre-effect witness over the DURABLE spine and pass it to the production egress broker,
  // DEFAULT-ON. This is the load-bearing step the self-audit found missing: a remote model send is now structurally
  // unreachable unless a durable witnessed intent was sealed first. `egressWitnessed` reports it on KeepApp.
  const egressWitness = new SpineDurableWitness(spine, "keep.egress.witness");
  const egressWitnessed = egressWitness !== undefined; // derived from the actual witness (not a hardcoded assertion)
  // One live privacy boundary is shared by the composed provider and the public diagnostic seam. Every invocation
  // creates a fresh ephemeral surrogate vault; audit records contain metadata only.
  const egressClassifier = new DataClassifier();
  const egressInterceptor = {
    intercept: (prompt: EgressPrompt, selectedProvider: { readonly isLocal: boolean }, policy?: EgressPolicy): EgressResult =>
      interceptEgress(prompt, selectedProvider, {
        classifier: egressClassifier,
        session: () => new RedactionGatewayCls(),
        audit: (e) => spine.stage({ type: "identity.action", actor: "egress", payload: { ...e } }),
      }, policy ?? {}),
  };
  // The broker audit record carries a bigint `seq`; the spine hashes via JSON.stringify (no bigint) — sanitize at the
  // bridge (self-audit: the FIRST real brokered egress previously failed closed on "cannot serialize a BigInt", a
  // latent bug the mechanism-only path never hit because nothing ever drove the live egress).
  const brokeredEgressProvider = buildDefaultBrokeredEgress(provider, { write: (r) => { spine.stage({ type: "identity.action", actor: "egress-broker", payload: jsonSafeRecord(r) }); } }, { transportClass, witness: egressWitness, ...(config.externalRouting === undefined ? {} : { externalRouting: config.externalRouting }), ...(ownerDescriptor === undefined ? {} : { ownerAuthority: true }), ...(releaseBoot === undefined ? {} : { releaseRuntime: releaseBoot.runtime }) });
  const egressProvider = transportClass === "remote"
    ? new GovernedRemoteProvider(
        brokeredEgressProvider,
        new ResidencyEnforcer(config.residency ?? { allowedRegions: [], egressAllowlist: [], allowedPurposes: [], airGapped: true }),
        new URL(selectedDescriptor!.baseUrl).hostname,
        config.remoteProcessing,
        (prompt, selectedProvider) => egressInterceptor.intercept(prompt, selectedProvider),
        (operation, context) => observedFailureDefenses.evaluate(operation, context),
        config.embeddingProcessing,
      )
    : brokeredEgressProvider;
  const tracedProvider = new TracingModelProvider(egressProvider, traceRecorder, priceFor);
  const gateway = new ModelGateway(tracedProvider);
  const semanticEncoder: (() => TaskMemoryEncoder) | undefined = encoderDescriptor === undefined ? undefined : (() => {
    const inner = constructCapturedRemoteProvider(encoderDescriptor, encoderRouting);
    const brokered = buildDefaultBrokeredEgress(inner, { write: r => { spine.stage({ type: "identity.action", actor: "egress-broker", payload: jsonSafeRecord(r) }); } }, {
      transportClass: "remote", witness: egressWitness,
      ...(encoderRouting === undefined ? {} : { externalRouting: encoderRouting }),
      ...(encoderRelease === undefined ? { ownerAuthority: true } : { releaseRuntime: encoderRelease.runtime }),
    });
    // Transport admission is shared, but query/document privacy and memo identity
    // belong to exactly one task-memory capability, never the runtime or tenant.
    return (): TaskMemoryEncoder => {
      const session = new RedactionGatewayCls({ reuseEntitiesWithinSession: true });
      const representationIdentity = session.representationIdentity!;
      const governed = new GovernedRemoteProvider(brokered,
        new ResidencyEnforcer(config.residency ?? { allowedRegions: [], egressAllowlist: [], allowedPurposes: [], airGapped: true }),
        new URL(encoderDescriptor.baseUrl).hostname, undefined,
        (prompt, selectedProvider) => ({ ...interceptEgress(prompt, selectedProvider, {
          classifier: egressClassifier, session: () => session,
          audit: e => spine.stage({ type: "identity.action", actor: "egress", payload: { ...e } }),
        }), representationIdentity }),
        (operation, context) => observedFailureDefenses.evaluate(operation, context), encoderProcessing, representationIdentity);
      const encoderGateway = new ModelGateway(new TracingModelProvider(governed, traceRecorder, priceFor));
      return Object.freeze({ identity: createHash("sha256").update(canonicalize({ encoder: encoderIdentity!, representationIdentity })).digest("hex"), dimension: encoderContract!.dimension, limits: encoderLimits!,
        embed: async (role, texts, controls) => {
          try {
            return await encoderGateway.embedBounded(texts.map(text => (role === "query" ? encoderContract!.queryPrefix : encoderContract!.documentPrefix) + text), {
              role, reserve: controls.reserve, ...(controls.signal === undefined ? {} : { signal: controls.signal }),
              ...(controls.assertCurrent === undefined ? {} : { assertAuthority: controls.assertCurrent }),
            });
          } catch (error) {
            // Preserve the policy boundary without leaking raw provider details or
            // misreporting an encoder refusal as loss of the human's command authority.
            // This classification does not settle any previously reserved/pending work.
            if (error instanceof EgressDeniedError) throw new TaskMemoryUnavailableError("encoder-policy");
            throw error;
          }
        },
      } satisfies TaskMemoryEncoder);
    };
  })();
  // One canonical memory system backs both the programmable second-brain surface and the non-engineer Front Door.
  // An injected Front Door store remains available for personal-mode embedding, but tenant deployments reject that
  // opaque backing above because its physical isolation cannot be measured at admission.
  const secondBrain = assembleSecondBrain({ spine, gateway,
    ...(config.frontDoorMemory === undefined ? {} : { memory: config.frontDoorMemory }),
  });
  const frontDoorMemory = secondBrain.memory;
  const resolveOutcomeAdaptation = (request: Parameters<OutcomeAdaptiveProvider["generate"]>[0]) => {
        const hinted = request.hints?.["projectId"];
        const scoped = adaptationProjectContext.getStore();
        if (scoped === undefined) return undefined;
        if (hinted !== undefined && (typeof hinted !== "string" || asProjectId(hinted) !== scoped.projectId)) throw new Error("model request adaptation binding conflicts with the active project scope");
        return { adaptation: outcomeAdaptation!(scoped.projectId), subjectId: scoped.subjectId };
      };
  const adaptationCapabilities = { current: (model: string, now: number) => {
    const view = pricingRegistry.modelFamilies.get(now);
    const family = pricingRegistry.familyFor(model, now);
    return { effortKnob: family.effortKnob, timeoutClass: family.timeoutClass, asOf: view.asOf, freshness: view.state };
  } };
  // L7 (money-enforcement): the AUTOMATED solve paths (ingress + the autonomy loop) call the model through
  // a metered provider under a granted budget envelope — durable reservations include pending calls,
  // and settlement uses reported usage. Input projection/prices remain trusted estimates. The
  // INTERACTIVE CLI path keeps using `gateway.generate` directly (unmetered — the operator is present).
  // A generous default envelope never blocks the n=1 free path ($0 local cost); an operator tightens
  // `config.autonomyBudget` to bound autonomous spend. HONEST SEAM: ONE envelope bounds the whole
  // automated-solve subsystem; per-project-run envelope granularity is filed as L7b.
  const autonomyBudgetEnvelope = config.autonomyBudget ?? defaultAutonomyEnvelope();
  // Bind the configured route to its pricing identity, not a decorated wrapper name.
  // Only the explicitly local/development configuration has a declared zero token fee.
  // Missing remote registry pricing remains unknown and cannot admit paid work.
  const meteringCost = new LenientCostModel((name) => name === tracedProvider.name
    ? selectedDescriptor ? priceFor(selectedDescriptor.model) : { inputPerM: 0, outputPerM: 0 }
    : undefined);
  const meteringBudgetLedger = new BudgetLedger(spine, meteringCost, Date.now, {
    bootstrap: { envelope: autonomyBudgetEnvelope, runId: "autonomy-subsystem" },
  });
  const autonomyVelocityBreaker = new TokenVelocityBreaker(spine, { maxRepeatedIdentical: 1000, maxUsdPerMinute: 100_000 });
  const autonomyMeteredGateway = new MeteredGateway(new ModelGateway(tracedProvider), meteringBudgetLedger, autonomyVelocityBreaker, spine);
  const baseMeteredProvider = new MeteredProvider(tracedProvider, autonomyMeteredGateway, {
    runId: "autonomy-subsystem",
    cls: "auto-research",
    tier: tracedProvider.isLocal ? "local" : "frontier",
  });
  // Adaptation wraps metering so its injected prompt and hints are included in the pre-call
  // budget projection; the metered gateway then invokes the traced provider exactly once.
  const meteredProvider = outcomeAdaptation
    ? new OutcomeAdaptiveProvider(baseMeteredProvider, resolveOutcomeAdaptation, adaptationCapabilities)
    : baseMeteredProvider;
  // Effective solver: an operator-supplied `solve` wins; else a `workspace` activates Keep's BUILT-IN Agentless solver
  // (using the composed provider — local by default, a frontier model in prod). Neither → autonomy stays opt-in/off.
  // Round-1 wiring: the operator's kill-switch handle, threaded into the built-in solver so a tripped
  // switch actually halts a solve on the configured path. default_solver.ts mints DEFAULT_SOLVER_IDENTITY_ID
  // from THIS registry per solve and gates on it; kill is monotone (a re-mint stays killed). Omitting it
  // (the prior default) left `identityLive` undefined = the switch inert on the shipped default path.
  const identityRegistry = new IdentityRegistry(spine);
  const materialization = config.repositoryMaterialization === undefined ? undefined : Object.freeze({ ...config.repositoryMaterialization });
  const materializationJournal = materialization ? spineMaterializationJournal(spine) : undefined;
  const preMaterializedTenantWorkspace = materialization !== undefined && config.tenantDeployment !== undefined && config.workspace !== undefined;
  let materializationReady: Promise<Awaited<ReturnType<typeof materializeRepository>>> | undefined;
  const ensureMaterialized = async (): Promise<void> => {
    if (!materialization || preMaterializedTenantWorkspace) return;
    if (!materializationReady) {
      const attempt = spine.withCoordinationLock("repository.materialization", () => materializeRepository(materialization, undefined, materializationJournal));
      materializationReady = attempt.catch((error) => { materializationReady = undefined; throw error; });
    }
    await materializationReady;
  };
  const materializedLocal = materialization && !preMaterializedTenantWorkspace ? new LocalFsWorkspace(materialization.workspaceBase) : undefined;
  const solverWorkspace: Workspace | undefined = config.workspace ?? (materializedLocal ? {
    files: async (repoRef, limits) => { await ensureMaterialized(); return materializedLocal.files(repoRef, limits); },
    tree: (repoRef) => materializedLocal.tree(repoRef),
    dir: (repoRef) => materializedLocal.dir(repoRef),
  } : undefined);
  const solverRepository = config.repoRef ?? materialization?.repoRef ?? ".";
  let defaultProjectTesterFor: ((check?: NonNullable<import("./solve/issue_model.js").EditPlan["goalCheck"]>) => ReturnType<typeof buildProjectTester> | undefined) | undefined;
  const solverRootIdentity = solverWorkspace ? identityRegistry.mint(DEFAULT_SOLVER_IDENTITY_ID, ["."]) : undefined;
  const vettingGates = buildVettingGates({ capability: provider instanceof LocalProvider ? "lean" : "none" });
  const builtInSolve = solverWorkspace
    ? buildDefaultSolver({
        spine, model: meteredProvider, workspace: solverWorkspace, identityRegistry, rootIdentity: solverRootIdentity!, repository: solverRepository, budgetEnvelopeId: autonomyBudgetEnvelope.id,
        governance: { vetPatch: vettingGates.vetPatch, spine },
        goalCheckRunnerFor: (repoRef, check) => {
          const tester = defaultProjectTesterFor?.(check);
          if (!tester) throw new Error("goal-check isolation is unavailable");
          return tester.feedbackRunner(repoRef);
        },
        ...(resolveSolverRunnerFor() ? { runnerFor: resolveSolverRunnerFor()! } : {}),
        ...(materialization && typeof solverWorkspace.dir === "function" ? { proposalEvidenceFor: async (repoRef: string, result: import("./solve/issue_model.js").SolveResult) => {
          if (!result.validation) throw new Error("recoverable proposal is missing validation checks");
          const git = new GitAdapter(solverWorkspace.dir!(repoRef));
          const observedBase = await git.head();
          if (observedBase !== materialization.commit) throw new Error("recoverable proposal base no longer matches the exact materialized revision");
          const diff = (await git.git(["diff", "--binary", "--no-ext-diff", materialization.commit, "--"])).stdout;
          if (diff.length === 0) throw new Error("recoverable proposal has no repository diff");
          return Object.freeze({
            baseRevision: materialization.commit, diff, checks: result.validation,
            rollback: { strategy: "git-apply-reverse" as const, patchSha256: createHash("sha256").update(diff).digest("hex") },
          });
        } } : {}),
      })
    : undefined;
  const effectiveSolve: SolveFn | undefined =
    config.solve ??
    (materialization && builtInSolve
      ? async (issue, context = {}) => {
          if (issue.repoRef !== materialization.repoRef) throw new Error("solve repoRef does not match the exact materialized repository");
          await ensureMaterialized();
          return builtInSolve(issue, context);
        }
      : builtInSolve);
  function resolveSolverRunnerFor(): ((repoRef: string, tree: FileTree) => TestRunner) | undefined {
    if (config.solverRunnerFor) return config.solverRunnerFor;
    const ws = solverWorkspace, tc = config.testCommand;
    if (ws && typeof ws.dir === "function" && tc) {
      const dirOf = (ref: string): string => ws.dir!(ref);
      const innerFor = sandboxedRunnerFor(dirOf, tc.command, tc.args, {
        ...(tc.namespaceJail !== undefined ? { namespaceJail: tc.namespaceJail } : {}),
        ...(tc.readOnlyPaths ? { readOnlyPaths: tc.readOnlyPaths } : {}),
        ...(tc.allowWritePaths ? { allowWritePaths: tc.allowWritePaths } : {}),
        ...(tc.allowNet !== undefined ? { allowNet: tc.allowNet } : {}),
        ...(tc.timeoutMs !== undefined ? { timeoutMs: tc.timeoutMs } : {}),
        ...(tc.cpuLimitSec !== undefined ? { cpuLimitSec: tc.cpuLimitSec } : {}),
        ...(tc.maxOutputBytes !== undefined ? { maxOutputBytes: tc.maxOutputBytes } : {}),
        ...(tc.envAllowlist ? { envAllowlist: tc.envAllowlist } : {}),
      });
      return (repoRef, tree) => {
        const tester = defaultProjectTesterFor?.();
        if (tester) return tester.feedbackRunner(repoRef);
        const projectDir = dirOf(repoRef);
        const requiredTier = config.projectTestRequiredTier ?? "process";
        const executor = config.projectTestIsolation
          ? selectExecutor(config.projectTestIsolation.capabilities, { spine, requiredTier, ...(config.projectTestIsolation.microvm ? { microvm: { ...config.projectTestIsolation.microvm, command: tc.command, args: tc.args } } : {}) })
          : new MinimumTierExecutor(new ProcessIsolationExecutor(spine), requiredTier, spine);
        return new IsolatedTestRunner(innerFor(repoRef), executor, projectDir);
      };
    }
    return undefined;
  }

  // --- 18.1: the SelfImprovementBus (Monitor wire). Records every solve to the shared K (spine), gates
  // learning on anchor-readiness (observing → learning), sequences learners (heal > protect > improve). ---
  // --- C4: the DriftMonitor (slow-compounding-misevolution defense) is constructed FIRST so the bus can
  // consult its safe-mode as the improve-gate; it is then registered on the bus as a protect-class learner
  // (so it observes every signal and can latch drift before improve-class learners run on that same signal). ---
  const driftMonitor = new DriftMonitor(
    config.anchorThreshold !== undefined ? { baselineSize: config.anchorThreshold } : {},
  );
  const learningErrorSink = new CollectingLearningErrorSink();
  const selfImprovementBus = new SelfImprovementBus({
    spine,
    errorSink: learningErrorSink,
    improveGate: () => !driftMonitor.inSafeMode(),
    ...(config.anchorThreshold !== undefined ? { anchorThreshold: config.anchorThreshold } : {}),
  });
  selfImprovementBus.register(driftMonitor.asLearner());
  // IMPROVE-01: real solve outcomes produce durable, bounded improvement proposals. This is a protect-class
  // observer: it is active during the evidence-gathering phase, but has no execution or authority surface.
  const needScheduler = new BoundedNeedScheduler(config.needScheduling, spine);
  selfImprovementBus.register(needScheduler);

  // --- 18.3: the Consolidation "sleep" pass — the artifact lifecycle. Registered on the bus as a protect-
  // observer (records opportunity/reuse from every signal, incl. observing) so the ledger is warm; its
  // consolidate() runs on the heartbeat cadence hook below (session-count, no daemon). ---
  const consolidation = new Consolidation(
    config.anchorThreshold !== undefined ? { cadenceSessions: config.consolidationCadence ?? 5 } : {},
  );
  selfImprovementBus.register(consolidation.asLearner());
  // Extract candidate action patterns from successful trajectories; extraction is not execution evidence.
  const skillDistiller = new SkillDistiller();
  // Sampled validation uses a nonempty default generator and caller-supplied oracle. The caller must execute
  // and check real task behavior; composition cannot verify that a supplied callback fulfills that contract.
  // --- 18.6: the SkillCanary — retention/reuse-reward/notify. A CEGIS-validated skill goes LIVE instantly as
  // an instant-rollback canary, graduates after 3 clean uses (K1), auto-demotes on any regression, notifies at
  // the right tier (K5: silent graduate / quiet-ticket rollback / page only irreversible). ---
  const skillCanary = new SkillCanary({
    ...(config.canaryGraduateFloor !== undefined ? { graduateFloor: config.canaryGraduateFloor } : {}),
    notifier: { notify: (notice) => {
      spine.stage({ type: "identity.action", actor: "skill-canary", payload: { event: "skill_canary.notice", ...notice, ts: Date.now() } });
      config.skillCanaryNotifier?.notify(notice);
    } },
  });
  selfImprovementBus.register({
    id: "skill-canary-outcome",
    loopClass: "protect",
    onOutcome: (signal) => { for (const skillId of new Set(signal.activeArtifacts ?? [])) skillCanary.recordUse(skillId, signal); },
  });
  // --- 18.7: SkillRetrieval — retrieve→filter→rerank→bounded-top-k the right skills for a task, reading REAL
  // canary (admission gate: never offer a rolled-back skill) + consolidation (utility) state via a port. ---
  const skillStateProvider: SkillStateProvider = {
    liveState: (id): SkillLiveState => skillCanary.state(id) ?? "unknown",
    utility: (id) => consolidation.record(id)?.utility ?? 0,
  };
  let skillEligible = (_skill: import("./loop/skill_distiller.js").DistilledSkill): boolean => false;
  const skillRetrieval = new SkillRetrieval({ state: skillStateProvider, eligible: (skill) => skillEligible(skill), ...(config.retrievalTopK !== undefined ? { topK: config.retrievalTopK } : {}) });
  // --- C3: the self-heal CEGIS loop for self-authored artifacts (heal-class). On a regressed skill/lesson it
  // attempts a localized, bounded CEGIS repair (reusing the validator) that must RE-CLEAR validation, re-
  // canaries on success, and rolls back + escalates otherwise. Never touches the frozen floor. Present only
  // when the CEGIS validator exists (an execution oracle was supplied). ---
  const skillValidator = config.skillOracle
    ? new SkillValidator({ oracle: config.skillOracle, generator: new PbtCounterexampleGenerator(), refiner: narrowingRefiner, safety: new EnvelopeForbiddenSinkCheck(), ...(config.skillPrograms ? { programs: config.skillPrograms } : {}) })
    : undefined;
  const skillCriticism = config.skillCriticism ? new BoundedCrossFamilyCriticism(config.skillCriticism.builderFamily, config.skillCriticism.critic) : undefined;
  let retainedSkills: import("./loop/skill_evaluator.js").RetainedSkillSink;
  const skillEvaluator = config.skillOracle ? new SkillEvaluator(config.skillOracle, skillCanary, skillCriticism, {
    add: (skill, expected) => retainedSkills.add(skill, expected),
    subject: (id) => retainedSkills.subject!(id),
    withdraw: (skill, expected) => retainedSkills.withdraw!(skill, expected),
  }) : undefined;
  const resolveCascadeFn = config.resolutionTiers && config.resolutionTiers.length > 0
    ? (issue: Issue) => resolveCascade({ tiers: config.resolutionTiers!, spine, ...(config.cascadeBudget ? { budget: config.cascadeBudget } : {}), ...(config.testGenerator ? { generator: config.testGenerator } : {}), ...(config.testExecutor ? { executor: config.testExecutor } : {}), ...(config.complexityRouter ? { complexity: config.complexityRouter } : {}) }, issue)
    : undefined;
  const requestedCandidateCount = config.bestOfN?.n ?? 3;
  if (config.candidateSolver && requestedCandidateCount > 1 && !config.candidateWorkspaceFactory) throw new Error("multi-candidate resolution requires a candidateWorkspaceFactory; distinct ids are not workspace isolation");
  const candidateSampler = config.candidateSolver && config.candidateWorkspaceFactory
    ? isolateCandidateSolver(config.candidateSolver, config.candidateWorkspaceFactory)
    : config.candidateSolver;
  const resolveWithTests = candidateSampler && config.testGenerator && config.testExecutor
    ? (issue: Issue) => selectBestOfNWithTests({ sample: candidateSampler, generator: config.testGenerator!, executor: config.testExecutor!, spine }, issue, { n: requestedCandidateCount, ...(config.bestOfN?.maxEdits !== undefined ? { maxEdits: config.bestOfN.maxEdits } : {}) })
    : undefined;

  // C3: self-heal loop — present only when the CEGIS validator exists (its execution oracle re-adjudicates repairs).
  const artifactSelfHeal = skillValidator ? new ArtifactSelfHeal({ validator: skillValidator, canary: skillCanary }) : undefined;
  // --- 18.8: LoRA opt-in bridge (rich-tier only). Connects model-adapter proposals to the LoRA tier (entry
  // gate + Colluding-LoRA composition eval + canary). Constructed ONLY when loraBridge deps are supplied —
  // absent, N=1 / free-tier / no-GPU is completely unaffected (gradient-free stays the floor). ---
  const adapterBridge = config.loraBridge ? new AdapterProposalBridge(config.loraBridge) : undefined;
  // --- 18.9: GovernedAnchor — governs growth/rotation of the frozen eval anchor from independently-verified
  // outcomes, enforcing bounded self-modification (the improver never sees/injects/edits its own held-out
  // cases). Present when a core case set is supplied; the MetaHarness consumes its snapshot(). ---
  const governedAnchor = config.anchorCore ? new GovernedAnchor(config.anchorCore) : undefined;
  if (governedAnchor && config.anchorCaseFromOutcome) selfImprovementBus.register({
    id: "governed-anchor-proposals",
    loopClass: "protect",
    onOutcome: (signal) => {
      const candidate = config.anchorCaseFromOutcome!(signal);
      if (candidate) governedAnchor.propose(candidate.outcome, candidate.validatingComponent);
    },
  });
  const cueAblation = config.cueAblation
    ? Object.freeze(evaluateCueAblation(config.cueAblation.cases, config.cueAblation.maxHarmfulFlipRate, config.cueAblation.askGateConfig))
    : undefined;
  // --- 19: the non-engineer FrontDoor. Deterministic jargon-free onboarding (always-works floor; no terminal/
  // config-file/JSON), optional LLM warming that never gates. Directives are captured to the canonical second-brain
  // memory by default and must earn trust. Local-first: doing nothing yields a working setup. ---
  // The FrontDoor's brain seam wraps the gateway (degrades to the deterministic path on any error → null).
  const frontDoorBrainCall: BrainCall = async (prompt, opts) => {
    try { const r = await gateway.generate({ prompt, maxTokens: opts.maxOutputTokens }); return r.text; }
    catch { return null; }
  };
  // Skill application: apply learned skills to front-door reasoning. The guarded top-k skills for the message's task
  // shape are injected as a delimited advisory block, and the call is tagged with the applied lesson ids (per-call cost).
  // Advisory-only — the pipeline gates still apply. Fires only when relevant skills exist; empty → the original prompt.
  const guidedFrontDoorBrainCall: BrainCall = skillGuided(frontDoorBrainCall, skillRetrieval, (p) => intentShapeByRule(p));
  const makeFrontDoor = (subject?: string): FrontDoor => {
    const memory: Pick<MemoryStore, "ingest"> = subject === undefined ? frontDoorMemory : {
      ingest: (content, opts) => frontDoorMemory.ingest(content, { ...opts, scope: "project", projectId: subject }),
    };
    // Each enterprise subject receives independent onboarding/router/driver/setup state. The backing bytes remain in
    // the one canonical MemoryStore, whose structural tenant index is injected above rather than duplicated.
    const working = buildWorkingPhase({
      spine,
      memory,
      brain: localBrainDescriptor(),
      brainCall: guidedFrontDoorBrainCall,
      onArtifacts: async (text) => {
          const chunks = chunkText(text);
          const summarize = async (chunkText_: string, prior: string) => {
            // Cache-ordered assembly: the stable summarize instruction is the durable prefix; the volatile prior+chunk are
            // the task tail — so the instruction prefix caches cleanly across chunks (stable-first / volatile-last).
            const assembled = promptLayer.assemble({
              taskShape: "summarize",
              durableContext: "You are summarizing a project's files for a non-engineer. Produce a short, plain-language summary.",
              goal: `Summary so far: ${prior}\n\nNew content to fold in:\n${chunkText_}`,
              profile: { tier: "standard", effortKnob: "none", timeoutClass: "standard" },
            });
            const r = await frontDoorBrainCall(assembled.text, { maxOutputTokens: 256 });
            return r ?? chunkText_.slice(0, 200);
          };
          const understanding = await buildProjectUnderstanding(spine, chunks, summarize, subject === undefined ? {} : { tenant: subject });
          return summarizeForHuman(understanding);
        },
    });
    const setup = buildSetupPhase({
      spine,
      brainCall: frontDoorBrainCall,
      probeLocal: (async () => ((provider instanceof LocalProvider) ? { baseURL: "http://localhost:11434/v1", model: "local" } : null)) as LocalProbe,
      env: {
        hasBrain: true,
        brainIsLocal: provider instanceof LocalProvider,
        modelIsWeak: config.localModelAvailable === true && provider instanceof LocalProvider,
        connectedAccounts: new Set<string>([
          ...((config.gitRemoteWired ?? false) ? ["git-remote"] : []),
          ...((config.researchWired ?? false) ? ["research"] : []),
        ]),
        hasApiKey: !(provider instanceof LocalProvider),
      },
    });
    return new FrontDoor(memory, {
      ...(config.frontDoorBrain ? { brain: config.frontDoorBrain } : {}), working, setup,
      ...(config.predictionSource ? { predictionSource: config.predictionSource } : {}),
      ...(config.cueAblation?.askGateConfig ? { askGateConfig: config.cueAblation.askGateConfig } : {}),
      useUncertaintyCues: cueAblation?.enabled === true,
    });
  };
  const frontDoor = makeFrontDoor();
  const tenantFrontDoors = new Map<string, FrontDoor>();
  const frontDoorForSubject = (subject: string): FrontDoor => {
    let selected = tenantFrontDoors.get(subject);
    if (selected !== undefined) return selected;
    if (tenantFrontDoors.size >= 10_000) throw new Error("front door tenant state ceiling reached");
    selected = makeFrontDoor(subject); tenantFrontDoors.set(subject, selected); return selected;
  };

  // --- C1: the trace-level ReferenceMonitor — the single un-bypassable enforcement point. Scattered safety
  // invariants (frozen-floor immutability, self-improvement-requires-triad, gated-merge-requires-approval)
  // are registered as contract clauses and checked over the event TRACE, not per-action. ---
  const referenceMonitor = new ReferenceMonitor();

  // F2: the oversight calibration wire — LEARNS to stop over-surfacing from real post-approval outcomes.
  // Loosening is human-authorized + governed + revocable; tightening (on a rising revert rate) is automatic.
  // The router consumes calibrationWire.activePolicyGates(); the post-approval revert/rework signal source is a
  // Git-revert signal is now BUILT (GitRevertSignalSource, via config.repoDir); a reopened-TICKET signal (real tracker) stays a deployment seam.
  const calibrationWire = new CalibrationWire(config.governance ? { governance: config.governance } : {});
  // Retire the revert-signal SEAM: when a real git tree is present, derive post-approval outcomes from real history.
  const revertSignal = config.repoDir ? new GitRevertSignalSource(new GitAdapter(config.repoDir), calibrationWire, spine) : undefined;

  // W2: the notification router — decides what actually reaches the human. Only the dangerous few interrupt;
  // routine auto-approved work is suppressed or batched into a digest (never per-PR). Consumes the F2 calibration
  // signal to suppress proven-clean classes. The delivery channel is a PORT (default in-memory; email/Slack/pager
  // are deployment seams). Wired to: the review flow (recordPending) + ingress dead-letters.
  const notifications = new NotificationRouter({ calibration: calibrationWire, spine, ...(config.governance ? { governance: config.governance } : {}) });
  const delegationParentFor: DelegationParentResolver = config.delegationParentFor
    ?? ((id, tenant) => id === OWNER.id && tenant === undefined ? OWNER : undefined);
  const authorization = new DelegationRegistry(config.authorization ?? new RbacAuthorizer(), spine, delegationParentFor);
  const sodOperators = new Map<string, Identity>();
  for (const op of config.operators ?? [{ id: "owner", isOperator: true, displayName: "Owner" }]) sodOperators.set(op.id, op);
  const separationOfDuties = new SeparationOfDuties(sodOperators, { n: config.sodN ?? 1 });
  separationOfDuties.onApproval((r) => spine.stage({ type: "identity.action", actor: "sod", payload: { event: "sod.approved", action: r.action, author: r.author, approvers: r.approvers, mode: r.mode, stepUpVerified: r.stepUpVerified, ts: r.ts } }));
  const bestOfNSolver = candidateSampler
    ? makeBestOfNSolver({ sample: candidateSampler, spine, ...(config.candidateSelector ? { selector: config.candidateSelector } : {}) }, { n: requestedCandidateCount, ...(config.bestOfN?.maxEdits !== undefined ? { maxEdits: config.bestOfN.maxEdits } : {}), ...(config.bestOfN?.stopWhenClean !== undefined ? { stopWhenClean: config.bestOfN.stopWhenClean } : {}) })
    : undefined;

  // W0: trigger ingress — the signature-verified, deduped front door for tracker events. Registers the real
  // Linear/Jira/GitHub normalizers (previously standalone), verifies HMAC over raw bytes, dedups on the spine,
  // and hands a normalized Issue to the solve seam (human-gated review; never an auto-merge). The HTTP listener
  // + real provider secrets + the solve handler light up at deployment (VERIFIED-SEAM); verify+dedup+route BUILT.
  const triggerRouter = new TriggerRouter();
  registerAllTrackers(triggerRouter);
  const triggerIngress = new TriggerIngress({
    verifier: new WebhookVerifier(),
    router: triggerRouter,
    spine,
    secretFor: (src) => config.triggerSecrets?.[src],
    onDeadLetter: (ticketId, reason) => notifications.notifyDeadLetter(ticketId, reason),
    ...(config.governance ? { governance: config.governance } : {}),
  });
  // W1: the hostile-by-default MCP gateway — every external MCP server sits behind it (deny-by-default allowlist,
  // tool-description pinning to kill rug pulls, untrusted-result tagging, destructive-call human-gating, and a
  // reference-monitor egress guard). The live server transport + scoped OAuth credential are deployment (SEAM).
  const mcpGateway = new HostileMcpGateway({ spine, referenceMonitor, ...(config.governance ? { governance: config.governance } : {}) });
  for (const clause of defaultKeepClauses()) referenceMonitor.register(clause);

  // --- 18.W: the SolveOutcomeWire — the adapter that feeds REAL solve outcomes into the self-improvement
  // subsystem (maps SolveToPrResult → OutcomeSignal → bus) and guards irreversible actions via the trace-
  // level reference monitor. This is what makes 18.0/18.1/C4/C1 receive real signals, not just demo traffic. ---
  const solveOutcomeWire = new SolveOutcomeWire(selfImprovementBus, referenceMonitor, undefined, learningErrorSink);

  // --- Learning heartbeat (provider-agnostic; never coupled to the provider). The per-solve learning loop
  // runs on the bus (above), NOT on this timer — so learning is never gated on the heartbeat. 18.3 registers
  // the offline consolidation "sleep" pass here (the cadence hook). ---
  const baseTick: HeartbeatTick = config.learningTick ?? (async () => { consolidation.consolidate(); });
  // Fold background reference revalidation into the always-on cadence (independent of any learningTick customization).
  const tick: HeartbeatTick = async () => { await baseTick(); await referenceRefresher.tick(); };
  const heartbeat = new LearningHeartbeat(tick, {
    intervalMs: config.heartbeatIntervalMs ?? 60_000,
  });

  // --- Boot secrets (fail-closed invariants / fail-soft optional infra) ---
  const boot = checkBootSecrets(
    config.secretRequirements ?? [],
    config.bootPolicy ?? { boundConnectors: [] },
    config.hasSecret ?? (() => false),
  );

  // --- Sovereignty (environment-adaptive posture): reflect real env, assert control-plane-local ---
  const localBrain = provider instanceof LocalProvider;
  // Single source of truth for research egress: gates both sovereignty posture AND the meta-harness triad's
  // research-currency check strength (full with egress, honestly degraded without — 18.0).
  const hasEgress = !localBrain || (config.researchWired ?? false) || (config.gitRemoteWired ?? false) || (config.backupWired ?? false);
  const posture = derivePosture({
    localModelAvailable: config.localModelAvailable ?? localBrain,
    brainLocation: localBrain ? "local" : (config.brainLocation ?? "hosted"),
    hasEgress,
    freeTierConstrained: config.freeTierConstrained ?? false,
  });
  const manifest = buildManifest({
    brain: !localBrain,
    researchVerification: config.researchWired ?? false,
    embeddings: config.embeddingsWired ?? false,
    gitRemote: config.gitRemoteWired ?? false,
    backup: config.backupWired ?? false,
    posture,
  });
  // What we actually guarantee in EVERY posture: the control plane (audit + governance + floors) is local.
  assertControlPlaneLocal(defaultControlPlaneStatus());
  // And the manifest must be honest (no undeclared hard dep; no telemetry) — holds for the free-tier operator too.
  assertSovereign(manifest);
  recordManifest(spine, manifest);

  // --- Meta-harness (self-improvement) — first-class + GOVERNED when a held-out eval anchor is provided.
  // The anchor is the deployment's frozen held-out corpus; absent → no self-improvement (safe default).
  const metaHarness = config.evalAnchor
    ? new MetaHarness({ anchor: config.evalAnchor, spine, hasEgress, ...(config.governance ? { governance: config.governance } : {}) })
    : undefined;

  // --- 18.2: the dormant improve-class learners. Registered on the bus ONLY when a proposer (MetaHarness)
  // exists — they propose through the governed loop, never mutate directly. Automatically dormant until
  // anchor-ready (observing→learning) and paused under drift safe-mode (C4). Deterministic version-minters
  // at the floor (no model needed): the mint is a content-addressed bump so proposals are distinct + auditable.
  // The CurriculumLearner (protect-class observer) registers regardless — it just tracks failure modes. ---
  const curriculumLearner = new CurriculumLearner();
  selfImprovementBus.register(curriculumLearner);
  if (metaHarness) {
    const bump = (v: string, evidence: readonly string[]): string => `${v}+${hashShort(evidence.join("|"))}`;
    selfImprovementBus.register(new PromptLearner(metaHarness, { currentVersion: (shape) => `prompt@${shape}`, mint: bump }));
    selfImprovementBus.register(new MemoryLearner(metaHarness, { currentVersion: () => "memory@live", mint: bump }));
  }

  // --- C2: the dual-memory consensus layer. A lesson is only trusted for retrieval once it reaches consensus
  // from INDEPENDENT provenance origins (not a raw count — that's defeatable by flooding); contradictions of
  // confirmed memory are quarantined as lesson-memory anomalies. Guards the MemoryLearner's proposals. ---
  const memoryConsensus = new MemoryConsensus();

  // ── Scheduled autonomy (7c) ── operator-toggled cadence under a one-time authorization envelope. EU AI Act Art.14
  // (human oversight, enforceable 2026-08-02) is satisfied natively: proposals accrue for review, never auto-merged;
  // budget breaches HALT the whole tick (enforcement); unrecoverable tasks dead-letter for a human; all events audited.
  const schedulerCostModel = new CostModel();
  const budgetLedger = new BudgetLedger(spine, schedulerCostModel);
  const deadLetterQueue = new DeadLetterQueue(spine);
  const scheduler = new Scheduler({ spine, ledger: budgetLedger, dlq: deadLetterQueue });
  // Saga orchestration table-stakes (7d): multi-step compensation, the non-persistable-region guard (wired into the
  // project loop's checkpointer, above), and OTel gen_ai span emission for external collectors.
  const nonPersistableRegistry = new NonPersistableRegistry(spine);
  // Long-horizon project loop: reuses the app's solve seam for software implementation when present and threads the
  // non-persistable registry so checkpoints are never taken mid-side-effect. Persistent project-scoped capabilities
  // share the same inert manager; softwareStrategyAvailable prevents that substrate from inventing solve authority.
  // Operator observability: a span recorder wired into the autonomy loop (per-stage spans → failure localization +
  // cost attribution), plus triage/confirm-by-rerun and cost rollup over real runs.
  const observability = buildObservabilitySuite(spine, traceRecorder);
  // Human-in-the-loop learning signals: human corrections (produced vs shipped) + finding dismissals become generalized
  // lessons in memory; PR-time lesson badges + objective spec-drift detection. Closes the human-correction → lesson loop.
  const learningSignals = buildLearningSignals(spine, gateway);
  // Unified vetting cascade: the deterministic consequence/patch floors are always-on (identical for every operator);
  // the model tiers above adapt to the brain (none → floor-only at N=1). Soundness dominates — a sound floor fail is final.
  // Govern the built-in solver's output: route its PR proposal through the composed cascade (vetPatch) + the
  // consequence-primary merge authority, so runProject yields a governed DECISION (autonomous-merge / human-merge /
  // abandon-retry / block), not a raw patch. Escalate-human is consumed as unverified (consequence gate decides), never
  // a direct interrupt — a heuristic concern on a reversible change resolves autonomously.
  const governedSolve: SolveFn | undefined = effectiveSolve
    ? config.solve
      ? withGovernance(effectiveSolve, { vetPatch: vettingGates.vetPatch, spine })
      : effectiveSolve
    : undefined;
  const scopedNeedView = config.projectPrincipal?.tenant === undefined
    ? undefined
    : needScheduler.forPrincipal(config.projectPrincipal, authorization);
  if (config.projectPrincipal?.tenant !== undefined && scopedNeedView === undefined) {
    throw new Error("compose: projectPrincipal cannot bind the configured solve path to its tenant");
  }
  const projectOutcomeWire = scopedNeedView === undefined
    ? solveOutcomeWire
    : new SolveOutcomeWire(selfImprovementBus, referenceMonitor, scopedNeedView.outcomeBinding, learningErrorSink);
  const monitoredSolve: SolveFn | undefined = governedSolve
    ? projectOutcomeWire.wrapSolve(governedSolve, { taskShape: "project" })
    : undefined;
  const observedSolve: SolveFn | undefined = monitoredSolve === undefined ? undefined : async (issue, context) => {
    const hinted = issue.hints?.["projectId"];
    let result;
    if (hinted === undefined) result = await monitoredSolve(issue, context);
    else {
    if (typeof hinted !== "string") throw new Error("solve adaptation project binding is invalid");
    const projectId = asProjectId(hinted);
    const project = projectManager.list().find((record) => record.id === projectId);
    if (project === undefined || projectManager.quarantine(projectId) !== undefined || (config.projectPrincipal?.tenant !== undefined && project.tenant !== config.projectPrincipal.tenant)) throw new Error("solve adaptation project binding is unauthorized");
    const active = adaptationProjectContext.getStore();
    if (active !== undefined) {
      if (active.projectId !== projectId) throw new Error("solve adaptation project binding conflicts with the active project scope");
      result = await monitoredSolve(issue, context);
    } else {
      result = await adaptationProjectContext.run({ projectId, subjectId: issue.id }, () => monitoredSolve(issue, context));
    }
    }
    skillDistiller.observeSolve(result.solveResult, issue);
    return result;
  };
  // One actual configured solve path now feeds governance, outcome learning, review intake, and project autonomy.
  if (observedSolve) triggerIngress.setHandler(makeClosedLoopHandler({ spine, notifications }, observedSolve));
  // ONE veto queue, shared by the autonomy loop (which enqueues a vetoed external goal) and the gateway (which
  // exposes the digest + approve/veto). `run` fires ONLY on explicit approve — it records the authorization to the
  // spine (auditable); re-executing an approved external goal is a follow-on increment.
  // P-7: the registry is now per-tenant isolated. n=1 uses the DEFAULT tenant view (behavior unchanged); a multi-tenant
  // deployment calls tenantRegistry.forTenant(t) so one tenant's skills never reach another's.
  const tenantRegistry = new TenantRegistryStore();
  // H-1: the redaction gateway — surrogate + ephemeral vault + quasi-id guard + honest tier label. Zero-config n=1;
  // policy-tunable thresholds for an org. The audit sink (spine) receives METADATA only — the vault never leaves it.
  const redactionGateway = new RedactionGateway({}, { audit: (e) => spine.stage({ type: "identity.action", actor: "redaction", payload: { ...e } }) });
  const personalDataStore = config.persistentPersonalData
    ? (() => {
        const root = pathJoin(config.dataDir, "personal-data");
        const keys = new CryptoShredKeyStore(new FileWrappedKeyPersistence({
          masterKeyPath: pathJoin(root, "master.key"),
          wrappedKeysPath: pathJoin(root, "wrapped-keys.json"),
        }));
        keys.onErasure((subject, phase) => spine.stage({
          type: "identity.action",
          actor: "personal-data",
          payload: { event: "key_destruction", subject, phase },
        }));
        return new PersistentPersonalDataStore({ enabled: true, path: pathJoin(root, "store.json"), subject: config.persistentPersonalData.subject, keys });
      })()
    : undefined;
  // H-3: the per-model harness compiler — known model → tuned, unknown → safe NL default, capability tier caps the rung.
  // Composes the AdaptivePromptLayer (supplies the ModelProfile it consumes). Zero-config n=1; per-model tuning for an org.
  const harnessCompiler = { compile: compileHarness };
  const registryStore = tenantRegistry.forTenant();
  const managedSkillRegistry = new ManagedSkillRegistry({
    store: registryStore,
    persistence: new FileSkillRegistryPersistence(pathJoin(config.dataDir, "skill-registry", "default.json")),
    allowedImportAuthorities: config.skillImportAuthorities ?? [],
    programs: config.skillPrograms ?? {},
    gateVerifiesPrograms: true,
    gate: async (skill) => {
      if (!skillValidator) return { ok: false, verdict: "validator-unavailable", reason: "skill validator is not configured" };
      const result = skillValidator.validate(skill);
      if (result.verdict !== "validated") return { ok: false, verdict: result.verdict, reason: result.reason };
      return { ok: true, verdict: result.verdict, checkedSkill: result.skill };
    },
    onAdmit: (skill) => { skillRetrieval.add(skill); skillCanary.goLive(skill.id, { revision: hashSkill(skill) }); },
  });
  skillEligible = (skill) => managedSkillRegistry.isEligible(skill);
  for (const pkg of managedSkillRegistry.activePackages()) { skillCanary.restoreLive(pkg.skill.id, pkg.contentHash); skillRetrieval.add(pkg.skill); }
  retainedSkills = {
    subject: (id) => managedSkillRegistry.subjectToken(id),
    add: (skill, expected) => {
      if (expected !== undefined && expected !== managedSkillRegistry.subjectToken(skill.id)) return { status: "changed", skill };
      const tracked = managedSkillRegistry.trackValidated(skill, "local-solve");
      if (tracked.active || tracked.mergedInto) skillRetrieval.add(tracked.pkg.skill);
      if (!tracked.active) skillCanary.forceRollback(skill.id, tracked.mergedInto ? `merged into equivalent ${tracked.mergedInto}` : "previously retired lifecycle");
      return { status: tracked.mergedInto ? "merged" : tracked.active ? "retained" : "retired", skill: tracked.pkg.skill };
    },
    withdraw: (skill, expected) => {
      if (expected !== undefined && expected !== managedSkillRegistry.subjectToken(skill.id)) return false;
      return managedSkillRegistry.withdrawExact(skill);
    },
  };
  selfImprovementBus.register({ id: "managed-skill-registry", loopClass: "protect", onOutcome: (signal) => {
    managedSkillRegistry.recordOutcome(signal);
    for (const id of managedSkillRegistry.retireUnused(signal.timestamp)) skillCanary.forceRollback(id, "unused skill retired");
  } });
  const vetoQueue = new VetoQueue({ spine, run: (action) => { spine.stage({ type: "identity.action", actor: "veto-queue", payload: { event: "approved_run", id: action.id, description: action.description } }); } });
  if (config.solve && config.projectEditor) throw new Error("compose: projectEditor requires the built-in canonical solver; custom solve seams cannot self-attest project edit consumption");
  const capabilityAuthorizationVerifier: CapabilityAuthorizationVerifier = (authorization) => {
    if (config.clientSigning?.adapter.descriptor.id === authorization.capabilityId) return config.clientSigning.verifyAuthorization(authorization);
    return config.capabilityAuthorizationVerifier?.(authorization) === true;
  };
  const infra = composeInfra({ spine, ...(config.dataDir !== undefined ? { repoDir: config.dataDir } : {}), capabilityAuthorizationVerifier });
  if (config.clientSigning) infra.capabilities.register(config.clientSigning.adapter);
  const clientSigning = config.clientSigning ? { sign: (input: { readonly platform: ClientSigningPlatform; readonly binaryBase64: string; readonly distribution: "private-development-only" }) => signClientBinary({ hub: infra.capabilities, capabilityId: config.clientSigning!.adapter.descriptor.id, verifyAuthorization: config.clientSigning!.verifyAuthorization, receipts: new FileClientSigningReceiptStore(pathJoin(config.dataDir, "client-signing", "receipts")), verifySignedBinary: config.clientSigning!.verifySignedBinary, ...(config.clientSigning!.authorizationFor ? { authorizationFor: config.clientSigning!.authorizationFor } : {}) }, input) } : undefined;
  if ([config.domainWorkflow !== undefined, config.domainWorkflows !== undefined, config.enableDomainWorkflows === true].filter(Boolean).length > 1) {
    throw new Error("compose: domainWorkflow, domainWorkflows, and enableDomainWorkflows are mutually exclusive");
  }
  if (config.domainWorkflow && config.projectEditor) throw new Error("compose: domainWorkflow and projectEditor are mutually exclusive production strategies");
  if (config.domainWorkflow && (config.projectTester || config.projectTestRequiredTier || config.projectTestIsolation)) throw new Error("compose: domainWorkflow cannot silently discard software project-test configuration");
  const projectEditor = config.projectEditor ?? (!config.solve && solverWorkspace && !config.domainWorkflow ? buildModelProjectEditPlanner(meteredProvider, solverWorkspace, solverRepository,
    { prepareGoalCheck: config.testCommand !== undefined && typeof solverWorkspace.dir === "function" && config.projectTester === undefined }) : undefined);
  if (config.projectTester && !solverWorkspace) throw new Error("compose: projectTester requires a canonical workspace for content-bound source evidence");
  const projectTester = config.domainWorkflow ? undefined : config.projectTester ?? (defaultProjectTesterFor = (check?: NonNullable<import("./solve/issue_model.js").EditPlan["goalCheck"]>) => {
    const workspace = solverWorkspace;
    const configuredTest = config.testCommand;
    const test = check === undefined || configuredTest === undefined ? configuredTest : {
      ...configuredTest, command: process.execPath,
      args: ["--input-type=module", "-e", `import test from 'node:test'; import assert from 'node:assert/strict';\ntest('requested outcome', async () => {\n${check.body}\n});\n`],
      envAllowlist: [],
    };
    if (!workspace || typeof workspace.dir !== "function" || !test) return undefined;
    const requiredTier = config.projectTestRequiredTier ?? "process";
    const executor = config.projectTestIsolation
      ? selectExecutor(config.projectTestIsolation.capabilities, {
          spine, requiredTier,
          ...(config.projectTestIsolation.microvm ? { microvm: { ...config.projectTestIsolation.microvm, command: test.command, args: test.args } } : {}),
        })
      : new MinimumTierExecutor(new ProcessIsolationExecutor(spine), requiredTier, spine);
    const selectedTier = executor.tier;
    let disposable: { repoRef: string; root: string; dir: string; workspace: LocalFsWorkspace } | undefined;
    const recreateDisposable = (repoRef: string) => {
      if (disposable) rmSync(disposable.root, { recursive: true, force: true });
      const root = mkdtempSync(pathJoin(tmpdir(), "keep-project-test-copy-"));
      const dir = pathJoin(root, "project");
      cpSync(workspace.dir!(repoRef), dir, { recursive: true, dereference: false, verbatimSymlinks: true, preserveTimestamps: true,
        filter: (source) => source === workspace.dir!(repoRef) || pathBasename(source) !== ".git" });
      disposable = { repoRef, root, dir, workspace: new LocalFsWorkspace(root) };
      return disposable;
    };
    const currentDisposable = (repoRef: string) => {
      if (!disposable || disposable.repoRef !== repoRef) throw new Error("disposable project-test source was not prepared for this repository");
      return disposable;
    };
    return buildProjectTester({
      snapshotFiles: (repoRef) => workspace.files(repoRef),
      canonicalProjectDirFor: (repoRef) => workspace.dir!(repoRef),
      executionProjectDirFor: (repoRef) => recreateDisposable(repoRef).dir,
      executionSnapshotFiles: (repoRef) => currentDisposable(repoRef).workspace.files("project"),
      disposeExecution: (repoRef) => {
        if (!disposable) return;
        const prepared = currentDisposable(repoRef);
        rmSync(prepared.root, { recursive: true, force: true });
        disposable = undefined;
      },
      selectedTier, requiredTier,
      command: test.command, args: test.args,
      ...(selectedTier === "microvm" && config.projectTestIsolation?.microvm
        ? { expectedMicrovmGuestExecutionRequestSha256: microvmGuestExecutionRequestDigest({ projectDir: ".", ...config.projectTestIsolation.microvm, command: test.command, args: test.args }) }
        : {}),
      runnerFor: (repoRef) => {
        const projectDir = currentDisposable(repoRef).dir;
        return new IsolatedTestRunner(
        new SandboxedCommandRunner({ command: test.command, args: test.args, projectDir,
          ...(test.namespaceJail !== undefined ? { namespaceJail: test.namespaceJail } : {}),
          ...(test.readOnlyPaths ? { readOnlyPaths: test.readOnlyPaths } : {}),
          ...(test.allowWritePaths ? { allowWritePaths: test.allowWritePaths } : {}),
          ...(test.allowNet !== undefined ? { allowNet: test.allowNet } : {}),
          ...(test.timeoutMs !== undefined ? { timeoutMs: test.timeoutMs } : {}),
          ...(test.cpuLimitSec !== undefined ? { cpuLimitSec: test.cpuLimitSec } : {}),
          ...(test.maxOutputBytes !== undefined ? { maxOutputBytes: test.maxOutputBytes } : {}),
          ...(test.envAllowlist ? { envAllowlist: test.envAllowlist } : {}) }),
        executor, projectDir,
      ); },
    });
  })();
  let fleetLifecycleForEffects: FleetAdmissionLifecycle | undefined;
  const fleetCapabilityDispatch = config.fleetLifecycle === undefined ? undefined : async (invocation: CapabilityInvocation, context: {
    readonly actor: string; readonly tenant?: string; readonly authorityId: string; readonly retrieval: string; readonly specification: string;
  }): Promise<CapabilityResult> => {
    const lifecycle = fleetLifecycleForEffects;
    if (lifecycle === undefined) return { ok: false, held: true, error: "fleet effect lifecycle is not ready" };
    if (tenantDeployment !== undefined && context.tenant === undefined) return { ok: false, held: true, error: "enterprise fleet effect authorization requires an exact tenant" };
    const tenant = context.tenant ?? "keep.n1.default";
    const descriptor = infra.capabilities.describe(invocation.capabilityId, context.tenant);
    if (descriptor?.fleet === undefined) return { ok: false, held: true, error: "fleet capability lacks an admitted server-owned resource profile" };
    const mediation = decideEffectMediation(invocation.operation, { confirmed: true });
    if (mediation.route !== "allow") return { ok: false, held: true, error: mediation.reason };
    const profile = descriptor.fleet;
    const target = profile.targetArgument !== undefined && Object.hasOwn(invocation.args, profile.targetArgument) ? invocation.args[profile.targetArgument] : invocation.args;
    const resource = `domain:${profile.resourceDomain}:target:${createHash("sha256").update(canonicalize(target)).digest("hex")}`;
    const input = createHash("sha256").update(canonicalize(invocation.args)).digest("hex");
    const effectDigest = capabilityInvocationDigest(invocation, descriptor, context.tenant);
    const operationId = `effect-${createHash("sha256").update(context.authorityId).update("\0").update(effectDigest).digest("hex").slice(0, 32)}`;
    let admitted;
    try {
      admitted = await lifecycle.admit({ operationId, tenant, agent: context.actor, amount: profile.admissionUnits,
        gateAutoProceed: true, writeSet: [resource], inverseDependsOn: [resource], externalSink: mediation.effect === "external",
        provenance: [{ agent: context.actor, taint: "trusted", source: `authority:${context.authorityId.slice(0, 96)}` }], effectDigest,
        basis: { model: gateway.providerName, input, retrieval: context.retrieval, tool: mediation.id,
          policy: lifecycle.policyIdentity(), operator: context.actor, infrastructure: capabilities.profileDigest,
          specification: context.specification } });
    } catch { return { ok: false, held: true, error: "fleet admission indeterminate" }; }
    if (!admitted.proceed) return { ok: false, held: true, error: `fleet admission held: ${admitted.reasons.join(",")}` };
    let result: CapabilityResult;
    try {
      result = await infra.capabilities.invoke(invocation, { requireVerified: true, confirm: true, ...(context.tenant === undefined ? {} : { tenant: context.tenant }), fleetPermit: admitted.handle });
    } catch { return { ok: false, held: false, output: { indeterminate: true }, error: "fleet capability rejected; outcome unknown, reconciliation required" }; }
    if (result.ok !== true && result.held !== true) return {
      ok: false, held: false, output: { indeterminate: true }, error: `fleet effect outcome unknown; reconciliation required: ${result.error ?? "adapter returned failure"}`,
    };
    try {
      const settled = result.ok ? await lifecycle.commit(admitted.handle) : await lifecycle.release(admitted.handle);
      if (!settled) return { ok: false, held: false, output: { indeterminate: true }, error: "fleet effect settlement indeterminate" };
    } catch { return { ok: false, held: false, output: { indeterminate: true }, error: "fleet effect settlement indeterminate" }; }
    return result;
  };
  const fleetSynthesisDispatch = fleetCapabilityDispatch === undefined ? undefined : async (invocation: CapabilityInvocation, authorization: AudiobookSynthesisAuthorization): Promise<CapabilityResult> => await fleetCapabilityDispatch(invocation, {
    actor: authorization.actor, ...(authorization.tenant === undefined ? {} : { tenant: authorization.tenant }), authorityId: authorization.id,
    retrieval: authorization.requestSha256, specification: "keep.audiobook-synthesis/v1",
  });
  const composedDomainWorkflow: DomainWorkflowConfig | undefined = config.domainWorkflow === undefined ? undefined : {
    kind: config.domainWorkflow.kind, worker: config.domainWorkflow.worker,
    ...(config.domainWorkflow.workerTimeoutMs === undefined ? {} : { workerTimeoutMs: config.domainWorkflow.workerTimeoutMs }),
    ...(config.domainWorkflow.synthesisTimeoutMs === undefined ? {} : { synthesisTimeoutMs: config.domainWorkflow.synthesisTimeoutMs }),
    ...(config.domainWorkflow.synthesis === undefined ? {} : { synthesis: buildCapabilityAudiobookSynthesisPort({ ...config.domainWorkflow.synthesis, hub: infra.capabilities, spine, ...(fleetSynthesisDispatch === undefined ? {} : { dispatch: fleetSynthesisDispatch }) }) }),
  };
  const composedDomainWorkflows: Omit<DomainWorkflowConfig, "kind"> | undefined = config.domainWorkflows !== undefined ? {
      worker: config.domainWorkflows.worker,
      ...(config.domainWorkflows.workerTimeoutMs === undefined ? {} : { workerTimeoutMs: config.domainWorkflows.workerTimeoutMs }),
      ...(config.domainWorkflows.synthesisTimeoutMs === undefined ? {} : { synthesisTimeoutMs: config.domainWorkflows.synthesisTimeoutMs }),
      ...(config.domainWorkflows.synthesis === undefined ? {} : { synthesis: buildCapabilityAudiobookSynthesisPort({ ...config.domainWorkflows.synthesis, hub: infra.capabilities, spine, ...(fleetSynthesisDispatch === undefined ? {} : { dispatch: fleetSynthesisDispatch }) }) }),
    } : config.enableDomainWorkflows ? { worker: buildModelDomainStageWorker(meteredProvider) } : undefined;
  const audiencePerformanceFor = projectManager === undefined ? undefined : (projectId: ProjectId): AudiencePerformanceCorpus => {
    const record = projectManager.list().find((candidate) => candidate.id === projectId);
    if (record === undefined || projectManager.quarantine(projectId) !== undefined) throw new Error("project audience corpus is unavailable");
    const session = projectManager.session(projectId);
    const documentName = AUDIENCE_PERFORMANCE_DOCUMENT;
    const ingestion = new IngestionPipeline({ ns: projectRegistry.namespace(projectId) });
    const context = {
      projectId,
      ...(record.tenant === undefined ? {} : { tenant: record.tenant }),
      ingestion,
      guard: (expectedDocumentRevision: number | undefined) => {
        const current = projectManager.list().find((candidate) => candidate.id === projectId);
        if (current === undefined || projectManager.quarantine(projectId) !== undefined) throw new Error("project audience corpus is unavailable");
        const observed = session.resolveDocumentVersioned(documentName).revision;
        if (observed !== expectedDocumentRevision) throw new ProjectSessionConflictError(`project document conflict: expected ${expectedDocumentRevision}, found ${observed}`);
      },
    };
    const corpus = new AudiencePerformanceCorpus(context, {
      load: () => {
        const document = session.resolveDocumentVersioned(documentName);
        if (document.value === undefined) return { snapshot: undefined, revision: document.revision };
        try { return { snapshot: JSON.parse(document.value) as unknown, revision: document.revision }; }
        catch { throw new Error("invalid persisted audience-performance corpus"); }
      },
      save: (snapshot, expectedRevision) => session.putDocumentVersioned(documentName, JSON.stringify(snapshot), expectedRevision),
    }, Date.now, config.audienceEvidenceFloor ?? 3);
    return corpus;
  };
  // A held native goal can inspect its configured source without cloning a repo,
  // constructing a runner, or feeding an unexecuted proposal into learning.
  // Custom phase ports never acquire this authority merely by claiming to be native.
  const preparationSource = materialization !== undefined && config.solve === undefined && config.projectEditor === undefined
    && config.projectIntentRouter === undefined && config.projectPlanner === undefined && config.projectLocalizer === undefined
    && config.projectRetriever === undefined && config.projectResearch === undefined
    ? new LocalFsWorkspace(realpathSync(materialization.sourceDir)) : undefined;
  const preparationWorkspace: Workspace | undefined = preparationSource === undefined ? undefined : {
    files: (repoRef, limits) => {
      if (repoRef !== solverRepository) throw new Error("preparation repository is outside the configured source");
      return preparationSource.files(".", limits);
    },
    tree: () => { throw new Error("native preparation has no live write tree"); },
  };
  const softwarePreparation = preparationWorkspace === undefined ? undefined : {
    binding: createHash("sha256").update(canonicalize({ version: "keep.native-preparation/v1",
      source: preparationSource!.authorityRoot(), repository: solverRepository, materialization,
      provider: descriptorDigest ?? (ownerDescriptor ? remoteProviderIdentityDigest(ownerDescriptor) : randomUUID()),
    })).digest("hex"),
    workspace: preparationWorkspace,
    editor: buildModelProjectEditPlanner(meteredProvider, preparationWorkspace, solverRepository),
    solve: buildDefaultSolver({ spine, model: meteredProvider, workspace: preparationWorkspace,
      identityRegistry, rootIdentity: solverRootIdentity!, repository: solverRepository, budgetEnvelopeId: autonomyBudgetEnvelope.id }),
  };
  // Only the installed, command-bound native path owns this operation. Opaque custom
  // solve/test ports and generic approval never acquire it. The first consumer is
  // the captured command. Its live actor fence is independent of optional memory;
  // selected memory retains its additional source/consent checks.
  const operationWorkspaceRoot = materialization === undefined ? undefined : realpathSync(materialization.workspaceBase);
  const softwareOperation: import("./autonomy/autonomy_loop.js").AutonomyLoopConfig["softwareOperation"] = softwarePreparation !== undefined && projectTester !== undefined
    && config.projectTester === undefined && config.testCommand !== undefined && config.workspace === undefined
    ? {
      binding: createHash("sha256").update(canonicalize({ version: "keep.native-repository-operation/v1",
        preparation: softwarePreparation.binding, workspace: operationWorkspaceRoot,
        test: config.testCommand, runtimePaths: config.runtimePaths ?? null,
      })).digest("hex"),
      authorize: (runId: string, projectId: ProjectId | undefined, goal: string): boolean => {
        if (projectId === undefined || projectRuntime === undefined) return false;
        try {
          if (realpathSync(materialization!.workspaceBase) !== operationWorkspaceRoot
            || realpathSync(materialization!.sourceDir) !== preparationSource!.authorityRoot()) return false;
          const command = projectRuntime.commandForJob(runId, projectId);
          if (command.goal !== goal || command.domainWorkflowKind !== undefined) return false;
          restoreCommandPrincipal(command, projectId);
          return true;
        } catch { return false; }
      },
    } : undefined;
  const autonomyLoop = projectManager !== undefined && projectCheckpoints !== undefined
    ? buildAutonomyLoop({ spine, ...(softwareOperation === undefined ? {} : { softwareOperation }), ...(softwarePreparation === undefined ? {} : { softwarePreparation }), solve: observedSolve ?? (async () => { throw new Error("unreachable unconfigured software solver"); }), softwareStrategyAvailable: observedSolve !== undefined, vetoQueue, checkpoints: projectCheckpoints, engineeringStatusProjections, manager: projectManager, ...(outcomeAdaptation ? { runInProjectContext: <T>(projectId: ProjectId, subjectId: string, run: () => Promise<T>) => adaptationProjectContext.run({ projectId, subjectId }, run) } : {}), ...(config.projectPosture ? { posture: config.projectPosture } : {}), ...(config.projectPermissionPolicy ? { permissionPolicy: config.projectPermissionPolicy } : {}), ...(config.projectResearch ? { research: config.projectResearch } : {}), ...(config.projectIntentRouter ? { intentRouter: config.projectIntentRouter } : {}), ...(config.projectRetriever ? { projectRetriever: config.projectRetriever } : {}), ...(config.projectRetrievalLimit !== undefined ? { projectRetrievalLimit: config.projectRetrievalLimit } : {}), ...(solverWorkspace ? { projectWorkspace: solverWorkspace } : {}), ...(config.projectLocalizer ? { projectLocalizer: config.projectLocalizer } : {}), ...(config.projectLocalizationTopK !== undefined ? { projectLocalizationTopK: config.projectLocalizationTopK } : {}), ...(config.projectPlanner ? { projectPlanner: config.projectPlanner } : {}), ...(projectEditor ? { projectEditor, solveConsumesAdmittedEdit: true as const } : {}), ...(projectTester ? { projectTester } : {}), ...(composedDomainWorkflow ? { domainWorkflow: composedDomainWorkflow } : {}), ...(composedDomainWorkflows ? { domainWorkflows: composedDomainWorkflows } : {}), ...((config.repoRef ?? materialization?.repoRef) ? { repoRef: config.repoRef ?? materialization!.repoRef } : {}), nonPersistable: nonPersistableRegistry, tracer: observability.recorder, lessonsForGoal: (goal) => skillRetrieval.retrieve({ taskShape: goal }).map((r) => r.skill.id) })
    : undefined;
  const memoryCustody = new FileMemoryCustody(pathJoin(config.dataDir, "memory-custody"));
  const restoreCommandPrincipal = (command: NativeProjectCommand, projectId: ProjectId): Principal => {
    const reference = command.principal;
    const principal = reference.kind === "agent" ? authorization.restorePrincipal(reference.grantId!)
      : config.identity !== undefined ? config.identity.registry.resolveReference(reference.id, reference.tenant)
      : config.tenantDeployment === undefined && reference.id === OWNER.id && reference.tenant === undefined ? OWNER
      : delegationParentFor(reference.id, reference.tenant);
    const project = projectManager.list().find(record => record.id === projectId);
    if (!principal || principal.id !== reference.id || principal.kind !== reference.kind || principal.tenant !== reference.tenant
      || !authorization.authorize(principal, "change.solve").allow || !project || project.tenant !== principal.tenant
      || (config.tenantDeployment !== undefined && principal.tenant !== config.tenantDeployment.tenantId)) throw new NativeProjectCommandUnavailableError("authority");
    projectManager.runnableSession(projectId);
    if (!autonomyLoop?.supportsStrategy(command.domainWorkflowKind)) throw new Error("project command strategy unavailable");
    return principal;
  };
  const taskMemoryForCommand = projectEditor !== undefined && config.projectEditor === undefined && config.solve === undefined
    ? (input: NativeProjectCommand, projectId: ProjectId): TaskMemoryContext => {
      const command = structuredClone(input);
      if (command.domainWorkflowKind !== undefined || command.binding !== projectRuntime?.commandBinding) throw new TaskMemoryUnavailableError("provider-binding");
      const selection = parseTaskMemorySelection(command.memoryContext);
      const currentScope = () => {
        const principal = restoreCommandPrincipal(command, projectId);
        if (selection.semantic && encoderAuthority === "owner" && principal.tenant !== undefined) throw new TaskMemoryUnavailableError("authority");
        if (!authorization.authorize(principal, "memory.read").allow) throw new TaskMemoryUnavailableError("authority");
        const scope = resolveMemoryScope({ principal, target: { scope: selection.scope,
          ...(selection.scope === "project" ? { projectId } : {}), ...(selection.agentId === undefined ? {} : { agentId: selection.agentId }) },
          personalMode: config.identity === undefined && config.tenantDeployment === undefined && principal.tenant === undefined,
          ...(config.tenantDeployment === undefined ? {} : { boundTenant: config.tenantDeployment.tenantId }), manager: projectManager,
          read: true, humanParent: actor => authorization.attribution(actor)?.humanPrincipalId });
        if (!scope) throw new TaskMemoryUnavailableError("authority");
        return scope;
      };
      const scope = currentScope(), scopeKey = canonicalize(scope);
      return createTaskMemoryContext({ partition: memoryCustody.partition(scope), scope, selection, provider: meteredProvider,
        ...(memoryRetentionPolicy === undefined ? {} : { retentionPolicy: memoryRetentionPolicy }),
        ...(semanticEncoder === undefined || selection.semantic === undefined ? {} : { encoder: semanticEncoder() }),
        authorize: () => canonicalize(currentScope()) === scopeKey });
    } : undefined;
  const projectRuntime = autonomyLoop !== undefined && projectManager !== undefined && spineDurable
    ? new ProjectRuntime(projectManager, { aggregateCeiling: 2, perProjectShare: 0.5 }, new SpineProjectJobJournal(spine), {
      ...(config.projectRuntimeOwnerId === undefined ? {} : { ownerId: config.projectRuntimeOwnerId, recoverCommands: true }),
      ...(config.projectRuntimePaused === undefined ? {} : { paused: config.projectRuntimePaused }),
      commands: {
        // Resource identity describes the physical workspace, not the provider or
        // project label. All commands sharing it serialize in the existing journal.
        ...(solverWorkspace?.dir === undefined ? {} : { resource: createHash("sha256").update(realpathSync(config.runtimePaths?.workspace ?? materialization?.workspaceBase ?? solverWorkspace.dir(solverRepository))).digest("hex") }),
        capabilities: [...(observedSolve === undefined ? [] : ["software-solver"]), ...(projectTester === undefined ? [] : ["repository-tests"])],
        observe: (projectId, jobId, expectedGoal, expectedContext) => observeGoalTask(projectCheckpoints.load(jobId), projectId, jobId, expectedGoal, expectedContext),
        // Opaque injected ports have no restart-stable implementation identity. They
        // remain usable now, but cannot silently recover as a different port later.
        binding: createHash("sha256").update(canonicalize({ version: "keep.native-project-runtime/v1", materialization: materialization ?? null,
          runtimePaths: config.runtimePaths ?? null, testCommand: config.testCommand ?? null,
          provider: descriptorDigest ?? (ownerDescriptor ? remoteProviderIdentityDigest(ownerDescriptor) : randomUUID()),
          ...(encoderIdentity === undefined ? {} : { semanticEncoder: encoderIdentity }),
          posture: config.projectPosture ?? null, tenant: config.tenantDeployment?.tenantId ?? null,
        })).digest("hex"),
        validate: (command, projectId) => {
          restoreCommandPrincipal(command, projectId);
          if (command.memoryContext !== undefined) {
            if (!taskMemoryForCommand) throw new Error("selected task memory executor is unavailable");
            taskMemoryForCommand(command, projectId);
          }
        },
        execute: (command, context) => autonomyLoop.runManagedProject(context.projectId, command.goal, {
          runId: context.jobId, signal: context.signal, trackActivity: context.trackActivity,
          ...(command.memoryContext === undefined ? {} : { memoryContext: taskMemoryForCommand!(command, context.projectId) }),
          ...(command.goalContext === undefined ? {} : { goalContext: command.goalContext }),
          ...(command.posture === undefined ? {} : { posture: command.posture }),
          ...(command.domainWorkflowKind === undefined ? {} : { domainWorkflowKind: command.domainWorkflowKind }),
        }),
      },
    })
    : undefined;
  const repositoryTransactions = projectRuntime ? new ProjectRepositoryTransactions(projectRuntime, new MultiRepositoryCoordinator(spine)) : undefined;
  const projectMerge = materialization && solverRootIdentity && projectCheckpoints && typeof solverWorkspace?.dir === "function"
    ? new GovernedLocalMerge({
        spine, checkpoints: projectCheckpoints, identityRegistry, rootIdentity: solverRootIdentity,
        projectDir: (repoRef) => solverWorkspace.dir!(repoRef), baseBranch: materialization.baseBranch ?? "main",
        ...(config.sourceLanding === true ? { sourceDir: materialization.sourceDir, advanceMaterialization: (commit: string) => materializationJournal!.save({ sourceDir: materialization.sourceDir, workspaceBase: materialization.workspaceBase, repoRef: materialization.repoRef, commit, baseBranch: materialization.baseBranch ?? "main" }) } : {}),
        ...(materialization.developmentForge ? { developmentForge: materialization.developmentForge } : {}),
      })
    : undefined;
  // Governance suite: on-demand signed evidence packs from the decision trail, regulatory incident clocks, and
  // deny-by-default residency/egress. Regulation-accurate (AI Act Art. 73 severity ladder); Omnibus target honesty-labeled.
  const governanceSuite = buildGovernanceSuite({
    spine,
    ...(config.governance ? { ledger: config.governance } : {}),
    ...(config.residency ? { residency: config.residency } : {}),
    ...(config.evidenceSigningKey ? { signingKey: config.evidenceSigningKey } : {}),
    ...(config.regimeVersion ? { regimeVersion: config.regimeVersion } : {}),
  });
  // L-INCIDENT-ON-TAMPER: a detected audit-chain TAMPER (L20a boot reconcile → diverged) auto-fires a
  // regulatory incident. SOTA 2026-08-19 correction: a bare audit-chain tamper is a CYBER-incident, so it starts
  // the NIS2 24h clock ONLY — it does NOT auto-start the EU AI Act Art.73 clock (that needs a harm outcome, which
  // this boot detection cannot assert) nor GDPR (no personal data implicated by an integrity tamper alone). No
  // severity is passed, so clocksFor computes NIS2-only. The clock legally starts at DETECTION; this RECORDS a
  // durable, timestamped detection + deadline — it does NOT file to any authority (reporting is the operator's
  // action, and the operator arms the AI-Act/GDPR clocks if the tamper turns out to meet those outcomes). The
  // `unreadable` case (below/L20a) is a LESSER internal integrity event, not a regulatory incident — also correct.
  if (witnessReconciliation.status === "diverged") {
    governanceSuite.incidents.capture("cyber-incident", `audit-chain integrity tamper detected at boot: ${witnessReconciliation.reason}`);
  }
  // Fleet projection is constructed only after witness reconciliation and incident capture, so optional fleet state
  // cannot suppress the canonical audit-tamper path. A policy mismatch disables fleet admission without failing boot.
  const fleetLifecycle = config.fleetLifecycle === undefined ? undefined : new FleetAdmissionLifecycle(spine, config.fleetLifecycle, { sharedTenancy: tenantDeployment !== undefined });
  fleetLifecycleForEffects = fleetLifecycle;
  if (fleetLifecycle !== undefined) infra.capabilities.installFleetDispatchClaimer(async (permit, effectDigest) => await fleetLifecycle.claimDispatch(permit, effectDigest));
  const telemetryDestinations: TelemetryDestinationRuntime[] = (config.privateTelemetryDestinations ?? []).map((destination) => {
    const built = buildPrivateOtlpCapability(destination);
    infra.capabilities.register(built.adapter);
    return Object.freeze({
      id: destination.id, ...(destination.tenant === undefined ? {} : { tenant: destination.tenant }), purpose: destination.purpose,
      authorityToken: built.authorityToken, destinationDigest: built.destinationDigest,
      pseudonymizationKey: destination.pseudonymizationKey, maxBatchSpans: destination.maxBatchSpans ?? 100,
    });
  });
  const fleetTelemetry = telemetryDestinations.length === 0 ? undefined : new DurableFleetTelemetry({
    spine, recorder: traceRecorder, hub: infra.capabilities, destinations: telemetryDestinations,
    ...(fleetCapabilityDispatch === undefined ? {} : { dispatch: async (invocation: CapabilityInvocation, context: { readonly actor: string; readonly tenant?: string; readonly authorityId: string; readonly retrieval: string }) => await fleetCapabilityDispatch(invocation, { ...context, specification: "keep.private-otlp-export/v1" }) }),
  });
  // Governed auto-RAG corpus: research sources ingested through the project-scoped governance pipeline; retrieval feeds
  // the RAG grounding floor. Isolation by construction (per-project namespace).
  const corpusSuite = buildCorpusSuite({});
  // Far-tier auto-training: OFF by default. Only composed when the operator opts in with training seams. decideTraining
  // is conservative, permission gates non-SOTA-safe training, and deploy needs a fresh per-session human authorization.
  const autoTraining = config.autoTraining ? buildAutoTrainingSuite(spine, config.autoTraining) : undefined;
  // M6: the closed self-improvement loop — OFF by default; composed only when the operator opts in. Composes
  // runSelfImprovementCycle with a shadow gate over the operator-supplied held-out corpus; never trains silently.
  const selfImprovement = config.selfImprovement?.enabled
    ? { runCycle: (signals: TrainingSignals, candidate?: { id: string; content: string }): SelfImprovementOutcome =>
          runSelfImprovementCycle(signals, { enabled: true, shadow: new ShadowModeGate(spine, config.selfImprovement!.corpus ?? []), safety: new ShadowModeGate(spine, config.selfImprovement!.safetyCorpus ?? []), ...(candidate ? { candidate } : {}) }) }
    : undefined;
  const sagaSequencer = new SagaSequencer(spine);
  const otelEmitter = new OtelGenAiEmitter(schedulerCostModel, spine);

  // M2 — the rolling-context wire: the live episodic-turn track (M1) + the context assembler that blends the
  // episodic (exact detail) and semantic (generalization) tracks into a redacted, bounded durableContext for the
  // harness. This is what makes the learning loop feed the prompt (the audit's true delta).
  const episodicTurns = new EpisodicTurnLog(new CryptoShredKeyStore());
  const contextAssembler = new ContextAssembler(
    semanticRetrieverFromStore(secondBrain.memory),
    episodicSourceFromLog(episodicTurns),
  );

  // 8.43 (EXTERNAL-EFFECT MEDIATION DECISION): expose the ONE class-consulting effect gate. HONEST SCOPE (corrected
  // 2026-08-17 after the cross-family veto): what is LOAD-BEARING today is that `CapabilityHub.invoke` consults
  // `decideEffectMediation` on EVERY call it routes (mutation-gate-verified: neutering unknown-HELD / external-HELD
  // reddens its test). This does NOT yet route keep_pipeline / non-default ingress / solve / push / merge through the
  // gate — those callers are UN-ROUTED and are the per-path WIRE items (deferred), NOT "already mediated". This block
  // only SURFACES the decision as a first-class composed capability. Enumeration completeness over ALL effect paths is
  // the METHOD/PATH REACHABILITY GATE (deferred), not the coarse enumerated tripwire in capability_port.ts.
  const effectMediation = { decide: decideEffectMediation, inventory: EFFECTFUL_ENTRY_POINTS } as const;
  spine.stage({
    type: "identity.action",
    actor: "effect-wrapper",
    payload: {
      event: "effect_mediation.active",
      entryPoints: EFFECTFUL_ENTRY_POINTS.map((e) => e.id),
      note: "every externally-effectful capability call routes through decideEffectMediation; unknown => HOLD (complete mediation)",
    },
  });
  const lifecycle = composeLifecycle();
  const nativeBoundaryTransport = config.nativeBoundaryTransport === undefined ? undefined : (() => {
    const developmentFixture = buildNativeTransportDevelopmentFixture();
    return Object.freeze({
      probe: (input: NativeTransportDevelopmentProbeInput) => exchangePackagedNativeCancel(
        config.nativeBoundaryTransport!,
        buildNativeTransportDevelopmentProbe(developmentFixture, input),
      ),
      developmentFixture,
    });
  })();
  return { memoryCustody, ...(memoryRetentionPolicy === undefined ? {} : { memoryRetentionPolicy }), ...(taskMemoryForCommand ? { taskMemoryForCommand } : {}), spine, witnessSink, witnessExport, ...(clientSigning ? { clientSigning } : {}), ...(cueAblation ? { cueAblation } : {}), ...(projectMerge ? { projectMerge } : {}), ...(repositoryTransactions ? { repositoryTransactions } : {}), ...(releaseBoot === undefined ? {} : { releaseGraph: releaseBoot.graph, releaseLedgers: releaseBoot.ledgers }), ...(externalReviewVerifier === undefined ? {} : { externalReviewVerifier }), ...(nativeBoundaryTransport === undefined ? {} : { nativeBoundaryTransport }), capabilities, observedFailureDefenses, enforcementTier: capabilities.tier, seamAudit, enforcementProfile, spineDurable, egressWitnessed, egressProvider, witnessReconciliation, identityRegistry, gateway, ...(config.runtimePaths ? { runtimePaths: config.runtimePaths } : {}), ...(tenantDeployment ? { tenantDeployment } : {}), ...(fleetLifecycle ? { fleetLifecycle } : {}), ...(fleetTelemetry ? { fleetTelemetry } : {}), secondBrain, episodicTurns, contextAssembler, infra, effectMediation, lifecycle, heartbeat, referenceRefresher, promptLayer, boot, manifest, posture, selfImprovementBus, driftMonitor, referenceMonitor, solveOutcomeWire, calibrationWire, ...(revertSignal ? { revertSignal } : {}), triggerIngress, mcpGateway, notifications, authorization, separationOfDuties, registryStore, managedSkillRegistry, tenantRegistry, redactionGateway, harnessCompiler, egressInterceptor, ...(personalDataStore ? { personalDataStore } : {}), ...(bestOfNSolver ? { bestOfNSolver } : {}), ...(resolveWithTests ? { resolveWithTests } : {}), ...(resolveCascadeFn ? { resolveCascade: resolveCascadeFn } : {}), ...(config.identity ? { identity: config.identity } : {}), curriculumLearner, needScheduler, consolidation, skillDistiller, skillCanary, skillRetrieval, memoryConsensus, ...(artifactSelfHeal ? { artifactSelfHeal } : {}), ...(adapterBridge ? { adapterBridge } : {}), ...(governedAnchor ? { governedAnchor } : {}), frontDoor, frontDoorForSubject, ...(skillValidator ? { skillValidator } : {}), ...(skillEvaluator ? { skillEvaluator } : {}), ...(metaHarness ? { metaHarness } : {}), scheduler, budgetLedger, deadLetterQueue, sagaSequencer, nonPersistableRegistry, otelEmitter, vettingGates, governanceSuite, corpusSuite, observability, learningSignals, ...(autoTraining ? { autoTraining } : {}), ...(selfImprovement ? { selfImprovement } : {}), ...(outcomeAdaptation ? { outcomeAdaptation, resetOutcomeAdaptation: resetOutcomeAdaptation!, projectAuditDigest: (projectId: ProjectId, domain: string, value: string) => projectRegistry.namespace(projectId).pseudonym(domain, value) } : {}), ...(audiencePerformanceFor ? { audiencePerformanceFor } : {}), ...(autonomyLoop && projectManager ? { autonomyLoop, projectManager, vetoQueue } : {}), ...(projectRuntime ? { projectRuntime } : {}) };
}

/** Deterministic short content hash for auditable version bumps (zero-dep, non-crypto FNV-1a). */
function hashShort(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(16).slice(0, 8);
}
