/**
 * Keep — Phase 0 substrate (public surface).
 *
 * The append-only hash-chained event spine + identity/RBAC/SoD + crypto-shred key
 * store. Everything downstream (memory, control, review, governance) reads this
 * layer. Built on Node built-ins only (zero runtime dependencies) so it deploys
 * anywhere; storage and locking are behind ports so Postgres/SQLite drop in later.
 */

export * from "./spine/event.js";
export {
  EventEnvelopeV1CanonicalRefusal,
  EventEnvelopeV1CodecIdentity,
  EventEnvelopeV1DigestDomain,
  EventEnvelopeV1Encode,
  EventEnvelopeV1EventTypes,
  EventEnvelopeV1Schema,
  type EventEnvelopeV1EffectCorrelation,
  type EventEnvelopeV1EventType,
  type EventEnvelopeV1Golden,
  type EventEnvelopeV1RefusalCode,
  type EventEnvelopeV1Result,
  type EventEnvelopeV1Track,
  type EventEnvelopeV1Value,
} from "./spine/event_envelope_v1.js";
export * from "./spine/hashchain.js";
export * from "./spine/upcaster.js";
export * from "./spine/store.js";
export * from "./spine/spine.js";
export * from "./lock/lock.js";
export * from "./keystore/keystore.js";
export * from "./privacy/persistent_personal_data_store.js";
export * from "./resilience/observed_failure_defense.js";
export * from "./learning/cross_family_criticism.js";
export * from "./loop/skill_evaluator.js";
export * from "./loop/skill_program.js";
export * from "./identity/identity.js";
export * from "./goal/goal_authority.js";
export * from "./goal/goal_transition.js";
export * from "./decomposition/decomposition_transition.js";
export * from "./decomposition/ticket_contract.js";
export * from "./decomposition/decomposition_graph.js";
export * from "./decomposition/track_coverage.js";
export * from "./decomposition/decomposition_review.js";
export * from "./decomposition/decomposition_review_events_v1.js";
export * from "./decomposition/decomposition_approval_events_v1.js";
export * from "./decomposition/decomposition_approval.js";
export * from "./decomposition/decomposition_publication.js";
export * from "./decomposition/n1_decomposition_integration.js";
export * from "./decomposition/enterprise_decomposition_integration.js";
export * from "./autonomy/project_state.js";
export * from "./autonomy/project_checkpoint_store.js";
export * from "./autonomy/yolo_ticket_coordinator_v1.js";
export * from "./backup/hourly_wip_supervisor_v1.js";
export * from "./backup/ticket_closure_supervisor_v1.js";
export * from "./research/goal_research.js";
export * from "./research/tri_research_admission.js";

// Discipline kernel — provider-neutral evidence, durability, artifact, and tracker ports
export * from "./discipline/contracts.js";
export * from "./discipline/review_policy.js";
export * from "./discipline/external_review_corroboration.js";

// Phase 0.5 — composition root + swappability ports
export * from "./gateway/gateway.js";
export * from "./gateway/governed_remote_provider.js";
export * from "./gateway/local_provider.js";
export * from "./gateway/http_gateway.js";
export * from "./loop/heartbeat.js";
export * from "./boot/secrets.js";
export * from "./compose.js";

// Phase 1 — memory wedge
export * from "./memory/model.js";
export * from "./memory/gates.js";
export * from "./memory/ingestion.js";
export * from "./memory/store.js";
export * from "./memory/starter_corpus.js";

// Phase 2 — control & escalation
export * from "./control/action_tier.js";
export * from "./control/confidence.js";
export * from "./control/killswitch.js";
export * from "./control/rollback.js";
export * from "./control/merge_gate.js";

// Phase 3 — review layer
export * from "./review/finding.js";
export * from "./review/security_verifier.js";
export * from "./review/heterogeneous.js";
export * from "./review/merge_readiness.js";

// Phase 3.5 — learning-loop features (need the PR/review substrate)
export * from "./learning/edit_delta.js";
export * from "./learning/shadow_mode.js";
export * from "./learning/baseline_metric.js";
export * from "./learning/badges_drift.js";

// Phase 3.5 — real structural differ + spine-curated corpus
export * from "./learning/edit_differ.js";
export * from "./learning/corpus_curation.js";

// Phase 4 — cost & observability
export * from "./observability/cost_model.js";
export * from "./observability/tracing.js";
export * from "./observability/fleet_telemetry.js";
export * from "./observability/forecasting.js";
export * from "./observability/failure_localization.js";
export * from "./observability/routing.js";

// Phase 5 — governance & compliance
export * from "./governance/policy_engine.js";
export * from "./governance/decision_record.js";
export * from "./governance/residency.js";
export * from "./governance/evidence_pack.js";
export * from "./governance/incident.js";

// Phase 6 — ecosystem & interfaces (MCP/A2A, triggers, CI/CD, templates)
export * from "./ecosystem/capability_port.js";
export * from "./ecosystem/mcp.js";
export * from "./ecosystem/a2a.js";
export * from "./ecosystem/integrations.js";

// Infra — real adapters wiring seams to live infrastructure
export * from "./infra/git_adapter.js";
export * from "./infra/process_isolation.js";
export * from "./infra/scanner_adapter.js";
export * from "./infra/tracker_adapters.js";
export * from "./infra/private_endpoint_adapters.js";
export * from "./infra/mcp_stdio_transport.js";
export * from "./infra/ci_adapter.js";
export * from "./infra/a2a_inprocess_transport.js";
export * from "./infra/compose_infra.js";
export * from "./platform/native_boundary_transport.js";
export * from "./platform/native_patch_capture.js";
export * from "./platform/native_boundary_development_fixture.js";

// Front door — F0 brain intake
export * from "./frontdoor/brain_port.js";
export * from "./frontdoor/brain_resolver.js";

// Front door — F1 conversational onboarding
export * from "./frontdoor/secret_intake.js";
export * from "./frontdoor/onboarding_conversation.js";

// Front door — F1.5 Plan-then-Execute gate
export * from "./frontdoor/action_schema.js";
export * from "./frontdoor/plan_execute_gate.js";

// Front door — F1.6 capability-adaptive tiering
export * from "./frontdoor/capability_adaptive.js";

// Front door — F1.8 role-based routing
export * from "./frontdoor/role_router.js";

// Front door — F1.9 resilient routing (registry + fallback chain)
export * from "./frontdoor/capability_registry.js";
export * from "./frontdoor/fallback_chain.js";

// Front door — F1.7 conversation driver (the keystone)
export * from "./frontdoor/proposal_parser.js";
export * from "./frontdoor/conversation_driver.js";

// Front door — F3a large-input ingestion & incremental understanding
export * from "./frontdoor/chunker.js";
export * from "./frontdoor/project_understanding.js";

// Front door — F3b revision & rebuild
export * from "./frontdoor/revision_store.js";
export * from "./frontdoor/rebuild_classifier.js";

// Front door — intent-shape router
export * from "./frontdoor/intent_router.js";

// Front door — F2 directive -> system translation
export * from "./frontdoor/directive_translator.js";
export * from "./frontdoor/config_applier.js";

// Recovered planned features — #28 dry-run, #20 batch digests
export * from "./control/dry_run.js";
export * from "./review/batch_digest.js";

// Theme 1 — instance isolation (compartmentalized multi-install)
export * from "./instance/bind_strategy.js";
export * from "./instance/instance_home.js";
export * from "./instance/registry.js";

// Theme 2 — currency layer (date awareness + prior-art check)
export * from "./currency/temporal_context.js";
export * from "./currency/landscape_catalog.js";
export * from "./currency/prior_art.js";

// BM25 ranker (zero-dep lexical retrieval)
export { Bm25Index, reciprocalRankFusion } from "./currency/bm25.js";
export type { Bm25Doc, Bm25Hit, Bm25Params } from "./currency/bm25.js";

// Theme 3a — soul/persona (name, personality, standing directives)
export * from "./soul/soul_config.js";
export * from "./soul/soul_render.js";

// Autonomy calibration (user-selectable levels + criticality + learned preference)
export * from "./frontdoor/autonomy_profile.js";

// Theme 5c — no-account local defaults + capability audit
export * from "./frontdoor/capability_audit.js";
export * from "./audit/tenant_audit_export.js";
export * from "./team/tenant_deployment_admission.js";
export * from "./release/solo_non_regression.js";
export * from "./fleet/fleet_lifecycle.js";
export * from "./frontdoor/local_first_defaults.js";

// Autonomy engine — progress narration (item 1)
export * from "./autonomy/progress_narrator.js";

// Autonomy engine — universal project loop backbone (item 2)
export * from "./autonomy/project_loop.js";

// Autonomy engine — intake feasibility / scope-of-competence check
export * from "./autonomy/feasibility_check.js";

// Autonomy engine — grounded cost/time projections (item 3)
export * from "./autonomy/grounded_estimator.js";

// Multi-project session layer (item 3.5) — stable identity + cryptographic namespacing (3.5a),
// isolated per-project workspace (3.5b), outer session manager with switch/archive/delete (3.5c)
export * from "./session/project_id.js";
export * from "./session/project_registry.js";
export * from "./session/project_session.js";
export * from "./session/project_session_manager.js";

// Secure data ingestion + governance (item 4.5) — deterministic PII classifier (4.5a),
// tokenizer + tag-driven handling policy (4.5b), ROPA/purpose-gate/erasure governance (4.5c),
// ingestion pipeline + retrieval backend port (4.5d)
export * from "./ingest/data_classifier.js";
export * from "./ingest/handling_policy.js";
export * from "./ingest/data_governance.js";
export * from "./ingest/content_sanitizer.js";
export * from "./ingest/ingestion_pipeline.js";

// Self-refreshing reference data (item 3.6) — generic SWR + stale-if-error container (3.6a),
// dated-seed registry of perishable categories (3.6b), background revalidator (3.6c)
export * from "./reference/reference_set.js";
export * from "./reference/reference_registry.js";
export * from "./reference/reference_refresher.js";

// Adaptive Prompt Layer (item 3.7) — model×complexity strategy matrix + adaptation seam (3.7a),
// complexity classifier + firewall router (3.7b), versioned prompt store + GEPA-style loop (3.7c),
// tailored vetting builder + top-level composer (3.7d)
export * from "./prompt/prompt_strategy.js";
export * from "./prompt/complexity_router.js";
export * from "./prompt/prompt_store.js";
export * from "./prompt/adaptive_prompt_layer.js";

// Logic Vetting (item 3.8) — deterministic sound critics (3.8a), grounded partial critics +
// single-model selective verification (3.8b), consensus + posture switch (3.8c), LogicVet panel
// + rabbit-hole guard (3.8d)
export * from "./logicvet/deterministic_critics.js";
export * from "./logicvet/grounded_critics.js";
export * from "./logicvet/consensus.js";
export * from "./logicvet/logic_vet.js";

// Verification Cascade (item 3.9) — generic tiered ladder (3.9a), confidence-driven escalation
// policy + pre-route + intra-tier consensus (3.9b), domain tier adapters incl. LogicVet floor (3.9c)
export * from "./cascade/verification_cascade.js";
export * from "./cascade/escalation_policy.js";
export * from "./cascade/tier_adapters.js";

// Auto-Research (item 4) — research-need detector + provenance model (4a), bounded ResearchLoop
// orchestrator (4b), deterministic citation/provenance floor + faithfulness seam as cascade Tier-0 (4c)
export * from "./research/research_need.js";
export * from "./research/research_loop.js";
export * from "./research/tri_research_admission.js";
export * from "./research/provenance_floor.js";

// Auto-RAG (item 5) — retrieval-need detector + CorpusBuilder over the governed pipeline (5a),
// grounded-answer builder + deterministic groundedness floor (5b), retrieval-sufficiency/abstain
// gate as cascade Tier-0 (5c)
export * from "./research/corpus_builder.js";
export * from "./research/grounded_answer.js";
export * from "./research/rag_grounding_floor.js";

// Auto-Learning (item 6) — the LearningLoop closing observe→distill→promote/retire over the
// TrustTier lessons (6a), and the RegressionGuard: two-signal rise-then-collapse detector +
// rollback-to-peak (6b)
export * from "./learning/learning_loop.js";
export * from "./learning/regression_guard.js";
export * from "./learning/audience_performance.js";

// Scheduler + AuthorizationEnvelope (item 7) — the one-time authorization envelope + budget ledger
// (7a), the MeteredGateway hard-stop enforcement + token-velocity breaker (7b), the operator-toggled
// Scheduler + dead-letter queue (7c), and the saga sequencer + non-persistable regions + OTel
// gen_ai emission (7d)
export * from "./scheduler/authorization_envelope.js";
export * from "./scheduler/metered_gateway.js";
export * from "./scheduler/scheduler.js";
export * from "./scheduler/saga_sequencer.js";

// Auto-Training / DataEngineLoop (item 8) — Snorkel-style narrow, verifiable data engineering:
// failure-mode detector (8a), labeling functions + denoising label model + correlation diagnostic
// (8b), the DataEngineLoop producing gradient-free eval-data/few-shot/anchors by default with a
// gated far-tier weight-training stub (8c)
export * from "./training/failure_mode_detector.js";
export * from "./training/labeling.js";
export * from "./training/data_engine_loop.js";

// Backup / uninstall (item 9) — BackupPort + content-addressed snapshot + always-on LocalBackup (9a),
// verifyRestore (+0 no-unverified-restore) + free-first off-machine prompt (9b), clean uninstall that
// crypto-shreds keys but leaves work intact at the backup target (9c)
export * from "./backup/backup_port.js";
export * from "./backup/verify_restore.js";
export * from "./backup/uninstall.js";

// LoRA local-adapter tier (item 10, optional) — the most gated capability: adapter model + versioning
// + entry gates (opt-in/auth/sandbox/poison-screen/verifiable-reward) (10a), before/after eval gate +
// colluding-LoRA composition check (10b), deploy orchestrator with canary + one-tap rollback (10c)
export * from "./lora/adapter_tier.js";
export * from "./lora/eval_gate.js";
export * from "./lora/deploy_orchestrator.js";

// Auto-Training system (item 11) — SAFELY SHIPPING real auto-train: the training-decision policy
// (when training beats gradient-free — usually not) (11a), the training loop + backend port that
// ACTUALLY trains via GRPO/QLoRA/safety-preserving with live reward-hacking monitoring (11b), the
// permission + plain-language explanation layer (11c), and the AutoTrainer orchestrator that ties
// decide → permission → train → the existing safety gauntlet (11d)
export * from "./autotrain/training_decision.js";
export * from "./autotrain/training_loop.js";
export * from "./autotrain/permission.js";
export * from "./autotrain/auto_trainer.js";

// HTTP model provider + record/replay (increment 12) — a real ModelProvider over HTTP with wire
// dialects (12a), SSE streaming with fail-closed truncation detection (12b), and port-level
// record/replay cassettes for deterministic offline runs (12c)
export * from "./gateway/wire_dialect.js";
export * from "./gateway/http_provider.js";
export * from "./gateway/sse.js";
export * from "./gateway/cassette.js";
export * from "./gateway/record_replay.js";
export * from "./gateway/provider_router.js";
export {
  MeasuredHardRouteBudget,
  MeasuredOutcomeRouter,
  assemblePrompt as assembleCostOfPassPrompt,
  chooseBudgetAwareRoute,
  chooseModel as chooseCostOfPassModel,
  costOfPass,
  escalateOnVetFailure,
  estimateComplexity as estimateCostOfPassComplexity,
  recordOutcome as recordCostOfPassOutcome,
  type BudgetAwareRoute,
  type ComplexityBand as CostOfPassComplexityBand,
  type HardRouteBudget,
  type HardRouteBudgetSnapshot,
  type MeasuredRoutingOutcome,
  type ModelProfile as CostOfPassModelProfile,
  type PromptFormat as CostOfPassPromptFormat,
  type RouteChoice as CostOfPassRouteChoice,
  type RouterPolicy as CostOfPassRouterPolicy,
  type RoutingUpdate,
  type TaskSignal as CostOfPassTaskSignal,
} from "./routing/cost_of_pass_router.js";

// SolvePipeline (increment 13) — Agentless-style localize→plan→apply→validate→repair machine
export * from "./solve/issue_model.js";
export * from "./solve/patch.js";
export * from "./solve/localize.js";
export * from "./solve/edit_planner.js";
export * from "./solve/validate.js";
export * from "./solve/repair_loop.js";
export * from "./solve/recovery_budget.js";
export * from "./solve/solve_pipeline.js";
export * from "./solve/project_loop_wiring.js";
export * from "./autonomy/project_edit_stage.js";
export * from "./autonomy/project_localization.js";
export * from "./autonomy/project_test_stage.js";
export * from "./autonomy/domain_workflows.js";
export * from "./autonomy/audiobook_synthesis_port.js";

// Code-structure graph + hybrid retrieval (increment 14) — local-first, on-device, never exfiltrates
export * from "./coderag/code_graph.js";
export * from "./coderag/hybrid_rank.js";
export * from "./coderag/embedding_stage.js";
export * from "./coderag/graph_localizer.js";

// Git remote + PR flow (increment 15) — branch-per-task, never-push-protected, never auto-merge
export * from "./git/git_remote.js";
export * from "./git/pull_request.js";
export * from "./git/pr_publisher.js";

// PR risk-tiering + oversight routing (increment 15.5) — reconciles fatigue with safety
export * from "./oversight/pr_risk.js";
export * from "./oversight/oversight_router.js";

// SWE-bench-contract eval harness (increment 16) — benchmark-agnostic, two-part oracle, variance+cost
export * from "./eval/swebench_task.js";
export * from "./eval/harness.js";
export * from "./eval/synthetic_suite.js";
export * from "./eval/report.js";

// End-to-end pipeline composition (increment 16.5) — the one-call golden path: issue -> PR
export * from "./pipeline/keep_pipeline.js";

// Governance/safety integration (increment 16.6) — SafetyRail default-on guardrails
export * from "./pipeline/safety_rail.js";
export * from "./pipeline/patch_verifier.js";
export * from "./pipeline/plan_vetter.js";
export * from "./pipeline/plan_consequences.js";
export * from "./pipeline/trajectory_checkpoint.js";
export * from "./pipeline/safe_remediation.js";
export * from "./pipeline/consequence_forecast.js";
export * from "./pipeline/decision_brief.js";
export * from "./pipeline/oversight_calibration.js";
export * from "./sovereignty/manifest.js";
export * from "./pipeline/plan_currency.js";
export * from "./sovereignty/posture.js";
export * from "./gateway/brain_ladder.js";
export * from "./cascade/verification_harness.js";
export * from "./cascade/unified_gate.js";
export * from "./isolation/isolation_tier.js";
export * from "./isolation/isolated_executor.js";
export * from "./meta/meta_harness.js";
export * from "./meta/proposal_triad.js";
export * from "./loop/self_improvement_bus.js";
export * from "./loop/drift_monitor.js";
export * from "./control/reference_monitor.js";
export * from "./control/reference_clauses.js";
export * from "./loop/solve_outcome_wire.js";
export * from "./loop/wiring_ledger.js";
export * from "./loop/learners.js";
export * from "./loop/consolidation.js";
export * from "./loop/skill_distiller.js";
export * from "./loop/skill_validator.js";
export * from "./loop/skill_validator_defaults.js";
export * from "./loop/skill_canary.js";
export * from "./loop/skill_retrieval.js";
export * from "./memory/consensus.js";
export * from "./loop/artifact_self_heal.js";
export * from "./lora/adapter_proposal_bridge.js";
export * from "./learning/governed_anchor.js";
export * from "./anticipate/cue_ablation.js";
export * from "./frontdoor/front_door.js";
export * from "./cli/cli_core.js";
export * from "./cli/decision_packet.js";
export * from "./oversight/calibration_wire.js";
export * from "./ingress/webhook_verifier.js";
export * from "./ingress/trigger_ingress.js";
export * from "./ingress/polling_source.js";
export * from "./ingress/http_ingress.js";
export * from "./ecosystem/hostile_mcp_gateway.js";
export * from "./notify/notification_router.js";
export * from "./loop/review_intake.js";
export * from "./review/non_engineer_view.js";
export * from "./review/review_core.js";
export * from "./review/review_web.js";
export * from "./review/review_server.js";
export * from "./identity/rbac.js";
export * from "./identity/session_store.js";
export * from "./identity/identity_provider.js";
export * from "./identity/delegation_registry.js";
export * from "./identity/security_gate.js";
export * from "./resolve/best_of_n.js";
export * from "./resolve/selector.js";
export * from "./resolve/novel_tests.js";
export * from "./resolve/budget_cascade.js";
export * from "./resolve/resolution_curve.js";
export * from "./monitor/solve_monitor.js";
export * from "./oversight/merge_authority.js";
export * from "./oversight/merge_executor.js";
export * from "./git/git_merge_port.js";
export * from "./gateway/resilient_model.js";
export * from "./frontdoor/working_phase.js";
export * from "./frontdoor/setup_phase.js";
export * from "./autonomy/autonomy_loop.js";
export * from "./autonomy/need_scheduler.js";
export * from "./cascade/vetting_gates.js";
export * from "./governance/governance_suite.js";
export * from "./research/corpus_suite.js";
export * from "./autotrain/auto_training_suite.js";
export * from "./observability/observability_suite.js";
export * from "./observability/trace_context.js";
export * from "./gateway/tracing_provider.js";
export * from "./loop/skill_application.js";
export * from "./learning/learning_signals.js";
export * from "./solve/workspace.js";
export * from "./solve/default_solver.js";
export * from "./solve/sandboxed_runner.js";
export * from "./oversight/revert_signal.js";
export * from "./identity/oidc_provider.js";
export * from "./eval/decontamination.js";
export * from "./eval/swe_eval.js";
export * from "./eval/eval_run.js";
export * from "./eval/local_suite.js";
export * from "./eval/official_swebench.js";
export * from "./research/local_retrieval_benchmark.js";
export * from "./infra/isolation_backend.js";
export * from "./client/client_core.js";
export * from "./client/client_signing.js";
export * from "./privacy/streaming_rehydrator.js";
export * from "./spine/event_admission_v1.js";
export * from "./spine/authoritative_append_v1.js";
export * from "./spine/committed_head_v1.js";
export * from "./spine/reducer_registry_v1.js";
export * from "./spine/version_registry_v1.js";
export * from "./spine/replay_projection_v1.js";
export * from "./spine/tail_recovery_v1.js";
export * from "./spine/authoritative_replay_v1.js";
export * from "./spine/goal_authority_events_v1.js";
export * from "./spine/engineering_status_projection_v1.js";
export * from "./spine/decomposition_result_events_v1.js";
export {
  FileN1CommittedHeadWitnessV1,
  N1EventAuthorityProductBuildIdentityV1,
  recoverN1EventAuthorityJourneyV1,
  requireEnterpriseFromN1JourneyV1,
  runN1EventAuthorityJourneyV1,
} from "./spine/n1_event_authority_integration_v1.js";
export type {
  N1EventAuthorityJourneyCodeV1,
  N1EventAuthorityJourneyInputV1,
  N1EventAuthorityJourneyReceiptV1,
  N1EventAuthorityJourneyResultV1,
  N1EventAuthorityRecoveryStreamV1,
  N1EventAuthorityTailRecoveryV1,
} from "./spine/n1_event_authority_integration_v1.js";
export {
  EnterpriseEventAuthorityProductBuildIdentityV1,
  recoverEnterpriseEventAuthorityJourneyV1,
  requireN1FromEnterpriseJourneyV1,
  runEnterpriseEventAuthorityJourneyV1,
} from "./spine/enterprise_event_authority_integration_v1.js";
export type {
  EnterpriseEventAuthorityJourneyCodeV1,
  EnterpriseEventAuthorityJourneyInputV1,
  EnterpriseEventAuthorityJourneyReceiptV1,
  EnterpriseEventAuthorityJourneyResultV1,
  EnterpriseEventAuthorityRecoveryStreamV1,
  EnterpriseEventAuthorityTailRecoveryV1,
} from "./spine/enterprise_event_authority_integration_v1.js";
