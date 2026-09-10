/**
 * KeepPipeline (Increment 16.5) — the end-to-end composition.
 *
 * Assembles the full spine that increments 13–16 built as separate, individually-proven pieces:
 *   issue → graph-localize → solve (localize/plan/apply/validate/repair) → risk-tier → PR proposal.
 * A red-team audit found those pieces were composed only in tests, with no single top-level entrypoint;
 * this closes that gap. An operator calls ONE method — `solveIssueToPR` — and gets a human-reviewable PR
 * with a risk-tiered oversight decision attached. Everything stays swappable behind ports (FileTree,
 * TestRunner, model, git, PR port); GraphLocalizer + oversight are wired as the defaults. Never merges;
 * the human gate is structural (increment 15). Zero deps.
 *
 * What would change it: the isolation tier (increment 17) wraps the TestRunner/FileTree the pipeline
 * drives — it plugs in behind the same ports without changing this composition.
 */

import type { Spine } from "../spine/spine.js";
import { RollbackLedger } from "../control/rollback.js";
import { IdentityRegistry, type AgentIdentity } from "../identity/agent_identity.js";
import type { ModelProvider } from "../gateway/gateway.js";
import type { AutonomyLevel } from "../frontdoor/autonomy_profile.js";
import { realpathSync } from "node:fs";

import type { Issue, SolveResult } from "../solve/issue_model.js";
import type { FileTree } from "../solve/patch.js";
import type { TestRunner, TestRunResult } from "../solve/validate.js";
import type { Localizer, RepoFile } from "../solve/localize.js";
import { SolvePipeline, type SolvePipelineOptions } from "../solve/solve_pipeline.js";

import { GraphLocalizer } from "../coderag/graph_localizer.js";
import type { Embedder } from "../coderag/embedding_stage.js";

import type { GitAdapter } from "../infra/git_adapter.js";
import { GitRemote, type RemoteConfig } from "../git/git_remote.js";
import { LocalPullRequest, type PullRequestPort, type PrManifest } from "../git/pull_request.js";
import { publishSolveAsPr, type PublishResult } from "../git/pr_publisher.js";

import { PrRiskAssessor } from "../oversight/pr_risk.js";
import { OversightRouter } from "../oversight/oversight_router.js";
import { decideMergeAuthority, decideComprehensionReceipt, mergeDecisionId, DEFAULT_MERGE_ENVELOPE, type MergeAuthorityDecision, type MergeEnvelope, type ComprehensionReceipt, type ComprehensionReceiptDecision } from "../oversight/merge_authority.js";
import { AutonomousMergeExecutor, missingPublicationActuatorRecoveryHold, type MergePort, type AutonomousMergeResult, type PublicationOperatorTrust, type PublicationRecoveryResult } from "../oversight/merge_executor.js";
import { GitMergePort } from "../git/git_merge_port.js";
import { IsolatedTestRunner, ProcessIsolationExecutor, jailedTree, selectExecutor, type IsolatedExecutor } from "../isolation/isolated_executor.js";
import { ResilientModelProvider } from "../gateway/resilient_model.js";
import { RoutedModelProvider, type RoutedModelConfig } from "../gateway/provider_router.js";
import type { BrainRung } from "../gateway/brain_ladder.js";
import { SafetyRail, type BreakGlassGrant, type RailDecision } from "./safety_rail.js";

/** One fail-closed appraisal shared by the post-merge enforcement path and its hostile tests. */
export function appraisePostMergeRun(res: TestRunResult): { regressed: boolean; detail?: string } {
  const failedCases = res.results.filter((row) => !row.passed).map((row) => row.name);
  const regressed = res.runnerError !== undefined || res.results.length === 0 || failedCases.length > 0;
  const detail = res.runnerError ?? (res.results.length === 0 ? "post-merge verifier returned no test results" : failedCases.join(", "));
  return { regressed, ...(regressed ? { detail } : {}) };
}
import { defaultPatchVetter, verifyPatch, type PatchVerifierInput } from "./patch_verifier.js";
import { defaultPlanVetter, type PlanVetDecision } from "./plan_vetter.js";
import { checkTrajectoryDrift, type TrajectoryDrift } from "./trajectory_checkpoint.js";
import { CompositionalForecast, type ForecastVerdict } from "./consequence_forecast.js";
import { isolationCeilingFromEvidence, weakerTier, type IsolationTier, type IsolationCapabilities } from "../isolation/isolation_tier.js";
import { createRunAttestationChannel, type IsolationAttestor, type IsolationVerifier } from "../isolation/isolation_attestation.js";
import { verifiedMicrovmMeasurementPolicyAuthorityDigest } from "../infra/microvm_boundary.js";
import { deriveEffectsFromEdits } from "./plan_consequences.js";
import { SafeRemediation, type RemediationOutcome } from "./safe_remediation.js";
import { buildDecisionBrief, type DecisionBrief } from "./decision_brief.js";
import { GovernanceLedger } from "../governance/decision_record.js";
import { KillSwitch } from "../control/killswitch.js";
import type { AuthorizationEnvelope } from "../scheduler/authorization_envelope.js";

/**
 * The id of the identity the pipeline mints for its solve path. Exported so an operator has a
 * NAMED HANDLE to revoke: `registry.kill(KEEP_SOLVE_IDENTITY_ID)`. A kill switch you cannot
 * address is not a kill switch.
 */
export const KEEP_SOLVE_IDENTITY_ID = "keep-solve";

export interface KeepPipelineDeps {
  readonly spine: Spine;
  /** The working tree (in-memory here; a real git worktree on Hetzner — same port). */
  readonly tree: FileTree;
  /** The test oracle (scripted here; a process-spawning runner on Hetzner — same port). */
  readonly runner: TestRunner;
  /** The planning/repair model (replay/local/http behind the gateway). */
  readonly model: ModelProvider;
  /** Optional fallback brain rungs (free/local/paid). Provided → the model becomes resilient (failover + defer). */
  readonly brainRungs?: readonly BrainRung[];
  /** Optional cost-cascade router config (multi-tier / front-of-house). Takes precedence over brainRungs when set. */
  readonly routedModel?: RoutedModelConfig;
  /** AM2: kill switch — engaged pauses autonomous merge (deny-by-default). */
  readonly killSwitchEngaged?: () => boolean;
  /** Separately administered verification keys for exceptional publication observations and their retained history. */
  readonly publicationOperatorTrust?: PublicationOperatorTrust;
  /** Optional: a custom localizer. Defaults to the on-device GraphLocalizer (increment 14). */
  readonly localizer?: Localizer;
  /** Optional embedder for the localizer's semantic channel. */
  readonly embedder?: Embedder;
  /** Optional vetting gate (used as the SafetyRail's patch-vetting function). Absent → fail-closed. */
  readonly vet?: (repoRef: string) => Promise<boolean>;
  /** Optional spend guard for the repair loop. */
  readonly withinBudget?: (round: number) => boolean;
  /**
   * Optional killswitch. If supplied and tripped, the pipeline refuses to run (checked first).
   * Reachable-by-default: the pipeline always constructs a SafetyRail, even at N=1.
   */
  readonly killSwitch?: KillSwitch;
  /** Optional governance ledger. Omit → one is created bound to the spine (decisions are still audited). */
  readonly governance?: GovernanceLedger;
  /** Optional custom pre-solve plan vetter. Omit → the default LogicVet-based plan gate (default-on). */
  readonly planVet?: (issue: Issue) => Promise<PlanVetDecision>;
  /**
   * The operator's brain capability (front vs back of room). Drives the capability-adaptive vetting
   * harness: rich → single + heterogeneous second brain tiers; lean/free-tier → single brain, cost-adaptive;
   * none → deterministic floor + human only. The deterministic floor is identical for every capability.
   * Omit → "lean" (a safe, cost-conscious default that still runs the full deterministic floor).
   */
  readonly brainCapability?: import("../cascade/verification_harness.js").BrainCapability;
  /** The isolation tier the AI-generated code executes under. Weaker isolation → more human review (17).
   * Omit → "process" (back-of-house-safe default: auto-approval suppressed unless microVM/gVisor present). */
  readonly isolationTier?: IsolationTier;
  /** Optional custom self-heal engine. Omit → the default narrowest-safe SafeRemediation (default-on). */
  readonly safeRemediation?: SafeRemediation;
  /** Isolation backend that wraps untrusted test execution. Omit → the built ProcessIsolationExecutor floor. */
  readonly isolationExecutor?: IsolatedExecutor;
  /**
   * BUILD-ORDER 1.3c — detected host isolation capabilities. When provided (and no explicit
   * `isolationExecutor`), the pipeline SELECTS the strongest available executor via `selectExecutor`: if a
   * strong runtime (gVisor/container) is really present it engages the strong `BoundaryExecutor` by
   * default; otherwise the round-1.3 process floor stays the default. Omit → the process floor (unchanged).
   */
  readonly isolationCapabilities?: IsolationCapabilities;
  /**
   * BUILD-ORDER 1.3c/1.3b — an explicit strong-tier boundary runner + auto-wire config for `selectExecutor`.
   * `detectRuntime`/`container` back the gVisor/container tiers; `detectMicrovm`/`microvm` back the TOP
   * microVM tier (engaged only when KVM+firecracker+a built kernel/rootfs are really present).
   */
  readonly strongBoundary?: {
    readonly boundaryRun?: (runner: import("../solve/validate.js").TestRunner, spec: import("../isolation/isolated_executor.js").ExecutionSpec) => Promise<import("../solve/validate.js").TestRunResult>;
    readonly detectRuntime?: () => import("../infra/container_boundary.js").ContainerRuntimeInfo;
    readonly container?: Omit<import("../infra/container_boundary.js").ContainerBoundarySpec, "projectDir">;
    readonly detectMicrovm?: () => import("../infra/microvm_boundary.js").MicrovmRuntimeInfo;
    readonly microvm?: Omit<import("../infra/microvm_boundary.js").MicrovmBoundarySpec, "projectDir">;
    /** BUILD-ORDER 1.5 — the Windows (non-POSIX) Job Object floor. `platform`/`detectWindows`/`windows` engage
     * the win32 Job Object backend behind the SAME port; `windowsBoundaryRun` is a host/VERIFIED-SEAM wiring.
     * PLATFORM-HONEST: the Windows floor is selected ONLY when the host platform is win32. */
    readonly platform?: string;
    readonly detectWindows?: () => import("../infra/windows_isolation.js").WindowsRuntimeInfo;
    readonly windows?: Omit<import("../infra/windows_isolation.js").WindowsBoundarySpec, "projectDir">;
    readonly windowsBoundaryRun?: (runner: import("../solve/validate.js").TestRunner, spec: import("../isolation/isolated_executor.js").ExecutionSpec) => Promise<import("../solve/validate.js").TestRunResult>;
  };
  /** Verifier-owned signed release policy. It is deliberately separate from strongBoundary.microvm so the
   * runner cannot nominate the policy against which its own measurements are appraised. */
  readonly microvmMeasurementPolicyAuthority?: import("../infra/microvm_boundary.js").VerifiedMicrovmMeasurementPolicyAuthority;
  /** Policy-forbidden operations the deterministic pre-apply logic-vet gate blocks in any edit plan. */
  readonly forbiddenActions?: readonly string[];
  /**
   * Per-agent identity registry (Core Addition C). ROUND 35 — this is what makes the identity
   * kill switch REACHABLE on the operator's own path.
   *
   * SUPPLIED BY THE OPERATOR ON PURPOSE. The pipeline deliberately does NOT construct its own
   * registry: a registry nothing outside can reach would make `kill()` unreachable, and a kill
   * switch nobody can throw is decorative. That is strictly WORSE than omitting it, because
   * `undefined` at least reports itself honestly as "not assessed (no veto)", whereas a private
   * registry would report "assessed and fine" forever.
   *
   * When supplied, the pipeline mints one identity (`KEEP_SOLVE_IDENTITY_ID`) from it and threads
   * identity + registry into the solve path. The operator revokes with
   * `registry.kill(KEEP_SOLVE_IDENTITY_ID)`; from then on the composed gate sees
   * `identityLive: false` and holds. Kill is monotone — re-minting does not resurrect a killed id.
   *
   * Omit ⇒ `identityLive` stays `undefined` ⇒ "not assessed (no veto)", exactly as before.
   *
   * SCOPE IS INERT HERE, and saying so matters: the minted scope is not enforced on this path
   * because `authorizeEffect` still has no caller (Z99). This identity is a REVOCATION HANDLE,
   * not a scope enforcer.
   */
  readonly identityRegistry?: IdentityRegistry;
  /**
   * ROUND 38 — the regions this Keep may write to, e.g. `["src", "test"]`.
   *
   * THE ONE KNOB AN OPERATOR SETS, and it is deliberately the thing they already know: which
   * directories this run is allowed to touch. Established practice for coding agents is an
   * explicit per-task "Files in Scope" list — "a curated allowlist is a small blast radius
   * written down" — and to "explicitly expose only the directories it needs."
   *
   * Enforced at the DECLARATION, not the write: a plan naming a file outside these regions is
   * refused as a plan, with the offending path named, rather than being caught later as a
   * write. `WriteGrant` already covers the write.
   *
   * Omit ⇒ unconstrained, exactly as before. Setting `["*"]` is the explicit way to say the
   * same thing.
   *
   * HONEST LIMIT: this constrains a CONFUSED agent, not a COMPROMISED one — the plan and the
   * allowlist live in the same process (R35-narrow). It is a blast-radius control, not a
   * security boundary.
   */
  readonly allowedPaths?: readonly string[];
}

export interface KeepPipelineGitDeps {
  readonly git: GitAdapter;
  readonly baseBranch: string;
  readonly remoteConfig?: RemoteConfig;
  /** Optional PR port. Defaults to LocalPullRequest. */
  readonly prPort?: PullRequestPort;
  /** AM2: the governed merge capability. Only reachable via an autonomous-merge verdict. Omit → no auto-merge. */
  readonly mergePort?: MergePort;
}

export interface SolveToPrOptions extends SolvePipelineOptions {
  /** The autonomous-merge envelope (what may merge without a human). Defaults to DEFAULT_MERGE_ENVELOPE. */
  readonly mergeEnvelope?: MergeEnvelope;
  /** The project root untrusted test execution is scoped to (isolation). Default ".". */
  readonly projectDir?: string;
  /** Explicit top-level non-Git inputs required by the test command (for example `node_modules`).
   * Firecracker measures all their bytes; Git publication refuses every ignored path not beneath this set. */
  readonly executionAuxiliaryRoots?: readonly string[];
  /** AM3: bounded outer re-solves for an unverified result before abandoning (helps stochastic models). Default 0
   *  — the inner repair loop already retries deterministically. Never bypasses a human gate for consequential work. */
  readonly maxAutoRetries?: number;
  /** Operator autonomy level for the oversight router. Defaults to "approver" (gate everything). */
  readonly autonomyLevel?: AutonomyLevel;
  /** F2: classes with a human-authorized reduced-escalation policy (from app.calibrationWire.activePolicyGates()). */
  readonly reducedEscalationClasses?: ReadonlySet<string>;
  /** Fan-in per file from the code graph (blast-radius signal), if available. */
  readonly fanIn?: Readonly<Record<string, number>>;
  /**
   * Optional authorization envelope. Omit → SafetyRail synthesizes a conservative default restrictive
   * one (Fork C, secure-by-default). N=1 / free-tier works out of the box, safely.
   */
  readonly envelope?: AuthorizationEnvelope;
  /** Agent id for the killswitch check. Defaults to the issue id. */
  readonly agentId?: string;
  /**
   * A separate, audited break-glass grant (Fork A). Can relax the vetting VERDICT only — NEVER the
   * human merge gate. Not a config flag; a distinct object with operator + reason + expiry.
   */
  readonly breakGlass?: BreakGlassGrant;
  /**
   * BUILD-ORDER 2.4 — a recorded, accountable acknowledgment of THIS run's merge decision. Only meaningful
   * for a `human-merge` verdict: on a CONSEQUENTIAL human-merge it satisfies the delivery-receipt (the
   * gated merge may then proceed with EVIDENCE the human engaged); its `decisionId` must match this
   * decision (mergeDecisionId), or it is stale and does not satisfy. Absent ⇒ an un-acknowledged
   * surfacing is durably recorded — a consequential one is held; a reversible one proceeds (documented).
   */
  readonly mergeReceipt?: ComprehensionReceipt;
  /**
   * BUILD-ORDER 2.4 — an operator-DECLARED allowance loosening a consequential delivery-receipt to
   * accept-and-document (proceed + record the un-acknowledged surfacing). Additive: it can only loosen a
   * consequential gate, never tighten reversible work, and it is never a silent default.
   */
  readonly receiptAllowance?: boolean;
}

export interface SolveToPrResult {
  readonly solveResult: SolveResult;
  /** The published PR (with the oversight decision attached), if a passing patch was produced. */
  readonly published?: PublishResult;
  readonly manifest?: PrManifest;
  /** AM1: the authoritative merge-authority decision (autonomous-merge / human-merge / abandon-retry / block). */
  readonly mergeAuthority?: MergeAuthorityDecision;
  /**
   * BUILD-ORDER 2.4 — the per-consequence comprehension-receipt decision bound to the human-facing merge
   * seam. `not-required` for anything the machine auto-resolves (front-of-house unchanged); on a human-
   * merge it is `delivery-receipt` (consequential — `mayProceed` false until an acknowledgment bound to
   * this decision is recorded) or `accept-and-document` (reversible — recorded, never blocked). This is a
   * durable spine audit fact, surfaced here for callers/landers to consult.
   */
  readonly comprehensionReceipt?: ComprehensionReceiptDecision;
  /** AM2: the outcome of the governed autonomous merge, if one was attempted. */
  readonly autoMerge?: AutonomousMergeResult;
  /** Durable publication attempts reconciled before this solve was allowed to begin. */
  readonly publicationRecovery?: readonly PublicationRecoveryResult[];
  /** AM3: set when a reversible, unverified change was auto-abandoned instead of bothering a human. */
  readonly abandoned?: { readonly reason: string; readonly retriesUsed: number };
  /**
   * The safety-rail outcome. If the pipeline refused before solving (killswitch/authorization), this
   * carries the reason and there is no solveResult patch. If vetting did not clear, the PR is still
   * created but forced to human review (never auto-approved).
   */
  readonly safety?: {
    readonly refusedBeforeSolve?: RailDecision;
    readonly planVetting?: PlanVetDecision;
    readonly trajectory?: TrajectoryDrift;
    readonly selfHealing?: RemediationOutcome;
    readonly decisionBrief?: DecisionBrief;
    readonly patchForecast?: ForecastVerdict;
    readonly brainCapability?: import("../cascade/verification_harness.js").BrainCapability;
    readonly isolationTier?: IsolationTier;
    readonly vettingCleared?: boolean;
    readonly vettingViaBreakGlass?: boolean;
    readonly vettingReason?: string;
  };
}

/** A SolveResult for a run refused before solving (killswitch/authorization). */
function gaveUp(issueId: string, reason: string): SolveResult {
  return { issueId, solved: false, stagesRun: [], repairRounds: 0, gaveUpReason: reason };
}

/**
 * The end-to-end pipeline. Construct once with the ports; call solveIssueToPR per issue.
 */
export class KeepPipeline {
  private readonly localizer: Localizer;
  private readonly governance: GovernanceLedger;
  private readonly safetyRail: SafetyRail;
  /** The (optionally resilient) model actually used by the solve pipeline. */
  private readonly model: ModelProvider;
  /** Pre-solve plan gate (LogicVet). Both plan- and patch-vetting run; they are not exclusive. */
  private readonly planVetter: (issue: Issue) => Promise<PlanVetDecision>;
  /** Deterministic self-heal-before-route (16.9a). Default-on with the narrowest-safe rule set. */
  private readonly safeRemediation: SafeRemediation;
  private readonly patchForecast: CompositionalForecast;
  private readonly brainCapability: import("../cascade/verification_harness.js").BrainCapability;
  private readonly isolationTier: IsolationTier;
  /**
   * BUILD-ORDER 1.7 — the ONE run-local attestation channel. The executor EMITS a signed attestation of the
   * tier it really ran (via `attestor`); this pipeline VERIFIES it (via `verifier`) before the tier grants an
   * autonomy ceiling. The HMAC key is fresh per pipeline instance and never leaves the process.
   */
  private readonly attestor: IsolationAttestor;
  private readonly verifier: IsolationVerifier;
  /** Holds the in-flight patch-verifier input (solve result + issue text) for the default vetter. */
  private currentPatchInput: PatchVerifierInput | undefined;
  /** Minted only when the operator supplies a registry. Absent ⇒ the undefined contract is preserved. */
  private readonly solveIdentity: AgentIdentity | undefined;

  constructor(private readonly deps: KeepPipelineDeps) {
    // Default to the on-device graph localizer (increment 14), optionally with a semantic embedder.
    this.localizer = deps.localizer ?? new GraphLocalizer(deps.embedder ? { embedder: deps.embedder } : {});
    // Governance/safety rails are DEFAULT-ON (increment 16.6, SOTA: enforcement is structural, not
    // opt-in). The rail is always constructed — even at N=1 — so the safe path is what you get by
    // doing nothing. Vetting is fail-closed: absent deps.vet → the rail forces human review.
    this.governance = deps.governance ?? new GovernanceLedger(deps.spine);
    // Vetting default: if the operator supplies no custom vet fn, use the real VerificationCascade
    // patch-vetter (sound tier over the patch's validation outcome) — NOT merely fail-closed-to-human.
    // The rail is still fail-closed around it (a throw → not cleared).
    this.model = deps.routedModel
      ? new RoutedModelProvider(deps.spine, deps.routedModel)
      : (deps.brainRungs && deps.brainRungs.length > 0)
      ? new ResilientModelProvider([{ id: deps.model.name, cost: deps.model.isLocal ? "local" : "paid", provider: deps.model }, ...deps.brainRungs], {}, deps.spine)
      : deps.model;
    const vetPatchFn = deps.vet ?? defaultPatchVetter(() => this.currentPatchInput);
    this.safetyRail = new SafetyRail({
      spine: deps.spine,
      governance: this.governance,
      ...(deps.killSwitch ? { killSwitch: deps.killSwitch } : {}),
      vetPatchFn,
    });
    // Pre-solve plan gate is DEFAULT-ON too (both gates run). Custom override via deps.planVet.
    this.planVetter = deps.planVet ?? defaultPlanVetter();
    // Deterministic self-heal-before-route (16.9a), default-on, audited. Custom via deps.safeRemediation.
    this.safeRemediation = deps.safeRemediation ?? new SafeRemediation({ governance: this.governance });
    this.patchForecast = new CompositionalForecast("patch-time");
    this.brainCapability = deps.brainCapability ?? "lean";
    this.isolationTier = deps.isolationTier ?? "process";
    // BUILD-ORDER 1.7 — mint the run-local attestation channel (executor emits, this pipeline verifies).
    const trustedMicrovmPolicyDigest = deps.microvmMeasurementPolicyAuthority
      ? verifiedMicrovmMeasurementPolicyAuthorityDigest(deps.microvmMeasurementPolicyAuthority)
      : undefined;
    const attestationChannel = createRunAttestationChannel({
      ...(trustedMicrovmPolicyDigest ? { trustedMicrovmMeasurementPolicyDigests: [trustedMicrovmPolicyDigest] } : {}),
    });
    this.attestor = attestationChannel.attestor;
    this.verifier = attestationChannel.verifier;
    // Mint ONLY from an operator-supplied registry (see the dep docstring). Scope "*" is inert on
    // this path — authorizeEffect has no caller (Z99) — so this is a revocation handle, not a
    // scope enforcer, and it is labelled that way rather than implying enforcement it lacks.
    this.solveIdentity = deps.identityRegistry?.mint(KEEP_SOLVE_IDENTITY_ID, ["*"]);
  }

  /**
   * BIND-DEFAULT-EXECUTION-PATH (BUILD-ORDER 1.1) — the byte-level execution boundary the pipeline binds
   * BY DEFAULT. Returns the operator's FileTree realpath-jailed to the project dir, so with NO
   * configuration a solve/apply cannot read or write outside the project (a refused write never lands on
   * the filesystem). Composes the isolation executor's own realpath jail (`jailedTree` ⇒
   * `resolvedWithinProject`) — one boundary, not a forked second. `jailedTree` is idempotent, so an
   * already-jailed operator tree is not double-wrapped. A hard default: the `FileTree` port is repo
   * content, which never legitimately targets outside the project; the operator-declared outside-project
   * allowance is additive and lives at the execution/namespace layer, never as a weaker default here.
   */
  executionTree(projectDir: string): FileTree {
    return jailedTree(this.deps.tree, projectDir);
  }

  /** Build the SolvePipeline with the wired localizer + ports. */
  /**
   * BUILD-ORDER 1.3c — WIRING (ledger 298): SELECT the strongest available isolation executor. When the
   * operator supplies detected `isolationCapabilities`, `selectExecutor` engages the strong-tier
   * `BoundaryExecutor` where a real runtime (gVisor/container) backs the claim — otherwise the round-1.3
   * process floor. Neutering this to always `new ProcessIsolationExecutor(...)` makes the pipeline STOP
   * selecting the strong executor where available → the strong-tier wiring proof reddens (RED).
   */
  private resolveIsolationExecutor(): IsolatedExecutor {
    const caps = this.deps.isolationCapabilities;
    if (!caps) return new ProcessIsolationExecutor(this.deps.spine);
    return selectExecutor(caps, {
      spine: this.deps.spine,
      ...(this.deps.strongBoundary?.boundaryRun ? { boundaryRun: this.deps.strongBoundary.boundaryRun } : {}),
      ...(this.deps.strongBoundary?.detectRuntime ? { detectRuntime: this.deps.strongBoundary.detectRuntime } : {}),
      ...(this.deps.strongBoundary?.container ? { container: this.deps.strongBoundary.container } : {}),
      ...(this.deps.strongBoundary?.detectMicrovm ? { detectMicrovm: this.deps.strongBoundary.detectMicrovm } : {}),
      ...(this.deps.strongBoundary?.microvm ? { microvm: this.deps.strongBoundary.microvm } : {}),
      // BUILD-ORDER 1.5 — the Windows Job Object floor (win32-gated inside selectExecutor).
      ...(this.deps.strongBoundary?.platform ? { platform: this.deps.strongBoundary.platform } : {}),
      ...(this.deps.strongBoundary?.detectWindows ? { detectWindows: this.deps.strongBoundary.detectWindows } : {}),
      ...(this.deps.strongBoundary?.windows ? { windows: this.deps.strongBoundary.windows } : {}),
      ...(this.deps.strongBoundary?.windowsBoundaryRun ? { windowsBoundaryRun: this.deps.strongBoundary.windowsBoundaryRun } : {}),
    });
  }

  private makeSolvePipeline(opts: SolvePipelineOptions, runner: TestRunner): SolvePipeline {
    // WIRING (ledger 298): the default execution path selects the ENFORCING tree — the realpath project
    // jail — not the raw operator tree. Neutering this to `this.deps.tree` reddens the wiring proof.
    const projectDir = (opts as SolveToPrOptions).projectDir ?? ".";
    return new SolvePipeline({
      spine: this.deps.spine,
      ledger: new RollbackLedger(this.deps.spine),
      tree: this.executionTree(projectDir),
      runner,
      localizer: this.localizer,
      model: this.model,
      ...(this.deps.vet ? { vet: this.deps.vet } : {}),
      ...(this.deps.withinBudget ? { withinBudget: this.deps.withinBudget } : {}),
      // ROUND 35: both fields, or neither. reversible_execution.ts computes
      //   identityLive = registry && identity ? authorize(identity).authorized : undefined
      // so supplying one alone would silently keep the switch unarmed.
      ...(this.deps.identityRegistry && this.solveIdentity
        ? { identity: this.solveIdentity, identityRegistry: this.deps.identityRegistry }
        : {}),
      ...(this.deps.allowedPaths ? { allowedPaths: this.deps.allowedPaths } : {}),
    }, { ...opts, ...(this.deps.forbiddenActions ? { forbiddenActions: this.deps.forbiddenActions } : {}) });
  }

  /**
   * Production recovery entrypoint. It reconstructs the verifier from each sealed attempt's exact repository and
   * project identities; callers do not supply mutable issue context to reinterpret an old publication.
   */
  async reconcilePublications(git: KeepPipelineGitDeps, agentId = KEEP_SOLVE_IDENTITY_ID): Promise<readonly PublicationRecoveryResult[]> {
    const mergePort = git.mergePort ?? (git.remoteConfig?.remote
      ? new GitMergePort(git.git, { pushRemote: git.remoteConfig.remote, ...(git.remoteConfig.expectedFetchUrlSha256 ? { expectedFetchUrlSha256: git.remoteConfig.expectedFetchUrlSha256 } : {}), ...(git.remoteConfig.expectedPushUrlSha256 ? { expectedPushUrlSha256: git.remoteConfig.expectedPushUrlSha256 } : {}), publicationSpine: this.deps.spine })
      : undefined);
    if (!mergePort) {
      const hold = missingPublicationActuatorRecoveryHold(this.deps.spine, this.deps.publicationOperatorTrust);
      return hold ? Object.freeze([hold]) : Object.freeze([]);
    }
    const isoExecutor = this.deps.isolationExecutor ?? this.resolveIsolationExecutor();
    const recoveryPaused = () => this.deps.killSwitchEngaged?.() === true || this.deps.killSwitch?.isTerminated(agentId) === true;
    const executor = new AutonomousMergeExecutor({
      port: mergePort,
      spine: this.deps.spine,
      postMergeVerify: async (spec) => {
        const isolatedRunner = new IsolatedTestRunner(this.deps.runner, isoExecutor, spec.projectDir, () => "medium");
        const res = await isolatedRunner.run(spec.repoRef);
        const appraisal = appraisePostMergeRun(res);
        const attestation = isoExecutor.attest?.(this.attestor, spec.projectDir, Date.now());
        const verification = this.verifier.verify(attestation);
        return {
          ...appraisal,
          ...(verification.ok && verification.verifiedTier === "microvm" && verification.verifiedProjectManifestDigest && verification.verifiedGuestExecutionRequestDigest
            ? { verifiedProjectManifestDigest: verification.verifiedProjectManifestDigest, verifiedGuestExecutionRequestDigest: verification.verifiedGuestExecutionRequestDigest, ...(verification.executionSubjectAuthority ? { executionSubjectAuthority: verification.executionSubjectAuthority } : {}) }
            : {}),
        };
      },
      killSwitchEngaged: recoveryPaused,
      ...(this.deps.publicationOperatorTrust ? { publicationOperatorTrust: this.deps.publicationOperatorTrust } : {}),
    });
    return await executor.reconcileOutstandingPublications();
  }

  /**
   * Solve an issue and (if solved) publish a human-reviewable PR with a risk-tiered oversight decision.
   * The one call an operator makes. Never merges.
   */
  async solveIssueToPR(issue: Issue, files: readonly RepoFile[], git: KeepPipelineGitDeps, opts: SolveToPrOptions = {}): Promise<SolveToPrResult> {
    const agentId = opts.agentId ?? issue.id;

    // Recover durable in-doubt publications before admitting any new work on the same serial publication lane.
    // A held/adverse result blocks this solve; determinate completed recovery is surfaced and normal work continues.
    let publicationRecovery: readonly PublicationRecoveryResult[];
    try { publicationRecovery = await this.reconcilePublications(git, agentId); }
    catch (error) {
      return { solveResult: gaveUp(issue.id, `publication recovery refused before solve: ${(error as Error).message}`) };
    }
    const blockingRecovery = publicationRecovery.find((row) => row.needsHuman || row.status === "uncertain" || row.status === "failed" || row.status === "refused");
    if (blockingRecovery) {
      return { solveResult: gaveUp(issue.id, `publication recovery held the serial merge lane: ${blockingRecovery.reason}`), publicationRecovery };
    }

    // ── Stage 0: killswitch (refuse to run if tripped) ──
    const killCheck = this.safetyRail.checkKillswitch(agentId);
    if (killCheck.outcome === "block-killed") {
      return { solveResult: gaveUp(issue.id, killCheck.reason), safety: { refusedBeforeSolve: killCheck } };
    }

    // ── Stage 1: authorization (deny-by-default; synthesize default restrictive envelope at N=1) ──
    const authz = await this.safetyRail.authorize(agentId, opts.envelope, issue.repoRef);
    if (authz.outcome === "deny") {
      return { solveResult: gaveUp(issue.id, authz.reason), safety: { refusedBeforeSolve: authz } };
    }

    // ── Stage 1.5: PRE-SOLVE plan vetting (consequence analysis). Both gates run. Fail-closed. ──
    const planVet = await this.planVetter(issue);
    this.governance.record({
      action: "vet.plan", actor: "keep-pipeline",
      policy: { effect: planVet.decision === "pass" ? "allow" : planVet.decision === "block" ? "deny" : "warn", ruleId: "plan-consequence-analysis", reason: planVet.reason, matchedRuleIds: ["plan-consequence-analysis"], policyVersion: "1" },
      outcome: planVet.decision === "pass" ? "proceeded" : planVet.decision === "block" ? "blocked" : "escalated-to-human",
    });
    if (planVet.decision === "block") {
      return { solveResult: gaveUp(issue.id, `plan vetting blocked: ${planVet.reason}`), safety: { planVetting: planVet } };
    }
    // An `escalate`/rework verdict proceeds but FORCES the PR to human review (never auto-approvable).
    const planEscalated = planVet.decision === "rework";

    // ── Isolation: wrap the test runner so every untrusted execution is scoped to the project dir and
    // audited, inside the selected tier. Fail-closed (a refused/escaping run is a runner error, never a green). ──
    const isoExecutor = this.deps.isolationExecutor ?? this.resolveIsolationExecutor();
    const isolatedRunner = new IsolatedTestRunner(this.deps.runner, isoExecutor, opts.projectDir ?? ".", () => "medium");

    // ── Stage 2: solve, with a bounded outer re-solve for an unverified result. The inner repair loop already
    // iterated the edit; an outer re-solve tries a fresh approach (useful for stochastic production models). It
    // never bypasses a human gate — consequential changes still route to a human at the verdict stage below. ──
    const pipeline = this.makeSolvePipeline(opts, isolatedRunner);
    const maxRetries = Math.max(0, opts.maxAutoRetries ?? 0);
    let solveResult = await pipeline.run(issue, files);
    let outerRetries = 0;
    while (outerRetries < maxRetries && !solveResult.prProposal && solveResult.recovery?.status === "ready" && (!solveResult.solved || !(solveResult.validation?.testsPassed ?? false))) {
      outerRetries++;
      this.deps.spine.stage({ type: "identity.action", actor: "keep-pipeline", payload: { event: "solve_retry", issueId: issue.id, attempt: outerRetries, ts: Date.now() } });
      const currentFiles = await Promise.all(files.map(async file => ({ ...file, content: await this.deps.tree.read(file.path) ?? file.content })));
      solveResult = await pipeline.run(issue, currentFiles);
    }

    // A test-passing, vet-refused proposal is not solved, but must still reach the
    // existing governed human/break-glass path. Never retry that authority decision.
    if (!solveResult.prProposal || !solveResult.validation?.testsPassed) {
      return { solveResult };
    }

    // ── Stage 3: vet the produced patch (fail-closed; break-glass can relax the verdict, Fork A) ──
    this.currentPatchInput = { solveResult, issueText: issue.text };
    let vet = await this.safetyRail.vetPatch(issue.repoRef, opts.breakGlass);
    let effectiveResult = solveResult;
    let remediation: RemediationOutcome | undefined;

    // ── Stage 3.25: SELF-HEAL BEFORE ROUTING (16.9a). If vetting didn't clear, try a deterministic,
    // provably-safe narrowing instead of routing to a (likely rubber-stamping) human. Never heals
    // forbidden classes; the narrowed patch must independently re-clear; audited with a rollback id. ──
    if (!vet.cleared) {
      const loc = await this.localizer.localize(issue, files, 8);
      const suspectPaths = loc.suspects.map((s) => s.path);
      remediation = this.safeRemediation.remediate({
        issueId: issue.id,
        input: { solveResult, issueText: issue.text },
        verdict: verifyPatch({ solveResult, issueText: issue.text }),
        suspectPaths,
      });
      if (remediation.healed && remediation.healedResult) {
        // Proceed with the healed (narrowed) patch and re-vet it through the rail (independent).
        effectiveResult = remediation.healedResult;
        this.currentPatchInput = { solveResult: effectiveResult, issueText: issue.text };
        vet = await this.safetyRail.vetPatch(issue.repoRef, opts.breakGlass);
      }
    }

    // ── Stage 3.5: TRAJECTORY checkpoint — did the patch drift beyond what the plan approved? ──
    // Second-order effects are a trajectory property; a patch can do more than the pre-solve plan gate
    // approved. Escalate on drift even if tests pass (catches the canonical cascade chain). Deterministic.
    const planApprovedClasses = (planVet.consequences?.effects ?? []).map((e) => e.cls);
    const drift = checkTrajectoryDrift(planApprovedClasses, effectiveResult.prProposal?.edits ?? []);
    this.governance.record({
      action: "vet.trajectory", actor: "keep-pipeline",
      policy: { effect: drift.drifted ? "warn" : "allow", ruleId: "trajectory-drift", reason: drift.reason, matchedRuleIds: ["trajectory-drift"], policyVersion: "1" },
      outcome: drift.drifted ? "escalated-to-human" : "proceeded",
    });

    // ── Stage 3.6: PATCH-TIME forecast (bespoke) — compositional forward projection on the ACTUAL edits ──
    // Richer than the plan-time forecast: real derived effects + directionality (a net-removed sink is
    // downgraded). Catches compositions (auth+egress, dep+egress, ...) that are benign in isolation.
    const patchEffects = deriveEffectsFromEdits((effectiveResult.prProposal?.edits ?? []).map((e) => ({ file: e.file, replace: e.replace })));
    const patchForecast = this.patchForecast.project(patchEffects);
    this.governance.record({
      action: "vet.patch-forecast", actor: "keep-pipeline",
      policy: { effect: patchForecast.decision === "escalate" ? "warn" : "allow", ruleId: "patch-forecast", reason: patchForecast.reason, matchedRuleIds: ["patch-forecast"], policyVersion: "1" },
      outcome: patchForecast.decision === "escalate" ? "escalated-to-human" : "proceeded",
    });

    // ── Stage 4: publish as a human-gated PR with risk-tiered oversight ──
    const remote = new GitRemote(git.git, git.remoteConfig ?? {});
    const prPort = git.prPort ?? new LocalPullRequest();
    const assessor = new PrRiskAssessor();
    const router = new OversightRouter({ autonomyLevel: opts.autonomyLevel ?? "approver", ...(opts.reducedEscalationClasses ? { reducedEscalationClasses: opts.reducedEscalationClasses } : {}) });

    // Force human review if patch vetting didn't clear, OR the plan escalated, OR the patch drifted, OR
    // the patch-time forecast reaches a bad sink.
    // ── Isolation → autonomy feedback (17): the weaker the isolation the AI-generated code ran under, the
    // more we route to a human, because a bad patch has a larger blast radius on escape. A "full" ceiling
    // (microVM/gVisor) leaves the normal gate; weaker ceilings suppress auto-approval.
    // ROUND 43 — the autonomy ceiling comes from the WEAKER of the declared tier and the tier
    // that actually ran, because a declaration is not evidence.
    //
    // MEASURED: `isolationTier` (line ~279) and `isolationExecutor` (line ~341) are independent
    // inputs and nothing compared them. Declaring `microvm` while `ProcessIsolationExecutor` ran
    // the tests granted the `full` ceiling — auto-approval, and so NO decision brief — purely on
    // the claim. Declaring a STRONGER tier made Keep LESS careful, which is a reward pointing
    // exactly the wrong way.
    //
    // Taking the minimum can only ever lower the ceiling relative to what is enforced, never
    // raise it, so an honest declaration costs nothing and a false one buys nothing.
    //
    // BUILD-ORDER 1.7 (BIND-EXECUTOR-TIER-ATTESTATION) — Z193: `isoExecutor.tier` was STILL the executor's
    // WORD (a class field). A mislabelled/swapped executor constructing `BoundaryExecutor("microvm", …)`
    // over the process floor bought the `full` ceiling on the label alone — the confused-deputy shape at
    // its last isolation-stack instance. Now the executor EMITS a signed attestation of the tier it really
    // ran + the MEASURED evidence, and this pipeline VERIFIES it: the effective actual-tier is what the
    // verifier RECOMPUTES from evidence (a forged-up tier caps DOWN to the proven tier; an absent/tampered
    // attestation → "none", no autonomy), never the stamped label. Neutering this back to
    // `weakerTier(this.isolationTier, isoExecutor.tier)` re-trusts the word → the wiring proof reddens (ledger 298).
    const attestation = isoExecutor.attest?.(this.attestor, opts.projectDir ?? ".", Date.now());
    const verification = this.verifier.verify(attestation);
    const effectiveTier = weakerTier(this.isolationTier, verification.verifiedTier);
    // BUILD-ORDER 2.3 (REVISIT-ISOLATION-GATING) — Z187: the autonomy ceiling is RE-DERIVED from the MEASURED
    // evidence (the 1.7 verifier's `verifiedTier` + `measuredDegradations`), not the tier label via the
    // static table. Re-measured this round: the 1.3 jail / 1.5 Job Object are CAPABILITIES, not the default
    // wiring, so the default process floor's evidence still recomputes to bare `process` → `minimal`
    // (unchanged, now evidence-bound not stale-asserted). A DEGRADED default run (net-deny unenforceable,
    // Job Object degraded) drops the ceiling one rung, so the merge gate below EXTENDS to the real boundary.
    // WIRING (ledger 298): neutering this back to `isolationAutonomyCeiling(effectiveTier)` re-reads the
    // static LABEL table and ignores the measured degradations → a degraded run buys the clean ceiling → RED.
    const isolationCeiling = isolationCeilingFromEvidence({ verifiedTier: effectiveTier, measuredDegradations: verification.measuredDegradations });
    const isolationPermitsAuto = isolationCeiling === "full";
    // ROUND 41 — an inert safety control also suppresses auto-approval, so the neutral decision
    // brief below is actually built.
    //
    // FOUND BY SWEEPING FOR OTHER CONSUMERS (Z172), not by design: wiring `inertControls` into
    // merge authority summoned a human, and this second decision still ignored it — so under
    // `microvm` isolation the run produced `human-merge` with the decision brief **ABSENT**.
    // Measured. A person was called in to own a merge and handed nothing to reason from, which is
    // the rubber-stamping the brief exists to prevent.
    //
    // Note the shape of the near-miss: the stronger the isolation, the more auto-approvable a run
    // is — correct when the isolation is the reason, wrong when the reason is a barrier switched
    // off. Two independent decisions consumed the same fact and only one had been told.
    const controlsInert = (effectiveResult.inertControls?.length ?? 0) > 0;
    const autoApprovable = vet.cleared && !planEscalated && !drift.drifted && patchForecast.decision !== "escalate" && isolationPermitsAuto && !controlsInert;

    // Build a NEUTRAL decision brief for the residual that routes to a human (non-persuasive: facts to
    // verify, not conclusions to accept — persuasive narratives increase rubber-stamping).
    const brief = autoApprovable ? undefined : buildDecisionBrief({
      issueText: issue.text,
      editFiles: [...new Set((effectiveResult.prProposal?.edits ?? []).map((e) => e.file))],
      ...(planVet.consequences ? { consequences: planVet.consequences } : {}),
      trajectory: drift,
      patchVerdict: verifyPatch({ solveResult: effectiveResult, issueText: issue.text }),
      ...(remediation ? { selfHealing: remediation } : {}),
    });

    // ── Merge authority (AM1): the authoritative, consequence-vs-confidence decision on whether this change
    // may merge autonomously, needs a human, should be retried, or is blocked. Computed from the SAME risk +
    // verification signals; audited now. (The physical autonomous merge + auto-revert is AM2.)
    const mergeRisk = assessor.assess({ proposal: effectiveResult.prProposal!, result: effectiveResult, ...(opts.fanIn ? { fanIn: opts.fanIn } : {}) });
    const patchVerdictForMerge = verifyPatch({ solveResult: effectiveResult, issueText: issue.text });
    const looksDestructive = (effectiveResult.prProposal?.edits ?? []).some((e) => e.replace.trim() === "" && e.search.trim().length > 40);
    const mergeAuthority = decideMergeAuthority({
      verification: {
        testsPassed: effectiveResult.validation?.testsPassed ?? false,
        vettingCleared: vet.cleared,
        soundFailure: patchVerdictForMerge.outcome === "fail",
      },
      consequence: {
        // Irreversibility is the hard gate; a large deletion or an escalated plan can't be auto-reverted cleanly.
        actionTier: looksDestructive || planEscalated ? "irreversible" : "reversible-internal",
        consequenceBand: mergeRisk.consequenceBand,
        alwaysGatePath: mergeRisk.forcedGate,
      },
      envelope: opts.mergeEnvelope ?? DEFAULT_MERGE_ENVELOPE,
      // ROUND 41: a safety control switched off makes this consequential, so autonomous merge is
      // suppressed and a person decides. Measured before building: without this, a run under an
      // inert allowlist emitted the warning AND auto-merged — the warning reached nobody,
      // because autonomous merge is precisely the path with no human reader.
      ...(effectiveResult.inertControls?.length ? { inertControls: effectiveResult.inertControls } : {}),
      // ROUND 42: the isolation ceiling reached auto-APPROVAL but never auto-MERGE, so a run
      // under `none` measured as autonomous-merge and merged — while the same tier's ceiling is
      // literally named `refuse-risky`. Only that tier is threaded; `process` and `container`
      // still permit autonomous merge, deliberately (see MergeAuthorityInputs).
      // Only a clean, completed strong boundary may authorize autonomous merge. `minimal` is not a synonym
      // for isolated: a process-scoped run shares the Keep principal and therefore remains human-gated.
      ...(isolationCeiling !== "full" ? { executionUnisolated: true } : {}),
    });
    this.deps.spine.stage({ type: "identity.action", actor: "keep-pipeline", payload: { event: "merge_authority", issueId: issue.id, verdict: mergeAuthority.verdict, reason: mergeAuthority.reason, consequential: mergeAuthority.consequential, verified: mergeAuthority.verified, consequenceBand: mergeRisk.consequenceBand, ts: Date.now() } });

    // ── Comprehension receipt (BUILD-ORDER 2.4, Z176): nothing here proved a human READ the warning.
    // Bind a per-CONSEQUENCE receipt to this seam, COMPOSED with the merge decision's OWN consequence
    // classification (mergeAuthority.consequential — not a second consequence probe). The decisionId
    // matches a receipt to THIS decision (a stale/mismatched receipt does not satisfy). This computes a
    // DECISION (PDP) and RECORDS it as an auditable spine fact — it is NOT the enforcement point. A
    // consequential human-merge decides delivery-receipt (mayProceed:false, recorded); a reversible one is
    // accept-and-document (recorded, never blocked); machine-auto-resolved verdicts demand nothing. Note the
    // "receipt" is an unauthenticated token (a forgeable decisionId match), so it is an audit/decision
    // primitive, not proof a human engaged — enforcement + an authenticated ack are a downstream lander's
    // job (2.4 reframe note at the merge seam). WIRING (ledger 298): neuter the compute/record → the wiring
    // proof reddens.
    const receiptDecisionId = mergeDecisionId(issue.id, mergeAuthority, mergeRisk.consequenceBand);
    const comprehensionReceipt = decideComprehensionReceipt({
      verdict: mergeAuthority.verdict,
      consequential: mergeAuthority.consequential,
      decisionId: receiptDecisionId,
      ...(opts.mergeReceipt ? { receipt: opts.mergeReceipt } : {}),
      ...(opts.receiptAllowance ? { operatorAllowance: opts.receiptAllowance } : {}),
    });
    // Durable audit fact on the spine (not a UI claim). Only where a human owns the merge — the default
    // auto-resolved path stays silent (no habituation-training noise). Records the disposition, whether the
    // gated merge may proceed, and — crucially — the UN-acknowledged surfacing so habituation is auditable.
    if (comprehensionReceipt.disposition !== "not-required") {
      this.deps.spine.stage({ type: "identity.action", actor: "keep-pipeline", payload: {
        event: "comprehension_receipt", issueId: issue.id, decisionId: receiptDecisionId,
        disposition: comprehensionReceipt.disposition, mayProceed: comprehensionReceipt.mayProceed,
        acknowledged: comprehensionReceipt.satisfiedBy !== undefined,
        ...(comprehensionReceipt.satisfiedBy ? { acknowledgedBy: comprehensionReceipt.satisfiedBy.acknowledgedBy } : {}),
        unacknowledgedSurfacing: comprehensionReceipt.recordUnacknowledged,
        reason: comprehensionReceipt.reason, ts: Date.now(),
      } });
    }

    // ── AM3: a reversible, unverified change is never a human's problem. The inner repair loop and any outer
    // re-solves already tried; since it's reversible + low-blast, abandon it with an audit record — do NOT publish
    // a review PR that a human would only rubber-stamp or bottleneck on. (Consequential unverified work took the
    // human-merge branch above, not this one.)
    if (mergeAuthority.verdict === "abandon-retry") {
      this.deps.spine.stage({ type: "identity.action", actor: "keep-pipeline", payload: { event: "solve_abandoned", issueId: issue.id, reason: mergeAuthority.reason, retriesUsed: outerRetries, consequenceBand: mergeRisk.consequenceBand, ts: Date.now() } });
      this.governance.record({
        action: "solve.abandon", actor: "keep-pipeline",
        policy: { effect: "allow", ruleId: "reversible-unverified-abandon", reason: mergeAuthority.reason, matchedRuleIds: ["reversible-unverified-abandon"], policyVersion: "1" },
        outcome: "proceeded",
      });
      return { solveResult: effectiveResult, mergeAuthority, comprehensionReceipt, abandoned: { reason: mergeAuthority.reason, retriesUsed: outerRetries } };
    }

    const published = await publishSolveAsPr(effectiveResult, {
      ...(mergeAuthority.verdict === "human-merge" ? { reviewOnly: true as const } : {}),
      git: git.git,
      remote,
      prPort,
      baseBranch: git.baseBranch,
      oversight: {
        assessor,
        router: autoApprovable ? router : new OversightRouter({ autonomyLevel: "observer" }),
        ...(opts.fanIn ? { fanIn: opts.fanIn } : {}),
      },
    });

    // ── AM2: if the merge authority cleared this for autonomous merge AND a merge port is wired, LAND it
    // through the governed executor — pre-merge re-validation, merge, post-merge regression watch → auto-revert.
    // The executor structurally refuses anything but an autonomous-merge verdict, so nothing consequential can
    // reach it. No port wired → the decision is recorded and the change waits (honest: no merge capability).
    let autoMerge: AutonomousMergeResult | undefined;
    // Candidate publication and base publication must share one remote identity. Silently degrading the
    // base leg to a local-only merge would make the remote CAS/reconciliation closure unreachable.
    const mergePort = git.mergePort ?? (git.remoteConfig?.remote
      ? new GitMergePort(git.git, { pushRemote: git.remoteConfig.remote, ...(git.remoteConfig.expectedFetchUrlSha256 ? { expectedFetchUrlSha256: git.remoteConfig.expectedFetchUrlSha256 } : {}), ...(git.remoteConfig.expectedPushUrlSha256 ? { expectedPushUrlSha256: git.remoteConfig.expectedPushUrlSha256 } : {}), publicationSpine: this.deps.spine })
      : undefined);
    // NOTE (2.4 reframe, ledger 402): this seam RECORDS + SURFACES the receipt decision as an audit fact;
    // it does NOT enforce it. The `&& comprehensionReceipt.mayProceed` conjunct below is redundant on this
    // path — an autonomous-merge verdict always yields `not-required`/mayProceed:true, and the actual hold
    // on a human-merge is the pre-existing structural gate (AutonomousMergeExecutor GATE 1), not this
    // receipt. Enforcing a consequential human-merge's `mayProceed:false` is DEFERRED to a downstream lander
    // (the PEP) that consults the surfaced flag; that lander — plus an AUTHENTICATED acknowledgment (a
    // signed identity, not today's forgeable decisionId match) — is filed for Phase 5.
    if (mergeAuthority.verdict === "autonomous-merge" && comprehensionReceipt.mayProceed) {
      if (!mergePort) {
        autoMerge = {
          status: "refused",
          reason: "autonomous publication requires an explicit remote target; no implicit origin fallback is permitted",
          needsHuman: false,
        };
      } else {
      const measuredProjectDir = realpathSync(opts.projectDir ?? ".");
      // The solve-time run predates publication and cannot authorize a commit that did not yet exist. Run the exact
      // published candidate again, then consume a fresh verifier-owned receipt for those post-commit bytes.
      const candidateRun = await isolatedRunner.run(issue.repoRef);
      const candidateAppraisal = appraisePostMergeRun(candidateRun);
      const candidateAttestation = isoExecutor.attest?.(this.attestor, measuredProjectDir, Date.now());
      const candidateVerification = this.verifier.verify(candidateAttestation);
      const candidateManifestDigest = !candidateAppraisal.regressed && candidateVerification.ok && candidateVerification.verifiedTier === "microvm"
        ? candidateVerification.verifiedProjectManifestDigest
        : undefined;
      const candidateGuestExecutionRequestDigest = candidateVerification.verifiedGuestExecutionRequestDigest;
      const candidateExecutionAuthority = candidateVerification.executionSubjectAuthority;
      if (!candidateManifestDigest || !candidateGuestExecutionRequestDigest || !candidateExecutionAuthority) {
        autoMerge = {
          status: "refused",
          reason: `published candidate has no fresh verifier-owned completed Firecracker identity${candidateAppraisal.detail ? `: ${candidateAppraisal.detail}` : ""}`,
          needsHuman: false,
        };
      } else {
        const executor = new AutonomousMergeExecutor({
        port: mergePort,
        spine: this.deps.spine,
        postMergeVerify: async () => {
          const res = await isolatedRunner.run(issue.repoRef);
          const appraisal = appraisePostMergeRun(res);
          const postMergeAttestation = isoExecutor.attest?.(this.attestor, measuredProjectDir, Date.now());
          const postMergeVerification = this.verifier.verify(postMergeAttestation);
          return {
            ...appraisal,
            ...(postMergeVerification.ok && postMergeVerification.verifiedTier === "microvm" && postMergeVerification.verifiedProjectManifestDigest && postMergeVerification.verifiedGuestExecutionRequestDigest
              ? { verifiedProjectManifestDigest: postMergeVerification.verifiedProjectManifestDigest, verifiedGuestExecutionRequestDigest: postMergeVerification.verifiedGuestExecutionRequestDigest, ...(postMergeVerification.executionSubjectAuthority ? { executionSubjectAuthority: postMergeVerification.executionSubjectAuthority } : {}) }
              : {}),
          };
        },
        ...(this.deps.killSwitchEngaged ? { killSwitchEngaged: this.deps.killSwitchEngaged } : {}),
        ...(this.deps.publicationOperatorTrust ? { publicationOperatorTrust: this.deps.publicationOperatorTrust } : {}),
        });
        autoMerge = await executor.execute(mergeAuthority, {
          issueId: issue.id,
          repoRef: issue.repoRef,
          branch: published.manifest.branch,
          baseBranch: git.baseBranch,
          expectedCandidateCommit: published.commit.artifact,
          expectedCandidateProjectManifestDigest: candidateManifestDigest,
          expectedGuestExecutionRequestDigest: candidateGuestExecutionRequestDigest,
          projectDir: measuredProjectDir,
          ...(opts.executionAuxiliaryRoots ? { executionAuxiliaryRoots: opts.executionAuxiliaryRoots } : {}),
        }, candidateExecutionAuthority);
      }
      }
    }

    // Audit the top-level run (the rail already recorded each gate to the governance ledger + spine).
    this.deps.spine.stage({
      type: "identity.action",
      actor: "keep-pipeline",
      payload: {
        event: "solve_to_pr",
        issueId: issue.id,
        solved: true,
        branch: published.manifest.branch,
        vettingCleared: vet.cleared,
        vettingViaBreakGlass: vet.viaBreakGlass,
        oversightBand: published.manifest.oversight?.band ?? "n/a",
        disposition: published.manifest.oversight?.disposition ?? "n/a",
        requiresImmediateAttention: published.manifest.oversight?.requiresImmediateAttention ?? true,
      },
    });

    return {
      solveResult: effectiveResult,
      ...(publicationRecovery.length > 0 ? { publicationRecovery } : {}),
      published,
      manifest: published.manifest,
      mergeAuthority,
      comprehensionReceipt,
      ...(autoMerge ? { autoMerge } : {}),
      safety: { vettingCleared: vet.cleared, vettingViaBreakGlass: vet.viaBreakGlass, vettingReason: vet.reason, planVetting: planVet, trajectory: drift, ...(remediation ? { selfHealing: remediation } : {}), ...(brief ? { decisionBrief: brief } : {}), patchForecast, brainCapability: this.brainCapability, isolationTier: this.isolationTier },
    };
  }
}
