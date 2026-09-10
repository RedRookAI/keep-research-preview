/**
 * SolvePipeline: issue + result model (Increment 13a).
 *
 * SOTA basis (2026-08-05): the canonical scaffold is Agentless's fixed localize → repair → validate
 * pipeline (adopted by OpenAI/Meta/DeepSeek). The decisive robustness choice (SWE-RL / Agentless Mini
 * / SWE-Fixer): the repair phase predicts SEARCH/REPLACE edits conditioned on file content, NOT raw
 * unified-diff line numbers — line-number diffs are the #1 patch-application failure mode (PAGENT).
 * So the edit format here is search/replace: find an exact code block, replace it. This applies
 * deterministically and reliably, which is exactly what we need to prove the machine here.
 *
 * The pipeline returns a PR PROPOSAL for the human merge gate — never auto-merges. Zero deps.
 */

import type { ProjectJobActivityTracker } from "../session/project_job_journal.js";
import type { TaskMemoryContext, TaskMemoryEmbeddingControls } from "../memory/task_context.js";

/** A ticket/issue to solve. */
export interface Issue {
  readonly id: string;
  /** The problem statement (issue body). */
  readonly text: string;
  /** Opaque reference to the working tree / repo this issue targets. */
  readonly repoRef: string;
  /** Optional caller hints (e.g. suspected area) — never required. */
  readonly hints?: Readonly<Record<string, unknown>>;
}

/** One search/replace edit: replace an EXACT block of text in a file with new text. */
export interface SearchReplaceEdit {
  readonly file: string;
  /** The exact text to find (must match verbatim, once). Line-number-independent. */
  readonly search: string;
  /** The replacement text. */
  readonly replace: string;
  /** Why this edit (for the audit trail + PR body). */
  readonly intent: string;
}

/** A structured edit plan the repair phase produces. */
export interface EditPlan {
  readonly edits: readonly SearchReplaceEdit[];
  /** Plain-language rationale for the whole plan (for the PR). */
  readonly rationale: string;
  /** Frozen, untrusted goal-specific test body; no commands, permissions or dependencies. */
  readonly goalCheck?: { readonly body: string; readonly requestSha256: string };
}

/**
 * A content-bound edit proposal prepared by a durable project stage. It carries no write
 * authority: SolvePipeline rechecks every binding against fresh bytes and remains the only
 * component allowed to vet, apply, validate, repair, and govern the edit.
 */
export interface AdmittedEditPlan {
  readonly schemaVersion: 1;
  readonly mechanism: "project-edit-stage";
  readonly repositoryRef: string;
  readonly repositoryTreeSha256: string;
  readonly allowedFiles: readonly string[];
  readonly allowedFileSha256: Readonly<Record<string, string>>;
  readonly taskId: string;
  readonly planStepId: string;
  readonly generation: {
    readonly model: string;
    readonly tokensIn: number;
    readonly tokensOut: number;
  };
  readonly plan: EditPlan;
}

/** Ephemeral host-owned planning capability. Never serialize this into project state. */
export interface AdmittedEditPlanningContext {
  /** Ephemeral current original-command authority; independent of optional memory. */
  readonly assertAuthority?: () => void;
  readonly memoryContext?: TaskMemoryContext;
  readonly signal: AbortSignal;
  readonly reserveCall: (inputBytes: number) => Promise<boolean>;
  readonly reserveEmbedding?: TaskMemoryEmbeddingControls["reserve"];
  readonly observe: (event: Readonly<Record<string, unknown>>) => void;
}

export interface SolveExecutionContext {
  /** Host-owned live authority fence. Never sourced from or serialized into model data. */
  readonly assertAuthority?: () => void;
  /** Attenuation only: prepare unexecuted data under the existing budget; never apply or run tests. */
  readonly executionCeiling?: "prepare";
  readonly memoryContext?: TaskMemoryContext;
  /** Ephemeral operator cancellation; never persisted as authority or a resume permit. */
  readonly signal?: AbortSignal;
  readonly trackActivity?: ProjectJobActivityTracker;
  readonly admittedEdit?: AdmittedEditPlan;
  /** Prepare under the canonical attempt's budget, not before it. Trusted host port. */
  readonly prepareAdmittedEdit?: (context: AdmittedEditPlanningContext) => Promise<AdmittedEditPlan>;
  /** Stable owner-initiated project run, not a retry, source hash, or model proposal. */
  readonly recoveryOperationId?: string;
  /** Trusted host reconciliation only; never populated from model output. */
  readonly recoveryReconciliation?: { readonly attemptId: string; readonly evidenceId: string };
  readonly recoveryDiagnosis?: { readonly holdId: string; readonly evidenceId: string };
}

export interface ProjectEditEffectReceipt {
  readonly schemaVersion: 1;
  readonly admissionSha256: string;
  /** Exact whole-repository identity after every retained initial and repair edit. */
  readonly repositoryTreeAfterSha256: string;
  readonly touchedFiles: readonly { readonly path: string; readonly beforeSha256: string; readonly afterSha256: string }[];
  readonly rollbackIds: readonly string[];
  readonly applied: true;
  readonly testsExecuted: true;
}

/** The result of applying an edit plan to the working tree. */
export interface PatchApplyResult {
  readonly applied: boolean;
  /** Per-edit outcomes (matched/ambiguous/not-found). */
  /**
   * ROUND 34: `held` added when the envelope became the default. A policy hold is NOT
   * "not-found" — the file was found and the edit was well-formed; a barrier refused it.
   * Reporting a hold as not-found was survivable while the envelope was off and holds
   * never happened in production. Flipping the default makes that mislabel the FIRST
   * thing an operator sees when a safety hold fires, which is exactly when the report
   * must be accurate.
   */
  readonly perEdit: readonly { file: string; status: "applied" | "not-found" | "ambiguous" | "held"; reason?: string }[];
  /** A rollback id registered in the RollbackLedger, if anything was applied. */
  readonly rollbackId?: string;
}

/** The test/validation oracle outcome. */
export interface ValidationOutcome {
  readonly processIsolation?: import("../infra/isolation_backend.js").ProcessIsolationObservation;
  readonly testsPassed: boolean;
  /** Count from the same oracle invocation; avoids rerunning solely for regression tracking. */
  readonly passedCount?: number;
  readonly passedTests?: readonly string[];
  /** Trusted runner classification, never inferred from model prose or keywords. */
  readonly failureKind?: "product" | "transient" | "harness" | "authority" | "ambiguous" | "unknown";
  /** Names/count of failing tests, for the repair loop to condition on. */
  readonly failures: readonly string[];
  /** Whether the verification cascade + logic vetting also cleared. */
  readonly vettingCleared: boolean;
  readonly detail: string;
}

/** A PR proposal — the human merge gate consumes this; Keep never auto-merges. */
export interface PrProposal {
  readonly title: string;
  readonly body: string;
  readonly branch: string;
  readonly edits: readonly SearchReplaceEdit[];
  readonly testsPassed: boolean;
}

export type SolveStage = "localize" | "plan" | "apply" | "validate" | "repair" | "done" | "gave-up";

export interface SolveLocalizationEvidence {
  readonly stages: readonly ("bm25" | "graph" | "embedding" | "llm-rerank")[];
  readonly selected: readonly { readonly path: string; readonly rank: number; readonly score: number; readonly isTest: boolean; readonly suspectSymbols?: readonly string[]; readonly reason: string }[];
}

export interface SolveAuthorityEvidence {
  readonly actorId: string; readonly parentActorId: string; readonly repository: string;
  readonly writeScope: readonly string[]; readonly writeGrant: "per-edit-one-shot";
  readonly budgetEnvelopeId: string; readonly delegation: "attenuated";
}

export interface RecoverableProposalEvidence {
  readonly baseRevision: string;
  readonly diff: string;
  readonly checks: ValidationOutcome;
  readonly consequence?: { readonly band: "low" | "medium" | "high"; readonly forcedGate: boolean; readonly reasons: readonly string[] };
  readonly rollback: { readonly strategy: "git-apply-reverse"; readonly patchSha256: string };
}

/** The full pipeline result. */
export interface SolveResult {
  readonly issueId: string;
  readonly solved: boolean;
  /** Inert output, deliberately not an AdmittedEditPlan or a passing PR/validation receipt. */
  readonly preparedProposal?: {
    readonly disposition: "unexecuted";
    readonly repositoryRef: string;
    readonly repositoryTreeSha256: string;
    readonly plan: EditPlan;
    readonly goalFulfilled: false;
  };
  readonly recovery?: import("./recovery_budget.js").RecoverySnapshot;
  /**
   * ROUND 41 — safety controls found configured off during this run (round 40's
   * `inertFloorInputs` / `inertBudgetInputs` output).
   *
   * Carried on the result so the merge-authority decision consumes the SAME value the PR body
   * reports. Recomputing it downstream would create a second threshold, and two thresholds for
   * one question drift apart — the R14 shape this project has already paid for once.
   */
  readonly inertControls?: readonly string[];
  /** The stages actually run, in order (for the audit trail). */
  readonly stagesRun: readonly SolveStage[];
  /** How many repair rounds were used. */
  readonly repairRounds: number;
  readonly localization?: SolveLocalizationEvidence;
  readonly authority?: SolveAuthorityEvidence;
  readonly proposalEvidence?: RecoverableProposalEvidence;
  readonly candidateFloorEvidence?: {
    readonly regression: { readonly executed: boolean; readonly passed: boolean; readonly failures: readonly string[] };
    readonly taskCompletion: { readonly evaluated: boolean; readonly complete: boolean; readonly missing: readonly string[]; readonly extraneous: readonly string[] };
  };
  /** The final validation outcome. */
  readonly validation?: ValidationOutcome;
  /** The PR proposal, if a passing patch was produced (never auto-merged). */
  readonly prProposal?: PrProposal;
  /** Why it gave up, if it did. */
  readonly gaveUpReason?: string;
  /** Content-bound evidence for a project-stage proposal actually admitted to this solve. */
  readonly admittedEdit?: AdmittedEditPlan;
  /** Actual committed-byte and rollback evidence; present on successful admitted project edits. */
  readonly projectEditReceipt?: ProjectEditEffectReceipt;
}
