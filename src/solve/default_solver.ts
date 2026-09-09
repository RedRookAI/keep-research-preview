/**
 * Default solver — composes the existing Agentless SolvePipeline (localize → plan → logic-vet → apply → validate →
 * repair → PR proposal) into the app's SolveFn, so runProject actually BUILDS instead of calling an opaque seam.
 *
 * Model: whatever the composed gateway is pointed at — the local provider by default (deterministic, air-gapped,
 * self-contained here) and a frontier model in production via the same port. The spine around the model is the
 * differentiator; the model is swappable.
 *
 * Test execution is a seam (`runnerFor`). Its default FAILS CLOSED: with no real runner, validation cannot pass, so a
 * change is never marked verified on vacuous evidence. A real sandboxed command runner is wired in the isolation
 * increment; a deterministic validator runner is used for in-environment proofs.
 */

import type { Spine } from "../spine/spine.js";
import type { ModelProvider } from "../gateway/gateway.js";
import type { Issue, SolveResult, SolveExecutionContext, RecoverableProposalEvidence, SolveAuthorityEvidence } from "./issue_model.js";
import type { SolveToPrResult } from "../pipeline/keep_pipeline.js";
import type { TestRunner, TestRunResult } from "./validate.js";
import { ensureMediated } from "./mediated_tree.js";
import type { FileTree } from "./patch.js";
import type { Workspace } from "./workspace.js";
import { SolvePipeline, inheritCanonicalAdmittedSolveResult, type SolvePipelineOptions } from "./solve_pipeline.js";
import { RollbackLedger } from "../control/rollback.js";
import { IdentityRegistry, DEFAULT_SOLVER_IDENTITY_ID, type AgentIdentity } from "../identity/agent_identity.js";
import { GraphLocalizer } from "../coderag/graph_localizer.js";
import type { SolveFn } from "../loop/review_intake.js";

export interface DefaultSolverConfig {
  readonly spine: Spine;
  /** The model behind the gateway (local default, frontier in prod). */
  readonly model: ModelProvider;
  /** The repo surface to solve against. */
  readonly workspace: Workspace;
  /** How to run tests for a repoRef against the (patched) tree. Default fails closed (validation cannot pass). */
  readonly runnerFor?: (repoRef: string, tree: FileTree) => TestRunner;
  /** Runs a frozen untrusted goal check through the host's existing isolated test boundary. */
  readonly goalCheckRunnerFor?: (repoRef: string, check: NonNullable<import("./issue_model.js").EditPlan["goalCheck"]>) => TestRunner;
  readonly options?: SolvePipelineOptions;
  /** Optional cascade vet gate (repoRef → cleared). */
  readonly vet?: (repoRef: string) => Promise<boolean>;
  /**
   * Per-agent identity registry (Core Addition C). ROUND 35 — wired here as well as in
   * KeepPipeline, because this is the OTHER operator entry point (it backs `SolveFn` for
   * review intake). Leaving it armed on one path and inert on the other would reproduce
   * exactly the gap round 34 named as Z138: a control a reader reasonably assumes is on.
   *
   * Operator-supplied on purpose — the operator holds `kill()`. Omit ⇒ `identityLive`
   * stays `undefined` ⇒ "not assessed (no veto)", unchanged.
   */
  readonly identityRegistry?: IdentityRegistry;
  readonly rootIdentity?: AgentIdentity;
  readonly repository?: string;
  readonly budgetEnvelopeId?: string;
  /** Installed exact-repository hook: captures the candidate's real Git patch and recovery binding. */
  readonly proposalEvidenceFor?: (repoRef: string, result: SolveResult) => Promise<Omit<RecoverableProposalEvidence, "consequence">>;
  /** Optional canonical governance for the built-in effectful solver. Rejected effects are compensated before return. */
  readonly governance?: GovernanceDeps;
}

/** A TestRunner that fails closed — no real execution available, so validation cannot pass on vacuous evidence. */
export function failClosedRunner(reason = "no test runner configured (enable the sandbox runner)"): TestRunner {
  return { async run(): Promise<TestRunResult> { return { results: [], runnerError: reason }; } };
}

/** A deterministic runner driven by a predicate over the (patched) tree — for in-environment proofs. */
export function validatorRunner(tree: FileTree, check: (tree: FileTree) => Promise<boolean> | boolean, testName = "validation"): TestRunner {
  return {
    async run(): Promise<TestRunResult> {
      const ok = await check(tree);
      return { results: [{ name: testName, passed: ok, ...(ok ? {} : { output: "validator predicate failed" }) }] };
    },
  };
}

export function buildDefaultSolver(cfg: DefaultSolverConfig): SolveFn {
  return async (issue: Issue, context: SolveExecutionContext = {}): Promise<SolveToPrResult> => {
    context = { ...context }; // Caller mutation during an await cannot lift the ceiling.
    const authorized = (): boolean => { try { context.assertAuthority?.(); return true; } catch { return false; } };
    const refused = (): SolveToPrResult => ({ solveResult: { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0,
      gaveUpReason: "native project command authority unavailable" } });
    if (!authorized()) return refused();
    // Check before invoking any effectful factory, not only inside the pipeline.
    if (context.executionCeiling !== undefined && context.executionCeiling !== "prepare") {
      return { solveResult: { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0, gaveUpReason: "unknown execution ceiling" } };
    }
    const preparationOnly = context.executionCeiling === "prepare";
    const assertPreparationIdentity = (): void => {
      if (!preparationOnly || !cfg.identityRegistry) return;
      const live = cfg.rootIdentity ? cfg.identityRegistry.authorize(cfg.rootIdentity).authorized
        : !cfg.identityRegistry.isKilled(DEFAULT_SOLVER_IDENTITY_ID);
      if (!live) throw new Error("solver preparation identity refused");
    };
    assertPreparationIdentity();
    // Minted per solve from the OPERATOR's registry, so `kill()` is reachable. Never minted
    // from a private registry: an unreachable kill switch reports "assessed and fine" forever,
    // which is worse than the honest `undefined`.
    if (cfg.repository !== undefined && issue.repoRef !== cfg.repository) throw new Error(`solve repository ${issue.repoRef} is outside the bound repository ${cfg.repository}`);
    const root = preparationOnly ? undefined : cfg.rootIdentity ?? cfg.identityRegistry?.mint(DEFAULT_SOLVER_IDENTITY_ID, ["."]);
    const identity = root && cfg.identityRegistry?.delegate(root, `${root.id}:${issue.id}`, ["."]);
    if (!preparationOnly && cfg.identityRegistry && !identity) throw new Error("solver delegation refused before repository access");
    const authority: SolveAuthorityEvidence | undefined = identity && root ? Object.freeze({
      actorId: identity.id, parentActorId: root.id, repository: issue.repoRef,
      writeScope: Object.freeze([...identity.scope]), writeGrant: "per-edit-one-shot",
      budgetEnvelopeId: cfg.budgetEnvelopeId ?? "unbound", delegation: "attenuated",
    }) : undefined;
    if (authority) cfg.spine.stage({ type: "identity.action", actor: authority.actorId, payload: { event: "solve.authority_bound", ...authority } });
    const files = await cfg.workspace.files(issue.repoRef);
    if (!authorized()) return refused();
    // Preparation holds a read-only snapshot, not even the live tree's write
    // capability. This also avoids invoking the workspace's effectful tree factory.
    const snapshot = preparationOnly ? new Map(files.map(file => [file.path, file.content])) : undefined;
    const tree = ensureMediated(preparationOnly ? {
      async read(path: string) { return snapshot!.get(path); },
      async write() { throw new Error("preparation ceiling forbids repository writes"); },
    } : cfg.workspace.tree(issue.repoRef)); // R23: agent path holds only a membrane
    const runner = preparationOnly
      ? { async run(): Promise<TestRunResult> { throw new Error("preparation ceiling forbids test execution"); } }
      : (cfg.runnerFor ?? (() => failClosedRunner()))(issue.repoRef, tree);
    const ledger = new RollbackLedger(cfg.spine);
    const finish = async (result: SolveToPrResult): Promise<SolveToPrResult> => {
      if (authorized()) return result;
      if (ledger.pending > 0) await ledger.rollback(ledger.pending, "native project command authority unavailable after solve");
      return { solveResult: { ...refused().solveResult,
        ...(result.solveResult.recovery === undefined ? {} : { recovery: result.solveResult.recovery }) } };
    };
    const pipeline = new SolvePipeline(
      {
        spine: cfg.spine,
        ledger,
        tree,
        runner,
        ...(!preparationOnly && cfg.goalCheckRunnerFor ? { goalCheckRunnerFor: cfg.goalCheckRunnerFor } : {}),
        localizer: new GraphLocalizer(),
        model: cfg.model,
        snapshotFiles: () => cfg.workspace.files(issue.repoRef),
        ...(cfg.vet ? { vet: cfg.vet } : {}),
        // Both fields or neither — reversible_execution.ts leaves identityLive undefined
        // unless BOTH are present, so supplying one alone silently keeps the switch unarmed.
        ...(identity && cfg.identityRegistry
          ? { identity, identityRegistry: cfg.identityRegistry }
          : {}),
      },
      cfg.options ?? {},
    );
    let solveResult: SolveResult = await pipeline.run(issue, files, context);
    if (preparationOnly) {
      assertPreparationIdentity();
      context.memoryContext?.assertCurrent();
      return finish({ solveResult });
    }
    if (solveResult.solved && solveResult.prProposal && cfg.proposalEvidenceFor) {
      solveResult = inheritCanonicalAdmittedSolveResult(solveResult, { ...solveResult, proposalEvidence: await cfg.proposalEvidenceFor(issue.repoRef, solveResult) });
    }
    const base = { solveResult: authority ? inheritCanonicalAdmittedSolveResult(solveResult, { ...solveResult, authority }) : solveResult };
    if (!cfg.governance) return finish(base);
    const governed = await withGovernance(async () => base, cfg.governance)(issue, context);
    if (governed.mergeAuthority?.verdict === "abandon-retry" || governed.mergeAuthority?.verdict === "block") {
      const rollback = await ledger.rollback(ledger.pending, `governance ${governed.mergeAuthority.verdict}: ${governed.mergeAuthority.reason}`);
      if (rollback.rolledBack === 0 && governed.solveResult.projectEditReceipt?.applied === true) {
        throw new Error(`governance ${governed.mergeAuthority.verdict} could not compensate the applied project edit`);
      }
      const { projectEditReceipt: _receipt, proposalEvidence: _proposalEvidence, ...compensatedData } = governed.solveResult;
      const compensated = inheritCanonicalAdmittedSolveResult(governed.solveResult, {
        ...compensatedData,
        solved: false,
        gaveUpReason: `applied proposal compensated after governance verdict ${governed.mergeAuthority.verdict}`,
      });
      return finish({ ...governed, solveResult: compensated });
    }
    return finish(governed);
  };
}

// ── Governance decorator (Increment 1.2) ──────────────────────────────────────────────────────────────────────

import type { CascadeOutcome } from "../cascade/verification_cascade.js";
import type { PatchVetPayload } from "../cascade/vetting_gates.js";
import { PrRiskAssessor } from "../oversight/pr_risk.js";
import { patchIntroducesDestructiveOp } from "../pipeline/patch_verifier.js";
import { structuralFloor, defaultFloorPolicy } from "../floor/structural_floor.js";
import { checkBudget, defaultBudgetPolicy } from "../budget/budget_ledger.js";
import { composeGate, defaultGatePolicy } from "../gate/composed_gate.js";
import { clampOptimizer, type Optimizer } from "../optimizer/raise_only_clamp.js";
import { effectProvenance } from "../provenance/effect_provenance.js";
import {
  decideMergeAuthority, mergeVerificationFromCascade, DEFAULT_MERGE_ENVELOPE,
  type MergeEnvelope,
} from "../oversight/merge_authority.js";

export interface GovernanceDeps {
  /** The composed vetting cascade's patch gate (deterministic sound floor → model tiers → human). */
  readonly vetPatch: (payload: PatchVetPayload, itemId?: string) => Promise<CascadeOutcome>;
  readonly spine: Spine;
  /** Consequence assessor (blast + reversibility + size — NOT confidence). Default: a fresh PrRiskAssessor. */
  readonly riskAssessor?: PrRiskAssessor;
  /** The autonomous-merge envelope (what may merge without a human). Default: DEFAULT_MERGE_ENVELOPE. */
  readonly envelope?: MergeEnvelope;
  /**
   * Optional UNTRUSTED optimizer (Step 2, layer 3). It may propose tightening the routing verdicts;
   * the raise-only clamp drops any loosen. Absent ⇒ noop (verdicts unchanged). Never trusted to lower a verdict.
   */
  readonly optimizer?: Optimizer;
}

/**
 * Wrap any SolveFn so its PR proposal is routed through the COMPOSED governance path: the vetting cascade
 * (`vetPatch`, the reconciled 3-valued sound-floor-first gate) produces a verification verdict, which
 * `mergeVerificationFromCascade` feeds — with the CONSEQUENCE (reversibility / blast / size, never confidence) from the
 * risk assessor — into the consequence-primary `decideMergeAuthority`. The result: a governed DECISION
 * (autonomous-merge / human-merge / abandon-retry / block), not a raw patch.
 *
 * Mission invariant (proven earlier): a heuristic concern on a REVERSIBLE change never bothers a human — it becomes
 * `abandon-retry`; a human is reached only when the change is genuinely consequential. Escalate-human is consumed as an
 * unverified verification signal here, NEVER as a direct interrupt.
 */
export function withGovernance(solve: SolveFn, deps: GovernanceDeps): SolveFn {
  const assessor = deps.riskAssessor ?? new PrRiskAssessor();
  const envelope = deps.envelope ?? DEFAULT_MERGE_ENVELOPE;
  return async (issue: Issue, context: SolveExecutionContext = {}): Promise<SolveToPrResult> => {
    const base = await solve(issue, context);
    const sr = base.solveResult;
    if (!sr.prProposal) return base; // nothing produced → nothing to govern

    // 1) Verification: the composed cascade (sound floor → model tiers → human), consumed the mission-safe way.
    const outcome = await deps.vetPatch({ solveResult: sr, issueText: issue.text });
    const verification = mergeVerificationFromCascade(outcome, { testsPassed: sr.validation?.testsPassed ?? false });

    // 2) Consequence: reversibility / blast / size only (never confidence).
    const risk = assessor.assess({ proposal: sr.prProposal, result: sr });
    const proposalEvidence = sr.proposalEvidence
      ? { ...sr.proposalEvidence, consequence: {
          band: risk.consequenceBand,
          forcedGate: risk.forcedGate,
          reasons: risk.reasons.filter((reason) => reason.axis !== "confidence").map((reason) => `[${reason.axis}] ${reason.detail}`),
        } }
      : undefined;
    // Structural floor (Step 2): a pure, decidable, model-independent verdict over the
    // op's declared effect. `gate` (irreversible / external / protected / unbounded /
    // unknown) feeds the existing consequence tier; it can only RAISE caution here.
    const floorVerdict = structuralFloor(
      {
        kind: "file.edit",
        writeSet: sr.prProposal.edits.map((e) => e.file),
        targets: sr.prProposal.edits.map((e) => e.file),
        hasInverse: true, // applyEditPlan records a concrete undo for in-workspace edits
        raw: sr.prProposal.edits.map((e) => e.replace).join("\n"),
      },
      defaultFloorPolicy(issue.repoRef ?? "repo"),
    );
    const looksDestructive =
      sr.prProposal.edits.some((e) => e.replace.trim() === "" && e.search.trim().length > 40) ||
      patchIntroducesDestructiveOp(sr.prProposal.edits) ||
      floorVerdict.verdict === "gate";

    // Composed gate (Step 2): deny-overrides fusion of floor + budget + reversibility class +
    // owner-presence → auto-proceed | human-hold. A human-hold route folds into the existing
    // consequence routing (→ irreversible tier → human path). It can only RAISE caution — an
    // over-budget edit that slips the destructive heuristics is caught here by the budget veto.
    const gateBudget = checkBudget(
      {
        edits: sr.prProposal.edits.length,
        filesTouched: new Set(sr.prProposal.edits.map((e) => e.file)).size,
        bytesWritten: sr.prProposal.edits.reduce((n, e) => n + Buffer.byteLength(e.replace, "utf8"), 0),
        fanOut: 0,
        steps: 1,
      },
      defaultBudgetPolicy(),
    );
    // Untrusted optimizer (Step 2, layer 3): it may PROPOSE tightening the verdicts but can only
    // RAISE caution — the raise-only clamp (trusted TCB) drops any loosen. The clamped floor/budget
    // then feed the gate; the optimizer never bypasses the gate or touches effects. Default = noop.
    const optimizerProposal = deps.optimizer?.propose({
      floor: floorVerdict.verdict,
      budget: gateBudget.verdict,
      route: "auto-proceed",
    }) ?? {};
    const clamped = clampOptimizer(
      { floor: floorVerdict.verdict, budget: gateBudget.verdict, route: "auto-proceed" },
      optimizerProposal,
    );
    const gateRoute = composeGate(
      {
        floor: clamped.final.floor,
        budget: clamped.final.budget,
        actionTier: looksDestructive ? "irreversible" : "reversible-internal",
        ownerPresent: true, // interactive solve context; owner-absent HOLD is a config/env SEAM
        // Provenance (2.6): assess the effect's origin. The issue is the input; in-env it is assumed
        // an internal/operator task (trusted). Labeling external issues / tool output / fetched pages
        // as untrusted and propagating that is the taint-tracer SEAM.
        provenance: effectProvenance({ inputs: [{ source: "issue", trust: "trusted" }] }).verdict,
      },
      defaultGatePolicy(),
    );
    // The optimizer may also tighten the final route directly (auto→hold), never loosen it.
    const clampedRoute = clampOptimizer(
      { floor: clamped.final.floor, budget: clamped.final.budget, route: gateRoute.route },
      { route: optimizerProposal.route },
    ).final.route;
    const routeToHuman = looksDestructive || clampedRoute === "human-hold";

    // 3) Consequence-primary decision.
    const mergeAuthority = decideMergeAuthority({
      verification,
      consequence: {
        actionTier: routeToHuman ? "irreversible" : "reversible-internal",
        consequenceBand: risk.consequenceBand,
        alwaysGatePath: risk.forcedGate,
      },
      envelope,
    });

    deps.spine.stage({
      type: "identity.action", actor: "solve-governance",
      payload: {
        event: "merge_authority", issueId: issue.id, verdict: mergeAuthority.verdict,
        cascade: outcome.finalDecision, consequenceBand: risk.consequenceBand, reason: mergeAuthority.reason,
      },
    });

    const governedSolveResult = proposalEvidence ? inheritCanonicalAdmittedSolveResult(sr, { ...sr, proposalEvidence }) : sr;
    const verificationGuidance = outcome.trail.map((result) => `${result.name}: ${result.reason}`).join("; ");
    return {
      ...base,
      solveResult: governedSolveResult,
      mergeAuthority,
      ...(mergeAuthority.verdict === "abandon-retry"
        ? { abandoned: { reason: `${mergeAuthority.reason}; verification evidence: ${verificationGuidance}`, retriesUsed: 0 } }
        : {}),
    };
  };
}
