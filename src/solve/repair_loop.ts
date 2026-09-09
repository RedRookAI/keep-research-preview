/** Bounded repair from retained observations. The runtime owns retry/compensation;
 * model proposals cannot reset limits, classify authority, or grant success. */
import { createHash } from "node:crypto";
import type { RollbackLedger } from "../control/rollback.js";
import type { Spine } from "../spine/spine.js";
import type { EditPlan, ValidationOutcome, PatchApplyResult } from "./issue_model.js";
import type { FileTree } from "./patch.js";
import { applyEditPlan } from "./patch.js";
import { ensureMediated } from "./mediated_tree.js";
import { validate, type TestRunner } from "./validate.js";
import type { FailureKind } from "../logic/plan_adapt.js";
import { RecoveryBudget, RecoveryHeldError, type RecoveryPermit } from "./recovery_budget.js";

export interface RepairDeps {
  readonly tree: FileTree;
  readonly runner: TestRunner;
  readonly ledger: RollbackLedger;
  readonly spine: Spine;
  replan(feedback: string, round: number, signal?: AbortSignal, permit?: RecoveryPermit): Promise<EditPlan>;
  vetEditPlan?: (plan: EditPlan) => { blocked: boolean; reason: string };
  withinBudget?: (round: number) => boolean;
  vet?: (repoRef: string) => Promise<boolean>;
  /** Trusted adapter classification only. Cannot override authority/ambiguity holds. */
  classifyFailure?: (feedback: string, round: number) => FailureKind;
  applyPlan?: (plan: EditPlan, round: number) => Promise<PatchApplyResult>;
  readonly recoveryBudget?: RecoveryBudget;
}
export interface RepairOptions { readonly maxRounds?: number; readonly maxElapsedMs?: number }
export interface RepairResult {
  readonly solved: boolean;
  readonly rounds: number;
  readonly validation: ValidationOutcome;
  readonly gaveUpReason?: string;
  readonly regressionTripped: boolean;
  readonly appliedPlans: readonly EditPlan[];
  readonly appliedRollbackIds: readonly string[];
}
const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const failureSet = (v: ValidationOutcome) => hash([...new Set(v.failures)].sort());

export async function repairLoop(issueId: string, repoRef: string, firstValidation: ValidationOutcome,
  firstRunPassCount: number, deps: RepairDeps, opts: RepairOptions = {}): Promise<RepairResult> {
  const maximum = opts.maxRounds ?? 3;
  let validation = firstValidation, round = 0, regressionTripped = false;
  const appliedPlans: EditPlan[] = [], appliedRollbackIds: string[] = [];
  const result = (reason?: string): RepairResult => ({
    solved: reason === undefined && validation.testsPassed && validation.vettingCleared,
    rounds: round, validation, regressionTripped, appliedPlans, appliedRollbackIds,
    ...(reason === undefined ? {} : { gaveUpReason: reason }),
  });
  if (validation.testsPassed) return result(validation.vettingCleared ? undefined : "vetting refused; authority hold");
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 1000) return result("invalid repair budget");
  if (maximum === 0) return result("max repair rounds reached");
  const budget = deps.recoveryBudget ?? new RecoveryBudget(deps.spine, JSON.stringify([repoRef, issueId]),
    { maxAttempts: maximum, maxElapsedMs: opts.maxElapsedMs ?? 1_800_000 });
  let bestPassCount = firstRunPassCount;
  let passing = new Set(firstValidation.passedTests ?? []);
  let unchangedFailures = await budget.observeFailures(firstValidation.failures);
  const observe = async (event: string, detail: Record<string, unknown>) => {
    deps.spine.stage({ type: "identity.action", actor: "repair", payload: { event, issueId, repoRef, ...detail } });
    await deps.spine.seal();
  };
  await observe("repair_initial_observation", { validation });
  while (!validation.testsPassed && round < maximum) {
    const typed = validation.failureKind;
    if (typed === "authority" || typed === "ambiguous" || typed === "harness" || typed === "unknown" ||
        (typed === undefined && validation.failures.includes("<runner-error>"))) {
      const reason = typed === "ambiguous" ? "ambiguous effect requires reconciliation" :
        typed === "authority" ? "authority hold" : "diagnosis required before another dispatch";
      await budget.hold(reason, typed === "ambiguous" ? "reconciliation" : typed === "authority" ? "authority" : "diagnosis");
      return result(reason);
    }
    if (deps.withinBudget && !deps.withinBudget(round + 1)) return result("spend budget exhausted");
    const feedback = validation.detail; // Never reacquire an already-observed failure by executing tests.
    const kind = typed === "transient" ? "transient" : deps.classifyFailure?.(feedback, round + 1) ?? "non-local";
    if (kind === "unknown") { await budget.hold("diagnosis required: unknown failure", "diagnosis"); return result("diagnosis required: unknown failure"); }
    if (unchangedFailures >= 2) {
      await observe("repair_diagnosis", { failureSet: failureSet(validation), unproductiveAttempts: unchangedFailures, kind, ownerApprovalRequired: false });
      if (kind === "transient") {
        await budget.hold("diagnosis required: unchanged transient has no corrective evidence", "diagnosis");
        return result("diagnosis required: unchanged transient has no corrective evidence");
      }
    }
    let permit;
    try { permit = await budget.reserve(); }
    catch (error) { return result(error instanceof RecoveryHeldError ? error.message : String(error)); }
    round++;
    try {
      const outcome = await budget.during(permit, async signal => {
        let applied: PatchApplyResult | undefined;
        let plan: EditPlan | undefined;
        if (kind !== "transient") {
          plan = await deps.replan(unchangedFailures >= 2
            ? `Diagnosis: the same named failures survived two attempts. Use the retained evidence to target a different correction.\n${feedback}`
            : feedback, round, signal, permit);
          await budget.assertLive(permit);
          if (deps.withinBudget && !deps.withinBudget(round)) return "spend budget exhausted";
          if (plan.edits.length === 0) return `re-plan produced no edits: ${plan.rationale}`;
          // Actual current source + edit semantics; ignore model rationale/nonces.
          const inputs = await Promise.all(plan.edits.map(async edit => [edit.file, await deps.tree.read(edit.file)]));
          const fingerprint = hash([inputs, plan.edits.map(e => [e.file, e.search, e.replace])]);
          if (!await budget.rememberPlan(fingerprint)) {
            await budget.hold("diagnosis required: identical edit repeated against identical inputs", "diagnosis");
            return "diagnosis required: identical edit repeated against identical inputs";
          }
          const gate = deps.vetEditPlan?.(plan);
          if (gate?.blocked) { await budget.hold(`authority hold: repair plan refused: ${gate.reason}`, "authority"); return `logic-vet blocked the repair edit plan before apply: ${gate.reason}`; }
          await budget.assertLive(permit);
          applied = deps.applyPlan ? await deps.applyPlan(plan, round) :
            await applyEditPlan(plan, ensureMediated(deps.tree), deps.ledger, { issueId });
          if (!applied.applied) return `repair patch did not apply: ${applied.perEdit.map(e => e.reason).filter(Boolean).join("; ")}`;
        }
        await budget.assertLive(permit);
        const observed = await validate(repoRef, deps.runner, deps.vet ? { vet: deps.vet } : {}, { signal, deadline: permit.deadline });
        await observe("repair_observation", { round, attempt: permit.attempt, validation: observed });
        const nextPassing = new Set(observed.passedTests ?? []);
        const count = observed.passedCount ?? (observed.testsPassed ? 1 : 0);
        const lost = [...passing].filter(name => !nextPassing.has(name));
        if (applied && (count < bestPassCount || lost.length > 0)) {
          regressionTripped = true;
          if (!applied.rollbackId) { await budget.hold("repair regression has no compensation identity"); return "repair regression requires reconciliation"; }
          // This is the sole compensation owner: never invoke a second count-based guard.
          const undo = await deps.ledger.rollbackAction(applied.rollbackId, "repair regression: restore exact prior state");
          if (!undo.rolledBack) { await budget.hold("repair inverse unavailable; reconcile workspace"); return "repair regression requires reconciliation"; }
          validation = { testsPassed: false, passedCount: 0, passedTests: [], failures: ["<revalidation-required>"], vettingCleared: false, failureKind: "unknown", detail: "repair regression guard: restored tree requires fresh validation" };
          await budget.hold("regression guard compensated repair; fresh validation required", "diagnosis");
          return "regression guard tripped (repair broke passing tests)";
        }
        unchangedFailures = await budget.observeFailures(observed.failures);
        validation = observed;
        passing = nextPassing;
        bestPassCount = Math.max(bestPassCount, count);
        if (plan && applied) {
          appliedPlans.push(plan);
          if (applied.rollbackId) appliedRollbackIds.push(applied.rollbackId);
        }
        if (validation.testsPassed && !validation.vettingCleared) {
          await budget.hold("authority hold: vetting refused", "authority");
          return "vetting refused; authority hold";
        }
        return undefined;
      });
      if (outcome !== undefined) return result(outcome);
    } catch (error) {
      return result(error instanceof RecoveryHeldError ? error.message : `reconciliation required: ${String(error)}`);
    } finally { await budget.finish(permit); }
    if (validation.testsPassed) return result();
  }
  return result("max repair rounds reached");
}
