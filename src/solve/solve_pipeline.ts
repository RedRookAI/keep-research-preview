/**
 * SolvePipeline orchestrator (Increment 13d).
 *
 * SOTA basis (2026-08-05): the Agentless fixed pipeline (localize → repair → validate) is competitive
 * with autonomous agent loops at a fraction of the cost, and its value is the test-gated structure
 * (Chen 2026). This orchestrates the 13a–c parts into that pipeline, emits ProgressNarrator events for
 * the operator, audits every stage to the spine (tamper-evident trajectory), and returns a PR PROPOSAL
 * for the human merge gate — Keep NEVER auto-merges. Runs deterministically here under the replay
 * provider (every model call goes through the gateway port). Zero deps.
 *
 * What would change it: an AgentLoop strategy behind the same Solver port if cross-scaffold evidence
 * favors it for our task mix — this pipeline stays as the deterministic, auditable default.
 */

import type { Spine } from "../spine/spine.js";
import type { RollbackLedger } from "../control/rollback.js";
import type { ModelProvider } from "../gateway/gateway.js";
import { ProgressNarrator } from "../autonomy/progress_narrator.js";

import type { Issue, SolveResult, SolveStage, PrProposal, EditPlan, SolveExecutionContext, AdmittedEditPlan, PatchApplyResult, SolveLocalizationEvidence } from "./issue_model.js";
import { isTestFile, type Localizer, type LocalizationResult, type RepoFile } from "./localize.js";
import { planEdits } from "./edit_planner.js";
import { TaskMemoryUnavailableError, type TaskMemoryContext } from "../memory/task_context.js";
import { ProjectEditAdmissionError } from "../autonomy/project_edit_stage.js";
import { applyEditPlan, canApply, resolveEditPlan, InMemoryFileTree, type FileTree } from "./patch.js";
import { ensureMediated, WriteGrant, runMediatedWith } from "./mediated_tree.js";
import { executeReversibly, type ReversibleIntent, type IntegrationPolicies } from "../integrate/reversible_execution.js";
import type { AgentIdentity, IdentityRegistry } from "../identity/agent_identity.js";
import { defaultFloorPolicy, inertFloorInputs, assessDeclaredScope } from "../floor/structural_floor.js";
import { inertBudgetInputs } from "../budget/budget_ledger.js";
import { defaultGatePolicy } from "../gate/composed_gate.js";
import { defaultBudgetPolicy } from "../budget/budget_ledger.js";
import { defaultAcceptanceTest } from "../ree/reversible_envelope.js";
import { validate, type TestRunner } from "./validate.js";
import { LogicVet, type LogicVetResult } from "../logicvet/logic_vet.js";
import type { Plan, PlanStep } from "../logicvet/deterministic_critics.js";

/** A deterministic, collision-resistant-enough signature of an edit plan's content (djb2 over file+search+replace). */
function editsSignature(plan: EditPlan): string {
  const s = plan.edits.map((e) => `${e.file}\u0000${e.search}\u0000${e.replace}`).join("\u0001");
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h.toString(36);
}
import { createHash } from "node:crypto";
import { projectRepositoryTreeSha256 } from "../autonomy/project_localization.js";

function sha256Text(text: string): string {
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}
const canonicalAdmittedResults = new WeakSet<object>();
/** Unforgeable process-local proof that the canonical pipeline consumed an admitted project edit. */
export function isCanonicalAdmittedSolveResult(result: SolveResult): boolean { return canonicalAdmittedResults.has(result); }
/** Preserve the process-local attestation only across a trusted canonical metadata extension. */
export function inheritCanonicalAdmittedSolveResult(source: SolveResult, extended: SolveResult): SolveResult {
  if (canonicalAdmittedResults.has(source)) canonicalAdmittedResults.add(extended);
  return extended;
}

import { repairLoop } from "./repair_loop.js";
import { RecoveryBudget, RecoveryHeldError, type RecoveryPermit } from "./recovery_budget.js";

export interface SolvePipelineDeps {
  readonly spine: Spine;
  readonly ledger: RollbackLedger;
  readonly tree: FileTree;
  readonly runner: TestRunner;
  readonly goalCheckRunnerFor?: (repoRef: string, check: NonNullable<EditPlan["goalCheck"]>) => TestRunner;
  readonly localizer: Localizer;
  /** The model behind the gateway (a replay/local/http provider) used for planning + repair. */
  readonly model: ModelProvider;
  /** Fresh trusted whole-repository enumeration required for content-bound project edits. */
  readonly snapshotFiles?: () => Promise<readonly RepoFile[]>;
  /** Optional vetting gate (verification cascade / logic vetting). */
  readonly vet?: (repoRef: string) => Promise<boolean>;
  /** Optional spend guard for the repair loop. */
  readonly withinBudget?: (round: number) => boolean;
  /**
   * Optional acting agent identity + its registry (Core Addition C). Threaded through to
   * `executeReversibly` so a killed/unknown/forged identity becomes a deny-capable gate input on
   * the composed path. Absent ⇒ `identityLive` stays undefined ⇒ "not assessed (no veto)", which is
   * the documented gate contract and is UNCHANGED by this wiring.
   *
   * Round 30: before this, the registry was never supplied at the call site, so the kill switch
   * could not fire even with the envelope enabled — the check evaluated, found nothing injected,
   * and fell through.
   */
  readonly identity?: AgentIdentity;
  readonly identityRegistry?: IdentityRegistry;
  /**
   * Strangler-fig cutover flag (Build Step 2). When true, an auto-proceed reversible apply flows
   * through the composed chain (floor → gate → REE envelope: checkpoint → fork → budget → accept →
   * commit/rollback) instead of direct applyEditPlan.
   *
   * ROUND 34 — DEFAULTS **ON**. Omitting this now routes through the envelope.
   *
   * The one-line revert, kept deliberately available: pass `reversibleEnvelope: false`. That
   * restores the direct `applyEditPlan` path exactly as it was, and it is covered by its own
   * test so it cannot rot while unused.
   *
   * BUILD-ORDER 2.5 (Z126) — THE RETIRE-VS-KEEP DECISION, BOUND ON EVIDENCE, NOT PREFERENCE.
   * Measured (see redrook-ops/.round-artifacts/ENVELOPE-FLAG-RETIREMENT/measurement.txt): the
   * direct-apply fallback is reached by NO non-test src caller, and equivalence-for-accepted-ops
   * holds — so retirement is *evidence-permitted*. It is NOT taken, because the disconfirming case
   * bites: the envelope has never executed against real work (BUILD-ORDER 1.8 real-provider run and
   * all of Phase 4 are open — every run to date is under the replay/in-memory fixtures), so this is
   * an IMMATURE cutover and deleting its one-line revert would strip the only revert path.
   *
   * DECISION: KEEP, but GOVERNED. This SUPERSEDES Round 34's keep, which rested on an UNMEASURABLE
   * criterion ("100% of traffic for a 2-4 week stabilization period") that a telemetry-less,
   * userless 0.0.1 tool can never satisfy — that framing would drift into a permanent border. The
   * SPECIFIC, MEASURABLE unmet criterion and the revisit trigger are recorded as a durable,
   * auditable fact in {@link REVERSIBLE_ENVELOPE_STABILIZATION} (validated fail-closed and
   * spine-audited on every kept-default run — see the apply seam), so the flag can never become a
   * silent permanent border.
   *
   * WHAT CHANGES FOR AN OPERATOR: edits that the barriers refuse no longer land. They return
   * `applied: false` with `status: "held"` and the gate's actual reasons, instead of being
   * applied and left for review after the fact. Equivalence is preserved for accepted ops —
   * the final tree state matches direct-apply — so benign work is unaffected.
   */
  readonly reversibleEnvelope?: boolean;
  /**
   * ROUND 38 — the operator's allowed write regions, handed to the structural floor.
   *
   * The floor already refuses protected paths and jail escapes, but as GLOBAL policy. Nothing
   * checked that the DECLARED write-set — `plan.edits.map((e) => e.file)`, i.e. model output —
   * was within an authority the operator had stated. This is that authority.
   *
   * Omit ⇒ unconstrained, byte-identical to before. See `FloorPolicy.allowedPaths`.
   */
  readonly allowedPaths?: readonly string[];
}

export interface SolvePipelineOptions {
  /** Suspect files to localize to (top-K). Default 3. */
  readonly localizeK?: number;
  /** Max repair rounds. Default 3. */
  readonly maxRepairRounds?: number;
  /** Frozen across reconstruction of the same logical solve. Default 30 minutes. */
  readonly recoveryMaxElapsedMs?: number;
  /** Policy-forbidden operations the deterministic logic-vet gate blocks in an edit plan (VeriPlan pattern). */
  readonly forbiddenActions?: readonly string[];
  /** Proportionality ceiling on edits per plan (the logic-vet size critic). Default 40. */
  readonly maxEditsPerPlan?: number;
}

/**
 * BUILD-ORDER 2.5 (Z126) — the KEEP decision for the `reversibleEnvelope` strangler-fig cutover
 * flag, recorded as a durable, auditable fact rather than a bare comment. Emitted to the spine on
 * every kept-default apply (see the apply seam) and asserted by the round's tests, so a "keep" is a
 * decision with a named, MEASURABLE revisit condition — never drift into a permanent border.
 *
 * HONESTY BOUND: this records only that the flag is kept and WHY (the specific unmet criterion),
 * never that the envelope is bug-free.
 */
export interface StabilizationRecord {
  readonly flag: string;
  readonly disposition: string;
  readonly unmetCriterion: string;
  readonly revisitWhen: string;
  readonly supersedes: string;
}

export const REVERSIBLE_ENVELOPE_STABILIZATION: StabilizationRecord = {
  flag: "reversibleEnvelope",
  disposition: "kept",
  /** The SPECIFIC stabilization criterion still unmet — measured, not "just in case". */
  unmetCriterion:
    "the envelope path has never executed against real work — every run to date is under the " +
    "deterministic replay/in-memory fixtures; BUILD-ORDER 1.8 (real-provider end-to-end) and all " +
    "of Phase 4 (real repo / SWE-bench) are open, so the cutover is immature and its one-line " +
    "direct-apply revert must stay.",
  /** The concrete trigger that flips this from keep to retire — tied to an existing milestone. */
  revisitWhen:
    "retire once BUILD-ORDER 1.8 (E-1 real-provider end-to-end) has exercised the envelope against " +
    "real work, OR at the first tagged release with users — whichever comes first.",
  /** What this decision replaces, so the border cannot silently persist on the old, unmeasurable rule. */
  supersedes:
    "Round 34's keep, which rested on an UNMEASURABLE criterion (100% of traffic for a 2-4 week " +
    "stabilization period) that a telemetry-less, userless 0.0.1 tool can never satisfy.",
};

/**
 * Return the stabilization record as a plain audit fact, FAIL-CLOSED: a keep with no recorded
 * unmet criterion or no revisit condition is not a governed decision, it is drift — so an empty
 * record throws rather than silently auditing a hollow "keep". Callers on the kept-default path
 * audit the returned value to the spine.
 */
export function reversibleEnvelopeStabilizationFact(
  record: StabilizationRecord = REVERSIBLE_ENVELOPE_STABILIZATION,
): StabilizationRecord {
  const unmet = record.unmetCriterion?.trim() ?? "";
  const revisit = record.revisitWhen?.trim() ?? "";
  if (unmet.length === 0 || revisit.length === 0) {
    throw new Error(
      "reversibleEnvelope KEEP is undocumented — a kept cutover flag must record BOTH the specific " +
        "unmet stabilization criterion AND a revisit condition (fail-closed: no silent permanent border).",
    );
  }
  return {
    flag: record.flag,
    disposition: record.disposition,
    unmetCriterion: unmet,
    revisitWhen: revisit,
    supersedes: record.supersedes,
  };
}

function taskMemoryRefusal(context: TaskMemoryContext | undefined, assertAuthority?: () => void): string | undefined {
  try { assertAuthority?.(); context?.assertCurrent(); return undefined; }
  catch (error) { return error instanceof TaskMemoryUnavailableError ? error.message
    : assertAuthority ? "native project command authority unavailable" : "selected task memory unavailable"; }
}

export class SolvePipeline {
  /** Deterministic logic-vet panel — default-on, zero-dep; persists recheck-suppression state across the run. */
  private readonly logicVet = new LogicVet();
  private readonly deps: SolvePipelineDeps;
  constructor(deps: SolvePipelineDeps, private readonly opts: SolvePipelineOptions = {}) {
    // R23: hold ONLY a mediated tree — the pipeline structurally cannot write unmediated.
    this.deps = { ...deps, tree: ensureMediated(deps.tree) };

    // BUILD-ORDER 2.1 (Z170) — CONFIG-TIME scope surfacing, at the DECLARATION/threading seam.
    //
    // This runs ONCE, at construction — before any run() — which is what makes it the config-time
    // (admission) channel, distinct from the per-run report inside run(). When the operator has
    // DECLARED a write-scope that admits everything (`["*"]`) or is malformed (`src/**/*.ts`), the
    // scope is recorded to the spine as an AUDITABLE CONSCIOUS-GRANT fact — so an over-broad or
    // mistyped authority is a decision the operator can see at set-time, never a silent authority
    // (2026: the `*` wildcard is the dominant breach origin AND the default tendency of the model
    // output this write-set derives from) and never a late surprise (the Z135 abandonment path).
    //
    // OBSERVE-ONLY: it stages an audit event, it never refuses, never changes a route, never narrows
    // the declared scope. An OMITTED scope declared nothing, so it records nothing — front-of-house
    // is byte-identical. A plain `["*"]` run still proceeds; the only delta is one set-time audit
    // record, NOT a per-run alert (recording once at declaration is the actionable, conscious-grant
    // form; a repeated warning on `["*"]` would be the alert-fatigue path the run-time report avoids).
    const scope = assessDeclaredScope(deps.allowedPaths);
    if (scope.worthRecording) {
      this.deps.spine.stage({
        type: "identity.action",
        actor: "scope-declaration",
        payload: {
          event: "scope.declared",
          disposition: scope.disposition,
          admitsEverything: scope.admitsEverything,
          declared: scope.declared,
          findings: scope.findings,
          // Honesty bound, stated in the record itself: this attests only what the scope ADMITS,
          // never that a wide scope is SAFE.
          note: "auditable set-time record of a declared over-broad/malformed write-scope; not a claim the scope is safe",
        },
      });
    }
  }

  /** Map the concrete edit plan to a LogicVet Plan and run the deterministic critic panel (pre-apply gate). */
  private vetEditPlan(issue: Issue, plan: EditPlan): LogicVetResult {
    const steps: PlanStep[] = plan.edits.map((e, i) => ({
      id: `edit-${i}`,
      // Scan the FULL added text (never truncated — a forbidden op could hide past any fixed cutoff).
      description: `${e.intent} [${e.file}] :: ${e.replace}`,
      dependsOn: [],
    }));
    const lvPlan: Plan = { goal: issue.text, steps };
    // Version key is derived from the edit CONTENT, so two different plans (e.g. across repair rounds) are
    // each fully vetted — positional step ids can never cross-suppress a different plan's edits.
    const versionKey = `${issue.id}:${editsSignature(plan)}`;
    try {
      return this.logicVet.vetArtifact(
        {
          plan: lvPlan,
          constraints: {
            maxSteps: this.opts.maxEditsPerPlan ?? 40,
            ...(this.opts.forbiddenActions && this.opts.forbiddenActions.length > 0 ? { forbiddenActions: this.opts.forbiddenActions } : {}),
          },
          taskShape: "implement",
        },
        versionKey,
        steps.map((s) => s.id),
      );
    } catch (e) {
      // Fail-closed: an errored vet blocks — never silently apply an unvetted plan.
      return { verdict: { decision: "block", posture: "strict", reason: `logic-vet errored — fail-closed: ${(e as Error).message}`, blocking: [], concerns: [], reworkTargets: [] }, critics: [], singleModel: true, note: "errored" };
    }
  }

  /** The pre-apply gate as a simple predicate — shared with the repair loop so repair edits are vetted too. */
  private editPlanGate(issue: Issue, admittedFiles?: ReadonlySet<string>): (plan: EditPlan) => { blocked: boolean; reason: string } {
    return (plan: EditPlan) => {
      const outside = admittedFiles === undefined ? [] : plan.edits.filter((edit) => !admittedFiles.has(edit.file)).map((edit) => edit.file);
      if (outside.length > 0) return { blocked: true, reason: `edit targets files outside the admitted project step: ${[...new Set(outside)].sort().join(", ")}` };
      const r = this.vetEditPlan(issue, plan);
      return { blocked: r.verdict.decision === "block", reason: r.verdict.reason };
    };
  }

  /**
   * Solve an issue against the provided repo files. Returns a SolveResult carrying a PR proposal when a
   * passing patch is produced. Never merges — the proposal is for the human gate.
   */
  async run(issue: Issue, files: readonly RepoFile[], context: SolveExecutionContext = {}): Promise<SolveResult> {
    context = { ...context }; // Preserve attenuation across asynchronous host/model calls.
    if (context.executionCeiling !== undefined && context.executionCeiling !== "prepare") {
      return this.gaveUp(issue.id, [], "unknown execution ceiling");
    }
    if (context.executionCeiling === "prepare" && context.admittedEdit === undefined && context.prepareAdmittedEdit === undefined) {
      return this.gaveUp(issue.id, [], "preparation requires content-bound project edit admission");
    }
    const budget = new RecoveryBudget(this.deps.spine, JSON.stringify([issue.repoRef, context.recoveryOperationId ?? issue.id]), {
      maxAttempts: (this.opts.maxRepairRounds ?? 3) + 1,
      maxElapsedMs: this.opts.recoveryMaxElapsedMs ?? 1_800_000,
      ...(context.memoryContext?.embeddingLimits === undefined ? {} : { embedding: context.memoryContext.embeddingLimits }),
    }, Date.now, context.signal, context.trackActivity);
    if (context.recoveryReconciliation) await budget.reconcile(context.recoveryReconciliation.attemptId, context.recoveryReconciliation.evidenceId);
    if (context.recoveryDiagnosis) await budget.resumeDiagnosis(context.recoveryDiagnosis.holdId, context.recoveryDiagnosis.evidenceId);
    let permit: RecoveryPermit;
    try { permit = await budget.reserve(); }
    catch (error) { return { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0, gaveUpReason: String(error), recovery: await budget.snapshot() }; }
    let result: SolveResult;
    try { result = await budget.withinDeadline(() => this.runAttempt(issue, files, context, budget, permit)); }
    catch (error) {
      await budget.hold(error instanceof RecoveryHeldError ? error.reason : "solve threw; reconciliation required");
      if (!(error instanceof RecoveryHeldError)) throw error;
      result = { issueId: issue.id, solved: false, stagesRun: [], repairRounds: 0, gaveUpReason: String(error) };
    } finally { await budget.finish(permit); }
    const recovery = await budget.snapshot();
    const finalRefusal = taskMemoryRefusal(context.memoryContext, context.assertAuthority);
    if (finalRefusal) {
      // A revoked command cannot return a successful proposal, including after
      // awaited tests or receipt construction. Compensation retains its own inverse
      // authority; it does not require the revoked forward-execution permission.
      try { if (this.deps.ledger.pending > 0) await this.deps.ledger.rollback(this.deps.ledger.pending, finalRefusal); }
      catch (error) { await budget.hold("authority changed; compensation requires reconciliation"); throw error; }
      await budget.hold(finalRefusal, "authority");
      return { ...this.gaveUp(issue.id, [...result.stagesRun], finalRefusal, result.localization), recovery: await budget.snapshot() };
    }
    if (result.preparedProposal !== undefined) {
      const refusal = taskMemoryRefusal(context.memoryContext);
      if (refusal || context.signal?.aborted || Date.now() >= recovery.deadline || !["ready", "exhausted"].includes(recovery.status)) {
        return { ...this.gaveUp(issue.id, [...result.stagesRun], refusal ?? "preparation budget is no longer active", result.localization), recovery };
      }
    }
    return inheritCanonicalAdmittedSolveResult(result, { ...result, recovery });
  }

  private async runAttempt(issue: Issue, files: readonly RepoFile[], context: SolveExecutionContext, budget: RecoveryBudget, permit: RecoveryPermit): Promise<SolveResult> {
    const narrator = new ProgressNarrator(issue.id, this.deps.spine);
    const stagesRun: SolveStage[] = [];

    // ROUND 40 — say so when a barrier has been configured into silence.
    //
    // Every other report in this pipeline fires on REFUSAL. A barrier that has been switched off
    // by configuration never refuses, so it is structurally invisible to all of them, and the
    // audit record of such a run is indistinguishable from a correctly-constrained one. This is
    // the only channel that reports a control which is NOT doing anything.
    //
    // Emitted through the narrator, so it lands in the operator's live feed AND on the
    // tamper-evident spine — a value on an object nobody reads would not be reporting.
    // Observe-only: it never changes a route, and a legal-but-wide configuration such as
    // `["*"]` is deliberately NOT reported (see `inertFloorInputs`).
    const inert = [
      ...inertFloorInputs(defaultFloorPolicy(issue.repoRef ?? "repo", this.deps.allowedPaths)),
      ...inertBudgetInputs(defaultBudgetPolicy()),
    ];
    for (const finding of inert) {
      // `narrate` already spine-logs every event ("Spine-log for the auditable trace"), so this
      // one call gives both the operator's feed and the tamper-evident record. A second explicit
      // audit() here would duplicate the same fact under two event shapes.
      narrator.narrate({ stage: "policy", phase: "blocked", headline: "A safety control is configured OFF", detail: finding });
    }
    const audit = (stage: SolveStage, payload: Record<string, unknown>) =>
      this.deps.spine.stage({ type: "identity.action", actor: "solve", payload: { stage, issueId: issue.id, ...payload } });

    // ── localize ──
    stagesRun.push("localize");
    narrator.start("localize", `Localizing the fix for issue ${issue.id}`);
    const hasProjectAdmission = context.admittedEdit !== undefined || context.prepareAdmittedEdit !== undefined;
    // The project already localized and vetted its evidence. Re-running a different
    // retrieval heuristic can lose its admitted task before preparation even starts.
    // Bind the selected write set after fresh admission validation below.
    let localization: LocalizationResult = hasProjectAdmission ? { suspects: [], stages: [] }
      : await budget.during(permit, () => this.deps.localizer.localize(issue, files, this.opts.localizeK ?? 3));
    let localizationEvidence: SolveLocalizationEvidence = {
      stages: Object.freeze([...localization.stages]),
      selected: Object.freeze(localization.suspects.map((suspect, index) => Object.freeze({
        path: suspect.path, rank: index + 1, score: suspect.score, isTest: suspect.isTest,
        ...(suspect.suspectSymbols ? { suspectSymbols: Object.freeze([...suspect.suspectSymbols]) } : {}),
        reason: `rank ${index + 1} from ${localization.stages.join(" + ")} retrieval at score ${suspect.score}${suspect.isTest ? "; test file was down-weighted" : ""}`,
      }))),
    };
    audit("localize", { suspects: localization.suspects.map((s) => s.path), stages: localization.stages });
    if (!hasProjectAdmission && localization.suspects.length === 0) {
      narrator.done("localize", "No suspect files found");
      return this.gaveUp(issue.id, stagesRun, "localization found no suspect files", localizationEvidence);
    }
    narrator.done("localize", hasProjectAdmission ? "Using persisted project localization; fresh admission checks still required" : `Suspect files: ${localization.suspects.map((s) => s.path).join(", ")}`);

    // ── plan ──
    stagesRun.push("plan");
    narrator.start("plan", "Planning the edit");
    if (context.admittedEdit && context.prepareAdmittedEdit) return this.gaveUp(issue.id, stagesRun, "conflicting prepared and deferred edit admission", localizationEvidence);
    const prepared = context.prepareAdmittedEdit ? await budget.during(permit, async signal => {
      try {
        return await context.prepareAdmittedEdit!({ signal,
          ...(context.assertAuthority === undefined ? {} : { assertAuthority: context.assertAuthority }),
          ...(context.memoryContext === undefined ? {} : { memoryContext: context.memoryContext }),
          reserveCall: bytes => budget.reservePlanningCall(permit, bytes), observe: event => audit("plan", event),
          reserveEmbedding: work => budget.reserveEmbeddingWork(permit, work),
        });
      } catch (error) {
        // Expected read-only refusal must not manufacture ambiguous effect debt.
        if (error instanceof ProjectEditAdmissionError) return error;
        throw error;
      }
    }) : context.admittedEdit;
    if (prepared instanceof ProjectEditAdmissionError) return this.gaveUp(issue.id, stagesRun, `project edit planning refused: ${prepared.message}`, localizationEvidence);
    const admitted = prepared;
    let admittedFiles: ReadonlySet<string> | undefined;
    if (admitted !== undefined) {
      const refusal = await this.validateAdmittedEdit(issue, files, admitted);
      if (refusal !== undefined) {
        narrator.done("plan", `Admitted project edit refused: ${refusal}`);
        return this.gaveUp(issue.id, stagesRun, `admitted project edit refused: ${refusal}`, localizationEvidence);
      }
      admittedFiles = new Set(admitted.allowedFiles);
      localization = { suspects: admitted.allowedFiles.map(path => ({ path, score: 0, isTest: isTestFile(path) })), stages: [] };
      localizationEvidence = { stages: [], selected: admitted.allowedFiles.map((path, index) => ({
        path, rank: index + 1, score: 0, isTest: isTestFile(path), reason: "freshly validated admitted project write set; no second retrieval ranking",
      })) };
    }
    const plan = admitted?.plan ?? await budget.during(permit, signal => planEdits(issue, localization, files, this.deps.model, {
      ...(context.assertAuthority === undefined ? {} : { assertAuthority: context.assertAuthority }),
      ...(context.memoryContext === undefined ? {} : { memoryContext: context.memoryContext }),
      signal, reserveCall: bytes => budget.reservePlanningCall(permit, bytes), observe: event => audit("plan", event),
      reserveEmbedding: work => budget.reserveEmbeddingWork(permit, work),
    }));
    audit("plan", { editCount: plan.edits.length, ...(context.memoryContext ? { memoryDerivativeNotice: context.memoryContext.copyNotice } : { rationale: plan.rationale }) });
    if (plan.edits.length === 0) {
      narrator.done("plan", "No edit plan produced");
      return this.gaveUp(issue.id, stagesRun, `edit planner produced no edits: ${plan.rationale}`, localizationEvidence);
    }
    narrator.done("plan", `Planned ${plan.edits.length} edit(s)`);

    // ── logic-vet the edit plan (deterministic pre-apply gate) ──
    // The LogicVet panel runs its SOUND deterministic critics over the concrete edits (mapped as
    // independent plan steps — no fabricated dependencies), with the rabbit-hole guard. Only a hard
    // BLOCK (a policy-forbidden/unsafe operation, or an errored vet) stops the apply — fail-closed,
    // never a silent apply of an unvetted plan; a rework/concern is audited and proceeds.
    const outside = admittedFiles === undefined ? [] : plan.edits.filter((edit) => !admittedFiles.has(edit.file)).map((edit) => edit.file);
    const scopeVerdict = outside.length === 0
      ? { blocked: false, reason: "" }
      : { blocked: true, reason: `edit targets files outside the admitted project step: ${[...new Set(outside)].sort().join(", ")}` };
    const planVerdict = this.vetEditPlan(issue, plan);
    audit("plan", { logicVet: planVerdict.verdict.decision, logicVetReason: planVerdict.verdict.reason, singleModel: planVerdict.singleModel });
    if (scopeVerdict.blocked || planVerdict.verdict.decision === "block") {
      const reason = scopeVerdict.blocked ? scopeVerdict.reason : planVerdict.verdict.reason;
      narrator.done("plan", `Edit plan blocked: ${reason}`);
      return this.gaveUp(issue.id, stagesRun, scopeVerdict.blocked ? `edit plan blocked before apply: ${reason}` : `logic-vet blocked the edit plan before apply: ${reason}`, localizationEvidence);
    }

    // An attenuated run ends before any effect port, runner, repair or PR work.
    // The returned data cannot be reused as admission: execution must validate a
    // fresh AdmittedEditPlan, and the enclosing project still owes the full goal.
    if (context.executionCeiling === "prepare") {
      await budget.assertLive(permit);
      const refusal = taskMemoryRefusal(context.memoryContext, context.assertAuthority);
      if (refusal) return this.gaveUp(issue.id, stagesRun, refusal, localizationEvidence);
      if (admitted === undefined) return this.gaveUp(issue.id, stagesRun, "preparation requires content-bound project edit admission", localizationEvidence);
      return {
        issueId: issue.id, solved: false, stagesRun, repairRounds: 0, localization: localizationEvidence,
        preparedProposal: { disposition: "unexecuted", repositoryRef: issue.repoRef,
          repositoryTreeSha256: admitted.repositoryTreeSha256, plan, goalFulfilled: false },
      };
    }

    const guardedRunner = (source: TestRunner): TestRunner => context.assertAuthority === undefined ? source : {
      run: async (repoRef, execution) => {
        const before = taskMemoryRefusal(undefined, context.assertAuthority);
        if (before) { await budget.hold(before, "authority"); throw new RecoveryHeldError(before); }
        const result = await source.run(repoRef, execution);
        const after = taskMemoryRefusal(undefined, context.assertAuthority);
        if (after) { await budget.hold(after, "authority"); throw new RecoveryHeldError(after); }
        return result;
      },
    };
    const regressionRunner = guardedRunner(this.deps.runner);
    let runner = regressionRunner;
    if (plan.goalCheck !== undefined) {
      const check = plan.goalCheck;
      if (!admitted || !this.deps.goalCheckRunnerFor || typeof check.body !== "string" || !check.body.trim()
        || Buffer.byteLength(check.body) > 16_384 || !/^[a-f0-9]{64}$/.test(check.requestSha256)) {
        return this.gaveUp(issue.id, stagesRun, "goal check lacks its bounded host execution capability", localizationEvidence);
      }
      const frozenCheck = Object.freeze({ body: check.body, requestSha256: check.requestSha256 });
      await budget.assertLive(permit);
      const checkMemoryRefusal = taskMemoryRefusal(context.memoryContext, context.assertAuthority);
      if (checkMemoryRefusal) return this.gaveUp(issue.id, stagesRun, checkMemoryRefusal, localizationEvidence);
      if (this.deps.identity && this.deps.identityRegistry && !this.deps.identityRegistry.authorize(this.deps.identity).authorized) {
        return this.gaveUp(issue.id, stagesRun, "goal check identity is no longer authorized", localizationEvidence);
      }
      const checkRunner = guardedRunner(this.deps.goalCheckRunnerFor(issue.repoRef, frozenCheck));
      const baseline = await budget.during(permit, signal => validate(issue.repoRef, checkRunner, {}, { signal, deadline: permit.deadline }));
      audit("plan", { goalCheck: "baseline", testsPassed: baseline.testsPassed, failureKind: baseline.failureKind });
      if (baseline.testsPassed || baseline.failureKind !== "product" || baseline.failures.includes("<runner-error>")) {
        return this.gaveUp(issue.id, stagesRun, "goal check did not demonstrate an executing baseline defect", localizationEvidence);
      }
      // Keep the verifier fixed across every repair. Model repair output never
      // replaces this runner or its argv; a stale repository suite is not enough.
      runner = { run: async (repoRef, execution) => {
        const regression = await regressionRunner.run(repoRef, execution);
        if (regression.runnerError) return regression;
        const outcome = await checkRunner.run(repoRef, execution);
        if (outcome.runnerError) return outcome;
        if (regression.results.length === 0 || outcome.results.length === 0) return { results: [], runnerError: "regression or goal verification discovered no tests", failureKind: "harness" };
        return { results: [...regression.results, ...outcome.results.map(row => ({ ...row, name: `goal: ${row.name}` }))] };
      } };
    }

    // ── apply ──
    stagesRun.push("apply");
    narrator.start("apply", "Applying the patch");
    await budget.assertLive(permit);
    const memoryRefusal = taskMemoryRefusal(context.memoryContext, context.assertAuthority);
    if (memoryRefusal) return this.gaveUp(issue.id, stagesRun, memoryRefusal, localizationEvidence);
    let applied: Awaited<ReturnType<typeof applyEditPlan>>;
    let initialRollbackId: string | undefined;
    if (admitted !== undefined || context.memoryContext !== undefined || context.assertAuthority !== undefined || (this.deps.reversibleEnvelope ?? true)) {
      // Negative-only preflight, as on the governed repair path. Resolve in an
      // isolated snapshot before registering any inverse or attempting a write.
      // A matched prefix is discarded when another hunk fails. Success here
      // grants nothing: live authority, freshness and commit checks remain below.
      // Exceptions still reach the existing uncertain-effect handler.
      const resolution = await resolveEditPlan(plan, new InMemoryFileTree(Object.fromEntries(files.map(file => [file.path, file.content]))));
      if (!resolution.ok) {
        const perEdit = resolution.perEdit.map(edit => ({ ...edit,
          status: edit.status === "applied" ? "held" as const : edit.status,
          reason: edit.reason ?? "whole plan refused before application",
        }));
        const why = resolution.perEdit.filter(edit => edit.status !== "applied")
          .map(edit => edit.reason ?? "plan is not applicable to the supplied snapshot").join("; ").slice(0, 500);
        audit("apply", { applied: false, classification: "non-applicable", effect: "not-attempted", perEdit });
        narrator.done("apply", `Patch not applied — ${why}`);
        return this.gaveUp(issue.id, stagesRun, `patch did not apply: ${why}`, localizationEvidence);
      }
      // BUILD-ORDER 2.5 (Z126) — this run takes the KEPT strangler-fig default. Record WHY the flag
      // is still kept as a durable, auditable spine fact (the specific unmet stabilization criterion
      // + its revisit condition), so a "keep" stays a governed decision and never drifts into a
      // silent permanent border. Fails closed if the record is ever hollowed out. Observe-only: this
      // never changes a route or the final tree state (benign work is byte-for-byte unaffected).
      audit("apply", { keptCutoverFlag: reversibleEnvelopeStabilizationFact() });
      // Strangler-fig ON path: route the reversible apply through the composed chain. The intent
      // applies the plan to a fork; the envelope commits the accepted result through the mediated
      // tree under a per-write grant (R23/R24 preserved). A human-hold route defers to the human path.
      const policies: IntegrationPolicies = {
        // BUILD-ORDER 2.2 (AUTHORIZE-THE-DECLARATION, Z156) — compose the ACTING AGENT's identity
        // scope into the floor policy as a SECOND authority, right where the operator's
        // `allowedPaths` is already composed. The floor then authorizes the declared write-set
        // against the INTERSECTION (allowedPaths ∩ identity.scope) via the SAME `withinScope`
        // predicate — one mechanism, not a second path-authority that could disagree (round 37
        // refused that). Omit the identity ⇒ `agentScope` stays absent ⇒ the floor policy is
        // byte-identical to the pre-2.2 global-only behaviour (front-of-house, no-identity path
        // unchanged). A legitimately minted/delegated identity's `.scope` is already the attenuated
        // intersection (the registry attenuates at delegate-time), so this composes attenuation
        // with the operator allowlist. THREAT BOUNDARY: a CONFUSED agent, not a COMPROMISED one
        // (R35-narrow) — OS-level attestation against a forged identity object is the R35 seam.
        floor: {
          ...defaultFloorPolicy(issue.repoRef ?? "repo", admitted?.allowedFiles ?? this.deps.allowedPaths),
          ...(this.deps.identity ? { agentScope: this.deps.identity.scope } : {}),
        },
        gate: defaultGatePolicy(),
        budget: defaultBudgetPolicy(),
        acceptance: defaultAcceptanceTest,
      };
      const intent: ReversibleIntent = {
        description: {
          kind: "file.edit",
          writeSet: plan.edits.map((e) => e.file),
          targets: plan.edits.map((e) => e.file),
          // R13 (round 32): COMPUTED, not asserted. This was hardcoded `true`, feeding the
          // structural floor a constant for one of its NECESSARY reversibility conditions —
          // `inverseConstructible` returns `op.hasInverse === true`, so the floor could never
          // refuse an irreversible op on this path.
          //
          // Conservative by design: reversibility is undecidable in general, so the honest
          // predicate answers "provably invertible" or "unknown ⇒ gate" rather than trying to be
          // exact. `canApply` already IS that predicate, exported and tested — it requires every
          // edit's search block to match EXACTLY ONCE, which is precisely the condition under
          // which a search/replace edit can be unambiguously reversed. Composed, not reinvented.
          hasInverse: await canApply(plan, this.deps.tree),
          raw: plan.edits.map((e) => e.replace).join("\n"),
        },
        apply: async (fork) => {
          // R14 (round 33): use the SAME match-or-refuse seam as the direct path.
          // This previously ran `if (cur.includes(search)) write(cur.replace(search, replace))`,
          // and `String.replace` with a string pattern replaces only the FIRST occurrence,
          // silently — so the envelope applied edits `applyEditPlan` REFUSES as ambiguous.
          // Two apply semantics was the bug. Now there is one, with two commit strategies: the
          // direct path commits through mediation + the rollback ledger; here the resolved
          // content is written to the fork, which the envelope itself rolls back.
          //
          // Refusal rather than disambiguation, following the established tool: git apply
          // "will refuse to create ambiguous hunks" and "fails the whole patch and does not
          // touch the working tree" when a hunk does not apply.
          const resolved = await resolveEditPlan(plan, fork);
          if (!resolved.ok) {
            // Surface the refusal rather than silently writing nothing — a silent no-op is its
            // own failure mode, and the caller must be able to tell "refused" from "applied
            // nothing". The envelope treats a throwing apply as a failed attempt and rolls back.
            throw new Error(
              `edit plan refused: ${resolved.perEdit.map((e) => `${e.file}:${e.status}${e.reason ? ` (${e.reason})` : ""}`).join("; ")}`,
            );
          }
          for (const [file, content] of resolved.nextContent) await fork.write(file, content);
        },
        actionTier: "reversible-internal",
      };
      if (admitted || context.memoryContext || context.assertAuthority) {
        initialRollbackId = `solve_${issue.id}_project_${Date.now()}`;
        const originals = new Map([...new Set(plan.edits.map((edit) => edit.file))].map((path) => [path, files.find((file) => file.path === path)!.content]));
        await this.registerRollbackBeforeEffect(issue.id, initialRollbackId, originals, plan, "initial");
      }
      const result = await executeReversibly(intent, policies, {
        spine: this.deps.spine,
        actor: "solve",
        operator: "solve",
        sign: (p) => `sig:${p}`,
        tree: this.deps.tree,
        ownerPresent: true,
        envelopeEnabled: true,
        ...(this.deps.identity ? { identity: this.deps.identity } : {}),
        ...(this.deps.identityRegistry ? { identityRegistry: this.deps.identityRegistry } : {}),
        ...(admitted || context.memoryContext || context.assertAuthority ? { precommit: async () => {
          const refusal = admitted ? await this.admissionFreshnessRefusal(admitted) : undefined;
          return refusal ?? taskMemoryRefusal(context.memoryContext, context.assertAuthority);
        } } : {}),
        ...(admitted ? { expectedContent: Object.freeze(Object.fromEntries([...new Set(plan.edits.map((edit) => edit.file))].map((path) => [path, files.find((file) => file.path === path)!.content]))) } : {}),
      });
      if (result.path === "envelope" && result.outcome.outcome === "committed") {
        applied = { applied: true, perEdit: plan.edits.map((e) => ({ file: e.file, status: "applied" as const })) };
      } else {
        // ROUND 34 — THE OPERATOR MUST LEARN WHY.
        //
        // This previously collapsed every non-commit to "reversible path did not commit:
        // human-hold" and labelled it `not-found`, discarding the reasons the gate had
        // already computed. That was survivable while the envelope was OFF, because these
        // holds never happened in production. With the envelope ON BY DEFAULT that string
        // is the FIRST thing an operator sees the first time a safety barrier fires.
        //
        // The config-safety research is that a staged rollout with production monitoring is
        // how a risky default change is normally de-risked — "configuration changes are
        // first applied to a small subset of traffic, devices, or regions before wider
        // promotion", with "explicit blast-radius control". A self-hosted, zero-dep, no-
        // telemetry tool CANNOT run that play: there is no fleet, no traffic split, and no
        // signal coming back. So the blast-radius budget has to be spent where it can
        // actually be spent — in the message the operator already reads.
        const why =
          result.path === "human-hold"
            ? `held for human review: ${result.reasons.join(", ")}`
            : result.path === "envelope" && result.outcome.outcome === "rolled-back"
              ? `rolled back: ${result.outcome.reason}${result.outcome.violated.length > 0 ? ` (violated: ${result.outcome.violated.join(", ")})` : ""}`
              : result.path === "envelope" && result.outcome.outcome === "refused"
                ? `refused by the envelope: ${result.outcome.reason}`
                : `did not commit: ${result.path}`;
        // `held`, not `not-found` — the file was found and the edit was well-formed; a
        // barrier refused it. See issue_model.ts.
        applied = { applied: false, perEdit: plan.edits.map((e) => ({ file: e.file, status: "held" as const, reason: why })) };
      }
    } else {
      applied = await applyEditPlan(plan, this.deps.tree, this.deps.ledger, { issueId: issue.id });
    }
    audit("apply", { applied: applied.applied, perEdit: applied.perEdit });
    if (!applied.applied) {
      // Carry the reason into the operator's live feed too, not just the return value.
      const why = applied.perEdit.map((e) => e.reason).filter(Boolean).join("; ");
      narrator.done("apply", why ? `Patch not applied — ${why}` : "Patch did not apply cleanly");
      return this.gaveUp(issue.id, stagesRun, `patch did not apply: ${why}`, localizationEvidence);
    }
    narrator.done("apply", "Patch applied");

    // ── validate ──
    stagesRun.push("validate");
    narrator.start("validate", "Running the test oracle");
    let validation = await budget.during(permit, signal => validate(issue.repoRef, runner, this.deps.vet ? { vet: this.deps.vet } : {}, { signal, deadline: permit.deadline }));
    await budget.finish(permit); // Inner repair consumes the same operation budget, not a fresh allowance.
    const firstPassCount = validation.passedCount ?? (validation.testsPassed ? 1 : 0);
    audit("validate", { testsPassed: validation.testsPassed, failures: validation.failures, vettingCleared: validation.vettingCleared });
    narrator.done("validate", validation.testsPassed ? "Tests passed" : `${validation.failures.length} test(s) failing`);
    if (validation.testsPassed && !validation.vettingCleared) {
      await budget.hold("authority hold: vetting refused", "authority");
      if (admitted) {
        if (this.deps.ledger.pending > 0) await this.deps.ledger.rollback(this.deps.ledger.pending, "admitted edit vetting refused");
        return { issueId: issue.id, solved: false, stagesRun, repairRounds: 0, localization: localizationEvidence, validation, gaveUpReason: validation.detail };
      }
      // A non-admitted proposal may still be presented to the existing human /
      // break-glass governance path. Its existence is not a claim of solved work.
    }

    // An unavailable oracle is not a code defect and must never enter model repair. More importantly,
    // an admitted project edit cannot remain in the canonical workspace without passing evidence.
    if (!validation.testsPassed && validation.failures.includes("<runner-error>")) {
      await budget.hold(`test capability requires diagnosis: ${validation.detail}`, "diagnosis");
      if (admitted && this.deps.ledger.pending > 0) await this.deps.ledger.rollback(this.deps.ledger.pending, "admitted edit lacked an executing test oracle");
      return { issueId: issue.id, solved: false, stagesRun, repairRounds: 0, localization: localizationEvidence, validation, gaveUpReason: validation.detail, ...(admitted ? { admittedEdit: admitted } : {}) };
    }

    // ── repair (only if needed) ──
    let repairRounds = 0;
    const retainedRepairPlans: EditPlan[] = [];
    const retainedRepairRollbackIds: string[] = [];
    if (!validation.testsPassed) {
      stagesRun.push("repair");
      narrator.start("repair", "Repairing against failing tests");
      const repair = await repairLoop(issue.id, issue.repoRef, validation, firstPassCount, {
        tree: this.deps.tree, runner, ledger: this.deps.ledger, spine: this.deps.spine,
        replan: async (feedback, _round, signal, repairPermit) => {
          if (!repairPermit) throw new RecoveryHeldError("repair planning requires its active attempt permit");
          const current = this.deps.snapshotFiles ? await this.deps.snapshotFiles() :
            await Promise.all(files.map(async file => ({ ...file, content: await this.deps.tree.read(file.path) ?? file.content })));
          const repaired = await planEdits(issue, localization, current, this.deps.model, {
            ...(context.assertAuthority === undefined ? {} : { assertAuthority: context.assertAuthority }),
            ...(context.memoryContext === undefined ? {} : { memoryContext: context.memoryContext }),
            repairContext: feedback, ...(signal ? { signal } : {}),
            reserveCall: bytes => budget.reservePlanningCall(repairPermit, bytes), observe: event => audit("plan", event),
            reserveEmbedding: work => budget.reserveEmbeddingWork(repairPermit, work),
          });
          const refusal = taskMemoryRefusal(context.memoryContext, context.assertAuthority);
          if (refusal) { await budget.hold(refusal, "authority"); throw new RecoveryHeldError(refusal); }
          return repaired;
        },
        recoveryBudget: budget,
        vetEditPlan: this.editPlanGate(issue, admittedFiles),
        applyPlan: (repairPlan, round) => this.applyGovernedRepair(issue, repairPlan, admitted?.allowedFiles ?? this.deps.allowedPaths, round, context.memoryContext, context.assertAuthority),
        ...(this.deps.withinBudget ? { withinBudget: this.deps.withinBudget } : {}),
        ...(this.deps.vet ? { vet: this.deps.vet } : {}),
      }, { maxRounds: this.opts.maxRepairRounds ?? 3 });
      repairRounds = repair.rounds;
      retainedRepairPlans.push(...repair.appliedPlans);
      retainedRepairRollbackIds.push(...repair.appliedRollbackIds);
      validation = repair.validation;
      audit("repair", { rounds: repair.rounds, solved: repair.solved, regressionTripped: repair.regressionTripped, gaveUpReason: repair.gaveUpReason });
      narrator.done("repair", repair.solved ? `Fixed after ${repair.rounds} round(s)` : `Gave up: ${repair.gaveUpReason}`);
      if (!repair.solved) {
        if (admitted && this.deps.ledger.pending > 0) await this.deps.ledger.rollback(this.deps.ledger.pending, "admitted edit did not pass bounded repair");
        return { issueId: issue.id, solved: false, stagesRun, repairRounds, localization: localizationEvidence, validation, ...(repair.gaveUpReason ? { gaveUpReason: repair.gaveUpReason } : {}), ...(admitted ? { admittedEdit: admitted } : {}) };
      }
    }

    // ── done: build the PR proposal (never auto-merge) ──
    stagesRun.push("done");
    const finalPlan: EditPlan = retainedRepairPlans.length === 0 ? plan : {
      rationale: [plan.rationale, ...retainedRepairPlans.map((repair, index) => `Repair ${index + 1}: ${repair.rationale}`)].join("\n"),
      edits: Object.freeze([...[...plan.edits], ...retainedRepairPlans.flatMap((repair) => [...repair.edits])]),
    };
    // The SAME `inert` value computed at run start — threaded, not recomputed. A second
    // computation would be a second threshold, and the two could drift apart (Z161/R14 shape).
    const prProposal = buildPrProposal(issue, finalPlan, validation.testsPassed, inert);
    audit("done", { branch: prProposal.branch, testsPassed: prProposal.testsPassed });
    narrator.done("done", `PR proposed on ${prProposal.branch} — awaiting human review (never auto-merged)`);

    const solvedResult: SolveResult = { issueId: issue.id, solved: validation.testsPassed && validation.vettingCleared, stagesRun, repairRounds, localization: localizationEvidence, validation, prProposal, ...(inert.length > 0 ? { inertControls: inert } : {}), ...(admitted ? { admittedEdit: admitted } : {}) };
    if (admitted) {
      const touched = [...new Set(finalPlan.edits.map((edit) => edit.file))].sort();
      const touchedFiles = await Promise.all(touched.map(async (path) => {
        const after = await this.deps.tree.read(path);
        if (after === undefined) throw new Error(`committed project edit target disappeared before receipt: ${path}`);
        return Object.freeze({ path, beforeSha256: admitted.allowedFileSha256[path]!, afterSha256: sha256Text(after) });
      }));
      const projectEditReceipt = Object.freeze({
        schemaVersion: 1, admissionSha256: sha256Text(JSON.stringify(admitted)),
        repositoryTreeAfterSha256: projectRepositoryTreeSha256(await this.deps.snapshotFiles!()),
        touchedFiles: Object.freeze(touchedFiles),
        rollbackIds: Object.freeze([...(initialRollbackId ? [initialRollbackId] : []), ...retainedRepairRollbackIds]), applied: true, testsExecuted: true,
      } as const);
      const attestedResult: SolveResult = { ...solvedResult, projectEditReceipt };
      canonicalAdmittedResults.add(attestedResult);
      return attestedResult;
    }
    return solvedResult;
  }

  private async registerRollbackBeforeEffect(issueId: string, rollbackId: string, originals: ReadonlyMap<string, string>, plan: EditPlan, phase: string): Promise<void> {
    const resolved = await resolveEditPlan(plan, new InMemoryFileTree(Object.fromEntries(originals)));
    if (!resolved.ok) throw new Error(`cannot register rollback for non-applicable ${phase} plan`);
    const expectedPost = Object.freeze(Object.fromEntries(resolved.nextContent));
    this.deps.ledger.record({
      id: rollbackId, artifact: `worktree:${issueId}:${phase}`,
      undo: async () => {
        if (!this.deps.tree.commitBatchIfUnchanged) throw new Error("rollback requires atomic batch compare-and-swap support");
        const restores = [...originals].map(([path, content]) => ({ path, content }));
        const alreadyOriginal = (await Promise.all(restores.map(async ({ path, content }) => (await this.deps.tree.read(path)) === content))).every(Boolean);
        if (alreadyOriginal) return; // intent was durable, but the guarded effect never committed (or was already compensated)
        const grant = new WriteGrant(restores);
        const restored = await runMediatedWith(grant, () => this.deps.tree.commitBatchIfUnchanged!(expectedPost, restores));
        if (!restored) throw new Error("rollback refused because committed bytes changed");
      },
    });
  }

  /** Repairs use the same floor → gate → identity → envelope chain as the initial project edit. */
  private async applyGovernedRepair(issue: Issue, plan: EditPlan, allowedPaths: readonly string[] | undefined, round: number, memoryContext?: TaskMemoryContext, assertAuthority?: () => void): Promise<PatchApplyResult> {
    const repairTreeDigest = this.deps.snapshotFiles ? projectRepositoryTreeSha256(await this.deps.snapshotFiles()) : undefined;
    const originals = new Map<string, string>();
    for (const path of new Set(plan.edits.map((edit) => edit.file))) {
      const content = await this.deps.tree.read(path);
      if (content === undefined) return { applied: false, perEdit: plan.edits.map((edit) => ({ file: edit.file, status: "not-found" as const, reason: "repair target disappeared" })) };
      originals.set(path, content);
    }
    // A model repair can legitimately be stale or non-applicable. That is a normal
    // fail-closed patch result, not an exceptional rollback-ledger failure. Resolve
    // before registering the inverse so a refused plan creates neither an effect nor
    // a misleading dormant rollback record.
    const repairResolution = await resolveEditPlan(plan, new InMemoryFileTree(Object.fromEntries(originals)));
    if (!repairResolution.ok) {
      return {
        applied: false,
        perEdit: repairResolution.perEdit.map((edit) => ({
          file: edit.file,
          status: edit.status === "applied" ? "held" as const : edit.status,
          reason: edit.reason ?? "repair plan is not applicable to the current bytes",
        })),
      };
    }
    const policies: IntegrationPolicies = {
      floor: { ...defaultFloorPolicy(issue.repoRef ?? "repo", allowedPaths), ...(this.deps.identity ? { agentScope: this.deps.identity.scope } : {}) },
      gate: defaultGatePolicy(), budget: defaultBudgetPolicy(), acceptance: defaultAcceptanceTest,
    };
    const intent: ReversibleIntent = {
      description: {
        kind: "file.edit", writeSet: plan.edits.map((edit) => edit.file), targets: plan.edits.map((edit) => edit.file),
        hasInverse: await canApply(plan, this.deps.tree), raw: plan.edits.map((edit) => edit.replace).join("\n"),
      },
      apply: async (fork) => {
        const resolved = await resolveEditPlan(plan, fork);
        if (!resolved.ok) throw new Error(`repair edit plan refused: ${resolved.perEdit.map((edit) => `${edit.file}:${edit.status}`).join("; ")}`);
        for (const [file, content] of resolved.nextContent) await fork.write(file, content);
      },
      actionTier: "reversible-internal",
    };
    const rollbackId = `solve_${issue.id}_repair_${round}_${Date.now()}`;
    await this.registerRollbackBeforeEffect(issue.id, rollbackId, originals, plan, `repair:${round}`);
    const result = await executeReversibly(intent, policies, {
      spine: this.deps.spine, actor: "solve-repair", operator: "solve", sign: (payload) => `sig:${payload}`,
      tree: this.deps.tree, ownerPresent: true, envelopeEnabled: true,
      ...(this.deps.identity ? { identity: this.deps.identity } : {}),
      ...(this.deps.identityRegistry ? { identityRegistry: this.deps.identityRegistry } : {}),
      precommit: async () => {
        if (repairTreeDigest !== undefined && this.deps.snapshotFiles && projectRepositoryTreeSha256(await this.deps.snapshotFiles()) !== repairTreeDigest) return "repository changed before repair commit";
        for (const [path, expected] of originals) if (await this.deps.tree.read(path) !== expected) return `repair target changed before commit: ${path}`;
        return taskMemoryRefusal(memoryContext, assertAuthority);
      },
      expectedContent: Object.freeze(Object.fromEntries(originals)),
    });
    if (result.path !== "envelope" || result.outcome.outcome !== "committed") {
      const reason = result.path === "human-hold" ? result.reasons.join(", ")
        : result.path === "envelope" ? result.outcome.outcome === "committed" ? "unexpected committed result" : result.outcome.reason
        : "direct fallback was unexpectedly selected";
      return { applied: false, perEdit: plan.edits.map((edit) => ({ file: edit.file, status: "held" as const, reason })) };
    }
    this.deps.spine.stage({ type: "identity.action", actor: "solve-repair", payload: { event: "governed_repair_committed", issueId: issue.id, round, rollbackId } });
    return { applied: true, perEdit: plan.edits.map((edit) => ({ file: edit.file, status: "applied" as const })), rollbackId };
  }

  /** Re-establish every durable project-stage claim at the immediate pre-effect boundary. */
  private async admissionFreshnessRefusal(admitted: AdmittedEditPlan): Promise<string | undefined> {
    if (this.deps.snapshotFiles === undefined) return "trusted live repository snapshot unavailable before commit";
    const liveFiles = await this.deps.snapshotFiles();
    if (projectRepositoryTreeSha256(liveFiles) !== admitted.repositoryTreeSha256) return "live repository changed before admitted edit commit";
    for (const path of admitted.allowedFiles) {
      const expected = admitted.allowedFileSha256[path];
      const live = await this.deps.tree.read(path);
      if (live === undefined || expected === undefined || sha256Text(live) !== expected) return `admitted file changed before commit: ${path}`;
    }
    return undefined;
  }

  /** Re-establish every durable project-stage claim at the immediate pre-effect boundary. */
  private async validateAdmittedEdit(issue: Issue, files: readonly RepoFile[], admitted: AdmittedEditPlan): Promise<string | undefined> {
    if (admitted.schemaVersion !== 1 || admitted.mechanism !== "project-edit-stage") return "unsupported admitted-edit schema or mechanism";
    if (admitted.repositoryRef !== issue.repoRef) return "proposal repository does not match the issue repository";
    if (issue.hints?.["projectTaskId"] !== admitted.taskId || issue.hints?.["planStepId"] !== admitted.planStepId) return "proposal is not bound to the admitted project task and plan step";
    if (this.deps.snapshotFiles === undefined) return "canonical solver has no trusted live repository snapshot capability";
    const liveFiles = await this.deps.snapshotFiles();
    if (admitted.repositoryTreeSha256 !== projectRepositoryTreeSha256(liveFiles)) return "live repository bytes changed after project edit planning";
    if (projectRepositoryTreeSha256(files) !== projectRepositoryTreeSha256(liveFiles)) return "caller repository snapshot is stale";
    if (!Array.isArray(admitted.allowedFiles) || admitted.allowedFiles.length === 0 || new Set(admitted.allowedFiles).size !== admitted.allowedFiles.length) {
      return "admitted file set must be non-empty and duplicate-free";
    }
    if (admitted.allowedFileSha256 === null || typeof admitted.allowedFileSha256 !== "object" || Array.isArray(admitted.allowedFileSha256)) {
      return "admitted file hashes are malformed";
    }
    const byPath = new Map(liveFiles.map((file) => [file.path, file.content]));
    const hashKeys = Object.keys(admitted.allowedFileSha256).sort();
    const allowed = [...admitted.allowedFiles].sort();
    if (hashKeys.length !== allowed.length || hashKeys.some((key, index) => key !== allowed[index])) return "admitted file hashes do not exactly cover the admitted file set";
    for (const path of allowed) {
      const listed = byPath.get(path);
      const live = await this.deps.tree.read(path);
      const expected = admitted.allowedFileSha256[path];
      if (listed === undefined || live === undefined || typeof expected !== "string" || sha256Text(listed) !== expected || sha256Text(live) !== expected) {
        return `admitted file changed or disappeared before apply: ${path}`;
      }
    }
    if (!Array.isArray(admitted.plan?.edits) || admitted.plan.edits.length === 0 || typeof admitted.plan.rationale !== "string") return "admitted edit plan is malformed";
    if (admitted.plan.edits.some((edit) => !admitted.allowedFiles.includes(edit.file))) return "admitted edit plan exceeds its file authority";
    return undefined;
  }

  private gaveUp(issueId: string, stagesRun: SolveStage[], reason: string, localization?: SolveLocalizationEvidence): SolveResult {
    stagesRun.push("gave-up");
    return { issueId, solved: false, stagesRun, repairRounds: 0, ...(localization ? { localization } : {}), gaveUpReason: reason };
  }
}

/** Build a human-reviewable PR proposal from a solved issue. Never merges. */
export function buildPrProposal(issue: Issue, plan: EditPlan, testsPassed: boolean, inertControls: readonly string[] = []): PrProposal {
  const branch = `keep/solve/${issue.id}`;
  const fileList = [...new Set(plan.edits.map((e) => e.file))];
  const body = [
    `## Fixes ${issue.id}`,
    ``,
    `**Issue:** ${issue.text}`,
    ``,
    `**Approach:** ${plan.rationale || "(see edits)"}`,
    ``,
    `**Files changed:** ${fileList.join(", ")}`,
    ``,
    `**Edits:**`,
    ...plan.edits.map((e) => `- \`${e.file}\`: ${e.intent}`),
    ``,
    testsPassed ? `✅ All tests pass.` : `⚠️ Tests do not all pass — review carefully.`,
    // ROUND 41 — a control that is switched off belongs beside the merge decision, not only in a
    // progress feed that scrolls. Written as a plain sentence an operator can act on, because the
    // PR body is a product surface and a policy identifier would not be read.
    //
    // Emitted ONLY when there is something to say — no heading, no "0 issues" line on a clean
    // run. A section that is usually empty is the section people learn to skip, which is the
    // habituation failure this round exists to avoid.
    ...(inertControls.length > 0
      ? [
          ``,
          `### ⚠️ A safety control was switched off for this run`,
          `Keep produced this change with one of its own checks disabled, so the usual evidence is weaker than it looks:`,
          ...inertControls.map((c) => `- ${c}`),
          `Autonomous merge was suppressed because of this — a person needs to decide.`,
        ]
      : []),
    ``,
    `_Proposed by Keep. This PR is awaiting human review and will not be merged automatically._`,
  ].join("\n");
  return { title: `Fix ${issue.id}`, body, branch, edits: plan.edits, testsPassed };
}
