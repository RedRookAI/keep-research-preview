/**
 * Best-of-N resolution (Increment R1) — the foundation of the resolution moat. Generate N candidate solutions for
 * an issue, score each with Keep's DETERMINISTIC verifier, and select the best by verification evidence — never by
 * model self-confidence.
 *
 * SOTA basis (2026-08-06):
 *  - Rule-based / execution-grounded verifiers are more objective than preference/reward-model scoring and free of
 *    inductive bias (arXiv 2503.24320; 2602.07670). Keep selects on `verifyPatch` (its SOUND tier-1 checks), the
 *    same verifier used by the safety gate — "training/selecting with the same verifier used at test time is
 *    critical" (arXiv 77gQUdQhE7).
 *  - Naive best-of-N DEGRADES via reward hacking when the verifier is imperfect (OpenReview QnjfkhrbYK; arXiv
 *    2604.04648). Mitigation here: score PRIMARILY on SOUND checks (hard to game — no-test-modification,
 *    no-secrets, edits-well-formed); heuristic flags are tie-breakers only; and selection is PESSIMISTIC — among
 *    equally-verified candidates the SAFER one (smaller blast radius, tests passed) wins.
 *  - Compute-optimal test-time scaling = sample for DIVERSITY + intelligent selection, not sharpening toward
 *    high-confidence modes (arXiv 2602.07670). N is bounded and we early-stop once a candidate is verified-clean.
 *
 * Best-of-N chooses WHICH candidate is proposed; it never decides whether a human reviews. The winner still flows
 * through the oversight tiering + the permanent human merge gate. Zero deps.
 *
 * What would change it: a trained reward/verifier model can be added as a tier-2 seam behind the same selection,
 * but SOUND deterministic checks stay primary (anti-hacking); a learned selector is R2 (hybrid), layered on top.
 */

import type { Issue, SolveResult } from "../solve/issue_model.js";
import { verifyPatch, type PatchVerdict, type PatchVerifierInput } from "../pipeline/patch_verifier.js";
import type { Spine } from "../spine/spine.js";
import type { Workspace } from "../solve/workspace.js";
import { randomUUID } from "node:crypto";

/** The N-sampling seam: produce the i-th candidate solution. A real provider samples at temperature for diversity. */
export interface CandidateExecution {
  /** Unique within one best-of-N run; callers use it to allocate a separate worktree/sandbox. */
  readonly executionId: string;
  readonly sampleIndex: number;
  readonly workspace?: Workspace;
  readonly repoRef?: string;
  readonly resolutionId?: string;
}
export type CandidateSolver = ((issue: Issue, sampleIndex: number, execution?: CandidateExecution) => Promise<SolveResult>) & { finishResolution?: (resolutionId: string) => void | Promise<void> };

export interface CandidateEvidence {
  readonly index: number;
  readonly executionId: string;
  readonly cleared: boolean;
  readonly testsPassed: boolean;
  readonly soundFailures: number;
  readonly flags: number;
  readonly outcome: PatchVerdict["outcome"] | "no-patch";
  readonly editCount: number;
}

export interface ResolutionDecisionPacket {
  readonly issueId: string;
  readonly requestedN: number;
  readonly sampled: number;
  readonly selectedIndex: number;
  readonly winnerCleared: boolean;
  readonly rationale: string;
  readonly candidates: readonly CandidateEvidence[];
}

export interface ScoredCandidate {
  readonly index: number;
  readonly result: SolveResult;
  readonly verdict: PatchVerdict | null; // null → the candidate produced no patch
  readonly soundFailures: number; // sound checks that FAILED (primary, anti-hacking signal)
  readonly flags: number; // heuristic flags (tie-breaker only)
  readonly cleared: boolean;
  readonly testsPassed: boolean;
  readonly editCount: number; // smaller = safer (pessimism)
  readonly repairRounds: number;
}

export interface BestOfNResult {
  readonly winner: SolveResult;
  readonly winnerVerdict: PatchVerdict | null;
  readonly winnerCleared: boolean;
  readonly scored: readonly ScoredCandidate[];
  readonly selectedIndex: number;
  readonly sampled: number;
  /** True iff at least one candidate cleared all sound checks — otherwise the winner is "least-bad", not verified. */
  readonly anyCleared: boolean;
  readonly decisionPacket: ResolutionDecisionPacket;
  readonly n1Baseline?: N1BaselineRecord;
}

export interface TaskFidelityMeasurement {
  readonly fullCoverage: boolean;
  readonly required: readonly string[];
  readonly covered: readonly string[];
  readonly missing: readonly string[];
  readonly extraneous: readonly string[];
  readonly basis: string;
}

export interface N1BaselineRecord {
  readonly candidateCount: 1;
  readonly correctness: { readonly solved: boolean; readonly verifierCleared: boolean; readonly testsPassed: boolean; readonly soundFailures: number };
  readonly taskFidelity: { readonly measured: true; readonly value: TaskFidelityMeasurement } | { readonly measured: false; readonly reason: string };
  readonly cost: { readonly measured: true; readonly usd: number; readonly basis: string } | { readonly measured: false; readonly reason: string };
  readonly latencyMs: number;
}

export interface BestOfNOptions {
  readonly n: number;
  readonly issueText?: string;
  readonly maxEdits?: number;
  /** Early-stop once a candidate clears all sound checks AND passed tests (compute-optimal). Default true. */
  readonly stopWhenClean?: boolean;
  /** Maximum simultaneously isolated samples. Defaults to N when collecting the full pool. */
  readonly concurrency?: number;
}

export interface SelectionResult {
  /** Index into the passed (already-cleared) array of the chosen candidate. */
  readonly index: number;
  readonly rationale: string;
}

/** R2 seam: choose among candidates that have ALL passed verification (applied only to the cleared set). */
export interface CandidateSelector {
  select(cleared: readonly ScoredCandidate[]): SelectionResult;
}

export interface BestOfNDeps {
  readonly sample: CandidateSolver;
  readonly verify?: (input: PatchVerifierInput) => PatchVerdict;
  readonly spine?: Spine;
  /** R2: hybrid selector for the verified set. Absent → deterministic safety-first tie-break (R1 behavior). */
  readonly selector?: CandidateSelector;
  readonly measureTaskFidelity?: (issue: Issue, result: SolveResult) => TaskFidelityMeasurement;
  readonly measureCostUsd?: (issue: Issue, result: SolveResult) => number | undefined;
  readonly now?: () => number;
}

/** The built-in default selector: R1 deterministic safety-first tie-break over the cleared set. */
const DEFAULT_SELECT = (cleared: readonly ScoredCandidate[]): SelectionResult => {
  let best = 0;
  for (let i = 1; i < cleared.length; i++) if (compareCandidates(cleared[i]!, cleared[best]!) < 0) best = i;
  return { index: best, rationale: `deterministic tie-break (safety-first) among ${cleared.length} verified candidate(s)` };
};

function selectFromCleared(selector: CandidateSelector | undefined, cleared: readonly ScoredCandidate[]): SelectionResult {
  if (!selector) return DEFAULT_SELECT(cleared);
  try {
    const selected = selector.select(cleared);
    if (Number.isInteger(selected.index) && selected.index >= 0 && selected.index < cleared.length && typeof selected.rationale === "string" && selected.rationale.trim() !== "") return selected;
  } catch { /* malformed selector output cannot escape the verified-set fallback */ }
  const fallback = DEFAULT_SELECT(cleared);
  return { ...fallback, rationale: `selector rejected; ${fallback.rationale}` };
}

const WORST = Number.POSITIVE_INFINITY;

function scoreCandidate(index: number, result: SolveResult, verify: (i: PatchVerifierInput) => PatchVerdict, issueText: string | undefined, maxEdits: number | undefined): ScoredCandidate {
  if (!result.solved || !result.prProposal) {
    // No patch produced — sorts last; cannot be verified.
    return { index, result, verdict: null, soundFailures: WORST, flags: WORST, cleared: false, testsPassed: false, editCount: WORST, repairRounds: result.repairRounds ?? 0 };
  }
  const verdict = verify({ solveResult: result, ...(issueText ? { issueText } : {}), ...(maxEdits !== undefined ? { maxEdits } : {}) });
  let soundFailures = 0, flags = 0;
  for (const c of verdict.checks) {
    if (c.sound && c.decision === "fail") soundFailures++;
    if (c.decision === "flag") flags++;
  }
  return {
    index, result, verdict,
    soundFailures, flags,
    cleared: verdict.cleared,
    testsPassed: result.prProposal.testsPassed,
    editCount: result.prProposal.edits.length,
    repairRounds: result.repairRounds ?? 0,
  };
}

const outcomeRank = (v: PatchVerdict | null): number => (v?.outcome === "pass" ? 0 : v?.outcome === "escalate-human" ? 1 : 2);

/** Pessimistic ordering: lower is better. Sound-correctness first, then safety (smaller/tested), flags last. */
export function compareCandidates(a: ScoredCandidate, b: ScoredCandidate): number {
  // 1) produced a patch at all
  const ap = a.verdict ? 0 : 1, bp = b.verdict ? 0 : 1;
  if (ap !== bp) return ap - bp;
  // 2) fewer SOUND failures (primary — anti reward-hacking)
  if (a.soundFailures !== b.soundFailures) return a.soundFailures - b.soundFailures;
  // 3) cleared beats not-cleared
  if (a.cleared !== b.cleared) return a.cleared ? -1 : 1;
  // 4) better verifier outcome
  const ao = outcomeRank(a.verdict), bo = outcomeRank(b.verdict);
  if (ao !== bo) return ao - bo;
  // 5) tests passed
  if (a.testsPassed !== b.testsPassed) return a.testsPassed ? -1 : 1;
  // 6) fewer heuristic flags
  if (a.flags !== b.flags) return a.flags - b.flags;
  // 7) smaller blast radius (pessimism: prefer the safer, smaller change)
  if (a.editCount !== b.editCount) return a.editCount - b.editCount;
  // 8) fewer repair rounds
  if (a.repairRounds !== b.repairRounds) return a.repairRounds - b.repairRounds;
  // 9) stable: prefer the earlier sample
  return a.index - b.index;
}

/** Score a set of candidate results against the deterministic floor (verifyPatch). Exposed for R3. */
export function scoreAll(results: readonly SolveResult[], opts: { verify?: (i: PatchVerifierInput) => PatchVerdict; issueText?: string; maxEdits?: number } = {}): ScoredCandidate[] {
  const verify = opts.verify ?? verifyPatch;
  return results.map((r, i) => scoreCandidate(i, r, verify, opts.issueText, opts.maxEdits));
}

/** Sample up to N candidates, verify each deterministically, and select the best by the pessimistic ordering. */
export async function selectBestOfN(deps: BestOfNDeps, issue: Issue, opts: BestOfNOptions): Promise<BestOfNResult> {
  const verify = deps.verify ?? verifyPatch;
  const stopWhenClean = opts.stopWhenClean ?? true;
  const n = Math.max(1, opts.n);
  const scored: ScoredCandidate[] = [];
  const resolutionId = randomUUID();
  const sampleLatency: number[] = [];
  const sampleCost: Array<{ usd: number; basis: string } | undefined> = [];

  const sampleOne = async (i: number): Promise<SolveResult> => {
    if (n !== 1) return deps.sample(issue, i, { executionId: `${issue.id}:candidate:${i}`, sampleIndex: i, resolutionId });
    const now = deps.now ?? (() => performance.now()); const started = now();
    const before = deps.spine?.currentEvents().length ?? 0;
    const result = await deps.sample(issue, i, { executionId: `${issue.id}:candidate:${i}`, sampleIndex: i, resolutionId });
    sampleLatency[i] = Math.max(0, now() - started);
    const explicit = deps.measureCostUsd?.(issue, result);
    if (explicit !== undefined && Number.isFinite(explicit) && explicit >= 0) sampleCost[i] = { usd: explicit, basis: "configured candidate cost meter" };
    else if (deps.spine) {
      const spans = deps.spine.currentEvents().slice(before).map((event) => event.payload as Record<string, unknown>).filter((payload) => payload["event"] === "span" && payload["taskId"] === issue.id && typeof payload["totalUsd"] === "number");
      if (spans.length > 0) sampleCost[i] = { usd: spans.reduce((sum, payload) => sum + Number(payload["totalUsd"]), 0), basis: `${spans.length} newly recorded trace span(s)` };
    }
    return result;
  };

  try {
    if (stopWhenClean) {
      for (let i = 0; i < n; i++) {
        const result = await sampleOne(i);
        const s = scoreCandidate(i, result, verify, opts.issueText, opts.maxEdits);
        scored.push(s);
        if (s.cleared && s.testsPassed) break;
      }
    } else {
      const concurrency = Math.max(1, Math.min(n, opts.concurrency ?? n));
      let next = 0;
      const workers = Array.from({ length: concurrency }, async () => {
        while (next < n) {
          const i = next++;
          const result = await sampleOne(i);
          scored[i] = scoreCandidate(i, result, verify, opts.issueText, opts.maxEdits);
        }
      });
      await Promise.all(workers);
    }
  } finally { await deps.sample.finishResolution?.(resolutionId); }

  const cleared = scored.filter((s) => s.cleared);
  let winner: ScoredCandidate;
  let selectionRationale: string;
  if (cleared.length > 0) {
    // Floor enforced: the selector only ever sees VERIFIED candidates, so it cannot override verification (R2).
    const sel = selectFromCleared(deps.selector, cleared);
    winner = cleared[sel.index]!;
    selectionRationale = sel.rationale;
  } else {
    winner = [...scored].sort(compareCandidates)[0]!;
    selectionRationale = "no candidate cleared verification — least-bad selected (flows to human review)";
  }
  const anyCleared = cleared.length > 0;
  const candidates: CandidateEvidence[] = scored.map((s) => ({
    index: s.index, executionId: `${issue.id}:candidate:${s.index}`, cleared: s.cleared,
    testsPassed: s.testsPassed, soundFailures: s.soundFailures === WORST ? -1 : s.soundFailures,
    flags: s.flags === WORST ? -1 : s.flags, outcome: s.verdict?.outcome ?? "no-patch",
    editCount: s.editCount === WORST ? -1 : s.editCount,
  }));
  const decisionPacket: ResolutionDecisionPacket = {
    issueId: issue.id, requestedN: n, sampled: scored.length, selectedIndex: winner.index,
    winnerCleared: winner.cleared, rationale: selectionRationale, candidates,
  };
  let n1Baseline: N1BaselineRecord | undefined;
  if (n === 1) {
    const fidelity = deps.measureTaskFidelity?.(issue, winner.result); const cost = sampleCost[winner.index];
    n1Baseline = Object.freeze({
      candidateCount: 1,
      correctness: Object.freeze({ solved: winner.result.solved, verifierCleared: winner.cleared, testsPassed: winner.testsPassed, soundFailures: winner.soundFailures === WORST ? -1 : winner.soundFailures }),
      taskFidelity: fidelity ? Object.freeze({ measured: true as const, value: fidelity }) : Object.freeze({ measured: false as const, reason: "no task-fidelity evaluator was configured; correctness is not treated as fidelity" }),
      cost: cost ? Object.freeze({ measured: true as const, usd: cost.usd, basis: cost.basis }) : Object.freeze({ measured: false as const, reason: "no candidate cost meter or attributable trace span was recorded; cost is unknown, not zero" }),
      latencyMs: sampleLatency[winner.index] ?? 0,
    });
  }

  deps.spine?.stage({
    type: "identity.action", actor: "best-of-n",
    payload: {
      event: "resolve.best_of_n",
      issueId: issue.id,
      sampled: scored.length,
      requestedN: n,
      selectedIndex: winner.index,
      winnerCleared: winner.cleared,
      anyCleared,
      selection: selectionRationale,
      decisionPacket,
      ...(n1Baseline ? { n1Baseline } : {}),
      candidates,
      ts: Date.now(),
    },
  });

  return { winner: winner.result, winnerVerdict: winner.verdict, winnerCleared: winner.cleared, scored, selectedIndex: winner.index, sampled: scored.length, anyCleared, decisionPacket, ...(n1Baseline ? { n1Baseline } : {}) };
}

/** Drop-in solver: best-of-N wrapped as a single (issue) → SolveResult, for the deploy-time solve seam / pipeline. */
export function makeBestOfNSolver(deps: BestOfNDeps, opts: BestOfNOptions): (issue: Issue) => Promise<SolveResult> {
  return async (issue: Issue) => (await selectBestOfN(deps, issue, opts)).winner;
}

