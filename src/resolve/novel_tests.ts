/**
 * Novel-test generation (Increment R3) — strengthen the verifier by generating DISCRIMINATING tests, and turn R2's
 * static approach-clustering into behavioral pass-profile clustering. The model that generates tests and the runner
 * that executes them are SEAMS; the pass-matrix ANALYSIS here is deterministic, zero-dep, and fully tested.
 *
 * SOTA basis (2026-08-06):
 *  - Neither code nor tests are guaranteed correct — "we need reliable tests to judge code and reliable code to
 *    judge tests, but have neither" (ACES, arXiv 2604.03922). So generated tests are HYPOTHESES, not ground truth
 *    (Nexus 2510.26423; TOGLL; TianPan): they inform selection + escalation, they can never auto-approve, and the
 *    SOUND floor (R1 verifyPatch) stays primary.
 *  - Weight tests by DISCRIMINATIVE POWER, not uniformly — a test's value tracks its pass-rate variance p(1-p)
 *    (ACES): a test everyone passes carries no signal; one that splits the pool ~50/50 is maximally informative.
 *  - A test that NO candidate passes is likely wrong / over-constrained → discard ("who tests the tests", ACES).
 *  - Behavioral evidence beats aggregation rules — cluster candidates by pass-profile (SemanticVote 2605.08680,
 *    +19–52 pts over output-pattern voting; CodeT consensus sets).
 *  - A behavioral fork among verified candidates → ESCALATE to a human; differential testing surfaces the fork
 *    (arXiv 2605.20473), but a majority can be confidently wrong (SEP 2604.06485), so Keep does not auto-pick it.
 *
 * What would change it: with a sandbox, the executor runs the tests for real (here it is injected); a multi-agent
 * deliberation-validation oracle (Nexus/CANDOR) can strengthen the generator behind the same port.
 */

import type { Issue, SolveResult } from "../solve/issue_model.js";
import { scoreAll, compareCandidates, type ScoredCandidate, type CandidateSelector, type CandidateSolver } from "./best_of_n.js";
import { makeHybridSelector } from "./selector.js";
import type { PatchVerifierInput, PatchVerdict } from "../pipeline/patch_verifier.js";
import type { Spine } from "../spine/spine.js";
import { randomUUID } from "node:crypto";

export interface GeneratedTest {
  readonly id: string;
  readonly description: string;
  // Executable content is deploy-side (the runner seam); the analysis only needs pass/fail results.
}
export type TestResult = "pass" | "fail" | "error";

/** Seam: the model proposes discriminating tests for this issue given the candidate solutions. */
export interface TestGenerator {
  generate(issue: Issue, candidates: readonly SolveResult[]): Promise<readonly GeneratedTest[]>;
}
/** Seam: run a generated test against a candidate patch in a sandbox. Injected in tests. */
export interface TestExecutor {
  run(test: GeneratedTest, candidate: SolveResult, candidateIndex: number): Promise<TestResult>;
}

export interface TestStat {
  readonly test: GeneratedTest;
  readonly passRate: number;
  /** p(1-p)·4 ∈ [0,1] — 0 when everyone (or no one) passes, 1 at a perfect 50/50 split. Zero for invalid tests. */
  readonly discriminativeWeight: number;
  readonly validated: boolean;
  readonly reason: string;
}

export interface PassMatrixAnalysis {
  readonly stats: readonly TestStat[];
  /** candidate index → its pass/fail fingerprint over the VALIDATED tests. */
  readonly profileByIndex: ReadonlyMap<number, string>;
  /** behavioral clusters (groups of candidate indices with identical validated-test profiles). */
  readonly clusters: readonly (readonly number[])[];
  /** ≥2 distinct behavioral profiles AND at least one discriminating test → the candidates behaviorally diverge. */
  readonly behavioralFork: boolean;
  /** candidate index → Σ discriminative weight of the validated tests it passes (a selection signal, not a floor). */
  readonly discriminatedScore: ReadonlyMap<number, number>;
}

/**
 * Analyze a pass-matrix. `matrix[t][c]` is candidate c's result on test t. `candidateIndices` are the original
 * sample indices (so profiles align with ScoredCandidate.index). Pure + deterministic.
 */
export function analyzePassMatrix(tests: readonly GeneratedTest[], candidateIndices: readonly number[], matrix: readonly (readonly TestResult[])[]): PassMatrixAnalysis {
  const nC = candidateIndices.length;
  const stats: TestStat[] = [];
  const validatedTestRows: { row: readonly TestResult[]; weight: number }[] = [];

  tests.forEach((test, t) => {
    const row = matrix[t] ?? [];
    const passes = row.filter((r) => r === "pass").length;
    const passRate = nC > 0 ? passes / nC : 0;
    if (passes === 0) {
      stats.push({ test, passRate, discriminativeWeight: 0, validated: false, reason: "no candidate passes — likely a wrong or over-constrained test; discarded" });
      return;
    }
    const weight = passRate * (1 - passRate) * 4; // variance, scaled to [0,1]
    stats.push({ test, passRate, discriminativeWeight: weight, validated: true, reason: passRate === 1 ? "all candidates pass — valid but non-discriminating (weight 0)" : "validated, discriminating" });
    validatedTestRows.push({ row, weight });
  });

  // Behavioral profile per candidate over VALIDATED tests only.
  const profileByIndex = new Map<number, string>();
  const discriminatedScore = new Map<number, number>();
  candidateIndices.forEach((candIdx, c) => {
    let profile = "";
    let score = 0;
    for (const { row, weight } of validatedTestRows) {
      const cell = row[c] ?? "error";
      profile += cell === "pass" ? "1" : cell === "fail" ? "0" : "e";
      if (cell === "pass") score += weight;
    }
    profileByIndex.set(candIdx, profile || "<no-validated-tests>");
    discriminatedScore.set(candIdx, score);
  });

  // Cluster by identical profile.
  const byProfile = new Map<string, number[]>();
  for (const candIdx of candidateIndices) {
    const p = profileByIndex.get(candIdx)!;
    (byProfile.get(p) ?? byProfile.set(p, []).get(p)!).push(candIdx);
  }
  const clusters = [...byProfile.values()];
  const hasDiscriminating = validatedTestRows.some((r) => r.weight > 0);
  const behavioralFork = clusters.length >= 2 && hasDiscriminating;

  return { stats, profileByIndex, clusters, behavioralFork, discriminatedScore };
}

/** Run the generator + executor seams to build the pass-matrix for a set of candidates. */
export async function buildPassMatrix(gen: TestGenerator, exec: TestExecutor, issue: Issue, candidates: readonly { readonly index: number; readonly result: SolveResult }[]): Promise<{ tests: readonly GeneratedTest[]; candidateIndices: number[]; matrix: TestResult[][] }> {
  const tests = await gen.generate(issue, candidates.map((c) => c.result));
  const candidateIndices = candidates.map((c) => c.index);
  const matrix: TestResult[][] = [];
  for (const test of tests) {
    const row: TestResult[] = [];
    for (const c of candidates) row.push(await exec.run(test, c.result, c.index));
    matrix.push(row);
  }
  return { tests, candidateIndices, matrix };
}

/** A selector that clusters verified candidates by their behavioral pass-profile (upgrades R2's static key). */
export function makeBehavioralSelector(analysis: PassMatrixAnalysis): CandidateSelector {
  return makeHybridSelector((c: ScoredCandidate) => analysis.profileByIndex.get(c.index) ?? "<none>");
}

export interface TestsResolveDeps {
  readonly sample: CandidateSolver;
  readonly generator: TestGenerator;
  readonly executor: TestExecutor;
  readonly verify?: (input: PatchVerifierInput) => PatchVerdict;
  readonly spine?: Spine;
}

export interface TestsResolveResult {
  readonly winner: SolveResult;
  readonly winnerCleared: boolean;
  readonly selectedIndex: number;
  /** True → verified candidates behaviorally diverge; the winner must go to human review (never auto-approved). */
  readonly behavioralFork: boolean;
  readonly analysis: PassMatrixAnalysis | null;
  readonly sampled: number;
}

/**
 * Best-of-N with generated tests. The SOUND floor (verifyPatch) is applied FIRST and is never overridden; generated
 * tests only (a) cluster the already-verified candidates behaviorally and (b) raise a behavioral-fork escalation.
 * A generated test can never auto-approve a candidate.
 */
export async function selectBestOfNWithTests(deps: TestsResolveDeps, issue: Issue, opts: { n: number; issueText?: string; maxEdits?: number }): Promise<TestsResolveResult> {
  const n = Math.max(1, opts.n);
  const results: SolveResult[] = [];
  const resolutionId = randomUUID();
  try {
    for (let i = 0; i < n; i++) {
      results.push(await deps.sample(issue, i, n === 1 ? undefined : {
        executionId: `${issue.id}:candidate:${i}`, sampleIndex: i, resolutionId,
      })); // no early-stop: need all for differential testing
    }
  } finally { await deps.sample.finishResolution?.(resolutionId); }
  const scored = scoreAll(results, { ...(deps.verify ? { verify: deps.verify } : {}), ...(opts.issueText ? { issueText: opts.issueText } : {}), ...(opts.maxEdits !== undefined ? { maxEdits: opts.maxEdits } : {}) });
  const cleared = scored.filter((s) => s.cleared);

  let winner: ScoredCandidate;
  let analysis: PassMatrixAnalysis | null = null;
  let behavioralFork = false;
  let rationale: string;

  if (cleared.length >= 2) {
    const { tests, candidateIndices, matrix } = await buildPassMatrix(deps.generator, deps.executor, issue, cleared.map((c) => ({ index: c.index, result: c.result })));
    analysis = analyzePassMatrix(tests, candidateIndices, matrix);
    behavioralFork = analysis.behavioralFork;
    const sel = makeBehavioralSelector(analysis).select(cleared);
    winner = cleared[sel.index] ?? cleared[0]!;
    rationale = sel.rationale;
  } else if (cleared.length === 1) {
    winner = cleared[0]!;
    rationale = "single verified candidate";
  } else {
    winner = [...scored].sort(compareCandidates)[0]!;
    rationale = "no candidate cleared verification — least-bad flows to human review";
  }

  deps.spine?.stage({
    type: "identity.action", actor: "novel-tests",
    payload: {
      event: "resolve.novel_tests",
      issueId: issue.id,
      sampled: scored.length,
      cleared: cleared.length,
      selectedIndex: winner.index,
      winnerCleared: winner.cleared,
      behavioralFork,
      validatedTests: analysis ? analysis.stats.filter((s) => s.validated).length : 0,
      discardedTests: analysis ? analysis.stats.filter((s) => !s.validated).length : 0,
      selection: rationale,
      ts: Date.now(),
    },
  });

  return { winner: winner.result, winnerCleared: winner.cleared, selectedIndex: winner.index, behavioralFork, analysis, sampled: scored.length };
}
