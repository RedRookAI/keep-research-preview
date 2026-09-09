/**
 * PrPublisher (Increment 15b) — orchestrates solve → branch → commit → push → PR manifest.
 *
 * Ties the SolvePipeline's PrProposal to the real git remote + PR port. Enforces the human gate end to
 * end: a keep/ task branch (never a shared branch), an attributed commit, a push that refuses
 * protected branches, and a PR manifest that surfaces intent-vs-executed + checks — and never merges.
 * Returns the push ReversibleAction so a rejected PR reverts cleanly and main is never touched.
 * Zero deps.
 */

import type { ReversibleAction } from "../control/rollback.js";
import type { GitAdapter } from "../infra/git_adapter.js";
import { GitRemote } from "./git_remote.js";
import { type PullRequestPort, type PrManifest, type PrCheck } from "./pull_request.js";
import type { SolveResult, PrProposal } from "../solve/issue_model.js";
import { PrRiskAssessor } from "../oversight/pr_risk.js";
import { OversightRouter } from "../oversight/oversight_router.js";
import { appraiseGitMutationControlPlane } from "./pinned_remote.js";
import { installedEffectAdmission, INSTALLED_EFFECT_OWNERS, type InstalledEffectAdmission } from "../control/installed_effect_admission.js";

export interface PrPublisherDeps {
  readonly git: GitAdapter;
  readonly remote: GitRemote;
  readonly prPort: PullRequestPort;
  readonly baseBranch: string;
  readonly effectAdmission?: InstalledEffectAdmission;
  /** Trusted governance may present a test-passing, vet-refused proposal to a
   * human. This never changes the result to solved and never authorizes a merge. */
  readonly reviewOnly?: true;
  /** Optional oversight layer (15.5): assess PR risk + route to a disposition. If omitted, behaves
   *  exactly as before (every PR sits equal, human-gated). Never affects the merge gate. */
  readonly oversight?: {
    readonly assessor: PrRiskAssessor;
    readonly router: OversightRouter;
    readonly fanIn?: Readonly<Record<string, number>>;
  };
}

export interface PublishResult {
  readonly manifest: PrManifest;
  /** Undo the push (delete the remote branch) — for a rejected PR. */
  readonly pushUndo: ReversibleAction;
  readonly commit: ReversibleAction;
}

/**
 * Publish a solved result as a PR. The working tree must already contain the applied edits (the
 * SolvePipeline applied them). This creates the branch, commits, pushes, and opens the PR — never
 * merging. Throws if the result isn't solved (nothing to propose) or has no PR proposal.
 */
export async function publishSolveAsPr(result: SolveResult, deps: PrPublisherDeps): Promise<PublishResult> {
  const reviewable = deps.reviewOnly === true && result.validation?.testsPassed === true &&
    result.validation.vettingCleared === false && result.recovery?.status === "authority" && result.prProposal?.testsPassed === true;
  if ((!result.solved && !reviewable) || !result.prProposal) {
    throw new Error(`cannot publish an unsolved result for ${result.issueId}`);
  }
  const proposal: PrProposal = result.prProposal;
  (deps.effectAdmission ?? installedEffectAdmission).admit(INSTALLED_EFFECT_OWNERS.proposalPublication.id);

  // Resolve the operator-owned transport before making any local branch/commit change. A missing or stale pin is a
  // refusal with zero partial local effects, not an exception discovered only at push time.
  await deps.remote.transport();

  // 1. Create the keep/ task branch (GitRemote enforces the prefix + protected-branch refusal).
  await deps.remote.createTaskBranch(proposal.branch);

  // 2. Commit the applied edits with an attribution trailer.
  const commit = await deps.remote.commitWithAttribution(proposal.title, `commit_${result.issueId}`);

  // 3. Compute the real diff (base..HEAD) for the reviewer.
  await appraiseGitMutationControlPlane(deps.git);
  const diff = (await deps.git.git(["diff", `${deps.baseBranch}...HEAD`])).stdout;

  // 4. Push the task branch (refuses protected branches).
  const pushUndo = await deps.remote.pushTaskBranch(proposal.branch, `push_${result.issueId}`);

  // 5. Build checks from the solve result (test results are informational — a human still approves).
  const checks: PrCheck[] = [
    { name: "tests", passed: proposal.testsPassed, ...(result.validation?.detail ? { detail: result.validation.detail } : {}) },
  ];
  if (result.validation && !result.validation.vettingCleared && result.validation.testsPassed) {
    checks.push({ name: "vetting", passed: false, detail: "verification cascade / logic vetting did not clear" });
  }

  // 6. Open the PR manifest — intent (issue) vs executed (edits) — never merges.
  const executed = proposal.edits.map((e) => `${e.file}: ${e.intent}`);

  // 6a. Optional oversight (15.5): assess risk + route to a disposition (never touches the merge gate).
  let oversight: PrManifest["oversight"] | undefined;
  if (deps.oversight) {
    const risk = deps.oversight.assessor.assess({
      proposal, result,
      ...(deps.oversight.fanIn ? { fanIn: deps.oversight.fanIn } : {}),
    });
    const decision = deps.oversight.router.route(risk);
    oversight = {
      band: decision.band,
      disposition: decision.disposition,
      mode: decision.mode,
      requiresImmediateAttention: decision.requiresImmediateAttention,
      reasons: [...risk.reasons.map((r) => `[${r.axis}] ${r.detail}`), ...decision.reasons],
    };
  }

  const manifest = await deps.prPort.open(proposal, {
    baseBranch: deps.baseBranch,
    diff,
    intent: bodyIntent(proposal),
    executed,
    checks,
    attribution: deps.remote.attributionTrailer(),
    ...(oversight ? { oversight } : {}),
  });

  return { manifest, pushUndo, commit };
}

/** Extract the intent line from the proposal body (the issue statement). */
function bodyIntent(proposal: PrProposal): string {
  const m = proposal.body.match(/\*\*Issue:\*\*\s*(.+)/);
  return m?.[1]?.trim() ?? proposal.title;
}
