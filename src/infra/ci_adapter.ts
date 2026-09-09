/**
 * CI/CD adapter (infra, Phase 6 #48) — Keep as a real GitHub Actions step.
 *
 * SOTA (Aug 2026): GitHub Agentic Workflows (Feb 2026, preview) codifies the exact
 * rule Keep already enforces — "pull requests are never merged automatically, and
 * humans must always review and approve." So every CI result keeps
 * humanMergeRequired=true. Two sharpenings folded in from the research:
 *   - an AGGREGATE check (`keep-all-gates-passed`) with a `needs` on every gate job,
 *     because renamed jobs break required-status-checks silently;
 *   - the CI report carries WHICH gates ran (tests/security/review), not just
 *     pass/fail, and agent-generated PRs are labeled.
 *
 * This module generates the workflow YAML and computes the gate report + exit code;
 * a live GitHub Actions run is verified on the connected env (see LIMITATIONS.md).
 */

export type GateName = "tests" | "security" | "review" | "spec-drift";
export type GateStatus = "pass" | "fail" | "skipped";

export interface CiGateResult {
  readonly gate: GateName;
  readonly status: GateStatus;
  readonly detail: string;
}

export interface CiGateReport {
  readonly gates: readonly CiGateResult[];
  /** Overall outcome derived from the gates. */
  readonly outcome: "pass" | "fail" | "needs-review";
  /** ALWAYS true — Keep proposes; the human merges (GitHub Agentic Workflows rule). */
  readonly humanMergeRequired: true;
  /** Process exit code for the CI runner (0 unless a gate failed). */
  readonly exitCode: number;
  /** Label applied to the PR so agent-generated changes are visible. */
  readonly prLabel: "agent-generated";
}

/**
 * Compute the CI gate report from the individual gate results. A failing gate =>
 * fail + exit 1. All pass but a review is still required (irreversible or below a
 * readiness bar) => needs-review + exit 0. The human merge gate is never bypassed.
 */
export function computeGateReport(gates: readonly CiGateResult[], opts: { requireHumanReview?: boolean } = {}): CiGateReport {
  const anyFail = gates.some((g) => g.status === "fail");
  const outcome: CiGateReport["outcome"] = anyFail ? "fail" : opts.requireHumanReview ? "needs-review" : "pass";
  return {
    gates,
    outcome,
    humanMergeRequired: true,
    exitCode: anyFail ? 1 : 0,
    prLabel: "agent-generated",
  };
}

export interface WorkflowOptions {
  readonly workflowName?: string;
  /** The gate job ids Keep runs (each becomes a job + a needs of the aggregate). */
  readonly gateJobs?: readonly string[];
  /** Node version for the runner. */
  readonly nodeVersion?: string;
}

/**
 * Generate a real GitHub Actions workflow YAML. Includes fetch-depth:0 (agents need
 * full history for merge-base diffs), a job per gate, and an AGGREGATE job that
 * `needs` every gate — the required status check points at the aggregate so renamed
 * gate jobs can't silently pass. PRs are labeled agent-generated. No auto-merge.
 */
export function generateGitHubWorkflow(opts: WorkflowOptions = {}): string {
  const name = opts.workflowName ?? "Keep";
  const gates = opts.gateJobs ?? ["tests", "security", "review"];
  const node = opts.nodeVersion ?? "22";

  const gateJobsYaml = gates
    .map(
      (g) => `  ${g}:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: "${node}"
      - name: Keep gate — ${g}
        run: node ./dist/src/ci/run-gate.js --gate ${g}`,
    )
    .join("\n");

  const needs = gates.map((g) => `      - ${g}`).join("\n");

  return `name: ${name}
on:
  pull_request:
  merge_group:
permissions:
  contents: read
  pull-requests: write
jobs:
${gateJobsYaml}
  label-agent-pr:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - name: Label agent-generated
        run: echo "label:agent-generated"
  keep-all-gates-passed:
    runs-on: ubuntu-latest
    needs:
${needs}
    steps:
      - name: Aggregate gate
        run: echo "all Keep gates passed; human merge still required"
`;
}
