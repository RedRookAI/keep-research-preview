/**
 * PullRequestPort + local PR manifest (Increment 15b).
 *
 * SOTA basis (2026-08-05): merge is the universal human boundary — every shipping agent routes through
 * human approval, and GitHub Agentic Workflows never auto-merge. The critical invariant (aibuilderclub
 * 2026, across 33,596 agent-authored PRs): the gate must NEVER be agent-on-agent — an agent may post
 * checks/worklists but must be structurally incapable of approving or merging. So this port has NO
 * approve() and NO merge() method — by construction, Keep cannot record an approval. Human review
 * should focus on "the delta between approved INTENT and executed ACTIONS" (GitHub community 2026), so
 * the manifest surfaces intent (the issue) vs executed (the edits + test results) explicitly.
 *
 * LocalPullRequest implements the port against a local bare remote (real, testable here). A hosted
 * GitHubPrAdapter/GitLabPrAdapter implements the same port on Hetzner. Zero deps.
 */

import type { PrProposal } from "../solve/issue_model.js";

/** A single check result attached to a PR (test run, lint, scan) — informational, never an approval. */
export interface PrCheck {
  readonly name: string;
  readonly passed: boolean;
  readonly detail?: string;
}

/** The review-ready manifest a reviewer sees. Contains everything needed to make the merge decision. */
export interface PrManifest {
  readonly id: string;
  readonly title: string;
  readonly body: string;
  readonly branch: string;
  readonly baseBranch: string;
  /** The exact unified diff a reviewer inspects. */
  readonly diff: string;
  /** INTENT: what the issue asked for (the approved goal). */
  readonly intent: string;
  /** EXECUTED: what Keep actually did (per-edit summaries). */
  readonly executed: readonly string[];
  /** Checks (tests/lint/scan) — informational; a human still approves. */
  readonly checks: readonly PrCheck[];
  /** Attribution (Keep run id, co-author) for auditability. */
  readonly attribution: string;
  /** Always false — Keep proposes; it never approves or merges. */
  readonly humanApprovalRequired: true;
  /** Oversight routing (increment 15.5): how loudly this PR asks for attention, and why. Optional so
   *  pre-15.5 callers still type-check. NEVER affects the merge gate — only review intensity. */
  readonly oversight?: {
    readonly band: "low" | "medium" | "high";
    readonly disposition: "auto-approved" | "human-approval-required" | "blocked";
    readonly mode: "silent-auto" | "notify-async" | "block-until-approved";
    readonly requiresImmediateAttention: boolean;
    readonly reasons: readonly string[];
  };
}

/**
 * The PR port. Note the ABSENCE of approve()/merge() — that absence is the safety property. A
 * PullRequestPort can open a PR and report its state; it can never advance it past human review.
 */
export interface PullRequestPort {
  /** Open a PR from a pushed task branch, returning the review manifest. Never merges. */
  open(proposal: PrProposal, ctx: OpenPrContext): Promise<PrManifest>;
  /** Read back an opened PR's manifest (for the reviewer UI). */
  get(id: string): Promise<PrManifest | undefined>;
  /** List open PRs (audit surface). */
  list(): Promise<readonly PrManifest[]>;
}

export interface OpenPrContext {
  readonly baseBranch: string;
  readonly diff: string;
  readonly intent: string;
  readonly executed: readonly string[];
  readonly checks: readonly PrCheck[];
  readonly attribution: string;
  readonly oversight?: PrManifest["oversight"];
}

/**
 * Local PR implementation: records the manifest in-memory (or a JSON store), keyed by branch. Backed by
 * a real pushed branch on a local bare remote. Has no approve/merge — the human reviews the manifest +
 * the real branch, then merges out-of-band with their own credentials.
 */
export class LocalPullRequest implements PullRequestPort {
  private readonly prs = new Map<string, PrManifest>();
  private seq = 0;

  async open(proposal: PrProposal, ctx: OpenPrContext): Promise<PrManifest> {
    const id = `PR-${++this.seq}`;
    const manifest: PrManifest = {
      id,
      title: proposal.title,
      body: proposal.body,
      branch: proposal.branch,
      baseBranch: ctx.baseBranch,
      diff: ctx.diff,
      intent: ctx.intent,
      executed: ctx.executed,
      checks: ctx.checks,
      attribution: ctx.attribution,
      humanApprovalRequired: true,
      ...(ctx.oversight ? { oversight: ctx.oversight } : {}),
    };
    this.prs.set(id, manifest);
    return manifest;
  }

  async get(id: string): Promise<PrManifest | undefined> {
    return this.prs.get(id);
  }

  async list(): Promise<readonly PrManifest[]> {
    return [...this.prs.values()];
  }
}

/**
 * Render a PR manifest as human-readable text (the reviewer's view). Leads with intent-vs-executed and
 * check results so the reviewer sees the delta between what was asked and what was done.
 */
export function renderManifest(m: PrManifest): string {
  const checkLines = m.checks.map((c) => `  ${c.passed ? "✅" : "❌"} ${c.name}${c.detail ? ` — ${c.detail}` : ""}`);
  const allChecksPass = m.checks.every((c) => c.passed);
  return [
    `PR ${m.id}: ${m.title}`,
    `  ${m.branch} → ${m.baseBranch}`,
    ``,
    `INTENT (what was asked):`,
    `  ${m.intent}`,
    ``,
    `EXECUTED (what Keep did):`,
    ...m.executed.map((e) => `  • ${e}`),
    ``,
    `CHECKS:`,
    ...(checkLines.length ? checkLines : ["  (none)"]),
    ``,
    `${m.attribution}`,
    ``,
    allChecksPass
      ? `⚠️ Checks pass, but this PR REQUIRES HUMAN REVIEW AND APPROVAL — Keep never merges.`
      : `⛔ Checks are failing — review carefully. Keep never merges.`,
  ].join("\n");
}
