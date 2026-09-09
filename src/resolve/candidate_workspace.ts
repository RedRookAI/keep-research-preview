import type { Issue } from "../solve/issue_model.js";
import { InMemoryWorkspace, type Workspace } from "../solve/workspace.js";
import type { CandidateExecution, CandidateSolver } from "./best_of_n.js";

export interface CandidateWorkspaceLease {
  readonly workspaceId: string;
  readonly workspace: Workspace;
  readonly repoRef: string;
  release(): void | Promise<void>;
}

export interface CandidateWorkspaceFactory {
  allocate(issue: Issue, execution: CandidateExecution): Promise<CandidateWorkspaceLease>;
  finishResolution?(resolutionId: string): void | Promise<void>;
}

/** Capture one immutable source snapshot and allocate a distinct mutable tree for every candidate. */
export class SnapshotCandidateWorkspaceFactory implements CandidateWorkspaceFactory {
  readonly #snapshots = new Map<string, Promise<Readonly<Record<string, string>>>>();
  constructor(private readonly source: Workspace) {}
  async allocate(issue: Issue, execution: CandidateExecution): Promise<CandidateWorkspaceLease> {
    if (!execution.resolutionId) throw new Error("candidate workspace allocation requires a resolution identity");
    const key = `${execution.resolutionId}\0${issue.repoRef}`;
    let snapshot = this.#snapshots.get(key);
    if (!snapshot) {
      snapshot = this.source.files(issue.repoRef).then((files) => Object.freeze(Object.fromEntries(files.map((file) => [file.path, file.content]))));
      this.#snapshots.set(key, snapshot);
    }
    const repoRef = execution.executionId.replace(/[^A-Za-z0-9._-]/g, "_");
    const workspace = new InMemoryWorkspace({ [repoRef]: { ...await snapshot } });
    return Object.freeze({ workspaceId: execution.executionId, workspace, repoRef, release: () => {} });
  }
  finishResolution(resolutionId: string): void { for (const key of this.#snapshots.keys()) if (key.startsWith(`${resolutionId}\0`)) this.#snapshots.delete(key); }
}

/** Allocation and release surround the existing sampler, including failure and cancellation exits. */
export function isolateCandidateSolver(sample: CandidateSolver, factory: CandidateWorkspaceFactory): CandidateSolver {
  const isolated: CandidateSolver = async (issue, sampleIndex, execution) => {
    if (!execution) throw new Error("candidate execution identity is required for workspace isolation");
    const lease = await factory.allocate(issue, execution);
    if (!lease.workspaceId || !lease.repoRef || !lease.workspace) throw new Error("candidate workspace factory returned an invalid lease");
    try {
      return await sample({ ...issue, repoRef: lease.repoRef }, sampleIndex, { ...execution, workspace: lease.workspace, repoRef: lease.repoRef });
    } finally { await lease.release(); }
  };
  isolated.finishResolution = (resolutionId) => factory.finishResolution?.(resolutionId);
  return isolated;
}

