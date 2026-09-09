/**
 * In-process A2A transport (infra, Phase 6 #47) — real + testable BYOA lifecycle.
 *
 * Implements the injected `A2ATransport` with a full A2A task lifecycle
 * (submitted -> working -> completed/failed/input-required), so the bring-your-own-
 * agent delegation path is verified end-to-end here without a network. Skills are
 * registered handlers; only TASK-LEVEL OUTCOMES are returned (never internal steps
 * — the trajectory caveat is preserved by shape). The remote HTTP/JSON-RPC A2A
 * transport stays a logged seam (see LIMITATIONS.md).
 */

import type { A2ATransport, A2ATaskState } from "../ecosystem/a2a.js";

export interface A2ASkillHandler {
  (args: Record<string, unknown>): Promise<{ output?: unknown; error?: string; needsInput?: boolean }>;
}

/** Observed lifecycle transitions (for tests/audit). */
export interface TaskLifecycle {
  readonly states: readonly A2ATaskState[];
}

export class InProcessA2ATransport implements A2ATransport {
  private readonly skills = new Map<string, A2ASkillHandler>();
  private lastLifecycle: A2ATaskState[] = [];

  registerSkill(name: string, handler: A2ASkillHandler): void {
    this.skills.set(name, handler);
  }

  get lifecycle(): TaskLifecycle {
    return { states: [...this.lastLifecycle] };
  }

  async sendTask(skill: string, args: Record<string, unknown>): Promise<{ state: A2ATaskState; output?: unknown; error?: string }> {
    this.lastLifecycle = ["submitted"];
    const handler = this.skills.get(skill);
    if (!handler) {
      this.lastLifecycle.push("failed");
      return { state: "failed", error: `no skill "${skill}"` };
    }
    this.lastLifecycle.push("working");
    try {
      const res = await handler(args);
      if (res.needsInput) {
        this.lastLifecycle.push("input-required");
        return { state: "input-required" };
      }
      if (res.error !== undefined) {
        this.lastLifecycle.push("failed");
        return { state: "failed", error: res.error };
      }
      this.lastLifecycle.push("completed");
      // Only the outcome is returned — never the handler's internal trajectory.
      return { state: "completed", ...(res.output !== undefined ? { output: res.output } : {}) };
    } catch (err) {
      this.lastLifecycle.push("failed");
      return { state: "failed", error: (err as Error).message };
    }
  }
}
