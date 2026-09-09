/**
 * Layered kill-switch (Phase 2, #23) — the real, unsolved market gap.
 *
 * Implements the 2026 four-primitive containment architecture:
 *   1. independent (out-of-process) termination — stop the agent WITHOUT its
 *      cooperation; it sits outside the agent's reasoning/orchestration.
 *   2. credential revocation — revoke the agent's scoped credential so a respawn
 *      can't resume; CASCADES to delegated children (killing a parent must recall
 *      children — a halt that leaves credentials live is not containment).
 *   3. circuit-breaker — automated threshold pause (action count, cost, loops),
 *      distinct from the manual kill-switch.
 *   4. network isolation — sever the agent's egress/service access.
 *
 * Every stop records a clean termination event to the spine (state at stop, the
 * triggering policy, cascade) so incidents leave clean records and a false-positive
 * termination is reviewable/reversible.
 */

import type { Spine } from "../spine/spine.js";

export interface AgentHandle {
  readonly agentId: string;
  /** The scoped credential id this agent holds (revocable). */
  readonly credentialId: string;
  /** Parent agent id, if this was delegated (for cascade). */
  readonly parentId?: string;
  /** An out-of-process terminate hook (e.g. kill the subprocess). Must not call into the agent. */
  readonly terminate: () => void;
}

export type StopReason = "manual-kill" | "circuit-breaker" | "cascade";

export interface TerminationRecord {
  readonly agentId: string;
  readonly reason: StopReason;
  readonly triggeringPolicy: string;
  readonly credentialRevoked: boolean;
  readonly networkIsolated: boolean;
  readonly cascadedTo: readonly string[];
  readonly ts: number;
}

export interface CircuitBreakerThresholds {
  readonly maxActions: number;
  readonly maxCostUsd: number;
  readonly maxLoops: number;
}

export class KillSwitch {
  private readonly agents = new Map<string, AgentHandle>();
  private readonly revokedCredentials = new Set<string>();
  private readonly isolated = new Set<string>();
  private readonly terminated = new Set<string>();

  constructor(
    private readonly spine: Spine,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  register(handle: AgentHandle): void {
    this.agents.set(handle.agentId, handle);
  }

  isRevoked(credentialId: string): boolean {
    return this.revokedCredentials.has(credentialId);
  }

  isTerminated(agentId: string): boolean {
    return this.terminated.has(agentId);
  }

  isIsolated(agentId: string): boolean {
    return this.isolated.has(agentId);
  }

  /**
   * The manual kill-switch. Out-of-process terminate + credential revoke + network
   * isolation, cascading to all delegated children. Records a clean termination
   * event. Idempotent per agent.
   */
  kill(agentId: string, triggeringPolicy: string, reason: StopReason = "manual-kill"): TerminationRecord {
    const handle = this.agents.get(agentId);
    if (!handle) throw new Error(`no registered agent ${agentId}`);

    // 1. out-of-process termination (does not ask the agent)
    if (!this.terminated.has(agentId)) {
      handle.terminate();
      this.terminated.add(agentId);
    }
    // 2. credential revocation (respawn can't resume)
    this.revokedCredentials.add(handle.credentialId);
    // 4. network isolation
    this.isolated.add(agentId);

    // cascade to children (recursively) — a halt that leaves children live isn't containment
    const cascadedTo: string[] = [];
    for (const child of this.children(agentId)) {
      const rec = this.kill(child.agentId, triggeringPolicy, "cascade");
      cascadedTo.push(child.agentId, ...rec.cascadedTo);
    }

    const record: TerminationRecord = {
      agentId,
      reason,
      triggeringPolicy,
      credentialRevoked: true,
      networkIsolated: true,
      cascadedTo,
      ts: this.clock(),
    };
    // clean termination event to the spine
    this.spine.stage({ type: "identity.action", actor: "killswitch", payload: { event: "termination", ...record } });
    return record;
  }

  private children(agentId: string): AgentHandle[] {
    return [...this.agents.values()].filter((a) => a.parentId === agentId);
  }

  /**
   * The automated circuit-breaker: trips (and kills) if any threshold is exceeded.
   * Returns the record if it tripped, else undefined.
   */
  checkCircuitBreaker(
    agentId: string,
    metrics: { actions: number; costUsd: number; loops: number },
    thresholds: CircuitBreakerThresholds,
  ): TerminationRecord | undefined {
    let breach: string | undefined;
    if (metrics.actions > thresholds.maxActions) breach = `actions ${metrics.actions} > ${thresholds.maxActions}`;
    else if (metrics.costUsd > thresholds.maxCostUsd) breach = `cost ${metrics.costUsd} > ${thresholds.maxCostUsd}`;
    else if (metrics.loops > thresholds.maxLoops) breach = `loops ${metrics.loops} > ${thresholds.maxLoops}`;
    if (!breach) return undefined;
    return this.kill(agentId, `circuit-breaker: ${breach}`, "circuit-breaker");
  }

  /**
   * Reverse a false-positive termination: re-issue the credential (a NEW credential
   * id) and clear isolation. The reversal is itself audited. The original
   * termination record remains in the spine.
   */
  reverseTermination(agentId: string, newCredentialId: string, justification: string): void {
    this.terminated.delete(agentId);
    this.isolated.delete(agentId);
    this.spine.stage({
      type: "identity.action",
      actor: "killswitch",
      payload: { event: "termination_reversed", agentId, newCredentialId, justification, ts: this.clock() },
    });
  }
}
