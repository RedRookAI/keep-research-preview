/**
 * R35 — OS process-group kill + fencing (killer-interface seam + in-env fencing logic).
 *
 * `IdentityRegistry.kill(id)` (agent_identity.ts) refuses a killed identity's effects at the gate. But
 * a COMPROMISED agent that bypasses the gate chokepoints, or an effect already IN FLIGHT when the kill
 * lands, needs enforcement the agent cannot ignore. R35 provides two things:
 *
 *   1. The OS KILL (the SEAM): `OsKiller.kill(processGroup)` → a real deployment does `cgroup.kill`
 *      (cgroups v2) / process-group SIGKILL to terminate the agent's whole process tree atomically. A
 *      single PID kill is insufficient (the agent may have forked); the cgroup kills the tree. The
 *      sandbox cannot do this, so it is a documented SEAM.
 *
 *   2. The FENCE (in-env provable): a monotonically increasing epoch per identity (Chubby/ZooKeeper
 *      fencing tokens). Each authorized effect carries the epoch it was leased under; `kill` BUMPS the
 *      epoch; the protected resource (the tree, via the mediated grant/membrane) REJECTS any commit
 *      whose token is below the current fence — "check the fencing token before any irreversible
 *      operation, not just before writes." This defeats the kill-mid-flight race: an effect authorized
 *      at epoch N cannot commit after a kill bumped the fence to N+1, even though the gate passed
 *      earlier. The check lives at the RESOURCE, not the holder — a compromised agent cannot ignore it.
 *
 * FAIL-SAFE: even if the OS kill FAILS (osKiller reports not-killed), the fence is still bumped, so the
 * revoked agent's in-flight and future effects are rejected at commit; the failure is surfaced for
 * escalation (isolate host / revoke upstream). A missing fence entry ⇒ treat as fenced (reject).
 *
 * BUILT vs SEAM: BUILT is the fence (monotonic epoch, bump-on-kill, reject-stale-at-commit) + the
 * killer-interface seam + the fail-safe escalation flag. The real OS PROCESS-GROUP KILL is the SEAM
 * (R35), the OS-enforcement family of R3/R27. In-env we prove the ENVELOPE-SIDE logic; the kernel
 * provides the actual termination.
 *
 * WHAT WOULD CHANGE IT: a deadman/lease with heartbeat expiry (auto-kill on missed heartbeat) extends
 * the trigger; a consensus-generated token (zxid/etcd revision) hardens monotonicity across replicas.
 * Neither lets a stale-token or killed effect commit.
 */

export type FenceToken = number;

/** The OS killer seam — a real deployment does cgroup.kill / process-group SIGKILL. */
export interface OsKiller {
  /** Terminate the whole process group/cgroup for a bound agent. Returns whether it succeeded. */
  kill(processGroup: string): { killed: boolean; reason?: string };
}

export type CommitAdmission =
  | { readonly admit: true; readonly token: FenceToken }
  | { readonly admit: false; readonly reason: string };

export type KillOutcome = {
  readonly killed: boolean; // whether the OS kill reported success
  readonly fenced: FenceToken; // the new fence epoch (bumped regardless of OS kill)
  readonly escalate: boolean; // true if the OS kill failed → surface for escalation
  readonly reason?: string;
};

/**
 * The fencing registry — the in-env-provable core. Binds an identity to a process group, issues
 * monotonic lease tokens, bumps the fence on kill, and admits/rejects commits by token.
 */
export class FencedKillRegistry {
  private readonly fence = new Map<string, FenceToken>(); // id → current fence epoch
  private readonly killed = new Set<string>();
  private readonly processGroup = new Map<string, string>(); // id → bound process group

  constructor(private readonly osKiller?: OsKiller) {}

  /** Bind an identity to its process group at jail-launch (R27) and open its fence at epoch 1. */
  bind(id: string, processGroup: string): void {
    if (!this.fence.has(id)) this.fence.set(id, 1);
    this.processGroup.set(id, processGroup);
  }

  /** Lease the CURRENT fence token to a live identity — the epoch an effect will carry. */
  lease(id: string): CommitAdmission {
    if (this.killed.has(id)) return { admit: false, reason: "killed-identity" };
    const t = this.fence.get(id);
    if (t === undefined) return { admit: false, reason: "unbound-identity" }; // fail-safe
    return { admit: true, token: t };
  }

  /**
   * Renew the lease (heartbeat / handoff): BUMP the fence and issue the new token, WITHOUT killing.
   * This is the per-acquisition monotonic fencing token — after a renewal, a token issued before it
   * is stale and rejected at commit even though the identity is alive. The deadman uses this: a missed
   * heartbeat renews to a new epoch, fencing the previous holder's in-flight effects.
   */
  renew(id: string): CommitAdmission {
    if (this.killed.has(id)) return { admit: false, reason: "killed-identity" };
    const cur = this.fence.get(id);
    if (cur === undefined) return { admit: false, reason: "unbound-identity" };
    const next = cur + 1;
    this.fence.set(id, next);
    return { admit: true, token: next };
  }

  /**
   * Kill: bump the fence (invalidates every prior token), mark killed, and invoke the OS killer. The
   * fence bump happens EVEN IF the OS kill fails — that is the fail-safe. Escalation is flagged.
   */
  kill(id: string, reason = "revoked"): KillOutcome {
    const cur = this.fence.get(id) ?? 0;
    const bumped = cur + 1;
    this.fence.set(id, bumped); // fence bump — in-flight tokens (≤ cur) are now stale
    this.killed.add(id);
    let killed = true;
    let escalate = false;
    let osReason: string | undefined;
    const pg = this.processGroup.get(id);
    if (this.osKiller && pg) {
      const r = this.osKiller.kill(pg);
      killed = r.killed;
      osReason = r.reason;
      if (!r.killed) escalate = true; // OS kill failed → escalate, but the fence already fails safe
    } else {
      // no OS killer wired (the SEAM) — the fence still fails safe, but the process is not terminated.
      killed = false;
      escalate = true;
      osReason = "no-os-killer-seam";
    }
    return { killed, fenced: bumped, escalate, ...(osReason !== undefined ? { reason: `${reason}:${osReason}` } : { reason }) };
  }

  isKilled(id: string): boolean {
    return this.killed.has(id);
  }

  /**
   * Admit a commit at the RESOURCE (the sole egress). Rejects a killed identity or a STALE token
   * (token below the current fence) — even if the gate passed earlier. Missing fence ⇒ reject.
   */
  admitAtCommit(id: string, presentedToken: FenceToken): CommitAdmission {
    if (this.killed.has(id)) return { admit: false, reason: "killed-identity" };
    const cur = this.fence.get(id);
    if (cur === undefined) return { admit: false, reason: "unbound-identity" }; // fail-safe
    if (presentedToken < cur) return { admit: false, reason: `stale-fence-token:${presentedToken}<${cur}` };
    return { admit: true, token: presentedToken };
  }
}

/** Pure fencing decision (for callers that hold their own state): reject killed or stale-token. */
export function fenceDecision(currentFence: FenceToken, killed: boolean, presentedToken: FenceToken): boolean {
  if (killed) return false;
  return presentedToken >= currentFence;
}
