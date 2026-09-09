/**
 * Identity/RBAC (Features 31, 37) + Separation of Duties (Round 19).
 *
 * Implements the owner-locked decision: TWO first-class deployment modes.
 *  - Multi-operator: N-of-M approval on the security-critical set; author != approver.
 *  - Single-operator: N=1 fully supported; never blocked by an absent second human;
 *    substitutes credential-compromise protections (step-up) for the second approver.
 * N>=2 is NEVER a hard requirement. Every approval is recorded to the spine.
 */

export type IdentityId = string;

export interface Identity {
  readonly id: IdentityId;
  /** True for human operators eligible to give SoD approvals. */
  readonly isOperator: boolean;
  readonly displayName: string;
}

/**
 * The security-critical action set (Round 19). Only these require SoD; routine
 * actions never do (avoids reviewer fatigue). Extensible.
 */
export type SecurityCriticalAction =
  | "memory.promote_global"
  | "isolation.lower_floor"
  | "policy.change_invariant"
  | "skill.approve_distribution"
  | "audit.config_change"
  | "control.disable_review_or_killswitch_or_mergegate"
  | "calibration.reduce_escalation";

export const SECURITY_CRITICAL_ACTIONS: ReadonlySet<string> = new Set<SecurityCriticalAction>([
  "memory.promote_global",
  "isolation.lower_floor",
  "policy.change_invariant",
  "skill.approve_distribution",
  "audit.config_change",
  "control.disable_review_or_killswitch_or_mergegate",
  "calibration.reduce_escalation",
]);

/** Hook so each approval decision is appended to the spine. */
export type ApprovalRecorder = (record: ApprovalRecord) => void;

export interface ApprovalRecord {
  readonly action: SecurityCriticalAction;
  readonly author: IdentityId;
  readonly approvers: readonly IdentityId[];
  readonly mode: "single-operator" | "multi-operator";
  readonly stepUpVerified: boolean;
  readonly ts: number;
}

export interface SoDConfig {
  /** Required distinct approvals (including or excluding author per rules below). */
  readonly n: number;
}

export class SeparationOfDuties {
  private readonly recorders: ApprovalRecorder[] = [];

  constructor(
    private readonly operators: ReadonlyMap<IdentityId, Identity>,
    private readonly config: SoDConfig,
  ) {
    if (config.n < 1) throw new Error("SoD N must be >= 1 (single-operator is N=1)");
  }

  onApproval(r: ApprovalRecorder): void {
    this.recorders.push(r);
  }

  /** Number of operators actually available — determines the effective mode. */
  private operatorCount(): number {
    let c = 0;
    for (const id of this.operators.values()) if (id.isOperator) c++;
    return c;
  }

  /**
   * Authorize a security-critical action.
   *
   * Multi-operator (>=2 operators AND N>=2): requires N distinct approvers and the
   * author may NOT be the sole approver (author != approver rule). Step-up MFA is
   * required from each approver (represented by stepUpVerified).
   *
   * Single-operator (only 1 operator, OR N=1): the sole operator self-approves, but
   * step-up (hardware key) is REQUIRED to stand in for the absent second human.
   *
   * Returns the recorded approval; throws if authorization fails.
   */
  authorize(params: {
    action: SecurityCriticalAction;
    author: IdentityId;
    approvers: readonly IdentityId[];
    stepUpVerified: boolean;
    now: number;
  }): ApprovalRecord {
    const { action, author, approvers, stepUpVerified, now } = params;
    if (!SECURITY_CRITICAL_ACTIONS.has(action)) {
      throw new Error(`${action} is not a security-critical action (no SoD needed)`);
    }
    const distinct = new Set(approvers);
    const opCount = this.operatorCount();
    const multiMode = opCount >= 2 && this.config.n >= 2;

    let record: ApprovalRecord;
    if (multiMode) {
      // author != sole approver
      if (distinct.size < this.config.n) {
        throw new Error(`multi-operator mode needs ${this.config.n} distinct approvers, got ${distinct.size}`);
      }
      if (distinct.size === 1 && distinct.has(author)) {
        throw new Error("author cannot be the sole approver (separation of duties)");
      }
      if (!stepUpVerified) {
        throw new Error("step-up MFA required for security-critical approval");
      }
      for (const a of distinct) {
        const op = this.operators.get(a);
        if (!op || !op.isOperator) throw new Error(`approver ${a} is not a registered operator`);
      }
      record = {
        action,
        author,
        approvers: [...distinct],
        mode: "multi-operator",
        stepUpVerified,
        ts: now,
      };
    } else {
      // Single-operator (N=1 or only one operator). Never blocked by an absent
      // second human; substitutes step-up for the second approver.
      if (!stepUpVerified) {
        throw new Error("single-operator mode requires step-up (hardware key) for security-critical actions");
      }
      const op = this.operators.get(author);
      if (!op || !op.isOperator) throw new Error(`author ${author} is not a registered operator`);
      record = {
        action,
        author,
        approvers: [author],
        mode: "single-operator",
        stepUpVerified,
        ts: now,
      };
    }
    for (const r of this.recorders) r(record);
    return record;
  }
}
