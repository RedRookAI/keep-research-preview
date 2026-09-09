import { createHash } from "node:crypto";

export interface ExecutionEvidence {
  readonly baselineScore: number;
  readonly candidateScore: number;
  readonly passed: boolean;
}

export interface CriticismRequest {
  readonly proposalId: string;
  readonly proposalKind: "skill" | "self-modification";
  readonly builderFamily: string;
  readonly summary: string;
  readonly execution: ExecutionEvidence;
}

export interface CrossFamilyCriticism {
  readonly reviewerFamily: string;
  readonly verdict: "clear" | "revise";
  readonly findings: readonly string[];
}

export interface CrossFamilyCritic {
  criticize(request: CriticismRequest): CrossFamilyCriticism;
}

export type CriticismGateResult =
  | { readonly status: "not-required" | "cleared"; readonly reviewCalls: number; readonly findings: readonly string[] }
  | { readonly status: "held"; readonly reviewCalls: number; readonly reason: string; readonly findings: readonly string[] };

/**
 * One-shot independent criticism gate for high-impact improvement proposals.
 * Execution is adjudicated first and cannot be overruled by prose. Each exact
 * proposal may invoke the critic once; revisions are new proposals and do not
 * trigger a debate with the original reviewer.
 */
export class BoundedCrossFamilyCriticism {
  private readonly reviewed = new Set<string>();

  constructor(
    private readonly builderFamily: string,
    private readonly critic?: CrossFamilyCritic,
  ) {}

  assess(request: Omit<CriticismRequest, "builderFamily">, highImpact: boolean): CriticismGateResult {
    if (!request.execution.passed) {
      return { status: "held", reviewCalls: 0, reason: "execution evidence did not pass", findings: [] };
    }
    if (!highImpact) return { status: "not-required", reviewCalls: 0, findings: [] };
    if (!this.critic) {
      return { status: "held", reviewCalls: 0, reason: "independent cross-family critic is unavailable", findings: [] };
    }

    const key = digest(request);
    if (this.reviewed.has(key)) {
      return { status: "held", reviewCalls: 0, reason: "this exact proposal already received its single criticism pass", findings: [] };
    }
    this.reviewed.add(key);
    const boundedRequest = Object.freeze({ ...request, execution: Object.freeze({ ...request.execution }), builderFamily: this.builderFamily });
    let result: { reviewerFamily: string; verdict: "clear" | "revise"; findings: readonly string[] };
    try {
      const raw = this.critic.criticize(boundedRequest);
      if (!raw || typeof raw.reviewerFamily !== "string" || (raw.verdict !== "clear" && raw.verdict !== "revise") || !Array.isArray(raw.findings) || !raw.findings.every((finding) => typeof finding === "string")) throw new TypeError("malformed criticism");
      result = { reviewerFamily: raw.reviewerFamily, verdict: raw.verdict, findings: Object.freeze([...raw.findings]) };
    } catch { return { status: "held", reviewCalls: 1, reason: "independent criticism failed or returned a malformed result", findings: [] }; }
    if (!result.reviewerFamily || result.reviewerFamily === this.builderFamily) {
      return { status: "held", reviewCalls: 1, reason: "critic is not from an independent model family", findings: result.findings };
    }
    if (result.verdict !== "clear" || result.findings.length > 0) {
      return { status: "held", reviewCalls: 1, reason: "independent criticism requires revision", findings: result.findings };
    }
    return { status: "cleared", reviewCalls: 1, findings: [] };
  }
}

function digest(request: Omit<CriticismRequest, "builderFamily">): string {
  return createHash("sha256").update(JSON.stringify(request)).digest("hex");
}
