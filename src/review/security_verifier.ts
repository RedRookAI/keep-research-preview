/**
 * Coordinates injected scanner adapters and weights findings for review.
 *
 * A scanner that requires compilation is skipped when the request is not compilable. Fallback
 * coverage is reported as reduced depth. Findings can be ranked using exploitability, reachability
 * and severity inputs. Scanner availability and the supplied ranking inputs need their own evidence.
 */

import type { Finding } from "./finding.js";

export interface ScanRequest {
  readonly language: string;
  readonly compilable: boolean;
  readonly diffFiles: readonly string[];
}

export interface ScannerResult {
  readonly findings: readonly Finding[];
  /** False if the scanner could not run to full depth (e.g. CodeQL DB-build failed). */
  readonly fullDepth: boolean;
  readonly note?: string;
}

/** A scanner adapter (Semgrep, CodeQL, ...). Injected; never imported by the gate. */
export interface Scanner {
  readonly name: string;
  /** True if this scanner requires a compilable environment (CodeQL) vs not (Semgrep). */
  readonly requiresCompilation: boolean;
  scan(req: ScanRequest): Promise<ScannerResult>;
}

/** Finding categories with additional review weight. */
const AI_RISK_KEYWORDS: readonly { rx: RegExp; weight: number }[] = [
  { rx: /injection|sqli|command inj/i, weight: 1.6 },
  { rx: /xss|cross-site/i, weight: 1.7 },
  { rx: /secret|hardcoded (key|password|token)/i, weight: 1.5 },
  { rx: /excessive privilege|over-?permission|broad scope/i, weight: 1.5 },
  { rx: /typosquat|hallucinated (package|dependency)/i, weight: 1.5 },
];

/** Metadata for ranking a finding (EPSS x reachability x CVSS). */
export interface RankInputs {
  /** Exploit Prediction Scoring System, 0..1 (probability of exploitation). */
  readonly epss: number;
  /** Reachability: is the vulnerable code actually reachable? 0..1. */
  readonly reachability: number;
  /** CVSS base score normalized to 0..1. */
  readonly cvss: number;
}

const SEVERITY_BASE: Record<Finding["severity"], number> = {
  critical: 1.0,
  high: 0.75,
  medium: 0.45,
  low: 0.2,
};

/** AI-risk weight for a finding message (>=1.0). */
export function aiRiskWeight(message: string): number {
  let w = 1.0;
  for (const k of AI_RISK_KEYWORDS) if (k.rx.test(message)) w = Math.max(w, k.weight);
  return w;
}

/**
 * Rank score: exploitability x reachability x severity, times AI-risk weight.
 * Ranking by this (not CVSS alone) puts real-damage findings first.
 */
export function rankScore(finding: Finding, inputs: RankInputs): number {
  const base = SEVERITY_BASE[finding.severity] * 0.4 + inputs.cvss * 0.6;
  return inputs.epss * inputs.reachability * base * aiRiskWeight(finding.message);
}

export interface VerificationResult {
  readonly findings: readonly Finding[];
  readonly fullDepth: boolean;
  readonly scannerUsed: string;
  readonly reducedDepthReason?: string;
}

export class SecurityVerifier {
  constructor(
    private readonly defaultScanner: Scanner, // Semgrep (no compilation)
    private readonly deepScanner?: Scanner, // CodeQL (operator-provided)
  ) {
    if (defaultScanner.requiresCompilation) {
      throw new Error("the default scanner must not require compilation (use Semgrep-class as default)");
    }
  }

  /**
   * Verify a change. Uses the deep scanner when available AND the code is
   * compilable; otherwise (or on deep-scan failure) falls back to the default,
   * NEVER blocking on a deep-scanner DB-build failure.
   */
  async verify(req: ScanRequest): Promise<VerificationResult> {
    if (this.deepScanner && req.compilable) {
      try {
        const deep = await this.deepScanner.scan(req);
        if (deep.fullDepth) {
          return { findings: deep.findings, fullDepth: true, scannerUsed: this.deepScanner.name };
        }
        // Deep scanner ran but not at full depth -> fall back, flag reduced depth.
        const fallback = await this.defaultScanner.scan(req);
        return {
          findings: fallback.findings,
          fullDepth: false,
          scannerUsed: this.defaultScanner.name,
          reducedDepthReason: deep.note ?? `${this.deepScanner.name} did not reach full depth`,
        };
      } catch (err) {
        // Deep-scan crashed (e.g. DB build failed) -> graceful degradation, do NOT block.
        const fallback = await this.defaultScanner.scan(req);
        return {
          findings: fallback.findings,
          fullDepth: false,
          scannerUsed: this.defaultScanner.name,
          reducedDepthReason: `${this.deepScanner.name} failed: ${(err as Error).message}; fell back to ${this.defaultScanner.name}`,
        };
      }
    }
    // Default path: Semgrep-class, always available, no compilation needed.
    const result = await this.defaultScanner.scan(req);
    return {
      findings: result.findings,
      fullDepth: result.fullDepth,
      scannerUsed: this.defaultScanner.name,
      ...(req.compilable ? {} : { reducedDepthReason: "no deep scanner configured; AST-based default used" }),
    };
  }
}
