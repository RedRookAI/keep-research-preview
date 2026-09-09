import { test } from "node:test";
import assert from "node:assert/strict";

import {
  filterForDisplay,
  costAsymmetry,
  inlineCount,
  type Finding,
} from "../src/review/finding.js";
import {
  SecurityVerifier,
  aiRiskWeight,
  rankScore,
  type Scanner,
  type ScanRequest,
} from "../src/review/security_verifier.js";
import {
  assertHeterogeneous,
  objectiveSelfReviewClean,
  type Authorship,
  type ObjectiveAnchor,
} from "../src/review/heterogeneous.js";
import {
  computeMergeReadiness,
  estimateReviewEffort,
  verificationDepth,
} from "../src/review/merge_readiness.js";

function finding(over: Partial<Finding>): Finding {
  return {
    id: "f", category: "security", severity: "high", confidence: 0.9,
    file: "a.ts", line: 1, message: "issue", detector: "test", ...over,
  };
}

// --- The two-tier detect->display law ---

test("cost-asymmetry: security/correctness are recall-favored; style is precision-favored", () => {
  assert.equal(costAsymmetry("security"), "recall-favored");
  assert.equal(costAsymmetry("correctness"), "recall-favored");
  assert.equal(costAsymmetry("style"), "precision-favored");
});

test("a high-severity security finding surfaces inline even at LOW confidence (recall-favored)", () => {
  const displayed = filterForDisplay([finding({ category: "security", severity: "critical", confidence: 0.35 })]);
  assert.equal(displayed[0]!.displayTier, "inline-blocking");
});

test("a low-confidence STYLE finding is silently logged, not shown (precision-favored)", () => {
  const displayed = filterForDisplay([finding({ category: "style", severity: "low", confidence: 0.5 })]);
  assert.equal(displayed[0]!.displayTier, "silently-logged"); // below the 0.8 precision bar
});

test("style findings never block, even at high confidence", () => {
  const displayed = filterForDisplay([finding({ category: "style", severity: "high", confidence: 0.95 })]);
  assert.notEqual(displayed[0]!.displayTier, "inline-blocking");
});

test("noise control: only recall-favored high/critical count as inline noise", () => {
  const displayed = filterForDisplay([
    finding({ category: "security", severity: "critical", confidence: 0.9 }),
    finding({ category: "style", severity: "low", confidence: 0.9 }),
    finding({ category: "docs", severity: "low", confidence: 0.9 }),
  ]);
  assert.equal(inlineCount(displayed), 1);
});

// --- Heterogeneous review guardrail ---

test("self-review is structurally refused (same agent)", () => {
  const a: Authorship = { agentId: "x", modelFamily: "claude" };
  assert.throws(() => assertHeterogeneous(a, a));
});

test("same-model-family review is refused (shared blind spots)", () => {
  const author: Authorship = { agentId: "writer", modelFamily: "claude" };
  const reviewer: Authorship = { agentId: "reviewer", modelFamily: "claude" };
  assert.throws(() => assertHeterogeneous(author, reviewer));
});

test("different-family review is allowed", () => {
  const author: Authorship = { agentId: "writer", modelFamily: "claude" };
  const reviewer: Authorship = { agentId: "auditor", modelFamily: "gemini" };
  assert.doesNotThrow(() => assertHeterogeneous(author, reviewer));
});

test("objective self-review requires tests-pass and no known regression", () => {
  const anchor: ObjectiveAnchor = { testsPass: true, approvedSpecIntent: "fix bug", knownRegressions: ["REG-42"] };
  assert.equal(objectiveSelfReviewClean(anchor, "clean change").clean, true);
  assert.equal(objectiveSelfReviewClean(anchor, "reintroduces REG-42").clean, false);
  assert.equal(objectiveSelfReviewClean({ ...anchor, testsPass: false }, "clean").clean, false);
});

// --- Security verifier: graceful degradation + AI-risk + ranking ---

const semgrep: Scanner = {
  name: "semgrep",
  requiresCompilation: false,
  scan: async () => ({ findings: [finding({ detector: "semgrep" })], fullDepth: true }),
};

test("security gate NEVER blocks on deep-scanner (CodeQL) DB-build failure — falls back to Semgrep", async () => {
  const codeql: Scanner = {
    name: "codeql",
    requiresCompilation: true,
    scan: async () => {
      throw new Error("DB build failed: bad build file");
    },
  };
  const verifier = new SecurityVerifier(semgrep, codeql);
  const req: ScanRequest = { language: "java", compilable: true, diffFiles: ["A.java"] };
  const result = await verifier.verify(req);
  assert.equal(result.scannerUsed, "semgrep"); // fell back
  assert.equal(result.fullDepth, false);
  assert.ok(result.reducedDepthReason?.includes("codeql")); // flagged reduced depth
});

test("default scanner must not require compilation (Semgrep-class default)", () => {
  const badDefault: Scanner = { name: "codeql", requiresCompilation: true, scan: async () => ({ findings: [], fullDepth: true }) };
  assert.throws(() => new SecurityVerifier(badDefault));
});

test("AI-risk weighting up-weights injection/XSS/secret findings", () => {
  assert.ok(aiRiskWeight("possible XSS in template") > 1.0);
  assert.ok(aiRiskWeight("SQL injection risk") > 1.0);
  assert.equal(aiRiskWeight("rename a local variable"), 1.0);
});

test("ranking uses EPSS x reachability x severity, not severity alone", () => {
  const f = finding({ severity: "critical", message: "XSS" });
  // Same severity, but unreachable -> much lower rank than reachable.
  const reachable = rankScore(f, { epss: 0.9, reachability: 1.0, cvss: 0.9 });
  const unreachable = rankScore(f, { epss: 0.9, reachability: 0.0, cvss: 0.9 });
  assert.ok(reachable > unreachable);
  assert.equal(unreachable, 0); // unreachable -> no real-damage rank
});

// --- Risk-proportional depth + merge readiness ---

test("verification depth scales with blast-radius tier (R14)", () => {
  assert.equal(verificationDepth("reversible-internal"), "light");
  assert.equal(verificationDepth("external-touching"), "standard");
  assert.equal(verificationDepth("irreversible"), "full");
});

test("review-effort estimation triages by cheap signals (never auto-rejects)", () => {
  assert.equal(estimateReviewEffort({ linesChanged: 10, filesTouched: 1, crossCutting: false, inlineFindings: 0 }), "trivial");
  assert.equal(
    estimateReviewEffort({ linesChanged: 800, filesTouched: 20, crossCutting: true, inlineFindings: 5 }),
    "high",
  );
});

test("merge-readiness produces a 5-dimension card and never auto-merges", () => {
  const displayed = filterForDisplay([finding({ category: "security", severity: "critical", confidence: 0.9 })]);
  const mr = computeMergeReadiness({
    displayed,
    intentSatisfied: true,
    testsPass: true,
    coverageRatio: 0.8,
    tier: "irreversible",
  });
  // All five dimensions present.
  assert.ok(["security", "reliability", "complexity", "hygiene", "coverage"].every((k) => k in mr.card));
  // A critical security finding surfaces as a blocker — but it's the HUMAN who decides.
  assert.equal(mr.hasBlockers, true);
  assert.equal(mr.reviewDepth, "full");
  assert.ok(mr.card.security < 1); // security dinged by the critical finding
});

test("a clean change yields high readiness with no blockers", () => {
  const mr = computeMergeReadiness({
    displayed: [],
    intentSatisfied: true,
    testsPass: true,
    coverageRatio: 0.9,
    tier: "reversible-internal",
  });
  assert.equal(mr.hasBlockers, false);
  assert.ok(mr.overall > 0.9);
});
