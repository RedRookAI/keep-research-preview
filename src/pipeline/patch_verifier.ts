/**
 * Patch verifier (Increment 16.7) — bespoke, diff-level verification for the PATCH stage.
 *
 * Purpose-built for this need (NOT a retrofit of the plan-shaped LogicVet, which vets a plan
 * pre-execution — a separate gate that also runs). SOTA-grounded (2026-08-05):
 *
 *  - The dangerous failure is the semantically-incorrect patch that passes all automated checks
 *    (~20% of agent patches; team-atlanta 2026). The #1 pattern is "functionality altered or broken"
 *    — the fix works but changes normal behavior in unintended ways (e.g. a correct null-check PLUS an
 *    unintended early-return). So "tests passed" is NOT sufficient; we inspect the DIFF SHAPE.
 *  - Mechanical checklist (arXiv 2605.02244, triadic-data): compiles / AST parses / imports resolve /
 *    tests pass / **patch does not modify test files** / **issue text not leaked into the patch** /
 *    **secrets + PII scanned**. Most vendors do the first three and skip the rest — test-file
 *    modification and solution-leakage are exactly where SWE-bench+ found threefold inflation.
 *  - Self-confirmation loop: when the agent writes both code and tests, the tests may validate the bug
 *    (Augment 2026). The cheap sound guard is "the patch must not touch the tests it's judged by."
 *
 * Two tiers: Tier-1 SOUND (deterministic mechanical checks — a sound fail cannot be overturned);
 * Tier-2 HEURISTIC (scope-creep / unintended-control-flow signals — advisory, can escalate to human).
 * Model-free and zero-dep; a model-based adversarial-test tier is a labelled seam behind this port.
 */

import { DEFAULT_ALWAYS_GATE_PATTERNS } from "../oversight/pr_risk.js";
import type { SolveResult, SearchReplaceEdit } from "../solve/issue_model.js";

export type PatchCheckDecision = "pass" | "fail" | "flag";

export interface PatchCheck {
  readonly name: string;
  readonly tier: 1 | 2;
  readonly sound: boolean;
  readonly decision: PatchCheckDecision;
  readonly reason: string;
}

export interface PatchVerdict {
  /** true iff no SOUND check failed AND no heuristic check flagged above the block threshold. */
  readonly cleared: boolean;
  /** overall: "pass" (clean), "fail" (a sound check failed), "escalate-human" (heuristic concerns). */
  readonly outcome: "pass" | "fail" | "escalate-human";
  readonly checks: readonly PatchCheck[];
  readonly reason: string;
}

export interface PatchVerifierInput {
  readonly solveResult: SolveResult;
  /** The issue text — to detect solution leakage into the patch. */
  readonly issueText?: string;
  /** Secret/PII scan patterns for diff content (defaults to the hardened sensitive-path set). */
  readonly secretPatterns?: readonly RegExp[];
  /** Max edits before scope-creep is flagged (heuristic; default 12). */
  readonly maxEdits?: number;
}

// ── mechanical (Tier-1, SOUND) checks ──

function isTestFile(path: string): boolean {
  const base = path.split("/").pop() ?? path;
  // Test directories + conventional test/spec filenames.
  if (/(^|\/)(tests?|__tests__|spec|e2e)\//i.test(path)) return true;
  if (/\.(test|spec)\.[a-z]+$/i.test(base) || /_test\.[a-z]+$/i.test(base) || /^test_.*\.[a-z]+$/i.test(base)) return true;
  // Test infrastructure / config that can silently alter the oracle (pytest, jest, vitest, mocha).
  if (/^(conftest\.py|pytest\.ini|tox\.ini|jest\.config\.[a-z]+|vitest\.config\.[a-z]+|\.mocharc\.[a-z]+|setup\.cfg)$/i.test(base)) return true;
  return false;
}

/** SOUND: a patch may not modify the very tests it is judged by (oracle-gaming / self-confirmation). */
function checkNoTestModification(edits: readonly SearchReplaceEdit[]): PatchCheck {
  const touched = edits.filter((e) => isTestFile(e.file)).map((e) => e.file);
  return touched.length === 0
    ? { name: "no-test-file-modification", tier: 1, sound: true, decision: "pass", reason: "patch touches no test files" }
    : { name: "no-test-file-modification", tier: 1, sound: true, decision: "fail", reason: `patch modifies test files (oracle-gaming risk): ${[...new Set(touched)].join(", ")}` };
}

/** SOUND: the produced patch must not introduce secrets / credentials into the diff. */
function checkNoSecretsIntroduced(edits: readonly SearchReplaceEdit[], patterns: readonly RegExp[]): PatchCheck {
  for (const e of edits) {
    // Only NEW content (the replacement), and only if it wasn't already in the searched text.
    const added = e.replace;
    for (const re of patterns) {
      if (re.test(added) && !re.test(e.search)) {
        return { name: "no-secrets-introduced", tier: 1, sound: true, decision: "fail", reason: `patch introduces a secret-like token in ${e.file} (pattern ${re.source.slice(0, 40)})` };
      }
    }
  }
  return { name: "no-secrets-introduced", tier: 1, sound: true, decision: "pass", reason: "no secret-like tokens introduced by the diff" };
}

/** SOUND: edits must be well-formed (non-empty search, an actual change). */
function checkEditsWellFormed(edits: readonly SearchReplaceEdit[]): PatchCheck {
  if (edits.length === 0) return { name: "edits-well-formed", tier: 1, sound: true, decision: "fail", reason: "no edits in the patch" };
  const bad = edits.find((e) => e.search.length === 0 || e.search === e.replace);
  return bad
    ? { name: "edits-well-formed", tier: 1, sound: true, decision: "fail", reason: `malformed edit in ${bad.file} (empty search or no-op)` }
    : { name: "edits-well-formed", tier: 1, sound: true, decision: "pass", reason: "all edits well-formed" };
}

/** SOUND: the patch's validation must show tests passing (the fix actually works). */
function checkTestsPass(solveResult: SolveResult): PatchCheck {
  const v = solveResult.validation;
  if (!v) return { name: "tests-pass", tier: 1, sound: true, decision: "fail", reason: "no validation outcome on the patch" };
  return v.testsPassed
    ? { name: "tests-pass", tier: 1, sound: true, decision: "pass", reason: "tests pass, no regression reported" }
    : { name: "tests-pass", tier: 1, sound: true, decision: "fail", reason: `tests not passing: ${(v.failures ?? []).join(", ") || "unknown"}` };
}

/** SOUND: the issue text should not be copied verbatim into the patch (solution-leakage inflation). */
function checkNoSolutionLeakage(edits: readonly SearchReplaceEdit[], issueText: string | undefined): PatchCheck {
  if (!issueText || issueText.trim().length < 40) return { name: "no-solution-leakage", tier: 1, sound: true, decision: "pass", reason: "no issue text to check (or too short)" };
  const norm = (s: string) => s.replace(/\s+/g, " ").trim().toLowerCase();
  const issue = norm(issueText);
  // Flag if a long contiguous slice of the issue appears verbatim in an added block.
  for (const e of edits) {
    const added = norm(e.replace);
    if (added.length >= 60 && issue.includes(added)) {
      return { name: "no-solution-leakage", tier: 1, sound: true, decision: "fail", reason: `patch content appears copied verbatim from the issue text in ${e.file}` };
    }
  }
  return { name: "no-solution-leakage", tier: 1, sound: true, decision: "pass", reason: "no verbatim issue-text leakage detected" };
}

/** Dangerous risk sinks whose NET addition increases static-analysis risk (SCAFFOLD-CEGIS monotonicity). */
const RISK_SINKS: readonly RegExp[] = [
  /\beval\s*\(/g,
  /\bnew\s+Function\s*\(/g,
  /\bexec(Sync|File|FileSync)?\s*\(/g,
  /\bchild_process\b/g,
  /\bspawn(Sync)?\s*\(/g,
  /\b(os\.system|subprocess\.(call|run|Popen)|shell=True)\b/g,
  /\b(pickle\.loads|yaml\.load\s*\((?![^)]*Loader)|marshal\.loads)\b/g,
  /\b__import__\s*\(/g,
];

/**
 * SOUND (safety-monotonicity, SCAFFOLD-CEGIS 2603.08520): a patch must not NET-ADD a dangerous risk sink
 * (eval/exec/shell/unsafe-deserialize) — i.e. it may not increase static-analysis risk vs the pre-image.
 * Counts sinks in added vs removed text per edit; a net increase fails (routes to human), even if tests pass.
 */
function checkSafetyMonotonicity(edits: readonly SearchReplaceEdit[]): PatchCheck {
  for (const e of edits) {
    for (const re of RISK_SINKS) {
      const added = countMatches(e.replace, re);
      const removed = countMatches(e.search, re);
      if (added > removed) {
        return { name: "safety-monotonicity", tier: 1, sound: true, decision: "fail", reason: `patch net-adds a risk sink in ${e.file} (${re.source.slice(0, 24)}: +${added - removed}) — static-analysis risk increased` };
      }
    }
  }
  return { name: "safety-monotonicity", tier: 1, sound: true, decision: "pass", reason: "no net increase in risk sinks (safety-monotone)" };
}

/**
 * Destructive-operation detection (red-team hardening, 2026-08-08) — targets the #1 real-world incident class: agents
 * that INTRODUCE destructive data/filesystem operations (PocketOS prod-DB deletion, DataTalks Terraform wipe). Two tiers:
 *   • CATASTROPHIC ops have no legitimate place in a source patch → a SOUND block.
 *   • DESTRUCTIVE data/infra ops are sometimes legitimate (a real migration) but ALWAYS need a human → a HEURISTIC flag
 *     (escalate-human), which the consequence assessor pairs with an irreversible tier → human-merge (never auto, never
 *     silently abandoned). Monotone: only a NET-ADDED op triggers, so REMOVING a destructive op is always fine.
 */
const CATASTROPHIC_OPS: readonly RegExp[] = [
  /\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+["']?[~/]/gi,     // rm -rf / or ~
  /\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+["']?\$?\{?HOME/gi,
  /\bmkfs\.[a-z0-9]+/gi,                              // format a filesystem
  /\bdd\s+[^\n]*\bof=\/dev\//gi,                   // overwrite a block device
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/g, // fork bomb
  />\s*\/dev\/(sd|nvme|disk|hd|null\/\.\.)/gi,
  /\bshred\s+-/gi,
];
const DESTRUCTIVE_DATA_OPS: readonly RegExp[] = [
  /\bDROP\s+(TABLE|DATABASE|SCHEMA|COLLECTION|INDEX)\b/gi,
  /\bTRUNCATE\s+(TABLE\s+)?[`"'\w]/gi,
  /\bDELETE\s+FROM\b(?![^;]*\bWHERE\b)/gi,          // DELETE with no WHERE
  /\.drop(Database|Collection|Table|Index)?\s*\(/g,   // mongo/orm .drop()
  /\bgit\s+push\s+[^\n]*(--force\b|-f\b)/gi,
  /\bgit\s+reset\s+--hard\b/gi,
  /\bgit\s+branch\s+-D\b/g,
  /\bterraform\s+destroy\b/gi,
  /\baws\s+[a-z0-9-]+\s+(delete|rm|rb)\b/gi,
  /\brm\s+-[a-z]*r[a-z]*f[a-z]*\b/gi,                 // any rm -rf (non-catastrophic path) is still consequential
];

/** Net-added match of any pattern in `pats` across the edits (added in replace beyond what was in search). */
function netAdds(edits: readonly SearchReplaceEdit[], pats: readonly RegExp[]): { file: string; pat: string } | null {
  for (const e of edits) for (const re of pats) {
    if (countMatches(e.replace, re) > countMatches(e.search, re)) return { file: e.file, pat: re.source.slice(0, 28) };
  }
  return null;
}

/** True if the patch net-introduces a destructive data/infra OR catastrophic operation (for consequence assessment). */
export function patchIntroducesDestructiveOp(edits: readonly SearchReplaceEdit[]): boolean {
  return netAdds(edits, CATASTROPHIC_OPS) !== null || netAdds(edits, DESTRUCTIVE_DATA_OPS) !== null;
}

/** SOUND: a patch must never net-add a catastrophic, never-legitimate operation (rm -rf /, mkfs, fork bomb, dd of=/dev). */
function checkNoCatastrophicOps(edits: readonly SearchReplaceEdit[]): PatchCheck {
  const hit = netAdds(edits, CATASTROPHIC_OPS);
  if (hit) return { name: "no-catastrophic-ops", tier: 1, sound: true, decision: "fail", reason: `patch net-adds a catastrophic operation in ${hit.file} (${hit.pat}) — never mergeable under any authority` };
  return { name: "no-catastrophic-ops", tier: 1, sound: true, decision: "pass", reason: "no catastrophic filesystem/disk operation introduced" };
}

/** HEURISTIC: a net-added destructive data/infra op (DROP TABLE, DELETE-without-WHERE, force-push, terraform destroy)
 *  always needs a human — sometimes legitimate (a migration), never auto-mergeable. */
function checkNoDestructiveDataOps(edits: readonly SearchReplaceEdit[]): PatchCheck {
  const hit = netAdds(edits, DESTRUCTIVE_DATA_OPS);
  if (hit) return { name: "destructive-data-op", tier: 2, sound: false, decision: "flag", reason: `edit in ${hit.file} introduces a destructive data/infra operation (${hit.pat}) — a human must own this (consequence-gated; never auto-merged, never silently abandoned)` };
  return { name: "destructive-data-op", tier: 2, sound: false, decision: "pass", reason: "no destructive data/infra operation introduced" };
}

// ── semantic (Tier-2, HEURISTIC) checks — the #1 "functionality altered" failure ──

/** HEURISTIC: an added early-return / control-flow change alongside a fix is the top semantic-failure pattern. */
function checkNoUnintendedControlFlow(edits: readonly SearchReplaceEdit[]): PatchCheck {
  for (const e of edits) {
    const addedReturns = countMatches(e.replace, /\breturn\b/g) - countMatches(e.search, /\breturn\b/g);
    const addedThrows = countMatches(e.replace, /\bthrow\b/g) - countMatches(e.search, /\bthrow\b/g);
    const addedExits = countMatches(e.replace, /\b(process\.exit|sys\.exit|break|continue)\b/g) - countMatches(e.search, /\b(process\.exit|sys\.exit|break|continue)\b/g);
    if (addedReturns > 0 || addedThrows > 0 || addedExits > 0) {
      return { name: "no-unintended-control-flow", tier: 2, sound: false, decision: "flag", reason: `edit in ${e.file} adds control-flow (returns:+${addedReturns} throws:+${addedThrows} exits:+${addedExits}) — verify it doesn't skip intended processing (top semantic-failure pattern)` };
    }
  }
  return { name: "no-unintended-control-flow", tier: 2, sound: false, decision: "pass", reason: "no new early-return/throw/exit control flow" };
}

/** HEURISTIC: too many edits or many distinct files suggests scope creep beyond the issue. */
function checkScope(edits: readonly SearchReplaceEdit[], maxEdits: number): PatchCheck {
  const files = new Set(edits.map((e) => e.file));
  if (edits.length > maxEdits) return { name: "scope-bounded", tier: 2, sound: false, decision: "flag", reason: `${edits.length} edits (> ${maxEdits}) — possible scope creep beyond the issue` };
  if (files.size > Math.max(4, Math.ceil(maxEdits / 3))) return { name: "scope-bounded", tier: 2, sound: false, decision: "flag", reason: `${files.size} distinct files touched — verify the change is not broader than the issue` };
  return { name: "scope-bounded", tier: 2, sound: false, decision: "pass", reason: `scope bounded (${edits.length} edits, ${files.size} files)` };
}

function countMatches(s: string, re: RegExp): number { return (s.match(re) ?? []).length; }

/**
 * Verify a produced patch. Runs the SOUND mechanical tier first (any sound fail → fail, short-circuit
 * semantics preserved), then the HEURISTIC semantic tier (any flag → escalate-human, never a silent
 * pass). Returns a structured verdict + full check trail (auditable).
 */
export function verifyPatch(input: PatchVerifierInput): PatchVerdict {
  const edits = input.solveResult.prProposal?.edits ?? [];
  const patterns = input.secretPatterns ?? DEFAULT_ALWAYS_GATE_PATTERNS;
  const maxEdits = input.maxEdits ?? 12;

  const soundChecks: PatchCheck[] = [
    checkEditsWellFormed(edits),
    checkTestsPass(input.solveResult),
    checkNoTestModification(edits),
    checkNoSecretsIntroduced(edits, patterns),
    checkNoSolutionLeakage(edits, input.issueText),
    checkSafetyMonotonicity(edits),
    checkNoCatastrophicOps(edits),
  ];
  const soundFail = soundChecks.find((c) => c.decision === "fail");
  if (soundFail) {
    return { cleared: false, outcome: "fail", checks: soundChecks, reason: `sound check failed: ${soundFail.reason}` };
  }

  const heuristicChecks: PatchCheck[] = [
    checkNoUnintendedControlFlow(edits),
    checkNoDestructiveDataOps(edits),
    checkScope(edits, maxEdits),
  ];
  const flagged = heuristicChecks.filter((c) => c.decision === "flag");
  const checks = [...soundChecks, ...heuristicChecks];
  if (flagged.length > 0) {
    return { cleared: false, outcome: "escalate-human", checks, reason: `heuristic concerns → human review: ${flagged.map((c) => c.reason).join("; ")}` };
  }

  return { cleared: true, outcome: "pass", checks, reason: "patch cleared all mechanical + heuristic checks" };
}

/**
 * The pipeline's default patch-vetting function. Returns a (repoRef)=>Promise<boolean> the SafetyRail
 * consumes: true iff the bespoke verifier clears the patch. The rail is still fail-closed around it.
 */
export function defaultPatchVetter(getInput: () => PatchVerifierInput | undefined): (repoRef: string) => Promise<boolean> {
  return async (): Promise<boolean> => {
    const input = getInput();
    if (!input) return false; // nothing to vet → fail-closed
    return verifyPatch(input).cleared;
  };
}
