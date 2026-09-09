import { test } from "node:test";
import assert from "node:assert/strict";

import { weakerTier, isolationAutonomyCeiling, TIER_STRENGTH } from "../src/isolation/isolation_tier.js";
import { ProcessIsolationExecutor } from "../src/isolation/isolated_executor.js";
import type { TestRunner } from "../src/solve/validate.js";

/**
 * ROUND 43 — A DECLARATION IS NOT EVIDENCE.
 *
 * The harness asked whether the DEFAULT isolation tier should be gated from autonomous merge.
 * Measuring first (requirement 1) produced a different and better answer.
 *
 * WHAT `process` ISOLATION ACTUALLY PREVENTS, at the wiring `keep_pipeline` uses
 * (`new ProcessIsolationExecutor(spine)` — no timeout — wrapping the operator's own runner):
 *
 *     read a file OUTSIDE the project dir : YES, full contents
 *     write a file OUTSIDE the project dir: YES
 *     ambient env vars visible           : 33
 *     unbounded busy loop                : YES, no timeout applied
 *     repoRef path traversal             : refused ✓
 *     high-risk patch                    : refused ✓
 *
 * So at this tier the executor validates a PATH ARGUMENT and writes an audit record; it does not
 * confine the execution when the inner runner is an ordinary in-process `TestRunner`. (The real
 * resource bounding lives in `SandboxedCommandRunner`, which `keep_pipeline` never builds.)
 *
 * BUT GATING THE DEFAULT WOULD BE THEATRE, and that is why this round did not do it: the harm
 * weak isolation permits happens at TEST time, before any merge decision exists. Gating the merge
 * cannot un-read a file. The only harm gating would address is a patch tampering with its own test
 * result — which requires a COMPROMISED agent, explicitly outside the stated threat model
 * (R35-narrow: confused, not compromised).
 *
 * THE ACTUAL DEFECT was next to it: the autonomy ceiling was computed from the DECLARED tier,
 * while a separate dep supplied the executor that really ran. Nothing compared them.
 */

const noopRunner: TestRunner = { async run() { return { results: [{ name: "t", passed: true }] }; } };

test("R43: the ceiling comes from the WEAKER of declared and actual", () => {
  assert.equal(weakerTier("microvm", "process"), "process", "a claim cannot raise the ceiling");
  assert.equal(weakerTier("process", "microvm"), "process", "and the order of arguments does not matter");
  assert.equal(weakerTier("microvm", "microvm"), "microvm", "an honest declaration costs nothing");
  assert.equal(weakerTier("none", "microvm"), "none", "the weakest always wins");
});

test("R43: declaring a stronger tier no longer buys a stronger ceiling", () => {
  // The measured defect, at the level of the rule. Declaring microvm while ProcessIsolationExecutor
  // runs previously yielded the `full` ceiling — auto-approval, and therefore NO decision brief —
  // purely on the claim. Note the direction of the old reward: a STRONGER claim made Keep LESS
  // careful, which is exactly backwards.
  const claimed = isolationAutonomyCeiling("microvm");
  const actual = isolationAutonomyCeiling(weakerTier("microvm", new ProcessIsolationExecutor().tier));

  assert.equal(claimed, "full", "the claim alone would have granted the top ceiling");
  assert.equal(actual, "minimal", "what actually ran determines it instead");
  assert.notEqual(claimed, actual, "and the two differ — the gap this closes");
});

test("R43: an honestly-declared strong tier is NOT penalised", () => {
  // Requirement: this must not punish an operator who wires a real boundary. If declaration and
  // executor agree, the ceiling is exactly what it always was.
  for (const tier of ["microvm", "gvisor", "container", "process", "none"] as const) {
    assert.equal(
      isolationAutonomyCeiling(weakerTier(tier, tier)), isolationAutonomyCeiling(tier),
      `${tier} declared honestly keeps its own ceiling`,
    );
  }
});

test("R43: the minimum is the fail-safe composition, in both directions", () => {
  // A claim can only ever LOWER the ceiling relative to what is enforced, never raise it — so
  // there is no configuration in which lying helps.
  const tiers = ["microvm", "gvisor", "container", "process", "none"] as const;
  for (const declared of tiers) {
    for (const actual of tiers) {
      const eff = weakerTier(declared, actual);
      assert.ok(
        TIER_STRENGTH[eff] <= TIER_STRENGTH[actual],
        `declared=${declared} actual=${actual}: the effective tier must never exceed what actually ran`,
      );
    }
  }
});

test("R43: what process isolation DOES enforce is still enforced", () => {
  // The round's measurement showed the executor does not confine an in-process runner. It does
  // still enforce two things, and those must not be lost while making the above point.
  const exec = new ProcessIsolationExecutor();
  const projectDir = "/tmp/r43-project";

  return Promise.all([
    exec.runIsolated(noopRunner, { projectDir, repoRef: `${projectDir}/../escape`, patchRisk: "medium" }),
    exec.runIsolated(noopRunner, { projectDir, repoRef: projectDir, patchRisk: "high" }),
  ]).then(([traversal, highRisk]) => {
    assert.equal(traversal.executed, false, "a repoRef that escapes the project dir is refused");
    assert.match(traversal.refusedReason ?? "", /escapes the project dir/);
    assert.equal(highRisk.executed, false, "a high-risk patch is refused at the process tier");
  });
});
