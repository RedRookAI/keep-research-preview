import { test } from "node:test";
import assert from "node:assert/strict";
import { SafeRemediation, type RemediationContext } from "../src/pipeline/safe_remediation.js";
import type { PatchVerifierInput } from "../src/pipeline/patch_verifier.js";
import { verifyPatch } from "../src/pipeline/patch_verifier.js";
import { GovernanceLedger } from "../src/governance/decision_record.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SolveResult, SearchReplaceEdit } from "../src/solve/issue_model.js";

function newSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-sr-"))), new InProcessLock(), new SchemaRegistry());
}
function solveWith(edits: SearchReplaceEdit[]): SolveResult {
  return {
    issueId: "x", solved: true, stagesRun: ["done"], repairRounds: 0,
    validation: { testsPassed: true, failures: [], vettingCleared: true, detail: "" },
    prProposal: { title: "t", body: "b", branch: "keep/solve/x", edits, testsPassed: true },
  };
}
function ctxFor(edits: SearchReplaceEdit[], suspectPaths: string[], issueText = ""): RemediationContext {
  const input: PatchVerifierInput = { solveResult: solveWith(edits), issueText, maxEdits: 12 };
  return { issueId: "x", input, verdict: verifyPatch(input), suspectPaths };
}

// Build a realistic scope-creep verdict: a small patch where one accidental UNRELATED edit pushes the
// edit count over a low maxEdits; dropping it narrows to a clean patch. maxEdits=3, 3 related + 1 unrelated.
function manyEditsCtx(): RemediationContext {
  const related: SearchReplaceEdit[] = Array.from({ length: 3 }, (_, i) => ({ file: `src/rel${i}.ts`, search: `aaaaaa${i}`, replace: `bbbbbb${i}`, intent: "fix" }));
  const unrelated: SearchReplaceEdit[] = [{ file: "src/UNRELATED.ts", search: "xxxxxx", replace: "yyyyyy", intent: "accidental" }];
  const suspects = related.map((e) => e.file);
  const input: PatchVerifierInput = { solveResult: solveWith([...related, ...unrelated]), maxEdits: 3 };
  return { issueId: "x", input, verdict: verifyPatch(input), suspectPaths: suspects };
}

test("INVARIANT: a provably-safe scope-creep concern is SELF-HEALED (drop unrelated edit) — no routing", () => {
  const sr = new SafeRemediation();
  const ctx = manyEditsCtx();
  assert.equal(ctx.verdict.cleared, false, "precondition: patch flagged (scope creep)");
  const out = sr.remediate(ctx);
  assert.equal(out.healed, true, "self-healed");
  assert.equal(out.ruleName, "drop-accidental-unrelated-edit");
  assert.ok(out.droppedEdits!.some((e) => e.file === "src/UNRELATED.ts"), "the accidental edit was dropped");
  assert.ok(out.rollbackId, "rollback id recorded");
});

test("INVARIANT: NEVER self-heals a patch touching a forbidden class (auth) — routes", () => {
  const sr = new SafeRemediation();
  // 3 related + 1 unrelated AUTH edit → scope flagged (4 edits > maxEdits 3), but auth is forbidden → route.
  const related: SearchReplaceEdit[] = Array.from({ length: 3 }, (_, i) => ({ file: `src/rel${i}.ts`, search: `aaaaaa${i}`, replace: `bbbbbb${i}`, intent: "fix" }));
  const authEdit: SearchReplaceEdit = { file: "src/auth/permission.ts", search: "checkPermission(u)", replace: "true", intent: "x" };
  const suspects = related.map((e) => e.file);
  const input: PatchVerifierInput = { solveResult: solveWith([...related, authEdit]), maxEdits: 3 };
  const ctx: RemediationContext = { issueId: "x", input, verdict: verifyPatch(input), suspectPaths: suspects };
  const out = sr.remediate(ctx);
  assert.equal(out.healed, false);
  assert.match(out.reason, /never auto-healed|auth/);
});

test("INVARIANT: self-heal cannot LAUNDER — if the narrowed patch still fails the sound floor, it routes", () => {
  // A rule that narrows to a still-failing patch (keeps a test-file edit → sound fail).
  const sr = new SafeRemediation({
    rules: [{
      name: "bad-heal", riskClass: "trivial-reversible",
      admissible: () => true,
      narrow: () => [{ file: "test/x.test.ts", search: "a", replace: "b", intent: "still bad" }],
    }],
    enabled: { "bad-heal": true },
  });
  const ctx = ctxFor([{ file: "src/x.ts", search: "aaaaaaaaa", replace: "bbbbbbbbb", intent: "fix" }, { file: "test/x.test.ts", search: "a", replace: "b", intent: "x" }], ["src/x.ts"]);
  const out = sr.remediate(ctx);
  assert.equal(out.healed, false, "narrowed patch still fails sound floor → not healed");
  assert.match(out.reason, /converged|routing/);
  assert.ok(out.attempts!.some((a) => !a.clearedSoundFloor), "the failed attempt is recorded in the trail");
});

test("INVARIANT: memory loop guard — same signature healed maxHeals times → routes", () => {
  const counts = new Map<string, number>();
  const sr = new SafeRemediation({ healCounts: counts, maxHealsPerSignature: 1 });
  const out1 = sr.remediate(manyEditsCtx());
  assert.equal(out1.healed, true, "first heal succeeds");
  const out2 = sr.remediate(manyEditsCtx());
  assert.equal(out2.healed, false, "second heal of same signature is loop-guarded → routes");
  assert.match(out2.reason, /loop guard|converged|routing/);
});

test("INVARIANT: shadow mode logs a would-be fix WITHOUT applying it", () => {
  const sr = new SafeRemediation({ shadow: { "drop-accidental-unrelated-edit": true } });
  const out = sr.remediate(manyEditsCtx());
  assert.equal(out.healed, false, "shadow does not apply");
  assert.equal(out.shadowed, true);
  assert.ok(out.droppedEdits!.length > 0, "shadow still reports what it WOULD drop");
});

test("INVARIANT: remediation is audited to the governance ledger (+ rollback id on apply)", async () => {
  const spine = newSpine();
  const gov = new GovernanceLedger(spine);
  const sr = new SafeRemediation({ governance: gov });
  const out = sr.remediate(manyEditsCtx());
  assert.equal(out.healed, true);
  await spine.seal();
  const trail = gov.readTrail();
  assert.ok(trail.some((x) => x.action === "remediate.applied"), "applied remediation audited");
});

test("reversibility: narrowing only REMOVES edits, never adds", () => {
  const sr = new SafeRemediation();
  const ctx = manyEditsCtx();
  const before = ctx.input.solveResult.prProposal!.edits.length;
  const out = sr.remediate(ctx);
  assert.equal(out.healed, true);
  assert.ok(out.healedResult!.prProposal!.edits.length < before, "healed patch has fewer edits (only removed)");
  // every kept edit existed in the original
  const originalFiles = new Set(ctx.input.solveResult.prProposal!.edits.map((e) => e.file));
  assert.ok(out.healedResult!.prProposal!.edits.every((e) => originalFiles.has(e.file)));
});

test("MULTI-ATTEMPT: tries a second targeted rule when the first doesn't clear, then heals", () => {
  // First rule narrows badly (keeps a test-file edit → sound fail); second rule narrows correctly.
  const badRule = { name: "bad", riskClass: "trivial-reversible" as const, admissible: () => true,
    narrow: () => [{ file: "test/x.test.ts", search: "a", replace: "b", intent: "bad" }] };
  const goodRule = { name: "good", riskClass: "trivial-reversible" as const, admissible: () => true,
    narrow: (c: RemediationContext) => c.input.solveResult.prProposal!.edits.filter((e) => c.suspectPaths.includes(e.file)) };
  const sr = new SafeRemediation({ rules: [badRule, goodRule], enabled: { bad: true, good: true }, maxAttempts: 3 });
  const out = sr.remediate(manyEditsCtx());
  assert.equal(out.healed, true, "second rule healed after the first failed");
  assert.equal(out.ruleName, "good");
  assert.ok(out.attempts!.length >= 2, "both attempts recorded");
});

test("BOUNDED: does not exceed the attempt budget (escalates on non-convergence)", () => {
  // Three rules that all fail to clear → after maxAttempts, escalate.
  const failRule = (n: string) => ({ name: n, riskClass: "trivial-reversible" as const, admissible: () => true,
    narrow: () => [{ file: "test/x.test.ts", search: "a", replace: "b", intent: n }] });
  const sr = new SafeRemediation({ rules: [failRule("r1"), failRule("r2"), failRule("r3"), failRule("r4")], enabled: { r1: true, r2: true, r3: true, r4: true }, maxAttempts: 2 });
  const out = sr.remediate(manyEditsCtx());
  assert.equal(out.healed, false);
  assert.equal(out.attempts!.length, 2, "stopped at the attempt budget (2), did not try r3/r4");
});

test("HETEROGENEOUS VERIFIER: a healed patch clearing the sound floor is REJECTED if the independent verifier declines", () => {
  const sr = new SafeRemediation({
    independentVerifier: { identity: { agentId: "reviewer", modelFamily: "other" }, verify: () => false },
    authorship: { agentId: "healer", modelFamily: "deterministic" },
  });
  const out = sr.remediate(manyEditsCtx());
  assert.equal(out.healed, false, "independent verifier veto → not healed");
  assert.ok(out.attempts!.some((a) => a.clearedSoundFloor && a.independentApproved === false), "attempt shows sound-cleared but independent-declined");
});

test("HETEROGENEOUS VERIFIER: an approving independent verifier lets the heal through (both gates pass)", () => {
  const sr = new SafeRemediation({
    independentVerifier: { identity: { agentId: "reviewer", modelFamily: "other" }, verify: () => true },
    authorship: { agentId: "healer", modelFamily: "deterministic" },
  });
  const out = sr.remediate(manyEditsCtx());
  assert.equal(out.healed, true);
  assert.ok(out.attempts!.some((a) => a.independentApproved === true));
});

test("HETEROGENEOUS VERIFIER: a same-family verifier is REFUSED at construction (self-review forbidden)", () => {
  assert.throws(() => new SafeRemediation({
    independentVerifier: { identity: { agentId: "healer", modelFamily: "deterministic" }, verify: () => true },
    authorship: { agentId: "healer", modelFamily: "deterministic" },
  }), /self-review|heterogeneity/);
});
