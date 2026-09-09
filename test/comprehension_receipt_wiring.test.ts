import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { KeepPipeline, type SolveToPrOptions } from "../src/pipeline/keep_pipeline.js";
import { ProcessIsolationExecutor } from "../src/isolation/isolated_executor.js";
import { type IsolationEvidence } from "../src/isolation/isolation_attestation.js";
import { InMemoryMergePort } from "./helpers/in_memory_merge_port.js";
import { pinnedGitDependencies } from "./helpers/pinned_git_dependencies.js";
import { DEFAULT_MERGE_ENVELOPE } from "../src/oversight/merge_authority.js";
import type { ModelProvider, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { RepoFile } from "../src/solve/localize.js";

/**
 * BUILD-ORDER 2.4 (COMPREHENSION-RECEIPT) — DOES THE PIPELINE RECORD AND CONSULT THE RECEIPT AT THE
 * MERGE SEAM? (Z140/ledger-298: the predicate is not the wiring.) comprehension_receipt.test.ts proves
 * the decision function; this file drives the REAL pipeline through solveIssueToPR and asserts the
 * observable an operator/auditor would notice: a CONSEQUENTIAL human-merge is held with a durable
 * delivery-receipt spine fact (mayProceed false) until an acknowledgment bound to THIS decision is
 * recorded. A merely reversible change does not neutralize an independently forced isolation gate:
 * the default process boundary remains consequential until real enforcement evidence exists.
 *
 * WIRING NEUTER (ledger 298): delete the decideComprehensionReceipt compute + spine.stage at the merge
 * seam (result.comprehensionReceipt goes undefined / the comprehension_receipt event disappears) → these
 * redden while the unit predicate stays green.
 */

const BROKEN = "export function add(a, b) { return a - b; }";

function setupRemote(): string {
  const root = mkdtempSync(join(tmpdir(), "b24w-"));
  const bare = join(root, "o.git"), work = join(root, "w");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  execFileSync("git", ["clone", "-q", bare, work]);
  const g = (a: string[]) => execFileSync("git", a, { cwd: work });
  g(["config", "user.email", "t@t"]); g(["config", "user.name", "t"]); g(["checkout", "-qb", "main"]);
  execFileSync("bash", ["-c", `mkdir -p ${join(work, "src")} && printf '%s' '${BROKEN}\n' > ${join(work, "src/calc.ts")}`]);
  g(["add", "-A"]); g(["commit", "-qm", "init"]); g(["push", "-q", "-u", "origin", "main"]);
  execFileSync("bash", ["-c", `printf '%s' 'export function add(a, b) { return a + b; }\n' > ${join(work, "src/calc.ts")}`]);
  return work;
}

const model: ModelProvider = {
  name: "fix", isLocal: true,
  async generate(): Promise<GenerateResult> {
    return { text: JSON.stringify({ rationale: "fix", edits: [{ file: "src/calc.ts", search: "a - b", replace: "a + b", intent: "fix" }] }), model: "fix", tokensIn: 1, tokensOut: 1 };
  },
  async embed(): Promise<Embedding[]> { return []; },
};

async function run(extra: Record<string, unknown>, opts: Partial<SolveToPrOptions> = {}) {
  const work = setupRemote();
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "b24ws-"))), new InProcessLock(), new SchemaRegistry());
  const tree = new InMemoryFileTree({ "src/calc.ts": BROKEN });
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  const files: RepoFile[] = [{ path: "src/calc.ts", content: BROKEN }];
  const result = await new KeepPipeline({ spine, tree, runner, model, ...extra } as never).solveIssueToPR(
    { id: "B24W", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" },
    files,
    pinnedGitDependencies(work, new InMemoryMergePort()),
    { autonomyLevel: "operator", ...opts },
  );
  return { result, spine };
}

/** A degraded default process floor → ceiling drops minimal→refuse-risky → a CONSEQUENTIAL human-merge. */
function degradedFloorExecutor(): ProcessIsolationExecutor {
  const spineForExec = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "b24p-"))), new InProcessLock(), new SchemaRegistry());
  const degraded: IsolationEvidence = { platform: process.platform, runtimeKind: "process", kvmPresent: false, imagesPresent: false, jobObjectSupport: false, degraded: ["net-deny-degraded"] };
  return new ProcessIsolationExecutor(spineForExec, { evidence: degraded });
}

function receiptEvents(spine: Spine) {
  return spine.currentEvents().filter((e) => (e.payload as { event?: string }).event === "comprehension_receipt");
}

test("2.4 WIRING: a CONSEQUENTIAL human-merge is HELD with a delivery-receipt spine fact (mayProceed false, no receipt)", async () => {
  const { result, spine } = await run({ isolationExecutor: degradedFloorExecutor() });
  assert.equal(result.mergeAuthority?.verdict, "human-merge", "a degraded floor routes to human-merge");
  assert.equal(result.mergeAuthority?.consequential, true, "and it is consequential");
  const r = result.comprehensionReceipt;
  assert.ok(r, "the pipeline surfaces a comprehension-receipt decision at the merge seam");
  assert.equal(r?.disposition, "delivery-receipt");
  assert.equal(r?.mayProceed, false, "the gated merge does not proceed autonomously without a recorded acknowledgment");

  const evs = receiptEvents(spine);
  assert.equal(evs.length, 1, "a durable comprehension_receipt fact is recorded on the spine (not a UI claim)");
  const p = evs[0]!.payload as Record<string, unknown>;
  assert.equal(p.disposition, "delivery-receipt");
  assert.equal(p.mayProceed, false);
  assert.equal(p.acknowledged, false);
  assert.equal(p.unacknowledgedSurfacing, true, "the UN-acknowledged surfacing is recorded so habituation is auditable");
});

test("2.4 WIRING: a receipt bound to THIS decision (via opts) lets the consequential merge proceed, acknowledged", async () => {
  // First run: read the decisionId the pipeline computed for this exact decision.
  const first = await run({ isolationExecutor: degradedFloorExecutor() });
  const decisionId = first.result.comprehensionReceipt?.decisionId;
  assert.ok(decisionId, "the decision id is surfaced so an operator knows what to acknowledge");

  // Second (deterministic) run supplying an acknowledgment bound to that decision.
  const { result, spine } = await run(
    { isolationExecutor: degradedFloorExecutor() },
    { mergeReceipt: { decisionId: decisionId!, acknowledgedBy: "operator@example", acknowledgedAt: 1 } },
  );
  const r = result.comprehensionReceipt;
  assert.equal(r?.disposition, "delivery-receipt");
  assert.equal(r?.mayProceed, true, "an acknowledgment bound to THIS decision lets the gated merge proceed");
  assert.equal(r?.satisfiedBy?.acknowledgedBy, "operator@example");

  const p = receiptEvents(spine)[0]!.payload as Record<string, unknown>;
  assert.equal(p.acknowledged, true);
  assert.equal(p.acknowledgedBy, "operator@example");
  assert.equal(p.unacknowledgedSurfacing, false);
});

test("2.4 WIRING: a STALE receipt (wrong decisionId) does NOT satisfy the consequential gate through the pipeline", async () => {
  const { result } = await run(
    { isolationExecutor: degradedFloorExecutor() },
    { mergeReceipt: { decisionId: "not-this-decision", acknowledgedBy: "operator@example", acknowledgedAt: 1 } },
  );
  assert.equal(result.comprehensionReceipt?.mayProceed, false, "an acknowledgment for a different decision must not unlock this merge");
});

test("2.4 WIRING: reversibility cannot erase the consequential isolation gate", async () => {
  // Verified + reversible, and the owner disabled autonomous merge. The default process boundary still
  // lacks native enforcement, so the independent isolation forced-gate remains consequential.
  const { result, spine } = await run(
    {},
    { mergeEnvelope: { ...DEFAULT_MERGE_ENVELOPE, autonomousMergeEnabled: false } },
  );
  assert.equal(result.mergeAuthority?.verdict, "human-merge");
  assert.equal(result.mergeAuthority?.consequential, true, "unproven isolation remains consequential even for a reversible patch");
  const r = result.comprehensionReceipt;
  assert.equal(r?.disposition, "delivery-receipt");
  assert.equal(r?.mayProceed, false, "reversibility cannot bypass the isolation hold");

  const p = receiptEvents(spine)[0]!.payload as Record<string, unknown>;
  assert.equal(p.disposition, "delivery-receipt");
  assert.equal(p.unacknowledgedSurfacing, true, "the unsatisfied hold is durably visible");
});

test("2.4 WIRING: the default process boundary requires a receipt and never auto-merges", async () => {
  const { result, spine } = await run({});
  assert.equal(result.mergeAuthority?.verdict, "human-merge", "the default cannot claim native isolation authority");
  assert.equal(result.comprehensionReceipt?.disposition, "delivery-receipt", "the consequential gate is surfaced");
  assert.equal(result.comprehensionReceipt?.mayProceed, false);
  assert.equal(receiptEvents(spine).length, 1, "the unsatisfied receipt is durably recorded");
});
