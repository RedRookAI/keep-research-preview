import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { RollbackLedger } from "../src/control/rollback.js";
import { HierarchicalLocalizer, type RepoFile } from "../src/solve/localize.js";
import { SolvePipeline } from "../src/solve/solve_pipeline.js";
import { IdentityRegistry } from "../src/identity/agent_identity.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";

/**
 * ROUND 35 — THE IDENTITY KILL SWITCH, ON THE PRODUCTION PATH.
 *
 * Round 30 armed the switch and proved it fires with an identity injected by a test. Round 34
 * made the composed path live by default. NEITHER made the switch reachable in production:
 *
 *   reversible_execution.ts:148
 *     identityLive = registry && identity ? registry.authorize(identity).authorized : undefined
 *
 * and no production construction site supplied either field, so `identityLive` was `undefined`
 * — "not assessed (no veto)" — on every real path.
 *
 * WHAT THIS ROUND BUILT, STATED NARROWLY. The registry is an in-process `Map`/`Set`, and the
 * research is unambiguous that this cannot be a security boundary on a local machine:
 * "because the agent process can't attest to itself, trust has to be rooted somewhere the agent
 * is not", and "tokens and keys held by a local process live in memory that other same-user
 * processes can read." So this is an OPERATOR REVOCATION CONTROL — it stops Keep's own solve
 * path on command. It is NOT anti-forgery against local code execution. See the round doc.
 *
 * The registry is OPERATOR-SUPPLIED for the reason that matters: a registry the pipeline minted
 * privately would leave `kill()` unreachable, and an unreachable kill switch reports
 * "assessed and fine" forever — strictly worse than the honest `undefined`.
 */

function freshSpine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "r35-"))), new InProcessLock(), new SchemaRegistry());
}

class PlanModel implements ModelProvider {
  readonly name = "plan-model";
  readonly isLocal = true;
  constructor(private readonly planJson: string) {}
  async generate(_r: GenerateRequest): Promise<GenerateResult> {
    return { text: this.planJson, model: this.name, tokensIn: 1, tokensOut: 1 };
  }
  async embed(_t: readonly string[]): Promise<Embedding[]> { return []; }
}

const runner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "t", passed: true }] }; } };

const BEFORE = "export const x = 1;\n";
const AFTER = "export const x = 2;\n";

/** An ordinary, benign edit — one the barriers otherwise ACCEPT. The identity is the only variable. */
const BENIGN = JSON.stringify({
  rationale: "ordinary single-file edit",
  edits: [{ file: "src/calc.ts", search: "export const x = 1;", replace: "export const x = 2;", intent: "bump" }],
});

function scenario(extra: Record<string, unknown>) {
  const files: RepoFile[] = [{ path: "src/calc.ts", content: BEFORE }];
  const tree = new InMemoryFileTree({ "src/calc.ts": BEFORE });
  const spine = freshSpine();
  const pipeline = new SolvePipeline({
    spine,
    ledger: new RollbackLedger(spine),
    tree,
    runner,
    localizer: new HierarchicalLocalizer(),
    model: new PlanModel(BENIGN),
    ...extra,
  } as never);
  return { tree, pipeline, files };
}

const ISSUE = { id: "R35", text: "bump the constant x in src/calc.ts", repoRef: "repo" };

test("R35: a KILLED identity is refused on the default path — the edit does not land", async () => {
  const registry = new IdentityRegistry();
  const identity = registry.mint("keep-solve", ["*"]);
  registry.kill("keep-solve", "operator revoked");

  const { tree, pipeline, files } = scenario({ identity, identityRegistry: registry });
  const result = await pipeline.run(ISSUE, files);

  // The run must actually reach apply — otherwise an unchanged tree proves nothing (Z136).
  assert.ok(result.stagesRun.includes("apply"), "the run must reach the apply stage");
  // THE EFFECT (Z108): a benign edit that would otherwise land is contained.
  assert.equal(await tree.read("src/calc.ts"), BEFORE, "a killed identity's edit must not land");
  assert.match(
    result.gaveUpReason ?? "", /killed-or-unknown-identity/,
    "the operator must be told the identity was the reason, not left guessing",
  );
});

test("R35: the SAME edit lands with a LIVE identity — the identity is the only variable", async () => {
  // Without this, test 1 proves only that something refused the edit, not that the kill switch
  // did. Same plan, same tree, same barriers; the single difference is kill().
  const registry = new IdentityRegistry();
  const identity = registry.mint("keep-solve", ["*"]);

  const { tree, pipeline, files } = scenario({ identity, identityRegistry: registry });
  const result = await pipeline.run(ISSUE, files);

  assert.equal(await tree.read("src/calc.ts"), AFTER, "a live identity does not impede ordinary work");
  assert.equal(result.solved, true);
});

test("R35: supplying NO identity preserves the `undefined` contract — not assessed, no veto", async () => {
  // Requirement 4. Other callers depend on omission meaning "not assessed", and arming the
  // switch must not quietly turn omission into a denial.
  const { tree, pipeline, files } = scenario({});
  const result = await pipeline.run(ISSUE, files);

  assert.equal(await tree.read("src/calc.ts"), AFTER, "omitting the identity must not start denying work");
  assert.equal(result.solved, true);
});

test("R35: supplying only ONE of the two fields leaves the switch UNARMED — and that is visible", async () => {
  // The trap this wiring is most likely to hit in the field. `identityLive` is computed as
  //   registry && identity ? authorize(identity) : undefined
  // so a caller who passes a registry but no identity (or vice versa) gets `undefined` —
  // "not assessed" — even though they believe they armed it. Pinning it so the asymmetry is a
  // documented fact rather than a surprise.
  const registry = new IdentityRegistry();
  const identity = registry.mint("keep-solve", ["*"]);
  registry.kill("keep-solve");

  const onlyRegistry = scenario({ identityRegistry: registry });
  await onlyRegistry.pipeline.run(ISSUE, onlyRegistry.files);
  assert.equal(
    await onlyRegistry.tree.read("src/calc.ts"), AFTER,
    "registry without identity ⇒ not assessed ⇒ the killed id does NOT veto",
  );

  const onlyIdentity = scenario({ identity });
  await onlyIdentity.pipeline.run(ISSUE, onlyIdentity.files);
  assert.equal(
    await onlyIdentity.tree.read("src/calc.ts"), AFTER,
    "identity without registry ⇒ not assessed ⇒ no veto",
  );
});

test("R35: kill is MONOTONE — re-minting the same id does not resurrect it", async () => {
  // `mint` overwrites the token but never clears `revoked`, so an operator cannot be tricked
  // into un-killing by reconstructing a pipeline. Asserted rather than assumed, because the
  // production paths mint on construction / per solve and would otherwise re-mint routinely.
  const registry = new IdentityRegistry();
  registry.mint("keep-solve", ["*"]);
  registry.kill("keep-solve");
  const reminted = registry.mint("keep-solve", ["*"]); // fresh token, same id

  assert.equal(registry.authorize(reminted).authorized, false, "a killed id stays killed across re-mint");

  const { tree, pipeline, files } = scenario({ identity: reminted, identityRegistry: registry });
  await pipeline.run(ISSUE, files);
  assert.equal(await tree.read("src/calc.ts"), BEFORE, "and the edit is still contained end to end");
});

test("R36: revocation after the gate but before commit now REFUSES (was: committed)", async () => {
  // ROUND 36 INVERTED THIS TEST, and the inversion is the disproof.
  //
  // In round 35 this same scenario asserted the opposite — that the in-flight op COMMITTED —
  // because authorization was computed once, upstream, and nothing re-asked before the write.
  // A precommit hook now re-asks immediately before any write, so the identical scenario must
  // now roll back. Nothing about the scenario changed; only the product did.
  //
  // executeReversibly authorizes ONCE, at reversible_execution.ts:148, and everything after —
  // twin, gate, fork, acceptance, commit — runs on that one verdict. `intent.apply` is invoked
  // TWICE: once by the digital twin (line 125, BEFORE the check) and once by the envelope
  // (line 204, AFTER it). Killing on the SECOND invocation therefore lands precisely inside the
  // window and nowhere else.
  const { executeReversibly } = await import("../src/integrate/reversible_execution.js");
  const { defaultFloorPolicy } = await import("../src/floor/structural_floor.js");
  const { defaultGatePolicy } = await import("../src/gate/composed_gate.js");
  const { defaultBudgetPolicy } = await import("../src/budget/budget_ledger.js");
  const { defaultAcceptanceTest } = await import("../src/ree/reversible_envelope.js");
  const { ensureMediated } = await import("../src/solve/mediated_tree.js");

  const registry = new IdentityRegistry();
  const identity = registry.mint("racer", ["*"]);
  const tree = ensureMediated(new InMemoryFileTree({ "a.txt": "old" }));

  let applyCalls = 0;
  const result = await executeReversibly(
    {
      description: { kind: "file.edit", writeSet: ["a.txt"], targets: ["a.txt"], hasInverse: true, raw: "new" },
      apply: async (t) => {
        applyCalls++;
        if (applyCalls === 2) registry.kill("racer", "revoked mid-flight"); // AFTER authorize
        await t.write("a.txt", "new");
      },
      actionTier: "reversible-internal",
    },
    { floor: defaultFloorPolicy("repo"), gate: defaultGatePolicy(), budget: defaultBudgetPolicy(), acceptance: defaultAcceptanceTest },
    {
      spine: freshSpine(), actor: "t", operator: "t", sign: (p) => `sig:${p}`,
      tree, ownerPresent: true, envelopeEnabled: true, identity, identityRegistry: registry,
    },
  );

  assert.equal(registry.authorize(identity).authorized, false, "the identity really was revoked mid-flight");
  assert.equal(result.path, "envelope", "the op still entered the envelope on the pre-revocation verdict");
  assert.equal(
    result.outcome.outcome, "rolled-back",
    "the precommit re-check refuses an op whose identity died after the gate",
  );
  if (result.outcome.outcome === "rolled-back") {
    assert.match(result.outcome.reason, /identity-revoked-before-commit:killed-identity/,
      "and names WHY, so the rollback is not indistinguishable from a metamorphic reject");
  }
  // THE EFFECT (Z108), and the atomicity guarantee with it: refusing at the last moment must
  // leave the tree byte-identical to pre, exactly as any other rollback does.
  assert.equal(await tree.read("a.txt"), "old", "nothing was written — the refusal is atomic");

  // The bound is unchanged and still worth asserting: the NEXT op is refused too.
  const second = await executeReversibly(
    {
      description: { kind: "file.edit", writeSet: ["a.txt"], targets: ["a.txt"], hasInverse: true, raw: "newer" },
      apply: async (t) => { await t.write("a.txt", "newer"); },
      actionTier: "reversible-internal",
    },
    { floor: defaultFloorPolicy("repo"), gate: defaultGatePolicy(), budget: defaultBudgetPolicy(), acceptance: defaultAcceptanceTest },
    {
      spine: freshSpine(), actor: "t", operator: "t", sign: (p) => `sig:${p}`,
      tree, ownerPresent: true, envelopeEnabled: true, identity, identityRegistry: registry,
    },
  );
  assert.equal(second.path, "human-hold", "the very next op is refused at the gate, as before");
  assert.equal(await tree.read("a.txt"), "old", "and nothing lands");
});

test("R36 RESIDUAL MEASURED: a revocation landing DURING the writes still completes them", async () => {
  // The honest other half. CWE-367 is explicit that narrowing the check-to-use gap "will not
  // fix the problem" — only atomic check-and-use does, and asynchronous writes make that
  // unavailable. So rather than claim the window is closed, the round MEASURES what is left.
  //
  // Construction: a two-file write-set, with a tree whose FIRST write revokes the identity.
  // The precommit check has already passed by then, and nothing re-checks inside the loop, so
  // the second write must still land. That is the residual window, exhibited rather than argued.
  const { executeReversibly } = await import("../src/integrate/reversible_execution.js");
  const { defaultFloorPolicy } = await import("../src/floor/structural_floor.js");
  const { defaultGatePolicy } = await import("../src/gate/composed_gate.js");
  const { defaultBudgetPolicy } = await import("../src/budget/budget_ledger.js");
  const { defaultAcceptanceTest } = await import("../src/ree/reversible_envelope.js");
  const { ensureMediated } = await import("../src/solve/mediated_tree.js");

  const registry = new IdentityRegistry();
  const identity = registry.mint("racer2", ["*"]);
  const inner = new InMemoryFileTree({ "a.txt": "old", "b.txt": "old" });

  let writes = 0;
  const revokingTree = ensureMediated({
    read: (p: string) => inner.read(p),
    write: async (p: string, c: string) => {
      writes++;
      if (writes === 1) registry.kill("racer2", "revoked mid-commit"); // INSIDE the write loop
      await inner.write(p, c);
    },
  } as never);

  const result = await executeReversibly(
    {
      description: { kind: "file.edit", writeSet: ["a.txt", "b.txt"], targets: ["a.txt", "b.txt"], hasInverse: true, raw: "new" },
      apply: async (t) => { await t.write("a.txt", "new"); await t.write("b.txt", "new"); },
      actionTier: "reversible-internal",
    },
    { floor: defaultFloorPolicy("repo"), gate: defaultGatePolicy(), budget: defaultBudgetPolicy(), acceptance: defaultAcceptanceTest },
    {
      spine: freshSpine(), actor: "t", operator: "t", sign: (p) => `sig:${p}`,
      tree: revokingTree, ownerPresent: true, envelopeEnabled: true, identity, identityRegistry: registry,
    },
  );

  assert.equal(result.path, "envelope");
  assert.equal(result.outcome.outcome, "committed", "the precommit check passed before the revocation landed");
  assert.equal(registry.authorize(identity).authorized, false, "and the identity died during the writes");
  assert.equal(
    await inner.read("b.txt"), "new",
    "RESIDUAL: a revocation inside the write loop does NOT stop the remaining writes",
  );
});

test("R36: the precommit hook does NOT fire for a caller who supplies no identity", async () => {
  // Requirement 3. The hook is supplied only alongside an identity, so a caller who passes
  // nothing gets no precommit at all — not a hook that happens to return undefined. Asserted
  // on the effect: ordinary work still commits, unchanged.
  const { executeReversibly } = await import("../src/integrate/reversible_execution.js");
  const { defaultFloorPolicy } = await import("../src/floor/structural_floor.js");
  const { defaultGatePolicy } = await import("../src/gate/composed_gate.js");
  const { defaultBudgetPolicy } = await import("../src/budget/budget_ledger.js");
  const { defaultAcceptanceTest } = await import("../src/ree/reversible_envelope.js");
  const { ensureMediated } = await import("../src/solve/mediated_tree.js");

  const tree = ensureMediated(new InMemoryFileTree({ "a.txt": "old" }));
  const result = await executeReversibly(
    {
      description: { kind: "file.edit", writeSet: ["a.txt"], targets: ["a.txt"], hasInverse: true, raw: "new" },
      apply: async (t) => { await t.write("a.txt", "new"); },
      actionTier: "reversible-internal",
    },
    { floor: defaultFloorPolicy("repo"), gate: defaultGatePolicy(), budget: defaultBudgetPolicy(), acceptance: defaultAcceptanceTest },
    { spine: freshSpine(), actor: "t", operator: "t", sign: (p) => `sig:${p}`, tree, ownerPresent: true, envelopeEnabled: true },
  );

  assert.equal(result.path, "envelope");
  assert.equal(await tree.read("a.txt"), "new", "no identity supplied ⇒ no new refusal path ⇒ unchanged");
});
