import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { InMemoryWorkspace } from "../src/solve/workspace.js";
import { validatorRunner } from "../src/solve/default_solver.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import type { FileTree } from "../src/solve/patch.js";
import { DEFAULT_SOLVER_IDENTITY_ID } from "../src/identity/agent_identity.js";

/**
 * ROUND 1 (ledger) — IS THE KILL SWITCH REACHABLE THROUGH `composeKeep`, not just the KeepPipeline twin?
 *
 * killswitch_operator_reachable.test.ts proves the switch through a hand-built `new KeepPipeline`. The
 * shipped composition is `composeKeep`, which wires the BUILT-IN solver (buildDefaultSolver) — and until
 * this round passed it an IdentityRegistry, the switch was inert on that path (identityLive undefined).
 * This test goes through `composeKeep(...)` + `runProject` — the wired configured-solve path — supplying
 * nothing but the config an operator gives, and revokes via the exposed `app.identityRegistry`.
 *
 * PROVEN-LIVE (harness A1): the disproof neuters compose's identityRegistry pass-through; the ARMED test
 * then goes RED (the revoked solve proceeds), which is what rules out "measuring the twin again".
 *
 * TARGET: [CONFIGURED] — a workspace + provider are supplied. The zero-config CLI path stays inert (the
 * shipped-entrypoint probe pins that); this arms the path where solving actually happens.
 */

const BUGGY = "export function add(a: number, b: number): number {\n  return a - b;\n}\n";
const CLEAN_PLAN = JSON.stringify({
  rationale: "fix",
  edits: [{ file: "src/math.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" }],
});

function scriptedModel(planJson: string): ModelProvider {
  return {
    name: "s",
    isLocal: true,
    async generate(_r: GenerateRequest): Promise<GenerateResult> {
      return { text: planJson, model: "s", tokensIn: 0, tokensOut: 0 } as GenerateResult;
    },
    async embed(t: readonly string[]): Promise<Embedding[]> {
      return t.map(() => [0]);
    },
  };
}

const passRunner = (_ref: string, tree: FileTree) =>
  validatorRunner(tree, async (t) => (await t.read("src/math.ts"))?.includes("a + b") ?? false);

async function freshApp() {
  const { composeKeep } = await import("../src/compose.js");
  return composeKeep({
    dataDir: mkdtempSync(join(tmpdir(), "keep-ks-")),
    developmentProvider: scriptedModel(CLEAN_PLAN),
    workspace: new InMemoryWorkspace({ "app-repo": { "src/math.ts": BUGGY } }),
    repoRef: "app-repo",
    solverRunnerFor: passRunner,
  });
}

function mergeDecision(app: { spine: { replay(): readonly { payload: unknown }[] } }) {
  return app.spine
    .replay()
    .map((e) => e.payload as Record<string, unknown> | undefined)
    .find((p) => p?.["event"] === "merge_authority");
}

test("KILLSWITCH (composeKeep, CONTROL): an un-revoked configured solve reaches a governed merge decision", async () => {
  const app = await freshApp();
  await app.autonomyLoop!.runProject("fix the add() operator so it returns a+b", { runId: "ks-ctl", stepBudget: 50 });
  await app.spine.seal();
  assert.ok(mergeDecision(app), "an un-revoked solve reaches a governed merge-authority decision (the control)");
});

test("KILLSWITCH (composeKeep, ARMED): tripping the switch HALTS the configured solve — no governed decision", async () => {
  const app = await freshApp();
  app.identityRegistry.kill(DEFAULT_SOLVER_IDENTITY_ID, "operator revoked");
  await app.autonomyLoop!.runProject("fix the add() operator so it returns a+b", { runId: "ks-armed", stepBudget: 50 });
  await app.spine.seal();
  assert.equal(mergeDecision(app), undefined, "a revoked solve path never proposes → no governed merge decision");
});

test("KILLSWITCH (composeKeep, AUDIT): the kill is recorded to the spine an auditor reads", async () => {
  const app = await freshApp();
  app.identityRegistry.kill(DEFAULT_SOLVER_IDENTITY_ID, "operator revoked");
  await app.spine.seal();
  const killed = app.spine
    .replay()
    .map((e) => e.payload as Record<string, unknown> | undefined)
    .some((p) => p?.["event"] === "agent.killed" && p?.["id"] === DEFAULT_SOLVER_IDENTITY_ID);
  assert.ok(killed, "the kill is audited to the spine with the revoked identity id");
});
