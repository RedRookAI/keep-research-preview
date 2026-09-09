/**
 * Flagship demo (Increment 1.3) — the whole spine in ONE runProject call.
 *
 * A single autonomous run carries the full governed chain end-to-end:
 *   feasibility pre-flight → real solve (localize → plan → apply → validate) → deterministic patch verification →
 *   consequence-gated merge authority → a tamper-evident, hash-verifiable trail.
 *
 * Self-contained: an in-memory workspace with a buggy file and a scripted model (the deterministic stand-in for a
 * frontier model — swap `provider` for a real one in production behind the same port). Runnable directly:
 *   node dist/src/demo/flagship.js
 * and asserted programmatically by test/flagship_demo.test.ts.
 */

import { composeKeep } from "../compose.js";
import { InMemoryWorkspace } from "../solve/workspace.js";
import { validatorRunner } from "../solve/default_solver.js";
import { verifyChain } from "../spine/hashchain.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../gateway/gateway.js";
import type { FileTree } from "../solve/patch.js";

const BUGGY = "export function add(a: number, b: number): number {\n  return a - b;\n}\n";
const FIX_PLAN = JSON.stringify({
  rationale: "the operator should be + not -",
  edits: [{ file: "src/math.ts", search: "return a - b;", replace: "return a + b;", intent: "fix the operator" }],
});

/** A deterministic scripted model — the in-env stand-in for a frontier model (same ModelProvider port). */
function scriptedModel(planJson: string): ModelProvider {
  return {
    name: "scripted-demo", isLocal: true,
    async generate(_req: GenerateRequest): Promise<GenerateResult> {
      return { text: planJson, model: "scripted-demo", tokensIn: 0, tokensOut: 0 } as GenerateResult;
    },
    async embed(texts: readonly string[]): Promise<Embedding[]> { return texts.map(() => [0]); },
  };
}

export interface FlagshipDemoResult {
  readonly goal: string;
  readonly feasibility: { readonly deliverability: string; readonly proceed: boolean };
  readonly visited: readonly string[];
  /** The governed merge-authority verdict read FROM the tamper-evident trail (source of truth). */
  readonly governedVerdict: string | undefined;
  readonly sealedEvents: number;
  /** The hash-chain verifies intact. */
  readonly chainOk: boolean;
  /** Tampering with a sealed event is DETECTED (verify flips to false). */
  readonly tamperDetected: boolean;
}

export interface FlagshipDemoOptions {
  /** Swap in a real frontier model for production; default is the deterministic scripted stand-in. */
  readonly provider?: ModelProvider;
  readonly dataDir: string;
  readonly goal?: string;
}

export async function runFlagshipDemo(opts: FlagshipDemoOptions): Promise<FlagshipDemoResult> {
  const goal = opts.goal ?? "fix the add() function so it returns a+b instead of a-b";

  // Compose Keep with the built-in solver over an in-memory repo. A workspace activates autonomy out of the box.
  const app = composeKeep({
    dataDir: opts.dataDir,
    developmentProvider: opts.provider ?? scriptedModel(FIX_PLAN),
    workspace: new InMemoryWorkspace({ "app-repo": { "src/math.ts": BUGGY } }),
    repoRef: "app-repo",
    // Deterministic validation over the patched tree (the sandboxed runner arrives in the isolation increment).
    solverRunnerFor: (_ref: string, tree: FileTree) =>
      validatorRunner(tree, async (t) => (await t.read("src/math.ts"))?.includes("a + b") ?? false),
  });

  // ONE call carries the whole chain.
  const run = await app.autonomyLoop!.runProject(goal, { runId: "flagship", stepBudget: 50 });

  // Commit the trail, then read the governed decision FROM it (the trail is the source of truth).
  await app.spine.seal();
  const events = app.spine.replay();
  const mergeEvt = events.map((e) => e.payload as Record<string, unknown>).find((p) => p?.["event"] === "merge_authority");

  // Tamper-evidence: the intact chain verifies; a mutated event is detected.
  const chainOk = app.spine.verify().ok;
  const blocks = (app.spine as unknown as { store: { readBlocks(): unknown[] } }).store.readBlocks() as Array<{ events: Array<Record<string, unknown>> }>;
  const tampered = blocks.map((b) => ({ ...b, events: b.events.map((e) => ({ ...e, actor: "tampered" })) }));
  const tamperDetected = blocks.length > 0 && verifyChain(tampered as never).ok === false;

  return {
    goal,
    feasibility: { deliverability: run.feasibility?.deliverability ?? "unknown", proceed: run.feasibility?.proceed ?? false },
    visited: run.visited,
    governedVerdict: mergeEvt?.["verdict"] as string | undefined,
    sealedEvents: events.length,
    chainOk,
    tamperDetected,
  };
}

/** Human-readable rendering of the demo result. */
export function formatFlagship(r: FlagshipDemoResult): string {
  const line = "─".repeat(64);
  return [
    line,
    "  KEEP — governed autonomous run (one ticket, end to end)",
    line,
    `  Goal            : ${r.goal}`,
    `  Feasibility     : ${r.feasibility.deliverability} → ${r.feasibility.proceed ? "proceed" : "pause"}`,
    `  Stages visited  : ${r.visited.join(" → ")}`,
    `  Governed verdict: ${r.governedVerdict ?? "(none)"}   ← from the tamper-evident trail`,
    `  Sealed events   : ${r.sealedEvents}`,
    `  Chain verifies  : ${r.chainOk ? "yes ✓" : "NO ✗"}`,
    `  Tamper detected : ${r.tamperDetected ? "yes ✓ (mutating a sealed event fails verification)" : "no"}`,
    line,
  ].join("\n");
}

// Run directly: `node dist/src/demo/flagship.js`
if (import.meta.url === `file://${process.argv[1]}`) {
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const result = await runFlagshipDemo({ dataDir: mkdtempSync(join(tmpdir(), "keep-flagship-")) });
  console.log(formatFlagship(result));
}
