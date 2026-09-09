/**
 * reachability_port.ts — Keep's thin, typescript-FREE seam onto the compiler-graph island sweep.
 *
 * WHY A PORT (BUILD-ORDER 8.4). The real reachability engine (tools/island_sweep.mjs) consumes the
 * `typescript` devDep to build a `ts.TypeChecker` program graph. typescript must NEVER be imported
 * from src/, or the shipped product would carry a runtime dependency. So the ts-consuming engine lives
 * in tools/ (build-time) and the product reaches it through THIS port, which speaks only node builtins
 * (child_process + path). src stays zero-runtime-dependency; the product still owns the capability.
 *
 * FAIL-CLOSED IS THE POINT. The cardinal defect in a reachability gate is FAIL-OPEN: a crashed sweep
 * whose empty output reads as "0 islands, all clear". So this port refuses to return a result unless
 * the engine EXITED 0 and stamped its success sentinel. A crash, a non-zero exit, unparseable output,
 * or a missing sentinel THROWS — the caller can never mistake a dead detector for a clean tree.
 *
 * HONEST SEAM. The engine labels dynamic import() / side-effect imports / DI registration
 * NEEDS-A-HUMAN-LOOK; this port surfaces that class verbatim and never collapses it into ISLAND or
 * RUNTIME-REACHABLE.
 */
import { execFileSync } from "node:child_process";
import { join } from "node:path";

/** The success sentinel the engine stamps into its JSON. Trust nothing that lacks it. */
export const ISLAND_SWEEP_SENTINEL = "ISLAND-SWEEP-OK";

export type ModuleClass =
  | "RUNTIME-REACHABLE"
  | "TYPE-ONLY-ISLAND"
  | "TYPES-ONLY-MODULE"
  | "NEEDS-A-HUMAN-LOOK"
  | "UNREFERENCED";

export interface SweepResult {
  scanned: number;
  roots: string[];
  islands: string[];
  needsHumanLook: string[];
  unreferenced: string[];
  runtimeReachable: string[];
  classes: Record<string, ModuleClass>;
}

export interface SweepOptions {
  /** Directory whose .ts modules form the graph. */
  root: string;
  /** Entry modules the two-color sweep marks reachability from. */
  entries: string[];
  /** Path to island_sweep.mjs. Defaults to tools/island_sweep.mjs under the current working dir. */
  enginePath?: string;
}

function defaultEnginePath(): string {
  return join(process.cwd(), "tools", "island_sweep.mjs");
}

/**
 * Run the compiler-graph sweep and return its classification — or THROW (fail-closed) if the engine
 * did not complete cleanly. A returned result is therefore always a result the engine actually
 * produced, never an empty stand-in for a crash.
 */
export function sweepIslands(opts: SweepOptions): SweepResult {
  const engine = opts.enginePath ?? defaultEnginePath();
  const args = [engine, "--root", opts.root, "--json"];
  for (const e of opts.entries) args.push("--entry", e);

  let stdout: string;
  try {
    stdout = execFileSync(process.execPath, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    // Non-zero exit / spawn failure / crash. FAIL CLOSED — never read a crash as "0 islands".
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(`island sweep did not run cleanly (fail-closed; a crashed sweep must never certify by silence): ${detail}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("island sweep produced unparseable output (fail-closed)");
  }

  const p = parsed as Partial<SweepResult> & { ok?: unknown; sentinel?: unknown };
  if (p.ok !== true || p.sentinel !== ISLAND_SWEEP_SENTINEL) {
    throw new Error("island sweep did not emit its success sentinel (fail-closed; the sweep may have aborted)");
  }

  return {
    scanned: p.scanned ?? 0,
    roots: p.roots ?? [],
    islands: p.islands ?? [],
    needsHumanLook: p.needsHumanLook ?? [],
    unreferenced: p.unreferenced ?? [],
    runtimeReachable: p.runtimeReachable ?? [],
    classes: (p.classes ?? {}) as Record<string, ModuleClass>,
  };
}

export interface RegressionResult {
  regressed: boolean;
  currentCount: number;
  baselineCount: number;
  delta: number;
}

/**
 * The gate's baseline-delta test. A NEW type-only island (count risen above the committed baseline)
 * is the real regression signal — a runtime wire silently degraded to `import type`-only. A count at
 * or below baseline is not a regression: verdicts are CANDIDATES, and the committed baseline is the
 * agreed set of known/accepted islands.
 */
export function islandRegression(currentIslands: string[], baselineCount: number): RegressionResult {
  const currentCount = currentIslands.length;
  return {
    regressed: currentCount > baselineCount,
    currentCount,
    baselineCount,
    delta: currentCount - baselineCount,
  };
}
