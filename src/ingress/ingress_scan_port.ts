/**
 * ingress_scan_port.ts — Keep's typescript-FREE seam onto the closed-world ingress scan (Increment 3, static closure).
 *
 * WHY A PORT. The scan engine (tools/ingress_sweep.mjs) consumes the `typescript` devDep to parse a real AST; that
 * must never be imported from src/, or the shipped product would carry a build dependency. So the engine lives in
 * tools/ (build-time) and the product reaches it through THIS port, which speaks only node builtins.
 *
 * FAIL-CLOSED. The cardinal defect is a crashed scan read as "0 findings, all clear". This port refuses any result
 * unless the engine EXITED 0 and stamped its success sentinel; a crash, non-zero exit, unparseable output, or missing
 * sentinel THROWS — a dead detector can never be mistaken for a closed world.
 */
import { execFileSync } from "node:child_process";
import { join } from "node:path";

/** The success sentinel the engine stamps. Trust nothing that lacks it. */
export const INGRESS_SWEEP_SENTINEL = "INGRESS-SWEEP-OK";

/** One forbidden ambient-authority construct found in a non-allowlisted module. */
export interface IngressFinding { readonly file: string; readonly line: number; readonly construct: string; }
export interface IngressScanResult { readonly scanned: number; readonly allow: readonly string[]; readonly findings: readonly IngressFinding[]; }

export interface IngressScanOptions {
  /** Directory whose .ts modules are scanned. */
  readonly root: string;
  /** Repo-relative (posix) paths of the approved adapter modules that may hold ambient authority. */
  readonly allow?: readonly string[];
  /** Path to ingress_sweep.mjs. Defaults to tools/ingress_sweep.mjs under the cwd. */
  readonly enginePath?: string;
}

function defaultEnginePath(): string { return join(process.cwd(), "tools", "ingress_sweep.mjs"); }

/**
 * Run the closed-world ingress scan and return its findings — or THROW (fail-closed) if the engine did not complete
 * cleanly. A returned result is always one the engine actually produced, never an empty stand-in for a crash.
 */
export function scanIngress(opts: IngressScanOptions): IngressScanResult {
  const engine = opts.enginePath ?? defaultEnginePath();
  const args = [engine, "--root", opts.root, "--json"];
  for (const a of opts.allow ?? []) args.push("--allow", a);

  let stdout: string;
  try {
    stdout = execFileSync(process.execPath, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(`ingress sweep did not run cleanly (fail-closed; a crashed scan must never certify by silence): ${detail}`);
  }

  let parsed: unknown;
  try { parsed = JSON.parse(stdout); } catch { throw new Error("ingress sweep produced unparseable output (fail-closed)"); }

  const p = parsed as Record<string, unknown>;
  if (p === null || typeof p !== "object" || p.ok !== true || p.sentinel !== INGRESS_SWEEP_SENTINEL) {
    throw new Error("ingress sweep did not emit its success sentinel (fail-closed; the scan may have aborted)");
  }
  // Strictly validate the result schema — a success-stamped but incomplete/malformed result must NOT certify clear.
  if (typeof p.scanned !== "number" || !Array.isArray(p.allow) || !Array.isArray(p.findings)) {
    throw new Error("ingress sweep result is malformed (fail-closed)");
  }
  for (const a of p.allow) if (typeof a !== "string") throw new Error("ingress sweep allow[] is malformed (fail-closed)");
  const findings: IngressFinding[] = p.findings.map((f) => {
    if (f === null || typeof f !== "object") throw new Error("ingress sweep finding is malformed (fail-closed)");
    const fo = f as Record<string, unknown>;
    if (typeof fo.file !== "string" || typeof fo.line !== "number" || typeof fo.construct !== "string") throw new Error("ingress sweep finding is malformed (fail-closed)");
    return { file: fo.file, line: fo.line, construct: fo.construct };
  });
  return { scanned: p.scanned, allow: p.allow as string[], findings };
}

/**
 * Assert the world is closed: no forbidden ambient-authority construct exists outside the approved adapters. Throws a
 * detailed error listing the violations. This is the build/CI gate's fail-closed assertion.
 */
export function assertClosedWorld(result: IngressScanResult): void {
  if (result.findings.length === 0) return;
  const lines = result.findings.map((f) => `  ${f.file}:${f.line} — ${f.construct}`).join("\n");
  throw new Error(`closed-world ingress violation: ${result.findings.length} forbidden construct(s) outside approved adapters:\n${lines}\n(declare the entrypoint in the ingress manifest via an approved adapter, or remove the construct)`);
}
