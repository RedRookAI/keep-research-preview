/**
 * effect_scan_port.ts — the typescript-FREE seam onto the closed-world EFFECT scan (Increment 4). Mirrors
 * ingress_scan_port: speaks only node builtins, and refuses any result unless the engine exited 0 with its sentinel
 * (fail-closed — a crashed scan can never be mistaken for "no unowned effects").
 */
import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { join } from "node:path";
import type { EffectFamily } from "./effect.js";

export const EFFECT_SWEEP_SENTINEL = "EFFECT-SWEEP-OK";

/** One use of an effect family's host primitive in a file that is NOT that family's declared owner. */
export interface EffectFinding { readonly file: string; readonly line: number; readonly family: string; readonly construct: string; }
export interface EffectScanResult { readonly scanned: number; readonly owners: readonly { readonly family: string; readonly owner: string }[]; readonly findings: readonly EffectFinding[]; readonly graphDigest: string; }

export interface EffectScanOptions {
  readonly root: string;
  /** family -> repo-relative (posix) owner path. A family with no owner => any use is unowned. */
  readonly owners?: ReadonlyMap<EffectFamily | string, string>;
  readonly enginePath?: string;
}

function defaultEnginePath(): string { return join(process.cwd(), "tools", "effect_sweep.mjs"); }

export function scanEffects(opts: EffectScanOptions): EffectScanResult {
  let stdout: string;
  try {
    const engine = realpathSync(opts.enginePath ?? defaultEnginePath());
    const args = [engine, "--root", opts.root, "--json"];
    for (const [family, owner] of opts.owners ?? new Map()) args.push("--owner", `${family}=${owner}`);
    // HERMETIC child environment: do not inherit dynamic-loader, interpreter, package-manager, locale, proxy, or path
    // variables. The executable/engine are absolute and the scanner needs no ambient configuration. Windows alone needs
    // its OS directory for native DLL resolution; copy those two values by exact allowlist.
    const env: NodeJS.ProcessEnv = {};
    if (process.platform === "win32") for (const key of ["SystemRoot", "WINDIR"] as const) if (process.env[key] !== undefined) env[key] = process.env[key];
    stdout = execFileSync(realpathSync(process.execPath), ["--disable-proto=throw", ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env });
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(`effect sweep did not run cleanly (fail-closed): ${detail}`);
  }

  let parsed: unknown;
  try { parsed = JSON.parse(stdout); } catch { throw new Error("effect sweep produced unparseable output (fail-closed)"); }
  const p = parsed as Record<string, unknown>;
  if (p === null || typeof p !== "object" || p.ok !== true || p.sentinel !== EFFECT_SWEEP_SENTINEL) throw new Error("effect sweep did not emit its success sentinel (fail-closed)");
  if (typeof p.scanned !== "number" || !Array.isArray(p.owners) || !Array.isArray(p.findings) || typeof p.graphDigest !== "string" || !/^[0-9a-f]{64}$/.test(p.graphDigest)) throw new Error("effect sweep result is malformed (fail-closed)");
  const findings: EffectFinding[] = p.findings.map((f) => {
    if (f === null || typeof f !== "object") throw new Error("effect finding is malformed (fail-closed)");
    const fo = f as Record<string, unknown>;
    if (typeof fo.file !== "string" || typeof fo.line !== "number" || typeof fo.family !== "string" || typeof fo.construct !== "string") throw new Error("effect finding is malformed (fail-closed)");
    return { file: fo.file, line: fo.line, family: fo.family, construct: fo.construct };
  });
  const owners = p.owners.map((o) => {
    const oo = o as Record<string, unknown>;
    if (typeof oo.family !== "string" || typeof oo.owner !== "string") throw new Error("effect owner entry malformed (fail-closed)");
    return { family: oo.family, owner: oo.owner };
  });
  return { scanned: p.scanned, owners, findings, graphDigest: p.graphDigest };
}

/** Assert every effect is owned: no family primitive is used outside its declared owner. Throws listing violations. */
export function assertOwnedEffects(result: EffectScanResult): void {
  if (result.findings.length === 0) return;
  const lines = result.findings.map((f) => `  ${f.file}:${f.line} — ${f.family} (${f.construct})`).join("\n");
  throw new Error(`unowned effect callsite(s): ${result.findings.length} use(s) of an effect family outside its declared owner:\n${lines}\n(move the effect behind its family's broker owner, or declare the owner in the effect manifest)`);
}
