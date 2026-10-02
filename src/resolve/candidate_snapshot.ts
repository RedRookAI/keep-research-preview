import { createHash } from "node:crypto";
import { types } from "node:util";
import type { SolveResult } from "../solve/issue_model.js";
import { inheritCanonicalAdmittedSolveResult } from "../solve/solve_pipeline.js";

/**
 * Own inert extension output before checking it. Readonly TypeScript types do not
 * prevent mutation through a sampler/cleanup/generator/executor/verifier/meter's retained alias.
 * This copies ordinary data (including optional undefined fields), never getters,
 * functions, class instances or shared mutable buffers. No caller object is frozen.
 */
export function captureCandidateData<T>(input: T): T {
  const path = new Set<object>(); let nodes = 0, textBytes = 0;
  const copy = (value: unknown, depth: number): unknown => {
    if (++nodes > 100_000 || depth > 64) throw new Error("candidate data exceeds structural limits");
    if (value === null || value === undefined || typeof value === "boolean") return value;
    if (typeof value === "string") {
      textBytes += Buffer.byteLength(value);
      if (textBytes > 16 * 1024 * 1024) throw new Error("candidate data exceeds text limit");
      return value;
    }
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value !== "object" || types.isProxy(value)) throw new Error("candidate data must be inert plain data");
    const array = Array.isArray(value), proto = Object.getPrototypeOf(value);
    if (array ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) throw new Error("candidate data must be inert plain data");
    if (path.has(value)) throw new Error("candidate data contains a cycle");
    if (Object.getOwnPropertySymbols(value).length) throw new Error("candidate data contains a symbol property");
    path.add(value);
    const out: Record<string, unknown> | unknown[] = array ? [] : {};
    const keys = Object.getOwnPropertyNames(value).filter(k => !array || k !== "length").sort();
    if (array && (keys.length !== value.length || keys.some(k => !/^(0|[1-9]\d*)$/.test(k) || Number(k) >= value.length))) throw new Error("candidate data requires dense plain arrays");
    for (const key of keys) {
      const property = Object.getOwnPropertyDescriptor(value, key)!;
      if (!("value" in property) || !property.enumerable) throw new Error("candidate data cannot contain accessors or hidden properties");
      Object.defineProperty(out, key, { value: copy(property.value, depth + 1), enumerable: true, writable: true, configurable: true });
    }
    path.delete(value);
    return Object.freeze(out);
  };
  return copy(input, 0) as T;
}

/** Identity of the inert JSON representation; absent and undefined optional fields are equivalent. */
export function candidateDataSha256(input: unknown): string {
  const json = JSON.stringify(captureCandidateData(input));
  if (json === undefined) throw new Error("candidate identity requires a JSON value");
  return createHash("sha256").update("keep.candidate-json/v1\0").update(json).digest("hex");
}

/** Preserve an existing canonical attestation only across this exact owned copy. */
export function captureSolveResult(input: SolveResult): SolveResult {
  return inheritCanonicalAdmittedSolveResult(input, captureCandidateData(input));
}

/** Cleanup is awaited; a cleanup error must not erase the original failure. */
export async function withCandidateCleanup<T>(work: () => Promise<T>, cleanup: () => void | Promise<void>): Promise<T> {
  let failed = false, primary: unknown, value: T | undefined;
  try { value = await work(); } catch (error) { failed = true; primary = error; }
  try { await cleanup(); } catch (error) {
    if (failed) throw new AggregateError([primary, error], "candidate operation and cleanup failed", { cause: primary });
    throw error;
  }
  if (failed) throw primary;
  return value as T;
}
