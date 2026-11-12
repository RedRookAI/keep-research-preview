/**
 * Typed registry and decision functions used by tools/neuter_engine.mjs for mutation checks.
 *
 * A guard is watched only when its named test ran and failed under the declared mutation. Equivalent
 * mutations are rejected, and the source tree must match its original fingerprint after restoration.
 * Catching one declared fault does not establish a complete specification or inventory of enforcement
 * sites. Method/path reachability and enumeration completeness remain separate concerns.
 * Reference: mutation testing, Hamlet (1977).
 */

/** A single declared safety guard: a real enforcement site, a non-equivalent neuter of it, and the
 *  test that MUST redden when the enforcement is removed. Mirrors the loop's mutation-gate registry. */
export interface Guard {
  /** One-line human name of the safety property. */
  readonly property: string;
  /** Path (under the registry treeRoot) of the file holding the REAL enforcement. */
  readonly file: string;
  /** An EXACT substring of the real enforcement — must occur EXACTLY ONCE (a precise, unambiguous anchor). */
  readonly find: string;
  /** The same site NEUTERED: a NON-EQUIVALENT, still-compiling mutation that removes the enforcement. */
  readonly replace: string;
  /** Path (under treeRoot) of the test file that guards the property. */
  readonly guardingTest: string;
  /** The exact test() title that MUST go red when the enforcement is neutered. */
  readonly guardingTestName: string;
  /** Advisory classification; not load-bearing to the engine. */
  readonly kind?: "behavior" | "completeness";
}

/** The machine-readable registry a round emits: the tree to operate on and the guards to prove. */
export interface GuardRegistry {
  /** Absolute path to the directory tree the guards live in (the fingerprint + mutation root). */
  readonly treeRoot: string;
  /** The declared guards. Empty ONLY when noEnforcement is true. */
  readonly guards: readonly Guard[];
  /** Optional shell command run (in treeRoot) to rebuild artifacts after each mutation; absent for
   *  source-runnable trees (plain JS/mjs) — a compiled project sets e.g. "npx tsc -p tsconfig.json". */
  readonly build?: string;
  /** A round that genuinely enforces NO new safety property declares this true with an empty guards[]. */
  readonly noEnforcement?: boolean;
}

/** WATCHED classification — the outcome of neutering one guard's real enforcement. */
export type WatchVerdict = "WATCHED" | "NOT-WATCHED" | "DID-NOT-RUN";

/**
 * DECISION (1). A guard is WATCHED iff its named guarding test actually RAN and went RED under the
 * mutation. `named` = the named test was found and executed; `testReddened` = that specific test
 * failed. A test that ran and STAYED GREEN is NOT-WATCHED — the enforcement can be removed and nothing
 * notices, which is the exact overclaim class the whole gate exists to catch. A test that never ran
 * cannot testify either way, so it is DID-NOT-RUN (a wrong test name/file), never a silent pass.
 */
export function classifyWatched(named: boolean, testReddened: boolean): WatchVerdict {
  if (!named) return "DID-NOT-RUN";
  return testReddened ? "WATCHED" : "NOT-WATCHED";
}

/** Strip comments and ALL whitespace so two syntactically-equal snippets normalize identically —
 *  the mechanical proxy for "the compiler cannot tell these apart, so no test can observe the swap". */
function normalizeSource(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, " ") // block comments carry no behavior
    .replace(/\/\/[^\n]*/g, " ") // line comments carry no behavior
    .replace(/\s+/g, ""); // whitespace between tokens carries no behavior
}

/**
 * DECISION (2). NON-EQUIVALENCE by construction. A mutation is observable only if it changes the
 * program's TOKENS, not just its formatting. A find/replace that differs only in whitespace or
 * comments is an EQUIVALENT mutant — the guarding test could pass or fail identically either way, so a
 * green result proves nothing and a red result would be noise. Such a mutation is rejected up front so
 * it can never be counted as evidence a guard is watched.
 */
export function isNonEquivalent(find: string, replace: string): boolean {
  if (find === replace) return false; // textually identical — no mutation at all
  return normalizeSource(find) !== normalizeSource(replace);
}

/**
 * DECISION (3). RESTORE VERIFICATION, fail-closed. After a neuter the tree must fingerprint EXACTLY as
 * it did before (src/spine/tree_fingerprint.ts is the oracle). Any drift means a mutation leaked onto
 * disk — the engine must never leave a mutated tree behind, so this THROWS rather than return a flag a
 * caller might ignore. `before`/`after` are two `sha256:` tree fingerprints.
 */
export function assertTreeRestored(before: string, after: string): void {
  if (before !== after) {
    throw new Error(
      `neuter_engine: tree NOT restored — fingerprint ${before} != ${after} (a mutation leaked to disk; fail-closed)`,
    );
  }
}

/** How many times `find` occurs in `source`. The engine requires EXACTLY 1: 0 = stale/wrong anchor,
 *  >1 = ambiguous (the engine might neuter the wrong occurrence). Kept here so the count is one notion. */
export function anchorOccurrences(source: string, find: string): number {
  if (find === "") return 0;
  return source.split(find).length - 1;
}

/** A per-guard structural check the engine runs before it dares mutate a real file. Returns a reason
 *  string when the guard is unusable, or null when it is well-formed. */
export function guardDefect(g: Guard, fileExists: boolean): string | null {
  if (!g.file || !g.find || g.replace === undefined || !g.guardingTest || !g.guardingTestName) {
    return "malformed: need file/find/replace/guardingTest/guardingTestName";
  }
  if (!fileExists) return `enforcement file ${g.file} does not exist`;
  return null;
}
