/**
 * guard_registry.ts — the TYPED contract + the three pure DECISIONS a neuter engine composes.
 *
 * WHY THIS EXISTS (BUILD-ORDER 8.7 — dogfood of redrook-ops/mutation-gate.mjs). The loop that BUILDS
 * Keep ships a mechanical "mutation gate": it applies a declared NON-EQUIVALENT mutation to a real
 * safety-enforcement site, re-runs the test that supposedly guards it, and FAILS if the test SURVIVES
 * (stays green) — because a test no fault can fail is not a test (Hamlet 1977). Keep, the PRODUCT, owes
 * a self-hosting user the SAME capability: prove THEIR safety guards are load-bearing, not decoration.
 * tools/neuter_engine.mjs is that engine; THIS module is the typed registry it reads plus the three
 * decision functions it composes — kept here, in src, so each decision is independently unit-tested AND
 * independently neuter-verifiable (the mutation gate proves each one load-bearing by removing it).
 *
 * THREE DECISIONS, each a distinct code path so a neuter of one cannot be mistaken for a neuter of
 * another (the isolation the whole method depends on):
 *   (1) WATCHED classification  — a guard is WATCHED iff its named test actually RAN and went RED under
 *                                 the mutation; a mutation that reddens no test is NOT-WATCHED (the
 *                                 not-load-bearing guard — a safety property silently rotted to décor).
 *   (2) NON-EQUIVALENCE         — a mutation the guarding test could not possibly observe (a
 *                                 whitespace/comment-only edit — the "equivalent mutant" of mutation
 *                                 testing) proves NOTHING; it is REJECTED, never counted as watched.
 *   (3) RESTORE VERIFICATION    — after each neuter the tree MUST be byte-identical again; the engine
 *                                 proves it with src/spine/tree_fingerprint.ts and this fail-closed
 *                                 assertion. Leaving a mutated tree on a crash is the cardinal defect.
 *
 * HONEST LIMIT. Being WATCHED proves a guard's test CATCHES this one declared fault — not that the
 * property is fully specified, and NOT that every enforcement site is enumerated. Enumeration
 * completeness over all effectful entry points is a SEPARATE concern (the method/path reachability
 * gate); this module does not claim it.
 *
 * ZERO-DEP, PURE. No I/O, no dependency — just types and total functions, so the tests pin the
 * decisions directly and the engine is a thin driver over them.
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
