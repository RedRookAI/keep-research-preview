/**
 * Path-scope predicate — the ONE place a path is tested against an allowed region.
 *
 * WHY THIS MODULE EXISTS (round 38). Two separate mechanisms needed the same question
 * answered: the identity model's `inScope` (agent scope, added round 30, canonicalised round
 * 37) and the structural floor's write-set allowlist (added this round). Writing the second
 * one would have produced two path-authority mechanisms that could disagree — the R14 shape,
 * which this project has already paid for once, and which round 37 explicitly refused to
 * create in the other direction. So the predicate moved here and both call it.
 *
 * CANONICALISE, THEN COMPARE — the order is the control, not a filter (round 37). An
 * authorization layer that prefix-matches a raw path while the layer beneath it resolves that
 * path is the standard traversal auth-bypass, with 2026 CVEs across mainstream gateways. The
 * remedy the advisories prescribe is exactly this: "canonicalization followed by a prefix
 * check is the pattern that holds against all bypass techniques."
 *
 * Purely lexical — no filesystem access, so it is zero-dep, deterministic, and cannot itself
 * be raced by a symlink swap between check and use.
 */

import { posix as posixPath } from "node:path";

/**
 * ROUND 39 — the ENTIRE supported glob surface, and it is deliberately this small.
 *
 * Supported: a pattern with NO slash that contains `*`, matched against the basename at any
 * depth (`*.md`, `*.json`, `Makefile*`). Plus the bare `*`, which admits everything.
 *
 * NOT supported: `**`, negation (`!`), character classes, and any `*` in a pattern that also
 * contains a slash (`src/*.ts`, `src/**​/*.ts`). Those are not silently ignored — they are
 * reported by `unsupportedScopePatterns` so the operator is told, rather than watching a scope
 * mysteriously refuse everything.
 *
 * WHY SO SMALL. The dialect research is unambiguous that partial glob support is the footgun:
 * "some treat `*` as matching directory separators while others don't. Doublestar `**` is
 * supported by most but not all", and negation has a notorious trap where "it is not possible
 * to re-include a file if a parent directory of that file is excluded." A half-implemented
 * glob is worse than none, because operators assume the missing half works. The response is a
 * surface small enough to state in one sentence and a loud error for everything else.
 */
function isBasenameGlob(pattern: string): boolean {
  return !pattern.includes("/") && pattern.includes("*");
}

/** `*` matches any run of characters within a single path segment. No other metacharacter. */
function globMatchesSegment(pattern: string, segment: string): boolean {
  const rx = pattern
    .split("*")
    .map((lit) => lit.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("[^/]*");
  return new RegExp(`^${rx}$`).test(segment);
}

/**
 * Scope entries this implementation does NOT support, so a caller can refuse loudly instead of
 * behaving mysteriously. An unsupported pattern is the operator's bug, and telling them is the
 * whole difference between a control they fix and a control they abandon (Z135).
 */
export function unsupportedScopePatterns(scope: readonly string[]): string[] {
  return scope.filter((s) => s !== "*" && s.includes("*") && s.includes("/"));
}

/** Resolve `.` and `..` lexically and drop a trailing slash, so comparisons are like-for-like. */
export function canonicalPath(p: string): string {
  const n = posixPath.normalize(p);
  return n.length > 1 && n.endsWith("/") ? n.slice(0, -1) : n;
}

/**
 * Is `path` inside one of `scope`'s allowed regions?
 *
 * `"*"` admits anything **inside the root**; a path that resolves above the root is refused
 * before the scope loop, so no entry — not even a wildcard — can re-admit it.
 *
 * An EMPTY scope admits nothing. That is the fail-safe direction and it is deliberate: a
 * caller that means "unconstrained" must say so with `["*"]` rather than by omission.
 */
export function withinScope(scope: readonly string[], path: string): boolean {
  const p = canonicalPath(path);
  if (p === ".." || p.startsWith("../")) return false;
  return scope.some((raw) => {
    if (raw === "*") return true;
    // ROUND 39 — a SLASHLESS pattern containing `*` matches the BASENAME at any depth.
    // This is gitignore's own rule ("if the pattern does not contain a slash, git treats it as
    // a shell glob pattern and checks for a match against the pathname relative to any level"),
    // chosen deliberately over a root-only reading: the research on ignore-file dialects is that
    // "differences bite users when they assume full compatibility", so where a behaviour is
    // implemented at all it should be the one operators already expect.
    if (isBasenameGlob(raw)) return globMatchesSegment(raw, p.slice(p.lastIndexOf("/") + 1));
    const prefix = canonicalPath(raw);
    // ROUND 39 — `.` (and `""`, which canonicalises to `.`) is the repo root, so it admits
    // everything inside it. Found by the adversarial scope sweep: `["."]` is an obvious way to
    // write "the whole project", and it previously admitted NOTHING, because no canonical path
    // begins with `./`. Fail-safe, so it would have been noticed — but a control that refuses
    // everything when told "the root" is a control the operator deletes.
    if (prefix === ".") return true;
    return p === prefix || p.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`);
  });
}
