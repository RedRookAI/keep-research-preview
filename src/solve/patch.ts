/**
 * SolvePipeline: the search/replace patch engine (Increment 13a).
 *
 * SOTA basis (2026-08-05): search/replace edits (find an exact block → replace) are the reliable edit
 * format used by the strongest Agentless-derived scaffolds (SWE-RL, SWE-Fixer). Unlike unified-diff
 * line numbers — the #1 patch-application failure mode — an exact-match edit either applies cleanly or
 * is rejected; it never silently applies to the wrong place. This engine enforces that: each edit must
 * match its search block EXACTLY and UNIQUELY, or it is reported not-found / ambiguous and NOT applied.
 *
 * Edits go against a real working tree (an injected FileTree port — a real filesystem on Hetzner, an
 * in-memory tree in tests). Every applied plan is one reversible RollbackLedger action whose undo
 * restores the exact original file contents. Zero deps.
 */

import type { RollbackLedger } from "../control/rollback.js";
import { runMediatedWith, WriteGrant } from "./mediated_tree.js";
import type { EditPlan, PatchApplyResult, SearchReplaceEdit } from "./issue_model.js";

/** The working-tree port: read/write files. Real fs on Hetzner; in-memory in tests. */
export interface FileTree {
  read(path: string): Promise<string | undefined>;
  write(path: string, content: string): Promise<void>;
  /** Atomic compare-and-swap batch for content-bound project commits. */
  commitBatchIfUnchanged?(expected: Readonly<Record<string, string>>, writes: readonly { readonly path: string; readonly content: string }[]): Promise<boolean>;
}

/** An in-memory FileTree for tests + deterministic runs here. */
export class InMemoryFileTree implements FileTree {
  private readonly files: Map<string, string>;
  constructor(initial: Record<string, string> = {}) {
    this.files = new Map(Object.entries(initial));
  }
  async read(path: string): Promise<string | undefined> { return this.files.get(path); }
  async write(path: string, content: string): Promise<void> { this.files.set(path, content); }
  async commitBatchIfUnchanged(expected: Readonly<Record<string, string>>, writes: readonly { readonly path: string; readonly content: string }[]): Promise<boolean> {
    for (const [path, content] of Object.entries(expected)) if (this.files.get(path) !== content) return false;
    for (const write of writes) this.files.set(write.path, write.content);
    return true;
  }
  /** Test helper: snapshot current contents. */
  snapshot(): Record<string, string> { return Object.fromEntries(this.files); }
}

/** Count non-overlapping occurrences of needle in haystack. */
function countOccurrences(haystack: string, needle: string): number {
  if (needle === "") return 0;
  let count = 0, idx = 0;
  for (;;) {
    const found = haystack.indexOf(needle, idx);
    if (found === -1) break;
    count++;
    idx = found + needle.length;
  }
  return count;
}

/**
 * Whitespace-tolerant match (SOTA hardening — CodeStruct 2026: whitespace sensitivity is the #1
 * string-replacement failure; Hermes-agent #32273 ships indent-aware fuzzy fallback). Finds a UNIQUE
 * region of the file that equals `search` after normalizing each line's leading whitespace and
 * trailing whitespace. Returns the exact original substring to replace + the indent delta to apply to
 * the replacement, or null if there is no match or the match is ambiguous. NEVER guesses: ambiguity or
 * absence → null (the caller keeps the never-wrong-apply guarantee).
 */
export interface FuzzyMatch {
  /** The exact original text in the file that the fuzzy search matched (to be replaced). */
  readonly matched: string;
  /** Leading-whitespace of the file region's first line (to re-indent the replacement). */
  readonly fileIndent: string;
  /** Leading-whitespace of the search block's first line (the model's indent base). */
  readonly searchIndent: string;
}

function leadingWs(line: string): string {
  const m = line.match(/^[ \t]*/);
  return m ? m[0] : "";
}
function normalizeLine(line: string): string {
  return line.replace(/^[ \t]+/, "").replace(/[ \t]+$/, "");
}
function normalizeBlock(block: string): string {
  return block.split("\n").map(normalizeLine).join("\n");
}

/** Find a unique whitespace-insensitive match of `search` within `content`. */
export function fuzzyFind(content: string, search: string): FuzzyMatch | null {
  const contentLines = content.split("\n");
  const searchLines = search.split("\n");
  const normSearch = searchLines.map(normalizeLine).join("\n");
  if (normSearch.trim() === "") return null;

  const matches: { start: number; end: number }[] = [];
  for (let i = 0; i + searchLines.length <= contentLines.length; i++) {
    const window = contentLines.slice(i, i + searchLines.length);
    if (window.map(normalizeLine).join("\n") === normSearch) {
      matches.push({ start: i, end: i + searchLines.length });
    }
  }
  if (matches.length !== 1) return null; // absent or ambiguous → refuse (never guess)

  const { start, end } = matches[0]!;
  const matched = contentLines.slice(start, end).join("\n");
  const firstFileLine = contentLines[start] ?? "";
  const firstSearchLine = searchLines[0] ?? "";
  return { matched, fileIndent: leadingWs(firstFileLine), searchIndent: leadingWs(firstSearchLine) };
}

/**
 * Re-indent a replacement block so its base indentation matches the file region it replaces. Shifts
 * every line by the (fileIndent - searchIndent) delta, so a model that emitted zero-indent code for a
 * method body that actually lives inside an 8-space class still lands correctly (Hermes-agent #32273).
 */
export function reindent(replace: string, fileIndent: string, searchIndent: string): string {
  if (fileIndent === searchIndent) return replace;
  const lines = replace.split("\n");
  return lines
    .map((line) => {
      if (line.trim() === "") return line; // leave blank lines alone
      const ws = leadingWs(line);
      // Strip the model's indent base, apply the file's indent base.
      const withoutSearchBase = ws.startsWith(searchIndent) ? ws.slice(searchIndent.length) : ws;
      return fileIndent + withoutSearchBase + line.slice(ws.length);
    })
    .join("\n");
}

/**
 * Apply an edit plan to the working tree. Each edit's search block must match EXACTLY and exactly
 * ONCE in its file, or that edit is rejected (not-found / ambiguous) and the whole plan is not
 * applied (all-or-nothing — a half-applied patch is worse than none). On success, registers ONE
 * reversible action in the ledger whose undo restores every touched file's original content.
 */
/**
 * R14 (round 33) — THE SHARED MATCH-OR-REFUSE SEAM.
 *
 * Extracted from `applyEditPlan` so the envelope path and the direct path cannot drift
 * apart again. They HAD drifted: the envelope's closure ran
 * `if (cur.includes(search)) write(cur.replace(search, replace))`, and
 * `String.prototype.replace` with a string pattern replaces only the FIRST occurrence,
 * silently — so the envelope applied edits this function REFUSES.
 *
 * Two apply semantics was the bug; a third would have been worse. One seam, two commit
 * strategies: `applyEditPlan` commits through mediation + the rollback ledger, while the
 * envelope writes the resolved content to its fork (an unmediated staging tree the
 * envelope itself rolls back).
 *
 * Refusal, not disambiguation — and that follows the established tool rather than taste:
 * "git apply by default will refuse to create ambiguous hunks", it "fails the whole patch
 * and does not touch the working tree" when a hunk does not apply, and "there is no
 * guaranteed safe way of dealing with fuzzy patches".
 *
 * ALL-OR-NOTHING: returns on the first unresolvable edit having written nothing.
 */
export async function resolveEditPlan(
  plan: EditPlan,
  tree: FileTree,
  opts: { fuzzyFallback?: boolean } = {},
): Promise<{
  ok: boolean;
  perEdit: { file: string; status: "applied" | "not-found" | "ambiguous" | "held"; reason?: string }[];
  nextContent: Map<string, string>;
  originals: Map<string, string>;
}> {
  const perEdit: { file: string; status: "applied" | "not-found" | "ambiguous" | "held"; reason?: string }[] = [];
  const originals = new Map<string, string>();
  const nextContent = new Map<string, string>();

  // Validate every edit against current (or in-progress) content first — all-or-nothing.
  for (const edit of plan.edits) {
    const current = nextContent.get(edit.file) ?? (await tree.read(edit.file));
    if (current === undefined) {
      perEdit.push({ file: edit.file, status: "not-found", reason: "file does not exist" });
      return { ok: false, perEdit, nextContent, originals };
    }
    if (!originals.has(edit.file)) originals.set(edit.file, current);
    const occ = countOccurrences(current, edit.search);
    if (occ === 1) {
      nextContent.set(edit.file, current.replace(edit.search, edit.replace));
      perEdit.push({ file: edit.file, status: "applied" });
      continue;
    }
    if (occ > 1) {
      perEdit.push({ file: edit.file, status: "ambiguous", reason: `search block matches ${occ}× — must be unique` });
      return { ok: false, perEdit, nextContent, originals };
    }
    // occ === 0: exact match failed. Optionally try the whitespace-tolerant fallback (still unique-or-refuse).
    if (opts.fuzzyFallback) {
      const fuzzy = fuzzyFind(current, edit.search);
      if (fuzzy) {
        const reindented = reindent(edit.replace, fuzzy.fileIndent, fuzzy.searchIndent);
        nextContent.set(edit.file, current.replace(fuzzy.matched, reindented));
        perEdit.push({ file: edit.file, status: "applied" });
        continue;
      }
    }
    perEdit.push({ file: edit.file, status: "not-found", reason: "search block not found (exact match required)" });
    return { ok: false, perEdit, nextContent, originals };
  }
  return { ok: true, perEdit, nextContent, originals };
}

/** Apply a plan to the real tree: resolve (shared seam), then commit under mediation + rollback. */
export async function applyEditPlan(
  plan: EditPlan,
  tree: FileTree,
  ledger: RollbackLedger,
  opts: { issueId: string; fuzzyFallback?: boolean },
): Promise<PatchApplyResult> {
  const r = await resolveEditPlan(plan, tree, opts);
  if (!r.ok) return { applied: false, perEdit: r.perEdit };
  const { perEdit, nextContent, originals } = r;

  // Commit all buffered writes AND register the reversible action under a per-commit
  // WRITE GRANT that names EXACTLY these writes (R24) — a mediatedTree admits only the
  // declared (path, content) writes, so no other in-scope write can ride along; the
  // effect stays coupled to its spine-recording ledger entry (the mediation invariant).
  const rollbackId = `solve_${opts.issueId}_${Date.now()}`;
  const forwardGrant = new WriteGrant([...nextContent].map(([path, content]) => ({ path, content })));
  const attempted: string[] = [];
  try {
    await runMediatedWith(forwardGrant, async () => {
      for (const [file, content] of nextContent) { attempted.push(file); await tree.write(file, content); }
    });
  } catch (writeError) {
    // Commit-failure atomicity: compensate every successfully written member before surfacing the
    // failure. Registration happens only after the full batch commits, so a half-write can never
    // escape without an immediate restore attempt.
    const restores = attempted.reverse().map((path) => ({ path, content: originals.get(path)! }));
    try {
      const restoreGrant = new WriteGrant(restores);
      await runMediatedWith(restoreGrant, async () => {
        for (const restore of restores) await tree.write(restore.path, restore.content);
      });
    } catch (restoreError) {
      throw new AggregateError([writeError, restoreError], "edit batch commit failed and restoration also failed");
    }
    throw writeError;
  }
  // Register ONE reversible action restoring every touched file only after the batch is complete.
  ledger.record({
    id: rollbackId,
    artifact: `worktree:${opts.issueId}`,
    undo: async () => {
      const undoGrant = new WriteGrant([...originals].map(([path, content]) => ({ path, content })));
      await runMediatedWith(undoGrant, async () => {
        for (const [file, original] of originals) await tree.write(file, original);
      });
    },
  });

  return { applied: true, perEdit, rollbackId };
}

/** Convenience: does this plan reference only files that exist + match uniquely? (dry-run check) */
export async function canApply(plan: EditPlan, tree: FileTree): Promise<boolean> {
  const buffer = new Map<string, string>();
  for (const edit of plan.edits) {
    const current = buffer.get(edit.file) ?? (await tree.read(edit.file));
    if (current === undefined || countOccurrences(current, edit.search) !== 1) return false;
    buffer.set(edit.file, current.replace(edit.search, edit.replace));
  }
  return true;
}

export type { SearchReplaceEdit };
