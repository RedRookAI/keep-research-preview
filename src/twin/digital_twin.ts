/**
 * Digital twin (Finding 1.1, layer 6) — a model-independent, deterministic PREVIEW of an op's TRUE
 * effect, compared against what the op DECLARED. An op that does more than it declared (actual ⊄
 * declared) is a deny-capable gate input.
 *
 * The twin computes the actual effect from the OP ITSELF — it applies the op to a shadow fork and
 * diffs — NOT from the model's self-report. So a lying declaration ("I only write a.txt") cannot hide
 * an undeclared write (the fork reveals b.txt); the fork wins over the declaration. This is the
 * terraform-plan / speculative-plan discipline: preview the real change before committing, and gate on
 * a surprise.
 *
 * AUTHORITY SCOPING (honest, from the research): a MISMATCH is a RELIABLE REJECT — the twin caught the
 * op doing more than it said. A MATCH is a WEAK PASS — HashiCorp's own caveat: "other changes in the
 * meantime might cause the final effect to differ, so re-check before applying." So a matching preview
 * does not guarantee the real apply matches (a TOCTOU gap); it only means no surprise was visible at
 * preview time. The twin therefore only ADDS caution (reliably gates surprises); it never certifies.
 *
 * SCOPE — BUILT vs SEAM: BUILT is the in-env twin over the FILE fork (declared-vs-actual write-set +
 * a static undeclared-external-sink screen of the produced content). A full EXTERNAL-effect twin — a
 * real preview of network/DB side effects (what a request would actually do to a remote system) —
 * is a SEAM (it needs a sandboxed replica of the external world). The file twin is exact; the external
 * twin is screened statically here and flagged for the real preview later.
 *
 * WHAT WOULD CHANGE IT: a richer effect model (permissions, deletions, renames) extends the diff; a
 * real external-world replica upgrades the sink screen to a true preview. Neither makes a mismatch
 * pass — the reject direction is fixed.
 */

import type { FileTree } from "../solve/patch.js";
import { InMemoryFileTree } from "../solve/patch.js";
import type { OpDescription } from "../floor/structural_floor.js";

/** Sink patterns screened in the ACTUAL content delta (same family the floor uses). */
const EXTERNAL_SINK_TEXT: readonly RegExp[] = [
  /\bgit\s+push\b/i,
  /\bcurl\b|\bwget\b|\bfetch\s*\(|\bhttps?:\/\/[^\s"'`)<>{}\]]+/i,
  /\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA|COLLECTION|INDEX)\b/i,
  /\bDELETE\s+FROM\b(?![^;]*\bWHERE\b)/i,
];

export interface TwinPreview {
  /** The DECLARED effect (write-set, sinks) the actual effect is checked against. */
  readonly description: OpDescription;
  /** The pre-state of the files the op may touch (read through the membrane by the caller). */
  readonly preState: Readonly<Record<string, string>>;
  /** Apply the op to the given tree (a throwaway shadow during the preview). */
  execute(tree: FileTree): Promise<void>;
}

export type TwinVerdict = {
  readonly verdict: "match" | "mismatch";
  readonly reasons: readonly string[];
  readonly actualWrites: readonly string[];
};

function diff(pre: Record<string, string>, post: Record<string, string>): string[] {
  const keys = new Set([...Object.keys(pre), ...Object.keys(post)]);
  const changed: string[] = [];
  for (const k of keys) if (pre[k] !== post[k]) changed.push(k);
  return changed;
}

function introducesExternalSink(before: string, after: string): boolean {
  return EXTERNAL_SINK_TEXT.some((pattern) => {
    const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
    const occurrences = (text: string): Map<string, number> => {
      const counts = new Map<string, number>();
      for (const match of text.matchAll(new RegExp(pattern.source, flags))) {
        const value = match[0]!.toLowerCase();
        counts.set(value, (counts.get(value) ?? 0) + 1);
      }
      return counts;
    };
    const prior = occurrences(before);
    for (const [value, count] of occurrences(after)) if (count > (prior.get(value) ?? 0)) return true;
    return false;
  });
}

/**
 * Preview the op on a shadow and compare actual-vs-declared. Total: an execute that throws yields an
 * uncomputable preview, which fails safe to mismatch.
 */
export async function digitalTwin(p: TwinPreview): Promise<TwinVerdict> {
  const pre = { ...p.preState };
  const fork = new InMemoryFileTree(pre);
  try {
    await p.execute(fork);
  } catch {
    return { verdict: "mismatch", reasons: ["preview-uncomputable"], actualWrites: [] };
  }
  const post = fork.snapshot();
  const actualWrites = diff(pre, post);
  const declared = new Set(p.description.writeSet ?? []); // undefined ⇒ empty ⇒ any write is undeclared

  const reasons: string[] = [];
  for (const w of actualWrites) {
    if (!declared.has(w)) reasons.push(`undeclared-write:${w}`); // actual ⊄ declared
  }

  // Undeclared external sink: the effect INTRODUCES a sink but declared none. Screening the
  // complete post-image caused safe edits to files that already contained URLs or fetch calls to
  // be held even when the edit did not add or alter that capability. The twin judges effects, so
  // pre-existing sink text belongs to the precondition rather than the candidate effect.
  const declaredSinks = p.description.externalSinks ?? [];
  if (declaredSinks.length === 0) {
    if (actualWrites.some((path) => introducesExternalSink(pre[path] ?? "", post[path] ?? ""))) {
      reasons.push("undeclared-external-sink");
    }
  }

  if (reasons.length === 0) return { verdict: "match", reasons: ["actual-effect-within-declared"], actualWrites };
  return { verdict: "mismatch", reasons, actualWrites };
}
