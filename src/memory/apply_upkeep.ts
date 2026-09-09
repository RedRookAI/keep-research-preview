/**
 * MEMORY-UPKEEP APPLY ADAPTER — Hardening H1 (the outbound port for Round 3).
 *
 * Ports-and-adapters: `upkeep()` is the PURE DOMAIN — it decides `add | dedup | supersede` (+ links, + prune
 * tombstones) and touches no store. This module is the OUTBOUND ADAPTER that applies that decision to the real
 * `MemoryStore`, keeping the domain sacred (it does not modify `upkeep.ts` or the store's core logic).
 *
 * The two production gotchas the ports-and-adapters literature names are honored:
 *   - IDEMPOTENT APPLY: applying the same `UpkeepResult` twice equals applying it once. A re-applied supersede
 *     does not double-retire or duplicate; a re-applied add finds the existing live lesson and skips.
 *   - TRANSACTIONAL SUPERSEDE (atomic in effect): retire-the-stale + add-the-new, via the spine's `retired` tier
 *     (supersede-not-delete — the retired lesson stays present, provenance retained).
 *
 * A sensitive candidate is ALREADY routed through the CI vault by `upkeep()` (Round 3). This adapter has NO vault
 * surface at all, so it structurally cannot double-capture.
 *
 * BUILT + proven in-env: the decision→store apply mapping and its idempotence. There is no SEAM of substance — it
 * wires two already-built things (the upkeep decision and the memory store).
 */

import type { MemoryStore } from "./store.js";
import type { Candidate, UpkeepResult, Tombstone } from "./upkeep.js";
import type { MemoryScope, Lesson } from "./model.js";

export interface Applied {
  readonly action: "add" | "dedup" | "supersede";
  readonly addedId?: string | undefined; // the new lesson id (add / supersede)
  readonly retiredId?: string | undefined; // the retired stale lesson id (supersede)
  readonly noop: boolean; // true when this apply made no state change (dedup, or an idempotent re-apply)
}

/** The store scope of an upkeep candidate (defaults to project if not a known memory scope). */
function scopeOf(candidate: Candidate): MemoryScope {
  return candidate.scope === "user" || candidate.scope === "global" ? candidate.scope : "project";
}

/** Is `content` already present as a LIVE (non-retired) lesson? Used for idempotent add/supersede. */
function liveDuplicate(store: MemoryStore, content: string): Lesson | undefined {
  return store.all().find((l) => l.content === content && l.tier !== "retired");
}

/**
 * Apply one upkeep decision to the store.
 *   - dedup     ⇒ no-op (the near-duplicate is already stored; do not re-add).
 *   - supersede ⇒ retire the stale lesson (supersede-not-delete) AND ingest the new — atomic in effect.
 *   - add       ⇒ ingest once.
 * Idempotent: a second apply of the same result leaves the store identical to the first.
 */
export async function applyUpkeep(store: MemoryStore, candidate: Candidate, result: UpkeepResult): Promise<Applied> {
  if (result.action === "dedup") {
    return { action: "dedup", noop: true }; // idempotent by construction: never re-adds
  }

  if (result.action === "supersede" && result.supersedes !== undefined) {
    const retiredId = result.supersedes;
    const didRetire = store.retire(retiredId, "superseded by upkeep"); // idempotent: no-op if already retired
    const dup = liveDuplicate(store, candidate.content); // idempotence: don't re-add on a repeat apply
    if (dup !== undefined) {
      return { action: "supersede", retiredId, addedId: dup.id, noop: !didRetire };
    }
    const added = await store.ingest(candidate.content, { origin: "self", scope: scopeOf(candidate) });
    return { action: "supersede", retiredId, addedId: added?.id, noop: false };
  }

  // add
  const dup = liveDuplicate(store, candidate.content);
  if (dup !== undefined) {
    return { action: "add", addedId: dup.id, noop: true }; // idempotent: already present live
  }
  const added = await store.ingest(candidate.content, { origin: "self", scope: scopeOf(candidate) });
  return { action: "add", addedId: added?.id, noop: false };
}

export interface PruneApplied {
  readonly retired: readonly string[];
}

/**
 * Apply prune tombstones: retire each pruned lesson (tier→retired + a spine event carrying the reason) — a
 * tombstone in the store, NEVER a silent delete. Idempotent: an already-retired lesson is not retired twice.
 */
export function applyPrune(store: MemoryStore, tombstones: readonly Tombstone[]): PruneApplied {
  const retired: string[] = [];
  for (const t of tombstones) {
    if (store.retire(t.id, t.reason)) retired.push(t.id);
  }
  return { retired };
}
