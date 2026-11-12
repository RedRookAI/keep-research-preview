/**
 * Deterministic deduplication, linking, supersession and pruning decisions over abstract memory items.
 *
 * Returns inspectable decisions without mutating the store. The caller applies them through an adapter.
 * Sensitive capture uses the contextual-integrity vault; supersession preserves prior records.
 * Similarity defaults to normalized equality and can be supplied by the deployment.
 */

import { SensitiveContextVault, classifySpecialCategory } from "../privacy/contextual_integrity.js";

/** A memory item, minimally. `key` is the logical TOPIC (same key across updates of the same fact). `Lesson` maps
 *  onto this via a thin adapter (id + content + a derived key + scope). */
export interface UpkeepItem {
  readonly id: string;
  readonly content: string;
  readonly key: string; // logical topic key — same fact keeps the same key across updates
  readonly scope: string; // for linking (project / user / global)
}

/** An incoming candidate to fold into memory. `subject` is set when it may be a personal disclosure. */
export interface Candidate {
  readonly content: string;
  readonly key: string;
  readonly scope: string;
  readonly subject?: string | undefined;
}

export type UpkeepAction = "add" | "dedup" | "supersede";

/** The inspectable decision. Everything the upkeep did is legible here — enhance-not-degrade. */
export interface UpkeepResult {
  readonly action: UpkeepAction;
  readonly dedupOf?: string | undefined; // existing id this duplicates (action = dedup)
  readonly supersedes?: string | undefined; // existing id this replaces (action = supersede)
  readonly links: readonly string[]; // related existing ids (same scope, different topic)
  readonly sensitive: boolean; // routed through the CI vault
}

/** Similarity SEAM. Default: normalized string equality (deterministic). A deployment injects embedding similarity. */
export type Similar = (a: string, b: string) => boolean;

function normalize(s: string): string {
  return s.trim().toLowerCase().replace(/\s+/g, " ");
}
export function normalizedEqual(a: string, b: string): boolean {
  return normalize(a) === normalize(b);
}

export interface UpkeepOptions {
  readonly similar?: Similar | undefined;
  readonly vault?: SensitiveContextVault | undefined;
}

/**
 * The upkeep decision for one incoming candidate against the existing items.
 *   - DEDUP: a same-topic item whose content is (near-)duplicate ⇒ merge, do not re-add.
 *   - SUPERSEDE: a same-topic item whose content DIFFERS ⇒ this is an update; supersede the stale one
 *     (supersede-not-delete — the caller retires it, provenance retained), do not duplicate.
 *   - ADD: no same-topic item ⇒ a new item.
 *   - LINK: existing items in the same scope on a DIFFERENT topic are related ⇒ linked.
 *   - SENSITIVE: a special-category disclosure routes through the CI vault.
 */
export function upkeep(existing: readonly UpkeepItem[], candidate: Candidate, opts?: UpkeepOptions): UpkeepResult {
  const similar = opts?.similar ?? normalizedEqual;

  // Route a special-category disclosure through the CI vault before anything else.
  let sensitive = false;
  if (opts?.vault !== undefined && candidate.subject !== undefined && classifySpecialCategory(candidate.content) !== undefined) {
    opts.vault.capture(candidate.subject, candidate.content);
    sensitive = true;
  }

  // LINK: same scope, different topic key.
  const links = existing.filter((e) => e.scope === candidate.scope && e.key !== candidate.key).map((e) => e.id);

  // DEDUP vs SUPERSEDE vs ADD, scoped to the same logical topic.
  const sameTopic = existing.filter((e) => e.key === candidate.key);
  const dup = sameTopic.find((e) => similar(e.content, candidate.content));
  if (dup !== undefined) return { action: "dedup", dedupOf: dup.id, links, sensitive };
  const stale = sameTopic.find((e) => !similar(e.content, candidate.content));
  if (stale !== undefined) return { action: "supersede", supersedes: stale.id, links, sensitive };
  return { action: "add", links, sensitive };
}

/** A prune record — never a silent delete. The content is not destroyed (the caller retires the item); this is the
 *  reversible, inspectable trail of what was pruned and why. */
export interface Tombstone {
  readonly id: string;
  readonly reason: string;
}

export interface PruneResult {
  readonly kept: readonly UpkeepItem[];
  readonly tombstones: readonly Tombstone[];
}

/**
 * Prune items a staleness predicate selects — but NEVER silently: each pruned item leaves a tombstone (id +
 * reason), so the operation is reversible and inspectable. `reason` defaults to a generic staleness note.
 */
export function prune(items: readonly UpkeepItem[], isStale: (i: UpkeepItem) => boolean, reason = "stale"): PruneResult {
  const kept: UpkeepItem[] = [];
  const tombstones: Tombstone[] = [];
  for (const it of items) {
    if (isStale(it)) tombstones.push({ id: it.id, reason: `pruned: ${reason}` });
    else kept.push(it);
  }
  return { kept, tombstones };
}
