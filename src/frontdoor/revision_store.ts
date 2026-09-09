/**
 * F3b — Revision store (structural, non-destructive supersession).
 *
 * "The human changed their mind — rebuild it." The 2026 memory consensus (Memanto,
 * Kumiho, Eywa) is non-destructive supersession: a revised belief RETIRES the old one
 * (marked, but retained) and links the replacement, enabling full temporal
 * reconstruction. This is the operator's locked choice — additive by default, the old
 * version always restorable.
 *
 * The safety-critical detail (the "supersession gap", arXiv 2606.27472): agents
 * MEASURABLY fail to answer with the current value after an update, and bigger models
 * / bigger memory don't fix it. So current-vs-superseded is STRUCTURAL here — the
 * current view deterministically excludes superseded versions; nothing relies on the
 * model "remembering" the newer fact.
 *
 * Grounded in AGM belief revision: minimal change (Relevance) + no unjustified
 * deletion (Core-Retainment). Actual DELETION of real work is NOT done here — that
 * routes through the F1.5 gate as destructive-tier (human tap). This store only ever
 * supersedes and restores; it never destroys.
 */

import type { Spine } from "../spine/spine.js";

export type RevisableKind = "directive" | "plan" | "understanding" | "preference";

export type VersionStatus = "current" | "superseded";

export interface Version {
  readonly id: string; // unique per version
  readonly itemKey: string; // stable key identifying the logical item across revisions
  readonly kind: RevisableKind;
  readonly content: string;
  readonly status: VersionStatus;
  readonly revisionOf?: string; // the version id this superseded (provenance chain)
  readonly supersededBy?: string; // set when this version is retired
  readonly reason?: string; // why it was revised (human's words)
  readonly ts: number;
  readonly spineEventId: string;
}

export class RevisionStore {
  /** All versions ever, in insertion order (append-only; nothing is deleted). */
  private readonly versions: Version[] = [];
  private seq = 0;

  constructor(private readonly spine: Spine) {}

  /** Create the first version of a new item. */
  create(itemKey: string, kind: RevisableKind, content: string, now = Date.now()): Version {
    const v = this.write({ itemKey, kind, content, status: "current", ts: now });
    return v;
  }

  /**
   * Revise an item: retire its current version (kept, linked) and write a new current
   * one. Additive — the old version remains in history and is restorable. Returns the
   * new version, or undefined if there's no current version to revise.
   */
  revise(itemKey: string, newContent: string, reason?: string, now = Date.now()): Version | undefined {
    const cur = this.current(itemKey);
    if (!cur) return undefined;
    const next = this.write({
      itemKey,
      kind: cur.kind,
      content: newContent,
      status: "current",
      revisionOf: cur.id,
      ...(reason !== undefined ? { reason } : {}),
      ts: now,
    });
    this.retire(cur.id, next.id, now);
    return next;
  }

  /**
   * Restore a specific prior version: it becomes current again (as a NEW version, so
   * the act of restoring is itself auditable and re-reversible). The currently-current
   * version is superseded by the restored copy.
   */
  restore(versionId: string, reason?: string, now = Date.now()): Version | undefined {
    const target = this.versions.find((v) => v.id === versionId);
    if (!target) return undefined;
    const cur = this.current(target.itemKey);
    const restored = this.write({
      itemKey: target.itemKey,
      kind: target.kind,
      content: target.content, // reinstate the old content
      status: "current",
      revisionOf: cur?.id ?? target.id,
      reason: reason ?? `restored version ${versionId}`,
      ts: now,
    });
    if (cur) this.retire(cur.id, restored.id, now);
    return restored;
  }

  /** The current (non-superseded) version of an item, or undefined. */
  current(itemKey: string): Version | undefined {
    // Structural: only a status==="current" version counts. Never model-inferred.
    return this.versions.find((v) => v.itemKey === itemKey && v.status === "current");
  }

  /** Full history of an item, oldest first (includes superseded versions). */
  history(itemKey: string): Version[] {
    return this.versions.filter((v) => v.itemKey === itemKey).sort((a, b) => a.ts - b.ts);
  }

  /** All current items of a kind (the ground-truth the system acts on). */
  allCurrent(kind?: RevisableKind): Version[] {
    return this.versions.filter((v) => v.status === "current" && (kind === undefined || v.kind === kind));
  }

  /** Reconstruct the content of an item as it was at a past timestamp (as-of query). */
  asOf(itemKey: string, ts: number): Version | undefined {
    // The version that was current at `ts`: created at or before ts, and either still
    // current or superseded after ts.
    const candidates = this.versions
      .filter((v) => v.itemKey === itemKey && v.ts <= ts)
      .sort((a, b) => b.ts - a.ts);
    for (const v of candidates) {
      const supersededAt = v.supersededBy ? this.versions.find((x) => x.id === v.supersededBy)?.ts : undefined;
      if (supersededAt === undefined || supersededAt > ts) return v;
    }
    return undefined;
  }

  private write(fields: Omit<Version, "id" | "spineEventId">): Version {
    const id = `ver_${++this.seq}`;
    const spineEventId = this.spine.stage({
      type: "identity.action",
      actor: "revision-store",
      payload: {
        event: "revision.write",
        versionId: id,
        itemKey: fields.itemKey,
        kind: fields.kind,
        status: fields.status,
        ...(fields.revisionOf !== undefined ? { revisionOf: fields.revisionOf } : {}),
        ...(fields.reason !== undefined ? { reason: fields.reason } : {}),
        // content is stored in the version record, not necessarily echoed to the spine payload
      },
    });
    const v: Version = { id, spineEventId, ...fields };
    this.versions.push(v);
    return v;
  }

  private retire(versionId: string, supersededBy: string, now: number): void {
    const idx = this.versions.findIndex((v) => v.id === versionId);
    if (idx < 0) return;
    const old = this.versions[idx]!;
    // Non-destructive: mark superseded + link forward. The record is KEPT.
    this.versions[idx] = { ...old, status: "superseded", supersededBy };
    this.spine.stage({
      type: "identity.action",
      actor: "revision-store",
      payload: { event: "revision.superseded", versionId, supersededBy, itemKey: old.itemKey, ts: now },
    });
  }
}
