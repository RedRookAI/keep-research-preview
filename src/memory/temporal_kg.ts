/**
 * TKG-MEMORY — a lightweight TEMPORAL KNOWLEDGE-GRAPH VIEW over the existing bitemporal MemoryStore. Facts are typed
 * edges (subject —relation→ object), each inheriting the store's valid-time interval. This is the Zep/Graphiti design
 * (arXiv 2501.13956): "each edge carries explicit bi-temporal validity… when new information contradicts an existing
 * fact, the edge is invalidated by writing a t_invalid rather than deleted." Keep implements that by composing the
 * store's `validAt` (as-of slice) + `closeValidInterval` (supersede-not-delete) — NO new persistence engine, NO Neo4j.
 *
 * HONEST SCOPE: this is a DERIVED VIEW, not a second source of truth — the store's lessons remain authoritative, and the
 * view inherits the store's post-filter-dilution caveat (as-of retrieval can under-use encoded time — arXiv 2601.07468).
 * Graphiti EXTRACTS edges from free text via an LLM; Keep's view is DETERMINISTIC over already-structured edge lessons —
 * LLM-based entity extraction from unstructured text is a separate, model-dependent seam (named, not faked).
 * SAFE: a contradiction closes the prior edge's interval (t_invalid := new t_valid), never deletes — history + audit
 *       are preserved. ZERO-DEP. BOTH-TRACKS: an n=1 personal fact-graph / an org shared knowledge graph.
 */

import type { MemoryStore } from "./store.js";
import type { Origin } from "./model.js";
import { contradicts, DEFAULT_CARDINALITY, type ContradictionConfig } from "./contradiction.js";

const EDGE_RX = /^\[edge\]\s+(.+?)\s+--(.+?)-->\s+(.+)$/;

export interface TkgEdge {
  readonly subject: string;
  readonly relation: string;
  readonly object: string;
  readonly validFrom: number;
  readonly validTo?: number;
  /** The backing lesson id (provenance; used to supersede via closeValidInterval). */
  readonly lessonId: string;
}

/** Encode a typed edge as deterministic lesson content (round-trips through EDGE_RX). */
export function encodeEdge(subject: string, relation: string, object: string): string {
  return `[edge] ${subject} --${relation}--> ${object}`;
}

/** Parse a lesson's content into an edge, or null if it is not a typed edge. */
function parseEdge(content: string, validFrom: number, validTo: number | undefined, lessonId: string): TkgEdge | null {
  const m = EDGE_RX.exec(content);
  if (!m) return null;
  const subject = m[1]!.trim(), relation = m[2]!.trim(), object = m[3]!.trim();
  if (!subject || !relation || !object) return null;
  return { subject, relation, object, validFrom, ...(validTo !== undefined ? { validTo } : {}), lessonId };
}

export class TemporalKnowledgeGraph {
  constructor(private readonly store: MemoryStore, private readonly now: () => number = () => Date.now(), private readonly contradictionConfig: ContradictionConfig = DEFAULT_CARDINALITY) {}

  /**
   * Add a typed edge valid from `validFrom` (default: now). If it CONTRADICTS a current edge — same subject+relation,
   * DIFFERENT object, still valid at `validFrom` — the prior edge is INVALIDATED by closing its interval at `validFrom`
   * (Graphiti: t_invalid := new t_valid). Supersede-not-delete. Returns the new edge, or undefined if malformed/rejected.
   */
  async addEdge(subject: string, relation: string, object: string, validFrom: number = this.now(), origin: Origin = "self"): Promise<TkgEdge | undefined> {
    // TYPING: subject/relation/object must all be non-empty.
    if (!subject.trim() || !relation.trim() || !object.trim()) return undefined;

    // CONTRADICTION (algebra): functional-relation value change, or explicit negation, within overlapping valid-time —
    // multi-valued/unknown relations are additive and never superseded (TOKI-CONTRADICTION).
    const next = { subject, relation, object, validFrom };
    for (const e of this.edgesAt(validFrom)) {
      if (contradicts(next, e, this.contradictionConfig)) {
        this.store.closeValidInterval(e.lessonId, validFrom); // t_invalid := new t_valid
      }
    }

    const lesson = await this.store.ingest(encodeEdge(subject, relation, object), { origin, validFrom });
    if (!lesson) return undefined; // rejected at ingestion (e.g. secret/copyleft gate)
    return { subject, relation, object, validFrom, lessonId: lesson.id };
  }

  /** As-of query: all typed edges VALID at `worldTime` (excludes edges that begin later or were invalidated before it). */
  edgesAt(worldTime: number): TkgEdge[] {
    const out: TkgEdge[] = [];
    for (const l of this.store.validAt(worldTime)) {
      const e = parseEdge(l.content, l.validFrom, l.validTo, l.id);
      if (e) out.push(e);
    }
    return out;
  }

  /** The current graph slice (edges valid now). */
  currentEdges(): TkgEdge[] {
    return this.edgesAt(this.now());
  }

  /** Neighbours of an entity at `worldTime` — edges where it is the subject. */
  relationsOf(subject: string, worldTime: number = this.now()): TkgEdge[] {
    return this.edgesAt(worldTime).filter((e) => e.subject === subject);
  }

  /**
   * HONEST: this view derives from the store; as-of retrieval can under-use encoded time (temporally misaligned recall).
   * Surfaced, never hidden — a derived view is not a second source of truth.
   */
  readonly caveat =
    "derived view over the bitemporal store (not a second source of truth); as-of graph retrieval can under-use encoded time — temporally misaligned recall is possible (arXiv 2601.07468). LLM-based entity extraction from unstructured text is a separate seam.";
}
