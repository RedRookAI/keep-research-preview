/**
 * IngestionPipeline + RetrievalBackend (Increment 4.5d) — the secure ingestion flow.
 *
 * SOTA basis (2026-08-04): the layered order is validate/sanitize → hash (immutable original) →
 * classify → handle-by-tag → chunk (semantic boundaries) + per-chunk hash → index → record ROPA.
 * Every stage deterministic + spine-loggable; no LLM in the security/handling path. Deletion
 * propagates to the index (Truto's "state-drift landmine": a vector must never answer using data
 * that legally no longer exists). Retrieval is behind a PORT — zero-dep keyword default now, a
 * dense/vector backend swaps in later WITHOUT changing the security/compliance envelope, and the
 * per-project isolation (session layer 3.5) wraps it unchanged.
 *
 * Zero deps.
 */

import { createHash } from "node:crypto";
import { DataClassifier, type SensitivityTier } from "./data_classifier.js";
import { HandlingPolicy, Tokenizer, type HandledText } from "./handling_policy.js";
import { ContentSanitizer } from "./content_sanitizer.js";
import {
  DataGovernance,
  type LawfulBasis,
  type Purpose,
} from "./data_governance.js";
import type { ProjectNamespace } from "../session/project_registry.js";

/** A chunk ready for indexing: safe-to-index text + provenance + hash. */
export interface IndexChunk {
  readonly chunkId: string;
  readonly sourceId: string;
  readonly projectId: string;
  readonly text: string; // already tokenized/masked per handling policy
  readonly chunkHash: string;
  readonly sensitivityTier: SensitivityTier;
}

/** A retrieval hit. */
export interface ChunkRetrievalHit {
  readonly chunk: IndexChunk;
  readonly score: number;
}

/**
 * Retrieval backend PORT. The default is zero-dep keyword scoring; a dense/vector backend
 * (embeddings + vector DB) implements the same interface later. Isolation is the caller's
 * concern (chunks are already project-scoped), so a backend never crosses projects.
 */
export interface RetrievalBackend {
  index(chunk: IndexChunk): void;
  search(projectId: string, query: string, k: number): ChunkRetrievalHit[];
  /** Drop every chunk for a source (erasure propagation). Returns count removed. */
  dropSource(sourceId: string): number;
  /** Chunks currently indexed for a project (audit/testing). */
  size(projectId: string): number;
}

/** Zero-dep keyword (TF-style, BM25-flavored) retrieval backend. Default. */
export class KeywordRetrievalBackend implements RetrievalBackend {
  private readonly chunks: IndexChunk[] = [];

  index(chunk: IndexChunk): void {
    this.chunks.push(chunk);
  }

  search(projectId: string, query: string, k: number): ChunkRetrievalHit[] {
    const terms = tokenizeQuery(query);
    if (terms.length === 0) return [];
    const hits: ChunkRetrievalHit[] = [];
    for (const c of this.chunks) {
      if (c.projectId !== projectId) continue; // hard project scope — never cross projects
      const text = c.text.toLowerCase();
      let score = 0;
      for (const t of terms) {
        // simple TF with length normalization (BM25-flavored, dependency-free)
        const occ = countOcc(text, t);
        if (occ > 0) score += occ / (1 + Math.log(1 + text.length));
      }
      if (score > 0) hits.push({ chunk: c, score });
    }
    return hits.sort((a, b) => b.score - a.score).slice(0, k);
  }

  dropSource(sourceId: string): number {
    const before = this.chunks.length;
    for (let i = this.chunks.length - 1; i >= 0; i--) {
      if (this.chunks[i]!.sourceId === sourceId) this.chunks.splice(i, 1);
    }
    return before - this.chunks.length;
  }

  size(projectId: string): number {
    return this.chunks.filter((c) => c.projectId === projectId).length;
  }
}

function tokenizeQuery(q: string): string[] {
  return q.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 1);
}
function countOcc(haystack: string, needle: string): number {
  let n = 0;
  let i = haystack.indexOf(needle);
  while (i !== -1) {
    n++;
    i = haystack.indexOf(needle, i + needle.length);
  }
  return n;
}

/** Result of ingesting one source. */
export interface IngestResult {
  readonly sourceId: string;
  readonly sensitivityTier: SensitivityTier;
  readonly chunksIndexed: number;
  readonly handling: HandledText["action"];
  readonly unstructuredPiiPossible: boolean;
  readonly injectionsNeutralized: number;
}

export class IngestionPipeline {
  private readonly classifier: DataClassifier;
  private readonly policy: HandlingPolicy;
  readonly governance: DataGovernance;
  readonly backend: RetrievalBackend;
  /** The tokenization vault — exposed so authorized callers can recover originals (detokenize). */
  readonly tokenizer: Tokenizer;
  private readonly sanitizer: ContentSanitizer;
  private readonly ns: ProjectNamespace;

  constructor(opts: {
    ns: ProjectNamespace;
    classifier?: DataClassifier;
    governance?: DataGovernance;
    backend?: RetrievalBackend;
    tokenizer?: Tokenizer;
    policy?: HandlingPolicy;
    sanitizer?: ContentSanitizer;
  }) {
    this.ns = opts.ns;
    this.classifier = opts.classifier ?? new DataClassifier();
    this.governance = opts.governance ?? new DataGovernance();
    this.backend = opts.backend ?? new KeywordRetrievalBackend();
    this.tokenizer = opts.tokenizer ?? new Tokenizer(opts.ns);
    this.policy = opts.policy ?? new HandlingPolicy(this.tokenizer);
    this.sanitizer = opts.sanitizer ?? new ContentSanitizer();
  }

  /**
   * Ingest one source: validate → hash → classify → handle-by-tag → chunk → index → record ROPA.
   * `purpose`/`lawfulBasis` declare why the data is being taken in (the basis for later
   * purpose-limitation checks). Returns a summary incl. honest unstructured-PII flag.
   */
  ingest(input: {
    sourceId: string;
    text: string;
    purpose: Purpose;
    lawfulBasis: LawfulBasis;
    baseTier?: SensitivityTier;
    subjects?: readonly string[];
    retainUntil?: number;
    chunkSize?: number;
  }): IngestResult {
    const projectId = this.ns.projectId;
    const contentHash = sha256(input.text);

    // classify (per-record; findings drive per-field handling)
    const cls = this.classifier.classify(input.text, input.baseTier ?? "internal");

    // chunk on rough semantic boundaries (paragraphs), then handle each chunk by tag
    const rawChunks = chunkText(input.text, input.chunkSize ?? 800);
    let handlingAction: HandledText["action"] = "keep";
    let indexed = 0;
    let injectionsNeutralized = 0;
    rawChunks.forEach((raw, i) => {
      // (1) SANITIZE untrusted content first — neutralize embedded injection before anything else.
      const sanitized = this.sanitizer.sanitize(raw);
      injectionsNeutralized += sanitized.report.neutralizedInstructions;
      const safe = sanitized.text;
      // (2) classify + handle the sanitized text
      const chunkFindings = this.classifier.detect(safe);
      const handled = this.policy.apply(safe, cls.tier, chunkFindings);
      handlingAction = handled.action;
      const chunk: IndexChunk = {
        chunkId: `${input.sourceId}#${i}`,
        sourceId: input.sourceId,
        projectId,
        text: handled.text,
        chunkHash: sha256(handled.text),
        sensitivityTier: cls.tier,
      };
      this.backend.index(chunk);
      indexed++;
    });

    // record the processing activity (ROPA)
    this.governance.register({
      sourceId: input.sourceId,
      projectId,
      contentHash,
      sensitivityTier: cls.tier,
      purpose: input.purpose,
      lawfulBasis: input.lawfulBasis,
      handlingApplied: handlingAction,
      ...(input.retainUntil !== undefined ? { retainUntil: input.retainUntil } : {}),
      ...(input.subjects !== undefined ? { subjects: input.subjects } : {}),
    });

    return {
      sourceId: input.sourceId,
      sensitivityTier: cls.tier,
      chunksIndexed: indexed,
      handling: handlingAction,
      unstructuredPiiPossible: cls.unstructuredPiiPossible,
      injectionsNeutralized,
    };
  }

  /** Search the project's index (project-scoped; never crosses projects). */
  search(query: string, k = 5): ChunkRetrievalHit[] {
    return this.backend.search(this.ns.projectId, query, k);
  }

  /**
   * Recover a single original value from a token (privileged detokenization — SOTA: a controlled
   * workflow). Throws if the token is unknown or the project key was crypto-shredded (erased).
   * This is how the operator gets the REAL value back (e.g. the customer's actual email to send).
   */
  detokenize(token: string): string {
    return this.tokenizer.detokenize(token);
  }

  /**
   * Reconstruct the ORIGINAL text from a tokenized/handled string by restoring every token to its
   * real value. Non-destructive proof-in-code: tokenized data + vault == the original. Throws if
   * the project was erased (keys shredded) — which is the correct behavior post-right-to-erasure.
   */
  reconstruct(handledText: string): string {
    let out = handledText;
    for (const entry of this.tokenizer.entries()) {
      if (out.includes(entry.token)) {
        out = out.split(entry.token).join(this.tokenizer.detokenize(entry.token));
      }
    }
    return out;
  }

  /**
   * ERASURE with propagation: drop the source's chunks from the index AND its ROPA record.
   * Prevents the state-drift landmine (a vector answering with legally-deleted data).
   */
  eraseSource(sourceId: string): { chunksDropped: number } {
    const chunksDropped = this.backend.dropSource(sourceId);
    this.governance.eraseSource(sourceId);
    return { chunksDropped };
  }

  /** Erase everything about a data subject (DSAR): every source about them + their chunks. */
  eraseSubject(subject: string): { sourcesErased: number; chunksDropped: number } {
    const sources = this.governance.eraseSubject(subject);
    let chunksDropped = 0;
    for (const s of sources) chunksDropped += this.backend.dropSource(s);
    return { sourcesErased: sources.length, chunksDropped };
  }
}

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

function chunkText(text: string, size: number): string[] {
  const paras = text.split(/\n\s*\n/).map((p) => p.trim()).filter(Boolean);
  const chunks: string[] = [];
  let cur = "";
  for (const p of paras) {
    if (cur.length + p.length + 2 > size && cur) {
      chunks.push(cur);
      cur = p;
    } else {
      cur = cur ? cur + "\n\n" + p : p;
    }
  }
  if (cur) chunks.push(cur);
  return chunks.length ? chunks : [text];
}
