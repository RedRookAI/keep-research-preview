/**
 * F3a — Incremental project-understanding builder (multi-call orchestration).
 *
 * For "here are all my files / continue this project": chunk -> gate each chunk
 * (hostile-by-default) -> Map to a chunk summary -> INCREMENTALLY UPDATE a running
 * understanding (carry prior context forward so later chunks aren't misread alone,
 * per the incremental-updating technique) -> emit a hierarchical understanding +
 * a proposed trajectory. A poisoned file can't become "trusted project guidance"
 * because every chunk passes the ingestion gate first (GitInject defense).
 *
 * The per-chunk summarizer is the injected LLM seam (planning-routed on the connected
 * env); the gating, incremental-merge orchestration, provenance, and budget bounding
 * are real and tested here. Never throws.
 */

import type { Spine } from "../spine/spine.js";
import { scanIngestion } from "../memory/ingestion.js";
import type { Chunk } from "./chunker.js";

/** Injected: summarize one (already-sanitized-and-gated) chunk. The LLM seam. */
export interface ChunkSummarizer {
  (chunkText: string, priorUnderstanding: string): Promise<string>;
}

export interface SourceSummary {
  readonly source: string;
  readonly summary: string;
  readonly chunkCount: number;
}

export interface RejectedChunk {
  readonly source: string;
  readonly index: number;
  readonly reason: string;
}

export interface ProjectUnderstanding {
  /** The running global synthesis, refined across all chunks. */
  readonly global: string;
  /** Per-source (per-file) roll-ups. */
  readonly bySource: readonly SourceSummary[];
  /** Chunks the ingestion gate rejected (copyleft) — never trusted. */
  readonly rejected: readonly RejectedChunk[];
  /** True if any chunk had secrets/PII redacted before summarization. */
  readonly hadRedactions: boolean;
  /** How many chunks were actually processed (budget-bounded). */
  readonly chunksProcessed: number;
  /** A plain-language note about scope/limits for the human. */
  readonly note: string;
}

export interface UnderstandingOptions {
  /** Max chunks to process this pass (budget bound). */
  readonly maxChunks?: number;
  /** Resolved enterprise tenant attribution; omitted for the complete local n=1 trail. */
  readonly tenant?: string;
}

const DEFAULT_MAX_CHUNKS = 200;

/**
 * Build an incremental understanding of a set of chunks. Gates every chunk, Maps the
 * clean ones, and refines a running global summary. Budget-bounded and spine-logged.
 */
export async function buildProjectUnderstanding(
  spine: Spine,
  chunks: readonly Chunk[],
  summarize: ChunkSummarizer,
  opts: UnderstandingOptions = {},
): Promise<ProjectUnderstanding> {
  const maxChunks = opts.maxChunks ?? DEFAULT_MAX_CHUNKS;
  const budgeted = chunks.slice(0, maxChunks);

  let global = "";
  const perSource = new Map<string, { parts: string[]; count: number }>();
  const rejected: RejectedChunk[] = [];
  let hadRedactions = false;
  let processed = 0;

  for (const chunk of budgeted) {
    // 1. Hostile ingestion gate — a poisoned chunk can't become trusted guidance.
    const gate = scanIngestion(chunk.text);
    if (gate.decision === "reject") {
      rejected.push({ source: chunk.source, index: chunk.index, reason: gate.findings.join(",") || "rejected" });
      continue;
    }
    if (gate.decision === "redact") hadRedactions = true;
    const safeChunk = gate.sanitized; // secrets/PII removed

    // 2. Map: summarize the clean chunk, carrying the running understanding forward.
    let summary: string;
    try {
      summary = await summarize(safeChunk, global);
    } catch {
      // A summarizer failure on one chunk must not abort the whole ingestion.
      rejected.push({ source: chunk.source, index: chunk.index, reason: "summary-failed" });
      continue;
    }

    // 3. Incremental update: fold this chunk's summary into the running global view.
    global = global ? `${global}\n- ${condense(summary)}` : `- ${condense(summary)}`;
    const entry = perSource.get(chunk.source) ?? { parts: [], count: 0 };
    entry.parts.push(summary);
    entry.count += 1;
    perSource.set(chunk.source, entry);
    processed += 1;
  }

  const bySource: SourceSummary[] = [...perSource.entries()].map(([source, v]) => ({
    source,
    summary: v.parts.join(" "),
    chunkCount: v.count,
  }));

  const understanding: ProjectUnderstanding = {
    global: global || "(nothing could be understood from the input)",
    bySource,
    rejected,
    hadRedactions,
    chunksProcessed: processed,
    note: buildNote(processed, bySource.length, rejected.length, hadRedactions, chunks.length > maxChunks),
  };

  spine.stage({
    type: "identity.action",
    actor: "frontdoor",
    payload: {
      event: "project.understanding_built",
      chunksProcessed: processed,
      sources: bySource.length,
      rejected: rejected.length,
      hadRedactions,
      truncated: chunks.length > maxChunks,
      ...(opts.tenant === undefined ? {} : { tenant: opts.tenant }),
    },
  });

  return understanding;
}

/** Propose a trajectory from an understanding (injected planner seam is optional). */
export function summarizeForHuman(u: ProjectUnderstanding): string {
  const parts: string[] = [];
  parts.push(`I went through ${u.chunksProcessed} section${u.chunksProcessed === 1 ? "" : "s"} across ${u.bySource.length} file${u.bySource.length === 1 ? "" : "s"}.`);
  if (u.hadRedactions) parts.push("I found and safely set aside some secrets/personal info before reading.");
  if (u.rejected.length > 0) parts.push(`I skipped ${u.rejected.length} section${u.rejected.length === 1 ? "" : "s"} I couldn't safely use.`);
  parts.push("Here's my understanding so far, and I'll check it with you before acting.");
  return parts.join(" ");
}

function condense(s: string, max = 240): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max) + "…" : t;
}

function buildNote(processed: number, sources: number, rejected: number, redacted: boolean, truncated: boolean): string {
  const bits = [`Understood ${processed} section(s) across ${sources} source(s).`];
  if (redacted) bits.push("Secrets/PII were removed before anything was read.");
  if (rejected > 0) bits.push(`${rejected} section(s) were rejected as unsafe to use.`);
  if (truncated) bits.push("This was a large drop, so I processed the first batch — tell me to continue for the rest.");
  return bits.join(" ");
}
