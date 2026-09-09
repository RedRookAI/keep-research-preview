/**
 * SolvePipeline: hierarchical two-stage localizer (Increment 13b).
 *
 * SOTA basis (2026-08-05): fault localization is THE primary bottleneck for issue resolution
 * (MobileDev-Bench 2026; SHERLOC: better localization → +5.95pp resolve). The reference method is
 * a BM25 precision/recall envelope that LLM localizers should sit ABOVE (arXiv 2606.11976, which uses
 * BM25 swept K=1..30 as the baseline curve). So: STAGE 1 is a deterministic BM25-style candidate
 * retriever (testable here, no model), and STAGE 2 is an LLM re-rank/narrow that beats the BM25
 * envelope. Two design constraints from the literature: (a) return a RANKED top-K set, not a single
 * file — predicting few files tanks recall on multi-file issues (SWE-bench Pro is 80% multi-file);
 * (b) down-weight TEST files — naive access over-predicts test files and degrades localization.
 *
 * The Localizer is a PORT: stage 1's candidate retrieval is swappable, so the real code-structure
 * graph + dense embeddings (increment 14) plug in behind it. Zero deps.
 */

import type { ModelProvider } from "../gateway/gateway.js";
import type { Issue } from "./issue_model.js";

/** A repository file available to localize over. */
export interface RepoFile {
  readonly path: string;
  readonly content: string;
}

/** A suspect location: a file, its BM25 score, and (after stage 2) suspect functions/spans. */
export interface SuspectFile {
  readonly path: string;
  readonly score: number;
  /** Suspect function/symbol names within the file (stage 2 narrowing), if any. */
  readonly suspectSymbols?: readonly string[];
  /** Whether this is a test file (surfaced, usually down-weighted). */
  readonly isTest: boolean;
}

export interface LocalizationResult {
  /** Ranked suspect files, most-suspect first (top-K). */
  readonly suspects: readonly SuspectFile[];
  /** Which stages ran (stage-2 is skipped when no model is provided — deterministic mode). */
  readonly stages: readonly ("bm25" | "graph" | "embedding" | "llm-rerank")[];
}

/** The localizer port. Stage-1 candidate retrieval is swappable (code graph plugs in at increment 14). */
export interface Localizer {
  localize(issue: Issue, files: readonly RepoFile[], k: number): Promise<LocalizationResult>;
}

/** Heuristic: is this a test file? (down-weighted to avoid test-file over-prediction). */
export function isTestFile(path: string): boolean {
  return /(^|\/)tests?\//.test(path) || /\.(test|spec)\.[a-z]+$/i.test(path) || /(^|\/)test_[^/]+$/.test(path) || /_test\.[a-z]+$/i.test(path);
}

function tokenize(s: string): string[] {
  return s.toLowerCase().split(/[^a-z0-9_]+/).filter((t) => t.length > 2);
}

function countOcc(hay: string, needle: string): number {
  let n = 0, i = 0;
  for (;;) { const f = hay.indexOf(needle, i); if (f === -1) break; n++; i = f + needle.length; }
  return n;
}

/** Stage 1: deterministic BM25-style file ranking for the issue text. Test files down-weighted. */
export function bm25Rank(issue: Issue, files: readonly RepoFile[], testPenalty = 0.25): SuspectFile[] {
  const terms = tokenize(issue.text);
  // Also boost exact filename / symbol mentions from the issue (a strong IR signal).
  const scored: SuspectFile[] = [];
  for (const f of files) {
    const text = f.content.toLowerCase();
    let score = 0;
    for (const t of terms) {
      const occ = countOcc(text, t);
      if (occ > 0) score += occ / (1 + Math.log(1 + text.length));
    }
    // Filename mention boost: issue explicitly names the file (common + high-precision).
    const base = f.path.toLowerCase().split("/").pop() ?? f.path.toLowerCase();
    if (issue.text.toLowerCase().includes(base)) score += 2;
    const test = isTestFile(f.path);
    if (test) score *= testPenalty; // down-weight test files
    if (score > 0) scored.push({ path: f.path, score, isTest: test });
  }
  return scored.sort((a, b) => b.score - a.score);
}

/**
 * The default localizer: BM25 stage 1, optional LLM re-rank stage 2. If no model is given, returns the
 * deterministic BM25 ranking (fully testable here). With a model, the LLM re-ranks the top candidates
 * and narrows to suspect symbols — expected to beat the BM25 envelope.
 */
export class HierarchicalLocalizer implements Localizer {
  constructor(private readonly model?: ModelProvider, private readonly opts: { candidatePool?: number } = {}) {}

  async localize(issue: Issue, files: readonly RepoFile[], k: number): Promise<LocalizationResult> {
    const ranked = bm25Rank(issue, files);
    const stages: ("bm25" | "llm-rerank")[] = ["bm25"];
    if (!this.model || ranked.length === 0) {
      return { suspects: ranked.slice(0, k), stages };
    }

    // Stage 2: give the model the top candidate paths + skeletons, ask for a ranked selection + symbols.
    const pool = ranked.slice(0, this.opts.candidatePool ?? Math.max(k * 3, 10));
    const skeletons = pool.map((s) => {
      const file = files.find((f) => f.path === s.path)!;
      return `FILE: ${s.path}\nSYMBOLS: ${extractSymbols(file.content).join(", ") || "(none)"}`;
    }).join("\n\n");
    const prompt = [
      `Issue: ${issue.text}`,
      ``,
      `Candidate files (ranked by keyword match):`,
      skeletons,
      ``,
      `Return STRICT JSON: {"suspects":[{"path":"...","symbols":["fn1"]}]} — the ${k} most likely files to edit, most-likely first. Only paths from the candidates.`,
    ].join("\n");

    let selection: { path: string; symbols?: string[] }[] = [];
    try {
      const res = await this.model.generate({ prompt, maxTokens: 512 });
      selection = parseSelection(res.text);
      stages.push("llm-rerank");
    } catch {
      // Model failed → fall back to BM25 ranking (graceful, deterministic floor holds).
      return { suspects: ranked.slice(0, k), stages };
    }

    // Merge the LLM selection back onto the BM25-scored suspects (keep score for audit).
    const byPath = new Map(ranked.map((s) => [s.path, s]));
    const merged: SuspectFile[] = [];
    for (const sel of selection) {
      const base = byPath.get(sel.path);
      if (!base) continue; // model must only pick from candidates
      merged.push({ ...base, ...(sel.symbols && sel.symbols.length > 0 ? { suspectSymbols: sel.symbols } : {}) });
    }
    // If the model returned nothing usable, fall back to BM25.
    const suspects = merged.length > 0 ? merged.slice(0, k) : ranked.slice(0, k);
    return { suspects, stages };
  }
}

/** Extract top-level symbol names (functions/classes/consts) — language-agnostic-ish, zero-dep. */
export function extractSymbols(content: string): string[] {
  const names = new Set<string>();
  const patterns = [
    /(?:function|def)\s+([A-Za-z_][A-Za-z0-9_]*)/g,
    /class\s+([A-Za-z_][A-Za-z0-9_]*)/g,
    /(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=/g,
    /([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{/g,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) if (m[1]) names.add(m[1]);
  }
  return [...names].slice(0, 40);
}

function parseSelection(text: string): { path: string; symbols?: string[] }[] {
  const cleaned = text.replace(/```json/gi, "").replace(/```/g, "").trim();
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start === -1 || end === -1) return [];
  try {
    const obj = JSON.parse(cleaned.slice(start, end + 1)) as { suspects?: { path?: unknown; symbols?: unknown }[] };
    return (obj.suspects ?? [])
      .filter((s) => typeof s.path === "string")
      .map((s) => ({ path: s.path as string, ...(Array.isArray(s.symbols) ? { symbols: (s.symbols as unknown[]).filter((x): x is string => typeof x === "string") } : {}) }));
  } catch {
    return [];
  }
}
