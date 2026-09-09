/** Reproducible CPU-only retrieval comparison against Keep's former whole-text hash projection. */
import { createHash } from "node:crypto";
import { cosineSimilarity, type Embedding } from "../gateway/gateway.js";

export interface EmbeddingRetrievalPort { embed(texts: readonly string[]): Promise<Embedding[]>; }
export interface RetrievalComparisonCase {
  readonly id: string;
  readonly query: string;
  readonly documents: readonly string[];
  readonly relevantIndex: number;
}
export interface LocalRetrievalComparison {
  readonly cases: number;
  readonly candidateRecallAt1: number;
  readonly formerBaselineRecallAt1: number;
  readonly recallAt1Delta: number;
  readonly candidateWins: boolean;
  readonly perCase: readonly { readonly id: string; readonly candidateTop: number; readonly baselineTop: number; readonly relevantIndex: number }[];
}

export const LOCAL_RETRIEVAL_CASES: readonly RetrievalComparisonCase[] = Object.freeze([
  { id: "token-expiry", query: "validate expired tokens", documents: ["tokenValidator validates token expiration", "render dashboard colors"], relevantIndex: 0 },
  { id: "request-retry", query: "retry failed requests", documents: ["request retries after failures", "format invoice totals"], relevantIndex: 0 },
  { id: "project-archive", query: "projects are archived", documents: ["archiveProject stores archived projects", "rotate signing keys"], relevantIndex: 0 },
  { id: "database-migration", query: "running database migrations", documents: ["runDatabaseMigration migrates databases", "compress image assets"], relevantIndex: 0 },
]);

/** The superseded algorithm, retained solely as a frozen comparison baseline. */
export function formerWholeTextHash(text: string): Embedding {
  const vec = new Array<number>(64).fill(0);
  for (let round = 0; round < 4; round++) {
    const digest = createHash("sha256").update(`${round}:${text}`).digest();
    for (let i = 0; i < digest.length; i++) vec[i] = (vec[i] ?? 0) + (digest[i]! - 128) / 128;
  }
  const norm = Math.sqrt(vec.reduce((sum, value) => sum + value * value, 0)) || 1;
  return vec.map((value) => value / norm);
}

function top(query: Embedding, documents: readonly Embedding[]): number {
  let best = 0;
  for (let i = 1; i < documents.length; i++) if (cosineSimilarity(query, documents[i]!) > cosineSimilarity(query, documents[best]!)) best = i;
  return best;
}

export async function compareLocalRetrieval(port: EmbeddingRetrievalPort, cases: readonly RetrievalComparisonCase[] = LOCAL_RETRIEVAL_CASES): Promise<LocalRetrievalComparison> {
  if (cases.length === 0) throw new Error("retrieval comparison requires a fixed non-empty case set");
  if (new Set(cases.map((item) => item.id)).size !== cases.length || cases.some((item) => item.documents.length < 2 || !Number.isInteger(item.relevantIndex) || item.relevantIndex < 0 || item.relevantIndex >= item.documents.length)) throw new Error("malformed retrieval comparison denominator");
  let candidateHits = 0; let baselineHits = 0;
  const perCase = [] as { id: string; candidateTop: number; baselineTop: number; relevantIndex: number }[];
  for (const item of cases) {
    const embedded = await port.embed([item.query, ...item.documents]);
    if (embedded.length !== item.documents.length + 1) throw new Error("embedding backend returned an incomplete comparison result");
    const candidateTop = top(embedded[0]!, embedded.slice(1));
    const baselineTop = top(formerWholeTextHash(item.query), item.documents.map(formerWholeTextHash));
    if (candidateTop === item.relevantIndex) candidateHits++;
    if (baselineTop === item.relevantIndex) baselineHits++;
    perCase.push({ id: item.id, candidateTop, baselineTop, relevantIndex: item.relevantIndex });
  }
  const candidateRecallAt1 = candidateHits / cases.length;
  const formerBaselineRecallAt1 = baselineHits / cases.length;
  return Object.freeze({ cases: cases.length, candidateRecallAt1, formerBaselineRecallAt1, recallAt1Delta: candidateRecallAt1 - formerBaselineRecallAt1, candidateWins: candidateRecallAt1 > formerBaselineRecallAt1, perCase: Object.freeze(perCase) });
}
