/**
 * Deterministic offline fixture (PROVIDER_LOCAL) — the zero-dependency test floor.
 *
 * Network-free by construction (isLocal=true), so retrieval/learning and the
 * air-gapped swap-matrix config work with no external services. Embeddings are
 * deterministic (hash-projected) — good enough to exercise the loop offline and
 * to keep tests deterministic. A production deployment swaps in an Ollama/TEI
 * adapter (BGE-M3 / Qwen3-Embedding, Apache/MIT) behind the same ModelProvider
 * port — no domain code changes.
 *
 * Node built-ins only.
 */

import { createHash } from "node:crypto";
import type {
  ModelProvider,
  GenerateRequest,
  GenerateResult,
  Embedding,
  EmbeddingBackendInfo,
} from "./gateway.js";

const DIM = 384;

export class LocalProvider implements ModelProvider {
  readonly name = "offline-fixture";
  readonly isLocal = true;

  info(): EmbeddingBackendInfo {
    // Keep's own deterministic backend; permissive by definition.
    return { model: "keep-local-feature-hash-v1", license: "permissive", isLocal: true };
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    // Deterministic stub: echoes a summary. Real local models plug in here.
    const text = `[offline-fixture] ${req.prompt.slice(0, 120)}`;
    return {
      text,
      model: this.name,
      tokensIn: req.prompt.length,
      tokensOut: text.length,
    };
  }

  async embed(texts: readonly string[]): Promise<Embedding[]> {
    return texts.map((t) => localFeatureEmbed(t));
  }
}

/**
 * Deterministic CPU-only feature-hashing embedding. Related texts share word,
 * stem and character-ngram features, so cosine distance carries useful retrieval
 * signal without a model download. Stronger backends retain the same provider port.
 */
function localFeatureEmbed(text: string): Embedding {
  const vec = new Array<number>(DIM).fill(0);
  const expanded = text.replace(/([a-z\d])([A-Z])/g, "$1 $2").toLowerCase();
  const words = expanded.match(/[\p{L}\p{N}]+/gu) ?? [];
  for (const word of words) {
    addFeature(vec, `w:${word}`, 2);
    const stem = lightStem(word);
    if (stem !== word) addFeature(vec, `s:${stem}`, 1.5);
    if (word.length >= 4) {
      const padded = `^${word}$`;
      for (let i = 0; i <= padded.length - 3; i++) addFeature(vec, `c:${padded.slice(i, i + 3)}`, 0.35);
    }
  }
  let norm = 0;
  for (const v of vec) norm += v * v;
  norm = Math.sqrt(norm) || 1;
  return vec.map((v) => v / norm);
}

function addFeature(vec: number[], feature: string, weight: number): void {
  const digest = createHash("sha256").update(feature).digest();
  const bucket = digest.readUInt32BE(0) % DIM;
  const sign = (digest[4]! & 1) === 0 ? 1 : -1;
  vec[bucket] = (vec[bucket] ?? 0) + sign * weight;
}

function lightStem(word: string): string {
  if (word.length > 5 && word.endsWith("ies")) return `${word.slice(0, -3)}y`;
  for (const suffix of ["ingly", "edly", "ing", "ed", "es", "s"] as const) {
    if (word.length > suffix.length + 3 && word.endsWith(suffix)) {
      const stem = word.slice(0, -suffix.length);
      return /(.)\1$/.test(stem) ? stem.slice(0, -1) : stem;
    }
  }
  return word;
}
