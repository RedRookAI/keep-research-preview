/**
 * Model gateway port (Phase 0.5) — fixes coupling-bugs #2 (embedding path) and
 * #4 (fitness model routing) from the swappability vetting.
 *
 * Root cause of those bugs: domain code (retrieval, fitness) hardcoded a concrete
 * provider (OpenRouter / the claw's model config), so swapping the provider broke
 * retrieval/learning and air-gap. Fix: ALL model-bound work goes through this one
 * port; the concrete provider is injected at the composition root from policy.
 *
 * Air-gap requirement (coupling-fix #2): a local embedding backend must exist so
 * retrieval/learning work offline.
 *
 * LICENSING POLICY (SOTA, Aug 2026 — verified): the default *local* embedding
 * backend MUST be a permissively-licensed model (Apache-2.0 / MIT — e.g. BGE-M3,
 * Qwen3-Embedding). Models under CC-BY-NC (e.g. NV-Embed-v2, jina-embeddings-v3/v4)
 * are NOT usable commercially and must never be the default. This mirrors Keep's
 * own license-SCA discipline (Round 20).
 */

/** A vector embedding. */
import type { BoundedEmbeddingOptions, BoundedEmbeddingResult } from "./http_provider.js";

export type Embedding = readonly number[];

export interface GenerateRequest {
  readonly prompt: string;
  readonly maxTokens?: number;
  readonly signal?: AbortSignal;
  /** Opaque routing hints (e.g. difficulty tier); interpreted by the adapter. */
  readonly hints?: Readonly<Record<string, unknown>>;
}

export interface GenerateResult {
  readonly text: string;
  readonly model: string;
  readonly tokensIn: number;
  readonly tokensOut: number;
  /** Provider route actually reported by an aggregator. Absent for direct/local providers. */
  readonly providerRoute?: string;
}

/** A model provider adapter. Injected at the composition root; never imported by domain code. */
export interface ModelProvider {
  readonly name: string;
  /** True if this provider needs no network egress (air-gap / sovereignty safe). */
  readonly isLocal: boolean;
  generate(req: GenerateRequest): Promise<GenerateResult>;
  /** OPTIONAL streaming: emit each text delta via onDelta; resolve with the assembled full result. Providers without
   *  this fall back to non-streaming (opt-in). The router pipes deltas through the egress rehydrator on the remote path. */
  generateStream?(req: GenerateRequest, onDelta?: (text: string) => void): Promise<GenerateResult>;
  embed(texts: readonly string[]): Promise<Embedding[]>;
  /** Optional governed bounded transport. Absence never falls back to unmetered embed. */
  embedBounded?(texts: readonly string[], options: BoundedEmbeddingOptions): Promise<BoundedEmbeddingResult>;
}

/** Commercial-use license classes for embedding backends (SOTA licensing gate). */
export type LicenseClass = "permissive" | "non-commercial" | "unknown";

export interface EmbeddingBackendInfo {
  readonly model: string;
  readonly license: LicenseClass;
  readonly isLocal: boolean;
}

/**
 * The model gateway: the single seam all model-bound work flows through.
 * Domain code (retrieval, fitness, dreaming) depends on THIS, never a provider.
 */
export class ModelGateway {
  constructor(private readonly provider: ModelProvider) {}

  get providerName(): string {
    return this.provider.name;
  }

  get isLocal(): boolean {
    return this.provider.isLocal;
  }

  generate(req: GenerateRequest): Promise<GenerateResult> {
    return this.provider.generate(req);
  }

  /** Embeddings for retrieval/learning — the path that was hardcoded (fix #2). */
  embed(texts: readonly string[]): Promise<Embedding[]> {
    return this.provider.embed(texts);
  }

  embedBounded(texts: readonly string[], options: BoundedEmbeddingOptions): Promise<BoundedEmbeddingResult> {
    if (!this.provider.embedBounded) throw new Error("bounded embedding is unavailable; no unmetered fallback");
    return this.provider.embedBounded(texts, options);
  }

  /** Fitness scoring routes through the gateway too (fix #4), not the claw config. */
  async fitnessScore(candidate: string, reference: string): Promise<number> {
    const [a, b] = await this.provider.embed([candidate, reference]);
    if (!a || !b) throw new Error("embedding backend returned no vectors");
    return cosineSimilarity(a, b);
  }

  /**
   * Guard: reject a non-commercial embedding backend as a *default* (Aug-2026
   * licensing rule). An operator may explicitly opt in for non-commercial use.
   */
  static assertUsableDefault(info: EmbeddingBackendInfo): void {
    if (info.license === "non-commercial") {
      throw new Error(
        `embedding model "${info.model}" is non-commercial (CC-BY-NC) and cannot be ` +
          `the default backend; choose a permissive (Apache/MIT) model such as BGE-M3 ` +
          `or Qwen3-Embedding, or explicitly opt in for non-commercial use`,
      );
    }
  }
}

export function cosineSimilarity(a: Embedding, b: Embedding): number {
  if (a.length !== b.length) throw new Error("embedding dimension mismatch");
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    const ai = a[i]!;
    const bi = b[i]!;
    dot += ai * bi;
    na += ai * ai;
    nb += bi * bi;
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}
