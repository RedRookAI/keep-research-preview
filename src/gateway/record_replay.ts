/**
 * RecordingProvider + ReplayProvider (Increment 12c).
 *
 * SOTA basis (2026-08-05): record at the ModelProvider port so surrounding pipeline code genuinely
 * runs (sixty-north 2026). Strict replay throws on a cassette miss — the guarantee that a CI run
 * makes NO live model call (TianPan 2026: deterministic replay). Fallthrough replay records-if-absent
 * (the VCR new_episodes flow) so a cassette builds up on the first real run and replays after.
 *
 * These wrap any ModelProvider; they also support generateStream when the wrapped provider has it, so
 * streaming pipelines are deterministic too (recorded as ordered deltas). Zero deps.
 */

import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "./gateway.js";
import {
  Cassette,
  keyOf,
  normalizeGenerate,
  normalizeEmbed,
  type CassetteStore,
  type Interaction,
} from "./cassette.js";

/** A provider that may also stream (HttpProvider does). */
export interface StreamingProvider extends ModelProvider {
  generateStream?(req: GenerateRequest, onDelta?: (text: string) => void): Promise<GenerateResult>;
}

/**
 * Wraps a real provider: passes every call through to it, and records the interaction to the cassette
 * (persisted via the store). Never records secrets — only the normalized request → result.
 */
export class RecordingProvider implements StreamingProvider {
  readonly name: string;
  readonly isLocal: boolean;
  private cassette: Cassette | undefined;

  constructor(private readonly inner: StreamingProvider, private readonly store: CassetteStore) {
    this.name = `record:${inner.name}`;
    this.isLocal = inner.isLocal;
  }

  private async cass(): Promise<Cassette> {
    if (!this.cassette) this.cassette = await this.store.load();
    return this.cassette;
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    const result = await this.inner.generate(req);
    const norm = normalizeGenerate("generate", this.inner.name, req);
    await this.record({ kind: "generate", key: keyOf(norm), request: norm, generateResult: result });
    return result;
  }

  async embed(texts: readonly string[]): Promise<Embedding[]> {
    const result = await this.inner.embed(texts);
    const norm = normalizeEmbed(this.inner.name, texts);
    await this.record({ kind: "embed", key: keyOf(norm), request: norm, embedResult: result.map((v) => [...v]) });
    return result;
  }

  async generateStream(req: GenerateRequest, onDelta?: (text: string) => void): Promise<GenerateResult> {
    if (!this.inner.generateStream) throw new Error(`${this.inner.name} does not support streaming`);
    const deltas: string[] = [];
    const result = await this.inner.generateStream(req, (d) => { deltas.push(d); onDelta?.(d); });
    const norm = normalizeGenerate("stream", this.inner.name, req);
    await this.record({ kind: "stream", key: keyOf(norm), request: norm, generateResult: result, streamDeltas: deltas });
    return result;
  }

  private async record(interaction: Interaction): Promise<void> {
    const c = await this.cass();
    c.put(interaction);
    await this.store.save(c);
  }
}

export interface ReplayOptions {
  /**
   * strict (default): a cassette miss THROWS — guarantees no live model call in CI.
   * fallthrough: on a miss, delegate to `inner` and record it (requires `inner`).
   */
  readonly mode?: "strict" | "fallthrough";
  readonly inner?: StreamingProvider;
  /** Store to record into when in fallthrough mode. */
  readonly store?: CassetteStore;
  /**
   * The model name the cassette was recorded under. REQUIRED for strict replay without an `inner`,
   * so the request key matches how it was recorded (the recorder keys under the real provider name).
   */
  readonly modelName?: string;
}

/** Error thrown on a strict-mode cassette miss. */
export class CassetteMissError extends Error {
  constructor(readonly key: string, readonly kind: string) {
    super(`cassette miss (${kind}, key ${key}) in strict replay — no live model call permitted`);
    this.name = "CassetteMissError";
  }
}

/**
 * Serves recorded interactions from a cassette. In strict mode a miss throws (deterministic CI). In
 * fallthrough mode it delegates to a wrapped provider and records the new interaction.
 */
export class ReplayProvider implements StreamingProvider {
  readonly name = "replay";
  readonly isLocal = true; // replay makes no network egress — air-gap safe by construction

  private readonly mode: "strict" | "fallthrough";

  constructor(private readonly cassette: Cassette, private readonly opts: ReplayOptions = {}) {
    this.mode = opts.mode ?? "strict";
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    const modelName = this.wrappedName();
    const norm = normalizeGenerate("generate", modelName, req);
    const hit = this.cassette.get(keyOf(norm));
    if (hit?.generateResult) return hit.generateResult;
    return this.miss("generate", keyOf(norm), async () => {
      if (!this.opts.inner) throw new CassetteMissError(keyOf(norm), "generate");
      return this.opts.inner.generate(req);
    }, req);
  }

  async embed(texts: readonly string[]): Promise<Embedding[]> {
    const modelName = this.wrappedName();
    const norm = normalizeEmbed(modelName, texts);
    const hit = this.cassette.get(keyOf(norm));
    if (hit?.embedResult) return hit.embedResult.map((v) => [...v] as Embedding);
    if (this.mode === "strict" || !this.opts.inner) throw new CassetteMissError(keyOf(norm), "embed");
    const result = await this.opts.inner.embed(texts);
    await this.recordFallthrough({ kind: "embed", key: keyOf(norm), request: norm, embedResult: result.map((v) => [...v]) });
    return result;
  }

  async generateStream(req: GenerateRequest, onDelta?: (text: string) => void): Promise<GenerateResult> {
    const modelName = this.wrappedName();
    const norm = normalizeGenerate("stream", modelName, req);
    const hit = this.cassette.get(keyOf(norm));
    if (hit?.generateResult) {
      // Re-emit recorded deltas so streaming consumers behave identically.
      for (const d of hit.streamDeltas ?? []) onDelta?.(d);
      return hit.generateResult;
    }
    if (this.mode === "strict" || !this.opts.inner?.generateStream) throw new CassetteMissError(keyOf(norm), "stream");
    const deltas: string[] = [];
    const result = await this.opts.inner.generateStream(req, (d) => { deltas.push(d); onDelta?.(d); });
    await this.recordFallthrough({ kind: "stream", key: keyOf(norm), request: norm, generateResult: result, streamDeltas: deltas });
    return result;
  }

  private async miss(kind: "generate", key: string, live: () => Promise<GenerateResult>, req: GenerateRequest): Promise<GenerateResult> {
    if (this.mode === "strict" || !this.opts.inner) throw new CassetteMissError(key, kind);
    const result = await live();
    const norm = normalizeGenerate("generate", this.opts.inner.name, req);
    await this.recordFallthrough({ kind: "generate", key: keyOf(norm), request: norm, generateResult: result });
    return result;
  }

  private async recordFallthrough(interaction: Interaction): Promise<void> {
    this.cassette.put(interaction);
    if (this.opts.store) await this.opts.store.save(this.cassette);
  }

  private wrappedName(): string {
    // Strict replay resolves the model name from the explicit option (recorded-under name), falling
    // back to inner's name in fallthrough mode. Throws if neither is available, rather than keying
    // under a wrong "unknown" name that would silently miss every cassette entry.
    const name = this.opts.modelName ?? this.opts.inner?.name;
    if (!name) throw new Error("ReplayProvider needs `modelName` (the name the cassette was recorded under) for strict replay");
    return name;
  }
}
