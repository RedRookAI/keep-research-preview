/**
 * Cassette + store for record/replay (Increment 12c).
 *
 * SOTA basis (2026-08-05): the VCR/cassette pattern is the established standard for deterministic,
 * zero-cost LLM testing (Docker cagent, LangChain, Agiflow 2026). The decisive refinement (sixty-
 * north/langchain-replay 2026): record the model's DECISIONS at the client/port level, NOT the HTTP
 * bytes — an HTTP-level cassette "freezes the entire agent loop; your tools never execute; the test
 * verifies the recording is valid, not that your code is correct." So Keep records at the
 * ModelProvider port (generate/embed/stream), and all surrounding pipeline code (retrieval, patch,
 * validation) genuinely runs against replayed model outputs.
 *
 * Security (cagent/LangChain): cassettes must never leak secrets. Because we record at the port level,
 * a cassette holds only the normalized request (prompt/maxTokens/hints) → result — never API keys or
 * auth headers. Keying is a stable content hash of the normalized request, so replay matches
 * deterministically. Zero deps (node:crypto for the hash).
 */

import { createHash } from "node:crypto";
import type { GenerateRequest, GenerateResult, Embedding } from "./gateway.js";
export type InteractionKind = "generate" | "embed" | "stream";

/** One recorded interaction: the normalized request key + the recorded result. */
export interface Interaction {
  readonly kind: InteractionKind;
  /** The content hash of the normalized request (the cassette key). */
  readonly key: string;
  /** Human-readable echo of the request, for debugging cassettes (never contains secrets). */
  readonly request: Record<string, unknown>;
  /** Recorded generate/stream result (text/model/tokens) — present for generate|stream. */
  readonly generateResult?: GenerateResult;
  /** For stream: the ordered text deltas, so replay can re-emit them. */
  readonly streamDeltas?: readonly string[];
  /** Recorded embeddings — present for embed. */
  readonly embedResult?: readonly (readonly number[])[];
}

/** Normalize a generate request into a stable, secret-free object for hashing. */
export function normalizeGenerate(kind: InteractionKind, model: string, req: GenerateRequest): Record<string, unknown> {
  return {
    kind,
    model,
    prompt: req.prompt,
    maxTokens: req.maxTokens ?? null,
    hints: req.hints ? stableSort(req.hints as Record<string, unknown>) : null,
  };
}

/** Normalize an embed request. */
export function normalizeEmbed(model: string, texts: readonly string[]): Record<string, unknown> {
  return { kind: "embed", model, texts: [...texts] };
}

/** Content-address a normalized request object → the cassette key. */
export function keyOf(normalized: Record<string, unknown>): string {
  const canonical = JSON.stringify(normalized, Object.keys(normalized).sort());
  return "cx_" + createHash("sha256").update(canonical).digest("hex").slice(0, 40);
}

function stableSort(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) out[k] = obj[k];
  return out;
}

/** A cassette: keyed interactions, serializable to/from JSON. */
export class Cassette {
  private readonly map = new Map<string, Interaction>();

  static fromJSON(json: string): Cassette {
    const c = new Cassette();
    const parsed = JSON.parse(json) as { interactions?: Interaction[] };
    for (const i of parsed.interactions ?? []) c.map.set(i.key, i);
    return c;
  }

  toJSON(): string {
    return JSON.stringify({ interactions: [...this.map.values()] }, null, 2);
  }

  get(key: string): Interaction | undefined {
    return this.map.get(key);
  }

  put(interaction: Interaction): void {
    this.map.set(interaction.key, interaction);
  }

  get size(): number {
    return this.map.size;
  }

  keys(): string[] {
    return [...this.map.keys()];
  }
}

/** Persistence seam for cassettes (in-memory for tests; file-backed for fixtures). */
export interface CassetteStore {
  load(): Promise<Cassette>;
  save(cassette: Cassette): Promise<void>;
}

/** In-memory store — holds a cassette instance directly. */
export class InMemoryCassetteStore implements CassetteStore {
  constructor(private cassette = new Cassette()) {}
  async load(): Promise<Cassette> { return this.cassette; }
  async save(cassette: Cassette): Promise<void> { this.cassette = cassette; }
}

/** File-backed store — persists the cassette JSON to a path (fixtures committed to the repo). */
export class FileCassetteStore implements CassetteStore {
  constructor(private readonly path: string, private readonly fs: { readFile: (p: string, enc: "utf8") => Promise<string>; writeFile: (p: string, data: string) => Promise<void> }) {}
  async load(): Promise<Cassette> {
    try { return Cassette.fromJSON(await this.fs.readFile(this.path, "utf8")); }
    catch { return new Cassette(); }
  }
  async save(cassette: Cassette): Promise<void> {
    await this.fs.writeFile(this.path, cassette.toJSON());
  }
}

