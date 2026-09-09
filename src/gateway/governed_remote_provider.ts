import type { Embedding, GenerateRequest, GenerateResult, ModelProvider } from "./gateway.js";
import { EgressDeniedError } from "./brokered_egress.js";
import type { ResidencyEnforcer } from "../governance/residency.js";
import type { EgressPrompt, EgressResult } from "../privacy/egress_interceptor.js";
import type { BoundedEmbeddingOptions, BoundedEmbeddingResult } from "./http_provider.js";

export interface RemoteProcessingDeclaration {
  readonly purpose: string;
  readonly region: string;
}
export type EmbeddingProcessingDeclaration = Readonly<Record<"query" | "document", RemoteProcessingDeclaration>>;

export type RemotePromptPrivacy = (prompt: EgressPrompt, provider: { readonly isLocal: false }) => EgressResult;
export type RemoteDefenseGate = (operation: "provider.generate" | "provider.embed", context: Readonly<Record<string, string>>) => { readonly allowed: boolean; readonly reason?: string };

/** Final policy wrapper around an already brokered remote provider. */
export class GovernedRemoteProvider implements ModelProvider {
  readonly name: string;
  readonly isLocal = false;

  readonly #inner: ModelProvider;
  readonly #residency: ResidencyEnforcer;
  readonly #host: string;
  readonly #declaration: RemoteProcessingDeclaration | undefined;
  readonly #privacy: RemotePromptPrivacy;
  readonly #defenseGate: RemoteDefenseGate;
  readonly #embeddingDeclaration: EmbeddingProcessingDeclaration | undefined;
  readonly #embeddingRepresentationIdentity: string | undefined;

  constructor(
    inner: ModelProvider,
    residency: ResidencyEnforcer,
    host: string,
    declaration: RemoteProcessingDeclaration | undefined,
    privacy: RemotePromptPrivacy,
    defenseGate: RemoteDefenseGate,
    embeddingDeclaration?: EmbeddingProcessingDeclaration,
    embeddingRepresentationIdentity?: string,
  ) {
    if (inner.isLocal) throw new Error("governed remote provider requires a remote transport");
    this.#inner = inner;
    this.#residency = residency;
    this.#host = host;
    this.#declaration = declaration === undefined
      ? undefined
      : Object.freeze({ purpose: declaration.purpose, region: declaration.region });
    this.#privacy = privacy;
    this.#defenseGate = defenseGate;
    this.#embeddingDeclaration = embeddingDeclaration === undefined ? undefined : Object.freeze({
      query: Object.freeze({ ...embeddingDeclaration.query }), document: Object.freeze({ ...embeddingDeclaration.document }),
    });
    if (embeddingRepresentationIdentity !== undefined && (!embeddingDeclaration ||
      !/^keep\.embedding-surrogates\/v1:[a-p]{32}$/u.test(embeddingRepresentationIdentity))) throw new Error("invalid host embedding representation identity");
    this.#embeddingRepresentationIdentity = embeddingRepresentationIdentity;
    this.name = `governed-remote(${inner.name})`;
  }

  #admit(operation: "provider.generate" | "provider.embed", declaration = this.#declaration, role?: "query" | "document"): void {
    if (!declaration) throw new EgressDeniedError("remote processing purpose and region are not declared");
    const decision = this.#residency.checkRemoteRequest(declaration.purpose, declaration.region, this.#host);
    if (!decision.allowed) throw new EgressDeniedError(decision.reason);
    const defense = this.#defenseGate(operation, { host: this.#host, purpose: declaration.purpose, region: declaration.region, ...(role === undefined ? {} : { role }) });
    if (!defense.allowed) throw new EgressDeniedError(defense.reason ?? `active observed-failure defense denied ${operation}`);
  }

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    return await this.#generateSafe(req);
  }

  async #generateSafe(req: GenerateRequest): Promise<GenerateResult> {
    this.#admit("provider.generate");
    const requestedSplit = req.hints?.["stablePrefixLen"];
    const splitAt = typeof requestedSplit === "number" && Number.isFinite(requestedSplit)
      ? Math.max(0, Math.min(req.prompt.length, Math.trunc(requestedSplit)))
      : 0;
    const privacy = this.#privacy({ stablePrefix: req.prompt.slice(0, splitAt), volatile: req.prompt.slice(splitAt) }, this);
    if (privacy.blocked) throw new EgressDeniedError(privacy.reason ?? "remote prompt privacy boundary denied dispatch");
    const result = await this.#inner.generate({ ...req, prompt: privacy.outbound });
    const restored = privacy.rehydrate(result.text);
    const scan = privacy.inspect(restored, { blockOnNovelSecret: true });
    if (scan.blockRecommended) throw new EgressDeniedError(scan.reason ?? "remote output privacy boundary withheld response");
    return { ...result, text: restored };
  }

  /** A remote stream is buffered behind the complete output verdict; unsafe partial output is never observable. */
  async generateStream(req: GenerateRequest, onDelta?: (text: string) => void): Promise<GenerateResult> {
    const safe = await this.#generateSafe(req);
    if (safe.text.length > 0) onDelta?.(safe.text);
    return safe;
  }

  async embed(texts: readonly string[]): Promise<Embedding[]> {
    this.#admit("provider.embed");
    const outbound = texts.map((text) => {
      const privacy = this.#privacy({ stablePrefix: "", volatile: text }, this);
      if (privacy.blocked) throw new EgressDeniedError(privacy.reason ?? "remote embedding privacy boundary denied dispatch");
      return privacy.outbound;
    });
    return await this.#inner.embed(outbound);
  }

  async embedBounded(texts: readonly string[], options: BoundedEmbeddingOptions): Promise<BoundedEmbeddingResult> {
    const role = options.role;
    if ((role !== "query" && role !== "document") || !this.#embeddingDeclaration) throw new EgressDeniedError("bounded embedding requires explicit query/document processing declarations");
    if (!this.#inner.embedBounded) throw new EgressDeniedError("bounded embedding unavailable; no unmetered fallback");
    const declaration = this.#embeddingDeclaration[role];
    this.#admit("provider.embed", declaration, role);
    if (!Array.isArray(texts) || texts.length > 65_536) throw new EgressDeniedError("invalid bounded embedding inputs");
    let bytes = 0;
    const outbound = texts.map(text => {
      if (typeof text !== "string" || !text || (bytes += Buffer.byteLength(text)) > 4_194_304) throw new EgressDeniedError("invalid bounded embedding windows");
      const privacy = this.#privacy({ stablePrefix: "", volatile: text }, this);
      if (privacy.blocked) throw new EgressDeniedError("remote embedding privacy boundary denied dispatch");
      // Only the host-composed task capability may pin a shared representation.
      // Untagged legacy per-call redaction still cannot support semantic ranking.
      if (this.#embeddingRepresentationIdentity !== undefined) {
        if (privacy.representationIdentity !== this.#embeddingRepresentationIdentity) throw new EgressDeniedError("embedding transformation identity changed");
      } else if (privacy.outbound !== text) throw new EgressDeniedError("embedding transformation identity is unavailable");
      return privacy.outbound;
    });
    const assertCallerAuthority = options.assertAuthority;
    return this.#inner.embedBounded(outbound, { ...options, role, assertAuthority: () => {
      this.#admit("provider.embed", declaration, role);
      assertCallerAuthority?.();
    } });
  }
}
