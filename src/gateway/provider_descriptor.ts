/** Inert, closed remote-provider configuration. Only this exact data crosses A4 boot; arbitrary factories never do. */
import { HttpProvider } from "./http_provider.js";
import type { ModelProvider } from "./gateway.js";
import { anthropicDialect, openAiDialect, openAiDialectWithRouting, type ExternalRoutingPolicy } from "./wire_dialect.js";
import { types } from "node:util";
import { eirDigest } from "../eir/canonical.js";

export interface RemoteProviderDescriptor { readonly mode: "openai-compatible" | "anthropic-compatible"; readonly baseUrl: string; readonly model: string; readonly apiKey: string; }
/** Declared representation contract, not proof of the endpoint's actual weights.
 * Prefixes are sent verbatim before query/document text; no vendor role is inferred. */
export interface SemanticEncoderContract {
  readonly modelRevision: string;
  readonly dimension: number;
  readonly queryPrefix: string;
  readonly documentPrefix: string;
}
export function captureSemanticEncoderContract(input: SemanticEncoderContract): SemanticEncoderContract {
  if (!input || typeof input !== "object" || types.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Reflect.ownKeys(input).map(String).sort().join(",") !== "dimension,documentPrefix,modelRevision,queryPrefix" ||
      Object.values(Object.getOwnPropertyDescriptors(input)).some(d => !("value" in d) || !d.enumerable)) throw new ProviderDescriptorError("embedding contract must be exact inert data");
  if (typeof input.modelRevision !== "string" || !input.modelRevision.trim() || Buffer.byteLength(input.modelRevision) > 1024 ||
      !Number.isSafeInteger(input.dimension) || input.dimension < 1 || input.dimension > 8192 ||
      ![input.queryPrefix, input.documentPrefix].every(value => typeof value === "string" && Buffer.byteLength(value) <= 4096 && !value.includes("\0"))) throw new ProviderDescriptorError("invalid declared embedding representation contract");
  return Object.freeze({ modelRevision: input.modelRevision, dimension: input.dimension, queryPrefix: input.queryPrefix, documentPrefix: input.documentPrefix });
}
const constructedProviderIdentities = new WeakMap<object, string>();
export class ProviderDescriptorError extends Error { constructor(message: string) { super(`remote provider descriptor: ${message}`); this.name = "ProviderDescriptorError"; } }
const safeText = (value: unknown, label: string, secret = false): string => { if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > 8_192 || value.includes("\0") || (!secret && value.trim() !== value)) throw new ProviderDescriptorError(`${label} is malformed`); return value; };

export function captureRemoteProviderDescriptor(input: unknown): RemoteProviderDescriptor {
  if (input === null || typeof input !== "object" || types.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) throw new ProviderDescriptorError("must be plain inert data");
  const ownKeys = Reflect.ownKeys(input); if (ownKeys.some((key) => typeof key !== "string") || [...ownKeys as string[]].sort().join(",") !== "apiKey,baseUrl,mode,model") throw new ProviderDescriptorError("keys must be exactly apiKey,baseUrl,mode,model");
  const descriptors = Object.getOwnPropertyDescriptors(input); if (Object.values(descriptors).some((descriptor) => descriptor.get !== undefined || descriptor.set !== undefined || descriptor.enumerable !== true || !("value" in descriptor))) throw new ProviderDescriptorError("must contain only enumerable data properties");
  const value = (key: "mode" | "baseUrl" | "model" | "apiKey"): unknown => descriptors[key]!.value;
  const mode = value("mode"); if (mode !== "openai-compatible" && mode !== "anthropic-compatible") throw new ProviderDescriptorError("mode is unsupported");
  const baseUrl = safeText(value("baseUrl"), "baseUrl"); let url: URL; try { url = new URL(baseUrl); } catch { throw new ProviderDescriptorError("baseUrl is not an absolute URL"); }
  if (url.username || url.password || url.search || url.hash) throw new ProviderDescriptorError("baseUrl contains credentials, query, or fragment");
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "localhost"; if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) throw new ProviderDescriptorError("baseUrl must use HTTPS except canonical loopback");
  return Object.freeze({ mode, baseUrl: url.toString().replace(/\/$/, ""), model: safeText(value("model"), "model"), apiKey: safeText(value("apiKey"), "apiKey", true) });
}

/** Constructors are audited built-ins and side-effect-free; network remains behind methods owned by brokered egress. */
export function constructCapturedRemoteProvider(descriptor: RemoteProviderDescriptor, routing?: ExternalRoutingPolicy): ModelProvider {
  const d = captureRemoteProviderDescriptor(descriptor); const provider = new HttpProvider({ baseUrl: d.baseUrl, model: d.model, apiKey: d.apiKey, dialect: d.mode === "anthropic-compatible" ? anthropicDialect : routing ? openAiDialectWithRouting(routing) : openAiDialect });
  constructedProviderIdentities.set(provider, remoteProviderIdentityDigest(d)); return provider;
}
/** Credential bytes are deliberately excluded; A8 binds a non-secret custody/key reference. */
export function remoteProviderIdentityDigest(descriptor: RemoteProviderDescriptor): string { const d = captureRemoteProviderDescriptor(descriptor); return eirDigest("keep.remote-provider-identity/v1", { mode: d.mode, baseUrl: d.baseUrl, model: d.model }); }
/** Returns identity only for a provider constructed by the audited built-in descriptor path. */
export function constructedRemoteProviderIdentity(provider: ModelProvider): string | undefined { return constructedProviderIdentities.get(provider as object); }
