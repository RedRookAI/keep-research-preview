/** Explicit encoder configuration; never inherits chat credentials, routes or consent. */
import { isAbsolute, resolve } from "node:path";
import { types } from "node:util";
import { captureRemoteProviderDescriptor, captureSemanticEncoderContract, type SemanticEncoderContract } from "../gateway/provider_descriptor.js";
import type { EmbeddingProcessingDeclaration } from "../gateway/governed_remote_provider.js";
import type { EmbeddingWork } from "../solve/recovery_budget.js";
import type { KeepConfig } from "../compose.js";
import type { CredentialReference } from "./runtime_config.js";
import { readProtectedProfile, writeProtectedProfile } from "./provider_profile.js";

export const ENCODER_PROFILE_SCHEMA = "keep.encoder-profile/v1";
export interface EncoderProfile {
  readonly schema: typeof ENCODER_PROFILE_SCHEMA;
  readonly name: string;
  readonly authority: "owner" | "organization";
  readonly location: "local" | "external";
  readonly protocol: "openai-compatible";
  readonly endpoint: string;
  readonly model: string;
  readonly credential: { readonly kind: "environment" } | { readonly kind: "file"; readonly path: string } | { readonly kind: "stdin" } | null;
  readonly contract: SemanticEncoderContract;
  readonly processing: EmbeddingProcessingDeclaration;
  readonly limits: EmbeddingWork;
  readonly routing?: { readonly providers: readonly string[] };
  readonly release?: { readonly bundlePath: string; readonly trustRootPath: string };
}

function object(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || types.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`encoder profile ${label} must be inert data`);
  if (Reflect.ownKeys(value).some(key => typeof key !== "string" || !keys.includes(key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !("value" in d) || !d.enumerable)) throw new Error(`encoder profile ${label} contains unknown or non-data fields`);
  return value as Record<string, unknown>;
}
function text(value: unknown, label: string): string {
  if (typeof value !== "string" || !value || value !== value.trim() || value.includes("\0") || Buffer.byteLength(value) > 8192) throw new Error(`encoder profile ${label} is malformed`);
  return value;
}
function absolute(value: unknown, label: string): string {
  const path = text(value, label); if (!isAbsolute(path)) throw new Error(`encoder profile ${label} must be absolute`); return path;
}
function positive(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) throw new Error(`encoder profile ${label} must be a positive safe integer`); return value;
}

export function parseEncoderProfile(value: unknown): EncoderProfile {
  const raw = object(value, ["schema", "name", "authority", "location", "protocol", "endpoint", "model", "credential", "contract", "processing", "limits", "routing", "release"], "root");
  if (raw["schema"] !== ENCODER_PROFILE_SCHEMA) throw new Error(`encoder profile schema must be ${ENCODER_PROFILE_SCHEMA}`);
  const name = text(raw["name"], "name"), authority = raw["authority"], location = raw["location"];
  if (authority !== "owner" && authority !== "organization") throw new Error("encoder profile authority must be owner or organization");
  if (location !== "local" && location !== "external") throw new Error("encoder profile location must be local or external");
  if (raw["protocol"] !== "openai-compatible") throw new Error("encoder profile requires the built-in OpenAI-compatible embedding protocol");
  const descriptor = captureRemoteProviderDescriptor({ mode: raw["protocol"], baseUrl: raw["endpoint"], model: raw["model"], apiKey: "configuration-validation-only" });
  const contract = captureSemanticEncoderContract(raw["contract"] as SemanticEncoderContract);
  const roles = object(raw["processing"], ["query", "document"], "processing");
  const role = (name: "query" | "document") => { const p = object(roles[name], ["purpose", "region"], `processing.${name}`); return Object.freeze({ purpose: text(p["purpose"], `${name}.purpose`), region: text(p["region"], `${name}.region`) }); };
  const processing = Object.freeze({ query: role("query"), document: role("document") });
  const work = object(raw["limits"], ["requests", "inputBytes", "windows"], "limits");
  const limits = Object.freeze({ requests: positive(work["requests"], "limits.requests"), inputBytes: positive(work["inputBytes"], "limits.inputBytes"), windows: positive(work["windows"], "limits.windows") });
  let credential: EncoderProfile["credential"];
  if (raw["credential"] === null) {
    const host = new URL(descriptor.baseUrl).hostname;
    if (authority !== "owner" || location !== "local" || !["localhost", "127.0.0.1", "[::1]"].includes(host)) throw new Error("only owner/local loopback encoders may omit credentials");
    credential = null;
  } else {
    const c = object(raw["credential"], ["kind", "path"], "credential");
    if (c["kind"] === "file") credential = Object.freeze({ kind: "file", path: absolute(c["path"], "credential.path") });
    else {
      if ((c["kind"] !== "environment" && c["kind"] !== "stdin") || Object.keys(c).some(key => key !== "kind")) throw new Error("encoder profile credential must be an environment, file or stdin reference");
      credential = Object.freeze({ kind: c["kind"] });
    }
  }
  let routing: EncoderProfile["routing"];
  if (raw["routing"] !== undefined) {
    const r = object(raw["routing"], ["providers"], "routing"), providers = r["providers"];
    if (location !== "external" || !Array.isArray(providers) || providers.length < 1 || providers.length > 32 || providers.some(p => typeof p !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$/u.test(p))) throw new Error("encoder profile routing requires a bounded external provider allowlist");
    routing = Object.freeze({ providers: Object.freeze([...providers] as string[]) });
  }
  let release: EncoderProfile["release"];
  if (raw["release"] !== undefined) { const r = object(raw["release"], ["bundlePath", "trustRootPath"], "release"); release = Object.freeze({ bundlePath: absolute(r["bundlePath"], "release.bundlePath"), trustRootPath: absolute(r["trustRootPath"], "release.trustRootPath") }); }
  if ((authority === "organization") !== (release !== undefined)) throw new Error("organization encoder requires its own release references; owner encoder cannot use release authority");
  return Object.freeze({ schema: ENCODER_PROFILE_SCHEMA, name, authority, location, protocol: "openai-compatible", endpoint: descriptor.baseUrl, model: descriptor.model, credential, contract, processing, limits, ...(routing ? { routing } : {}), ...(release ? { release } : {}) });
}

export function loadEncoderProfile(path: string): EncoderProfile { return parseEncoderProfile(readProtectedProfile(path, "encoder profile")); }
export function writeEncoderProfile(path: string, profile: EncoderProfile): void { writeProtectedProfile(path, parseEncoderProfile(profile)); }

export function encoderCredentialReference(profile: EncoderProfile, env: Readonly<Record<string, string | undefined>>): CredentialReference | undefined {
  const credential = profile.credential, value = env["KEEP_ENCODER_API_KEY"];
  if (credential?.kind !== "environment" && value !== undefined) throw new Error("KEEP_ENCODER_API_KEY conflicts with the encoder profile credential reference");
  if (credential?.kind === "environment") {
    if (!value || value !== value.trim() || value.includes("\0") || Buffer.byteLength(value) > 8192) throw new Error("encoder profile requires a valid KEEP_ENCODER_API_KEY; chat credentials are not inherited");
    return Object.freeze({ kind: "environment", name: "KEEP_ENCODER_API_KEY" });
  }
  return credential ?? undefined;
}

export function encoderProfileDescriptor(profile: EncoderProfile, credential: string | undefined) {
  if (!credential && profile.credential !== null) throw new Error("encoder credential is empty");
  return captureRemoteProviderDescriptor({ mode: profile.protocol, baseUrl: profile.endpoint, model: profile.model, apiKey: credential ?? "keep-owner-local-no-token" });
}

export function configuredSemanticEncoder(profile: EncoderProfile, credential: string | undefined, verifiedRelease?: NonNullable<KeepConfig["semanticEncoder"]>["verifiedRelease"]): NonNullable<KeepConfig["semanticEncoder"]> {
  if ((profile.authority === "organization") !== (verifiedRelease !== undefined)) throw new Error("encoder configuration requires its own matching release admission");
  return { authority: profile.authority, provider: encoderProfileDescriptor(profile, credential), contract: profile.contract, processing: profile.processing, limits: profile.limits,
    ...(profile.routing ? { externalRouting: { providers: profile.routing.providers, zeroDataRetention: true, dataCollection: "deny", allowFallbacks: false } } : {}),
    ...(verifiedRelease ? { verifiedRelease } : {}) };
}

/** Strict CLI flags deliberately accept references, never a credential value. */
export function encoderProfileFromArgs(args: readonly string[], cwd: string): { path: string; profile: EncoderProfile } {
  const allowed = ["profile", "name", "authority", "location", "endpoint", "model", "revision", "dimension", "query-prefix", "document-prefix", "query-purpose", "document-purpose", "region", "requests", "input-bytes", "windows", "credential", "credential-file", "providers", "release-bundle", "release-trust-root"];
  const fields = new Map<string, string>();
  for (const arg of args) { const m = /^--([a-z][a-z-]*)=(.*)$/su.exec(arg); if (!m || !allowed.includes(m[1]!) || fields.has(m[1]!)) throw new Error("invalid, unknown or duplicate encoder option (see docs/semantic-memory.md)"); fields.set(m[1]!, m[2]!); }
  const get = (name: string) => { const value = fields.get(name); if (value === undefined) throw new Error(`--${name}=... is required`); return value; };
  const integer = (name: string) => { const value = get(name); if (!/^[1-9][0-9]*$/u.test(value)) throw new Error(`--${name} must be a positive integer`); return Number(value); };
  const kind = get("credential");
  if (!["none", "environment", "file", "stdin"].includes(kind) || (kind === "file") !== fields.has("credential-file")) throw new Error("encoder credential must be none, environment, file or stdin; only file accepts --credential-file");
  const hasRelease = fields.has("release-bundle") || fields.has("release-trust-root");
  const profile = parseEncoderProfile({ schema: ENCODER_PROFILE_SCHEMA, name: get("name"), authority: get("authority"), location: get("location"), protocol: "openai-compatible", endpoint: get("endpoint"), model: get("model"),
    credential: kind === "none" ? null : kind === "file" ? { kind, path: get("credential-file") } : { kind },
    contract: { modelRevision: get("revision"), dimension: integer("dimension"), queryPrefix: get("query-prefix"), documentPrefix: get("document-prefix") },
    processing: { query: { purpose: get("query-purpose"), region: get("region") }, document: { purpose: get("document-purpose"), region: get("region") } },
    limits: { requests: integer("requests"), inputBytes: integer("input-bytes"), windows: integer("windows") },
    ...(fields.has("providers") ? { routing: { providers: get("providers").split(",") } } : {}),
    ...(hasRelease ? { release: { bundlePath: get("release-bundle"), trustRootPath: get("release-trust-root") } } : {}) });
  return { path: resolve(cwd, get("profile")), profile };
}
