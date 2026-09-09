/**
 * Theme 5c (No-Account Local Defaults), Part 2 — local-first defaults resolver.
 *
 * A fresh Keep must be usable with ZERO external accounts and no cloud signup. This
 * resolver decides how a new install boots: probe for a LOCAL OpenAI-compatible endpoint
 * (the 2026 standard — Ollama :11434, LM Studio :1234, Jan :1337, GPT4All :4891, all
 * no-account and OpenAI-compatible); if found, point Keep at it (fully local, offline);
 * if not, boot in deterministic-fallback mode (the no-model reversible-internal
 * capabilities still work) and tell the operator how to add a local model — never
 * demanding an account or a cloud key.
 *
 * The probe is injected so core has no network dependency. Zero deps.
 */

import type { BrainDescriptor } from "./brain_port.js";

export interface LocalEndpoint {
  readonly name: string;
  readonly baseURL: string;
  /** Default model id hint (operator can override). */
  readonly modelHint?: string;
  readonly asOf: string;
}

/** Known local, no-account, OpenAI-compatible endpoints (dated; refreshable). */
const KNOWN_LOCAL_ENDPOINTS_AS_OF = "2026-08-01";
export const KNOWN_LOCAL_ENDPOINTS: readonly LocalEndpoint[] = [
  { name: "Ollama", baseURL: "http://localhost:11434/v1", modelHint: "qwen3", asOf: KNOWN_LOCAL_ENDPOINTS_AS_OF },
  { name: "LM Studio", baseURL: "http://localhost:1234/v1", asOf: KNOWN_LOCAL_ENDPOINTS_AS_OF },
  { name: "Jan", baseURL: "http://localhost:1337/v1", asOf: KNOWN_LOCAL_ENDPOINTS_AS_OF },
  { name: "GPT4All", baseURL: "http://localhost:4891/v1", asOf: KNOWN_LOCAL_ENDPOINTS_AS_OF },
];

/** Injected probe: does an OpenAI-compatible server answer at this baseURL? */
export interface EndpointProbe {
  (baseURL: string): Promise<{ reachable: boolean; modelId?: string }>;
}

export type BootMode = "local-model" | "deterministic-fallback";

export interface LocalFirstPlan {
  readonly mode: BootMode;
  /** The brain to use, if a local endpoint was found. Null in fallback mode. */
  readonly brain: BrainDescriptor | null;
  /** The endpoint chosen, if any. */
  readonly endpoint?: LocalEndpoint;
  /** Honest, non-nagging guidance for the operator. */
  readonly guidance: string;
  /** True if this plan required NO external account and NO cloud key. */
  readonly noAccountRequired: true;
}

/**
 * Resolve how a fresh Keep should boot, preferring a local no-account model. Probes the
 * known local endpoints in order; the first reachable one wins. If none are reachable,
 * returns a deterministic-fallback plan with guidance (never an account demand).
 */
export async function resolveLocalFirstDefaults(
  probe: EndpointProbe,
  endpoints: readonly LocalEndpoint[] = KNOWN_LOCAL_ENDPOINTS,
): Promise<LocalFirstPlan> {
  for (const ep of endpoints) {
    let result: { reachable: boolean; modelId?: string };
    try {
      result = await probe(ep.baseURL);
    } catch {
      continue; // unreachable -> try next
    }
    if (result.reachable) {
      const brain: BrainDescriptor = {
        kind: "openai-compatible",
        providerLabel: `${ep.name} (local)`,
        baseURL: ep.baseURL,
        apiKey: "", // local endpoints need no key
        model: result.modelId ?? ep.modelHint ?? "local-model",
      };
      return {
        mode: "local-model",
        brain,
        endpoint: ep,
        guidance: `Found ${ep.name} running locally — Keep is using it. Everything runs on this machine, offline, with no account and no cloud.`,
        noAccountRequired: true,
      };
    }
  }
  return {
    mode: "deterministic-fallback",
    brain: null,
    guidance:
      "No local model detected yet — Keep is running in its no-model mode (goal capture, file work, local git, dry-runs, and previews all work). To unlock conversation and planning with zero account and full privacy, start a local model like Ollama (`ollama serve`), LM Studio, or Jan, then Keep will pick it up automatically. A hosted API key is optional and only helps on the hardest reasoning.",
    noAccountRequired: true,
  };
}

/** Staleness note for the known-endpoints list (mirrors the currency-layer pattern). */
export function endpointsAsOf(): string {
  return KNOWN_LOCAL_ENDPOINTS_AS_OF;
}
