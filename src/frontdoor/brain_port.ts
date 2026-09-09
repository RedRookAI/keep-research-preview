/**
 * F0 — Brain port + credential intake (the front door's first step).
 *
 * "Hook in the AI of your choice." The moat is working with EVERYTHING, so the port
 * is built around the shape that already does: an OpenAI-COMPATIBLE descriptor
 * {baseURL, apiKey, model}. As of Aug 2026 the OpenAI API format is the de-facto
 * universal standard — Anthropic, Gemini, OpenRouter, Groq, NVIDIA NIM, and every
 * local runtime (Ollama, llama.cpp, vLLM, LM Studio) and OpenClaw all speak it, so
 * switching provider is just base_url + api_key. One shape, (almost) every brain.
 *
 * Agent-runtime brains (Claude Code as a subprocess, OpenClaw, Hermes/NVIDIA) are a
 * DISTINCT kind, declared here as a labeled seam and implemented on the connected
 * environment. Messages are jargon-free by rule.
 */

/** The kinds of brain Keep can hook into. */
export type BrainKind =
  | "openai-compatible" // any {baseURL, apiKey, model} — the universal path
  | "local" // a local runtime (Ollama/llama.cpp) — no real key needed
  | "agent-runtime" // Claude Code / OpenClaw / Hermes as the brain (seam)
  | "unknown"; // shape we don't recognize — accepted, not rejected

/** A brain configuration behind the port. */
export interface BrainDescriptor {
  readonly kind: BrainKind;
  /** Human label of the detected provider, e.g. "Anthropic", "OpenRouter", "a local model". */
  readonly providerLabel: string;
  readonly baseURL: string;
  /** The credential. For local runtimes this is a placeholder like "local". */
  readonly apiKey: string;
  /** The model id/name, if the human gave one (else a sensible default is chosen later). */
  readonly model?: string;
}

/** Known base URLs for provider kinds we can name (helps auto-fill). */
const PROVIDER_BASE_URLS: Record<string, string> = {
  anthropic: "https://api.anthropic.com/v1",
  openai: "https://api.openai.com/v1",
  openrouter: "https://openrouter.ai/api/v1",
  gemini: "https://generativelanguage.googleapis.com/v1beta/openai",
  groq: "https://api.groq.com/openai/v1",
  "nvidia-nim": "https://integrate.api.nvidia.com/v1",
  local: "http://localhost:11434/v1", // Ollama default
};

export interface DetectedProvider {
  /** A machine key like "anthropic" | "openrouter" | "openai" | "gemini" | "unknown". */
  readonly id: string;
  readonly label: string;
  /** A suggested base URL if we recognize the provider (the human can override). */
  readonly suggestedBaseURL?: string | undefined;
  readonly kind: BrainKind;
}

/**
 * Detect the provider from a pasted credential by its real prefix. Detect-and-
 * proceed: an unrecognized shape is returned as "unknown", NEVER rejected — new
 * providers appear constantly and gatekeeping breaks the "works with everything" moat.
 */
export function detectProviderKind(rawKey: string): DetectedProvider {
  const key = rawKey.trim();
  if (key.startsWith("sk-ant-")) {
    return { id: "anthropic", label: "Anthropic (Claude)", suggestedBaseURL: PROVIDER_BASE_URLS["anthropic"], kind: "openai-compatible" };
  }
  if (key.startsWith("sk-or-")) {
    return { id: "openrouter", label: "OpenRouter", suggestedBaseURL: PROVIDER_BASE_URLS["openrouter"], kind: "openai-compatible" };
  }
  if (key.startsWith("gsk_")) {
    return { id: "groq", label: "Groq", suggestedBaseURL: PROVIDER_BASE_URLS["groq"], kind: "openai-compatible" };
  }
  if (key.startsWith("nvapi-")) {
    return { id: "nvidia-nim", label: "NVIDIA", suggestedBaseURL: PROVIDER_BASE_URLS["nvidia-nim"], kind: "openai-compatible" };
  }
  if (key.startsWith("AIza")) {
    return { id: "gemini", label: "Google Gemini", suggestedBaseURL: PROVIDER_BASE_URLS["gemini"], kind: "openai-compatible" };
  }
  if (key.startsWith("sk-")) {
    // Generic OpenAI-style key (OpenAI and many compatible providers).
    return { id: "openai", label: "OpenAI (or an OpenAI-compatible provider)", suggestedBaseURL: PROVIDER_BASE_URLS["openai"], kind: "openai-compatible" };
  }
  // Unknown shape — still accepted. The human can paste a base URL to go with it.
  return { id: "unknown", label: "your provider", kind: "unknown" };
}

export interface CredentialCheck {
  readonly ok: boolean;
  /** A plain-language, jargon-free message about what to do next. */
  readonly message: string;
  readonly detected?: DetectedProvider;
}

/**
 * Structural, jargon-free check of a pasted credential. This does NOT call the
 * network (that's a connected-env step) — it only catches the obvious "this doesn't
 * look like a key yet" cases so the human gets a friendly nudge, not an auth error.
 */
export function checkCredentialShape(rawKey: string): CredentialCheck {
  const key = rawKey.trim();
  if (key.length === 0) {
    return { ok: false, message: "Paste your AI key here to get started, or leave it blank to try the built-in offline model first." };
  }
  if (key.length < 12 || /\s/.test(key)) {
    return { ok: false, message: "That doesn't look like a complete key yet — it's usually one long line with no spaces. Try pasting it again." };
  }
  const detected = detectProviderKind(key);
  const who = detected.id === "unknown" ? "your provider" : detected.label;
  return { ok: true, message: `Looks good — that's a key for ${who}. You're ready to go.`, detected };
}

/** Build a brain descriptor from a validated key + optional overrides. */
export function brainFromKey(rawKey: string, opts: { baseURL?: string; model?: string } = {}): BrainDescriptor {
  const key = rawKey.trim();
  const detected = detectProviderKind(key);
  const baseURL = opts.baseURL ?? detected.suggestedBaseURL ?? "";
  return {
    kind: detected.kind === "unknown" ? "openai-compatible" : detected.kind, // treat unknown as OpenAI-compatible by default
    providerLabel: detected.label,
    baseURL,
    apiKey: key,
    ...(opts.model !== undefined ? { model: opts.model } : {}),
  };
}

/** Build a local-runtime brain descriptor (no real key). */
export function localBrain(baseURL: string = PROVIDER_BASE_URLS["local"]!, model?: string): BrainDescriptor {
  return {
    kind: "local",
    providerLabel: "the built-in offline model",
    baseURL,
    apiKey: "local",
    ...(model !== undefined ? { model } : {}),
  };
}

export { PROVIDER_BASE_URLS };
