/**
 * ONBOARDING INTAKE ROUTER — Round 7 of the personalization moat. The onboarding flow: model choice FIRST, then a
 * bot-led intake that accepts as many input types as possible and saves everything through the safe path.
 *
 * The onboarding conversation is already a deterministic progressive-disclosure cold start (jargon-free,
 * one-question-at-a-time, never-loops, captures directives as probation memory). This round adds the two pieces
 * around it: (1) MODEL CHOICE FIRST — the provider (local / API / Claude-Max / OpenRouter) is selected before any
 * project work, and the n=1-local path needs zero cloud dependency; (2) BROAD INTAKE — many input types, each
 * routed to its parser (the SEAM), then saved THROUGH the CI vault (special-category disclosures are vaulted) and
 * the upkeep loop (dedup/link/supersede), data-minimizing (Round 2). An unsupported type DEGRADES GRACEFULLY to a
 * typed result — never a crash, never a silent accept.
 *
 * BUILT + proven in-env: the model-first ordering, the intake routing, the save-through-vault-and-upkeep, and the
 * graceful degradation. SEAM: the per-format parsers (voice→text, image→text, zip expansion — the actual codecs).
 */

import { upkeep, type UpkeepItem, type UpkeepResult } from "../memory/upkeep.js";
import type { SensitiveContextVault } from "../privacy/contextual_integrity.js";

// ---- 1. Model choice FIRST ----

export type ProviderKind = "local" | "api" | "claude-max" | "openrouter";

export interface SetupState {
  readonly provider?: ProviderKind | undefined; // the chosen model/provider (undefined = not yet chosen)
}

export type ModelFirstResult =
  | { readonly ready: true; readonly provider: ProviderKind; readonly cloudRequired: boolean }
  | { readonly ready: false; readonly reason: "needs-model-choice" };

/**
 * The model/provider choice PRECEDES any project work. Until a provider is chosen, onboarding cannot proceed. The
 * n=1-local path requires no cloud (cloudRequired = false) — the "back of house" runs entirely on the operator's
 * own model.
 */
export function modelFirst(setup: SetupState): ModelFirstResult {
  if (setup.provider === undefined) return { ready: false, reason: "needs-model-choice" };
  const cloudRequired = setup.provider !== "local"; // local ⇒ zero cloud dependency
  return { ready: true, provider: setup.provider, cloudRequired };
}

// ---- 2. Broad intake ----

/** The input types intake accepts. Text-native kinds pass through; binary kinds need a parser (the SEAM). */
const TEXT_NATIVE: ReadonlySet<string> = new Set(["note", "text", "markdown"]);
const BINARY: ReadonlySet<string> = new Set(["zip", "voice", "audio", "image", "pdf", "doc"]);

export interface IntakeItem {
  readonly kind: string; // declared type (mimetype-ish)
  readonly content: string; // text for text-native; raw handle for binary (a parser extracts text)
  readonly subject?: string | undefined; // if this may be a personal disclosure
}

/** A per-format extractor (voice→text, image→text, zip expansion). Injected; the SEAM. Returns undefined if it
 *  can't extract. */
export type Parser = (item: IntakeItem) => string | undefined;

export interface IntakeOptions {
  readonly vault?: SensitiveContextVault | undefined;
  readonly existing?: readonly UpkeepItem[] | undefined;
  readonly parser?: Parser | undefined;
  readonly key?: string | undefined;
}

export type IntakeResult =
  | { readonly status: "ingested"; readonly kind: string; readonly savedToVault: boolean; readonly upkeep: UpkeepResult }
  | { readonly status: "unsupported"; readonly kind: string };

function extractText(item: IntakeItem, parser?: Parser): string | undefined {
  if (TEXT_NATIVE.has(item.kind)) return item.content; // pass through
  if (BINARY.has(item.kind)) return parser !== undefined ? parser(item) : undefined; // needs the parser SEAM
  return undefined;
}

/**
 * Route one intake item: dispatch by type to its parser (SEAM), then save the extracted content THROUGH the upkeep
 * loop — which itself routes any special-category disclosure through the CI vault and dedups/links/supersedes. An
 * unsupported type (or a binary type with no parser) DEGRADES GRACEFULLY to a typed `unsupported` result — never a
 * throw, never a silent accept.
 */
export function routeIntake(item: IntakeItem, opts?: IntakeOptions): IntakeResult {
  if (!TEXT_NATIVE.has(item.kind) && !BINARY.has(item.kind)) {
    return { status: "unsupported", kind: item.kind }; // graceful degradation, not a throw
  }
  const text = extractText(item, opts?.parser);
  if (text === undefined) {
    return { status: "unsupported", kind: item.kind }; // binary with no parser ⇒ degrade gracefully
  }
  const candidate = {
    content: text,
    key: opts?.key ?? text.slice(0, 24),
    scope: "user",
    subject: item.subject,
  };
  const result = upkeep(opts?.existing ?? [], candidate, opts?.vault !== undefined ? { vault: opts.vault } : {});
  return { status: "ingested", kind: item.kind, savedToVault: result.sensitive, upkeep: result };
}
