/**
 * Theme 3a — SoulConfig (structured persona; SOFT config only).
 *
 * The load-bearing 2026 rule (Flowgrammers, clawsouls, Zylos): SEPARATE PERSONALITY
 * FROM POLICY. A soul answers "who is this agent?" — name, tone, stance, decision
 * defaults. It NEVER answers "how must it behave?" under pressure — refusals, scope,
 * and permissions are structural (the F1.5 gate + PolicyEngine), because persona-encoded
 * rules break on 20–30% of adversarial prompts (Gray Swan). So the soul shapes voice and
 * can never touch the gate.
 *
 * A soul is UNTRUSTED input (persona-hijacking is a documented attack): every field is
 * sanitized, and any attempt to smuggle permissions/scope/meta-instructions into the
 * persona is stripped and flagged — a persona can't grant itself powers. Ships a
 * friendly default identity when none is set. Zero deps.
 */

import { sanitizeForPrompt } from "../frontdoor/chunker.js";

export interface SoulConfig {
  /** What the operator calls the system. */
  readonly name: string;
  /** One-line self-description (voice, not authority). */
  readonly tagline?: string;
  /** Tone/communication style (e.g. "warm, concise, plain-language"). */
  readonly tone?: string;
  /** Guiding principles (soft — how it prefers to work, not what it's allowed to do). */
  readonly principles?: readonly string[];
  /** Soft boundaries the persona prefers (NOT security policy — those live in the gate). */
  readonly boundaries?: readonly string[];
  /** Decision/recommendation style (e.g. "offers options, recommends one"). */
  readonly decisionStyle?: string;
  /** Optional presentation hints (sets up Theme 3b voice). */
  readonly voiceHint?: string;
  /** Fields that were stripped for attempting to encode authority (audit/transparency). */
  readonly rejectedDirectives?: readonly string[];
}

/** The friendly default identity when the operator hasn't set a soul yet. */
export const DEFAULT_SOUL: SoulConfig = {
  name: "Keep",
  tagline: "your build partner — plans carefully, checks with you before anything risky, and gets better as you work together.",
  tone: "warm, clear, plain-language; never condescending",
  principles: ["explain things simply", "surface what already exists before building", "keep you in control of anything that can't be undone"],
  decisionStyle: "offer a couple of options and recommend one, with the reasons",
};

/**
 * Phrases that attempt to smuggle AUTHORITY into a persona (permissions, scope,
 * meta-instructions). These are stripped from persona fields — a soul can't grant
 * itself powers; scope changes must go through F2's human-gated path.
 */
const AUTHORITY_INJECTION_RX =
  /\b(you (may|can now|are allowed to|have permission to) (spend|deploy|delete|send|access|pay|purchase|grant|buy|charge|wire|transfer|publish|post)|ignore (previous|all|prior)|disregard (the|your) (rules|policy|guardrails|instructions)|always auto[- ]?approve|(never (ask|check|confirm)|stop asking|without (approval|confirmation|asking))[^.]{0,40}(spend|deploy|delete|send|pay|purchase|money|production|prod|access|buy|charge)|bypass (the|your)? ?(safety|gate|policy|guardrail)|override (the|your)? ?(safety|gate|policy|guardrail)|full (admin|root) access|grant yourself)\b/i;

function cleanField(raw: string | undefined, rejected: string[]): string | undefined {
  if (raw === undefined) return undefined;
  const sanitized = sanitizeForPrompt(raw).trim();
  if (AUTHORITY_INJECTION_RX.test(sanitized)) {
    // Drop the ENTIRE field — don't leave garbled remnants that could still color the
    // persona's voice. Persona sets voice, not authority; the whole clause is discarded.
    rejected.push(raw);
    return undefined;
  }
  return sanitized.length > 0 ? sanitized : undefined;
}

function cleanList(raw: readonly string[] | undefined, rejected: string[]): string[] | undefined {
  if (!raw) return undefined;
  const out: string[] = [];
  for (const item of raw) {
    const cleaned = cleanField(item, rejected);
    if (cleaned) out.push(cleaned);
  }
  return out.length > 0 ? out : undefined;
}

export interface RawSoul {
  readonly name?: string;
  readonly tagline?: string;
  readonly tone?: string;
  readonly principles?: readonly string[];
  readonly boundaries?: readonly string[];
  readonly decisionStyle?: string;
  readonly voiceHint?: string;
}

/**
 * Parse + sanitize a raw soul into a safe SoulConfig. Untrusted-input hardened:
 * sanitizes every field and strips any authority-injection attempts (flagged in
 * rejectedDirectives for transparency). Falls back to the default name if none given.
 */
export function parseSoul(raw: RawSoul): SoulConfig {
  const rejected: string[] = [];
  const name = cleanField(raw.name, rejected) ?? DEFAULT_SOUL.name;

  const soul: SoulConfig = {
    name,
    ...(cleanField(raw.tagline, rejected) !== undefined ? { tagline: cleanField(raw.tagline, rejected)! } : {}),
    ...(cleanField(raw.tone, rejected) !== undefined ? { tone: cleanField(raw.tone, rejected)! } : {}),
    ...(cleanList(raw.principles, rejected) !== undefined ? { principles: cleanList(raw.principles, rejected)! } : {}),
    ...(cleanList(raw.boundaries, rejected) !== undefined ? { boundaries: cleanList(raw.boundaries, rejected)! } : {}),
    ...(cleanField(raw.decisionStyle, rejected) !== undefined ? { decisionStyle: cleanField(raw.decisionStyle, rejected)! } : {}),
    ...(cleanField(raw.voiceHint, rejected) !== undefined ? { voiceHint: cleanField(raw.voiceHint, rejected)! } : {}),
    ...(rejected.length > 0 ? { rejectedDirectives: rejected } : {}),
  };
  return soul;
}
