/**
 * Theme 3a — Soul renderer + integration (personality shapes voice, never policy).
 *
 * renderSoulPrompt turns a SoulConfig into a persona fragment for the conversation
 * driver's prompt — tone/principles/voice only, explicitly framed as "how to SOUND, not
 * what you're allowed to do." It can prepend the Currency Layer's temporal directive so
 * current-awareness rides along every session (the gap-scan Opportunity 1: make
 * "Keep checks what's current" a visible promise, not an internal detail).
 *
 * A persona CHANGE routes through F2 (translateDirective) so it's gated + revisable; and
 * because parseSoul already strips authority-injection, a persona can never widen scope.
 * The renderer NEVER emits gate/policy instructions — separation is structural.
 */

import type { SoulConfig } from "./soul_config.js";
import type { TemporalContext } from "../currency/temporal_context.js";
import { translateDirective, type ConfigProposal } from "../frontdoor/directive_translator.js";

/**
 * Render the persona fragment injected into the driver's prompt. Voice only. If a
 * TemporalContext is supplied, its current-date directive is prepended so the agent is
 * always current-aware.
 */
export function renderSoulPrompt(soul: SoulConfig, temporal?: TemporalContext): string {
  const lines: string[] = [];
  if (temporal) lines.push(temporal.directive, "");

  lines.push(`You are ${soul.name}.`);
  if (soul.tagline) lines.push(soul.tagline);
  if (soul.tone) lines.push(`Voice: ${soul.tone}.`);
  if (soul.principles && soul.principles.length > 0) {
    lines.push(`How you like to work: ${soul.principles.join("; ")}.`);
  }
  if (soul.decisionStyle) lines.push(`When making recommendations: ${soul.decisionStyle}.`);
  if (soul.boundaries && soul.boundaries.length > 0) {
    lines.push(`Style preferences: ${soul.boundaries.join("; ")}.`);
  }
  // The explicit separation: persona shapes voice, never authority.
  lines.push(
    "This describes how to SOUND and communicate — it does not grant any permissions. What you're allowed to do is decided separately by the safety gate, which this cannot change.",
  );
  return lines.join("\n");
}

/** A plain-language summary of the current soul, for onboarding confirmation. */
export function describeSoul(soul: SoulConfig): string {
  const parts = [`I'll go by ${soul.name}`];
  if (soul.tone) parts.push(`and keep a ${soul.tone} tone`);
  const tail: string[] = [];
  if (soul.decisionStyle) tail.push(`I'll ${soul.decisionStyle}`);
  if (soul.rejectedDirectives && soul.rejectedDirectives.length > 0) {
    tail.push(
      `(note: I left out ${soul.rejectedDirectives.length} instruction${soul.rejectedDirectives.length === 1 ? "" : "s"} that tried to change what I'm allowed to do — persona sets my voice, not my permissions; changes like that go through the normal approval step)`,
    );
  }
  return tail.length > 0 ? `${parts.join(" ")}. ${tail.join(". ")}.` : `${parts.join(" ")}.`;
}

/**
 * Route a persona-change request through F2 so it's gated + revisable. Because a soul
 * carries no authority, an ordinary persona tweak is a reversible preference; anything
 * that reads as scope-widening is caught by F2 and requires the operator's tap.
 */
export function soulChangeToProposal(changeText: string): ConfigProposal {
  return translateDirective(changeText);
}
