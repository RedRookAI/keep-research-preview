/**
 * DESLOP-PASS — a single-pass, prose-only, BYTE-VERIFIED de-slop transform. It removes filler/hedge/grandiose prose while
 * leaving everything that matters byte-identical: code blocks, numbers, quoted strings, and redaction SURROGATE TOKENS.
 * The 2026 de-slop literature is emphatic that naive suppression corrupts ("banning 'indigestible' also bans 'in' and
 * 'digest'" — Thoughtworks 2026) and that a cleanup must "preserve the original meaning and claims EXACTLY, only subtract
 * hedging and filler" (de-slop-ai 2026) and return text "identical to the input except for intended changes" (CRAC, arXiv
 * 2605.16984). So this extracts the protected spans before and after the transform and requires them to be byte-identical;
 * if any protected span changed, the pass is REJECTED and the ORIGINAL is returned (fail-safe — never a corrupted output).
 *
 * The transform is an INJECTED port — the reference is a deterministic filler remover; a grounded LLM rewriter is the
 * NAMED SEAM. It runs BEFORE re-hydration when the output was redacted for a remote call, so surrogate tokens must survive
 * (they are protected). HONEST: it only subtracts unprotected prose, never injects stance ("don't trade AI-slop for
 * louder slop"); it is TRANSFORM-PLUS-VERIFY, not a gate (changes no verdict). It is a QUALITY pass, NOT an AI-detector
 * evasion tool (EU AI Act transparency obligations, 2026-08; watermark removal is out of scope). Deterministic. ZERO-DEP.
 */

/** An injected prose transform. Reference = deterministic filler remover; a grounded LLM rewriter is the SEAM. */
export interface DeslopTransform {
  transform(prose: string): string;
}

/** The redaction surrogate-token format ⟦CATEGORY#seq⟧ (U+27E6…U+27E7) — reused from the redaction-gateway convention. */
export const SURROGATE_TOKEN = /\u27E6[^\u27E7]*\u27E7/g;

export interface DeslopInput {
  readonly text: string;
  readonly transform: DeslopTransform;
  /** Extra protected-span pattern (e.g. the surrogate token). Code blocks, numbers, and quotes are ALWAYS protected. */
  readonly surrogatePattern?: RegExp;
}

export type DeslopOutcome = "cleaned" | "rejected-protected-span-changed" | "no-op" | "transform-error";

export interface DeslopResult {
  /** The cleaned text, OR the original if rejected/no-op (fail-safe defaults to original). */
  readonly output: string;
  readonly outcome: DeslopOutcome;
  readonly protectedSpansPreserved: boolean;
  /** HONEST: transform-plus-verify — changes no verdict. */
  readonly changesVerdict: false;
  readonly reason: string;
}

/** Extract the ordered multiset (sorted) of protected spans: fenced/inline code, quoted strings, numbers, and surrogates. */
function protectedSpans(text: string, surrogate?: RegExp): string[] {
  const spans: string[] = [];
  const patterns: RegExp[] = [
    /```[\s\S]*?```/g, // fenced code
    /`[^`]+`/g,         // inline code
    /"[^"]*"/g,         // double-quoted string
    /'[^']*'/g,         // single-quoted string
    /-?\d+(?:\.\d+)?/g, // numbers
  ];
  if (surrogate) patterns.push(new RegExp(surrogate.source, surrogate.flags.includes("g") ? surrogate.flags : `${surrogate.flags}g`));
  for (const p of patterns) for (const m of text.matchAll(p)) spans.push(m[0]);
  return spans.sort();
}

export function deslopPass(input: DeslopInput): DeslopResult {
  const before = protectedSpans(input.text, input.surrogatePattern);
  // FAIL-SAFE: the transform is an INJECTED, untrusted port. One that THROWS must never crash the caller; keep the original.
  let transformed: string;
  try {
    transformed = input.transform.transform(input.text);
  } catch {
    return { output: input.text, outcome: "transform-error", protectedSpansPreserved: true, changesVerdict: false, reason: "deslop transform threw — failed safe to the original (untrusted injected port)" };
  }
  if (transformed === input.text) {
    return { output: input.text, outcome: "no-op", protectedSpansPreserved: true, changesVerdict: false, reason: "transform made no change" };
  }
  const after = protectedSpans(transformed, input.surrogatePattern);
  const preserved = before.length === after.length && before.every((s, i) => s === after[i]);
  if (!preserved) {
    // FAIL-SAFE: a protected span (code / number / quote / surrogate) changed — reject, return the ORIGINAL untouched.
    return { output: input.text, outcome: "rejected-protected-span-changed", protectedSpansPreserved: false, changesVerdict: false, reason: "a protected span (code/number/quote/surrogate) changed — pass rejected, original returned (fail-safe)" };
  }
  return { output: transformed, outcome: "cleaned", protectedSpansPreserved: true, changesVerdict: false, reason: "prose-only cleanup; all protected spans byte-identical" };
}

// The reference deterministic filler/hedge remover. Removes known filler PHRASES (which never contain protected content) +
// the em-dash-as-connector tell. Conservative by design — the byte-verify is the safety net for any overreach.
const FILLER_PATTERNS: readonly RegExp[] = [
  /\bit'?s worth noting that\s*/gi,
  /\bit is important to note that\s*/gi,
  /\bit should be noted that\s*/gi,
  /\bneedless to say,?\s*/gi,
  /\bat the end of the day,?\s*/gi,
  /\bin today'?s (?:ever-evolving|fast-paced|rapidly changing) (?:landscape|world),?\s*/gi,
  /\bwhen it comes to\s*/gi,
];

export const referenceDeslopTransform: DeslopTransform = {
  transform(prose: string): string {
    let out = prose;
    for (const p of FILLER_PATTERNS) out = out.replace(p, "");
    return out;
  },
};
