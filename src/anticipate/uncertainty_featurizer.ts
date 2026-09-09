/**
 * LINGUISTIC-CUE UNCERTAINTY FEATURIZER (moat-heart — the uncertainty side of the ask-gate).
 *
 * The ask-gate decides ask-vs-proceed on uncertainty × consequence. Its uncertainty input today is only the intent
 * router's shape confidence. This module adds a second, content-neutral source: the message's own hedging.
 * Grounded in Principle 2 of KEEP_LINGUISTIC_CUES_RESEARCH.md (Clark & Fox Tree 2002; Lakoff hedges; CoNLL-2010
 * hedge detection) — hedges and disfluency mark the speaker's PROCESSING DIFFICULTY / uncertainty, explicitly
 * distinct from lie detection. The written analogs are hedges ("maybe", "I think"), self-corrections ("I mean",
 * "actually"), trailing qualifiers ("...or something"), vagueness ("stuff", "somehow"), multi-intent ("and also"),
 * and tag-questions ("right?").
 *
 * This is a CONSTRAINED build — the constraints ARE the feature, and a featurizer that violates them is a failure
 * even if accurate:
 *   - NO-VERDICT: cues describe the MESSAGE's ambiguity, never label the person (no "anxious", no "uncertain" as a
 *     trait, never any honesty/deception judgment — the discredited SCAN use is out of scope permanently).
 *   - EPHEMERAL: a pure function of the current message. It persists NOTHING — inferred psychological state stays
 *     ephemeral (the n=1↔org asymmetry: a durable "who's wavering" record is a surveillance asset at org scale).
 *   - RELATIVE-TO-SELF: cue strength may be scored against the user's OWN typical rate (optional self-baseline);
 *     with no baseline it uses only the absolute in-message cues — never a population norm (so an habitually
 *     indirect communicator isn't perpetually "uncertain").
 *   - WEAK / ADDITIVE: every cue is a weak probabilistic input; no single cue triggers action — it feeds a
 *     threshold, default-gentle.
 *   - SERVE, TRANSPARENT: the only use is "ask a better question / be gentler"; the `note` is a legible reason.
 *
 * BUILT + proven in-env: the deterministic message-level cue extraction + additive scoring + self-relative
 * adjustment + soft-OR blend. SEAM: a learned detector could slot behind the same interface; the per-user
 * self-baseline is supplied by the caller (a transparent, user-owned running style measure), never inferred here.
 */

/** Message-level cue kinds. NOTE: every kind describes the MESSAGE, never the person (no-verdict). */
export type CueKind = "hedge" | "self-correction" | "trailing-qualifier" | "vagueness" | "multi-intent" | "tag-question";

export interface UncertaintyCue {
  readonly kind: CueKind;
  readonly match: string;
}

export interface UncertaintyFeatures {
  /** 0..1 message-level ambiguity signal (ephemeral — not stored, not a person-trait). */
  readonly uncertainty: number;
  readonly cues: readonly UncertaintyCue[];
  /** Transparent, message-level reason (never a person-label). */
  readonly note: string;
}

export interface FeaturizeOpts {
  /**
   * The user's OWN typical cue density (0..1), if a transparent per-session self-baseline exists. Cue strength is
   * scored relative to it (an habitually hedgy user isn't perpetually "uncertain"). Absent → absolute cues only.
   */
  readonly selfBaselineRate?: number;
}

/** Each cue KIND is a weak additive input. Weights are small so a single cue never dominates. */
const CUE_PATTERNS: readonly { kind: CueKind; rx: RegExp; weight: number }[] = [
  { kind: "hedge", weight: 0.35, rx: /\b(maybe|perhaps|i think|i guess|i suppose|not sure|kind of|kinda|sort of|sorta|probably|possibly|i feel like|i dunno|dunno|not certain|somewhat|i'?m not sure)\b/i },
  { kind: "self-correction", weight: 0.25, rx: /\b(i mean|actually|or rather|no wait|scratch that|let me rephrase|on second thought)\b/i },
  { kind: "trailing-qualifier", weight: 0.25, rx: /(or something|or whatever|\.\.\.|…)\s*$/i },
  { kind: "vagueness", weight: 0.2, rx: /\b(something|somehow|somewhere|stuff|things|whatever|some kind of|a bit|a little)\b/i },
  { kind: "multi-intent", weight: 0.2, rx: /\b(and also|or maybe|and maybe|or else|as well as)\b/i },
  { kind: "tag-question", weight: 0.15, rx: /\b(right|yeah|ok|okay|yes|no)\?\s*$/i },
];

function clamp01(x: number): number {
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

/**
 * Featurize a message's uncertainty from its linguistic cues. Pure and ephemeral: same input → same output, no
 * stored state. The result describes the MESSAGE, never the person.
 */
export function featurizeUncertainty(message: string, opts?: FeaturizeOpts): UncertaintyFeatures {
  const cues: UncertaintyCue[] = [];
  let raw = 0;
  for (const p of CUE_PATTERNS) {
    const m = p.rx.exec(message);
    if (m) {
      cues.push({ kind: p.kind, match: m[0].trim() });
      raw += p.weight; // additive over DISTINCT kinds (one match per kind)
    }
  }
  // Relative-to-self: discount by the user's own typical cue density, if known. Never a population norm.
  const baseline = opts?.selfBaselineRate !== undefined ? clamp01(opts.selfBaselineRate) : 0;
  const uncertainty = clamp01(raw - baseline);
  return { uncertainty, cues, note: describeMessage(cues) };
}

/** Build a message-level, no-verdict reason from the cue kinds present. Describes the MESSAGE, never the person. */
function describeMessage(cues: readonly UncertaintyCue[]): string {
  if (cues.length === 0) return "the message reads as direct — no hedging cues";
  const phrases: Record<CueKind, string> = {
    hedge: "hedges",
    "self-correction": "self-corrects",
    "trailing-qualifier": "trails off",
    vagueness: "is under-specified",
    "multi-intent": "carries more than one intent",
    "tag-question": "seeks confirmation",
  };
  const parts = [...new Set(cues.map((c) => phrases[c.kind]))];
  return `the message ${parts.join(", ")}`;
}

/**
 * Blend two uncertainty sources (e.g. 1 - intent-confidence, and the cue uncertainty) by soft-OR:
 * 1 - (1-a)(1-b). Either source can RAISE the combined uncertainty; neither can lower it below the other — a
 * precautionary composition (the cue signal adds caution, never removes it).
 */
export function blendUncertainty(a: number, b: number): number {
  const x = clamp01(a);
  const y = clamp01(b);
  return 1 - (1 - x) * (1 - y);
}
