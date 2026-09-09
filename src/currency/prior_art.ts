/**
 * Theme 2 (Currency Layer), Part 3 — priorArtCheck (the anti-reinvention planning step).
 *
 * Before Keep plans to BUILD something, it checks whether it already exists and surfaces
 * an adopt / build / combine recommendation to the human. Grounded in the SOTA
 * build-vs-adopt axes (maintenance burden, external dependency, licensing, cost) and the
 * "don't reinvent the wheel; build only for core differentiation or sovereign control"
 * default. Free/open options are surfaced first and preferred over paid unless paid is
 * materially better (the operator's locked principle). It is HONEST when it can't
 * verify — no fabricated confidence.
 *
 * The recommendation is advisory; the human decides.
 */

import type { Spine } from "../spine/spine.js";
import type { TemporalContext } from "./temporal_context.js";
import { LandscapeCatalog, type LandscapeEntry } from "./landscape_catalog.js";

export type PriorArtVerdict = "adopt" | "build" | "combine";

/** Injected live-search seam — returns fresh existing-option candidates, or null offline. */
export interface PriorArtSearch {
  (goal: string, keywords: readonly string[]): Promise<readonly LandscapeEntry[] | null>;
}

export interface PriorArtReport {
  readonly verdict: PriorArtVerdict;
  /** Existing options found, free/open first. */
  readonly options: readonly LandscapeEntry[];
  /** Whether findings could be verified as current (search available). */
  readonly verified: boolean;
  /** Plain-language recommendation shown to the human (advisory). */
  readonly recommendation: string;
  /** Honest caveat about staleness / inability to verify, if any. */
  readonly caveat?: string;
}

export interface PriorArtInput {
  readonly goal: string;
  readonly keywords: readonly string[];
  /** True if the goal is core/differentiating to the user (favors build). */
  readonly isCoreDifferentiator?: boolean;
  /** True if the user needs sovereign/offline control (favors build). */
  readonly needsSovereignControl?: boolean;
}

/**
 * Run the prior-art check. Consults the catalog + optional live search, then recommends
 * adopt / build / combine. Never fabricates currency it doesn't have.
 */
export async function priorArtCheck(
  input: PriorArtInput,
  deps: { spine: Spine; catalog: LandscapeCatalog; temporal: TemporalContext; search?: PriorArtSearch },
  now: Date = new Date(),
): Promise<PriorArtReport> {
  const fromCatalog = deps.catalog.matchesTask(input.keywords);

  // Optional live search for fresher options.
  let fromSearch: readonly LandscapeEntry[] | null = null;
  if (deps.search && deps.temporal.canVerify) {
    try {
      fromSearch = await deps.search(input.goal, input.keywords);
    } catch {
      fromSearch = null;
    }
  }

  // Merge (search results are fresher; dedupe by name), free/open first.
  const merged = mergeOptions(fromCatalog, fromSearch ?? []);
  const verified = fromSearch !== null;

  const verdict = decideVerdict(input, merged);
  const recommendation = buildRecommendation(verdict, merged, input);
  const caveat = buildCaveat(verified, deps.catalog, now, deps.temporal);

  deps.spine.stage({
    type: "identity.action",
    actor: "currency",
    payload: {
      event: "prior_art.checked",
      goalKeywords: input.keywords.join(","),
      verdict,
      optionsFound: merged.length,
      verified,
    },
  });

  return {
    verdict,
    options: merged,
    verified,
    recommendation,
    ...(caveat !== undefined ? { caveat } : {}),
  };
}

function mergeOptions(a: readonly LandscapeEntry[], b: readonly LandscapeEntry[]): LandscapeEntry[] {
  const byName = new Map<string, LandscapeEntry>();
  for (const e of a) byName.set(e.name.toLowerCase(), e);
  for (const e of b) byName.set(e.name.toLowerCase(), e); // search overrides catalog (fresher)
  return [...byName.values()].sort((x, y) => costRank(x.cost) - costRank(y.cost));
}

function decideVerdict(input: PriorArtInput, options: readonly LandscapeEntry[]): PriorArtVerdict {
  // Core differentiator or sovereign-control need favors build (SOTA default).
  if (input.isCoreDifferentiator || input.needsSovereignControl) {
    return options.length > 0 ? "combine" : "build";
  }
  if (options.length === 0) return "build"; // nothing exists -> build
  const hasFreeOption = options.some((o) => o.cost === "free");
  return hasFreeOption ? "adopt" : "combine"; // free option -> adopt; only paid -> combine
}

function buildRecommendation(verdict: PriorArtVerdict, options: readonly LandscapeEntry[], input: PriorArtInput): string {
  const free = options.filter((o) => o.cost === "free");
  const paid = options.filter((o) => o.cost !== "free");
  const nameList = (es: readonly LandscapeEntry[]) => es.map((e) => e.name).join(", ");

  switch (verdict) {
    case "adopt":
      return `Before building this, worth knowing it may already exist: ${nameList(free)} look like free/open options that could do it${paid.length ? ` (paid alternatives exist too: ${nameList(paid)}, only worth it if they're clearly better)` : ""}. Adopt one, or I can build if you'd rather own it.`;
    case "combine":
      return input.isCoreDifferentiator || input.needsSovereignControl
        ? `This is core to what you're doing, so building it is reasonable — but ${nameList(options)} exist and might handle parts of it. A hybrid (build the special bits, reuse the rest) is often best.`
        : `The existing options here are paid (${nameList(paid)}). We could adopt one, or build a free version — your call.`;
    case "build":
      return `I didn't find an existing option that fits, so building it makes sense. I'll proceed with a plan.`;
  }
}

function buildCaveat(verified: boolean, catalog: LandscapeCatalog, now: Date, temporal: TemporalContext): string | undefined {
  if (verified) return undefined;
  if (!temporal.canVerify) {
    return `I couldn't check for the very latest options (no live search this session), so this is based on what I knew as of ${catalog.stalenessNote(now).replace(/^Options current as of /, "").replace(/\.$/, "")} — worth a fresh look before committing.`;
  }
  return catalog.isStale(now) ? catalog.stalenessNote(now) : undefined;
}

function costRank(c: LandscapeEntry["cost"]): number {
  return c === "free" ? 0 : c === "freemium" ? 1 : 2;
}
