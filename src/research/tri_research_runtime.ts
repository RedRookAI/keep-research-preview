/** Built-in three-lane research coordinator. Retrieval is an adapter, never the coordinator. */

export type TriResearchLane = "current" | "historical" | "cross-disciplinary";

export interface TriResearchSource {
  readonly id: string;
  readonly title: string;
  readonly locator: string;
  readonly retrievedAt: string;
  /** Publication/effective date used for current-window verification. */
  readonly asOf?: string;
  readonly summary: string;
  readonly stale?: boolean;
  readonly routeId?: string;
}

export interface TriResearchTransport {
  readonly id: string;
  search(lane: TriResearchLane, query: string, context: { readonly asOf: string; readonly currentSince: string }): Promise<readonly TriResearchSource[] | null>;
}

export interface TriResearchLaneReport {
  readonly lane: TriResearchLane;
  readonly query: string;
  readonly routesTried: readonly string[];
  readonly sources: readonly TriResearchSource[];
  readonly verified: boolean;
  readonly debt?: string;
  readonly usableForBoundedWork: boolean;
}

export interface TriResearchReport {
  readonly schema: "keep.tri-research/v1";
  readonly asOf: string;
  readonly currentSince: string;
  readonly lanes: Readonly<Record<TriResearchLane, TriResearchLaneReport>>;
  readonly complete: boolean;
}

/**
 * A deliberately narrower admission predicate than `complete`. Current evidence must still be
 * verified; only the two non-current lanes may fall back to explicitly labelled LKG material.
 * Callers must additionally prove that the work they intend to continue is local and reversible.
 */
export function supportsBoundedReversibleWork(report: TriResearchReport): boolean {
  return report.lanes.current.verified
    && report.lanes.historical.usableForBoundedWork
    && report.lanes["cross-disciplinary"].usableForBoundedWork;
}

export interface TriResearchRuntimeConfig {
  readonly transports?: readonly TriResearchTransport[];
  readonly asOf?: () => string;
  /** Explicitly policy-permitted LKG evidence. It remains stale and cannot satisfy current. */
  readonly lastKnownGood?: Partial<Record<TriResearchLane, readonly TriResearchSource[]>>;
  readonly transportTimeoutMs?: number;
}

export class TriResearchRuntime {
  readonly #transports: readonly TriResearchTransport[];
  readonly #asOf: () => string;
  readonly #lastKnownGood: Partial<Record<TriResearchLane, readonly TriResearchSource[]>>;
  readonly #transportTimeoutMs: number;

  constructor(config: TriResearchRuntimeConfig = {}) {
    this.#transports = config.transports ?? [];
    this.#asOf = config.asOf ?? (() => new Date().toISOString().slice(0, 10));
    this.#lastKnownGood = config.lastKnownGood ?? {};
    this.#transportTimeoutMs = config.transportTimeoutMs ?? 30_000;
    if (!Number.isSafeInteger(this.#transportTimeoutMs) || this.#transportTimeoutMs <= 0) throw new RangeError("transportTimeoutMs must be a positive safe integer");
  }

  async run(goal: string): Promise<TriResearchReport> {
    const asOf = validDay(this.#asOf(), "asOf");
    const currentSince = shiftUtcMonths(asOf, -3);
    const queries: Readonly<Record<TriResearchLane, string>> = {
      current: `${goal} current state of the art evidence ${currentSince}..${asOf}`,
      historical: `${goal} historical mechanisms failures and prior art`,
      "cross-disciplinary": `${goal} proven transferable mechanisms from other disciplines`,
    };
    const entries = await Promise.all((Object.keys(queries) as TriResearchLane[]).map(async (lane) => [lane, await this.runLane(lane, queries[lane], asOf, currentSince)] as const));
    const lanes = Object.fromEntries(entries) as Record<TriResearchLane, TriResearchLaneReport>;
    return { schema: "keep.tri-research/v1", asOf, currentSince, lanes, complete: Object.values(lanes).every((lane) => lane.verified) };
  }

  private async runLane(lane: TriResearchLane, query: string, asOf: string, currentSince: string): Promise<TriResearchLaneReport> {
    const routesTried: string[] = [];
    const sources: TriResearchSource[] = [];
    const seen = new Set<string>();
    for (const transport of this.#transports) {
      routesTried.push(transport.id);
      let found: readonly TriResearchSource[] | null = null;
      try { found = await withTimeout(transport.search(lane, query, { asOf, currentSince }), this.#transportTimeoutMs); } catch { /* exact route remains visible; alternate routes continue */ }
      for (const source of found ?? []) {
        if (seen.has(source.id)) continue;
        seen.add(source.id);
        sources.push({ ...source, routeId: transport.id });
      }
      if (sources.some((source) => isAdmissibleTriResearchSource(lane, source, currentSince, asOf))) break;
    }
    if (!sources.some((source) => isAdmissibleTriResearchSource(lane, source, currentSince, asOf))) {
      for (const source of this.#lastKnownGood[lane] ?? []) {
        if (!seen.has(source.id)) { seen.add(source.id); sources.push({ ...source, stale: true, routeId: "last-known-good" }); }
      }
    }
    const verified = sources.some((source) => isAdmissibleTriResearchSource(lane, source, currentSince, asOf));
    const debt = verified ? undefined : lane === "current"
      ? `current/SOTA evidence for ${currentSince}..${asOf} is unavailable; stale evidence cannot satisfy this lane`
      : `${lane} evidence is unavailable from routes: ${routesTried.join(", ") || "none configured"}`;
    const usableForBoundedWork = verified || (lane !== "current" && sources.some(isUsableLastKnownGoodSource));
    return { lane, query, routesTried, sources, verified, usableForBoundedWork, ...(debt === undefined ? {} : { debt }) };
  }
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error(`research transport timed out after ${timeoutMs}ms`)), timeoutMs); }),
    ]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

/** The single source-admission predicate shared by coordination and downstream evidence consumers. */
export function isAdmissibleTriResearchSource(lane: TriResearchLane, source: TriResearchSource, since: string, asOf: string): boolean {
  if (source.stale === true || source.id.trim().length === 0 || source.locator.trim().length === 0 || source.summary.trim().length === 0) return false;
  if (!validInstant(source.retrievedAt)) return false;
  if (lane !== "current") return true;
  const retrieved = Date.parse(source.retrievedAt);
  const asOfStart = Date.parse(`${asOf}T00:00:00Z`);
  const asOfEnd = Date.parse(`${asOf}T23:59:59.999Z`);
  if (retrieved < asOfStart || retrieved > asOfEnd) return false;
  if (source.asOf === undefined) return false;
  const day = Date.parse(`${source.asOf}T00:00:00Z`);
  return Number.isFinite(day) && day >= Date.parse(`${since}T00:00:00Z`) && day <= Date.parse(`${asOf}T23:59:59Z`);
}

/** Explicitly weaker than fresh admission, but still requires identifiable, timestamped provenance. */
export function isUsableLastKnownGoodSource(source: TriResearchSource): boolean {
  return source.stale === true && source.id.length > 0 && source.locator.length > 0
    && source.summary.trim().length > 0 && validInstant(source.retrievedAt);
}

function validInstant(value: string): boolean { return Number.isFinite(Date.parse(value)); }

function validDay(value: string, label: string): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value) || !Number.isFinite(Date.parse(`${value}T00:00:00Z`))) throw new RangeError(`${label} must be YYYY-MM-DD`);
  return value;
}

function shiftUtcMonths(day: string, delta: number): string {
  const date = new Date(`${day}T00:00:00Z`);
  const originalDay = date.getUTCDate();
  date.setUTCDate(1);
  date.setUTCMonth(date.getUTCMonth() + delta);
  const finalDay = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 0)).getUTCDate();
  date.setUTCDate(Math.min(originalDay, finalDay));
  return date.toISOString().slice(0, 10);
}
