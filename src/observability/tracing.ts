/**
 * Hierarchical tracing + cost attribution (Phase 4, #41 + #39).
 *
 * Spans nest via parentId to form the trace TREE — the distributed-tracing model,
 * built on the Phase 0 spine (cost as an attribute on events, hierarchical
 * parent-child). Each span carries a CostBreakdown and dimension tags. The
 * attribution engine rolls up spend across all four grains:
 *   - per-task, per-agent (Claude/Gemini/Codex/DeepSeek), per-node, and
 *   - per-LESSON (cost of the builds a lesson influenced) — the novel grain nobody
 *     else can do, enabled by memory provenance + spine cost.
 */

import { createHash, randomUUID } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import type { CostBreakdown } from "./cost_model.js";
import { scanIngestion } from "../memory/ingestion.js";

export interface Span {
  readonly spanId: string;
  readonly parentId?: string;
  readonly traceId: string;
  readonly name: string;
  /** Dimension tags for attribution. */
  readonly taskId: string;
  /** Exact shared-deployment owner. Omitted is the private n=1 namespace only. */
  readonly tenant?: string;
  /** Concrete provider adapter that served the call; distinct from model/agent identity. */
  readonly provider?: string;
  readonly agent?: string;
  readonly node?: string;
  /** Lessons that influenced this span's work (enables per-lesson attribution). */
  readonly lessonIds: readonly string[];
  readonly cost: CostBreakdown;
  readonly tokens?: { readonly input: number; readonly output: number };
  readonly startTs: number;
  readonly endTs: number;
  /** Typed status for failure localization. */
  readonly status: "ok" | "llm-error" | "tool-error" | "timeout-error";
}

export interface SpanInput {
  readonly parentId?: string;
  readonly traceId?: string;
  readonly name: string;
  readonly taskId: string;
  readonly tenant?: string;
  readonly provider?: string;
  readonly agent?: string;
  readonly node?: string;
  readonly lessonIds?: readonly string[];
  readonly cost: CostBreakdown;
  readonly tokens?: { readonly input: number; readonly output: number };
  readonly startTs: number;
  readonly endTs: number;
  readonly status?: Span["status"];
}

export class TraceRecorder {
  private readonly spans = new Map<string, Span>();
  private readonly quarantined = new Set<string>();

  constructor(
    private readonly spine: Spine,
    private readonly clock: () => number = () => Date.now(),
  ) {
    for (const event of this.spine.replay()) {
      if (event.actor !== "trace" || event.payload["event"] !== "span" || event.payload["schema"] !== "keep.trace-span/v1") continue;
      const span = captureSpan(event.payload);
      if (span === undefined) { this.quarantined.add(event.id); continue; }
      const prior = this.spans.get(span.spanId);
      if (prior !== undefined) { this.spans.delete(span.spanId); this.quarantined.add(span.spanId); continue; }
      if (!this.quarantined.has(span.spanId)) this.spans.set(span.spanId, span);
    }
  }

  /** Record a span (and persist a compact copy to the spine for provenance). */
  record(input: SpanInput): Span {
    const span = captureSpan({
      spanId: randomUUID(),
      traceId: input.traceId ?? (input.parentId ? this.spans.get(input.parentId)?.traceId ?? randomUUID() : randomUUID()),
      name: input.name,
      taskId: input.taskId,
      lessonIds: input.lessonIds ?? [],
      cost: input.cost,
      ...(input.tokens !== undefined ? { tokens: { ...input.tokens } } : {}),
      startTs: input.startTs,
      endTs: input.endTs,
      status: input.status ?? "ok",
      ...(input.parentId !== undefined ? { parentId: input.parentId } : {}),
      ...(input.tenant !== undefined ? { tenant: input.tenant } : {}),
      ...(input.provider !== undefined ? { provider: input.provider } : {}),
      ...(input.agent !== undefined ? { agent: input.agent } : {}),
      ...(input.node !== undefined ? { node: input.node } : {}),
    });
    if (span === undefined) throw new Error("invalid trace span");
    this.spine.stage({
      type: "identity.action",
      actor: "trace",
      payload: {
        event: "span", schema: "keep.trace-span/v1", ...span,
      },
    });
    this.spans.set(span.spanId, span);
    return span;
  }

  all(tenant?: string): Span[] {
    if (tenant !== undefined && !SAFE_ID.test(tenant)) throw new Error("invalid trace tenant");
    return [...this.spans.values()].filter((span) => tenant === undefined || span.tenant === tenant);
  }

  /** The child spans of a given span (for hierarchical walking). */
  children(spanId: string): Span[] {
    return this.all().filter((s) => s.parentId === spanId);
  }

  /** All spans in a trace, in start order. */
  trace(traceId: string): Span[] {
    const storedTraceId = minimized(traceId, true);
    return this.all().filter((s) => s.traceId === storedTraceId).sort((a, b) => a.startTs - b.startTs);
  }

  integrityStatus(): { readonly quarantined: number } { return { quarantined: this.quarantined.size }; }
}

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const STATUSES = new Set<Span["status"]>(["ok", "llm-error", "tool-error", "timeout-error"]);

function text(value: unknown, maxBytes: number): value is string {
  return typeof value === "string" && value.length > 0 && !value.includes("\0") && Buffer.byteLength(value, "utf8") <= maxBytes;
}

function minimized(value: string, identity: boolean): string {
  const scanned = scanIngestion(value);
  if (identity && (scanned.decision === "reject" || scanned.sanitized !== value)) {
    // Identity fields must remain joinable and collision-resistant after privacy
    // minimization. A generic redaction marker would collapse unrelated runs.
    return `redacted-${createHash("sha256").update("keep.trace-redaction/v1\0").update(value).digest("hex")}`;
  }
  if (scanned.decision !== "reject") return scanned.sanitized;
  return identity ? `redacted-${createHash("sha256").update("keep.trace-redaction/v1\0").update(value).digest("hex")}` : "[REDACTED]";
}

function captureSpan(value: unknown): Span | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const row = value as Record<string, unknown>;
  if (!text(row["spanId"], 256) || !text(row["traceId"], 256) || !text(row["name"], 4096) || !text(row["taskId"], 4096)) return undefined;
  for (const key of ["parentId", "provider", "agent", "node"] as const) if (row[key] !== undefined && !text(row[key], 512)) return undefined;
  if (row["tenant"] !== undefined && (typeof row["tenant"] !== "string" || !SAFE_ID.test(row["tenant"]))) return undefined;
  if (!Array.isArray(row["lessonIds"]) || row["lessonIds"].length > 64 || row["lessonIds"].some((id) => !text(id, 512))) return undefined;
  if (row["cost"] === null || typeof row["cost"] !== "object" || Array.isArray(row["cost"])) return undefined;
  const cost = row["cost"] as Record<string, unknown>;
  const costKeys = ["inputUsd", "cachedInputUsd", "outputUsd", "tokenUsd", "humanUsd", "infraUsd", "toolApiUsd", "totalUsd"] as const;
  if (costKeys.some((key) => typeof cost[key] !== "number" || !Number.isFinite(cost[key]) || (cost[key] as number) < 0)) return undefined;
  if (typeof row["startTs"] !== "number" || !Number.isFinite(row["startTs"]) || typeof row["endTs"] !== "number" || !Number.isFinite(row["endTs"]) || row["endTs"] < row["startTs"] || !STATUSES.has(row["status"] as Span["status"])) return undefined;
  const tokens = row["tokens"];
  if (tokens !== undefined && (tokens === null || typeof tokens !== "object" || Array.isArray(tokens)
    || !Number.isSafeInteger((tokens as Record<string, unknown>)["input"]) || ((tokens as Record<string, number>)["input"] ?? -1) < 0
    || !Number.isSafeInteger((tokens as Record<string, unknown>)["output"]) || ((tokens as Record<string, number>)["output"] ?? -1) < 0)) return undefined;
  return Object.freeze({
    spanId: minimized(row["spanId"], true), traceId: minimized(row["traceId"], true), name: minimized(row["name"], false), taskId: minimized(row["taskId"], true),
    lessonIds: Object.freeze((row["lessonIds"] as string[]).map((id) => minimized(id, true))),
    cost: Object.freeze(Object.fromEntries(costKeys.map((key) => [key, cost[key]]))) as unknown as CostBreakdown,
    startTs: row["startTs"], endTs: row["endTs"], status: row["status"] as Span["status"],
    ...(row["parentId"] === undefined ? {} : { parentId: minimized(row["parentId"] as string, true) }),
    ...(row["tenant"] === undefined ? {} : { tenant: row["tenant"] as string }),
    ...(row["provider"] === undefined ? {} : { provider: minimized(row["provider"] as string, false) }),
    ...(row["agent"] === undefined ? {} : { agent: minimized(row["agent"] as string, true) }),
    ...(row["node"] === undefined ? {} : { node: minimized(row["node"] as string, false) }),
    ...(tokens === undefined ? {} : { tokens: Object.freeze({ input: (tokens as Record<string, number>)["input"]!, output: (tokens as Record<string, number>)["output"]! }) }),
  });
}

export interface Attribution {
  readonly byTask: Map<string, number>;
  readonly byProvider: Map<string, number>;
  readonly byAgent: Map<string, number>;
  readonly byNode: Map<string, number>;
  readonly byLesson: Map<string, number>;
  readonly total: number;
}

/** Roll up spend across all four attribution grains. Per-lesson is the novel one. */
export function attributeCost(spans: readonly Span[]): Attribution {
  const byTask = new Map<string, number>();
  const byProvider = new Map<string, number>();
  const byAgent = new Map<string, number>();
  const byNode = new Map<string, number>();
  const byLesson = new Map<string, number>();
  let total = 0;

  for (const s of spans) {
    const c = s.cost.totalUsd;
    total += c;
    add(byTask, s.taskId, c);
    if (s.provider) add(byProvider, s.provider, c);
    if (s.agent) add(byAgent, s.agent, c);
    if (s.node) add(byNode, s.node, c);
    // Per-lesson: attribute this span's cost to each lesson that influenced it.
    // (If multiple lessons influenced a build, each is credited the full build cost
    // it shaped — attribution is about influence, not partition; documented as such.)
    for (const lessonId of s.lessonIds) add(byLesson, lessonId, c);
  }
  return { byTask, byProvider, byAgent, byNode, byLesson, total };
}

function add(m: Map<string, number>, key: string, v: number): void {
  m.set(key, (m.get(key) ?? 0) + v);
}
