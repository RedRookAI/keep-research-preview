import { attributeCost, type Span } from "./tracing.js";
import { forecastTask, type CostBand } from "./forecasting.js";
import { createHash, createHmac } from "node:crypto";
import { canonicalize } from "../spine/event.js";
import type { Spine } from "../spine/spine.js";
import type { CapabilityHub, CapabilityInvocation, CapabilityResult } from "../ecosystem/capability_port.js";

export interface LocalCostTraceView {
  readonly totalUsd: number;
  readonly attribution: {
    readonly providers: readonly { readonly id: string; readonly usd: number }[];
    readonly tasks: readonly { readonly id: string; readonly usd: number }[];
    readonly agents: readonly { readonly id: string; readonly usd: number }[];
    readonly lessons: readonly { readonly id: string; readonly usd: number }[];
  };
  readonly forecast: CostBand;
  readonly traces: readonly {
    readonly traceId: string; readonly spanId: string; readonly taskId: string;
    readonly provider?: string; readonly agent?: string; readonly lessonIds: readonly string[];
    readonly usd: number; readonly status: Span["status"];
  }[];
  readonly page: { readonly offset: number; readonly limit: number; readonly total: number; readonly nextOffset: number | null };
}

function rows(values: ReadonlyMap<string, number>): readonly { readonly id: string; readonly usd: number }[] {
  return Object.freeze([...values].map(([id, usd]) => Object.freeze({ id, usd })).sort((a, b) => b.usd - a.usd || a.id.localeCompare(b.id)));
}

/** Complete local aggregates plus a bounded detail page, derived only from measured canonical spans. */
export function localCostTraceView(spans: readonly Span[], page: { readonly offset?: number; readonly limit?: number } = {}): LocalCostTraceView {
  if (!Array.isArray(spans) || spans.length > 100_000) throw new Error("trace view exceeds the supported history bound");
  const offset = page.offset ?? 0, limit = page.limit ?? Math.min(1_000, Math.max(1, spans.length));
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 1_000) throw new Error("invalid trace page");
  const attributed = attributeCost(spans);
  const detail = spans.slice(offset, offset + limit).map((span) => Object.freeze({
    traceId: span.traceId, spanId: span.spanId, taskId: span.taskId,
    ...(span.provider === undefined ? {} : { provider: span.provider }),
    ...(span.agent === undefined ? {} : { agent: span.agent }),
    lessonIds: Object.freeze([...span.lessonIds]), usd: span.cost.totalUsd, status: span.status,
  }));
  return Object.freeze({
    totalUsd: attributed.total,
    attribution: Object.freeze({ providers: rows(attributed.byProvider), tasks: rows(attributed.byTask), agents: rows(attributed.byAgent), lessons: rows(attributed.byLesson) }),
    forecast: Object.freeze(forecastTask([...attributed.byTask.values()])),
    traces: Object.freeze(detail),
    page: Object.freeze({ offset, limit, total: spans.length, nextOffset: offset + detail.length < spans.length ? offset + detail.length : null }),
  });
}

export interface MeasuredRun {
  readonly taskId: string;
  readonly model: string;
  readonly costUsd: number;
  readonly passed: boolean;
  readonly traceId: string;
}

export interface ModelEconomics {
  readonly model: string;
  readonly attempts: number;
  readonly passes: number;
  readonly passRate: number;
  readonly costPerPassUsd?: number;
}

export interface FleetView {
  readonly totalUsd: number;
  readonly successfulTasks: number;
  readonly failedTasks: number;
  readonly forecast: CostBand;
  readonly models: readonly ModelEconomics[];
  readonly traces: readonly { readonly traceId: string; readonly taskId: string; readonly model: string; readonly costUsd: number; readonly status: "passed" | "failed" }[];
}

function validRun(run: MeasuredRun): boolean {
  return run !== null && typeof run === "object" && typeof run.taskId === "string" && run.taskId.length > 0 && Buffer.byteLength(run.taskId, "utf8") <= 4_096
    && typeof run.traceId === "string" && run.traceId.length > 0 && Buffer.byteLength(run.traceId, "utf8") <= 256
    && typeof run.model === "string" && run.model.length > 0 && Buffer.byteLength(run.model, "utf8") <= 512
    && typeof run.costUsd === "number" && Number.isFinite(run.costUsd) && run.costUsd >= 0 && typeof run.passed === "boolean";
}

/** Fleet economics retain failed-attempt spend; no failure is removed from cost-per-pass. */
export function fleetView(runs: readonly MeasuredRun[]): FleetView {
  if (!Array.isArray(runs) || runs.length > 100_000 || runs.some((run) => !validRun(run))) throw new Error("invalid measured fleet runs");
  const grouped = new Map<string, MeasuredRun[]>();
  for (const run of runs) grouped.set(run.model, [...(grouped.get(run.model) ?? []), run]);
  const models = [...grouped].map(([model, samples]): ModelEconomics => {
    const passes = samples.filter((sample) => sample.passed).length;
    const spent = samples.reduce((sum, sample) => sum + sample.costUsd, 0);
    return Object.freeze({ model, attempts: samples.length, passes, passRate: passes / samples.length, ...(passes === 0 ? {} : { costPerPassUsd: spent / passes }) });
  }).sort((a, b) => a.model.localeCompare(b.model));
  return Object.freeze({
    totalUsd: runs.reduce((sum, run) => sum + run.costUsd, 0),
    successfulTasks: runs.filter((run) => run.passed).length,
    failedTasks: runs.filter((run) => !run.passed).length,
    forecast: Object.freeze(forecastTask(runs.map((run) => run.costUsd))),
    models: Object.freeze(models),
    traces: Object.freeze(runs.map((run) => Object.freeze({ traceId: run.traceId, taskId: run.taskId, model: run.model, costUsd: run.costUsd, status: run.passed ? "passed" as const : "failed" as const }))),
  });
}

/** Cheapest measured cost-of-pass among models clearing the explicit quality floor. */
export function optimizeProviderPrice(view: FleetView, minimumPassRate: number): ModelEconomics | undefined {
  if (!Number.isFinite(minimumPassRate) || minimumPassRate < 0 || minimumPassRate > 1) throw new Error("invalid minimum pass rate");
  return [...view.models]
    .filter((model) => model.passRate >= minimumPassRate && model.costPerPassUsd !== undefined)
    .sort((a, b) => a.costPerPassUsd! - b.costPerPassUsd! || b.passRate - a.passRate || a.model.localeCompare(b.model))[0];
}

export interface OtlpSpan {
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId?: string;
  readonly name: string;
  readonly startTimeUnixNano: string;
  readonly endTimeUnixNano: string;
  readonly attributes: Readonly<Record<string, string | number>>;
  readonly status: "OK" | "ERROR";
}

export interface OtlpSink { export(spans: readonly OtlpSpan[]): Promise<void>; }

function pseudonym(key: string, value: string, bytes: 8 | 16): string {
  return createHmac("sha256", key).update(value).digest("hex").slice(0, bytes * 2);
}

function exportLabel(value: string): string {
  const lowered = value.toLowerCase();
  if (/[\r\n\0]/u.test(value) || /(?:[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|(?:sk|ghp|github_pat|xox[baprs])[-_][a-z0-9_-]{12,}|bearer\s+[a-z0-9._~-]{12,})/iu.test(lowered)) return "[REDACTED]";
  return Buffer.byteLength(value, "utf8") <= 128 ? value : `${value.slice(0, 96)}…`;
}

export function toPrivateOtlpSpans(spans: readonly Span[], pseudonymizationKey: string): readonly OtlpSpan[] {
  if (typeof pseudonymizationKey !== "string" || Buffer.byteLength(pseudonymizationKey, "utf8") < 32 || Buffer.byteLength(pseudonymizationKey, "utf8") > 4_096) throw new Error("invalid telemetry pseudonymization key");
  if (!Array.isArray(spans) || spans.length > 500) throw new Error("OTLP batch exceeds the supported bound");
  return Object.freeze(spans.map((span): OtlpSpan => Object.freeze({
    traceId: pseudonym(pseudonymizationKey, span.traceId, 16), spanId: pseudonym(pseudonymizationKey, span.spanId, 8),
    ...(span.parentId === undefined ? {} : { parentSpanId: pseudonym(pseudonymizationKey, span.parentId, 8) }),
    name: exportLabel(span.name), startTimeUnixNano: String(Math.trunc(span.startTs * 1_000_000)), endTimeUnixNano: String(Math.trunc(span.endTs * 1_000_000)),
    attributes: Object.freeze({
      "keep.task.id": pseudonym(pseudonymizationKey, span.taskId, 16), "keep.cost.usd": span.cost.totalUsd,
      ...(span.provider === undefined ? {} : { "keep.provider": exportLabel(span.provider) }),
      ...(span.agent === undefined ? {} : { "keep.agent": pseudonym(pseudonymizationKey, span.agent, 16) }),
      ...(span.node === undefined ? {} : { "keep.node": exportLabel(span.node) }),
    }), status: span.status === "ok" ? "OK" : "ERROR",
  })));
}

/** Compatibility mapper for injected sinks; explicit callers await delivery and receive failures. */
export class FleetTelemetryExporter {
  constructor(private readonly sink: OtlpSink, private readonly pseudonymizationKey = "keep-local-telemetry-pseudonym-key-v1") {}
  async export(spans: readonly Span[]): Promise<number> {
    const payload = toPrivateOtlpSpans(spans, this.pseudonymizationKey);
    if (payload.length !== 0) await this.sink.export(payload);
    return payload.length;
  }
}

export interface TelemetryDestinationRuntime {
  readonly id: string;
  readonly tenant?: string;
  readonly purpose: string;
  readonly authorityToken: string;
  readonly destinationDigest: string;
  readonly pseudonymizationKey: string;
  readonly maxBatchSpans: number;
}

export interface TelemetryExportRequest {
  readonly destinationId: string;
  readonly purpose: string;
  readonly actor: string;
  readonly tenant?: string;
  readonly traceId?: string;
  readonly offset?: number;
  readonly limit?: number;
  readonly signal?: AbortSignal;
}

export type TelemetryExportResult =
  | { readonly status: "completed"; readonly exported: number; readonly nextOffset: number | null; readonly exportId?: string }
  | { readonly status: "held" | "failed" | "unreconciled"; readonly exported: 0; readonly reason: string; readonly exportId?: string };

export interface DurableFleetTelemetryConfig {
  readonly spine: Spine;
  readonly recorder: { all(tenant?: string): Span[] };
  readonly hub: CapabilityHub;
  readonly destinations: readonly TelemetryDestinationRuntime[];
  readonly dispatch?: (invocation: CapabilityInvocation, context: { readonly actor: string; readonly tenant?: string; readonly authorityId: string; readonly retrieval: string }) => Promise<CapabilityResult>;
}

/** Explicit durable export transaction; local tracing never depends on collector availability. */
export class DurableFleetTelemetry {
  readonly #destinations = new Map<string, TelemetryDestinationRuntime>();
  constructor(private readonly config: DurableFleetTelemetryConfig) {
    if (!config.spine.durableStorage()) throw new Error("telemetry export requires a durable Spine");
    for (const destination of config.destinations) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(destination.id) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(destination.purpose)
        || (destination.tenant !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(destination.tenant))
        || !Number.isSafeInteger(destination.maxBatchSpans) || destination.maxBatchSpans < 1 || destination.maxBatchSpans > 500
        || !/^[a-f0-9]{64}$/u.test(destination.destinationDigest) || this.#destinations.has(this.key(destination.id, destination.tenant))) throw new Error("invalid or duplicate telemetry destination");
      toPrivateOtlpSpans([], destination.pseudonymizationKey);
      this.#destinations.set(this.key(destination.id, destination.tenant), Object.freeze({ ...destination }));
    }
  }

  list(tenant?: string): readonly { readonly id: string; readonly purpose: string; readonly destinationDigest: string; readonly maxBatchSpans: number }[] {
    return Object.freeze([...this.#destinations.values()].filter((destination) => destination.tenant === tenant).map(({ id, purpose, destinationDigest, maxBatchSpans }) => Object.freeze({ id, purpose, destinationDigest, maxBatchSpans })));
  }

  outstanding(tenant?: string): readonly { readonly exportId: string; readonly destinationId: string; readonly destinationDigest: string; readonly purpose: string; readonly count: number; readonly offset: number }[] {
    const open = new Map<string, { exportId: string; destinationId: string; destinationDigest: string; purpose: string; count: number; offset: number; tenant: string | null }>();
    for (const event of this.config.spine.replay()) {
      if (event.type === "effect.intent" && event.payload["kind"] === "telemetry.export.intent" && typeof event.payload["destinationId"] === "string" && typeof event.payload["destinationDigest"] === "string"
        && typeof event.payload["purpose"] === "string" && Number.isSafeInteger(event.payload["count"]) && Number.isSafeInteger(event.payload["offset"]) && (event.payload["tenant"] === null || typeof event.payload["tenant"] === "string")) {
        open.set(event.id, { exportId: event.id, destinationId: event.payload["destinationId"], destinationDigest: event.payload["destinationDigest"], purpose: event.payload["purpose"], count: event.payload["count"] as number, offset: event.payload["offset"] as number, tenant: event.payload["tenant"] as string | null });
      }
      if ((event.type === "effect.receipt" || event.type === "effect.terminal") && typeof event.payload["intentEntryHash"] === "string") open.delete(event.payload["intentEntryHash"]);
    }
    const expectedTenant = tenant ?? null;
    return Object.freeze([...open.values()].filter((row) => row.tenant === expectedTenant).map(({ tenant: _tenant, ...row }) => Object.freeze(row)));
  }

  async reconcile(request: { readonly exportId: string; readonly outcome: "delivered" | "failed"; readonly evidenceId: string; readonly actor: string; readonly tenant?: string }): Promise<boolean> {
    if (typeof request.exportId !== "string" || typeof request.evidenceId !== "string" || request.evidenceId.length === 0 || Buffer.byteLength(request.evidenceId, "utf8") > 512 || /[\u0000-\u001f\u007f]/u.test(request.evidenceId)) return false;
    const row = this.outstanding(request.tenant).find((candidate) => candidate.exportId === request.exportId);
    if (row === undefined) return false;
    this.config.spine.stage({ type: request.outcome === "delivered" ? "effect.receipt" : "effect.terminal", actor: request.actor, payload: {
      kind: "telemetry.export.reconciled", intentEntryHash: row.exportId, destinationDigest: row.destinationDigest,
      disposition: request.outcome, evidenceId: request.evidenceId,
    } });
    try { await this.config.spine.seal(); } catch { return false; }
    return this.outstanding(request.tenant).every((candidate) => candidate.exportId !== request.exportId);
  }

  async export(request: TelemetryExportRequest): Promise<TelemetryExportResult> {
    if (typeof request.actor !== "string" || request.actor.length === 0 || Buffer.byteLength(request.actor, "utf8") > 512 || /[\u0000-\u001f\u007f]/u.test(request.actor)
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(request.destinationId) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(request.purpose)) return { status: "held", exported: 0, reason: "invalid telemetry export identity" };
    const destination = this.#destinations.get(this.key(request.destinationId, request.tenant));
    if (destination === undefined || destination.purpose !== request.purpose) return { status: "held", exported: 0, reason: "telemetry destination, tenant, or purpose is not configured" };
    if (request.traceId !== undefined && (request.traceId.length === 0 || Buffer.byteLength(request.traceId, "utf8") > 256 || request.traceId.includes("\0"))) return { status: "held", exported: 0, reason: "invalid telemetry trace identity" };
    const offset = request.offset ?? 0, limit = request.limit ?? destination.maxBatchSpans;
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > destination.maxBatchSpans) return { status: "held", exported: 0, reason: "invalid telemetry export page" };
    const available = this.config.recorder.all(request.tenant).filter((span) => request.traceId === undefined || span.traceId === request.traceId);
    const selected = available.slice(offset, offset + limit), nextOffset = offset + selected.length < available.length ? offset + selected.length : null;
    if (selected.length === 0) return { status: "completed", exported: 0, nextOffset };
    const spans = toPrivateOtlpSpans(selected, destination.pseudonymizationKey);
    const payload = Object.freeze({ resourceSpans: Object.freeze([{ scopeSpans: Object.freeze([{ scope: Object.freeze({ name: "keep" }), spans }]) }]) });
    const batchDigest = createHash("sha256").update("keep.telemetry-export-batch/v1\0").update(canonicalize(payload)).digest("hex");
    const intentEntryHash = this.config.spine.stage({ type: "effect.intent", actor: request.actor, payload: {
      kind: "telemetry.export.intent", destinationId: destination.id, destinationDigest: destination.destinationDigest,
      tenant: request.tenant ?? null, purpose: request.purpose, batchDigest, count: spans.length, offset,
    } });
    try { await this.config.spine.seal(); } catch { return { status: "failed", exported: 0, reason: "telemetry export intent could not be durably sealed" }; }
    if (request.signal?.aborted) {
      if (!await this.terminal(request.actor, intentEntryHash, "aborted before dispatch")) return { status: "unreconciled", exported: 0, reason: "telemetry export was cancelled but its terminal record could not be durably sealed", exportId: intentEntryHash };
      return { status: "failed", exported: 0, reason: "telemetry export cancelled", exportId: intentEntryHash };
    }
    const invocation: CapabilityInvocation = { capabilityId: destination.id, operation: "telemetry.export", args: {
      authorityToken: destination.authorityToken, destinationDigest: destination.destinationDigest, exportId: intentEntryHash, purpose: request.purpose, payload,
    }, auditArgs: "digest", ...(request.signal === undefined ? {} : { signal: request.signal }) };
    let result: CapabilityResult;
    const fleetActor = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(request.actor) ? request.actor : `principal-${createHash("sha256").update(request.actor).digest("hex").slice(0, 32)}`;
    try {
      result = this.config.dispatch === undefined
        ? await this.config.hub.invoke(invocation, { requireVerified: true, confirm: true, ...(request.tenant === undefined ? {} : { tenant: request.tenant }) })
        : await this.config.dispatch(invocation, { actor: fleetActor, ...(request.tenant === undefined ? {} : { tenant: request.tenant }), authorityId: intentEntryHash, retrieval: batchDigest });
    } catch { return { status: "unreconciled", exported: 0, reason: "telemetry dispatch outcome is indeterminate", exportId: intentEntryHash }; }
    if (!result.ok) {
      if (!result.held && result.output !== null && typeof result.output === "object" && (result.output as Record<string, unknown>)["indeterminate"] === true) return { status: "unreconciled", exported: 0, reason: result.error ?? "telemetry dispatch outcome is indeterminate", exportId: intentEntryHash };
      if (!await this.terminal(request.actor, intentEntryHash, result.error ?? "telemetry collector refused export")) return { status: "unreconciled", exported: 0, reason: "telemetry failed but its terminal record could not be durably sealed", exportId: intentEntryHash };
      return { status: result.held ? "held" : "failed", exported: 0, reason: result.error ?? "telemetry collector refused export", exportId: intentEntryHash };
    }
    this.config.spine.stage({ type: "effect.receipt", actor: request.actor, payload: { kind: "telemetry.export.receipt", intentEntryHash, destinationDigest: destination.destinationDigest, batchDigest, count: spans.length } });
    try { await this.config.spine.seal(); } catch { return { status: "unreconciled", exported: 0, reason: "telemetry was delivered but its receipt could not be durably sealed", exportId: intentEntryHash }; }
    return { status: "completed", exported: spans.length, nextOffset, exportId: intentEntryHash };
  }

  private key(id: string, tenant?: string): string { return `${tenant ?? "keep.n1.default"}\0${id}`; }
  private async terminal(actor: string, intentEntryHash: string, reason: string): Promise<boolean> {
    this.config.spine.stage({ type: "effect.terminal", actor, payload: { kind: "telemetry.export.terminal", intentEntryHash, disposition: "error", reason: reason.slice(0, 512) } });
    try { await this.config.spine.seal(); return true; }
    catch { return false; }
  }
}
