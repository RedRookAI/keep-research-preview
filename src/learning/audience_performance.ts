import { createHash } from "node:crypto";
import { ContentSanitizer, frameAsUntrustedData } from "../ingest/content_sanitizer.js";
import { IngestionPipeline } from "../ingest/ingestion_pipeline.js";
import { canonicalize } from "../spine/event.js";

export type AudienceSource = "instagram" | "youtube" | "portfolio";
export const AUDIENCE_SOURCES: readonly AudienceSource[] = Object.freeze(["instagram", "youtube", "portfolio"]);
export const AUDIENCE_PERFORMANCE_DOCUMENT = "audience-performance-corpus";
export interface AudienceIngestPrincipal { readonly id: string; readonly kind: "human" | "agent" | "service"; }

export interface PerformanceItem {
  readonly source: AudienceSource;
  readonly id: string;
  readonly title?: string;
  readonly text: string;
  /** User-owned observations. Keep does not claim the platform attested them. */
  readonly metrics: Readonly<Record<string, number>>;
  readonly attributes?: readonly string[];
  readonly exportId?: string;
  readonly observedAt?: number;
}

interface StoredPerformanceItem extends PerformanceItem {
  readonly attributes: readonly string[];
  readonly exportId: string;
  readonly observedAt: number;
  readonly importedAt: number;
  readonly itemDigest: string;
  readonly provenance: "authenticated-principal-unattested-export";
  readonly ingestedBy: AudienceIngestPrincipal;
  readonly projectId: string;
  readonly tenant: string | null;
  readonly purpose: "audience-performance-analysis";
  readonly lawfulBasis: "consent";
  readonly sensitivityTier: "internal";
  readonly metricSemantics: Readonly<Record<string, "user-provided-unattested">>;
}

export interface PerformanceSignal {
  readonly attribute: string;
  readonly observations: number;
  readonly average: number;
  readonly lift: number;
  readonly standardError: number | null;
  readonly comparisonObservations: number;
  readonly evidence: "exploratory" | "measured" | "no-contrast";
}
export interface PerformanceAnalysis {
  readonly metric: string;
  readonly items: number;
  readonly baseline: number;
  readonly source: AudienceSource;
  readonly causal: false;
  readonly signals: readonly PerformanceSignal[];
}
export interface GenerationCandidate { readonly id: string; readonly text: string; readonly attributes?: readonly string[]; }
export interface RankedCandidate extends GenerationCandidate { readonly score: number; readonly reasons: readonly string[]; readonly evidence: "none" | "exploratory" | "measured"; }
export interface AudiencePerformancePersistence { load(): { readonly snapshot: unknown; readonly revision: number | undefined }; save(snapshot: unknown, expectedRevision: number | undefined): number; }
export interface AudiencePerformanceContext {
  readonly projectId: string;
  readonly tenant?: string;
  readonly ingestion: IngestionPipeline;
  readonly guard?: (expectedDocumentRevision: number | undefined) => void;
}

const SOURCES = new Set<AudienceSource>(AUDIENCE_SOURCES);
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const MAX_CONTENT_BYTES = 1024 * 1024;
const MAX_CORPUS_BYTES = 8 * 1024 * 1024;
const MAX_ITEMS = 10_000;
const MAX_METRICS = 100;
const MAX_ATTRIBUTES = 100;
const MIN_MEASURED_OBSERVATIONS = 3;
const PERSISTED_ITEM_KEYS = new Set(["source", "id", "title", "text", "metrics", "attributes", "exportId", "observedAt", "importedAt", "itemDigest", "provenance", "ingestedBy", "projectId", "tenant", "purpose", "lawfulBasis", "sensitivityTier", "metricSemantics"]);

const digest = (value: string): string => createHash("sha256").update(value).digest("hex");
function finiteMetric(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new Error(`metric ${name} must be a finite non-negative number`);
  return value;
}
function boundedText(value: unknown, label: string, max: number): string {
  if (typeof value !== "string" || value.includes("\0") || Buffer.byteLength(value, "utf8") > max) throw new Error(`${label} is invalid or oversized`);
  return value;
}
function cleanAttributes(values: unknown): string[] {
  if (values === undefined) return [];
  if (!Array.isArray(values) || values.length > MAX_ATTRIBUTES || values.some((value) => typeof value !== "string" || Buffer.byteLength(value, "utf8") > 128 || value.includes("\0"))) throw new Error("performance attributes exceed the bound");
  return [...new Set(values.map((value) => value.trim().toLowerCase()).filter(Boolean))].sort();
}
function canonicalItem(item: PerformanceItem, now: number, ingestedBy: AudienceIngestPrincipal, context: AudiencePerformanceContext): StoredPerformanceItem {
  if (item === null || typeof item !== "object" || !SOURCES.has(item.source)) throw new Error("unsupported audience export source");
  const id = boundedText(item.id, "performance item id", 256).trim();
  if (!id || /[\u0000-\u001f\u007f]/u.test(id)) throw new Error("performance item id is required and cannot contain control characters");
  const text = boundedText(item.text, "performance item text", MAX_CONTENT_BYTES);
  const title = item.title === undefined ? undefined : boundedText(item.title, "performance item title", MAX_CONTENT_BYTES).trim();
  if (!text.trim() && !title) throw new Error("performance item content is required");
  if (Buffer.byteLength(`${title ?? ""}\n${text}`, "utf8") > MAX_CONTENT_BYTES) throw new Error("performance item content exceeds the byte bound");
  if (item.metrics === null || typeof item.metrics !== "object" || Array.isArray(item.metrics)) throw new Error("performance metrics are required");
  const metricRows = Object.entries(item.metrics);
  if (metricRows.length === 0 || metricRows.length > MAX_METRICS) throw new Error("at least one bounded user-provided metric is required");
  const metrics: Record<string, number> = {};
  for (const [rawName, rawValue] of metricRows) {
    const name = rawName.trim();
    if (!SAFE_NAME.test(name)) throw new Error("metric name is required and bounded");
    metrics[name] = finiteMetric(rawValue, name);
  }
  const attributes = cleanAttributes(item.attributes);
  const hostileFields = [id, ...attributes].map((value) => new ContentSanitizer().sanitize(value));
  if (hostileFields.some((value) => value.report.neutralizedInstructions > 0)) throw new Error("hostile instructions in audience export identity or attributes are not admitted");
  const exportId = item.exportId === undefined ? `unattested-${digest(`${item.source}\0${id}`).slice(0, 32)}` : boundedText(item.exportId, "export id", 256).trim();
  if (!exportId || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(exportId) || /[\u0000-\u001f\u007f]/u.test(exportId)) throw new Error("export id is invalid");
  const observedAt = item.observedAt ?? now;
  if (!Number.isSafeInteger(observedAt) || observedAt < 0 || observedAt > now + 300_000) throw new Error("observation time is invalid");
  if (!ingestedBy || typeof ingestedBy.id !== "string" || !ingestedBy.id.trim() || Buffer.byteLength(ingestedBy.id, "utf8") > 512 || !["human", "agent", "service"].includes(ingestedBy.kind)) throw new Error("authenticated ingest principal is required");
  const actor = Object.freeze({ id: ingestedBy.id, kind: ingestedBy.kind });
  const metricSemantics = Object.freeze(Object.fromEntries(Object.keys(metrics).map((name) => [name, "user-provided-unattested" as const])));
  const governance = { projectId: context.projectId, tenant: context.tenant ?? null, purpose: "audience-performance-analysis" as const, lawfulBasis: "consent" as const, sensitivityTier: "internal" as const, metricSemantics };
  const material = canonicalize({ source: item.source, id, title: title ?? null, text, metrics, attributes, exportId, observedAt, ingestedBy: actor, ...governance });
  return Object.freeze({ source: item.source, id, ...(title ? { title } : {}), text, metrics: Object.freeze(metrics), attributes: Object.freeze(attributes), exportId, observedAt, importedAt: now, itemDigest: digest(material), provenance: "authenticated-principal-unattested-export", ingestedBy: actor, ...governance });
}
function variance(values: readonly number[], mean: number): number | null {
  if (values.length < 2) return null;
  return values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (values.length - 1);
}
function tokens(value: string): string[] { return value.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter((term) => term.length > 1); }

export class AudiencePerformanceCorpus {
  readonly #items = new Map<string, StoredPerformanceItem>();
  readonly #sanitizer = new ContentSanitizer();
  #revision: number;
  #persistencePresent: boolean;
  constructor(private readonly context: AudiencePerformanceContext, private readonly persistence?: AudiencePerformancePersistence, private readonly clock: () => number = Date.now, private readonly minimumEvidence = MIN_MEASURED_OBSERVATIONS) {
    if (!Number.isSafeInteger(minimumEvidence) || minimumEvidence < 2 || minimumEvidence > 10_000) throw new Error("audience evidence floor must be between 2 and 10000");
    const loaded = persistence?.load() ?? { snapshot: undefined, revision: undefined };
    this.#revision = loaded.revision ?? 0;
    this.#persistencePresent = loaded.revision !== undefined;
    if (loaded.snapshot === undefined) return;
    if (!Number.isSafeInteger(loaded.revision) || loaded.revision! < 0) throw new Error("invalid persisted audience-performance revision");
    const persisted = loaded.snapshot;
    if (persisted === null || typeof persisted !== "object" || Array.isArray(persisted)) throw new Error("invalid persisted audience-performance corpus");
    const row = persisted as Record<string, unknown>;
    if (row["schemaVersion"] !== 1 || !Array.isArray(row["items"]) || row["items"].length > MAX_ITEMS || Object.keys(row).some((key) => !["schemaVersion", "items"].includes(key))) throw new Error("invalid persisted audience-performance corpus");
    for (const value of row["items"]) {
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid persisted performance item");
      const raw = value as Record<string, unknown>;
      if (Object.keys(raw).some((key) => !PERSISTED_ITEM_KEYS.has(key))
        || !Number.isSafeInteger(raw["importedAt"]) || (raw["importedAt"] as number) < 0
        || typeof raw["itemDigest"] !== "string" || !/^[a-f0-9]{64}$/u.test(raw["itemDigest"])
        || raw["provenance"] !== "authenticated-principal-unattested-export"
        || raw["ingestedBy"] === null || typeof raw["ingestedBy"] !== "object" || Array.isArray(raw["ingestedBy"])) throw new Error("invalid persisted performance item");
      const candidate = raw as unknown as StoredPerformanceItem;
      if (candidate.importedAt > this.clock() + 300_000) throw new Error("persisted performance import time is invalid");
      const normalized = canonicalItem(candidate, candidate.importedAt, candidate.ingestedBy, context);
      if (candidate.provenance !== normalized.provenance || candidate.itemDigest !== normalized.itemDigest || candidate.importedAt !== normalized.importedAt) throw new Error("persisted performance provenance is invalid");
      const key = `${normalized.source}:${normalized.id}`;
      if (this.#items.has(key)) throw new Error("duplicate persisted performance item");
      this.#items.set(key, normalized);
      context.ingestion.ingest({ sourceId: key, text: `${normalized.title ?? ""}\n${normalized.text}\n${normalized.attributes.join(" ")}`, purpose: normalized.purpose, lawfulBasis: normalized.lawfulBasis, baseTier: normalized.sensitivityTier });
    }
  }

  private guard(): void { this.context.guard?.(this.#persistencePresent ? this.#revision : undefined); }

  ingest(item: PerformanceItem, ingestedBy: AudienceIngestPrincipal): { readonly items: number; readonly replaced: boolean; readonly itemDigest: string; readonly priorDigest?: string; readonly platformAttested: false; readonly observedAt: number; readonly remainingBytes: number } {
    this.guard();
    const normalized = canonicalItem(item, this.clock(), ingestedBy, this.context);
    const hostile = this.#sanitizer.sanitize(`${normalized.title ?? ""}\n${normalized.text}`);
    if (hostile.report.neutralizedInstructions > 0) throw new Error("hostile instructions in owned export are not admitted to the corpus");
    const key = `${normalized.source}:${normalized.id}`;
    const next = new Map(this.#items); const prior = next.get(key);
    if (prior !== undefined && normalized.observedAt < prior.observedAt) throw new Error("stale audience export cannot replace a newer observation");
    const replaced = prior !== undefined; next.set(key, normalized);
    const snapshot = Object.freeze({ schemaVersion: 1 as const, items: Object.freeze([...next.values()].sort((a, b) => `${a.source}:${a.id}`.localeCompare(`${b.source}:${b.id}`))) });
    const snapshotBytes = Buffer.byteLength(JSON.stringify(snapshot), "utf8");
    if (snapshot.items.length > MAX_ITEMS || snapshotBytes > MAX_CORPUS_BYTES) throw new Error("audience-performance corpus exceeds the durable bound");
    const nextRevision = this.persistence?.save(snapshot, this.#persistencePresent ? this.#revision : undefined) ?? this.#revision;
    if (prior !== undefined) this.context.ingestion.eraseSource(key);
    this.context.ingestion.ingest({ sourceId: key, text: `${normalized.title ?? ""}\n${normalized.text}\n${normalized.attributes.join(" ")}`, purpose: normalized.purpose, lawfulBasis: normalized.lawfulBasis, baseTier: normalized.sensitivityTier });
    this.#revision = nextRevision;
    if (this.persistence !== undefined) this.#persistencePresent = true;
    this.#items.clear(); for (const [id, value] of next) this.#items.set(id, value);
    return Object.freeze({ items: this.#items.size, replaced, itemDigest: normalized.itemDigest, ...(prior ? { priorDigest: prior.itemDigest } : {}), platformAttested: false, observedAt: normalized.observedAt, remainingBytes: MAX_CORPUS_BYTES - snapshotBytes });
  }

  search(query: string, k = 5): ReadonlyArray<{ sourceId: string; text: string; score: number; itemDigest: string }> {
    this.guard();
    if (typeof query !== "string" || Buffer.byteLength(query, "utf8") > 4_096 || !Number.isSafeInteger(k) || k < 1 || k > 100) throw new Error("bounded search query required");
    const terms = tokens(query); if (terms.length === 0) return [];
    return [...this.#items.values()].map((item) => {
      const searchable = new Set(tokens(`${item.title ?? ""}\n${item.text}\n${item.attributes.join(" ")}`));
      const score = terms.reduce((sum, term) => sum + (searchable.has(term) ? 1 : 0), 0) / terms.length;
      const sourceId = `${item.source}:${item.id}`;
      return { sourceId, text: frameAsUntrustedData([item.title, item.text].filter(Boolean).join("\n"), sourceId), score, itemDigest: item.itemDigest };
    }).filter((hit) => hit.score > 0).sort((a, b) => b.score - a.score || a.sourceId.localeCompare(b.sourceId)).slice(0, k);
  }

  analyze(metric: string, higherIsBetter = true, source?: AudienceSource): PerformanceAnalysis {
    this.guard();
    if (!SAFE_NAME.test(metric)) throw new Error("metric name is required and bounded");
    if (source !== undefined && !SOURCES.has(source)) throw new Error("unsupported audience export source");
    const eligible = [...this.#items.values()].filter((item) => Object.hasOwn(item.metrics, metric));
    const sourceSet = [...new Set(eligible.map((item) => item.source))];
    if (source === undefined && sourceSet.length > 1) throw new Error(`metric ${metric} exists across multiple sources (${sourceSet.sort().join(", ")}); an exact source is required`);
    const selectedSource = source ?? sourceSet[0];
    const measured = eligible.filter((item) => item.source === selectedSource);
    if (measured.length === 0) throw new Error(`no user-provided values for metric ${metric}`);
    const values = measured.map((item) => finiteMetric(item.metrics[metric], metric));
    const baseline = values.reduce((sum, value) => sum + value, 0) / values.length;
    const attributes = [...new Set(measured.flatMap((item) => item.attributes))];
    const direction = higherIsBetter ? 1 : -1;
    const signals = attributes.map((attribute): PerformanceSignal => {
      const observations = measured.flatMap((item, index) => item.attributes.includes(attribute) ? [values[index]!] : []);
      const comparison = measured.flatMap((item, index) => item.attributes.includes(attribute) ? [] : [values[index]!]);
      const average = observations.reduce((sum, value) => sum + value, 0) / observations.length;
      const comparisonAverage = comparison.length === 0 ? baseline : comparison.reduce((sum, value) => sum + value, 0) / comparison.length;
      const sampleVariance = variance(observations, average); const comparisonVariance = variance(comparison, comparisonAverage);
      const standardError = sampleVariance === null || comparisonVariance === null ? null : Math.sqrt(sampleVariance / observations.length + comparisonVariance / comparison.length);
      const lift = (average - comparisonAverage) * direction;
      const evidence = comparison.length === 0 ? "no-contrast" : observations.length >= this.minimumEvidence && comparison.length >= this.minimumEvidence && standardError !== null && Math.abs(lift) > 1.96 * standardError ? "measured" : "exploratory";
      return Object.freeze({ attribute, observations: observations.length, comparisonObservations: comparison.length, average, lift, standardError, evidence });
    }).sort((a, b) => b.lift - a.lift || b.observations - a.observations || a.attribute.localeCompare(b.attribute));
    return Object.freeze({ metric, items: measured.length, baseline, source: selectedSource!, causal: false, signals: Object.freeze(signals) });
  }

  rankCandidates(candidates: readonly GenerationCandidate[], metric: string, higherIsBetter = true, source?: AudienceSource, preparedAnalysis?: PerformanceAnalysis): RankedCandidate[] {
    this.guard();
    if (!Array.isArray(candidates) || candidates.length === 0 || candidates.length > 100) throw new Error("generation candidates must contain 1 to 100 bounded items");
    const ids = new Set<string>();
    const normalized: Array<{ readonly id: string; readonly text: string; readonly attributes: string[] }> = candidates.map((candidate) => {
      if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) throw new Error("generation candidate is invalid");
      const id = boundedText(candidate.id, "generation candidate id", 256).trim();
      const text = boundedText(candidate.text, "generation candidate text", MAX_CONTENT_BYTES);
      if (!id || !text.trim() || ids.has(id)) throw new Error("generation candidate ids must be unique and content is required");
      ids.add(id); return { id, text, attributes: cleanAttributes(candidate.attributes) };
    });
    const analysis = preparedAnalysis ?? this.analyze(metric, higherIsBetter, source); const signals = new Map(analysis.signals.map((signal) => [signal.attribute, signal]));
    return normalized.map((candidate): RankedCandidate => {
      const contributing = candidate.attributes.map((attribute) => signals.get(attribute)).filter((signal): signal is PerformanceSignal => signal !== undefined);
      const measuredSignals = contributing.filter((signal) => signal.evidence === "measured");
      const score = measuredSignals.reduce((sum, signal) => sum + signal.lift * (signal.observations / (signal.observations + this.minimumEvidence)), 0);
      const evidence = contributing.length === 0 ? "none" : measuredSignals.length === contributing.length ? "measured" : "exploratory";
      const reasons = contributing.sort((a, b) => b.lift - a.lift).map((signal) => `${signal.attribute}: ${signal.lift >= 0 ? "+" : ""}${signal.lift.toFixed(2)} vs non-matching items (${signal.observations} matching, ${signal.comparisonObservations} comparison; ${signal.evidence}; descriptive, not causal)`);
      return Object.freeze({ ...candidate, score, reasons: Object.freeze(reasons), evidence });
    }).sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  }

  forget(source: AudienceSource, id: string): { readonly removed: boolean; readonly items: number; readonly remainingBytes: number } {
    this.guard();
    if (!SOURCES.has(source)) throw new Error("unsupported audience export source");
    const cleanId = boundedText(id, "performance item id", 256).trim();
    const key = `${source}:${cleanId}`; if (!this.#items.has(key)) return { removed: false, items: this.#items.size, remainingBytes: MAX_CORPUS_BYTES - Buffer.byteLength(JSON.stringify({ schemaVersion: 1, items: [...this.#items.values()] }), "utf8") };
    const next = new Map(this.#items); next.delete(key);
    const snapshot = Object.freeze({ schemaVersion: 1 as const, items: Object.freeze([...next.values()].sort((a, b) => `${a.source}:${a.id}`.localeCompare(`${b.source}:${b.id}`))) });
    const nextRevision = this.persistence?.save(snapshot, this.#persistencePresent ? this.#revision : undefined) ?? this.#revision;
    this.context.ingestion.eraseSource(key); this.#revision = nextRevision; this.#items.delete(key);
    if (this.persistence !== undefined) this.#persistencePresent = true;
    return { removed: true, items: this.#items.size, remainingBytes: MAX_CORPUS_BYTES - Buffer.byteLength(JSON.stringify(snapshot), "utf8") };
  }

  governanceExport(): Array<Record<string, unknown>> { this.guard(); return this.context.ingestion.governance.ropaExport(); }
}
