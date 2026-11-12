/** Score configured models using recorded measurements, a dated snapshot and structural fallback. */

import type { BrainDescriptor } from "./brain_port.js";
import { classifyCapability, type CapabilityTier, type CapabilitySignals } from "./capability_adaptive.js";

export type CapabilitySource = "measured" | "snapshot" | "inferred";

export interface CapabilityRecord {
  /** A stable key for the model (providerLabel + model, or just providerLabel). */
  readonly key: string;
  readonly tier: CapabilityTier;
  /** 0..1 capability score used for ranking. */
  readonly score: number;
  readonly source: CapabilitySource;
  /** ISO date (YYYY-MM-DD) this record was last updated. */
  readonly asOf: string;
}

const TIER_SCORE: Record<CapabilityTier, number> = { rich: 0.9, standard: 0.65, lean: 0.4, minimal: 0.15 };

function brainKey(brain: BrainDescriptor): string {
  return brain.model ? `${brain.providerLabel}::${brain.model}` : brain.providerLabel;
}

function todayISO(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

/** How stale a registry's knowledge is considered, in days, before it warns. */
const STALE_AFTER_DAYS = 120;

export class CapabilityRegistry {
  /** Measured quality from own runs: key -> {score, asOf}. Highest precedence. */
  private readonly measured = new Map<string, { score: number; asOf: string }>();
  /** Snapshot capability data (refreshable): key -> record. */
  private readonly snapshot = new Map<string, CapabilityRecord>();
  private snapshotAsOf: string;

  constructor(snapshotAsOf?: string, seed: readonly CapabilityRecord[] = []) {
    this.snapshotAsOf = snapshotAsOf ?? todayISO();
    for (const r of seed) this.snapshot.set(r.key, r);
  }

  /**
   * Record a MEASURED quality observation from an actual run (self-update from
   * experience). Uses an exponential moving average so recent runs weigh more.
   */
  recordMeasuredQuality(brain: BrainDescriptor, quality01: number, now: Date = new Date()): void {
    const key = brainKey(brain);
    const prev = this.measured.get(key);
    const blended = prev ? prev.score * 0.7 + quality01 * 0.3 : quality01;
    this.measured.set(key, { score: clamp01(blended), asOf: todayISO(now) });
  }

  /** Refresh the snapshot (e.g. from a live benchmark feed on the connected env). */
  refreshSnapshot(records: readonly CapabilityRecord[], asOf?: string): void {
    for (const r of records) this.snapshot.set(r.key, r);
    this.snapshotAsOf = asOf ?? todayISO();
  }

  /** The capability record for a brain, using the highest-trust available signal. */
  capabilityOf(brain: BrainDescriptor, signals: CapabilitySignals = {}): CapabilityRecord {
    const key = brainKey(brain);

    const m = this.measured.get(key);
    if (m) return { key, tier: scoreToTier(m.score), score: m.score, source: "measured", asOf: m.asOf };

    const snap = this.snapshot.get(key);
    if (snap) return snap;

    // Structural inference floor.
    const tier = classifyCapability(brain, signals);
    return { key, tier, score: TIER_SCORE[tier], source: "inferred", asOf: this.snapshotAsOf };
  }

  /** Whether the registry's snapshot knowledge is stale relative to `now`. */
  isStale(now: Date = new Date()): boolean {
    const ageDays = (Date.parse(todayISO(now)) - Date.parse(this.snapshotAsOf)) / 86_400_000;
    return ageDays > STALE_AFTER_DAYS;
  }

  /** A plain-language staleness note for the operator/dashboard. */
  stalenessNote(now: Date = new Date()): string {
    return this.isStale(now)
      ? `The model ranking snapshot from ${this.snapshotAsOf} is out of date. Refresh the list or compare recent results from your configured models.`
      : `Model rankings are current as of ${this.snapshotAsOf}, with any recorded results from your setup.`;
  }
}

function clamp01(n: number): number {
  return n < 0 ? 0 : n > 1 ? 1 : n;
}
function scoreToTier(score: number): CapabilityTier {
  if (score >= 0.85) return "rich";
  if (score >= 0.6) return "standard";
  if (score >= 0.35) return "lean";
  return "minimal";
}
