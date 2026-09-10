/**
 * SkillCanary (Increment 18.6, Phase S) — retention + reuse-reward + notify. Completes the skill lifecycle:
 * a CEGIS-validated skill (18.5) does NOT wait in shadow — it goes LIVE immediately as an instant-rollback
 * CANARY, earns full trust through real use, and auto-rolls-back the moment it regresses. Safety comes from
 * REVERSIBILITY + BOUNDED BLAST RADIUS + AUTO-ROLLBACK, not from delay (KEEP_INSTANT_SAFE_ACTIVATION).
 *
 * SOTA basis (2026-08-05):
 *  - Progressive delivery: "Deploy, Observe, Decide, Expand" — ship instantly behind an instant kill-switch,
 *    watch a small blast radius, auto-roll-back on regression (canary/feature-flags 2026). Safety = structure,
 *    not time.
 *  - Sequential/evidence-based promotion, not a fixed wait — "promote as soon as confidence is reached"
 *    (GrowthBook AI-canary 2026; Netflix sequential canary). Keep's per-use signal is STRONG (execution +
 *    human verdict ≈ near-binary), so FAR fewer uses than a traffic canary are needed.
 *  - KEEP_KNOBS_RESOLVED: K1 canary floor 3 clean uses / ceiling ~10 / INSTANT-DEMOTE on any regression;
 *    K5 alert tiers — SILENT (Log) graduate, quiet TICKET rollback, PAGE only irreversible/ambiguous.
 *
 * Zero runtime deps. Notifier behind a port (digest at the floor; pager integration at the rich tier).
 */

import { reuseSignal, type OutcomeSignal } from "./self_improvement_bus.js";

export type CanaryState = "canary" | "graduated" | "rolled-back";

/** Alert tiers (K5) — by reversibility + actionability. */
export type AlertTier = "log" | "ticket" | "page";

export interface CanaryNotice {
  readonly tier: AlertTier;
  readonly skillId: string;
  readonly message: string;
}

/** A notifier port. The floor writes to a digest (log/ticket); the rich tier can page. */
export interface CanaryNotifier {
  notify(notice: CanaryNotice): void;
}

export interface SkillCanaryConfig {
  /** Clean uses to graduate provisional → full (K1 floor). Default 3. */
  readonly graduateFloor?: number;
  /** Ceiling of uses after which a still-un-graduated canary just stays provisional (K1). Default 10. */
  readonly ceiling?: number;
  readonly notifier?: CanaryNotifier;
}

interface CanaryRecord {
  readonly skillId: string;
  state: CanaryState;
  cleanUses: number;      // consecutive clean triggered uses
  totalUses: number;
  /** True if this skill touches an irreversible/external effect (→ rollback Pages instead of Tickets). */
  readonly irreversible: boolean;
  revision?: string;
}

export interface UseResult {
  readonly skillId: string;
  readonly state: CanaryState;
  readonly cleanUses: number;
  /** What happened this use: graduated / demoted / still-canary / (skill unknown). */
  readonly transition: "went-live" | "graduated" | "rolled-back" | "still-canary" | "unknown" | "unchanged";
}

export class SkillCanary {
  private readonly graduateFloor: number;
  private readonly ceiling: number;
  private readonly notifier: CanaryNotifier | undefined;
  private readonly records = new Map<string, CanaryRecord>();

  constructor(config: SkillCanaryConfig = {}) {
    this.graduateFloor = config.graduateFloor ?? 3;
    this.ceiling = config.ceiling ?? 10;
    this.notifier = config.notifier;
  }

  /**
   * Trusted callers activate only after their required admission has committed. A
   * changed, explicitly bound revision starts a fresh canary; repeated activation
   * returns its actual state. This component does not perform validation itself.
   */
  goLive(skillId: string, opts: { irreversible?: boolean; revision?: string } = {}): UseResult {
    const existing = this.records.get(skillId);
    const replaced = existing?.revision !== undefined && opts.revision !== undefined && existing.revision !== opts.revision;
    if (!existing || replaced) {
      this.records.set(skillId, { skillId, state: "canary", cleanUses: 0, totalUses: 0, irreversible: opts.irreversible ?? existing?.irreversible ?? false,
        ...(opts.revision !== undefined ? { revision: opts.revision } : {}) });
      this.emit("log", skillId, "skill promoted provisionally as a monitored canary");
      return { skillId, state: "canary", cleanUses: 0, transition: "went-live" };
    }
    // An unbound terminal record establishes neither identity nor a changed version.
    if (existing.state !== "rolled-back" && existing.revision === undefined && opts.revision !== undefined) existing.revision = opts.revision;
    return { skillId, state: existing.state, cleanUses: existing.cleanUses, transition: "unchanged" };
  }

  /** Restore a previously admitted live skill after restart without claiming a new promotion or notifying again. */
  restoreLive(skillId: string, revision?: string): void {
    if (!this.records.has(skillId)) this.records.set(skillId, { skillId, state: "canary", cleanUses: 0, totalUses: 0, irreversible: false,
      ...(revision !== undefined ? { revision } : {}) });
  }

  revision(skillId: string): string | undefined { return this.records.get(skillId)?.revision; }

  /**
   * Record one triggered USE of a live skill, adjudicated by the outcome signal (execution + human verdict via
   * reuseSignal). A positive-reward use is a clean use → may graduate at the floor. ANY regression (negative
   * reward: failed test OR human reject) → INSTANT DEMOTE (rollback), no "3 strikes". Blast-radius minimization.
   */
  recordUse(skillId: string, signal: OutcomeSignal): UseResult {
    const rec = this.records.get(skillId);
    if (!rec) return { skillId, state: "rolled-back", cleanUses: 0, transition: "unknown" };
    if (rec.state !== "canary") {
      // Already graduated or rolled back — graduated skills still get monitored (a regression can demote a
      // graduated skill too), but a rolled-back one is terminal.
      if (rec.state === "graduated") return this.monitorGraduated(rec, signal);
      return { skillId, state: rec.state, cleanUses: rec.cleanUses, transition: "still-canary" };
    }

    rec.totalUses++;
    const { reward } = reuseSignal(signal);

    // INSTANT DEMOTE on a regression. A regression is EITHER a failed test OR an explicit human REJECT — the
    // human merge gate is authoritative for retention (a reject means the skill produced a PR they won't
    // merge, even if tests passed). This is distinct from the net reuse-REWARD (which stays net-neutral for
    // passing-tests+reject as the Goodhart guard on graduation CREDIT — a reject never counts as a clean use).
    const regressed = !signal.testsPassed || signal.mergeVerdict === "rejected";
    if (regressed) {
      rec.state = "rolled-back";
      this.emitRollback(rec, signal);
      return { skillId, state: "rolled-back", cleanUses: rec.cleanUses, transition: "rolled-back" };
    }

    if (reward > 0) rec.cleanUses++;
    // else reward == 0 (neutral, e.g. a "pending" human verdict) — not clean, not a regression.

    if (rec.cleanUses >= this.graduateFloor) {
      rec.state = "graduated";
      this.emit("log", rec.skillId, `skill graduated to full trust after ${rec.cleanUses} clean uses`);
      return { skillId, state: "graduated", cleanUses: rec.cleanUses, transition: "graduated" };
    }
    return { skillId, state: "canary", cleanUses: rec.cleanUses, transition: "still-canary" };
  }

  /** A graduated skill is still watched: a later regression demotes it (drift/reuse decline). */
  private monitorGraduated(rec: CanaryRecord, signal: OutcomeSignal): UseResult {
    const regressed = !signal.testsPassed || signal.mergeVerdict === "rejected";
    if (regressed) {
      rec.state = "rolled-back";
      this.emitRollback(rec, signal);
      return { skillId: rec.skillId, state: "rolled-back", cleanUses: rec.cleanUses, transition: "rolled-back" };
    }
    return { skillId: rec.skillId, state: "graduated", cleanUses: rec.cleanUses, transition: "still-canary" };
  }

  /** External trigger: drift safe-mode or reuse-reward decline forces a rollback (not a per-use failure). */
  forceRollback(skillId: string, reason: string): UseResult {
    const rec = this.records.get(skillId);
    if (!rec || rec.state === "rolled-back") return { skillId, state: "rolled-back", cleanUses: 0, transition: rec ? "still-canary" : "unknown" };
    rec.state = "rolled-back";
    this.emit(rec.irreversible ? "page" : "ticket", skillId, `skill rolled back: ${reason}`);
    return { skillId, state: "rolled-back", cleanUses: rec.cleanUses, transition: "rolled-back" };
  }

  state(skillId: string): CanaryState | undefined { return this.records.get(skillId)?.state; }
  /** Live skills (canary or graduated) — the ones currently in use. */
  liveSkills(): readonly string[] {
    return [...this.records.values()].filter((r) => r.state !== "rolled-back").map((r) => r.skillId);
  }

  private emitRollback(rec: CanaryRecord, signal: OutcomeSignal): void {
    // K5: reversible rollback = quiet Ticket (no human action needed); irreversible = Page.
    const tier: AlertTier = rec.irreversible ? "page" : "ticket";
    const why = signal.mergeVerdict === "rejected" ? (signal.rejectReason ?? "human rejected the PR") : "produced failing tests";
    this.emit(tier, rec.skillId, `tried a skill, it underperformed (${why}) — reverted${rec.irreversible ? " (IRREVERSIBLE — needs review)" : ", nothing to do"}`);
  }

  private emit(tier: AlertTier, skillId: string, message: string): void {
    try { this.notifier?.notify({ tier, skillId, message }); }
    catch { /* notification failure cannot split or reverse the canary state transition */ }
  }
}
