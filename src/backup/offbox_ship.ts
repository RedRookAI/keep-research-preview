/**
 * OFFBOX-CONTINUOUS-SHIP-AND-RESTORE (BUILD-ORDER 8.5a) — a CONTINUOUS, fail-closed-VISIBLE off-box
 * ship driver that dogfoods 8.3's validate-on-write discipline at the STORAGE boundary.
 *
 * SOTA basis (2026): the 3-2-1-1-0 rule, and specifically the "0" — zero unverified restores. "A
 * backup you have not tested is not a backup." The 2026 posture is sharper still: an un-verified
 * off-box copy is a LIABILITY, because ransomware deletes/encrypts the primary AND the un-immutable
 * copy — so a ship subsystem must VERIFY the copy it wrote (re-read the object, re-check its hash),
 * never trust the write acknowledgement, and it must fail CLOSED-AND-VISIBLE (UNHEALTHY + alarm),
 * never degrade a ship/verify failure to a quiet green.
 *
 * WHAT THIS DRIVER DOES, on a cadence: it ships the latest sealed snapshot to an INJECTED BackupPort
 * sink, then immediately RE-FETCHES the shipped copy from that sink and RE-RUNS the EXISTING
 * `verifyRestore` predicate over the FETCHED bytes (chain re-verify + content-root match) against the
 * SOURCE (expected) root — the same "+0" notion of a verified backup, not a second one. Ship success
 * ALONE never marks the driver healthy; only a re-fetched-and-re-verified copy does.
 *
 * FRONT OF HOUSE: point it at any BackupPort you own (a private git repo / rsync / S3-compatible path)
 * with zero config beyond the sink; it ships on a cadence, is IGNORABLE (shipOnce/tick NEVER throw —
 * a failure turns the health line red, it does not block the caller), and surfaces one honest health
 * line (healthy / last-verified-at / last-error). BACK OF HOUSE: the durable off-box copy's integrity
 * is CONTINUOUSLY re-proven; a ship failure OR a copy that fails verification leaves the driver
 * UNHEALTHY with a visible alarm — never a silent green.
 *
 * HONEST SEAM (never silently claimed here): `verifyRestore` proves the COPY is complete and
 * untampered, NOT that the off-box TARGET is tamper-proof — WORM/Object-Lock, an independent witness
 * co-sign and credential separation are BUILD-ORDER 8.5b (NEEDS-8.5b) — and NOT that the source truth
 * was itself honest (that remains the province of the higher gates). See OFFBOX_DURABILITY_CAVEAT.
 *
 * Zero deps; no network here — the sink is an injected port, so the cadence + verify-after-ship +
 * fail-closed logic is fully testable with an in-memory/temp-dir fake and NO real egress.
 */

import type { SealedBlock } from "../spine/hashchain.js";
import type { Snapshot, SnapshotRef, BackupPort, Hasher } from "./backup_port.js";
import { buildSnapshot } from "./backup_port.js";
import { verifyRestore, type RestoreVerification } from "./verify_restore.js";

/** What a "verified restore" proves — and, honestly, what it does NOT (the labeled seam). */
export const OFFBOX_DURABILITY_CAVEAT =
  "verified restore proves the shipped COPY is complete and untampered (chain re-verify + content-root " +
  "match, the existing verifyRestore predicate), NOT that the off-box target is tamper-proof " +
  "(WORM/Object-Lock, an independent witness co-sign, credential separation are NEEDS-8.5b) and NOT " +
  "that the source truth was itself honest (that remains the province of the higher gates).";

/** A source of the latest sealed chain to snapshot — injected (the spine's blocks). */
export type ChainSource = () => readonly SealedBlock[];

/** The single honest health state. UNHEALTHY whenever a ship OR a verification has failed. */
export interface ShipHealth {
  /** Green ONLY after a re-fetched-and-re-verified copy; a fresh driver is UNHEALTHY (nothing verified yet). */
  readonly healthy: boolean;
  /** Epoch ms when a shipped copy last PASSED verifyRestore (undefined until the first verified ship). */
  readonly lastVerifiedAt?: number;
  /** The VISIBLE alarm text while UNHEALTHY (a ship failure or a failed verification). */
  readonly lastError?: string;
  /** The id of the last copy that verified. */
  readonly lastShippedId?: string;
  /** Ship attempts so far. */
  readonly ships: number;
  /** Ships whose copy was re-fetched AND re-verified (verifiedShips <= ships always). */
  readonly verifiedShips: number;
}

export interface ShipOutcome {
  readonly ok: boolean;
  readonly ref?: SnapshotRef;
  /** The verifyRestore result over the FETCHED copy — the composition proof (present whenever a copy was fetched). */
  readonly verification?: RestoreVerification;
  readonly health: ShipHealth;
}

/** A tick that fell inside the cadence window and did nothing — IGNORABLE, never a ship. */
export interface ShipSkipped {
  readonly skipped: true;
  readonly health: ShipHealth;
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * The continuous off-box ship driver. Composed over the EXISTING `buildSnapshot` + `verifyRestore`
 * primitives — one notion of a verified backup, re-proven continuously at the storage boundary.
 */
export class OffboxShipDriver {
  // UNHEALTHY until the first ship is re-fetched AND re-verified: an untested backup is not a backup.
  private _healthy = false;
  private _lastVerifiedAt: number | undefined;
  private _lastError: string | undefined = "no ship verified yet";
  private _lastShippedId: string | undefined;
  private _ships = 0;
  private _verifiedShips = 0;
  private _lastShipAt = Number.NEGATIVE_INFINITY;

  constructor(
    private readonly sink: BackupPort,
    private readonly source: ChainSource,
    private readonly hasher: Hasher,
    /** Minimum ms between ships — the cadence. `tick` is a no-op inside this window (never blocks). */
    private readonly intervalMs: number,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  health(): ShipHealth {
    return {
      healthy: this._healthy,
      ...(this._lastVerifiedAt !== undefined ? { lastVerifiedAt: this._lastVerifiedAt } : {}),
      ...(this._lastError !== undefined ? { lastError: this._lastError } : {}),
      ...(this._lastShippedId !== undefined ? { lastShippedId: this._lastShippedId } : {}),
      ships: this._ships,
      verifiedShips: this._verifiedShips,
    };
  }

  /** One honest health line for an operator to glance at. */
  healthLine(): string {
    const h = this.health();
    const stamp = h.lastVerifiedAt !== undefined ? new Date(h.lastVerifiedAt).toISOString() : "never";
    return h.healthy
      ? `offbox ${this.sink.name}: HEALTHY — last verified ${stamp} (${h.verifiedShips}/${h.ships} ships verified)`
      : `offbox ${this.sink.name}: UNHEALTHY — ${h.lastError ?? "not yet verified"} (${h.verifiedShips}/${h.ships} ships verified; last verified ${stamp})`;
  }

  /** Whether the cadence window has elapsed since the last ship attempt. */
  due(now: number = this.clock()): boolean {
    return now - this._lastShipAt >= this.intervalMs;
  }

  /**
   * A cadence tick: ships + verifies IF due, otherwise a no-op. IGNORABLE — never throws, never
   * blocks the main loop; a failure only turns the health line red.
   */
  async tick(now: number = this.clock()): Promise<ShipOutcome | ShipSkipped> {
    if (!this.due(now)) return { skipped: true, health: this.health() };
    return this.shipOnce(now);
  }

  /**
   * Ship the latest sealed snapshot to the sink, then RE-FETCH and RE-VERIFY the shipped copy.
   * Marks the driver healthy ONLY on a proven round-trip. Never throws (fail-closed-and-visible).
   */
  async shipOnce(now: number = this.clock()): Promise<ShipOutcome> {
    this._ships++;
    this._lastShipAt = now;
    const snapshot = buildSnapshot(this.source(), this.hasher, now);

    // (1) SHIP — write the snapshot to the off-box sink. Never trust the ack that follows.
    let ref: SnapshotRef;
    try {
      ref = await this.sink.put(snapshot);
    } catch (e) {
      return this.fail(`ship FAILED to ${this.sink.name}: ${msg(e)}`);
    }

    // (2) RE-FETCH the shipped copy FROM the sink — not the in-memory snapshot. A write ack proves
    //     the sink accepted bytes, not that a complete, untampered object is now durably at rest.
    let fetched: Snapshot | undefined;
    try {
      fetched = await this.sink.get(ref.id);
    } catch (e) {
      return this.fail(`re-fetch FAILED after ship (${ref.id}) from ${this.sink.name}: ${msg(e)}`);
    }
    if (!fetched) {
      return this.fail(`shipped copy ${ref.id} NOT FOUND on re-fetch from ${this.sink.name} — the write-ack was a lie`);
    }

    // (3) RE-VERIFY the FETCHED bytes with the EXISTING verifyRestore predicate, against the SOURCE
    //     (expected) root — chain re-verify + content-root match. A copy that lands but does not
    //     verify is NOT a durable backup.
    const verification = verifyRestore(fetched.blocks, snapshot.contentRoot, this.hasher, now);
    if (!verification.ok) {
      return this.fail(`shipped copy FAILED verifyRestore on ${this.sink.name}: ${verification.reason}`, verification);
    }

    // (4) HEALTHY — only now, after a re-fetched-and-re-verified round-trip.
    this._verifiedShips++;
    this._lastShippedId = ref.id;
    this._lastVerifiedAt = now;
    this._lastError = undefined;
    this._healthy = true;
    return { ok: true, ref, verification, health: this.health() };
  }

  /** Fail CLOSED-AND-VISIBLE: raise the alarm and stay UNHEALTHY until a ship verifies again. */
  private fail(error: string, verification?: RestoreVerification): ShipOutcome {
    this._healthy = false;
    this._lastError = error;
    return { ok: false, ...(verification ? { verification } : {}), health: this.health() };
  }
}
