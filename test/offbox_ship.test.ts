import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import type { SealedBlock } from "../src/spine/hashchain.js";
import type { StagedEvent } from "../src/spine/event.js";
import { buildSnapshot, type Snapshot, type SnapshotRef, type BackupPort } from "../src/backup/backup_port.js";
import { verifyRestore } from "../src/backup/verify_restore.js";
import { OffboxShipDriver, OFFBOX_DURABILITY_CAVEAT } from "../src/backup/offbox_ship.js";
import { composeLifecycle } from "../src/lifecycle/compose_lifecycle.js";

/**
 * OFFBOX-CONTINUOUS-SHIP-AND-RESTORE (BUILD-ORDER 8.5a). Five paired-neuter tests, each isolating a
 * distinct guard on the continuous off-box ship driver, driven by a FAULT-INJECTING in-memory sink —
 * NO real network egress. The sink accepts writes and can corrupt / truncate / drop / refuse on READ,
 * so the cadence + verify-after-ship + fail-closed-VISIBLE behaviour is deterministic and offline.
 */

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

function blocksOf(spine: Spine): readonly SealedBlock[] {
  return (spine as unknown as { store: { readBlocks(): SealedBlock[] } }).store.readBlocks();
}

/** Produce a real sealed chain by staging + sealing events (mirrors backup.test.ts). */
async function sealedChain(events = 3): Promise<readonly SealedBlock[]> {
  const dir = mkdtempSync(join(tmpdir(), "keep-offbox-"));
  const spine = new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
  for (let i = 0; i < events; i++) {
    spine.stage({ type: "generic", actor: "test", payload: { i } });
    await spine.seal();
  }
  return blocksOf(spine);
}

/** Tamper one event WITHOUT changing block count — a corrupt-on-read copy that lies about its content. */
function tamperOne(blocks: readonly SealedBlock[]): readonly SealedBlock[] {
  const out = blocks.map((b) => ({ ...b, events: b.events.slice() as StagedEvent[] }));
  const b = out[out.length - 1]!;
  const e = b.events[0]!;
  b.events[0] = { ...e, payload: { ...(e.payload as object), injected: "TAMPERED-IN-TRANSIT" } } as StagedEvent;
  return out;
}

type ReadMode = "exact" | "truncate" | "tamperSameCount" | "notFound" | "throwOnGet";

/** A fault-injecting BackupPort: accepts writes, can corrupt/drop/refuse on read (fixture only). */
class FaultSink implements BackupPort {
  readonly requiresAccount = false;
  private readonly store = new Map<string, Snapshot>();
  throwOnPut = false;
  readMode: ReadMode = "exact";
  constructor(readonly name = "fault-sink") {}

  async put(snapshot: Snapshot): Promise<SnapshotRef> {
    if (this.throwOnPut) throw new Error("sink write refused (injected fault)");
    this.store.set(snapshot.id, snapshot);
    return { id: snapshot.id, contentRoot: snapshot.contentRoot, takenAt: snapshot.takenAt, blockCount: snapshot.blockCount };
  }
  async list(): Promise<readonly SnapshotRef[]> {
    return [...this.store.values()].map((s) => ({ id: s.id, contentRoot: s.contentRoot, takenAt: s.takenAt, blockCount: s.blockCount }));
  }
  async get(id: string): Promise<Snapshot | undefined> {
    const s = this.store.get(id);
    if (!s) return undefined;
    switch (this.readMode) {
      case "throwOnGet": throw new Error("sink read failed (injected fault)");
      case "notFound": return undefined; // write ack'd, object not actually durable
      case "truncate": return { ...s, blocks: s.blocks.slice(0, -1), blockCount: s.blockCount - 1 };
      case "tamperSameCount": return { ...s, blocks: tamperOne(s.blocks) };
      default: return s;
    }
  }
}

// ── T-a — verify is load-bearing: a fresh driver is UNHEALTHY (nothing verified yet). [neuter a] ──
test("offbox: a fresh driver is UNHEALTHY until a ship is re-fetched AND re-verified (never a silent green)", async () => {
  const blocks = await sealedChain(3);
  const sink = new FaultSink();
  const driver = new OffboxShipDriver(sink, () => blocks, sha256, 1000, () => 0);

  // Nothing has been shipped+verified, so the driver must NOT report healthy — an untested backup is
  // not a backup. (neuter a starts _healthy=true and this flips RED.)
  const h0 = driver.health();
  assert.equal(h0.healthy, false, "a driver that has verified nothing must be UNHEALTHY");
  assert.equal(h0.verifiedShips, 0);
  assert.equal(h0.lastVerifiedAt, undefined);
  assert.match(driver.healthLine(), /UNHEALTHY/);

  // And after one good ship it DOES go healthy — proving the flip is real, not stuck.
  const out = await driver.shipOnce(5000);
  assert.equal(out.ok, true);
  assert.equal(driver.health().healthy, true);
  assert.equal(driver.health().lastVerifiedAt, 5000);
});

// ── T-b — fail-closed-and-VISIBLE on a ship failure, IGNORABLE (never throws/blocks). [neuter b] ──
test("offbox: a ship failure leaves the driver UNHEALTHY with a visible alarm, and shipOnce never throws", async () => {
  const blocks = await sealedChain(3);
  const sink = new FaultSink();
  const driver = new OffboxShipDriver(sink, () => blocks, sha256, 1000, () => 0);

  // The sink refuses the write. A backup subsystem must fail CLOSED-AND-VISIBLE, never swallow it.
  sink.throwOnPut = true;
  const out = await driver.shipOnce(1000); // must resolve, not throw (IGNORABLE)
  assert.equal(out.ok, false);
  assert.equal(out.health.healthy, false, "a swallowed ship failure -> silent green is the cardinal defect");
  assert.match(out.health.lastError ?? "", /ship FAILED/);
  assert.match(driver.healthLine(), /UNHEALTHY/);
  assert.equal(out.health.ships, 1, "the attempt is counted");
  assert.equal(out.health.verifiedShips, 0, "nothing verified");

  // A copy the sink ack'd but does not actually hold is ALSO caught, still without throwing.
  sink.throwOnPut = false;
  sink.readMode = "notFound";
  const out2 = await driver.shipOnce(3000);
  assert.equal(out2.ok, false);
  assert.equal(out2.health.healthy, false);
  assert.match(out2.health.lastError ?? "", /NOT FOUND|write-ack was a lie/);
});

// ── T-c — verify runs over the FETCHED copy, not the in-memory snapshot: truncation caught. [neuter c] ──
test("offbox: a copy TRUNCATED in transit fails verification over the FETCHED bytes (not the in-memory snapshot)", async () => {
  const blocks = await sealedChain(4);
  const sink = new FaultSink();
  const driver = new OffboxShipDriver(sink, () => blocks, sha256, 1000, () => 0);

  // The write succeeds; the sink drops the last block on read (a corrupt/incomplete durable copy).
  sink.readMode = "truncate";
  const out = await driver.shipOnce(1000);
  assert.equal(out.ok, false, "a truncated fetched copy must fail — verifying the in-memory snapshot would falsely pass");
  assert.equal(out.health.healthy, false);
  assert.ok(out.verification && out.verification.ok === false, "verifyRestore ran over the FETCHED bytes and failed");
  assert.match(out.health.lastError ?? "", /FAILED verifyRestore/);
});

// ── T-d — composition: the health verdict IS the verifyRestore predicate's result, not a private check. [neuter d] ──
test("offbox: a healthy ship's verdict IS the verifyRestore predicate over the fetched copy (one notion of a verified backup)", async () => {
  const blocks = await sealedChain(3);
  const sink = new FaultSink();
  const driver = new OffboxShipDriver(sink, () => blocks, sha256, 1000, () => 0);

  const now = 7777;
  const expected = buildSnapshot(blocks, sha256, now); // the driver builds the identical snapshot
  const out = await driver.shipOnce(now);
  assert.equal(out.ok, true);

  // The driver's verification must be EXACTLY what verifyRestore returns over the fetched copy against
  // the source root — proving it composes the existing predicate, not a second weaker private check.
  const direct = verifyRestore(blocks, expected.contentRoot, sha256, now);
  assert.deepEqual(out.verification, direct, "driver verdict == verifyRestore(fetched, sourceRoot) — the SAME predicate");
  assert.equal(out.verification!.chain.ok, true, "carries the chain-integrity result (a private count/root check would not)");
  assert.equal(out.verification!.rootMatches, true);
  assert.equal(out.verification!.recomputedRoot, expected.contentRoot, "recomputed root of the fetched copy == the expected source root");
  assert.match(out.verification!.reason, /content root matches/);
});

// ── T-e — cadence: IGNORABLE — a tick inside the window does NOT re-ship (never blocks the loop). [neuter e] ──
test("offbox: tick ships on a cadence and is a no-op inside the interval window (ignorable, non-blocking)", async () => {
  const blocks = await sealedChain(3);
  const sink = new FaultSink();
  const driver = new OffboxShipDriver(sink, () => blocks, sha256, 1000);

  const t1 = await driver.tick(0); // due at t=0 -> ships
  assert.ok(!("skipped" in t1), "first tick ships");
  assert.equal(driver.health().ships, 1);

  const t2 = await driver.tick(500); // inside the 1000ms window -> no-op
  assert.ok("skipped" in t2 && t2.skipped === true, "a tick inside the cadence window must NOT re-ship");
  assert.equal(driver.health().ships, 1, "ship count unchanged inside the window");

  const t3 = await driver.tick(1000); // window elapsed -> ships again
  assert.ok(!("skipped" in t3), "tick after the interval ships again");
  assert.equal(driver.health().ships, 2);
});

// ── Composition/wiring + honest-seam label (no new failure surface; strengthens the round). ──
test("offbox: composeLifecycle exposes the driver factory and the NEEDS-8.5b durability caveat is labeled, not claimed", async () => {
  const blocks = await sealedChain(2);
  const life = composeLifecycle();
  assert.equal(typeof life.makeOffboxShipDriver, "function", "the continuous ship driver is reachable on the composed lifecycle");

  const sink = new FaultSink();
  const driver = life.makeOffboxShipDriver(sink, () => blocks, sha256, 1000, () => 0);
  const out = await driver.shipOnce(42);
  assert.equal(out.ok, true, "the composed driver ships + verifies against a real injected sink");

  // The seam is LABELED, never silently claimed: durability of the target (WORM/witness/creds) is 8.5b.
  assert.equal(life.offboxDurabilityCaveat, OFFBOX_DURABILITY_CAVEAT);
  assert.match(life.offboxDurabilityCaveat, /NEEDS-8\.5b/);
  assert.match(life.offboxDurabilityCaveat, /COPY is complete and untampered/);
});
