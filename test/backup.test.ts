import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import type { SealedBlock } from "../src/spine/hashchain.js";

import {
  buildSnapshot,
  LocalBackup,
  type Snapshot,
} from "../src/backup/backup_port.js";
import {
  verifyRestore,
  verifySnapshotRoundTrip,
  offMachinePrompt,
  OFF_MACHINE_OPTIONS,
} from "../src/backup/verify_restore.js";
import {
  uninstall,
  renderUninstallSummary,
  FileOwnedRemovalPort,
  type RemovalPort,
} from "../src/backup/uninstall.js";

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-backup-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

/** Produce a real sealed chain by staging + sealing some events. */
async function sealedChain(events = 3): Promise<{ spine: Spine; blocks: readonly SealedBlock[] }> {
  const spine = newSpine();
  for (let i = 0; i < events; i++) {
    spine.stage({ type: "generic", actor: "test", payload: { i } });
    await spine.seal();
  }
  return { spine, blocks: blocksOf(spine) };
}
function blocksOf(spine: Spine): readonly SealedBlock[] {
  // The spine exposes readBlocks via its store; use verify path's source through a checkpoint.
  return (spine as unknown as { store: { readBlocks(): SealedBlock[] } }).store.readBlocks();
}

// ── Content-addressed snapshot + immutable LocalBackup ──────────────────────

test("INVARIANT: buildSnapshot is content-addressed (same chain → same id + root)", async () => {
  const { spine } = await sealedChain(3);
  const blocks = blocksOf(spine);
  const s1 = buildSnapshot(blocks, sha256, 1000);
  const s2 = buildSnapshot(blocks, sha256, 9999); // different time, same content
  assert.equal(s1.id, s2.id, "same content → same id (time doesn't change the address)");
  assert.equal(s1.contentRoot, s2.contentRoot);
});

test("INVARIANT: LocalBackup is idempotent on identical content", async () => {
  const { spine } = await sealedChain(2);
  const snap = buildSnapshot(blocksOf(spine), sha256, 1);
  const backup = new LocalBackup();
  const r1 = await backup.put(snap);
  const r2 = await backup.put(snap);
  assert.equal(r1.id, r2.id);
  assert.equal((await backup.list()).length, 1, "no duplicate stored");
});

test("INVARIANT: LocalBackup REFUSES to overwrite a differing snapshot at the same id (immutability)", async () => {
  const backup = new LocalBackup();
  const fakeA: Snapshot = { contentRoot: "aaa", blocks: [], blockCount: 0, eventCount: 0, takenAt: 1, id: "snap_x" };
  const fakeB: Snapshot = { contentRoot: "bbb", blocks: [], blockCount: 0, eventCount: 0, takenAt: 2, id: "snap_x" }; // same id, diff content
  await backup.put(fakeA);
  await assert.rejects(() => backup.put(fakeB), /immutability violation/, "cannot silently overwrite history");
});

// ── verifyRestore: the +0 property ──────────────────────────────────────────

test("INVARIANT: verifyRestore passes on an intact restored chain", async () => {
  const { spine } = await sealedChain(3);
  const blocks = blocksOf(spine);
  const snap = buildSnapshot(blocks, sha256, 1);
  const v = verifyRestore(blocks, snap.contentRoot, sha256);
  assert.equal(v.ok, true, v.reason);
  assert.equal(v.rootMatches, true);
});

test("INVARIANT: verifyRestore FAILS on a truncated restore (missing blocks)", async () => {
  const { spine } = await sealedChain(4);
  const blocks = blocksOf(spine);
  const snap = buildSnapshot(blocks, sha256, 1);
  const truncated = blocks.slice(0, blocks.length - 1); // drop the last block
  const v = verifyRestore(truncated, snap.contentRoot, sha256);
  assert.equal(v.ok, false, "truncated restore must not verify");
});

test("INVARIANT: verifyRestore FAILS on a content-root mismatch", async () => {
  const { spine } = await sealedChain(3);
  const blocks = blocksOf(spine);
  const v = verifyRestore(blocks, "not-the-real-root", sha256);
  assert.equal(v.ok, false);
  assert.equal(v.rootMatches, false);
});

test("INVARIANT: verifyRestore FAILS on event tampering (chain integrity)", async () => {
  const { spine } = await sealedChain(3);
  const blocks = blocksOf(spine).map((b) => ({ ...b, events: b.events.map((e) => ({ ...e, actor: "tampered" })) }));
  const snap = buildSnapshot(blocksOf(spine), sha256, 1);
  const v = verifyRestore(blocks, snap.contentRoot, sha256);
  assert.equal(v.ok, false, "tampered events must fail chain verification");
});

test("round-trip verify via the backup port passes for a stored snapshot", async () => {
  const { spine } = await sealedChain(3);
  const snap = buildSnapshot(blocksOf(spine), sha256, 1);
  const backup = new LocalBackup();
  await backup.put(snap);
  const v = await verifySnapshotRoundTrip(backup, snap.id, sha256);
  assert.equal(v.ok, true, v.reason);
});

// ── Off-machine prompt: free-first, ignorable, backs off ────────────────────

test("INVARIANT: off-machine options list FREE options before paid", () => {
  const paidIdx = OFF_MACHINE_OPTIONS.findIndex((o) => !o.free);
  const freeIdxs = OFF_MACHINE_OPTIONS.map((o, i) => (o.free ? i : -1)).filter((i) => i >= 0);
  assert.ok(freeIdxs.every((i) => i < paidIdx), "all free options come before the paid one");
  assert.equal(OFF_MACHINE_OPTIONS[0]!.kind, "git-private", "free git first");
});

test("prompt surfaces when unconfigured, stays quiet when configured", () => {
  assert.equal(offMachinePrompt({ configured: false, dismissedCount: 0 }).shouldPrompt, true);
  assert.equal(offMachinePrompt({ configured: true, dismissedCount: 0 }).shouldPrompt, false);
});

test("INVARIANT: prompt backs off after dismissals (present, never nagging)", () => {
  const now = 10_000_000_000;
  // dismissedCount 1 → 3-day backoff window. 1h after a dismissal → not due yet.
  const soon = offMachinePrompt({ configured: false, lastPromptedAt: now, dismissedCount: 1 }, now + 3_600_000);
  assert.equal(soon.shouldPrompt, false, "not due 1h after a dismissal");
  // 4 days later (past the 3d window) → due again.
  const later = offMachinePrompt({ configured: false, lastPromptedAt: now, dismissedCount: 1 }, now + 4 * 86_400_000);
  assert.equal(later.shouldPrompt, true, "re-surfaces after the backoff window");
  // Escalation: a later dismissal waits longer (7d bucket not due at 4d).
  const escalated = offMachinePrompt({ configured: false, lastPromptedAt: now, dismissedCount: 2 }, now + 4 * 86_400_000);
  assert.equal(escalated.shouldPrompt, false, "backoff escalates with repeated dismissals");
});

// ── Uninstall: preserve work, shred keys, abort-on-backup-fail ──────────────

function fakeRemoval(): { port: RemovalPort; removedHome: () => string | undefined; plan: { instanceHome: string; registryEntries: string[]; runfiles: string[] }; ownership: { ownedPaths: string[]; preservedRepositories: string[] } } {
  let home: string | undefined;
  const plan = { instanceHome: "/home/.keep/instances/inst1", registryEntries: ["/home/.keep/registry/inst1.json"], runfiles: ["/run/keep.sock"] };
  const port: RemovalPort = {
    async plan() { return plan; },
    async apply(admitted, progress) { home = admitted.instanceHome; const paths = [...admitted.runfiles, ...admitted.registryEntries, admitted.instanceHome];
      return paths.map((path) => { progress({ phase: "attempting", path }); progress({ phase: "removed", path }); return { path, status: "removed" as const }; }); },
  };
  return { port, plan, ownership: { ownedPaths: [plan.instanceHome, ...plan.registryEntries, ...plan.runfiles], preservedRepositories: ["/home/alice/project"] }, removedHome: () => home };
}

function finalBackup(backup: LocalBackup, snapshot: () => Snapshot) {
  return async () => { const ref = await backup.put(snapshot()); return { id: ref.id, inventoryDigest: ref.contentRoot, target: backup.name, verified: true as const }; };
}

test("INVARIANT: uninstall shreds keys + removes instance but PRESERVES the backup target", async () => {
  const spine = newSpine();
  const keystore = new CryptoShredKeyStore();
  keystore.ensureKey("prj1");
  keystore.ensureKey("prj2");
  const backup = new LocalBackup();
  const { spine: cSpine } = await sealedChain(2);
  const snapFn = () => buildSnapshot(blocksOf(cSpine), sha256, Date.now());
  const { port, ownership } = fakeRemoval();

  const manifest = await uninstall(
    { instanceId: "inst1", keySubjects: ["prj1", "prj2"], finalBackup: true },
    { spine, keystore, removal: port, ownership, finalBackup: finalBackup(backup, snapFn) },
  );
  assert.equal(manifest.completed, true);
  assert.equal(manifest.removed.keysShredded.length, 2, "both keys shredded");
  assert.ok(manifest.finalBackupId, "final backup taken");
  assert.equal((await backup.list()).length, 1, "backup PRESERVED — not deleted by uninstall");
  assert.match(manifest.preserved.note, /outside the validated removal plan/);
});

test("INVARIANT: uninstall ABORTS (removes nothing) if the final backup fails without force", async () => {
  const spine = newSpine();
  const keystore = new CryptoShredKeyStore();
  keystore.ensureKey("prj1");
  const { port, ownership, removedHome } = fakeRemoval();
  const manifest = await uninstall(
    { instanceId: "inst1", keySubjects: ["prj1"], finalBackup: true, force: false },
    { spine, keystore, removal: port, ownership, finalBackup: async () => { throw new Error("disk full"); } },
  );
  assert.equal(manifest.completed, false, "aborted");
  assert.equal(manifest.removed.keysShredded.length, 0, "no keys shredded on abort");
  assert.equal(removedHome(), undefined, "instance home NOT removed on abort");
  assert.equal(keystore.ensureKey("prj1"), false, "key still exists (ensureKey returns false = already present)");
});

test("OPS-06 concrete removal deletes only exact owned paths and preserves repositories plus unselected keys", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-uninstall-owned-"));
  const instanceHome = join(root, "keep", "instances", "inst1");
  const registry = join(root, "keep", "registry", "inst1.json");
  const runfile = join(root, "run", "inst1.sock");
  const repository = join(root, "repositories", "project");
  for (const directory of [instanceHome, join(root, "keep", "registry"), join(root, "run"), repository]) mkdirSync(directory, { recursive: true });
  writeFileSync(join(instanceHome, "state"), "owned"); writeFileSync(registry, "owned"); writeFileSync(runfile, "owned"); writeFileSync(join(repository, "work.txt"), "preserve me");
  const plan = { instanceHome, registryEntries: [registry], runfiles: [runfile] };
  const ownership = { ownedPaths: [instanceHome, registry, runfile], preservedRepositories: [repository] };
  const removal = new FileOwnedRemovalPort("inst1", plan, ownership);
  const keystore = new CryptoShredKeyStore(); keystore.ensureKey("selected"); keystore.ensureKey("keep-key");
  const manifest = await uninstall({ instanceId: "inst1", keySubjects: ["selected"] }, {
    spine: newSpine(), keystore, removal, ownership,
    finalBackup: async () => ({ id: "backup-1", inventoryDigest: "a".repeat(64), target: "private-offbox", verified: true }),
  });
  assert.equal(manifest.completed, true);
  assert.equal(existsSync(instanceHome), false); assert.equal(existsSync(registry), false); assert.equal(existsSync(runfile), false);
  assert.equal(existsSync(join(repository, "work.txt")), true, "user repository survives");
  assert.equal(keystore.hasKey("selected"), false); assert.equal(keystore.hasKey("keep-key"), true, "only selected secrets are shredded");
});

test("OPS-06 rejects repository overlap before backup, deletion, or key shredding", async () => {
  let applied = false, backedUp = false;
  const plan = { instanceHome: "/srv/user", registryEntries: [], runfiles: [] };
  const removal: RemovalPort = { async plan() { return plan; }, async apply() { applied = true; return []; } };
  const ownership = { ownedPaths: ["/srv/user"], preservedRepositories: ["/srv/user/project"] };
  const keystore = new CryptoShredKeyStore(); keystore.ensureKey("selected");
  await assert.rejects(uninstall({ instanceId: "inst1", keySubjects: ["selected"] }, {
    spine: newSpine(), keystore, removal, ownership,
    finalBackup: async () => { backedUp = true; return { id: "backup-1", inventoryDigest: "a".repeat(64), target: "offbox", verified: true }; },
  }), /overlaps a preserved repository/);
  assert.equal(backedUp, false); assert.equal(applied, false); assert.equal(keystore.hasKey("selected"), true);
});

test("renderUninstallSummary prints what was removed + preserved", async () => {
  const spine = newSpine();
  const keystore = new CryptoShredKeyStore();
  keystore.ensureKey("prj1");
  const backup = new LocalBackup();
  const { spine: cSpine } = await sealedChain(1);
  const { port, ownership } = fakeRemoval();
  const manifest = await uninstall(
    { instanceId: "inst1", keySubjects: ["prj1"], finalBackup: true },
    { spine, keystore, removal: port, ownership, finalBackup: finalBackup(backup, () => buildSnapshot(blocksOf(cSpine), sha256, 1)) },
  );
  const summary = renderUninstallSummary(manifest);
  assert.match(summary, /Removed:/);
  assert.match(summary, /crypto-shredded: 1/);
  assert.match(summary, /Preserved:/);
});
