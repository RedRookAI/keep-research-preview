import { test } from "node:test";
import assert from "node:assert/strict";

import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import {
  ProjectRegistry,
  CrossProjectAccessError,
} from "../src/session/project_registry.js";
import {
  ProjectSessionManager,
  defaultCompactor,
} from "../src/session/project_session_manager.js";
import { isProjectId, mintProjectId, asProjectId } from "../src/session/project_id.js";
import type { ProjectState } from "../src/autonomy/project_loop.js";
import { PROJECT_STATE_SCHEMA_VERSION } from "../src/autonomy/project_state.js";

function freshManager() {
  const keys = new CryptoShredKeyStore();
  const registry = new ProjectRegistry(keys);
  const mgr = new ProjectSessionManager(registry);
  return { keys, registry, mgr };
}

// ── Identity ────────────────────────────────────────────────────────────────

test("ProjectId is stable, opaque, and collision-resistant", () => {
  const a = mintProjectId();
  const b = mintProjectId();
  assert.notEqual(a, b, "two mints must differ");
  assert.ok(isProjectId(a), "minted id must validate");
  assert.throws(() => asProjectId("not-an-id"), "malformed id must throw at the boundary");
});

// ── INVARIANT: cross-project access throws (deterministic, not model-mediated) ──

test("INVARIANT: a namespace for A cannot be used to touch B's keys (cross-access throws)", () => {
  const { registry } = freshManager();
  const a = registry.create("A").id;
  const b = registry.create("B").id;
  const nsA = registry.namespace(a);
  const keyA = nsA.key("corpus:doc1");
  // ownership check passes for A, throws for B — deterministic boundary
  assert.doesNotThrow(() => registry.assertOwnership(a, keyA));
  assert.throws(
    () => registry.assertOwnership(b, keyA),
    (e: unknown) => e instanceof CrossProjectAccessError,
    "B must not be able to claim A's namespaced key",
  );
});

test("INVARIANT: namespaced keys for two projects never collide (cache-key isolation)", () => {
  const { registry } = freshManager();
  const a = registry.namespace(registry.create("A").id);
  const b = registry.namespace(registry.create("B").id);
  assert.notEqual(a.key("cache:qX"), b.key("cache:qX"), "same logical key must differ across projects");
});

// ── INVARIANT: per-project encryption — A's data is ciphertext without A's key ──

test("INVARIANT: each project's data is encrypted under its OWN key", () => {
  const { registry } = freshManager();
  const a = registry.namespace(registry.create("A").id);
  const b = registry.namespace(registry.create("B").id);
  const cipher = a.encrypt("A's secret plan");
  // A decrypts its own data
  assert.equal(a.decrypt(cipher), "A's secret plan");
  // B, using its OWN key, cannot decrypt A's ciphertext (auth-tag/key mismatch throws)
  assert.throws(() => b.decrypt(cipher), "B's key must not decrypt A's ciphertext");
});

// ── INVARIANT: crypto-shred delete leaves other projects bit-identical ──

test("INVARIANT: deleting/shredding A leaves B fully intact; A becomes unrecoverable", () => {
  const { registry, mgr } = freshManager();
  const a = mgr.create({ name: "A" }).id;
  const b = mgr.create({ name: "B" }).id;

  const nsB = registry.namespace(b);
  const bCipher = nsB.encrypt("B stays readable");

  // capture A's ciphertext, then delete A (crypto-shred)
  const nsA = registry.namespace(a);
  const aCipher = nsA.encrypt("A about to vanish");
  mgr.delete(a);

  // A is gone and unrecoverable
  assert.throws(() => registry.get(a), "deleted project must not resolve");
  assert.throws(() => registry.namespace(a).decrypt(aCipher), "A's data is unrecoverable post-shred");

  // B is bit-identical / fully readable
  assert.equal(registry.namespace(b).decrypt(bCipher), "B stays readable", "B unaffected by A's deletion");
  assert.ok(registry.has(b), "B still present");
});

// ── INVARIANT: history is encrypted at rest, readable in-session ──

test("INVARIANT: session history round-trips (encrypted at rest, plaintext on read)", () => {
  const { mgr } = freshManager();
  const p = mgr.create({ name: "novel" }).id;
  const s = mgr.session(p);
  s.append("user", "Write chapter 1");
  s.append("assistant", "Here is chapter 1...");
  const h = s.history();
  assert.equal(h.length, 2);
  assert.equal(h[0]!.text, "Write chapter 1");
  assert.equal(h[1]!.role, "assistant");
  assert.equal(h[0]!.seq, 0, "sequence is stable/ordered");
});

test("INVARIANT: one project's session cannot read another's history", () => {
  const { mgr } = freshManager();
  const a = mgr.create({ name: "A" }).id;
  const b = mgr.create({ name: "B" }).id;
  mgr.session(a).append("user", "A-only content");
  mgr.session(b).append("user", "B-only content");
  assert.equal(mgr.session(a).history().length, 1);
  assert.equal(mgr.session(a).history()[0]!.text, "A-only content");
  assert.equal(mgr.session(b).history()[0]!.text, "B-only content");
  // no API hands A a handle to B's session; sessions are keyed by id
  assert.notEqual(mgr.session(a), mgr.session(b));
});

// ── Compaction preserves load-bearing facts ──

test("compaction summarizes old history but preserves load-bearing facts", () => {
  const { mgr } = freshManager();
  const p = mgr.create({ name: "proj" }).id;
  const s = mgr.session(p);
  s.append("user", "goal");
  s.append("assistant", "wrote /src/app.ts with the parser");
  s.append("tool", "tests: 12 pass");
  s.append("event", "checkpoint at plan stage");
  const before = s.liveCount();
  assert.equal(before, 4);
  const note = s.compactOldest(3, defaultCompactor);
  assert.ok(note, "a note is produced");
  assert.equal(s.liveCount(), 1, "compacted originals dropped from live history");
  assert.ok(
    note!.keptFacts.some((f) => f.includes("/src/app.ts")),
    "load-bearing fact (file path) preserved in the typed note",
  );
});

test("compaction is bounded/no-op-safe (0 or over-count does not corrupt)", () => {
  const { mgr } = freshManager();
  const s = mgr.session(mgr.create({ name: "p" }).id);
  s.append("user", "x");
  assert.equal(s.compactOldest(0, defaultCompactor), undefined, "compacting 0 is a no-op");
  assert.equal(s.liveCount(), 1);
  const note = s.compactOldest(999, defaultCompactor); // more than present
  assert.ok(note);
  assert.equal(s.liveCount(), 0, "over-count is clamped to what's present");
});

// ── Switch loses nothing; background continuation ──

function fakeState(runId: string, stage: ProjectState["stage"]): ProjectState {
  return {
    schemaVersion: PROJECT_STATE_SCHEMA_VERSION,
    revision: 0,
    runId,
    goal: "g",
    stage,
    artifacts: {},
    posture: "autonomous",
    stepsRemaining: 5,
    reworkCount: 0,
    status: "running",
    retry: { attemptsByStage: {}, attemptsConsumed: 0, runLimit: 8 },
    consumedSignals: [],
  };
}

test("switch checkpoints the outgoing project and restores the incoming (nothing lost)", () => {
  const { mgr } = freshManager();
  const drone = mgr.create({ name: "drone" }).id;
  const novel = mgr.create({ name: "novel" }).id;

  // work on drone, checkpoint mid-plan
  const ds = mgr.session(drone);
  ds.append("user", "drone SOTA research");
  ds.checkpoint(fakeState("d1", "plan"));
  mgr.switch(drone); // activate drone
  assert.equal(mgr.active(undefined), drone);

  // switch to novel, keeping drone in the background
  const r = mgr.switch(novel);
  assert.equal(r.incoming, novel);
  assert.equal(r.outgoing, drone);
  assert.equal(mgr.active(undefined), novel);

  // come back to drone: its checkpoint is intact (a restore, not a replay)
  mgr.switch(drone);
  const restored = mgr.session(drone).lastCheckpoint();
  assert.ok(restored, "drone checkpoint survived the round-trip");
  assert.equal(restored!.stage, "plan", "resumes exactly where it left off");
  assert.equal(restored!.runId, "d1");
});

test("backgrounded project keeps its session + checkpoint (can continue in-envelope)", () => {
  const { registry, mgr } = freshManager();
  const p = mgr.create({ name: "bg" }).id;
  mgr.session(p).checkpoint(fakeState("r", "implement"));
  mgr.switch(p);
  mgr.background(p);
  assert.equal(mgr.active(undefined), undefined, "backgrounded project is no longer foreground");
  assert.equal(registry.get(p).lifecycle, "background");
  assert.ok(mgr.session(p).lastCheckpoint(), "checkpoint retained for background continuation");
});

// ── Budget envelope is per-project ──

test("budget envelope is per-project and independent", () => {
  const { mgr } = freshManager();
  const a = mgr.create({ name: "A", budget: { dailyTokenCap: 100, spentTokensToday: 0 } }).id;
  const b = mgr.create({ name: "B", budget: { dailyTokenCap: 100, spentTokensToday: 0 } }).id;
  assert.equal(mgr.session(a).spend(90), true, "A within budget");
  assert.equal(mgr.session(a).spend(20), false, "A now over budget");
  assert.equal(mgr.session(b).withinBudget(), true, "B unaffected by A's spend");
});
