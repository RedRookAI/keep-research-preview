import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  verificationProvenance, sealProvenance, anchorSeal, reconcileSealWitness, type VerificationProvenance,
} from "../src/audit/decision_audit.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InMemoryWitnessSink } from "../src/spine/witness_sink.js";

const rec = (id: string): VerificationProvenance => verificationProvenance({ subjectId: id, deterministicPass: true });
function makeSpine(clock: () => number = () => 1000) {
  const dir = mkdtempSync(join(tmpdir(), "keep-mirror-"));
  return { spine: new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry(), clock), dir };
}

test("WITNESS-MIRROR (a): emitting pins the anchored seal's head to the external sink; reconcile confirms agreement", async () => {
  const { spine } = makeSpine();
  const sink = new InMemoryWitnessSink();
  anchorSeal(spine, sealProvenance(rec("s1"))); await spine.seal();
  assert.equal(reconcileSealWitness(spine, sink).status, "unreconciled", "first call bootstraps the external record");
  assert.ok(sink.latest(), "the head witness is now pinned to the sink");
  // advance: a further sealed block reconciles as a forward-consistent extension
  anchorSeal(spine, sealProvenance(rec("s2"))); await spine.seal();
  const r = reconcileSealWitness(spine, sink);
  assert.equal(r.status, "agreed");
  assert.equal(r.reconciled, true);
});

test("WITNESS-MIRROR (b): a silently-rewritten local chain diverges from the external record and is reported tamper", async () => {
  const { spine, dir } = makeSpine(() => 2000);
  const sink = new InMemoryWitnessSink();
  anchorSeal(spine, sealProvenance(rec("orig"))); await spine.seal();
  reconcileSealWitness(spine, sink); // bootstrap → sink pins the good head
  // silently rewrite the local chain on disk (equivocation): change the witnessed event
  const chainPath = join(dir, "chain.jsonl");
  writeFileSync(chainPath, readFileSync(chainPath, "utf8").replace(/"sealHash":"[0-9a-f]+"/, '"sealHash":"deadbeef"'));
  const r = reconcileSealWitness(spine, sink);
  assert.equal(r.reconciled, false);
  assert.equal(r.status, "diverged", "the rewritten chain diverges from the external witness");
  assert.match(r.reason, /TAMPER/);
});

test("WITNESS-MIRROR (c): a truncated/rolled-back local chain is caught against the external witness", async () => {
  const { spine, dir } = makeSpine(() => 3000);
  const sink = new InMemoryWitnessSink();
  anchorSeal(spine, sealProvenance(rec("b1"))); await spine.seal();
  anchorSeal(spine, sealProvenance(rec("b2"))); await spine.seal();
  reconcileSealWitness(spine, sink); // bootstrap at 2-block head
  // roll the local chain back to 1 block (truncation)
  const chainPath = join(dir, "chain.jsonl");
  const lines = readFileSync(chainPath, "utf8").trim().split("\n");
  writeFileSync(chainPath, lines[0]! + "\n");
  const r = reconcileSealWitness(spine, sink);
  assert.equal(r.reconciled, false);
  assert.equal(r.status, "diverged", "a truncated chain is caught against the pinned witness");
});

test("WITNESS-MIRROR (d): an absent external record is reported unreconciled, never assumed to agree", async () => {
  const { spine } = makeSpine();
  const sink = new InMemoryWitnessSink();
  anchorSeal(spine, sealProvenance(rec("d1"))); await spine.seal();
  const r = reconcileSealWitness(spine, sink); // sink empty → no prior to reconcile against
  assert.equal(r.reconciled, false, "no external record → not assumed to agree");
  assert.equal(r.status, "unreconciled");
});

test("WITNESS-MIRROR (e): honesty — a single external sink is not overclaimed as an M-of-N public network", async () => {
  const { spine } = makeSpine();
  const sink = new InMemoryWitnessSink();
  anchorSeal(spine, sealProvenance(rec("e1"))); await spine.seal();
  const r = reconcileSealWitness(spine, sink);
  assert.equal(r.witnessScope, "single-external", "honestly a single external witness — not an M-of-N quorum");
});
