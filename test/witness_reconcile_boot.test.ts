import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeKeep } from "../src/compose.js";
import { InMemoryWitnessSink } from "../src/spine/witness_sink.js";

/**
 * ROUND 4 (ledger L20a) — is the published witness actually USED to detect tampering, or merely written?
 *
 * MEASURED FIRST: L4 makes seal()/checkpoint() PUBLISH the head to an independent witness, but nothing ever
 * reconciled the local chain against it — `reconcileSealWitness`/`spine.reconcileAgainst` had zero non-test
 * callers. So a TRUNCATION or FORK of the chain between runs was published-but-never-checked. This round calls
 * `reconcileSealWitness` at boot (composeKeep), exposes the verdict on KeepApp, and on TAMPER (diverged) stages
 * a loud `witness_tamper_detected` event.
 *
 * PROVEN-LIVE (harness A1). Disproof neuters:
 *   - drop the boot reconcile / hardcode the verdict -> DIVERGED-STATUS goes RED
 *   - change `if (status === "diverged")` to `if (false)` -> TAMPER-AUDITED goes RED (status stays green)
 * HONEST SEAM: single-external witness (witnessScope) — an M-of-N quorum / out-of-write-set location is a
 * declared SEAM; same-write-set tampering of BOTH chain and sink is undetectable here.
 */

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "keep-l20-"));
}

test("TAMPER-AT-BOOT: boot reconciles the chain against the witness and flags divergence + audits it", async () => {
  // a witness pinning a head (seq 5) the FRESH/empty chain cannot satisfy = a truncation/fork the reconcile must catch
  const sink = new InMemoryWitnessSink();
  sink.publish({ seq: 5, cumulativeRoot: "a".repeat(64), headHash: "b".repeat(64) });

  const app = composeKeep({ dataDir: tmp(), witnessSink: sink });

  assert.equal(app.witnessReconciliation.status, "diverged", "DIVERGED-STATUS: boot reconcile flags the tamper");
  await app.spine.seal(); // the tamper event was staged at boot; seal it so it is on the hash-chain
  const audited = app.spine.replay().some((e) => (e.payload as Record<string, unknown> | undefined)?.["event"] === "witness_tamper_detected");
  assert.ok(audited, "TAMPER-AUDITED: a witness_tamper_detected event is recorded to the spine");
});

test("FAIL-SAFE-DEGRADE: a corrupt/partial witness file does NOT crash boot — it degrades to `unreadable` + audits", async () => {
  // a partial write (process killed mid-append / power loss) leaves a malformed JSONL line. The boot reader
  // must NOT crash the whole app (that would turn detection into a boot DoS); it degrades + records.
  const dir = tmp();
  writeFileSync(join(dir, "witness.jsonl"), '{"seq":0,"cumulativeRoot":"aaa'); // truncated mid-write, invalid JSON
  const app = composeKeep({ dataDir: dir }); // MUST NOT THROW
  assert.equal(app.witnessReconciliation.status, "unreadable", "a corrupt witness file degrades to `unreadable`, boot survives");
  await app.spine.seal();
  const audited = app.spine.replay().some((e) => (e.payload as Record<string, unknown> | undefined)?.["event"] === "witness_unreadable");
  assert.ok(audited, "the unreadable witness is recorded to the spine");
});

test("NO-FALSE-POSITIVE: a fresh boot with no prior witness is `unreconciled`, never `diverged`", () => {
  const app = composeKeep({ dataDir: tmp() }); // default empty FileWitnessSink, empty chain
  assert.equal(app.witnessReconciliation.status, "unreconciled", "first boot bootstraps, never assumed-agree, never a false tamper");
  const falseTamper = app.spine.replay().some((e) => (e.payload as Record<string, unknown> | undefined)?.["event"] === "witness_tamper_detected");
  assert.equal(falseTamper, false, "no tamper event on a clean first boot");
});
