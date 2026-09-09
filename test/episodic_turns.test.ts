import { test } from "node:test";
import assert from "node:assert/strict";

import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { EpisodicTurnLog, type TurnRecord } from "../src/memory/episodic_turns.js";

function log(): { keys: CryptoShredKeyStore; log: EpisodicTurnLog } {
  const keys = new CryptoShredKeyStore();
  let t = 1_000;
  const l = new EpisodicTurnLog(keys, () => t++);
  return { keys, log: l };
}

// Synthetic secret (regression pattern — never real): AWS-shaped key + email.
const SYN_SECRET = "AKIAIOSFODNN7EXAMPLE";
const SYN_EMAIL = "jane.doe@example.com";

test("records a turn and reads it back (round-trip)", () => {
  const { log: l } = log();
  const d = l.record({
    scope: "project",
    subject: "user-1",
    origin: "self",
    trusted: true,
    content: { goal: "add a retry to the uploader", action: "patched upload.ts", outcome: "clean-resolved" },
  });
  assert.equal(d.status, "recorded");
  const rec = (d as { record: TurnRecord }).record;
  const r = l.read(rec.id);
  assert.equal(r.status, "ok");
  if (r.status === "ok") {
    assert.equal(r.content.goal, "add a retry to the uploader");
    assert.equal(r.content.action, "patched upload.ts");
    assert.equal(r.content.outcome, "clean-resolved");
  }
});

test("addressable recall by key; missing key → not-found", () => {
  const { log: l } = log();
  const d = l.record({ scope: "user", subject: "u", origin: "self", trusted: true, content: { goal: "g1" } });
  const id = (d as { record: TurnRecord }).record.id;
  assert.ok(l.getTurn(id));
  assert.equal(l.getTurn("turn-999"), undefined);
  assert.equal(l.read("turn-999").status, "not-found");
});

test("append-only: no mutate/delete API; all() returns a copy", () => {
  const { log: l } = log();
  l.record({ scope: "user", subject: "u", origin: "self", trusted: true, content: { goal: "a" } });
  l.record({ scope: "user", subject: "u", origin: "self", trusted: true, content: { goal: "b" } });
  const snap = l.all();
  assert.equal(snap.length, 2);
  // Mutating the returned array must not affect the log (defensive copy).
  (snap as TurnRecord[]).pop();
  assert.equal(l.size(), 2);
  // Structural: there is no delete/update method on the log.
  assert.equal((l as unknown as Record<string, unknown>)["delete"], undefined);
  assert.equal((l as unknown as Record<string, unknown>)["update"], undefined);
});

test("PROVENANCE/TRUST cap: untrusted source is never confirmed (→ candidate); trusted → probation", () => {
  const { log: l } = log();
  const ext = l.record({ scope: "project", subject: "u", origin: "external", trusted: false, content: { goal: "from a pasted doc" } });
  const self = l.record({ scope: "project", subject: "u", origin: "self", trusted: true, content: { goal: "from our own loop" } });
  const extRec = (ext as { record: TurnRecord }).record;
  const selfRec = (self as { record: TurnRecord }).record;
  assert.equal(extRec.trust, "candidate");
  assert.equal(selfRec.trust, "probation");
  // The security invariant: NO write path yields a confirmed turn.
  for (const rec of l.all()) assert.notEqual(rec.trust, "confirmed");
  assert.equal(extRec.origin, "external");
});

test("WRITE BOUNDARY: secrets are redacted before persist; copyleft is rejected", () => {
  const { log: l } = log();
  // Secret → redacted (accepted, but the stored payload must not contain the secret).
  const d = l.record({ scope: "user", subject: "u", origin: "external", trusted: false, content: { goal: `deploy key ${SYN_SECRET} and email ${SYN_EMAIL}` } });
  assert.equal(d.status, "recorded");
  const rec = (d as { record: TurnRecord }).record;
  assert.ok(rec.ingestFindings.length > 0, "expected findings for the secret");
  const r = l.read(rec.id);
  assert.equal(r.status, "ok");
  if (r.status === "ok") {
    assert.ok(!r.content.goal.includes(SYN_SECRET), "the AWS key must not be stored in cleartext");
  }
  // Copyleft → hard reject (nothing persisted).
  const before = l.size();
  const rej = l.record({ scope: "user", subject: "u", origin: "external", trusted: false, content: { goal: "reuse this GPL v3 licensed snippet" } });
  assert.equal(rej.status, "rejected");
  assert.equal(l.size(), before, "a rejected turn must not be appended");
});

test("HASH-CHAIN: verifies clean; a tampered historical record breaks the chain", () => {
  const { log: l } = log();
  for (let i = 0; i < 4; i++) l.record({ scope: "user", subject: "u", origin: "self", trusted: true, content: { goal: `g${i}` } });
  assert.equal(l.verifyChain().ok, true);
  // Tamper with a historical record's stored trust (reach in past the readonly type to simulate corruption).
  const snap = l.all();
  const victim = snap[1] as unknown as { trust: string };
  // We can't mutate the copy to affect internals, so tamper the internal array directly for the test.
  const internal = (l as unknown as { records: Array<{ trust: string; hash: string }> }).records;
  internal[1]!.trust = "confirmed"; // an attacker elevating a memory's trust
  const v = l.verifyChain();
  assert.equal(v.ok, false);
  assert.equal(v.brokenAt, 1);
  void victim;
});

test("CRYPTO-SHRED: erasing a subject makes their turns unreadable; the chain still verifies", () => {
  const { log: l } = log();
  const a = l.record({ scope: "user", subject: "alice", origin: "self", trusted: true, content: { goal: "alice secret plan" } });
  l.record({ scope: "user", subject: "bob", origin: "self", trusted: true, content: { goal: "bob task" } });
  const aliceId = (a as { record: TurnRecord }).record.id;
  assert.equal(l.read(aliceId).status, "ok");

  const shredded = l.eraseSubject("alice");
  assert.equal(shredded, true);
  // Alice's content is now unrecoverable...
  assert.equal(l.read(aliceId).status, "erased");
  // ...but the record and the chain survive (tamper-evidence intact through erasure).
  assert.ok(l.getTurn(aliceId), "the record itself remains (ciphertext)");
  assert.equal(l.verifyChain().ok, true);
});

test("both-tracks: distinct subjects are isolated for erasure", () => {
  const { log: l } = log();
  const a = l.record({ scope: "global", subject: "tenant-A", origin: "self", trusted: true, content: { goal: "A data" } });
  const b = l.record({ scope: "global", subject: "tenant-B", origin: "self", trusted: true, content: { goal: "B data" } });
  l.eraseSubject("tenant-A");
  assert.equal(l.read((a as { record: TurnRecord }).record.id).status, "erased");
  assert.equal(l.read((b as { record: TurnRecord }).record.id).status, "ok"); // B unaffected
});
