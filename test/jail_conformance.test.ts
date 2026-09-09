import { test } from "node:test";
import assert from "node:assert/strict";

import { jailedAttempt, StubJail, type Jail, type JailRequest, type Write } from "../src/ree/jail.js";
import type { EnvelopeOp } from "../src/ree/reversible_envelope.js";

// R27 fork-jail — conformance test for the ENVELOPE-SIDE contract (in-env). The real OS jail
// (namespaces + seccomp + Landlock + overlayfs) is the SEAM; here we prove the logic runReversibly
// delegates to: a breach never commits, and only the jail's captured writes reach the sole egress.
// Verify by disproof.

const cleanOp = (writes: readonly Write[]): EnvelopeOp => ({
  description: { kind: "file.edit", writeSet: writes.map((w) => w.path), hasInverse: true },
  execute: async (t) => { for (const w of writes) await t.write(w.path, w.content); },
});

function sink() {
  const committed: Write[] = [];
  return { committed, commit: async (ws: readonly Write[]) => { committed.push(...ws); } };
}
const acceptAll = () => true;

test("JAIL: a clean run commits the captured writes through the SOLE egress", async () => {
  const jail = new StubJail();
  const s = sink();
  const req: JailRequest = { op: cleanOp([{ path: "a.txt", content: "new" }]), preState: { "a.txt": "old" } };
  const out = await jailedAttempt(jail, req, { commit: s.commit, accept: acceptAll });
  assert.equal(out.outcome, "committed");
  assert.deepEqual(s.committed, [{ path: "a.txt", content: "new" }], "only the captured write reached the sink");
});

test("JAIL: a BREACH rolls back with NO commit (fail-safe)", async () => {
  const jail = new StubJail({ forceBreach: "seccomp-violation:connect" });
  const s = sink();
  const req: JailRequest = { op: cleanOp([{ path: "a.txt", content: "x" }]), preState: { "a.txt": "old" } };
  const out = await jailedAttempt(jail, req, { commit: s.commit, accept: acceptAll });
  assert.equal(out.outcome, "rolled-back");
  if (out.outcome === "rolled-back") assert.ok(out.reason.startsWith("jail-breach"));
  assert.equal(s.committed.length, 0, "a breach never commits");
});

test("JAIL: an executor crash inside the jail is a breach → rollback, no commit", async () => {
  const crashOp: EnvelopeOp = {
    description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true },
    execute: async () => { throw new Error("boom"); },
  };
  const s = sink();
  const out = await jailedAttempt(new StubJail(), { op: crashOp, preState: { "a.txt": "old" } }, { commit: s.commit, accept: acceptAll });
  assert.equal(out.outcome, "rolled-back");
  assert.equal(s.committed.length, 0);
});

test("JAIL: a jail whose run() throws fails safe to rollback", async () => {
  const s = sink();
  const out = await jailedAttempt(new StubJail({ throwOnRun: true }), { op: cleanOp([]), preState: {} }, { commit: s.commit, accept: acceptAll });
  assert.equal(out.outcome, "rolled-back");
  assert.equal(s.committed.length, 0);
});

test("JAIL: acceptance rejection rolls back with no commit (reliable reject)", async () => {
  const s = sink();
  const req: JailRequest = { op: cleanOp([{ path: "a.txt", content: "new" }]), preState: { "a.txt": "old" } };
  const out = await jailedAttempt(new StubJail(), req, { commit: s.commit, accept: () => false });
  assert.equal(out.outcome, "rolled-back");
  assert.equal(s.committed.length, 0);
});

test("JAIL: the captured writes are the ONLY egress — an op that writes b.txt cannot smuggle past capture", async () => {
  // the stub captures the real diff; whatever the op writes IS what the supervisor captures. There is
  // no path from the op to the sink except through the captured writes (which acceptance can still reject).
  const jail: Jail = new StubJail();
  const s = sink();
  const req: JailRequest = {
    op: cleanOp([{ path: "a.txt", content: "1" }, { path: "b.txt", content: "2" }]),
    preState: { "a.txt": "old" },
  };
  // acceptance that only permits a.txt (models write-set scoping) → the whole attempt rolls back.
  const out = await jailedAttempt(jail, req, { commit: s.commit, accept: (ws) => ws.every((w) => w.path === "a.txt") });
  assert.equal(out.outcome, "rolled-back", "an out-of-scope captured write is rejected, not smuggled");
  assert.equal(s.committed.length, 0);
});
