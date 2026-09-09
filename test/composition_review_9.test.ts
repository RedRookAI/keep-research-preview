import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { composeGate, defaultGatePolicy, type GateInputs } from "../src/gate/composed_gate.js";
import { InMemoryFileTree, type FileTree } from "../src/solve/patch.js";
import { mediatedTree } from "../src/solve/mediated_tree.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { defaultFloorPolicy } from "../src/floor/structural_floor.js";
import { defaultBudgetPolicy } from "../src/budget/budget_ledger.js";
import { defaultAcceptanceTest } from "../src/ree/reversible_envelope.js";
import { executeReversibly, type ReversibleIntent, type IntegrationPolicies, type IntegrationDeps } from "../src/integrate/reversible_execution.js";
import { IdentityRegistry } from "../src/identity/agent_identity.js";
import { InMemoryAuditSink } from "../src/audit/decision_audit.js";

// FULL-SYSTEM CLOSE-OUT REVIEW — attack the NINE-barrier composition at the three NEW-barrier seams
// (ai-bom, identity, tcb) added since the six-barrier review. STPA + common-cause-failure lens. Every
// test BITES (goes red if the composition property is neutered).

function newSpine() {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-rev9-"))), new InProcessLock(), new SchemaRegistry());
}
const policies = (): IntegrationPolicies => ({
  floor: defaultFloorPolicy("repo"), gate: defaultGatePolicy(), budget: defaultBudgetPolicy(), acceptance: defaultAcceptanceTest,
});
function baseDeps(tree: FileTree, extra: Partial<IntegrationDeps> = {}): IntegrationDeps {
  return { spine: newSpine(), actor: "t", operator: "o", sign: (p) => p, tree, ownerPresent: true, envelopeEnabled: true, ...extra };
}
const cleanIntent = (): ReversibleIntent => ({
  description: { kind: "file.edit", writeSet: ["a.txt"], hasInverse: true, raw: "new" },
  apply: async (t) => { await t.write("a.txt", "new"); },
  actionTier: "reversible-internal",
});

// ── HUNT (a): BYPASS — each NEW barrier independently holds the integrated path (no execution). ──
test("HUNT-A9: a killed identity holds the integrated path — tree untouched", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree = mediatedTree(inner);
  const reg = new IdentityRegistry();
  const agent = reg.mint("agent-1", ["a.txt"]);
  reg.kill("agent-1");
  const res = await executeReversibly(cleanIntent(), policies(), baseDeps(tree, { identity: agent, identityRegistry: reg }));
  assert.equal(res.path, "human-hold", "killed identity → gate held");
  assert.equal(await tree.read("a.txt"), "old", "no execution");
});

test("HUNT-A9: a drifted TCB holds the integrated path — tree untouched", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree = mediatedTree(inner);
  const res = await executeReversibly(cleanIntent(), policies(), baseDeps(tree, { tcbIntact: false }));
  assert.equal(res.path, "human-hold", "tcb drift → gate held");
  assert.equal(await tree.read("a.txt"), "old", "no execution");
});

// ── HUNT (b): COMMON-CAUSE — the two hash-family barriers (ai-bom + tcb) share sha256. Even if a
//    single fault defeats BOTH (force both to PASS), a DIVERSE non-hash barrier still vetoes. The
//    composition does not collapse to the sha256-coupled set. ──
test("HUNT-B9: with BOTH hash-family barriers passing, a diverse barrier (twin) still vetoes", () => {
  // simulate a total sha256-family compromise: bom + tcb both wrongly report OK.
  const hashFamilyDefeated: GateInputs = {
    floor: "reversible-execute", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true,
    bomVerified: true, tcbIntact: true, // the coupled pair, both "passing"
    twin: "mismatch", // a DIVERSE, non-hash barrier
  };
  const r = composeGate(hashFamilyDefeated, defaultGatePolicy());
  assert.equal(r.route, "human-hold", "a diverse non-hash barrier holds despite the hash family passing");
  assert.ok(r.reasons.includes("digital-twin-mismatch"));
});

test("HUNT-B9: with BOTH hash-family barriers passing, the floor still vetoes (diversity, second witness)", () => {
  const r = composeGate({
    floor: "gate", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true,
    bomVerified: true, tcbIntact: true, provenance: "untrusted-derived", // provenance is also non-hash
  }, defaultGatePolicy());
  assert.equal(r.route, "human-hold");
  // two independent non-hash witnesses present: floor gate AND untrusted provenance.
  assert.ok(r.reasons.includes("floor-gate") || r.reasons.some((x) => x.includes("floor")));
  assert.ok(r.reasons.includes("untrusted-derived-provenance"));
});

// ── HUNT (b'): INDEPENDENCE — identity (a random token) and provenance (an input-origin label) are
//    keyed on DIFFERENT things; a live identity does not rescue an untrusted-derived effect. ──
test("HUNT-B9': a LIVE identity does not rescue an untrusted-derived-provenance effect", () => {
  const r = composeGate({
    floor: "reversible-execute", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true,
    identityLive: true, // identity is fine…
    provenance: "untrusted-derived", // …but provenance independently vetoes
  }, defaultGatePolicy());
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.includes("untrusted-derived-provenance"));
});

// ── HUNT (c): ORDERING / STALE-READ — the gate reads the CURRENT bom verification in the same call;
//    a tampered BOM (bomVerified=false) holds; there is no stale "verified" carried forward. ──
test("HUNT-C9: a false bomVerified in the same decision holds — no stale verified value", () => {
  const green: GateInputs = { floor: "reversible-execute", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true };
  assert.equal(composeGate({ ...green, bomVerified: true }, defaultGatePolicy()).route, "auto-proceed");
  assert.equal(composeGate({ ...green, bomVerified: false }, defaultGatePolicy()).route, "human-hold", "the current verdict decides");
});

// ── HUNT (e): AUDIT is observe-only even on the NEW barriers — a new-barrier hold is audited and the
//    route is unchanged; auditing never flips a hold to proceed. ──
test("HUNT-E9: an identity-hold is audited and the route stays held (audit never alters the decision)", async () => {
  const inner = new InMemoryFileTree({ "a.txt": "old" });
  const tree = mediatedTree(inner);
  const reg = new IdentityRegistry();
  const agent = reg.mint("agent-2", ["a.txt"]);
  reg.kill("agent-2");
  const sink = new InMemoryAuditSink();
  const res = await executeReversibly(cleanIntent(), policies(), baseDeps(tree, { identity: agent, identityRegistry: reg, auditSink: sink }));
  assert.equal(res.path, "human-hold", "route held");
  assert.equal(sink.records.length, 1, "the hold was audited");
  assert.equal(sink.records[0]!.record.route, "human-hold", "the audit reflects the hold");
  assert.ok(sink.records[0]!.record.reasons.includes("killed-or-unknown-identity"));
  assert.equal(await tree.read("a.txt"), "old", "auditing did not cause execution");
});
