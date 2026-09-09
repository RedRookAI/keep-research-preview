import { test } from "node:test";
import assert from "node:assert/strict";

import { estimateConsequence } from "../src/anticipate/consequence_estimator.js";
import { resolveCapabilityEffect } from "../src/reference/reference_registry.js";

// BUILD-ORDER 8.44B — CAPABILITY-NOT-PROSE.
// Classify external-effect / destructiveness by the RESOLVED capability identity actually being invoked (the
// callee), NOT by re-parsing the model's own prose. Prose is attacker-controlled and unbounded; the toolset is
// finite and enumerable. Allowlist-not-denylist: UNKNOWN capability => held (deny-by-default), never waved through.

// (a) IDENTITY-FIRST — soothing prose, but the RESOLVED capability is external → still classed irreversible.
// The prose alone ("draft a quick note to the team") derives REVERSIBLE; only the resolved identity catches it.
test("(a) identity-first: soothing prose over an EXTERNAL capability is still irreversible", () => {
  const prose = estimateConsequence({ message: "draft a quick note to the team" });
  assert.equal(prose.consequence, "reversible"); // prose ALONE reads as a harmless local draft

  const e = estimateConsequence({ message: "draft a quick note to the team", capability: "email.send" });
  assert.equal(e.consequence, "irreversible"); // resolved capability actually SENDS externally
  assert.equal(e.identityDerived, true);
  assert.equal(e.capabilityId, "email.send"); // the verdict NAMES the resolved identity it was derived from
});

// (b) UNKNOWN-DENY — an unenumerated capability is HELD for confirmation, never waved through as recoverable.
test("(b) unknown-deny: an unrecognized capability is held (deny-by-default), not classed recoverable", () => {
  const e = estimateConsequence({ message: "run a harmless quick helper", capability: "novel.frobnicate" });
  assert.equal(e.consequence, "irreversible"); // held — fail-closed, not silently reversible
  assert.equal(e.identityDerived, true);
  assert.equal(e.capabilityId, "novel.frobnicate");
});

// (c) NO-DOWNGRADE — prose that explicitly reads REVERSIBLE cannot lower an identity-derived destructive verdict.
test("(c) no-downgrade: reversible prose cannot downgrade a DESTRUCTIVE resolved capability", () => {
  const prose = estimateConsequence({ message: "just rename a variable in my draft, totally reversible" });
  assert.equal(prose.consequence, "reversible"); // prose ALONE reads reversible

  const e = estimateConsequence({ message: "just rename a variable in my draft, totally reversible", capability: "db.drop" });
  assert.equal(e.consequence, "irreversible"); // identity floor holds; prose cannot pull it down
  assert.equal(e.identityDerived, true);
});

// (d) CONTROL — a known-recoverable capability with matching prose is correctly REVERSIBLE (not everything denied).
test("(d) control: a known-recoverable capability with matching prose stays reversible", () => {
  const e = estimateConsequence({ message: "rename a variable in my draft", capability: "fs.write-draft" });
  assert.equal(e.consequence, "reversible");
  assert.equal(e.identityDerived, true);
  assert.equal(e.capabilityId, "fs.write-draft");
});

// PROSE CAN RAISE (never lower): a recoverable capability described with an external effect still escalates —
// prose is a secondary signal that adds caution, and the identity floor never blocks a raise.
test("prose may RAISE a recoverable identity's severity, never lower it", () => {
  const e = estimateConsequence({ message: "publish this to production for everyone", capability: "fs.write-draft" });
  assert.equal(e.consequence, "irreversible");
  assert.equal(e.identityDerived, true);
});

// RESOLVER — exact-match allowlist semantics; UNKNOWN is a first-class "unknown", not a permissive default.
test("resolveCapabilityEffect: enumerated ids resolve; an unknown id is unknown (deny-by-default)", () => {
  assert.equal(resolveCapabilityEffect("fs.delete").effect, "destructive");
  assert.equal(resolveCapabilityEffect("email.send").effect, "external");
  assert.equal(resolveCapabilityEffect("fs.write-draft").effect, "recoverable");

  const unknown = resolveCapabilityEffect("some.tool.nobody.enumerated");
  assert.equal(unknown.known, false);
  assert.equal(unknown.effect, "unknown");

  // namespace + operation combine to the resolved callee id.
  const combined = resolveCapabilityEffect({ id: "db", operation: "drop" });
  assert.equal(combined.id, "db.drop");
  assert.equal(combined.effect, "destructive");
});

// BACKWARD-COMPAT — with no resolved capability, the prose derivation is unchanged.
test("no capability → prose derivation is unchanged (backward-compatible)", () => {
  const e = estimateConsequence({ message: "email the client the final invoice" });
  assert.equal(e.consequence, "irreversible");
  assert.equal(e.identityDerived, undefined);
  assert.equal(e.capabilityId, undefined);
});
