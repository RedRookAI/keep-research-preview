import { test } from "node:test";
import assert from "node:assert/strict";

import {
  may,
  ownerResolver,
  rebacResolver,
  type AuthzPrincipal,
  type Resource,
  type Tuple,
  type AuthzAction,
} from "../src/authz/authorization.js";
import { type Principal } from "../src/identity/rbac.js";

// T1: the authorization spine — one may() interface, two tracks (owner N=1 floor + ReBAC org ceiling), agent
// delegation bounded by principal, fail-closed. Standing both-and: BOTH tracks proven. Verify by disproof.

const human = (id: string, role: Principal["role"] = "operator"): AuthzPrincipal => ({ principal: { id, kind: "human", role } });
const owner: AuthzPrincipal = { principal: { id: "owner", kind: "human", role: "owner" } };
const mem = (scope: Resource["scope"], id?: string): Resource => ({ surface: "memory", scope, ...(id !== undefined ? { id } : {}) });

test("N=1 FLOOR: the sole owner may do every action on every surface (owner never locked out)", () => {
  const r = ownerResolver("owner");
  const actions: AuthzAction[] = ["read", "write", "promote", "share", "configure"];
  for (const a of actions) {
    for (const s of ["user", "project", "team", "global"] as const) {
      assert.equal(may(owner, a, mem(s), r).allow, true, `owner denied ${a}@${s} — the N=1 floor dropped`);
    }
  }
  assert.equal(may(human("stranger"), "read", mem("global"), r).allow, false, "a non-owner is default-denied on the N=1 track");
});

test("ORG CEILING: a member of the owning team may read the project; a non-member is denied", () => {
  const tuples: readonly Tuple[] = [
    { subject: "alice", relation: "member-of", object: "team:eng" },
    { subject: "team:eng", relation: "owner-of", object: "project:x" },
  ];
  const r = rebacResolver(tuples);
  const proj = mem("project", "x");
  assert.equal(may(human("alice"), "read", proj, r).allow, true, "a member of the owning team may read (graph walk)");
  assert.equal(may(human("bob"), "read", proj, r).allow, false, "a non-member is denied — no cross-user leak");
});

test("ORG CEILING: a viewer may read but not write; write needs owner/member", () => {
  const tuples: readonly Tuple[] = [{ subject: "carol", relation: "viewer-of", object: "project:x" }];
  const r = rebacResolver(tuples);
  const proj = mem("project", "x");
  assert.equal(may(human("carol"), "read", proj, r).allow, true, "viewer may read");
  assert.equal(may(human("carol"), "write", proj, r).allow, false, "viewer may not write");
});

test("DELEGATION frontier: an agent acting for a user can never exceed its principal", () => {
  const tuples: readonly Tuple[] = [{ subject: "alice", relation: "owner-of", object: "project:x" }];
  const r = rebacResolver(tuples);
  const proj = mem("project", "x");
  // bob is NOT related to project:x ⇒ bob is denied. An agent acting FOR bob must also be denied,
  // even though the agent's own grant includes 'read'.
  const agentForBob: AuthzPrincipal = {
    principal: { id: "keep-agent", kind: "agent", role: "agent" },
    actingFor: human("bob"),
    ownGrant: new Set<AuthzAction>(["read", "write"]),
  };
  assert.equal(may(agentForBob, "read", proj, r).allow, false, "the agent is bounded by its principal (bob), not its own grant");
  // control: an agent acting for alice (who IS owner) is allowed read, but bounded by its own grant on write-excluded
  const agentForAlice: AuthzPrincipal = {
    principal: { id: "keep-agent", kind: "agent", role: "agent" },
    actingFor: human("alice"),
    ownGrant: new Set<AuthzAction>(["read"]), // own grant excludes write
  };
  assert.equal(may(agentForAlice, "read", proj, r).allow, true, "agent within principal + own grant ⇒ allowed");
  assert.equal(may(agentForAlice, "write", proj, r).allow, false, "agent's own grant excludes write ⇒ denied (intersection)");
});

test("ONE INTERFACE: the same may() serves the owner track and the rebac track", () => {
  const soloAllow = may(owner, "write", mem("global"), ownerResolver("owner")).allow;
  const orgAllow = may(human("alice"), "read", mem("project", "x"), rebacResolver([
    { subject: "alice", relation: "owner-of", object: "project:x" },
  ])).allow;
  assert.equal(soloAllow, true, "solo instance answers through may()");
  assert.equal(orgAllow, true, "org instance answers through the SAME may()");
});

test("FAIL-CLOSED: an incomplete/unknown envelope defaults to deny", () => {
  const r = ownerResolver("owner");
  assert.equal(may(owner, "obliterate" as AuthzAction, mem("global"), r).allow, false, "unknown action ⇒ deny");
  assert.equal(may({ principal: { id: "", kind: "human", role: "owner" } }, "read", mem("global"), r).allow, false, "missing principal id ⇒ deny");
  assert.equal(may(owner, "read", { surface: "bogus" as Resource["surface"], scope: "global" }, r).allow, false, "unknown surface ⇒ deny");
});

test("deterministic: same envelope ⇒ same decision", () => {
  const r = rebacResolver([{ subject: "alice", relation: "owner-of", object: "project:x" }]);
  const call = (): Decision => may(human("alice"), "read", mem("project", "x"), r);
  assert.deepEqual(call(), call());
});

import type { Decision } from "../src/authz/authorization.js";
