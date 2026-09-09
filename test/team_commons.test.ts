import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { promoteToShared, retractFromShared, type PromotionDeps } from "../src/memory/team_commons.js";
import { ownerResolver, rebacResolver, type AuthzPrincipal, type Tuple } from "../src/authz/authorization.js";
import { MemoryStore } from "../src/memory/store.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";

// T2: the team memory commons — governed promotion (Ostrom commons). BOTH tracks: N=1 frictionless global scope +
// org ratified commons. authorize-across-principals + CI-respect + graduated ratification + contagion containment.

function newStore(): MemoryStore {
  const dir = mkdtempSync(join(tmpdir(), "keep-t2-"));
  return new MemoryStore(new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry()), new ModelGateway(new LocalProvider()));
}
const human = (id: string): AuthzPrincipal => ({ principal: { id, kind: "human", role: "operator" } });
const owner: AuthzPrincipal = { principal: { id: "owner", kind: "human", role: "owner" } };

// org fixture: alice is a member of team:eng which owns team:eng's shared scope
const orgTuples: readonly Tuple[] = [
  { subject: "alice", relation: "member-of", object: "team:eng" },
  { subject: "team:eng", relation: "owner-of", object: "team:eng" },
];

test("ORG authority across principals: a member may promote to the team; a non-member is denied", async () => {
  const store = newStore();
  const deps: PromotionDeps = { resolver: rebacResolver(orgTuples), store };
  const req = { content: "prefers trunk-based development", targetScope: "team" as const, targetId: "eng" };
  // note the ReBAC object for a team scope is "team:<id>" = "team:eng"
  const member = await promoteToShared({ ...req, targetId: "eng" }, human("alice"), deps);
  // alice member-of team:eng, team:eng owner-of team:eng ⇒ authorized
  assert.equal(member.status, "promoted", "a member with promote authority may promote");
  const outsider = await promoteToShared({ ...req, targetId: "eng" }, human("bob"), deps);
  assert.equal(outsider.status, "denied", "a non-member is denied — no unauthorized contribution");
});

test("CI-respect across principals: special-category context is blocked from the shared scope", async () => {
  const store = newStore();
  const deps: PromotionDeps = { resolver: ownerResolver("owner"), store };
  const sensitive = await promoteToShared({ content: "I was diagnosed with cancer", targetScope: "global" }, owner, deps);
  assert.equal(sensitive.status, "blocked-sensitive", "protected context cannot be published to the commons");
  const ordinary = await promoteToShared({ content: "prefers dark mode", targetScope: "global" }, owner, deps);
  assert.equal(ordinary.status, "promoted", "ordinary knowledge is promoted");
});

test("graduated ratification: a promoted entry enters the shared scope at probation, not confirmed", async () => {
  const store = newStore();
  const deps: PromotionDeps = { resolver: ownerResolver("owner"), store };
  const r = await promoteToShared({ content: "use conventional commits", targetScope: "global", originId: "L1" }, owner, deps);
  assert.equal(r.status, "promoted");
  if (r.status === "promoted") {
    const entry = store.get(r.sharedId)!;
    assert.equal(entry.tier, "probation", "enters at probation (ratifiable), not confirmed (no authority laundering)");
    assert.equal(entry.scope, "global", "in the shared library scope");
  }
});

test("containment: retracting a shared entry retires + tombstones it (propagation stopped)", async () => {
  const store = newStore();
  const deps: PromotionDeps = { resolver: ownerResolver("owner"), store };
  const r = await promoteToShared({ content: "poisoned team advice", targetScope: "global" }, owner, deps);
  assert.equal(r.status, "promoted");
  if (r.status === "promoted") {
    const res = retractFromShared(r.sharedId, { store }, "poisoned");
    assert.equal(res.retracted, true);
    assert.equal(store.get(r.sharedId)!.tier, "retired", "the retracted entry is contained (retired), not left to spread");
  }
});

test("N=1 FLOOR: the sole owner promotes to a personal global scope frictionlessly (no team id)", async () => {
  const store = newStore();
  const deps: PromotionDeps = { resolver: ownerResolver("owner"), store };
  const r = await promoteToShared({ content: "my own working note", targetScope: "global" }, owner, deps);
  assert.equal(r.status, "promoted", "the solo owner's shared library works with zero org setup");
});

test("deterministic: same request + fixture ⇒ same status", async () => {
  const mk = () => promoteToShared({ content: "stable note", targetScope: "global" }, owner, { resolver: ownerResolver("owner"), store: newStore() });
  assert.equal((await mk()).status, (await mk()).status);
});
