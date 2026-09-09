import { test } from "node:test";
import assert from "node:assert/strict";

import { IdentityRegistry } from "../src/identity/agent_identity.js";
import { InMemoryFileTree } from "../src/solve/patch.js";
import { WriteGrant, runMediatedWith, mediatedTree } from "../src/solve/mediated_tree.js";

/**
 * ROUND 37 — Z99 RESOLVED, AND NOT THE WAY THE HARNESS EXPECTED.
 *
 * The harness offered two outcomes: wire `authorizeEffect` into the write path, or delete it.
 * Reading the code produced a third that is more honest than either.
 *
 * `authorizeEffect` is NOT redundant machinery to be deleted — it is the QUERY behind the
 * attenuating-delegation property, and the existing identity tests use it as exactly that.
 *
 * But it must NOT be wired into the write path either, because `WriteGrant` already enforces
 * something strictly stronger there:
 *
 *   mediated_tree.ts:63   findIndex((w) => w.path === path && w.content === content)
 *
 * An EXACT (path, content) match against the declared write-set, consumed one-shot. A prefix
 * scope check cannot refuse anything that exact-match admits, so adding one to the commit path
 * would be a second, weaker authorization mechanism disagreeing with the first — the R14 shape
 * this project already paid for once. And on every production path the minted scope is `["*"]`
 * (round 35), so such a check would evaluate to "allowed" always: decoration, which Z141 says is
 * worse than an honest absence.
 *
 * WHAT THE ROUND DID FIX is the defect found while deciding: the scope comparison was a raw
 * `startsWith` on un-normalised paths.
 */

test("Z99: scope no longer admits a traversal path (was: ALLOWED)", () => {
  // THE DEFECT, reproduced exactly as it behaved before this round.
  const reg = new IdentityRegistry();
  const agent = reg.mint("agent", ["src"]);

  assert.equal(reg.authorizeEffect(agent, "src/a.ts").authorized, true, "ordinary in-scope path still allowed");
  assert.equal(
    reg.authorizeEffect(agent, "src/../.env").authorized, false,
    "a path that RESOLVES outside the scope must be refused, not admitted by its prefix",
  );
  assert.equal(
    reg.authorizeEffect(agent, "src/../../etc/passwd").authorized, false,
    "and one that escapes the root entirely is refused before any prefix is consulted",
  );
  // Canonicalisation must not over-refuse: a no-op segment is still in scope.
  assert.equal(reg.authorizeEffect(agent, "src/./b.ts").authorized, true, "'.' segments are not an escape");
});

test("Z99: ATTENUATION no longer widens through traversal — the stated property is now true", () => {
  // The module header claims a delegated sub-identity's scope "can only narrow, never widen".
  // It could widen: `attenuate` filters with the same unnormalised prefix check, so a child
  // asking for `src/../.env` under a parent scoped to `src` was GRANTED it. That is a granted
  // capability outside the parent's authority — the one thing attenuating delegation exists to
  // prevent.
  const reg = new IdentityRegistry();
  const parent = reg.mint("parent", ["src"]);
  const child = reg.delegate(parent, "child", ["src/../.env", "src/ok.ts", "etc"])!;

  assert.deepEqual(child.scope, ["src/ok.ts"], "only the genuinely-inside request survives");
  assert.ok(!child.scope.includes("src/../.env"), "a traversal request must not be granted");
  assert.equal(reg.authorizeEffect(child, ".env").authorized, false, "and the child cannot reach it");
});

test("Z99: the scope check is NOT the write-path enforcement — WriteGrant is, and it is stronger", async () => {
  // The evidence for not wiring `authorizeEffect` into the commit. A write is admitted only by
  // an exact (path, content) match against the declared set. A scope check cannot add anything
  // here: any path a prefix scope would admit must ALSO be in the declared write-set to land.
  const inner = new InMemoryFileTree({ "src/a.ts": "old" });
  const tree = mediatedTree(inner);
  const grant = new WriteGrant([{ path: "src/a.ts", content: "new" }]);

  await runMediatedWith(grant, async () => {
    // Declared path, declared content → admitted.
    await tree.write("src/a.ts", "new");
    // Same path, DIFFERENT content → refused. A scope check would have allowed this: the path
    // is squarely inside `src`. Exact-match is strictly stronger than prefix-match.
    await assert.rejects(
      () => tree.write("src/a.ts", "smuggled"),
      /unmediated effect blocked/,
      "content is part of the authority, which no path scope can express",
    );
    // A second write to the same declared path → refused; the grant is one-shot.
    await assert.rejects(() => tree.write("src/a.ts", "new"), /unmediated effect blocked/);
  });

  assert.equal(await inner.read("src/a.ts"), "new", "exactly the declared write landed, once");
});

test("Z99: a wildcard scope makes a scope check vacuous — which is why it is not wired", () => {
  // Both production paths mint with `["*"]` (round 35), and there is no operator-facing way to
  // set anything narrower. A check wired against this would return "allowed" for every path
  // ever proposed, while reading in the audit as though scope were enforced. Pinned so the
  // claim in the round doc is a test, not a paragraph.
  const reg = new IdentityRegistry();
  const agent = reg.mint("keep-solve", ["*"]);
  for (const p of ["src/a.ts", ".env", "anything/at/all", "a/b/../c.ts"]) {
    assert.equal(reg.authorizeEffect(agent, p).authorized, true, `wildcard admits ${p}`);
  }

  // ONE THING WILDCARD NO LONGER ADMITS, and it is an improvement worth pinning rather than
  // a regression. The root-escape check runs BEFORE the scope loop, so `["*"]` now means
  // "anything inside the root", not "literally any string". Found because this very test
  // asserted the old semantics and went red — the product was right and the test was wrong.
  assert.equal(
    reg.authorizeEffect(agent, "../../etc/passwd").authorized, false,
    "not even a wildcard scope authorises a path that resolves above the root",
  );
});
