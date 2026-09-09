import { test } from "node:test";
import assert from "node:assert/strict";

import { InMemoryFileTree, resolveEditPlan } from "../src/solve/patch.js";

/**
 * R14 — DIVERGENT APPLY SEMANTICS (round 33).
 *
 * The two apply paths disagreed, and the ENVELOPE was the weaker one:
 *
 *   direct    applyEditPlan:  occ > 1 → status "ambiguous", applied: false   ← REFUSES
 *   envelope  closure:        cur.replace(search, replace)  ← FIRST OCCURRENCE, SILENT
 *
 * `String.prototype.replace` with a string pattern replaces only the first occurrence. So the
 * path about to become live applied edits the current path refuses.
 *
 * Fixed by extracting `resolveEditPlan` — one match-or-refuse seam, two commit strategies.
 * Refusal rather than disambiguation follows the established tool: git apply "will refuse to
 * create ambiguous hunks" and "fails the whole patch and does not touch the working tree".
 *
 * THESE TESTS EXERCISE THE SEAM DIRECTLY, ON A FORK-LIKE TREE. R13 now gates ambiguous plans
 * at the floor before apply is reached, so a pipeline-level test would pass for the WRONG
 * REASON — the "assertion both paths satisfy" trap the harness warned about.
 */

const AMBIGUOUS = { edits: [{ file: "a.txt", search: "dup", replace: "changed" }] } as never;

test("R14: an AMBIGUOUS edit is REFUSED at the seam, and the tree is untouched", async () => {
  const before = "dup\nmiddle\ndup\n";
  const fork = new InMemoryFileTree({ "a.txt": before });

  const r = await resolveEditPlan(AMBIGUOUS, fork);

  assert.equal(r.ok, false, "an ambiguous edit must be refused");
  assert.match(
    r.perEdit[0]!.reason ?? "", /matches 2× — must be unique/,
    "the refusal must name why, so the caller can tell refused from applied-nothing",
  );
  // Assert on the EFFECT (Z108): nothing was written, and nothing was staged to be written.
  assert.equal(await fork.read("a.txt"), before, "the tree must be untouched");
  assert.equal(r.nextContent.size, 0, "no content may be staged for an ambiguous plan");
});

test("R14: the OLD semantics would have applied it to the first occurrence", async () => {
  // This is the bug, reproduced exactly, so the fix has something to be measured against.
  const before = "dup\nmiddle\ndup\n";
  const cur = before;
  const old = cur.includes("dup") ? cur.replace("dup", "changed") : cur;

  assert.equal(old, "changed\nmiddle\ndup\n", "String.replace hits only the first occurrence");
  assert.notEqual(old, before, "the old closure silently mutated an ambiguous file");
});

test("R14: a UNIQUE edit still resolves and stages exactly the right content", async () => {
  const fork = new InMemoryFileTree({ "a.txt": "only-once\ntail\n" });
  const r = await resolveEditPlan(
    { edits: [{ file: "a.txt", search: "only-once", replace: "changed" }] } as never,
    fork,
  );

  assert.equal(r.ok, true, "a uniquely-matching edit resolves");
  assert.equal(r.nextContent.get("a.txt"), "changed\ntail\n", "the staged content is correct");
});

test("R14: all-or-nothing — one bad edit refuses the WHOLE plan, staging nothing", async () => {
  const fork = new InMemoryFileTree({ "a.txt": "unique\n", "b.txt": "dup\ndup\n" });
  const r = await resolveEditPlan(
    {
      edits: [
        { file: "a.txt", search: "unique", replace: "ok" },      // resolvable
        { file: "b.txt", search: "dup", replace: "changed" },    // ambiguous
      ],
    } as never,
    fork,
  );

  assert.equal(r.ok, false, "the whole plan is refused");
  assert.equal(await fork.read("a.txt"), "unique\n", "the resolvable edit must NOT have landed");
});
