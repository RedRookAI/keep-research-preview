import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, statSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import {
  classifyWatched,
  isNonEquivalent,
  assertTreeRestored,
  anchorOccurrences,
  guardDefect,
} from "../src/graph/guard_registry.js";
import { fingerprintTree } from "../src/spine/tree_fingerprint.js";

/**
 * NEUTER-ENGINE CONTRACT (BUILD-ORDER 8.7). tools/neuter_engine.mjs proves a safety guard is
 * LOAD-BEARING by neutering its real enforcement and failing if the guarding test survives. These
 * tests pin the three composed decisions directly (WATCHED classification, non-equivalence, restore
 * verification) AND drive the whole engine over a FIXTURE registry + fixture tree — no real-source
 * mutation, deterministic, offline. Each is paired with an isolating neuter in the round's
 * disproof-red.txt: neutering DECISION (1) reddens ONLY "not-load-bearing guard flagged NOT-WATCHED";
 * (2) ONLY "equivalent mutation rejected"; (3)/the engine restore ONLY the restore tests.
 */

// ── DECISION (1): WATCHED classification ──────────────────────────────────────────────────────────
test("not-load-bearing guard flagged NOT-WATCHED", () => {
  // A mutation that RAN a test which STAYED GREEN means the real enforcement can be removed unnoticed.
  assert.equal(classifyWatched(true, false), "NOT-WATCHED");
  // Neutering the enforcement reddened the test → the guard is load-bearing.
  assert.equal(classifyWatched(true, true), "WATCHED");
  // The named test never ran → it cannot testify; never a silent pass.
  assert.equal(classifyWatched(false, false), "DID-NOT-RUN");
  assert.equal(classifyWatched(false, true), "DID-NOT-RUN");
});

// ── DECISION (2): non-equivalence ─────────────────────────────────────────────────────────────────
test("equivalent mutation rejected", () => {
  // Whitespace-only and comment-only edits are equivalent mutants: no test can observe them, so they
  // prove nothing and must be rejected before they can be counted as evidence.
  assert.equal(isNonEquivalent("a > 5", "a  >  5"), false);
  assert.equal(isNonEquivalent("x === y", "x === y // note"), false);
  assert.equal(isNonEquivalent("a > 5", "a > 5"), false);
  // A real token change is observable.
  assert.equal(isNonEquivalent("a > 5", "a > 999"), true);
  assert.equal(isNonEquivalent('route: "hold"', 'route: "allow"'), true);
});

// ── DECISION (3): restore verification (fail-closed) ──────────────────────────────────────────────
test("revert-verifier fails closed on fingerprint mismatch", () => {
  // A tree that does not fingerprint identically after a neuter has a mutation leaked to disk → throw.
  assert.throws(() => assertTreeRestored("sha256:aaa", "sha256:bbb"), /NOT restored/);
  // Identical fingerprints → restore proven, no throw.
  assert.doesNotThrow(() => assertTreeRestored("sha256:aaa", "sha256:aaa"));
});

test("anchor + defect guards reject an unusable guard", () => {
  assert.equal(anchorOccurrences("if (n > 5) throw; if (n > 5) throw;", "n > 5"), 2);
  assert.equal(anchorOccurrences("if (n > 5) throw;", "n > 5"), 1);
  assert.equal(anchorOccurrences("nothing here", "n > 5"), 0);
  const good = {
    property: "p", file: "guard.mjs", find: "n > 5", replace: "n > 999",
    guardingTest: "guard.test.mjs", guardingTestName: "rejects over-limit",
  } as const;
  assert.equal(guardDefect(good, true), null);
  assert.match(guardDefect(good, false) ?? "", /does not exist/);
  assert.match(guardDefect({ ...good, find: "" }, true) ?? "", /malformed/);
});

// ── END-TO-END over a fixture registry + fixture tree ─────────────────────────────────────────────
const ENGINE = join(process.cwd(), "tools", "neuter_engine.mjs");

/** Build a throwaway tree with a load-bearing fixture guard + its test + a registry pointing at them. */
function makeFixture(): { dir: string; registry: string; guardFile: string } {
  const dir = mkdtempSync(join(tmpdir(), "keep-neuter-fixture-"));
  writeFileSync(
    join(dir, "guard.mjs"),
    "export function admit(n) {\n  if (n > 5) throw new Error('over limit');\n  return n;\n}\n",
  );
  writeFileSync(
    join(dir, "guard.test.mjs"),
    "import { test } from 'node:test';\n" +
      "import assert from 'node:assert/strict';\n" +
      "import { admit } from './guard.mjs';\n" +
      "test('rejects over-limit', () => {\n" +
      "  assert.throws(() => admit(6));\n" +
      "  assert.equal(admit(3), 3);\n" +
      "});\n",
  );
  const registry = join(dir, "registry.json");
  writeFileSync(
    registry,
    JSON.stringify({
      treeRoot: dir,
      guards: [
        {
          property: "values over the limit are rejected",
          file: "guard.mjs",
          find: "n > 5",
          replace: "n > 999",
          guardingTest: "guard.test.mjs",
          guardingTestName: "rejects over-limit",
        },
      ],
    }),
  );
  return { dir, registry, guardFile: join(dir, "guard.mjs") };
}

test("engine classifies a load-bearing fixture guard WATCHED", () => {
  // Verdict-focused: neutering the fixture's real enforcement reddens its test, so the engine must
  // report WATCHED for the property (and never NOT-WATCHED). Deliberately does NOT assert the exit
  // code — that is the restore test's concern, so this neuter isolates from the restore neuter.
  const { dir, registry } = makeFixture();
  try {
    const r = spawnSync("node", [ENGINE, registry], { encoding: "utf8" });
    assert.match(r.stdout, /WATCHED/, `engine should report a WATCHED verdict\n${r.stdout}\n${r.stderr}`);
    assert.doesNotMatch(r.stdout, /NOT-WATCHED/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tree fingerprint restored after each neuter", () => {
  // Restore-focused: the engine must leave the tree byte-identical (proven by the Merkle fingerprint
  // AND the raw bytes) and, being fail-closed, exit 0 with a "restore PROVEN" line. If the revert is
  // neutered, the mutated guard.mjs is left in place, the fingerprint diverges, and the engine exits
  // nonzero — this test reddens while the WATCHED verdict test stays green.
  const { dir, registry, guardFile } = makeFixture();
  try {
    const pristineFp = fingerprintTree(dir);
    const pristineBytes = readFileSync(guardFile, "utf8");
    const r = spawnSync("node", [ENGINE, registry], { encoding: "utf8" });
    assert.equal(readFileSync(guardFile, "utf8"), pristineBytes, `guard.mjs left mutated\n${r.stdout}`);
    assert.equal(fingerprintTree(dir), pristineFp, "tree fingerprint changed — a mutation leaked");
    assert.match(r.stdout, /restore PROVEN/);
    assert.equal(r.status, 0, `engine should exit 0 when the tree restores cleanly\n${r.stdout}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("isolation: node_modules is symlinked into the copy — a guard chain that imports from it still verifies WATCHED", () => {
  // The engine copies the tree EXCEPT node_modules, then SYMLINKS node_modules so the build/test resolves the toolchain.
  // Proof: the guard + its test both import from node_modules; if the symlink failed, the imports would fail and the test
  // would not run (not WATCHED). A WATCHED verdict proves node_modules resolved through the symlink in the isolated copy.
  const dir = mkdtempSync(join(tmpdir(), "keep-neuter-nm-"));
  try {
    mkdirSync(join(dir, "node_modules"), { recursive: true });
    writeFileSync(join(dir, "node_modules", "dep.mjs"), "export const LIMIT = 5;\n"); // a "dependency" resolved via node_modules
    writeFileSync(join(dir, "guard.mjs"), "import { LIMIT } from './node_modules/dep.mjs';\nexport function admit(n) {\n  if (n > LIMIT) throw new Error('over');\n  return n;\n}\n");
    writeFileSync(join(dir, "guard.test.mjs"), "import { test } from 'node:test';\nimport assert from 'node:assert/strict';\nimport { admit } from './guard.mjs';\nimport { LIMIT } from './node_modules/dep.mjs';\ntest('rejects over-limit', () => { assert.equal(LIMIT, 5); assert.throws(() => admit(6)); assert.equal(admit(3), 3); });\n");
    const registry = join(dir, "registry.json");
    writeFileSync(registry, JSON.stringify({ treeRoot: dir, guards: [{ property: "over-limit rejected (dep-backed)", file: "guard.mjs", find: "n > LIMIT", replace: "n > 999", guardingTest: "guard.test.mjs", guardingTestName: "rejects over-limit" }] }));
    const r = spawnSync("node", [ENGINE, registry], { encoding: "utf8" });
    assert.match(r.stdout, /WATCHED/, `node_modules symlink must resolve in the copy so the guard chain runs\n${r.stdout}\n${r.stderr}`);
    assert.doesNotMatch(r.stdout, /NOT-WATCHED|DID-NOT-RUN/);
    assert.equal(r.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("isolation: the engine never WRITES the LIVE tree — the guard file's mtime is unchanged", () => {
  // The engine mutates an isolated COPY, never the live tree. Proof by mtime (robust even as root, which bypasses file
  // permissions but not mtime updates): under isolation the live guard file is only READ (to copy) and never WRITTEN, so
  // its mtime is unchanged across a full run. If the engine mutated the live tree (the pre-isolation behaviour), the
  // mutate+restore writes would bump the mtime. Content is also byte-identical.
  const { dir, registry, guardFile } = makeFixture();
  try {
    const pristine = readFileSync(guardFile, "utf8");
    const before = statSync(guardFile).mtimeMs;
    // ensure a detectable gap so a write during the run yields a strictly-greater mtime.
    const start = Date.now(); while (Date.now() - start < 20) { /* spin ~20ms */ }
    const r = spawnSync("node", [ENGINE, registry], { encoding: "utf8" });
    assert.match(r.stdout, /WATCHED/, `engine should still verify WATCHED\n${r.stdout}\n${r.stderr}`);
    assert.equal(r.status, 0, `engine should exit 0\n${r.stdout}\n${r.stderr}`);
    assert.equal(statSync(guardFile).mtimeMs, before, "the LIVE guard file was WRITTEN (mtime changed) — the engine did not isolate the mutation to a copy");
    assert.equal(readFileSync(guardFile, "utf8"), pristine, "the live guard file must be byte-identical (never written)");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
