import { test } from "node:test";
import assert from "node:assert/strict";

import { withinScope, unsupportedScopePatterns } from "../src/authz/path_scope.js";
import { structuralFloor, defaultFloorPolicy } from "../src/floor/structural_floor.js";

/**
 * ROUND 39 — MAKING A SCOPE STATABLE, WITH THE SMALLEST POSSIBLE GLOB.
 *
 * Round 38 shipped `allowedPaths` and then measured it into a corner: a directory allowlist
 * refused 6-7 of 9 legitimate fixes, every refusal a root-level file, because a directory list
 * cannot say "and the ordinary project files at the root".
 *
 * The dialect research is emphatic that PARTIAL glob support is the footgun — "differences bite
 * users when they assume full compatibility", `**` is "supported by most but not all", and
 * negation has the notorious trap that "it is not possible to re-include a file if a parent
 * directory of that file is excluded". So the supported surface is deliberately one sentence
 * wide, it follows gitignore where it exists at all, and EVERYTHING ELSE IS REPORTED rather than
 * silently ignored.
 *
 * These tests specify what is supported AND what is not, because the cases a round declines to
 * implement are exactly the ones an operator will otherwise assume work.
 */

test("R39 ACCEPTANCE: a plausible scope now admits all nine legitimate fix shapes", () => {
  // This is the round's acceptance criterion, not a nice-to-have. A scope an operator would
  // write unprompted must stop refusing honest work, or the control gets set to ["*"] forever.
  const scope = ["src", "test", "scripts", ".github", "*.json", "*.md"];
  const fixes = [
    ["src/solve/patch.ts"],
    ["src/solve/patch.ts", "test/patch.test.ts"],
    ["src/identity/agent_identity.ts", "test/agent_identity.test.ts", "KEEP_REDTEAM_HARDENING_PLAN.md"],
    ["package.json"],
    ["tsconfig.json"],
    [".github/workflows/ci.yml"],
    ["scripts/gen.mjs"],
    ["README.md"],
  ];
  for (const writeSet of fixes) {
    const v = structuralFloor(
      { kind: "file.edit", writeSet, targets: writeSet, hasInverse: true, raw: "ordinary edit" },
      defaultFloorPolicy("repo", scope),
    );
    assert.equal(v.verdict, "reversible-execute", `legitimate fix refused: ${writeSet.join(", ")}`);
  }
});

test("R39: and that scope STILL refuses things — usable is not the same as useless", () => {
  // A syntax permissive enough to be usable may be permissive enough to be worthless. Checked
  // rather than hoped (harness §4).
  const policy = defaultFloorPolicy("repo", ["src", "test", "scripts", ".github", "*.json", "*.md"]);
  for (const p of ["infra/deploy.tf", "vendor/lib.js", "Makefile", "dist/bundle.js"]) {
    const v = structuralFloor(
      { kind: "file.edit", writeSet: [p], targets: [p], hasInverse: true, raw: "x" },
      policy,
    );
    assert.equal(v.verdict, "gate", `${p} should still be outside the scope`);
  }
});

test("R39: a slashless glob matches the BASENAME at any depth — gitignore's own rule", () => {
  assert.equal(withinScope(["*.md"], "README.md"), true, "at the root");
  assert.equal(withinScope(["*.md"], "docs/guide/intro.md"), true, "and nested, as gitignore does");
  assert.equal(withinScope(["*.md"], "README.txt"), false, "a different extension is not admitted");
});

test("R39: `*` does not cross a path separator inside a segment", () => {
  // The single most-cited dialect difference: whether `*` spans `/`. Here it does not, and that
  // is pinned so a later change cannot silently widen every scope in existence.
  assert.equal(withinScope(["src*"], "src/foo.ts"), false, "`src*` is a basename pattern, not a prefix");
  assert.equal(withinScope(["*.ts"], "src/a.ts"), true, "but the basename itself matches at depth");
  assert.equal(withinScope(["a*c"], "abc"), true);
  assert.equal(withinScope(["a*c"], "ab/c"), false, "no crossing the separator");
});

test("R39: UNSUPPORTED patterns are reported, not silently ignored", () => {
  // Without this, `src/**/*.ts` matches nothing, every plan is refused, and the operator
  // concludes the control is broken and removes it — abandonment reached by a spelling mistake
  // that nobody reported (Z135).
  assert.deepEqual(unsupportedScopePatterns(["src", "*.md", "src/**/*.ts", "src/*.ts"]), ["src/**/*.ts", "src/*.ts"]);
  assert.deepEqual(unsupportedScopePatterns(["src", "*.md", "*"]), [], "the supported forms are not flagged");

  const v = structuralFloor(
    { kind: "file.edit", writeSet: ["src/a.ts"], targets: ["src/a.ts"], hasInverse: true, raw: "x" },
    defaultFloorPolicy("repo", ["src/**/*.ts"]),
  );
  assert.equal(v.verdict, "gate");
  assert.ok(
    v.reasons.some((r) => r.startsWith("unsupported-scope-pattern:src/**/*.ts")),
    "the operator must be told their pattern is unsupported, and which forms are",
  );
});

test("R39: a refusal names the minimal addition that would permit it", () => {
  // A dead-end refusal is switched off; a refusal you can act on in one step is kept.
  const v = structuralFloor(
    { kind: "file.edit", writeSet: ["scripts/gen.mjs"], targets: ["scripts/gen.mjs"], hasInverse: true, raw: "x" },
    defaultFloorPolicy("repo", ["src"]),
  );
  assert.ok(
    v.reasons.some((r) => r.includes('add "scripts" to allowedPaths')),
    "the reason must name the directory to add",
  );

  const rootFile = structuralFloor(
    { kind: "file.edit", writeSet: ["README.md"], targets: ["README.md"], hasInverse: true, raw: "x" },
    defaultFloorPolicy("repo", ["src"]),
  );
  assert.ok(
    rootFile.reasons.some((r) => r.includes('add "README.md" to allowedPaths')),
    "a root-level file names itself, not a directory",
  );
});

test("R39 ADVERSARIAL: `.` means the repo root, and a stray bare `*` silently disables the control", () => {
  // Both found by sweeping plausible-looking scopes for ones that behave unexpectedly.
  //
  // FIXED: `["."]` — an obvious way to write "the whole project" — previously admitted NOTHING,
  // because no canonical path begins with `./`. Fail-safe, so it would have been noticed, but a
  // control that refuses everything when told "the root" gets deleted rather than debugged.
  assert.equal(withinScope(["."], "src/a.ts"), true, "'.' is the root and admits what is inside it");
  assert.equal(withinScope([""], "src/a.ts"), true, "'' canonicalises to '.' and behaves the same");
  assert.equal(withinScope(["."], "../escape.ts"), false, "but still not above the root");

  // REPORTED, NOT FIXED: a bare `*` alongside other entries admits EVERYTHING. The scope reads
  // as restrictive because it names real directories, and permits the whole tree. This is
  // documented `*` behaviour rather than a defect, and the floor cannot surface it — nothing
  // gates, so no reason is ever emitted. Closing it needs config-time validation, which has no
  // home yet. Pinned here so the behaviour is a stated fact rather than a surprise.
  assert.equal(withinScope(["src", "*"], "infra/deploy.tf"), true, "SEAM: a stray '*' disables the allowlist");
});

test("R39: every property round 38 proved still holds, for its own reasons", () => {
  // Requirement 3. The glob must not have quietly changed canonicalisation, the root-escape
  // rule, or the empty/omitted distinction.
  assert.equal(withinScope(["src"], "src/../.env"), false, "canonicalise-then-compare survives");
  assert.equal(withinScope(["*"], "../../etc/passwd"), false, "root escape refused before the scope loop");
  assert.equal(withinScope([], "src/a.ts"), false, "[] admits nothing");
  assert.equal(withinScope(["*"], "anything/at/all.ts"), true, "bare * still admits inside the root");

  const op = { kind: "file.edit", writeSet: ["src/a.ts"], targets: ["src/a.ts"], hasInverse: true, raw: "x" };
  assert.equal(structuralFloor(op, defaultFloorPolicy("repo")).verdict, "reversible-execute", "omitted ⇒ inert");
});
