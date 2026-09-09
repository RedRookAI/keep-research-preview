#!/usr/bin/env node
/**
 * neuter_engine.mjs — Keep's OWN mutation-neuter engine (BUILD-ORDER 8.7). [netguard-allow]
 *
 * The dogfood: the loop that builds Keep ships redrook-ops/mutation-gate.mjs, which proves a safety
 * guard is LOAD-BEARING by neutering its real enforcement and failing if the guarding test survives.
 * Keep, the product, owes a self-hosting user the same engine so THEIR CI can prove THEIR guards are
 * load-bearing, not decoration. This is that engine — but COMPOSED over Keep's own primitives:
 *   - the revert oracle is src/spine/tree_fingerprint.ts (a real Merkle tree fingerprint), not a shell
 *     hash, so "the tree was restored" is proven byte-identical or the run FAILS closed;
 *   - the three decisions (WATCHED classification, non-equivalence, restore-verification) live in
 *     src/graph/guard_registry.ts as pure, unit-tested, independently neuter-verifiable functions.
 *
 * ISOLATION (2026-08-18). The engine copies the tree to a throwaway dir and mutates ONLY that copy — the LIVE tree is
 * never touched, so a crash / kill mid-run can never leave a neutered (safety-disabled) file behind, and a concurrent
 * edit is never clobbered. Safety is by CONSTRUCTION; the in-copy restore + fingerprint proof remain as a per-guard
 * self-consistency check. (Dogfood of the review-agent worktree-isolation fix; git-agnostic — works on any tree.)
 *
 * CONTRACT. Given a guard registry JSON { treeRoot, build?, guards[] }, for EACH guard:
 *   1. structural check + require the `find` anchor to occur EXACTLY ONCE (a precise handle);
 *   2. reject an EQUIVALENT mutation (whitespace/comment-only — it could prove nothing);
 *   3. fingerprint the tree; apply the NON-EQUIVALENT mutation to the REAL site; (re)build if asked;
 *   4. run the NAMED guarding test and read whether IT (not a sibling) went red;
 *   5. classify WATCHED / NOT-WATCHED / DID-NOT-RUN;
 *   6. ALWAYS restore from the pristine in-memory buffer, then PROVE the tree fingerprint is identical
 *      again (assertTreeRestored, fail-closed).
 *
 * FRONT OF HOUSE: `node tools/neuter_engine.mjs <registry.json>` prints a per-property
 * WATCHED/NOT-WATCHED table + a fingerprint proof the tree was restored — offline, one command.
 * BACK OF HOUSE: exit 0 IFF every guard is WATCHED and every restore verified; a NOT-WATCHED guard (a
 * safety property whose deletion reddens no test) FAILS the build. Any survivor, ambiguous anchor,
 * equivalent mutation, missing test, or failed restore => exit 1 (fail-closed).
 *
 * HONEST LIMIT: WATCHED proves a guard's test catches THIS declared fault — not that the property is
 * fully specified, nor that every enforcement site is enumerated (that is the separate reachability
 * gate). Zero runtime dep: node builtins + Keep's own compiled dist.
 */
import { readFileSync, writeFileSync, existsSync, cpSync, rmSync, symlinkSync, mkdtempSync, chmodSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ENGINE_DIR = dirname(fileURLToPath(import.meta.url));
const distUrl = (rel) => pathToFileURL(join(ENGINE_DIR, "..", "dist", rel)).href;

// COMPOSED over Keep's own primitives — imported from the built dist, never re-implemented here.
const { classifyWatched, isNonEquivalent, assertTreeRestored, anchorOccurrences, guardDefect } =
  await import(distUrl("src/graph/guard_registry.js"));
const { fingerprintTree } = await import(distUrl("src/spine/tree_fingerprint.js"));

function fail(msg) {
  console.error(`[neuter_engine] ${msg}`);
  process.exit(2);
}

const regPath = process.argv[2] ?? process.env.KEEP_GUARD_REGISTRY ?? "";
if (!regPath) fail("usage: neuter_engine.mjs <guard_registry.json>");
if (!existsSync(regPath)) fail(`no registry at ${regPath}`);

const reg = JSON.parse(readFileSync(regPath, "utf8"));
const LIVE = process.env.KEEP_NEUTER_TREE ?? reg.treeRoot;
if (!LIVE || !existsSync(LIVE)) fail(`registry treeRoot missing or does not exist: ${LIVE}`);

// ISOLATION (dogfood of the review-agent worktree fix). The engine NEVER mutates the live tree: it copies the tree to a
// throwaway dir and runs ALL mutation/build/test THERE, so a crash / kill -9 / OOM / power-loss BETWEEN the mutate and the
// restore can never leave a NEUTERED (safety-disabled) file in the live tree (the old in-place mutation could — the
// finally-restore and the end-of-run fingerprint proof are both bypassed by a hard kill), and a concurrent edit is never
// clobbered. node_modules is SYMLINKED (not copied) so the build resolves the toolchain; .git is skipped. Git-agnostic.
const ISO = mkdtempSync(join(tmpdir(), "keep-neuter-iso-"));
let cleaned = false;
const cleanup = () => { if (cleaned) return; cleaned = true; try { rmSync(ISO, { recursive: true, force: true }); } catch { /* best-effort */ } };
process.on("exit", cleanup);
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => { cleanup(); process.exit(130); });
try {
  cpSync(LIVE, ISO, { recursive: true, filter: (src) => !/(^|[\\/])(node_modules|\.git)([\\/]|$)/.test(src) });
} catch (e) { fail(`cannot create the isolation copy of the tree: ${e.message}`); }
try { symlinkSync(resolve(LIVE, "node_modules"), join(ISO, "node_modules")); } catch { /* no node_modules (a plain fixture) — no build needed */ }
const TREE = ISO; // all mutation/build/test target the ISOLATED copy; the live tree is untouched by construction
const guards = Array.isArray(reg.guards) ? reg.guards : [];

if (reg.noEnforcement === true && guards.length === 0) {
  console.log(`[neuter_engine] registry declares noEnforcement (no verifiable safety property) — nothing to prove.`);
  process.exit(0);
}
if (guards.length === 0) fail("registry has no guards and did not declare noEnforcement — fail-closed");

// Run the ONE named guarding test against the tree and report whether that SPECIFIC test ran and
// whether IT went red (a mutation can redden a sibling; we isolate the property's own test).
function runNamedTest(build, guardingTest, testName) {
  if (build) {
    const b = spawnSync("bash", ["-c", build], { cwd: TREE, encoding: "utf8", timeout: 240000 });
    if (b.status !== 0) {
      // A mutation that will not even build is a behavior change the compiler catches → counts as red.
      return { built: false, named: true, red: true, note: "build failed under mutation (build-breaking → red)" };
    }
  }
  // Run the guarding test in a CLEAN context: strip NODE_TEST_CONTEXT so a nested `node --test`
  // (e.g. when the engine is itself invoked from inside a test runner) emits plain top-level TAP
  // rather than the subtest child protocol, and force the TAP reporter so the "ok/not ok" lines exist.
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const t = spawnSync("node", ["--test", "--test-reporter=tap", guardingTest], {
    cwd: TREE,
    encoding: "utf8",
    timeout: 240000,
    env,
  });
  const out = (t.stdout || "") + (t.stderr || "");
  // node --test emits TAP when not a TTY: "ok N - <name>" / "not ok N - <name>".
  const esc = String(testName).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const named = new RegExp(`^ok \\d+ - .*${esc}`, "m").test(out) || new RegExp(`^not ok \\d+ - .*${esc}`, "m").test(out);
  const red = new RegExp(`^not ok \\d+ - .*${esc}`, "m").test(out);
  return { built: true, named, red, out };
}

const fpGlobalBefore = fingerprintTree(TREE);
console.log(`[neuter_engine] tree ${TREE}`);
console.log(`[neuter_engine] fingerprint (pre-run): ${fpGlobalBefore}`);
console.log(`[neuter_engine] neuter-verifying ${guards.length} declared guard(s)\n`);

const rows = [];
let failed = 0;

for (const g of guards) {
  const label = g.property || g.file;
  const abs = join(TREE, g.file || "");
  const defect = guardDefect(g, existsSync(abs));
  if (defect) {
    rows.push({ label, verdict: "MALFORMED", detail: defect });
    failed++;
    continue;
  }
  const original = readFileSync(abs, "utf8");
  const occ = anchorOccurrences(original, g.find);
  if (occ !== 1) {
    rows.push({ label, verdict: "BAD-ANCHOR", detail: `'find' occurs ${occ}x in ${g.file} (need exactly 1)` });
    failed++;
    continue;
  }
  if (!isNonEquivalent(g.find, g.replace)) {
    rows.push({ label, verdict: "EQUIVALENT-REJECTED", detail: "mutation is whitespace/comment-only — proves nothing" });
    failed++;
    continue;
  }

  const fpBefore = fingerprintTree(TREE);
  let verdict, detail;
  try {
    try { chmodSync(abs, 0o644); } catch { /* ensure the COPY's file is writable even if the source tree is read-only */ }
    writeFileSync(abs, original.replace(g.find, g.replace)); // apply the NON-EQUIVALENT mutation to the isolated COPY's site
    const { named, red, note } = runNamedTest(reg.build, g.guardingTest, g.guardingTestName);
    verdict = classifyWatched(named, red);
    detail = verdict === "WATCHED"
      ? `neutering the real enforcement reddened "${g.guardingTestName}"${note ? " (" + note + ")" : ""}`
      : verdict === "NOT-WATCHED"
        ? `"${g.guardingTestName}" SURVIVED the mutation — the enforcement can be removed and this test stays green`
        : `"${g.guardingTestName}" (${g.guardingTest}) never ran — wrong test name/file`;
    if (verdict !== "WATCHED") failed++;
  } finally {
    writeFileSync(abs, original); // restore from the pristine in-memory buffer, ALWAYS
  }
  // The verdict is what we computed; record it whatever the restore does — a restore failure is a
  // SEPARATE fault, tracked on its own row, and must not erase the WATCHED/NOT-WATCHED finding.
  rows.push({ label, verdict, detail });
  // Prove the restore byte-identical via the tree fingerprint (fail-closed: throws if a mutation leaked).
  try {
    assertTreeRestored(fpBefore, fingerprintTree(TREE));
  } catch (e) {
    rows.push({ label, verdict: "RESTORE-FAILED", detail: String(e.message).split("\n")[0] });
    failed++;
  }
}

// Per-property table (front of house).
const pad = Math.max(...rows.map((r) => r.verdict.length));
console.log("  PROPERTY                                              VERDICT");
console.log("  " + "-".repeat(70));
for (const r of rows) {
  console.log(`  ${r.label.slice(0, 50).padEnd(51)} ${r.verdict.padEnd(pad)}  ${r.detail}`);
}

// Global restore proof: the whole tree is byte-identical to before the run (fail-closed).
const fpGlobalAfter = fingerprintTree(TREE);
console.log("");
try {
  assertTreeRestored(fpGlobalBefore, fpGlobalAfter);
  console.log(`[neuter_engine] restore PROVEN: tree fingerprint identical (${fpGlobalAfter})`);
} catch (e) {
  console.log(`[neuter_engine] ${String(e.message).split("\n")[0]}`);
  failed++;
}

console.log(
  failed === 0
    ? `[neuter_engine] ALL ${guards.length} guard(s) WATCHED (each real enforcement is load-bearing) — PASS`
    : `[neuter_engine] ${failed} guard(s) NOT load-bearing / not restored — FAIL`,
);
process.exit(failed === 0 ? 0 : 1);
