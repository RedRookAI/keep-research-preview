import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, basename, relative } from "node:path";

/**
 * Orphan-export contract — the finer dimension the module-level island check (no_islands.test.ts) cannot see.
 *
 * no_islands proves every MODULE is consumed (or a documented exception). But a consumed module can still carry an
 * exported symbol that nothing references — a dead export hiding inside a live module. This test reads the actual
 * symbol graph and asserts every exported VALUE (function / class / const) is either referenced outside its own file,
 * or is a DOCUMENTED, reasoned exception. A new dead export fails here, exactly like a new island fails there.
 *
 * Scope + conservatism (to stay false-positive-free):
 *  - Values only (function/class/const). Types/interfaces are erased and traced differently — out of scope.
 *  - "Dead" = zero word-boundary references in any OTHER non-barrel src or test file, AND not used inside its own file
 *    beyond the export declaration (a symbol used internally is merely over-exported — benign, not flagged).
 *  - Exports in modules that are themselves unconsumed (island allowlist) are skipped — the whole module is unwired by
 *    design, so its exports are expected to be unreferenced; no_islands already governs those.
 */

const srcDir = join(process.cwd(), "src");
const testDir = join(process.cwd(), "test");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

const srcFiles = walk(srcDir);
const testFiles = walk(testDir);
const allFiles = [...srcFiles, ...testFiles];
const text = new Map<string, string>(allFiles.map((p) => [p, readFileSync(p, "utf8")]));

// Modules with at least one non-barrel, non-self consumer are "live". (Mirrors no_islands' consumer rule.)
function liveModules(): Set<string> {
  const count = new Map<string, number>();
  for (const p of srcFiles) count.set(basename(p, ".ts"), 0);
  const impRe = /from\s+"([^"]+)\.js"/g;
  for (const p of srcFiles) {
    if (basename(p) === "index.ts") continue;
    const self = basename(p, ".ts");
    let m: RegExpExecArray | null;
    const t = text.get(p)!;
    while ((m = impRe.exec(t))) {
      const tb = basename(m[1]!);
      if (count.has(tb) && tb !== self) count.set(tb, count.get(tb)! + 1);
    }
  }
  return new Set([...count.entries()].filter(([, c]) => c > 0).map(([b]) => b));
}

const live = liveModules();
const expRe = /^export\s+(?:async\s+)?(?:function|class|const)\s+([A-Za-z0-9_]+)/gm;

function isDeadExport(defPath: string, name: string): boolean {
  const re = new RegExp(`\\b${name}\\b`);
  for (const q of allFiles) {
    if (q === defPath || basename(q) === "index.ts") continue;
    if (basename(q) === "no_orphan_exports.test.ts") continue; // this contract lists the names; don't count itself
    if (re.test(text.get(q)!)) return false; // referenced somewhere external → not dead
  }
  // Not referenced externally. Used inside its own file (beyond the single declaration)? → over-exported, benign.
  const own = text.get(defPath)!;
  const occurrences = (own.match(new RegExp(`\\b${name}\\b`, "g")) ?? []).length;
  return occurrences <= 1;
}

// ── Documented orphan-export exceptions (dead in a LIVE module, kept deliberately) ──
// Each is unwired API SURFACE, not broken code. Remove an entry when the export gains a real consumer.
const ORPHAN_EXPORTS = new Set<string>([
  "cassette::FileCassetteStore",             // alternative (file-backed) record/replay store a user can wire for persistence; InMemory variant is the default in use
  "resolve/selector::DEFAULT_SELECTOR",      // default CandidateSelector impl offered for callers; selection is injected elsewhere today
  "review/heterogeneous::heterogeneousReview", // convenience wrapper; the enforced guardrails (assert/checkHeterogeneous) are the consumed primitives
  "escalation_policy::certaintyFromSignals", // documented tier helper (behavioral certainty) — part of the cascade API surface, wired when a tier reports certainty
  "review/review_core::getManifest",         // public PR-manifest accessor on KeepApp for external callers/UI; not used by internal runtime paths
  "gateway/wire_dialect::WIRE_DIALECTS",     // the supported-dialect registry (data); dialect selection currently flows through typed helpers
  "eir/eir::obligationId",                   // completes the EIR node-id family (principalId/effectId/guardId/obligationId); the compiler (Incr 2) emits bundle-native rules, so the Obligation node's id is first consumed by a later increment that lowers to EIR Obligation nodes
  "logic/plan_gate::stateSimulationGated",   // plan-gate state-simulation predicate exported for the plan-gate API surface; currently unconsumed (its runtime caller is a future plan-gate wiring), genuinely dead-but-not-wrong
  "observability/fleet_telemetry::FleetTelemetryExporter", // preserved public compatibility adapter for callers that inject an OtlpSink; the installed path uses the stronger durable exporter
  // L4: FileWitnessSink is no longer dead — composeKeep now constructs it as the default audit-chain
  // witness (src/compose.ts), so it is a live consumer and no longer belongs on this allowlist.
]);

function key(defPath: string, name: string): string {
  const rel = relative(srcDir, defPath).replace(/\.ts$/, "");
  const short = basename(defPath, ".ts");
  // accept either "<module>::name" or "<subdir>/<module>::name" in the allowlist
  return `${short}::${name}`;
  void rel;
}
function relKey(defPath: string, name: string): string {
  return `${relative(srcDir, defPath).replace(/\.ts$/, "")}::${name}`;
}

test("no orphan exports: every dead export in a LIVE module is a documented exception", () => {
  const dead: string[] = [];
  for (const p of srcFiles) {
    if (basename(p) === "index.ts") continue;
    if (!live.has(basename(p, ".ts"))) continue; // island module — governed by no_islands
    const t = text.get(p)!;
    let m: RegExpExecArray | null;
    expRe.lastIndex = 0;
    while ((m = expRe.exec(t))) {
      const name = m[1]!;
      if (isDeadExport(p, name)) {
        const k1 = key(p, name);
        const k2 = relKey(p, name);
        if (!ORPHAN_EXPORTS.has(k1) && !ORPHAN_EXPORTS.has(k2)) dead.push(k2);
      }
    }
  }
  assert.deepEqual(dead.sort(), [], `New dead export(s) found in live modules — wire, test-consume, remove, or document in ORPHAN_EXPORTS:\n${dead.sort().join("\n")}`);
});

test("orphan-export allowlist stays honest: every documented exception is still actually dead", () => {
  // Build the set of currently-dead exports (module::name and subdir/module::name forms).
  const deadKeys = new Set<string>();
  for (const p of srcFiles) {
    if (basename(p) === "index.ts") continue;
    if (!live.has(basename(p, ".ts"))) continue;
    const t = text.get(p)!;
    let m: RegExpExecArray | null;
    expRe.lastIndex = 0;
    while ((m = expRe.exec(t))) {
      const name = m[1]!;
      if (isDeadExport(p, name)) { deadKeys.add(key(p, name)); deadKeys.add(relKey(p, name)); }
    }
  }
  const stale = [...ORPHAN_EXPORTS].filter((k) => !deadKeys.has(k)).sort();
  assert.deepEqual(stale, [], `ORPHAN_EXPORTS entries that are now referenced (remove them — they're wired):\n${stale.join("\n")}`);
});
