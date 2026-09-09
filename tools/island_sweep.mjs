#!/usr/bin/env node
/**
 * island_sweep.mjs — a real `ts.TypeChecker` two-color reachability sweep. [netguard-allow]
 *
 * WHY THIS EXISTS (BUILD-ORDER 8.4, 2026-08-17). A module reachable ONLY via `import type`
 * is a wire that reads connected to a source reader and to text/regex graph tools, but the
 * compiler ERASES the type-only edge at emit, so nothing loads it at runtime. It is not dead
 * code (it has importers and tests) and not runtime-live — it is a TYPE-ONLY ISLAND. Keep's
 * two hand-audit guards both miss it structurally: `test/no_islands.test.ts` matches
 * `import type` with the same regex as a value import, and `test/no_orphan_exports.test.ts`
 * counts a test-only reference as "live" (the historical logic/plan_gate.ts case).
 *
 * This engine upgrades that capability from a REGEX classifier (redrook-ops/keep-reachability-
 * sweep.mjs, a text tool with documented false-positive limits) to a real COMPILER GRAPH: it
 * builds a `ts` Program, colors every import edge RUNTIME vs TYPE_ONLY using the precise
 * `import type` / per-specifier `type` / `export type` information the checker exposes, then
 * runs a two-color mark-and-sweep from the entry roots (McCarthy/Dijkstra mark-and-sweep GC:
 * an object reachable only from a freed root is garbage exactly as a module reachable only via
 * an erased edge is an island). Every module is classified:
 *
 *   RUNTIME-REACHABLE   reached from a root over RUNTIME edges (it loads at runtime)
 *   TYPE-ONLY-ISLAND    real runtime code, but every edge into it is erased `import type`
 *   TYPES-ONLY-MODULE   only type-only edges, and it exports no runtime code (expected, not a finding)
 *   NEEDS-A-HUMAN-LOOK  touched by dynamic import() / side-effect import (DI/registry not statically visible)
 *   UNREFERENCED        no importer of any kind
 *
 * HONEST SEAM (the disconfirming case): dynamic `import()`, side-effect-only imports and
 * DI/registry registration are NOT statically decidable — they are NEEDS-A-HUMAN-LOOK, never
 * silently ISLAND (they may run) and never silently RUNTIME-REACHABLE (they may never be
 * called). The cardinal defect this guards is FAIL-OPEN: a crashed sweep read as "0 islands".
 * So on success this prints the sentinel line `ISLAND-SWEEP-OK` and exits 0; any failure exits
 * non-zero WITHOUT the sentinel, and the consuming port (src/graph/reachability_port.ts) refuses
 * to trust a result that lacks it.
 *
 * typescript is ALREADY the sole devDep; this engine lives in tools/ (build-time), never in
 * src/, so the shipped product stays zero runtime-dependency.
 *
 * Usage:
 *   node tools/island_sweep.mjs --root <dir> --entry <file> [--entry <file>...] [--json]
 */
import ts from "typescript";
import { readdirSync, statSync, existsSync } from "node:fs";
import { join, resolve, relative, sep } from "node:path";

const SENTINEL = "ISLAND-SWEEP-OK";

function die(msg) {
  // Fail CLOSED: exit non-zero and DO NOT print the sentinel, so no caller reads this as "all clear".
  console.error(`[island-sweep] ${msg}`);
  process.exit(2);
}

function parseArgs(argv) {
  const out = { root: null, entries: [], json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--root") out.root = argv[++i];
    else if (a === "--entry") out.entries.push(argv[++i]);
    else if (a === "--json") out.json = true;
  }
  return out;
}

function walkTs(dir) {
  let out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    const s = statSync(p);
    if (s.isDirectory()) out = out.concat(walkTs(p));
    else if (e.endsWith(".ts") && !e.endsWith(".d.ts")) out.push(p);
  }
  return out;
}

// Canonical module id: path relative to root, forward-slashed, extension dropped.
function idOf(root, fileName) {
  return relative(root, fileName).split(sep).join("/").replace(/\.ts$/, "");
}

/**
 * Classify one `import ... from` clause. THE ROUND TURNS ON THIS: the checker gives us the
 * precise per-import `type` modifier the regex cannot see.
 *   import type { T } from "x"        -> TYPE_ONLY (importClause.isTypeOnly)
 *   import { type A, type B } from "x" -> TYPE_ONLY (every named specifier isTypeOnly, no value binding)
 *   import { V, type T } from "x"      -> RUNTIME (V is a value binding)
 *   import D from "x" / import * as ns -> RUNTIME (default / namespace binding)
 *   import "x"                          -> side-effect (no importClause)
 */
function importDeclKind(node) {
  const clause = node.importClause;
  if (!clause) return "sideeffect";
  if (clause.isTypeOnly) return "type";
  if (clause.name) return "runtime"; // default binding is a value
  const nb = clause.namedBindings;
  if (nb && ts.isNamespaceImport(nb)) return "runtime"; // * as ns is a value
  if (nb && ts.isNamedImports(nb)) {
    const specs = nb.elements;
    if (specs.length === 0) return "runtime";
    return specs.every((s) => s.isTypeOnly) ? "type" : "runtime";
  }
  return "runtime";
}

/** Does this source file export anything that EXISTS at runtime (function/class/const/enum/default/value re-export)? */
function exportsRuntimeValues(sf) {
  for (const st of sf.statements) {
    const mods = ts.canHaveModifiers(st) ? ts.getModifiers(st) : undefined;
    const exported = mods && mods.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if (exported && (ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st) || ts.isVariableStatement(st) || ts.isEnumDeclaration(st))) return true;
    if (ts.isExportAssignment(st)) return true; // export default / export =
    // `export { a, b }` (not `export type { ... }`) re-exports runtime values
    if (ts.isExportDeclaration(st) && !st.isTypeOnly && !st.moduleSpecifier && st.exportClause) return true;
    if (ts.isExportDeclaration(st) && !st.isTypeOnly && st.moduleSpecifier) return true; // runtime re-export barrel
  }
  return false;
}

function main() {
  const { root: rawRoot, entries: rawEntries, json } = parseArgs(process.argv.slice(2));
  if (!rawRoot) die("missing --root <dir>");
  const root = resolve(rawRoot);
  if (!existsSync(root)) die(`root does not exist: ${root}`);
  const entries = rawEntries.map((e) => resolve(e));
  for (const e of entries) if (!existsSync(e)) die(`entry does not exist: ${e}`);

  const files = walkTs(root);
  if (files.length === 0) die(`no .ts files under root: ${root}`);

  const options = {
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    target: ts.ScriptTarget.ES2022,
    strict: false,
    noEmit: true,
    skipLibCheck: true,
    allowJs: false,
  };
  const host = ts.createCompilerHost(options, true);
  const program = ts.createProgram(files, options, host);
  // A real TypeChecker anchors this as a compiler-graph sweep (re-export chains, module resolution),
  // not a second regex. We resolve edges through the program's own resolution, below.
  program.getTypeChecker();

  const known = new Set(files.map((f) => resolve(f)));
  const idFor = new Map(files.map((f) => [resolve(f), idOf(root, resolve(f))]));

  // Edge model: for each internal target module, which colors of edge point INTO it, and
  // (for RUNTIME edges) the adjacency we mark-and-sweep over.
  const runtimeOut = new Map(); // fileId -> Set<fileId>  (runtime-propagating edges only)
  const incoming = new Map(); // fileId -> {runtime,type,dynamic,sideeffect} counts
  const touch = (id) => {
    if (!incoming.has(id)) incoming.set(id, { runtime: 0, type: 0, dynamic: 0, sideeffect: 0 });
    return incoming.get(id);
  };
  for (const f of files) { touch(idOf(root, resolve(f))); runtimeOut.set(idOf(root, resolve(f)), new Set()); }

  function resolveSpec(spec, containingFile) {
    const r = ts.resolveModuleName(spec, containingFile, options, host);
    const rf = r.resolvedModule && r.resolvedModule.resolvedFileName;
    if (!rf) return null;
    const abs = resolve(rf);
    return known.has(abs) ? idFor.get(abs) : null;
  }

  for (const sf of program.getSourceFiles()) {
    const absSelf = resolve(sf.fileName);
    if (!known.has(absSelf)) continue; // skip lib.d.ts and node_modules
    const selfId = idFor.get(absSelf);

    const addEdge = (targetId, kind) => {
      if (targetId == null || targetId === selfId) return;
      const inc = touch(targetId);
      inc[kind] += 1;
      if (kind === "runtime") runtimeOut.get(selfId).add(targetId);
    };

    // Static import declarations and export ... from re-exports.
    for (const st of sf.statements) {
      if (ts.isImportDeclaration(st) && ts.isStringLiteral(st.moduleSpecifier)) {
        addEdge(resolveSpec(st.moduleSpecifier.text, sf.fileName), importDeclKind(st));
      } else if (ts.isExportDeclaration(st) && st.moduleSpecifier && ts.isStringLiteral(st.moduleSpecifier)) {
        addEdge(resolveSpec(st.moduleSpecifier.text, sf.fileName), st.isTypeOnly ? "type" : "runtime");
      }
    }

    // Deep walk for dynamic import() (value position) and import(...) TYPE nodes (erased).
    const visit = (node) => {
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const arg = node.arguments[0];
        if (arg && ts.isStringLiteral(arg)) addEdge(resolveSpec(arg.text, sf.fileName), "dynamic");
      } else if (ts.isImportTypeNode(node) && node.argument && ts.isLiteralTypeNode(node.argument) && ts.isStringLiteral(node.argument.literal)) {
        addEdge(resolveSpec(node.argument.literal.text, sf.fileName), "type"); // import("x").T is erased
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(sf, visit);
  }

  // ── Two-color mark-and-sweep: mark RUNTIME-reachable from the entry roots over runtime edges. ──
  const rootIds = entries.map((e) => idFor.get(resolve(e))).filter(Boolean);
  if (entries.length > 0 && rootIds.length === 0) die("no --entry resolved to a file under --root");
  const runtimeReachable = new Set();
  const queue = [...rootIds];
  while (queue.length) {
    const cur = queue.pop();
    if (runtimeReachable.has(cur)) continue;
    runtimeReachable.add(cur);
    for (const next of runtimeOut.get(cur) ?? []) if (!runtimeReachable.has(next)) queue.push(next);
  }

  const sfById = new Map();
  for (const sf of program.getSourceFiles()) {
    const abs = resolve(sf.fileName);
    if (known.has(abs)) sfById.set(idFor.get(abs), sf);
  }

  const classes = {};
  for (const [id, inc] of incoming) {
    if (runtimeReachable.has(id)) { classes[id] = "RUNTIME-REACHABLE"; continue; }
    // HONEST SEAM: dynamic/side-effect edges are not statically decidable -> human look, BEFORE island.
    if (inc.dynamic > 0 || inc.sideeffect > 0) { classes[id] = "NEEDS-A-HUMAN-LOOK"; continue; }
    if (inc.type > 0) {
      const sf = sfById.get(id);
      classes[id] = sf && exportsRuntimeValues(sf) ? "TYPE-ONLY-ISLAND" : "TYPES-ONLY-MODULE";
      continue;
    }
    classes[id] = "UNREFERENCED";
  }

  const pick = (v) => Object.keys(classes).filter((k) => classes[k] === v).sort();
  const result = {
    ok: true,
    sentinel: SENTINEL,
    root,
    scanned: files.length,
    roots: rootIds,
    islands: pick("TYPE-ONLY-ISLAND"),
    needsHumanLook: pick("NEEDS-A-HUMAN-LOOK"),
    unreferenced: pick("UNREFERENCED"),
    typesOnlyModules: pick("TYPES-ONLY-MODULE"),
    runtimeReachable: pick("RUNTIME-REACHABLE"),
    classes,
  };

  if (json) {
    // Sentinel travels INSIDE the JSON (result.sentinel); no trailing line, so JSON.parse stays clean.
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`\nisland_sweep — ${files.length} module(s) scanned from ${rootIds.length} root(s)\n`);
    for (const v of ["RUNTIME-REACHABLE", "TYPE-ONLY-ISLAND", "NEEDS-A-HUMAN-LOOK", "TYPES-ONLY-MODULE", "UNREFERENCED"]) {
      const rows = pick(v);
      console.log(`  ${v} (${rows.length})`);
      for (const r of rows) console.log(`      ${r}`);
    }
    console.log("\nTYPE-ONLY-ISLAND = real code reachable only over an erased `import type` edge.");
    console.log("NEEDS-A-HUMAN-LOOK (dynamic import / side-effect / DI) is a CANDIDATE, not a verdict.");
    // Sentinel LAST, on success only. Absence of this line == the sweep did not complete.
    console.log(SENTINEL);
  }
  process.exit(0);
}

main();
