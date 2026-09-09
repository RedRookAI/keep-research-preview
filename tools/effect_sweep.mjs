#!/usr/bin/env node
/**
 * effect_sweep.mjs — a real `ts` AST scan for the CLOSED-WORLD EFFECT INVENTORY (Increment 4). [netguard-allow]
 *
 * The outbound dual of ingress_sweep. Every effect FAMILY (fs, net, dns, tls, dgram, subprocess, worker, module-load,
 * env, clock, random, hostinfo) has exactly ONE declared broker OWNER. This scanner reports any use of a family's raw
 * host primitives in a file that is NOT its declared owner (an UNOWNED EFFECT callsite): importing the family's node
 * builtin (static/dynamic/require), a hidden builtin loader (process.binding / getBuiltinModule), or the non-import
 * families' callsites (process.env, Date.now/new Date/performance.now/process.hrtime, Math.random). Owners are passed
 * as `--owner <family>=<repo-relative-path>`; a family with no owner is owned by NOBODY, so ANY use is unowned.
 *
 * FAIL-CLOSED. On success prints the sentinel `EFFECT-SWEEP-OK` + exit 0; any failure (bad args, unreadable/unparseable
 * file) exits non-zero WITHOUT the sentinel, and the port refuses any result lacking it. `typescript` is the sole
 * devDep; this engine lives in tools/ (build-time) so the shipped product stays zero-runtime-dependency.
 *
 * HONEST BOUNDARY. Per-file syntactic detection of the family gateways (imports + the enumerated ambient callsites).
 * Obtaining a family's authority by opaque identity (string-built module ids behind data flow) or laundering it ACROSS
 * files is general provenance analysis, deferred to Increment 15; OS-level impossibility of bypass is Increment 10.
 *
 * Usage: node tools/effect_sweep.mjs --root <dir> [--owner <family>=<relpath>]... [--json]
 */
import ts from "typescript";
import { readdirSync, statSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve, relative } from "node:path";

const SENTINEL = "EFFECT-SWEEP-OK";
const sha256hex = (s) => createHash("sha256").update(s).digest("hex");
const die = (msg) => { console.error(`[effect-sweep] ${msg}`); process.exit(2); };

// node builtin module -> effect family. Importing any of these is an effect-family gateway.
const MODULE_FAMILY = new Map(Object.entries({
  fs: "fs", "fs/promises": "fs",
  net: "net", http: "net", https: "net", http2: "net",
  dns: "dns", "dns/promises": "dns",
  tls: "tls", dgram: "dgram",
  child_process: "subprocess",
  worker_threads: "worker", cluster: "worker",
  module: "module-load",
  timers: "clock", "timers/promises": "clock",
  os: "hostinfo", "perf_hooks": "clock",
  crypto: "random",
}).flatMap(([m, fam]) => [[m, fam], [`node:${m}`, fam]]));

// Randomness / key-generation method names (Web Crypto + node:crypto) — entropy-drawing, receiver-independent by name.
const RANDOM_METHODS = new Set(["getRandomValues", "randomUUID", "randomBytes", "randomInt", "randomFill", "randomFillSync", "generateKey", "generateKeyPair", "generateKeyPairSync", "generatePrime", "generatePrimeSync"]);
// Direct `process.<prop>` host-metadata reads (value-level, like process.env). process.cwd() is handled as a call.
const HOSTINFO_PROPS = new Set(["platform", "arch", "version", "versions", "pid", "ppid", "execPath", "execArgv", "config", "features", "release", "argv0", "argv", "title", "debugPort", "mainModule", "allowedNodeEnvironmentFlags", "sourceMapsEnabled", "report", "channel", "connected"]);
const GLOBAL_OBJECTS = new Set(["globalThis", "global", "window", "self"]);
const NAVIGATOR_HOSTINFO = new Set(["userAgent", "platform", "language", "languages", "hardwareConcurrency", "deviceMemory", "appVersion", "vendor", "oscpu", "product", "onLine"]);
const isGlobalObj = (n) => { const u = unwrap(n); return ts.isIdentifier(u) && GLOBAL_OBJECTS.has(u.text); };
const NET_CTORS = new Set(["WebSocket", "EventSource", "XMLHttpRequest"]);
const WORKER_CTORS = new Set(["Worker", "SharedWorker"]);
const SCHEDULERS = new Set(["setTimeout", "setInterval", "setImmediate", "queueMicrotask", "requestAnimationFrame", "requestIdleCallback"]);

function parseArgs(argv) {
  const out = { root: null, owners: new Map(), json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--root") out.root = argv[++i];
    else if (a === "--owner") { const kv = argv[++i] ?? ""; const eq = kv.indexOf("="); if (eq < 0) die(`--owner needs family=path, got "${kv}"`); out.owners.set(kv.slice(0, eq), kv.slice(eq + 1).replace(/\\/g, "/")); }
    else if (a === "--json") out.json = true;
    else die(`unknown argument ${a}`);
  }
  return out;
}

function walkSrc(dir) {
  const SRC = /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/;
  const DECL = /\.d\.(ts|mts|cts)$/;
  let out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e); const s = statSync(p);
    if (s.isDirectory()) out = out.concat(walkSrc(p));
    else if (SRC.test(e) && !DECL.test(e)) out.push(p);
  }
  return out;
}

function unwrap(c) {
  for (;;) {
    if (ts.isParenthesizedExpression(c) || ts.isNonNullExpression(c) || ts.isAsExpression(c) || ts.isTypeAssertionExpression(c) || (ts.isSatisfiesExpression && ts.isSatisfiesExpression(c))) { c = c.expression; continue; }
    if (ts.isBinaryExpression(c) && c.operatorToken.kind === ts.SyntaxKind.CommaToken) { c = c.right; continue; }
    return c;
  }
}
function memberName(c) {
  if (ts.isPropertyAccessExpression(c)) return { name: c.name.text, obj: c.expression };
  if (ts.isElementAccessExpression(c) && ts.isStringLiteralLike(c.argumentExpression)) return { name: c.argumentExpression.text, obj: c.expression };
  return null;
}

/** The effect family a node references, or null. Returns {family, construct} findings via the collector. */
function familyFindings(node, add) {
  // static import / export...from a family module
  if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier)) {
    const fam = MODULE_FAMILY.get(node.moduleSpecifier.text);
    if (fam) add(node, fam, `import:${node.moduleSpecifier.text}`);
  }
  if (ts.isImportEqualsDeclaration(node) && node.moduleReference && ts.isExternalModuleReference(node.moduleReference) && ts.isStringLiteralLike(node.moduleReference.expression)) {
    const fam = MODULE_FAMILY.get(node.moduleReference.expression.text);
    if (fam) add(node, fam, `import:${node.moduleReference.expression.text}`);
  }
  if (ts.isCallExpression(node)) {
    const c = unwrap(node.expression);
    // dynamic import() / require() / createRequire()().require / process.binding / getBuiltinModule of a family module
    if (node.expression.kind === ts.SyntaxKind.ImportKeyword) { const a0 = node.arguments[0]; famFromArg(a0, node, add, "dynamic-import"); }
    if (ts.isIdentifier(c) && (c.text === "require")) { const a0 = node.arguments[0]; if (!a0 || !ts.isStringLiteralLike(a0)) add(node, "module-load", "computed-require"); else famFromArg(a0, node, add, "require"); }
    const acc = memberName(c);
    if (acc !== null) {
      if (acc.name === "require" || acc.name === "getBuiltinModule" || acc.name === "binding") { const a0 = node.arguments[0]; if (!a0 || !ts.isStringLiteralLike(a0)) add(node, "module-load", `computed-${acc.name}`); else famFromArg(a0, node, add, acc.name); }
    }
    // global network + clock + random ambient callsites
    if (ts.isIdentifier(c)) {
      if (c.text === "Date") add(node, "clock", "Date()");
      if (c.text === "fetch") add(node, "net", "fetch");                 // global fetch (network)
      if (SCHEDULERS.has(c.text)) add(node, "clock", c.text);            // timer/scheduler (deferred callback)
    }
    if (acc !== null) {
      if ((acc.name === "now") && ts.isIdentifier(acc.obj) && (acc.obj.text === "Date" || acc.obj.text === "performance")) add(node, "clock", `${acc.obj.text}.now`);
      if (acc.name === "hrtime" && ts.isIdentifier(acc.obj) && acc.obj.text === "process") add(node, "clock", "process.hrtime");
      if (acc.name === "nextTick" && ts.isIdentifier(acc.obj) && acc.obj.text === "process") add(node, "clock", "process.nextTick");
      if (acc.name === "random" && ts.isIdentifier(acc.obj) && acc.obj.text === "Math") add(node, "random", "Math.random");
      // Web Crypto + node crypto randomness/keygen — entropy-drawing primitives (receiver-independent by their names).
      if (RANDOM_METHODS.has(acc.name)) add(node, "random", acc.name);
      if (acc.name === "sendBeacon") add(node, "net", "sendBeacon");                          // navigator.sendBeacon
      if (acc.name === "fetch" && isGlobalObj(acc.obj)) add(node, "net", "fetch");            // globalThis/window.fetch
      if (SCHEDULERS.has(acc.name)) add(node, "clock", acc.name);                            // globalThis.setTimeout / timers.setTimeout
      if (acc.name === "cwd" && ts.isIdentifier(acc.obj) && acc.obj.text === "process") add(node, "hostinfo", "process.cwd"); // host cwd
      if ((acc.name === "kill" || acc.name === "abort" || acc.name === "exit" || acc.name === "disconnect" || acc.name === "chdir" || acc.name === "setuid" || acc.name === "setgid" || acc.name === "umask") && ts.isIdentifier(acc.obj) && acc.obj.text === "process") add(node, "subprocess", `process.${acc.name}`); // process control
      // process.hrtime.bigint() / any call on process.hrtime -> clock
      const oacc = memberName(unwrap(acc.obj));
      if (oacc !== null && oacc.name === "hrtime" && ts.isIdentifier(oacc.obj) && oacc.obj.text === "process") add(node, "clock", `process.hrtime.${acc.name}`);
      if (ts.isIdentifier(acc.obj) && acc.obj.text === "process") {
        if (acc.name === "uptime") add(node, "clock", "process.uptime");
        if (acc.name === "cpuUsage" || acc.name === "memoryUsage" || acc.name === "resourceUsage" || acc.name === "constrainedMemory" || acc.name === "availableMemory") add(node, "hostinfo", `process.${acc.name}`);
      }
    }
  }
  if (ts.isNewExpression(node) && node.expression) {
    const c = unwrap(node.expression);
    if (ts.isIdentifier(c)) {
      const n = c.text;
      if (n === "Date") add(node, "clock", "new Date");
      if (NET_CTORS.has(n)) add(node, "net", `new ${n}`);
      if (WORKER_CTORS.has(n)) add(node, "worker", `new ${n}`);
    }
    const macc = memberName(c); // qualified: new globalThis.Worker / new window.WebSocket
    if (macc !== null) {
      if (NET_CTORS.has(macc.name)) add(node, "net", `new ${macc.name}`);
      if (WORKER_CTORS.has(macc.name)) add(node, "worker", `new ${macc.name}`);
      if (macc.name === "Date") add(node, "clock", "new Date");
    }
  }
  // value-level reads: process.<host-metadata> (platform/arch/…) -> hostinfo; performance.timeOrigin -> clock.
  {
    const hacc = memberName(node);
    if (hacc !== null && ts.isIdentifier(hacc.obj)) {
      if (HOSTINFO_PROPS.has(hacc.name) && hacc.obj.text === "process") add(node, "hostinfo", `process.${hacc.name}`);
      if (hacc.name === "timeOrigin" && hacc.obj.text === "performance") add(node, "clock", "performance.timeOrigin");
      if (NAVIGATOR_HOSTINFO.has(hacc.name) && hacc.obj.text === "navigator") add(node, "hostinfo", `navigator.${hacc.name}`);
    }
  }
  // process.env access (property or element)
  const macc = memberName(node);
  if (macc !== null && macc.name === "env" && ts.isIdentifier(macc.obj) && macc.obj.text === "process") add(node, "env", "process.env");
}
function famFromArg(a0, node, add, how) {
  if (a0 && ts.isStringLiteralLike(a0)) { const fam = MODULE_FAMILY.get(a0.text); if (fam) add(node, fam, `${how}:${a0.text}`); }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.root) die("missing --root");
  const root = resolve(args.root);
  const owners = args.owners; // family -> owner relpath
  let files;
  try { files = walkSrc(root); } catch (e) { die(`cannot walk root: ${e.message}`); }

  const findings = [];
  const fileDigests = []; // {file, digest} — commits to the EXACT bytes scanned (kills scan-then-swap once bound + verified)
  let scanned = 0;
  for (const file of files) {
    const rel = relative(root, file).replace(/\\/g, "/");
    scanned++;
    let buf, text;
    try { buf = readFileSync(file); } catch (e) { die(`cannot read ${rel}: ${e.message}`); } // raw BYTES (not utf8-decoded)
    fileDigests.push({ file: rel, digest: sha256hex(buf) });                                   // hash EXACT bytes — no U+FFFD collision
    // Decode for parsing, but REJECT invalid UTF-8 so "source text" and "hashed bytes" cannot diverge (fail-closed).
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(buf); } catch { die(`invalid UTF-8 in ${rel} (fail-closed)`); }
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    if (sf.parseDiagnostics && sf.parseDiagnostics.length > 0) die(`parse error in ${rel} (fail-closed)`);
    const add = (node, family, construct) => {
      if (owners.get(family) === rel) return; // this file IS the declared owner of the family — allowed
      const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
      findings.push({ file: rel, line: line + 1, family, construct });
    };
    const visit = (node) => { familyFindings(node, add); ts.forEachChild(node, visit); };
    visit(sf);
  }

  findings.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  fileDigests.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  // graphDigest commits to the exact (relpath, content-hash) set scanned — a canonical, order-independent artifact digest.
  const ownersList = [...owners.entries()].map(([f, o]) => ({ family: f, owner: o })).sort((a, b) => (a.family < b.family ? -1 : 1));
  const graphDigest = sha256hex(JSON.stringify(fileDigests)); // canonical INJECTIVE encoding (JSON escapes file paths)
  const result = { ok: true, sentinel: SENTINEL, scanned, owners: ownersList, findings, graphDigest };
  if (args.json) writeFileSync(1, JSON.stringify(result));
  else { process.stdout.write(`${SENTINEL} scanned=${scanned} findings=${findings.length}\n`); for (const f of findings) process.stdout.write(`  ${f.file}:${f.line} ${f.family} ${f.construct}\n`); }
  process.exit(0);
}

main();
