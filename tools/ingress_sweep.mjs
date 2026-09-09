#!/usr/bin/env node
/**
 * ingress_sweep.mjs — a real `ts` AST scan for the CLOSED-WORLD INGRESS INVENTORY (Increment 3, static closure). [netguard-allow]
 *
 * WHY THIS EXISTS. The sealed ingress registry (src/ingress/ingress_registry.ts) makes "every dispatch goes through a
 * signed, policy-addressable, sealed set" true — but ONLY if no listener/callback/code-generation site exists OUTSIDE
 * the registry's adapters. Without that static guarantee the registry is BYPASSABLE (open a raw `net.createServer` and
 * you have an unmediated entrypoint) — the exact "inert control" failure. This engine is the STATIC-CLOSURE proof: it
 * parses every source file (a real TypeScript AST, not a regex) and reports any forbidden ambient-authority construct
 * in a NON-allowlisted module. Only audited adapter modules (the `--allow` list) may hold that authority.
 *
 * Forbidden constructs (each is a way to obtain an un-declared entrypoint or to generate code): eval / indirect eval,
 * `new Function`/`AsyncFunction`/`GeneratorFunction`, `vm` code generation, dynamic `import()`, computed `require` /
 * `createRequire`, raw server creation (`createServer`/`createSecureServer`/`listen`), `setTimeout`/`setInterval`/
 * `setImmediate`, `process` signal/lifecycle handlers (`process.on/once/addListener/prependListener`),
 * `addEventListener`, and `new Worker`. Ambiguity is treated as a finding, never silently allowed.
 *
 * FAIL-CLOSED IS THE POINT. The cardinal defect is a crashed scan read as "0 findings, all clear". So on success this
 * prints the sentinel `INGRESS-SWEEP-OK` and exits 0; any failure exits non-zero WITHOUT the sentinel, and the port
 * (src/ingress/ingress_scan_port.ts) refuses any result lacking it. `typescript` is already the sole devDep; this
 * engine lives in tools/ (build-time) so the shipped product stays zero runtime-dependency.
 *
 * HONEST BOUNDARY (a trusted assumption, named not hidden). This is a PER-FILE syntactic detector. It catches every
 * STRAIGHTFORWARD use of an ambient-authority capability — the real threat this increment addresses: a developer (or
 * a prompt-injected agent) adding a raw listener / timer / eval / dynamic import — AND a wide net of same-file
 * obfuscation (aliasing, member-access, computed-global, reflected, conditional, destructuring, tagged-template,
 * intra-file taint). Process signal/lifecycle handlers are additionally caught by their EVENT NAME (`.on("SIG*"|
 * uncaughtException|…)`), so even an inter-procedural same-file helper `f(p){ p.on("SIGTERM",cb) }; f(process)` is
 * caught regardless of how the receiver was obtained.
 *
 * It CANNOT defeat an adversary who obfuscates a capability's IDENTITY beyond source syntax: dynamically-built names
 * via runtime string ops behind opaque data flow, Proxy/getter indirection, INTER-PROCEDURAL data-flow of a capability
 * value through parameters/returns with a non-literal event, or laundering ACROSS files. That is general taint/
 * data-flow analysis — closed by later increments: INTER-FILE + inter-procedural provenance + assured mutation
 * (Increment 15) and the measured artifact boundary binding the shipped graph to the scanned graph (Increment 5) — and
 * such obfuscation is itself a glaring review signal. The allowlist is the audited-adapter TCB (trusted build config).
 *
 * Usage: node tools/ingress_sweep.mjs --root <dir> [--allow <relpath>]... [--json]
 */
import ts from "typescript";
import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, resolve, relative } from "node:path";

const SENTINEL = "INGRESS-SWEEP-OK";

function die(msg) {
  console.error(`[ingress-sweep] ${msg}`);
  process.exit(2); // fail CLOSED: no sentinel
}

function parseArgs(argv) {
  const out = { root: null, allow: [], json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--root") out.root = argv[++i];
    else if (a === "--allow") out.allow.push(argv[++i]);
    else if (a === "--json") out.json = true;
    else die(`unknown argument ${a}`);
  }
  return out;
}

// Every build-eligible TypeScript/JS source extension (a forbidden construct in x.mts/x.cts/x.tsx must not evade the
// scan just because walkTs only looked at .ts). Declaration files (.d.*) carry no runtime code and are skipped.
const SOURCE_RE = /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/;
const DECL_RE = /\.d\.(ts|mts|cts)$/;
function walkTs(dir) {
  let out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    const s = statSync(p);
    if (s.isDirectory()) out = out.concat(walkTs(p));
    else if (SOURCE_RE.test(e) && !DECL_RE.test(e)) out.push(p);
  }
  return out;
}

// Node builtins that grant ambient ingress/codegen authority. Importing ANY of these outside an approved adapter is a
// finding on its own — which catches every import-alias bypass (`import {createServer as s}`, `import * as net`, …).
const FORBIDDEN_MODULES = new Set([
  "net", "http", "https", "http2", "tls", "dgram", "vm", "worker_threads", "cluster",
  "child_process", "inspector", "repl", "module", "timers", "timers/promises", "events",
].flatMap((m) => [m, `node:${m}`]));
// Globals whose mere REFERENCE-as-a-value is a finding (catches same-file aliasing: `const e = eval; e(x)`).
const FORBIDDEN_REFS = new Set(["eval", "Function", "AsyncFunction", "GeneratorFunction", "setTimeout", "setInterval", "setImmediate", "queueMicrotask", "requestAnimationFrame", "requestIdleCallback", "addEventListener", "require", "createRequire", "Worker"]);
// Callback-SCHEDULING globals (run code outside the mediated flow, like the covered timers).
const SCHEDULERS = new Set(["setTimeout", "setInterval", "setImmediate", "queueMicrotask", "requestAnimationFrame", "requestIdleCallback"]);
// Member names that are UNAMBIGUOUSLY an ambient-authority capability — reading `obj.<name>` AT ALL (not only calling
// it) is a finding, so laundering the value through an object literal / ternary / arg / .call chain is caught. These
// names never occur as ordinary property reads in this codebase (unlike `constructor`/`listen`/`on`, which stay call-only).
const UNAMBIGUOUS_MEMBER_NAMES = new Set([
  "eval", "Function", "AsyncFunction", "GeneratorFunction", "createRequire", "addEventListener",
  "setTimeout", "setInterval", "setImmediate", "queueMicrotask", "requestAnimationFrame", "requestIdleCallback",
  "createServer", "createSecureServer", "listen", "runInNewContext", "runInThisContext", "runInContext",
  "compileFunction", "Worker", "Script", "SourceTextModule",
  "setUncaughtExceptionCaptureCallback", "getBuiltinModule", "nextTick", // process/module-specific, never a plain read
]);
// Global capability containers — a COMPUTED read `globalThis[expr]` can name any forbidden capability, so it is a
// finding on its own (catches `globalThis["ev"+"al"]`, `globalThis[key]`).
const GLOBAL_OBJECTS = new Set(["globalThis", "global", "window", "self", "globalObject"]);
const LISTENER_METHODS = new Set(["createServer", "createSecureServer", "listen", "connect"]);
const VM_METHODS = new Set(["runInNewContext", "runInThisContext", "runInContext", "compileFunction"]);
const PROCESS_HANDLERS = new Set(["on", "once", "addListener", "prependListener", "prependOnceListener"]);
// Process-specific lifecycle event names (SIG* signals are matched by prefix). A `.on(<one of these>, cb)` registers a
// process handler NO MATTER how the receiver was obtained — so a helper `function f(p){ p.on("SIGTERM",cb) }; f(process)`
// (inter-procedural, but same-file and un-obfuscated) is caught by the EVENT NAME, side-stepping receiver tracking.
// The COMPLETE authoritative set of Node `process` events (Node docs) + all SIG* signals (matched by prefix). A
// `.on(<one of these>, cb)` registers a process lifecycle/signal handler regardless of how the receiver was obtained,
// so an inter-procedural same-file helper is caught by the EVENT NAME. Their few non-process emitters (ChildProcess/
// Worker/cluster/MessagePort) all require a forbidden module import that is itself already flagged.
const PROCESS_EVENT_NAMES = new Set([
  "beforeExit", "disconnect", "exit", "message", "multipleResolves", "rejectionHandled",
  "uncaughtException", "uncaughtExceptionMonitor", "unhandledRejection", "warning", "worker",
]);
const isProcessEventName = (s) => typeof s === "string" && (s.startsWith("SIG") || PROCESS_EVENT_NAMES.has(s));

// Per-file sets reset at the start of each file's scan: identifiers denoting a global capability container
// (globalThis/… + aliases), and identifiers denoting `process` (+ aliases). Read by isForbiddenSource et al.
let currentGlobals = new Set();
let currentProcAliases = new Set(["process"]);
let currentStreamAliases = new Set();

const STREAM_NAMES = new Set(["stdin", "stdout", "stderr"]);

function unwrapCallee(c) {
  // Unwrap every value-transparent wrapper so `(server.listen as any)()`, `(0, eval)(x)`, `(<F>fn)()`, `fn!()` cannot
  // hide the real callee. Loops to a fixpoint so nested wrappers also unwrap.
  for (;;) {
    if (ts.isParenthesizedExpression(c) || ts.isNonNullExpression(c) || ts.isAsExpression(c) || ts.isTypeAssertionExpression(c) || (ts.isSatisfiesExpression && ts.isSatisfiesExpression(c))) { c = c.expression; continue; }
    if (ts.isBinaryExpression(c) && c.operatorToken.kind === ts.SyntaxKind.CommaToken) { c = c.right; continue; }
    return c;
  }
}

/** True iff `obj` denotes a process standard stream: a same-file stream alias, or `<process>.stdin|stdout|stderr`. */
function isStreamReceiver(obj) {
  const o = unwrapCallee(obj);
  if (ts.isIdentifier(o) && currentStreamAliases.has(o.text)) return true;
  const acc = memberName(o);
  return acc !== null && STREAM_NAMES.has(acc.name) && isProcessReceiver(acc.obj);
}

/** True iff `obj` denotes the `process` object: the bare identifier / a same-file alias, or `<global>.process`. */
function isProcessReceiver(obj) {
  const o = unwrapCallee(obj);
  if (ts.isIdentifier(o) && currentProcAliases.has(o.text)) return true;
  const acc = memberName(o);
  if (acc === null || acc.name !== "process") return false;
  const gobj = unwrapCallee(acc.obj);
  return ts.isIdentifier(gobj) && currentGlobals.has(gobj.text);
}

/** Classify an already-unwrapped CALLEE expression (identifier or member form) as a forbidden construct, or null. */
function classifyCallee(c) {
  if (ts.isIdentifier(c)) {
    const n = c.text;
    if (n === "eval") return "eval";
    if (n === "Function" || n === "AsyncFunction" || n === "GeneratorFunction") return "Function-call";
    if (n === "addEventListener") return "addEventListener";
    if (SCHEDULERS.has(n)) return `timer:${n}`;
    if (n === "createRequire") return "createRequire";
    if (LISTENER_METHODS.has(n)) return `listener:${n}`;
  }
  const acc = memberName(c);
  if (acc !== null) {
    const { name, obj } = acc;
    if (name === "eval") return "eval";
    if (name === "Function" || name === "AsyncFunction" || name === "GeneratorFunction") return "Function-call";
    if (name === "constructor") return "constructor-codegen";
    if (LISTENER_METHODS.has(name)) return `listener:${name}`;
    if (name === "addEventListener") return "addEventListener";
    if (SCHEDULERS.has(name)) return `timer:${name}`;
    if (name === "createRequire") return "createRequire";
    if (name === "nextTick") return "timer:nextTick";
    if (name === "getBuiltinModule" || name === "setUncaughtExceptionCaptureCallback") return `process-loader:${name}`;
    if (VM_METHODS.has(name)) return `vm-codegen:${name}`;
    if (PROCESS_HANDLERS.has(name) && isProcessReceiver(obj)) return `process-handler:${name}`;
  }
  return null;
}

/** Classify a call/new/tagged-template node as a forbidden construct, or return null. Pure AST inspection. */
function classify(node) {
  // dynamic import(): a CallExpression whose callee is the `import` keyword
  if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) return "dynamic-import";
  // a tagged template `tag`...`` INVOKES its tag — same forbidden-callee analysis, no argument-based cases.
  if (ts.isTaggedTemplateExpression(node)) return classifyCallee(unwrapCallee(node.tag));
  if (ts.isCallExpression(node)) {
    const c = unwrapCallee(node.expression);
    const byCallee = classifyCallee(c);
    if (byCallee !== null) return byCallee;
    // A CONDITIONAL callee `(cond ? forbidden : other)(x)` is forbidden if EITHER branch is (ambiguity = finding).
    if (ts.isConditionalExpression(c)) {
      const t = classifyCallee(unwrapCallee(c.whenTrue)); if (t !== null) return `conditional-callee:${t}`;
      const f = classifyCallee(unwrapCallee(c.whenFalse)); if (f !== null) return `conditional-callee:${f}`;
    }
    const acc = memberName(c);
    if (acc !== null) {
      // Reflected invocation of a forbidden capability: `globalThis.eval.call(null, src)` / `.apply` / `.bind`.
      if ((acc.name === "call" || acc.name === "apply" || acc.name === "bind") && isForbiddenSource(acc.obj)) return "reflected-invoke";
      // `Reflect.apply(fn, …)` / `Reflect.construct(fn, …)` where fn is a forbidden capability.
      if ((acc.name === "apply" || acc.name === "construct") && ts.isIdentifier(acc.obj) && acc.obj.text === "Reflect") {
        const a0 = node.arguments[0]; if (a0 && isForbiddenSource(a0)) return "reflected-apply";
      }
    }
    if (ts.isIdentifier(c) && c.text === "require") { const a0 = node.arguments[0]; if (a0 === undefined || !ts.isStringLiteralLike(a0)) return "computed-require"; }
    // module.require(x) / globalThis.require(x) — a module-loading callee that is not a bare `require`.
    if (acc !== null && acc.name === "require") { const a0 = node.arguments[0]; if (a0 === undefined || !ts.isStringLiteralLike(a0)) return "computed-require"; if (FORBIDDEN_MODULES.has(a0.text)) return `forbidden-module-import:${a0.text}`; }
    // Ambiguity = finding: a NON-literal computed member call (obj[expr](...)) can hide any protected capability.
    if (ts.isElementAccessExpression(c) && !ts.isStringLiteralLike(c.argumentExpression)) return "computed-member-call";
  }
  if (ts.isNewExpression(node) && node.expression) {
    const c = unwrapCallee(node.expression);
    if (ts.isIdentifier(c)) {
      const n = c.text;
      if (n === "Function" || n === "AsyncFunction" || n === "GeneratorFunction") return "new-Function";
      if (n === "Worker") return "new-Worker";
    }
    const acc = memberName(c);
    if (acc !== null) {
      if (acc.name === "Function" || acc.name === "AsyncFunction" || acc.name === "GeneratorFunction") return "new-Function";
      if (acc.name === "Script" || acc.name === "SourceTextModule") return `vm-codegen:new-${acc.name}`;
      if (acc.name === "Worker") return "new-Worker";
    }
    // conditional constructor `new (cond ? Worker : Other)(url)` — forbidden if a branch is
    if (ts.isConditionalExpression(c)) {
      for (const b of [c.whenTrue, c.whenFalse]) {
        const u = unwrapCallee(b);
        if (ts.isIdentifier(u) && (u.text === "Function" || u.text === "AsyncFunction" || u.text === "GeneratorFunction" || u.text === "Worker")) return "conditional-new";
        const a = memberName(u);
        if (a && (a.name === "Function" || a.name === "Worker" || a.name === "Script" || a.name === "SourceTextModule")) return "conditional-new";
      }
    }
    // `new globalThis["Fun"+"ction"](x)` — computed constructor
    if (ts.isElementAccessExpression(c) && !ts.isStringLiteralLike(c.argumentExpression)) return "computed-member-new";
  }
  return null;
}

/** For a property access `obj.name` or a string-literal element access `obj["name"]`, return {name, obj}; else null. */
function memberName(c) {
  if (ts.isPropertyAccessExpression(c)) return { name: c.name.text, obj: c.expression };
  if (ts.isElementAccessExpression(c) && ts.isStringLiteralLike(c.argumentExpression)) return { name: c.argumentExpression.text, obj: c.expression };
  return null;
}

/** The forbidden node module a static `import`/`export ... from`/`require("literal")` targets, or null. */
function forbiddenImport(node) {
  if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier)) {
    if (FORBIDDEN_MODULES.has(node.moduleSpecifier.text)) return `forbidden-module-import:${node.moduleSpecifier.text}`;
  }
  if (ts.isImportEqualsDeclaration(node) && node.moduleReference && ts.isExternalModuleReference(node.moduleReference) && node.moduleReference.expression && ts.isStringLiteralLike(node.moduleReference.expression)) {
    if (FORBIDDEN_MODULES.has(node.moduleReference.expression.text)) return `forbidden-module-import:${node.moduleReference.expression.text}`;
  }
  if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "require") {
    const a0 = node.arguments[0];
    if (a0 && ts.isStringLiteralLike(a0) && FORBIDDEN_MODULES.has(a0.text)) return `forbidden-module-import:${a0.text}`;
  }
  return null;
}

// Member names whose EXTRACTION-as-a-value taints a local (so `const e = x.eval; e(src)` is caught). Excludes the
// generic emitter handlers (on/once) — those are only flagged as `process.on(...)` calls, not as taint sources.
const FORBIDDEN_MEMBER_NAMES = new Set([
  "eval", "Function", "AsyncFunction", "GeneratorFunction", "constructor", "createRequire",
  "setTimeout", "setInterval", "setImmediate", "addEventListener",
  ...LISTENER_METHODS, ...VM_METHODS, "Script", "SourceTextModule", "Worker",
]);

/** True iff `node` is a COMPUTED read of a global capability container: `globalThis[expr]` (non-literal key). The
 * receiver is checked against `globalNames` (globalThis/global/… plus any same-file aliases of them). */
function isComputedGlobalAccess(e, globalNames = currentGlobals) {
  if (!ts.isElementAccessExpression(e) || ts.isStringLiteralLike(e.argumentExpression)) return false;
  const obj = unwrapCallee(e.expression);
  return ts.isIdentifier(obj) && globalNames.has(obj.text);
}

/** True iff the expression EXTRACTS a forbidden capability value (global ref, forbidden member, computed global, or a
 * conditional whose branch is forbidden). `globalNames` includes globalThis + same-file aliases. */
function isForbiddenSource(expr, globalNames = currentGlobals) {
  const e = unwrapCallee(expr);
  if (ts.isIdentifier(e) && FORBIDDEN_REFS.has(e.text)) return true;
  if (isComputedGlobalAccess(e, globalNames)) return true;
  if (ts.isConditionalExpression(e)) return isForbiddenSource(e.whenTrue, globalNames) || isForbiddenSource(e.whenFalse, globalNames);
  const acc = memberName(e);
  if (acc !== null && FORBIDDEN_MEMBER_NAMES.has(acc.name)) return true;
  // a listener method extracted from `process` OR a process standard stream: process.on / process.stdin.on / …
  if (acc !== null && PROCESS_HANDLERS.has(acc.name) && (isProcessReceiver(acc.obj) || isStreamReceiver(acc.obj))) return true;
  return false;
}

/** A computed read of a global capability container, reported at value level (catches `globalThis["ev"+"al"]`). */
function computedGlobalAccess(node) {
  return isComputedGlobalAccess(node, currentGlobals) ? "computed-global-access" : null;
}

/** An object-literal / binding key that names a forbidden capability — catches destructuring ASSIGNMENT
 * `({ eval: e } = globalThis)` and object-literal key laundering `{ eval: x }`. */
function objectKeyForbidden(node) {
  let key = null;
  if (ts.isPropertyAssignment(node) || ts.isShorthandPropertyAssignment(node)) key = node.name;
  else return null;
  let name = null;
  if (key && ts.isIdentifier(key)) name = key.text;
  else if (key && ts.isStringLiteral(key)) name = key.text;
  if (name === null) return null;
  if (UNAMBIGUOUS_MEMBER_NAMES.has(name)) return `object-key-forbidden:${name}`;
  // process signal-handler in a destructuring ASSIGNMENT from `process`: ({ on } = process)
  if (PROCESS_HANDLERS.has(name)) {
    const obj = node.parent; // ObjectLiteralExpression
    if (obj && ts.isObjectLiteralExpression(obj) && obj.parent && ts.isBinaryExpression(obj.parent) && obj.parent.operatorToken.kind === ts.SyntaxKind.EqualsToken && obj.parent.left === obj) {
      if (isProcessReceiver(obj.parent.right)) return `destructured-process-handler:${name}`;
    }
  }
  return null;
}

/** Collect the set of local names TAINTED by an assignment from a forbidden source (fixpoint over `x = y` chains). */
function collectTainted(sf) {
  const bindings = []; // { name, init }
  const gather = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) bindings.push({ name: node.name.text, init: node.initializer });
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) bindings.push({ name: node.left.text, init: node.right });
    ts.forEachChild(node, gather);
  };
  gather(sf);
  const tainted = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const b of bindings) {
      if (tainted.has(b.name)) continue;
      const src = unwrapCallee(b.init);
      if (isForbiddenSource(b.init) || (ts.isIdentifier(src) && tainted.has(src.text))) { tainted.add(b.name); changed = true; }
    }
  }
  return tainted;
}

/** A forbidden member ACCESS reported at VALUE level (obj.eval, globalThis.createServer, …) — catches laundering the
 * capability through an object literal / ternary / argument / .call chain without ever binding it to a local. */
function forbiddenMemberAccess(node) {
  if (!ts.isPropertyAccessExpression(node) && !(ts.isElementAccessExpression(node) && node.argumentExpression && ts.isStringLiteralLike(node.argumentExpression))) return null;
  const acc = memberName(node);
  return acc !== null && UNAMBIGUOUS_MEMBER_NAMES.has(acc.name) ? `forbidden-member:${acc.name}` : null;
}

/** A destructuring `const { eval: e } = globalThis` / `const { on } = process` extracts a forbidden capability. */
function destructuredForbidden(node) {
  if (!ts.isBindingElement(node)) return null;
  const key = node.propertyName ?? node.name; // `{ eval: e }` -> propertyName "eval"; `{ eval }` -> name "eval"
  let name = null;
  if (key && ts.isIdentifier(key)) name = key.text;
  else if (key && ts.isStringLiteral(key)) name = key.text;
  if (name === null) return null;
  if (UNAMBIGUOUS_MEMBER_NAMES.has(name) || FORBIDDEN_MEMBER_NAMES.has(name)) return `destructured-forbidden:${name}`;
  // a process signal-handler destructured FROM `process`: const { on } = process
  if (PROCESS_HANDLERS.has(name)) {
    const pat = node.parent; // ObjectBindingPattern
    if (pat && ts.isObjectBindingPattern(pat) && pat.parent && ts.isVariableDeclaration(pat.parent) && pat.parent.initializer) {
      if (isProcessReceiver(pat.parent.initializer)) return `destructured-process-handler:${name}`;
    }
  }
  return null;
}

/** An assignment to an `on*` event-handler property (window.onmessage = cb / worker.onerror = cb) — a listener
 * registration that does not go through addEventListener/.on. */
function eventHandlerProperty(node) {
  if (!ts.isBinaryExpression(node) || node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return null;
  const lhs = node.left;
  let name = null;
  if (ts.isPropertyAccessExpression(lhs)) name = lhs.name.text;
  else if (ts.isElementAccessExpression(lhs) && ts.isStringLiteralLike(lhs.argumentExpression)) name = lhs.argumentExpression.text;
  return name !== null && /^on[a-z]/.test(name) ? `event-handler-property:${name}` : null;
}

/** Collect locals bound to bare `process` (fixpoint over `p = process`, `q = p`), so `p.on(...)` is caught. */
function collectProcessAliases(sf) {
  const bindings = [];
  const gather = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) bindings.push({ name: node.name.text, init: node.initializer });
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) bindings.push({ name: node.left.text, init: node.right });
    ts.forEachChild(node, gather);
  };
  gather(sf);
  const aliases = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const b of bindings) {
      if (aliases.has(b.name)) continue;
      const src = unwrapCallee(b.init);
      const macc = memberName(src);
      if ((ts.isIdentifier(src) && (src.text === "process" || aliases.has(src.text))) ||
          (macc !== null && macc.name === "process" && ts.isIdentifier(macc.obj) && currentGlobals.has(macc.obj.text))) { aliases.add(b.name); changed = true; }
    }
  }
  return aliases;
}

/** Collect locals bound to a global capability container (const gt = globalThis; g2 = gt), so gt[expr] is caught. */
function collectGlobalAliases(sf) {
  const bindings = [];
  const gather = (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) bindings.push({ name: node.name.text, init: node.initializer });
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) bindings.push({ name: node.left.text, init: node.right });
    ts.forEachChild(node, gather);
  };
  gather(sf);
  const aliases = new Set(GLOBAL_OBJECTS);
  let changed = true;
  while (changed) {
    changed = false;
    for (const b of bindings) {
      if (aliases.has(b.name)) continue;
      const src = unwrapCallee(b.init);
      if (ts.isIdentifier(src) && aliases.has(src.text)) { aliases.add(b.name); changed = true; }
    }
  }
  return aliases;
}

/** Collect locals that alias a process standard stream: `const s = process.stdin`, `const { stdin } = process`, chains. */
function collectStreamAliases(sf) {
  const STREAMS = STREAM_NAMES;
  const aliases = new Set();
  const bindings = [];   // { name, init }
  const destructs = [];  // { name, from, key }
  const gather = (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      if (ts.isIdentifier(node.name)) bindings.push({ name: node.name.text, init: node.initializer });
      else if (ts.isObjectBindingPattern(node.name)) for (const el of node.name.elements) {
        if (ts.isBindingElement(el) && ts.isIdentifier(el.name)) {
          const key = el.propertyName ?? el.name;
          const kn = ts.isIdentifier(key) ? key.text : (ts.isStringLiteral(key) ? key.text : null);
          if (kn) destructs.push({ name: el.name.text, from: node.initializer, key: kn });
        }
      }
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      if (ts.isIdentifier(node.left)) bindings.push({ name: node.left.text, init: node.right });
      // assignment destructuring: ({ stdin: x, stdout } = process)
      else if (ts.isObjectLiteralExpression(node.left)) for (const prop of node.left.properties) {
        if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name) && ts.isIdentifier(prop.initializer)) destructs.push({ name: prop.initializer.text, from: node.right, key: prop.name.text });
        else if (ts.isShorthandPropertyAssignment(prop)) destructs.push({ name: prop.name.text, from: node.right, key: prop.name.text });
      }
    }
    ts.forEachChild(node, gather);
  };
  gather(sf);
  const isStreamSource = (init) => { const m = memberName(unwrapCallee(init)); return m !== null && STREAMS.has(m.name) && isProcessReceiver(m.obj); };
  let changed = true;
  while (changed) {
    changed = false;
    for (const b of bindings) { if (aliases.has(b.name)) continue; const src = unwrapCallee(b.init); if (isStreamSource(b.init) || (ts.isIdentifier(src) && aliases.has(src.text))) { aliases.add(b.name); changed = true; } }
    for (const d of destructs) { if (aliases.has(d.name)) continue; if (STREAMS.has(d.key) && isProcessReceiver(d.from)) { aliases.add(d.name); changed = true; } }
  }
  return aliases;
}

/** True iff `node` is a bare reference (value position) to a forbidden global — the same-file aliasing bypass. */
function forbiddenRef(node) {
  if (!ts.isIdentifier(node) || !FORBIDDEN_REFS.has(node.text)) return null;
  const p = node.parent;
  // exclude: property NAME (obj.eval), a declaration/binding name, an import/export specifier name, an object property key,
  // a labeled/parameter name — i.e. only flag genuine VALUE references to the global.
  if (p && ts.isPropertyAccessExpression(p) && p.name === node) return null;
  if (p && (ts.isVariableDeclaration(p) || ts.isFunctionDeclaration(p) || ts.isParameter(p) || ts.isBindingElement(p) || ts.isPropertyAssignment(p) || ts.isPropertySignature(p) || ts.isMethodDeclaration(p)) && p.name === node) return null;
  if (p && (ts.isImportSpecifier(p) || ts.isExportSpecifier(p)) ) return null;
  if (p && ts.isQualifiedName(p)) return null; // type position
  return `forbidden-ref:${node.text}`;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.root) die("missing --root");
  const root = resolve(args.root);
  const allow = new Set(args.allow.map((a) => a.replace(/\\/g, "/")));
  let files;
  try { files = walkTs(root); } catch (e) { die(`cannot walk root: ${e.message}`); }

  const findings = [];
  let scanned = 0;
  for (const file of files) {
    const rel = relative(root, file).replace(/\\/g, "/");
    if (allow.has(rel)) continue; // approved adapter module — sole holder of ambient authority
    scanned++;
    let text;
    try { text = readFileSync(file, "utf8"); } catch (e) { die(`cannot read ${rel}: ${e.message}`); }
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);
    // FAIL CLOSED on a parse error: a partially-parsed file must never certify "0 findings" by silence.
    if (sf.parseDiagnostics && sf.parseDiagnostics.length > 0) die(`parse error in ${rel} (fail-closed): the scan cannot be trusted on unparseable input`);
    currentGlobals = collectGlobalAliases(sf); // globalThis + same-file aliases (must precede taint/classify use)
    const procAliases = collectProcessAliases(sf); // locals bound to bare `process` (const p = process; p.on(…))
    currentProcAliases = new Set(["process", ...procAliases]); // must precede collectTainted (isForbiddenSource reads it)
    currentStreamAliases = collectStreamAliases(sf); // locals aliasing process.stdin/stdout/stderr (before taint use)
    const streamAliases = currentStreamAliases;
    const tainted = collectTainted(sf); // locals aliased from a forbidden source (const e = globalThis.eval; …)
    const add = (node, construct) => {
      if (construct === null) return;
      const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
      findings.push({ file: rel, line: line + 1, construct });
    };
    const isTaintedId = (e) => { const u = unwrapCallee(e); return ts.isIdentifier(u) && tainted.has(u.text); };
    const taintedCall = (node) => {
      let callee = null;
      if (ts.isTaggedTemplateExpression(node)) callee = node.tag;
      else if ((ts.isCallExpression(node) || ts.isNewExpression(node)) && node.expression) callee = node.expression;
      if (callee === null) return null;
      const c = unwrapCallee(callee);
      if (ts.isIdentifier(c) && tainted.has(c.text)) return `tainted-alias-call:${c.text}`;
      const acc = memberName(c);
      if (acc !== null) {
        // <tainted>.call/apply/bind(...)
        if ((acc.name === "call" || acc.name === "apply" || acc.name === "bind") && isTaintedId(acc.obj)) return "tainted-reflected-invoke";
        // Reflect.apply/construct(<tainted>, ...)
        if ((acc.name === "apply" || acc.name === "construct") && ts.isIdentifier(acc.obj) && acc.obj.text === "Reflect" && ts.isCallExpression(node) && node.arguments[0] && isTaintedId(node.arguments[0])) return "reflected-apply";
      }
      return null;
    };
    const processHandlerOnAlias = (node) => {
      if (!ts.isCallExpression(node) || !node.expression) return null;
      const acc = memberName(unwrapCallee(node.expression));
      if (acc === null || !PROCESS_HANDLERS.has(acc.name)) return null;
      // (a) receiver is a same-file process alias
      if (ts.isIdentifier(acc.obj) && procAliases.has(acc.obj.text)) return `process-handler-alias:${acc.name}`;
      // (a2) a listener on a process standard stream: process.stdin/stdout/stderr.on(...), incl. same-file stream aliases
      const rcv = unwrapCallee(acc.obj);
      if (ts.isIdentifier(rcv) && streamAliases.has(rcv.text)) return `process-stream-listener:${acc.name}`;
      const rm = memberName(rcv);
      if (rm !== null && (rm.name === "stdin" || rm.name === "stdout" || rm.name === "stderr") && isProcessReceiver(rm.obj)) return `process-stream-listener:${acc.name}`;
      // (b) EVENT-NAME based: `.on("SIG*"|lifecycle, …)` is a process handler regardless of receiver (inter-procedural-proof)
      const a0 = node.arguments[0];
      if (a0 && ts.isStringLiteralLike(a0) && isProcessEventName(a0.text)) return `process-signal-handler:${a0.text}`;
      return null;
    };
    // free-function form `once(process, "SIGTERM")` / `on(emitter, "SIG*")` (node:events) — the EVENT is arg1.
    const eventsFreeFn = (node) => {
      if (!ts.isCallExpression(node)) return null;
      const c = unwrapCallee(node.expression);
      if (!ts.isIdentifier(c) || (c.text !== "once" && c.text !== "on")) return null;
      const a1 = node.arguments[1];
      return a1 && ts.isStringLiteralLike(a1) && isProcessEventName(a1.text) ? `process-signal-handler:${a1.text}` : null;
    };
    const visit = (node) => {
      add(node, classify(node));              // call/new/tagged-template forbidden constructs
      add(node, forbiddenImport(node));       // importing an ambient-authority module (catches import aliases)
      add(node, forbiddenRef(node));          // bare reference to a forbidden global (catches same-file aliasing)
      add(node, forbiddenMemberAccess(node)); // reading a forbidden capability member at value level (catches laundering)
      add(node, computedGlobalAccess(node));  // globalThis["ev"+"al"] / globalThis[key]
      add(node, destructuredForbidden(node)); // `const { eval: e } = globalThis` (binding pattern)
      add(node, objectKeyForbidden(node));    // `({ eval: e } = globalThis)` / `{ eval: x }` (object-literal key)
      add(node, taintedCall(node));           // call/new through a local aliased from a forbidden source
      add(node, processHandlerOnAlias(node)); // `const p = process; p.on(...)` + event-name based
      add(node, eventsFreeFn(node));          // `once(process, "SIGTERM")` free-function form (node:events)
      add(node, eventHandlerProperty(node));  // window.onmessage = cb / worker.onerror = cb
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }

  findings.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line));
  const result = { ok: true, sentinel: SENTINEL, scanned, allow: [...allow].sort(), findings };
  if (args.json) process.stdout.write(JSON.stringify(result));
  else {
    process.stdout.write(`${SENTINEL} scanned=${scanned} findings=${findings.length}\n`);
    for (const f of findings) process.stdout.write(`  ${f.file}:${f.line} ${f.construct}\n`);
  }
  process.exit(0);
}

main();
