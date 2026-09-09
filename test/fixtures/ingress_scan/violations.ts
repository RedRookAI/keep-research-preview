// Fixture: every forbidden ambient-authority construct + the trivial per-file BYPASSES a naive scanner misses, in a
// NON-allowlisted module. The scanner must flag each. Never imported/run — only PARSED. Must typecheck.
import { createServer } from "node:http";        // forbidden-module-import (+ alias bypass below)
import { createServer as mkServer } from "node:https";
import { Worker } from "node:worker_threads";
import * as vm from "node:vm";
import { once } from "node:events";

declare const addEventListener: (t: string, cb: () => void) => void;
declare const require: (s: unknown) => unknown;

export function violations(): void {
  eval("1 + 1");
  const f = new Function("return 1");
  const g = Function("return 2");            // Function-call (no `new`)
  const spec = "node:fs";
  void import(spec);                          // dynamic import
  createServer(() => {}).listen(0);           // listener by imported name + .listen
  mkServer(() => {});                         // listener via import alias
  setInterval(() => {}, 1000);
  process.on("SIGINT", () => {});
  addEventListener("x", () => {});
  const mod = "m";
  require(mod);                               // computed require
  const w = new Worker("w.js");
  const server = createServer();
  server["listen"](0);                        // string-literal element access == server.listen()
  new vm.Script("code");                      // vm code generation via new
  vm.runInNewContext("code");                 // vm code generation via call
  const e = eval;                             // same-file alias of a forbidden global
  e("aliased");
  globalThis.eval("via-global");              // forbidden global via member access
  new globalThis.Function("y");               // Function constructor via member access
  (server.listen as unknown as () => void)(); // wrapped callee (as-cast) still resolves to .listen
  (() => {}).constructor("z");                // Function-constructor codegen with NO forbidden identifier
  const ge = globalThis.eval;                 // extract a forbidden member value to a local (taint) ...
  ge("extracted");                            // ... then call it
  const F2 = globalThis.Function;
  new F2("src")();
  const C = (() => {}).constructor;
  (C as (s: string) => () => void)("src")();
  (globalThis.Function as unknown as (s: TemplateStringsArray) => () => void)`return 1`;  // tagged-template call of a forbidden callee
  globalThis.eval.call(null, "reflected");              // reflected invoke of a forbidden capability
  Reflect.apply(globalThis.eval, null, ["applied"]);    // Reflect.apply of a forbidden capability
  const box = { ev: globalThis.eval };                  // launder a forbidden value through an object literal
  box.ev("boxed");
  const chosen = (1 > 0 ? globalThis.eval : String);    // ... or a ternary
  chosen("ternary");
  const { eval: destE } = globalThis;                   // ... or destructuring by property name
  destE("destructured");
  const W = Worker;                                     // bare Worker alias
  new W("aliased.js");
  const proc = process;                                 // process alias
  proc.on("SIGTERM", () => {});
  process.on.call(process, "SIGHUP", () => {});         // reflected process-handler registration
  const boundOn = process.on.bind(process);             // bound + extracted process handler
  boundOn("SIGUSR1", () => {});
  const { on } = process;                               // destructured process handler
  on("SIGWINCH", () => {});
  (globalThis as unknown as { process: NodeJS.Process }).process.on("SIGABRT", () => {}); // globalThis.process.on
  const gproc = (globalThis as unknown as { process: NodeJS.Process }).process;
  const { once: onc } = gproc;                          // destructure a handler from globalThis.process (via alias)
  onc("SIGQUIT", () => {});
  const dyn = "ev" + "al";
  (globalThis as unknown as Record<string, (s: string) => void>)[dyn]!("computed-direct"); // computed global access
  const gt = globalThis;                                 // global-object alias
  (gt as unknown as Record<string, (s: string) => void>)[dyn]!("computed-alias");
  let eAssign: unknown;
  ({ eval: eAssign } = globalThis);                      // destructuring ASSIGNMENT extraction
  void eAssign;
  const ctor = 1 > 0 ? f.constructor : String;          // conditional value with a forbidden branch (taint)
  (ctor as (s: string) => void)("cond");
  new (1 > 0 ? globalThis.Function : Object)("x" as never); // conditional constructor
  const obj: Record<string, () => void> = { listen: () => {} };
  const key = "listen";
  obj[key]!();                                // computed-member call (obj[expr]() can hide any capability)
  installHandlers(process);                             // process passed to a same-file helper param
  void once(process, "SIGTERM");                        // node:events free-function process listener (event is arg1)
  process.stdin.on("data", () => {});                   // external-input ingress via a process standard stream
  const { stdin } = process;                            // ... or a destructured stream alias
  stdin.on("data", () => {});
  process.setUncaughtExceptionCaptureCallback(() => {}); // process callback API (not an EventEmitter method)
  const streamOn = process.stdin.on.bind(process.stdin); // stream listener-method extraction/bind
  streamOn("data", () => {});
  let inp: NodeJS.ReadStream | undefined;
  ({ stdin: inp } = process);                           // stream assignment destructuring
  inp?.on("data", () => {});
  (globalThis as unknown as { onmessage: () => void }).onmessage = () => {}; // on* event-handler property
  queueMicrotask(() => {});                              // scheduler
  process.nextTick(() => {});
  (globalThis as unknown as { require: (s: string) => unknown }).require("node:fs"); // global-container require
  (process as unknown as { getBuiltinModule: (s: string) => unknown }).getBuiltinModule("node:http"); // builtin loader
  void f; void g; void w;
}

function installHandlers(p: NodeJS.Process): void {
  p.on("SIGTERM", () => {});                            // caught by the SIG* event name regardless of receiver identity
  p.on("exit", () => {});                               // "exit" lifecycle event, also caught by name
}
