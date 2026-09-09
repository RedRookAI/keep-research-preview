// A NON-owner using several effect families directly — each must be flagged as an unowned effect callsite.
import { readFileSync } from "node:fs";        // fs (not the owner)
import { execSync } from "node:child_process"; // subprocess (no owner)
export function bad(): void {
  readFileSync("/etc/passwd", "utf8");
  execSync("ls");
  process.kill(1, "SIGTERM");                  // subprocess (process control)
  const home = process.env.HOME;               // env
  const r = Math.random();                     // random
  const t = Date.now();                        // clock
  setTimeout(() => {}, 10);                    // clock (scheduler)
  process.nextTick(() => {});                  // clock (scheduler)
  void fetch("http://example.com");            // net (global fetch)
  (globalThis.crypto as { getRandomValues: (a: Uint8Array) => Uint8Array }).getRandomValues(new Uint8Array(4)); // random
  const plat = process.platform;               // hostinfo
  const cwd = process.cwd();                    // hostinfo
  void (globalThis as unknown as { fetch: (u: string) => unknown }).fetch("http://x"); // net (qualified fetch)
  const hb = process.hrtime.bigint();          // clock (process.hrtime.bigint)
  const up = process.uptime();                 // clock
  const to = performance.timeOrigin;           // clock read
  const cpu = process.cpuUsage();              // hostinfo
  const av = process.argv;                     // hostinfo (argv)
  const ua = navigator.userAgent;              // hostinfo (navigator)
  void ua;
  void av;
  void plat; void cwd; void hb; void up; void to; void cpu;
  void home; void r; void t;
}
