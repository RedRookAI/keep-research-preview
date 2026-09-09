/**
 * Round 0 enforcement — the network-denial test guard. [netguard-allow]
 *
 * Preloaded via `node --import ./dist/test/_netguard.js` before the test suite (see package.json
 * "test"). Policy: DENY outbound egress to NON-loopback hosts (real network) unless a host is
 * explicitly allowlisted via KEEP_TEST_NET_ALLOW (comma-separated) — which only an explicit T1+ round
 * may set. Loopback (localhost / 127.0.0.1 / ::1) is ALLOWED: a local test server is not egress.
 *
 * Why: the ledger-build harness (A6) requires enforcement to be artifact-based, not trust-based — a
 * T0 round must make no real outbound call, and that must be DETECTED loudly, not merely promised.
 *
 * Honest seams (named, not hidden): this guards Node's `fetch` and the `node:http`/`node:https`
 * clients — the model-call egress surface (fetch) plus HTTP(S) clients. It does NOT intercept raw
 * `node:net` sockets or `child_process` transports (e.g. `git` over SSH/https as a subprocess); those
 * remain a named seam for a later enforcement round. It is a test-harness guard, not a runtime
 * sandbox.
 */
import http from "node:http"; // [netguard-allow]
import https from "node:https"; // [netguard-allow]

const LOOPBACK = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0", ""]);
const ALLOW = new Set(
  (process.env["KEEP_TEST_NET_ALLOW"] ?? "").split(",").map((s) => s.trim()).filter(Boolean),
);

function hostnameOf(target: unknown): string {
  try {
    if (typeof target === "string") return new URL(target).hostname.replace(/^\[|\]$/g, "");
    if (target instanceof URL) return target.hostname.replace(/^\[|\]$/g, "");
    if (target && typeof target === "object" && "url" in (target as Record<string, unknown>)) {
      return new URL(String((target as Record<string, unknown>)["url"])).hostname.replace(/^\[|\]$/g, "");
    }
  } catch {
    /* unparseable → treat as non-egress (relative URL, etc.) */
  }
  return "";
}

function egressDenied(host: string): boolean {
  if (LOOPBACK.has(host)) return false;
  if (ALLOW.has(host)) return false;
  return true;
}

function reason(host: string, via: string): string {
  return (
    `[netguard] blocked outbound ${via} to '${host}' during a T0 test run. Round-0 enforcement: a T0 ` +
    `round must make no real egress. Allowlist a host via KEEP_TEST_NET_ALLOW for an explicit T1+ round.`
  );
}

// --- fetch: the model-call egress surface. Reject (not sync-throw) to honor fetch semantics. --- [netguard-allow]
const realFetch = globalThis.fetch;
if (typeof realFetch === "function") {
  const guardedFetch = ((input: unknown, init?: unknown): Promise<Response> => {
    const host = hostnameOf(input);
    if (egressDenied(host)) return Promise.reject(new Error(reason(host, "fetch")));
    return (realFetch as (i: unknown, n?: unknown) => Promise<Response>)(input, init);
  }) as typeof fetch;
  Object.defineProperty(globalThis, "fetch", { value: guardedFetch, writable: true, configurable: true });
}

// --- http/https clients (HTTP(S) clients, git-over-https). Sync-throw matches client error semantics. --- [netguard-allow]
function guardRequest<T extends (...args: never[]) => unknown>(real: T, scheme: string): T {
  return function (this: unknown, ...args: unknown[]): unknown {
    let host = "";
    const a0 = args[0];
    if (typeof a0 === "string" || a0 instanceof URL) host = hostnameOf(a0);
    else if (a0 && typeof a0 === "object") {
      const o = a0 as Record<string, unknown>;
      host = String(o["hostname"] ?? o["host"] ?? "").replace(/:\d+$/, "");
    }
    if (egressDenied(host)) throw new Error(reason(host, `${scheme}.request`));
    return (real as unknown as (...a: unknown[]) => unknown).apply(this, args);
  } as unknown as T;
}
const h = http as unknown as Record<string, unknown>;
const hs = https as unknown as Record<string, unknown>;
h["request"] = guardRequest(h["request"] as (...a: never[]) => unknown, "http");
h["get"] = guardRequest(h["get"] as (...a: never[]) => unknown, "http");
hs["request"] = guardRequest(hs["request"] as (...a: never[]) => unknown, "https");
hs["get"] = guardRequest(hs["get"] as (...a: never[]) => unknown, "https");

export {}; // module marker (no runtime exports; side-effecting preload)
