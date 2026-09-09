import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

/**
 * Proves the network-denial guard (test/_netguard.ts) is LIVE and load-bearing. These properties hold
 * ONLY when _netguard is preloaded (package.json "test" uses `node --import ./dist/test/_netguard.js`).
 * Running this file WITHOUT the guard fails — which is exactly the disproof that the guard is wired
 * into the real test command, not merely present.
 */

test("NETGUARD (a): a non-loopback fetch is BLOCKED with a [netguard] error", async () => {
  await assert.rejects(
    () => (globalThis.fetch as typeof fetch)("http://example.com/"),
    (e: unknown) => e instanceof Error && e.message.includes("[netguard]"),
  );
});

test("NETGUARD (b): a loopback fetch is ALLOWED — a local test server is not egress", async () => {
  // Nothing is listening on :1, so it rejects with a connection error — but NOT the netguard error.
  await assert.rejects(
    () => (globalThis.fetch as typeof fetch)("http://127.0.0.1:1/"),
    (e: unknown) => e instanceof Error && !e.message.includes("[netguard]"),
  );
});

test("NETGUARD (c): a non-loopback http client call is BLOCKED", () => {
  assert.throws(
    () => http.request("http://example.com/"),
    (e: unknown) => e instanceof Error && e.message.includes("[netguard]"),
  );
});

test("NETGUARD (d): a loopback http client call is NOT blocked by netguard", () => {
  assert.doesNotThrow(() => {
    const req = http.request("http://127.0.0.1:1/");
    req.on("error", () => {}); // swallow the async connection failure
    req.destroy();
  });
});
