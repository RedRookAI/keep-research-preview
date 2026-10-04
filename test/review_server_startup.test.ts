import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { startReviewServer } from "../src/review/review_server.js";
import type { KeepApp } from "../src/compose.js";

test("occupied review port rejects in a surviving child and leaves its owner usable", { timeout: 10_000 }, async () => {
  const owner = createServer((_req, res) => res.end("original listener"));
  owner.listen(0, "127.0.0.1"); await once(owner, "listening");
  const address = owner.address(); assert.ok(address && typeof address === "object");
  const port = address.port;
  const moduleUrl = new URL("../src/review/review_server.js", import.meta.url).href;
  const source = `
    import { startReviewServer } from ${JSON.stringify(moduleUrl)};
    let refusal;
    try { await startReviewServer({}, { port: ${port} }); throw new Error("unexpected bind"); }
    catch (error) { if (error.code !== "EADDRINUSE") throw error; refusal = error.code; }
    const fresh = await startReviewServer({}, { port: 0 });
    const freshPort = fresh.port; await fresh.close();
    console.log(JSON.stringify({ refusal, survived: true, freshPort, closed: true }));
  `;
  const env = { ...process.env }; delete env["NODE_TEST_CONTEXT"];
  const child = spawn(process.execPath, ["--input-type=module", "--eval", source], { env, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "", stderr = "";
  child.stdout.on("data", data => { stdout += data; }); child.stderr.on("data", data => { stderr += data; });
  const deadline = setTimeout(() => child.kill("SIGKILL"), 5_000);
  try {
    const [code, signal] = await once(child, "close");
    assert.equal(code, 0, stderr); assert.equal(signal, null);
    const result = JSON.parse(stdout) as { refusal: string; survived: boolean; freshPort: number; closed: boolean };
    assert.equal(result.refusal, "EADDRINUSE"); assert.equal(result.survived, true);
    assert.ok(result.freshPort > 0); assert.equal(result.closed, true);
    assert.equal(await (await fetch(`http://127.0.0.1:${port}`)).text(), "original listener");
  } finally {
    clearTimeout(deadline); if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await new Promise<void>((resolve, reject) => owner.close(error => error ? reject(error) : resolve()));
  }
});

test("review server returns its actual loopback origin and releases a normal ephemeral port", { timeout: 5_000 }, async () => {
  // The socket startup contract does not call into the app until a request arrives.
  const handle = await startReviewServer({} as KeepApp, { port: 0, token: "fixture" });
  assert.ok(handle.port > 0); assert.equal(handle.origin, `http://127.0.0.1:${handle.port}`);
  assert.equal(handle.url, `${handle.origin}/?token=fixture`);
  await handle.close();
  const replacement = createServer(); replacement.listen(handle.port, "127.0.0.1");
  try { await once(replacement, "listening"); }
  finally { await new Promise<void>((resolve, reject) => replacement.close(error => error ? reject(error) : resolve())); }
});
