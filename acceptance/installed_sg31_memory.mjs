/** Installed CLI + socket + fresh-server custody proof, not frontier retrieval or full enterprise qualification. */
import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createSign, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const installed = process.env.KEEP_INSTALLED_PACKAGE_ROOT;
if (!installed) throw new Error("KEEP_INSTALLED_PACKAGE_ROOT required; no source substitute");
const keep = await import(pathToFileURL(join(installed, "dist/src/index.js")).href);
const here = fileURLToPath(import.meta.url), token = "c".repeat(64);
const issuer = "https://sg31-identity.example", audience = "sg31-memory";

if (process.argv[2] === "server") {
  const [mode, root, encodedKey] = process.argv.slice(3);
  const identity = mode === "enterprise" ? {
    provider: new keep.OidcJwksProvider({ issuer, audience, jwks: { keys: [JSON.parse(encodedKey)] } }),
    registry: new keep.PrincipalRegistry([
      { subject: "alice", role: "maintainer", id: "alice", tenant: "alpha" },
      { subject: "teammate", role: "maintainer", id: "teammate", tenant: "alpha" },
      { subject: "foreign", role: "maintainer", id: "foreign", tenant: "beta" },
      { subject: "viewer", role: "viewer", id: "viewer", tenant: "alpha" },
    ]), sessions: new keep.SessionStore(),
  } : undefined;
  const app = keep.composeKeep({ dataDir: join(root, "state"), ...(identity ? { identity } : {}) });
  let project = app.projectManager.list().find(project => project.name === "Installed memory project");
  if (!project) project = app.projectManager.create({ name: "Installed memory project", ...(identity ? { tenant: "alpha" } : {}) });
  const server = await keep.startGatewayServer(app, { port: 0, token, ...(identity ? { identity } : {}) });
  process.on("message", async message => { if (message === "stop") { await server.close(); process.disconnect(); } });
  process.send({ origin: server.origin, projectId: project.id });
} else {
  for (const mode of ["owner", "enterprise"]) test(`installed ${mode}: ordinary durable memory CLI survives a real server restart`, { timeout: 30000 }, async t => {
    const root = mkdtempSync(join(tmpdir(), "keep-installed-memory-"));
    const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = { ...publicKey.export({ format: "jwk" }), kid: "sg31", alg: "RS256", use: "sig" };
    let server, ready;
    const baseEnv = { PATH: process.env.PATH ?? "/usr/bin:/bin", KEEP_INSTALLED_PACKAGE_ROOT: installed };
    const start = async () => {
      server = spawn(process.execPath, [here, "server", mode, root, JSON.stringify(jwk)], { env: baseEnv, stdio: ["ignore", "pipe", "pipe", "ipc"] });
      let stderr = ""; server.stderr.on("data", bytes => { stderr += bytes; });
      ready = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("memory server readiness timed out: " + stderr)), 8000);
        server.once("message", message => { clearTimeout(timer); resolve(message); });
        server.once("error", error => { clearTimeout(timer); reject(error); });
        server.once("exit", code => { clearTimeout(timer); reject(new Error("memory server exited " + code + ": " + stderr)); });
      });
    };
    const stop = async () => {
      if (!server || server.exitCode !== null) return;
      const child = server;
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => { child.kill("SIGTERM"); reject(new Error("owned server did not stop")); }, 5000);
        child.once("exit", () => { clearTimeout(timer); resolve(); }); child.send("stop");
      });
    };
    t.after(stop); await start();
    const login = async subject => {
      if (mode === "owner") return undefined;
      const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "sg31", typ: "JWT" })).toString("base64url");
      const payload = Buffer.from(JSON.stringify({ sub: subject, iss: issuer, aud: audience, exp: Math.floor(Date.now() / 1000) + 60 })).toString("base64url");
      const signature = createSign("RSA-SHA256").update(`${header}.${payload}`).end().sign(privateKey).toString("base64url");
      const response = await fetch(ready.origin + "/auth/session", { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ assertion: `${header}.${payload}.${signature}` }), signal: AbortSignal.timeout(5000) });
      assert.equal(response.status, 200); const session = (await response.json()).session;
      const path = join(root, subject + ".session"); writeFileSync(path, session + "\n", { mode: 0o600 }); return path;
    };
    let session = await login("alice");
    const target = mode === "enterprise" ? ["--scope=project", "--project=" + ready.projectId] : ["--scope=user"];
    const cli = (args, selectedSession = session, selectedToken = token) => spawnSync(process.execPath, [join(installed, "dist/src/main.js"), "memory", ...args], {
      env: { ...baseEnv, KEEP_GATEWAY_URL: ready.origin, KEEP_GATEWAY_TOKEN: selectedToken, ...(selectedSession ? { KEEP_GATEWAY_SESSION_FILE: selectedSession } : {}) },
      encoding: "utf8", timeout: 8000, maxBuffer: 1024 * 1024,
    });
    const successful = result => { assert.equal(result.status, 0, result.stdout + result.stderr); return result.stdout; };
    assert.notEqual(cli(["init", ...target]).status, 0, "explicit retention consent is required");
    successful(cli(["init", "--retain", ...target]));
    const content = "Synthetic installed retained deployment decision";
    const useUntil = Date.now() + 60000, deadlineFlag = "--use-until=" + useUntil;
    const stored = successful(cli(["store", content, "--kind=decision", "--durable", deadlineFlag, "--operation-id=first-write", ...target]));
    const id = /Stored\. id=([^\s]+)/u.exec(stored)?.[1]; assert.ok(id, stored);
    const replay = successful(cli(["store", content, "--kind=decision", "--durable", deadlineFlag, "--operation-id=first-write", ...target]));
    assert.equal(/Stored\. id=([^\s]+)/u.exec(replay)?.[1], id);
    assert.match(successful(cli(["recall", "deployment decision", "--durable", "--operation-id=first-read", ...target])), /Synthetic installed retained deployment decision/u);
    if (mode === "enterprise") {
      assert.match(successful(cli(["review", id, "--durable", ...target], await login("teammate"))), /Synthetic installed retained deployment decision/u);
      assert.notEqual(cli(["review", id, "--durable", ...target], await login("foreign")).status, 0);
      assert.notEqual(cli(["store", "Synthetic forbidden write", "--durable", ...target], await login("viewer")).status, 0);
    }
    const projectId = ready.projectId; await stop(); await start();
    assert.equal(ready.projectId, projectId); session = await login("alice");
    const reviewed = successful(cli(["review", id, "--durable", ...target]));
    assert.match(reviewed, /Synthetic installed retained deployment decision/u);
    const custody = JSON.parse(/custody=(.+) useStatus=/u.exec(reviewed)?.[1] ?? "null"); assert.ok(custody);
    assert.equal(custody.source.actorId, mode === "owner" ? "owner" : "alice");
    assert.equal(custody.scope.tenantId, mode === "owner" ? undefined : "alpha");
    assert.equal(custody.assertion, "asserted"); assert.equal(custody.uncertainty, "unassessed"); assert.equal(custody.authority, "none");
    assert.equal(custody.retention.useUntil, useUntil); assert.deepEqual(custody.derivatives.coEncrypted, ["embedding", "access"]);
    const corrected = successful(cli(["correct", id, "Synthetic corrected installed decision", "--durable", "--operation-id=correction", ...target]));
    const newId = /new=([^\s]+)/u.exec(corrected)?.[1]; assert.ok(newId, corrected);
    assert.match(successful(cli(["review", id, "--durable", ...target])), /tier=retired/u);
    const successorReview = successful(cli(["review", newId, "--durable", ...target]));
    assert.match(successorReview, new RegExp("lineage=supersedes:" + id));
    const successor = JSON.parse(/custody=(.+) useStatus=/u.exec(successorReview)?.[1] ?? "null");
    assert.equal(successor.retention.useUntil, useUntil); assert.equal(successor.supersedes, id);
    assert.equal(successor.consentEventId, custody.consentEventId);
    assert.match(successful(cli(["recall", "deployment decision", "--durable", "--operation-id=first-read", ...target])), /No memories found/u,
      "an original recall receipt must not re-expose its subsequently retired item");
    const expires = Date.now() + 2000;
    const expiring = successful(cli(["store", "Synthetic short lived memory", "--durable", "--use-until=" + expires, "--operation-id=expiring", ...target]));
    const expiringId = /Stored\. id=([^\s]+)/u.exec(expiring)?.[1]; assert.ok(expiringId);
    // Real wall time, bounded to two seconds; no replacement provider/server or hidden source path.
    await new Promise(resolve => setTimeout(resolve, Math.max(0, expires - Date.now() + 5)));
    const expired = successful(cli(["review", expiringId, "--durable", ...target]));
    assert.match(expired, /Content withheld.*erasure remains pending/u); assert.doesNotMatch(expired, /Synthetic short lived memory/u);
    const survivorText = successful(cli(["store", "Synthetic independent erasure survivor", "--durable", "--operation-id=survivor", ...target]));
    const survivorId = /Stored\. id=([^\s]+)/u.exec(survivorText)?.[1]; assert.ok(survivorId);
    successful(cli(["hold", newId, "--hold-id=installed-hold", "--operation-id=hold", ...target]));
    const heldErase = cli(["erase", id, "--operation-id=erase-root", ...target]);
    assert.notEqual(heldErase.status, 0); assert.match(heldErase.stdout, /legal-hold/u, "a held derivative blocks erasing its source");
    successful(cli(["hold", newId, "--hold-id=installed-hold", "--release", "--operation-id=release", ...target]));
    const erased = successful(cli(["erase", id, "--operation-id=erase-root", ...target]));
    assert.match(erased, /Local memory key revoked/u); assert.match(erased, /outside copies.*pending/u);
    if (mode === "enterprise") assert.notEqual(cli(["erase", survivorId, "--operation-id=foreign-erase", ...target], await login("foreign")).status, 0);
    await stop(); await start(); session = await login("alice");
    assert.match(successful(cli(["erase", id, "--operation-id=erase-root", ...target])), /Local memory key revoked/u);
    for (const erasedId of [id, newId]) {
      const gone = cli(["review", erasedId, "--durable", ...target]);
      assert.notEqual(gone.status, 0); assert.match(gone.stdout, /memory deletion admitted/u);
      assert.doesNotMatch(gone.stdout, /Synthetic (?:installed retained deployment|corrected installed) decision/u);
    }
    assert.match(successful(cli(["review", survivorId, "--durable", ...target])), /Synthetic independent erasure survivor/u);
    for (const args of [
      ["recall", "deployment decision", "--durable", "--operation-id=first-read", ...target],
      ["store", content, "--kind=decision", "--durable", deadlineFlag, "--operation-id=first-write", ...target],
      ["correct", id, "Synthetic corrected installed decision", "--durable", "--operation-id=correction", ...target],
    ]) {
      const withheld = cli(args); assert.notEqual(withheld.status, 0); assert.match(withheld.stdout, /receipt-erased/u);
    }
    const listed = successful(cli(["list", "--durable", ...target]));
    assert.doesNotMatch(listed, /Synthetic (?:installed retained deployment|corrected installed) decision/u);
    assert.match(successful(cli(["store", "Synthetic fresh post-erasure memory", "--durable", "--operation-id=post-erasure", ...target])), /Stored/u);
    assert.notEqual(cli(["list", "--durable", ...target], session, "d".repeat(64)).status, 0);
    await stop();
  });
}
