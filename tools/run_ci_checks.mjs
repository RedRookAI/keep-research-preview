#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tests = ["workflow", "release_licensing", "runtime_config", "oidc_provider", "identity_x1", "filesystem_lock", "instance_isolation", "chat_channel"];
const profile = "partial-unprivileged";
const deadline = performance.now() + 10 * 60_000;
const env = { ...process.env };
delete env.NODE_TEST_CONTEXT;

function run(phase, command, args) {
  const remaining = Math.floor((deadline - performance.now()) / 1000);
  if (remaining <= 0) throw new Error(`CI shared deadline reached before ${phase}`);
  console.log(JSON.stringify({ profile, phase, command: [command, ...args], timeoutSeconds: remaining }));
  // GNU timeout owns the child process group; the outer CI/container envelope owns total resources.
  const result = spawnSync("/usr/bin/timeout", ["--kill-after=2s", `${remaining}s`, command, ...args], {
    cwd: root, env, encoding: "utf8", maxBuffer: 8 * 1024 * 1024,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  console.log(JSON.stringify({ profile, phase, status: result.status, signal: result.signal, error: result.error?.message }));
  if (result.error || result.signal || result.status !== 0) {
    process.exitCode = result.status && result.status > 0 ? result.status : 1;
    throw new Error(`Declared CI phase ${phase} failed`);
  }
  return result.stdout;
}

try {
  if (process.argv.length !== 2) throw new Error("CI runner accepts no arguments");
  if (process.version !== "v22.23.2") throw new Error(`CI requires Node v22.23.2; observed ${process.version}`);
  if (process.platform !== "linux" || !existsSync("/usr/bin/timeout")) throw new Error("CI requires Linux GNU timeout");
  console.log("PARTIAL unprivileged CI checks; not full-source/native/installed-artifact qualification.");
  run("locked-install", "npm", ["ci", "--ignore-scripts", "--no-audit", "--no-fund"]);
  run("typecheck", process.execPath, ["node_modules/typescript/bin/tsc", "-p", "tsconfig.json"]);
  run("notices", process.execPath, ["tools/release_notices.mjs", "--check"]);
  const files = tests.map(name => `dist/test/${name}.test.js`);
  for (const file of files) if (!existsSync(resolve(root, file))) throw new Error(`Declared CI test missing: ${file}`);
  const tap = run("fixed-focused-tests", process.execPath, ["--import", "./dist/test/_netguard.js", "--test", "--test-concurrency=1", ...files]);
  const count = name => Number(tap.match(new RegExp(`^# ${name} (\\d+)$`, "m"))?.[1] ?? NaN);
  if (!(count("tests") > 0) || count("pass") !== count("tests") || count("fail") !== 0 || count("skipped") !== 0 || count("cancelled") !== 0) {
    throw new Error("Declared CI tests must actually execute without failures, skips or cancellations");
  }
  console.log(JSON.stringify({ profile, result: "PASS", tests: count("tests"), fullSourceQualified: false, nativeQualified: false, installedArtifactQualified: false }));
} catch (error) {
  process.exitCode ||= 1;
  console.error(JSON.stringify({ profile, result: "FAIL", reason: String(error), fullSourceQualified: false }));
}
