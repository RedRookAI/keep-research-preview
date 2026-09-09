import { existsSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";

// These are scheduling controls, not evidence reuse or permission to omit a required phase.
const options = { workers: 1, phase: "all", reporter: "spec", timeoutMs: 1_200_000, portable: false, buildFixtures: false };
const seen = new Set();
for (const arg of process.argv.slice(2)) {
  const [key, value] = arg.split("=");
  if (seen.has(key)) throw new Error(`duplicate runner option: ${key}`);
  seen.add(key);
  if (arg === "--portable") options.portable = true;
  else if (arg === "--build-native-fixtures") options.buildFixtures = true;
  else if (/^--workers=[1-9][0-9]*$/u.test(arg) && Number(value) <= 64) options.workers = Number(value);
  else if (key === "--phase" && ["all", "ordinary", "release-security", "native"].includes(value) && arg === `${key}=${value}`) options.phase = value;
  else if (key === "--reporter" && ["dot", "spec", "tap"].includes(value) && arg === `${key}=${value}`) options.reporter = value;
  else if (/^--timeout-ms=[1-9][0-9]*$/u.test(arg) && Number(value) <= 86_400_000) options.timeoutMs = Number(value);
  else throw new Error(`invalid runner option: ${arg}; use --workers=1..64 --phase=all|ordinary|release-security|native --reporter=spec|tap|dot --timeout-ms=N --portable --build-native-fixtures`);
}
if (options.portable && options.phase === "native") throw new Error("portable profile cannot qualify native tests");
const deadline = performance.now() + options.timeoutMs;
const childEnv = { ...process.env, KEEP_ASSURANCE_PROFILE: options.portable ? "portable" : "full" };
// A fresh runner must not inherit node:test's internal child identity from its caller.
// Otherwise nested --test invocations can exit successfully without running their files.
delete childEnv.NODE_TEST_CONTEXT;
function execute(args) {
  const timeout = Math.floor(deadline - performance.now());
  if (timeout <= 0) throw new Error("qualification runner total time budget exhausted");
  const result = spawnSync(process.execPath, args, { cwd: process.cwd(), env: childEnv, stdio: "inherit", timeout, killSignal: "SIGKILL" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const testDir = join(process.cwd(), "dist", "test");
const files = readdirSync(testDir).filter((name) => name.endsWith(".test.js")).sort();
const portable = options.portable;
const native = files.filter((name) => name.startsWith("native_"));
const serial = files.filter((name) => name === "capability_graph_v2.test.js");
const completeArtifact = files.filter((name) => name === "tenant_deployment_admission.test.js");
const ordinary = files.filter((name) => !name.startsWith("native_") && !serial.includes(name) && !(portable && completeArtifact.includes(name)));

function ensureNativeTestFixtures() {
  const target = join(process.cwd(), "native", "target", "x86_64-unknown-linux-musl", "debug");
  const required = ["keep-native-protocol-oracle", "keep-native-p2-d2-overlay-oracle"];
  if (required.every((name) => existsSync(join(target, name)))) return;
  if (!options.buildFixtures) throw new Error("native test fixtures absent; build with node tools/native_p1_gate.mjs --verify, or explicitly pass --build-native-fixtures within the same resource envelope");
  process.stdout.write("[test:full] native fixtures absent; building the pinned Rust test/oracle set once\n");
  execute(["tools/native_p1_gate.mjs", "--verify"]);
  for (const name of required) if (!existsSync(join(target, name))) throw new Error(`native fixture build did not produce ${name}`);
}

function run(label, names, concurrency) {
  if (names.length === 0) throw new Error(`required phase has no test files: ${label}`);
  process.stdout.write(`[test:full] ${label}: ${names.length} files, concurrency ${concurrency}\n`);
  execute([
    "--import", "./dist/test/_netguard.js",
    "--test", `--test-concurrency=${concurrency}`, `--test-reporter=${options.reporter}`,
    ...names.map((name) => join("dist", "test", name)),
  ]);
}

process.stdout.write(`[test:full] profile=${portable ? "portable" : "full"} phase=${options.phase} workers=${options.workers}; ${options.phase === "all" ? "complete selected profile" : "PARTIAL phase only, not full qualification"}; external process-tree memory/CPU containment still required\n`);
// Check fixture availability before consuming a full ordinary phase's budget.
if (!portable && ["all", "native"].includes(options.phase)) ensureNativeTestFixtures();
if (["all", "ordinary"].includes(options.phase)) run("ordinary", ordinary, options.workers);
if (["all", "release-security"].includes(options.phase)) run(portable ? "portable release/security" : "release/security", serial, 1);
if (portable && options.phase === "all") {
  process.stdout.write(`[test:full] designated-host complete-artifact: ${completeArtifact.length} file not claimed by portable CI\n`);
}
if (!portable && ["all", "native"].includes(options.phase)) run("native", native, 1);
