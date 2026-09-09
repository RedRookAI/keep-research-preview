import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

// Tests run via `node --test dist/test/*.test.js` from the repo root, so cwd is the package root.
const root = process.cwd();
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  bin?: Record<string, string>; license?: string; files?: string[]; scripts?: Record<string, string>;
};

test("PACKAGING: the `keep` bin points at a file that exists on disk", () => {
  assert.ok(pkg.bin && pkg.bin["keep"], "package.json declares a `keep` bin");
  const binPath = pkg.bin!["keep"]!;
  assert.ok(existsSync(join(root, binPath)), `bin target ${binPath} exists (run the build first)`);
});

test("PACKAGING: the bin entrypoint carries the node shebang, in source AND in the built target", () => {
  const src = readFileSync(join(root, "src/main.ts"), "utf8");
  assert.ok(src.startsWith("#!/usr/bin/env node"), "src/main.ts starts with the node shebang");
  // The shebang must survive compilation, or the installed `keep` command will not execute.
  const built = readFileSync(join(root, pkg.bin!["keep"]!), "utf8");
  assert.ok(built.startsWith("#!/usr/bin/env node"), "the built bin target carries the shebang");
});

test("PACKAGING: the entrypoint invokes the real composed runCli (not a stub)", () => {
  const mainTs = readFileSync(join(root, "src/main.ts"), "utf8");
  assert.match(mainTs, /from ["']\.\/cli\/keep\.js["']/, "main.ts delegates to the keep entrypoint");
  const keepTs = readFileSync(join(root, "src/cli/keep.ts"), "utf8");
  assert.match(keepTs, /import \{[^}]*\brunCli\b[^}]*\} from ["']\.\/cli_core\.js["']/, "keep.ts imports the real runCli from cli_core");
  assert.match(keepTs, /\brunCli\(/, "keep.ts calls runCli");
  assert.match(keepTs, /composeKeep\(/, "keep.ts composes a real KeepApp (not a stub)");
  assert.doesNotMatch(mainTs, /process\.exit\(/u, "the executable must not kill a live serve command after startup");
  assert.match(mainTs, /process\.exitCode\s*=/u, "ordinary command failures still set the process exit status");
});

test("PACKAGING: attribution and explicit pack-time build metadata are present, not publication clearance", () => {
  assert.equal(pkg.license, "MIT", "license field is MIT");
  assert.ok(existsSync(join(root, "LICENSE")), "a LICENSE file exists");
  assert.ok(existsSync(join(root, ".gitignore")), "a .gitignore exists");
  assert.ok(Array.isArray(pkg.files) && pkg.files.includes("dist/src/"), "files allowlist ships the built engine");
  assert.equal(pkg.scripts?.["prepare"], undefined, "dependency installation does not implicitly compile native code");
  assert.equal(pkg.scripts?.["prepack"], "npm run test:notices && npm run build");
});

test("TEST TOPOLOGY: the authoritative suite does not rerun compiled native gates as named prepasses", () => {
  assert.equal(pkg.scripts?.["test"], "npm run test:full", "npm test delegates to the one authoritative suite");
  const full = pkg.scripts?.["test:full"] ?? "";
  assert.match(full, /run_full_tests\.mjs/, "the complete compiled test set remains authoritative through the bounded runner");
  const runner = readFileSync(join(root, "tools/run_full_tests.mjs"), "utf8");
  assert.match(runner, /endsWith\("\.test\.js"\)/, "the runner discovers the complete compiled test set");
  assert.match(runner, /run\("ordinary"[\s\S]*run\("native"/, "ordinary and native tests both remain required");
  assert.match(runner, /ensureNativeTestFixtures\(\)/, "a clean checkout builds the pinned native test oracles before consuming them");
  assert.doesNotMatch(full, /test:native-p1|test:native-p2-deps/, "compiled native gates execute once through the complete set");
  assert.ok(pkg.scripts?.["test:native-p1"] && pkg.scripts?.["test:native-p2-deps"], "focused native commands remain available");
});

test("PACKAGING: the contract-enforcing fake microVM exists only in the unshipped test tree", () => {
  const production = readFileSync(join(root, "src/infra/microvm_boundary.ts"), "utf8");
  const testOnly = readFileSync(join(root, "test/helpers/fake_microvm_boundary.ts"), "utf8");
  assert.doesNotMatch(production, /buildContractEnforcingFakeMicrovmBoundary/);
  assert.match(testOnly, /buildContractEnforcingFakeMicrovmBoundary/);
  assert.ok(!pkg.files?.some((path) => path === "test/" || path === "test/helpers/" || path.includes("fake_microvm_boundary")), "test-only fake is outside the npm allowlist; an explicitly shipped parity fixture is not the fake");
});
