import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";

const selected = ["workflow", "release_licensing", "runtime_config", "oidc_provider", "identity_x1", "filesystem_lock", "instance_isolation", "chat_channel", "ci_checks", "self_improvement_loop", "instance_setup", "proposal_export", "repository_prerequisites", "organization_login", "organization_refresh", "organization_admission", "repository_clone_isolation"];

/** Exercise the real coordinator with inert install/compile/notice commands and
 * real Node test files. These fixtures do not qualify dependencies or notices. */
function fixture(version: string, range: unknown = ">=22.23.3 <23", outcome: "pass" | "empty" | "skip" | "fail" = "pass") {
  const root = mkdtempSync(join(tmpdir(), "keep-ci-contract-"));
  for (const directory of ["tools", "bin", "node_modules/typescript/bin", "dist/test"]) mkdirSync(join(root, directory), { recursive: true });
  copyFileSync("tools/run_ci_checks.mjs", join(root, "tools/run_ci_checks.mjs"));
  writeFileSync(join(root, "package.json"), JSON.stringify({ type: "module", engines: { node: range } }));
  writeFileSync(join(root, "version.mjs"), `Object.defineProperty(process, 'version', { value: ${JSON.stringify(version)} });`);
  writeFileSync(join(root, "bin/npm"), '#!/bin/sh\nprintf "install\\n" >> "$KEEP_CI_EVENTS"\nexit "${KEEP_CI_INSTALL_EXIT:-0}"\n', { mode: 0o700 });
  writeFileSync(join(root, "node_modules/typescript/bin/tsc"), "import {appendFileSync} from 'node:fs'; appendFileSync(process.env.KEEP_CI_EVENTS,'compile\\n');\n");
  writeFileSync(join(root, "tools/release_notices.mjs"), "import {appendFileSync} from 'node:fs'; appendFileSync(process.env.KEEP_CI_EVENTS,'notices\\n'); process.exit(Number(process.env.KEEP_CI_NOTICES_EXIT ?? 0));\n");
  writeFileSync(join(root, "dist/test/_netguard.js"), "");
  for (const [index, name] of selected.entries()) {
    const body = outcome === "empty" ? `import {describe} from 'node:test'; describe(${JSON.stringify(name)},()=>{});`
      : `import {test} from 'node:test'; test(${JSON.stringify(name)},${outcome === "skip" && index === 0 ? "{skip:true}," : ""}()=>{${outcome === "fail" && index === 0 ? "throw Error('fixture outcome failure');" : ""}});`;
    writeFileSync(join(root, `dist/test/${name}.test.js`), body);
  }
  const events = join(root, "events");
  return {
    root,
    run(extra: NodeJS.ProcessEnv = {}) {
      const inherited = { ...process.env };
      delete inherited["NODE_TEST_CONTEXT"];
      const env: NodeJS.ProcessEnv = { ...inherited, PATH: `${join(root, "bin")}:/usr/bin:/bin`, KEEP_CI_EVENTS: events, ...extra };
      return spawnSync(process.execPath, ["--import", join(root, "version.mjs"), join(root, "tools/run_ci_checks.mjs")], {
        cwd: root, env, encoding: "utf8", timeout: 15_000, maxBuffer: 2 * 1024 * 1024,
      });
    },
    events: () => existsSync(events) ? readFileSync(events, "utf8").trim().split("\n") : [],
    dispose: () => rmSync(root, { recursive: true, force: true }),
  };
}

test("CI admits the package's minimum and newer supported Node patches before locked installation", () => {
  for (const version of ["v22.23.3", "v22.23.4", "v22.24.0"]) {
    const f = fixture(version);
    try {
      const result = f.run({ KEEP_CI_INSTALL_EXIT: "71" });
      assert.equal(result.status, 71, result.stderr);
      assert.deepEqual(f.events(), ["install"]);
      assert.match(result.stdout, /"phase":"locked-install"/u);
      assert.doesNotMatch(result.stderr, /CI requires Node/u);
    } finally { f.dispose(); }
  }
});

test("CI refuses old, other-major and unstable Node versions before dependency or test work", () => {
  for (const version of ["v22.23.2", "v22.22.99", "v20.99.99", "v23.0.0", "v24.0.0", "v22.23.4-nightly"]) {
    const f = fixture(version);
    try {
      const result = f.run();
      assert.notEqual(result.status, 0, version);
      assert.deepEqual(f.events(), [], version);
      assert.match(result.stderr, /CI requires/u);
    } finally { f.dispose(); }
  }
});

test("CI reads the actual package range and refuses unsupported or malformed contracts", () => {
  for (const range of [">=22.23.5 <23", "^22", ">=22.23.3 <22", undefined]) {
    const f = fixture("v22.23.4", range);
    try {
      if (range === undefined) writeFileSync(join(f.root, "package.json"), JSON.stringify({ type: "module" }));
      const result = f.run();
      assert.notEqual(result.status, 0, String(range));
      assert.deepEqual(f.events(), [], String(range));
    } finally { f.dispose(); }
  }
});

test("CI reports a passing partial profile only after all selected real test cases execute", () => {
  const f = fixture("v22.23.4");
  try {
    const result = f.run({ NODE_TEST_CONTEXT: "child-v8" });
    assert.equal(result.status, 0, result.stderr + result.stdout);
    assert.deepEqual(f.events(), ["install", "compile", "notices"]);
    const summary = result.stdout.split("\n").filter(line => line.startsWith("{"))
      .map(line => JSON.parse(line) as Record<string, unknown>).find(row => row["result"] === "PASS");
    assert.deepEqual(summary, { profile: "partial-unprivileged", result: "PASS", tests: selected.length,
      fullSourceQualified: false, nativeQualified: false, installedArtifactQualified: false });
  } finally { f.dispose(); }
});

test("CI refuses zero-case suites, skipped cases and failing cases", () => {
  for (const outcome of ["empty", "skip", "fail"] as const) {
    const f = fixture("v22.23.4", ">=22.23.3 <23", outcome);
    try {
      const result = f.run();
      assert.notEqual(result.status, 0, outcome);
      assert.doesNotMatch(result.stdout, /"result":"PASS"/u);
      assert.deepEqual(f.events(), ["install", "compile", "notices"]);
    } finally { f.dispose(); }
  }
});

test("a failed notice check stops before focused test execution", () => {
  const f = fixture("v22.23.4");
  try {
    const result = f.run({ KEEP_CI_NOTICES_EXIT: "73" });
    assert.equal(result.status, 73, result.stderr);
    assert.deepEqual(f.events(), ["install", "compile", "notices"]);
    assert.doesNotMatch(result.stdout, /"phase":"fixed-focused-tests"|"result":"PASS"/u);
  } finally { f.dispose(); }
});
