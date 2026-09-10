import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, existsSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { classifyExportLocation, DurableWitnessExport, WitnessExportError } from "../src/witness/witness_export.js";
import { resolvedWithinProject } from "../src/infra/process_isolation.js";
import { SandboxedCommandRunner } from "../src/solve/sandboxed_runner.js";
import { composeKeep } from "../src/compose.js";
import { jailedTree } from "../src/isolation/isolated_executor.js";

// Synthetic owned paths only. Directory classification is not a kernel jail or
// independent witness custody. These tests do not mutate the frozen audit baseline.
function paths() {
  const root = mkdtempSync(join(tmpdir(), "keep-path-components-"));
  const data = join(root, "data");
  mkdirSync(join(data, "..cache"), { recursive: true });
  mkdirSync(join(data, "ordinary"));
  mkdirSync(join(root, "sibling"));
  return { root, data };
}

for (const finding of ["KEEP-09B-001", "KEEP-11A-004"] as const) {
  test(`${finding}: classify exact parent components, not dot-prefixed child names`, () => {
    const { root, data } = paths();
    const cases: readonly (readonly [string, boolean])[] = [
      [data, true], [join(data, "ordinary"), true], [join(data, "ordinary/new"), true],
      [join(data, "..cache"), true], [join(data, "..cache/new"), true],
      [join(data, "..audit-reference/new"), true], [join(data, "..."), true],
      [join(data, "%2e%2e"), true], [root, false], [join(root, "sibling"), false],
      [join(root, "data-other"), false], [join(data, "../sibling/new"), false],
    ];
    for (const [candidate, inside] of cases) {
      const actual = finding === "KEEP-09B-001"
        ? !classifyExportLocation(candidate, data).outOfWriteSet
        : resolvedWithinProject(data, candidate);
      assert.equal(actual, inside, candidate);
    }
    // Relative input is specifically project-relative for the runner helper.
    if (finding === "KEEP-11A-004") {
      assert.equal(resolvedWithinProject(data, "..cache/new"), true);
      assert.equal(resolvedWithinProject(data, "../sibling/new"), false);
    }
  });
}

test("path components retain canonical alias checks for existing and new descendants", () => {
  const { root, data } = paths();
  const alias = join(root, "alias");
  symlinkSync(data, alias, "dir");
  symlinkSync(join(root, "sibling"), join(data, "..out"), "dir");
  for (const suffix of ["..cache", "..cache/new"]) {
    assert.equal(classifyExportLocation(join(alias, suffix), data).outOfWriteSet, false);
    assert.equal(resolvedWithinProject(alias, join(data, suffix)), true);
  }
  for (const suffix of ["..out", "..out/new"]) {
    assert.equal(classifyExportLocation(join(data, suffix), data).outOfWriteSet, true);
    assert.equal(resolvedWithinProject(data, suffix), false);
  }
});

test("KEEP-09B-001: export constructor refuses before creating a dot-prefixed child", () => {
  const { data } = paths();
  const inside = join(data, "..audit-reference");
  assert.throws(() => new DurableWitnessExport(inside, data), WitnessExportError);
  assert.equal(existsSync(inside), false, "refused destination was not created");
});

for (const key of ["witnessDir", "witnessExportDir"] as const) {
  test(`KEEP-09B-001: composition refuses required inside ${key}; explicit detection-only remains usable`, async () => {
    const { data } = paths();
    const inside = join(data, "..audit-reference");
    assert.throws(() => composeKeep({ dataDir: data, [key]: inside, requireIndependentWitness: true }), WitnessExportError);
    assert.equal(existsSync(inside), false, "failed required mode did not create a witness destination");
    const app = composeKeep({ dataDir: data, [key]: inside, requireIndependentWitness: false });
    assert.equal(app.witnessExport.outOfWriteSet, false);
    app.spine.stage({ type: "generic", actor: "synthetic", payload: { case: key } });
    await app.spine.seal();
    assert.ok(app.witnessSink.history().length > 0);
  });
}

test("KEEP-09B-001: required outside export publishes and survives reconstruction without replacing old data", async () => {
  const { root, data } = paths();
  const outside = join(root, "..reference");
  const config = { dataDir: data, witnessExportDir: outside, requireIndependentWitness: true };
  const app = composeKeep(config);
  assert.equal(app.witnessExport.outOfWriteSet, true);
  app.spine.stage({ type: "generic", actor: "synthetic", payload: { retained: true } });
  await app.spine.seal();
  const file = join(outside, "witness-export.jsonl");
  assert.equal(realpathSync(file), join(realpathSync(root), "..reference/witness-export.jsonl"));
  const before = readFileSync(file);
  const history = app.witnessSink.history();
  assert.ok(history.length > 0);
  const restored = composeKeep(config);
  assert.equal(restored.witnessExport.outOfWriteSet, true);
  assert.deepEqual(restored.witnessSink.history(), history);
  assert.deepEqual(readFileSync(file), before);
});

test("KEEP-11A-004: real runner permits contained dot-prefix scope and refuses outside before child effect", async () => {
  const { root, data } = paths();
  const marker = join(data, "ran.txt");
  const runner = new SandboxedCommandRunner({ command: process.execPath,
    args: ["-e", "require('node:fs').appendFileSync('ran.txt','entry\\n');console.log('ok 1 - useful work')"],
    projectDir: data, namespaceJail: false, timeoutMs: 2000 });
  const result = await runner.run(join(data, "..cache"));
  assert.equal(result.runnerError, undefined);
  assert.deepEqual(result.results, [{ name: "useful work", passed: true }]);
  assert.equal(readFileSync(marker, "utf8"), "entry\n");
  const refusal = await runner.run(join(root, "sibling"));
  assert.match(refusal.runnerError ?? "", /escapes/);
  assert.equal(refusal.results.length, 0);
  assert.equal(readFileSync(marker, "utf8"), "entry\n", "outside refusal did not enter child");
});

test("KEEP-11A-004: FileTree allows useful dot-prefix files but still refuses outside and git control writes", async () => {
  const { root, data } = paths();
  const tree = jailedTree({
    async read(p) { try { return readFileSync(resolve(data, p), "utf8"); } catch { return undefined; } },
    async write(p, content) { writeFileSync(resolve(data, p), content); },
  }, data);
  await tree.write("..cache/new.txt", "useful");
  assert.equal(await tree.read("..cache/new.txt"), "useful");
  const target = join(root, "sibling/outside.txt");
  await assert.rejects(() => tree.write(target, "refused"), /project-jail refused write/);
  assert.equal(existsSync(target), false);
  mkdirSync(join(data, "..cache/.git"));
  await assert.rejects(() => tree.write("..cache/.git/config", "refused"), /project-jail refused write/);
  assert.equal(existsSync(join(data, "..cache/.git/config")), false);
});
