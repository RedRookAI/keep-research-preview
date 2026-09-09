import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  FileSoloReleaseBaselineStore,
  captureCanonicalSoloObservation,
  captureInstalledPackageSubjectDigest,
  captureSoloReleaseBaseline,
  soloReleaseIdentityDigest,
  verifySoloNonRegression,
  type SoloReleaseObservation,
} from "../src/release/solo_non_regression.js";

function installedFixture(): string {
  const root = mkdtempSync(join(tmpdir(), "keep-installed-subject-"));
  mkdirSync(join(root, "dist"));
  writeFileSync(join(root, "package.json"), JSON.stringify({ name: "keep-fixture", files: ["dist/"] }));
  writeFileSync(join(root, "README.md"), "readme");
  writeFileSync(join(root, "LICENSE"), "license");
  writeFileSync(join(root, "dist", "index.js"), "export const value = 1;\n");
  return root;
}

const observation = (over: Partial<SoloReleaseObservation> = {}): SoloReleaseObservation => ({
  startupMs: 120, p95LatencyMs: 40, ownerCount: 1,
  configurationDigest: soloReleaseIdentityDigest({ provider: "local", projects: true }),
  authorityDigest: soloReleaseIdentityDigest({ mode: "single-owner", owner: "owner" }),
  behaviorDigest: soloReleaseIdentityDigest({ route: "local-core", version: 1 }),
  installedSubjectDigest: soloReleaseIdentityDigest({ package: "keep", version: "0.0.1" }),
  ...over,
});

test("TEAM-01 captures a content-bound n=1 release baseline and admits one exact comparison", () => {
  const baseline = captureSoloReleaseBaseline(observation(), { startupMs: 200, p95LatencyMs: 75 });
  assert.equal(Object.isFrozen(baseline), true);
  assert.match(baseline.baselineDigest, /^[a-f0-9]{64}$/u);
  assert.deepEqual(verifySoloNonRegression(baseline, observation()), { admitted: true, baselineDigest: baseline.baselineDigest });
  assert.throws(() => captureSoloReleaseBaseline(observation(), { startupMs: 119, p95LatencyMs: 75 }), /exceeds/);
});

test("TEAM-01 canonical observation owns configuration, authority, and behavior identities", () => {
  const installed = "e".repeat(64);
  const first = captureCanonicalSoloObservation({ startupMs: 12, p95LatencyMs: 7 }, installed);
  const second = captureCanonicalSoloObservation({ startupMs: 99, p95LatencyMs: 55 }, installed);
  assert.deepEqual(
    { configurationDigest: first.configurationDigest, authorityDigest: first.authorityDigest, behaviorDigest: first.behaviorDigest, ownerCount: first.ownerCount },
    { configurationDigest: second.configurationDigest, authorityDigest: second.authorityDigest, behaviorDigest: second.behaviorDigest, ownerCount: second.ownerCount },
  );
  assert.deepEqual({ startupMs: second.startupMs, p95LatencyMs: second.p95LatencyMs, installedSubjectDigest: second.installedSubjectDigest },
    { startupMs: 99, p95LatencyMs: 55, installedSubjectDigest: installed });
  assert.equal(Object.isFrozen(first), true);
});

test("TEAM-01 reports every performance, configuration, authority, behavior, and installed-subject regression once", () => {
  const baseline = captureSoloReleaseBaseline(observation(), { startupMs: 200, p95LatencyMs: 75 });
  const result = verifySoloNonRegression(baseline, observation({
    startupMs: 201, p95LatencyMs: 76,
    configurationDigest: "a".repeat(64), authorityDigest: "b".repeat(64), behaviorDigest: "c".repeat(64), installedSubjectDigest: "d".repeat(64),
  }));
  assert.equal(result.admitted, false);
  if (!result.admitted) {
    assert.equal(result.reasons.length, 6);
    assert.match(result.reasons.join(";"), /startup.*p95 latency.*configuration.*authority.*behavior.*installed release subject/u);
  }
  assert.equal(verifySoloNonRegression(baseline, observation()).admitted, true, "a failed comparison cannot mutate or renew the baseline");
});

test("TEAM-01 durable baseline is write-once, strict, private, restartable, and tamper-evident", () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-solo-release-")), path = join(dir, "evidence", "solo-baseline.json");
  const baseline = captureSoloReleaseBaseline(observation(), { startupMs: 200, p95LatencyMs: 75 });
  const first = new FileSoloReleaseBaselineStore(path);
  first.pin(baseline);
  assert.deepEqual(new FileSoloReleaseBaselineStore(path).load(), baseline);
  assert.throws(() => first.pin(baseline), /EEXIST/u, "a second writer cannot replace the pinned evidence");
  const stored = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  writeFileSync(path, JSON.stringify({ ...stored, behaviorDigest: "f".repeat(64) }), { mode: 0o600 });
  chmodSync(path, 0o600);
  assert.throws(() => new FileSoloReleaseBaselineStore(path).load(), /digest mismatch/u);
});

test("TEAM-01 installed-subject measurement binds shipped bytes but excludes undeclared runtime state", () => {
  const root = installedFixture();
  const first = captureInstalledPackageSubjectDigest(root);
  writeFileSync(join(root, "runtime.log"), "mutable runtime state");
  assert.equal(captureInstalledPackageSubjectDigest(root), first);
  writeFileSync(join(root, "dist", "index.js"), "export const value = 2;\n");
  assert.notEqual(captureInstalledPackageSubjectDigest(root), first);
});

test("TEAM-01 installed-subject measurement rejects traversal and symbolic-link package entries", () => {
  const traversal = installedFixture();
  writeFileSync(join(traversal, "package.json"), JSON.stringify({ name: "keep-fixture", files: ["../outside"] }));
  assert.throws(() => captureInstalledPackageSubjectDigest(traversal), /unsafe path/u);

  const linked = installedFixture();
  symlinkSync(join(linked, "README.md"), join(linked, "dist", "linked"));
  assert.throws(() => captureInstalledPackageSubjectDigest(linked), /symbolic link/u);
});

test("TEAM-01 installed-subject measurement accepts valid packages without optional README or LICENSE", () => {
  const root = installedFixture();
  const withoutDocs = mkdtempSync(join(tmpdir(), "keep-installed-subject-no-docs-"));
  mkdirSync(join(withoutDocs, "dist"));
  writeFileSync(join(withoutDocs, "package.json"), JSON.stringify({ name: "keep-fixture", files: ["dist/"] }));
  writeFileSync(join(withoutDocs, "dist", "index.js"), "export const value = 1;\n");
  assert.match(captureInstalledPackageSubjectDigest(withoutDocs), /^[a-f0-9]{64}$/u);
  assert.match(captureInstalledPackageSubjectDigest(root), /^[a-f0-9]{64}$/u);
});
