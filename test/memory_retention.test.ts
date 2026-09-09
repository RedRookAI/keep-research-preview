import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, chmodSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureMemoryRetentionPolicy, admitPrivateMemorySource, privateRetentionAllowed, MEMORY_RETENTION_POLICY_SCHEMA } from "../src/memory/retention.js";
import { loadMemoryRetentionProfile, writeMemoryRetentionProfile, memoryRetentionProfileFromArgs } from "../src/cli/memory_retention_profile.js";
import { scanIngestion } from "../src/memory/ingestion.js";

const configuration = (authority: "owner" | "organization") => ({ schema: MEMORY_RETENTION_POLICY_SCHEMA as typeof MEMORY_RETENTION_POLICY_SCHEMA, authority, purposes: [{ id: "contact-memory", maxUseMs: 1000 }] });
for (const authority of ["owner", "organization"] as const) {
  test(`private-source ${authority}: explicit policy preserves exact private facts without weakening sanitized defaults`, () => {
    const policy = captureMemoryRetentionPolicy(configuration(authority));
    const content = "Contact example@example.invalid; reference 123-45-6789.\nPreserve spacing.  ";
    const request = { content, purpose: "contact-memory", useUntil: 2000 };
    const result = admitPrivateMemorySource(policy, authority, request, 1000);
    assert.equal(result.accepted, true); if (!result.accepted) return;
    assert.equal(result.content, content); assert.deepEqual(result.findings, ["pii:email", "pii:ssn-like"]);
    assert.equal(result.retention.policyIdentity, policy.identity); assert.equal(result.retention.representation, "keep.memory.private-source/v1");
    assert.equal(scanIngestion(content).sanitized, "Contact [REDACTED-PII]; reference [REDACTED-PII].\nPreserve spacing.  ");
    for (const current of [undefined, captureMemoryRetentionPolicy(configuration(authority === "owner" ? "organization" : "owner")), captureMemoryRetentionPolicy({ ...configuration(authority), purposes: [] })]) {
      assert.equal(admitPrivateMemorySource(current, authority, request, 1000).accepted, false);
      assert.equal(privateRetentionAllowed(current, authority, request.purpose, 1000, 2000, 1500), false);
    }
    assert.equal(admitPrivateMemorySource(policy, authority, { ...request, purpose: "unadmitted-purpose" }, 1000).accepted, false);
  });
  test(`private-source ${authority}: explicit bounded lifetime and current policy fence future use`, () => {
    const policy = captureMemoryRetentionPolicy(configuration(authority));
    for (const useUntil of [null, undefined, NaN, Infinity, 0, 1000, 2001, Number.MAX_SAFE_INTEGER + 1]) {
      assert.equal(admitPrivateMemorySource(policy, authority, { content: "Contact fact", purpose: "contact-memory", useUntil: useUntil as number | null }, 1000).accepted, false);
    }
    assert.equal(privateRetentionAllowed(policy, authority, "contact-memory", 1000, 2000, 1999), true);
    assert.equal(privateRetentionAllowed(policy, authority, "contact-memory", 1000, 2000, 2000), false);
    assert.equal(privateRetentionAllowed(policy, authority, "contact-memory", 1000, 2000, 999), false);
    const shortened = captureMemoryRetentionPolicy({ ...configuration(authority), purposes: [{ id: "contact-memory", maxUseMs: 500 }] });
    assert.equal(privateRetentionAllowed(shortened, authority, "contact-memory", 1000, 2000, 1100), false);
    const unlimited = captureMemoryRetentionPolicy({ ...configuration(authority), purposes: [{ id: "contact-memory", maxUseMs: null }] });
    assert.equal(admitPrivateMemorySource(unlimited, authority, { content: "Fact", purpose: "contact-memory", useUntil: null }, 1000).accepted, true);
    assert.equal(privateRetentionAllowed(unlimited, authority, "contact-memory", 1000, undefined as unknown as null, 1000), false);
  });
  test(`private-source ${authority}: existing secret and license detectors refuse the entire write without returning raw rejected content`, () => {
    const policy = captureMemoryRetentionPolicy(configuration(authority));
    for (const content of ["Contact example@example.invalid. AKIA1234567890ABCDEF", "-----BEGIN PRIVATE KEY-----", "SPDX-License-Identifier: GPL-3.0", "AbCdEfGhIjKlMnOpQrStUvWx1234567890"]) {
      const result = admitPrivateMemorySource(policy, authority, { content, purpose: "contact-memory", useUntil: 2000 }, 1000);
      assert.equal(result.accepted, false); if (result.accepted) continue;
      assert.equal(result.reason, "ingestion"); assert.ok(result.findings.length); assert.ok(!JSON.stringify(result).includes(content));
      assert.equal("content" in result, false); assert.equal("retention" in result, false);
    }
  });
  test(`private-source ${authority}: protected profile roundtrip and authority mismatch`, t => {
    const root = mkdtempSync(join(tmpdir(), "keep-retention-profile-")); t.after(() => rmSync(root, { recursive: true, force: true }));
    const path = join(root, "policy.json"); writeMemoryRetentionProfile(path, configuration(authority));
    assert.deepEqual(loadMemoryRetentionProfile(path, authority), captureMemoryRetentionPolicy(configuration(authority)));
    assert.equal("identity" in JSON.parse(readFileSync(path, "utf8")), false);
    assert.throws(() => loadMemoryRetentionProfile(path, authority === "owner" ? "organization" : "owner"), /authority/u);
    assert.throws(() => loadMemoryRetentionProfile("relative.json", authority), /absolute/u);
    chmodSync(path, 0o644); assert.throws(() => loadMemoryRetentionProfile(path, authority), /permission|0600|private/u);
  });
}

test("retention configure requires explicit bounded purposes and duration without duplicate or ignored flags", () => {
  const args = ["--profile=retention.json", "--authority=owner", "--purposes=contacts,project-memory", "--max-use-ms=60000"];
  const configured = memoryRetentionProfileFromArgs(args, "/tmp");
  assert.equal(configured.path, "/tmp/retention.json");
  assert.deepEqual(configured.policy.purposes, [{ id: "contacts", maxUseMs: 60000 }, { id: "project-memory", maxUseMs: 60000 }]);
  for (const invalid of [args.slice(0, 3), [...args, "--authority=organization"], [...args, "--ignored=true"],
    args.map(arg => arg.startsWith("--max-use-ms=") ? "--max-use-ms=0" : arg),
    args.map(arg => arg.startsWith("--purposes=") ? "--purposes=contacts,contacts" : arg)]) assert.throws(() => memoryRetentionProfileFromArgs(invalid, "/tmp"));
});

test("private retention policy capture rejects executable/malformed input and freezes semantic identity", () => {
  const original = configuration("owner"), captured = captureMemoryRetentionPolicy(original);
  original.purposes[0]!.maxUseMs = 99999; original.purposes.push({ id: "other", maxUseMs: 1000 });
  assert.deepEqual(captured.purposes, [{ id: "contact-memory", maxUseMs: 1000 }]);
  assert.ok(Object.isFrozen(captured) && Object.isFrozen(captured.purposes) && Object.isFrozen(captured.purposes[0]));
  const rows = [{ id: "alpha", maxUseMs: null }, { id: "beta", maxUseMs: 1000 }];
  assert.equal(captureMemoryRetentionPolicy({ ...configuration("owner"), purposes: rows }).identity,
    captureMemoryRetentionPolicy({ ...configuration("owner"), purposes: [...rows].reverse() }).identity);
  let getters = 0;
  const getter = { ...configuration("owner"), get purposes() { getters++; return []; } };
  const hostileArray: unknown[] = []; Object.defineProperty(hostileArray, "0", { get() { getters++; return rows[0]; }, enumerable: true });
  for (const value of [null, [], {}, { ...configuration("owner"), identity: "f".repeat(64) }, getter, new Proxy(configuration("owner"), {}),
    { ...configuration("owner"), purposes: hostileArray }, { ...configuration("owner"), purposes: Array(1) },
    { ...configuration("owner"), purposes: [{ id: "Bad Purpose", maxUseMs: null }] },
    { ...configuration("owner"), purposes: [rows[0], rows[0]] },
    ...[0, -1, NaN, Infinity, undefined, "1000"].map(maxUseMs => ({ ...configuration("owner"), purposes: [{ id: "alpha", maxUseMs }] }))]) {
    assert.throws(() => captureMemoryRetentionPolicy(value));
  }
  assert.equal(getters, 0);
});
