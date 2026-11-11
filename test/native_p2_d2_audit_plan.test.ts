import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import { captureAuditPlanV1 } from "../src/platform/native_p2_d2_audit_plan.js";

import { auditPlanFixture as fixture } from "./helpers/native_patch_application_fixture.js";

const digest = (value: number): string => value.toString(16).padStart(64, "0");
const oracle = process.env.KEEP_P2_CAPTURE_ORACLE ?? fileURLToPath(new URL("../../native/target/x86_64-unknown-linux-musl/debug/keep-native-p2-d2-overlay-oracle", import.meta.url));

const capture = (value: CanonicalValue = fixture()) => captureAuditPlanV1(encodeCanonical(value));
function rust(value: CanonicalValue): string {
  const result = spawnSync(oracle, [], { input: `AUDIT\t${Buffer.from(encodeCanonical(value)).toString("hex")}\n`, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr); return result.stdout.trim();
}

test("AuditPlanV1 captures a nonempty two-family registry and immutable canonical bytes", () => {
  const bytes = encodeCanonical(fixture()); const plan = captureAuditPlanV1(bytes);
  assert.match(plan.auditPlanDigest, /^[0-9a-f]{64}$/u);
  assert.deepEqual(plan.canonicalBytes(), bytes);
  assert.equal(rust(fixture()), `OK\t${plan.auditPlanDigest}`);
  const copy = plan.canonicalBytes(); copy[0] = copy[0]! ^ 0xff;
  assert.deepEqual(plan.canonicalBytes(), bytes);
});

test("AuditPlanV1 refuses registry, independence, authority, threshold, and mechanism neuters", () => {
  const mutants: Record<string, CanonicalValue>[] = [];
  const empty = fixture(); (empty.reviewerRegistry as Record<string, CanonicalValue>).reviewers = []; mutants.push(empty);
  const sameCustodian = fixture(); (((sameCustodian.reviewerRegistry as Record<string, CanonicalValue>).reviewers as CanonicalValue[])[1] as Record<string, CanonicalValue>).custodianFamily = "cloudflare-workers"; mutants.push(sameCustodian);
  const overlap = fixture(); (((overlap.reviewerRegistry as Record<string, CanonicalValue>).reviewers as CanonicalValue[])[0] as Record<string, CanonicalValue>).publicKeyOrTrustRoot = digest(1); mutants.push(overlap);
  const weak = fixture(); ((weak.requiredClaims as CanonicalValue[])[0] as Record<string, CanonicalValue>).minimumReviewers = 1n; mutants.push(weak);
  const mismatch = fixture(); (((mismatch.reviewerRegistry as Record<string, CanonicalValue>).reviewers as CanonicalValue[])[0] as Record<string, CanonicalValue>).publicKeyAlgorithm = "sigstore-fulcio-ecdsa-p256"; mutants.push(mismatch);
  const expired = fixture(); const expiredReviewer = (((expired.reviewerRegistry as Record<string, CanonicalValue>).reviewers as CanonicalValue[])[0] as Record<string, CanonicalValue>); expiredReviewer.validFromCounter = 9n; expiredReviewer.validThroughCounter = 8n; mutants.push(expired);
  const disabled = fixture(); (disabled.separationPolicy as Record<string, CanonicalValue>).keysOffCollectorHost = false; mutants.push(disabled);
  const extra = fixture(); (extra.reviewerRegistry as Record<string, CanonicalValue>).status = "approved"; mutants.push(extra);
  for (const mutant of mutants) { assert.throws(() => capture(mutant)); assert.match(rust(mutant), /^ERR\t/u); }
});


test("AuditPlanV1 uses one intrinsic bounded snapshot despite caller length shadows", () => {
  const bytes = encodeCanonical(fixture()), expected = captureAuditPlanV1(bytes);
  const hostile = Uint8Array.from(bytes);
  Object.defineProperty(hostile, "byteLength", { value: 2 * 1024 * 1024 });
  assert.equal(captureAuditPlanV1(hostile).auditPlanDigest, expected.auditPlanDigest);
  const oversized = new Uint8Array(1024 * 1024 + 1);
  Object.defineProperty(oversized, "byteLength", { value: 1 });
  assert.throws(() => captureAuditPlanV1(oversized), /encoded-size bound/);
});
