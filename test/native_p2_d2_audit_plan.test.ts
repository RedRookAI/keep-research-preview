import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import { captureAuditPlanV1 } from "../src/platform/native_p2_d2_audit_plan.js";

const digest = (value: number): string => value.toString(16).padStart(64, "0");
const roles = ["advisory", "build-policy", "correctness", "license", "unsafe-contract"];
const oracle = fileURLToPath(new URL("../../native/target/x86_64-unknown-linux-musl/debug/keep-native-p2-d2-overlay-oracle", import.meta.url));

function reviewer(overrides: Record<string, CanonicalValue>): Record<string, CanonicalValue> {
  return {
    principal: "reviewer.default", reviewerFamily: "provider.default", custodianFamily: "custodian.default",
    mechanism: "ed25519-service", publicKeyAlgorithm: "ed25519", publicKeyOrTrustRoot: digest(3),
    issuer: null, subject: null, repository: null, workflow: null, allowedRoles: roles,
    validFromCounter: 1n, validThroughCounter: 1000n, revocationIdentity: digest(5), ...overrides,
  };
}

function fixture(): Record<string, CanonicalValue> {
  return {
    schema: "keep.p2-d2-audit-plan", version: 1n, planId: "keep.p2-d2.audit.2026-08-27",
    claimSchema: "keep.p2-d2-evidence/v1",
    reviewerRegistry: {
      schema: "keep.p2-d2-native-reviewer-registry", version: 1n,
      registryId: "keep.p2-d2.reviewers.2026-08-27", revocationListDigest: digest(7),
      reviewers: [
        reviewer({ principal: "reviewer.cloudflare-anthropic", reviewerFamily: "anthropic",
          custodianFamily: "cloudflare-workers", publicKeyOrTrustRoot: digest(3), revocationIdentity: digest(5) }),
        reviewer({ principal: "reviewer.github-openai", reviewerFamily: "openai",
          custodianFamily: "github-actions-sigstore", mechanism: "sigstore-keyless",
          publicKeyAlgorithm: "sigstore-fulcio-ecdsa-p256", publicKeyOrTrustRoot: digest(4),
          issuer: "https://token.actions.githubusercontent.com", subject: "repo:example/keep-fixture:ref:refs/heads/main",
          repository: "example/keep-fixture", workflow: ".github/workflows/p2-d2-offhost-review.yml@refs/heads/main",
          revocationIdentity: digest(6) }),
      ],
    },
    producerKeyDigests: [digest(1)], validatorKeyDigests: [digest(2)],
    requiredClaims: roles.map((role) => ({ role, minimumReviewers: 2n, minimumReviewerFamilies: 2n, minimumCustodianFamilies: 2n })),
    separationPolicy: { distinctPrincipals: true, distinctReviewerFamilies: true, distinctCustodianFamilies: true,
      producerReviewerDisjoint: true, validatorReviewerDisjoint: true, keysOffCollectorHost: true },
  };
}

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
