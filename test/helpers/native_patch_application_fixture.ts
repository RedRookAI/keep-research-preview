import type { CanonicalValue } from "../../src/eir/canonical.js";
const digest = (value: number): string => value.toString(16).padStart(64, "0");
const roles = ["advisory", "build-policy", "correctness", "license", "unsafe-contract"];
function reviewer(overrides: Record<string, CanonicalValue>): Record<string, CanonicalValue> {
  return {
    principal: "reviewer.default", reviewerFamily: "provider.default", custodianFamily: "custodian.default",
    mechanism: "ed25519-service", publicKeyAlgorithm: "ed25519", publicKeyOrTrustRoot: digest(3),
    issuer: null, subject: null, repository: null, workflow: null, allowedRoles: roles,
    validFromCounter: 1n, validThroughCounter: 1000n, revocationIdentity: digest(5), ...overrides,
  };
}

export function auditPlanFixture(): Record<string, CanonicalValue> {
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

