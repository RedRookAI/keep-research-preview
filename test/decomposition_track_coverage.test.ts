import test from "node:test";
import assert from "node:assert/strict";

import {
  admitTrackCoverage,
  admittedTicketAuthorityDigest,
  executableTicketBodyDigest,
  trackAllocationScopeDigest,
  trackCoverageCandidateDigest,
  trackEquivalenceDigest,
  trackWitnessDigest,
  type TrackAllocationScopeEntryV1,
  type TrackCoverageCandidateV1,
  type TrackCoveragePrerequisiteV1,
  type TrackWitnessV1,
  type TrustedTrackAllocationScopeV1,
} from "../src/decomposition/track_coverage.js";
import type { AdmittedTicketAuthorityV1, ExecutableTicketBodyV1 } from "../src/decomposition/ticket_contract.js";

const H = (character: string) => character.repeat(64);
const CLOSURE = Buffer.from("ewogICJzY2hlbWFfdmVyc2lvbiI6IDEsCiAgInN0YXR1cyI6ICJDT01QTEVURSIsCiAgInRpY2tldF9pZCI6ICJQRy0wNC1UMDAyIiwKICAiYXBwcm92ZWRfdGlja2V0X2JvZHlfZGlnZXN0IjogImZmOTEzYjk1ZmI0ZmMyY2I0NjAzYWUwODFkYTk4NDc3N2IzNzI3MTU0OTY1YWYzNTMzNTRkZDMzYTU3YzBkMzAiLAogICJwcm9kdWN0X2NvbW1pdCI6ICI3OTY3NmI0ZjkxMzRhM2IxMmFmNmFmNzM0ZWVkM2M0OGYyM2ZmYzIyIiwKICAicGxhbm5pbmdfY29tbWl0IjogImJmMGM4YzIyMGQ4YTM3OTIwMzBmZWExOGUyMTM0YzU1NjVmNjAyZGEiLAogICJjbG9zdXJlX3Byb2ZpbGUiOiAiRlVMTF9LRUVQX0VYQUNUX0NPTU1JVF9WMSIsCiAgImNvbXBsZXRpb25fZXZpZGVuY2UiOiBbCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogMCwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI3NjA5NDE3ZjA1NTE2OTI4ZGQyYzg4NGE3ZDkyYmE1Yjc3ZGIwNTcxYzJmZjliMGNhMWU2ODdlMGU2NzViMjA2IgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxLAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjE5NjJiODAwZWFlZjg3Yjc3MDA1MTE2ZmI1ZmU4NzE2ODI4MTVlMzE3ODcyYzYyY2QxNjVkMWQ2ZGIwYTY3ODAiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDIsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiODQwNTkxYmIxMDM1NDMzYmNkYjA2ZWM3NmViOTUyYTQ1NDI0ZTEyNzE2NTg0MzlhODAxOGM5MjE5NDFhMmM5YiIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogMywKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI1N2JlNGIyNDI0YTc5NGFhZTEyOGZhYmVmZDRhZmE0MWI1YmM1Mzc0YTdiOWI2ZWEyYWVlZWY1M2RkNGVlZmRiIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiA0LAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjllMjc3ZDZiMDljNTE0MTM5Zjk2YmQxM2Y5MTc0ZDA3YWZmNThkNzM4ZTdjMjhlYTFhMmIwYmQ5YmRkMzU5MzYiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDUsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiYmFmZWYyYWRjNWI3OTViODhhMjE5NDQ5OWNhNWNmNWZlNTI1YzcxNDg4MWRmN2MyYzZmNzNjZTg0YTUxY2VkNSIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogNiwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI2YzNhMzA4ZjNlNGRiYTVkZjM3OTg1YjIyMzQyNmRkNjA1N2UyOTcxMWEwZTY3ZmI0ZDBiNWM4NTk4NjM2NDhkIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiA3LAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjk3MGQ0MjdlMDBhOGY2NmUyYWJhOTM2ZDc5Y2Y2MmFlODFlNTkyMWFmNzA3NGFjYWQ4MTA0ZDE0NDk5NTdkMGIiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDgsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiZGE0ODY3NWRlMzM0NWEwZWQ1NWVlYzY4YjQwODViMTVkMDU5MmFmMTA2ZjA5YjQ2YmMwZThiMzM4NWJjYTMzMCIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogOSwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICIzMTNlY2I5NTNmZmJlYzlhYzA0YzY4NGU5NGQ3NTg1M2I3ZWJhYzYwODY3OWJmZWNhMjM0ZmQ2MmFhNjljM2QyIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxMCwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICIxYmQ4YzUzYWM0Njg4ZThhYzRjMmEzZjRiYzFhNmJhNDk5ZmRlOTY3MWI5ODJjNmU4YmZlNDI2NjYyYjhlMzY5IgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxMSwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICJjMjYzY2IyM2NiZjQ0NDg2MDdkMjg3OTRkZjU0NzY1Y2QwNGM2NWVjMTY2YmMxNmIwNThlZDJiNDRlN2I2YjYzIgogICAgfQogIF0sCiAgImdpdGh1Yl9yZWFkYmFjayI6IHsKICAgICJzb3VyY2VfcmVtb3RlX2NvbW1pdCI6ICI3OTY3NmI0ZjkxMzRhM2IxMmFmNmFmNzM0ZWVkM2M0OGYyM2ZmYzIyIiwKICAgICJwYWNrYWdlX2Fzc2V0X3VybCI6ICJodHRwczovL2dpdGh1Yi5jb20vUmVkUm9va0FJL2tlZXAtdGFyYmFsbC1iYWNrdXAvcmVsZWFzZXMvZG93bmxvYWQvcGctMDQtdDAwMi1jbG9zdXJlLTIwMjYuMDkuMDMva2VlcC0wLjAuMS50Z3oiLAogICAgInBhY2thZ2Vfc2hhMjU2IjogIjc4OGYyNjk3ZTY1MmU3ZGI2MjJhYzc0Nzg5OWVmNmE2M2E2M2E1MjNlNjg0ZmE0NGJmMjViMmZiZmRkOTk5YjkiLAogICAgInJldHJpZXZlZF9wYWNrYWdlX3NoYTI1NiI6ICI3ODhmMjY5N2U2NTJlN2RiNjIyYWM3NDc4OTllZjZhNjNhNjNhNTIzZTY4NGZhNDRiZjI1YjJmYmZkZDk5OWI5IiwKICAgICJyZXRyaWV2ZWRfaW5zdGFsbF9zdGF0dXMiOiAiUEFTUyIKICB9LAogICJjbG9zZWRfYXQiOiAiMjAyNi0wOS0wM1QyMjoxNDozOSswMjowMCIKfQo=", "base64").toString("utf8");
const prerequisite: TrackCoveragePrerequisiteV1 = {
  closure_bytes: CLOSURE,
  closure_digest: "faa4b817a6769d8de78dca233b2d090472d8cc05d08bde07ea9dccd22cfa30e5",
  product_commit: "79676b4f9134a3b12af6af734eed3c48f23ffc22",
  closure_profile: "FULL_KEEP_EXACT_COMMIT_V1",
};
const clone = <T>(value: T): T => structuredClone(value);

function ticketBody(track: "n1" | "enterprise"): ExecutableTicketBodyV1 {
  const owner = { kind: "owner" as const, owner_id: "owner-1", custody_id: "local-custody-1" };
  const organization = {
    kind: "organization" as const,
    organization_id: "org-1",
    actor_id: "actor-1",
    role_id: "builder",
    separation_policy_id: "two-person-release",
    custody_evidence_digest: H("c"),
    isolation_evidence_digest: H("d"),
  };
  const prefix = track === "n1" ? "N1" : "ENT";
  return {
    schema_version: 1,
    node_kind: "EXECUTABLE_LEAF",
    ticket_id: `BODY-${prefix}`,
    title: `${track} executable body`,
    outcomes: [{ kind: "PRODUCT_CHANGE", statement: `${track} behavior exists`, invariant: `${track} remains first class` }],
    scope_ids: [`PG-04-T004-${prefix}`],
    requirements: [`${prefix}-DIRECT`],
    threats: ["track substitution"],
    mutation_surface: ["src/decomposition/track_coverage.ts"],
    effect_surface: ["track-coverage admission"],
    cases: [
      { id: `${prefix}-DIRECT`, input: `${track} direct witness`, oracle: "admitted", classification: "ACCEPTANCE" },
      { id: `${prefix}-EXCLUSION`, input: `${track} substituted for opposite track`, oracle: "refused", classification: "HOSTILE" },
    ],
    resources: { max_changed_subsystems: 1, focused_test_minutes: 5, full_closure_minutes: 30, max_new_runtime_dependencies: 0, fixed_case_count: 2 },
    ambiguities: [],
    closure: {
      profile: "FULL_KEEP_EXACT_COMMIT_V1",
      steps: [{ id: "focused", command: "node --test", maximum_minutes: 5 }],
      source_push: true, source_readback: true, package_push: true, package_readback: true,
      blank_install: true, n1_journey: true, enterprise_journey: true,
    },
    authority: track === "n1" ? owner : organization,
  };
}

function admitted(track: "n1" | "enterprise"): AdmittedTicketAuthorityV1 {
  const body = ticketBody(track);
  return {
    status: "EXECUTABLE_TICKET_ADMITTED",
    ticket_id: body.ticket_id,
    ticket_body_digest: executableTicketBodyDigest(body),
    track,
    body,
  };
}

interface Fixture {
  authorities: AdmittedTicketAuthorityV1[];
  scope: TrustedTrackAllocationScopeV1;
  candidate: TrackCoverageCandidateV1;
}

function sealWitness(witness: Omit<TrackWitnessV1, "witness_digest">): TrackWitnessV1 {
  const result = { ...witness, witness_digest: H("0") };
  result.witness_digest = trackWitnessDigest(result);
  return result;
}

function fixture(mode: "paired" | "shared" = "paired"): Fixture {
  const authorities = [admitted("n1"), admitted("enterprise")];
  const mechanism = H("a"), evidence = H("b");
  const n1 = sealWitness({ target_track: "n1", kind: "DIRECT", ceremony: "LOCAL_OWNER", authority_digest: admittedTicketAuthorityDigest(authorities[0]!), case_id: "N1-DIRECT" });
  const enterprise = sealWitness({ target_track: "enterprise", kind: "DIRECT", ceremony: "ORGANIZATION", authority_digest: admittedTicketAuthorityDigest(authorities[1]!), case_id: "ENT-DIRECT" });
  const entry: TrackAllocationScopeEntryV1 = {
    logical_ticket_id: "LOGICAL-1", mode,
    n1_body_digest: authorities[0]!.ticket_body_digest,
    enterprise_body_digest: authorities[1]!.ticket_body_digest,
    n1_case_id: "N1-DIRECT", enterprise_case_id: "ENT-DIRECT",
    counterpart_ticket_id: null,
    shared_mechanism_digest: mode === "shared" ? mechanism : null,
    shared_evidence_digest: mode === "shared" ? evidence : null,
  };
  const projection = trackAllocationScopeDigest([entry]);
  const scope: TrustedTrackAllocationScopeV1 = {
    schema_version: 1, status: "TRACK_ALLOCATION_SCOPE_ADMITTED",
    generation: `sha256:${H("9")}`, approved_ticket_inventory_digest: "f0b8b60c7b497b6422fc43afeb310d18ea3d28f3decfe666d44deb54963399db",
    logical_allocation_projection_digest: projection, entries: [entry],
  };
  const equivalence = mode === "shared" ? {
    mechanism_digest: mechanism, evidence_digest: evidence,
    n1_witness_digest: n1.witness_digest, enterprise_witness_digest: enterprise.witness_digest,
    equivalence_digest: H("0"),
  } : null;
  if (equivalence) equivalence.equivalence_digest = trackEquivalenceDigest(equivalence);
  const candidate: TrackCoverageCandidateV1 = {
    schema_version: 1, allocation_id: "allocation-1", generation: scope.generation,
    candidate_digest: H("0"), scope_projection_digest: projection,
    allocations: [{ logical_ticket_id: "LOGICAL-1", mode, mechanism_digest: mechanism, n1_witness: n1, enterprise_witness: enterprise, equivalence }],
  };
  (candidate as { candidate_digest: string }).candidate_digest = trackCoverageCandidateDigest(candidate);
  return { authorities, scope, candidate };
}

function reciprocalFixture(): Fixture {
  const authorities = [admitted("n1"), admitted("enterprise")];
  const n1Digest = admittedTicketAuthorityDigest(authorities[0]!);
  const enterpriseDigest = admittedTicketAuthorityDigest(authorities[1]!);
  const allocations = [
    {
      logical_ticket_id: "N1-ONLY", mode: "n1" as const, mechanism_digest: H("a"), equivalence: null,
      n1_witness: sealWitness({ target_track: "n1", kind: "DIRECT", ceremony: "LOCAL_OWNER", authority_digest: n1Digest, case_id: "N1-DIRECT" }),
      enterprise_witness: sealWitness({ target_track: "enterprise", kind: "EXCLUSION", ceremony: "LOCAL_OWNER", authority_digest: n1Digest, case_id: "N1-EXCLUSION" }),
    },
    {
      logical_ticket_id: "ENTERPRISE-ONLY", mode: "enterprise" as const, mechanism_digest: H("b"), equivalence: null,
      n1_witness: sealWitness({ target_track: "n1", kind: "EXCLUSION", ceremony: "ORGANIZATION", authority_digest: enterpriseDigest, case_id: "ENT-EXCLUSION" }),
      enterprise_witness: sealWitness({ target_track: "enterprise", kind: "DIRECT", ceremony: "ORGANIZATION", authority_digest: enterpriseDigest, case_id: "ENT-DIRECT" }),
    },
  ];
  const entries: TrackAllocationScopeEntryV1[] = [
    { logical_ticket_id: "N1-ONLY", mode: "n1", n1_body_digest: authorities[0]!.ticket_body_digest, enterprise_body_digest: authorities[0]!.ticket_body_digest, n1_case_id: "N1-DIRECT", enterprise_case_id: "N1-EXCLUSION", counterpart_ticket_id: "ENTERPRISE-ONLY", shared_mechanism_digest: null, shared_evidence_digest: null },
    { logical_ticket_id: "ENTERPRISE-ONLY", mode: "enterprise", n1_body_digest: authorities[1]!.ticket_body_digest, enterprise_body_digest: authorities[1]!.ticket_body_digest, n1_case_id: "ENT-EXCLUSION", enterprise_case_id: "ENT-DIRECT", counterpart_ticket_id: "N1-ONLY", shared_mechanism_digest: null, shared_evidence_digest: null },
  ];
  const projection = trackAllocationScopeDigest(entries), generation = `sha256:${H("9")}`;
  const scope: TrustedTrackAllocationScopeV1 = { schema_version: 1, status: "TRACK_ALLOCATION_SCOPE_ADMITTED", generation, approved_ticket_inventory_digest: "f0b8b60c7b497b6422fc43afeb310d18ea3d28f3decfe666d44deb54963399db", logical_allocation_projection_digest: projection, entries };
  const candidate: TrackCoverageCandidateV1 = { schema_version: 1, allocation_id: "reciprocal", generation, candidate_digest: H("0"), scope_projection_digest: projection, allocations };
  (candidate as { candidate_digest: string }).candidate_digest = trackCoverageCandidateDigest(candidate);
  return { authorities, scope, candidate };
}

function reseal(f: Fixture): void {
  for (const authority of f.authorities) {
    (authority as { ticket_body_digest: string }).ticket_body_digest = executableTicketBodyDigest(authority.body);
  }
  const allocation = f.candidate.allocations[0]!;
  const n1Authority = f.authorities.find((authority) => authority.track === "n1")!;
  const enterpriseAuthority = f.authorities.find((authority) => authority.track === "enterprise")!;
  (allocation.n1_witness as { authority_digest: string }).authority_digest = admittedTicketAuthorityDigest(n1Authority);
  (allocation.enterprise_witness as { authority_digest: string }).authority_digest = admittedTicketAuthorityDigest(enterpriseAuthority);
  (allocation.n1_witness as { witness_digest: string }).witness_digest = trackWitnessDigest(allocation.n1_witness);
  (allocation.enterprise_witness as { witness_digest: string }).witness_digest = trackWitnessDigest(allocation.enterprise_witness);
  const entry = f.scope.entries[0]!;
  (entry as { n1_body_digest: string | null }).n1_body_digest = n1Authority.ticket_body_digest;
  (entry as { enterprise_body_digest: string | null }).enterprise_body_digest = enterpriseAuthority.ticket_body_digest;
  if (allocation.equivalence) {
    (allocation.equivalence as { n1_witness_digest: string }).n1_witness_digest = allocation.n1_witness.witness_digest;
    (allocation.equivalence as { enterprise_witness_digest: string }).enterprise_witness_digest = allocation.enterprise_witness.witness_digest;
    (allocation.equivalence as { equivalence_digest: string }).equivalence_digest = trackEquivalenceDigest(allocation.equivalence);
  }
  const scopeDigest = trackAllocationScopeDigest(f.scope.entries);
  (f.scope as { logical_allocation_projection_digest: string }).logical_allocation_projection_digest = scopeDigest;
  (f.candidate as { scope_projection_digest: string }).scope_projection_digest = scopeDigest;
  (f.candidate as { candidate_digest: string }).candidate_digest = trackCoverageCandidateDigest(f.candidate);
}

function denied(f: Fixture, denial: string, reason: string | null = null): void {
  const result = admitTrackCoverage(f.candidate, f.authorities, f.scope, prerequisite);
  assert.equal(result.admitted, false);
  if (result.admitted) return;
  assert.equal(result.denial, denial);
  assert.equal(result.reason, reason);
}

test("PG-04-T004-FC01 directly admits local-owner n=1 without organization ceremony", () => {
  const f = fixture(), before = clone(f);
  const result = admitTrackCoverage(f.candidate, f.authorities, f.scope, prerequisite);
  assert.equal(result.admitted, true);
  assert.deepEqual(f, before);
  if (!result.admitted) return;
  assert.equal(f.authorities[0]!.body.authority.kind, "owner");
  assert.equal(f.candidate.allocations[0]!.n1_witness.ceremony, "LOCAL_OWNER");
});

test("PG-04-T004-FC02 directly admits attributed enterprise custody and isolation", () => {
  const f = fixture();
  const result = admitTrackCoverage(f.candidate, f.authorities, f.scope, prerequisite);
  assert.equal(result.admitted, true);
  assert.equal(f.authorities[1]!.body.authority.kind, "organization");
  if (!result.admitted) return;
  assert.equal(result.authority.authority_digests.length, 2);
  assert.equal(result.authority.witness_digests.length, 2);
});

test("PG-04-T004-FC03 missing scoped n=1 DIRECT has its typed reason", () => {
  const f = fixture();
  (f.candidate.allocations[0]!.n1_witness as { authority_digest: string }).authority_digest = H("7");
  denied(f, "TRACK_COVERAGE_MISSING", "MISSING_N1_DIRECT");
});

test("PG-04-T004-FC04 missing scoped enterprise DIRECT has its typed reason", () => {
  const f = fixture();
  (f.candidate.allocations[0]!.enterprise_witness as { authority_digest: string }).authority_digest = H("7");
  denied(f, "TRACK_COVERAGE_MISSING", "MISSING_ENTERPRISE_DIRECT");
});

test("PG-04-T004-FC05 shared mode requires exact scope-bound equivalence", () => {
  const f = fixture("shared");
  (f.candidate.allocations[0] as { equivalence: null }).equivalence = null;
  const result = admitTrackCoverage(f.candidate, f.authorities, f.scope, prerequisite);
  assert.equal(result.admitted, false);
  if (result.admitted) return;
  assert.equal(result.denial, "UNSUPPORTED_TRACK_EQUIVALENCE");
  assert.equal(result.owner_stop, "UNRESOLVED_TRACK_EQUIVALENCE");
});

test("PG-04-T004-FC06 blank enterprise custody is a semantic custody denial", () => {
  const f = fixture();
  const authority = f.authorities[1]!.body.authority;
  assert.equal(authority.kind, "organization");
  if (authority.kind !== "organization") return;
  (authority as { custody_evidence_digest: string }).custody_evidence_digest = "";
  reseal(f);
  denied(f, "ENTERPRISE_CUSTODY_MISSING");
});

test("PG-04-T004-FC07 organization ceremony is forbidden for owner-backed n=1", () => {
  const f = fixture();
  (f.candidate.allocations[0]!.n1_witness as { ceremony: "ORGANIZATION" }).ceremony = "ORGANIZATION";
  (f.candidate.allocations[0]!.n1_witness as { witness_digest: string }).witness_digest = trackWitnessDigest(f.candidate.allocations[0]!.n1_witness);
  (f.candidate as { candidate_digest: string }).candidate_digest = trackCoverageCandidateDigest(f.candidate);
  denied(f, "N1_ENTERPRISE_CEREMONY_FORBIDDEN");
});

test("enterprise custody denial precedes n=1 ceremony denial under simultaneous faults", () => {
  const f = fixture();
  const organization = f.authorities[1]!.body.authority;
  assert.equal(organization.kind, "organization");
  if (organization.kind !== "organization") return;
  (organization as { custody_evidence_digest: string }).custody_evidence_digest = "";
  reseal(f);
  (f.candidate.allocations[0]!.n1_witness as { ceremony: "ORGANIZATION" }).ceremony = "ORGANIZATION";
  (f.candidate.allocations[0]!.n1_witness as { witness_digest: string }).witness_digest = trackWitnessDigest(f.candidate.allocations[0]!.n1_witness);
  (f.candidate as { candidate_digest: string }).candidate_digest = trackCoverageCandidateDigest(f.candidate);
  denied(f, "ENTERPRISE_CUSTODY_MISSING");
});

test("n=1 owner identity is exact and organization authority in its slot is substitution", () => {
  const blank = fixture();
  const owner = blank.authorities[0]!.body.authority;
  assert.equal(owner.kind, "owner");
  if (owner.kind !== "owner") return;
  (owner as { owner_id: string }).owner_id = "";
  reseal(blank);
  denied(blank, "TRACK_RECEIPT_SUBSTITUTED");

  const substituted = fixture();
  (substituted.authorities[0]!.body as { authority: ExecutableTicketBodyV1["authority"] }).authority = clone(substituted.authorities[1]!.body.authority);
  reseal(substituted);
  denied(substituted, "TRACK_RECEIPT_SUBSTITUTED");
});

test("PG-04-T004-FC08 recognizable cross-slot witness is substitution, not parity", () => {
  const f = fixture();
  const allocation = f.candidate.allocations[0]!;
  const n1 = allocation.n1_witness;
  (allocation as { n1_witness: TrackWitnessV1 }).n1_witness = allocation.enterprise_witness;
  (allocation as { enterprise_witness: TrackWitnessV1 }).enterprise_witness = n1;
  denied(f, "TRACK_RECEIPT_SUBSTITUTED");
});

test("PG-04-T004-FC09 recovery is deterministic, immutable, and recursively frozen", () => {
  const f = fixture();
  const first = admitTrackCoverage(clone(f.candidate), clone(f.authorities), clone(f.scope), clone(prerequisite));
  const second = admitTrackCoverage(clone(f.candidate), clone(f.authorities), clone(f.scope), clone(prerequisite));
  assert.deepEqual(first, second);
  assert.equal(first.admitted, true);
  if (!first.admitted) return;
  assert.equal(Object.isFrozen(first.authority), true);
  assert.equal(Object.isFrozen(first.authority.candidate.allocations), true);
  assert.equal(Object.isFrozen(first.authority.candidate.allocations[0]!.n1_witness), true);
});

test("reciprocal n=1 and enterprise single-track allocations admit and mismatch refuses", () => {
  const valid = reciprocalFixture();
  assert.equal(admitTrackCoverage(valid.candidate, valid.authorities, valid.scope, prerequisite).admitted, true);

  const mismatch = reciprocalFixture();
  (mismatch.scope.entries[0] as { counterpart_ticket_id: string | null }).counterpart_ticket_id = null;
  const projection = trackAllocationScopeDigest(mismatch.scope.entries);
  (mismatch.scope as { logical_allocation_projection_digest: string }).logical_allocation_projection_digest = projection;
  (mismatch.candidate as { scope_projection_digest: string }).scope_projection_digest = projection;
  denied(mismatch, "TRACK_COVERAGE_MISSING", "ALLOCATION_SET_MISMATCH");
});

test("scope shrinkage and body pass-through forgery cannot self-authorize", () => {
  const shrunk = fixture();
  (shrunk.scope.entries as TrackAllocationScopeEntryV1[]).push({ ...clone(shrunk.scope.entries[0]!), logical_ticket_id: "LOGICAL-2" });
  const expandedDigest = trackAllocationScopeDigest(shrunk.scope.entries);
  (shrunk.scope as { logical_allocation_projection_digest: string }).logical_allocation_projection_digest = expandedDigest;
  (shrunk.candidate as { scope_projection_digest: string }).scope_projection_digest = expandedDigest;
  denied(shrunk, "TRACK_COVERAGE_MISSING", "ALLOCATION_SET_MISMATCH");

  const forged = fixture();
  (forged.authorities[0]!.body as { title: string }).title = "mutated after admission";
  const forgedDigest = admittedTicketAuthorityDigest(forged.authorities[0]!);
  (forged.candidate.allocations[0]!.n1_witness as { authority_digest: string }).authority_digest = forgedDigest;
  (forged.candidate.allocations[0]!.n1_witness as { witness_digest: string }).witness_digest = trackWitnessDigest(forged.candidate.allocations[0]!.n1_witness);
  denied(forged, "TRACK_COVERAGE_MISSING", "AUTHORITY_BODY_DIGEST_INVALID");
});

test("approved inventory and non-null DIRECT body pins are load-bearing", () => {
  const inventory = fixture();
  (inventory.scope as { approved_ticket_inventory_digest: string }).approved_ticket_inventory_digest = H("f");
  denied(inventory, "TRACK_COVERAGE_MISSING", "APPROVED_INVENTORY_MISMATCH");

  const pin = fixture();
  (pin.scope.entries[0] as { n1_body_digest: string | null }).n1_body_digest = null;
  const projection = trackAllocationScopeDigest(pin.scope.entries);
  (pin.scope as { logical_allocation_projection_digest: string }).logical_allocation_projection_digest = projection;
  (pin.candidate as { scope_projection_digest: string }).scope_projection_digest = projection;
  denied(pin, "TRACK_COVERAGE_MISSING", "SCOPE_INVALID");
});

test("hostile cyclic, malformed nested, proxy, and getter inputs deny without throwing", () => {
  const cyclic = fixture();
  (cyclic.authorities[0]!.body as unknown as Record<string, unknown>).loop = cyclic.authorities[0]!.body;
  assert.doesNotThrow(() => denied(cyclic, "MALFORMED_OR_UNKNOWN_FIELD"));

  const malformed = fixture();
  (malformed.authorities[0]!.body as unknown as { cases: unknown[] }).cases = [null];
  assert.doesNotThrow(() => denied(malformed, "MALFORMED_OR_UNKNOWN_FIELD"));

  const proxied = fixture();
  const proxy = new Proxy(proxied.candidate, {});
  const proxyResult = admitTrackCoverage(proxy, proxied.authorities, proxied.scope, prerequisite);
  assert.deepEqual(proxyResult, { admitted: false, denial: "MALFORMED_OR_UNKNOWN_FIELD", reason: null, owner_stop: null });

  const getter = fixture();
  Object.defineProperty(getter.authorities[0]!.body, "surprise", { enumerable: true, get() { throw new Error("hostile getter"); } });
  const getterResult = admitTrackCoverage(getter.candidate, getter.authorities, getter.scope, prerequisite);
  assert.deepEqual(getterResult, { admitted: false, denial: "MALFORMED_OR_UNKNOWN_FIELD", reason: null, owner_stop: null });
});

test("foreign authority, missing case, duplicate authority, and stale candidate are distinct", () => {
  const foreign = fixture();
  foreign.authorities.push(admitted("n1"));
  denied(foreign, "TRACK_COVERAGE_MISSING", "AUTHORITY_MISSING");

  const missingCase = fixture();
  (missingCase.authorities[0]!.body.cases as ExecutableTicketBodyV1["cases"][number][]).splice(0, 1);
  reseal(missingCase);
  denied(missingCase, "TRACK_COVERAGE_MISSING", "SCOPED_CASE_MISSING");

  const duplicate = fixture();
  duplicate.authorities.push(clone(duplicate.authorities[0]!));
  denied(duplicate, "TRACK_COVERAGE_MISSING", "AUTHORITY_MISSING");

  const stale = fixture();
  (stale.candidate as { candidate_digest: string }).candidate_digest = H("6");
  denied(stale, "STALE_DERIVATION");
});

test("unknown keys and exact T002 prerequisite drift fail before semantic admission", () => {
  const malformed = fixture();
  (malformed.candidate as unknown as Record<string, unknown>)["surprise"] = true;
  denied(malformed, "MALFORMED_OR_UNKNOWN_FIELD");

  const f = fixture();
  const drifted = { ...prerequisite, product_commit: "0".repeat(40) };
  const result = admitTrackCoverage(f.candidate, f.authorities, f.scope, drifted);
  assert.equal(result.admitted, false);
  if (!result.admitted) assert.equal(result.denial, "PREREQUISITE_AUTHORITY_INVALID");
});
