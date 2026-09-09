import { test } from "node:test";
import assert from "node:assert/strict";

import {
  decideComprehensionReceipt,
  mergeDecisionId,
  type ComprehensionReceipt,
  type MergeAuthorityDecision,
} from "../src/oversight/merge_authority.js";

/**
 * BUILD-ORDER 2.4 (COMPREHENSION-RECEIPT) — the ONE receipt decision function, per CONSEQUENCE.
 *
 * PROVE BY DISPROOF (INVERTED). Each test pins an invariant; the paired neuter (named in the round's
 * disproof-red.txt) reddens THAT invariant and isolates. decideComprehensionReceipt is fed the EXISTING
 * consequence classification (mergeAuthority.consequential) — it never re-derives consequence.
 *
 * HONEST BOUND under test: a receipt proves an accountable action bound to THIS decision, NEVER
 * comprehension. So the only thing asserted is "was a bound acknowledgment recorded", not "understood".
 */

const DID = "issue-7|human-merge|consequential|high|verified, but irreversible / high-blast / sensitive — the owner owns this merge";

function receipt(decisionId: string): ComprehensionReceipt {
  return { decisionId, acknowledgedBy: "operator@example", acknowledgedAt: 1000 };
}

// (a) A CONSEQUENTIAL human-merge with NO recorded receipt does not proceed autonomously.
//     NEUTER (RED-a): the consequential no-receipt branch returns mayProceed:true -> this reddens.
test("2.4(a) consequential human-merge with NO receipt does NOT proceed (delivery-receipt gate)", () => {
  const d = decideComprehensionReceipt({ verdict: "human-merge", consequential: true, decisionId: DID });
  assert.equal(d.disposition, "delivery-receipt");
  assert.equal(d.mayProceed, false, "a consequential human-merge must not proceed autonomously on an unread warning");
  assert.equal(d.recordUnacknowledged, true, "the un-acknowledged surfacing is durably recorded");
});

test("2.4(a+) a VALID receipt bound to this decision satisfies the delivery-receipt", () => {
  const d = decideComprehensionReceipt({ verdict: "human-merge", consequential: true, decisionId: DID, receipt: receipt(DID) });
  assert.equal(d.disposition, "delivery-receipt");
  assert.equal(d.mayProceed, true, "an accountable acknowledgment bound to THIS decision lets the gated merge proceed");
  assert.ok(d.satisfiedBy, "the satisfying receipt is echoed for the audit fact");
  assert.equal(d.recordUnacknowledged, false);
});

// (b) A REVERSIBLE surfacing is accept-and-document (recorded, NOT blocked) — the anti-bottleneck invariant.
//     NEUTER (RED-b): make the reversible branch set mayProceed:false (block) -> this reddens.
test("2.4(b) reversible human-merge is accept-and-document — recorded, NEVER blocked", () => {
  const d = decideComprehensionReceipt({ verdict: "human-merge", consequential: false, decisionId: DID });
  assert.equal(d.disposition, "accept-and-document");
  assert.equal(d.mayProceed, true, "a reversible surfacing must never become a human bottleneck");
  assert.equal(d.recordUnacknowledged, true, "but the un-acknowledged surfacing IS durably recorded (habituation-auditable)");
});

// (c) The receipt is bound to THIS decision — a stale/mismatched receipt does not satisfy it.
//     NEUTER (RED-c): drop the `receipt.decisionId === i.decisionId` check (accept any receipt) -> this reddens.
test("2.4(c) a STALE/mismatched receipt does NOT satisfy a consequential gate (bound to THIS decision)", () => {
  const stale = receipt("issue-7|human-merge|consequential|high|SOME OTHER REASON");
  const d = decideComprehensionReceipt({ verdict: "human-merge", consequential: true, decisionId: DID, receipt: stale });
  assert.equal(d.mayProceed, false, "an acknowledgment minted for a different decision must not unlock this one");
  assert.equal(d.satisfiedBy, undefined);
});

test("2.4(c+) mergeDecisionId changes when the decision facts change (a receipt cannot carry over)", () => {
  const base: MergeAuthorityDecision = { verdict: "human-merge", reason: "R1", consequential: true, verified: true };
  const id1 = mergeDecisionId("issue-7", base, "high");
  const id2 = mergeDecisionId("issue-7", { ...base, reason: "R2" }, "high");
  const id3 = mergeDecisionId("issue-9", base, "high");
  assert.notEqual(id1, id2, "a different surfaced reason is a different decision id");
  assert.notEqual(id1, id3, "a different issue is a different decision id");
});

// (d) The default reversible auto-merge path demands NO receipt (front-of-house unchanged).
//     NEUTER (RED-d): make a non-human-merge verdict demand a receipt (mayProceed false) -> this reddens.
test("2.4(d) autonomous-merge demands NO receipt — front-of-house autonomy untouched", () => {
  const d = decideComprehensionReceipt({ verdict: "autonomous-merge", consequential: false, decisionId: DID });
  assert.equal(d.disposition, "not-required");
  assert.equal(d.mayProceed, true, "a reversible, low-blast change the machine resolves demands no click, no wait");
  assert.equal(d.recordUnacknowledged, false, "and nothing un-acknowledged is recorded (no habituation-training noise)");
});

test("2.4(d) abandon-retry and block also demand NO receipt", () => {
  for (const verdict of ["abandon-retry", "block"] as const) {
    const d = decideComprehensionReceipt({ verdict, consequential: verdict === "block", decisionId: DID });
    assert.equal(d.disposition, "not-required", `${verdict} is not a human-owned merge`);
    assert.equal(d.mayProceed, true);
  }
});

// Operator-declared allowance: additive loosening of a consequential gate; never a silent default.
test("2.4 operator allowance LOOSENS a consequential delivery-receipt to accept-and-document (recorded)", () => {
  const d = decideComprehensionReceipt({ verdict: "human-merge", consequential: true, decisionId: DID, operatorAllowance: true });
  assert.equal(d.disposition, "accept-and-document");
  assert.equal(d.mayProceed, true, "the operator DECLARED this consequential path may proceed without a receipt");
  assert.equal(d.recordUnacknowledged, true, "the loosening is recorded as an un-acknowledged surfacing — never silent");
});

test("2.4 an allowance NEVER tightens reversible work (a reversible surfacing stays accept-and-document, unblocked)", () => {
  const withAllow = decideComprehensionReceipt({ verdict: "human-merge", consequential: false, decisionId: DID, operatorAllowance: true });
  assert.equal(withAllow.mayProceed, true);
  assert.equal(withAllow.disposition, "accept-and-document");
});
