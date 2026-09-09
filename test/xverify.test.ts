import { test } from "node:test";
import assert from "node:assert/strict";

import { crossFamilyVerify, type Authorship } from "../src/review/heterogeneous.js";

const author: Authorship = { agentId: "keep-healer", modelFamily: "anthropic" };
const crossVerifier = { identity: { agentId: "auditor", modelFamily: "gemini" } as Authorship };
const sameFamilyVerifier = { identity: { agentId: "auditor-2", modelFamily: "anthropic" } as Authorship };

test("XVERIFY (a): deterministic pass + a DIFFERENT-family verifier approval is accepted", () => {
  const v = crossFamilyVerify({ deterministicPass: true, author, verifier: { ...crossVerifier, approved: true } });
  assert.equal(v.accepted, true);
  assert.equal(v.independent, true, "gemini ≠ anthropic → independent");
  assert.equal(v.authorFamily, "anthropic");
  assert.equal(v.verifierFamily, "gemini");
});

test("XVERIFY (b): a SAME-family verifier is rejected as non-independent (no rubber-stamp)", () => {
  const v = crossFamilyVerify({ deterministicPass: true, author, verifier: { ...sameFamilyVerifier, approved: true } });
  assert.equal(v.accepted, false, "a same-family verifier's approval cannot bless under a cross-family policy");
  assert.equal(v.independent, false);
  assert.match(v.reason, /not independent|same model family/i);
});

test("XVERIFY (c): the deterministic oracle is authoritative — a deterministic FAIL is never overridden to pass", () => {
  const v = crossFamilyVerify({ deterministicPass: false, author, verifier: { ...crossVerifier, approved: true } });
  assert.equal(v.accepted, false, "a passing cross-family verifier cannot override a hard deterministic fail");
  assert.equal(v.deterministicPass, false);
  assert.match(v.reason, /deterministic oracle FAILED|authoritative/);
});

test("XVERIFY (d): with no verifier configured, the deterministic-only path accepts a clean fix (n=1 default)", () => {
  const v = crossFamilyVerify({ deterministicPass: true, author });
  assert.equal(v.accepted, true);
  assert.equal(v.usedVerifier, false);
  assert.match(v.reason, /deterministic floor governs|n=1/);
});

test("XVERIFY (e): the cross-family decision is reported honestly (families + agreement)", () => {
  const approved = crossFamilyVerify({ deterministicPass: true, author, verifier: { ...crossVerifier, approved: true } });
  assert.equal(approved.agreement, true);
  assert.ok(approved.reason.includes("anthropic") && approved.reason.includes("gemini"), "both families named");
  const declined = crossFamilyVerify({ deterministicPass: true, author, verifier: { ...crossVerifier, approved: false } });
  assert.equal(declined.accepted, false, "independent verifier declined → additional gate not cleared");
  assert.equal(declined.agreement, false);
  assert.match(declined.reason, /DECLINED/);
});

test("XVERIFY (additive): a cross-family verifier can only ADD scrutiny, never lower the bar", () => {
  // deterministic pass + verifier declines → not accepted (bar raised, not lowered)
  const declined = crossFamilyVerify({ deterministicPass: true, author, verifier: { ...crossVerifier, approved: false } });
  assert.equal(declined.accepted, false);
  // deterministic fail + verifier approves → still not accepted (bar not lowered)
  const failOverride = crossFamilyVerify({ deterministicPass: false, author, verifier: { ...crossVerifier, approved: true } });
  assert.equal(failOverride.accepted, false);
});
