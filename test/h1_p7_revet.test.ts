import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execSync } from "node:child_process";

import { RedactionGateway } from "../src/privacy/redaction_gateway.js";
import { DataClassifier, type NerRecognizer } from "../src/ingest/data_classifier.js";
import { globalScopeDisciplineCheck } from "../src/registry/tenant_registry.js";

// an NER stub that returns a LOW-confidence org finding (deterministic findings are always confidence 1)
const uncertainNer: NerRecognizer = (text) => (/Acme/.test(text) ? [{ category: "org", start: text.indexOf("Acme"), end: text.indexOf("Acme") + 4, value: "Acme", confidence: 0.4, source: "ner" }] : []);

test("H-1-REVET FAIL-SAFE (a): high-risk context + low-confidence finding → blockRecommended", () => {
  const gw = new RedactionGateway({ highRisk: true }, { ner: uncertainNer });
  const r = gw.redact("deal with Acme corp");
  assert.equal(r.blockRecommended, true);
  assert.match(r.reviewReason!, /review before egress/i);
});

test("H-1-REVET NO OVER-BLOCK (b): low-risk OR high-confidence does not block", () => {
  // high-risk but only a deterministic (confidence-1) finding → not uncertain → no block
  const highConf = new RedactionGateway({ highRisk: true }).redact("email alice@corp.com");
  assert.equal(highConf.blockRecommended, false, "a confident detection does not over-block");
  // low-risk context with an uncertain finding → still no block (not high-risk)
  const lowRisk = new RedactionGateway({}, { ner: uncertainNer }).redact("deal with Acme corp");
  assert.equal(lowRisk.blockRecommended, false, "low-risk context never fail-safe-blocks");
});

test("H-1-REVET REDUCES-NOT-GUARANTEES (c): the result never claims guaranteed anonymity", () => {
  const r = new RedactionGateway().redact("email alice@corp.com");
  assert.equal(r.reducesNotGuarantees, true, "honest scope marker present");
  // the tier vocabulary never contains a 'guaranteed' claim
  assert.ok(["anonymized", "pseudonymized", "identifiable"].includes(r.tier));
});

test("H-1-REVET QUASI-ID MONITOR (d): still fires at the threshold", () => {
  const gw = new RedactionGateway({ quasiIdThreshold: 2 });
  const r = gw.redact("ip 10.0.0.1 and phone 415-555-1212 and email x@y.com");
  assert.equal(r.reidentificationRisk, true, "quasi-id set over threshold → re-identification risk");
});

test("P-7-REVET CITATION GUARD (e): no 'brotcode' string remains anywhere in shipped src", () => {
  const hits = execSync("grep -rl brotcode src/ || true", { cwd: process.cwd() }).toString().trim();
  assert.equal(hits, "", `unverified 'brotcode' citation must be gone; found in: ${hits}`);
});

test("P-7-REVET PERSISTENT-SEAM (f): tenant docs assert RLS + per-tenant KEK requirement", () => {
  const doc = readFileSync("src/session/project_registry.ts", "utf8");
  assert.match(doc, /ROW-LEVEL SECURITY|RLS/, "docs must state DB-level RLS is required for the persistent seam");
  assert.match(doc, /per-tenant KEK/, "docs must state per-tenant KEK envelope encryption");
});

test("P-7-REVET GLOBAL-SCOPE DISCIPLINE (g): tenant-identifying content at global scope is flagged", () => {
  const flagged = globalScopeDisciplineCheck("contact alice@acme.com", "global");
  assert.equal(flagged.flagged, true, "identifying content at global scope is flagged");
  const projectOk = globalScopeDisciplineCheck("contact alice@acme.com", "project");
  assert.equal(projectOk.flagged, false, "same content project-scoped is fine");
  const cleanGlobal = globalScopeDisciplineCheck("a generic reusable coding lesson", "global");
  assert.equal(cleanGlobal.flagged, false, "non-identifying content is fine at global scope");
});
