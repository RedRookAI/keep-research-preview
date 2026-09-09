import { test } from "node:test";
import assert from "node:assert/strict";

import { scanOutput } from "../src/privacy/output_filter.js";
import { interceptEgress } from "../src/privacy/egress_interceptor.js";
import { RedactionGateway } from "../src/privacy/redaction_gateway.js";
import { DataClassifier } from "../src/ingest/data_classifier.js";

const classifier = new DataClassifier();

test("LLM06 (a): a NOVEL secret in the output (not from the vault) is flagged", () => {
  const scan = scanOutput("here is the key AKIA1234567890ABCDEF for you", { classifier, authorizedValues: new Set() });
  assert.equal(scan.flagged, true, "a model-emitted AWS key is flagged");
  assert.ok(scan.novelByCategory["aws_access_key"]! >= 1);
});

test("LLM06 (b): our OWN rehydrated value is NOT flagged (authorized)", () => {
  // simulate: the model echoed back a value that WE rehydrated (it's in our vault) → authorized, not a leak
  const authorized = new Set(["alice@corp.com"]);
  const scan = scanOutput("done, emailed alice@corp.com as requested", { classifier, authorizedValues: authorized });
  assert.equal(scan.flagged, false, "an authorized (rehydrated) value is not a novel leak");
});

test("LLM06 (b2): a DIFFERENT email than ours IS flagged (cross-tenant leak)", () => {
  const authorized = new Set(["alice@corp.com"]);
  const scan = scanOutput("also here is bob@other-tenant.com", { classifier, authorizedValues: authorized });
  assert.equal(scan.flagged, true, "a different tenant's identifier is a novel leak");
});

test("LLM06 (c): under a high-assurance policy, a novel-secret hit BLOCKS the response", () => {
  const scan = scanOutput("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", { classifier, authorizedValues: new Set() }, { blockOnNovelSecret: true });
  assert.equal(scan.flagged, true);
  assert.equal(scan.blockRecommended, true, "high-assurance policy blocks");
  // without the policy, it's flagged but not blocked
  const flagOnly = scanOutput("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", { classifier, authorizedValues: new Set() });
  assert.equal(flagOnly.blockRecommended, false, "default policy flags but does not block");
});

test("LLM06 (d): a benign output (no secret) passes clean (no over-block)", () => {
  const scan = scanOutput("the build passed and all tests are green", { classifier, authorizedValues: new Set() }, { blockOnNovelSecret: true });
  assert.equal(scan.flagged, false, "benign output is not flagged");
  assert.equal(scan.blockRecommended, false);
});

test("LLM06 (e): the hit is recorded on the per-direction (inbound) audit — metadata only", () => {
  const events: Array<{ direction: string; perCategory: Record<string, number>; blocked: boolean }> = [];
  const scan = scanOutput("leak AKIA1234567890ABCDEF", { classifier, authorizedValues: new Set(), audit: (e) => events.push(e) }, { blockOnNovelSecret: true });
  assert.equal(scan.flagged, true);
  assert.equal(events.length, 1);
  assert.equal(events[0]!.direction, "inbound");
  assert.equal(events[0]!.blocked, true);
  assert.ok(events[0]!.perCategory["aws_access_key"]! >= 1);
  // metadata only — the audit event carries counts, never the real value
  assert.ok(!JSON.stringify(events[0]).includes("AKIA1234567890ABCDEF"), "the real secret value never hits the audit sink");
});

test("LLM06 wired: the interceptor's inspect() excludes our vault value but flags a novel one", () => {
  const eg = interceptEgress(
    { stablePrefix: "", volatile: "contact alice@corp.com" },
    { isLocal: false },
    { classifier, session: () => new RedactionGateway() },
  );
  // the response (rehydrated) echoes our authorized email + a novel AWS key
  const rehydrated = "emailed alice@corp.com; also AKIA1234567890ABCDEF";
  const scan = eg.inspect(rehydrated, { blockOnNovelSecret: true });
  assert.equal(scan.flagged, true, "the novel AWS key is flagged");
  assert.ok(!("email" in scan.novelByCategory), "our own rehydrated email is authorized, not flagged");
  assert.ok(scan.novelByCategory["aws_access_key"]! >= 1);
});
