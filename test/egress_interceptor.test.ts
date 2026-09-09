import { test } from "node:test";
import assert from "node:assert/strict";

import { interceptEgress, type EgressAuditEvent } from "../src/privacy/egress_interceptor.js";
import { RedactionGateway } from "../src/privacy/redaction_gateway.js";
import { DataClassifier, type NerRecognizer } from "../src/ingest/data_classifier.js";

const REMOTE = { isLocal: false };
const LOCAL = { isLocal: true };
const classifier = new DataClassifier();
const session = () => new RedactionGateway();

test("R-EGRESS REMOTE REDACT: PII+proprietary is redacted before send", () => {
  const r = interceptEgress({ stablePrefix: "SYSTEM: help.", volatile: " email me at alice@corp.com" }, REMOTE, { classifier, session });
  assert.equal(r.skipped, false);
  assert.ok(!r.outbound.includes("alice@corp.com"), "the email never appears in the outbound prompt");
  assert.ok(r.surrogateCount >= 1);
});

test("R-EGRESS LOCAL SKIP: a local provider is not redacted (nothing egresses)", () => {
  const r = interceptEgress({ stablePrefix: "SYSTEM: help.", volatile: " email alice@corp.com" }, LOCAL, { classifier, session });
  assert.equal(r.skipped, true, "local -> skipped");
  assert.equal(r.outbound, "SYSTEM: help. email alice@corp.com", "prompt sent unchanged (no needless work)");
});

test("R-EGRESS REHYDRATE: the response is rehydrated so the caller loses no context", () => {
  const r = interceptEgress({ stablePrefix: "SYSTEM.", volatile: " ping alice@corp.com" }, REMOTE, { classifier, session });
  // the model echoes the surrogate back; rehydrate restores the real value
  const surrogate = r.outbound.slice(r.outbound.indexOf("\u27E6"));
  assert.equal(r.rehydrate(`ok, I emailed ${surrogate}`), "ok, I emailed alice@corp.com", "surrogate restored on the response");
});

test("R-EGRESS AUDIT: real values never reach the audit sink (metadata only)", () => {
  const audited: EgressAuditEvent[] = [];
  interceptEgress({ stablePrefix: "S.", volatile: " ssn 123-45-6789" }, REMOTE, { classifier, session, audit: (e) => audited.push(e) });
  const dump = JSON.stringify(audited);
  assert.ok(!dump.includes("123-45-6789"), "real value never in the audit");
  assert.ok(audited[0]!.perCategory["ssn"] === 1, "per-entity metadata present");
});

test("R-EGRESS REJECT CONTEXT-DROP: a rewrite that drops task-necessary content is rejected", () => {
  const rewrite = (t: string) => t.replace("MUSTKEEP", ""); // drops required content
  const r = interceptEgress(
    { stablePrefix: "S.", volatile: " do the MUSTKEEP task" },
    REMOTE,
    { classifier, session, rewrite },
    { requiredContent: ["MUSTKEEP"] },
  );
  assert.ok(r.outbound.includes("MUSTKEEP"), "the context-dropping rewrite was rejected");
});

test("R-EGRESS PER-CALL VAULT: call A's surrogates never rehydrate into call B's response", () => {
  const a = interceptEgress({ stablePrefix: "S.", volatile: " alice@corp.com" }, REMOTE, { classifier, session });
  const b = interceptEgress({ stablePrefix: "S.", volatile: " bob@corp.com" }, REMOTE, { classifier, session });
  const aSurrogate = a.outbound.slice(a.outbound.indexOf("\u27E6"));
  // A's REAL value lives only in A's vault; B's vault never contains it, so B can never surface alice@corp.com.
  assert.ok(!b.rehydrate(aSurrogate).includes("alice@corp.com"), "A's real value never surfaces through B's isolated vault");
  assert.equal(a.rehydrate(aSurrogate), "alice@corp.com", "A's own vault restores A's value (sanity)");
});

test("R-EGRESS CACHE-PRESERVING: a clean stable prefix is left byte-identical (rewrite touches volatile only)", () => {
  const rewrite = (t: string) => t.replace(/SYSTEM/g, "SYS"); // would mutate the prefix if applied to the whole prompt
  const prefix = "SYSTEM: you are a careful engineer.";
  const r = interceptEgress({ stablePrefix: prefix, volatile: " fix the SYSTEM bug" }, REMOTE, { classifier, session, rewrite });
  assert.ok(r.outbound.startsWith(prefix), "the stable prefix is byte-identical -> cache preserved");
  assert.equal(r.cacheMissForced, false, "no forced prefix redaction for a clean prefix");
});

test("R-EGRESS FAIL-SAFE: high-risk path with low-confidence detection BLOCKS (never fail-open)", () => {
  const ner: NerRecognizer = (text) => (/Acme/.test(text) ? [{ category: "org", start: text.indexOf("Acme"), end: text.indexOf("Acme") + 4, value: "Acme", confidence: 0.4, source: "ner" }] : []);
  const uncertain = new DataClassifier(ner);
  const r = interceptEgress({ stablePrefix: "S.", volatile: " deal with Acme" }, REMOTE, { classifier: uncertain, session }, { highRisk: true });
  assert.equal(r.blocked, true, "uncertain detection in a high-risk path blocks");
  assert.equal(r.outbound, "", "nothing egresses when blocked (fail-safe)");
});
