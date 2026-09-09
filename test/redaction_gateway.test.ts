import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

import { RedactionGateway, type RedactionAuditEvent } from "../src/privacy/redaction_gateway.js";

test("embedding session preserves exact entity equality without cross-session/process names", () => {
  const a = new RedactionGateway({ reuseEntitiesWithinSession: true });
  const b = new RedactionGateway({ reuseEntitiesWithinSession: true });
  const email = "private.person@example.test", other = "other.person@example.test";
  const document = a.redact(`${email} ${email} ${other}`), query = a.redact(email);
  const tokens = document.redacted.match(/⟦[^⟧]+⟧/gu)!;
  assert.equal(tokens[0], tokens[1]); assert.notEqual(tokens[1], tokens[2]);
  assert.equal(query.redacted, tokens[0]); assert.equal(a.rehydrate(query.redacted), email);
  assert.notEqual(b.redact(email).redacted, query.redacted);
  assert.notEqual(a.representationIdentity, b.representationIdentity);
  const legacy = new RedactionGateway();
  assert.equal(legacy.representationIdentity, undefined);
  assert.notEqual(legacy.redact(email).redacted, legacy.redact(email).redacted);
  const script = `import { RedactionGateway } from ${JSON.stringify(new URL("../src/privacy/redaction_gateway.js", import.meta.url).href)};
    const g = new RedactionGateway({reuseEntitiesWithinSession:true}); console.log(JSON.stringify({identity:g.representationIdentity,text:g.redact(${JSON.stringify(email)}).redacted}));`;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8", timeout: 5000 });
  assert.equal(child.status, 0, child.stderr); const fresh = JSON.parse(child.stdout);
  assert.notEqual(fresh.identity, a.representationIdentity); assert.notEqual(fresh.text, query.redacted);
  assert.equal(document.tier, "pseudonymized"); assert.equal(document.reducesNotGuarantees, true);
});

test("H-1 SURROGATE: PII is surrogated then re-hydrated faithfully (round-trip)", () => {
  const g = new RedactionGateway();
  const r = g.redact("contact me at alice@example.com about it");
  assert.ok(!r.redacted.includes("alice@example.com"), "the email is surrogated out of the text");
  assert.ok(r.surrogateCount >= 1, "at least one surrogate created");
  assert.equal(g.rehydrate(r.redacted), "contact me at alice@example.com about it", "re-hydration restores the original");
});

test("H-1 EPHEMERAL VAULT: real values never reach the audit sink (only metadata)", () => {
  const audited: RedactionAuditEvent[] = [];
  const g = new RedactionGateway({}, { audit: (e) => audited.push(e) });
  g.redact("my ssn is 123-45-6789");
  const dump = JSON.stringify(audited);
  assert.ok(!dump.includes("123-45-6789"), "the real value never appears in what the audit sink received");
  assert.ok(audited.length === 1 && audited[0]!.surrogateCount >= 1, "the sink got metadata (counts/tier) only");
});

test("H-1 QUASI-ID: a quasi-identifier set crossing the threshold flags re-id risk + downgrades the tier", () => {
  const g = new RedactionGateway({ quasiIdThreshold: 2 }); // 2 distinct quasi-ids ⇒ risk
  g.redact("call 415-555-0100"); // phone (quasi-id 1)
  const r = g.redact("from host 10.0.0.5"); // ip_address (quasi-id 2) → crosses threshold
  assert.equal(r.reidentificationRisk, true, "the accumulated quasi-id set is over threshold");
  assert.equal(r.tier, "identifiable", "over-tolerance ⇒ NOT anonymized/pseudonymized");
});

test("H-1 HONEST TIER: surrogated text is pseudonymized (reversible), clean text is anonymized", () => {
  const g = new RedactionGateway();
  const withPii = g.redact("card 4111 1111 1111 1111"); // a direct identifier, surrogated
  assert.equal(withPii.tier, "pseudonymized", "surrogated (reversible) ⇒ pseudonymized, never anonymized");
  const clean = new RedactionGateway().redact("the quarterly plan looks solid");
  assert.equal(clean.tier, "anonymized", "no PII, no residual risk ⇒ anonymized");
});
