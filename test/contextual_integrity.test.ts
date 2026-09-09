import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SensitiveContextVault,
  classifySpecialCategory,
  type VaultEntry,
} from "../src/privacy/contextual_integrity.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";

// CI sensitive-context vault: appropriate-flow-not-secrecy, default-deny egress, user-scoped, reveal-to-subject.
// BUILT: CI flow-control + user-scoping + reveal. SEAM: the special-category detector + the persistent store.

function vault(): SensitiveContextVault {
  const reg = new ProjectRegistry(new CryptoShredKeyStore());
  return new SensitiveContextVault(reg.namespace(reg.create("P").id));
}

test("special-category detection: a free-text health disclosure is caught and captured (the cancer case)", () => {
  assert.equal(classifySpecialCategory("I was diagnosed with cancer last week"), "health");
  const v = vault();
  const entry = v.capture("alice", "I was diagnosed with cancer last week");
  assert.ok(entry, "the disclosure is vaulted");
  assert.equal(entry?.informationType, "health");
});

test("data-minimization: general (non-special-category) text is NOT captured", () => {
  assert.equal(classifySpecialCategory("the deploy script needs a retry on timeout"), undefined);
  const v = vault();
  assert.equal(v.capture("alice", "the deploy script needs a retry on timeout"), undefined, "vault ignores general text");
});

test("CI default-deny (sole guard): in-context flow allowed; wrong recipient OR wrong purpose DENIED", () => {
  const v = vault();
  const e = v.capture("alice", "I have diabetes")!;
  assert.equal(v.mayFlow(e, { recipient: "alice", purpose: "assist-subject" }), true, "in-context use the subject asked for");
  assert.equal(v.mayFlow(e, { recipient: "bob", purpose: "assist-subject" }), false, "a teammate recipient is out of context");
  assert.equal(v.mayFlow(e, { recipient: "alice", purpose: "marketing" }), false, "a marketing purpose is out of context");
});

test("user-scoping + reveal: the subject reads their own context; another user in the same project gets nothing", () => {
  const v = vault();
  v.capture("alice", "I was diagnosed with cancer");
  const mine = v.revealToSubject("alice");
  assert.equal(mine.length, 1, "alice sees her own disclosure");
  assert.equal(mine[0]?.content, "I was diagnosed with cancer", "and it decrypts for her");
  assert.equal(v.revealToSubject("bob").length, 0, "bob (same project, different user) sees nothing");
});

test("least-privilege: an entry with no permitted recipients/purposes lets nothing flow", () => {
  const v = vault();
  const e = v.capture("alice", "I am living with HIV", { permittedRecipients: [], permittedPurposes: [] })!;
  assert.equal(v.mayFlow(e, { recipient: "alice", purpose: "assist-subject" }), false, "nothing flows without an explicit grant");
});

test("deterministic: the same entry + request resolve identically", () => {
  const v = vault();
  const e = v.capture("alice", "I have epilepsy")!;
  const req = { recipient: "alice", purpose: "assist-subject" };
  assert.equal(v.mayFlow(e, req), v.mayFlow(e, req));
});
