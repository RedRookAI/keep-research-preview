import { test } from "node:test";
import assert from "node:assert/strict";

import { modelFirst, routeIntake, type IntakeItem } from "../src/intake/intake.js";
import { SensitiveContextVault } from "../src/privacy/contextual_integrity.js";
import { ProjectRegistry } from "../src/session/project_registry.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";

// Onboarding intake router: model-first + broad intake through the vault + graceful degradation. BUILT: ordering
// + routing + save-through-vault. SEAM: the per-format parsers. Verify by disproof.

function vault(): SensitiveContextVault {
  const reg = new ProjectRegistry(new CryptoShredKeyStore());
  return new SensitiveContextVault(reg.namespace(reg.create("P").id));
}

test("model choice FIRST: no provider ⇒ needs-model-choice, not project work", () => {
  const r = modelFirst({});
  assert.equal(r.ready, false);
  if (!r.ready) assert.equal(r.reason, "needs-model-choice");
  assert.equal(modelFirst({ provider: "api" }).ready, true, "a chosen provider ⇒ ready");
});

test("n=1-local needs no cloud; other providers do", () => {
  const local = modelFirst({ provider: "local" });
  assert.ok(local.ready && local.cloudRequired === false, "local ⇒ zero cloud dependency");
  const api = modelFirst({ provider: "openrouter" });
  assert.ok(api.ready && api.cloudRequired === true, "a cloud provider requires cloud");
});

test("save-through-the-vault (sole guard): a special-category intake is vaulted via upkeep", () => {
  const v = vault();
  const item: IntakeItem = { kind: "note", content: "I was diagnosed with cancer", subject: "alice" };
  const r = routeIntake(item, { vault: v });
  assert.equal(r.status, "ingested");
  if (r.status === "ingested") assert.equal(r.savedToVault, true, "the disclosure routed through the CI vault");
  assert.equal(v.revealToSubject("alice").length, 1, "and is captured there, subject-scoped");
});

test("unsupported type degrades gracefully — a typed result, never a throw", () => {
  let r: ReturnType<typeof routeIntake> | undefined;
  assert.doesNotThrow(() => { r = routeIntake({ kind: "exe", content: "MZ..." }); }, "no crash on an unsupported type");
  assert.equal(r?.status, "unsupported");
});

test("binary type routes to its parser (SEAM): with a parser it ingests; without one it degrades", () => {
  const withParser = routeIntake({ kind: "voice", content: "<audio>" }, { parser: () => "transcribed words" });
  assert.equal(withParser.status, "ingested", "a parser extracts text ⇒ ingested");
  const noParser = routeIntake({ kind: "voice", content: "<audio>" });
  assert.equal(noParser.status, "unsupported", "no parser ⇒ graceful degradation");
});

test("deterministic: same item + no vault ⇒ same result shape", () => {
  const item: IntakeItem = { kind: "text", content: "hello" };
  assert.deepEqual(routeIntake(item), routeIntake(item));
});
