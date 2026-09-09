import { test } from "node:test";
import assert from "node:assert/strict";

import { buildDefaultBrokeredEgress, EgressDeniedError } from "../src/gateway/brokered_egress.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import type { ModelProvider } from "../src/gateway/gateway.js";
import type { RestrictedReleaseRuntime } from "../src/graph/release_boot.js";

// A4 surface test. The broker/permit/owner mechanics have their own exhaustive suites; this file proves the public
// composition factory exposes no raw wrapper/owner constructor and refuses unadmitted remote construction.
const remote = (): ModelProvider => ({
  name: "unadmitted", isLocal: false,
  async generate() { throw new Error("must never execute"); },
  async embed() { throw new Error("must never execute"); },
});

test("brokered egress factory refuses every remote transport without an opaque installed-release admission", () => {
  assert.throws(() => buildDefaultBrokeredEgress(remote(), { write() {} }, { transportClass: "remote" }), (error) => error instanceof EgressDeniedError && /installed-release runtime authority/.test(error.message));
  const structurallyForged = { admission: {}, authority: {} } as unknown as RestrictedReleaseRuntime;
  assert.throws(() => buildDefaultBrokeredEgress(remote(), { write() {} }, { transportClass: "remote", releaseRuntime: structurallyForged }), (error) => error instanceof EgressDeniedError && /installed-release runtime authority/.test(error.message));
});

test("built-in local provider is wrapped without exporting a raw transport handle", async () => {
  const inner = new LocalProvider();
  const wrapped = buildDefaultBrokeredEgress(inner, { write() {} }, { transportClass: "local" });
  assert.notEqual(wrapped, inner);
  assert.equal(wrapped.isLocal, true);
  assert.equal((wrapped as unknown as Record<string, unknown>).inner, undefined);
  assert.equal((wrapped as unknown as Record<string, unknown>).deps, undefined);
  assert.match((await wrapped.generate({ prompt: "hello" })).text, /\[offline-fixture\]/);
});

test("broker permit identity preserves only the structured-output transport hint", async () => {
  let observedHints: Readonly<Record<string, unknown>> | undefined;
  const inner: ModelProvider = { name: "structured", isLocal: false, async generate(request) { observedHints = request.hints; return { text: "{}", model: "m", tokensIn: 1, tokensOut: 1 }; }, async embed() { return []; } };
  const wrapped = buildDefaultBrokeredEgress(inner, { write() {} }, { transportClass: "remote", ownerAuthority: true });
  await wrapped.generate({ prompt: "repository", hints: { structuredOutput: true, ambient: "must-not-cross" } });
  assert.deepEqual(observedHints, { structuredOutput: true });
});

test("owner egress binds privacy policy and rejects a returned route outside its allowlist", async () => {
  const policy = { zeroDataRetention: true, dataCollection: "deny" as const, allowFallbacks: false as const, providers: ["Admitted"] } as const;
  const inner: ModelProvider = { name: "aggregator", isLocal: false, async generate() { return { text: "x", model: "m", tokensIn: 1, tokensOut: 1, providerRoute: "Other" }; }, async embed() { return []; } };
  const wrapped = buildDefaultBrokeredEgress(inner, { write() {} }, { transportClass: "remote", ownerAuthority: true, externalRouting: policy });
  await assert.rejects(wrapped.generate({ prompt: "repository" }), /outside the admitted allowlist/u);
});
