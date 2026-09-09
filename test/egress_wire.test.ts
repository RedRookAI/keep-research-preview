import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ProviderRouter, EgressBlockedError, type EgressFn } from "../src/gateway/provider_router.js";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../src/gateway/gateway.js";
import { interceptEgress } from "../src/privacy/egress_interceptor.js";
import { RedactionGateway } from "../src/privacy/redaction_gateway.js";
import { DataClassifier, type NerRecognizer } from "../src/ingest/data_classifier.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

const spine = () => new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-egw-"))), new InProcessLock(), new SchemaRegistry());

// a provider that records the prompt it received and can echo a surrogate back in its answer
class RecordingProvider implements ModelProvider {
  readonly name = "rec";
  lastPrompt = "";
  constructor(readonly isLocal: boolean, private readonly echo = false) {}
  async generate(req: GenerateRequest): Promise<GenerateResult> {
    this.lastPrompt = req.prompt;
    // echo mode: reply containing the first surrogate token so we can test rehydration
    const m = /\u27E6[^\u27E7]+\u27E7/.exec(req.prompt);
    const text = this.echo && m ? `done for ${m[0]}` : "ok";
    return { text, model: "rec", tokensIn: 1, tokensOut: 1 };
  }
  async embed(): Promise<Embedding[]> { return []; }
}

const classifier = new DataClassifier();
const egressFn = (policy = {}): EgressFn => (prompt, provider) =>
  interceptEgress(prompt, provider, { classifier, session: () => new RedactionGateway() }, policy);

function router(egress: EgressFn) {
  const r = new ProviderRouter(spine(), () => 1, { egress });
  return r;
}
const reg = (p: ModelProvider) => ({ id: "p1", tier: "standard" as const, costWeight: 1, provider: p });

test("R-EGRESS-WIRE (a): a REMOTE generate() sends a redacted prompt — raw PII never reaches the provider", async () => {
  const prov = new RecordingProvider(false);
  const r = router(egressFn()); r.register(reg(prov));
  await r.run({ prompt: "please email alice@corp.com about the invoice" });
  assert.ok(!prov.lastPrompt.includes("alice@corp.com"), "the provider received a redacted prompt");
  assert.match(prov.lastPrompt, /\u27E6email#\d+@v[a-z]+\u27E7/, "a per-call surrogate reached the provider instead");
});

test("R-EGRESS-WIRE (b): a LOCAL generate() is byte-identical (no redaction)", async () => {
  const prov = new RecordingProvider(true);
  const r = router(egressFn()); r.register(reg(prov));
  const original = "email alice@corp.com now";
  await r.run({ prompt: original });
  assert.equal(prov.lastPrompt, original, "a local provider receives the prompt byte-identical");
});

test("R-EGRESS-WIRE (c): the response is rehydrated before returning to the caller", async () => {
  const prov = new RecordingProvider(false, true); // echoes the surrogate
  const r = router(egressFn()); r.register(reg(prov));
  const out = await r.run({ prompt: "ping alice@corp.com" });
  assert.ok(out.result.text.includes("alice@corp.com"), "surrogate rehydrated to the real value in the answer");
  assert.ok(!out.result.text.includes("\u27E6"), "no surrogate token leaks to the caller");
});

test("R-EGRESS-WIRE (d): blockRecommended fails the call SAFE — nothing is sent", async () => {
  const uncertainNer: NerRecognizer = (t) => (/Acme/.test(t) ? [{ category: "org", start: t.indexOf("Acme"), end: t.indexOf("Acme") + 4, value: "Acme", confidence: 0.4, source: "ner" }] : []);
  const uncertain = new DataClassifier(uncertainNer);
  const blockingEgress: EgressFn = (p, prov) => interceptEgress(p, prov, { classifier: uncertain, session: () => new RedactionGateway() }, { highRisk: true });
  const prov = new RecordingProvider(false);
  const r = router(blockingEgress); r.register(reg(prov));
  await assert.rejects(() => r.run({ prompt: "deal with Acme" }), (e) => e instanceof EgressBlockedError, "high-risk + uncertain → EgressBlockedError");
  assert.equal(prov.lastPrompt, "", "the provider was never called — failed safe");
});

test("R-EGRESS-WIRE (e): a clean stable prefix reaches the provider byte-identical (cache preserved)", async () => {
  const prov = new RecordingProvider(false);
  // a rewrite that PREPENDS a marker to the volatile portion — if the split were wrong (whole prompt treated as
  // volatile), the marker would land before the prefix and churn the cacheable prefix.
  const rewritingEgress: EgressFn = (p, provider) =>
    interceptEgress(p, provider, { classifier, session: () => new RedactionGateway(), rewrite: (t) => "[R] " + t }, {});
  const r = router(rewritingEgress); r.register(reg(prov));
  const prefix = "SYSTEM: you are a careful engineer. ";
  const volatile = "fix bug for alice@corp.com";
  await r.run({ prompt: prefix + volatile, hints: { stablePrefixLen: prefix.length } });
  assert.ok(prov.lastPrompt.startsWith(prefix), "the clean stable prefix is byte-identical → prompt cache preserved");
  assert.ok(prov.lastPrompt.includes("[R] "), "the rewrite was applied to the volatile portion");
  assert.ok(!prov.lastPrompt.includes("alice@corp.com"), "the volatile portion was still redacted");
});

test("R-EGRESS-WIRE default: omitting an injected egress fn retains the safe remote privacy floor", async () => {
  const prov = new RecordingProvider(false);
  const r = new ProviderRouter(spine(), () => 1, {}); r.register(reg(prov));
  await r.run({ prompt: "email alice@corp.com" });
  assert.doesNotMatch(prov.lastPrompt, /alice@corp\.com/, "the default router never creates a remote privacy bypass");
  assert.match(prov.lastPrompt, /\u27E6email#\d+@v[a-z]+\u27E7/);
});
