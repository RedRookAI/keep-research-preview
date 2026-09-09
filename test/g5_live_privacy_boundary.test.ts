import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { DataClassifier } from "../src/ingest/data_classifier.js";
import { DataGovernance } from "../src/ingest/data_governance.js";
import { ProviderRouter, EgressBlockedError, type EgressFn } from "../src/gateway/provider_router.js";
import type { Embedding, GenerateRequest, GenerateResult, ModelProvider } from "../src/gateway/gateway.js";
import { ResidencyEnforcer } from "../src/governance/residency.js";
import { RedactionGateway } from "../src/privacy/redaction_gateway.js";
import { interceptEgress } from "../src/privacy/egress_interceptor.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { mintProjectId } from "../src/session/project_id.js";

class Remote implements ModelProvider {
  readonly name = "remote"; readonly isLocal = false; calls = 0; lastPrompt = "";
  constructor(private readonly answer: string) {}
  async generate(req: GenerateRequest): Promise<GenerateResult> { this.calls++; this.lastPrompt = req.prompt; return { text: this.answer, model: "remote", tokensIn: 1, tokensOut: 1 }; }
  async embed(): Promise<Embedding[]> { return []; }
}

class StreamingRemote extends Remote {
  async generateStream(req: GenerateRequest, onDelta: (text: string) => void): Promise<GenerateResult> {
    this.calls++; this.lastPrompt = req.prompt;
    onDelta("leaked AKIA1234"); onDelta("567890ABCDEF");
    return { text: "leaked AKIA1234567890ABCDEF", model: "remote", tokensIn: 1, tokensOut: 1 };
  }
}

function setup(answer = "safe answer") {
  const governance = new DataGovernance();
  governance.register({ sourceId: "customer", projectId: mintProjectId(), contentHash: "h", sensitivityTier: "regulated", purpose: "support", lawfulBasis: "consent", handlingApplied: "tokenize" });
  const residency = new ResidencyEnforcer({ allowedRegions: ["eu"], egressAllowlist: ["eu.provider.test"] });
  const allowedContext = new Set(["health:1"]);
  const classifier = new DataClassifier();
  const egress: EgressFn = (prompt, provider) => interceptEgress(prompt, provider, {
    classifier, session: () => new RedactionGateway(),
    checkPurpose: (id, purpose) => governance.checkPurpose(id, purpose),
    checkResidency: (region, host) => residency.checkRequest(region, host),
    checkContextFlow: (id, recipient, purpose) => allowedContext.has(id) && recipient === "alice" && purpose === "support",
  });
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-g5-"))), new InProcessLock(), new SchemaRegistry());
  const router = new ProviderRouter(spine, () => 1, { egress });
  const provider = new Remote(answer);
  router.register({ id: "remote", tier: "standard", costWeight: 1, provider });
  return { router, provider };
}

const flow = { purpose: "support", region: "eu", host: "eu.provider.test", sourceIds: ["customer"], recipient: "alice", contextEntryIds: ["health:1"] };

test("G5 live boundary permits only purpose/residency/context-cleared egress and surrogates PII", async () => {
  const { router, provider } = setup();
  await router.run({ prompt: "email alice@example.com", hints: { egressFlow: flow } });
  assert.equal(provider.calls, 1);
  assert.ok(!provider.lastPrompt.includes("alice@example.com"));
  assert.match(provider.lastPrompt, /email#1/);
});

test("G5 live boundary fails before provider on wrong purpose, residency, or contextual recipient", async () => {
  for (const bad of [
    { ...flow, purpose: "marketing" },
    { ...flow, region: "us" },
    { ...flow, recipient: "bob" },
  ]) {
    const { router, provider } = setup();
    await assert.rejects(router.run({ prompt: "private", hints: { egressFlow: bad } }), EgressBlockedError);
    assert.equal(provider.calls, 0);
  }
});

test("G5 live output filter blocks a novel secret instead of delivering it", async () => {
  const { router, provider } = setup("leaked AKIA1234567890ABCDEF");
  await assert.rejects(router.run({ prompt: "safe", hints: { egressFlow: flow } }), EgressBlockedError);
  assert.equal(provider.calls, 1, "the response was produced but refused at the inbound boundary");
});

test("G5 streamed output is held until whole-response filtering passes", async () => {
  const { router } = setup();
  const provider = new StreamingRemote("unused");
  router.register({ id: "stream", tier: "minimal", costWeight: 0, provider });
  const delivered: string[] = [];
  await assert.rejects(router.runStream({ prompt: "safe", hints: { egressFlow: flow } }, (s) => delivered.push(s)), EgressBlockedError);
  assert.deepEqual(delivered, [], "no partial secret was delivered before the final filter verdict");
});

