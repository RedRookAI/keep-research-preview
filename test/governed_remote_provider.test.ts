import { test } from "node:test";
import assert from "node:assert/strict";

import type { Embedding, GenerateRequest, GenerateResult, ModelProvider } from "../src/gateway/gateway.js";
import { EgressDeniedError } from "../src/gateway/brokered_egress.js";
import { GovernedRemoteProvider, type RemoteProcessingDeclaration } from "../src/gateway/governed_remote_provider.js";
import { ResidencyEnforcer, type ResidencyPolicy } from "../src/governance/residency.js";
import { DataClassifier } from "../src/ingest/data_classifier.js";
import { interceptEgress } from "../src/privacy/egress_interceptor.js";
import { RedactionGateway } from "../src/privacy/redaction_gateway.js";
import type { BoundedEmbeddingOptions } from "../src/gateway/http_provider.js";

test("bounded private representations pin document/query identity and retain policy refusal", async () => {
  const sent: string[][] = [];
  const inner: ModelProvider = { name: "private-representation-fixture", isLocal: false,
    async generate() { throw new Error("not generation"); }, async embed() { throw new Error("not legacy"); },
    async embedBounded(texts) { sent.push([...texts]); return { vectors: texts.map(() => [1, 0]), reserved: {requests:0,inputBytes:0,windows:0}, dispatched:{requests:0,inputBytes:0,windows:0} }; } };
  const session = new RedactionGateway({ reuseEntitiesWithinSession: true }), identity = session.representationIdentity!;
  let tag: string | undefined = identity;
  const provider = new GovernedRemoteProvider(inner, new ResidencyEnforcer({ allowedRegions:["eu"], egressAllowlist:["private.models.test"], allowedPurposes:["memory-query","memory-document"] }),
    "private.models.test", undefined, (prompt, remote) => ({ ...interceptEgress(prompt, remote, {classifier:new DataClassifier(),session:()=>session}), ...(tag === undefined ? {} : {representationIdentity:tag}) }),
    () => ({allowed:true}), {query:{purpose:"memory-query",region:"eu"},document:{purpose:"memory-document",region:"eu"}}, identity);
  const options: BoundedEmbeddingOptions = { role:"document", reserve:async()=>{throw new Error("inner probe has no HTTP/budget");} };
  const email = "secret.person@example.test";
  await provider.embedBounded([`passage: contact ${email}`], options);
  await provider.embedBounded([`query: contact ${email}`], {...options,role:"query"});
  assert.ok(!JSON.stringify(sent).includes(email));
  assert.equal(sent[0]![0]!.match(/⟦[^⟧]+⟧/u)![0], sent[1]![0]!.match(/⟦[^⟧]+⟧/u)![0]);
  tag = new RedactionGateway({reuseEntitiesWithinSession:true}).representationIdentity!;
  await assert.rejects(provider.embedBounded(["unchanged text"], options), /transformation identity changed/u);
  tag = undefined;
  await assert.rejects(provider.embedBounded([email], options), /transformation identity changed/u);
  assert.equal(sent.length, 2);
  tag = identity;
  const { role: _role, ...withoutRole } = options;
  await assert.rejects(provider.embedBounded([email], withoutRole), /explicit query\/document/u);
  assert.equal(sent.length, 2);
});

class CountingRemoteProvider implements ModelProvider {
  readonly name = "counting-remote";
  readonly isLocal = false;
  generateCalls = 0;
  embedCalls = 0;
  lastGeneratePrompt = "";
  lastEmbedTexts: readonly string[] = [];
  responseText = "ok";
  echoPrompt = false;

  async generate(req: GenerateRequest): Promise<GenerateResult> {
    this.generateCalls += 1;
    this.lastGeneratePrompt = req.prompt;
    return { text: this.echoPrompt ? `reply to ${req.prompt.match(/⟦[^⟧]+⟧/)?.[0] ?? "none"}` : this.responseText, model: "test", tokensIn: 1, tokensOut: 1 };
  }

  async embed(texts: readonly string[]): Promise<Embedding[]> {
    this.embedCalls += 1;
    this.lastEmbedTexts = texts;
    return texts.map(() => [1, 0]);
  }
}

const allowedPolicy: ResidencyPolicy = {
  allowedPurposes: ["code-assistance"],
  allowedRegions: ["eu"],
  egressAllowlist: ["private.models.test"],
};

function governed(
  inner: CountingRemoteProvider,
  declaration: RemoteProcessingDeclaration | undefined,
  host = "private.models.test",
  policy = allowedPolicy,
  defenseGate: (operation: "provider.generate" | "provider.embed", context: Readonly<Record<string, string>>) => { readonly allowed: boolean; readonly reason?: string } = () => ({ allowed: true }),
): GovernedRemoteProvider {
  const classifier = new DataClassifier();
  return new GovernedRemoteProvider(
    inner,
    new ResidencyEnforcer(policy),
    host,
    declaration,
    (prompt, provider) => interceptEgress(prompt, provider, { classifier, session: () => new RedactionGateway() }),
    defenseGate,
  );
}

test("remote generate and embedding dispatch only after purpose, region, and destination all pass", async () => {
  const inner = new CountingRemoteProvider();
  const provider = governed(inner, { purpose: "code-assistance", region: "eu" });

  assert.equal((await provider.generate({ prompt: "work" })).text, "ok");
  assert.deepEqual(await provider.embed(["work"]), [[1, 0]]);
  assert.equal(inner.generateCalls, 1);
  assert.equal(inner.embedCalls, 1);
});

test("every denied remote-processing declaration fails before underlying dispatch", async () => {
  const cases: readonly {
    name: string;
    declaration?: RemoteProcessingDeclaration;
    host?: string;
    policy?: ResidencyPolicy;
  }[] = [
    { name: "missing declaration" },
    { name: "undeclared purpose", declaration: { purpose: "training", region: "eu" } },
    { name: "disallowed region", declaration: { purpose: "code-assistance", region: "us" } },
    { name: "non-allowlisted destination", declaration: { purpose: "code-assistance", region: "eu" }, host: "other.models.test" },
    { name: "air gap", declaration: { purpose: "code-assistance", region: "eu" }, policy: { ...allowedPolicy, airGapped: true } },
  ];

  for (const c of cases) {
    const inner = new CountingRemoteProvider();
    const provider = governed(inner, c.declaration, c.host, c.policy);
    await assert.rejects(provider.generate({ prompt: "must not leave" }), EgressDeniedError, c.name);
    await assert.rejects(provider.embed(["must not leave"]), EgressDeniedError, c.name);
    assert.equal(inner.generateCalls, 0, `${c.name}: generate transport was not reached`);
    assert.equal(inner.embedCalls, 0, `${c.name}: embedding transport was not reached`);
  }
});

test("governance dependencies are runtime-private and the declaration is captured by value", async () => {
  const inner = new CountingRemoteProvider();
  const declaration = { purpose: "code-assistance", region: "eu" };
  const provider = governed(inner, declaration);

  assert.equal((provider as unknown as Record<string, unknown>).inner, undefined);
  assert.equal((provider as unknown as Record<string, unknown>).residency, undefined);
  declaration.purpose = "training";
  await provider.generate({ prompt: "captured declaration remains authorized" });
  assert.equal(inner.generateCalls, 1);
});

test("remote policy is snapshotted so later config mutation cannot expand dispatch authority", async () => {
  const inner = new CountingRemoteProvider();
  const purposes: string[] = [];
  const regions: string[] = ["eu"];
  const hosts: string[] = ["private.models.test"];
  const provider = governed(inner, { purpose: "code-assistance", region: "eu" }, "private.models.test", {
    allowedPurposes: purposes,
    allowedRegions: regions,
    egressAllowlist: hosts,
  });

  purposes.push("code-assistance");
  await assert.rejects(provider.generate({ prompt: "must remain denied" }), EgressDeniedError);
  assert.equal(inner.generateCalls, 0);
});

test("remote prompts and embedding inputs use per-call surrogates and matching responses restore locally", async () => {
  const inner = new CountingRemoteProvider();
  const provider = governed(inner, { purpose: "code-assistance", region: "eu" });

  await provider.generate({ prompt: "contact alice@example.com" });
  assert.doesNotMatch(inner.lastGeneratePrompt, /alice@example\.com/);
  assert.match(inner.lastGeneratePrompt, /⟦email#1@v[a-z]+⟧/);
  const firstCallToken = inner.lastGeneratePrompt.match(/⟦[^⟧]+⟧/)![0];

  inner.responseText = "reply to ⟦email#1@vzzzz⟧";
  const unmatched = await provider.generate({ prompt: "contact bob@example.com" });
  assert.equal(unmatched.text, inner.responseText, "a token outside this call's vault is never restored");

  inner.echoPrompt = true;
  const matching = await provider.generate({ prompt: "contact carol@example.com" });
  assert.equal(matching.text, "reply to carol@example.com");
  assert.notEqual(inner.lastGeneratePrompt.match(/⟦[^⟧]+⟧/)![0], firstCallToken, "calls cannot share a surrogate token");

  await provider.embed(["alice@example.com", "safe"]);
  assert.doesNotMatch(inner.lastEmbedTexts.join(" "), /alice@example\.com/);
  assert.match(inner.lastEmbedTexts[0]!, /⟦email#1@v[a-z]+⟧/);
});

test("buffered and streamed novel-secret output is withheld before any caller delivery", async () => {
  const inner = new CountingRemoteProvider();
  const provider = governed(inner, { purpose: "code-assistance", region: "eu" });
  inner.responseText = "leaked AKIA1234567890ABCDEF";

  await assert.rejects(provider.generate({ prompt: "safe" }), EgressDeniedError);
  const delivered: string[] = [];
  await assert.rejects(provider.generateStream({ prompt: "safe" }, (text) => delivered.push(text)), EgressDeniedError);
  assert.equal(delivered.length, 0, "no unsafe buffered or partial stream content was released");

  inner.responseText = "safe answer";
  const safe = await provider.generateStream({ prompt: "safe" }, (text) => delivered.push(text));
  assert.equal(safe.text, "safe answer");
  assert.deepEqual(delivered, ["safe answer"], "safe stream content is released only after the complete verdict");
});

test("an injected exact-scope defense gate blocks live remote dispatch without spreading to other operations", async () => {
  let active = true;
  const inner = new CountingRemoteProvider();
  const provider = governed(inner, { purpose: "code-assistance", region: "eu" }, "private.models.test", allowedPolicy, (operation, context) =>
    active && operation === "provider.generate" && context["host"] === "private.models.test"
      ? { allowed: false, reason: "observed provider failure" }
      : { allowed: true });
  await assert.rejects(provider.generate({ prompt: "safe" }), /observed provider failure/);
  assert.equal(inner.generateCalls, 0);
  await provider.embed(["safe"]);
  assert.equal(inner.embedCalls, 1, "the exact generate defense does not spread to embedding");
  active = false;
  await provider.generate({ prompt: "safe" });
  assert.equal(inner.generateCalls, 1, "removing the injected restriction restores dispatch");
});

test("a local provider cannot be mislabeled as governed remote transport", () => {
  const local: ModelProvider = {
    name: "local",
    isLocal: true,
    async generate() { return { text: "", model: "local", tokensIn: 0, tokensOut: 0 }; },
    async embed() { return []; },
  };
  assert.throws(
    () => new GovernedRemoteProvider(
      local,
      new ResidencyEnforcer(allowedPolicy),
      "private.models.test",
      { purpose: "code-assistance", region: "eu" },
      (prompt, provider) => interceptEgress(prompt, provider, { classifier: new DataClassifier(), session: () => new RedactionGateway() }),
      () => ({ allowed: true }),
    ),
    /requires a remote transport/,
  );
});
