import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { CryptoShredKeyStore } from "../src/keystore/keystore.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { MemoryStore } from "../src/memory/store.js";

import { SecretSafeIntake } from "../src/frontdoor/secret_intake.js";
import { OnboardingConversation } from "../src/frontdoor/onboarding_conversation.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-f1-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}
function newMemory(spine: Spine): MemoryStore {
  return new MemoryStore(spine, new ModelGateway(new LocalProvider()));
}

// --- Secret-safe intake ---

test("a pasted API key is removed from the safe text and captured to the keystore", () => {
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  const key = "sk-ant-abcdefghij1234567890KLMNOP";
  const r = intake.process(`here is my key ${key} thanks`);
  assert.ok(!r.safeText.includes(key)); // brain + spine never see the raw key
  assert.ok(r.safeText.includes("{{secret:cred_1}}")); // deterministic placeholder
  assert.equal(r.captured.length, 1);
  assert.equal(intake.resolve(r.captured[0]!.subject), key); // resolvable back for real use
});

test("intake acknowledgment is warm and jargon-free (never an error)", () => {
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  const r = intake.process("my key is sk-ant-abcdefghij1234567890KLMNOP");
  assert.ok(r.acknowledgment.length > 0);
  assert.ok(!/error|invalid|denied|fail/i.test(r.acknowledgment));
  assert.ok(/Anthropic/.test(r.acknowledgment));
});

test("a message with no secret passes through unchanged", () => {
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  const r = intake.process("I want to build a todo app");
  assert.equal(r.safeText, "I want to build a todo app");
  assert.equal(r.captured.length, 0);
  assert.equal(r.acknowledgment, "");
});

test("multiple secrets in one message are all captured and removed", () => {
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  const r = intake.process("openai sk-abcdefghij1234567890XYZ and github ghp_abcdefghij1234567890abcdefghij12");
  assert.ok(r.captured.length >= 2);
  assert.ok(!/sk-abcdefghij|ghp_abcdefghij/.test(r.safeText));
});

test("forget() crypto-shreds a captured secret (unrecoverable)", () => {
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  const r = intake.process("key sk-ant-abcdefghij1234567890KLMNOP");
  const subj = r.captured[0]!.subject;
  assert.ok(intake.resolve(subj));
  intake.forget(subj);
  assert.equal(intake.resolve(subj), undefined);
});

test("the raw key never appears anywhere in the safe text even if repeated", () => {
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  const key = "sk-ant-abcdefghij1234567890KLMNOP";
  const r = intake.process(`${key} ... and again ${key}`);
  assert.ok(!r.safeText.includes(key));
});

// --- Red-team fix: low-entropy human secrets (passwords/PINs/logins) that entropy misses ---

test("a labelled low-entropy password is captured (the 'email login' case)", () => {
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  const r = intake.process("my email is bob@example.com and password is MyDog2024");
  assert.ok(r.captured.length >= 1);
  assert.ok(!r.safeText.includes("MyDog2024")); // weak password removed before brain/spine
});

test("a spelled-out bearer token and a 'pwd:' value are captured despite low entropy", () => {
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  assert.ok(!intake.process("use bearer abc123def456ghi789").safeText.includes("abc123def456ghi789"));
  assert.ok(!intake.process("pwd: Summer2024!").safeText.includes("Summer2024!"));
});

test("label detector does NOT over-capture innocent phrases (no false positives)", () => {
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  for (const phrase of ["the token bucket algorithm is what I need", "the api key thing is confusing to me", "my password strategy needs work"]) {
    assert.equal(intake.process(phrase).captured.length, 0, `should not capture: ${phrase}`);
  }
});

// --- Onboarding conversation ---

test("name extraction handles the common phrasings a real human uses", async () => {
  for (const [said, expected] of [["I am Sam", "Sam"], ["I'm Alex", "Alex"], ["my name is Jordan", "Jordan"], ["Riley", "Riley"], ["it's Casey", "Casey"]] as const) {
    const convo = new OnboardingConversation(newMemory(newSpine()));
    await convo.next(said);
    assert.equal(convo.context.humanName, expected, `for "${said}"`);
  }
});

test("greeting is the exact opening line", () => {
  const convo = new OnboardingConversation(newMemory(newSpine()));
  assert.equal(convo.greeting().say, "Hi! What can I call you?");
});

test("conversation runs name -> ai-name -> goal, one question per turn", async () => {
  const convo = new OnboardingConversation(newMemory(newSpine()));
  const t1 = await convo.next("I'm Alex");
  assert.ok(t1.say.includes("Alex"));
  assert.equal(t1.awaiting, "ask-ai-name");
  const t2 = await convo.next("call you Ada");
  assert.ok(t2.say.includes("Ada"));
  assert.equal(t2.awaiting, "ask-goal");
  assert.equal(convo.context.humanName, "Alex");
  assert.equal(convo.context.aiName, "Ada"); // exact extraction, not the whole phrase
});

test("a vague goal triggers exactly ONE clarifying question, then proceeds (no loop)", async () => {
  const convo = new OnboardingConversation(newMemory(newSpine()));
  await convo.next("Alex");
  await convo.next("Ada");
  const t = await convo.next("build something"); // vague
  assert.equal(t.awaiting, "clarify-goal");
  const t2 = await convo.next("a new website for my bakery");
  assert.equal(t2.awaiting, "ask-channel"); // moved on, did not loop
});

test("a specific goal skips clarification", async () => {
  const convo = new OnboardingConversation(newMemory(newSpine()));
  await convo.next("Alex");
  await convo.next("Ada");
  const t = await convo.next("add retry-with-backoff to the payments client in the api repo");
  assert.equal(t.awaiting, "ask-channel"); // specific enough, no clarify step
});

test("directives are captured as probation memory items (external origin, must earn trust)", async () => {
  const spine = newSpine();
  const memory = newMemory(spine);
  const convo = new OnboardingConversation(memory);
  await convo.next("Alex");
  await convo.next("Ada");
  await convo.next("fix the broken login flow");
  assert.ok(convo.capturedDirectives.some((d) => d.text.startsWith("Goal:")));
  // The directive is stored but NOT confirmed (it must earn trust before configuring anything).
  const directive = convo.capturedDirectives.find((d) => d.lessonId);
  assert.ok(directive);
});

test("channel + email are captured and the closing line names the human", async () => {
  const convo = new OnboardingConversation(newMemory(newSpine()));
  await convo.next("Alex");
  await convo.next("Ada");
  await convo.next("add retry-with-backoff to the payments client");
  const chan = await convo.next("Slack please");
  assert.equal(chan.awaiting, "ask-email");
  assert.equal(convo.context.desiredChannel, "slack");
  const done = await convo.next("yes");
  assert.equal(done.done, true);
  assert.equal(convo.context.wantsEmail, true);
  assert.ok(done.say.includes("Alex"));
});
