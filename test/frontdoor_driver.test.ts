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
import { PolicyEngine } from "../src/governance/policy_engine.js";

import { parseProposal } from "../src/frontdoor/proposal_parser.js";
import { SecretSafeIntake } from "../src/frontdoor/secret_intake.js";
import { PlanExecuteGate } from "../src/frontdoor/plan_execute_gate.js";
import { OnboardingConversation } from "../src/frontdoor/onboarding_conversation.js";
import { adaptiveProfileFor } from "../src/frontdoor/capability_adaptive.js";
import { localBrain, brainFromKey } from "../src/frontdoor/brain_port.js";
import { ConversationDriver, type BrainCall } from "../src/frontdoor/conversation_driver.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-f17-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}
function newMemory(spine: Spine): MemoryStore {
  return new MemoryStore(spine, new ModelGateway(new LocalProvider()));
}

// --- Parser ---

test("a valid action JSON parses into a typed action", () => {
  const o = parseProposal('{"action":"capture_goal","args":{"goal":"ship the api"},"rationale":"user asked"}');
  assert.equal(o.kind, "action");
  if (o.kind === "action") assert.equal(o.action.kind, "capture_goal");
});

test("a {reply:...} or bare prose parses as a reply", () => {
  assert.equal(parseProposal('{"reply":"Sure, what would you like to work on?"}').kind, "reply");
  assert.equal(parseProposal("Just a friendly sentence with no JSON.").kind, "reply");
});

test("an unknown action kind is invalid with a corrective clarification listing real actions", () => {
  const o = parseProposal('{"action":"rm_rf_everything","args":{}}');
  assert.equal(o.kind, "invalid");
  if (o.kind === "invalid") assert.ok(o.clarification.includes("capture_goal")); // tells the model what's allowed
});

test("malformed JSON and args-as-array are invalid", () => {
  assert.equal(parseProposal('{"action":"capture_goal", args:}').kind, "invalid");
  assert.equal(parseProposal('{"action":"capture_goal","args":[1,2,3]}').kind, "invalid");
});

test("JSON embedded in code fences / prose is still extracted", () => {
  const o = parseProposal('Here you go:\n```json\n{"action":"set_preference","args":{"tone":"brief"}}\n```\n');
  assert.equal(o.kind, "action");
});

// --- Driver keystone: end-to-end wiring ---

function buildDriver(brainCall: BrainCall, opts: { minimal?: boolean } = {}) {
  const spine = newSpine();
  const intake = new SecretSafeIntake(new CryptoShredKeyStore());
  const gate = new PlanExecuteGate(spine, new PolicyEngine("v1", []), async () => ({ safe: true }));
  const convo = new OnboardingConversation(newMemory(spine));
  const profile = opts.minimal
    ? adaptiveProfileFor(localBrain(), { lowResourceDeclared: true }) // minimal -> deterministic
    : adaptiveProfileFor(brainFromKey("sk-ant-x1234567890", { baseURL: "https://x/v1" }), { contextWindow: 1_000_000, costPerMTokUSD: 5 });
  return { driver: new ConversationDriver(intake, gate, convo, profile, brainCall), spine };
}

test("a valid capture_goal proposal flows through the gate and auto-approves", async () => {
  const brain: BrainCall = async () => '{"action":"capture_goal","args":{"goal":"ship api"},"rationale":"user asked"}';
  const { driver } = buildDriver(brain);
  const t = await driver.turn("I want to ship my API");
  assert.equal(t.source, "llm");
  assert.equal(t.gateDecision!.disposition, "auto-approved");
});

test("a secret in the message is captured (secretAck set) and never sent to the brain", async () => {
  let promptSeen = "";
  const brain: BrainCall = async (p) => { promptSeen = p; return '{"reply":"got it"}'; };
  const { driver } = buildDriver(brain);
  const t = await driver.turn("my key is sk-ant-supersecretvalue123456");
  assert.ok(t.secretAck.length > 0); // captured
  assert.ok(!promptSeen.includes("supersecretvalue123456")); // never reached the brain
});

test("a malformed reply triggers retry-with-clarification and recovers", async () => {
  let call = 0;
  const brain: BrainCall = async () => {
    call++;
    return call === 1 ? '{"action":"nonexistent_action"}' : '{"action":"capture_goal","args":{},"rationale":"ok"}';
  };
  const { driver } = buildDriver(brain);
  const t = await driver.turn("do the thing");
  assert.equal(call, 2); // retried once after the clarification
  assert.equal(t.gateDecision!.disposition, "auto-approved");
});

test("brain unavailable (null) falls back to the deterministic flow", async () => {
  const brain: BrainCall = async () => null; // fallback chain exhausted
  const { driver } = buildDriver(brain);
  const t = await driver.turn("hello");
  assert.equal(t.source, "llm-fallback-to-deterministic");
  assert.ok(t.say.length > 0); // deterministic flow produced a turn
});

test("minimal-tier profile uses the deterministic flow directly (no brain call)", async () => {
  let called = false;
  const brain: BrainCall = async () => { called = true; return "{}"; };
  const { driver } = buildDriver(brain, { minimal: true });
  const t = await driver.turn("hi there");
  assert.equal(called, false); // never called the brain
  assert.equal(t.source, "deterministic");
});

// --- The safety property survives integration ---

test("a destructive proposal is STILL human-gated end-to-end through the driver", async () => {
  const brain: BrainCall = async () => '{"action":"drop_database","args":{},"rationale":"clean slate"}';
  const { driver } = buildDriver(brain);
  const t = await driver.turn("wipe everything and start fresh");
  assert.equal(t.gateDecision!.disposition, "human-approval-required"); // gate held through the driver
});

test("repeated malformed output eventually falls back to deterministic (never loops forever)", async () => {
  const brain: BrainCall = async () => '{"action":"still_wrong"}'; // always invalid
  const { driver } = buildDriver(brain);
  const t = await driver.turn("go");
  assert.equal(t.source, "llm-fallback-to-deterministic"); // bounded retries -> fallback
});
