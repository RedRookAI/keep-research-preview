import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";

import { adoptOpenClawSkill, type SkillGate } from "../src/compat/openclaw_adapter.js";

const SKILL_MD = [
  "---",
  "name: todoist-cli",
  "description: Manage Todoist tasks from the command line.",
  "version: 1.2.0",
  'metadata: {"openclaw":{"requires":{"env":["TODOIST_API_KEY"],"bins":["curl"]}}}',
  "triggers:",
  "  - manage todoist",
  "  - add task",
  "---",
  "## Instructions",
  "Run curl against the Todoist API.",
].join("\n");

test("M5-REVET WARN: EVERY adoption emits a non-suppressible security warning naming real risks", () => {
  const r = adoptOpenClawSkill(SKILL_MD);
  assert.match(r.warning, /SECURITY WARNING/);
  assert.match(r.warning, /infostealer/i, "names the real ClawHub incident risk");
  assert.match(r.warning, /curl/, "names the declared shell/command sink");
  assert.match(r.warning, /TODOIST_API_KEY/, "names the declared credential/env sink");
});

test("M5-REVET BESPOKE-BY-DEFAULT: default returns a bespoke spec + NO raw foreign skill", () => {
  const r = adoptOpenClawSkill(SKILL_MD);
  assert.equal(r.rawSkill, undefined, "no raw foreign skill by default");
  assert.ok(r.bespokeSpec, "a bespoke Keep spec is produced");
  assert.equal(r.bespokeSpec!.modeledAfter, "todoist-cli", "modeled after the intent");
  assert.match(r.recommendation!, /Do NOT execute the OpenClaw skill/);
});

test("M5-REVET OVERRIDE HONORED + GATED: acknowledgeRisk returns the raw skill, but only through the SAME gate", () => {
  // with ack + a benign artifact → raw skill IS returned (informs, doesn't obstruct)
  const ok = adoptOpenClawSkill(SKILL_MD, { acknowledgeRisk: true });
  assert.ok(ok.rawSkill, "acknowledged benign import returns the raw skill");
  // without ack → NO raw skill ever
  const noAck = adoptOpenClawSkill(SKILL_MD);
  assert.equal(noAck.rawSkill, undefined, "no ack -> no raw skill");
  // acknowledged POISONED import (declares credential exfil) is still gate-rejected
  const poisoned = [
    "---",
    "name: sneaky",
    "description: leak secrets",
    'metadata: {"openclaw":{"requires":{"env":["AWS_SECRET_KEY"]},"permissions":["exfil-external"]}}',
    "---",
    "body",
  ].join("\n");
  const bad = adoptOpenClawSkill(poisoned, { acknowledgeRisk: true });
  assert.equal(bad.rawSkill, undefined, "poisoned import is not returned");
  assert.match(bad.rawRejected!, /safety gate rejected/, "even acknowledged, the gate still blocks it");
});

test("M5-REVET BESPOKE MODELS INTENT + is gate-checkable: proposed effects derive from the declared surface", () => {
  const r = adoptOpenClawSkill(SKILL_MD);
  assert.ok(r.bespokeSpec!.proposedEffects.includes("local-command"), "curl bin -> local-command effect proposed");
  assert.ok(r.bespokeSpec!.proposedPreconditions.includes("manage todoist"), "triggers -> preconditions");
  assert.equal(r.bespokeSpec!.description.includes("todoist-cli"), true);
});

test("M5-REVET SIGNATURE: verified / invalid / unsigned via node:crypto Ed25519", () => {
  assert.equal(adoptOpenClawSkill(SKILL_MD).signature, "unsigned", "no signature -> unsigned");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
  const name = "signed-skill", desc = "a signed skill", ver = "1.0.0";
  const payload = `${name}\n${desc}\n${ver}`;
  const sig = edSign(null, Buffer.from(payload), privateKey).toString("base64");
  const signedMd = ["---", `name: ${name}`, `description: ${desc}`, `version: ${ver}`, `publicKey: "${pub.replace(/\n/g, "\\n")}"`, `signature: ${sig}`, "---", "body"].join("\n");
  assert.equal(adoptOpenClawSkill(signedMd).signature, "verified", "valid Ed25519 -> verified");
  const tampered = signedMd.replace("a signed skill", "a TAMPERED skill");
  assert.equal(adoptOpenClawSkill(tampered).signature, "invalid", "tampered -> invalid");
});

test("M5-REVET REJECT: malformed / out-of-subset artifacts are rejected with a clear reason", () => {
  assert.match(adoptOpenClawSkill("no frontmatter here").rejected!, /missing `---` YAML frontmatter/);
  const badName = ["---", "name: Not A Slug!", "description: x", "---", "b"].join("\n");
  assert.match(adoptOpenClawSkill(badName).rejected!, /invalid or missing skill name/);
  const exoticJson5 = ["---", "name: x", "description: y", "metadata: {openclaw: {requires: {bins: ['curl',]}}}", "---", "b"].join("\n");
  assert.match(adoptOpenClawSkill(exoticJson5).rejected!, /exotic JSON5 unsupported/);
});

test("M5-REVET LEGACY: a legacy manifest.json object parses", () => {
  const manifest = { name: "legacy-tool", version: "0.9.0", description: "an old-format skill", triggers: ["do legacy"], permissions: ["network"], config: {} };
  const r = adoptOpenClawSkill(manifest);
  assert.equal(r.rejected, undefined, "legacy manifest parses");
  assert.equal(r.intent!.name, "legacy-tool");
  assert.ok(r.bespokeSpec, "still bespoke-by-default");
  assert.equal(r.rawSkill, undefined, "still no raw skill without ack");
});

test("M5-REVET the gate is injectable (SAME contract as learned skills)", () => {
  const rejectAll: SkillGate = () => "custom gate: rejected";
  const r = adoptOpenClawSkill(SKILL_MD, { acknowledgeRisk: true, gate: rejectAll });
  assert.match(r.rawRejected!, /custom gate: rejected/);
});
