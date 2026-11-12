import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest, type GatewayRequest } from "../src/gateway/http_gateway.js";
import { captureTaskSkillGuidance } from "../src/loop/task_skill_guidance.js";
import { planEdits } from "../src/solve/edit_planner.js";
import type { ModelProvider } from "../src/gateway/gateway.js";
import { hashSkill, publishSkill } from "../src/registry/skill_registry.js";
import type { DistilledSkill } from "../src/loop/skill_distiller.js";
import type { Principal } from "../src/identity/rbac.js";

const TOKEN = "owned-skill-recovery-fixture";
const request = (method: string, path: string, body?: unknown): GatewayRequest => ({ method, path, query: {}, headers: { authorization: `Bearer ${TOKEN}` }, body: body === undefined ? "" : JSON.stringify(body) });
function skill(description: string): DistilledSkill {
  return { format: "keep.skill/v1", id: "fixture:recovery", name: "Recovery fixture", description,
    relevanceKey: "software-change", requiredAuthority: ["workspace:write"], confidence: "corroborated", provenance: ["owned-fixture"],
    envelope: { preconditions: ["local repository task"], postconditions: [], declaredEffects: ["local-edit"], steps: [{ action: description === "v1" ? "Replace broken with fixed" : "Replace broken with regressed", targetPattern: "{file}" }] } };
}

test("personal operator restores exact revalidated prior skill; restart retains the selected content and failure history", async t => {
  const root = mkdtempSync(join(tmpdir(), "keep-skill-http-"));t.after(() => rmSync(root, { recursive: true, force: true }));
  let regressed = false;
  const config = { dataDir: root, skillImportAuthorities: ["workspace:write"] as const,
    skillOracle: { runWithSkill: (candidate: DistilledSkill) => !(regressed && candidate.description === "v2"), runBaseline: () => false } };
  let app = composeKeep(config);
  const v1 = skill("v1"), v2 = skill("v2");
  const firstAdmission = await app.managedSkillRegistry.add(publishSkill(v1, "fixture", 1));
  assert.equal(firstAdmission.ok, true, JSON.stringify(firstAdmission));
  const originalToken = app.managedSkillRegistry.subjectToken(v1.id);
  const oldGuidance = captureTaskSkillGuidance(app.skillRetrieval, app.managedSkillRegistry, app.skillCanary, "software-change", () => true);
  assert.ok(oldGuidance);
  assert.equal((await app.managedSkillRegistry.add(publishSkill(v2, "fixture", 2))).ok, true);
  app.managedSkillRegistry.recordOutcome({ solveId: "failed-v2", taskShape: "software-change", testsPassed: false, mergeVerdict: "rejected", activeArtifacts: [v2.id], timestamp: 3 });
  regressed = true;
  const historyRequest = { ...request("GET", "/skill/versions"), query: { skillId: v2.id } };
  const before = await handleGatewayRequest(app, historyRequest, { token: TOKEN }); assert.equal(before.status, 200);
  const metadata = JSON.parse(before.body);
  assert.equal(metadata.subjectToken, app.managedSkillRegistry.subjectToken(v2.id));
  assert.ok(!before.body.includes('"envelope"'), "operator history contains metadata, not raw guidance");
  const restore = { skillId: v2.id, failedContentHash: hashSkill(v2), previousContentHash: hashSkill(v1), expectedSubjectToken: metadata.subjectToken };
  const stale = await handleGatewayRequest(app, request("POST", "/skill/restore", { ...restore, expectedSubjectToken: originalToken }), { token: TOKEN });
  assert.equal(stale.status, 409);
  const restored = await handleGatewayRequest(app, request("POST", "/skill/restore", restore), { token: TOKEN });
  assert.equal(restored.status, 200, restored.body);
  assert.equal(JSON.parse(restored.body).contentHash, hashSkill(v1));
  assert.notEqual(app.managedSkillRegistry.subjectToken(v1.id), originalToken, "restoration cannot revive an old captured admission instance");
  assert.throws(() => oldGuidance.assertCurrent(), /no longer current/u);
  assert.equal(app.managedSkillRegistry.isEligible(v1), true);
  assert.equal(app.skillCanary.revision(v1.id), hashSkill(v1));
  assert.ok(app.skillRetrieval.retrieve({ taskShape: "software-change" }).some(r => hashSkill(r.skill) === hashSkill(v1)));
  assert.equal((await handleGatewayRequest(app, request("POST", "/skill/restore", restore), { token: TOKEN })).status, 409, "stale restore replay cannot select a different version");
  const currentToken = app.managedSkillRegistry.subjectToken(v1.id);
  app = composeKeep(config);
  assert.equal(app.managedSkillRegistry.isEligible(v1), true);
  assert.equal(app.managedSkillRegistry.subjectToken(v1.id), currentToken, "unchanged restart preserves the current admission instance");
  const after = await handleGatewayRequest(app, historyRequest, { token: TOKEN });
  assert.match(after.body, /failed-v2/u);
  const restoredGuidance = captureTaskSkillGuidance(app.skillRetrieval, app.managedSkillRegistry, app.skillCanary, "software-change", () => true);
  assert.ok(restoredGuidance);
  let observedPrompt = "";
  const model: ModelProvider = { name: "controlled-restored-consumer", isLocal: true, embed: async () => [], generate: async request => {
    observedPrompt = request.prompt;
    request.assertAuthority?.();
    const good = request.prompt.includes("Replace broken with fixed") && request.prompt.includes(hashSkill(v1));
    return { model: "controlled-restored-consumer", tokensIn: 10, tokensOut: 10,
      text: JSON.stringify({ action: "plan", rationale: "Consume the current restored advice", edits: [{ file: "value.txt", search: "broken", replace: good ? "fixed" : "regressed", intent: "repair" }] }) };
  } };
  const plan = await planEdits({ id: "restored-task", text: "Repair broken value", repoRef: "owned" },
    { suspects: [{ path: "value.txt", score: 1, isTest: false }], stages: ["bm25"] }, [{ path: "value.txt", content: "broken" }], model,
    { skillGuidance: restoredGuidance, maxModelCalls: 1 });
  assert.equal(plan.edits[0]?.replace, "fixed", "actual planner consumes restored guidance, not a rollback label");
  assert.ok(observedPrompt.includes(hashSkill(v1)) && !observedPrompt.includes(hashSkill(v2)));
  const forget = (contentHash: string) => handleGatewayRequest(app, request("POST", "/skill/forget-version", {
    skillId: v1.id, contentHash, expectedSubjectToken: app.managedSkillRegistry.subjectToken(v1.id),
  }), { token: TOKEN });
  assert.equal((await forget(hashSkill(v1))).status, 409, "history erasure cannot remove selected content");
  assert.equal((await forget(hashSkill(v2))).status, 200);
  assert.ok(!readFileSync(join(root, "skill-registry", "default.json"), "utf8").includes("Replace broken with regressed"), "forgotten archived body is absent from current persistence");
  app = composeKeep(config);
  const forgotten = JSON.parse((await handleGatewayRequest(app, historyRequest, { token: TOKEN })).body);
  assert.ok(forgotten.forgottenVersionHashes.includes(hashSkill(v2)));


});

test("restoration metadata/mutation refuses agent, viewer and tenant access to the personal registry", async t => {
  const root = mkdtempSync(join(tmpdir(), "keep-skill-http-refusal-"));t.after(() => rmSync(root, { recursive: true, force: true }));
  const app = composeKeep({ dataDir: root });
  const principals: Principal[] = [
    { kind: "agent", id: "agent", role: "owner" },
    { kind: "human", id: "viewer", role: "viewer" },
    { kind: "human", id: "tenant-owner", role: "owner", tenant: "another-tenant" },
  ];
  for (const principal of principals) {
    const sec = { token: TOKEN, principalFor: () => principal };
    assert.equal((await handleGatewayRequest(app, { ...request("GET", "/skill/versions"), query: { skillId: "private" } }, sec)).status, 403);
    assert.equal((await handleGatewayRequest(app, request("POST", "/skill/restore", {}), sec)).status, 403);
    assert.equal((await handleGatewayRequest(app, request("POST", "/skill/forget-version", {}), sec)).status, 403);
  }
  const invalid = await handleGatewayRequest(app, request("POST", "/skill/restore", { skillId: "private", failedContentHash: "a".repeat(64), previousContentHash: "b".repeat(64), expectedSubjectToken: "c".repeat(64), force: true }), { token: TOKEN });
  assert.equal(invalid.status, 400);
  const unauthenticated = { ...request("GET", "/skill/versions"), headers: {} };
  assert.equal((await handleGatewayRequest(app, unauthenticated, { token: TOKEN })).status, 401);
});
