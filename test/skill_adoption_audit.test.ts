import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SkillDistiller, type SolveTrajectory } from "../src/loop/skill_distiller.js";
import { adoptOpenClawSkill } from "../src/compat/openclaw_adapter.js";
import { composeKeep } from "../src/compose.js";
import { handleGatewayRequest } from "../src/gateway/http_gateway.js";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
function document(extra: readonly string[] = [], permissions: readonly string[] = ["file-write"], body = "SYNTHETIC BODY: update supplied notes.") {
  return ["---", "name: local-notes", "description: Synthetic notes.", "version: 1.0",
    `metadata: ${JSON.stringify({ openclaw: { requires: { bins: [], env: [], os: ["linux"] }, permissions } })}`,
    "triggers:", "  - maintain notes", ...extra, "---", body].join("\n");
}
const trajectory = (solveId: string, effect: string, requiredAuthority: SolveTrajectory["requiredAuthority"] = ["workspace:write"]): SolveTrajectory => ({
  solveId, taskShape: "numeric-repair", succeeded: true, requiredAuthority,
  steps: [{ action: "edit", target: `${solveId}.mjs`, effect }],
});

test("KEEP-06C-001 a later effect on a retained action cannot disappear when source order changes", () => {
  const safe = trajectory("safe", "modifies repository files");
  const forbidden = trajectory("later", "external-send", ["workspace:read", "workspace:write"]);
  for (const traces of [[safe, forbidden], [forbidden, safe]]) {
    const result = new SkillDistiller().distill(traces);
    assert.equal(result.skill, undefined);
    assert.match(result.rejected ?? "", /forbidden/);
  }
  const other = trajectory("other", "records a local observation", ["workspace:read"]);
  for (const traces of [[safe, other], [other, safe]]) {
    const result = new SkillDistiller().distill(traces);
    assert.ok(result.skill);
    assert.deepEqual([...result.skill.envelope.declaredEffects].sort(), ["modifies repository files", "records a local observation"].sort());
    assert.deepEqual([...result.skill.requiredAuthority].sort(), ["workspace:read", "workspace:write"]);
    assert.deepEqual([...result.skill.provenance].sort(), ["other", "safe"]);
  }
});

test("KEEP-06C-002 acknowledged static package retains the specification's file-write requirement", async () => {
  const root = mkdtempSync(join(tmpdir(), "keep-adoption-write-"));
  let executionCalls = 0;
  const app = composeKeep({ dataDir: root, skillOracle: { runBaseline: () => { executionCalls++; return false; }, runWithSkill: () => { executionCalls++; return false; } } });
  const proposed = adoptOpenClawSkill(document());
  assert.ok(proposed.bespokeSpec?.proposedEffects.includes("file-write"));
  const response = await handleGatewayRequest(app, { method: "POST", path: "/skill/adopt-openclaw", query: {},
    headers: { authorization: "Bearer synthetic-adoption-owner" }, body: JSON.stringify({ skill: document(), acknowledgeRisk: true }) }, { token: "synthetic-adoption-owner" });
  assert.equal(response.status, 200);
  assert.equal(JSON.parse(response.body).adopted, true);
  const stored = app.registryStore!.get("openclaw:local-notes")!;
  assert.ok(stored.skill.envelope.declaredEffects.includes("file-write"));
  assert.deepEqual(stored.skill.requiredAuthority, ["workspace:write"]);
  assert.deepEqual(stored.skill.envelope.steps, []);
  assert.deepEqual(app.skillRetrieval.retrieve({ taskShape: "maintain notes" }), []);
  assert.equal(app.managedSkillRegistry.lifecycle(stored.skill.id), undefined);
  assert.equal(app.skillCanary.state(stored.skill.id), undefined);
  assert.equal(executionCalls, 0);
});

test("KEEP-06C-003 forbidden flow and block permissions never become an empty accepted declaration", () => {
  const base = document([], []).split("\n").filter(line => !line.startsWith("metadata:")).join("\n");
  for (const permission of ["permissions: [external-send]", "permissions:\n  - external-send", 'permissions: ["external-send"]']) {
    const result = adoptOpenClawSkill(base.replace("\n---\n", `\n${permission}\n---\n`), { acknowledgeRisk: true });
    assert.equal(result.rawSkill, undefined, permission);
    assert.ok(result.rejected || result.rawRejected);
  }
  assert.ok(adoptOpenClawSkill(document(), { acknowledgeRisk: true }).rawSkill);
});

test("KEEP-06C-004 signature reports triplet-only validity and an untrusted embedded signer", () => {
  const keys = generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  const signature = sign(null, Buffer.from("local-notes\nSynthetic notes.\n1.0"), keys.privateKey).toString("base64");
  const signed = document([`publicKey: "${publicKey.replace(/\n/g, "\\n")}"`, `signature: ${signature}`]);
  for (const text of [signed, signed.replace("SYNTHETIC BODY", "CHANGED BODY"), signed.replace('"file-write"', '"network"').replace("maintain notes", "changed trigger")]) {
    const result = adoptOpenClawSkill(text, { acknowledgeRisk: true });
    assert.equal(result.signature, "verified-intent-fields");
    // Kept structurally local so the failing-before test can compile against the original API.
    const info = (result as unknown as { signatureInfo: { coveredFields: string[]; signerTrust: string; sourceSha256: string; signerSpkiSha256: string; uncoveredFields: string[] } }).signatureInfo;
    assert.deepEqual(info.coveredFields, ["name", "description", "version"]);
    assert.equal(info.signerTrust, "untrusted-embedded-key");
    assert.equal(info.sourceSha256, sha(text));
    assert.equal(info.signerSpkiSha256, createHash("sha256").update(keys.publicKey.export({ type: "spki", format: "der" })).digest("hex"));
    assert.ok(info.uncoveredFields.includes("body"));
    assert.ok(info.uncoveredFields.includes("permissions"));
    assert.match(result.warning, /untrusted|not established/i);
    assert.ok(result.rawSkill?.provenance.includes(`source-sha256:${sha(text)}`));
  }
  assert.equal(adoptOpenClawSkill(signed.replace("Synthetic notes.", "Changed notes.")).signature, "invalid");
});

test("extraction exposes omitted action scope and repeated actions cannot hide an effect", () => {
  const safe = trajectory("safe", "modifies repository files");
  const repeated = { ...trajectory("repeated", "modifies repository files"), steps: [
    ...safe.steps, { action: "edit", target: "another.mjs", effect: "external-send" },
  ] };
  for (const traces of [[safe, repeated], [repeated, safe]]) assert.equal(new SkillDistiller().distill(traces).skill, undefined);
  const omitted = { ...trajectory("other", "modifies repository files"), steps: [...safe.steps, { action: "send", target: "sink", effect: "external-send" }] };
  const result = new SkillDistiller().distill([safe, omitted]);
  assert.ok(result.skill, "a distinct omitted action is not part of the extracted candidate");
  assert.deepEqual(result.extraction?.retainedActions, ["edit"]);
  assert.equal(result.extraction?.omittedSourceSteps, 1);
  assert.equal(result.extraction?.distinctSourceSolves, 2);
  const duplicate = new SkillDistiller().distill([safe, safe]);
  assert.equal(duplicate.skill?.confidence, "low");
  assert.deepEqual(duplicate.skill?.provenance, ["safe"]);
  const collapsed = new SkillDistiller().distill([{ ...safe, steps: [{ action: "read", target: "input.mjs" }, { action: "write", target: "output.mjs" }] }]);
  assert.equal(collapsed.extraction?.collapsedTargetSlots, true);
  assert.deepEqual(collapsed.skill?.envelope.parameters, [{ name: "file", type: "string", required: true }], "file is one shared envelope parameter, not one slot per action");
  assert.deepEqual(collapsed.skill?.envelope.steps.map(s => s.targetPattern), ["{file}", "{file}"]);
  const shared = new SkillDistiller().distill([{ ...safe, steps: [{ action: "read", target: "same.mjs" }, { action: "write", target: "same.mjs" }] }]);
  assert.equal(shared.extraction?.collapsedTargetSlots, false, "one target reused by two actions loses no distinct-target relation");
});

test("malformed consumed declarations reject the entire authenticated catalog operation", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-adoption-parse-")) });
  const metadata = (value: unknown) => document().replace(/^metadata:.*$/m, `metadata: ${JSON.stringify(value)}`);
  const inputs: (string | Record<string, unknown>)[] = [
    document(["permissions: external-send"]),
    document(["permissions: [external-send]"]),
    document(["permissions:", "  - external-send", "permissions: []"]),
    document(["signature: fake", "signature: other"]),
    document(["  permissions: external-send"]),
    document().replace(/^metadata:.*$/m, 'metadata: {"openclaw":{"permissions":["external-send"],"permissions":[]}}'),
    document().replace(/^metadata:.*$/m, "metadata: {openclaw: {permissions: ['external-send']}}"),
    metadata({ openclaw: { permissions: ["file-write", 7] } }),
    metadata({ openclaw: { permissions: "external-send" } }),
    metadata({ openclaw: { permissions: { "external-send": "false" } } }),
    metadata({ openclaw: { permissions: null } }),
    metadata({ openclaw: { requires: { bins: "curl" } } }),
    metadata({ openclaw: { requires: null } }),
    metadata({ openclaw: [] }),
    { name: "legacy", permissions: "external-send" },
    { name: "legacy", permissions: ["file-write", { hidden: "external-send" }] },
    { name: "legacy", triggers: "hidden" },
  ];
  for (const input of inputs) {
    const response = await handleGatewayRequest(app, { method: "POST", path: "/skill/adopt-openclaw", query: {}, headers: { authorization: "Bearer parser-owner" },
      body: JSON.stringify({ skill: input, acknowledgeRisk: true }) }, { token: "parser-owner" });
    const body = JSON.parse(response.body);
    assert.equal(response.status, 422, JSON.stringify(input));
    assert.equal(body.signature, "not-checked");
    assert.ok(body.reason);
    assert.deepEqual(app.registryStore!.list(), []);
    assert.deepEqual(app.managedSkillRegistry.activePackages(), []);
  }
});

test("supported lists share one spec/package mapping; unknown declarations remain inspectable", () => {
  const mixed = document().replace(/^metadata:.*$/m, 'metadata: {"openclaw":{"requires":{"bins":["synthetic-bin"]},"permissions":["file-write","file-read","network","mystery-access"]}}');
  const result = adoptOpenClawSkill(mixed, { acknowledgeRisk: true });
  assert.ok(result.rawSkill);
  assert.deepEqual(result.rawSkill.envelope.declaredEffects, result.bespokeSpec?.proposedEffects);
  for (const effect of ["file-write", "file-read", "network-read", "local-command", "declared-permission:mystery-access"]) assert.ok(result.rawSkill.envelope.declaredEffects.includes(effect));
  assert.deepEqual([...result.rawSkill.requiredAuthority].sort(), ["sandbox:execute", "workspace:read", "workspace:write"]);
  assert.ok(result.unsupported.some(s => s.includes("mystery-access")));
  assert.ok(result.unsupported.some(s => s.includes("permission:network") && s.includes("no authority type")));
  const disabled = document().replace(/^metadata:.*$/m, 'metadata: {"openclaw":{"permissions":{"external-send":false,"file-write":true}}}');
  assert.ok(adoptOpenClawSkill(disabled, { acknowledgeRisk: true }).rawSkill);
  const enabled = disabled.replace('"external-send":false', '"external-send":true');
  assert.equal(adoptOpenClawSkill(enabled, { acknowledgeRisk: true }).rawSkill, undefined);
  for (const field of ['permissions: []', 'permissions: ["file-write"]', 'permissions:\n  - "file-write"']) {
    assert.ok(adoptOpenClawSkill(document([field], []), { acknowledgeRisk: true }).rawSkill);
  }
});

test("allowed-tools scalar remains metadata, not permission or parsed executable rules", () => {
  const result = adoptOpenClawSkill(document(['allowed-tools: "Read Write Bash(echo hello)"'], []), { acknowledgeRisk: true });
  assert.ok(result.rawSkill);
  assert.deepEqual(result.intent?.surface.tools, ["Read Write Bash(echo hello)"], "scalar declaration is retained intact, not split inside an argument");
  assert.deepEqual(result.rawSkill.requiredAuthority, []);
  assert.deepEqual(result.rawSkill.envelope.steps, []);
  assert.ok(result.unsupported.some(s => s.includes("tool requirements")));
  const flow = adoptOpenClawSkill(document(["allowed-tools: [Read, Write]"], []), { acknowledgeRisk: true });
  assert.match(flow.rejected ?? "", /unsupported-input-language/);
  assert.equal(flow.rawSkill, undefined);
});

test("signature controls distinguish missing, incomplete, invalid, self-rekeyed and DER keys", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-adoption-signature-")) });
  assert.equal(adoptOpenClawSkill(document()).signature, "unsigned");
  assert.equal(adoptOpenClawSkill(document(["signature: bad"])).signature, "invalid");
  const fingerprints = new Set<string>();
  for (const keyFormat of ["pem", "der"] as const) {
    const keys = generateKeyPairSync("ed25519");
    const encoded = keyFormat === "pem" ? keys.publicKey.export({ type: "spki", format: "pem" }).toString().replace(/\n/g, "\\n") : keys.publicKey.export({ type: "spki", format: "der" }).toString("base64");
    const signature = sign(null, Buffer.from("local-notes\nSynthetic notes.\n1.0"), keys.privateKey).toString("base64");
    const signed = document([`publicKey: "${encoded}"`, `signature: ${signature}`]);
    for (const mutation of [signed, signed.replace("name: local-notes", "name: changed-notes"), signed.replace("version: 1.0", "version: 2.0")]) {
      const result = adoptOpenClawSkill(mutation, { acknowledgeRisk: true });
      assert.equal(result.signature, mutation === signed ? "verified-intent-fields" : "invalid");
      assert.equal(result.signatureInfo?.signerTrust, "untrusted-embedded-key");
      assert.equal(result.signatureInfo?.sourceDigestSigned, false);
      assert.ok(result.rawSkill, "invalid signatures remain clearly labeled static inspection, not execution admission");
    }
    const response = await handleGatewayRequest(app, { method: "POST", path: "/skill/adopt-openclaw", query: {}, headers: { authorization: "Bearer signature-owner" },
      body: JSON.stringify({ skill: signed, acknowledgeRisk: true }) }, { token: "signature-owner" });
    const body = JSON.parse(response.body);
    assert.equal(body.signature, "verified-intent-fields");
    assert.equal(body.signatureInfo.sourceSha256, sha(signed));
    assert.equal(body.signatureInfo.sourceDigestSigned, false);
    fingerprints.add(body.signatureInfo.signerSpkiSha256);
    assert.ok(app.registryStore!.get("openclaw:local-notes")!.skill.provenance.includes(`signer-spki-sha256:${body.signatureInfo.signerSpkiSha256}`));
    assert.equal(app.managedSkillRegistry.admissionStatus("openclaw:local-notes"), "catalog-only");
    assert.deepEqual(app.skillRetrieval.retrieve({ taskShape: "maintain notes" }), []);
  }
  assert.equal(fingerprints.size, 2, "new self-signed key remains a different, untrusted signer");
});

test("static adoption still requires authentication and an actual Boolean acknowledgment", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-adoption-auth-")) });
  for (const acknowledgment of [undefined, false, "true"]) {
    const response = await handleGatewayRequest(app, { method: "POST", path: "/skill/adopt-openclaw", query: {}, headers: { authorization: "Bearer static-owner" },
      body: JSON.stringify({ skill: document(), acknowledgeRisk: acknowledgment }) }, { token: "static-owner" });
    assert.equal(JSON.parse(response.body).adopted, false);
    assert.deepEqual(app.registryStore!.list(), []);
  }
  const denied = await handleGatewayRequest(app, { method: "POST", path: "/skill/adopt-openclaw", query: {}, headers: {},
    body: JSON.stringify({ skill: document(), acknowledgeRisk: true }) }, { token: "static-owner" });
  assert.equal(denied.status, 401);
  assert.deepEqual(app.registryStore!.list(), []);
});

test("tenant adoption stores only in the authenticated tenant and still grants no execution", async () => {
  const app = composeKeep({ dataDir: mkdtempSync(join(tmpdir(), "keep-adoption-tenant-")) });
  const security = (tenant: string) => ({ token: "tenant-owner", principalFor: () => ({ id: `owner-${tenant}`, kind: "human" as const, role: "owner" as const, tenant }) });
  const request = { method: "POST", path: "/skill/adopt-openclaw", query: {}, headers: { authorization: "Bearer tenant-owner" },
    body: JSON.stringify({ skill: document(), acknowledgeRisk: true }) };
  const adopted = await handleGatewayRequest(app, request, security("alpha"));
  assert.equal(JSON.parse(adopted.body).adopted, true);
  for (const tenant of ["alpha", "beta"]) {
    const listing = await handleGatewayRequest(app, { ...request, method: "GET", path: "/skills", body: "" }, security(tenant));
    assert.deepEqual(JSON.parse(listing.body).skills.map((s: { id: string }) => s.id), tenant === "alpha" ? ["openclaw:local-notes"] : []);
  }
  assert.deepEqual(app.registryStore!.list(), [], "tenant catalog does not become default managed registry state");
  assert.deepEqual(app.skillRetrieval.retrieve({ taskShape: "maintain notes" }), []);
});

test("legacy source digest and translation use the same detached JSON input", () => {
  let reads = 0;
  const input = { name: "legacy-snapshot", get permissions() { return ++reads === 1 ? ["file-read"] : ["file-write"]; } };
  const result = adoptOpenClawSkill(input, { acknowledgeRisk: true });
  assert.ok(result.rawSkill);
  assert.deepEqual(result.intent?.surface.permissions, ["file-read"]);
  assert.equal(result.signatureInfo?.sourceSha256, sha(JSON.stringify({ name: "legacy-snapshot", permissions: ["file-read"] })));
  assert.deepEqual(result.rawSkill.requiredAuthority, ["workspace:read"]);
  assert.equal(reads, 1);
});

test("a custom static gate cannot silently rewrite the declared candidate it checks", () => {
  const result = adoptOpenClawSkill(document(), { acknowledgeRisk: true, gate: candidate => {
    (candidate.envelope.declaredEffects as string[]).length = 0;
    return null;
  } });
  assert.equal(result.rawSkill, undefined);
  assert.match(result.rawRejected ?? "", /gate/);
  assert.ok(result.bespokeSpec?.proposedEffects.includes("file-write"));
});
