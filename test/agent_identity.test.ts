import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { IdentityRegistry, type AgentIdentity } from "../src/identity/agent_identity.js";
import { composeGate, defaultGatePolicy, type GateInputs } from "../src/gate/composed_gate.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";

// Core Addition C — per-agent identity + kill. These prove identity is an unforgeable capability
// (not a claimed name), delegation attenuates, and a killed/unknown identity's effects are refused
// (fail-safe). Verify by disproof.

function newSpine() {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "id-spine-"))), new InProcessLock(), new SchemaRegistry());
}

test("IDENTITY: a live, in-scope identity authorizes its effect", () => {
  const reg = new IdentityRegistry();
  const agent = reg.mint("agent-1", ["src/"]);
  assert.equal(reg.authorize(agent).authorized, true);
  assert.equal(reg.authorizeEffect(agent, "src/app.ts").authorized, true);
});

test("IDENTITY: a KILLED identity is refused (revocation)", () => {
  const reg = new IdentityRegistry();
  const agent = reg.mint("agent-1", ["src/"]);
  reg.kill("agent-1");
  const r = reg.authorize(agent);
  assert.equal(r.authorized, false);
  if (!r.authorized) assert.equal(r.reason, "killed-identity");
  assert.equal(reg.authorizeEffect(agent, "src/app.ts").authorized, false);
});

test("IDENTITY: an UNKNOWN identity is refused (fail-safe)", () => {
  const reg = new IdentityRegistry();
  const forged: AgentIdentity = { id: "never-minted", token: "deadbeef", scope: ["*"] };
  const r = reg.authorize(forged);
  assert.equal(r.authorized, false);
  if (!r.authorized) assert.equal(r.reason, "unknown-identity");
});

test("IDENTITY: a FORGED token (right id, wrong token) is refused — a name is not a capability", () => {
  const reg = new IdentityRegistry();
  reg.mint("agent-1", ["src/"]);
  const impostor: AgentIdentity = { id: "agent-1", token: "0".repeat(64), scope: ["*"] };
  const r = reg.authorize(impostor);
  assert.equal(r.authorized, false);
  if (!r.authorized) assert.equal(r.reason, "forged-token");
});

test("IDENTITY: a delegated sub-identity CANNOT exceed its parent's scope (attenuation)", () => {
  const reg = new IdentityRegistry();
  const parent = reg.mint("parent", ["src/feature/"]);
  const child = reg.delegate(parent, "child", ["src/feature/x/", "src/OTHER/", "/etc/"])!;
  // only the in-parent-scope prefix survives; the wider requests are dropped.
  assert.ok(child.scope.includes("src/feature/x/"));
  assert.ok(!child.scope.includes("src/OTHER/"));
  assert.ok(!child.scope.includes("/etc/"));
  assert.equal(reg.authorizeEffect(child, "src/feature/x/a.ts").authorized, true);
  assert.equal(reg.authorizeEffect(child, "src/OTHER/secret.ts").authorized, false);
});

test("IDENTITY: an out-of-scope effect from a live identity is refused", () => {
  const reg = new IdentityRegistry();
  const agent = reg.mint("agent-1", ["src/"]);
  const r = reg.authorizeEffect(agent, "secrets/key.pem");
  assert.equal(r.authorized, false);
  if (!r.authorized) assert.ok(r.reason.startsWith("out-of-scope"));
});

test("IDENTITY: a dead/forged parent cannot delegate", () => {
  const reg = new IdentityRegistry();
  const parent = reg.mint("parent", ["src/"]);
  reg.kill("parent");
  assert.equal(reg.delegate(parent, "child", ["src/"]), undefined);
});

test("IDENTITY: kill is recorded to the spine and the chain still verifies", async () => {
  const spine = newSpine();
  const reg = new IdentityRegistry(spine);
  reg.mint("agent-1", ["src/"]);
  const before = spine.replay().length;
  reg.kill("agent-1", "misbehaving");
  await spine.seal();
  assert.ok(spine.replay().length > before, "the kill was recorded to the spine");
  assert.equal(spine.verify().ok, true);
  assert.ok(spine.replay().some((e) => (e.payload as Record<string, unknown>)?.event === "agent.killed"));
});

test("IDENTITY: a killed identity STAYS killed (revocation is monotone)", () => {
  const reg = new IdentityRegistry();
  const agent = reg.mint("agent-1", ["src/"]);
  reg.kill("agent-1");
  reg.mint("agent-1", ["src/"]); // even a re-mint of the same id does not un-revoke it
  assert.equal(reg.isKilled("agent-1"), true);
  assert.equal(reg.authorize(agent).authorized, false);
});

// ── the gate veto ──
const green: GateInputs = { floor: "reversible-execute", budget: "within-budget", actionTier: "reversible-internal", ownerPresent: true };

test("IDENTITY+GATE: a killed/unknown identity vetoes an otherwise-green op → human-hold", () => {
  const r = composeGate({ ...green, identityLive: false }, defaultGatePolicy());
  assert.equal(r.route, "human-hold");
  assert.ok(r.reasons.includes("killed-or-unknown-identity"));
});

test("IDENTITY+GATE: a live identity does not veto", () => {
  assert.equal(composeGate({ ...green, identityLive: true }, defaultGatePolicy()).route, "auto-proceed");
});
