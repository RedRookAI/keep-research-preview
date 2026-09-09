import { test } from "node:test";
import assert from "node:assert/strict";

import { auditCapabilities, DEFAULT_CAPABILITIES, type AuditEnv } from "../src/frontdoor/capability_audit.js";
import { resolveLocalFirstDefaults, type EndpointProbe } from "../src/frontdoor/local_first_defaults.js";

// --- Capability audit ---

const freshNoAccount: AuditEnv = {
  hasBrain: false,
  brainIsLocal: false,
  modelIsWeak: false,
  connectedAccounts: new Set(),
  hasApiKey: false,
};

test("on a fresh install with no brain and no accounts, no-setup capabilities still work", () => {
  const report = auditCapabilities(freshNoAccount);
  const noSetup = report.statuses.filter((s) => s.capability.requires === "nothing");
  assert.ok(noSetup.length > 0);
  assert.ok(noSetup.every((s) => s.state === "available")); // all work with zero setup
});

test("Keep reports it works WITHOUT external accounts even when none are connected", () => {
  const report = auditCapabilities(freshNoAccount);
  assert.equal(report.worksWithoutAccounts, true);
  assert.ok(/no account|zero external accounts|without/i.test(report.summary));
});

test("capabilities needing a model surface a FREE/LOCAL alternative, not an account demand", () => {
  const report = auditCapabilities(freshNoAccount);
  const converse = report.statuses.find((s) => s.capability.id === "converse");
  assert.equal(converse!.state, "unavailable");
  assert.ok(/local|ollama|offline|no account/i.test(converse!.note));
  assert.ok(!/sign up|credit card|subscribe/i.test(converse!.note));
});

test("with a weak local model, strong-reasoning capabilities are honestly marked degraded", () => {
  const weakLocal: AuditEnv = { hasBrain: true, brainIsLocal: true, modelIsWeak: true, connectedAccounts: new Set(), hasApiKey: false };
  const report = auditCapabilities(weakLocal);
  const plan = report.statuses.find((s) => s.capability.id === "plan_decompose");
  assert.equal(plan!.state, "available-degraded");
  assert.ok(/less reliably|stronger model/i.test(plan!.note));
});

test("external-account capabilities are optional with a free alternative surfaced first", () => {
  const report = auditCapabilities(freshNoAccount);
  const gitRemote = report.statuses.find((s) => s.capability.id === "git_remote");
  assert.equal(gitRemote!.state, "unavailable");
  assert.ok(/local git|offline|no account|optional/i.test(gitRemote!.note));
});

test("a strong local model makes planning fully available (not degraded)", () => {
  const strongLocal: AuditEnv = { hasBrain: true, brainIsLocal: true, modelIsWeak: false, connectedAccounts: new Set(), hasApiKey: false };
  const report = auditCapabilities(strongLocal);
  const plan = report.statuses.find((s) => s.capability.id === "plan_decompose");
  assert.equal(plan!.state, "available");
});

// --- Local-first defaults resolver ---

test("resolver prefers a reachable local endpoint and needs no account/key", async () => {
  const probe: EndpointProbe = async (baseURL) => ({ reachable: baseURL.includes("11434"), modelId: "qwen3" });
  const plan = await resolveLocalFirstDefaults(probe);
  assert.equal(plan.mode, "local-model");
  assert.ok(plan.brain);
  assert.equal(plan.brain!.apiKey, ""); // local needs no key
  assert.ok(plan.brain!.baseURL.includes("11434"));
  assert.equal(plan.noAccountRequired, true);
});

test("resolver falls back to deterministic mode (no account demand) when no endpoint is reachable", async () => {
  const probe: EndpointProbe = async () => ({ reachable: false });
  const plan = await resolveLocalFirstDefaults(probe);
  assert.equal(plan.mode, "deterministic-fallback");
  assert.equal(plan.brain, null);
  assert.equal(plan.noAccountRequired, true);
  assert.ok(/ollama|local model|optional/i.test(plan.guidance));
  assert.ok(!/sign up|create an account|credit card/i.test(plan.guidance));
});

test("resolver survives a probe that throws (treats as unreachable, tries next)", async () => {
  const probe: EndpointProbe = async (baseURL) => {
    if (baseURL.includes("11434")) throw new Error("connection refused");
    return { reachable: baseURL.includes("1234") };
  };
  const plan = await resolveLocalFirstDefaults(probe);
  assert.equal(plan.mode, "local-model");
  assert.ok(plan.brain!.baseURL.includes("1234")); // fell through to LM Studio
});
