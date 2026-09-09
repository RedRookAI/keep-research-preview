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

import { detectProviderKind, checkCredentialShape, brainFromKey, localBrain } from "../src/frontdoor/brain_port.js";
import { BrainResolver, type LocalProbe } from "../src/frontdoor/brain_resolver.js";

function newSpine(): Spine {
  const dir = mkdtempSync(join(tmpdir(), "keep-f0-"));
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

// --- Provider detection (real prefixes; unknown accepted) ---

test("provider detection maps real key prefixes to providers", () => {
  assert.equal(detectProviderKind("sk-ant-abc123xyz789").id, "anthropic");
  assert.equal(detectProviderKind("sk-or-v1-abc123xyz").id, "openrouter");
  assert.equal(detectProviderKind("gsk_abc123xyz789").id, "groq");
  assert.equal(detectProviderKind("nvapi-abc123xyz789").id, "nvidia-nim");
  assert.equal(detectProviderKind("AIzaSyAbc123xyz789").id, "gemini");
  assert.equal(detectProviderKind("sk-abc123xyz789").id, "openai"); // generic OpenAI-style
});

test("an UNKNOWN key shape is accepted (not rejected) — the works-with-everything moat", () => {
  const d = detectProviderKind("some-new-provider-token-2027");
  assert.equal(d.id, "unknown");
  assert.equal(d.label, "your provider");
  // And brainFromKey still produces a usable OpenAI-compatible descriptor.
  const brain = brainFromKey("some-new-provider-token-2027", { baseURL: "https://new.example/v1" });
  assert.equal(brain.kind, "openai-compatible");
  assert.equal(brain.baseURL, "https://new.example/v1");
});

// --- Jargon-free credential checks ---

test("empty key gives a friendly nudge, not an error", () => {
  const c = checkCredentialShape("");
  assert.equal(c.ok, false);
  assert.ok(c.message.toLowerCase().includes("paste"));
  assert.ok(!/error|invalid|auth/i.test(c.message)); // no jargon
});

test("incomplete key (too short / has spaces) is caught with plain language", () => {
  assert.equal(checkCredentialShape("sk-123").ok, false);
  assert.equal(checkCredentialShape("sk-ant part1 part2").ok, false);
});

test("a well-formed key passes and names the provider in plain language", () => {
  const c = checkCredentialShape("sk-ant-abcdef1234567890");
  assert.equal(c.ok, true);
  assert.ok(c.message.includes("Anthropic"));
});

// --- Resolver flow: local-first, else ask (no dead-end), key path ---

test("resolveDefault uses the local model when one is present", async () => {
  const probe: LocalProbe = async () => ({ baseURL: "http://localhost:11434/v1", model: "qwen3.5:32b" });
  const r = new BrainResolver(newSpine(), new CryptoShredKeyStore(), probe);
  const out = await r.resolveDefault();
  assert.equal(out.state, "using-local");
  assert.equal(out.brain!.kind, "local");
  assert.ok(out.message.includes("private model"));
});

test("resolveDefault does NOT dead-end when no local model — it asks for a key", async () => {
  const probe: LocalProbe = async () => null; // no local runtime
  const r = new BrainResolver(newSpine(), new CryptoShredKeyStore(), probe);
  const out = await r.resolveDefault();
  assert.equal(out.state, "need-key");
  assert.ok(out.message.toLowerCase().includes("paste your ai key"));
  assert.ok(!/error|fail/i.test(out.message)); // not framed as a failure
});

test("resolveWithKey connects, stores the credential crypto-shredded, and it's retrievable", async () => {
  const r = new BrainResolver(newSpine(), new CryptoShredKeyStore(), async () => null);
  const out = await r.resolveWithKey("sk-ant-secretkey1234567890");
  assert.equal(out.state, "using-key");
  assert.equal(out.brain!.providerLabel, "Anthropic (Claude)");
  assert.equal(r.storedKey(), "sk-ant-secretkey1234567890"); // decrypts back
});

test("forgetKey crypto-shreds the credential (unrecoverable)", async () => {
  const r = new BrainResolver(newSpine(), new CryptoShredKeyStore(), async () => null);
  await r.resolveWithKey("sk-ant-secretkey1234567890");
  r.forgetKey();
  assert.equal(r.storedKey(), undefined); // gone
});

test("resolveWithKey gives a friendly nudge (need-key) for an incomplete key, no throw", async () => {
  const r = new BrainResolver(newSpine(), new CryptoShredKeyStore(), async () => null);
  const out = await r.resolveWithKey("sk-1");
  assert.equal(out.state, "need-key");
});

test("the API key is NEVER written to the spine (only a hasKey flag + provider)", async () => {
  const spine = newSpine();
  const r = new BrainResolver(spine, new CryptoShredKeyStore(), async () => null);
  await r.resolveWithKey("sk-ant-supersecretvalue999");
  const dump = JSON.stringify(spine.currentEvents());
  assert.ok(!dump.includes("supersecretvalue999")); // key not leaked to the audit trail
  assert.ok(dump.includes("brain.selected"));
  assert.ok(dump.includes("hasKey"));
});

test("localBrain builds a no-real-key descriptor", () => {
  const b = localBrain();
  assert.equal(b.kind, "local");
  assert.equal(b.apiKey, "local");
});
