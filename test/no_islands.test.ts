import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, basename } from "node:path";

/**
 * NO-ISLANDS CONTRACT (audit, 2026-08-06).
 *
 * "Everything wired end to end, no orphans" was a convention enforced by hand via the wiring ledger. A filesystem
 * audit found the ledger's per-module `pending-wire` list UNDERCOUNTED the modules that are tested but not consumed
 * by the runtime import graph. This test makes the real state a CHECKED contract: it reads the actual import graph
 * and asserts every unconsumed src module is a DOCUMENTED, allowlisted exception. A new module that nobody wires
 * fails this test until it is either wired or added here with a justification — so islands can never grow silently.
 *
 * The allowlist is categorized and honest. Nothing here is dead (every entry has tests); each is unconsumed for a
 * stated reason. As built-ahead components get wired into compose, they must be REMOVED from the allowlist (the
 * second test enforces that — a stale entry means the module is now wired and the list is lying).
 */

function walk(dir: string): string[] {
  let out: string[] = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    const s = statSync(p);
    if (s.isDirectory()) out = out.concat(walk(p));
    else if (e.endsWith(".ts")) out.push(p);
  }
  return out;
}

function unconsumedModules(srcDir: string): Set<string> {
  const files = walk(srcDir);
  const consumerCount = new Map<string, number>();
  for (const f of files) {
    const txt = readFileSync(f, "utf8");
    for (const m of txt.matchAll(/from\s+"([^"]+)\.js"/g)) {
      const b = m[1]!.split("/").pop()!;
      if (!consumerCount.has(b)) consumerCount.set(b, 0);
      // A consumer is a non-barrel, non-self src file.
      if (!f.endsWith("index.ts") && basename(f) !== `${b}.ts`) consumerCount.set(b, consumerCount.get(b)! + 1);
    }
  }
  const un = new Set<string>();
  for (const f of files) {
    const b = basename(f, ".ts");
    if (b === "index") continue;
    if ((consumerCount.get(b) ?? 0) === 0) un.add(b);
  }
  return un;
}

function packageConsumerModules(srcDir: string): Set<string> {
  const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8")) as { bin?: Record<string, string>; exports?: Record<string, string> };
  const targets = [...Object.values(pkg.bin ?? {}), ...Object.values(pkg.exports ?? {})];
  const consumers = new Set(targets.map((target) => basename(target, ".js")));
  if (consumers.has("index")) {
    const barrel = readFileSync(join(srcDir, "index.ts"), "utf8");
    for (const match of barrel.matchAll(/from\s+"([^"]+)\.js"/gu)) consumers.add(match[1]!.split("/").pop()!);
  }
  return consumers;
}

// ── The documented allowlist of modules that are intentionally NOT in the runtime import graph ──

// Entry points + external adapters: invoked from outside the composed app (CLI/HTTP/CI/transports), never imported.
const ENTRY_AND_ADAPTERS = ["flagship", "gateway_mcp"];

// Eval / ops tooling + data-as-code: used by the eval harness, ops commands, or read as data — not core runtime.
const TOOLING = ["memory_eval"];

// Proving harnesses: encode/verify an invariant in tests; the real enforcement is structural elsewhere.
const PROVING_HARNESS: string[] = [];

// Build-time gate ports: src-resident interfaces onto a tools/ engine that consumes a DEVdep (typescript).
// They are unwired from the runtime graph BY DESIGN — the shipped product must not spawn a devDep-consuming
// engine, so these load only under the test/CI gate, never in compose. Genuinely unconsumed, not dead.
const BUILD_TIME_GATE = [
  // reachability_port (BUILD-ORDER 8.4): the typescript-free seam onto tools/island_sweep.mjs, the real
  // ts.TypeChecker two-color reachability sweep. Its consumer is test/reachability_island.test.ts (the gate);
  // it is never in the runtime import graph because the engine it drives needs the typescript devDep, which
  // the zero-runtime-dep product does not ship. Fully tested; keep here while it stays build-time-only.
  "reachability_port",
  // effect_scan_port (Mechanical-Enforcement Increment 4): the typescript-free seam onto tools/effect_sweep.mjs, the
  // real ts-AST CLOSED-WORLD EFFECT scanner that reports any effect-family host primitive used outside its declared
  // owner. Consumers are the build-time gate (test/effect_scan.test.ts) AND authority_gate (Incr 10a); never the runtime
  // graph, by design. NOTE: now consumed by authority_gate, so it is no longer an island — see the honest-list test.
  // authority_gate (Mechanical-Enforcement Increment 10a): the ARTIFACT-BOUND CLOSED-WORLD AUTHORITY GATE — verifies the
  // signed manifest's artifactGraphDigest equals the deployed source graph's digest (scan-then-swap dead), that no
  // unowned effect callsite exists except a KNOWN legacy one, and that the signed waiver only SHRINKS vs its baseline.
  // It CONSUMES effect_scan_port (EffectScanResult) + bom_signing + eir/canonical. Its consumer is the build-time gate
  // (test/authority_gate.test.ts) and, once wired, boot/compose artifact appraisal — never the runtime workload path.
  // ingress_scan_port (Mechanical-Enforcement Increment 3): the typescript-free seam onto tools/ingress_sweep.mjs, the
  // real ts-AST CLOSED-WORLD scanner that proves no listener/callback/code-gen construct exists outside approved
  // ingress adapters (static closure — what makes the sealed registry non-bypassable). Its consumer is the build-time
  // gate (test/ingress_scan.test.ts); never the runtime graph, by design (the product must not ship the ts devDep).
  "ingress_scan_port",
  // guard_registry (BUILD-ORDER 8.7): the typed guard-registry contract + the three pure decisions
  // (WATCHED classification, non-equivalence, restore-verification) that tools/neuter_engine.mjs composes
  // to prove a self-hosting user's safety guards are LOAD-BEARING. Its consumers are the build-time engine
  // (tools/neuter_engine.mjs) and test/neuter_engine.test.ts (the gate) — never the runtime compose graph,
  // by design, exactly like reachability_port. Fully tested; keep here while it stays build-time-only.
  "guard_registry",
];

// Ledger-documented pending-wire (await a findings-producing review queue, a probe, rates, a search, or a model call).
const PENDING_WIRE: string[] = [];

// Built-ahead-of-consumer: tested components whose runtime consumer (a conversation/front-door driver, the provider
// cascade, the governance/scheduler wiring, the research grounding pipeline) is a future increment. The genuine
// wiring backlog — see KEEP_ISLAND_AUDIT.md. Each must be REMOVED from here when wired.
const BUILT_AHEAD: string[] = [
  // native_boundary_port (Linux D1/D2/D3 Track A5): the zero-runtime-dependency, canonical bounded protocol/session
  // contract for the native helper boundary. It deliberately has no production transport consumer until A6 lands
  // the packaged native helper and transport; wiring a fake or ambient-process implementation here would overclaim
  // enforcement. Its test-only fake is not shipped. REMOVE when A6 connects the real helper boundary.
  "native_boundary_port",
  // native_authority_schema_v1 (A6 P2-S1): dependency-free, non-authorizing authority-record metadata and
  // TS/Rust differential preimage corpus. It consumes the P1 schema module, closing that prior island. Runtime
  // consumption is mechanically prohibited until later P2 resolver,
  // B0/B3, and production-crypto gates receive their own GO. REMOVE when the verified resolver owns this capture.
  "native_authority_schema_v1",
  // native_p2_d2_audit_plan is the provider-neutral validator for the preserved
  // P2-D2-OFF-HOST-REVIEWER-CUSTODY seam. It cannot enter runtime authorization until
  // the owner later provisions the off-host registry; tests prove its closed schema now.
  "native_p2_d2_audit_plan",
  // native_production_resolution_observation independently recomputes the safe-Rust
  // resolver transcript in the mounted integration probe. Runtime composition is
  // intentionally forbidden until production crypto/B0/B3 admission makes the native
  // resolver authorizing. REMOVE when that admitted resolver is wired to launch.
  "native_production_resolution_observation",
  // profile_attestation (AUTH-KERNEL profile evidence): signed, boot/deployment/nonce/time/key-epoch bound measurement
  // verification with a replay fence and explicit prober-independence pin. Its consumer is the forthcoming D2
  // pre-dispatch profile challenge; landing separately keeps the verifier's hostile cases reviewable. REMOVE when D2
  // consumes it. The signer/verifier remain ports so native Ed25519/HSM custody does not leak into policy logic.
  "profile_attestation",
  // tree_fingerprint: the whole-workspace "same source" identity primitive (BUILD-ORDER 8.2). Its
  // consumers are future increments — 8.7 revert-verification ("is this the tree we reverted to?")
  // and 8.8 reproducible-build diff ("is this the tree we attested?"). Built-ahead of both; REMOVE
  // from here when the first consumer wires it. Fully tested (test/tree_fingerprint.test.ts).
  "tree_fingerprint",
  // ingress_registry (Mechanical-Enforcement Increment 3): the sealed Closed-World Ingress Registry — top of the
  // ingress kernel (address.ts + schema.ts + ingress.ts + ingress_manifest.ts, all consumed below it). It CONSUMES
  // policy/compiler.ts (verifyBundle + SignedBundle for the E_M=E_P coverage binding — which is why `compiler` is no
  // longer built-ahead), so the whole ingress kernel is wired end-to-end EXCEPT its own top: the registry's first
  // runtime consumer is compose (ingress wiring) / Increment 8 (Ingress Admission Gate). Built-ahead; REMOVE when that
  // wires it. Fully tested (test/ingress_registry.test.ts).
  "ingress_registry",
  // channel + boundary (Mechanical-Enforcement Increment 5 — Attested Monitor Boundary): the authenticated
  // length-prefixed vsock channel (channel.ts — HMAC frames, seq/replay-window/deadline, session binding, fail-stop)
  // and the measured signed boot descriptor + appraisal (boundary.ts). Pure-TS (node:crypto only); the Firecracker
  // image/seccomp/vsock substrate is the existing tier + honest seams. The Increment-6 Decision Kernel is deliberately
  // TRANSPORT-AGNOSTIC (pure evaluator) so the SAME bytes run behind this boundary; the code wiring the kernel's
  // request/response frames onto this channel lands with the monitor deployment. Built-ahead. Fully tested
  // (test/monitor_boundary.test.ts).
  "channel", "boundary",
  // admission (Mechanical-Enforcement Increment 8 — Ingress Admission Gate): the trust-boundary admission pipeline that
  // channel-authenticates, bounds, schema-decodes, kernel-authorizes, and mints a root permit before any handler runs,
  // handing authority only via an unforgeable admission context. It CONSUMES kernel/decision.ts (the decision — so
  // `decision` is no longer an island; this is Incr 8 wiring onto Incr 6), permit/permit.ts (mintRoot — issuance, the
  // authority deferred from Incr 7), ingress/ingress + schema + ingress_manifest (closed-world seal), eir/canonical.
  // First runtime consumer is Increment 9 (Effect Broker), which redeems the minted permit at effect dispatch.
  // Built-ahead; REMOVE when that wires it. Fully tested (test/admission.test.ts).
  "admission",
];

const ALLOWLIST = new Set<string>([...ENTRY_AND_ADAPTERS, ...TOOLING, ...PROVING_HARNESS, ...BUILD_TIME_GATE, ...PENDING_WIRE, ...BUILT_AHEAD]);

const srcDir = join(process.cwd(), "src");

test("no accidental islands: every unconsumed src module is a documented, allowlisted exception", () => {
  const unconsumed = unconsumedModules(srcDir);
  const packageConsumers = packageConsumerModules(srcDir);
  const unexplained = [...unconsumed].filter((m) => !packageConsumers.has(m) && !ALLOWLIST.has(m)).sort();
  assert.deepEqual(unexplained, [], `New unwired module(s) detected — wire them into compose, or add to the allowlist in test/no_islands.test.ts with a justification: ${unexplained.join(", ")}`);
});

test("island allowlist stays honest: every allowlisted module is still actually unconsumed (remove once wired)", () => {
  const unconsumed = unconsumedModules(srcDir);
  const packageConsumers = packageConsumerModules(srcDir);
  const stale = [...ALLOWLIST].filter((m) => packageConsumers.has(m) || !unconsumed.has(m)).sort();
  assert.deepEqual(stale, [], `Allowlisted module(s) are now wired (or renamed/removed) — delete them from the allowlist so it stays honest: ${stale.join(", ")}`);
});
