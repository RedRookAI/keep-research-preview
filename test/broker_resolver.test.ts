import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync, symlinkSync, renameSync, openSync, fstatSync, readFileSync, readSync, closeSync, statSync, constants } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { compilePolicy, type SignedBundle, type CompilerSigner } from "../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";
import type { JsonValue } from "../src/policy/json.js";
import { validateEffectDecl, type EffectFamily } from "../src/effect/effect.js";
import { compileEffectManifest, type EffectManifestSigner } from "../src/effect/effect_manifest.js";
import { mintRoot, type Permit, type PermitClaims, type PermitKey } from "../src/permit/permit.js";
import { RedemptionLedger } from "../src/permit/ledger.js";
import { EffectBroker, MapIdempotencyStore, type FamilyBinding, type BrokerRequest, type ObjectAdapter, type PreparedTarget, type AuditSink } from "../src/broker/broker.js";
import type { CanonicalValue } from "../src/eir/canonical.js";

// Mechanical-Enforcement Increment 11 — RESOLVER-BOUND CANONICAL GUARDS. For an object-based (fs) family the broker binds
// redemption + execution to the EXACT object the adapter opens (inode identity from an O_NOFOLLOW fd, read THROUGH the fd),
// NOT the caller's decoy objectId or a re-resolvable path. Proven by disproof (neuter a check in src/broker/broker.ts →
// a named test reddens):
//   resolved-id binding (decoy)   => "a permit for object A cannot act on a different object B (decoy binding)"
//   symlink policy at prepare      => "a final-component symlink target is rejected at prepare (O_NOFOLLOW)"
//   execute-through-handle (TOCTOU)=> "a path swapped after prepare still reads the ORIGINAL opened object (TOCTOU)"

const KEYID = "k1", SECRET = "s3cr3t";
const psigner: CompilerSigner = { signer: new StubSigner(SECRET, KEYID), keyid: KEYID, verifyKey: SECRET };
const ptrust: TrustPolicy = { trustedKeys: new Map([[KEYID, SECRET]]), threshold: 1 };
const EK = "ek1", ES = "effect-secret";
const esigner: EffectManifestSigner = { signer: new StubSigner(ES, EK), keyid: EK, verifyKey: ES };
const etrust: TrustPolicy = { trustedKeys: new Map([[EK, ES]]), threshold: 1 };
const permitKey: PermitKey = { issuer: "monitor", rootKey: "root-K" };
const SEAMS = { artifactGraphDigest: "a".repeat(64), scannerToolDigest: "b".repeat(64) };
const FS_AUD = "broker-fs";

function policyBundle(): SignedBundle {
  const p: JsonValue = {
    version: 1n, combiningAlgorithm: "deny-overrides",
    principals: [{ name: "agent", labels: [] }],
    effects: [{ id: "e", effectType: "fs.read", resourceSelector: "/x" }],
    guards: [], rules: [{ id: "r", decision: "permit", subjects: ["agent"], entryPoints: ["*"], effect: "e" }],
  };
  return compilePolicy(p, [psigner]);
}
const bundle = policyBundle();
const effectId = bundle.payload.effects[0]!.id;

/** The canonical inode identity of a file (dev:ino) — the identity the adapter derives from the OPENED object. */
function inodeId(path: string): string { const s = statSync(path, { bigint: true }); return `fs.inode/v1:${s.dev}:${s.ino}`; }

/**
 * A REAL reference fs-read ObjectAdapter (Increment 11): prepare opens the path with O_NOFOLLOW (a final-component symlink
 * is refused at open), derives identity from the OPENED fd (fstat dev:ino), and reads THROUGH the fd at execute — never
 * reopening the caller's path (TOCTOU-safe). Handles are held adapter-private (provenance). The full openat/intermediate-
 * symlink policy is the OS verified-seam; this proves the SPINE with a real fd.
 */
function fsReadAdapter(): ObjectAdapter & { openFds: () => number } {
  const handles = new WeakMap<PreparedTarget, { fd: number }>();
  let open = 0, closed = 0;
  return {
    openFds: () => open - closed,
    prepare(_operation: string, args: CanonicalValue): PreparedTarget {
      const path = (args as { path?: unknown }).path;
      if (typeof path !== "string") throw new Error("fs adapter: args.path must be a string");
      const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); // final-component symlink => throws ELOOP
      open++;
      try {
        const s = fstatSync(fd, { bigint: true });
        const pt: PreparedTarget = { canonicalId: `fs.inode/v1:${s.dev}:${s.ino}` };
        handles.set(pt, { fd });
        return pt;
      } catch (e) { try { closeSync(fd); closed++; } catch { /* */ } throw e; } // no leaked fd if identity derivation throws
    },
    async execute(prepared: PreparedTarget, _signal): Promise<CanonicalValue> {
      const h = handles.get(prepared);
      if (h === undefined) throw new Error("fs adapter: unknown/forged prepared target"); // provenance
      const buf = Buffer.alloc(4096);
      const n = readSync(h.fd, buf, 0, buf.length, 0); // read THROUGH the fd — never reopen the path
      return { bytes: buf.subarray(0, n).toString("utf8") };
    },
    release(prepared: PreparedTarget): void {
      const h = handles.get(prepared);
      if (h !== undefined) { try { closeSync(h.fd); closed++; } catch { /* best-effort */ } handles.delete(prepared); }
    },
  };
}

interface Built { broker: EffectBroker; adapter: ReturnType<typeof fsReadAdapter>; }
function buildFsBroker(): Built {
  const fsDecl = validateEffectDecl({ family: "fs", owner: "src/fs/owner.ts" });
  const manifest = compileEffectManifest([fsDecl], bundle, SEAMS, [esigner]);
  const adapter = fsReadAdapter();
  const sink: AuditSink = { write() {} };
  const bindings = new Map<EffectFamily, FamilyBinding>([["fs", { adapter, audience: FS_AUD, operations: new Map([["read", "read"]]) }]]);
  const broker = new EffectBroker(manifest, bundle, { manifestTrust: etrust, policyTrust: ptrust }, permitKey, new RedemptionLedger(), new MapIdempotencyStore(), bindings, sink, "res-nonce-1");
  return { broker, adapter };
}
function permitFor(objectId: string, over: Partial<PermitClaims> = {}): Permit {
  return mintRoot({ issuer: "monitor", subject: "agent", session: "req-1", effectId, objectId, rights: ["read"], guardDigest: "a".repeat(64), epoch: 0n, notBefore: 0n, notAfter: 1000n, nonce: "req-1", maxRedemptions: 1n, audience: [FS_AUD], ...over }, permitKey);
}
function req(p: Permit, path: string, over: Partial<BrokerRequest> = {}): BrokerRequest {
  return { permit: p, subject: "agent", session: "req-1", effectId, objectId: "CALLER-DECOY", family: "fs", operation: "read", args: { path }, idempotencyKey: "idem-1", ...over };
}

let tmp: string;
test.afterEach(() => { if (tmp) { try { rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } } });

test("happy path: a permit bound to the RESOLVED inode reads the exact object through the fd", async () => {
  tmp = mkdtempSync(join(tmpdir(), "keep-res-"));
  const fileA = join(tmp, "a.txt"); writeFileSync(fileA, "SECRET-A");
  const { broker, adapter } = buildFsBroker();
  const r = await broker.dispatch(req(permitFor(inodeId(fileA)), fileA), 100n, 0n);
  assert.equal(r.ok, true);
  if (r.ok) assert.equal((r.output as { bytes: string }).bytes, "SECRET-A");
  assert.equal(adapter.openFds(), 0, "the prepared fd is released after the effect (no leak)");
});

test("a permit for object A cannot act on a different object B (decoy binding — the keystone)", async () => {
  tmp = mkdtempSync(join(tmpdir(), "keep-res-"));
  const fileA = join(tmp, "a.txt"); writeFileSync(fileA, "SAFE-A");
  const fileB = join(tmp, "b.txt"); writeFileSync(fileB, "FORBIDDEN-B");
  const { broker, adapter } = buildFsBroker();
  // The caller holds a permit for A's inode AND CLAIMS objectId = A's inode (a plausible lie), but the args point at B.
  // The broker resolves the args -> B's inode -> binds redemption to B -> permit(A) != B -> deny. WITHOUT the resolver
  // (neuter), redemption would use the caller's claimed A, succeed, and the adapter's fd (opened on B) would leak B.
  const r = await broker.dispatch(req(permitFor(inodeId(fileA)), fileB, { objectId: inodeId(fileA) }), 100n, 0n);
  assert.equal(r.ok, false, "a permit for A must not act on B");
  assert.match((r as { reason: string }).reason, /not redeemable/);
  if (r.ok) assert.notEqual((r as unknown as { output: { bytes: string } }).output.bytes, "FORBIDDEN-B");
  assert.equal(adapter.openFds(), 0, "the fd opened at prepare is released even on a redeem-deny");
});

test("a final-component symlink target is rejected at prepare (O_NOFOLLOW)", async () => {
  tmp = mkdtempSync(join(tmpdir(), "keep-res-"));
  const secret = join(tmp, "secret.txt"); writeFileSync(secret, "TOP-SECRET");
  const link = join(tmp, "link"); symlinkSync(secret, link);
  const { broker } = buildFsBroker();
  // args.path is a symlink -> O_NOFOLLOW makes openSync throw ELOOP -> prepare fails -> deny, no read.
  const r = await broker.dispatch(req(permitFor(inodeId(secret)), link), 100n, 0n);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /object prepare failed/);
});

test("a path swapped AFTER prepare still reads the ORIGINAL opened object (TOCTOU — execute through the handle)", async () => {
  tmp = mkdtempSync(join(tmpdir(), "keep-res-"));
  const target = join(tmp, "target.txt"); writeFileSync(target, "ORIGINAL-A");
  const evil = join(tmp, "evil.txt"); writeFileSync(evil, "SWAPPED-B");
  const idA = inodeId(target);
  // adapter that PAUSES between open and read, so the test can swap the path in the window.
  const handles = new WeakMap<PreparedTarget, { fd: number }>();
  const adapter: ObjectAdapter = {
    prepare(_op, args) { const fd = openSync((args as { path: string }).path, constants.O_RDONLY | constants.O_NOFOLLOW); try { const s = fstatSync(fd, { bigint: true }); const pt = { canonicalId: `fs.inode/v1:${s.dev}:${s.ino}` }; handles.set(pt, { fd }); return pt; } catch (e) { try { closeSync(fd); } catch { /* */ } throw e; } },
    async execute(prepared) {
      // TOCTOU window: replace the path with a different file BEFORE reading. A handle-based read must ignore this.
      renameSync(evil, target); // target now points at the SWAPPED-B inode
      const h = handles.get(prepared)!; const buf = Buffer.alloc(64); const n = readSync(h.fd, buf, 0, 64, 0);
      return { bytes: buf.subarray(0, n).toString("utf8") };
    },
    release(prepared) { const h = handles.get(prepared); if (h) { try { closeSync(h.fd); } catch { /* */ } handles.delete(prepared); } },
  };
  const fsDecl = validateEffectDecl({ family: "fs", owner: "src/fs/owner.ts" });
  const manifest = compileEffectManifest([fsDecl], bundle, SEAMS, [esigner]);
  const broker = new EffectBroker(manifest, bundle, { manifestTrust: etrust, policyTrust: ptrust }, permitKey, new RedemptionLedger(), new MapIdempotencyStore(), new Map<EffectFamily, FamilyBinding>([["fs", { adapter, audience: FS_AUD, operations: new Map([["read", "read"]]) }]]), { write() {} }, "res-nonce-2");
  const r = await broker.dispatch(req(permitFor(idA), target), 100n, 0n);
  assert.equal(r.ok, true);
  if (r.ok) assert.equal((r.output as { bytes: string }).bytes, "ORIGINAL-A", "the read went through the original fd, not the swapped path");
});

/** A fault-injecting adapter (canonicalId = "fixed-id") + a release counter, for totality/lifecycle disproofs. */
function faultAdapter(fault: "throwing-getter" | "malformed-id" | "execute-throw" | "release-throw" | "none"): ObjectAdapter & { releases: () => number } {
  let releases = 0;
  return {
    releases: () => releases,
    prepare(): PreparedTarget {
      if (fault === "throwing-getter") return Object.defineProperty({}, "canonicalId", { get() { throw new Error("hostile getter"); }, enumerable: true }) as PreparedTarget;
      if (fault === "malformed-id") return { canonicalId: 42 as unknown as string };
      return { canonicalId: "fs.fixed/v1:1" };
    },
    async execute(): Promise<CanonicalValue> { if (fault === "execute-throw") throw new Error("execute boom"); return { ok: true }; },
    release(): void { releases++; if (fault === "release-throw") throw new Error("release boom"); },
  };
}
function buildWith(adapter: ObjectAdapter): EffectBroker {
  const fsDecl = validateEffectDecl({ family: "fs", owner: "src/fs/owner.ts" });
  const manifest = compileEffectManifest([fsDecl], bundle, SEAMS, [esigner]);
  return new EffectBroker(manifest, bundle, { manifestTrust: etrust, policyTrust: ptrust }, permitKey, new RedemptionLedger(), new MapIdempotencyStore(), new Map<EffectFamily, FamilyBinding>([["fs", { adapter, audience: FS_AUD, operations: new Map([["read", "read"]]) }]]), { write() {} }, "res-nonce-3");
}

test("a hostile adapter (throwing canonicalId getter) is fail-closed AND releases the handle (totality)", async () => {
  const adapter = faultAdapter("throwing-getter");
  const r = await buildWith(adapter).dispatch(req(permitFor("fs.fixed/v1:1"), "/x"), 100n, 0n); // must resolve, not reject
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /malformed prepared target/);
  assert.equal(adapter.releases(), 1, "the prepared handle is released even when canonicalId throws");
});

test("a malformed prepared target (non-text canonicalId) is denied AND releases the handle", async () => {
  const adapter = faultAdapter("malformed-id");
  const r = await buildWith(adapter).dispatch(req(permitFor("fs.fixed/v1:1"), "/x"), 100n, 0n);
  assert.equal(r.ok, false);
  assert.equal(adapter.releases(), 1);
});

test("an execute that throws is fail-closed AND releases the handle", async () => {
  const adapter = faultAdapter("execute-throw");
  const r = await buildWith(adapter).dispatch(req(permitFor("fs.fixed/v1:1"), "/x"), 100n, 0n);
  assert.equal(r.ok, false);
  assert.match((r as { reason: string }).reason, /dispatch failed/);
  assert.equal(adapter.releases(), 1);
});

test("a release that throws does NOT mask a successful effect (result stays ok; no strand)", async () => {
  const adapter = faultAdapter("release-throw");
  const r = await buildWith(adapter).dispatch(req(permitFor("fs.fixed/v1:1"), "/x"), 100n, 0n);
  assert.equal(r.ok, true, "the effect succeeded; a best-effort release throw must not mask it");
  assert.equal(adapter.releases(), 1);
});

test("construction: a family binding must have EXACTLY ONE of {executor, adapter}", () => {
  const fsDecl = validateEffectDecl({ family: "fs", owner: "src/fs/owner.ts" });
  const manifest = compileEffectManifest([fsDecl], bundle, SEAMS, [esigner]);
  const led = new RedemptionLedger();
  const ops = new Map([["read", "read"]]);
  const adapter = fsReadAdapter();
  const mk = (b: FamilyBinding) => new EffectBroker(manifest, bundle, { manifestTrust: etrust, policyTrust: ptrust }, permitKey, led, new MapIdempotencyStore(), new Map([["fs", b]]), { write() {} }, "n");
  // BOTH executor and adapter -> reject.
  assert.throws(() => mk({ executor: () => null, adapter, audience: FS_AUD, operations: ops } as FamilyBinding), /EXACTLY ONE/);
  // NEITHER -> reject.
  assert.throws(() => mk({ audience: FS_AUD, operations: ops } as unknown as FamilyBinding), /EXACTLY ONE/);
  // a PRESENT-but-malformed alternative alongside a valid one -> reject (present-ness, not valid-looking-ness).
  assert.throws(() => mk({ adapter, executor: 0 as unknown as never, audience: FS_AUD, operations: ops } as FamilyBinding), /EXACTLY ONE/);
  assert.throws(() => mk({ executor: () => null, adapter: {} as unknown as never, audience: FS_AUD, operations: ops } as FamilyBinding), /EXACTLY ONE/);
  // an EXPLICIT `executor: undefined` (own property present) alongside a valid adapter -> reject. Property PRESENCE
  // (Object.hasOwn), not nullish-value detection: an ambiguous both-keys binding cannot slip through as adapter-only. [SEV2a]
  assert.throws(() => mk({ adapter, executor: undefined, audience: FS_AUD, operations: ops } as unknown as FamilyBinding), /EXACTLY ONE/);
  assert.throws(() => mk({ executor: () => null, adapter: undefined, audience: FS_AUD, operations: ops } as unknown as FamilyBinding), /EXACTLY ONE/);
  // a present adapter that is not {prepare,execute,release} -> reject.
  assert.throws(() => mk({ adapter: { prepare() { /* */ } } as unknown as never, audience: FS_AUD, operations: ops } as FamilyBinding), /adapter must be/);
  // a present `adapter: null` -> BRANDED BrokerError, NOT a raw TypeError (typeof null === "object" must not slip past the
  // object check into a `.prepare`-on-null access). Fails closed with the right error class. [SEV3-1]
  assert.throws(() => mk({ adapter: null as unknown as never, audience: FS_AUD, operations: ops } as unknown as FamilyBinding), /adapter must be/);
  // adapter alone -> OK.
  assert.ok(mk({ adapter, audience: FS_AUD, operations: ops }));
});
