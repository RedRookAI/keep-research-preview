import { test } from "node:test";
import assert from "node:assert/strict";

import { compilePolicy, type SignedBundle, type CompilerSigner } from "../src/policy/compiler.js";
import { StubSigner, type TrustPolicy } from "../src/bom/bom_signing.js";
import type { JsonValue } from "../src/policy/json.js";
import { validateEffectDecl, type EffectFamily } from "../src/effect/effect.js";
import { compileEffectManifest, type EffectManifestSigner } from "../src/effect/effect_manifest.js";
import { mintRoot, type Permit, type PermitClaims, type PermitKey } from "../src/permit/permit.js";
import { RedemptionLedger } from "../src/permit/ledger.js";
import { EffectBroker, MapIdempotencyStore, type IdempotencyStore, type InFlight, type Executor, type AuditSink, type BrokerRequest, type FamilyBinding, type Authorized, type ObjectAdapter } from "../src/broker/broker.js";
import { intentEntryHash, SpineDurableWitness, type DurableWitness, type WitnessIntent, type WitnessAck, type WitnessReceipt, type WitnessTerminal, type ReplayDisclosure } from "../src/witness/pre_effect_witness.js";
import { Spine } from "../src/spine/spine.js";
import type { SpineStore } from "../src/spine/store.js";
import type { StagedEvent } from "../src/spine/event.js";
import type { SealedBlock } from "../src/spine/hashchain.js";
import { FileSpineStore, type DurableIO } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import type { CanonicalValue } from "../src/eir/canonical.js";
import { mkdtempSync, rmSync, fstatSync, openSync as nOpen, writeSync as nWrite, fsyncSync as nFsync, closeSync as nClose } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** A DurableIO spy: counts fsyncs PER PATH and writes ONE byte per call, so a passing test proves the short-write loop
 *  wrote the full block AND that fsync actually ran on the specific file (distinguishing crash-durability from mere
 *  page-cache persistence). `fsyncByPath` maps each fsync'd fd back to the path it was opened with. */
function spyIO(): { io: DurableIO; counts: { fsync: number; writes: number }; fsyncByPath: Record<string, number> } {
  const counts = { fsync: 0, writes: 0 };
  const fsyncByPath: Record<string, number> = {};
  const fdPath = new Map<number, string>();
  const io: DurableIO = {
    openSync: (p, f) => { const fd = nOpen(p, f); fdPath.set(fd, p); return fd; },
    writeSync: (fd, buf, off, len) => { counts.writes++; return nWrite(fd, buf, off, Math.min(len, 1)); },
    fsyncSync: (fd) => { counts.fsync++; const p = fdPath.get(fd); if (p !== undefined) fsyncByPath[p] = (fsyncByPath[p] ?? 0) + 1; nFsync(fd); },
    closeSync: (fd) => { fdPath.delete(fd); nClose(fd); },
  };
  return { io, counts, fsyncByPath };
}

// Mechanical-Enforcement Increment 12a — PRE-EFFECT WITNESS INTERLOCK. Frontier property: a consequential effect is
// structurally unreachable unless a DURABLE commitment to its PREPARED execution was sealed FIRST (ack re-validated by
// the broker), and the receipt is bound back to that intent so a replay cannot disclose an unwitnessed result. Proven
// by disproof — neutering a check in src/broker/broker.ts (or the witness) reddens a named test:
//   sealIntent-before-execute (fail-closed) => "a failing witness aborts BEFORE any effect"
//   ack re-validation (entryHash+exec)       => "a witness ack that does not bind THIS intent is denied"
//   intent-happens-before-executor           => "the intent is sealed before the executor runs"
//   receipt binds intent (bind /v2)          => "a replay whose stored witnessEntry is tampered is denied, not disclosed"
//   replay-disclosure fail-closed            => "a served replay is witnessed before disclosure; a broken witness denies it"
//   terminal on execute error                => "an execute error seals a terminal bound to the intent (not a crash orphan)"
//   execution binding (exact-object)         => "an adapter family binds the RESOLVED object (exact-object)"
//   spine composition (no new chain)         => "intent+receipt are events on the existing spine chain"

const KEYID = "k1", SECRET = "s3cr3t";
const psigner: CompilerSigner = { signer: new StubSigner(SECRET, KEYID), keyid: KEYID, verifyKey: SECRET };
const ptrust: TrustPolicy = { trustedKeys: new Map([[KEYID, SECRET]]), threshold: 1 };
const EK = "ek1", ESEC = "effect-secret";
const esigner: EffectManifestSigner = { signer: new StubSigner(ESEC, EK), keyid: EK, verifyKey: ESEC };
const etrust: TrustPolicy = { trustedKeys: new Map([[EK, ESEC]]), threshold: 1 };
const SEAMS = { artifactGraphDigest: "a".repeat(64), scannerToolDigest: "b".repeat(64) };
const permitKey: PermitKey = { issuer: "monitor", rootKey: "root-K" };

function policyBundle(): SignedBundle {
  const p: JsonValue = {
    version: 1n, combiningAlgorithm: "deny-overrides",
    principals: [{ name: "agent", labels: [] }],
    effects: [{ id: "e", effectType: "fs.read", resourceSelector: "/x" }],
    guards: [],
    rules: [{ id: "r", decision: "permit", subjects: ["agent"], entryPoints: ["*"], effect: "e" }],
  };
  return compilePolicy(p, [psigner]);
}

/** A configurable in-memory DurableWitness that RECORDS every call (order-stamped) and can be told to misbehave. By
 *  default it returns a CORRECTLY-BOUND ack (entryHash = the intent content id, executionDigest echoed). */
interface WitnessLog { seq: number; kind: string; intentHash?: string; disposition?: string }
class RecordingWitness implements DurableWitness {
  readonly log: WitnessLog[] = [];
  #tick = 0;
  constructor(private readonly opts: { failIntent?: boolean; badEntry?: boolean; badExec?: boolean; failReplay?: boolean; failReceipt?: boolean } = {}) {}
  async sealIntent(i: WitnessIntent): Promise<WitnessAck> {
    this.log.push({ seq: this.#tick++, kind: "intent", intentHash: intentEntryHash(i) });
    if (this.opts.failIntent) throw new Error("witness down");
    return {
      chainId: "test", seq: 0n, root: "0".repeat(64), headHash: "0".repeat(64),
      entryHash: this.opts.badEntry ? "d".repeat(64) : intentEntryHash(i),
      executionDigest: this.opts.badExec ? "e".repeat(64) : i.executionDigest,
    };
  }
  async sealReceipt(r: WitnessReceipt): Promise<void> { this.log.push({ seq: this.#tick++, kind: "receipt", intentHash: r.intentEntryHash }); if (this.opts.failReceipt) throw new Error("witness down (receipt)"); }
  async sealTerminal(t: WitnessTerminal): Promise<void> { this.log.push({ seq: this.#tick++, kind: "terminal", intentHash: t.intentEntryHash, disposition: t.disposition }); }
  async observeReplay(r: ReplayDisclosure): Promise<void> { this.log.push({ seq: this.#tick++, kind: "replay", intentHash: r.intentEntryHash }); if (this.opts.failReplay) throw new Error("witness down (replay)"); }
}

interface Canary { calls: Authorized[]; order: number[]; }
function build(opts: { witness?: DurableWitness; exec?: Executor; idem?: IdempotencyStore; adapter?: ObjectAdapter } = {}) {
  const bundle = policyBundle();
  const effectId = bundle.payload.effects[0]!.id;
  const fsDecl = validateEffectDecl({ family: "fs", owner: "src/fs/owner.ts" });
  const manifest = compileEffectManifest([fsDecl], bundle, SEAMS, [esigner]);
  const canary: Canary = { calls: [], order: [] };
  let tick = 100;
  const executor: Executor = opts.exec ?? ((authz) => { canary.calls.push(authz); canary.order.push(tick++); return { ok: true }; });
  const audit = { records: [] as CanonicalValue[] };
  const sink: AuditSink = { write(r) { audit.records.push(r); } };
  const operations = new Map([["read", "read"], ["write", "write"]]);
  const ledger = new RedemptionLedger();
  const binding: FamilyBinding = opts.adapter ? { adapter: opts.adapter, audience: "broker-fs", operations } : { executor, audience: "broker-fs", operations };
  const bindings = new Map<EffectFamily, FamilyBinding>([["fs", binding]]);
  const broker = new EffectBroker(manifest, bundle, { manifestTrust: etrust, policyTrust: ptrust }, permitKey, ledger, opts.idem ?? new MapIdempotencyStore(), bindings, sink, "broker-nonce-1", opts.witness);
  return { broker, audit, canary, effectId, ledger, tickRef: () => tick };
}
function permit(effectId: string, over: Partial<PermitClaims> = {}): Permit {
  const claims: PermitClaims = {
    issuer: "monitor", subject: "agent", session: "req-1", effectId, objectId: "obj-1",
    rights: ["read", "write"], guardDigest: "a".repeat(64), epoch: 0n,
    notBefore: 0n, notAfter: 1000n, nonce: "req-1", maxRedemptions: 1n, audience: ["broker-fs"], ...over,
  };
  return mintRoot(claims, permitKey);
}
function req(effectId: string, p: Permit, over: Partial<BrokerRequest> = {}): BrokerRequest {
  return { permit: p, subject: "agent", session: "req-1", effectId, objectId: "obj-1", family: "fs", operation: "read", args: { path: "/x" }, idempotencyKey: "idem-1", ...over };
}
const kinds = (recs: CanonicalValue[]): string[] => recs.map((r) => (r as { kind: string }).kind);

test("witness coupling: a failing witness aborts BEFORE any effect (fail-closed, retryable)", async () => {
  const w = new RecordingWitness({ failIntent: true });
  const { broker, canary, effectId } = build({ witness: w });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false, "a down witness must deny the effect");
  assert.equal(canary.calls.length, 0, "the executor must NEVER run without a durable intent");
  assert.equal(w.log.filter((l) => l.kind === "intent").length, 1, "sealIntent was attempted");
  assert.equal(w.log.filter((l) => l.kind === "receipt").length, 0, "no receipt — the effect did not run");
});

test("ack re-validation: a witness ack that does not bind THIS intent is denied (bad entryHash)", async () => {
  const { broker, canary, effectId } = build({ witness: new RecordingWitness({ badEntry: true }) });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false);
  assert.equal(canary.calls.length, 0, "a stale/forged ack must not open the gate");
});

test("ack re-validation: a witness ack echoing a DIFFERENT executionDigest is denied", async () => {
  const { broker, canary, effectId } = build({ witness: new RecordingWitness({ badExec: true }) });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false);
  assert.equal(canary.calls.length, 0);
});

test("ordering: the intent is sealed BEFORE the executor runs (last fallible pre-effect step)", async () => {
  const w = new RecordingWitness();
  const order: string[] = [];
  const exec: Executor = () => { order.push("execute"); return { ok: true }; };
  const wRec = new Proxy(w, { get(t, p) { if (p === "sealIntent") return async (i: WitnessIntent) => { order.push("sealIntent"); return t.sealIntent(i); }; return (t as unknown as Record<string, unknown>)[p as string]; } }) as DurableWitness;
  const { broker, effectId } = build({ witness: wRec, exec });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, true);
  assert.deepEqual(order, ["sealIntent", "execute"], "sealIntent must happen-before the executor");
});

test("happy path witnessed: intent+receipt sealed, result carries witnessEntry, executor runs once", async () => {
  const w = new RecordingWitness();
  const { broker, canary, effectId } = build({ witness: w });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, true);
  assert.equal(canary.calls.length, 1);
  if (r.ok) { assert.equal(typeof r.witnessEntry, "string"); assert.equal(r.witnessEntry!.length, 64); }
  const seq = w.log.map((l) => l.kind);
  assert.deepEqual(seq, ["intent", "receipt"], "a completed effect seals exactly intent then receipt");
  // the receipt is bound to the same intent entry the ack returned.
  assert.equal(w.log[0]!.intentHash, w.log[1]!.intentHash);
});

test("terminal on execute error: an executor error seals a terminal bound to the intent (not a crash orphan)", async () => {
  const w = new RecordingWitness();
  const { broker, effectId } = build({ witness: w, exec: () => { throw new Error("boom"); } });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false);
  const seq = w.log.map((l) => l.kind);
  assert.deepEqual(seq, ["intent", "terminal"], "an errored effect seals intent then terminal");
  assert.equal(w.log[0]!.intentHash, w.log[1]!.intentHash, "the terminal is bound to the sealed intent");
});

test("replay disclosure: a served replay is witnessed before disclosure; a broken witness denies it", async () => {
  // 1st dispatch (fresh) with a good witness stores a witnessed Sealed. 2nd (same idemKey) is a REPLAY.
  const idem = new MapIdempotencyStore();
  const good = new RecordingWitness();
  const b1 = build({ witness: good, idem });
  const p1 = permit(b1.effectId);
  const r1 = await b1.broker.dispatch(req(b1.effectId, p1), 100n, 0n);
  assert.equal(r1.ok, true);
  // A replay through a broker whose witness FAILS observeReplay must DENY (no unwitnessed disclosure).
  const bad = new RecordingWitness({ failReplay: true });
  const b2 = build({ witness: bad, idem, exec: () => { throw new Error("replay must not re-run the executor"); } });
  const p2 = permit(b2.effectId, { nonce: "req-2" });
  const r2 = await b2.broker.dispatch(req(b2.effectId, p2), 100n, 0n);
  assert.equal(r2.ok, false, "a broken replay-witness must deny the disclosure");
  assert.ok(bad.log.some((l) => l.kind === "replay"), "observeReplay was attempted");
  // A replay through a good witness DISCLOSES and records the disclosure, without re-running the executor.
  const good2 = new RecordingWitness();
  const b3 = build({ witness: good2, idem, exec: () => { throw new Error("replay must not re-run the executor"); } });
  const p3 = permit(b3.effectId, { nonce: "req-3" });
  const r3 = await b3.broker.dispatch(req(b3.effectId, p3), 100n, 0n);
  assert.equal(r3.ok, true, "a valid replay discloses the cached result");
  assert.ok(good2.log.some((l) => l.kind === "replay"), "the disclosure was witnessed");
});

/** A Byzantine store that, on a REPLAY read, swaps the stored result's witnessEntry but keeps the original bind. */
class WitnessTamperStore implements IdempotencyStore {
  readonly #m = new Map<string, InFlight>();
  reserve(key: string, entry: InFlight): { entry: InFlight; fresh: boolean } {
    const existing = this.#m.get(key);
    if (existing !== undefined) {
      const tampered: InFlight = existing.then((s) => (s.result.ok ? Object.freeze({ result: Object.freeze({ ...s.result, witnessEntry: "d".repeat(64) }), bind: s.bind }) : s));
      return { entry: tampered, fresh: false };
    }
    this.#m.set(key, entry); return { entry, fresh: true };
  }
  release(): void { /* noop */ }
}

test("receipt binds intent: a replay whose stored witnessEntry is tampered is DENIED, not disclosed (bind /v2)", async () => {
  const idem = new WitnessTamperStore();
  const b1 = build({ witness: new RecordingWitness(), idem });
  const r1 = await b1.broker.dispatch(req(b1.effectId, permit(b1.effectId)), 100n, 0n);
  assert.equal(r1.ok, true);
  const b2 = build({ witness: new RecordingWitness(), idem, exec: () => { throw new Error("must not run"); } });
  const r2 = await b2.broker.dispatch(req(b2.effectId, permit(b2.effectId, { nonce: "req-2" })), 100n, 0n);
  assert.equal(r2.ok, false, "a tampered witnessEntry breaks the /v2 bind → deny, never disclose");
});

// ---- Integration with the REAL SpineDurableWitness (composition, not a new chain) ----
/** Minimal in-memory SpineStore for tests (the interface is 6 methods). */
class MemSpineStore implements SpineStore {
  #staged: StagedEvent[] = []; readonly #blocks: SealedBlock[] = [];
  appendStaged(e: StagedEvent): void { this.#staged.push(e); }
  readStaged(): StagedEvent[] { return this.#staged.slice(); }
  removeStaged(count: number): void { this.#staged = this.#staged.slice(count); }
  appendBlock(b: SealedBlock): void { this.#blocks.push(b); }
  readBlocks(): SealedBlock[] { return this.#blocks.slice(); }
  lastBlock(): SealedBlock | undefined { return this.#blocks[this.#blocks.length - 1]; }
}
function spineWitness(): { witness: SpineDurableWitness; spine: Spine } {
  const spine = new Spine(new MemSpineStore(), new InProcessLock(), new SchemaRegistry());
  return { witness: new SpineDurableWitness(spine, "chain-1"), spine };
}

test("spine composition: intent+receipt are events on the EXISTING spine chain (no new log)", async () => {
  const { witness, spine } = spineWitness();
  const { broker, effectId } = build({ witness });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, true);
  const types = spine.replay().map((e) => e.type);
  assert.ok(types.includes("effect.intent"), `chain had ${types.join(",")}`);
  assert.ok(types.includes("effect.receipt"), `chain had ${types.join(",")}`);
  assert.equal(spine.verify().ok, true, "the spine chain still verifies");
});

test("execution binding: an adapter family binds the RESOLVED object (exact-object)", async () => {
  const { witness, spine } = spineWitness();
  // an adapter whose prepared canonicalId differs from the caller's decoy objectId.
  const adapter: ObjectAdapter = {
    prepare: () => ({ canonicalId: "resolved-XYZ" }),
    execute: () => ({ ok: true }),
    release: () => { /* noop */ },
  };
  const { broker, effectId } = build({ witness, adapter });
  // Incr 11: the broker redeems against the RESOLVED id, so the permit authorizes "resolved-XYZ"; the request's
  // objectId "obj-1" is a decoy the broker ignores after prepare.
  const r = await broker.dispatch(req(effectId, permit(effectId, { objectId: "resolved-XYZ" }), { objectId: "obj-1" }), 100n, 0n);
  assert.equal(r.ok, true);
  const intentEv = spine.replay().find((e) => e.type === "effect.intent");
  assert.ok(intentEv, "an intent event was sealed");
  const payload = intentEv!.payload as { bindingKind: string; objectId: string };
  assert.equal(payload.bindingKind, "exact-object", "an adapter family is exact-object bound");
  assert.equal(payload.objectId, "resolved-XYZ", "bound to the RESOLVED object, not the caller decoy obj-1");
});

test("constructor: a witness missing sealReceipt is REJECTED (not a silently-skipped interlock)", () => {
  const bad = { sealIntent() {}, sealTerminal() {}, observeReplay() {} } as unknown as DurableWitness; // no sealReceipt
  assert.throws(() => build({ witness: bad }), /DurableWitness \{sealIntent, sealReceipt, sealTerminal, observeReplay\}/);
  void EffectBroker; // (constructor exercised via build())
});

test("receipt-seal failure ⇒ result is NOT marked witnessed (/v1), effect still ran", async () => {
  const w = new RecordingWitness({ failReceipt: true });
  const { broker, canary, effectId } = build({ witness: w });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, true, "the effect ran and the output is returned");
  assert.equal(canary.calls.length, 1);
  if (r.ok) assert.equal(r.witnessEntry, undefined, "a failed receipt must NOT be presented as witnessed (/v2)");
  assert.ok(w.log.some((l) => l.kind === "receipt"), "a receipt seal was attempted");
});

test("a WITNESSED /v2 result cannot be disclosed by a witness-less broker (denied)", async () => {
  const idem = new MapIdempotencyStore();
  const b1 = build({ witness: new RecordingWitness(), idem });
  const r1 = await b1.broker.dispatch(req(b1.effectId, permit(b1.effectId)), 100n, 0n);
  assert.equal(r1.ok, true);
  if (r1.ok) assert.equal(typeof r1.witnessEntry, "string", "the stored Sealed is /v2 witnessed");
  // Replay the SAME idemKey through a WITNESS-LESS broker sharing the store: it must DENY, not leak.
  const b2 = build({ idem, exec: () => { throw new Error("must not run"); } });
  const r2 = await b2.broker.dispatch(req(b2.effectId, permit(b2.effectId, { nonce: "req-2" })), 100n, 0n);
  assert.equal(r2.ok, false, "a witness-less broker must not disclose a witnessed result");
});

test("abort DURING execute seals an ABORTED terminal (not a definite error)", async () => {
  const w = new RecordingWitness();
  const ac = new AbortController();
  // an executor that never resolves but triggers the abort — race() then rejects via the signal.
  const exec: Executor = () => new Promise<CanonicalValue>(() => { ac.abort(); });
  const { broker, effectId } = build({ witness: w, exec });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n, ac.signal);
  assert.equal(r.ok, false);
  const term = w.log.find((l) => l.kind === "terminal");
  assert.ok(term, "a terminal was sealed");
  assert.equal(term!.disposition, "aborted", "a caller-abort during execute is ABORTED, not error");
});

test("sealIntent throw seals a best-effort ABORTED terminal (no false crash orphan)", async () => {
  const w = new RecordingWitness({ failIntent: true });
  const { broker, effectId } = build({ witness: w });
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, false);
  const term = w.log.find((l) => l.kind === "terminal");
  assert.ok(term, "a best-effort terminal was sealed after the intent-seal throw");
  assert.equal(term!.disposition, "aborted");
});

test("durability: the CHAIN append is fsync'd AND short writes loop to completion (crash-survival)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-witness-dur-"));
  try {
    const { io, fsyncByPath } = spyIO();
    const store = new FileSpineStore(dir, { fsync: true, io }); // 1-byte-at-a-time writes exercise the short-write loop
    const spine = new Spine(store, new InProcessLock(), new SchemaRegistry());
    const { broker, effectId } = build({ witness: new SpineDurableWitness(spine, "chain-dur") });
    const chainPath = join(dir, "chain.jsonl");
    const chainFsyncsBefore = fsyncByPath[chainPath] ?? 0;
    const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
    assert.equal(r.ok, true);
    assert.ok((fsyncByPath[chainPath] ?? 0) > chainFsyncsBefore, "the SEALED CHAIN append itself was fsync'd (not just some file)");
    // a FRESH store over the SAME dir must parse the intent block — proof the 1-byte short-write loop wrote it WHOLE
    // (a torn line would not parse) and that it was durably persisted.
    const reopened = new FileSpineStore(dir);
    const types = reopened.readBlocks().flatMap((b) => b.events.map((e) => e.type));
    assert.ok(types.includes("effect.intent"), `the full intent block survived; chain had ${types.join(",")}`);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("durability: a newly-created data directory's parent entry is fsync'd (POSIX dir-entry durability)", () => {
  const base = mkdtempSync(join(tmpdir(), "keep-witness-mkdir-"));
  try {
    const { io, fsyncByPath } = spyIO();
    const dataDir = join(base, "sub", "deep"); // two levels that do NOT exist yet
    new FileSpineStore(dataDir, { fsync: true, io });
    // each created dir's PARENT must have been fsync'd so the new entry is durable: parents are base/sub and base.
    assert.ok((fsyncByPath[join(base, "sub")] ?? 0) > 0, "the parent of the deepest new dir was fsync'd");
    assert.ok((fsyncByPath[base] ?? 0) > 0, "the parent of the first new dir was fsync'd");
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test("durability: an operational dir-fsync error (EIO) PROPAGATES fail-closed; unsupported (EINVAL) is tolerated", () => {
  const baseDir = mkdtempSync(join(tmpdir(), "keep-witness-eio-"));
  try {
    const throwingIO = (code: string, target: "directory" | "file" = "directory"): DurableIO => ({
      openSync: (p, f) => nOpen(p, f), writeSync: (fd, b, o, l) => nWrite(fd, b, o, l), closeSync: (fd) => nClose(fd),
      fsyncSync: (fd) => {
        if (fstatSync(fd).isDirectory() !== (target === "directory")) { nFsync(fd); return; }
        const e = new Error(code) as Error & { code: string }; e.code = code; throw e;
      },
    });
    // constructing in a NEW dir triggers a directory fsync; operational/permission errors must surface, only genuine
    // platform-unsupported codes are tolerated.
    assert.throws(() => new FileSpineStore(join(baseDir, "eio"), { fsync: true, io: throwingIO("EIO") }), /EIO/, "an operational fsync failure must fail closed, not be swallowed");
    assert.throws(() => new FileSpineStore(join(baseDir, "eacces"), { fsync: true, io: throwingIO("EACCES") }), /EACCES/, "a permission/ACL/sandbox denial must surface, not be hidden as a platform limit");
    assert.throws(() => new FileSpineStore(join(baseDir, "eperm"), { fsync: true, io: throwingIO("EPERM") }), /EPERM/, "an EPERM denial must surface");
    assert.doesNotThrow(() => new FileSpineStore(join(baseDir, "einval"), { fsync: true, io: throwingIO("EINVAL") }), "a platform-unsupported dir fsync (EINVAL) is tolerated (named seam)");
    assert.doesNotThrow(() => new FileSpineStore(join(baseDir, "eisdir"), { fsync: true, io: throwingIO("EISDIR") }), "a platform-unsupported dir fsync (EISDIR) is tolerated");
    assert.throws(() => new FileSpineStore(join(baseDir, "file-einval"), { fsync: true, io: throwingIO("EINVAL", "file") }), /EINVAL/, "file fsync failure must not be mistaken for unsupported directory flushing");
    assert.throws(() => new FileSpineStore(join(baseDir, "file-eio"), { fsync: true, io: throwingIO("EIO", "file") }), /EIO/);
  } finally { rmSync(baseDir, { recursive: true, force: true }); }
});

test("durability: fsync:false never invokes the configured IO flush", async () => {
  const dir = mkdtempSync(join(tmpdir(), "keep-witness-nodur-"));
  try {
    const { io, counts } = spyIO();
    const store = new FileSpineStore(dir, { fsync: false, io });
    const spine = new Spine(store, new InProcessLock(), new SchemaRegistry());
    const { broker, effectId } = build({ witness: new SpineDurableWitness(spine, "chain-nodur") });
    const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
    assert.equal(r.ok, true);
    assert.equal(counts.fsync, 0, "the non-durable path must never fsync (distinguishes it from crash-durable mode)");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("legacy: no witness ⇒ no witnessEntry, fully back-compatible", async () => {
  const { broker, canary, audit, effectId } = build();
  const r = await broker.dispatch(req(effectId, permit(effectId)), 100n, 0n);
  assert.equal(r.ok, true);
  assert.equal(canary.calls.length, 1);
  if (r.ok) assert.equal(r.witnessEntry, undefined, "a witness-less broker sets no witnessEntry");
  assert.ok(kinds(audit.records).includes("result"));
});
