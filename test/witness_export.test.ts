import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, appendFileSync, symlinkSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { classifyExportLocation, assertOutOfWriteSet, DurableWitnessExport, WitnessExportError, verifyAgainstExport, classifyChain, highestWitness, isValidWitness } from "../src/witness/witness_export.js";
import { composeKeep } from "../src/compose.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import type { ChainWitness } from "../src/spine/hashchain.js";

// Mechanical-Enforcement Increment 12b — ROOT EXPORT OUT OF THE WRITE-SET + EXTERNAL-REFERENCE VERIFIER. Frontier
// property: the chain root is exported OUT of the producer's write-set (fsync-durable, symlink-canonicalized), and a
// THIRD PARTY re-derives it against that caller-supplied reference — with "internally consistent" mechanically distinct
// from "verified". Out-of-write-set is NECESSARY not SUFFICIENT (true independence = separate principal/quorum = seam).
// Proven by disproof:
//   out-of-write-set (symlink-safe)   => "a symlink into dataDir is NOT classified out-of-write-set"
//   requireIndependent fails closed   => "requireIndependentWitness refuses a same-write-set witness on every branch"
//   verifier requires external ref    => "no root => UNVERIFIED (exit 3), never a false VERIFIED"
//   anti-rollback / fork / conflict   => the verifier exit codes 2 / 1

const CLI = join(process.cwd(), "tools", "witness_verify.mjs");
function tmp(prefix: string): string { return mkdtempSync(join(tmpdir(), prefix)); }
const H = (c: string) => c.repeat(64);

test("out-of-write-set: same-dir / inside-dataDir is NOT out-of-write-set; a sibling IS", () => {
  const data = tmp("keep-12b-owset-");
  try {
    assert.equal(classifyExportLocation(data, data).outOfWriteSet, false, "equal path is same write-set");
    assert.equal(classifyExportLocation(join(data, "witness"), data).outOfWriteSet, false, "a subdir of dataDir is same write-set");
    const sib = tmp("keep-12b-sib-");
    assert.equal(classifyExportLocation(sib, data).outOfWriteSet, true, "a separate path is out-of-write-set");
    rmSync(sib, { recursive: true, force: true });
    assert.throws(() => assertOutOfWriteSet(join(data, "w"), data), /out-of-write-set witness was required/);
  } finally { rmSync(data, { recursive: true, force: true }); }
});

test("out-of-write-set is SYMLINK-SAFE: a witness dir symlinked into dataDir is NOT out-of-write-set", () => {
  const base = tmp("keep-12b-sym-");
  try {
    const realData = join(base, "realdata"); mkdirSync(realData);
    const dataLink = join(base, "datalink"); symlinkSync(realData, dataLink); // dataDir given as a symlink
    // a witness path physically INSIDE realData but reached via a lexically-outside alias must be caught.
    const aliasOutside = join(base, "outside"); symlinkSync(realData, aliasOutside); // /base/outside -> /base/realdata
    const witnessViaAlias = join(aliasOutside, "witness");
    assert.equal(classifyExportLocation(witnessViaAlias, dataLink).outOfWriteSet, false, "a symlink alias into dataDir must NOT read as out-of-write-set");
    assert.throws(() => new DurableWitnessExport(witnessViaAlias, dataLink), WitnessExportError, "the constructor must refuse the aliased same-write-set path");
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test("DurableWitnessExport REFUSES a same-write-set destination and a traversal filename", () => {
  const dataDir = tmp("keep-12b-data-");
  try {
    assert.throws(() => new DurableWitnessExport(join(dataDir, "witness"), dataDir), WitnessExportError);
    assert.throws(() => new DurableWitnessExport(dataDir, dataDir), WitnessExportError);
    const exportDir = tmp("keep-12b-exp-");
    assert.throws(() => new DurableWitnessExport(exportDir, dataDir, { filename: "../data/root" }), /basename/, "a traversal filename must be refused");
    rmSync(exportDir, { recursive: true, force: true });
  } finally { rmSync(dataDir, { recursive: true, force: true }); }
});

test("DurableWitnessExport publishes fsync-durably to an out-of-write-set path; roots survive a fresh reader", () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    const exp = new DurableWitnessExport(exportDir, dataDir);
    assert.equal(exp.location.outOfWriteSet, true);
    exp.publish({ seq: 0, cumulativeRoot: H("a"), headHash: H("b") });
    exp.publish({ seq: 1, cumulativeRoot: H("c"), headHash: H("d") });
    const reopened = new DurableWitnessExport(exportDir, dataDir);
    assert.equal(reopened.history().length, 2);
    assert.equal(reopened.latest()!.seq, 1);
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("publish REJECTS a malformed witness; history TOLERATES a torn trailing line; latest = highest seq", () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    const exp = new DurableWitnessExport(exportDir, dataDir);
    assert.throws(() => exp.publish({ seq: -1, cumulativeRoot: H("a"), headHash: H("b") } as ChainWitness), WitnessExportError, "negative seq refused");
    assert.throws(() => exp.publish({ seq: 0, cumulativeRoot: "short", headHash: H("b") } as unknown as ChainWitness), WitnessExportError, "non-hex root refused");
    exp.publish({ seq: 5, cumulativeRoot: H("a"), headHash: H("b") });
    exp.publish({ seq: 2, cumulativeRoot: H("c"), headHash: H("d") }); // lower seq appended AFTER
    // a torn/partial trailing line must NOT crash the reader.
    appendFileSync(join(exportDir, "witness-export.jsonl"), '{"seq":9,"cumulativeRoot":"');
    const reopened = new DurableWitnessExport(exportDir, dataDir);
    assert.doesNotThrow(() => reopened.history());
    assert.equal(reopened.history().length, 2, "the torn line is skipped, valid records kept");
    assert.equal(reopened.latest()!.seq, 5, "latest is the HIGHEST seq, not the last line");
    assert.equal(isValidWitness({ seq: 5, cumulativeRoot: H("a"), headHash: H("b") }), true);
    assert.equal(isValidWitness({ seq: 1.5, cumulativeRoot: H("a"), headHash: H("b") }), false);
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("highestWitness: conflict at the MAX seq (order-independent); a fork BELOW the HWM is not a conflict", () => {
  const a: ChainWitness = { seq: 3, cumulativeRoot: H("a"), headHash: H("a") };
  const b: ChainWitness = { seq: 3, cumulativeRoot: H("b"), headHash: H("b") };
  const five: ChainWitness = { seq: 5, cumulativeRoot: H("5"), headHash: H("5") };
  assert.equal(highestWitness([a]).kind, "ok");
  assert.equal(highestWitness([a, b]).kind, "conflict", "same max seq, different digests => the external history forked");
  // ORDER-INDEPENDENCE: whether the two seq-3 forks come before or after the seq-5 HWM, both classify identically —
  // a fork BELOW the HWM does not affect anti-rollback against the HWM.
  assert.equal(highestWitness([a, b, five]).kind, "ok", "a fork at seq 3 below the HWM (5) is not a conflict");
  assert.equal(highestWitness([five, a, b]).kind, "ok", "…and the same regardless of order");
  // a genuine fork AT the HWM is a conflict either order.
  const fiveB: ChainWitness = { seq: 5, cumulativeRoot: H("6"), headHash: H("6") };
  assert.equal(highestWitness([five, fiveB]).kind, "conflict");
  assert.equal(highestWitness([fiveB, a, five]).kind, "conflict");
  assert.equal(highestWitness([{ seq: -1, cumulativeRoot: H("a"), headHash: H("a") } as ChainWitness]).kind, "invalid");
});

test("history THROWS on a complete corrupt line (not a torn trailing fragment) — no silent anti-rollback downgrade", () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    const exp = new DurableWitnessExport(exportDir, dataDir);
    exp.publish({ seq: 0, cumulativeRoot: H("a"), headHash: H("b") });
    exp.publish({ seq: 1, cumulativeRoot: H("c"), headHash: H("d") });
    // corrupt the HIGHEST (complete, newline-terminated) record — this must NOT be silently skipped (which would let a
    // consumer fall back to the older seq-0 root and defeat anti-rollback); it is CORRUPTION and must throw.
    const path = join(exportDir, "witness-export.jsonl");
    const raw = readFileSync(path, "utf8");
    writeFileSync(path, raw.replace(H("d"), "not-a-hash") );
    const reopened = new DurableWitnessExport(exportDir, dataDir);
    assert.throws(() => reopened.history(), WitnessExportError, "a complete corrupt record must surface loud, never be dropped");
    assert.throws(() => reopened.latest(), WitnessExportError);
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("history THROWS on a highest record blanked to whitespace (blank record is corruption, not skippable)", () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    const exp = new DurableWitnessExport(exportDir, dataDir);
    exp.publish({ seq: 0, cumulativeRoot: H("a"), headHash: H("b") });
    exp.publish({ seq: 1, cumulativeRoot: H("c"), headHash: H("d") });
    const path = join(exportDir, "witness-export.jsonl");
    const lines = readFileSync(path, "utf8").split("\n");
    lines[1] = "   "; // blank out the highest (complete, terminated) record
    writeFileSync(path, lines.join("\n"));
    assert.throws(() => new DurableWitnessExport(exportDir, dataDir).history(), WitnessExportError, "a blanked highest record must not silently downgrade to the older root");
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("constructor REJECTS a pre-existing leaf that is a symlink (would follow it out of the pinned dir)", () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    // plant witness-export.jsonl as a symlink pointing INTO dataDir before construction.
    const evil = join(dataDir, "evil.jsonl"); writeFileSync(evil, "");
    symlinkSync(evil, join(exportDir, "witness-export.jsonl"));
    assert.throws(() => new DurableWitnessExport(exportDir, dataDir), WitnessExportError, "a symlink leaf must be refused, not followed");
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("constructor REJECTS a pre-existing DANGLING leaf symlink (existsSync would miss it; 'a'-open would create the target)", () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    // a symlink to a NON-EXISTENT target inside dataDir: existsSync() follows the link and returns false, but a later
    // append would create dataDir/evil-target.jsonl. lstat must still catch it.
    symlinkSync(join(dataDir, "evil-target.jsonl"), join(exportDir, "witness-export.jsonl"));
    assert.throws(() => new DurableWitnessExport(exportDir, dataDir), WitnessExportError, "a dangling symlink leaf must be refused");
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("latest THROWS on a conflicting external history (fork at the HWM), fail-closed", () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    const exp = new DurableWitnessExport(exportDir, dataDir);
    exp.publish({ seq: 2, cumulativeRoot: H("a"), headHash: H("a") });
    exp.publish({ seq: 2, cumulativeRoot: H("b"), headHash: H("b") }); // fork at the max seq
    assert.throws(() => exp.latest(), WitnessExportError, "a forked export must fail closed, not return an arbitrary root");
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("a second DurableWitnessExport over an existing export does NOT truncate published roots (wx create)", () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    const a = new DurableWitnessExport(exportDir, dataDir);
    a.publish({ seq: 0, cumulativeRoot: H("a"), headHash: H("b") });
    const b = new DurableWitnessExport(exportDir, dataDir); // re-open the SAME export dir
    assert.equal(b.history().length, 1, "re-opening must not truncate the existing export");
    b.publish({ seq: 1, cumulativeRoot: H("c"), headHash: H("d") });
    assert.equal(new DurableWitnessExport(exportDir, dataDir).history().length, 2);
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("verifyAgainstExport: empty is UNWITNESSED; matching verifies; truncation is rollback; conflict is fork", async () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    const store = new FileSpineStore(dataDir);
    const spine = new Spine(store, new InProcessLock(), new SchemaRegistry());
    const exp = new DurableWitnessExport(exportDir, dataDir);
    assert.equal(verifyAgainstExport(store.readBlocks(), exp.history()).ok, false);
    spine.stage({ type: "generic", actor: "t", payload: { i: 0 } }); await spine.seal(); exp.publish(spine.witnessHead()!);
    spine.stage({ type: "generic", actor: "t", payload: { i: 1 } }); await spine.seal(); exp.publish(spine.witnessHead()!);
    const full = store.readBlocks();
    assert.equal(verifyAgainstExport(full, exp.history()).ok, true);
    const check = verifyAgainstExport(full.slice(0, full.length - 1), exp.history());
    assert.equal(check.ok, false); assert.equal(check.kind, "truncation");
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("classifyChain: internally-consistent (no root) vs verified vs tamper (fork) vs rollback vs conflict", async () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    const store = new FileSpineStore(dataDir);
    const spine = new Spine(store, new InProcessLock(), new SchemaRegistry());
    const exp = new DurableWitnessExport(exportDir, dataDir);
    spine.stage({ type: "generic", actor: "t", payload: { i: 0 } }); await spine.seal(); exp.publish(spine.witnessHead()!);
    const blocks = store.readBlocks();
    const lastSeq = blocks[blocks.length - 1]!.seq;
    assert.equal(classifyChain(blocks, undefined).kind, "internally-consistent");
    assert.equal(classifyChain(blocks, exp.history()).kind, "verified");
    assert.equal(classifyChain(blocks, [{ seq: lastSeq, cumulativeRoot: H("f"), headHash: H("f") }]).kind, "tamper");
    assert.equal(classifyChain(blocks, [{ seq: lastSeq + 5, cumulativeRoot: H("e"), headHash: H("e") }]).kind, "rollback");
    // a self-forked external history (conflict) is tamper.
    assert.equal(classifyChain(blocks, [{ seq: lastSeq, cumulativeRoot: H("a"), headHash: H("a") }, { seq: lastSeq, cumulativeRoot: H("b"), headHash: H("b") }]).kind, "tamper");
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

// ---- the STANDALONE verifier CLI (the third party) ----
async function sealChain(dataDir: string, exportDir: string, n: number): Promise<void> {
  const store = new FileSpineStore(dataDir);
  const spine = new Spine(store, new InProcessLock(), new SchemaRegistry());
  const exp = new DurableWitnessExport(exportDir, dataDir);
  for (let i = 0; i < n; i++) { spine.stage({ type: "generic", actor: "t", payload: { i } }); await spine.seal(); exp.publish(spine.witnessHead()!); }
}
const runCli = (args: string[]) => spawnSync("node", [CLI, ...args], { encoding: "utf8" });

test("verifier CLI: VERIFIED (exit 0) with an external root; UNVERIFIED (exit 3) without one", async () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    await sealChain(dataDir, exportDir, 3);
    const chain = join(dataDir, "chain.jsonl"); const root = join(exportDir, "witness-export.jsonl");
    const v = runCli(["--chain", chain, "--root", root]);
    assert.equal(v.status, 0, `expected VERIFIED\n${v.stdout}\n${v.stderr}`);
    assert.match(v.stdout, /VERIFIED/);
    assert.doesNotMatch(v.stdout, /\bindependent\b/i, "the CLI must NOT claim independence (only a caller-supplied reference)");
    const u = runCli(["--chain", chain]);
    assert.equal(u.status, 3, "no external reference must be UNVERIFIED, not a false pass");
    assert.match(u.stderr, /UNVERIFIED|NOT a verification/);
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("verifier CLI: TAMPER (exit 1) on a mutated chain; ROLLBACK (exit 2) below the exported HWM", async () => {
  const dataDir = tmp("keep-12b-data-"); const exportDir = tmp("keep-12b-exp-");
  try {
    await sealChain(dataDir, exportDir, 3);
    const chain = join(dataDir, "chain.jsonl"); const root = join(exportDir, "witness-export.jsonl");
    const raw = readFileSync(chain, "utf8");
    writeFileSync(chain, raw.replace(/"i":0/, '"i":9'));
    assert.equal(runCli(["--chain", chain, "--root", root]).status, 1, "a mutated chain is TAMPER");
    const blocks = raw.split("\n").filter((l) => l.trim().length > 0);
    writeFileSync(chain, blocks[0] + "\n");
    assert.equal(runCli(["--chain", chain, "--root", root]).status, 2, "a chain below the exported HWM is ROLLBACK");
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("verifier CLI: usage error (exit 4) when --chain is missing", () => {
  assert.equal(runCli([]).status, 4);
});

// ---- compose ARM: the live app wires the export honestly + fails closed when required ----
test("composeKeep: default is detection-only and reports it honestly (not silently out-of-write-set)", () => {
  const dataDir = tmp("keep-12b-c-");
  try {
    const app = composeKeep({ dataDir });
    assert.equal(app.witnessExport.outOfWriteSet, false, "the same-dir default must report NOT out-of-write-set");
  } finally { rmSync(dataDir, { recursive: true, force: true }); }
});

test("composeKeep: an out-of-write-set witnessExportDir yields a durable, live export", async () => {
  const dataDir = tmp("keep-12b-c-"); const exportDir = tmp("keep-12b-ce-");
  try {
    const app = composeKeep({ dataDir, witnessExportDir: exportDir });
    assert.equal(app.witnessExport.outOfWriteSet, true);
    assert.ok(app.witnessSink instanceof DurableWitnessExport);
    app.spine.stage({ type: "generic", actor: "t", payload: { x: 1 } });
    await app.spine.seal();
    assert.ok(app.witnessSink.history().length >= 1, "the seal exported a root out of the write-set");
  } finally { rmSync(dataDir, { recursive: true, force: true }); rmSync(exportDir, { recursive: true, force: true }); }
});

test("composeKeep: requireIndependentWitness FAILS CLOSED on EVERY same-write-set branch", () => {
  const dataDir = tmp("keep-12b-c-");
  try {
    // (a) no export dir at all -> the same-dir default is refused.
    assert.throws(() => composeKeep({ dataDir, requireIndependentWitness: true }), WitnessExportError, "default same-dir must be refused");
    // (b) an explicitly same-write-set witnessDir -> refused.
    assert.throws(() => composeKeep({ dataDir, witnessDir: join(dataDir, "inside"), requireIndependentWitness: true }), WitnessExportError, "same-dir witnessDir must be refused");
    // (c) a same-write-set export dir -> refused.
    assert.throws(() => composeKeep({ dataDir, witnessExportDir: join(dataDir, "inside"), requireIndependentWitness: true }), WitnessExportError, "same-dir export must be refused");
  } finally { rmSync(dataDir, { recursive: true, force: true }); }
});
