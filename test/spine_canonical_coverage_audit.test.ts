import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { canonicalize, type StagedEvent } from "../src/spine/event.js";
import { FileSpineStore } from "../src/spine/store.js";
import { Spine } from "../src/spine/spine.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import { makeWitness, verifyChain, type SealedBlock } from "../src/spine/hashchain.js";
import { classifyChain } from "../src/witness/witness_export.js";
import { composeKeep } from "../src/compose.js";

const hash = (s: string) => createHash("sha256").update(s).digest("hex");
const fixture = () => mkdtempSync(join(tmpdir(), "keep-canonical-coverage-"));
const core = (dir: string) => new Spine(new FileSpineStore(dir, { fsync: true }), new InProcessLock(), new SchemaRegistry());
const special = () => JSON.parse('{"ordinary":"unchanged","__proto__":{"marker":"ORIGINAL"},"nested":[{"__proto__":"ORIGINAL"}]}') as Record<string, unknown>;

// Historical test-only encoder, intentionally reproducing the released defect.
function legacyEncode(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (v === null || typeof v !== "object") return v;
    if (Array.isArray(v)) return v.map(sort);
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(v).sort()) out[key] = sort((v as Record<string, unknown>)[key]);
    return out;
  };
  return JSON.stringify(sort(value));
}
function legacyBlock(payload: Record<string, unknown>): SealedBlock {
  const event: StagedEvent = { id: "historical", schemaVersion: 1, type: "generic", ts: 1234, actor: "test", payload };
  const cumulativeRoot = hash("0".repeat(64) + "|" + legacyEncode(event));
  const body = { seq: 0, prevHash: "0".repeat(64), ts: 1234, cumulativeRoot, events: [legacyEncode(event)] };
  return { ...body, events: [event], hash: hash(legacyEncode(body)) };
}

if (process.argv[2] === "--coverage-read") {
  const dir = process.argv[3]!, expected = process.argv[4] === "true";
  const before = readFileSync(join(dir, "chain.jsonl"));
  const result = core(dir).verifiedReplay();
  assert.equal(result.verification.ok, expected);
  if (!expected) assert.equal(result.events.length, 0);
  assert.deepEqual(readFileSync(join(dir, "chain.jsonl")), before, "reader must not rehash old or damaged evidence");
  console.log(JSON.stringify({ verified: result.verification.ok, events: result.events.length }));
} else {
  const childRead = (dir: string, expected: boolean) => {
    const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--coverage-read", dir, String(expected)], { encoding: "utf8", timeout: 15_000, maxBuffer: 64 * 1024 });
    assert.equal(child.status, 0, child.stderr + child.stdout);
    assert.equal(JSON.parse(child.stdout).verified, expected);
  };
  test("KEEP-09A-001 canonical JSON retains special own keys and ordinary byte ordering", () => {
    assert.equal(typeof canonicalize(special()), "string");
    const collision = JSON.parse('{"a":1,"__proto__":{"a":2}}');
    assert.equal(legacyEncode(collision), legacyEncode({ a: 1 }), "historical encoding collision, not a SHA collision");
    assert.notEqual(canonicalize(collision), canonicalize({ a: 1 }));
    assert.equal(canonicalize({ z: 1, a: { b: 2, a: 1 }, values: [true, null, "é"] }), '{"a":{"a":1,"b":2},"values":[true,null,"é"],"z":1}');
    assert.equal(canonicalize(JSON.parse('{"10":"ten","2":"two","a":1}')), '{"2":"two","10":"ten","a":1}');
    for (const value of [null, true, 7, "data", { marker: "data" }]) {
      const input = JSON.parse(JSON.stringify({ nested: [{ constructor: "data", prototype: "data", toJSON: "data" }] }));
      Object.defineProperty(input, "__proto__", { value, enumerable: true });
      Object.defineProperty(input.nested[0], "__proto__", { value, enumerable: true });
      assert.deepEqual(JSON.parse(canonicalize(input)), input);
      assert.notEqual(canonicalize(input), canonicalize({ nested: [{ constructor: "data", prototype: "data", toJSON: "data" }] }));
    }
    for (const value of [null, true, 0, -1, 1.25, "é\u0000", [], {}, [1, { z: false, a: null }]]) {
      for (const input of [value, { z: value, a: value }, { "10": value, "2": value, nested: [value] }]) {
        assert.equal(canonicalize(input), legacyEncode(input), "ordinary historical encoding remains identical");
      }
    }
  });
  test("KEEP-09A-001 ordinary legacy prefix extends with corrected special-key history", async () => {
    const dir = fixture(), spine = core(dir);
    const prefix = legacyBlock({ ordinary: "retained" });
    const prefixBytes = JSON.stringify(prefix) + "\n";
    writeFileSync(join(dir, "chain.jsonl"), prefixBytes);
    const witness = makeWitness([prefix])!;
    spine.stage({ actor: "test", type: "generic", payload: special() });
    const newBlock = await spine.seal();
    assert.equal(newBlock?.seq, 1);
    const blocks = new FileSpineStore(dir, { fsync: true }).readBlocks();
    assert.equal(verifyChain(blocks).ok, true);
    assert.equal(classifyChain(blocks, [witness]).kind, "verified");
    assert.ok(readFileSync(join(dir, "chain.jsonl"), "utf8").startsWith(prefixBytes));
    childRead(dir, true);
    Object.defineProperty(blocks[0]!.events[0]!.payload, "__proto__", { value: { newlyInserted: true }, enumerable: true });
    writeFileSync(join(dir, "chain.jsonl"), blocks.map(b => JSON.stringify(b)).join("\n") + "\n");
    assert.equal(classifyChain(blocks, [witness]).kind, "tamper", "adding an omitted key must not preserve an ordinary historical witness");
    childRead(dir, false);
  });
  for (const tenant of [undefined, "alpha"] as const) {
    test(`KEEP-09A-001 ${tenant ?? "personal"}: stored special-key changes fail replay and fixed-reference verification`, async () => {
      const dir = fixture(), app = composeKeep({ dataDir: dir, fleetLifecycle: { cap: 10, maxPerBasis: 8 },
        developmentProvider: { name: "no-model", isLocal: true, generate: async () => { throw Error("unexpected model"); }, embed: async () => { throw Error("unexpected embedding"); } } });
      const payload = special();
      if (tenant !== undefined) payload["tenant"] = tenant;
      const id = app.spine.stage({ actor: "test", type: "generic", payload });
      await app.spine.seal();
      assert.deepEqual(app.spine.verifiedReplay().events.find(e => e.id === id)!.payload, payload);
      const path = join(dir, "chain.jsonl"), original = readFileSync(path, "utf8"), blocks = original.trim().split("\n").map(s => JSON.parse(s)) as SealedBlock[];
      const witness = makeWitness(blocks)!;
      assert.equal(classifyChain(blocks, [witness]).kind, "verified");
      childRead(dir, true);
      for (const location of ["top", "array"]) {
        const changed = JSON.parse(JSON.stringify(blocks)) as SealedBlock[];
        const p = changed.flatMap(b => b.events).find(e => e.id === id)!.payload as Record<string, any>;
        if (location === "top") p["__proto__"].marker = "ALTERED";
        else p["nested"][0]["__proto__"] = "ALTERED";
        writeFileSync(path, changed.map(b => JSON.stringify(b)).join("\n") + "\n");
        assert.equal(app.spine.verifiedReplay().verification.ok, false);
        assert.equal(app.spine.verifiedReplay().events.length, 0);
        assert.equal(classifyChain(changed, [witness]).kind, "tamper");
        assert.throws(() => app.fleetLifecycle!.active(), /unverifiable Spine/);
        childRead(dir, false);
      }
      // Test-owned fixture restoration is not a product history repair.
      writeFileSync(path, original);
      assert.equal(app.spine.verify().ok, true);
    });
  }
  for (const hasSpecial of [false, true]) {
    test(`KEEP-09A-001 legacy ${hasSpecial ? "under-covered" : "ordinary"} history is not silently upgraded`, () => {
      const dir = fixture(); core(dir);
      const block = legacyBlock(hasSpecial ? special() : { ordinary: "unchanged", nested: [1, 2] });
      const bytes = JSON.stringify(block) + "\n";
      writeFileSync(join(dir, "chain.jsonl"), bytes);
      assert.equal(verifyChain([block]).ok, !hasSpecial);
      assert.equal(classifyChain([block], [makeWitness([block])!]).kind, hasSpecial ? "tamper" : "verified");
      childRead(dir, !hasSpecial);
      assert.equal(readFileSync(join(dir, "chain.jsonl"), "utf8"), bytes);
    });
  }
}
