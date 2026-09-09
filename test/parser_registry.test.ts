import { test } from "node:test";
import assert from "node:assert/strict";

import { ParserRegistry, type ResourceBudget } from "../src/intake/parser_registry.js";
import { type IntakeItem } from "../src/intake/intake.js";

// H3: the intake safe-parsing registry — dispatch + a resource-bound gate against decompression bombs. BUILT:
// dispatch + output/depth/ratio caps. SEAM: the real codecs. Verify by disproof.

const HUGE = 1_000_000_000;
const item = (kind: string, content: string): IntakeItem => ({ kind, content });

test("output cap: a parser whose output exceeds maxOutputBytes is rejected (output-too-large)", () => {
  // isolate: generous depth + ratio, tight output; large input so ratio does NOT trip first.
  const budget: ResourceBudget = { maxOutputBytes: 100, maxDepth: HUGE, maxRatio: HUGE };
  const reg = new ParserRegistry(budget);
  reg.register("zip", () => ({ text: "x".repeat(500) })); // 500 bytes out
  const r = reg.parse(item("zip", "y".repeat(10000))); // big input ⇒ ratio 0.05, safe
  assert.equal(r.status, "rejected");
  if (r.status === "rejected") assert.equal(r.reason, "output-too-large");
});

test("depth cap: a nesting depth beyond maxDepth is rejected (too-deep)", () => {
  const budget: ResourceBudget = { maxOutputBytes: HUGE, maxDepth: 3, maxRatio: HUGE };
  const reg = new ParserRegistry(budget);
  reg.register("zip", () => ({ text: "small", depth: 9 })); // nested 9 deep
  const r = reg.parse(item("zip", "input"));
  assert.equal(r.status, "rejected");
  if (r.status === "rejected") assert.equal(r.reason, "too-deep");
});

test("ratio cap: a tiny input claiming a huge output is rejected (ratio-exceeded)", () => {
  const budget: ResourceBudget = { maxOutputBytes: HUGE, maxDepth: HUGE, maxRatio: 10 };
  const reg = new ParserRegistry(budget);
  reg.register("zip", () => ({ text: "z".repeat(1000) })); // 1000 bytes out
  const r = reg.parse(item("zip", "tiny")); // 4-byte input ⇒ ratio 250 > 10
  assert.equal(r.status, "rejected");
  if (r.status === "rejected") assert.equal(r.reason, "ratio-exceeded");
});

test("dispatch: a within-budget registered parser returns tainted text", () => {
  const reg = new ParserRegistry(); // default budget (generous)
  reg.register("voice", () => ({ text: "transcribed words" }));
  const r = reg.parse(item("voice", "<audio bytes here padding padding>"));
  assert.equal(r.status, "parsed");
  if (r.status === "parsed") {
    assert.equal(r.text.value, "transcribed words");
    assert.equal(r.text.taint, "untrusted", "extracted content stays tainted");
  }
});

test("graceful degradation: an unregistered kind, and a throwing codec, both ⇒ unsupported (no throw)", () => {
  const reg = new ParserRegistry();
  assert.equal(reg.parse(item("exe", "MZ...")).status, "unsupported", "unregistered kind");
  reg.register("image", () => { throw new Error("codec blew up"); });
  let r: ReturnType<ParserRegistry["parse"]> | undefined;
  assert.doesNotThrow(() => { r = reg.parse(item("image", "img bytes")); }, "a throwing codec does not crash the box");
  assert.equal(r?.status, "unsupported");
});

test("asParser adapts for routeIntake: within budget ⇒ text; over budget ⇒ undefined (intake degrades)", () => {
  const reg = new ParserRegistry({ maxOutputBytes: 100, maxDepth: HUGE, maxRatio: HUGE });
  reg.register("doc", (it) => ({ text: it.content.length > 50 ? "x".repeat(500) : "ok short" }));
  const parse = reg.asParser();
  assert.equal(parse(item("doc", "short input")), "ok short", "within budget ⇒ extracted text");
  assert.equal(parse(item("doc", "a".repeat(60))), undefined, "over budget ⇒ undefined (routeIntake will degrade)");
});

test("deterministic: same item + budget ⇒ same result", () => {
  const reg = new ParserRegistry();
  reg.register("text-blob", () => ({ text: "same" }));
  assert.deepEqual(reg.parse(item("text-blob", "in")), reg.parse(item("text-blob", "in")));
});
