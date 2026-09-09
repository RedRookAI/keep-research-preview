import { test } from "node:test";
import assert from "node:assert/strict";

import { StreamingRehydrator, rehydrateStream } from "../src/privacy/streaming_rehydrator.js";
import { RedactionGateway } from "../src/privacy/redaction_gateway.js";

// build a real vault: redact a text, capture the surrogate + a rehydrate closure bound to the real values.
function realVault(text: string): { redacted: string; rehydrate: (s: string) => string } {
  const gw = new RedactionGateway();
  const r = gw.redact(text);
  return { redacted: r.redacted, rehydrate: (s: string) => gw.rehydrate(s) };
}

// split a string into arbitrary chunk sizes
function chunkify(s: string, size: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < s.length; i += size) out.push(s.slice(i, i + size));
  return out;
}

test("R-EGRESS-STREAM (a): a surrogate SPLIT across two chunks is rehydrated, not emitted raw", () => {
  const { redacted, rehydrate } = realVault("reach me at alice@corp.com thanks");
  // redacted looks like "reach me at ⟦email#1⟧ thanks"; split it right inside the surrogate
  const openIdx = redacted.indexOf("\u27E6");
  const chunk1 = redacted.slice(0, openIdx + 4); // "...⟦ema"
  const chunk2 = redacted.slice(openIdx + 4);    // "il#1⟧ thanks"
  const r = new StreamingRehydrator(rehydrate);
  let out = r.push(chunk1);
  out += r.push(chunk2);
  out += r.flush();
  assert.ok(out.includes("alice@corp.com"), "the split surrogate was rehydrated");
  assert.ok(!out.includes("\u27E6"), "no surrogate token (partial or whole) leaked to the caller");
});

test("R-EGRESS-STREAM (b): a surrogate WHOLE in one chunk still rehydrates", () => {
  const { redacted, rehydrate } = realVault("ping alice@corp.com now");
  const r = new StreamingRehydrator(rehydrate);
  const out = r.push(redacted) + r.flush();
  assert.ok(out.includes("alice@corp.com"));
  assert.ok(!out.includes("\u27E6"));
});

test("R-EGRESS-STREAM (c): streamed concatenation is BYTE-EXACT with the non-streamed rehydrate", () => {
  const { redacted, rehydrate } = realVault("emails: a@x.com and b@y.com and phone 415-555-1212");
  const nonStreamed = rehydrate(redacted);
  for (const size of [1, 2, 3, 5, 7, 13]) {
    const r = new StreamingRehydrator(rehydrate);
    let streamed = "";
    for (const c of chunkify(redacted, size)) streamed += r.push(c);
    streamed += r.flush();
    assert.equal(streamed, nonStreamed, `byte-exact at chunk size ${size}`);
  }
});

test("R-EGRESS-STREAM (d): stream end FLUSHES a buffered tail (no dropped/truncated bytes)", () => {
  const { redacted, rehydrate } = realVault("contact alice@corp.com");
  const openIdx = redacted.indexOf("\u27E6");
  const slice = redacted.slice(0, openIdx + 3); // "...⟦em" — ends MID-surrogate, so the tail stays buffered
  const r = new StreamingRehydrator(rehydrate);
  const emitted = r.push(slice);   // emits the safe prefix; holds the dangling "⟦em"
  const flushed = r.flush();        // must emit the held "⟦em" (rehydrate is a no-op on the incomplete token)
  assert.equal(emitted + flushed, slice, "flush emits the held tail byte-for-byte; nothing dropped");
});

test("R-EGRESS-STREAM (e): text with NO surrogate streams through unchanged (no over-buffering/stall)", () => {
  const rehydrate = (s: string) => s; // empty vault
  const r = new StreamingRehydrator(rehydrate);
  const first = r.push("hello world, no PII here");
  assert.equal(first, "hello world, no PII here", "clean text is emitted immediately, not buffered");
  assert.equal(r.flush(), "", "nothing left to flush");
});

test("R-EGRESS-STREAM (e2): a stray unmatched open longer than a surrogate is released (no unbounded stall)", () => {
  const rehydrate = (s: string) => s;
  const r = new StreamingRehydrator(rehydrate, 8); // tiny bound
  const stray = "\u27E6" + "x".repeat(50); // an open that never closes, well past the bound
  const out = r.push(stray);
  assert.ok(out.length > 0, "the over-long dangling open is released, not held forever");
});

test("R-EGRESS-STREAM async helper: rehydrateStream yields rehydrated chunks incl. the flushed tail", async () => {
  const { redacted, rehydrate } = realVault("hi alice@corp.com bye");
  async function* gen() { for (const c of chunkify(redacted, 3)) yield c; }
  let out = "";
  for await (const piece of rehydrateStream(gen(), rehydrate)) out += piece;
  assert.equal(out, rehydrate(redacted), "async stream rehydration is byte-exact");
});
