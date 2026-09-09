import { test } from "node:test";
import assert from "node:assert/strict";

import { featurizeUncertainty, blendUncertainty, type CueKind } from "../src/anticipate/uncertainty_featurizer.js";
import { decideAsk } from "../src/anticipate/ask_gate.js";

const ALLOWED_KINDS: ReadonlySet<CueKind> = new Set(["hedge", "self-correction", "trailing-qualifier", "vagueness", "multi-intent", "tag-question"]);

test("HEDGED > CRISP: a hedged message reads as more uncertain than a direct one", () => {
  const hedged = featurizeUncertainty("maybe, i think, sort of change the homepage or something");
  const crisp = featurizeUncertainty("change the homepage header to blue");
  assert.ok(hedged.uncertainty > crisp.uncertainty, "hedged message has higher uncertainty");
  assert.equal(crisp.uncertainty, 0, "a direct message carries no hedging uncertainty");
  assert.ok(hedged.cues.length >= 2, "multiple cues detected");
});

test("EPHEMERAL: no cross-call state — intervening messages never change a re-featurized result", () => {
  const first = featurizeUncertainty("maybe, i think, sort of");
  featurizeUncertainty("delete everything in production now"); // very different intervening call
  featurizeUncertainty("a crisp clear direct request");
  const again = featurizeUncertainty("maybe, i think, sort of");
  assert.deepEqual(again, first, "the featurizer persists nothing — no drift from intervening messages");
});

test("NO-VERDICT: cues are message-level only; the note never labels the person", () => {
  const f = featurizeUncertainty("um, maybe, i'm not sure, or something");
  for (const c of f.cues) assert.ok(ALLOWED_KINDS.has(c.kind), `cue kind ${c.kind} must be message-level`);
  // The note describes the MESSAGE, not the person — no state/trait labels.
  assert.ok(/^the message /.test(f.note));
  for (const banned of ["you ", "anxious", "nervous", "uncertain person", "insecure", "lying", "deceptive"]) {
    assert.ok(!f.note.toLowerCase().includes(banned), `note must not contain a person-label: ${banned}`);
  }
});

test("RELATIVE-TO-SELF: a self-baseline discounts an habitually-hedgy user's cues", () => {
  const msg = "maybe, i think";
  const absolute = featurizeUncertainty(msg);
  const relative = featurizeUncertainty(msg, { selfBaselineRate: 0.3 });
  assert.ok(relative.uncertainty < absolute.uncertainty, "self-baseline lowers the signal for a hedgy communicator");
});

test("WEAK/ADDITIVE: a single cue is weak (below the reversible proceed line), many saturate", () => {
  const one = featurizeUncertainty("maybe do the thing"); // 'maybe' hedge + 'thing' vagueness
  assert.ok(one.uncertainty <= 0.6, "a couple of cues stay modest, not a trigger by itself");
  const many = featurizeUncertainty("maybe, i mean actually, sort of, and also, or something");
  assert.ok(many.uncertainty >= 0.8, "stacked cues saturate toward high uncertainty");
});

test("BLEND is soft-OR: raises, never lowers below either source", () => {
  assert.equal(blendUncertainty(0.7, 0), 0.7);
  assert.ok(blendUncertainty(0.7, 0.5) > 0.7, "adding cue uncertainty raises the blend");
  assert.ok(blendUncertainty(0.7, 0.5) <= 1);
});

test("COMPOSITION: cue uncertainty feeds the gate without overriding consequence", () => {
  const vague = featurizeUncertainty("maybe, sort of, or something").uncertainty;
  // Vague + reversible → still proceeds (low stakes dominate).
  assert.notEqual(decideAsk({ intentUncertainty: vague, consequence: "reversible" }).verdict, "ask");
  // Vague + irreversible → asks (uncertain AND costly).
  assert.equal(decideAsk({ intentUncertainty: vague, consequence: "irreversible" }).verdict, "ask");
});
