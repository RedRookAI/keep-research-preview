import { test } from "node:test";
import assert from "node:assert/strict";

import { preReturnDeliberation, type DeliberationCritic } from "../src/routing/uncertainty_router.js";

// a deterministic structural critic: longer-with-more-digits is NOT rewarded; we score by a fixed lookup so tests are exact
const scoreOf = (m: Record<string, number>): DeliberationCritic => ({ score: (c) => m[c] ?? 0 });

test("PRE-RETURN-DELIBERATION (a): high-consequence is deliberated; trivial/reversible skips (consequence-gated)", () => {
  const critic = scoreOf({ orig: 1, rev: 5 });
  const rev = preReturnDeliberation({ original: "orig", revision: "rev", consequence: "reversible", critic });
  assert.equal(rev.deliberated, false);
  assert.equal(rev.outcome, "skipped-trivial");
  assert.equal(rev.returned, "orig", "trivial fast-path returns original unreviewed");
  const irr = preReturnDeliberation({ original: "orig", revision: "rev", consequence: "irreversible", critic });
  assert.equal(irr.deliberated, true, "irreversible is deliberated");
  const unk = preReturnDeliberation({ original: "orig", revision: "rev", consequence: "unknown", critic });
  assert.equal(unk.deliberated, true, "unknown is deliberated (fail-safe)");
});

test("PRE-RETURN-DELIBERATION (b): a clearly-better revision replaces the original", () => {
  const r = preReturnDeliberation({ original: "orig", revision: "rev", consequence: "irreversible", critic: scoreOf({ orig: 1, rev: 9 }) });
  assert.equal(r.outcome, "replaced-with-revision");
  assert.equal(r.returned, "rev");
});

test("PRE-RETURN-DELIBERATION (c): a tie or within-margin 'improvement' keeps the original (no change-for-change's-sake)", () => {
  // exact tie → keep
  const tie = preReturnDeliberation({ original: "orig", revision: "rev", consequence: "irreversible", critic: scoreOf({ orig: 5, rev: 5 }) });
  assert.equal(tie.outcome, "kept-original");
  assert.equal(tie.returned, "orig");
  // +2 improvement but margin 5 → ambiguous → keep
  const amb = preReturnDeliberation({ original: "orig", revision: "rev", consequence: "irreversible", margin: 5, critic: scoreOf({ orig: 5, rev: 7 }) });
  assert.equal(amb.outcome, "kept-original", "a within-margin gain is not 'clearly better'");
});

test("PRE-RETURN-DELIBERATION (d): deliberation can only keep-or-improve, never return a worse result", () => {
  const critic = scoreOf({ orig: 8, rev: 2 }); // revision is WORSE
  const r = preReturnDeliberation({ original: "orig", revision: "rev", consequence: "irreversible", critic });
  assert.equal(r.outcome, "kept-original", "a worse revision is never returned");
  assert.equal(r.returned, "orig");
  assert.ok(critic.score(r.returned) >= critic.score("orig"), "the returned result is never scored worse than the original");
});

test("PRE-RETURN-DELIBERATION (e): report-plus-choose + deterministic (changes no verdict; injected critic; stable)", () => {
  const critic = scoreOf({ orig: 1, rev: 9 });
  const input = { original: "orig", revision: "rev", consequence: "irreversible" as const, critic };
  const a = preReturnDeliberation(input);
  const b = preReturnDeliberation(input);
  assert.equal(a.changesVerdict, false, "changes no verdict — report-plus-choose only");
  assert.deepEqual(a, b, "deterministic — same inputs → same choice");
  assert.ok(a.returned === "orig" || a.returned === "rev", "returns one of {original, revision}, nothing invented");
});

test("PRE-RETURN-DELIBERATION (both-tracks): no-revision keeps original; org high-consequence always reviewed", () => {
  const critic = scoreOf({ orig: 3 });
  const noRev = preReturnDeliberation({ original: "orig", consequence: "irreversible", critic });
  assert.equal(noRev.outcome, "kept-original");
  assert.equal(noRev.deliberated, true, "org: the high-consequence path still engages even with nothing to swap in");
});
