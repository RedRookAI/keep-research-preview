import { test } from "node:test";
import assert from "node:assert/strict";

import { containsVerbatim, normalizeForVerbatim } from "../src/research/grounded_answer.js";
import {
  verifyClaim,
  verifyClaimSound,
  ResearchProvenanceFloorTier,
  type CitationFetchPort,
  type ResearchVetPayload,
} from "../src/research/provenance_floor.js";
import type { ResearchClaim } from "../src/research/research_need.js";
import { VerificationCascade } from "../src/cascade/verification_cascade.js";
import { ConfidenceEscalationPolicy } from "../src/cascade/escalation_policy.js";
import { buildVettingGates } from "../src/cascade/vetting_gates.js";

// DOGFOOD-CITATION-AUTHENTICITY (BUILD-ORDER 8.1). A SOUND lexical verbatim-presence check strengthens the
// provenance floor: a Citation whose quoted supportingText is reachable-but-ABSENT at its locator is a sound
// statement-hallucination fail; unreachable/offline → unverifiable (honest seam). Keep's equivalent of the
// loop's redrook-ops/sota-citation-check.mjs. Tests use an INJECTED FAKE fetch port — never real network.

/** A fake, deterministic fetch port: returns scripted page text; any unlisted locator is unreachable (null). */
const fakePort = (pages: Record<string, string | null>): CitationFetchPort => (loc) => pages[loc] ?? null;

const REAL_PAGE = "The sky is blue due to Rayleigh scattering of sunlight by air molecules.";
const cite = (over: Record<string, unknown> = {}) => ({
  id: "z",
  title: "Optics",
  locator: "http://source",
  supportingText: "the sky is blue due to Rayleigh scattering",
  ...over,
});
const claimWith = (over: Record<string, unknown> = {}): ResearchClaim => ({
  id: "c1",
  text: "the sky is blue",
  citations: [cite(over) as never],
});

// ── The lexical primitive ────────────────────────────────────────────────────

test("verbatim primitive: present ignoring quote-mark style + whitespace; a paraphrase is ABSENT", () => {
  // whitespace-insensitive + quote-wrapping-insensitive
  assert.equal(containsVerbatim(REAL_PAGE, '  "the sky is blue due to   Rayleigh scattering" '), true);
  assert.equal(containsVerbatim("He said “hello world” today", 'hello world'), true);
  // a faithful PARAPHRASE (different words) is NOT verbatim-present — the sibling property
  assert.equal(containsVerbatim(REAL_PAGE, "the atmosphere appears azure from light scattering"), false);
  // empty quote is not a positive presence claim
  assert.equal(containsVerbatim(REAL_PAGE, "   "), false);
  assert.equal(normalizeForVerbatim('  "He  said"  '), "he said");
});

// ── The sound overlay on verifyClaim ─────────────────────────────────────────

test("sound floor: reachable-but-ABSENT verbatim quote → unsupported + sound (statement hallucination)", async () => {
  // Neuter target (a): forcing containsVerbatim to always-present reddens THIS test (fabrication passes).
  const fetch = fakePort({ "http://source": "A totally unrelated page about tax law and nothing about the sky." });
  const prov = await verifyClaimSound(claimWith(), { fetch });
  assert.equal(prov.status, "unsupported", "quote not on the page → statement hallucination");
  assert.equal(prov.sound, true, "a fetched-evidence verdict is SOUND — a fuzzy tier cannot overturn it");
});

test("INVERTED (was present→grounded,sound): a present quote with NO faithfulness checker is unverifiable — presence proves EXISTENCE, not support", async () => {
  // a847b40 asserted present→grounded,sound:true here. That was the laundering DEFECT: a real-but-
  // irrelevant quote conferred a sound pass. Verbatim presence must NEVER upgrade `unverifiable`
  // (no faithfulness checker → support-of-claim is unconfirmed). Presence is a veto on fabrication,
  // not a grant of support.
  const fetch = fakePort({ "http://source": REAL_PAGE });
  const prov = await verifyClaimSound(claimWith(), { fetch }); // present, but no faithfulness gauge
  assert.equal(prov.status, "unverifiable", "presence alone never confers support");
  assert.notEqual(prov.sound, true, "grounding/existence is never a SOUND signal");
});

test("additive-only (defect #1): a present quote whose faithfulness FAILS is `unsupported`, NOT grounded, NOT sound", async () => {
  // Neuter (a): re-introduce the additive-only violation — `if (present.length > 0) return grounded,sound`
  // BEFORE the recompute — and this test reddens (a failing faithfulness laundered into a sound pass).
  const fetch = fakePort({ "http://source": REAL_PAGE });
  const prov = await verifyClaimSound(claimWith(), { fetch, faithfulness: () => 0.1 });
  assert.equal(prov.status, "unsupported", "present quote does not override a failing faithfulness score");
  assert.notEqual(prov.sound, true, "a fuzzy faithfulness fail is not sound — it must still climb");
});

test("grounded is never SOUND (defect property d): a present + faithful quote grounds, but sound is unset", async () => {
  // Neuter (c): make the recompute/grounded path stamp `sound:true` — this test reddens.
  const fetch = fakePort({ "http://source": REAL_PAGE });
  const prov = await verifyClaimSound(claimWith(), { fetch, faithfulness: () => 0.9 });
  assert.equal(prov.status, "grounded", "present + faithful is grounded (fuzzy)");
  assert.notEqual(prov.sound, true, "grounding is NEVER sound — only fabrication FAILS are sound");
});

test("per-citation invalidation (defect #2): cite A present(0.1) + cite B ABSENT-fabricated(0.95) does NOT ground via B", async () => {
  // Neuter (b): let an absent citation keep its faithfulness score in the aggregation (push `absent`
  // into `survivors`) — then B's 0.95 grounds the claim and this test reddens. A fabricated quote is
  // written to FIT the claim, so it scores HIGH; only DISCARDING its score on proven-absence stops it.
  const fetch = fakePort({
    "http://a": REAL_PAGE, // A's quote is verbatim-present here
    "http://b": "An unrelated page that does not contain the fabricated quote at all.",
  });
  const faithfulness = (_claim: string, st: string) => (st.startsWith("FABRICATED") ? 0.95 : 0.1);
  const claim: ResearchClaim = {
    id: "c2",
    text: "the sky is blue",
    citations: [
      { id: "A", title: "real", locator: "http://a", supportingText: "the sky is blue due to Rayleigh scattering" },
      { id: "B", title: "fake", locator: "http://b", supportingText: "FABRICATED quote engineered to score high" },
    ],
  };
  const prov = await verifyClaimSound(claim, { fetch, faithfulness });
  assert.notEqual(prov.status, "grounded", "an absent-fabricated citation must not ground the claim");
  assert.equal(prov.status, "unsupported", "surviving citation A scores 0.1 < 0.6 → fuzzy unsupported");
  assert.notEqual(prov.sound, true, "a real present sibling means the residual is fuzzy, not a sound fail");
});

test("honest seam: no fetch port → unverifiable, NOT a pass; unreachable source → base verdict", async () => {
  // Neuter target (c): making the no-port branch return a silent grounded pass reddens THIS test.
  const noPort = await verifyClaimSound(claimWith(), {}); // offline / no port injected
  assert.equal(noPort.status, "unverifiable", "offline: honest unverifiable, never a silent pass");
  assert.notEqual(noPort.sound, true);
  // port present but the source is unreachable (null) → cannot confirm/deny → base verdict, not a pass/fail
  const unreachable = await verifyClaimSound(claimWith(), { fetch: fakePort({ "http://source": null }) });
  assert.equal(unreachable.status, "unverifiable", "unreachable is unverifiable, never a silent pass or false fail");
});

test("disconfirming case: a faithful PARAPHRASE on the page does not pass as a verbatim quote", async () => {
  // The page semantically entails the claim (a paraphrase) but does NOT contain the quoted words. A
  // semantic faithfulness score would pass it; the SOUND lexical check must fail it. Verbatim dominates.
  const fetch = fakePort({ "http://source": "The atmosphere appears azure because light scatters off air." });
  const prov = await verifyClaimSound(claimWith(), { fetch, faithfulness: () => 0.99 });
  assert.equal(prov.status, "unsupported", "a confident paraphrase is not a verbatim quote");
  assert.equal(prov.sound, true, "sound lexical verdict is not overturned by the high semantic score");
});

test("offline byte-parity: verifyClaimSound with no port equals verifyClaim (default unchanged)", async () => {
  for (const c of [claimWith(), claimWith({ locator: "" }), { id: "n", text: "x", citations: [] } as ResearchClaim]) {
    const sync = verifyClaim(c, { faithfulness: () => 0.9 });
    const sound = await verifyClaimSound(c, { faithfulness: () => 0.9 });
    assert.deepEqual(sound, sync, "no fetch port → the sound overlay is byte-identical to the sync floor");
  }
});

// ── The tier / cascade ───────────────────────────────────────────────────────

test("tier: a reachable-but-absent verbatim quote is a SOUND cascade FAIL", async () => {
  const cascade = new VerificationCascade<ResearchVetPayload>([new ResearchProvenanceFloorTier()], new ConfidenceEscalationPolicy());
  const fetch = fakePort({ "http://source": "unrelated page" });
  const out = await cascade.run({ id: "x", kind: "research-claim", payload: { claims: [claimWith()], options: { fetch } } });
  assert.equal(out.finalDecision, "fail", "a fabricated quote is a sound floor fail");
  assert.equal(out.decidedAtTier, 0);
  assert.match(out.reason, /quote-absent-at-source/);
});

test("tier: a verbatim-present AND faithful quote passes the floor", async () => {
  const cascade = new VerificationCascade<ResearchVetPayload>([new ResearchProvenanceFloorTier()], new ConfidenceEscalationPolicy());
  const fetch = fakePort({ "http://source": REAL_PAGE });
  // Present is necessary but not sufficient — support (faithfulness) is the other half.
  const out = await cascade.run({ id: "x", kind: "research-claim", payload: { claims: [claimWith()], options: { fetch, faithfulness: () => 0.9 } } });
  assert.equal(out.finalDecision, "pass");
});

test("tier: a verbatim-present but UNfaithful quote does NOT pass the floor — it climbs (no laundering)", async () => {
  const cascade = new VerificationCascade<ResearchVetPayload>([new ResearchProvenanceFloorTier()], new ConfidenceEscalationPolicy());
  const fetch = fakePort({ "http://source": REAL_PAGE });
  const out = await cascade.run({ id: "x", kind: "research-claim", payload: { claims: [claimWith()], options: { fetch, faithfulness: () => 0.1 } } });
  assert.notEqual(out.finalDecision, "pass", "a present-but-irrelevant quote must not be a floor pass");
});

// ── The wiring through the vetting gate ──────────────────────────────────────

test("WIRING: buildVettingGates.researchFetch routes the fetch port into the floor (fabrication caught end-to-end)", async () => {
  // Neuter target (d): dropping the fetch-merge in vetting_gates.vetResearchClaim reddens THIS test.
  // An adversarial model tier that always blesses — the sound verbatim floor must still win.
  const blessing = () => ({ decision: "pass" as const, reason: "trust me", certainty: 1 });
  const fetch = fakePort({ "http://source": "a page with no such quote on it" });
  const gates = buildVettingGates({ capability: "lean", researchSingleBrain: blessing, researchFetch: fetch });
  const out = await gates.vetResearchClaim({ claims: [claimWith()] });
  assert.equal(out.finalDecision, "fail", "gate-level fetch port catches the fabricated citation the model blessed");
  assert.equal(out.decidedAtTier, 0);
});

test("FRONT OF HOUSE: offline gate leaves a real citation unverifiable (escalate-human) — no false fail, no silent pass", async () => {
  // Solo operator, no fetch port injected (offline/default): a real citation is neither passed nor failed —
  // it climbs honestly. Never a silent pass, never a false block.
  const gates = buildVettingGates({ capability: "none" });
  const out = await gates.vetResearchClaim({ claims: [claimWith()] });
  assert.equal(out.finalDecision, "escalate-human", "offline: honest climb, not a pass and not a false fail");
});

test("FRONT OF HOUSE: a real source with a real, FAITHFUL quote passes the gate — no new friction, no false block", async () => {
  const gates = buildVettingGates({ capability: "none", researchFetch: fakePort({ "http://source": REAL_PAGE }) });
  // A genuine citation: present at its source AND supporting the claim (faithful). Passes cleanly.
  const out = await gates.vetResearchClaim({ claims: [claimWith()], options: { faithfulness: () => 0.9 } });
  assert.equal(out.finalDecision, "pass", "a genuine, faithful citation is grounded and passes");
});
