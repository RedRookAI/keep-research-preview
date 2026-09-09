import { test } from "node:test";
import assert from "node:assert/strict";

import {
  makeFetchReceipt,
  verifyFetchReceipt,
  evaluateResearchTriple,
  ResearchLoop,
  type TripleEvalContext,
} from "../src/research/research_loop.js";
import type { ResearchTriple, AxisSource, FetchReceipt } from "../src/research/research_need.js";
import { ageInDays, isHistoricalSource, isFreshSource } from "../src/currency/temporal_context.js";
import { buildVettingGates } from "../src/cascade/vetting_gates.js";

// TRI-FORMULA-ENFORCED-RESEARCH (BUILD-ORDER 8.6). Three axes, three DISTINCT machine predicates:
// TODAY = fetched+fresh + a hashed fetch receipt sealed to the spine; HISTORICAL = a source that FAILS
// the recency filter; CROSS-DISC = a foreign domain tag + an explicit analogical mapping. A triple that
// fills only one or two slots is REJECTED — a same-day-only search is a third of the picture. Keep's
// dogfood of the loop's sota-citation-check.mjs + the tri-formula STANDING HARNESS. No real network.

const TODAY = "2026-08-17";
const BODY = "Certificate Transparency binds a content digest to a signed timestamp.";

/** A valid TODAY slot: fresh as-of, a real receipt minted from BODY, and the body to re-verify it. */
function todaySlot(body = BODY, asOf = TODAY): AxisSource {
  const receipt = makeFetchReceipt("https://example.test/ct", body, `${asOf}T09:00:00Z`);
  return { axis: "today", citation: { id: "c-today", title: "CT posture", locator: "https://example.test/ct", asOf }, receipt, fetchedBody: body };
}

/** A valid HISTORICAL slot: a source old enough to FAIL the recency filter (years back). */
function historicalSlot(asOf = "2015-06-01"): AxisSource {
  return { axis: "historical", citation: { id: "c-hist", title: "primary vs secondary source", locator: "https://lib.test/primary", asOf, domain: "history" } };
}

/** A valid CROSS-DISC slot: a foreign domain (!= build domain) + an explicit analogical mapping. */
function crossDiscSlot(domain = "journalism", mapping = "the two-source rule maps onto: fresh != independent, so require a foreign axis"): AxisSource {
  return { axis: "cross-disc", citation: { id: "c-cross", title: "two-source rule", locator: "https://news.test/two-source", asOf: "2019-01-01", domain }, analogicalMapping: mapping };
}

const CTX: TripleEvalContext = { todayISO: TODAY, buildDomain: "security" };

function triple(over: Partial<ResearchTriple> = {}): ResearchTriple {
  return { today: todaySlot(), historical: historicalSlot(), crossDisc: crossDiscSlot(), ...over };
}

// ── 1. The happy path: a well-formed triple satisfies all three axes ──────────
test("a well-formed triple satisfies all three distinct axes", () => {
  const v = evaluateResearchTriple(triple(), CTX);
  assert.equal(v.ok, true, v.reason);
  assert.equal(v.honestSeam, false);
  assert.equal(v.slots.today.ok, true);
  assert.equal(v.slots.historical.ok, true);
  assert.equal(v.slots["cross-disc"].ok, true);
});

// ── 2. NEUTER (a) target — the HISTORICAL recency filter ──────────────────────
// Three same-day sources are NOT three axes: a same-day link in the historical slot FAILS recency.
test("a same-day source in the historical slot is REJECTED (recency filter)", () => {
  const v = evaluateResearchTriple(triple({ historical: historicalSlot(TODAY) }), CTX);
  assert.equal(v.ok, false);
  assert.equal(v.honestSeam, false); // a failed axis is not an honest seam
  assert.equal(v.slots.historical.ok, false);
  // isolation: the OTHER two axes still pass — only the historical mechanism rejects.
  assert.equal(v.slots.today.ok, true);
  assert.equal(v.slots["cross-disc"].ok, true);
});

// ── 3. NEUTER (b) target — the CROSS-DISC domain-!= check ─────────────────────
// A cross-disc source from the build's OWN domain is same-field, not cross-disciplinary corroboration.
test("a cross-disc source sharing the build domain is REJECTED (domain must differ)", () => {
  const v = evaluateResearchTriple(triple({ crossDisc: crossDiscSlot("security") }), CTX);
  assert.equal(v.ok, false);
  assert.equal(v.slots["cross-disc"].ok, false);
  // isolation: the mapping IS present, so ONLY the domain-equality check fires; other axes green.
  assert.equal(v.slots.today.ok, true);
  assert.equal(v.slots.historical.ok, true);
});

// ── 4. NEUTER (c) target — the fetch-receipt sha256/seal verify ───────────────
// A TODAY claim whose receipt does not bind the body (tampered) fails CLOSED — not an honest seam.
test("a TODAY receipt whose sha256(body) mismatches fails closed", () => {
  const slot = todaySlot();
  const tampered: AxisSource = { ...slot, fetchedBody: `${BODY} (silently edited after minting)` };
  const v = evaluateResearchTriple(triple({ today: tampered }), CTX);
  assert.equal(v.ok, false);
  assert.equal(v.slots.today.ok, false);
  assert.equal(v.slots.today.seam, undefined); // fabrication, NOT an honest seam
  assert.match(v.slots.today.reason, /fails closed|mismatch|does not verify/);
  // isolation: historical + cross-disc still pass — only the receipt mechanism fails.
  assert.equal(v.slots.historical.ok, true);
  assert.equal(v.slots["cross-disc"].ok, true);
});

// ── 5. NEUTER (d) target — the CROSS-DISC analogical-mapping presence ──────────
// A foreign-domain link with NO mapping is a bare link, not a transferred insight.
test("a cross-disc source with no analogical mapping is REJECTED", () => {
  const v = evaluateResearchTriple(triple({ crossDisc: crossDiscSlot("journalism", "") }), CTX);
  assert.equal(v.ok, false);
  assert.equal(v.slots["cross-disc"].ok, false);
  assert.match(v.slots["cross-disc"].reason, /analogical mapping/);
  // isolation: the domain IS foreign, so ONLY the mapping-presence check fires; other axes green.
  assert.equal(v.slots.today.ok, true);
  assert.equal(v.slots.historical.ok, true);
});

// ── 6. FRONT-OF-HOUSE — offline TODAY is an honest seam, not a block ──────────
test("offline (no receipt) TODAY is an honest seam when HIST + CROSS are filled", () => {
  const offlineToday: AxisSource = { axis: "today", citation: { id: "c-today", title: "no fetch", asOf: TODAY } };
  const v = evaluateResearchTriple(triple({ today: offlineToday }), CTX);
  assert.equal(v.ok, false); // not fully satisfied...
  assert.equal(v.honestSeam, true); // ...but honest, not a fabrication or a hard block
  assert.equal(v.slots.today.seam, true);
  assert.equal(v.slots.historical.ok, true);
  assert.equal(v.slots["cross-disc"].ok, true);
  assert.match(v.slots.today.reason, /seam|offline|unverifiable/i);
});

// ── 7. The fetch-receipt primitive: mint / verify / tamper ────────────────────
test("makeFetchReceipt binds bytes and verifyFetchReceipt fails closed on tamper", () => {
  const r = makeFetchReceipt("https://example.test/x", BODY, `${TODAY}T00:00:00Z`);
  assert.equal(r.bodySha256.length, 64);
  assert.equal(verifyFetchReceipt(r, BODY), true);
  // tampered BODY → sha256 mismatch → false
  assert.equal(verifyFetchReceipt(r, `${BODY} x`), false);
  // tampered SEAL → recompute mismatch → false
  const forgedSeal: FetchReceipt = { ...r, seal: "0".repeat(64) };
  assert.equal(verifyFetchReceipt(forgedSeal, BODY), false);
  // tampered bodySha256 field (claims a different digest) → seal no longer recomputes → false
  const forgedDigest: FetchReceipt = { ...r, bodySha256: "f".repeat(64) };
  assert.equal(verifyFetchReceipt(forgedDigest, BODY), false);
});

// ── 8. Sealed to the spine: receipts chain over the spine fold (priorRoot) ────
test("receipts are sealed to the spine — a different priorRoot yields a different seal", () => {
  const a = makeFetchReceipt("https://example.test/a", "alpha", `${TODAY}T00:00:00Z`);
  // chain the second against the first's seal (spine-native fold), as ResearchLoop.run does
  const b = makeFetchReceipt("https://example.test/b", "beta", `${TODAY}T00:00:00Z`, a.seal);
  assert.notEqual(a.seal, b.seal);
  assert.equal(verifyFetchReceipt(a, "alpha"), true);
  assert.equal(verifyFetchReceipt(b, "beta"), true);
  // the SAME body+url+time sealed at a different root produces a different seal → the seal binds history
  const bAtGenesis = makeFetchReceipt("https://example.test/b", "beta", `${TODAY}T00:00:00Z`);
  assert.notEqual(b.seal, bAtGenesis.seal);
});

// ── 9. Recency predicates reuse the currency clock (same-day partitions cleanly) ──
test("recency predicates: a same-day link fills TODAY but never HISTORICAL", () => {
  assert.equal(ageInDays(TODAY, TODAY), 0);
  assert.equal(ageInDays("2025-08-17", TODAY), 365); // exactly one non-leap year back
  assert.equal(ageInDays("2026-07-18", TODAY), 30); // 30 days back
  // same day: fresh yes, historical no
  assert.equal(isFreshSource(TODAY, TODAY), true);
  assert.equal(isHistoricalSource(TODAY, TODAY), false);
  // years old: historical yes, fresh no
  assert.equal(isHistoricalSource("2015-06-01", TODAY), true);
  assert.equal(isFreshSource("2015-06-01", TODAY), false);
  // undated / future: neither asserts a property we don't know
  assert.equal(isHistoricalSource(undefined, TODAY), false);
  assert.equal(isFreshSource("2099-01-01", TODAY), false); // future is not fresh
  assert.equal(ageInDays("not-a-date", TODAY), undefined);
});

// ── 10. The loop mints a receipt ONLY when a real fetch delivered bytes ───────
test("ResearchLoop mints a receipt for fetched bytes and none for snippet-only", async () => {
  const withBytes = new ResearchLoop({
    context: { canVerify: true, todayISO: TODAY },
    search: () => [{ title: "s", locator: "https://example.test/s", snippet: "snip", asOf: TODAY, body: "REAL BYTES", fetchedAt: `${TODAY}T10:00:00Z` }],
  });
  const r1 = await withBytes.run("latest 2026 sota on retrieval provenance");
  assert.equal(r1.receipts?.length, 1);
  assert.equal(verifyFetchReceipt(r1.receipts![0]!, "REAL BYTES"), true);

  const snippetOnly = new ResearchLoop({
    context: { canVerify: true, todayISO: TODAY },
    search: () => [{ title: "s", locator: "https://example.test/s", snippet: "snip", asOf: TODAY }],
  });
  const r2 = await snippetOnly.run("latest 2026 sota on retrieval provenance");
  assert.equal(r2.receipts, undefined); // honest absence — no bytes, no receipt
});

// ── 11. The vetting gate exposes the tri-formula predicate ────────────────────
test("buildVettingGates().vetResearchTriple composes the tri-formula gate", () => {
  const gates = buildVettingGates({ capability: "none" });
  const pass = gates.vetResearchTriple({ triple: triple(), context: CTX });
  assert.equal(pass.ok, true, pass.reason);
  const rejected = gates.vetResearchTriple({ triple: triple({ historical: historicalSlot(TODAY) }), context: CTX });
  assert.equal(rejected.ok, false);
  assert.equal(rejected.slots.historical.ok, false);
});

// ── 12. A receipt with no body to re-verify against fails closed (not a seam) ──
test("a TODAY receipt with no fetched body fails closed", () => {
  const base = todaySlot();
  const noBody: AxisSource = { axis: "today", citation: base.citation, receipt: base.receipt! }; // fetchedBody omitted
  const v = evaluateResearchTriple(triple({ today: noBody }), CTX);
  assert.equal(v.slots.today.ok, false);
  assert.equal(v.slots.today.seam, undefined); // a receipt you can't check is a bare claim, not a seam
});
