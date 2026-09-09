import { test } from "node:test";
import assert from "node:assert/strict";

import {
  chainTaint,
  extendChain,
  checkCrossAgentFlow,
  declassifyChain,
  crossAgentAdmit,
  type ProvenanceChain,
  type Hop,
} from "../src/fleet/cross_agent_taint.js";

// Finding 2.4 — the cross-agent taint barrier. Proves the cross-agent chain logic that catches a
// forbidden source→sink path split across agents. The cross-host label propagation is the SEAM.

const hop = (agent: string, taint: "trusted" | "untrusted" | undefined, source: string): Hop => ({ agent, taint, source });

test("2.4: a 3-agent chain (retrieve tainted → transform → external emit) is DENIED at the sink", () => {
  // hop1 retrieves untrusted content; hops 2 & 3 handle it — their OWN inputs look clean (trusted).
  let chain: ProvenanceChain = { hops: [hop("retriever", "untrusted", "web_fetch")] };
  chain = extendChain(chain, hop("transformer", "trusted", "internal")); // transformer's own input is clean
  chain = extendChain(chain, hop("emitter", "trusted", "internal")); // emitter's own input is clean
  const check = checkCrossAgentFlow({ agent: "emitter", externalSink: true, chain });
  assert.equal(check.clean, false, "the cross-agent chain carries the retriever's taint to the sink");
  if (!check.clean) assert.ok(check.reason.startsWith("cross-agent-tainted-sink"));
});

test("2.4: an all-trusted cross-agent chain proceeds — no false positive (isolated)", () => {
  const chain: ProvenanceChain = { hops: [hop("a", "trusted", "internal"), hop("b", "trusted", "internal")] };
  assert.equal(checkCrossAgentFlow({ agent: "b", externalSink: true, chain }).clean, true);
});

test("2.4: an unknown-origin hop OR an empty chain ⇒ tainted (fail-safe, isolated)", () => {
  const unknown: ProvenanceChain = { hops: [hop("a", "trusted", "internal"), hop("b", undefined, "unknown")] };
  assert.equal(chainTaint(unknown), "untrusted", "an unknown hop taints the chain");
  assert.equal(checkCrossAgentFlow({ agent: "b", externalSink: true, chain: unknown }).clean, false);
  assert.equal(chainTaint({ hops: [] }), "untrusted", "an empty chain is untrusted");
});

test("2.4: an agent CANNOT self-declassify a cross-agent flow; an AUTHORIZED declassify clears it (isolated)", () => {
  const chain: ProvenanceChain = { hops: [hop("retriever", "untrusted", "web_fetch"), hop("emitter", "trusted", "internal")] };
  const selfAttempt = declassifyChain(chain, { by: "emitter", authorized: false, reason: "trust me" });
  assert.equal(checkCrossAgentFlow({ agent: "emitter", externalSink: true, chain: selfAttempt }).clean, false, "self-declassify ignored");
  const cleared = declassifyChain(chain, { by: "operator", authorized: true, reason: "reviewed" });
  assert.equal(checkCrossAgentFlow({ agent: "emitter", externalSink: true, chain: cleared }).clean, true, "authorized declassify clears");
});

test("2.4: a non-external-sink effect is not a release — not blocked here (taint still carried)", () => {
  const chain: ProvenanceChain = { hops: [hop("retriever", "untrusted", "web_fetch")] };
  assert.equal(checkCrossAgentFlow({ agent: "x", externalSink: false, chain }).clean, true, "internal effect is not the sink");
  // but the taint is preserved in the chain for the eventual sink.
  assert.equal(chainTaint(chain), "untrusted");
});

test("2.4: malformed and empty provenance fails closed before either sink or non-sink admission", () => {
  assert.deepEqual(checkCrossAgentFlow({ agent: "", externalSink: false, chain: { hops: [] } }), { clean: false, reason: "unknown-provenance-chain" });
  assert.deepEqual(checkCrossAgentFlow({ agent: "a", externalSink: false, chain: { hops: [{ agent: "", taint: "trusted", source: "x" }] } }), { clean: false, reason: "unknown-provenance-hop" });
});

test("2.4: crossAgentAdmit composes ABOVE the gate — both must clear (isolated)", () => {
  const clean = { clean: true } as const;
  const tainted = { clean: false, reason: "cross-agent-tainted-sink:web_fetch@retriever" } as const;
  assert.equal(crossAgentAdmit(true, clean).proceed, true);
  assert.equal(crossAgentAdmit(true, tainted).proceed, false, "gate passed but the cross-agent flow holds");
  assert.equal(crossAgentAdmit(false, clean).proceed, false, "gate hold never overridden");
});
