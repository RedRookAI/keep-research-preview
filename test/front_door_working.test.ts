import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { MemoryStore } from "../src/memory/store.js";
import { ModelGateway } from "../src/gateway/gateway.js";
import { LocalProvider } from "../src/gateway/local_provider.js";
import { FrontDoor } from "../src/frontdoor/front_door.js";
import { buildWorkingPhase, brainBackedReviewer, deterministicFailClosedReviewer } from "../src/frontdoor/working_phase.js";
import type { PredictionSource } from "../src/frontdoor/front_door.js";
import { priorPosterior, updatePosterior, posteriorMean, type SuccessPosterior } from "../src/routing/uncertainty_router.js";
import { localBrain } from "../src/frontdoor/brain_port.js";
import type { BrainCall } from "../src/frontdoor/conversation_driver.js";

function spine(): Spine {
  return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-fdw-"))), new InProcessLock(), new SchemaRegistry());
}

/** Build a FrontDoor whose working phase uses a scripted brain. */
function frontDoor(brainCall: BrainCall, extra: { onArtifacts?: (t: string, n: number) => Promise<string> } = {}): FrontDoor {
  const sp = spine();
  const memory = new MemoryStore(sp, new ModelGateway(new LocalProvider()));
  const working = buildWorkingPhase({
    spine: sp, memory, brain: localBrain(), brainCall,
    ...(extra.onArtifacts ? { onArtifacts: extra.onArtifacts } : {}),
  });
  return new FrontDoor(memory, { working });
}

const replyBrain = (text: string): BrainCall => async () => JSON.stringify({ kind: "reply", text });

/** A FrontDoor with an injected (org-calibrated) ask-gate config. */
function frontDoorCfg(brainCall: BrainCall, askGateConfig: import("../src/anticipate/ask_gate.js").AskGateConfig): FrontDoor {
  const sp = spine();
  const memory = new MemoryStore(sp, new ModelGateway(new LocalProvider()));
  const working = buildWorkingPhase({ spine: sp, memory, brain: localBrain(), brainCall });
  return new FrontDoor(memory, { working, askGateConfig, useUncertaintyCues: true });
}

test("WORKING PHASE: a concrete task drives the keystone conversation loop", async () => {
  const fd = frontDoor(replyBrain("Sure — I'll add that."));
  const r = await fd.handle("add a login button to the homepage");
  assert.equal(r.kind, "converse");
  assert.equal(r.shape, "concrete-task");
  assert.ok(r.driverTurn, "the keystone driver produced a turn");
});

test("WORKING PHASE: a revision is classified additive-vs-destructive before driving", async () => {
  const fd = frontDoor(replyBrain("Got it, revising."));
  const r = await fd.handle("actually, change the plan — use a different approach");
  assert.equal(r.shape, "revision");
  assert.ok(r.rebuild, "a rebuild classification was attached");
  assert.equal(r.rebuild?.isPureRevision, true, "a plan revision is a pure, reversible revision (additive by default)");
});

test("WORKING PHASE: 'here are my files' → build understanding, NOT treated as a task", async () => {
  let understood = false;
  const fd = frontDoor(replyBrain("x"), { onArtifacts: async () => { understood = true; return "I read through your 3 files and here's what I understand..."; } });
  const r = await fd.handle("here are all my files, please continue this project", { hasAttachments: true, attachmentCount: 3 });
  assert.equal(r.shape, "artifact-drop");
  assert.equal(r.kind, "understand");
  assert.ok(understood, "the artifact handler (project understanding) ran");
});

test("ASK-GATE: reversible-CONTENT ambiguity PROCEEDS (autonomous-by-default) with a stated assumption", async () => {
  const fd = frontDoor(replyBrain("Sure, tell me more."));
  const r = await fd.handle("maybe tweak the homepage colors a bit"); // ambiguous shape; proceeding is a reversible edit
  assert.equal(r.shape, "ambiguous");
  assert.equal(r.kind, "converse", "reversible ambiguity proceeds instead of interrogating");
  assert.ok(/best read of this/.test(r.say), "proceed-with-note surfaces the transparent assumption");
  assert.ok(r.driverTurn, "it drove a turn on the best guess");
});

test("ASK-GATE: irreversible-signalled ambiguity ASKS one question (the one case worth a question)", async () => {
  const fd = frontDoor(replyBrain("x"));
  const r = await fd.handle("wipe it all"); // ambiguous shape, but proceeding would be irreversible
  assert.equal(r.shape, "ambiguous");
  assert.equal(r.kind, "clarify", "irreversible ambiguity still asks before acting");
  assert.ok(r.say.length > 0);
});

test("ASK-GATE: contentless ambiguity is UNKNOWN → asks (precautionary; the derived estimator won't assume safe)", async () => {
  const fd = frontDoor(replyBrain("x"));
  const r = await fd.handle("hmm"); // no consequence signal at all → unknown → precautionary ask
  assert.equal(r.shape, "ambiguous");
  assert.equal(r.kind, "clarify", "an unknown-consequence message errs toward a gentle question, not a silent guess");
});

test("ACTION GATE: a HEDGED + irreversible action asks before driving (the cue featurizer tips it)", async () => {
  const fd = frontDoor(replyBrain("x"));
  const r = await fd.handle("maybe wipe it and start over, i think?"); // revision shape; wipe = irreversible; hedged
  assert.equal(r.shape, "revision");
  assert.equal(r.kind, "clarify", "hedging about an irreversible action tips proceed -> ask");
  assert.ok(/hard to undo/.test(r.say), "it confirms before the consequential action");
});

test("ACTION GATE: the cue featurizer is DECISIVE at the margin — crisp irreversible proceeds, hedged asks", async () => {
  // An ask-averse org calibration (higher askCost) opens headroom below the ask line, so the SAME irreversible
  // action flips on hedging alone — this is where the featurizer changes a real outcome.
  const cfg = { lossWeight: { reversible: 0.1, irreversible: 1.0, unknown: 0.7 } as const, askCost: 0.25, noteThreshold: 0.5 };
  const fd = frontDoorCfg(replyBrain("Okay."), cfg);
  const crisp = await fd.handle("wipe it and start over");
  assert.equal(crisp.kind, "converse", "clear intent proceeds under the ask-averse calibration");
  const hedged = await fd.handle("maybe wipe it and start over, i think?");
  assert.equal(hedged.kind, "clarify", "the same action, hedged, asks — the cue featurizer tips it");
});

test("WORKING PHASE (degrade never break): brain unavailable → deterministic path, no throw", async () => {
  const fd = frontDoor(async () => null); // brain totally unavailable
  const r = await fd.handle("add a feature to my app");
  assert.equal(r.kind, "converse");
  assert.equal(r.driverTurn?.source, "llm-fallback-to-deterministic", "degraded to the deterministic onboarding flow");
});

test("WORKING PHASE (privacy): a secret in the message NEVER reaches the brain", async () => {
  let seenByBrain = "";
  const fd = frontDoor(async (prompt) => { seenByBrain = prompt; return JSON.stringify({ kind: "reply", text: "ok" }); });
  await fd.handle("my api key is sk-ant-SECRET123456789 please store it");
  assert.ok(!seenByBrain.includes("SECRET123456789"), "the raw secret was scrubbed before the brain saw the message");
});

test("REVIEWER (fail-closed): the brain-backed reviewer treats a brain outage as UNSAFE", async () => {
  const reviewer = brainBackedReviewer(async () => null); // brain down
  const verdict = await reviewer({ kind: "config.set" as never, args: {}, rationale: "x" }, "framing");
  assert.equal(verdict.safe, false, "a review we couldn't complete is UNSAFE, never waved through");
});

test("REVIEWER (fail-closed): an unparseable verdict is UNSAFE; a clean SAFE is respected", async () => {
  assert.equal((await brainBackedReviewer(async () => "SAFE")({ kind: "note.add" as never, args: {}, rationale: "x" }, "f")).safe, true);
  assert.equal((await brainBackedReviewer(async () => "hmm maybe?")({ kind: "note.add" as never, args: {}, rationale: "x" }, "f")).safe, false);
  assert.equal((await brainBackedReviewer(async () => "UNSAFE: leaks data")({ kind: "note.add" as never, args: {}, rationale: "x" }, "f")).safe, false);
});


// ── predict loop (offers on pull at conversation boundaries) ───────────────────

function proven(): SuccessPosterior { let p = priorPosterior(); for (let i = 0; i < 30; i++) p = updatePosterior(p, true); return p; }

/** A prediction source over a single reversible pattern with a mutable belief; records what it persists. */
function makeSource(initial: SuccessPosterior, spy: { persisted?: SuccessPosterior } = {}): PredictionSource {
  const store = new Map<string, SuccessPosterior>([["pat", initial]]);
  return {
    candidates: () => [{ id: "pat", description: "open the file you edited yesterday", consequence: "reversible", confidence: store.get("pat")!, utility: 4, interruptionCost: 0.1 }],
    persist: (id, updated) => { store.set(id, updated); spy.persisted = updated; },
  };
}

function frontDoorPred(source: PredictionSource): FrontDoor {
  const sp = spine();
  const memory = new MemoryStore(sp, new ModelGateway(new LocalProvider()));
  const working = buildWorkingPhase({ spine: sp, memory, brain: localBrain(), brainCall: replyBrain("Sure — done.") });
  return new FrontDoor(memory, { working, predictionSource: source });
}

test("PREDICT LOOP: a confident reversible prediction surfaces a transparent OFFER on the turn", async () => {
  const fd = frontDoorPred(makeSource(proven()));
  const r = await fd.handle("add a login button to the homepage"); // converse turn → offer consulted
  assert.ok(r.offer, "a proven prediction surfaces an offer");
  assert.ok(/open the file you edited yesterday/.test(r.offer!.text), "the offer is transparent about what it proposes");
  assert.equal(r.offer!.patternId, "pat");
});

test("PREDICT LOOP: an unproven prediction stays SILENT (probation — no offer on first sight)", async () => {
  const fd = frontDoorPred(makeSource(priorPosterior()));
  const r = await fd.handle("add a login button to the homepage");
  assert.equal(r.offer, undefined, "an unproven pattern does not surface an offer");
});

test("PREDICT LOOP: an offer is a SUGGESTION — surfacing it executes nothing (no auto-resolution)", async () => {
  const spy: { persisted?: SuccessPosterior } = {};
  const fd = frontDoorPred(makeSource(proven(), spy));
  const r = await fd.handle("add a login button to the homepage");
  assert.ok(r.offer, "the offer surfaced");
  assert.equal(spy.persisted, undefined, "surfacing an offer records NO outcome — nothing is executed until the user acts");
});

test("PREDICT LOOP: a declined offer LOWERS the belief via recordPredictionOutcome (overridable)", async () => {
  const spy: { persisted?: SuccessPosterior } = {};
  const start = proven();
  const fd = frontDoorPred(makeSource(start, spy));
  await fd.handle("add a login button to the homepage");
  fd.resolveOffer(false); // the user declines
  assert.ok(spy.persisted, "a resolved offer persists an updated belief");
  assert.ok(posteriorMean(spy.persisted!) < posteriorMean(start), "declining lowers the belief");
});
