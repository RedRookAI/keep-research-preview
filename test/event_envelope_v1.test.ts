import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

import { decodeCanonical, eirDigest, encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import {
  EventEnvelopeV1CanonicalRefusal,
  EventEnvelopeV1CodecIdentity,
  EventEnvelopeV1Encode,
  EventEnvelopeV1EventTypes,
  EventEnvelopeV1Schema,
  type EventEnvelopeV1Value,
} from "../src/spine/event_envelope_v1.js";

const frozenCanonicalHex = "ae65636f64656378276b6565702e726663383934392d636f72652d64657465726d696e69737469632d63626f722e763165747261636b626e3166736368656d6178196b6565702e7370696e652e6576656e742d656e76656c6f7065677061796c6f6164a2676f7574636f6d656e7368697020636f72726563746c796776657273696f6e01686163746f725f6964676f776e65722d316873657175656e6365016a6576656e745f747970656d676f616c2e61646d69747465646a686973746f72795f696469686973746f72792d316d636f6465635f76657273696f6e016e736368656d615f76657273696f6e0170617574686f726974795f646f6d61696e6b6c6f63616c2d6f776e6572726566666563745f636f7272656c6174696f6ef6737072656465636573736f725f686561645f696466686561642d30747072656465636573736f725f6576656e745f6964676576656e742d30";
const frozenDigests = {
  "generic": "45db523a00dd656205abd36829c801fec70943b1fd3d445feb5bf8431915a12f",
  "goal.admitted": "557a16a500f7d32789fb6532d6d7efb81fb21b07617a2d2f1b5439f4d06f3193",
  "decomposition.reviewed": "a0bde5ab97a144a510ab532ae9ce06bd4968623afa25e370ca069f73570edd47",
  "decomposition.published": "360ae05cb4115033c5483e9e99442b1e518cf63d479f7ec7a3b82fa2240af7e3",
  "ticket.admitted": "19342fe26f27345fd90ecca22c7b1e290d926b0e83ee6d2de6aba44fce499251",
  "owner.delegation_granted": "50620a039273d8cd4eeea663f393f3bf2c7d2a3a0d300119609b5b3c9ce1645f",
  "recovery.n1_observed": "e1e359f48ca2e77959e7bbcbed68beb1d942ef2a738c5b2eb169caf7b3defe3b",
  "recovery.enterprise_observed": "8e79c474ffb838f9726e6f223138d67e2641401ba59bc5375817cbb845b33d1a",
} as const;

const fixture = (overrides: Partial<EventEnvelopeV1Value> = {}): EventEnvelopeV1Value => ({
  schema: EventEnvelopeV1Schema,
  schema_version: 1n,
  codec: EventEnvelopeV1CodecIdentity,
  codec_version: 1n,
  history_id: "history-1",
  sequence: 1n,
  predecessor_event_id: "event-0",
  predecessor_head_id: "head-0",
  event_type: "goal.admitted",
  actor_id: "owner-1",
  authority_domain: "local-owner",
  track: "n1",
  payload: { outcome: "ship correctly", version: 1n },
  effect_correlation: null,
  ...overrides,
});

const accepted = (value: unknown) => {
  const result = EventEnvelopeV1Encode(value);
  if (!result.ok) assert.fail(result.code);
  return result;
};

const denied = (value: unknown, code: string) => {
  const result = EventEnvelopeV1Encode(value);
  assert.deepEqual(result, { ok: false, code });
};

test("PG-05-T001-FC01 fresh processes and every owned event family share frozen bytes", () => {
  const first = accepted(fixture());
  assert.equal(Buffer.from(first.canonical_bytes).toString("hex"), frozenCanonicalHex);
  assert.equal(first.event_digest, frozenDigests["goal.admitted"]);
  const moduleUrl = new URL("../src/spine/event_envelope_v1.js", import.meta.url).href;
  const script = `import {EventEnvelopeV1Encode,EventEnvelopeV1Schema,EventEnvelopeV1CodecIdentity} from ${JSON.stringify(moduleUrl)};const r=EventEnvelopeV1Encode({schema:EventEnvelopeV1Schema,schema_version:1n,codec:EventEnvelopeV1CodecIdentity,codec_version:1n,history_id:"history-1",sequence:1n,predecessor_event_id:"event-0",predecessor_head_id:"head-0",event_type:"goal.admitted",actor_id:"owner-1",authority_domain:"local-owner",track:"n1",payload:{outcome:"ship correctly",version:1n},effect_correlation:null});if(!r.ok)throw new Error(r.code);process.stdout.write(Buffer.from(r.canonical_bytes).toString("hex")+" "+r.event_digest);`;
  for (let i = 0; i < 2; i++) {
    const child = spawnSync(process.execPath, ["--input-type=module", "--eval", script], { encoding: "utf8" });
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, `${Buffer.from(first.canonical_bytes).toString("hex")} ${first.event_digest}`);
  }
  for (const event_type of Object.keys(frozenDigests) as (keyof typeof frozenDigests)[]) {
    const authority = event_type === "recovery.enterprise_observed"
      ? { actor_id: "org-actor", authority_domain: "tenant/acme", track: "enterprise" as const }
      : {};
    assert.equal(accepted(fixture({ event_type, ...authority })).event_digest, frozenDigests[event_type]);
  }
});

test("PG-05-T001-FC02 neutral content parity does not merge track authority", () => {
  const payload = { neutral: "same", count: 1n } as const;
  const contentHex = Buffer.from(encodeCanonical(payload)).toString("hex");
  const n1 = accepted(fixture({ payload, actor_id: "local-owner", authority_domain: "local", track: "n1" }));
  const enterprise = accepted(fixture({ payload, actor_id: "org-actor", authority_domain: "tenant/acme", track: "enterprise" }));
  const n1Envelope = decodeCanonical(n1.canonical_bytes) as Record<string, CanonicalValue>;
  const enterpriseEnvelope = decodeCanonical(enterprise.canonical_bytes) as Record<string, CanonicalValue>;
  assert.equal(Buffer.from(encodeCanonical(n1Envelope.payload!)).toString("hex"), contentHex);
  assert.equal(Buffer.from(encodeCanonical(enterpriseEnvelope.payload!)).toString("hex"), contentHex);
  assert.notEqual(Buffer.from(n1.canonical_bytes).toString("hex"), Buffer.from(enterprise.canonical_bytes).toString("hex"));
  assert.notEqual(n1.event_digest, enterprise.event_digest);
});

test("PG-05-T001-FC03 exact envelope, schema, codec, and type close before encoding", () => {
  denied({ ...fixture(), extra: 1n }, "EVENT_ENVELOPE_FIELDS_INVALID");
  const missing = { ...fixture() } as Record<string, unknown>; delete missing.payload;
  denied(missing, "EVENT_ENVELOPE_FIELDS_INVALID");
  denied(fixture({ schema: "unknown" as typeof EventEnvelopeV1Schema }), "EVENT_SCHEMA_UNSUPPORTED");
  denied(fixture({ codec_version: 2n }), "EVENT_CODEC_UNSUPPORTED");
  denied(fixture({ event_type: "unknown" as EventEnvelopeV1Value["event_type"] }), "EVENT_TYPE_UNSUPPORTED");
});

test("PG-05-T001-FC04 unsupported values refuse without coercion, mutation, or fault masking", () => {
  const original = fixture();
  denied({ ...original, sequence: 1 }, "EVENT_CONTROL_INTEGER_INVALID");
  denied({ ...original, sequence: -1n }, "EVENT_CONTROL_INTEGER_INVALID");
  denied({ ...original, payload: { bad: undefined } }, "EVENT_CANONICAL_VALUE_INVALID");
  denied({ ...original, payload: { bad: Number.NaN } }, "EVENT_CANONICAL_VALUE_INVALID");
  denied({ ...original, actor_id: "e\u0301" }, "EVENT_TEXT_INVALID");
  denied({ ...original, actor_id: "bad\uD800" }, "EVENT_TEXT_INVALID");
  denied({ ...original, payload: new Date() }, "EVENT_CANONICAL_VALUE_INVALID");
  denied(new Proxy(original, {}), "EVENT_ENVELOPE_FIELDS_INVALID");
  const accessor = { ...original }; Object.defineProperty(accessor, "payload", { enumerable: true, get: () => ({ bad: true }) });
  denied(accessor, "EVENT_ENVELOPE_FIELDS_INVALID");
  let deep: unknown = "leaf"; for (let i = 0; i < 65; i++) deep = [deep];
  denied({ ...original, payload: deep }, "EVENT_CANONICAL_VALUE_INVALID");
  const success = accepted(original);
  assert.deepEqual(original, fixture());
  assert.deepEqual(success.canonical_bytes, encodeCanonical(original as unknown as CanonicalValue));
  assert.equal(success.event_digest, eirDigest("keep.spine.event-envelope.v1", original as unknown as CanonicalValue));
  assert.equal(EventEnvelopeV1CanonicalRefusal({ name: "CanonicalError" }), "EVENT_CANONICAL_VALUE_INVALID");
  const fault = new Error("programmer fault");
  assert.throws(() => EventEnvelopeV1CanonicalRefusal(fault), (error) => error === fault);
});

test("PG-05-T001-FC05 competing serializer identity is refused", () => {
  denied(fixture({ codec: "json" as typeof EventEnvelopeV1CodecIdentity }), "EVENT_CODEC_UNSUPPORTED");
});

test("PG-05-T001-FC06 effect intent and result correlation is exact and performs no effect", () => {
  denied(fixture({ event_type: "effect.intent", effect_correlation: null }), "EVENT_EFFECT_CORRELATION_INVALID");
  denied(fixture({ event_type: "generic", effect_correlation: { phase: "intent", correlation_id: "corr-1" } }), "EVENT_EFFECT_CORRELATION_INVALID");
  denied(fixture({ event_type: "effect.receipt", effect_correlation: { phase: "receipt", correlation_id: "corr-1" } as unknown as EventEnvelopeV1Value["effect_correlation"] }), "EVENT_EFFECT_CORRELATION_INVALID");
  denied(fixture({ event_type: "effect.receipt", effect_correlation: { phase: "intent", correlation_id: "corr-1", intent_event_id: "intent-1" } as unknown as EventEnvelopeV1Value["effect_correlation"] }), "EVENT_EFFECT_CORRELATION_INVALID");
  assert.equal(accepted(fixture({ event_type: "effect.intent", effect_correlation: { phase: "intent", correlation_id: "corr-1" } })).ok, true);
  assert.equal(accepted(fixture({ event_type: "effect.receipt", effect_correlation: { phase: "receipt", correlation_id: "corr-1", intent_event_id: "intent-1" } })).ok, true);
});

test("PG-05-T001-FC07 admitted runtime records the frozen golden", () => {
  const result = accepted(fixture());
  assert.equal(process.release.name, "node");
  assert.equal(process.platform, "linux");
  assert.equal(process.arch, "x64");
  assert.match(result.event_digest, /^[0-9a-f]{64}$/);
  assert.ok(result.canonical_bytes.length > 0);
  assert.equal(EventEnvelopeV1Encode(fixture(), { canonical_hex: frozenCanonicalHex, event_digest: frozenDigests["goal.admitted"] }).ok, true);
});

test("PG-05-T001-FC08 a differing executed-runtime golden admits no identity", () => {
  const baseline = accepted(fixture());
  const result = EventEnvelopeV1Encode(fixture(), { canonical_hex: "00", event_digest: baseline.event_digest });
  assert.deepEqual(result, { ok: false, code: "EVENT_CANONICAL_GOLDEN_MISMATCH" });
  const hostile = Object.defineProperty({}, "canonical_hex", { enumerable: true, get: () => { throw new Error("must not run"); } });
  Object.defineProperty(hostile, "event_digest", { enumerable: true, value: baseline.event_digest });
  assert.deepEqual(EventEnvelopeV1Encode(fixture(), hostile as unknown as { canonical_hex: string; event_digest: string }), { ok: false, code: "EVENT_CANONICAL_GOLDEN_MISMATCH" });
});

test("PG-05-T001 controls: genesis nulls, uint64 bound, and frozen type list", () => {
  assert.equal(accepted(fixture({ sequence: 0n, predecessor_event_id: null, predecessor_head_id: null })).ok, true);
  denied(fixture({ sequence: 0n }), "EVENT_PREDECESSOR_INVALID");
  denied(fixture({ sequence: 0x1_0000_0000_0000_0000n }), "EVENT_CONTROL_INTEGER_INVALID");
  assert.ok(Object.isFrozen(EventEnvelopeV1EventTypes));
  assert.deepEqual([...EventEnvelopeV1EventTypes], [
    "generic",
    "identity.created",
    "identity.action",
    "sod.approval",
    "keystore.key_created",
    "keystore.key_shredded",
    "restoration.attestation",
    "checkpoint",
    "effect.intent",
    "effect.receipt",
    "effect.terminal",
    "effect.replay-disclosure",
    "goal.admitted",
    "goal.transitioned",
    "decomposition.proposed",
    "decomposition.transitioned",
    "decomposition.reviewed",
    "decomposition.approved",
    "decomposition.published",
    "ticket.admitted",
    "owner.delegation_granted",
    "owner.delegation_revoked",
    "owner.delegation_superseded",
    "delegated.admission",
    "owner.notified",
    "execution.stopped",
    "execution.resumed",
    "recovery.n1_observed",
    "recovery.enterprise_observed",
  ]);
});
