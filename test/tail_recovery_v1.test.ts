import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { eirDigest } from "../src/eir/canonical.js";
import { FileSystemLock, type DistributedLock } from "../src/lock/lock.js";
import {
  AuthoritativeAppendV1,
  type AuthoritativeAppendV1Receipt,
} from "../src/spine/authoritative_append_v1.js";
import {
  CommittedHeadV1,
  type CommittedHeadV1Receipt,
  type CommittedHeadV1WitnessAck,
  type CommittedHeadV1WitnessPort,
} from "../src/spine/committed_head_v1.js";
import {
  type EventAdmissionV1LineageRecord,
  type EventAdmissionV1TrustedContext,
} from "../src/spine/event_admission_v1.js";
import {
  EventEnvelopeV1CodecIdentity,
  EventEnvelopeV1Schema,
  type EventEnvelopeV1Value,
} from "../src/spine/event_envelope_v1.js";
import {
  TailRecoveryV1,
  type TailRecoveryV1Io,
} from "../src/spine/tail_recovery_v1.js";

const profile = {
  kind: "verified-local-posix-v1" as const,
  max_record_bytes: 1_048_576n,
};
const keys = generateKeyPairSync("ed25519"),
  publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
const fresh = () => mkdtempSync(join(tmpdir(), "keep-t008-"));
class Witness implements CommittedHeadV1WitnessPort {
  current: CommittedHeadV1WitnessAck | null = null;
  async latest() {
    return this.current;
  }
  async compareAndPersist(
    expected: string | null,
    bytes: Uint8Array,
  ): Promise<CommittedHeadV1WitnessAck> {
    assert.equal(
      this.current?.ok === true ? this.current.checkpoint_digest : null,
      expected,
    );
    const ack = {
      ok: true as const,
      durable: true as const,
      checkpoint_bytes: bytes,
      checkpoint_digest: eirDigest(
        "keep.spine.committed-head-checkpoint-bytes.v1",
        bytes,
      ),
      signature: new Uint8Array(sign(null, bytes, keys.privateKey)),
    };
    this.current = ack;
    return ack;
  }
}
const context = (
  kind: "n1" | "enterprise",
  lineage: readonly EventAdmissionV1LineageRecord[] = [],
): EventAdmissionV1TrustedContext =>
  kind === "n1"
    ? {
        kind: "n1",
        track: "n1",
        history_id: "h-local",
        actor_id: "owner",
        authority_domain: "local",
        custody_id: "disk",
        committed_lineage: lineage,
        witnessed_head: lineage.length
          ? {
              sequence: lineage.at(-1)!.sequence,
              event_id: lineage.at(-1)!.event_id,
              head_id: lineage.at(-1)!.head_id,
            }
          : null,
      }
    : {
        kind: "enterprise",
        track: "enterprise",
        history_id: "h-enterprise",
        actor_id: "agent",
        authority_domain: "org/tenant",
        custody_id: "hsm",
        organization_id: "org",
        tenant_id: "tenant",
        actor_role_id: "release",
        isolation_id: "iso",
        committed_lineage: lineage,
        witnessed_head: lineage.length
          ? {
              sequence: lineage.at(-1)!.sequence,
              event_id: lineage.at(-1)!.event_id,
              head_id: lineage.at(-1)!.head_id,
            }
          : null,
      };
const proposal = (
  c: EventAdmissionV1TrustedContext,
  value: string,
): EventEnvelopeV1Value => {
  const t = c.committed_lineage.at(-1);
  return {
    schema: EventEnvelopeV1Schema,
    schema_version: 1n,
    codec: EventEnvelopeV1CodecIdentity,
    codec_version: 1n,
    history_id: c.history_id,
    sequence: t ? t.sequence + 1n : 0n,
    predecessor_event_id: t?.event_id ?? null,
    predecessor_head_id: t?.head_id ?? null,
    event_type: "goal.admitted",
    actor_id: c.actor_id,
    authority_domain: c.authority_domain,
    track: c.track,
    payload: { value },
    effect_correlation: null,
  };
};
async function fixture(kind: "n1" | "enterprise" = "n1"): Promise<{
  root: string;
  committed: CommittedHeadV1Receipt;
  tail: AuthoritativeAppendV1Receipt;
  lock: DistributedLock;
}> {
  const root = fresh();
  mkdirSync(join(root, ".locks"), { mode: 0o700 });
  const witness = new Witness(),
    base = context(kind),
    append = new AuthoritativeAppendV1({
      storage_root: root,
      durability_profile: profile,
    });
  const committedResult = await new CommittedHeadV1({
    append,
    history_storage_domain: "history-disk",
    witness_storage_domain: "witness-disk",
    witness,
    witness_public_key: publicKey,
  }).commit(proposal(base, "committed"), base);
  assert.equal(committedResult.ok, true);
  if (!committedResult.ok) throw new Error("commit refused");
  const committed = committedResult.receipt,
    lineage: EventAdmissionV1LineageRecord[] = [
      {
        sequence: committed.sequence,
        event_id: committed.event_id,
        head_id: committed.next_head_id,
        predecessor_event_id: null,
        predecessor_head_id: null,
      },
    ],
    next = context(kind, lineage),
    tailResult = await append.append(proposal(next, "tail"), next);
  assert.equal(tailResult.ok, true);
  if (!tailResult.ok) throw new Error("append refused");
  return {
    root,
    committed,
    tail: tailResult.receipt,
    lock: new FileSystemLock(join(root, ".locks")),
  };
}
const truncate = (r: AuthoritativeAppendV1Receipt) => {
  const bytes = r.record_bytes.slice(0, r.record_bytes.length - 7);
  writeFileSync(r.final_path, bytes, { mode: 0o600 });
  return bytes;
};
const recover = (
  f: Awaited<ReturnType<typeof fixture>>,
  io?: Partial<TailRecoveryV1Io>,
) =>
  new TailRecoveryV1({
    storage_root: f.root,
    max_record_bytes: profile.max_record_bytes,
    lock: f.lock,
    ...(io ? { io } : {}),
  }).recover(f.tail, f.committed);

test("PG-05-T008-FC01 quarantines only an exact n1 strict-prefix tail and converges on retry", async () => {
  const f = await fixture(),
    original = truncate(f.tail),
    r = await recover(f);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.code, "TAIL_QUARANTINED");
  assert.deepEqual(r.disposition.original_bytes, original);
  assert.deepEqual(
    new Uint8Array(readFileSync(r.disposition.quarantine_path)),
    original,
  );
  assert.equal(r.disposition.committed_head_id, f.committed.next_head_id);
  assert.equal(r.disposition.committed_history_mutated, false);
  assert.deepEqual(await recover(f), r);
});
test("PG-05-T008-FC02 preserves exact enterprise tenant and isolation authority", async () => {
  const f = await fixture("enterprise");
  truncate(f.tail);
  const r = await recover(f);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.disposition.authority.kind, "enterprise");
  if (r.disposition.authority.kind === "enterprise")
    assert.deepEqual(
      [
        r.disposition.authority.organization_id,
        r.disposition.authority.tenant_id,
        r.disposition.authority.actor_role_id,
        r.disposition.authority.isolation_id,
      ],
      ["org", "tenant", "release", "iso"],
    );
});
test("PG-05-T008-FC03 absent or refusing writer fence mutates nothing", async () => {
  const f = await fixture(),
    bytes = truncate(f.tail),
    missing = await new TailRecoveryV1({
      storage_root: f.root,
      max_record_bytes: profile.max_record_bytes,
    }).recover(f.tail, f.committed);
  assert.deepEqual(missing, { ok: false, code: "WRITER_FENCED" });
  assert.deepEqual(new Uint8Array(readFileSync(f.tail.final_path)), bytes);
  const lock: DistributedLock = {
    async withLock() {
      throw new Error("stale");
    },
  };
  assert.deepEqual(
    await new TailRecoveryV1({
      storage_root: f.root,
      max_record_bytes: profile.max_record_bytes,
      lock,
    }).recover(f.tail, f.committed),
    { ok: false, code: "WRITER_FENCED" },
  );
  assert.deepEqual(new Uint8Array(readFileSync(f.tail.final_path)), bytes);
});
test("PG-05-T008-FC04 committed-prefix corruption is never quarantined", async () => {
  const f = await fixture();
  truncate(f.tail);
  writeFileSync(f.committed.final_path, new Uint8Array([1, 2, 3]), {
    mode: 0o600,
  });
  assert.deepEqual(await recover(f), {
    ok: false,
    code: "COMMITTED_HISTORY_CORRUPT",
  });
  assert.deepEqual(
    new Uint8Array(readFileSync(f.committed.final_path)),
    new Uint8Array([1, 2, 3]),
  );
});
test("PG-05-T008-FC05 malformed physically complete final record is corruption", async () => {
  const f = await fixture(),
    bad = f.tail.record_bytes.slice();
  bad[bad.length - 1] = bad[bad.length - 1]! ^ 1;
  writeFileSync(f.tail.final_path, bad, { mode: 0o600 });
  assert.deepEqual(await recover(f), {
    ok: false,
    code: "COMMITTED_HISTORY_CORRUPT",
  });
  assert.deepEqual(new Uint8Array(readFileSync(f.tail.final_path)), bad);
});
test("PG-05-T008-FC06 quarantine failure retains the original active bytes", async () => {
  const f = await fixture(),
    bytes = truncate(f.tail),
    io: Partial<TailRecoveryV1Io> = {
      link() {
        const e = new Error("full") as NodeJS.ErrnoException;
        e.code = "ENOSPC";
        throw e;
      },
    };
  assert.deepEqual(await recover(f, io), {
    ok: false,
    code: "QUARANTINE_REQUIRED",
  });
  assert.deepEqual(new Uint8Array(readFileSync(f.tail.final_path)), bytes);
  const postUnlink = await fixture(),
    postUnlinkBytes = truncate(postUnlink.tail);
  let syncs = 0;
  const syncFailure: Partial<TailRecoveryV1Io> = {
    fsync(fd, native) {
      syncs += 1;
      if (syncs === 3) throw new Error("post-unlink sync failed");
      native(fd);
    },
  };
  assert.deepEqual(await recover(postUnlink, syncFailure), {
    ok: false,
    code: "QUARANTINE_REQUIRED",
  });
  assert.deepEqual(
    new Uint8Array(readFileSync(postUnlink.tail.final_path)),
    postUnlinkBytes,
  );
});
test("PG-05-T008-FC07 earlier corruption wins over an apparent incomplete tail", async () => {
  const f = await fixture(),
    tail = truncate(f.tail);
  writeFileSync(f.committed.final_path, new Uint8Array([9]), { mode: 0o600 });
  assert.deepEqual(await recover(f), {
    ok: false,
    code: "COMMITTED_HISTORY_CORRUPT",
  });
  assert.deepEqual(new Uint8Array(readFileSync(f.tail.final_path)), tail);
});
