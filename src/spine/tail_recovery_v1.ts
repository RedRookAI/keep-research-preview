import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  unlinkSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";

import {
  decodeCanonical,
  eirDigest,
  encodeCanonical,
  type CanonicalValue,
} from "../eir/canonical.js";
import { type DistributedLock } from "../lock/lock.js";
import {
  AuthoritativeAppendV1HistoryPath,
  type AuthoritativeAppendV1Receipt,
} from "./authoritative_append_v1.js";
import {
  CommittedHeadV1CheckpointDigestDomain,
  type CommittedHeadV1Receipt,
} from "./committed_head_v1.js";
import {
  EventAdmissionV1HeadDigestDomain,
  type EventAdmissionV1Authority,
} from "./event_admission_v1.js";
import { EventEnvelopeV1Encode } from "./event_envelope_v1.js";

export const TailRecoveryV1QuarantineDigestDomain =
  "keep.spine.quarantined-tail-bytes.v1" as const;
export interface TailRecoveryV1Io {
  link(source: string, destination: string, native: typeof linkSync): void;
  fsync(fd: number, native: typeof fsyncSync): void;
  unlink(path: string, native: typeof unlinkSync): void;
}
export interface TailRecoveryV1Options {
  readonly storage_root: string;
  readonly max_record_bytes: bigint;
  readonly lock?: DistributedLock;
  readonly io?: Partial<TailRecoveryV1Io>;
}
export interface TailRecoveryV1Disposition {
  readonly history_id: string;
  readonly sequence: bigint;
  readonly event_id: string;
  readonly committed_head_id: string;
  readonly authority: EventAdmissionV1Authority;
  readonly original_bytes: Uint8Array;
  readonly original_digest: string;
  readonly active_path: string;
  readonly quarantine_path: string;
  readonly committed_history_mutated: false;
  readonly tail_quarantined: true;
}
export type TailRecoveryV1Result =
  | {
      readonly ok: true;
      readonly code: "TAIL_QUARANTINED";
      readonly disposition: TailRecoveryV1Disposition;
    }
  | {
      readonly ok: false;
      readonly code:
        | "WRITER_FENCED"
        | "COMMITTED_HISTORY_CORRUPT"
        | "QUARANTINE_REQUIRED"
        | "NO_INCOMPLETE_TAIL";
    };

const recordPattern = /^([0-9a-f]{16})-([0-9a-f]{64})\.record$/;
const hex64 = /^[0-9a-f]{64}$/;
const sequenceHex = (n: bigint) => n.toString(16).padStart(16, "0");
const safeSequence = (n: unknown): n is bigint =>
  typeof n === "bigint" &&
  n >= 0n &&
  n <= 0xffffffffffffffffn &&
  n <= BigInt(Number.MAX_SAFE_INTEGER);
const sameBytes = (a: Uint8Array, b: Uint8Array) =>
  Buffer.from(a).equals(Buffer.from(b));
const digestBytes = (domain: string, bytes: Uint8Array) =>
  createHash("sha256").update(domain).update("\0").update(bytes).digest("hex");
function exactKeys(
  value: unknown,
  keys: readonly string[],
): value is Record<string, CanonicalValue> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value instanceof Uint8Array
  )
    return false;
  const actual = Reflect.ownKeys(value);
  return (
    actual.length === keys.length &&
    actual.every((k) => typeof k === "string" && keys.includes(k))
  );
}
function sameAuthority(a: unknown, b: unknown): boolean {
  try {
    return sameBytes(
      encodeCanonical(a as CanonicalValue),
      encodeCanonical(b as CanonicalValue),
    );
  } catch {
    return false;
  }
}
function privateDirectory(path: string): boolean {
  try {
    const s = lstatSync(path),
      uid = typeof process.getuid === "function" ? process.getuid() : s.uid;
    return (
      s.isDirectory() &&
      !s.isSymbolicLink() &&
      s.uid === uid &&
      (s.mode & 0o077) === 0
    );
  } catch {
    return false;
  }
}
function readPrivateFile(path: string, maximum: number): Uint8Array | null {
  let fd: number | undefined;
  try {
    fd = openSync(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const s = fstatSync(fd),
      uid = typeof process.getuid === "function" ? process.getuid() : s.uid;
    if (
      !s.isFile() ||
      s.uid !== uid ||
      (s.mode & 0o077) !== 0 ||
      s.size > maximum
    )
      return null;
    return new Uint8Array(readFileSync(fd));
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}
function syncDirectory(
  path: string,
  sync: (fd: number, native: typeof fsyncSync) => void,
): void {
  const fd = openSync(
    path,
    constants.O_RDONLY |
      constants.O_DIRECTORY |
      constants.O_NOFOLLOW |
      constants.O_NONBLOCK,
  );
  try {
    sync(fd, fsyncSync);
  } finally {
    closeSync(fd);
  }
}
type Parsed = {
  history_id: string;
  sequence: bigint;
  event_id: string;
  next_head_id: string;
  predecessor_event_id: string | null;
  predecessor_head_id: string | null;
  authority: EventAdmissionV1Authority;
};
function parseRecord(bytes: Uint8Array): Parsed | null {
  try {
    const outer = decodeCanonical(bytes);
    if (
      !exactKeys(outer, [
        "schema",
        "schema_version",
        "payload",
        "payload_length",
        "payload_digest",
      ]) ||
      outer.schema !== "keep.spine.authoritative-frame" ||
      outer.schema_version !== 1n ||
      !(outer.payload instanceof Uint8Array) ||
      outer.payload_length !== BigInt(outer.payload.length) ||
      outer.payload_digest !==
        createHash("sha256").update(outer.payload).digest("hex")
    )
      return null;
    const p = decodeCanonical(outer.payload);
    if (
      !exactKeys(p, [
        "schema",
        "schema_version",
        "event_bytes",
        "history_id",
        "sequence",
        "predecessor_event_id",
        "predecessor_head_id",
        "event_id",
        "next_head_id",
        "authority",
      ]) ||
      p.schema !== "keep.spine.authoritative-record" ||
      p.schema_version !== 1n ||
      !(p.event_bytes instanceof Uint8Array) ||
      typeof p.history_id !== "string" ||
      typeof p.sequence !== "bigint" ||
      typeof p.event_id !== "string" ||
      typeof p.next_head_id !== "string" ||
      !hex64.test(p.event_id) ||
      !hex64.test(p.next_head_id) ||
      !(
        p.predecessor_event_id === null ||
        (typeof p.predecessor_event_id === "string" &&
          hex64.test(p.predecessor_event_id))
      ) ||
      !(
        p.predecessor_head_id === null ||
        (typeof p.predecessor_head_id === "string" &&
          hex64.test(p.predecessor_head_id))
      )
    )
      return null;
    const event = decodeCanonical(p.event_bytes);
    if (
      !exactKeys(event, [
        "schema",
        "schema_version",
        "codec",
        "codec_version",
        "history_id",
        "sequence",
        "predecessor_event_id",
        "predecessor_head_id",
        "event_type",
        "actor_id",
        "authority_domain",
        "track",
        "payload",
        "effect_correlation",
      ])
    )
      return null;
    const encoded = EventEnvelopeV1Encode(event);
    if (
      !encoded.ok ||
      encoded.event_digest !== p.event_id ||
      !sameBytes(encoded.canonical_bytes, p.event_bytes)
    )
      return null;
    if (
      event.history_id !== p.history_id ||
      event.sequence !== p.sequence ||
      event.predecessor_event_id !== p.predecessor_event_id ||
      event.predecessor_head_id !== p.predecessor_head_id
    )
      return null;
    const authorityKeys =
      event.track === "enterprise"
        ? [
            "kind",
            "track",
            "actor_id",
            "authority_domain",
            "custody_id",
            "organization_id",
            "tenant_id",
            "actor_role_id",
            "isolation_id",
          ]
        : ["kind", "track", "actor_id", "authority_domain", "custody_id"];
    if (
      !exactKeys(p.authority, authorityKeys) ||
      p.authority.kind !== event.track ||
      p.authority.track !== event.track ||
      p.authority.actor_id !== event.actor_id ||
      p.authority.authority_domain !== event.authority_domain
    )
      return null;
    if (
      p.next_head_id !==
      eirDigest(EventAdmissionV1HeadDigestDomain, {
        history_id: p.history_id,
        sequence: p.sequence,
        event_id: p.event_id,
        predecessor_head_id: p.predecessor_head_id,
      })
    )
      return null;
    return {
      history_id: p.history_id,
      sequence: p.sequence,
      event_id: p.event_id,
      next_head_id: p.next_head_id,
      predecessor_event_id: p.predecessor_event_id as string | null,
      predecessor_head_id: p.predecessor_head_id as string | null,
      authority: p.authority as unknown as EventAdmissionV1Authority,
    };
  } catch {
    return null;
  }
}
function validAppendReceipt(
  value: unknown,
  root: string,
): value is AuthoritativeAppendV1Receipt {
  if (value === null || typeof value !== "object") return false;
  const r = value as Partial<AuthoritativeAppendV1Receipt>;
  if (
    typeof r.history_id !== "string" ||
    !safeSequence(r.sequence) ||
    typeof r.event_id !== "string" ||
    typeof r.next_head_id !== "string" ||
    !hex64.test(r.event_id) ||
    !hex64.test(r.next_head_id) ||
    typeof r.final_path !== "string" ||
    !(r.record_bytes instanceof Uint8Array) ||
    typeof r.record_digest !== "string" ||
    r.durability_profile !== "verified-local-posix-v1" ||
    r.durable !== true ||
    r.witnessed !== false ||
    r.committed !== false ||
    r.authoritative !== false
  )
    return false;
  const parsed = parseRecord(r.record_bytes),
    expected = join(
      AuthoritativeAppendV1HistoryPath(root, r.history_id),
      `${sequenceHex(r.sequence)}-${r.event_id}.record`,
    );
  return (
    parsed !== null &&
    parsed.history_id === r.history_id &&
    parsed.sequence === r.sequence &&
    parsed.event_id === r.event_id &&
    parsed.next_head_id === r.next_head_id &&
    sameAuthority(parsed.authority, r.authority) &&
    r.final_path === expected &&
    r.record_digest ===
      eirDigest("keep.spine.authoritative-record-bytes.v1", r.record_bytes)
  );
}
function validCommittedReceipt(
  value: unknown,
  root: string,
): value is CommittedHeadV1Receipt {
  if (value === null || typeof value !== "object") return false;
  const r = value as Partial<CommittedHeadV1Receipt>;
  if (
    typeof r.history_id !== "string" ||
    !safeSequence(r.sequence) ||
    typeof r.event_id !== "string" ||
    typeof r.next_head_id !== "string" ||
    !hex64.test(r.event_id) ||
    !hex64.test(r.next_head_id) ||
    typeof r.final_path !== "string" ||
    !(r.record_bytes instanceof Uint8Array) ||
    typeof r.record_digest !== "string" ||
    typeof r.witness_id !== "string" ||
    typeof r.checkpoint_digest !== "string" ||
    !(r.checkpoint_bytes instanceof Uint8Array) ||
    !(r.witness_signature instanceof Uint8Array) ||
    r.durability_profile !== "verified-local-posix-v1" ||
    r.durable !== true ||
    r.witnessed !== true ||
    r.committed !== true ||
    r.authoritative !== false
  )
    return false;
  const parsed = parseRecord(r.record_bytes),
    expected = join(
      AuthoritativeAppendV1HistoryPath(root, r.history_id),
      `${sequenceHex(r.sequence)}-${r.event_id}.record`,
    );
  if (
    parsed === null ||
    parsed.history_id !== r.history_id ||
    parsed.sequence !== r.sequence ||
    parsed.event_id !== r.event_id ||
    parsed.next_head_id !== r.next_head_id ||
    !sameAuthority(parsed.authority, r.authority) ||
    r.final_path !== expected ||
    r.record_digest !==
      eirDigest("keep.spine.authoritative-record-bytes.v1", r.record_bytes) ||
    r.checkpoint_digest !==
      eirDigest(CommittedHeadV1CheckpointDigestDomain, r.checkpoint_bytes)
  )
    return false;
  try {
    const c = decodeCanonical(r.checkpoint_bytes);
    return (
      exactKeys(c, [
        "schema",
        "schema_version",
        "witness_id",
        "history_storage_domain",
        "witness_storage_domain",
        "history_id",
        "sequence",
        "event_id",
        "head_id",
        "record_digest",
        "authority",
        "prior_witness_digest",
      ]) &&
      c.schema === "keep.spine.committed-head-checkpoint" &&
      c.schema_version === 1n &&
      c.witness_id === r.witness_id &&
      c.history_id === r.history_id &&
      c.sequence === r.sequence &&
      c.event_id === r.event_id &&
      c.head_id === r.next_head_id &&
      c.record_digest === r.record_digest &&
      sameAuthority(c.authority, r.authority)
    );
  } catch {
    return false;
  }
}
function copyAuthority(
  a: EventAdmissionV1Authority,
): EventAdmissionV1Authority {
  return a.kind === "n1"
    ? Object.freeze({
        kind: "n1",
        track: "n1",
        actor_id: a.actor_id,
        authority_domain: a.authority_domain,
        custody_id: a.custody_id,
      })
    : Object.freeze({
        kind: "enterprise",
        track: "enterprise",
        actor_id: a.actor_id,
        authority_domain: a.authority_domain,
        custody_id: a.custody_id,
        organization_id: a.organization_id,
        tenant_id: a.tenant_id,
        actor_role_id: a.actor_role_id,
        isolation_id: a.isolation_id,
      });
}

export class TailRecoveryV1 {
  constructor(private readonly options: TailRecoveryV1Options) {}
  async recover(
    appendReceipt: unknown,
    committedReceipt: unknown,
  ): Promise<TailRecoveryV1Result> {
    const lock = this.options.lock;
    if (lock === undefined) return { ok: false, code: "WRITER_FENCED" };
    let capturedAppend: unknown, capturedCommitted: unknown;
    try {
      capturedAppend = structuredClone(appendReceipt);
      capturedCommitted = structuredClone(committedReceipt);
    } catch {
      capturedAppend = null;
      capturedCommitted = null;
    }
    const historyId =
      typeof (capturedAppend as { history_id?: unknown })?.history_id ===
      "string"
        ? (capturedAppend as { history_id: string }).history_id
        : "invalid";
    try {
      return await lock.withLock(historyId, async () => {
        try {
          return this.inside(capturedAppend, capturedCommitted);
        } catch {
          return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" } as const;
        }
      });
    } catch {
      return { ok: false, code: "WRITER_FENCED" };
    }
  }
  private inside(
    appendValue: unknown,
    committedValue: unknown,
  ): TailRecoveryV1Result {
    const maximum = this.options.max_record_bytes;
    if (
      maximum <= 0n ||
      maximum > 67_108_864n ||
      !privateDirectory(this.options.storage_root)
    )
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    const max = Number(maximum);
    if (
      !validAppendReceipt(appendValue, this.options.storage_root) ||
      !validCommittedReceipt(committedValue, this.options.storage_root)
    )
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    const append = appendValue,
      committed = committedValue;
    if (
      append.history_id !== committed.history_id ||
      append.sequence !== committed.sequence + 1n ||
      !sameAuthority(append.authority, committed.authority)
    )
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    const expectedTail = parseRecord(append.record_bytes);
    if (
      expectedTail === null ||
      expectedTail.predecessor_event_id !== committed.event_id ||
      expectedTail.predecessor_head_id !== committed.next_head_id
    )
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    const history = AuthoritativeAppendV1HistoryPath(
      this.options.storage_root,
      append.history_id,
    );
    if (
      !privateDirectory(history) ||
      dirname(append.final_path) !== history ||
      basename(append.final_path) !==
        `${sequenceHex(append.sequence)}-${append.event_id}.record`
    )
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    let names: string[];
    try {
      names = readdirSync(history)
        .filter((n) => n.endsWith(".record"))
        .sort();
    } catch {
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    }
    let prior: Parsed | null = null;
    for (let i = 0; i <= Number(committed.sequence); i++) {
      const name = names[i],
        m = name === undefined ? null : recordPattern.exec(name);
      if (!m || BigInt(`0x${m[1]!}`) !== BigInt(i))
        return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
      const bytes = readPrivateFile(join(history, name!), max),
        record = bytes === null ? null : parseRecord(bytes);
      if (
        record === null ||
        record.history_id !== append.history_id ||
        record.sequence !== BigInt(i) ||
        record.event_id !== m[2] ||
        (i === 0 &&
          (record.predecessor_event_id !== null ||
            record.predecessor_head_id !== null)) ||
        (prior !== null &&
          (record.predecessor_event_id !== prior.event_id ||
            record.predecessor_head_id !== prior.next_head_id))
      )
        return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
      prior = record;
    }
    if (
      prior === null ||
      prior.sequence !== committed.sequence ||
      prior.event_id !== committed.event_id ||
      prior.next_head_id !== committed.next_head_id ||
      !sameAuthority(prior.authority, committed.authority)
    )
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    const committedBytes = readPrivateFile(committed.final_path, max);
    if (
      committedBytes === null ||
      !sameBytes(committedBytes, committed.record_bytes)
    )
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    const expectedName = basename(append.final_path),
      tailIndex = Number(committed.sequence) + 1;
    if (
      names.length > tailIndex + 1 ||
      (names.length === tailIndex + 1 && names[tailIndex] !== expectedName)
    )
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    const active = readPrivateFile(append.final_path, max);
    if (active === null) {
      if (names.length !== tailIndex)
        return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
      return this.retryCompleted(history, append, committed, max);
    }
    if (
      active.length === append.record_bytes.length &&
      sameBytes(active, append.record_bytes)
    )
      return { ok: false, code: "NO_INCOMPLETE_TAIL" };
    if (
      active.length === 0 ||
      active.length >= append.record_bytes.length ||
      !sameBytes(active, append.record_bytes.slice(0, active.length))
    )
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    return this.quarantine(history, active, append, committed, max);
  }
  private quarantine(
    history: string,
    original: Uint8Array,
    append: AuthoritativeAppendV1Receipt,
    committed: CommittedHeadV1Receipt,
    max: number,
  ): TailRecoveryV1Result {
    const digest = digestBytes(TailRecoveryV1QuarantineDigestDomain, original),
      directory = join(history, ".quarantine"),
      path = join(
        directory,
        `${sequenceHex(append.sequence)}-${append.event_id}.incomplete-${digest}.record`,
      ),
      io = {
        link:
          this.options.io?.link ??
          ((a: string, b: string, n: typeof linkSync) => n(a, b)),
        fsync:
          this.options.io?.fsync ??
          ((fd: number, n: typeof fsyncSync) => n(fd)),
        unlink:
          this.options.io?.unlink ??
          ((p: string, n: typeof unlinkSync) => n(p)),
      };
    try {
      if (!privateDirectory(directory)) {
        mkdirSync(directory, { mode: 0o700 });
        if (!privateDirectory(directory))
          throw new Error("quarantine directory refused");
        syncDirectory(history, io.fsync);
      }
      try {
        io.link(append.final_path, path, linkSync);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      }
      syncDirectory(directory, io.fsync);
      const retained = readPrivateFile(path, max),
        active = readPrivateFile(append.final_path, max);
      if (
        retained === null ||
        active === null ||
        !sameBytes(retained, original) ||
        !sameBytes(active, original)
      )
        throw new Error("quarantine verification failed");
      io.unlink(append.final_path, unlinkSync);
      try {
        syncDirectory(history, io.fsync);
      } catch (syncError) {
        // The evidence name is already durable. Restore the active name when the
        // post-unlink directory sync cannot be proven, then refuse disposition.
        try {
          io.link(path, append.final_path, linkSync);
          syncDirectory(history, io.fsync);
        } catch {}
        throw syncError;
      }
      return this.success(append, committed, original, digest, path);
    } catch {
      return { ok: false, code: "QUARANTINE_REQUIRED" };
    }
  }
  private retryCompleted(
    history: string,
    append: AuthoritativeAppendV1Receipt,
    committed: CommittedHeadV1Receipt,
    max: number,
  ): TailRecoveryV1Result {
    const directory = join(history, ".quarantine");
    if (!privateDirectory(directory))
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    let matches: string[];
    try {
      const prefix = `${sequenceHex(append.sequence)}-${append.event_id}.incomplete-`;
      matches = readdirSync(directory).filter(
        (n) => n.startsWith(prefix) && n.endsWith(".record"),
      );
    } catch {
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    }
    if (matches.length !== 1)
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    const name = matches[0]!,
      m = /\.incomplete-([0-9a-f]{64})\.record$/.exec(name),
      path = join(directory, name),
      original = readPrivateFile(path, max);
    if (
      m === null ||
      original === null ||
      original.length === 0 ||
      original.length >= append.record_bytes.length ||
      !sameBytes(original, append.record_bytes.slice(0, original.length)) ||
      digestBytes(TailRecoveryV1QuarantineDigestDomain, original) !== m[1]
    )
      return { ok: false, code: "COMMITTED_HISTORY_CORRUPT" };
    try {
      syncDirectory(history, this.options.io?.fsync ?? ((fd, n) => n(fd)));
    } catch {
      return { ok: false, code: "QUARANTINE_REQUIRED" };
    }
    return this.success(append, committed, original, m[1], path);
  }
  private success(
    append: AuthoritativeAppendV1Receipt,
    committed: CommittedHeadV1Receipt,
    bytes: Uint8Array,
    digest: string,
    path: string,
  ): TailRecoveryV1Result {
    return {
      ok: true,
      code: "TAIL_QUARANTINED",
      disposition: Object.freeze({
        history_id: append.history_id,
        sequence: append.sequence,
        event_id: append.event_id,
        committed_head_id: committed.next_head_id,
        authority: copyAuthority(append.authority),
        original_bytes: new Uint8Array(bytes),
        original_digest: digest,
        active_path: append.final_path,
        quarantine_path: path,
        committed_history_mutated: false,
        tail_quarantined: true,
      }),
    };
  }
}
