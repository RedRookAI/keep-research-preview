import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { decodeCanonical, encodeCanonical, type CanonicalValue } from "../src/eir/canonical.js";
import {
  captureP2S1Canonical,
  P2_S1_COMBINED_DIGEST_REGISTRY,
  P2_S1_DIGEST_REGISTRY,
  P2_S1_SCHEMA_INVENTORY,
  P2_S1_RUST_SCHEMA_NAMES,
  P2_S1_RECURSIVE_SCHEMA_METADATA,
  P2_S1_AUTHORITY_BOUNDARY,
  p2S1OperationDigest,
  p2S1DerivedDigest,
  p2S1SignaturePreimage,
  validateP2S1CombinedDigestRegistry,
  validateP2S1DigestRegistry,
} from "../src/platform/native_authority_schema_v1.js";

const D = "ab".repeat(32);
const E = "cd".repeat(32);
const bytes = (value: CanonicalValue): Uint8Array => encodeCanonical(value);
const scopeKey = { authorityId: "authority.1", namespace: "native", scope: "host.1", genesisRootDigest: D };
const oracle = fileURLToPath(new URL("../../native/target/x86_64-unknown-linux-musl/debug/keep-native-protocol-oracle", import.meta.url));

const operations = {
  "b3-genesis-operation": { schema: "keep.native-b3-operation", version: 1n, operationKind: "genesis", genesisBaseDigest: D, b0RootEnvelopeDigest: D, b3ProfileEnvelopeDigest: D, derivedGenesisStateDigest: D, requestNonce: new Uint8Array(32).fill(1) },
  "b3-read-operation": { schema: "keep.native-b3-operation", version: 1n, operationKind: "read", scopeKey, requestNonce: new Uint8Array(32).fill(2) },
  "b3-cas-operation": { schema: "keep.native-b3-operation", version: 1n, operationKind: "compare-and-advance", scopeKey, expectedStateDigest: D, newStateDigest: E, callerPurpose: { purpose: "rollback", authorization: { kind: "rollback", authorizationEnvelopeDigest: D } }, requestNonce: new Uint8Array(32).fill(3) },
  "b3-lease-operation": { schema: "keep.native-b3-operation", version: 1n, operationKind: "validate-lease", scopeKey, generation: 1n, headEnvelopeDigest: D, b3CounterCeiling: 10n, requestNonce: new Uint8Array(32).fill(4) },
  "b3-subscribe-operation": { schema: "keep.native-b3-operation", version: 1n, operationKind: "subscribe-invalidation", scopeKey, generation: 1n, sessionId: "session.1", requestNonce: new Uint8Array(32).fill(5) },
} as const;
const rustOperationNames = {
  "b3-genesis-operation": "B3GenesisOperationV1",
  "b3-read-operation": "B3ReadOperationV1",
  "b3-cas-operation": "B3CasOperationV1",
  "b3-lease-operation": "B3LeaseOperationV1",
  "b3-subscribe-operation": "B3SubscribeOperationV1",
} as const;
const envelope = (payload: CanonicalValue): CanonicalValue => ({
  payload,
  payloadDigest: createHash("sha256").update(bytes(payload)).digest("hex"),
  signatures: [{ keyId: "development.release.1", algorithm: "ed25519", keyEpoch: 1n, signature: new Uint8Array(64).fill(1) }],
});

test("P2-S1 operation schemas are exact, bounded, and domain separated", () => {
  for (const [schema, value] of Object.entries(operations)) {
    const encoded = bytes(value as unknown as CanonicalValue);
    const captured = captureP2S1Canonical(encoded, schema as keyof typeof operations);
    assert.deepEqual(captured.canonicalBytes, encoded);
    const digest = p2S1OperationDigest(encoded, schema as keyof typeof operations);
    assert.match(digest.hex, /^[0-9a-f]{64}$/);
    assert.notEqual(digest.hex, createHash("sha256").update(encoded).digest("hex"));
    assert.throws(() => captureP2S1Canonical(bytes({ ...(value as object), extra: 1n } as CanonicalValue), schema as keyof typeof operations), /fields are not exact/);
  }
  const cas = structuredClone(operations["b3-cas-operation"]) as unknown as {
    callerPurpose: { authorization: { kind: string } };
  };
  cas.callerPurpose.authorization.kind = "recovery";
  assert.throws(() => captureP2S1Canonical(bytes(cas as unknown as CanonicalValue), "b3-cas-operation"), /mismatch/);
  const proxy = new Proxy(bytes(operations["b3-read-operation"] as unknown as CanonicalValue), {});
  assert.throws(() => captureP2S1Canonical(proxy, "b3-read-operation"), /owned byte string/);
});

test("P2-S1 TS and safe Rust agree on operation bytes and preimage digests", () => {
  for (const [schema, value] of Object.entries(operations)) {
    const encoded = bytes(value as unknown as CanonicalValue);
    const rustSchema = rustOperationNames[schema as keyof typeof operations];
    const result = spawnSync(oracle, [], {
      input: `P2OP:${rustSchema}:${Buffer.from(encoded).toString("hex")}\n`,
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), `P2OP\t${rustSchema}\t${p2S1OperationDigest(encoded, schema as keyof typeof operations).hex}`);
  }
});

test("P2-S1 invalidation ACK chaining and frozen P1 identifiers reject parity mutants", () => {
  const framePayload = { schema: "keep.native-b3-invalidation", version: 1n, authorityId: "authority.1", b3ProfileEnvelopeDigest: D, scopeKey, sessionId: "session.1", frameKind: "heartbeat", sequence: 1n, priorGeneration: 1n, newGeneration: 1n, newStateDigest: D, counter: 1n, requestNonce: new Uint8Array(32), priorAckDigest: null } as const;
  const frame = (payload: CanonicalValue): CanonicalValue => envelope(payload);
  assert.doesNotThrow(() => captureP2S1Canonical(bytes(frame(framePayload as unknown as CanonicalValue)), "b3-invalidation"));
  for (const payload of [
    { ...framePayload, priorAckDigest: E },
    { ...framePayload, sequence: 2n, priorAckDigest: null },
  ] as const) {
    const encoded = bytes(frame(payload as unknown as CanonicalValue));
    assert.throws(() => captureP2S1Canonical(encoded, "b3-invalidation"), /ACK chain/);
    const rust = spawnSync(oracle, [], { input: `P2:B3InvalidationFrameV1:${Buffer.from(encoded).toString("hex")}\n`, encoding: "utf8" });
    assert.match(rust.stdout, /^ERR\t/);
  }

  const read = (authorityId: string): CanonicalValue => ({ ...operations["b3-read-operation"], scopeKey: { ...scopeKey, authorityId } } as unknown as CanonicalValue);
  assert.doesNotThrow(() => captureP2S1Canonical(bytes(read(`a${"x".repeat(126)}@`)), "b3-read-operation"));
  for (const invalid of ["a+b", `a${"x".repeat(128)}`]) {
    const encoded = bytes(read(invalid));
    assert.throws(() => captureP2S1Canonical(encoded, "b3-read-operation"), /identifier grammar/);
    const rust = spawnSync(oracle, [], { input: `P2:B3ReadOperationV1:${Buffer.from(encoded).toString("hex")}\n`, encoding: "utf8" });
    assert.match(rust.stdout, /^ERR\t/);
  }
});

test("P2-S1 TS and safe Rust expose the same complete top-level schema inventory", () => {
  const result = spawnSync(oracle, [], { input: "P2SCHEMAS\n", encoding: "utf8", maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  const rows = result.stdout.trim().slice("P2SCHEMAS\t".length).split(";").map((row) => {
    const [name, , shape, , fields] = row.split("|");
    return { name: name!, shape: shape!, fields: fields!.split(",") };
  });
  assert.deepEqual(rows.map(({ name, shape, fields }) => ({ name, shape, fields })), P2_S1_SCHEMA_INVENTORY);
});

test("P2-S1 TS and safe Rust expose byte-identical recursive schema metadata", () => {
  const result = spawnSync(oracle, [], { input: "P2SCHEMADETAIL\n", encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), `P2SCHEMADETAIL\t${Buffer.from(P2_S1_RECURSIVE_SCHEMA_METADATA).toString("hex")}`);
});

test("P2-S1 TS accepts every independently constructed safe-Rust schema fixture", () => {
  const result = spawnSync(oracle, [], { input: "P2CORPUS\n", encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  const reverse = new Map(Object.entries(P2_S1_RUST_SCHEMA_NAMES).map(([ts, rust]) => [rust, ts]));
  const rows = result.stdout.trim().slice("P2CORPUS\t".length).split(";");
  assert.equal(rows.length, P2_S1_SCHEMA_INVENTORY.length);
  for (const row of rows) {
    const [rustSchema, hex] = row.split("|");
    const tsSchema = reverse.get(rustSchema!);
    assert(tsSchema, `unmapped Rust schema ${rustSchema}`);
    assert.doesNotThrow(() => captureP2S1Canonical(Uint8Array.from(Buffer.from(hex!, "hex")), tsSchema as keyof typeof P2_S1_RUST_SCHEMA_NAMES), rustSchema);
  }
});

test("P2-S1 TS and safe Rust reject top-level hostile mutants for every schema", () => {
  const result = spawnSync(oracle, [], { input: "P2CORPUS\n", encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  const reverse = new Map(Object.entries(P2_S1_RUST_SCHEMA_NAMES).map(([ts, rust]) => [rust, ts]));
  for (const row of result.stdout.trim().slice("P2CORPUS\t".length).split(";")) {
    const [rustSchema, hex] = row.split("|");
    const tsSchema = reverse.get(rustSchema!)!;
    const original = decodeCanonical(Uint8Array.from(Buffer.from(hex!, "hex"))) as Record<string, CanonicalValue>;
    const missing = structuredClone(original);
    delete missing[Object.keys(missing)[0]!];
    const mutants: CanonicalValue[] = [
      { ...original, unexpectedField: 1n },
      missing,
      { ...original, schema: null },
    ];
    for (const mutant of mutants) {
      const encoded = bytes(mutant);
      assert.throws(() => captureP2S1Canonical(encoded, tsSchema as keyof typeof P2_S1_RUST_SCHEMA_NAMES), /native authority schema/, `${rustSchema} TS`);
      const rust = spawnSync(oracle, [], { input: `P2:${rustSchema}:${Buffer.from(encoded).toString("hex")}\n`, encoding: "utf8" });
      assert.match(rust.stdout, /^ERR\t/, `${rustSchema} Rust accepted hostile mutant`);
    }
  }
});

test("P2-S1 TS and safe Rust reject authority interval and reproducibility semantic mutants", () => {
  const corpus = spawnSync(oracle, [], { input: "P2CORPUS\n", encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(corpus.status, 0, corpus.stderr);
  const fixtures = new Map(corpus.stdout.trim().slice("P2CORPUS\t".length).split(";").map((row) => {
    const [name, hex] = row.split("|");
    return [name!, decodeCanonical(Uint8Array.from(Buffer.from(hex!, "hex"))) as Record<string, CanonicalValue>];
  }));
  const mutateEnvelope = (name: string, mutate: (payload: Record<string, CanonicalValue>) => void): Uint8Array => {
    const record = structuredClone(fixtures.get(name)!) as Record<string, CanonicalValue>;
    const payload = record.payload as Record<string, CanonicalValue>;
    mutate(payload);
    record.payloadDigest = createHash("sha256").update(bytes(payload)).digest("hex");
    return bytes(record);
  };
  const cases = [
    ["build-identity", "NativeBuildIdentityV1", mutateEnvelope("NativeBuildIdentityV1", (payload) => {
      payload.validFromCounter = 10n; payload.validUntilCounter = 9n;
    })],
    ["provenance", "NativeProvenanceV1", mutateEnvelope("NativeProvenanceV1", (payload) => {
      payload.startedCounter = 10n; payload.finishedCounter = 9n;
    })],
    ["reproducibility", "NativeReproducibilityRecordV1", mutateEnvelope("NativeReproducibilityRecordV1", (payload) => {
      payload.disagreements = [{ path: "artifact", leftBuilderId: "builder.1", rightBuilderId: "builder.2", leftDigest: D, rightDigest: E, reasonCode: "bytes-differ" }];
    })],
  ] as const;
  for (const [tsSchema, rustSchema, encoded] of cases) {
    assert.throws(() => captureP2S1Canonical(encoded, tsSchema), /validity interval|counter interval|disagreements/);
    const rust = spawnSync(oracle, [], { input: `P2:${rustSchema}:${Buffer.from(encoded).toString("hex")}\n`, encoding: "utf8" });
    assert.match(rust.stdout, /^ERR\t/, `${rustSchema} accepted semantic mutant`);
  }
});

test("P2-S1 TS and safe Rust join signer trust and provenance URI digest authority", () => {
  const corpus = spawnSync(oracle, [], { input: "P2CORPUS\n", encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  assert.equal(corpus.status, 0, corpus.stderr);
  const fixtures = new Map(corpus.stdout.trim().slice("P2CORPUS\t".length).split(";").map((row) => {
    const [name, hex] = row.split("|");
    return [name!, decodeCanonical(Uint8Array.from(Buffer.from(hex!, "hex"))) as Record<string, CanonicalValue>];
  }));
  const timestamp = structuredClone(fixtures.get("NativeTimestampV1")!) as Record<string, CanonicalValue>;
  (timestamp.payload as Record<string, CanonicalValue>).trustClass = "production";
  (timestamp.signatures as Record<string, CanonicalValue>[])[0]!.keyId = "development.timestamp.1";
  timestamp.payloadDigest = createHash("sha256").update(bytes(timestamp.payload!)).digest("hex");
  const trustBytes = bytes(timestamp);
  assert.throws(() => captureP2S1Canonical(trustBytes, "timestamp"), /key namespace/);
  assert.match(spawnSync(oracle, [], { input: `P2:NativeTimestampV1:${Buffer.from(trustBytes).toString("hex")}\n`, encoding: "utf8" }).stdout, /^ERR\t/);

  for (const successor of [false, true]) {
    const root = structuredClone(fixtures.get("NativeRootV1")!) as Record<string, CanonicalValue>;
    const payload = root.payload as Record<string, CanonicalValue>;
    if (successor) {
      payload.rootEpoch = 1n;
      payload.predecessorRootEnvelopeDigest = D;
      (root.signatures as Record<string, CanonicalValue>[])[0]!.authorizationRole = "root";
      root.payloadDigest = createHash("sha256").update(bytes(payload)).digest("hex");
    }
    (root.signatures as Record<string, CanonicalValue>[])[0]!.keyId = "development.root.1";
    const encoded = bytes(root);
    assert.throws(() => captureP2S1Canonical(encoded, "root"), /key namespace/);
    assert.match(spawnSync(oracle, [], { input: `P2:NativeRootV1:${Buffer.from(encoded).toString("hex")}\n`, encoding: "utf8" }).stdout, /^ERR\t/);
  }

  for (const [uri, digestType] of [["keep-artifact:item", "AttackerChosenDigest"], ["keep-source:item", "ArtifactDigest"]] as const) {
    const provenance = structuredClone(fixtures.get("NativeProvenanceV1")!) as Record<string, CanonicalValue>;
    const payload = provenance.payload as Record<string, CanonicalValue>;
    payload.materials = [{ uri, digestType, digest: D }];
    provenance.payloadDigest = createHash("sha256").update(bytes(payload)).digest("hex");
    const encoded = bytes(provenance);
    assert.throws(() => captureP2S1Canonical(encoded, "provenance"), /closed enum|URI\/digest type mismatch/);
    assert.match(spawnSync(oracle, [], { input: `P2:NativeProvenanceV1:${Buffer.from(encoded).toString("hex")}\n`, encoding: "utf8" }).stdout, /^ERR\t/);
  }
});

test("P2-S1 TS and safe Rust accept identical authority and supply records", () => {
  const timestamp = envelope({ schema: "keep.native-timestamp", version: 1n, trustClass: "development", nativeClosureBaseDigest: D, artifactVersion: 1n, deploymentEpoch: 1n, releaseKeyEpoch: 1n, timestampKeyEpoch: 1n, issuedCounter: 1n, expiresCounter: 2n, revocationCheckpointEnvelopeDigest: E, revocationSequence: 1n });
  const inventory = { schema: "keep.native-artifact-inventory", version: 1n, buildId: "build.1", targetTriple: "x86_64-unknown-linux-musl", variant: "static", rows: [{ artifactId: "helper", kind: "helper", digest: D, size: 1n, mode: "0555", targetTriple: "x86_64-unknown-linux-musl", variant: "static", releaseMember: true }] };
  for (const [tsSchema, rustSchema, value] of [["timestamp", "NativeTimestampV1", timestamp], ["artifact-inventory", "NativeArtifactInventoryV1", inventory]] as const) {
    const encoded = bytes(value);
    assert.doesNotThrow(() => captureP2S1Canonical(encoded, tsSchema));
    const result = spawnSync(oracle, [], { input: `P2:${rustSchema}:${Buffer.from(encoded).toString("hex")}\n`, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(`^P2\\t${rustSchema}\\t`));
  }
  const signatureResult = spawnSync(oracle, [], { input: `P2SIG:NativeTimestampV1:${Buffer.from(bytes((timestamp as Record<string, CanonicalValue>).payload!)).toString("hex")}\n`, encoding: "utf8" });
  assert.equal(signatureResult.stdout.trim(), `P2SIG\tNativeTimestampV1\t${Buffer.from(p2S1SignaturePreimage(bytes(timestamp), "timestamp")).toString("hex")}`);
  const bad = structuredClone(timestamp) as Record<string, CanonicalValue>;
  bad.payloadDigest = E;
  assert.throws(() => captureP2S1Canonical(bytes(bad), "timestamp"), /payload digest/);
  const zeroSignature = structuredClone(timestamp) as Record<string, CanonicalValue>;
  (zeroSignature.signatures as Record<string, CanonicalValue>[])[0]!.signature = new Uint8Array(64);
  assert.doesNotThrow(() => captureP2S1Canonical(bytes(zeroSignature), "timestamp"));
  const duplicate = structuredClone(timestamp) as Record<string, CanonicalValue>;
  duplicate.signatures = [
    ...(duplicate.signatures as CanonicalValue[]),
    ...(duplicate.signatures as CanonicalValue[]),
  ];
  assert.throws(() => captureP2S1Canonical(bytes(duplicate), "timestamp"), /sorted|unique/);
});

test("P2-S1 auxiliary schemas preserve typed values and ordered arguments", () => {
  const observation = { schema: "keep.native-observation-result", version: 1n, resultCode: "pass", facts: [
    { factId: "a", valueType: "boolean", value: true },
    { factId: "b", valueType: "uint64", value: 7n },
    { factId: "c", valueType: "identifier", value: "fact.value" },
  ] };
  assert.doesNotThrow(() => captureP2S1Canonical(bytes(observation), "observation-result"));
  assert.throws(() => captureP2S1Canonical(bytes({ ...observation, facts: [{ factId: "a", valueType: "uint64", value: "7" }] }), "observation-result"), /uint64/);
  const command = { schema: "keep.native-build-command", version: 1n, executableDigest: D, arguments: ["z", "a"] };
  assert.doesNotThrow(() => captureP2S1Canonical(bytes(command), "build-command"));
  const journal = { schema: "keep.native-journal-entries", version: 1n, entries: [
    { sequence: 2n, eventCode: "start", subjectDigest: D, counter: 3n },
    { sequence: 4n, eventCode: "end", subjectDigest: E, counter: 4n },
  ] };
  assert.throws(() => captureP2S1Canonical(bytes(journal), "journal-entries"), /consecutive/);
});

test("P2-S1 policy schemas close rights, joins, and ordering", () => {
  const landlock = { schema: "keep.native-landlock-policy", version: 1n, minimumAbi: 6n,
    handledFilesystemRights: ["execute", "read-file"], handledNetworkRights: ["bind-tcp"], handledScopeRights: [],
    rules: [
      { kind: "path-beneath", path: "/bin", accessRights: ["execute"] },
      { kind: "tcp-port", port: 443n, accessRights: ["bind-tcp"] },
    ] };
  assert.doesNotThrow(() => captureP2S1Canonical(bytes(landlock), "landlock"));
  assert.throws(() => captureP2S1Canonical(bytes({ ...landlock, rules: [{ kind: "path-beneath", path: "/bin", accessRights: ["write-file"] }] }), "landlock"), /unhandled/);
  assert.throws(() => captureP2S1Canonical(bytes({ ...landlock, handledFilesystemRights: ["unknown"] }), "landlock"), /closed enum/);
  for (const path of ["/.", "/..", "/../../etc", "/usr/../etc"])
    assert.throws(() => captureP2S1Canonical(bytes({ ...landlock, rules: [{ kind: "path-beneath", path, accessRights: ["execute"] }] }), "landlock"), /text grammar/);
  const seccomp = { schema: "keep.native-seccomp-policy", version: 1n, architecture: "x86_64", defaultAction: "kill-process", rules: [
    { syscall: "openat", action: "errno", errno: 1n, arguments: [{ index: 0n, operator: "masked-eq", value: 0n, mask: 3n }] },
  ] };
  assert.doesNotThrow(() => captureP2S1Canonical(bytes(seccomp), "seccomp"));
  assert.notEqual(p2S1DerivedDigest(bytes(seccomp), "seccomp", "launch").semantic, p2S1DerivedDigest(bytes(seccomp), "seccomp", "steady").semantic);
  assert.throws(() => captureP2S1Canonical(bytes({ ...seccomp, rules: [{ syscall: "openat", action: "allow", errno: 1n, arguments: [] }] }), "seccomp"), /errno\/action/);
  const tooManyIoRows = Array.from({ length: 129 }, (_, index) => ({
    deviceMajor: 1n,
    deviceMinor: BigInt(index),
    readBytesPerSecond: 1n,
    writeBytesPerSecond: null,
    readIops: null,
    writeIops: null,
  }));
  assert.throws(() => captureP2S1Canonical(bytes({ schema: "keep.native-io-max", version: 1n, defaultPolicy: "deny-unlisted", rows: tooManyIoRows }), "io-max"), /collection bound/);
  const reversed = { ...landlock, rules: [...landlock.rules].reverse() };
  assert.throws(() => captureP2S1Canonical(bytes(reversed), "landlock"), /sorted unique/);

  const landlockV2 = {
    schema: "keep.native-landlock-policy", version: 2n, minimumAbi: 4n, effectiveAbi: 10n, reviewedMaximumAbi: 10n,
    handledFilesystemRights: ["execute", "ioctl-dev", "make-block", "make-char", "make-dir", "make-fifo", "make-reg", "make-sock", "make-sym", "read-dir", "read-file", "refer", "remove-dir", "remove-file", "resolve-unix", "truncate", "write-file"],
    handledNetworkRights: ["bind-tcp", "bind-udp", "connect-send-udp", "connect-tcp"],
    handledScopeRights: ["abstract-unix-socket", "signal"],
    rules: [
      { kind: "path-beneath", path: "/", accessRights: ["execute", "read-dir", "read-file"] },
      { kind: "tcp-port", port: 443n, accessRights: ["connect-tcp"] },
      { kind: "udp-port", port: 53n, accessRights: ["connect-send-udp"] },
    ],
  };
  const landlockV2Bytes = bytes(landlockV2);
  assert.doesNotThrow(() => captureP2S1Canonical(landlockV2Bytes, "landlock-v2"));
  assert.notEqual(p2S1DerivedDigest(landlockV2Bytes, "landlock-v2").hex, p2S1DerivedDigest(bytes(landlock), "landlock").hex);
  const rustV2 = spawnSync(oracle, [], { input: `P2:NativeLandlockPolicyV2:${Buffer.from(landlockV2Bytes).toString("hex")}\n`, encoding: "utf8" });
  assert.equal(rustV2.status, 0, rustV2.stderr);
  assert.match(rustV2.stdout, /^P2\tNativeLandlockPolicyV2\t/);
  const fullFs = landlockV2.handledFilesystemRights;
  for (let abi = 4; abi <= 10; abi++) {
    const profile = {
      ...landlockV2,
      effectiveAbi: BigInt(abi),
      handledFilesystemRights: fullFs.filter((right) => right !== "resolve-unix" && (right !== "ioctl-dev" || abi >= 5) || (right === "resolve-unix" && abi >= 9)),
      handledNetworkRights: abi >= 10 ? landlockV2.handledNetworkRights : ["bind-tcp", "connect-tcp"],
      handledScopeRights: abi >= 6 ? landlockV2.handledScopeRights : [],
      rules: [],
    };
    const encoded = bytes(profile);
    assert.doesNotThrow(() => captureP2S1Canonical(encoded, "landlock-v2"), `ABI ${abi}`);
    const rust = spawnSync(oracle, [], { input: `P2:NativeLandlockPolicyV2:${Buffer.from(encoded).toString("hex")}\n`, encoding: "utf8" });
    assert.match(rust.stdout, /^P2\tNativeLandlockPolicyV2\t/, `ABI ${abi}: ${rust.stdout}${rust.stderr}`);
  }
  for (const mutant of [
    { ...landlockV2, version: 1n },
    { ...landlockV2, reviewedMaximumAbi: 11n },
    { ...landlockV2, effectiveAbi: 4n },
    { ...landlockV2, minimumAbi: 10n, effectiveAbi: 9n },
    { ...landlockV2, handledFilesystemRights: landlockV2.handledFilesystemRights.filter((right) => right !== "resolve-unix") },
    { ...landlockV2, handledNetworkRights: landlockV2.handledNetworkRights.filter((right) => right !== "bind-udp") },
    { ...landlockV2, rules: [{ kind: "tcp-port", port: 443n, accessRights: ["connect-send-udp"] }] },
  ] as CanonicalValue[]) {
    const encoded = bytes(mutant);
    assert.throws(() => captureP2S1Canonical(encoded, "landlock-v2"), /native authority schema/);
    const rust = spawnSync(oracle, [], { input: `P2:NativeLandlockPolicyV2:${Buffer.from(encoded).toString("hex")}\n`, encoding: "utf8" });
    assert.match(rust.stdout, /^ERR\t/);
  }
});

test("P2-S1 remains mechanically non-authorizing", () => {
  assert.deepEqual(P2_S1_AUTHORITY_BOUNDARY, {
    dependencyFree: true,
    signatureVerification: false,
    filesystemAuthority: false,
    b3Authority: false,
    productionBrand: false,
    nativeExecution: false,
    credentialAuthority: false,
    networkAuthority: false,
  });
});

test("P2-S1 type-derived digest registry closes every operation preimage", () => {
  validateP2S1DigestRegistry(P2_S1_DIGEST_REGISTRY);
  assert(P2_S1_DIGEST_REGISTRY.some((entry) => entry.path.includes("authorizationEnvelopeDigest")));
  assert(P2_S1_DIGEST_REGISTRY.some((entry) => entry.path === "NativeInvocationV1.inputs[].artifactDigest"));
  for (const schema of Object.keys(operations)) {
    const name = rustOperationNames[schema as keyof typeof operations];
    const derived = P2_S1_DIGEST_REGISTRY.find((entry) => entry.path === `${name}.$contentDigest`)!;
    const inputs = P2_S1_DIGEST_REGISTRY.filter((entry) =>
      entry.path.startsWith(`${name}.`) && !entry.path.includes(".$"));
    assert.deepEqual([...derived.dependsOn].sort(), inputs.map((entry) => entry.path).sort());
  }
  const missing = P2_S1_DIGEST_REGISTRY.filter((entry) => entry.path !== "NativeInvocationV1.inputs[].artifactDigest");
  assert.throws(() => validateP2S1DigestRegistry(missing), /coverage/);
  const reverse = P2_S1_DIGEST_REGISTRY.map((entry) => ({ ...entry, dependsOn: [...entry.dependsOn] }));
  const leaf = reverse.find((entry) => entry.rank === 0)!;
  leaf.dependsOn.push(reverse.find((entry) => entry.rank === 1)!.path);
  assert.throws(() => validateP2S1DigestRegistry(reverse), /reverse or cyclic/);
  validateP2S1CombinedDigestRegistry(P2_S1_COMBINED_DIGEST_REGISTRY);
  for (const [consumer, producer] of ([
    ["NativeProvenanceV1.toolchainClosureEnvelopeDigest", "NativeToolchainClosureV1.$envelopeDigest"],
    ["NativeProvenanceV1.invocationDigest", "NativeInvocationV1.$contentDigest"],
    ["NativeReproducibilityRecordV1.builderProvenanceEnvelopeDigests", "NativeProvenanceV1.$envelopeDigest"],
    ["NativeReproducibilityRecordV1.comparisonDigest", "NativeComparisonV1.$contentDigest"],
  ] as const)) assert(P2_S1_COMBINED_DIGEST_REGISTRY.find((entry) => entry.path === consumer)!.dependsOn.includes(producer));
});

test("P2-S1 TS and safe Rust expose one byte-identical combined digest DAG", () => {
  const result = spawnSync(oracle, [], { input: "P2REGISTRY\n", encoding: "utf8", maxBuffer: 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  const expected = `P2REGISTRY\t${P2_S1_COMBINED_DIGEST_REGISTRY.map((entry) =>
    `${entry.path}|${entry.semanticType}|${entry.rank}|${[...entry.dependsOn].sort().join(",")}`).join(";")}`;
  assert.equal(result.stdout.trim(), expected);
});
