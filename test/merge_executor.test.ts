import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AutonomousMergeExecutor, classifyPostMergeExecutionSubject, makePublicationAttempt, missingPublicationActuatorRecoveryHold, parsePublicationAttempt, publicationAttemptDigest, type MergeSpec, type MergeExecutorDeps, type PublishedMergeIdentity } from "../src/oversight/merge_executor.js";
import { InMemoryMergePort } from "./helpers/in_memory_merge_port.js";
import type { MergeAuthorityDecision, MergeAuthorityVerdict } from "../src/oversight/merge_authority.js";
import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { InProcessLock } from "../src/lock/lock.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { createHash, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { canonicalize } from "../src/spine/event.js";

function spine(): Spine { return new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-am2-")), { fsync: true }), new InProcessLock(), new SchemaRegistry()); }
const spec: MergeSpec = {
  issueId: "AM2-1",
  repoRef: "repo",
  branch: "keep/solve/AM2-1",
  baseBranch: "main",
  expectedCandidateCommit: "a".repeat(40),
  expectedCandidateProjectManifestDigest: "b".repeat(64),
  expectedGuestExecutionRequestDigest: "c".repeat(64),
  projectDir: "/project",
};
const decision = (verdict: MergeAuthorityVerdict): MergeAuthorityDecision => ({ verdict, reason: "test", consequential: verdict === "human-merge", verified: verdict === "autonomous-merge" });
const identity: PublishedMergeIdentity = {
  candidateCommit: spec.expectedCandidateCommit, candidateTree: "1".repeat(40), candidateProjectManifestDigest: spec.expectedCandidateProjectManifestDigest,
  baseCommit: "2".repeat(40), baseTree: "3".repeat(40), expectedMergedTree: "4".repeat(40), mergedCommit: "5".repeat(40),
  mergedTree: "4".repeat(40), publishedCommit: "5".repeat(40), publishedTree: "4".repeat(40),
  publishedProjectManifestDigest: spec.expectedCandidateProjectManifestDigest, publicationTarget: "remote:origin:refs/heads/main",
};
function exec(port: InMemoryMergePort, over: Partial<MergeExecutorDeps> = {}) {
  const s = over.spine ?? spine();
  const deps: MergeExecutorDeps = { port, spine: s, postMergeVerify: over.postMergeVerify ?? (async (candidate, identity) => ({ regressed: false, verifiedProjectManifestDigest: identity.publishedProjectManifestDigest, verifiedGuestExecutionRequestDigest: candidate.expectedGuestExecutionRequestDigest })), ...(over.killSwitchEngaged ? { killSwitchEngaged: over.killSwitchEngaged } : {}), ...(over.publicationOperatorTrust ? { publicationOperatorTrust: over.publicationOperatorTrust } : {}) };
  return { ex: new AutonomousMergeExecutor(deps), s };
}
class CountingMergePort extends InMemoryMergePort {
  observeCalls = 0;
  reconcileAbsentCalls = 0;
  override async observePublication(attempt: Parameters<InMemoryMergePort["observePublication"]>[0]) { this.observeCalls++; return super.observePublication(attempt); }
  override async reconcileAbsentPublication() { this.reconcileAbsentCalls++; return super.reconcileAbsentPublication(); }
}
const events = (s: Spine) => s.currentEvents().map((e) => (e.payload as Record<string, unknown>)["event"]);

test("AM2c CARRIER: exact publication attempt is stable and unknown-field substitution refuses", () => {
  const attempt = makePublicationAttempt(spec, identity);
  assert.equal(parsePublicationAttempt(attempt).operationId, attempt.operationId);
  assert.equal(publicationAttemptDigest(parsePublicationAttempt(JSON.parse(JSON.stringify(attempt)))), publicationAttemptDigest(attempt));
  assert.throws(() => parsePublicationAttempt({ ...attempt, surprise: true }), /missing or unknown fields/);
});

test("AM2c CARRIER: proxy and accessor inputs execute zero caller code", () => {
  let traps = 0;
  const proxy = new Proxy(spec, { get() { traps++; throw new Error("trap executed"); }, ownKeys() { traps++; throw new Error("trap executed"); } });
  assert.throws(() => makePublicationAttempt(proxy, identity), /inert plain object/);
  assert.equal(traps, 0);
  let reads = 0;
  const accessor = { ...JSON.parse(JSON.stringify(makePublicationAttempt(spec, identity))) } as Record<string, unknown>;
  Object.defineProperty(accessor, "operationId", { enumerable: true, get() { reads++; return "0".repeat(64); } });
  assert.throws(() => parsePublicationAttempt(accessor), /data property/);
  assert.equal(reads, 0);
});

async function sealAttempt(s: Spine, attempt: ReturnType<typeof makePublicationAttempt>): Promise<void> {
  s.stage({ type: "effect.intent", actor: "test", payload: { kind: "auto_merge.publication_prepared", attemptDigest: publicationAttemptDigest(attempt), attempt } });
  await s.seal();
}

async function sealTerminal(s: Spine, attempt: ReturnType<typeof makePublicationAttempt>): Promise<void> {
  s.stage({ type: "effect.terminal", actor: "test", payload: { kind: "auto_merge.publication_terminal", attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId, disposition: "reconciled-effect-absent", reason: "test terminal" } });
  await s.seal();
}
async function sealVerifiedFact(s: Spine, attempt: ReturnType<typeof makePublicationAttempt>): Promise<void> {
  s.stage({ type: "effect.receipt", actor: "test", payload: {
    kind: "auto_merge.publication_verified", attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId,
    publishedCommit: attempt.identity.publishedCommit, publishedTree: attempt.identity.publishedTree,
    verifiedProjectManifestDigest: attempt.identity.publishedProjectManifestDigest,
    verifiedGuestExecutionRequestDigest: attempt.spec.expectedGuestExecutionRequestDigest,
  } });
  await s.seal();
}

function signedAdjudication(attempt: ReturnType<typeof makePublicationAttempt>, disposition: "effect-occurred" | "effect-absent", keyId: string, privateKey: KeyObject, evidence = "9".repeat(64)) {
  const unsigned = { schema: "keep.publication-operator-adjudication/v1" as const, attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId, adjudicatedDisposition: disposition, observedCommit: disposition === "effect-occurred" ? attempt.attemptedCommit : attempt.priorPublishedCommit, operatorEvidenceDigest: evidence, reason: `${disposition} independently observed`, keyId };
  return { ...unsigned, signatureBase64: sign(null, Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64") };
}

function signedQuarantineAcknowledgement(quarantineDigest: string, keyId: string, privateKey: KeyObject) {
  const unsigned = { schema: "keep.publication-quarantine-acknowledgement/v1" as const, quarantineDigest, operatorEvidenceDigest: "8".repeat(64), reason: "operator inspected exact carrier", keyId };
  return { ...unsigned, signatureBase64: sign(null, Buffer.from(`keep.publication-quarantine-acknowledgement/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64") };
}

test("AM2c RECOVERY: missing publication configuration cannot erase a prepared attempt", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity);
  assert.equal(missingPublicationActuatorRecoveryHold(s), undefined);
  await sealAttempt(s, attempt);
  const hold = missingPublicationActuatorRecoveryHold(s);
  assert.equal(hold?.status, "uncertain");
  assert.equal(hold?.operationId, attempt.operationId);
  assert.equal(hold?.attemptDigest, publicationAttemptDigest(attempt));
  await sealTerminal(s, attempt);
  assert.equal(missingPublicationActuatorRecoveryHold(s), undefined);
});

test("AM2c LINEAGE: a terminalized attempt permits one later sequential attempt for the same operation", async () => {
  const s = spine();
  const first = makePublicationAttempt(spec, identity);
  const second = makePublicationAttempt(spec, { ...identity, mergedCommit: "6".repeat(40), publishedCommit: "6".repeat(40) });
  assert.equal(first.operationId, second.operationId);
  assert.notEqual(publicationAttemptDigest(first), publicationAttemptDigest(second));
  await sealAttempt(s, first); await sealTerminal(s, first); await sealAttempt(s, second);
  const { ex } = exec(new InMemoryMergePort({ publicationUncertain: true }), { spine: s });
  const result = await ex.reconcileOutstandingPublications();
  assert.equal(result.length, 1);
  assert.equal(result[0]?.attemptDigest, publicationAttemptDigest(second));
  assert.equal(result[0]?.status, "uncertain");
});

test("AM2c LINEAGE: concurrent prepared attempts are independently reconciled instead of permanently wedging the lane", async () => {
  const s = spine();
  const first = makePublicationAttempt(spec, identity);
  const second = makePublicationAttempt(spec, { ...identity, mergedCommit: "6".repeat(40), publishedCommit: "6".repeat(40) });
  await sealAttempt(s, first); await sealAttempt(s, second);
  const { ex } = exec(new InMemoryMergePort(), { spine: s });
  const result = await ex.reconcileOutstandingPublications();
  assert.equal(result.length, 2);
  assert.ok(result.every((row) => row.status === "uncertain" && !/forked/.test(row.reason)));
  assert.deepEqual(new Set(result.map((row) => row.attemptDigest)), new Set([publicationAttemptDigest(first), publicationAttemptDigest(second)]));
});

test("AM2c STRUCTURE: a substituted redundant digest is quarantined while the self-identifying attempt is still reconciled", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity);
  s.stage({ type: "effect.intent", actor: "test", payload: { kind: "auto_merge.publication_prepared", attemptDigest: "f".repeat(64), attempt } });
  await s.seal();
  const result = await exec(new InMemoryMergePort(), { spine: s }).ex.reconcileOutstandingPublications();
  assert.equal(result.length, 2);
  assert.ok(result.some((row) => row.attemptDigest !== publicationAttemptDigest(attempt) && /digest does not recompute/.test(row.reason)));
  assert.ok(result.some((row) => row.attemptDigest === publicationAttemptDigest(attempt) && row.status === "uncertain" && /Firecracker authority/.test(row.reason)));
});

test("AM2c LINEAGE: a duplicate prepared carrier cannot reopen an already terminalized attempt", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity);
  await sealAttempt(s, attempt); await sealTerminal(s, attempt); await sealAttempt(s, attempt);
  assert.deepEqual(await exec(new InMemoryMergePort(), { spine: s }).ex.reconcileOutstandingPublications(), []);
  assert.equal(missingPublicationActuatorRecoveryHold(s), undefined);
});

test("AM2c STRUCTURE: an orphan malformed terminal is surfaced without suppressing healthy recovery", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt); await sealVerifiedFact(s, attempt);
  s.stage({ type: "effect.terminal", actor: "test", payload: {
    kind: "auto_merge.publication_terminal", attemptDigest: "e".repeat(64), operationId: "d".repeat(64),
    disposition: "invented-success", reason: "hostile",
  } });
  await s.seal();
  const result = await exec(new InMemoryMergePort(), { spine: s }).ex.reconcileOutstandingPublications();
  assert.equal(result.length, 2);
  assert.ok(result.some((row) => row.attemptDigest !== publicationAttemptDigest(attempt) && row.status === "uncertain" && /malformed publication terminal/.test(row.reason)));
  assert.ok(result.some((row) => row.attemptDigest === publicationAttemptDigest(attempt) && row.status !== "uncertain"));
});

test("AM2c STRUCTURE: a malformed prepared record is quarantined without wedging a healthy lineage", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt); await sealVerifiedFact(s, attempt);
  s.stage({ type: "effect.intent", actor: "hostile", payload: { kind: "auto_merge.publication_prepared", attempt: {} } });
  await s.seal();
  const result = await exec(new InMemoryMergePort(), { spine: s }).ex.reconcileOutstandingPublications();
  assert.equal(result.length, 2);
  assert.ok(result.some((row) => row.status === "uncertain" && /malformed publication preparation quarantined/.test(row.reason)));
  assert.ok(result.some((row) => row.attemptDigest === publicationAttemptDigest(attempt) && row.status !== "uncertain"));
});

test("AM2c QUARANTINE: explicit durable acknowledgment clears only the named malformed carrier", async () => {
  const s = spine();
  s.stage({ type: "effect.intent", actor: "hostile", payload: { kind: "auto_merge.publication_prepared", attempt: {} } });
  await s.seal();
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "quarantine-operator", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const { ex } = exec(new InMemoryMergePort(), { spine: s, publicationOperatorTrust: trust });
  const first = await ex.reconcileOutstandingPublications();
  assert.equal(first.length, 1);
  assert.match(first[0]?.reason ?? "", /quarantined/);
  const unsigned = { schema: "keep.publication-quarantine-acknowledgement/v1" as const, quarantineDigest: first[0]!.attemptDigest, operatorEvidenceDigest: "8".repeat(64), reason: "operator inspected the immutable malformed historical carrier", keyId: trust.keyId };
  const signatureBase64 = sign(null, Buffer.from(`keep.publication-quarantine-acknowledgement/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64");
  await ex.acknowledgePublicationQuarantine({ ...unsigned, signatureBase64 });
  await ex.acknowledgePublicationQuarantine({ ...unsigned, signatureBase64 }); // operator retry is idempotent evidence
  assert.ok((await ex.reconcileOutstandingPublications()).every((row) => !row.needsHuman && row.status !== "uncertain"));
  assert.equal(missingPublicationActuatorRecoveryHold(s, trust), undefined, "signed acknowledgment also makes actuator-free cold start recoverable");
  assert.ok(s.replay().some((event) => (event.payload as Record<string, unknown>).kind === "auto_merge.publication_quarantine_acknowledged"));
});

test("AM2c QUARANTINE: a valid prepared effect remains non-erasable", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
  const preparedEvent = s.replay().find((event) => (event.payload as Record<string, unknown>).kind === "auto_merge.publication_prepared")!;
  const quarantineDigest = createHash("sha256").update("keep.publication-quarantine/v1\0").update(canonicalize(preparedEvent)).digest("hex");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "non-erasure-operator", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const unsigned = { schema: "keep.publication-quarantine-acknowledgement/v1" as const, quarantineDigest, operatorEvidenceDigest: "1".repeat(64), reason: "hostile attempt to erase valid preparation", keyId: trust.keyId };
  const signatureBase64 = sign(null, Buffer.from(`keep.publication-quarantine-acknowledgement/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64");
  await assert.rejects(() => exec(new InMemoryMergePort(), { spine: s, publicationOperatorTrust: trust }).ex.acknowledgePublicationQuarantine({ ...unsigned, signatureBase64 }), /valid prepared publication effect cannot be quarantined/);
});

test("AM2c QUARANTINE: valid receipt, terminal, and adjudication facts are non-erasable", async () => {
  for (const kind of ["receipt", "terminal", "adjudication"] as const) {
    const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
    const { publicKey, privateKey } = generateKeyPairSync("ed25519"); const trust = { keyId: `operator-${kind}`, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
    if (kind === "receipt") await sealVerifiedFact(s, attempt);
    else if (kind === "terminal") await sealTerminal(s, attempt);
    else { s.stage({ type: "effect.terminal", actor: "operator", payload: { kind: "auto_merge.publication_adjudicated", adjudication: signedAdjudication(attempt, "effect-absent", trust.keyId, privateKey) } }); await s.seal(); }
    const target = s.replay().filter((event) => (event.payload as Record<string, unknown>).kind === (kind === "receipt" ? "auto_merge.publication_verified" : kind === "terminal" ? "auto_merge.publication_terminal" : "auto_merge.publication_adjudicated")).at(-1)!;
    const quarantineDigest = createHash("sha256").update("keep.publication-quarantine/v1\0").update(canonicalize(target)).digest("hex");
    const { ex } = exec(new InMemoryMergePort(), { spine: s, publicationOperatorTrust: trust });
    await assert.rejects(ex.acknowledgePublicationQuarantine(signedQuarantineAcknowledgement(quarantineDigest, trust.keyId, privateKey)), /valid publication (?:verified receipt|terminal|adjudication) cannot be quarantined/);
  }
});

test("AM2c READER CONVERGENCE: contradictory adjudications hold the later carrier and block effects", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519"); const trust = { keyId: "adjudication-conflict", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  s.stage({ type: "effect.terminal", actor: "operator", payload: { kind: "auto_merge.publication_adjudicated", adjudication: signedAdjudication(attempt, "effect-occurred", trust.keyId, privateKey, "1".repeat(64)) } }); await s.seal();
  s.stage({ type: "effect.terminal", actor: "operator", payload: { kind: "auto_merge.publication_adjudicated", adjudication: signedAdjudication(attempt, "effect-absent", trust.keyId, privateKey, "2".repeat(64)) } }); await s.seal();
  const port = new CountingMergePort(); const withActuator = await exec(port, { spine: s, publicationOperatorTrust: trust }).ex.reconcileOutstandingPublications(); const withoutActuator = missingPublicationActuatorRecoveryHold(s, trust);
  assert.equal(withActuator.length, 1); assert.match(withActuator[0]?.reason ?? "", /adjudication contradicts an earlier adjudication/); assert.equal(port.observeCalls, 0); assert.equal(port.reconcileAbsentCalls, 0);
  assert.equal(withoutActuator?.reason, withActuator[0]?.reason); assert.equal(withoutActuator?.attemptDigest, withActuator[0]?.attemptDigest);
});

test("AM2c READER CONVERGENCE: verified receipt and effect-absent adjudication share one contradiction hold", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt); await sealVerifiedFact(s, attempt);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519"); const trust = { keyId: "receipt-adjudication-conflict", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  s.stage({ type: "effect.terminal", actor: "operator", payload: { kind: "auto_merge.publication_adjudicated", adjudication: signedAdjudication(attempt, "effect-absent", trust.keyId, privateKey) } }); await s.seal();
  const port = new CountingMergePort(); const withActuator = await exec(port, { spine: s, publicationOperatorTrust: trust }).ex.reconcileOutstandingPublications(); const withoutActuator = missingPublicationActuatorRecoveryHold(s, trust);
  const expected = withActuator.find((row) => /effect-absent adjudication contradicts/.test(row.reason)); assert.ok(expected); assert.equal(port.observeCalls, 0); assert.equal(port.reconcileAbsentCalls, 0);
  assert.equal(withoutActuator?.reason, expected.reason); assert.equal(withoutActuator?.attemptDigest, expected.attemptDigest);
});

test("AM2c READER CONVERGENCE: terminal/adjudication contradictions are symmetric and effect-free", async () => {
  const attempt = makePublicationAttempt(spec, identity);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "terminal-adjudication-order", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const signed = signedAdjudication(attempt, "effect-absent", trust.keyId, privateKey);
  const evaluate = async (adjudicationFirst: boolean) => {
    const s = spine(); await sealAttempt(s, attempt);
    const adjudication = { type: "effect.terminal" as const, actor: "operator", payload: { kind: "auto_merge.publication_adjudicated", adjudication: signed } };
    const terminal = { type: "effect.terminal" as const, actor: "test", payload: { kind: "auto_merge.publication_terminal", attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId, disposition: "reconciled-effect-occurred", reason: "effect observed" } };
    for (const event of adjudicationFirst ? [adjudication, terminal] : [terminal, adjudication]) { s.stage(event); await s.seal(); }
    const port = new CountingMergePort(); const withActuator = await exec(port, { spine: s, publicationOperatorTrust: trust }).ex.reconcileOutstandingPublications();
    const hold = withActuator.find((row) => row.reason === "publication terminal contradicts operator adjudication");
    assert.ok(hold); assert.equal(port.observeCalls, 0); assert.equal(port.reconcileAbsentCalls, 0);
    const withoutActuator = missingPublicationActuatorRecoveryHold(s, trust);
    assert.equal(withoutActuator?.reason, hold.reason); assert.equal(withoutActuator?.attemptDigest, hold.attemptDigest);
    return hold;
  };
  const first = await evaluate(true); const second = await evaluate(false);
  assert.equal(first.attemptDigest, second.attemptDigest, "conflict identity is independent of replay order");
});

test("AM2c READER CONVERGENCE: agreeing terminal/adjudication pairs remain clean in either order", async () => {
  for (const [adjudicatedDisposition, terminalDisposition] of [["effect-absent", "reconciled-effect-absent"], ["effect-occurred", "reconciled-effect-occurred"]] as const) for (const adjudicationFirst of [true, false]) {
    const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const trust = { keyId: `terminal-adjudication-agreement-${adjudicationFirst}`, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
    const adjudication = { type: "effect.terminal" as const, actor: "operator", payload: { kind: "auto_merge.publication_adjudicated", adjudication: signedAdjudication(attempt, adjudicatedDisposition, trust.keyId, privateKey) } };
    const terminal = { type: "effect.terminal" as const, actor: "test", payload: { kind: "auto_merge.publication_terminal", attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId, disposition: terminalDisposition, reason: `${adjudicatedDisposition} observed` } };
    for (const event of adjudicationFirst ? [adjudication, terminal] : [terminal, adjudication]) { s.stage(event); await s.seal(); }
    assert.deepEqual(await exec(new CountingMergePort(), { spine: s, publicationOperatorTrust: trust }).ex.reconcileOutstandingPublications(), []);
    assert.equal(missingPublicationActuatorRecoveryHold(s, trust), undefined);
  }
});

test("AM2c QUARANTINE: disposition clears only a redundant-digest defect and never the independently carried effect", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
  s.stage({ type: "effect.intent", actor: "hostile", payload: { kind: "auto_merge.publication_prepared", attemptDigest: "f".repeat(64), attempt } }); await s.seal();
  const malformed = s.replay().find((event) => (event.payload as Record<string, unknown>).attemptDigest === "f".repeat(64))!;
  const quarantineDigest = createHash("sha256").update("keep.publication-quarantine/v1\0").update(canonicalize(malformed)).digest("hex");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "redundant-field-operator", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const unsigned = { schema: "keep.publication-quarantine-acknowledgement/v1" as const, quarantineDigest, operatorEvidenceDigest: "2".repeat(64), reason: "redundant digest inspected; exact preparation remains independently carried", keyId: trust.keyId };
  const signatureBase64 = sign(null, Buffer.from(`keep.publication-quarantine-acknowledgement/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64");
  const { ex } = exec(new InMemoryMergePort({ publicationUncertain: true }), { spine: s, publicationOperatorTrust: trust });
  await ex.acknowledgePublicationQuarantine({ ...unsigned, signatureBase64 });
  const rows = await ex.reconcileOutstandingPublications();
  assert.ok(!rows.some((row) => row.attemptDigest === quarantineDigest));
  assert.ok(rows.some((row) => row.attemptDigest === publicationAttemptDigest(attempt)), "the publication effect remains outstanding");
  assert.equal(missingPublicationActuatorRecoveryHold(s, trust)?.attemptDigest, publicationAttemptDigest(attempt));
  await sealTerminal(s, attempt);
  assert.deepEqual(await ex.reconcileOutstandingPublications(), []);
  assert.equal(missingPublicationActuatorRecoveryHold(s, trust), undefined);
});

test("AM2c QUARANTINE: a malformed redundant digest cannot erase the sole parseable preparation", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity);
  s.stage({ type: "effect.intent", actor: "hostile", payload: { kind: "auto_merge.publication_prepared", attemptDigest: "f".repeat(64), attempt } }); await s.seal();
  const target = s.replay()[0]!;
  const quarantineDigest = createHash("sha256").update("keep.publication-quarantine/v1\0").update(canonicalize(target)).digest("hex");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "sole-carrier-operator", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const unsigned = { schema: "keep.publication-quarantine-acknowledgement/v1" as const, quarantineDigest, operatorEvidenceDigest: "3".repeat(64), reason: "hostile attempt to discard the only recoverable effect identity", keyId: trust.keyId };
  const signatureBase64 = sign(null, Buffer.from(`keep.publication-quarantine-acknowledgement/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64");
  await assert.rejects(() => exec(new InMemoryMergePort(), { spine: s, publicationOperatorTrust: trust }).ex.acknowledgePublicationQuarantine({ ...unsigned, signatureBase64 }), /sole carrier/);
});

test("AM2c OPERATOR TRUST: a revoked historical key cannot authorize a quarantine disposition", async () => {
  const s = spine();
  s.stage({ type: "effect.intent", actor: "hostile", payload: { kind: "auto_merge.publication_prepared", attempt: {} } }); await s.seal();
  const target = s.replay()[0]!;
  const quarantineDigest = createHash("sha256").update("keep.publication-quarantine/v1\0").update(canonicalize(target)).digest("hex");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const keyId = "revoked-operator";
  const trust = { keyId: "current-operator", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(), historicalKeys: [{ keyId, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() }], revokedKeyIds: [keyId] };
  const unsigned = { schema: "keep.publication-quarantine-acknowledgement/v1" as const, quarantineDigest, operatorEvidenceDigest: "4".repeat(64), reason: "a revoked key must not regain authority from valid cryptographic bytes", keyId };
  const signatureBase64 = sign(null, Buffer.from(`keep.publication-quarantine-acknowledgement/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64");
  await assert.rejects(() => exec(new InMemoryMergePort(), { spine: s, publicationOperatorTrust: trust }).ex.acknowledgePublicationQuarantine({ ...unsigned, signatureBase64 }), /revoked/);
});

test("AM2c OPERATOR TRUST: revocation cannot retroactively make sealed valid adjudication quarantinable", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
  const { publicKey: historicalPublic, privateKey: historicalPrivate } = generateKeyPairSync("ed25519");
  const { publicKey: currentPublic, privateKey: currentPrivate } = generateKeyPairSync("ed25519");
  const historicalKeyId = "historical-adjudicator";
  const trust = { keyId: "current-operator", publicKeyPem: currentPublic.export({ type: "spki", format: "pem" }).toString(), historicalKeys: [{ keyId: historicalKeyId, publicKeyPem: historicalPublic.export({ type: "spki", format: "pem" }).toString() }], revokedKeyIds: [historicalKeyId] };
  const adjudicationUnsigned = { schema: "keep.publication-operator-adjudication/v1" as const, attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId, adjudicatedDisposition: "effect-absent" as const, observedCommit: attempt.priorPublishedCommit, operatorEvidenceDigest: "a".repeat(64), reason: "sealed before this historical key was revoked", keyId: historicalKeyId };
  const adjudicationSignature = sign(null, Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(adjudicationUnsigned)}`, "utf8"), historicalPrivate).toString("base64");
  s.stage({ type: "effect.terminal", actor: "historical", payload: { kind: "auto_merge.publication_adjudicated", adjudication: { ...adjudicationUnsigned, signatureBase64: adjudicationSignature } } }); await s.seal();
  const target = s.replay().at(-1)!;
  const quarantineDigest = createHash("sha256").update("keep.publication-quarantine/v1\0").update(canonicalize(target)).digest("hex");
  const acknowledgementUnsigned = { schema: "keep.publication-quarantine-acknowledgement/v1" as const, quarantineDigest, operatorEvidenceDigest: "b".repeat(64), reason: "attempted retroactive erasure", keyId: trust.keyId };
  const acknowledgementSignature = sign(null, Buffer.from(`keep.publication-quarantine-acknowledgement/v1\0${canonicalize(acknowledgementUnsigned)}`, "utf8"), currentPrivate).toString("base64");
  const { ex } = exec(new InMemoryMergePort(), { spine: s, publicationOperatorTrust: trust });
  assert.ok((await ex.reconcileOutstandingPublications()).every((row) => !row.needsHuman && row.status !== "uncertain"));
  await assert.rejects(() => ex.acknowledgePublicationQuarantine({ ...acknowledgementUnsigned, signatureBase64: acknowledgementSignature }), /valid publication adjudication cannot be quarantined/);
});

test("AM2c ADJUDICATION: a signed exact-attempt decision closes an otherwise in-doubt legacy target", async () => {
  const s = spine();
  const attempt = makePublicationAttempt(spec, identity);
  await sealAttempt(s, attempt);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "operator-2026", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const unsigned = {
    schema: "keep.publication-operator-adjudication/v1" as const,
    attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId,
    adjudicatedDisposition: "effect-absent" as const, observedCommit: attempt.priorPublishedCommit,
    operatorEvidenceDigest: "9".repeat(64), reason: "authoritative ref inspected during target-schema migration", keyId: trust.keyId,
  };
  const signatureBase64 = sign(null, Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64");
  let reconciliations = 0;
  class ReconciledPort extends InMemoryMergePort {
    override async reconcileAbsentPublication() { reconciliations++; return { reconciled: true, reason: "residue preserved and base restored" }; }
  }
  const { ex } = exec(new ReconciledPort({ publicationUncertain: true }), { spine: s, publicationOperatorTrust: trust });
  assert.equal((await ex.reconcileOutstandingPublications())[0]?.status, "uncertain");
  await ex.adjudicatePublication({ ...unsigned, signatureBase64 });
  assert.equal(reconciliations, 1, "the signed observation drives the real absent-effect reconciliation path");
  assert.deepEqual(await ex.reconcileOutstandingPublications(), []);
  await assert.rejects(() => ex.adjudicatePublication({ ...unsigned, signatureBase64 }), /existing terminal/);
  const tampered = { ...unsigned, attemptDigest: "8".repeat(64), signatureBase64 };
  await assert.rejects(() => ex.adjudicatePublication(tampered), /signature is invalid/);
});

test("AM2c ADJUDICATION: invalid terminal-shaped input cannot permanently deny a valid decision", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
  s.stage({ type: "effect.terminal", actor: "hostile", payload: { kind: "auto_merge.publication_adjudicated", adjudication: { attemptDigest: publicationAttemptDigest(attempt) } } });
  await s.seal();
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "operator-valid", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const unsigned = { schema: "keep.publication-operator-adjudication/v1" as const, attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId, adjudicatedDisposition: "effect-absent" as const, observedCommit: attempt.priorPublishedCommit, operatorEvidenceDigest: "7".repeat(64), reason: "exact ref inspection", keyId: trust.keyId };
  const signatureBase64 = sign(null, Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64");
  const { ex } = exec(new InMemoryMergePort({ publicationUncertain: true }), { spine: s, publicationOperatorTrust: trust });
  await ex.adjudicatePublication({ ...unsigned, signatureBase64 });
  const recovery = await ex.reconcileOutstandingPublications();
  const garbage = recovery.find((row) => /cannot be verified/.test(row.reason));
  assert.ok(garbage, "garbage remains visible as a separate hold");
  assert.equal(missingPublicationActuatorRecoveryHold(s, trust)?.attemptDigest, garbage!.attemptDigest, "actuator-free recovery sees the same malformed adjudication");
  assert.ok(!recovery.some((row) => row.attemptDigest === publicationAttemptDigest(attempt)), "the valid decision still reconciles its exact attempt");
  const acknowledgementUnsigned = { schema: "keep.publication-quarantine-acknowledgement/v1" as const, quarantineDigest: garbage!.attemptDigest, operatorEvidenceDigest: "1".repeat(64), reason: "operator quarantined exact malformed adjudication carrier", keyId: trust.keyId };
  const acknowledgementSignature = sign(null, Buffer.from(`keep.publication-quarantine-acknowledgement/v1\0${canonicalize(acknowledgementUnsigned)}`, "utf8"), privateKey).toString("base64");
  await ex.acknowledgePublicationQuarantine({ ...acknowledgementUnsigned, signatureBase64: acknowledgementSignature });
  assert.deepEqual(await ex.reconcileOutstandingPublications(), []);
  assert.equal(missingPublicationActuatorRecoveryHold(s, trust), undefined, "both readers discharge the exact malformed adjudication after signed disposition");
});

test("AM2c READER CONVERGENCE: byte-identical verified receipts are idempotent while substituted receipts hold", async () => {
  {
    const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt); await sealVerifiedFact(s, attempt); await sealVerifiedFact(s, attempt);
    const { ex } = exec(new InMemoryMergePort(), { spine: s });
    assert.ok((await ex.reconcileOutstandingPublications()).every((row) => !row.needsHuman && row.status !== "uncertain"));
    assert.equal(missingPublicationActuatorRecoveryHold(s), undefined);
  }
  {
    const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt); await sealVerifiedFact(s, attempt);
      s.stage({ type: "effect.receipt", actor: "hostile", payload: {
        kind: "auto_merge.publication_verified", attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId,
        publishedCommit: attempt.identity.publishedCommit, publishedTree: "f".repeat(40),
        verifiedProjectManifestDigest: attempt.identity.publishedProjectManifestDigest,
        verifiedGuestExecutionRequestDigest: attempt.spec.expectedGuestExecutionRequestDigest,
      } });
      await s.seal();
    const { ex } = exec(new InMemoryMergePort(), { spine: s });
    const withActuator = await ex.reconcileOutstandingPublications();
    const expected = withActuator.find((row) => /verified receipt is orphaned, substituted, or duplicated/.test(row.reason));
    assert.ok(expected, "substituted receipt is held by actuator recovery");
    const withoutActuator = missingPublicationActuatorRecoveryHold(s);
    assert.equal(withoutActuator?.attemptDigest, expected!.attemptDigest, "substituted receipt is held by actuator-free recovery with the same carrier identity");
  }
});

test("AM2c READER CONVERGENCE: contradictory terminals and verified facts produce the same carrier hold", async () => {
  for (const scenario of ["verified-versus-absent", "conflicting-terminals"] as const) {
    const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
    if (scenario === "verified-versus-absent") {
      await sealVerifiedFact(s, attempt); await sealTerminal(s, attempt);
    } else {
      await sealTerminal(s, attempt);
      s.stage({ type: "effect.terminal", actor: "hostile", payload: { kind: "auto_merge.publication_terminal", attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId, disposition: "reconciled-effect-occurred", reason: "contradictory second terminal" } }); await s.seal();
    }
    const { ex } = exec(new InMemoryMergePort(), { spine: s });
    const withActuator = await ex.reconcileOutstandingPublications();
    const contradiction = withActuator.find((row) => /contradict/.test(row.reason));
    assert.ok(contradiction, `${scenario} remains a content-addressed contradiction hold`);
    assert.equal(missingPublicationActuatorRecoveryHold(s)?.attemptDigest, contradiction!.attemptDigest, `${scenario} has one shared hold identity`);
  }
});

test("AM2c ADJUDICATION: a signed but wrong-operation historical observation cannot deny an exact decision", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "operator-history", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const wrong = { schema: "keep.publication-operator-adjudication/v1" as const, attemptDigest: publicationAttemptDigest(attempt), operationId: "0".repeat(64), adjudicatedDisposition: "effect-absent" as const, observedCommit: attempt.priorPublishedCommit, operatorEvidenceDigest: "3".repeat(64), reason: "stale operation identity", keyId: trust.keyId };
  const wrongSignature = sign(null, Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(wrong)}`, "utf8"), privateKey).toString("base64");
  s.stage({ type: "effect.terminal", actor: "historical", payload: { kind: "auto_merge.publication_adjudicated", adjudication: { ...wrong, signatureBase64: wrongSignature } } }); await s.seal();
  const exact = { ...wrong, operationId: attempt.operationId, operatorEvidenceDigest: "2".repeat(64), reason: "current exact operation observation" };
  const exactSignature = sign(null, Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(exact)}`, "utf8"), privateKey).toString("base64");
  const { ex } = exec(new InMemoryMergePort({ publicationUncertain: true }), { spine: s, publicationOperatorTrust: trust });
  await ex.adjudicatePublication({ ...exact, signatureBase64: exactSignature });
  const held = await ex.reconcileOutstandingPublications();
  assert.ok(held.some((row) => /cannot be verified/.test(row.reason)), "wrong-operation signed history remains a content-addressed hold");
  assert.ok(!held.some((row) => row.attemptDigest === publicationAttemptDigest(attempt)), "the exact attempt was reconciled despite the stale signed row");
});

test("AM2c ADJUDICATION: mismatched ordinary terminal cannot deny recovery and is clearable only by signed content disposition", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
  s.stage({ type: "effect.terminal", actor: "hostile", payload: { kind: "auto_merge.publication_terminal", attemptDigest: publicationAttemptDigest(attempt), operationId: "0".repeat(64), disposition: "reconciled-effect-absent", reason: "substituted lineage" } });
  await s.seal();
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "terminal-operator", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const adjudicationUnsigned = { schema: "keep.publication-operator-adjudication/v1" as const, attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId, adjudicatedDisposition: "effect-absent" as const, observedCommit: attempt.priorPublishedCommit, operatorEvidenceDigest: "5".repeat(64), reason: "authoritative ref inspected", keyId: trust.keyId };
  const adjudicationSignature = sign(null, Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(adjudicationUnsigned)}`, "utf8"), privateKey).toString("base64");
  const { ex } = exec(new InMemoryMergePort({ publicationUncertain: true }), { spine: s, publicationOperatorTrust: trust });
  await ex.adjudicatePublication({ ...adjudicationUnsigned, signatureBase64: adjudicationSignature });
  const held = await ex.reconcileOutstandingPublications();
  const orphan = held.find((row) => /no exact prior prepared attempt/.test(row.reason));
  assert.ok(orphan, "substituted terminal remains visible by its content identity");
  assert.equal(missingPublicationActuatorRecoveryHold(s, trust)?.attemptDigest, orphan!.attemptDigest, "actuator-free recovery sees the same substituted terminal");
  const acknowledgementUnsigned = { schema: "keep.publication-quarantine-acknowledgement/v1" as const, quarantineDigest: orphan!.attemptDigest, operatorEvidenceDigest: "4".repeat(64), reason: "operator quarantined the exact substituted terminal carrier", keyId: trust.keyId };
  const acknowledgementSignature = sign(null, Buffer.from(`keep.publication-quarantine-acknowledgement/v1\0${canonicalize(acknowledgementUnsigned)}`, "utf8"), privateKey).toString("base64");
  await ex.acknowledgePublicationQuarantine({ ...acknowledgementUnsigned, signatureBase64: acknowledgementSignature });
  assert.deepEqual(await ex.reconcileOutstandingPublications(), []);
  assert.equal(missingPublicationActuatorRecoveryHold(s, trust), undefined, "both recovery readers honor the exact signed carrier disposition");
});

test("AM2c ADJUDICATION: effect-absent cannot contradict a durable verified publication receipt", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt); await sealVerifiedFact(s, attempt);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "operator-verified", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const unsigned = { schema: "keep.publication-operator-adjudication/v1" as const, attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId, adjudicatedDisposition: "effect-absent" as const, observedCommit: attempt.priorPublishedCommit, operatorEvidenceDigest: "6".repeat(64), reason: "contradictory observation", keyId: trust.keyId };
  const signatureBase64 = sign(null, Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64");
  const { ex } = exec(new InMemoryMergePort({ publicationUncertain: true }), { spine: s, publicationOperatorTrust: trust });
  await assert.rejects(() => ex.adjudicatePublication({ ...unsigned, signatureBase64 }), /contradicts a durable verified/);
});

test("AM2c RECOVERY: kill switch holds before any authoritative observation", async () => {
  const s = spine(); await sealAttempt(s, makePublicationAttempt(spec, identity));
  let observations = 0;
  class ObservedPort extends InMemoryMergePort { override async observePublication(attempt: ReturnType<typeof makePublicationAttempt>) { observations++; return super.observePublication(attempt); } }
  const { ex } = exec(new ObservedPort(), { spine: s, killSwitchEngaged: () => true });
  const result = await ex.reconcileOutstandingPublications();
  assert.equal(result[0]?.status, "refused");
  assert.equal(observations, 0);
});

test("AM2c RECOVERY: a durable verified fact is reconfirmed without rerunning or reverting on verifier outage", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
  s.stage({ type: "effect.receipt", actor: "test", payload: {
    kind: "auto_merge.publication_verified", attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId,
    publishedCommit: identity.publishedCommit, publishedTree: identity.publishedTree,
    verifiedProjectManifestDigest: identity.publishedProjectManifestDigest,
    verifiedGuestExecutionRequestDigest: spec.expectedGuestExecutionRequestDigest,
  } });
  await s.seal();
  assert.equal(missingPublicationActuatorRecoveryHold(s)?.attemptDigest, publicationAttemptDigest(attempt), "a verified fact without a terminal remains held when the actuator is absent");
  let verificationCalls = 0; let revertCalls = 0;
  class RecoveryPort extends InMemoryMergePort {
    override async revert(...args: Parameters<InMemoryMergePort["revert"]>) { revertCalls++; return super.revert(...args); }
  }
  const { ex } = exec(new RecoveryPort(), { spine: s, postMergeVerify: async () => { verificationCalls++; throw new Error("Firecracker unavailable"); } });
  const result = await ex.reconcileOutstandingPublications();
  assert.equal(result[0]?.status, "merged");
  assert.equal(verificationCalls, 0);
  assert.equal(revertCalls, 0);
});

test("AM2c READER CONVERGENCE: well-formed adjudications remain held until reconciliation terminalizes", async () => {
  for (const disposition of ["effect-occurred", "effect-absent"] as const) {
    const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const trust = { keyId: `unfinished-${disposition}`, publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
    const unsigned = {
      schema: "keep.publication-operator-adjudication/v1" as const, attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId,
      adjudicatedDisposition: disposition, observedCommit: disposition === "effect-occurred" ? attempt.attemptedCommit : attempt.priorPublishedCommit,
      operatorEvidenceDigest: (disposition === "effect-occurred" ? "a" : "b").repeat(64), reason: "well-formed observation whose local reconciliation is unfinished", keyId: trust.keyId,
    };
    const signatureBase64 = sign(null, Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64");
    s.stage({ type: "effect.terminal", actor: "operator", payload: { kind: "auto_merge.publication_adjudicated", adjudication: { ...unsigned, signatureBase64 } } }); await s.seal();
    class UnfinishedPort extends InMemoryMergePort {
      override async reconcileAbsentPublication() { return { reconciled: false, reason: "local residue remains" }; }
    }
    const { ex } = exec(new UnfinishedPort(), { spine: s, publicationOperatorTrust: trust, postMergeVerify: async () => { throw new Error("verifier unavailable"); } });
    const withActuator = await ex.reconcileOutstandingPublications();
    assert.equal(withActuator[0]?.status, "uncertain");
    assert.equal(withActuator[0]?.attemptDigest, publicationAttemptDigest(attempt));
    assert.equal(missingPublicationActuatorRecoveryHold(s, trust)?.attemptDigest, withActuator[0]?.attemptDigest, `${disposition} remains held by both readers until a terminal exists`);
  }
});

test("AM2c RECOVERY: incomplete fresh verifier output holds an observed effect and never compensates it", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt);
  let revertCalls = 0;
  class RecoveryPort extends InMemoryMergePort {
    override async revert(...args: Parameters<InMemoryMergePort["revert"]>) { revertCalls++; return super.revert(...args); }
  }
  const { ex } = exec(new RecoveryPort(), { spine: s, postMergeVerify: async () => ({ regressed: false }) });
  const result = await ex.reconcileOutstandingPublications();
  assert.equal(result[0]?.status, "uncertain");
  assert.match(result[0]?.reason ?? "", /no current matching Firecracker authority/);
  assert.equal(revertCalls, 0);
});

test("AM2c RACE: concurrent recovery processes serialize observation and terminalization", async () => {
  const s = spine(); const attempt = makePublicationAttempt(spec, identity); await sealAttempt(s, attempt); await sealVerifiedFact(s, attempt);
  let observations = 0; let active = 0; let maximumActive = 0;
  class SlowPort extends InMemoryMergePort {
    override async observePublication(attempt: ReturnType<typeof makePublicationAttempt>) {
      observations++; active++; maximumActive = Math.max(maximumActive, active);
      await new Promise((resolve) => setTimeout(resolve, 20));
      try { return await super.observePublication(attempt); } finally { active--; }
    }
  }
  const port = new SlowPort();
  const first = exec(port, { spine: s }).ex;
  const second = exec(port, { spine: s }).ex;
  const [a, b] = await Promise.all([first.reconcileOutstandingPublications(), second.reconcileOutstandingPublications()]);
  assert.equal(observations, 1, "the later recovery replays the first terminal instead of re-observing the effect");
  assert.equal(maximumActive, 1);
  assert.equal(a.length + b.length, 1);
});

// ── THE STRUCTURAL GATE: only autonomous-merge can ever merge ──
for (const v of ["human-merge", "abandon-retry", "block"] as const) {
  test(`AM2 GATE: a "${v}" verdict is REFUSED — nothing is ever merged`, async () => {
    const port = new InMemoryMergePort();
    const { ex } = exec(port);
    const r = await ex.execute(decision(v), spec);
    assert.equal(r.status, "refused");
    assert.equal(port.liveCount, 0, "the executor never called merge for a non-autonomous verdict");
  });
}

test("AM2 AUTHORITY: an InMemoryMergePort subclass cannot inherit the effect-free test exception", async () => {
  let preflightInvoked = false;
  class EffectfulImitation extends InMemoryMergePort {
    override async dryRun(candidate: MergeSpec) {
      preflightInvoked = true;
      return super.dryRun(candidate);
    }
  }
  const s = spine();
  const ex = new AutonomousMergeExecutor({
    port: new EffectfulImitation(), spine: s,
    postMergeVerify: async () => ({ regressed: false }),
  });
  const result = await ex.execute(decision("autonomous-merge"), spec);
  assert.equal(result.status, "refused");
  assert.equal(preflightInvoked, false, "authority is checked before any caller-controlled port method");
});

// ── KILL SWITCH + PRE-MERGE guards ──
test("AM2: the kill switch pauses autonomous merge entirely (deny-by-default)", async () => {
  const port = new InMemoryMergePort();
  const { ex } = exec(port, { killSwitchEngaged: () => true });
  const r = await ex.execute(decision("autonomous-merge"), spec);
  assert.equal(r.status, "refused");
  assert.equal(port.liveCount, 0);
});

for (const row of [
  { name: "exact request", observed: spec.expectedGuestExecutionRequestDigest, requestMismatch: false },
  { name: "absent request", observed: undefined, requestMismatch: true },
  { name: "changed request", observed: "d".repeat(64), requestMismatch: true },
] as const) {
  test(`AM2 POST-MERGE REQUEST: ${row.name} is classified fail-closed`, () => {
    const result = classifyPostMergeExecutionSubject(
      spec,
      { publishedProjectManifestDigest: spec.expectedCandidateProjectManifestDigest },
      {
        verifiedProjectManifestDigest: spec.expectedCandidateProjectManifestDigest,
        ...(row.observed === undefined ? {} : { verifiedGuestExecutionRequestDigest: row.observed }),
      },
      true,
    );
    assert.equal(result.requestMismatch, row.requestMismatch);
    assert.equal(result.mismatch, row.requestMismatch, "request identity alone must decide this otherwise-clean classification");
  });
}
