import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";

import { Spine } from "../src/spine/spine.js";
import { FileSpineStore } from "../src/spine/store.js";
import { SchemaRegistry } from "../src/spine/upcaster.js";
import { InProcessLock } from "../src/lock/lock.js";
import type { ModelProvider, GenerateResult, Embedding } from "../src/gateway/gateway.js";

import { InMemoryFileTree } from "../src/solve/patch.js";
import type { TestRunner, TestRunResult } from "../src/solve/validate.js";
import type { Issue } from "../src/solve/issue_model.js";
import type { RepoFile } from "../src/solve/localize.js";
import { GitAdapter } from "../src/infra/git_adapter.js";
import { KeepPipeline } from "../src/pipeline/keep_pipeline.js";
import { BoundaryExecutor } from "../src/isolation/isolated_executor.js";
import { seamEvidenceForTier } from "../src/isolation/isolation_attestation.js";
import { InMemoryMergePort } from "./helpers/in_memory_merge_port.js";
import { pinnedRemoteFetchUrlSha256, pinnedRemoteUrlSha256 } from "../src/git/pinned_remote.js";
import { makePublicationAttempt, publicationAttemptDigest, type MergeSpec, type PublishedMergeIdentity } from "../src/oversight/merge_executor.js";
import { canonicalize } from "../src/spine/event.js";

function newSpine(dir: string): Spine {
  return new Spine(new FileSpineStore(dir), new InProcessLock(), new SchemaRegistry());
}

function setupRemote(seedFile: string, seedContent: string): { work: string; bare: string } {
  const root = mkdtempSync(join(tmpdir(), "keep-e2e-"));
  const bare = join(root, "o.git"); const work = join(root, "w");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  execFileSync("git", ["clone", "-q", bare, work]);
  const g = (a: string[]) => execFileSync("git", a, { cwd: work });
  g(["config", "user.email", "t@t"]); g(["config", "user.name", "t"]); g(["checkout", "-qb", "main"]);
  execFileSync("bash", ["-c", `mkdir -p "$(dirname ${join(work, seedFile)})" && printf '%s' ${JSON.stringify(seedContent)} > ${join(work, seedFile)}`]);
  g(["add", "-A"]); g(["commit", "-qm", "init"]); g(["push", "-q", "-u", "origin", "main"]);
  g(["remote", "set-url", "origin", `file://${bare}`]);
  return { work, bare };
}

function gitDeps(work: string) {
  const url = execFileSync("git", ["remote", "get-url", "--push", "origin"], { cwd: work }).toString().trim();
  return { git: new GitAdapter(work), baseBranch: "main", remoteConfig: { remote: "origin", expectedFetchUrlSha256: pinnedRemoteFetchUrlSha256(url), expectedPushUrlSha256: pinnedRemoteUrlSha256(url) } } as const;
}

function fixModel(search: string, replace: string): ModelProvider {
  return {
    name: "fix", isLocal: true,
    async generate(): Promise<GenerateResult> {
      return { text: JSON.stringify({ rationale: "fix", edits: [{ file: "src/calc.ts", search, replace, intent: "fix" }] }), model: "fix", tokensIn: 1, tokensOut: 1 };
    },
    async embed(): Promise<Embedding[]> { return []; },
  };
}

test("PUBLICATION RECOVERY WIRING: installed pipeline consumes configured operator trust and reconciles the signed observation", async () => {
  const { work } = setupRemote("src/calc.ts", "export const x = 1;\n");
  const spine = new Spine(new FileSpineStore(mkdtempSync(join(tmpdir(), "keep-e2e-adjudication-")), { fsync: true }), new InProcessLock(), new SchemaRegistry());
  const spec: MergeSpec = { issueId: "RECOVER-1", repoRef: work, branch: "keep/solve/RECOVER-1", baseBranch: "main", expectedCandidateCommit: "a".repeat(40), expectedCandidateProjectManifestDigest: "b".repeat(64), expectedGuestExecutionRequestDigest: "c".repeat(64), projectDir: work };
  const identity: PublishedMergeIdentity = { candidateCommit: spec.expectedCandidateCommit, candidateTree: "1".repeat(40), candidateProjectManifestDigest: spec.expectedCandidateProjectManifestDigest, baseCommit: "2".repeat(40), baseTree: "3".repeat(40), expectedMergedTree: "4".repeat(40), mergedCommit: "5".repeat(40), mergedTree: "4".repeat(40), publishedCommit: "5".repeat(40), publishedTree: "4".repeat(40), publishedProjectManifestDigest: spec.expectedCandidateProjectManifestDigest, publicationTarget: "remote:origin:refs/heads/main" };
  const attempt = makePublicationAttempt(spec, identity);
  spine.stage({ type: "effect.intent", actor: "test", payload: { kind: "auto_merge.publication_prepared", attemptDigest: publicationAttemptDigest(attempt), attempt } });
  await spine.seal();
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const trust = { keyId: "pipeline-operator", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
  const unsigned = { schema: "keep.publication-operator-adjudication/v1" as const, attemptDigest: publicationAttemptDigest(attempt), operationId: attempt.operationId, adjudicatedDisposition: "effect-absent" as const, observedCommit: attempt.priorPublishedCommit, operatorEvidenceDigest: "9".repeat(64), reason: "authoritative ref inspected", keyId: trust.keyId };
  const signatureBase64 = sign(null, Buffer.from(`keep.publication-operator-adjudication/v1\0${canonicalize(unsigned)}`, "utf8"), privateKey).toString("base64");
  spine.stage({ type: "effect.terminal", actor: "operator", payload: { kind: "auto_merge.publication_adjudicated", adjudication: { ...unsigned, signatureBase64 } } });
  await spine.seal();
  const baseDeps = { spine, tree: new InMemoryFileTree({}), runner: { async run() { return { results: [{ name: "unused", passed: true }] }; } }, model: fixModel("x", "y") };
  const noTrust = new KeepPipeline(baseDeps);
  const held = await noTrust.reconcilePublications({ ...gitDeps(work), mergePort: new InMemoryMergePort({ publicationUncertain: true }) });
  assert.match(held[0]?.reason ?? "", /no operator trust root is configured/);
  const configured = new KeepPipeline({ ...baseDeps, publicationOperatorTrust: trust });
  const reconciled = await configured.reconcilePublications({ ...gitDeps(work), mergePort: new InMemoryMergePort({ publicationUncertain: true }) });
  assert.equal(reconciled[0]?.status, "abstained");
  assert.deepEqual(await configured.reconcilePublications({ ...gitDeps(work), mergePort: new InMemoryMergePort({ publicationUncertain: true }) }), []);
});

test("INVARIANT: ONE call runs the whole spine → human-gated PR on a real remote (audit-closing test)", async () => {
  const { work, bare } = setupRemote("src/calc.ts", "export function add(a, b) { return a - b; }\n");
  const dir = mkdtempSync(join(tmpdir(), "keep-e2e-spine-"));
  const spine = newSpine(dir);

  const files: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
  const tree = new InMemoryFileTree({ "src/calc.ts": "export function add(a, b) { return a - b; }" });
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };

  // Apply the fix to the real working tree too (so the git diff is real), mirroring what a real
  // FileTree bound to the worktree would do.
  const pipeline = new KeepPipeline({ spine, tree, runner, model: fixModel("return a - b;", "return a + b;") });
  execFileSync("bash", ["-c", `mkdir -p "$(dirname ${join(work, "src/calc.ts")})" && printf '%s' 'export function add(a, b) { return a + b; }\n' > ${join(work, "src/calc.ts")}`]);

  const issue: Issue = { id: "E2E-1", text: "add() in calc.ts subtracts instead of adds", repoRef: "e2e" };
  const result = await pipeline.solveIssueToPR(issue, files, { ...gitDeps(work), mergePort: new InMemoryMergePort() }, { autonomyLevel: "operator" });

  assert.equal(result.solveResult.solved, true, "the whole spine ran and solved");
  assert.ok(result.manifest, "a PR manifest was produced in one call");
  assert.equal(result.manifest!.humanApprovalRequired, true, "human gate intact");
  assert.ok(result.manifest!.oversight, "oversight decision attached");
  // AM1: the merge-authority decision is computed, attached, and audited on a real run. The
  // default process-backed executor cannot establish the native isolation floor, so even this
  // verified reversible change remains human-gated.
  assert.ok(result.mergeAuthority, "AM1: merge-authority decision attached to the result");
  assert.equal(result.mergeAuthority!.verdict, "human-merge", "missing native isolation evidence keeps the real run human-gated");
  assert.ok(spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "merge_authority"), "the merge-authority decision was audited to the spine");
  assert.equal(result.autoMerge, undefined, "the merge port cannot bypass the isolation floor");
  assert.equal(spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "auto_merge.verified"), false, "no autonomous-merge success was recorded");
  // Isolation: every untrusted test execution ran inside the isolation tier and was audited.
  assert.ok(spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "isolated_execution"), "test execution went through the isolation boundary");
  // NO-FALSE-POSITIVE: the isolation backstop clause must NOT fire on a legitimate solve (isolation ran before publish).
  {
    const { ReferenceMonitor } = await import("../src/control/reference_monitor.js");
    const { defaultKeepClauses } = await import("../src/control/reference_clauses.js");
    const rm = new ReferenceMonitor();
    for (const c of defaultKeepClauses()) rm.register(c);
    const trace = spine.currentEvents().map((e) => ({ type: String((e as { type?: string }).type ?? "identity.action"), actor: "keep", payload: e.payload as Record<string, unknown> }));
    const violations = rm.audit(trace).filter((v) => v.clauseId === "external-effect-requires-isolation");
    assert.deepEqual(violations, [], "a real solve (isolation before publish) does not trip the isolation backstop");
  }
  // The branch reached the real remote.
  const verify = mkdtempSync(join(tmpdir(), "keep-e2e-v-"));
  execFileSync("git", ["clone", "-q", bare, verify]);
  assert.match(execFileSync("git", ["branch", "-a"], { cwd: verify }).toString(), /keep\/solve\/E2E-1/);
});

test("INVARIANT: an unsolvable issue returns a solveResult with no PR (graceful)", async () => {
  const { work } = setupRemote("src/calc.ts", "export function add(a, b) { return a - b; }\n");
  const dir = mkdtempSync(join(tmpdir(), "keep-e2e-u-"));
  const spine = newSpine(dir);
  const files: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
  const tree = new InMemoryFileTree({ "src/calc.ts": "export function add(a, b) { return a - b; }" });
  const runner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [{ name: "add", passed: false, output: "nope" }] }; } };

  // Model proposes an edit that won't match → apply fails → gives up.
  const pipeline = new KeepPipeline({ spine, tree, runner, model: fixModel("nonexistent code", "x") });
  const issue: Issue = { id: "U-1", text: "unfixable", repoRef: "u" };
  const result = await pipeline.solveIssueToPR(issue, files, gitDeps(work));
  assert.equal(result.solveResult.solved, false);
  assert.equal(result.manifest, undefined, "no PR for an unsolved issue");
});

test("INVARIANT: the top-level solve_to_pr run is audited to the spine", async () => {
  const { work } = setupRemote("src/calc.ts", "export function add(a, b) { return a - b; }\n");
  const dir = mkdtempSync(join(tmpdir(), "keep-e2e-a-"));
  const spine = newSpine(dir);
  const files: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
  const tree = new InMemoryFileTree({ "src/calc.ts": "export function add(a, b) { return a - b; }" });
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      return { results: [{ name: "add", passed: c.includes("a + b") }] };
    },
  };
  execFileSync("bash", ["-c", `mkdir -p "$(dirname ${join(work, "src/calc.ts")})" && printf '%s' 'export function add(a, b) { return a + b; }\n' > ${join(work, "src/calc.ts")}`]);
  const pipeline = new KeepPipeline({ spine, tree, runner, model: fixModel("return a - b;", "return a + b;") });
  await pipeline.solveIssueToPR({ id: "A-1", text: "add subtracts", repoRef: "a" }, files, gitDeps(work), { autonomyLevel: "operator" });
  await spine.seal();
  const events = spine.replay().filter((e) => (e.payload as Record<string, unknown>)["event"] === "solve_to_pr");
  assert.equal(events.length, 1, "the top-level run is on the tamper-evident spine");
});

test("INVARIANT: the default localizer is the on-device GraphLocalizer", () => {
  const spine = newSpine(mkdtempSync(join(tmpdir(), "keep-e2e-l-")));
  const tree = new InMemoryFileTree({});
  const runner: TestRunner = { async run(): Promise<TestRunResult> { return { results: [] }; } };
  const pipeline = new KeepPipeline({ spine, tree, runner, model: fixModel("a", "b") });
  // Access the private field for the test (structural check that we defaulted correctly).
  const loc = (pipeline as unknown as { localizer: { constructor: { name: string } } }).localizer;
  assert.equal(loc.constructor.name, "GraphLocalizer");
});

// ─── F2: an authorized calibration policy threads through solveIssueToPR → the router ───

async function solveOnce(opts: { reducedEscalationClasses?: ReadonlySet<string> }) {
  const dir = mkdtempSync(join(tmpdir(), "keep-f2-"));
  const { work } = setupRemote("src/calc.ts", "export function add(a, b) { return a - b; }\n");
  const spine = newSpine(dir);
  const files: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
  const tree = new InMemoryFileTree({ "src/calc.ts": "export function add(a, b) { return a - b; }" });
  const runner: TestRunner = {
    async run(): Promise<TestRunResult> {
      const c = (await tree.read("src/calc.ts")) ?? "";
      const ok = c.includes("a + b");
      return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] };
    },
  };
  // This exercises the F2 calibration-policy path with a deliberately nonauthorizing seam. A
  // seam may prove policy threading, but it cannot establish the process/microVM enforcement
  // needed to relax the product's approval floor.
  const microvmExecutor = new BoundaryExecutor("microvm", (r, s) => r.run(s.repoRef), spine, "microvm", seamEvidenceForTier("microvm"));
  const pipeline = new KeepPipeline({ spine, tree, runner, model: fixModel("return a - b;", "return a + b;"), isolationTier: "microvm", isolationExecutor: microvmExecutor });
  execFileSync("bash", ["-c", `mkdir -p "$(dirname ${join(work, "src/calc.ts")})" && printf '%s' 'export function add(a, b) { return a + b; }\\n' > ${join(work, "src/calc.ts")}`]);
  const issue: Issue = { id: "F2-1", text: "add() in calc.ts subtracts instead of adds", repoRef: "f2" };
  return pipeline.solveIssueToPR(issue, files, gitDeps(work), { autonomyLevel: "approver", ...(opts.reducedEscalationClasses ? { reducedEscalationClasses: opts.reducedEscalationClasses } : {}) });
}

test("F2 end-to-end: calibration policy cannot override a nonauthorizing isolation seam", async () => {
  const gated = await solveOnce({});
  assert.equal(gated.manifest!.oversight!.disposition, "human-approval-required", "at approver, no policy → gated");
  const band = gated.manifest!.oversight!.band;
  assert.notEqual(band, "high", "a one-line clean fix should not be high risk");

  const withPolicy = await solveOnce({ reducedEscalationClasses: new Set([band]) });
  assert.equal(withPolicy.manifest!.oversight!.disposition, "human-approval-required", "policy cannot turn seam evidence into enforcement authority");
  assert.equal(withPolicy.manifest!.humanApprovalRequired, true, "the approval floor remains intact");
});

// ── AM3: reversible uncertainty never reaches a human ────────────────────────

function calcRunnerFor(tree: InMemoryFileTree): TestRunner {
  return { async run(): Promise<TestRunResult> { const c = (await tree.read("src/calc.ts")) ?? ""; const ok = c.includes("a + b"); return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "expected +" }) }] }; } };
}

test("AM3: an unverified reversible change remains human-gated when isolation is unproven", async () => {
  const { work } = setupRemote("src/calc.ts", "export function add(a, b) { return a - b; }\n");
  const spine = newSpine(mkdtempSync(join(tmpdir(), "keep-am3a-")));
  const files: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
  const tree = new InMemoryFileTree({ "src/calc.ts": "export function add(a, b) { return a - b; }" });
  // Fixing model → tests pass (solved). vet:false → never clears vetting → unverified. Reversible + low-blast.
  const pipeline = new KeepPipeline({ spine, tree, runner: calcRunnerFor(tree), model: fixModel("return a - b;", "return a + b;"), vet: async () => false });
  execFileSync("bash", ["-c", `printf '%s' 'export function add(a, b) { return a + b; }\n' > ${join(work, "src/calc.ts")}`]);
  const result = await pipeline.solveIssueToPR(issueOf("AM3-1"), files, gitDeps(work), {});
  assert.equal(result.mergeAuthority?.verdict, "human-merge", "the isolation forced gate dominates the reversible retry policy");
  assert.equal(result.abandoned, undefined, "the forced gate prevents automatic abandonment");
  assert.ok(result.manifest, "a human-facing PR preserves the unverified candidate for review");
  assert.equal(result.autoMerge, undefined, "and nothing was merged");
  assert.equal(spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "solve_abandoned"), false, "the candidate was not silently discarded");
});

test("AM3 CONTRAST: an unverified change on a SENSITIVE (always-gate) path goes to a HUMAN, not abandoned", async () => {
  const { work } = setupRemote("src/auth/session.ts", "export function login(a, b) { return a - b; }\n");
  const spine = newSpine(mkdtempSync(join(tmpdir(), "keep-am3b-")));
  const files: RepoFile[] = [{ path: "src/auth/session.ts", content: "export function login(a, b) { return a - b; }" }];
  const tree = new InMemoryFileTree({ "src/auth/session.ts": "export function login(a, b) { return a - b; }" });
  const runner: TestRunner = { async run(): Promise<TestRunResult> { const c = (await tree.read("src/auth/session.ts")) ?? ""; const ok = c.includes("a + b"); return { results: [{ name: "login", passed: ok, ...(ok ? {} : { output: "x" }) }] }; } };
  const model: ModelProvider = { name: "fix", isLocal: true, async generate(): Promise<GenerateResult> { return { text: JSON.stringify({ rationale: "fix", edits: [{ file: "src/auth/session.ts", search: "return a - b;", replace: "return a + b;", intent: "fix" }] }), model: "fix", tokensIn: 1, tokensOut: 1 }; }, async embed(): Promise<Embedding[]> { return []; } };
  const pipeline = new KeepPipeline({ spine, tree, runner, model, vet: async () => false });
  execFileSync("bash", ["-c", `mkdir -p ${join(work, "src/auth")} && printf '%s' 'export function login(a, b) { return a + b; }\n' > ${join(work, "src/auth/session.ts")}`]);
  const result = await pipeline.solveIssueToPR(issueOf("AM3-2", "login in auth"), files, gitDeps(work), {});
  assert.equal(result.mergeAuthority?.verdict, "human-merge", "a sensitive path is consequential → a human decides");
  assert.equal(result.abandoned, undefined, "NOT abandoned — the human is (correctly) involved for a sensitive change");
  assert.ok(result.manifest, "a human-facing PR WAS published");
});

test("AM3: outer re-solves cannot replenish the inner recovery allowance — no human bothered", async () => {
  const { work } = setupRemote("src/calc.ts", "export function add(a, b) { return a - b; }\n");
  const spine = newSpine(mkdtempSync(join(tmpdir(), "keep-am3c-")));
  const files: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
  const tree = new InMemoryFileTree({ "src/calc.ts": "export function add(a, b) { return a - b; }" });
  // Non-fixing model: outer re-solves share the inner allowance instead of multiplying it.
  const pipeline = new KeepPipeline({ spine, tree, runner: calcRunnerFor(tree), model: fixModel("return a - b;", "return a - b; /* noop */") });
  const result = await pipeline.solveIssueToPR(issueOf("AM3-3"), files, gitDeps(work), { maxAutoRetries: 2 });
  const retries = spine.currentEvents().filter((e) => (e.payload as Record<string, unknown>)["event"] === "solve_retry").length;
  assert.equal(retries, 1, "the inner attempts leave room for only one outer re-solve");
  assert.equal(result.solveResult.recovery?.attempts, 4);
  assert.equal(result.solveResult.recovery?.status, "exhausted");
  assert.equal(result.solveResult.solved, false, "still unsolved after retries");
  assert.equal(result.manifest, undefined, "no human PR for an unsolved reversible attempt");
});

function issueOf(id: string, text = "add() in calc.ts subtracts instead of adds"): Issue { return { id, text, repoRef: "e2e" }; }

test("PROVIDER RESILIENCE: with brainRungs, a 429 on the primary model FAILS OVER and the solve still lands", async () => {
  const { work } = setupRemote("src/calc.ts", "export function add(a, b) { return a - b; }\n");
  const spine = newSpine(mkdtempSync(join(tmpdir(), "keep-res-")));
  const files: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
  const tree = new InMemoryFileTree({ "src/calc.ts": "export function add(a, b) { return a - b; }" });
  const runner: TestRunner = { async run(): Promise<TestRunResult> { const c = (await tree.read("src/calc.ts")) ?? ""; const ok = c.includes("a + b"); return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "x" }) }] }; } };
  const { ProviderError } = await import("../src/gateway/http_provider.js");
  // Primary model always 429s; the fallback rung produces the fix.
  const primary: ModelProvider = { name: "primary", isLocal: false, async generate(): Promise<GenerateResult> { throw new ProviderError("429", 429, false); }, async embed(): Promise<Embedding[]> { return []; } };
  const fallback: ModelProvider = fixModel("return a - b;", "return a + b;");
  const pipeline = new KeepPipeline({ spine, tree, runner, model: primary, brainRungs: [{ id: "fallback", cost: "free", provider: fallback }] });
  execFileSync("bash", ["-c", `printf '%s' 'export function add(a, b) { return a + b; }\n' > ${join(work, "src/calc.ts")}`]);
  const result = await pipeline.solveIssueToPR(issueOf("RES-1"), files, gitDeps(work), {});
  assert.equal(result.solveResult.solved, true, "the fallback rung served the request after the primary 429'd");
  assert.ok(spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "brain_ladder.ok"), "the resilient ladder was used + audited");
});

test("COST-CASCADE WIRE: with routedModel config, the pipeline solves through the ProviderRouter brain (cheapest-that-clears)", async () => {
  const { work } = setupRemote("src/calc.ts", "export function add(a, b) { return a - b; }\n");
  const spine = newSpine(mkdtempSync(join(tmpdir(), "keep-routed-")));
  const files: RepoFile[] = [{ path: "src/calc.ts", content: "export function add(a, b) { return a - b; }" }];
  const tree = new InMemoryFileTree({ "src/calc.ts": "export function add(a, b) { return a - b; }" });
  const runner: TestRunner = { async run(): Promise<TestRunResult> { const c = (await tree.read("src/calc.ts")) ?? ""; const ok = c.includes("a + b"); return { results: [{ name: "add", passed: ok, ...(ok ? {} : { output: "x" }) }] }; } };
  const cheap = fixModel("return a - b;", "return a + b;"); // the cheap tier produces the fix
  const providers = [{ id: "cheap", tier: "minimal" as const, costWeight: 1, provider: cheap }];
  const pipeline = new KeepPipeline({ spine, tree, runner, model: cheap, routedModel: { providers, predictor: () => 0.9 } });
  execFileSync("bash", ["-c", `printf '%s' 'export function add(a, b) { return a + b; }\n' > ${join(work, "src/calc.ts")}`]);
  const result = await pipeline.solveIssueToPR(issueOf("ROUTED-1"), files, gitDeps(work), {});
  assert.equal(result.solveResult.solved, true, "solved via the cost-cascade router brain");
  assert.ok(spine.currentEvents().some((e) => (e.payload as Record<string, unknown>)["event"] === "routed"), "the router audited its route");
});
