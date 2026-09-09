import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const script = fileURLToPath(import.meta.url);
if (process.env.KEEP_ENTERPRISE_GATEWAY_CHILD !== "1") {
  if (process.platform !== "linux") throw new Error("installed enterprise release admission requires Linux mount namespaces");
  const childEnv = { ...process.env, KEEP_ENTERPRISE_GATEWAY_CHILD: "1" };
  delete childEnv.NODE_TEST_CONTEXT;
  execFileSync("unshare", ["-Urm", process.execPath, script], { env: childEnv, stdio: "inherit", timeout: 10 * 60_000 });
  process.exit(0);
}

const tarball = process.env.KEEP_TARBALL;
const sourceRoot = process.env.KEEP_SOURCE_ROOT;
const testLocation = process.env.KEEP_ENTERPRISE_TEST_LOCATION ?? "external";
if (testLocation !== "external" && testLocation !== "local") throw new Error("KEEP_ENTERPRISE_TEST_LOCATION must be external or local");
const localTest = testLocation === "local";
const apiKey = localTest ? randomBytes(32).toString("hex") : process.env.LLM_API_KEY;
const upstreamBase = localTest ? process.env.KEEP_LOCAL_MODEL_BASE_URL : process.env.LLM_BASE_URL;
const model = localTest ? process.env.KEEP_LOCAL_MODEL : process.env.LLM_MODEL;
for (const [name, value] of Object.entries({ KEEP_TARBALL: tarball, KEEP_SOURCE_ROOT: sourceRoot, providerCredential: apiKey, providerBase: upstreamBase, providerModel: model })) if (!value) throw new Error(`${name} is required`);

let localProxyMode = "forward"; const localProxyObservations = [];
const localProxy = localTest ? createServer(async (request, response) => {
  if (request.headers.authorization !== `Bearer ${apiKey}`) { response.writeHead(401).end('{"error":"unauthorized"}'); return; }
  if (localProxyMode === "capacity") { response.writeHead(429, { "content-type": "application/json", "retry-after": "1" }).end('{"error":{"message":"tenant capacity exhausted"}}'); return; }
  const chunks = []; for await (const chunk of request) chunks.push(chunk); const body = Buffer.concat(chunks);
  localProxyObservations.push({ method: request.method, path: request.url, authorization: true, bodyBytes: body.byteLength });
  const upstream = await fetch(new URL(request.url ?? "/", upstreamBase), { method: request.method, headers: { "content-type": request.headers["content-type"] ?? "application/json" }, body });
  response.writeHead(upstream.status, Object.fromEntries(upstream.headers)); response.end(Buffer.from(await upstream.arrayBuffer()));
}) : undefined;
if (localProxy) await new Promise((resolve) => localProxy.listen(0, "127.0.0.1", resolve));
const localProxyAddress = localProxy?.address();
const configuredBase = localTest ? `http://127.0.0.1:${typeof localProxyAddress === "object" && localProxyAddress ? localProxyAddress.port : 0}` : upstreamBase;

const fixtureModule = await import(pathToFileURL(join(sourceRoot, "dist", "test", "support", "installed_release_fixture.js")).href);
const descriptorModule = await import(pathToFileURL(join(sourceRoot, "dist", "src", "gateway", "provider_descriptor.js")).href);
const root = mkdtempSync(join(tmpdir(), `keep-installed-enterprise-external-${testLocation}-`));
const consumer = join(root, "consumer"); mkdirSync(consumer);
writeFileSync(join(consumer, "package.json"), '{"name":"keep-enterprise-consumer","private":true}\n');
execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], { cwd: consumer, stdio: "pipe" });
const installedRoot = join(consumer, "node_modules", "keep");
const entry = join(installedRoot, "dist", "src", "main.js");
const base = new URL(configuredBase); base.pathname = base.pathname.replace(/\/v1\/?$/u, "");
const provider = { mode: "openai-compatible", baseUrl: base.toString().replace(/\/$/u, ""), model, apiKey };
const descriptorDigest = descriptorModule.remoteProviderIdentityDigest(provider);

const authorityRoot = join(root, "authority"); mkdirSync(authorityRoot, { mode: 0o700 });
const scannerRoot = join(authorityRoot, "scanner"); mkdirSync(join(scannerRoot, "tools"), { recursive: true }); mkdirSync(join(scannerRoot, "node_modules"), { recursive: true });
execFileSync("cp", ["-a", join(sourceRoot, "tools", "effect_sweep.mjs"), join(scannerRoot, "tools", "effect_sweep.mjs")]);
execFileSync("cp", ["-a", join(sourceRoot, "node_modules", "typescript"), join(scannerRoot, "node_modules", "typescript")]);
const scannerEnginePath = join(scannerRoot, "tools", "effect_sweep.mjs");
const release = fixtureModule.createSignedInstalledReleaseFixture(installedRoot, descriptorDigest, BigInt(Date.now()), scannerEnginePath);
const bundlePath = join(authorityRoot, "release.cbor"), trustPath = join(authorityRoot, "release-root.cbor");
writeFileSync(bundlePath, release.bundle, { mode: 0o600 }); writeFileSync(trustPath, release.trustRoot, { mode: 0o600 });

const issuer = "https://idp.enterprise.example", audience = "keep-enterprise-gateway";
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwksPath = join(root, "jwks.json"), rosterPath = join(root, "principals.json"), delegationPath = join(root, "delegation.json"), residencyPath = join(root, "residency.json");
const writeProtectedJson = (path, value) => { writeFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 }); chmodSync(path, 0o600); };
writeProtectedJson(jwksPath, { keys: [{ ...publicKey.export({ format: "jwk" }), kid: "enterprise-k1", alg: "RS256", use: "sig" }] });
writeProtectedJson(rosterPath, { schema: "keep.principal-roster/v1", tenantId: "alpha", principals: [{ subject: "alice-sub", role: "owner", id: "alice" }, { subject: "reviewer-sub", role: "reviewer", id: "reviewer" }] });
writeProtectedJson(delegationPath, { schema: "keep.delegation-policy/v1", tenantId: "alpha", parents: ["alice"] });
writeProtectedJson(residencyPath, { schema: "keep.residency-policy/v1", tenantId: "alpha", allowedPurposes: ["software-development"], allowedRegions: [testLocation], egressAllowlist: [base.hostname] });

execFileSync("mount", ["--bind", authorityRoot, authorityRoot]); execFileSync("mount", ["-o", "remount,bind,ro", authorityRoot]);
execFileSync("mount", ["--bind", installedRoot, installedRoot]); execFileSync("mount", ["-o", "remount,bind,ro", installedRoot]);

const profile = join(root, "provider.json"), dataDir = join(root, "data"); mkdirSync(dataDir, { mode: 0o700 });
const repository = join(root, "repository"), workspace = join(root, "workspaces"); mkdirSync(repository); mkdirSync(workspace);
execFileSync("git", ["init", "-q", "-b", "main"], { cwd: repository });
execFileSync("git", ["config", "user.name", "Keep Enterprise Fixture"], { cwd: repository }); execFileSync("git", ["config", "user.email", "enterprise@example.invalid"], { cwd: repository });
writeFileSync(join(repository, "calc.js"), "export function add(a, b) { return a - b; }\n");
writeFileSync(join(repository, "calc.test.js"), "import test from 'node:test'; import assert from 'node:assert/strict'; import { add } from './calc.js'; test('add returns the sum', () => assert.equal(add(2, 3), 5));\n");
execFileSync("git", ["add", "-A"], { cwd: repository }); execFileSync("git", ["commit", "-qm", "failing add implementation"], { cwd: repository });
const git = (...args) => execFileSync("git", args, { cwd: repository, encoding: "utf8" }).trim();
const initialRevision = git("rev-parse", "HEAD");
const initialTree = git("rev-parse", `${initialRevision}^{tree}`);
const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("KEEP_") && name !== "LLM_API_KEY"));
const runtimeEnv = { ...cleanEnv, KEEP_PROFILE: profile, KEEP_PROVIDER_API_KEY: apiKey, KEEP_DATA_DIR: dataDir, KEEP_REPOSITORY: repository, KEEP_WORKSPACE_BASE: workspace, KEEP_REVISION: initialRevision, KEEP_REPO_REF: "enterprise-project", KEEP_TEST_COMMAND: process.execPath, KEEP_TEST_ARGS_JSON: '["--test","calc.test.js"]', KEEP_PROJECT_POSTURE: "approval-required" };
const configureProfile = (profilePath, purpose, region, providers) => execFileSync(process.execPath, [entry, "provider", "configure", `--profile=${profilePath}`, `--name=stage-enterprise-${testLocation}`, `--location=${testLocation}`, "--authority=organization", "--protocol=openai-compatible", `--endpoint=${provider.baseUrl}`, `--model=${model}`, `--purpose=${purpose}`, `--region=${region}`, "--credential=environment", ...(providers ? [`--providers=${providers}`] : []), "--tenant=alpha", `--issuer=${issuer}`, `--audience=${audience}`, `--jwks=${jwksPath}`, `--principal-roster=${rosterPath}`, `--delegation-policy=${delegationPath}`, `--residency-policy=${residencyPath}`, `--scanner-engine=${scannerEnginePath}`, "--audit-scope=tenant", `--release-bundle=${bundlePath}`, `--release-trust-root=${trustPath}`], { cwd: consumer, env: runtimeEnv, encoding: "utf8" });
const configure = configureProfile(profile, "software-development", testLocation, localTest ? undefined : "Azure");
assert.match(configure, /no credential value was stored/u);
assert.doesNotMatch(`${configure}${readFileSync(profile, "utf8")}`, new RegExp(apiKey.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")));

const freePort = await new Promise((resolve) => { const probe = createServer(); probe.listen(0, "127.0.0.1", () => { const address = probe.address(); const port = typeof address === "object" && address ? address.port : 0; probe.close(() => resolve(port)); }); });
const gatewayArgs = [entry, "serve", "--gateway", `--port=${freePort}`];
const startGateway = () => { const child = spawn(process.execPath, gatewayArgs, { cwd: consumer, env: runtimeEnv, stdio: ["ignore", "pipe", "pipe"] }); child.keepStderr = ""; child.stderr.setEncoding("utf8"); child.stderr.on("data", (chunk) => { child.keepStderr = `${child.keepStderr}${String(chunk)}`.slice(-16_384); }); return child; };
const waitFor = async (predicate, label, child) => { for (let attempt = 0; attempt < 200; attempt++) { if (child?.exitCode !== null) throw new Error(`${label} process exited ${child.exitCode}: ${child.keepStderr}`); if (await predicate()) return; await new Promise((resolve) => setTimeout(resolve, 50)); } throw new Error(`timed out waiting for ${label}: ${child?.keepStderr ?? ""}`); };
const stopGateway = async (child) => { child.kill("SIGTERM"); await new Promise((resolve) => { const timer = setTimeout(() => { child.kill("SIGKILL"); resolve(); }, 5_000); child.once("close", () => { clearTimeout(timer); resolve(); }); }); };
const tokenPath = join(dataDir, "gateway-token");
let gateway = startGateway();
await waitFor(async () => existsSync(tokenPath) && await fetch(`http://127.0.0.1:${freePort}/health`).then((response) => response.ok).catch(() => false), "admitted enterprise gateway", gateway);
const gatewayToken = readFileSync(tokenPath, "utf8").trim();
assert.match(gatewayToken, /^[0-9a-f]{48}$/u);

const assertion = (subject) => {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "enterprise-k1", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ sub: subject, iss: issuer, aud: audience, exp: Math.floor(Date.now() / 1_000) + 60 })).toString("base64url");
  const signature = createSign("RSA-SHA256").update(`${header}.${payload}`).end().sign(privateKey).toString("base64url");
  return `${header}.${payload}.${signature}`;
};
const call = async (method, path, session, body) => { const response = await fetch(`http://127.0.0.1:${freePort}${path}`, { method, headers: { authorization: `Bearer ${gatewayToken}`, ...(session ? { "x-keep-session": session } : {}), "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }); return { status: response.status, body: await response.text() }; };
const authenticate = async (subject) => { const response = await call("POST", "/auth/session", undefined, { assertion: assertion(subject) }); assert.equal(response.status, 200, response.body); return JSON.parse(response.body).session; };
const alice = await authenticate("alice-sub");
assert.equal((await call("POST", "/auth/session", undefined, { assertion: assertion("foreign-tenant-sub") })).status, 403, "an unrostered foreign tenant identity is refused before project discovery");
const delegated = await call("POST", "/delegation/issue", alice, { agentId: "build-agent", grantId: "stage4-agent", expiresAt: Date.now() + 60_000, permissions: ["change.solve", "review.approve"] });
assert.equal(delegated.status, 200, delegated.body); assert.equal(JSON.parse(delegated.body).agentId, "build-agent");
assert.equal((await call("GET", "/audit/export", JSON.parse(delegated.body).session)).status, 403, "delegated agent cannot export organization evidence");

await stopGateway(gateway);
gateway = startGateway();
await waitFor(async () => await fetch(`http://127.0.0.1:${freePort}/health`).then((response) => response.ok).catch(() => false), "restarted enterprise gateway", gateway);
assert.equal(readFileSync(tokenPath, "utf8").trim(), gatewayToken, "gateway pairing token survives restart");
assert.equal((await call("GET", "/audit", alice)).status, 403, "server-side identity sessions do not survive restart without reauthentication");
const reauthenticated = await authenticate("alice-sub");
assert.equal((await call("GET", "/audit/export", reauthenticated)).status, 200);
const reviewer = await authenticate("reviewer-sub");
const workingAgentResponse = await call("POST", "/delegation/issue", reauthenticated, { agentId: "working-agent", grantId: "stage4-working-agent", expiresAt: Date.now() + 10 * 60_000, permissions: ["change.solve", "review.approve"] });
assert.equal(workingAgentResponse.status, 200, workingAgentResponse.body);
const workingAgent = JSON.parse(workingAgentResponse.body).session;
const proposed = await call("POST", "/project", workingAgent, { goal: "The add function fails its declared test. Diagnose and fix the implementation without changing the test.", posture: "approval-required" });
assert.equal(proposed.status, 200, proposed.body);
const proposal = JSON.parse(proposed.body); assert.equal(proposal.status, "completed", proposed.body); assert.equal(proposal.proposal, true); assert.match(proposal.proposalDigest, /^[0-9a-f]{64}$/u);
assert.equal(git("rev-parse", "HEAD"), initialRevision); assert.match(readFileSync(join(repository, "calc.js"), "utf8"), /a - b/u);
assert.equal((await call("POST", "/project/merge", workingAgent, { runId: proposal.runId, decision: "approve", proposalDigest: proposal.proposalDigest })).status, 403, "the delegated solver cannot approve its own proposal");
assert.equal((await call("POST", "/delegation/revoke", reauthenticated, { grantId: "stage4-working-agent" })).status, 200);
assert.equal((await call("POST", "/project", workingAgent, { goal: "revoked agent must not start another project" })).status, 403, "delegation revocation is immediate");

await stopGateway(gateway); gateway = startGateway();
await waitFor(async () => await fetch(`http://127.0.0.1:${freePort}/health`).then((response) => response.ok).catch(() => false), "project-state restart", gateway);
assert.equal(readFileSync(tokenPath, "utf8").trim(), gatewayToken);
const reviewerAfterRestart = await authenticate("reviewer-sub");
const persisted = await call("GET", `/project?runId=${encodeURIComponent(proposal.runId)}`, reviewerAfterRestart);
assert.equal(persisted.status, 200, persisted.body);
const merged = await call("POST", "/project/merge", reviewerAfterRestart, { runId: proposal.runId, decision: "approve", proposalDigest: proposal.proposalDigest });
assert.equal(merged.status, 200, merged.body); assert.notEqual(git("rev-parse", "HEAD"), initialRevision); assert.match(readFileSync(join(repository, "calc.js"), "utf8"), /a \+ b/u);
execFileSync(process.execPath, ["--test", "calc.test.js"], { cwd: repository, stdio: "pipe" });
const reverted = await call("POST", "/project/revert", reviewerAfterRestart, { runId: proposal.runId });
assert.equal(reverted.status, 200, reverted.body); assert.equal(git("rev-parse", "HEAD^{tree}"), initialTree); assert.match(readFileSync(join(repository, "calc.js"), "utf8"), /a - b/u);

await stopGateway(gateway); runtimeEnv.KEEP_REVISION = git("rev-parse", "HEAD"); runtimeEnv.KEEP_REPO_REF = "enterprise-veto"; gateway = startGateway();
await waitFor(async () => await fetch(`http://127.0.0.1:${freePort}/health`).then((response) => response.ok).catch(() => false), "independent veto workspace restart", gateway);
const adminAfterRestart = await authenticate("alice-sub"), vetoReviewer = await authenticate("reviewer-sub");
const vetoAgentResponse = await call("POST", "/delegation/issue", adminAfterRestart, { agentId: "veto-agent", grantId: "stage4-veto-agent", expiresAt: Date.now() + 10 * 60_000, permissions: ["change.solve"] });
assert.equal(vetoAgentResponse.status, 200, vetoAgentResponse.body);
const vetoProposalResponse = await call("POST", "/project", JSON.parse(vetoAgentResponse.body).session, { goal: "The add function fails its declared test. Diagnose and fix the implementation without changing the test.", posture: "approval-required" });
assert.equal(vetoProposalResponse.status, 200, vetoProposalResponse.body); const vetoProposal = JSON.parse(vetoProposalResponse.body); assert.equal(vetoProposal.proposal, true, vetoProposalResponse.body); assert.match(vetoProposal.proposalDigest, /^[0-9a-f]{64}$/u);
const vetoed = await call("POST", "/project/merge", vetoReviewer, { runId: vetoProposal.runId, decision: "veto", proposalDigest: vetoProposal.proposalDigest });
assert.equal(vetoed.status, 200, vetoed.body);
const lateApproval = await call("POST", "/project/merge", vetoReviewer, { runId: vetoProposal.runId, decision: "approve", proposalDigest: vetoProposal.proposalDigest });
assert.equal(lateApproval.status, 200, lateApproval.body); assert.match(lateApproval.body, /veto is durable/u); assert.equal(git("rev-parse", "HEAD^{tree}"), initialTree);
const audit = await call("GET", "/audit/export", adminAfterRestart); assert.equal(audit.status, 200, audit.body); assert.equal(JSON.parse(audit.body).rows.every((row) => row.payload.tenant === "alpha"), true);
await stopGateway(gateway);

for (const denied of [
  { label: "purpose", purpose: "marketing", region: testLocation, providers: localTest ? undefined : "Azure" },
  { label: "region", purpose: "software-development", region: "unapproved-region", providers: localTest ? undefined : "Azure" },
  ...(localTest ? [] : [{ label: "route", purpose: "software-development", region: "external", providers: "OpenAI" }]),
]) {
  const deniedProfile = join(root, `provider-denied-${denied.label}.json`);
  configureProfile(deniedProfile, denied.purpose, denied.region, denied.providers);
  runtimeEnv.KEEP_PROFILE = deniedProfile; runtimeEnv.KEEP_REPO_REF = `enterprise-denied-${denied.label}`;
  gateway = startGateway();
  await waitFor(async () => await fetch(`http://127.0.0.1:${freePort}/health`).then((response) => response.ok).catch(() => false), `${denied.label} refusal gateway`, gateway);
  const deniedAdmin = await authenticate("alice-sub");
  const deniedAgentResponse = await call("POST", "/delegation/issue", deniedAdmin, { agentId: `${denied.label}-agent`, grantId: `stage4-${denied.label}-agent`, expiresAt: Date.now() + 60_000, permissions: ["change.solve"] });
  assert.equal(deniedAgentResponse.status, 200, deniedAgentResponse.body);
  const deniedProject = await call("POST", "/project", JSON.parse(deniedAgentResponse.body).session, { goal: "Fix the failing add implementation without changing its test.", posture: "approval-required" });
  assert.equal(deniedProject.status, 200, `${denied.label} policy must return a durable held run: ${deniedProject.body}`);
  const deniedOutcome = JSON.parse(deniedProject.body);
  assert.equal(deniedOutcome.status, "waiting-retry", deniedProject.body); assert.equal(deniedOutcome.proposal, false, deniedProject.body);
  assert.match(deniedOutcome.note, denied.label === "purpose" ? /purpose .* not in allowed remote-purpose set/u : denied.label === "region" ? /region .* not in allowed residency set/u : /(?:provider route .* outside the admitted allowlist|No endpoints found matching your data policy)/u);
  assert.equal(git("rev-parse", "HEAD^{tree}"), initialTree, `${denied.label} refusal must not mutate source`);
  await stopGateway(gateway);
}

if (localProxy) {
  localProxyMode = "capacity"; const capacityProfile = join(root, "provider-denied-capacity.json"); configureProfile(capacityProfile, "software-development", "local", undefined);
  runtimeEnv.KEEP_PROFILE = capacityProfile; runtimeEnv.KEEP_REPO_REF = "enterprise-denied-capacity"; gateway = startGateway();
  await waitFor(async () => await fetch(`http://127.0.0.1:${freePort}/health`).then((response) => response.ok).catch(() => false), "capacity refusal gateway", gateway);
  const capacityAdmin = await authenticate("alice-sub"); const capacityAgent = await call("POST", "/delegation/issue", capacityAdmin, { agentId: "capacity-agent", grantId: "stage5-capacity-agent", expiresAt: Date.now() + 60_000, permissions: ["change.solve"] });
  const capacityRun = await call("POST", "/project", JSON.parse(capacityAgent.body).session, { goal: "Fix the failing add implementation without changing its test.", posture: "approval-required" });
  assert.equal(capacityRun.status, 200, capacityRun.body); assert.equal(JSON.parse(capacityRun.body).status, "waiting-retry", capacityRun.body); assert.match(JSON.parse(capacityRun.body).note, /429|capacity exhausted/u); assert.equal(git("rev-parse", "HEAD^{tree}"), initialTree);
  await stopGateway(gateway); await new Promise((resolve) => localProxy.close(resolve));
  runtimeEnv.KEEP_REPO_REF = "enterprise-denied-unavailable"; gateway = startGateway();
  await waitFor(async () => await fetch(`http://127.0.0.1:${freePort}/health`).then((response) => response.ok).catch(() => false), "unavailable local service gateway", gateway);
  const unavailableAdmin = await authenticate("alice-sub"); const unavailableAgent = await call("POST", "/delegation/issue", unavailableAdmin, { agentId: "unavailable-agent", grantId: "stage5-unavailable-agent", expiresAt: Date.now() + 60_000, permissions: ["change.solve"] });
  const unavailableRun = await call("POST", "/project", JSON.parse(unavailableAgent.body).session, { goal: "Fix the failing add implementation without changing its test.", posture: "approval-required" });
  assert.equal(unavailableRun.status, 200, unavailableRun.body); assert.equal(JSON.parse(unavailableRun.body).status, "waiting-retry", unavailableRun.body); assert.match(JSON.parse(unavailableRun.body).note, /ECONNREFUSED|fetch failed|connection refused/u); assert.equal(git("rev-parse", "HEAD^{tree}"), initialTree);
  await stopGateway(gateway);
  assert.equal(localProxyObservations.length > 0, true, "the authenticated local proxy observed real inference"); assert.equal(localProxyObservations.every((row) => row.authorization === true), true);
}

assert.equal(readFileSync(profile, "utf8").includes(apiKey), false);
for (const path of [bundlePath, trustPath, jwksPath, rosterPath, delegationPath, residencyPath]) assert.equal(path.startsWith(installedRoot), false);
process.stdout.write(`installed enterprise/${testLocation} gateway walking skeleton passed at ${root}\n`);
