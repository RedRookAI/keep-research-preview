import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import { decompositionResultReplayFixture } from "./decomposition_result_replay_fixture.mjs";

const installedRoot = process.env.KEEP_INSTALLED_PACKAGE_ROOT;
if (!installedRoot) throw new Error("KEEP_INSTALLED_PACKAGE_ROOT is required");
const keep = await import(pathToFileURL(join(installedRoot, "dist", "src", "index.js")).href);

function roots(base, tenantId) {
  const root = join(base, tenantId);
  const dataRoot = join(root, "data"), repositoryRoot = join(root, "repository"), workspaceRoot = join(root, "workspace"), witnessRoot = join(root, "witness");
  for (const path of [dataRoot, repositoryRoot, workspaceRoot, witnessRoot]) mkdirSync(path, { recursive: true });
  return { tenantId, dataRoot, repositoryRoot, workspaceRoot, witnessRoot };
}

function enterpriseGoalLifecycleFixture(roleId="maintainer"){
  const h=c=>c.repeat(64),d=h("d"),now="2026-09-03T00:00:00Z",body={schema_version:1,goal_id:"installed-enterprise-lifecycle",outcome:"authorize architecture without execution",authority:{kind:"organization",organization_id:"org",actor_id:"alice",role_id:roleId,separation_policy_id:"sod"},scope_ids:["S1"],track_obligations:{n1:["local"],enterprise:["organization"],parity:["same-integrity"],equivalent:false},assumptions:["clock injected"],finish_conditions:["architecture authority"],non_goals:[{statement:"no execution",retained_by:["PG-04"]}],research_contract:{current:["current"],historical:["historical"],cross_disciplinary:["assurance"]},adverse_evidence_questions:["what fails"],falsifiers:["scope loss"],dependency_closures:[{id:"PG-03-T003",digest:d}],created_by:"alice",created_at:now,executable:false},goal_digest=keep.goalDigest(body);
  const stable=v=>Array.isArray(v)?v.map(stable):v!==null&&typeof v==="object"?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v,digest=v=>createHash("sha256").update(JSON.stringify(stable(v))).digest("hex");
  const protocol={schema_version:1,goal_digest,predecessor_digest:d,questions:{current:"frontier?",historical:"failure?",cross_disciplinary:"transfer?"},inclusion_rules:["primary"],exclusion_rules:["generic"],freshness_policies:{mutable_current_months:3,versioned_standard:"IDENTITY",immutable_local:"IDENTITY"},expected_adverse_evidence:["failure"],falsifiers:["simpler"],required_consequence_classes:["goal_question","scope","architecture","requirement","threat","test_oracle"]},rows=[["c","current","mutable-current","SUPPORTS"],["h","historical","immutable-local","MIXED"],["x","cross-disciplinary","versioned-standard","ADVERSE"]].map(([id,lane,source_class,evidence_stance])=>({row_id:id,lane,locator:`https://enterprise-lifecycle.example/${id}`,query:`q-${id}`,candidate:`c-${id}`,observation:`o-${id}`,observed_at:"2026-06-03T00:00:00Z",observed_identity:`i-${id}`,source_class,disposition:"SELECTED",disposition_reason:"selected",uncertainty:"bounded",evidence_stance})),record={schema_version:1,goal_digest,predecessor_digest:d,protocol_digest:keep.researchProtocolDigest(protocol),rows,adverse_evidence:["adverse"],falsifiers:["falsifier"],consequences:protocol.required_consequence_classes.map((className,i)=>({consequence_id:`k${i}`,class:className,statement:`${className} consequence`,mechanism:"admission",source_row_ids:[rows[i%3].row_id]})),executable:false};
  const descendants={protocol:{digest:h("1"),depends_on:["goal"],status:"ACTIVE"},research:{digest:h("2"),depends_on:["protocol"],status:"ACTIVE"},semantic_admission:{digest:h("3"),depends_on:["research"],status:"ACTIVE"},architecture:{digest:h("4"),depends_on:["semantic_admission"],status:"ACTIVE"},decomposition:{digest:h("5"),depends_on:["architecture"],status:"ACTIVE"},owner_approval:{digest:h("6"),depends_on:["decomposition"],status:"ACTIVE"},tickets:{digest:h("7"),depends_on:["owner_approval"],status:"ACTIVE"}},protocolDigest=keep.researchProtocolDigest(protocol),researchDigest=digest(record),initial={schema_version:1,phase:"GOAL_PROPOSED",active_head_digest:goal_digest,ancestor_digests:{goal:goal_digest,protocol:protocolDigest,research:researchDigest},descendants,downstream_vets_consumed:0};let state=structuredClone(initial);const transitions=[];
  for(let i=1;i<keep.GOAL_TRANSITION_PHASES.length;i++){const to=keep.GOAL_TRANSITION_PHASES[i],p={schema_version:1,from_phase:state.phase,to_phase:to,expected_active_head_digest:state.active_head_digest,next_head_digest:h("0"),required_ancestor_digests:{...state.ancestor_digests},consequence_graph:{questions:["q"],scope_ids:["scope"],sources:["source"],mechanisms:["mechanism"],consequences:["consequence"],edges:[{from:"q",to:"mechanism"},{from:"scope",to:"mechanism"},{from:"source",to:"mechanism"},{from:"source",to:"consequence"},{from:"mechanism",to:"consequence"}],owner_stops:[]},semantic_admission:null,trusted_reviewer_ids:["reviewer"],expected_ticket_digest:h("a"),expected_policy_digest:h("b"),expected_evidence_digest:h("c"),authority_verdict:"PASS",supersedes:null,authority_context:{kind:"enterprise",organization_id:"org",actor_id:"alice",role_id:roleId,separation_policy_id:"sod",local_owner_substitution:false},downstream_vet:null};if(to==="RESEARCH_SEMANTIC_PASS")p.semantic_admission={schema_version:1,ticket_digest:h("a"),round:1,research_digest:p.required_ancestor_digests.research,author_family:"OpenAI",reviewer_family:"Anthropic",reviewer_id:"reviewer",policy_digest:h("b"),evidence_digest:h("c"),reviewed_at:now,verdict:"PASS"};p.next_head_digest=to==="GOAL_ADMITTED"?goal_digest:to==="RESEARCH_PROTOCOL_FROZEN"?protocolDigest:to==="RESEARCH_CANDIDATE"||to==="RESEARCH_STRUCTURAL_PASS"?researchDigest:to==="RESEARCH_SEMANTIC_PASS"?digest(p.semantic_admission):digest({goal_digest,protocol_digest:protocolDigest,research_digest:researchDigest,semantic_digest:transitions.at(-1).next_head_digest,consequence_graph:p.consequence_graph});transitions.push(p);state=keep.evaluateGoalTransition(state,p).state}
  return {schema_version:1,goal_candidate:{body,goal_digest},authority_context:{kind:"enterprise",goal_digest,decision_id:"decision",decided_at:now,principal_id:"alice",authority_domain:"organization",verification_result:"PASS",organization_id:"org",role_id:roleId,separation_policy_id:"sod",evidence_digest:h("e")},scope_authority:{known_scope_ids:["S1"],required_scope_ids:["S1"],required_track_obligations:{n1:["local"],enterprise:["organization"],parity:["same-integrity"]},dependency_closures:{"PG-03-T003":d}},research_protocol:protocol,research_record:record,observed_at:now,current_source_identities:Object.fromEntries(rows.map(r=>[r.locator,r.observed_identity])),transition_state:initial,transitions,executable:false};
}

if(process.env.KEEP_ENTERPRISE_T002_COMPLETE_ROOT){const request=t002EnterpriseRequest("fresh",process.env.KEEP_ENTERPRISE_T002_COMPLETE_ROOT);writeFileSync(join(process.env.KEEP_ENTERPRISE_T002_COMPLETE_ROOT,"request.json"),JSON.stringify(request),{mode:0o600});const result=await keep.runEnterpriseEventAuthorityJourneyV1(request);if(!result.ok)throw new Error(result.code);writeFileSync(join(process.env.KEEP_ENTERPRISE_T002_COMPLETE_ROOT,"receipt.json"),JSON.stringify(result.receipt),{mode:0o600});process.exit(0);}
if(process.env.KEEP_ENTERPRISE_T002_CRASH_ROOT){const request=t002EnterpriseRequest("crash",process.env.KEEP_ENTERPRISE_T002_CRASH_ROOT);writeFileSync(join(process.env.KEEP_ENTERPRISE_T002_CRASH_ROOT,"request.json"),JSON.stringify(request),{mode:0o600});const internal=await import(pathToFileURL(join(installedRoot,"dist","src","spine","enterprise_event_authority_integration_v1.js")).href);await internal.runEnterpriseEventAuthorityCrashAfterDurableAppendTestOnlyV1(request,"approval",2);throw new Error("crash adapter returned");}

test("installed enterprise: real socket credentials preserve tenant authority, residency, audit scope, restart and revocation", async () => {
  const base = mkdtempSync(join(tmpdir(), "keep-installed-enterprise-"));
  const alphaRoots = roots(base, "alpha"), betaRoots = roots(base, "beta");
  const baselinePath = join(alphaRoots.dataRoot, "solo-baseline.json");
  const current = { startupMs: 10, p95LatencyMs: 5 };
  const observation = keep.captureCanonicalSoloObservation(current, keep.captureInstalledPackageSubjectDigest(installedRoot));
  new keep.FileSoloReleaseBaselineStore(baselinePath).pin(keep.captureSoloReleaseBaseline(observation, { startupMs: 20, p95LatencyMs: 10 }));
  const alpha = { id: "alice", kind: "human", role: "maintainer", tenant: "alpha" };
  const config = {
    dataDir: alphaRoots.dataRoot,
    runtimePaths: { repository: alphaRoots.repositoryRoot, workspace: alphaRoots.workspaceRoot },
    workspace: new keep.LocalFsWorkspace(alphaRoots.workspaceRoot),
    solve: async (issue) => ({ solveResult: { issueId: issue.id, solved: true, stagesRun: [], repairRounds: 0, validation: { testsPassed: true, detail: "enterprise fixture" } } }),
    projectPosture: "approval-required",
    delegationParentFor: (id, tenant) => id === alpha.id && tenant === alpha.tenant ? alpha : undefined,
    tenantDeployment: { tenantId: "alpha", peers: [betaRoots], soloNonRegression: { baselinePath, current } },
    residency: { allowedRegions: ["eu"], allowedPurposes: ["software-development"], egressAllowlist: ["models.eu.example"] },
  };

  const issuer = "https://idp.enterprise.example";
  const audience = "keep-enterprise-gateway";
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "enterprise-k1", alg: "RS256", use: "sig" };
  const provider = new keep.OidcJwksProvider({ jwks: { keys: [jwk] }, issuer, audience });
  const registry = new keep.PrincipalRegistry([
    { subject: "alice-sub", role: "maintainer", id: "alice", tenant: "alpha" },
    { subject: "bob-sub", role: "maintainer", id: "bob", tenant: "beta" },
    { subject: "eve-sub", role: "viewer", id: "eve", tenant: "alpha" },
  ]);
  const sessions = new keep.SessionStore();
  const signAssertion = (subject) => {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "enterprise-k1", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ sub: subject, iss: issuer, aud: audience, exp: Math.floor(Date.now() / 1000) + 60 })).toString("base64url");
    const signature = createSign("RSA-SHA256").update(`${header}.${payload}`).end().sign(privateKey).toString("base64url");
    return `${header}.${payload}.${signature}`;
  };
  const authenticate = async (subject) => {
    const assertion = signAssertion(subject);
    const identity = await provider.verify(assertion, Date.now());
    assert.notEqual(identity, null, "the deployment IdP assertion must verify before a session is issued");
    const principal = registry.resolve(identity);
    assert.notEqual(principal, null, "the verified identity must have an explicit deny-by-default principal mapping");
    return sessions.create(principal, Date.now()).id;
  };
  const alphaSession = await authenticate("alice-sub");
  const betaSession = await authenticate("bob-sub");
  const viewerSession = await authenticate("eve-sub");

  let app = keep.composeKeep(config);
  const delegated = await app.authorization.issue(alpha, "build-agent", ["change.solve", "review.approve"], Date.now() + 60_000, Date.now(), "installed-enterprise-grant");
  const delegatedSession = sessions.create(delegated, Date.now()).id;
  const gatewayToken = "installed-enterprise-gateway";
  const principalFor = (req) => sessions.get(req.headers["x-keep-session"], Date.now())?.principal;
  let server = await keep.startGatewayServer(app, { port: 0, token: gatewayToken, principalFor });
  const request = async (session, method, path, body) => {
    const response = await fetch(new URL(path, server.origin), { method, headers: { authorization: `Bearer ${gatewayToken}`, "x-keep-session": session, "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.text() };
  };

  try {
    const started = await request(alphaSession, "POST", "/project", { goal: "email the enterprise tenant report", stepBudget: 20 });
    assert.equal(started.status, 200, started.body);
    const held = JSON.parse(started.body);
    const runId = held.runId;
    assert.equal(held.status, "waiting-approval");
    assert.equal((await request(delegatedSession, "POST", "/project/resume", { runId, approval: { decisionId: held.wait.decisionId, approved: true } })).status, 403, "a delegated solver cannot approve its own held work");
    assert.equal((await request(alphaSession, "POST", "/project/resume", { runId, approval: { decisionId: held.wait.decisionId, approved: true } })).status, 200, "an independently authenticated human can approve held work");
    assert.equal((await request(betaSession, "GET", `/project?runId=${encodeURIComponent(runId)}`)).status, 404, "foreign tenant cannot discover the project over the socket");
    assert.equal((await request(viewerSession, "GET", "/audit/export")).status, 403, "viewer cannot bulk-export tenant evidence");
    app.spine.stage({ type: "identity.action", actor: "alpha", payload: { event: "enterprise.fixture", tenant: "alpha" } });
    app.spine.stage({ type: "identity.action", actor: "beta", payload: { event: "enterprise.fixture", tenant: "beta" } });
    const exported = JSON.parse((await request(alphaSession, "GET", "/audit/export")).body);
    assert.equal(exported.rows.every((row) => row.payload.tenant === "alpha"), true);
    assert.equal(app.governanceSuite.residency.checkRemoteRequest("software-development", "eu", "models.eu.example").allowed, true);
    assert.equal(app.governanceSuite.residency.checkRemoteRequest("software-development", "us", "models.eu.example").allowed, false);
    assert.equal(app.governanceSuite.residency.checkRemoteRequest("marketing", "eu", "models.eu.example").allowed, false);
    assert.equal(await app.authorization.revoke(delegated.grantId), true);
    assert.equal((await request(delegatedSession, "POST", "/project", { goal: "revoked agent must not start work", stepBudget: 1 })).status, 403);
    sessions.revoke(viewerSession);
    assert.equal((await request(viewerSession, "GET", "/audit")).status, 403, "revoked user session is refused immediately");

    const admissionDigest = app.tenantDeployment.rootAdmission.rosterDigest;
    await server.close();
    app = keep.composeKeep(config);
    server = await keep.startGatewayServer(app, { port: 0, token: gatewayToken, principalFor });
    assert.equal(app.authorization.restorePrincipal(delegated.grantId), undefined, "delegation revocation survives restart");
    assert.equal(app.tenantDeployment.rootAdmission.rosterDigest, admissionDigest);
    assert.equal(app.spine.currentEvents().filter((event) => event.actor === "tenant-deployment" && event.payload.event === "tenant_deployment.admitted").length, 1);
    assert.equal((await request(betaSession, "GET", `/project?runId=${encodeURIComponent(runId)}`)).status, 404);
    assert.equal((await request(delegatedSession, "POST", "/project", { goal: "revoked grant remains refused after restart", stepBudget: 1 })).status, 403);
  } finally {
    await server.close();
  }
});

test("installed enterprise: attributed organization authority admits while local-owner substitution is refused", () => {
  const dependencyDigest = "d".repeat(64), evidenceDigest = "e".repeat(64);
  const body = { schema_version:1, goal_id:"installed-enterprise-goal", outcome:"Keep admits the complete organization goal", authority:{kind:"organization",organization_id:"org-1",actor_id:"alice",role_id:"maintainer",separation_policy_id:"sod-1"}, scope_ids:["ES-S002","ES-S004"], track_obligations:{n1:["local-owner remains first-class"],enterprise:["attributed organization role"],parity:["identical integrity"],equivalent:false}, assumptions:["trusted identity adapter"], finish_conditions:["authority is immutable and non-executable"], non_goals:[{statement:"no ticket authority",retained_by:["PG-04"]}], research_contract:{current:["current primary evidence"],historical:["historical Keep evidence"],cross_disciplinary:["assurance transfer"]}, adverse_evidence_questions:["what would falsify admission"], falsifiers:["authority substitution"], dependency_closures:[{id:"PG-02",digest:dependencyDigest}], created_by:"alice", created_at:"2026-09-03T00:00:00Z", executable:false };
  const digest = keep.goalDigest(body);
  const scope = {known_scope_ids:["ES-S002","ES-S004"],required_scope_ids:["ES-S002","ES-S004"],required_track_obligations:{n1:["local-owner remains first-class"],enterprise:["attributed organization role"],parity:["identical integrity"]},dependency_closures:{"PG-02":dependencyDigest}};
  const enterprise = {kind:"enterprise",goal_digest:digest,decision_id:"installed-enterprise-decision",decided_at:"2026-09-03T00:00:01Z",principal_id:"alice",authority_domain:"organization",verification_result:"PASS",organization_id:"org-1",role_id:"maintainer",separation_policy_id:"sod-1",evidence_digest:evidenceDigest};
  const admitted = keep.admitGoal(null,{body,goal_digest:digest},enterprise,scope);
  assert.equal(admitted.admitted,true);
  const localSubstitution = {kind:"n1",goal_digest:digest,decision_id:"forged-local",decided_at:"2026-09-03T00:00:01Z",principal_id:"alice",authority_domain:"local-owner",verification_result:"PASS",custody_id:"local"};
  const refused = keep.admitGoal(null,{body,goal_digest:digest},localSubstitution,scope);
  assert.deepEqual(refused,{admitted:false,denial:"ENTERPRISE_AUTHORITY_REQUIRED"});
});

test("installed enterprise: attributed organization research uses identical rigor and refuses support-only evidence",()=>{
  const goal={status:"GOAL_ADMITTED",goal_digest:"b".repeat(64),body:{authority:{kind:"organization",organization_id:"org-1"}},authority_context:{kind:"enterprise",authority_domain:"organization",organization_id:"org-1",role_id:"maintainer"},executable:false};
  const protocol={schema_version:1,goal_digest:goal.goal_digest,predecessor_digest:"d".repeat(64),questions:{current:"current?",historical:"history?",cross_disciplinary:"transfer?"},inclusion_rules:["primary"],exclusion_rules:["generic"],freshness_policies:{mutable_current_months:3,versioned_standard:"IDENTITY",immutable_local:"IDENTITY"},expected_adverse_evidence:["failure"],falsifiers:["simpler equal design"],required_consequence_classes:["goal_question","scope","architecture","requirement","threat","test_oracle"]};
  const rows=[["c","current"],["h","historical"],["x","cross-disciplinary"]].map(([id,lane])=>({row_id:id,lane,locator:`https://enterprise.test/${id}`,query:`q-${id}`,candidate:`c-${id}`,observation:`o-${id}`,observed_at:"2026-06-03T00:00:00Z",observed_identity:`i-${id}`,source_class:id==="c"?"mutable-current":"immutable-local",disposition:"SELECTED",disposition_reason:`r-${id}`,uncertainty:`u-${id}`,evidence_stance:"SUPPORTS"}));
  const record={schema_version:1,goal_digest:goal.goal_digest,predecessor_digest:protocol.predecessor_digest,protocol_digest:keep.researchProtocolDigest(protocol),rows,adverse_evidence:["claimed but unsupported"],falsifiers:["falsifier"],consequences:protocol.required_consequence_classes.map((kind,i)=>({consequence_id:`k${i}`,class:kind,statement:`${kind} consequence`,mechanism:"ledger",source_row_ids:[rows[i%3].row_id]})),executable:false};
  const result=keep.admitGoalResearch(goal,protocol,record,"2026-09-03T00:00:00Z",Object.fromEntries(rows.map(r=>[r.locator,r.observed_identity])));
  assert.deepEqual(result,{admitted:false,denial:"ADVERSE_EVIDENCE_MISSING"});
  const localGoal={...goal,goal_digest:"a".repeat(64),body:{authority:{kind:"owner"}},authority_context:{kind:"n1",authority_domain:"local-owner"}};
  const substituted=keep.admitGoalResearch(localGoal,protocol,{...record,goal_digest:localGoal.goal_digest},"2026-09-03T00:00:00Z",Object.fromEntries(rows.map(r=>[r.locator,r.observed_identity])));
  assert.deepEqual(substituted,{admitted:false,denial:"RESEARCH_PROTOCOL_MISSING"},"local-owner authority cannot substitute for protocol-bound organization authority");
});

test("installed enterprise: organization transition is first-class and refuses local-owner substitution",()=>{
  const h=(c)=>c.repeat(64),descendants={protocol:{digest:h("1"),depends_on:["goal"],status:"ACTIVE"},research:{digest:h("2"),depends_on:["protocol"],status:"ACTIVE"},semantic_admission:{digest:h("3"),depends_on:["research"],status:"ACTIVE"},architecture:{digest:h("4"),depends_on:["semantic_admission"],status:"ACTIVE"},decomposition:{digest:h("5"),depends_on:["architecture"],status:"ACTIVE"},owner_approval:{digest:h("6"),depends_on:["decomposition"],status:"ACTIVE"},tickets:{digest:h("7"),depends_on:["owner_approval"],status:"ACTIVE"}};
  const state={schema_version:1,phase:"GOAL_PROPOSED",active_head_digest:h("8"),ancestor_digests:{goal:h("9"),protocol:h("1"),research:h("2")},descendants,downstream_vets_consumed:0};
  const consequence_graph={questions:["q"],scope_ids:["scope"],sources:["source"],mechanisms:["mechanism"],consequences:["consequence"],edges:[{from:"q",to:"mechanism"},{from:"scope",to:"mechanism"},{from:"source",to:"mechanism"},{from:"source",to:"consequence"},{from:"mechanism",to:"consequence"}],owner_stops:[]};
  const proposal={schema_version:1,from_phase:"GOAL_PROPOSED",to_phase:"GOAL_ADMITTED",expected_active_head_digest:h("8"),next_head_digest:h("a"),required_ancestor_digests:{goal:h("9"),protocol:h("1"),research:h("2")},consequence_graph,semantic_admission:null,trusted_reviewer_ids:["reviewer"],expected_ticket_digest:h("b"),expected_policy_digest:h("c"),expected_evidence_digest:h("d"),authority_verdict:"PASS",supersedes:null,authority_context:{kind:"enterprise",organization_id:"org-1",actor_id:"alice",role_id:"maintainer",separation_policy_id:"sod-1",local_owner_substitution:false},downstream_vet:null};
  assert.equal(keep.evaluateGoalTransition(state,proposal).code,"ADVANCED");
  const substituted=structuredClone(proposal);substituted.authority_context.local_owner_substitution=true;
  assert.equal(keep.evaluateGoalTransition(state,substituted).code,"MALFORMED_OR_UNKNOWN_FIELD");
});

test("installed enterprise: composed public project entry refuses an unwitnessed lifecycle and never solves",async()=>{
  const dataDir=mkdtempSync(join(tmpdir(),"keep-installed-enterprise-lifecycle-"));let solves=0;
  let app=keep.composeKeep({dataDir,solve:async()=>{solves++;throw new Error("goal authority reached solve")}});const request=enterpriseGoalLifecycleFixture();
  let result=await app.autonomyLoop.runProject("installed enterprise lifecycle",{runId:"installed-enterprise-lifecycle",goalLifecycle:request,stepBudget:3});assert.equal(result.state.status,"running");
  app=keep.composeKeep({dataDir,solve:async()=>{solves++;throw new Error("goal authority reached solve")}});result=await app.autonomyLoop.runProject("installed enterprise lifecycle",{runId:"installed-enterprise-lifecycle",goalLifecycle:request});
  assert.equal(result.state.status,"running");assert.equal(result.goalLifecycle.code,"GOAL_EVENT_AUTHORITY_REQUIRED");assert.equal(result.state.revision,0);assert.equal(solves,0);assert.deepEqual(result.state.artifacts,{});
});

test("PG-04-T001 installed enterprise: attributed transition rejects local-owner substitution",()=>{
  const h=(c)=>c.repeat(64),g=(c)=>`sha256:${h(c)}`;
  const derived_authorities={architecture:{digest:h("1"),depends_on:["graph"],status:"ACTIVE"},decomposition:{digest:h("2"),depends_on:["architecture"],status:"ACTIVE"},owner_approval:{digest:h("3"),depends_on:["decomposition"],status:"ACTIVE"},ticket_activation:{digest:h("4"),depends_on:["owner_approval"],status:"ACTIVE"}};
  const state={schema_version:1,phase:"ARCHITECTURE_AUTHORIZED",approved_graph_digest:h("a"),active_generation:g("b"),derived_authorities};
  const proposal={schema_version:1,from_phase:"ARCHITECTURE_AUTHORIZED",to_phase:"ARCHITECTURE_CANDIDATE",writer_id:"writer",writer_generation:g("c"),observed_graph_digest:h("a"),expected_generation:g("b"),record_class:"CANONICAL",authority_context:{kind:"enterprise",organization_id:"org",actor_id:"alice",role_id:"maintainer",separation_policy_id:"sod",local_owner_substitution:false}};
  const authority={schema_version:1,evaluation_mode:"LIVE",canonical_writer_id:"writer",canonical_writer_generation:g("c")};
  const result=keep.evaluateDecompositionTransition(state,proposal,authority);assert.equal(result.code,"ADVANCED");
  const substituted=structuredClone(proposal);substituted.authority_context.local_owner_substitution=true;
  assert.equal(keep.evaluateDecompositionTransition(state,substituted,authority).code,"MALFORMED_OR_UNKNOWN_FIELD");
});

test("PG-04-T002 installed enterprise: attributed custody and isolation are non-substitutable", () => {
  const h = (c) => c.repeat(64),
    g = (c) => `sha256:${h(c)}`;
  const body = {
    schema_version: 1,
    node_kind: "EXECUTABLE_LEAF",
    ticket_id: "PG-04-T002",
    title: "bounded organization ticket",
    outcomes: [
      {
        kind: "PRODUCT_CHANGE",
        statement: "admit one ticket",
        invariant: "complete bodies only",
      },
    ],
    scope_ids: ["ES-S004"],
    requirements: ["R1"],
    threats: ["authority substitution"],
    mutation_surface: [
      "product:/workspace/fixture-product:src/decomposition/ticket_contract.ts",
    ],
    effect_surface: ["ticket-admission"],
    cases: [
      {
        id: "FC02",
        input: "enterprise",
        oracle: "accepted",
        classification: "ACCEPTANCE",
      },
    ],
    resources: {
      max_changed_subsystems: 2,
      focused_test_minutes: 45,
      full_closure_minutes: 120,
      max_new_runtime_dependencies: 0,
      fixed_case_count: 1,
    },
    ambiguities: [],
    closure: {
      profile: "FULL_KEEP_EXACT_COMMIT_V1",
      steps: [{ id: "full", command: "npm test", maximum_minutes: 120 }],
      source_push: true,
      source_readback: true,
      package_push: true,
      package_readback: true,
      blank_install: true,
      n1_journey: true,
      enterprise_journey: true,
    },
    authority: {
      kind: "organization",
      organization_id: "org",
      actor_id: "alice",
      role_id: "maintainer",
      separation_policy_id: "sod",
      custody_evidence_digest: h("c"),
      isolation_evidence_digest: h("d"),
    },
  };
  const transition = {
    code: "ADVANCED",
    advanced: true,
    state: {
      schema_version: 1,
      phase: "FIRST_TICKET_RESEARCH_AUTHORIZED",
      approved_graph_digest: h("a"),
      active_generation: g("b"),
      derived_authorities: {
        architecture: { digest: h("1"), depends_on: ["graph"], status: "ACTIVE" },
        decomposition: { digest: h("2"), depends_on: ["architecture"], status: "ACTIVE" },
        owner_approval: { digest: h("3"), depends_on: ["decomposition"], status: "ACTIVE" },
        ticket_activation: { digest: h("4"), depends_on: ["owner_approval"], status: "ACTIVE" },
      },
    },
    stale_descendants: [],
    owner_stop: null,
  };
  const context = {
    kind: "enterprise",
    organization_id: "org",
    actor_id: "alice",
    role_id: "maintainer",
    separation_policy_id: "sod",
    local_owner_substitution: false,
  };
  const scope = {
    ticket_id: "PG-04-T002",
    ticket_body_digest: h("e"),
    approved_graph_digest: h("a"),
    active_generation: g("b"),
  };
  const result = keep.admitExecutableTicket(body, transition, context, scope);
  assert.equal(result.admitted, true);
  if (result.admitted) {
    assert.equal(result.authority.track, "enterprise");
    assert.equal(result.authority.body.authority.actor_id, "alice");
  }
  const substituted = keep.admitExecutableTicket(
    body,
    transition,
    { ...context, actor_id: "mallory" },
    scope,
  );
  assert.deepEqual(substituted, {
    admitted: false,
    denial: "TRACK_AUTHORITY_INVALID",
  });
});

test("PG-04-T003 installed enterprise: organization graph requires attributed custody and isolation",()=>{
  const closure=Buffer.from("ewogICJzY2hlbWFfdmVyc2lvbiI6IDEsCiAgInN0YXR1cyI6ICJDT01QTEVURSIsCiAgInRpY2tldF9pZCI6ICJQRy0wNC1UMDAyIiwKICAiYXBwcm92ZWRfdGlja2V0X2JvZHlfZGlnZXN0IjogImZmOTEzYjk1ZmI0ZmMyY2I0NjAzYWUwODFkYTk4NDc3N2IzNzI3MTU0OTY1YWYzNTMzNTRkZDMzYTU3YzBkMzAiLAogICJwcm9kdWN0X2NvbW1pdCI6ICI3OTY3NmI0ZjkxMzRhM2IxMmFmNmFmNzM0ZWVkM2M0OGYyM2ZmYzIyIiwKICAicGxhbm5pbmdfY29tbWl0IjogImJmMGM4YzIyMGQ4YTM3OTIwMzBmZWExOGUyMTM0YzU1NjVmNjAyZGEiLAogICJjbG9zdXJlX3Byb2ZpbGUiOiAiRlVMTF9LRUVQX0VYQUNUX0NPTU1JVF9WMSIsCiAgImNvbXBsZXRpb25fZXZpZGVuY2UiOiBbCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogMCwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI3NjA5NDE3ZjA1NTE2OTI4ZGQyYzg4NGE3ZDkyYmE1Yjc3ZGIwNTcxYzJmZjliMGNhMWU2ODdlMGU2NzViMjA2IgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxLAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjE5NjJiODAwZWFlZjg3Yjc3MDA1MTE2ZmI1ZmU4NzE2ODI4MTVlMzE3ODcyYzYyY2QxNjVkMWQ2ZGIwYTY3ODAiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDIsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiODQwNTkxYmIxMDM1NDMzYmNkYjA2ZWM3NmViOTUyYTQ1NDI0ZTEyNzE2NTg0MzlhODAxOGM5MjE5NDFhMmM5YiIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogMywKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI1N2JlNGIyNDI0YTc5NGFhZTEyOGZhYmVmZDRhZmE0MWI1YmM1Mzc0YTdiOWI2ZWEyYWVlZWY1M2RkNGVlZmRiIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiA0LAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjllMjc3ZDZiMDljNTE0MTM5Zjk2YmQxM2Y5MTc0ZDA3YWZmNThkNzM4ZTdjMjhlYTFhMmIwYmQ5YmRkMzU5MzYiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDUsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiYmFmZWYyYWRjNWI3OTViODhhMjE5NDQ5OWNhNWNmNWZlNTI1YzcxNDg4MWRmN2MyYzZmNzNjZTg0YTUxY2VkNSIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogNiwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI2YzNhMzA4ZjNlNGRiYTVkZjM3OTg1YjIyMzQyNmRkNjA1N2UyOTcxMWEwZTY3ZmI0ZDBiNWM4NTk4NjM2NDhkIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiA3LAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjk3MGQ0MjdlMDBhOGY2NmUyYWJhOTM2ZDc5Y2Y2MmFlODFlNTkyMWFmNzA3NGFjYWQ4MTA0ZDE0NDk5NTdkMGIiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDgsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiZGE0ODY3NWRlMzM0NWEwZWQ1NWVlYzY4YjQwODViMTVkMDU5MmFmMTA2ZjA5YjQ2YmMwZThiMzM4NWJjYTMzMCIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogOSwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICIzMTNlY2I5NTNmZmJlYzlhYzA0YzY4NGU5NGQ3NTg1M2I3ZWJhYzYwODY3OWJmZWNhMjM0ZmQ2MmFhNjljM2QyIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxMCwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICIxYmQ4YzUzYWM0Njg4ZThhYzRjMmEzZjRiYzFhNmJhNDk5ZmRlOTY3MWI5ODJjNmU4YmZlNDI2NjYyYjhlMzY5IgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxMSwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICJjMjYzY2IyM2NiZjQ0NDg2MDdkMjg3OTRkZjU0NzY1Y2QwNGM2NWVjMTY2YmMxNmIwNThlZDJiNDRlN2I2YjYzIgogICAgfQogIF0sCiAgImdpdGh1Yl9yZWFkYmFjayI6IHsKICAgICJzb3VyY2VfcmVtb3RlX2NvbW1pdCI6ICI3OTY3NmI0ZjkxMzRhM2IxMmFmNmFmNzM0ZWVkM2M0OGYyM2ZmYzIyIiwKICAgICJwYWNrYWdlX2Fzc2V0X3VybCI6ICJodHRwczovL2dpdGh1Yi5jb20vUmVkUm9va0FJL2tlZXAtdGFyYmFsbC1iYWNrdXAvcmVsZWFzZXMvZG93bmxvYWQvcGctMDQtdDAwMi1jbG9zdXJlLTIwMjYuMDkuMDMva2VlcC0wLjAuMS50Z3oiLAogICAgInBhY2thZ2Vfc2hhMjU2IjogIjc4OGYyNjk3ZTY1MmU3ZGI2MjJhYzc0Nzg5OWVmNmE2M2E2M2E1MjNlNjg0ZmE0NGJmMjViMmZiZmRkOTk5YjkiLAogICAgInJldHJpZXZlZF9wYWNrYWdlX3NoYTI1NiI6ICI3ODhmMjY5N2U2NTJlN2RiNjIyYWM3NDc4OTllZjZhNjNhNjNhNTIzZTY4NGZhNDRiZjI1YjJmYmZkZDk5OWI5IiwKICAgICJyZXRyaWV2ZWRfaW5zdGFsbF9zdGF0dXMiOiAiUEFTUyIKICB9LAogICJjbG9zZWRfYXQiOiAiMjAyNi0wOS0wM1QyMjoxNDozOSswMjowMCIKfQo=","base64").toString("utf8"),h=c=>c.repeat(64),classes=["scope","research","requirement","threat_control","test","track","surface","retained_work"],nodes=[{ticket_id:"A",ticket_body_digest:h("a")},{ticket_id:"B",ticket_body_digest:h("b")}];
  const stable=v=>Array.isArray(v)?v.map(stable):v!==null&&typeof v==="object"?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])])):v,digest=v=>createHash("sha256").update(JSON.stringify(stable(v))).digest("hex"),universes=Object.fromEntries(classes.map(k=>[k,[`${k}-1`]])),coverage_relations=classes.flatMap(coverage_class=>nodes.map(n=>({coverage_class,item_id:`${coverage_class}-1`,ticket_id:n.ticket_id}))),node_coverage=nodes.map(n=>({ticket_id:n.ticket_id,...Object.fromEntries(classes.map(k=>[k,[`${k}-1`]]))})),trace_relations=["surface","threat_control","test","retained_work"].flatMap(to_class=>["research","scope"].map(from_class=>({from_class,from_item_id:`${from_class}-1`,to_class,to_item_id:`${to_class}-1`})));
  const admitted=nodes.map(n=>({status:"EXECUTABLE_TICKET_ADMITTED",...n,track:"enterprise",body:{ticket_id:n.ticket_id}})),candidate={schema_version:1,graph_id:"installed-enterprise",generation:`sha256:${h("c")}`,node_inventory_digest:digest(nodes),candidate_digest:h("0"),nodes,dependency_edges:[{upstream_ticket_id:"A",downstream_ticket_id:"B",required_receipt_class:"FULL_KEEP_EXACT_COMMIT_V1_TICKET_CLOSURE",consumed_behavior:"B consumes A authority"}],coverage_universes:universes,coverage_relations,trace_relations,node_coverage,track_authority:{kind:"organization",organization_id:"org",actor_id:"alice",role_id:"maintainer",separation_policy_id:"sod",custody_evidence_digest:h("d"),isolation_evidence_digest:h("e")}};candidate.candidate_digest=keep.decompositionGraphCandidateDigest(candidate);
  const prerequisite={closure_bytes:closure,closure_digest:"faa4b817a6769d8de78dca233b2d090472d8cc05d08bde07ea9dccd22cfa30e5",product_commit:"79676b4f9134a3b12af6af734eed3c48f23ffc22",closure_profile:"FULL_KEEP_EXACT_COMMIT_V1"},context={kind:"enterprise",organization_id:"org",actor_id:"alice",role_id:"maintainer",separation_policy_id:"sod",local_owner_substitution:false};
  const result=keep.admitDecompositionGraph(candidate,admitted,prerequisite,context);assert.equal(result.admitted,true);if(result.admitted){assert.equal(result.authority.track,"enterprise");assert.equal(result.authority.graph.track_authority.actor_id,"alice")}
  assert.deepEqual(keep.admitDecompositionGraph(candidate,admitted,prerequisite,{...context,actor_id:"mallory"}),{admitted:false,denial:"TRACK_AUTHORITY_INVALID"});
});


test("PG-04-T004 installed enterprise: coequal track coverage preserves its direct authority ceremony",()=>{
  const h=c=>c.repeat(64),g=c=>`sha256:${h(c)}`,closure=Buffer.from("ewogICJzY2hlbWFfdmVyc2lvbiI6IDEsCiAgInN0YXR1cyI6ICJDT01QTEVURSIsCiAgInRpY2tldF9pZCI6ICJQRy0wNC1UMDAyIiwKICAiYXBwcm92ZWRfdGlja2V0X2JvZHlfZGlnZXN0IjogImZmOTEzYjk1ZmI0ZmMyY2I0NjAzYWUwODFkYTk4NDc3N2IzNzI3MTU0OTY1YWYzNTMzNTRkZDMzYTU3YzBkMzAiLAogICJwcm9kdWN0X2NvbW1pdCI6ICI3OTY3NmI0ZjkxMzRhM2IxMmFmNmFmNzM0ZWVkM2M0OGYyM2ZmYzIyIiwKICAicGxhbm5pbmdfY29tbWl0IjogImJmMGM4YzIyMGQ4YTM3OTIwMzBmZWExOGUyMTM0YzU1NjVmNjAyZGEiLAogICJjbG9zdXJlX3Byb2ZpbGUiOiAiRlVMTF9LRUVQX0VYQUNUX0NPTU1JVF9WMSIsCiAgImNvbXBsZXRpb25fZXZpZGVuY2UiOiBbCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogMCwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI3NjA5NDE3ZjA1NTE2OTI4ZGQyYzg4NGE3ZDkyYmE1Yjc3ZGIwNTcxYzJmZjliMGNhMWU2ODdlMGU2NzViMjA2IgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxLAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjE5NjJiODAwZWFlZjg3Yjc3MDA1MTE2ZmI1ZmU4NzE2ODI4MTVlMzE3ODcyYzYyY2QxNjVkMWQ2ZGIwYTY3ODAiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDIsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiODQwNTkxYmIxMDM1NDMzYmNkYjA2ZWM3NmViOTUyYTQ1NDI0ZTEyNzE2NTg0MzlhODAxOGM5MjE5NDFhMmM5YiIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogMywKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI1N2JlNGIyNDI0YTc5NGFhZTEyOGZhYmVmZDRhZmE0MWI1YmM1Mzc0YTdiOWI2ZWEyYWVlZWY1M2RkNGVlZmRiIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiA0LAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjllMjc3ZDZiMDljNTE0MTM5Zjk2YmQxM2Y5MTc0ZDA3YWZmNThkNzM4ZTdjMjhlYTFhMmIwYmQ5YmRkMzU5MzYiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDUsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiYmFmZWYyYWRjNWI3OTViODhhMjE5NDQ5OWNhNWNmNWZlNTI1YzcxNDg4MWRmN2MyYzZmNzNjZTg0YTUxY2VkNSIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogNiwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI2YzNhMzA4ZjNlNGRiYTVkZjM3OTg1YjIyMzQyNmRkNjA1N2UyOTcxMWEwZTY3ZmI0ZDBiNWM4NTk4NjM2NDhkIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiA3LAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjk3MGQ0MjdlMDBhOGY2NmUyYWJhOTM2ZDc5Y2Y2MmFlODFlNTkyMWFmNzA3NGFjYWQ4MTA0ZDE0NDk5NTdkMGIiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDgsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiZGE0ODY3NWRlMzM0NWEwZWQ1NWVlYzY4YjQwODViMTVkMDU5MmFmMTA2ZjA5YjQ2YmMwZThiMzM4NWJjYTMzMCIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogOSwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICIzMTNlY2I5NTNmZmJlYzlhYzA0YzY4NGU5NGQ3NTg1M2I3ZWJhYzYwODY3OWJmZWNhMjM0ZmQ2MmFhNjljM2QyIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxMCwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICIxYmQ4YzUzYWM0Njg4ZThhYzRjMmEzZjRiYzFhNmJhNDk5ZmRlOTY3MWI5ODJjNmU4YmZlNDI2NjYyYjhlMzY5IgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxMSwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICJjMjYzY2IyM2NiZjQ0NDg2MDdkMjg3OTRkZjU0NzY1Y2QwNGM2NWVjMTY2YmMxNmIwNThlZDJiNDRlN2I2YjYzIgogICAgfQogIF0sCiAgImdpdGh1Yl9yZWFkYmFjayI6IHsKICAgICJzb3VyY2VfcmVtb3RlX2NvbW1pdCI6ICI3OTY3NmI0ZjkxMzRhM2IxMmFmNmFmNzM0ZWVkM2M0OGYyM2ZmYzIyIiwKICAgICJwYWNrYWdlX2Fzc2V0X3VybCI6ICJodHRwczovL2dpdGh1Yi5jb20vUmVkUm9va0FJL2tlZXAtdGFyYmFsbC1iYWNrdXAvcmVsZWFzZXMvZG93bmxvYWQvcGctMDQtdDAwMi1jbG9zdXJlLTIwMjYuMDkuMDMva2VlcC0wLjAuMS50Z3oiLAogICAgInBhY2thZ2Vfc2hhMjU2IjogIjc4OGYyNjk3ZTY1MmU3ZGI2MjJhYzc0Nzg5OWVmNmE2M2E2M2E1MjNlNjg0ZmE0NGJmMjViMmZiZmRkOTk5YjkiLAogICAgInJldHJpZXZlZF9wYWNrYWdlX3NoYTI1NiI6ICI3ODhmMjY5N2U2NTJlN2RiNjIyYWM3NDc4OTllZjZhNjNhNjNhNTIzZTY4NGZhNDRiZjI1YjJmYmZkZDk5OWI5IiwKICAgICJyZXRyaWV2ZWRfaW5zdGFsbF9zdGF0dXMiOiAiUEFTUyIKICB9LAogICJjbG9zZWRfYXQiOiAiMjAyNi0wOS0wM1QyMjoxNDozOSswMjowMCIKfQo=","base64").toString("utf8");
  const transition={code:"ADVANCED",advanced:true,state:{schema_version:1,phase:"FIRST_TICKET_RESEARCH_AUTHORIZED",approved_graph_digest:h("a"),active_generation:g("b"),derived_authorities:{architecture:{digest:h("1"),depends_on:["graph"],status:"ACTIVE"},decomposition:{digest:h("2"),depends_on:["architecture"],status:"ACTIVE"},owner_approval:{digest:h("3"),depends_on:["decomposition"],status:"ACTIVE"},ticket_activation:{digest:h("4"),depends_on:["owner_approval"],status:"ACTIVE"}}},stale_descendants:[],owner_stop:null};
  const make=(track)=>{const prefix=track==="n1"?"N1":"ENT",authority=track==="n1"?{kind:"owner",owner_id:"owner",custody_id:"local"}:{kind:"organization",organization_id:"org",actor_id:"alice",role_id:"maintainer",separation_policy_id:"sod",custody_evidence_digest:h("c"),isolation_evidence_digest:h("d")},body={schema_version:1,node_kind:"EXECUTABLE_LEAF",ticket_id:`INSTALLED-${prefix}`,title:`${track} body`,outcomes:[{kind:"PRODUCT_CHANGE",statement:`${track} covered`,invariant:"coequal tracks"}],scope_ids:["ES-S004"],requirements:[`${prefix}-DIRECT`],threats:["substitution"],mutation_surface:["src/decomposition/track_coverage.ts"],effect_surface:["track admission"],cases:[{id:`${prefix}-DIRECT`,input:"direct",oracle:"admit",classification:"ACCEPTANCE"},{id:`${prefix}-EXCLUSION`,input:"substitute",oracle:"refuse",classification:"HOSTILE"}],resources:{max_changed_subsystems:2,focused_test_minutes:45,full_closure_minutes:120,max_new_runtime_dependencies:0,fixed_case_count:2},ambiguities:[],closure:{profile:"FULL_KEEP_EXACT_COMMIT_V1",steps:[{id:"full",command:"npm test",maximum_minutes:120}],source_push:true,source_readback:true,package_push:true,package_readback:true,blank_install:true,n1_journey:true,enterprise_journey:true},authority},digest=keep.executableTicketBodyDigest(body),context=track==="n1"?{kind:"n1",principal_id:"owner",custody_id:"local",organization_services:"ABSENT"}:{kind:"enterprise",organization_id:"org",actor_id:"alice",role_id:"maintainer",separation_policy_id:"sod",local_owner_substitution:false},admission=keep.admitExecutableTicket(body,transition,context,{ticket_id:body.ticket_id,ticket_body_digest:digest,approved_graph_digest:h("a"),active_generation:g("b")});assert.equal(admission.admitted,true);if(!admission.admitted)throw new Error("fixture admission failed");return admission.authority;};
  const owner=make("n1"),org=make("enterprise"),ownerDigest=keep.admittedTicketAuthorityDigest(owner),orgDigest=keep.admittedTicketAuthorityDigest(org),seal=w=>({...w,witness_digest:keep.trackWitnessDigest(w)}),n1=seal({target_track:"n1",kind:"DIRECT",ceremony:"LOCAL_OWNER",authority_digest:ownerDigest,case_id:"N1-DIRECT"}),enterprise=seal({target_track:"enterprise",kind:"DIRECT",ceremony:"ORGANIZATION",authority_digest:orgDigest,case_id:"ENT-DIRECT"}),entry={logical_ticket_id:"INSTALLED-PAIR",mode:"paired",n1_body_digest:owner.ticket_body_digest,enterprise_body_digest:org.ticket_body_digest,n1_case_id:"N1-DIRECT",enterprise_case_id:"ENT-DIRECT",counterpart_ticket_id:null,shared_mechanism_digest:null,shared_evidence_digest:null},projection=keep.trackAllocationScopeDigest([entry]),scope={schema_version:1,status:"TRACK_ALLOCATION_SCOPE_ADMITTED",generation:g("9"),approved_ticket_inventory_digest:"f0b8b60c7b497b6422fc43afeb310d18ea3d28f3decfe666d44deb54963399db",logical_allocation_projection_digest:projection,entries:[entry]},candidate={schema_version:1,allocation_id:"installed-pair",generation:g("9"),candidate_digest:h("0"),scope_projection_digest:projection,allocations:[{logical_ticket_id:"INSTALLED-PAIR",mode:"paired",mechanism_digest:h("e"),n1_witness:n1,enterprise_witness:enterprise,equivalence:null}]};candidate.candidate_digest=keep.trackCoverageCandidateDigest(candidate);
  const result=keep.admitTrackCoverage(candidate,[owner,org],scope,{closure_bytes:closure,closure_digest:"faa4b817a6769d8de78dca233b2d090472d8cc05d08bde07ea9dccd22cfa30e5",product_commit:"79676b4f9134a3b12af6af734eed3c48f23ffc22",closure_profile:"FULL_KEEP_EXACT_COMMIT_V1"});assert.equal(result.admitted,true);if(!result.admitted)return;assert.equal(result.authority.candidate.allocations[0].enterprise_witness.ceremony,"ORGANIZATION");assert.equal(org.body.authority.kind,"organization");
});

test("PG-04-T005 installed enterprise: reviewability requires attributed custody and isolation",()=>{
  const h=c=>c.repeat(64),g=c=>`sha256:${h(c)}`,reviewers=[{reviewer_id:"local-reviewer",reviewer_family:"Anthropic Claude"},{reviewer_id:"org-reviewer",reviewer_family:"Anthropic Claude"}],closures={"PG-04-T002":{role:"TICKET_BODIES_AND_BOUNDS",closure_bytes:Buffer.from("ewogICJzY2hlbWFfdmVyc2lvbiI6IDEsCiAgInN0YXR1cyI6ICJDT01QTEVURSIsCiAgInRpY2tldF9pZCI6ICJQRy0wNC1UMDAyIiwKICAiYXBwcm92ZWRfdGlja2V0X2JvZHlfZGlnZXN0IjogImZmOTEzYjk1ZmI0ZmMyY2I0NjAzYWUwODFkYTk4NDc3N2IzNzI3MTU0OTY1YWYzNTMzNTRkZDMzYTU3YzBkMzAiLAogICJwcm9kdWN0X2NvbW1pdCI6ICI3OTY3NmI0ZjkxMzRhM2IxMmFmNmFmNzM0ZWVkM2M0OGYyM2ZmYzIyIiwKICAicGxhbm5pbmdfY29tbWl0IjogImJmMGM4YzIyMGQ4YTM3OTIwMzBmZWExOGUyMTM0YzU1NjVmNjAyZGEiLAogICJjbG9zdXJlX3Byb2ZpbGUiOiAiRlVMTF9LRUVQX0VYQUNUX0NPTU1JVF9WMSIsCiAgImNvbXBsZXRpb25fZXZpZGVuY2UiOiBbCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogMCwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI3NjA5NDE3ZjA1NTE2OTI4ZGQyYzg4NGE3ZDkyYmE1Yjc3ZGIwNTcxYzJmZjliMGNhMWU2ODdlMGU2NzViMjA2IgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxLAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjE5NjJiODAwZWFlZjg3Yjc3MDA1MTE2ZmI1ZmU4NzE2ODI4MTVlMzE3ODcyYzYyY2QxNjVkMWQ2ZGIwYTY3ODAiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDIsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiODQwNTkxYmIxMDM1NDMzYmNkYjA2ZWM3NmViOTUyYTQ1NDI0ZTEyNzE2NTg0MzlhODAxOGM5MjE5NDFhMmM5YiIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogMywKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI1N2JlNGIyNDI0YTc5NGFhZTEyOGZhYmVmZDRhZmE0MWI1YmM1Mzc0YTdiOWI2ZWEyYWVlZWY1M2RkNGVlZmRiIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiA0LAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjllMjc3ZDZiMDljNTE0MTM5Zjk2YmQxM2Y5MTc0ZDA3YWZmNThkNzM4ZTdjMjhlYTFhMmIwYmQ5YmRkMzU5MzYiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDUsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiYmFmZWYyYWRjNWI3OTViODhhMjE5NDQ5OWNhNWNmNWZlNTI1YzcxNDg4MWRmN2MyYzZmNzNjZTg0YTUxY2VkNSIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogNiwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICI2YzNhMzA4ZjNlNGRiYTVkZjM3OTg1YjIyMzQyNmRkNjA1N2UyOTcxMWEwZTY3ZmI0ZDBiNWM4NTk4NjM2NDhkIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiA3LAogICAgICAiZXZpZGVuY2VfZGlnZXN0IjogIjk3MGQ0MjdlMDBhOGY2NmUyYWJhOTM2ZDc5Y2Y2MmFlODFlNTkyMWFmNzA3NGFjYWQ4MTA0ZDE0NDk5NTdkMGIiCiAgICB9LAogICAgewogICAgICAiY29tcGxldGlvbl9pbmRleCI6IDgsCiAgICAgICJldmlkZW5jZV9kaWdlc3QiOiAiZGE0ODY3NWRlMzM0NWEwZWQ1NWVlYzY4YjQwODViMTVkMDU5MmFmMTA2ZjA5YjQ2YmMwZThiMzM4NWJjYTMzMCIKICAgIH0sCiAgICB7CiAgICAgICJjb21wbGV0aW9uX2luZGV4IjogOSwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICIzMTNlY2I5NTNmZmJlYzlhYzA0YzY4NGU5NGQ3NTg1M2I3ZWJhYzYwODY3OWJmZWNhMjM0ZmQ2MmFhNjljM2QyIgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxMCwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICIxYmQ4YzUzYWM0Njg4ZThhYzRjMmEzZjRiYzFhNmJhNDk5ZmRlOTY3MWI5ODJjNmU4YmZlNDI2NjYyYjhlMzY5IgogICAgfSwKICAgIHsKICAgICAgImNvbXBsZXRpb25faW5kZXgiOiAxMSwKICAgICAgImV2aWRlbmNlX2RpZ2VzdCI6ICJjMjYzY2IyM2NiZjQ0NDg2MDdkMjg3OTRkZjU0NzY1Y2QwNGM2NWVjMTY2YmMxNmIwNThlZDJiNDRlN2I2YjYzIgogICAgfQogIF0sCiAgImdpdGh1Yl9yZWFkYmFjayI6IHsKICAgICJzb3VyY2VfcmVtb3RlX2NvbW1pdCI6ICI3OTY3NmI0ZjkxMzRhM2IxMmFmNmFmNzM0ZWVkM2M0OGYyM2ZmYzIyIiwKICAgICJwYWNrYWdlX2Fzc2V0X3VybCI6ICJodHRwczovL2dpdGh1Yi5jb20vUmVkUm9va0FJL2tlZXAtdGFyYmFsbC1iYWNrdXAvcmVsZWFzZXMvZG93bmxvYWQvcGctMDQtdDAwMi1jbG9zdXJlLTIwMjYuMDkuMDMva2VlcC0wLjAuMS50Z3oiLAogICAgInBhY2thZ2Vfc2hhMjU2IjogIjc4OGYyNjk3ZTY1MmU3ZGI2MjJhYzc0Nzg5OWVmNmE2M2E2M2E1MjNlNjg0ZmE0NGJmMjViMmZiZmRkOTk5YjkiLAogICAgInJldHJpZXZlZF9wYWNrYWdlX3NoYTI1NiI6ICI3ODhmMjY5N2U2NTJlN2RiNjIyYWM3NDc4OTllZjZhNjNhNjNhNTIzZTY4NGZhNDRiZjI1YjJmYmZkZDk5OWI5IiwKICAgICJyZXRyaWV2ZWRfaW5zdGFsbF9zdGF0dXMiOiAiUEFTUyIKICB9LAogICJjbG9zZWRfYXQiOiAiMjAyNi0wOS0wM1QyMjoxNDozOSswMjowMCIKfQo=","base64").toString("utf8"),closure_digest:"faa4b817a6769d8de78dca233b2d090472d8cc05d08bde07ea9dccd22cfa30e5",product_commit:"79676b4f9134a3b12af6af734eed3c48f23ffc22"},"PG-04-T003":{role:"GRAPH_AND_RECIPROCAL_COVERAGE",closure_bytes:Buffer.from("ewogICJzY2hlbWFfdmVyc2lvbiI6IDEsCiAgInN0YXR1cyI6ICJDT01QTEVURSIsCiAgInRpY2tldF9pZCI6ICJQRy0wNC1UMDAzIiwKICAiYXBwcm92ZWRfdGlja2V0X2JvZHlfZGlnZXN0IjogImRiZWJjY2I5OTBjZWZlYzk4MDE2MTIyOTY0N2JhNTZmYzMwN2Q4Y2IwZDAwOGVjYzIyYmM1YmMyMmVhN2Y4NDIiLAogICJwcm9kdWN0X2NvbW1pdCI6ICI5Y2QyZTYyYjUwNWI2ZTYxMzk5YjcyYzlmY2Y4MDBhMzUwNDU3N2RlIiwKICAicGxhbm5pbmdfY29tbWl0IjogIjgxYmRkZWFiMDVhOGM2ZTRkZTdmMWZjOGQ1OTk0NGEzNjUzZjg5YjgiLAogICJjbG9zdXJlX3Byb2ZpbGUiOiAiRlVMTF9LRUVQX0VYQUNUX0NPTU1JVF9WMSIsCiAgImNvbXBsZXRpb25fZXZpZGVuY2UiOiBbCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiAwLCAiZXZpZGVuY2VfZGlnZXN0IjogIjdhYTJmYWMzNTM1OGQ1M2YwMTc1ZDcxNTc2NDBmM2I5NThhNDI4YTVhNWI5YzE0ZGU3MWFhOTE3Nzk2MDAzNGQifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDEsICJldmlkZW5jZV9kaWdlc3QiOiAiMmYwOGM0Nzg0OTU1ODZkYzYyNWE1M2QxYTE0YjM5OGNiMWUyODNlOTQ4ZjFmYzk4YmZjZTc3ZjMxMDAyM2U1YiJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogMiwgImV2aWRlbmNlX2RpZ2VzdCI6ICI5Nzg3NTkzNzc4NGQ4MGQ4ZTgwZTIwZWEwYjYxMTIxNjM0YjE3OGFkMGQ5ZTE1NWNhMTU1YTFlOTBmOTIzYjI4In0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiAzLCAiZXZpZGVuY2VfZGlnZXN0IjogImFmNDQ2MmM2OTUwZGVmY2I2OWM2ZDI1ZmU5MzA3ODYwZjhjOWE3NGFmNTRkNGMxZjEwNTM1OGVhZjU1NGY3MzkifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDQsICJldmlkZW5jZV9kaWdlc3QiOiAiYzI3YTRiOWE1M2E5YzIxY2Y4MTQ4YTEyNTU5ODA5OGIxNmZjY2JkNWZmNjk1MDBmZGMxZTcxYTNkZTU1MzE3ZCJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogNSwgImV2aWRlbmNlX2RpZ2VzdCI6ICJjNTQ5ZTFjZDVhMWM2Zjk0YTFhMjA1ZTczYWZjZjE3YTVjNTQzNWMwNzE2MmFjYTM4YjM1OGNkOTdkNjE3ZDI1In0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiA2LCAiZXZpZGVuY2VfZGlnZXN0IjogIjY2ZDdjZTk4YjBiZTA5Zjk5YTEwMmFmMTE3MjE2MDA5Y2FhYmQ0ZWQyYWNkZjU0YTQ1Mjk5MWNiMTljMmJkNzYifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDcsICJldmlkZW5jZV9kaWdlc3QiOiAiMzdhZmMwYTQxYTAyZmE5MmM3NmNiYzZmNmNmNDAyYTkzMWRiNzc5NDM0YjI3OWY0NDJiNWU0NjlhYjFhZmI4OCJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogOCwgImV2aWRlbmNlX2RpZ2VzdCI6ICI4NDViNDAzMzNiYjI2YTRmNjYwZWE0MTQwMGQ3MGQ1MDE4YWNhOTc3YjMxNGI5NjczYTBiMDJiMzM1ZThhNGNlIn0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiA5LCAiZXZpZGVuY2VfZGlnZXN0IjogIjk0ZmVkNTcwNzg4ZjlmZDFiMDBiMGViMjQ3ZGY0MGU2ZWNjZDg2NjA4ZTIyNGRjMGIyZTZjYTU4OWFjNjE4ZDgifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDEwLCAiZXZpZGVuY2VfZGlnZXN0IjogImZlNzYzZTUyMTFkYTJmZWY1N2E5ZDZjMTliMWJjMjUxNWY3NmRhOTQxMGU1MzAwY2U1MjE3NDg5OGU3NjQ1YWEifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDExLCAiZXZpZGVuY2VfZGlnZXN0IjogImI4OTdkOGM1MTFlNzIxNjkwNTllNjU1MmRjNjllOTY5ZDViMGNlMTlmZDNjOTM3NTcyOWVmMWJkYzgwYWY0YjUifQogIF0sCiAgImdpdGh1Yl9yZWFkYmFjayI6IHsKICAgICJzb3VyY2VfcmVtb3RlX2NvbW1pdCI6ICI5Y2QyZTYyYjUwNWI2ZTYxMzk5YjcyYzlmY2Y4MDBhMzUwNDU3N2RlIiwKICAgICJwYWNrYWdlX2Fzc2V0X3VybCI6ICJodHRwczovL2dpdGh1Yi5jb20vUmVkUm9va0FJL2tlZXAtdGFyYmFsbC1iYWNrdXAvcmVsZWFzZXMvZG93bmxvYWQvcGctMDQtdDAwMy1jbG9zdXJlLTIwMjYuMDkuMDMva2VlcC0wLjAuMS50Z3oiLAogICAgInBhY2thZ2Vfc2hhMjU2IjogImIyNDM5YzM0MmZlMzE5YTQwMDAzM2EyYWE1YmM2YjhiNzNhNTE2N2MzZTEwYzNjYmZhNzI4ZTZhYjllOWVhYjYiLAogICAgInJldHJpZXZlZF9wYWNrYWdlX3NoYTI1NiI6ICJiMjQzOWMzNDJmZTMxOWE0MDAwMzNhMmFhNWJjNmI4YjczYTUxNjdjM2UxMGMzY2JmYTcyOGU2YWI5ZTllYWI2IiwKICAgICJyZXRyaWV2ZWRfaW5zdGFsbF9zdGF0dXMiOiAiUEFTUyIKICB9LAogICJjbG9zZWRfYXQiOiAiMjAyNi0wOS0wM1QyMzo1Mzo0MSswMjowMCIKfQo=","base64").toString("utf8"),closure_digest:"41268ed1843199a7cff0775176d702d2940a1b2c0698a2e4e0e588d79825b28d",product_commit:"9cd2e62b505b6e61399b72c9fcf800a3504577de"},"PG-04-T004":{role:"TRACK_ALLOCATION",closure_bytes:Buffer.from("ewogICJzY2hlbWFfdmVyc2lvbiI6IDEsCiAgInN0YXR1cyI6ICJDT01QTEVURSIsCiAgInRpY2tldF9pZCI6ICJQRy0wNC1UMDA0IiwKICAiYXBwcm92ZWRfdGlja2V0X2JvZHlfZGlnZXN0IjogImI2OTRhZGJiYWY5OWQyZDVkODcyNGY5ZDJkNWRiMjYxNjAzMjBkNmIxZDc2OTBiNGUzMWFmMjA0YmEzMzNjZDIiLAogICJwcm9kdWN0X2NvbW1pdCI6ICJmMjczODY3NjVkMGE5NjQ0MTMyNDBhN2Q4ZTgyMWI4NTg0MDMxMWQ3IiwKICAicGxhbm5pbmdfY29tbWl0IjogImM3NDUxOTkzMTkwYTQwNmQyZDBlZmJlMjMzZGQxZjIyNTAyNjBiZGYiLAogICJjbG9zdXJlX3Byb2ZpbGUiOiAiRlVMTF9LRUVQX0VYQUNUX0NPTU1JVF9WMSIsCiAgImNvbXBsZXRpb25fZXZpZGVuY2UiOiBbCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiAwLCAiZXZpZGVuY2VfZGlnZXN0IjogIjNiZGMwYjA3Y2RjNTljYTk4N2M1NTRkNGIxYTczNzkyYjU5YjA0NDk3MDdmY2RjMDAyOTUxZGMwZGNjMWMwZWUifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDEsICJldmlkZW5jZV9kaWdlc3QiOiAiYzkwNDBkNmVhMzE0ZmMzYWRiYTZhY2NmZjBkZDc2YWNhMDY5M2I4MTc3MjA4NmRlOTZkYjAyY2U1YzU5N2E0NSJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogMiwgImV2aWRlbmNlX2RpZ2VzdCI6ICI0YzYzNWRlNDMwZGMwOWIwZjllMDgxNTVjZDQyMzI2MGIwOTQxNDA2NjQ0YWZlMDAzOWU1NGRmY2EyMTY0NzcwIn0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiAzLCAiZXZpZGVuY2VfZGlnZXN0IjogImFmNDQ2MmM2OTUwZGVmY2I2OWM2ZDI1ZmU5MzA3ODYwZjhjOWE3NGFmNTRkNGMxZjEwNTM1OGVhZjU1NGY3MzkifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDQsICJldmlkZW5jZV9kaWdlc3QiOiAiOTM5ZDQ4Nzc3ODQyZGJiYWVhOTE2ZjcxNzdiODIyNTc4MWYzMjNiZGQ3YzAzYjBlMDc5MDZkNzdmNWNkNTljNyJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogNSwgImV2aWRlbmNlX2RpZ2VzdCI6ICJjOTJkNDdiM2YxNmI3YjQwODIyNzYzMDRjMWRiNWNkNGIyM2E2MGI0YzRjNmEyNTNmYzY4ZGZiMTM2YTEwZjBmIn0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiA2LCAiZXZpZGVuY2VfZGlnZXN0IjogImViOTQ5ZDQ2ZjQyY2QxMmE2YzExN2FlZGRhYWQ3N2RmYzZkNGJmNjMwOGU1Y2ZhMDFlMDU5NDA4OWE5YWYxMTQifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDcsICJldmlkZW5jZV9kaWdlc3QiOiAiMWI1YjQ5OWZhMGM4YWU5NWM5ZDEwYjI1OTVmOTEyYzQxYjc0ZDczMjEzMThkZWM0MjY1MTMyNzU5NDk2OGVjNSJ9LAogICAgeyJjb21wbGV0aW9uX2luZGV4IjogOCwgImV2aWRlbmNlX2RpZ2VzdCI6ICIxM2ViOTYxNGNlMmFjNzVjYjJjNGI5M2JlNTAxNDY3MGI0ZmQ0ODQyY2NmZjFlYzNhNjY0YzdjZDlmM2FlZmI3In0sCiAgICB7ImNvbXBsZXRpb25faW5kZXgiOiA5LCAiZXZpZGVuY2VfZGlnZXN0IjogImViMWE0Nzg4NTA0MTZjMWE3YjJjZjc5MjRlZjY3MTA0ZGUzZjdlMzMyM2ZmYjc1ZjdiMjBhOTViNDAwMWQ5MTkifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDEwLCAiZXZpZGVuY2VfZGlnZXN0IjogIjE5NWU0OGRkMjI4OTNmNThhOGQzNzE5NzI3MmM4NDEyZDUwMDEyZDQ2ODU5ZWVjNWEwOWIzYTQ1N2QzYzg0ZDEifSwKICAgIHsiY29tcGxldGlvbl9pbmRleCI6IDExLCAiZXZpZGVuY2VfZGlnZXN0IjogImJlYWEyNjJhY2I2YzBjZGNiNDQzZGE0MDEwMjJlYjRmM2JlNzRjYzk3YThmMDJhYzAwOWNkYWFhZWE2OTc2NWEifQogIF0sCiAgImdpdGh1Yl9yZWFkYmFjayI6IHsKICAgICJzb3VyY2VfcmVtb3RlX2NvbW1pdCI6ICJmMjczODY3NjVkMGE5NjQ0MTMyNDBhN2Q4ZTgyMWI4NTg0MDMxMWQ3IiwKICAgICJwYWNrYWdlX2Fzc2V0X3VybCI6ICJodHRwczovL2dpdGh1Yi5jb20vUmVkUm9va0FJL2tlZXAtdGFyYmFsbC1iYWNrdXAvcmVsZWFzZXMvZG93bmxvYWQvcGctMDQtdDAwNC1jbG9zdXJlLTIwMjYuMDkuMDQva2VlcC0wLjAuMS50Z3oiLAogICAgInBhY2thZ2Vfc2hhMjU2IjogIjI0MjNlNWYxMDQyMWVjZDkyZGFmOGMwMjg0OWVjOTRmNTBiOThmN2FhZTM1YWIzNDM0ODRmYmVhMWI1NDM4ZDIiLAogICAgInJldHJpZXZlZF9wYWNrYWdlX3NoYTI1NiI6ICIyNDIzZTVmMTA0MjFlY2Q5MmRhZjhjMDI4NDllYzk0ZjUwYjk4ZjdhYWUzNWFiMzQzNDg0ZmJlYTFiNTQzOGQyIiwKICAgICJyZXRyaWV2ZWRfaW5zdGFsbF9zdGF0dXMiOiAiUEFTUyIKICB9LAogICJjbG9zZWRfYXQiOiAiMjAyNi0wOS0wNFQwMTozNzowMCswMjowMCIKfQo=","base64").toString("utf8"),closure_digest:"452a60a757fca16df48f5137851e00c48ded8e0f844517089fc585ddc217f797",product_commit:"f27386765d0a964413240a7d8e821b85840311d7"}};
  const prerequisites=Object.entries(closures).map(([ticket_id,receipt])=>({ticket_id,...receipt})),scope={schema_version:1,status:"DECOMPOSITION_REVIEW_SCOPE_ADMITTED",generation:g("a"),approved_inventory_digest:"f0b8b60c7b497b6422fc43afeb310d18ea3d28f3decfe666d44deb54963399db",candidate_digest:h("1"),manifest_digest:h("2"),scope_digest:h("3"),candidate_author_id:"codex",candidate_author_family:"OpenAI Codex",bounds:{maximum_files:20,maximum_bytes:1000000,maximum_cases:14,maximum_minutes:120},disclosed_reviewers:reviewers,prerequisites},context={schema_version:1,kind:"enterprise",organization_id:"red-rook",actor_id:"org-reviewer",reviewer_id:"org-reviewer",reviewer_family:"Anthropic Claude",role_id:"independent-reviewer",separation_policy_id:"sod-1",custody_evidence_digest:h("c"),isolation_evidence_digest:h("d"),local_owner_substitution:false};
  const state=keep.initialDecompositionReviewState(scope),body={schema_version:1,kind:"ATTEST_ASSESSABLE",expected_generation:state.generation,reviewer_id:context.reviewer_id,assessable:true,observed_files:10,observed_bytes:20000,observed_cases:14,estimated_minutes:90},action={...body,attestation_digest:keep.decompositionReviewDigest(body)},result=keep.advanceDecompositionReview(state,action,context,scope);
  assert.equal(result.advanced,true);assert.equal(result.state.phase,"VET_1_OPEN");assert.equal(result.state.used_rounds,0);assert.equal(context.local_owner_substitution,false);assert.equal(result.state.active_track,"enterprise");
  const substituted=keep.advanceDecompositionReview(state,action,{...context,local_owner_substitution:true},scope);assert.equal(substituted.advanced,false);assert.equal(substituted.code,"MALFORMED_OR_UNKNOWN_FIELD");
});

test("PG-04-T006 installed enterprise: attributed organization authority approves",()=>{
  const h=c=>c.repeat(64),g=c=>`sha256:${h(c)}`,owner={schema_version:1,kind:"enterprise",organization_id:"org",actor_id:"approver",role_id:"owner-approver",separation_policy_id:"sod",custody_evidence_digest:h("a"),isolation_evidence_digest:h("b"),local_owner_substitution:false},generation=g("1"),graph=h("2"),candidate=h("3"),manifest=h("4"),scopeDigest=h("5"),reviewBody={schema_version:1,status:"TWO_ROUND_DECOMPOSITION_REVIEW_COMPLETE",generation,candidate_digest:candidate,manifest_digest:manifest,scope_digest:scopeDigest,used:2,reviewers:[{round:1,reviewer_id:"a",reviewer_family:"claude",track:"n1"},{round:2,reviewer_id:"b",reviewer_family:"gemini",track:"enterprise"}],repair_chains:[],open_findings:[]},transition={schema_version:1,phase:"OWNER_APPROVED",approved_graph_digest:graph,active_generation:generation,derived_authorities:{architecture:{digest:h("6"),depends_on:[],status:"ACTIVE"},decomposition:{digest:h("7"),depends_on:[h("6")],status:"ACTIVE"},owner_approval:{digest:h("8"),depends_on:[h("7")],status:"ACTIVE"},ticket_activation:{digest:h("9"),depends_on:[h("8")],status:"ACTIVE"}}},scope={schema_version:1,status:"DECOMPOSITION_APPROVAL_SCOPE_ADMITTED",approved_inventory_digest:"f0b8b60c7b497b6422fc43afeb310d18ea3d28f3decfe666d44deb54963399db",generation,graph_digest:graph,candidate_digest:candidate,manifest_digest:manifest,scope_digest:scopeDigest,parent_scope_ids:["n1","enterprise"],proposed_scope_ids:["n1","enterprise"],candidate_author_id:"builder",candidate_author_family:"codex",expected_owner:{kind:"enterprise",organization_id:owner.organization_id,actor_id:owner.actor_id,role_id:owner.role_id,separation_policy_id:owner.separation_policy_id},transition_state:transition,transition_result:{code:"ADVANCED",advanced:true,state:transition,stale_descendants:[],owner_stop:null},observed_graph_digest:null,review_disposition:{...reviewBody,disposition_digest:keep.decompositionReviewDigest(reviewBody)},architecture_authority_digest:h("6"),decomposition_authority_digest:h("7")},state=keep.initialDecompositionApprovalState(scope),current=state.generations.at(-1),body={schema_version:1,kind:"APPROVE_GENERATION",expected_generation:generation,expected_record_digest:current.record_digest,owner,disposition_digest:scope.review_disposition.disposition_digest},action={schema_version:1,kind:"APPROVE_GENERATION",expected_generation:generation,expected_record_digest:current.record_digest,approval_digest:keep.decompositionApprovalDigest(body)},result=keep.advanceDecompositionApproval(state,action,owner,scope);
  assert.equal(result.code,"ADVANCED");assert.equal(result.state.generations.at(-1).status,"APPROVED");assert.equal(owner.local_owner_substitution,false);assert.equal(result.state.implementation_authorized,false);
});

test("PG-04-T007 installed enterprise: attributed package uses the same byte oracle and rejects substitution",()=>{
  const h=c=>c.repeat(64),generation=`sha256:${h("1")}`,members=[{path:"planning/decomposition/organization-owner.json",sha256:h("a")},{path:"planning/decomposition/custody-evidence.json",sha256:h("c")},{path:"planning/decomposition/isolation-evidence.json",sha256:h("d")}],manifest={schema_version:1,generation,authority_digest:h("e"),members},base={schema_version:1,generation,parent_record_digest:null,graph_digest:h("2"),candidate_digest:h("3"),manifest_digest:keep.decompositionPublicationDigest(manifest),scope_digest:h("4"),scope_ids:["n1","enterprise"],amendment_authorization_digest:"GENESIS",evidence_digests:[h("c"),h("d")],review_disposition_digest:h("5"),approval_digest:h("6"),status:"APPROVED"},approved_generation={...base,record_digest:keep.decompositionApprovalDigest(base)},input={schema_version:1,canonical_remote:"origin",canonical_ref:"refs/heads/main",expected_remote_commit:h("7"),expected_product_commit:"a798bf022659983f0fc7c786ce2de358ff9ab80f",approved_generation,manifest,product_predecessor:{commit:"a798bf022659983f0fc7c786ce2de358ff9ab80f",clean:true},observation:{remote:"origin",ref:"refs/heads/main",advertised_commit:h("7"),fetched_commit:h("7"),reachable:true,generation,product_commit:"a798bf022659983f0fc7c786ce2de358ff9ab80f",members}};assert.equal(keep.verifyDecompositionPublication(input).code,"ADVANCED");assert.equal(members.some(x=>x.path.includes("custody")),true);assert.equal(members.some(x=>x.path.includes("isolation")),true);input.observation.members=members.filter(x=>!x.path.includes("custody"));assert.equal(keep.verifyDecompositionPublication(input).code,"DECOMPOSITION_NOT_DURABLE");
});

test("PG-04-T008 installed enterprise: attributed custody activates once and rejects local substitution",()=>{
  const h=c=>c.repeat(64),generation=`sha256:${h("a")}`,authority={kind:"enterprise",organization_id:"org",actor_id:"alice",role_id:"maintainer",separation_policy_id:"sod",custody_evidence_digest:h("d"),isolation_evidence_digest:h("e"),local_owner_substitution:false},request={schema_version:1,expected_generation:generation,approved_generation:{generation,publication_receipt_digest:h("b"),remote_readback_commit:h("c"),remote_ref_matched:true,tickets:[{ticket_id:"PG-04-T009",dependency_ticket_ids:["PG-04-T008"],track:"enterprise"}]},state:{schema_version:1,active_generation:generation,active_ticket_id:null,closed_ticket_ids:["PG-04-T008"]},selected_ticket_id:"PG-04-T009",authority,implementation_authorized:false};
  const result=keep.activateTicketResearch(request);assert.equal(result.code,"TICKET_RESEARCH_AUTHORIZED");assert.equal(result.receipt.track,"enterprise");assert.deepEqual(result.receipt.authority,authority);assert.equal(result.receipt.implementation_authorized,false);
  request.authority={kind:"n1",owner_id:"owner",custody_id:"local",organization_services:"ABSENT"};assert.equal(keep.activateTicketResearch(request).code,"TRACK_AUTHORITY_SUBSTITUTION");
});

test("PG-04-T008 repair installed enterprise: SG suffix progress preserves attributed custody",()=>{
  const h=c=>c.repeat(64),generation=`sha256:${h("a")}`,authority={kind:"enterprise",organization_id:"org",actor_id:"alice",role_id:"maintainer",separation_policy_id:"sod",custody_evidence_digest:h("d"),isolation_evidence_digest:h("e"),local_owner_substitution:false},activation={schema_version:1,expected_generation:generation,approved_generation:{generation,publication_receipt_digest:h("b"),remote_readback_commit:h("c"),remote_ref_matched:true,tickets:[{ticket_id:"SG-01-T003B",dependency_ticket_ids:["SG-01-T003"],track:"enterprise"}]},state:{schema_version:1,active_generation:generation,active_ticket_id:null,closed_ticket_ids:["SG-01-T003"]},selected_ticket_id:"SG-01-T003B",authority,implementation_authorized:false};
  assert.equal(keep.isTicketResearchIdV1("SG-01-T003B"),true);const admitted=keep.activateTicketResearch(activation);assert.equal(admitted.code,"TICKET_RESEARCH_AUTHORIZED");assert.deepEqual(admitted.receipt.authority,authority);
  const progress=keep.validateTicketResearchProgressV1({activation,receipt:admitted.receipt,current_state:{...activation.state,active_ticket_id:"SG-01-T003B"}});assert.equal(progress.code,"TICKET_RESEARCH_PROGRESS_VALID");assert.equal(progress.progress.ticket_status,"ACTIVE");assert.equal(progress.progress.closed_in_generation_count,0);assert.deepEqual(progress.progress.closed_outside_generation,["SG-01-T003"]);assert.equal(progress.progress.authoritative,false);assert.equal(progress.progress.receipt_digest,admitted.receipt.receipt_digest);
});

function t014EnterpriseRequest(label) { return {...decompositionResultReplayFixture("enterprise"),schema_version:1,data_directory:mkdtempSync(join(tmpdir(),`keep-t014-enterprise-${label}-`)),custody_evidence:"PRESENT",isolation_evidence:"PRESENT",public_seam_authorized:true,implementation_authorized:false}; }

function enterpriseDomainEvents(bundle,runId){return bundle.events.map(row=>({...JSON.parse(row.proposal.payload.domain_json),run_id:runId}));}
function t002EnterpriseRequest(label,root=mkdtempSync(join(tmpdir(),`keep-t002-enterprise-${label}-`))){const run_id=`installed-t002-${label}`,goal_request=enterpriseGoalLifecycleFixture("approver"),goal_events=[];for(let i=0;;i++){const event=keep.nextGoalAuthorityEventV1(run_id,goal_request,i);if(event===null)break;goal_events.push(event)}const prior=decompositionResultReplayFixture("enterprise"),{privateKey,publicKey}=generateKeyPairSync("ed25519");return {schema_version:1,project_id:`project-${label}`,run_id,data_directory:join(root,"data"),history_directory:join(root,"history"),witness_directory:join(root,"witness"),organization_id:"org",tenant_id:"tenant",actor_id:"alice",actor_role_id:"approver",separation_policy_id:"sod",custody_id:"org-custody",isolation_id:"isolation",custody_evidence_digest:"a".repeat(64),isolation_evidence_digest:"b".repeat(64),witness_private_key:privateKey.export({type:"pkcs8",format:"pem"}).toString(),witness_public_key:publicKey.export({type:"spki",format:"pem"}).toString(),goal_request,goal_events,review_events:enterpriseDomainEvents(prior.review_history,run_id),approval_events:enterpriseDomainEvents(prior.approval_history,run_id),activation:prior.activation};}

test("SG-01-T002 installed enterprise: fresh process reconstructs after disposable views are deleted",async()=>{const root=mkdtempSync(join(tmpdir(),"keep-t002-enterprise-fresh-"));try{const child=spawnSync(process.execPath,[fileURLToPath(import.meta.url)],{env:{...process.env,KEEP_ENTERPRISE_T002_COMPLETE_ROOT:root},encoding:"utf8"});assert.equal(child.status,0,child.stderr||child.stdout);const request=JSON.parse(readFileSync(join(root,"request.json"),"utf8")),first=JSON.parse(readFileSync(join(root,"receipt.json"),"utf8"));rmSync(request.data_directory,{recursive:true,force:true});const {witness_private_key:_,...recovery}=request,restarted=await keep.recoverEnterpriseEventAuthorityJourneyV1(recovery);assert.equal(restarted.code,"ENTERPRISE_EVENT_AUTHORITY_RECOVERED");assert.equal(restarted.receipt.receipt_digest,first.receipt_digest);assert.equal(restarted.receipt.tenant_id,"tenant");}finally{rmSync(root,{recursive:true,force:true})}});

test("SG-01-T002 installed enterprise: real process death quarantines the unwitnessed tail",async()=>{const root=mkdtempSync(join(tmpdir(),"keep-t002-enterprise-crash-"));try{const child=spawnSync(process.execPath,[fileURLToPath(import.meta.url)],{env:{...process.env,KEEP_ENTERPRISE_T002_CRASH_ROOT:root},encoding:"utf8"});assert.equal(child.signal,"SIGKILL",child.stderr||child.stdout);const request=JSON.parse(readFileSync(join(root,"request.json"),"utf8")),{witness_private_key:_,...recovery}=request;rmSync(request.data_directory,{recursive:true,force:true});const result=await keep.recoverEnterpriseEventAuthorityJourneyV1(recovery);assert.equal(result.code,"ENTERPRISE_UNWITNESSED_TAIL_RECOVERED");assert.equal(result.recovery.streams.approval.status,"TAIL_QUARANTINED");assert.equal(result.recovery.streams.goal.status,"WITNESSED");assert.equal(result.recovery.streams.review.status,"WITNESSED");}finally{rmSync(root,{recursive:true,force:true})}});

test("PG-05-T014 installed enterprise: replay-bound evidence persists attributed tenant custody",()=>{
  const request=t014EnterpriseRequest("direct"),fresh=keep.runEnterpriseDecompositionJourney(request);assert.equal(fresh.code,"ENTERPRISE_DECOMPOSITION_JOURNEY_COMPLETE");assert.equal(fresh.receipt.active_ticket_id,"PG-05-T014");assert.equal(fresh.receipt.track,"enterprise");assert.equal(fresh.receipt.authority.tenant_id,"tenant");assert.equal(fresh.receipt.authority.custody_id,"org-custody");assert.equal(fresh.receipt.authority.isolation_id,"isolation");assert.equal(fresh.receipt.lifecycle_authoritative,false);assert.deepEqual(fresh.stage_invocations,{reconstruction:1,activation:1});const recovered=keep.recoverEnterpriseDecompositionJourney(request);assert.equal(recovered.code,"ENTERPRISE_DECOMPOSITION_JOURNEY_RECOVERED");assert.equal(recovered.receipt.event_digest,fresh.receipt.event_digest);
});

test("PG-05-T014 installed enterprise: custody, isolation, local substitution and implementation claims fail before persistence",()=>{
  const custody=t014EnterpriseRequest("custody");custody.custody_evidence="MISSING";assert.equal(keep.runEnterpriseDecompositionJourney(custody).code,"ENTERPRISE_CUSTODY_MISSING");const isolation=t014EnterpriseRequest("isolation");isolation.isolation_evidence="MISSING";assert.equal(keep.runEnterpriseDecompositionJourney(isolation).code,"ENTERPRISE_CUSTODY_MISSING");const local=t014EnterpriseRequest("local");local.activation.authority={kind:"n1",owner_id:"owner",custody_id:"local",organization_services:"ABSENT"};assert.equal(keep.runEnterpriseDecompositionJourney(local).code,"TRACK_AUTHORITY_SUBSTITUTION");const claimed=t014EnterpriseRequest("claim");claimed.implementation_authorized=true;assert.equal(keep.runEnterpriseDecompositionJourney(claimed).code,"DECOMPOSITION_CANNOT_AUTHORIZE_IMPLEMENTATION");
});

test("PG-05-T014 installed enterprise: foreign tenant and legacy bytes cannot recover authority",()=>{
  const request=t014EnterpriseRequest("foreign");const fresh=keep.runEnterpriseDecompositionJourney(request);assert.equal(fresh.code,"ENTERPRISE_DECOMPOSITION_JOURNEY_COMPLETE");const path=join(request.data_directory,"enterprise-decomposition-result-event-v1.json"),foreign=JSON.parse(readFileSync(path,"utf8"));foreign.authority.tenant_id="foreign";writeFileSync(path,JSON.stringify(foreign));assert.equal(keep.recoverEnterpriseDecompositionJourney(request).code,"TENANT_ISOLATION_MISMATCH");writeFileSync(path,JSON.stringify({schema_version:1,status:"ENTERPRISE_DECOMPOSITION_JOURNEY_COMPLETE"}));assert.equal(keep.recoverEnterpriseDecompositionJourney(request).code,"LEGACY_AUTHORITY_GAP");
});
