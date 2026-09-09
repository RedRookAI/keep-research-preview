import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const installedRoot = process.env.KEEP_INSTALLED_PACKAGE_ROOT;
if (!installedRoot) throw new Error("KEEP_INSTALLED_PACKAGE_ROOT is required");
const keep = await import(pathToFileURL(join(installedRoot, "dist", "src", "index.js")).href);
const here = fileURLToPath(import.meta.url);
const H = (character) => character.repeat(64);
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value !== null && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const digest = (value) => createHash("sha256").update(canonical(value)).digest("hex");
const body = { id: "SG-01-T003B", title: "Resume installed YOLO work after process loss", requirements: ["one bounded step"], finish_conditions: ["fresh process resumes"], research_contract: { lanes: ["current", "historical", "cross"] }, mutation_surface: ["coordinator"], scope_rows: ["K-001"], resource_bounds: { peak_ram_mib: 2048, peak_disk_mib: 10240, max_parallel_processes: 3 } };
const wipBody = { id: "SG-01-T004", title: "Publish and restore hourly WIP", requirements: ["publish hourly WIP"], finish_conditions: ["blank restore matches"], research_contract: { lanes: ["current", "historical", "cross"] }, mutation_surface: ["src/backup/hourly_wip_supervisor_v1.ts"], scope_rows: ["K-002"], resource_bounds: { peak_ram_mib: 512, peak_disk_mib: 3072, max_parallel_processes: 1 } };
const closureBody = { id: "SG-01-T005", title: "Close exact recovered ticket", requirements: ["close exact remotely recovered bytes"], finish_conditions: ["both direct tracks and authenticated readback pass"], research_contract: { lanes: ["current", "historical", "cross"] }, mutation_surface: ["src/backup/ticket_closure_supervisor_v1.ts"] };

function research(track) {
  const generation = `sha256:${H("a")}`;
  const activation = { schema_version: 1, approved_generation: { generation, publication_receipt_digest: H("d"), remote_readback_commit: "b".repeat(40), remote_ref_matched: true, tickets: [{ ticket_id: "PG-04-T008", track, dependency_ticket_ids: [] }, { ticket_id: "SG-01-T003B", track, dependency_ticket_ids: ["PG-04-T008"] }] }, state: { schema_version: 1, active_generation: generation, active_ticket_id: null, closed_ticket_ids: ["PG-04-T008"] }, selected_ticket_id: "SG-01-T003B", expected_generation: generation, authority: track === "n1" ? { kind: "n1", owner_id: "owner", custody_id: "local", organization_services: "ABSENT" } : { kind: "enterprise", organization_id: "org", actor_id: "agent", role_id: "maintainer", separation_policy_id: "sod", custody_evidence_digest: H("c"), isolation_evidence_digest: H("e"), local_owner_substitution: false }, implementation_authorized: false };
  const activated = keep.activateTicketResearch(activation); assert.equal(activated.advanced, true);
  return { activation, receipt: activated.receipt, current_state: { schema_version: 1, active_generation: generation, active_ticket_id: "SG-01-T003B", closed_ticket_ids: ["PG-04-T008"] } };
}

function wipResearch(track) {
  const generation = `sha256:${H("a")}`, authority = track === "n1" ? { kind: "n1", owner_id: "owner", custody_id: "owner-custody", organization_services: "ABSENT" } : { kind: "enterprise", organization_id: "org", actor_id: "agent", role_id: "maintainer", separation_policy_id: "sod", custody_evidence_digest: H("c"), isolation_evidence_digest: H("e"), local_owner_substitution: false };
  const activation = { schema_version: 1, approved_generation: { generation, publication_receipt_digest: H("d"), remote_readback_commit: "b".repeat(40), remote_ref_matched: true, tickets: [{ ticket_id: "PG-04-T008", track, dependency_ticket_ids: [] }, { ticket_id: "SG-01-T003B", track, dependency_ticket_ids: ["PG-04-T008"] }, { ticket_id: "SG-01-T004", track, dependency_ticket_ids: ["SG-01-T003B"] }] }, state: { schema_version: 1, active_generation: generation, active_ticket_id: null, closed_ticket_ids: ["PG-04-T008", "SG-01-T003B"] }, selected_ticket_id: "SG-01-T004", expected_generation: generation, authority, implementation_authorized: false };
  const activated = keep.activateTicketResearch(activation); assert.equal(activated.advanced, true);
  return { activation, receipt: activated.receipt, current_state: { schema_version: 1, active_generation: generation, active_ticket_id: "SG-01-T004", closed_ticket_ids: ["PG-04-T008", "SG-01-T003B"] } };
}

const facts = { requested_scope_ids: ["K-001"], protected_workload_effects: [], requested_effects: [{ description: "isolated blank-install fixture", class: "pure-local" }], requested_vet_round: 0, resources: { estimated_ram_mib: 64, estimated_disk_mib: 10, estimated_processes: 1 } };

if (process.env.KEEP_SG01_T005_CHILD === "1") {
  const request = JSON.parse(readFileSync(process.env.KEEP_SG01_T005_REQUEST, "utf8"));
  let protectedDenied = false; try { readFileSync(request.denied_path); } catch (error) { protectedDenied = error?.code === "ERR_ACCESS_DENIED" || error?.code === "ENOENT"; }
  if (!protectedDenied) throw new Error("installed closure child reached protected host path");
  for (const symbol of ["TicketClosureSupervisorV1", "InvalidTicketClosureError", "TicketClosureEvidenceMismatchError", "TicketClosureEffectOutcomeUnresolvedError", "TicketClosureFailedError", "TicketClosureRetryableError"]) if (typeof keep[symbol] !== "function") throw new Error(`package-root export missing: ${symbol}`);
  const trackAuthority = (track) => track === "n1" ? { kind: "n1", owner_id: "owner", custody_id: "owner-custody", organization_services: "ABSENT" } : { kind: "enterprise", organization_id: "org", tenant_id: "tenant", actor_id: "agent", role_id: "maintainer", separation_policy_id: "sod", custody_id: "org-custody", isolation_id: "isolated", custody_evidence_digest: H("c"), isolation_evidence_digest: H("e"), local_owner_substitution: false };
  const stores = { n1: new keep.FileWorkAttemptAuthorityV1("/work/attempt-n1"), enterprise: new keep.FileWorkAttemptAuthorityV1("/work/attempt-enterprise") };
  const admitted = {};
  for (const track of ["n1", "enterprise"]) admitted[track] = await stores[track].admit({ project_id: "project", goal_id: "goal", subgoal_id: "SG-01", ticket_id: "SG-01-T005", ticket_body: closureBody, ticket_body_digest: digest(closureBody), failure_lessons: [{ id: "FL-009", digest: H("f") }], track, authority: trackAuthority(track), product_commit: "a".repeat(40), interpreter_identity: process.version });
  const refs = Object.fromEntries(["n1", "enterprise"].map((track) => [track, { identity_digest: admitted[track].identity_digest, attempt_id: admitted[track].attempt_id, generation: admitted[track].generation }]));
  let fences = { n1: stores.n1.fence(refs.n1), enterprise: stores.enterprise.fence(refs.enterprise) };
  writeFileSync("/work/retained.tgz", "real bounded installed artifact bytes\n"); const artifact = createHash("sha256").update(readFileSync("/work/retained.tgz")).digest("hex");
  const subject = { project_id: "project", goal_id: "goal", subgoal_id: "SG-01", ticket_id: "SG-01-T005", approved_ticket_body_json: JSON.stringify(closureBody), approved_ticket_body_sha256: createHash("sha256").update(JSON.stringify(closureBody)).digest("hex"), attempt_fence_ticket_body_digest: digest(closureBody), product_commit: "a".repeat(40), closure_profile_sha256: H("1"), lockfile_sha256: H("2"), build_recipe_sha256: H("3"), environment_identity_sha256: H("4"), retained_artifact_sha256: artifact, n1_authority_digest: digest(trackAuthority("n1")), enterprise_authority_digest: digest(trackAuthority("enterprise")), source_remote: "fixture/source#candidate", artifact_remote: "fixture/artifact#release", attempts: refs };
  const results = ["PASS", "REMOTE_SHA_MATCH", "PASS", "PASS", "PASS", "PASS", "PASS", "PASS", "REMOTE_IDENTITY_RECORDED", "REMOTE_IDENTITIES_MATCH", "DIGEST_ARCHIVE_REINSTALL_RESTART_BOUNDED_SMOKE_PASS", "COMPLETE"];
  const stepFacts = [{ clean: true, source_commit: subject.product_commit }, { authenticated: true, source_commit: subject.product_commit, source_remote: subject.source_remote }, { focused_sha256: H("5"), portable_sha256: H("6"), full_native_sha256: H("7") }, { artifact_sha256: artifact }, { manifest_sha256: H("8") }, { archive_inspection_sha256: H("9"), artifact_sha256: artifact }, { artifact_sha256: artifact, blank_install_sha256: H("a") }, { artifact_sha256: artifact, installed_tracks_sha256: H("b") }, { artifact_remote: subject.artifact_remote, artifact_sha256: artifact, asset_id: "asset-1", authenticated: true, state: "uploaded" }, { artifact_sha256: artifact, authenticated_readback_sha256: H("c"), source_commit: subject.product_commit }, { artifact_sha256: artifact, retrieved_smoke_sha256: H("d") }, { conjunction_sha256: H("e") }];
  const stepResult = (index) => ({ result: results[index], facts: stepFacts[index], ...([6, 7, 10].includes(index) ? { tracks: { n1: { authority_digest: subject.n1_authority_digest, artifact_sha256: artifact, evidence_sha256: createHash("sha256").update(`installed-n1-${index}`).digest("hex"), direct: true, result: "PASS" }, enterprise: { authority_digest: subject.enterprise_authority_digest, artifact_sha256: artifact, evidence_sha256: createHash("sha256").update(`installed-enterprise-${index}`).digest("hex"), direct: true, result: "PASS" } } } : {}) });
  const effects = [];
  const port = { observe: async (operation) => operation.completion_index === 1 ? { status: "MATCH", operation_id: operation.operation_id, value: stepResult(1) } : { status: "ABSENT" }, execute: async (operation) => { effects.push(operation.operation_id); return stepResult(operation.completion_index); } };
  const supervisor = new keep.TicketClosureSupervisorV1("/work/closure", subject);
  while (supervisor.status().completed_indices.length < 8) await supervisor.advance(fences, port);
  const expectedRemoteOperation = createHash("sha256").update(subject.ticket_id).update("\0").update(digest(subject)).update("\0").update("8").digest("hex");
  const nextN1 = await stores.n1.takeover(fences.n1.reference), nextEnterprise = await stores.enterprise.takeover(fences.enterprise.reference);
  fences = { n1: stores.n1.fence(nextN1), enterprise: stores.enterprise.fence(nextEnterprise) };
  while (supervisor.status().completed_indices.length < 11) await supervisor.advance(fences, port);
  const partial = supervisor.status();
  let mixedRefused = false; try { new keep.TicketClosureSupervisorV1("/work/mixed", { ...subject, enterprise_authority_digest: subject.n1_authority_digest }); } catch (error) { mixedRefused = error?.name === "InvalidTicketClosureError"; }
  const ambiguous = new keep.TicketClosureSupervisorV1("/work/ambiguous", subject), ambiguityEffects = [];
  const ambiguousPort = { observe: async (operation) => operation.completion_index === 1 ? { status: "MATCH", operation_id: operation.operation_id, value: stepResult(1) } : operation.completion_index === 8 ? { status: "UNKNOWN", reason: "ambiguous transport" } : { status: "ABSENT" }, execute: async (operation) => { ambiguityEffects.push(operation); return stepResult(operation.completion_index); } };
  while (ambiguous.status().completed_indices.length < 8) await ambiguous.advance(fences, ambiguousPort);
  try { await ambiguous.advance(fences, ambiguousPort); } catch (error) { if (error?.name !== "TicketClosureEffectOutcomeUnresolvedError") throw error; }
  await supervisor.advance(fences, port); const complete = supervisor.status(); const restarted = new keep.TicketClosureSupervisorV1("/work/closure", subject).status();
  const selectedAuthority = request.track === "n1" ? admitted.n1.identity.authority : admitted.enterprise.identity.authority;
  writeFileSync(request.output, `${JSON.stringify({ requested_track: request.track, selected_authority_kind: selectedAuthority.kind, selected_authority_detail: request.track === "n1" ? selectedAuthority.organization_services : selectedAuthority.tenant_id, partial_state: partial.state, partial_percentage: partial.completion_percentage, complete_state: complete.state, restart_state: restarted.state, evidence_count_n1: supervisor.load("n1").evidence.length, evidence_count_enterprise: supervisor.load("enterprise").evidence.length, distinct_track_evidence: supervisor.load("n1").evidence[10].tracks.n1.evidence_sha256 !== supervisor.load("enterprise").evidence[10].tracks.enterprise.evidence_sha256, mixed_refused: mixedRefused, protected_denied: protectedDenied, effects_count: effects.length, effects_unique: new Set(effects).size === effects.length, takeover_operation_stable: effects.includes(expectedRemoteOperation), ambiguous_state: ambiguous.status().state, ambiguous_remote_effects: ambiguityEffects.filter((operation) => operation.completion_index === 8).length })}\n`);
  process.exit(0);
}

if (process.env.KEEP_SG01_T004_CHILD === "1") {
  const request = JSON.parse(readFileSync(process.env.KEEP_SG01_T004_REQUEST, "utf8"));
  let protectedDenied = false; try { readFileSync(request.denied_path); } catch (error) { protectedDenied = error?.code === "ERR_ACCESS_DENIED" || error?.code === "ENOENT"; }
  if (!protectedDenied) throw new Error("isolated WIP child reached the protected-root analogue");
  const source = "/work/source", remote = "/work/remote.git"; mkdirSync(source); mkdirSync(remote);
  const git = new keep.GitAdapter(source); await git.git(["init"]); await git.git(["config", "user.name", "Installed WIP"]); await git.git(["config", "user.email", "wip@invalid"]);
  writeFileSync(join(source, "tracked.txt"), "base\n"); await git.git(["add", "tracked.txt"]); await git.git(["commit", "-m", "base"]); const base = (await git.git(["rev-parse", "HEAD"])).stdout.trim();
  const remoteGit = new keep.GitAdapter(remote); await remoteGit.git(["init", "--bare"]); const remoteUrl = "file:///work/remote.git"; await git.git(["remote", "add", "origin", remoteUrl]); await git.git(["push", "origin", "HEAD:refs/heads/main"]);
  writeFileSync(join(source, "tracked.txt"), "staged\n"); await git.git(["add", "tracked.txt"]); writeFileSync(join(source, "tracked.txt"), "worktree\n"); writeFileSync(join(source, "new.txt"), `${request.track} untracked\n`);
  const authority = request.track === "n1" ? { kind: "n1", owner_id: "owner", custody_id: "owner-custody", organization_services: "ABSENT" } : { kind: "enterprise", organization_id: "org", tenant_id: "tenant", actor_id: "agent", role_id: "maintainer", separation_policy_id: "sod", custody_id: "org-custody", isolation_id: "isolated", custody_evidence_digest: H("c"), isolation_evidence_digest: H("e"), local_owner_substitution: false };
  const identity = { project_id: "project", goal_id: "goal", subgoal_id: "SG-01", ticket_id: "SG-01-T004", ticket_body: wipBody, ticket_body_digest: digest(wipBody), failure_lessons: [{ id: "FL-004", digest: H("f") }], track: request.track, authority, product_commit: base, interpreter_identity: process.version };
  const attemptAuthority = new keep.FileWorkAttemptAuthorityV1("/work/attempt"); const admitted = await attemptAuthority.admit(identity); const reference = { identity_digest: admitted.identity_digest, attempt_id: admitted.attempt_id, generation: admitted.generation };
  const hash = (domain, value) => createHash("sha256").update(`${domain}\0`).update(value).digest("hex");
  const port = new keep.GitWipPublicationPortV1({ workspace_root: "/work/publication", remote: "recovery", fetch_url: remoteUrl, push_url: remoteUrl, fetch_url_sha256: hash("keep.git-fetch-url/v1", remoteUrl), push_url_sha256: hash("keep.git-push-url/v1", remoteUrl), git_factory: (root) => new keep.GitAdapter(root) });
  const supervisor = new keep.HourlyWipSupervisorV1("/work/state", port); const recoveryRef = `refs/heads/keep-wip/${request.track}/${admitted.identity_digest}`;
  const composed = await keep.runYoloTicketStepWithHourlyWipV1({ coordinator: new keep.YoloTicketCoordinatorV1(), coordinator_input: { attempt_authority: attemptAuthority, attempt: reference, configured_posture: "autonomous", research_progress: wipResearch(request.track), boundary_facts: { requested_scope_ids: ["K-002"], protected_workload_effects: [], requested_effects: [{ description: "isolated hourly recovery", class: "pure-local" }], requested_vet_round: 0, resources: { estimated_ram_mib: 64, estimated_disk_mib: 10, estimated_processes: 1 } }, action: async () => ({ outcome: "ADVANCE", evidence_digest: H("9") }) }, supervisor, wip_request: { project_root: source, git, allowlist: ["new.txt", "tracked.txt"], last_result: "installed focused checks pending", next_action: "resume exact ticket" }, now_ms: 51 * 3_600_000 }); const result = composed.wip; if (!result) throw new Error("composed WIP trigger did not run");
  assert.equal(result.status, "REMOTE_VERIFIED", JSON.stringify(result));
  if (readdirSync("/work/publication").length !== 0) throw new Error("verified WIP left unbounded prepared state"); rmSync(source, { recursive: true }); rmSync("/work/state", { recursive: true }); rmSync("/work/publication", { recursive: true }); rmSync("/work/attempt", { recursive: true });
  const recoveryPort = new keep.GitWipPublicationPortV1({ workspace_root: "/work/recovery", remote: "recovery", fetch_url: remoteUrl, push_url: remoteUrl, fetch_url_sha256: hash("keep.git-fetch-url/v1", remoteUrl), push_url_sha256: hash("keep.git-push-url/v1", remoteUrl), git_factory: (root) => new keep.GitAdapter(root) });
  const expected = { attempt: { identity_digest: admitted.identity_digest, attempt_id: admitted.attempt_id, generation: admitted.generation, track: admitted.identity.track, authority: admitted.identity.authority, product_commit: admitted.identity.product_commit, interpreter_identity: admitted.identity.interpreter_identity } };
  const readback = await recoveryPort.recover(recoveryRef, expected); await recoveryPort.materialize(readback, "/work/restored", expected); const restoredGit = new keep.GitAdapter("/work/restored");
  const tampered = structuredClone(readback.snapshot); tampered.attempt.authority = request.track === "n1" ? { ...authority, owner_id: "substitute" } : { kind: "n1", owner_id: "owner", custody_id: "owner-custody", organization_services: "ABSENT" }; const oldDigest = tampered.manifest_sha256; delete tampered.manifest_sha256; tampered.manifest_sha256 = digest(tampered); let substitutionRefused = false; try { await recoveryPort.materialize({ ...readback, snapshot: tampered }, "/work/substituted", expected); } catch { substitutionRefused = true; } if (!substitutionRefused || tampered.manifest_sha256 === oldDigest) throw new Error("re-digested identity substitution was not independently refused");
  writeFileSync(request.output, `${JSON.stringify({ status: result.status, combined_effects_performed: composed.combined_effects_performed, transition_count: composed.step.attempt.transitions.length, completion_basis_points: composed.step.status.completion.basis_points, track: readback.snapshot.attempt.track, authority: readback.snapshot.attempt.authority, identity_digest: readback.snapshot.attempt.identity_digest, attempt_id: readback.snapshot.attempt.attempt_id, generation: readback.snapshot.attempt.generation, base_commit: readback.snapshot.base_commit, tampered_refused: substitutionRefused, tracked: readFileSync("/work/restored/tracked.txt", "utf8"), untracked: readFileSync("/work/restored/new.txt", "utf8"), index: (await restoredGit.git(["show", ":tracked.txt"])).stdout, dirty_status: (await restoredGit.git(["status", "--porcelain=v1", "--untracked-files=all", "--no-renames"])).stdout, protected_denied: protectedDenied })}\n`);
  process.exit(0);
}

if (process.env.KEEP_SG01_T003B_CHILD === "1") {
  const request = JSON.parse(readFileSync(process.env.KEEP_SG01_T003B_REQUEST, "utf8"));
  const attempt_authority = new keep.FileWorkAttemptAuthorityV1(request.attempt_directory);
  try {
    let protectedDenied = false; try { readFileSync(request.denied_path); } catch (error) { protectedDenied = error?.code === "ERR_ACCESS_DENIED" || error?.code === "ENOENT"; }
    if (!protectedDenied) throw new Error("isolated child reached the protected-root analogue");
    if (request.crash_point === "before-work") process.kill(process.pid, "SIGKILL");
    const result = await new keep.YoloTicketCoordinatorV1().step({ attempt_authority, attempt: request.attempt, configured_posture: "autonomous", research_progress: request.research, boundary_facts: facts,
      action: async (stage) => { writeFileSync(request.action_marker, `${stage}\n`, { flag: "a" }); if (request.crash_point === "after-work-before-record") process.kill(process.pid, "SIGKILL"); return { outcome: "ADVANCE", evidence_digest: digest({ stage, track: request.track }) }; },
      status_sink: { publish: () => { if (request.crash_point === "after-record") process.kill(process.pid, "SIGKILL"); } },
    });
    writeFileSync(request.output, `${JSON.stringify({ code: result.code, next_stage: result.status.next_stage, generation: result.status.attempt_generation, track: result.attempt.identity.track, completion: result.status.completion.display, authoritative: result.status.authoritative })}\n`);
  } catch (error) {
    writeFileSync(request.output, `${JSON.stringify({ error: error?.name ?? "Error", code: error?.code ?? null, message: error?.message ?? String(error) })}\n`);
  }
  process.exit(0);
}

function runChild(requestPath) {
  const root = dirname(requestPath), result = spawnSync("bwrap", sandboxArgs(root), { cwd: root, env: { ...process.env, KEEP_INSTALLED_PACKAGE_ROOT: "/keep-installed", KEEP_SG01_T003B_CHILD: "1", KEEP_SG01_T003B_REQUEST: "/work/request.json" }, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
}

function crashChild(requestPath) {
  const root = dirname(requestPath), result = spawnSync("bwrap", sandboxArgs(root), { cwd: root, env: { ...process.env, KEEP_INSTALLED_PACKAGE_ROOT: "/keep-installed", KEEP_SG01_T003B_CHILD: "1", KEEP_SG01_T003B_REQUEST: "/work/request.json" }, encoding: "utf8" });
  assert.equal(result.signal === "SIGKILL" || result.status === 137, true, `${result.status}: ${result.stderr}`);
}

function sandboxArgs(root) {
  // `/bin` is read-only and supplies Git's local receive helper shell; all namespaces and network remain unshared.
  return ["--unshare-all", "--die-with-parent", "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64", "--ro-bind", "/etc", "/etc", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", root, "/work", "--ro-bind", installedRoot, "/keep-installed", "--ro-bind", dirname(here), "/acceptance", "--chdir", "/work", process.execPath, `/acceptance/${here.split("/").at(-1)}`];
}

for (const track of ["n1", "enterprise"]) test(`SG-01-T003-C09/C14/C15/C17 installed ${track}: isolated fresh processes resume and stale generation is fenced`, async () => {
  const root = mkdtempSync(join(tmpdir(), `keep-installed-sg01-t003b-${track}-`)), attemptDirectory = join(root, "attempt"), output = join(root, "result.json"), requestPath = join(root, "request.json"), actionMarker = join(root, "actions.txt");
  const attempt_authority = new keep.FileWorkAttemptAuthorityV1(attemptDirectory);
  const workAuthority = track === "n1" ? { kind: "n1", owner_id: "owner", custody_id: "local", organization_services: "ABSENT" } : { kind: "enterprise", organization_id: "org", tenant_id: "tenant", actor_id: "agent", role_id: "maintainer", separation_policy_id: "sod", custody_id: "org-custody", isolation_id: "iso", custody_evidence_digest: H("c"), isolation_evidence_digest: H("e"), local_owner_substitution: false };
  const admitted = await attempt_authority.admit({ project_id: `prj_${track === "n1" ? "1".repeat(32) : "2".repeat(32)}`, goal_id: "goal", subgoal_id: "SG-01", ticket_id: "SG-01-T003B", ticket_body: body, ticket_body_digest: digest(body), failure_lessons: [{ id: "FL-004", digest: H("f") }], track, authority: workAuthority, product_commit: "9".repeat(40), interpreter_identity: process.version });
  const deniedRoot = mkdtempSync(join(tmpdir(), "keep-installed-protected-analogue-")), deniedPath = join(deniedRoot, "sentinel"); writeFileSync(deniedPath, "must remain unreachable\n");
  const old = { identity_digest: admitted.identity_digest, attempt_id: admitted.attempt_id, generation: admitted.generation }, request = { attempt_directory: "/work/attempt", attempt: old, research: research(track), track, output: "/work/result.json", action_marker: "/work/actions.txt", denied_path: "/protected/sentinel", crash_point: "before-work" };
  writeFileSync(requestPath, JSON.stringify(request)); crashChild(requestPath); assert.equal(attempt_authority.load(old).transitions.length, 0);
  request.crash_point = "after-work-before-record"; writeFileSync(requestPath, JSON.stringify(request)); crashChild(requestPath); assert.equal(attempt_authority.load(old).transitions.length, 0); assert.equal(readFileSync(actionMarker, "utf8").trim().split("\n").length, 1);
  request.crash_point = null; writeFileSync(requestPath, JSON.stringify(request)); runChild(requestPath); let result = JSON.parse(readFileSync(output, "utf8"));
  assert.deepEqual(result, { code: "ADVANCED", next_stage: "RESEARCH_COMPLETE", generation: 0, track, completion: "1/2 (50.00%)", authoritative: false });
  request.crash_point = "after-record"; writeFileSync(requestPath, JSON.stringify(request)); crashChild(requestPath); assert.equal(attempt_authority.load(old).transitions.length, 2);
  request.crash_point = null; writeFileSync(requestPath, JSON.stringify(request)); runChild(requestPath); result = JSON.parse(readFileSync(output, "utf8")); assert.equal(result.next_stage, "IMPLEMENTING");
  const successor = await attempt_authority.takeover(old); runChild(requestPath); assert.equal(JSON.parse(readFileSync(output, "utf8")).error, "StaleWorkAttemptError");
  request.attempt = { identity_digest: successor.identity_digest, attempt_id: successor.attempt_id, generation: successor.generation }; writeFileSync(requestPath, JSON.stringify(request)); runChild(requestPath); result = JSON.parse(readFileSync(output, "utf8"));
  assert.equal(result.code, "ADVANCED"); assert.equal(result.generation, 1); assert.equal(result.next_stage, "CANDIDATE_FROZEN");
});

for (const track of ["n1", "enterprise"]) test(`SG-01-T004-C10/C11/C12/C13 installed ${track}: remote WIP restores exactly in a networkless blank sandbox`, () => {
  const root = mkdtempSync(join(tmpdir(), `keep-installed-sg01-t004-${track}-`)), output = join(root, "wip-result.json"), requestPath = join(root, "wip-request.json"), protectedRoot = mkdtempSync(join(tmpdir(), "keep-installed-real-protected-")), protectedSentinel = join(protectedRoot, "sentinel"); writeFileSync(protectedSentinel, "host-visible-only\n"); assert.equal(readFileSync(protectedSentinel, "utf8"), "host-visible-only\n");
  writeFileSync(requestPath, JSON.stringify({ track, output: "/work/wip-result.json", denied_path: protectedSentinel }));
  const result = spawnSync("bwrap", sandboxArgs(root), { cwd: root, env: { ...process.env, KEEP_INSTALLED_PACKAGE_ROOT: "/keep-installed", KEEP_SG01_T004_CHILD: "1", KEEP_SG01_T004_REQUEST: "/work/wip-request.json" }, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr); const observed = JSON.parse(readFileSync(output, "utf8"));
  assert.equal(observed.status, "REMOTE_VERIFIED"); assert.equal(observed.combined_effects_performed, true); assert.equal(observed.transition_count, 1); assert.equal(observed.completion_basis_points, 6666); assert.equal(observed.track, track); assert.equal(observed.authority.kind, track); assert.equal(observed.tampered_refused, true); assert.equal(observed.tracked, "worktree\n"); assert.equal(observed.untracked, `${track} untracked\n`); assert.equal(observed.index, "staged\n"); assert.equal(observed.dirty_status, "MM tracked.txt\n?? new.txt\n"); assert.equal(observed.protected_denied, true);
  if (track === "n1") assert.equal(observed.authority.organization_services, "ABSENT"); else { assert.equal(observed.authority.tenant_id, "tenant"); assert.equal(observed.authority.local_owner_substitution, false); }
});

for (const track of ["n1", "enterprise"]) test(`SG-01-T005-C02-C04/C08-C13/C15/C16 installed ${track}: exact package closure is track-distinct, resumable, and isolated`, () => {
  const root = mkdtempSync(join(tmpdir(), `keep-installed-sg01-t005-${track}-`)), output = join(root, "closure-result.json"), requestPath = join(root, "closure-request.json"), protectedRoot = mkdtempSync(join(tmpdir(), "keep-installed-t005-protected-")), protectedSentinel = join(protectedRoot, "sentinel");
  writeFileSync(protectedSentinel, "must remain host-only\n"); writeFileSync(requestPath, JSON.stringify({ track, output: "/work/closure-result.json", denied_path: protectedSentinel }));
  const result = spawnSync("bwrap", sandboxArgs(root), { cwd: root, env: { ...process.env, KEEP_INSTALLED_PACKAGE_ROOT: "/keep-installed", KEEP_SG01_T005_CHILD: "1", KEEP_SG01_T005_REQUEST: "/work/closure-request.json" }, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr); const observed = JSON.parse(readFileSync(output, "utf8"));
  assert.deepEqual(observed, { requested_track: track, selected_authority_kind: track, selected_authority_detail: track === "n1" ? "ABSENT" : "tenant", partial_state: "IN_PROGRESS", partial_percentage: 91, complete_state: "COMPLETE", restart_state: "COMPLETE", evidence_count_n1: 12, evidence_count_enterprise: 12, distinct_track_evidence: true, mixed_refused: true, protected_denied: true, effects_count: 11, effects_unique: true, takeover_operation_stable: true, ambiguous_state: "EFFECT_OUTCOME_UNRESOLVED_OWNER_STOP", ambiguous_remote_effects: 0 });
});
