import { DatabaseSync } from "node:sqlite";
import { closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, openSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { KeepHold, SHA256, acceptedResponse, hash, isTerminal, statusResponse } from "./contracts.mjs";

function privateStat(stat, directory = false) {
  if (!(directory ? stat.isDirectory() : stat.isFile()) || (!directory && stat.nlink !== 1)
    || (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid?.()))) throw new KeepHold("private-storage");
}
function credential(path, assertCurrent) {
  assertCurrent();
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = fstatSync(fd); privateStat(stat);
    if (stat.size < 64 || stat.size > 65) throw new KeepHold("credential");
    const token = readFileSync(fd, "utf8").replace(/\n$/u, "");
    if (!SHA256.test(token)) throw new KeepHold("credential");
    return token;
  } finally { closeSync(fd); }
}

/** One private database, no daemon or lease. SQLite serializes short transactions;
 * no transaction or filesystem lock is held across a network await. */
class Journal {
  constructor(directory, scope) {
    scope.assertCurrent();
    const root = lstatSync(directory); privateStat(root, true);
    if (root.isSymbolicLink()) throw new KeepHold("private-storage");
    const path = join(directory, "keep-submissions.sqlite");
    if (!existsSync(path)) {
      try {
        const fd = openSync(path, "wx", 0o600); closeSync(fd);
        if (process.platform !== "win32") { const parent = openSync(directory, "r"); try { fsyncSync(parent); } finally { closeSync(parent); } }
      } catch (error) { if (error.code !== "EEXIST") throw error; }
    }
    for (const file of [path, `${path}-wal`, `${path}-shm`, `${path}-journal`]) if (existsSync(file)) {
      const stat = lstatSync(file); privateStat(stat);
      if (stat.isSymbolicLink()) throw new KeepHold("private-storage");
    }
    scope.assertCurrent();
    this.db = new DatabaseSync(path, { allowExtension: false, enableDoubleQuotedStringLiterals: false, defensive: true });
    try {
      this.db.exec("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;");
      this.transaction(scope, () => {
        const version = this.db.prepare("PRAGMA user_version").get().user_version;
        if (version === 0) {
          if (this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1").get()) throw new KeepHold("journal");
          this.db.exec(`CREATE TABLE submissions (
            id INTEGER PRIMARY KEY, request TEXT NOT NULL UNIQUE, conversation TEXT NOT NULL,
            binding TEXT NOT NULL, call_key TEXT NOT NULL, body TEXT NOT NULL,
            project_id TEXT, job_id TEXT, observation TEXT, terminal INTEGER NOT NULL DEFAULT 0 CHECK(terminal IN (0,1)),
            UNIQUE(binding,call_key)
          ) STRICT;
          CREATE INDEX submissions_conversation ON submissions(conversation,id);
          PRAGMA user_version=1;`);
        } else if (version !== 1) throw new KeepHold("journal");
      });
    } catch (error) { this.db.close(); throw error; }
  }
  transaction(scope, run) {
    scope.assertCurrent(); this.db.exec("BEGIN IMMEDIATE");
    try { const result = run(); scope.assertCurrent(); this.db.exec("COMMIT"); return result; }
    catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }
  latest(scope) { return this.db.prepare("SELECT * FROM submissions WHERE conversation=? ORDER BY id DESC LIMIT 1").get(scope.conversation); }
  submission(scope, binding, goal) {
    return this.transaction(scope, () => {
      const same = this.db.prepare("SELECT * FROM submissions WHERE binding=? AND call_key=?").get(binding, scope.call);
      if (same) {
        if (same.conversation !== scope.conversation || JSON.parse(same.body).goal !== goal) throw new KeepHold("conflict");
        return { record: same, previous: false };
      }
      const previous = this.latest(scope);
      if (previous && !previous.terminal) return { record: previous, previous: true };
      const request = `keep:${hash(["keep.openclaw-request/v1", binding, scope.conversation, scope.call])}`;
      const body = JSON.stringify({ goal, idempotencyKey: request });
      this.db.prepare("INSERT INTO submissions(request,conversation,binding,call_key,body) VALUES (?,?,?,?,?)")
        .run(request, scope.conversation, binding, scope.call, body);
      return { record: this.db.prepare("SELECT * FROM submissions WHERE request=?").get(request), previous: false };
    });
  }
  accepted(scope, record, accepted) {
    this.transaction(scope, () => {
      const changed = this.db.prepare(`UPDATE submissions SET project_id=?,job_id=? WHERE request=? AND conversation=? AND binding=?
        AND (project_id IS NULL OR project_id=?) AND (job_id IS NULL OR job_id=?)`)
        .run(accepted.projectId, accepted.jobId, record.request, scope.conversation, record.binding, accepted.projectId, accepted.jobId);
      if (changed.changes !== 1) throw new KeepHold("conflict");
    });
    return { ...record, project_id: accepted.projectId, job_id: accepted.jobId };
  }
  observed(scope, record, status) {
    this.transaction(scope, () => {
      const changed = this.db.prepare("UPDATE submissions SET observation=?,terminal=MAX(terminal,?) WHERE request=? AND conversation=? AND binding=? AND project_id=? AND job_id=?")
        .run(JSON.stringify(status), isTerminal(status) ? 1 : 0, record.request, scope.conversation, record.binding, status.projectId, status.jobId);
      if (changed.changes !== 1) throw new KeepHold("conflict");
    });
  }
  close() { this.db.close(); }
}

async function request(config, scope, token, method, path, body, signal) {
  scope.assertCurrent();
  let response;
  try {
    response = await fetch(config.endpoint + path, {
      method, redirect: "error", signal: AbortSignal.any([AbortSignal.timeout(config.requestTimeoutMs), ...(signal ? [signal] : [])]),
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, ...(body === undefined ? {} : { body }),
    });
  } catch { throw new KeepHold(signal?.aborted ? "cancelled" : "unavailable"); }
  scope.assertCurrent();
  if (![200, 202].includes(response.status)) {
    await response.body?.cancel();
    throw new KeepHold([401, 403].includes(response.status) ? "credential" : response.status === 409 ? "server-hold" : "unavailable");
  }
  if (!/^application\/json(?:;|$)/iu.test(response.headers.get("content-type") ?? "") || !response.body) {
    await response.body?.cancel(); throw new KeepHold("response");
  }
  const reader = response.body.getReader(); let bytes = 0; const chunks = [];
  try {
    for (;;) {
      const part = await reader.read(); scope.assertCurrent();
      if (part.done) break;
      bytes += part.value.length;
      if (bytes > 65536) throw new KeepHold("response");
      chunks.push(part.value);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  scope.assertCurrent();
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8").split(token).join("[redacted]")); }
  catch { throw new KeepHold("response"); }
}

/** Each explicit tool call makes at most one submission request and one status
 * request. Recovering a lost acknowledgement uses the original saved body/key. */
export async function useKeep(config, scope, operation, goal, signal) {
  const token = credential(config.tokenFile, scope.assertCurrent);
  const binding = hash(["keep.openclaw-client/v1", config.endpoint, config.clientId, config.grantId, config.commandBinding, config.openclawAgentId, hash(token)]);
  const journal = new Journal(config.stateDirectory, scope);
  try {
    const selected = operation === "submit" ? journal.submission(scope, binding, goal) : { record: journal.latest(scope), previous: false };
    let record = selected.record;
    if (!record) return { state: "empty", nextAction: "Submit a repository goal with keep_submit." };
    if (record.conversation !== scope.conversation || typeof record.body !== "string" || Buffer.byteLength(record.body) > 6 * 900 * 1024 + 1024) throw new KeepHold("journal");
    const body = JSON.parse(record.body);
    if (!body || Object.keys(body).sort().join() !== "goal,idempotencyKey" || body.idempotencyKey !== record.request || typeof body.goal !== "string" || !body.goal.trim() || Buffer.byteLength(body.goal) > 900 * 1024) throw new KeepHold("journal");
    if (record.binding !== binding) {
      if (!record.terminal || !record.observation || !record.job_id || !record.project_id) throw new KeepHold("binding");
      const status = statusResponse(JSON.parse(record.observation), { jobId: record.job_id, projectId: record.project_id });
      scope.assertCurrent(); return { state: "recorded", previousWork: true, status, nextAction: "This is the previous binding's retained terminal observation. A new explicit goal may now be submitted." };
    }
    if (!record.job_id) {
      const response = await request(config, scope, token, "POST", "/project", record.body, signal);
      scope.assertCurrent(); record = journal.accepted(scope, record, acceptedResponse(response));
    }
    if (!record.project_id || !record.job_id) throw new KeepHold("journal");
    const response = await request(config, scope, token, "GET", `/project/jobs?jobId=${encodeURIComponent(record.job_id)}`, undefined, signal);
    const status = statusResponse(response, { jobId: record.job_id, projectId: record.project_id });
    scope.assertCurrent(); journal.observed(scope, record, status); scope.assertCurrent();
    let nextAction = status.run?.wait?.kind === "approval" ? "The owner must approve or decline the exact pending step in Keep's console."
      : status.proposal.available ? "Inspect the exact diff and repository checks in Keep's console; proposal review is a separate human decision."
      : "Inspect the recorded wait or job state in Keep; do not resubmit under a new identity.";
    if (isTerminal(status)) nextAction = "This request has a recorded terminal outcome. Inspect its actual delivery status before starting another explicit goal.";
    if (selected.previous) nextAction = "An earlier submission occupies this conversation. The new goal was not submitted. " + nextAction;
    return { state: "observed", previousWork: selected.previous, status, nextAction };
  } finally { journal.close(); }
}

const HOLD_MESSAGES = {
  configuration: "The operator must finish the fixed Keep client configuration.",
  context: "This tool requires the configured owner-direct agent and a current session invocation.",
  input: "Use only the declared tool input; endpoint, identity, paths and approvals cannot be supplied as arguments.",
  credential: "Keep client authentication is unavailable, expired or refused. Ask the owner to inspect the configured restricted credential.",
  binding: "The client binding changed while earlier work was unresolved. Inspect that work with the owner; do not reset its journal or use another key.",
  conflict: "The saved request or acknowledgement conflicts. Preserve the journal and inspect the original Keep job.",
  journal: "The saved submission journal is unavailable or incompatible. Preserve it; do not replace it to bypass uncertain work.",
  "private-storage": "The operator must provide private owned state and credential files.",
  "server-hold": "Keep held or refused the saved request. Preserve its identity and inspect the original state with the owner.",
  cancelled: "The local tool call was cancelled. Keep may still have accepted work; recover the saved submission on the next valid invocation.",
  unavailable: "Keep could not be observed. Preserve the saved request; the next valid call can recover its original identity.",
  response: "Keep did not return the supported bounded response. Preserve the original submission and inspect the instance.",
};
export function heldResult(error) {
  const code = error instanceof KeepHold && Object.hasOwn(HOLD_MESSAGES, error.code) ? error.code : "invocation-or-state-unavailable";
  return { state: "held", code, nextAction: HOLD_MESSAGES[code] ?? "The invocation or local state became unavailable. Work may already exist; recover through a valid invocation without resetting state." };
}
