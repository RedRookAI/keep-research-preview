/** Portable projection of retained proposal evidence. Export never authorizes delivery. */
import { createHash } from "node:crypto";
import { canonicalize } from "../spine/event.js";

type Row = Record<string, unknown>;
const SCHEMA = "keep.proposal-export/v1";
export const MAX_PROPOSAL_EXPORT_BYTES = 16 * 1024 * 1024;
export interface ProposalExport {
  readonly schema: typeof SCHEMA;
  readonly assurance: "unsigned-retained-evidence";
  readonly data: {
    readonly projectId: string; readonly runId: string;
    readonly proposal: { readonly baseRevision: string; readonly diff: string; readonly patchSha256: string;
      readonly checks: { readonly testsPassed: boolean; readonly vettingCleared: boolean; readonly passedTests: readonly string[]; readonly failedTests: readonly string[] } };
    readonly requester: { readonly kind: string; readonly idSha256: string | null };
    readonly exporterIdSha256: string;
    readonly decisions: readonly { readonly event: string; readonly decision: string | null; readonly status: string | null; readonly humanIdSha256: string | null; readonly proposalDigest: string | null }[];
    readonly delivery: { readonly observation: "last-recorded"; readonly workspace: string; readonly sourceMerge: string; readonly sourceRevert: string };
  };
  readonly sha256: string;
}
function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function row(value: unknown): Row {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("proposal evidence is unavailable");
  return value as Row;
}
function text(value: unknown, max = 4096): string {
  if (typeof value !== "string" || !value.length || value.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) throw new Error("invalid portable evidence text");
  return value;
}
function digest(value: unknown): string {
  const s = text(value); if (!/^[a-f0-9]{64}$/u.test(s)) throw new Error("invalid evidence digest"); return s;
}
function flag(value: unknown): boolean { if (typeof value !== "boolean") throw new Error("missing recorded check result"); return value; }
function list(value: unknown): unknown[] { if (!Array.isArray(value) || value.length > 10000) throw new Error("invalid evidence list"); return value; }
function identity(value: unknown): string | null { return typeof value === "string" && value.length > 0 ? hash(value) : null; }
function nullableDigest(value: unknown): string | null { return value === null ? null : digest(value); }

function safePatchPaths(diff: string): void {
  let files = 0;
  for (const line of diff.split("\n")) {
    if (!line.startsWith("diff --git ")) continue;
    const match = /^diff --git a\/([^\s]+) b\/([^\s]+)$/u.exec(line);
    if (!match) throw new Error("portable patch requires ordinary relative file paths");
    for (const path of match.slice(1)) {
      const parts = path!.split("/");
      if (/[\\"':]/u.test(path!) || path!.startsWith("/") || parts.some(p => !p || p === "." || p === ".." || p === ".git")
        || parts.some(p => /^(?:\.env(?:\..*)?|id_rsa|id_ed25519)$/iu.test(p) || /\.(?:pem|key|p12|pfx)$/iu.test(p)))
        throw new Error("portable patch contains an unsafe or credential file path");
    }
    files++;
  }
  if (!files) throw new Error("portable patch has no recorded Git file changes");
}

function normalize(value: unknown): ProposalExport["data"] {
  const d = row(value), p = row(d["proposal"]), checks = row(p["checks"]), requester = row(d["requester"]), delivery = row(d["delivery"]);
  const baseRevision = text(p["baseRevision"]);
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/u.test(baseRevision)) throw new Error("missing pinned source revision");
  const diff = text(p["diff"], MAX_PROPOSAL_EXPORT_BYTES), patchSha256 = digest(p["patchSha256"]);
  if (hash(diff) !== patchSha256) throw new Error("retained patch digest mismatch");
  safePatchPaths(diff);
  if (!["human", "agent", "service", "unknown"].includes(String(requester["kind"]))) throw new Error("invalid requester kind");
  if (delivery["observation"] !== "last-recorded") throw new Error("invalid delivery observation");
  return {
    projectId: text(d["projectId"]), runId: text(d["runId"]),
    proposal: { baseRevision, diff, patchSha256, checks: { testsPassed: flag(checks["testsPassed"]), vettingCleared: flag(checks["vettingCleared"]),
      passedTests: list(checks["passedTests"]).map(v => text(v)), failedTests: list(checks["failedTests"]).map(v => text(v)) } },
    requester: { kind: text(requester["kind"]), idSha256: nullableDigest(requester["idSha256"]) },
    exporterIdSha256: digest(d["exporterIdSha256"]),
    decisions: list(d["decisions"]).map(value => { const r = row(value); return { event: text(r["event"]),
      decision: r["decision"] === null ? null : text(r["decision"]), status: r["status"] === null ? null : text(r["status"]), humanIdSha256: nullableDigest(r["humanIdSha256"]), proposalDigest: nullableDigest(r["proposalDigest"]) }; }),
    delivery: { observation: "last-recorded", workspace: text(delivery["workspace"]), sourceMerge: text(delivery["sourceMerge"]), sourceRevert: text(delivery["sourceRevert"]) },
  };
}

/** Unknown historical identities stay unknown; free-form diagnostics/prompts are excluded. */
export function createProposalExport(input: {
  readonly projectId: string; readonly runId: string; readonly evidence: unknown; readonly requester: unknown;
  readonly exporterId: string;
  readonly decisions: readonly Row[]; readonly delivery: unknown; readonly forbiddenValues: readonly string[];
}): ProposalExport {
  const p = row(input.evidence), checks = row(p["checks"]), rollback = row(p["rollback"]), delivery = row(input.delivery);
  const requester = input.requester === null ? {} : row(input.requester), source = row(delivery["source"]);
  const data = normalize({ projectId: input.projectId, runId: input.runId,
    proposal: { baseRevision: p["baseRevision"], diff: p["diff"], patchSha256: rollback["patchSha256"], checks: {
      testsPassed: checks["testsPassed"], vettingCleared: checks["vettingCleared"], passedTests: checks["passedTests"] ?? [], failedTests: checks["failures"] ?? [],
    } }, requester: { kind: requester["kind"] ?? "unknown", idSha256: identity(requester["id"]) }, exporterIdSha256: hash(text(input.exporterId)),
    decisions: input.decisions.map(r => ({ event: r["event"], decision: typeof r["decision"] === "string" ? r["decision"] : typeof r["approved"] === "boolean" ? r["approved"] ? "approved" : "declined" : null,
      status: typeof r["status"] === "string" ? r["status"] : null,
      humanIdSha256: identity(r["humanPrincipalId"]), proposalDigest: typeof r["proposalDigest"] === "string" ? r["proposalDigest"] : null })),
    delivery: { observation: "last-recorded", workspace: row(delivery["workspace"])["status"], sourceMerge: row(source["merge"])["status"], sourceRevert: row(source["revert"])["status"] },
  });
  // Refuse rather than rewriting a patch whose exact digest binds decisions.
  const portable = canonicalize(data);
  if (input.forbiddenValues.some(value => value.length > 0 && portable.includes(JSON.stringify(value).slice(1, -1)))
    || /(?:Bearer\s+[A-Za-z0-9._~-]+|(?:\/root\/|\/home\/|\/Users\/|\/tmp\/|\/etc\/|\/var\/|\/opt\/|[A-Za-z]:\\\\)|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_\-]{8,}|(?:api[_-]?key|password|secret|token)\s*[=:]\s*\\?["']?[^\s"',;]{4,})/iu.test(portable))
    throw new Error("portable evidence contains a credential or private host path; inspect the retained proposal locally");
  const body = { schema: SCHEMA, assurance: "unsigned-retained-evidence" as const, data };
  const result: ProposalExport = { ...body, schema: SCHEMA, sha256: hash(canonicalize(body)) };
  if (Buffer.byteLength(JSON.stringify(result)) > MAX_PROPOSAL_EXPORT_BYTES) throw new Error("portable evidence exceeds 16 MiB");
  return result;
}

/** Checks self-integrity and shape, without claiming an independently authenticated issuer. */
export function verifyProposalExport(input: string): ProposalExport {
  if (Buffer.byteLength(input) > MAX_PROPOSAL_EXPORT_BYTES) throw new Error("portable evidence exceeds 16 MiB");
  const r = row(JSON.parse(input)), data = normalize(r["data"]);
  if (r["schema"] !== SCHEMA || r["assurance"] !== "unsigned-retained-evidence") throw new Error("unsupported proposal export");
  const body = { schema: SCHEMA, assurance: "unsigned-retained-evidence" as const, data };
  const result: ProposalExport = { ...body, schema: SCHEMA, sha256: digest(r["sha256"]) };
  if (result.sha256 !== hash(canonicalize(body)) || canonicalize(result) !== canonicalize(r)) throw new Error("portable evidence integrity mismatch");
  return result;
}
