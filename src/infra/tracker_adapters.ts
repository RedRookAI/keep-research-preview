/**
 * Tracker webhook normalizers (infra, Phase 6 #46).
 *
 * Real normalizers for Linear, Jira, and GitHub Issues webhook payloads,
 * implementing the TrackerAdapter port. Each maps a tracker's native webhook JSON
 * into Keep's NormalizedTrigger so the rest of Keep is tracker-agnostic. The
 * normalization logic is real and tested against sample payloads here; live webhook
 * DELIVERY (endpoint, signature verification) is wired on the connected env.
 */

import type { NormalizedTrigger, TrackerAdapter, TrackerSource, TriggerRouter } from "../ecosystem/integrations.js";

type Kind = NormalizedTrigger["kind"];

/** Linear webhook: { action: "create"|"update", type: "Issue"|"Comment", data: {...} }. */
export const linearAdapter: TrackerAdapter = {
  source: "linear",
  normalize(p): NormalizedTrigger | undefined {
    const type = String(p["type"] ?? "");
    const action = String(p["action"] ?? "");
    const data = (p["data"] ?? {}) as Record<string, unknown>;
    let kind: Kind | undefined;
    if (type === "Issue" && action === "create") kind = "ticket.created";
    else if (type === "Issue" && action === "update") kind = "ticket.updated";
    else if (type === "Comment" && action === "create") kind = "comment.added";
    if (!kind) return undefined;
    const labels = Array.isArray(data["labels"]) ? (data["labels"] as Array<Record<string, unknown>>).map((l) => String(l["name"] ?? "")) : [];
    return {
      source: "linear",
      kind,
      ticketId: String(data["identifier"] ?? data["id"] ?? ""),
      title: String(data["title"] ?? ""),
      body: String(data["description"] ?? data["body"] ?? ""),
      labels,
    };
  },
};

/** Jira webhook: { webhookEvent: "jira:issue_created"|..., issue: { key, fields } }. */
export const jiraAdapter: TrackerAdapter = {
  source: "jira",
  normalize(p): NormalizedTrigger | undefined {
    const event = String(p["webhookEvent"] ?? "");
    const issue = (p["issue"] ?? {}) as Record<string, unknown>;
    const fields = (issue["fields"] ?? {}) as Record<string, unknown>;
    let kind: Kind | undefined;
    if (event === "jira:issue_created") kind = "ticket.created";
    else if (event === "jira:issue_updated") kind = "ticket.updated";
    else if (event === "comment_created") kind = "comment.added";
    if (!kind) return undefined;
    const labels = Array.isArray(fields["labels"]) ? (fields["labels"] as unknown[]).map(String) : [];
    return {
      source: "jira",
      kind,
      ticketId: String(issue["key"] ?? ""),
      title: String(fields["summary"] ?? ""),
      body: String(fields["description"] ?? ""),
      labels,
    };
  },
};

/** GitHub Issues webhook: { action: "opened"|"edited"|"labeled", issue: {...} }. */
export const githubIssuesAdapter: TrackerAdapter = {
  source: "github-issues",
  normalize(p): NormalizedTrigger | undefined {
    const action = String(p["action"] ?? "");
    const issue = (p["issue"] ?? {}) as Record<string, unknown>;
    if (!issue["number"] && !issue["id"]) return undefined;
    let kind: Kind;
    if (action === "opened") kind = "ticket.created";
    else if (action === "reopened") kind = "ticket.reopened";
    else if (action === "edited") kind = "ticket.updated";
    else if (action === "labeled") kind = "ticket.labeled";
    else return undefined;
    const labels = Array.isArray(issue["labels"]) ? (issue["labels"] as Array<Record<string, unknown>>).map((l) => String(l["name"] ?? "")) : [];
    return {
      source: "github-issues",
      kind,
      ticketId: String(issue["number"] ?? issue["id"] ?? ""),
      title: String(issue["title"] ?? ""),
      body: String(issue["body"] ?? ""),
      labels,
    };
  },
};

/** GitLab issue hook. Object attributes are the authoritative issue snapshot. */
export const gitlabAdapter: TrackerAdapter = {
  source: "gitlab",
  normalize(p): NormalizedTrigger | undefined {
    if (p["object_kind"] !== "issue") return undefined;
    const issue = (p["object_attributes"] ?? {}) as Record<string, unknown>;
    const action = String(issue["action"] ?? "");
    const kind: Kind | undefined = action === "open" ? "ticket.created" : action === "reopen" ? "ticket.reopened" : action === "update" ? "ticket.updated" : undefined;
    if (!kind || (issue["iid"] === undefined && issue["id"] === undefined)) return undefined;
    const labels = Array.isArray(p["labels"]) ? (p["labels"] as Array<Record<string, unknown>>).map((label) => String(label["title"] ?? "")).filter(Boolean) : [];
    return { source: "gitlab", kind, ticketId: String(issue["iid"] ?? issue["id"]), title: String(issue["title"] ?? ""), body: String(issue["description"] ?? ""), labels };
  },
};

/**
 * Generic adapter — the provider-agnostic escape hatch so Keep is NOT limited to Linear/Jira/GitHub. Any
 * tracker (Gitea, Bugzilla, Trello, Asana, a homegrown system, a shell script) can drive Keep by POSTing a
 * small tolerant envelope. Accepts common field aliases so most trackers map with little or no transform:
 *   { id|ticketId|key|number, title|summary|name, body|description|text, labels?: string[]|{name}[],
 *     kind|action?: created|updated|labeled|comment (default: ticket.created) }
 */
export const genericAdapter: TrackerAdapter = {
  source: "generic",
  normalize(p): NormalizedTrigger | undefined {
    const pick = (...keys: string[]): string => {
      for (const k of keys) if (p[k] !== undefined && p[k] !== null) return String(p[k]);
      return "";
    };
    const ticketId = pick("ticketId", "id", "key", "number", "iid");
    if (!ticketId) return undefined; // must identify the ticket
    const raw = String(p["kind"] ?? p["action"] ?? "").toLowerCase();
    let kind: Kind = "ticket.created";
    if (raw.includes("comment")) kind = "comment.added";
    else if (raw.includes("label")) kind = "ticket.labeled";
    else if (raw.includes("reopen")) kind = "ticket.reopened";
    else if (raw.includes("update") || raw.includes("edit")) kind = "ticket.updated";
    else if (raw.includes("creat") || raw.includes("open") || raw === "") kind = "ticket.created";
    else return undefined; // explicit but unrecognized action → reject (fail-closed, don't guess)
    const rawLabels = p["labels"];
    const labels = Array.isArray(rawLabels)
      ? rawLabels.map((l) => (typeof l === "string" ? l : String((l as Record<string, unknown>)?.["name"] ?? ""))).filter((s) => s.length > 0)
      : [];
    return { source: "generic", kind, ticketId, title: pick("title", "summary", "name"), body: pick("body", "description", "text"), labels };
  },
};

export const ALL_TRACKER_ADAPTERS: readonly TrackerAdapter[] = [linearAdapter, jiraAdapter, githubIssuesAdapter, gitlabAdapter, genericAdapter];

/** Register the real tracker adapters on a router. */
export function registerAllTrackers(router: TriggerRouter): TrackerSource[] {
  for (const a of ALL_TRACKER_ADAPTERS) router.register(a);
  return router.supportedSources();
}
