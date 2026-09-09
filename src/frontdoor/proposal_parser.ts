/**
 * F1.7 — Proposal parser (the tool-call layer, in front of the F1.5 decision gate).
 *
 * The LLM's raw output is untrusted and non-deterministic, so we parse+validate it
 * into a typed ProposedAction BEFORE anything acts on it. On any failure we return a
 * corrective, jargon-free clarification to feed back to the model — the 2026
 * "retry-with-clarification" pattern, which resolves most malformed-output cases
 * without a human ("that action isn't available; here's what I can do"). Never throws.
 *
 * The model may also just TALK (a conversational reply with no action) — that's a
 * first-class outcome, not an error.
 */

import { isKnownActionKind, type ProposedAction, type ActionKind } from "./action_schema.js";

export type ParseOutcome =
  | { kind: "action"; action: ProposedAction }
  | { kind: "reply"; text: string } // the model chose to just respond
  | { kind: "invalid"; clarification: string }; // malformed -> feed this back to the model

/** The action kinds, listed for the corrective message. */
const KNOWN_KINDS_HINT =
  "capture_goal, set_preference, note_project, start_background_research, index_uploaded_file, bind_channel, request_file_access, suggest_runtime, delete_data, drop_database, revoke_access, spend_money, send_external_comms, deploy_production, grant_broad_scope";

/**
 * Extract the first balanced top-level JSON object from a string (tolerant of code
 * fences and surrounding prose). Returns the substring or null.
 */
function extractJsonObject(text: string): string | null {
  const start = text.indexOf("{");
  if (start < 0) return null;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i]!;
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
    } else {
      if (ch === '"') inStr = true;
      else if (ch === "{") depth++;
      else if (ch === "}") {
        depth--;
        if (depth === 0) return text.slice(start, i + 1);
      }
    }
  }
  return null;
}

/**
 * Parse the model's raw output. Expected action shape (the model is prompted for it):
 *   { "action": "<kind>", "args": { ... }, "rationale": "..." }
 * or a plain reply:
 *   { "reply": "..." }  (or just prose with no JSON object -> treated as a reply)
 */
export function parseProposal(raw: string): ParseOutcome {
  const jsonStr = extractJsonObject(raw);
  if (!jsonStr) {
    // No JSON at all — treat the whole thing as a conversational reply.
    const text = raw.trim();
    return text.length > 0 ? { kind: "reply", text } : { kind: "invalid", clarification: emptyClarification() };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    return { kind: "invalid", clarification: `I couldn't read that as a valid instruction. Please reply with a single JSON object like {"action":"capture_goal","args":{...},"rationale":"..."} or {"reply":"..."}.` };
  }

  if (typeof parsed !== "object" || parsed === null) {
    return { kind: "invalid", clarification: emptyClarification() };
  }
  const obj = parsed as Record<string, unknown>;

  // A plain reply.
  if (typeof obj["reply"] === "string" && obj["action"] === undefined) {
    return { kind: "reply", text: (obj["reply"] as string).trim() };
  }

  // An action.
  const kind = obj["action"];
  if (typeof kind !== "string") {
    return { kind: "invalid", clarification: `I need an "action" field naming what to do. Available actions are: ${KNOWN_KINDS_HINT}. Or use {"reply":"..."} to just respond.` };
  }
  if (!isKnownActionKind(kind)) {
    return { kind: "invalid", clarification: `The action "${kind}" isn't available. The ones I can do are: ${KNOWN_KINDS_HINT}.` };
  }
  const args = obj["args"];
  if (args !== undefined && (typeof args !== "object" || args === null || Array.isArray(args))) {
    return { kind: "invalid", clarification: `The "args" field must be an object (like {"name":"..."}), not a list or a value.` };
  }
  const rationale = typeof obj["rationale"] === "string" ? (obj["rationale"] as string) : "";

  return {
    kind: "action",
    action: {
      kind: kind as ActionKind,
      args: (args as Record<string, unknown> | undefined) ?? {},
      rationale,
    },
  };
}

function emptyClarification(): string {
  return `Please reply with either an action like {"action":"capture_goal","args":{...},"rationale":"..."} or a message like {"reply":"..."}.`;
}
