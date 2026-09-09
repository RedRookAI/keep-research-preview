/**
 * Theme 5c (No-Account Local Defaults), Part 1 — CapabilityAudit.
 *
 * Keep is sovereign/self-hostable and N=1-first: it must WORK on a fresh install with no
 * external accounts, and be honest about what needs what. The 2026 trap (Botmonster) is
 * frameworks that assume "an OpenAI key and a credit card" and make the local path a
 * footnote. Keep inverts that: the no-account path is the default, and this audit tells
 * the operator plainly what works right now vs. what a given capability requires.
 *
 * Each capability declares a RequirementLevel. The audit reports availability against the
 * current environment and, per the locked free-first principle, surfaces a free/local
 * alternative for each gap BEFORE mentioning any paid account. It never nags.
 */

export type RequirementLevel =
  | "nothing" // works on a bare fresh install, zero setup
  | "local-model" // needs a local OpenAI-compatible endpoint (Ollama/LM Studio/Jan) — no account
  | "byo-key" // needs a bring-your-own API key the operator controls
  | "external-account"; // needs GitHub/Slack/Telegram/etc.

export interface Capability {
  readonly id: string;
  /** Plain-language description of what this lets the operator do. */
  readonly summary: string;
  readonly requires: RequirementLevel;
  /**
   * If unavailable, a free/local way to get it (surfaced FIRST, before any paid path).
   * e.g. "point Keep at a local Ollama model — no account needed".
   */
  readonly freeAlternative?: string;
  /** True if this capability needs strong reasoning (degrades on small local models). */
  readonly needsStrongReasoning?: boolean;
}

/** The current runtime environment the audit checks against. */
export interface AuditEnv {
  /** Is a brain (any OpenAI-compatible endpoint) configured? */
  readonly hasBrain: boolean;
  /** Is that brain a LOCAL endpoint (localhost / no cloud)? */
  readonly brainIsLocal: boolean;
  /** Is the local/available model weak (small local model)? Composes with F1.6. */
  readonly modelIsWeak: boolean;
  /** Which external accounts are connected (e.g. "github", "slack"). */
  readonly connectedAccounts: ReadonlySet<string>;
  /** Are any BYO API keys present? */
  readonly hasApiKey: boolean;
}

export type AvailabilityState = "available" | "available-degraded" | "unavailable";

export interface CapabilityStatus {
  readonly capability: Capability;
  readonly state: AvailabilityState;
  /** Plain-language explanation the operator sees. */
  readonly note: string;
}

export interface AuditReport {
  readonly statuses: readonly CapabilityStatus[];
  /** Count that work right now with the current (possibly zero-account) setup. */
  readonly availableNow: number;
  /** True if Keep is usable with ZERO external accounts in this environment. */
  readonly worksWithoutAccounts: boolean;
  /** A short, honest summary for the operator. */
  readonly summary: string;
}

/**
 * The default capability registry — the things Keep can do, and what each needs. This is
 * deliberately data so new capabilities register themselves rather than hardcoding logic.
 */
export const DEFAULT_CAPABILITIES: readonly Capability[] = [
  { id: "converse", summary: "Talk with you, understand goals, and plan work", requires: "local-model", freeAlternative: "point Keep at a local model (Ollama/LM Studio/Jan) — no account, runs offline", needsStrongReasoning: false },
  { id: "plan_decompose", summary: "Break a goal into a reviewable plan", requires: "local-model", freeAlternative: "a local model handles this; a stronger model plans better", needsStrongReasoning: true },
  { id: "revise_beliefs", summary: "Remember decisions and revise them over time", requires: "nothing" },
  { id: "local_files", summary: "Read and work with files you point it at on this machine", requires: "nothing" },
  { id: "dry_run", summary: "Preview a plan + predicted changes with zero writes", requires: "nothing" },
  { id: "instance_isolation", summary: "Run multiple projects side by side without conflicts", requires: "nothing" },
  { id: "prior_art_check", summary: "Check whether something already exists before building it", requires: "local-model", freeAlternative: "works with a local model; live web search sharpens it", needsStrongReasoning: true },
  { id: "git_local", summary: "Version your work with local git (commits, diffs, revert)", requires: "nothing" },
  { id: "git_remote", summary: "Push/pull to a hosted repo and open PRs", requires: "external-account", freeAlternative: "local git works fully offline with no account; a remote is only needed to share/host" },
  { id: "chat_channels", summary: "Talk to Keep from Slack/Telegram/Discord", requires: "external-account", freeAlternative: "the local web/CLI interface needs no account; channels are optional" },
  { id: "cloud_model", summary: "Use a top-tier hosted model for the hardest reasoning", requires: "byo-key", freeAlternative: "a local model covers most work; a hosted key only helps on the hardest tasks", needsStrongReasoning: true },
];

/** Run the audit against the current environment. */
export function auditCapabilities(env: AuditEnv, capabilities: readonly Capability[] = DEFAULT_CAPABILITIES): AuditReport {
  const statuses = capabilities.map((c) => statusFor(c, env));
  const availableNow = statuses.filter((s) => s.state !== "unavailable").length;
  // "Works without accounts" asks a specific question: does anything REQUIRE an external
  // account for Keep to function? A missing local model is a different axis (no signup
  // fixes it). So this is true whenever every external-account capability is OPTIONAL —
  // i.e. it offers a free/local alternative rather than being mandatory.
  const worksWithoutAccounts = capabilities
    .filter((c) => c.requires === "external-account")
    .every((c) => c.freeAlternative !== undefined);

  const summary = buildSummary(availableNow, statuses.length, env, worksWithoutAccounts);
  return { statuses, availableNow, worksWithoutAccounts, summary };
}

function statusFor(c: Capability, env: AuditEnv): CapabilityStatus {
  switch (c.requires) {
    case "nothing":
      return { capability: c, state: "available", note: "Works right now — no setup needed." };
    case "local-model": {
      if (!env.hasBrain) {
        return { capability: c, state: "unavailable", note: c.freeAlternative ? `Needs a model. ${cap(c.freeAlternative)}` : "Needs a model to be configured." };
      }
      if (c.needsStrongReasoning && env.modelIsWeak) {
        return { capability: c, state: "available-degraded", note: "Works, but a small local model will do this less reliably — a stronger model improves it." };
      }
      return { capability: c, state: "available", note: env.brainIsLocal ? "Works with your local model — fully offline, no account." : "Works with your configured model." };
    }
    case "byo-key": {
      if (env.hasApiKey || (env.hasBrain && !env.brainIsLocal)) {
        return { capability: c, state: "available", note: "Available with your configured key." };
      }
      return { capability: c, state: "unavailable", note: c.freeAlternative ? cap(c.freeAlternative) : "Needs a bring-your-own API key." };
    }
    case "external-account": {
      // Which account? Heuristic by id.
      const acct = c.id.includes("git") ? "github" : c.id.includes("chat") || c.id.includes("channel") ? "chat" : c.id;
      if (env.connectedAccounts.has(acct)) {
        return { capability: c, state: "available", note: "Available — account connected." };
      }
      return { capability: c, state: "unavailable", note: c.freeAlternative ? `Optional. ${cap(c.freeAlternative)}` : "Optional — needs an external account." };
    }
  }
}

function buildSummary(availableNow: number, total: number, env: AuditEnv, worksWithoutAccounts: boolean): string {
  const base = `${availableNow} of ${total} capabilities are available right now`;
  if (!env.hasBrain) {
    return `${base}. Keep runs with no account and no cloud — to unlock planning and conversation, point it at a local model (Ollama, LM Studio, or Jan). Nothing here requires an external account or signup.`;
  }
  const acctNote = worksWithoutAccounts
    ? "Everything essential works with zero external accounts — hosted repos and chat channels are optional extras, not requirements."
    : "";
  const localNote = env.brainIsLocal ? " Your model is local, so your data never leaves this machine." : "";
  return `${base}.${localNote} ${acctNote}`.trim();
}

function cap(s: string): string {
  return s.length > 0 ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}
