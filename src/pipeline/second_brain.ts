/**
 * SECOND-BRAIN ORCHESTRATION (Hardening H4 glue) — the thin wire that composes the second-brain ingest path.
 *
 * The moat + hardening rounds built the pieces; this helper composes them into one path:
 *   parse (H3 safe-parsing registry) → upkeep decision + CI-vault capture (R3/R1) → land in the REAL MemoryStore
 *   (H1 applyUpkeep).
 *
 * It is the one missing wire the arc left: `routeIntake` (R7) runs the upkeep decision and vault capture but does
 * NOT land memories in the store (it returns the decision). This helper adds the store landing via H1. It is pure
 * orchestration — no new domain logic — and it modifies no domain module.
 */

import { ParserRegistry } from "../intake/parser_registry.js";
import { upkeep, type Candidate, type UpkeepItem, type UpkeepResult } from "../memory/upkeep.js";
import { applyUpkeep, type Applied } from "../memory/apply_upkeep.js";
import type { MemoryStore } from "../memory/store.js";
import type { SensitiveContextVault } from "../privacy/contextual_integrity.js";
import type { IntakeItem } from "../intake/intake.js";

const TEXT_NATIVE: ReadonlySet<string> = new Set(["note", "text", "markdown"]);

export interface SecondBrainDeps {
  readonly store: MemoryStore;
  readonly vault: SensitiveContextVault;
  readonly registry: ParserRegistry;
}

export type IngestOutcome =
  | { readonly status: "ingested"; readonly applied: Applied; readonly result: UpkeepResult; readonly savedToVault: boolean }
  | { readonly status: "unsupported"; readonly kind: string };

/**
 * Ingest one item into the second brain: parse (safe-parsing gate for binary kinds), decide (upkeep + vault
 * capture of any special-category disclosure), and land it in the real store (H1). An unsupported/over-budget
 * item degrades gracefully.
 */
export async function ingestToSecondBrain(
  item: IntakeItem,
  deps: SecondBrainDeps,
  existing: readonly UpkeepItem[] = [],
  key?: string,
): Promise<IngestOutcome> {
  let text: string | undefined;
  if (TEXT_NATIVE.has(item.kind)) {
    text = item.content; // pass-through
  } else {
    const parsed = deps.registry.parse(item); // H3 safe-parsing gate (bomb ⇒ rejected ⇒ undefined)
    text = parsed.status === "parsed" ? parsed.text.value : undefined;
  }
  if (text === undefined) return { status: "unsupported", kind: item.kind };

  const candidate: Candidate = {
    content: text,
    key: key ?? text.slice(0, 24),
    scope: "user",
    subject: item.subject,
  };
  const result = upkeep(existing, candidate, { vault: deps.vault }); // decide + capture sensitive in the vault
  const applied = await applyUpkeep(deps.store, candidate, result); // land in the REAL store (H1)
  return { status: "ingested", applied, result, savedToVault: result.sensitive };
}
