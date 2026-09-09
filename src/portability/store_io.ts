/**
 * PORTABILITY STORE-I/O ADAPTER — Hardening H2 (the outbound port for Round 8).
 *
 * Ports-and-adapters: `exportAll`/`importAll` are PURE DOMAIN — they operate on an abstract `DerivedState` and
 * touch no store. This module is the OUTBOUND ADAPTER that assembles `DerivedState` FROM the real stores on export
 * and applies `Restored` TO them on import, keeping the domain sacred (`portability.ts` is unmodified).
 *
 * The load-bearing properties (research):
 *   - ROUND-TRIP FIDELITY: a live round-trip `assemble → export → import → applyRestored` through the real stores
 *     reproduces the derived state (content).
 *   - METAMORPHIC STABILITY: `export → import → export` yields an equivalent bundle (an MR for a system with no
 *     simple oracle — a second full round-trip is stable).
 *   - SAFE RE-HYDRATION preserved: imported memories land at PROBATION (never confirmed — no authority laundering),
 *     and R8's CI-scoping still filters another subject's data on assembly.
 *
 * BUILT + proven in-env: the store↔DerivedState assembly/application mapping and its round-trip fidelity. SEAM:
 * the wire format (still) and the memory→subject identity resolver.
 */

import {
  exportAll,
  importAll,
  type DerivedState,
  type PortableMemory,
  type PortablePreference,
  type PortableLens,
  type PortableConnector,
  type PortableCorrection,
  type Portable,
  type ImportResult,
  type Restored,
} from "./portability.js";
import type { MemoryStore } from "../memory/store.js";
import type { Lesson, MemoryScope } from "../memory/model.js";

export interface DerivedSources {
  readonly memoryStore: MemoryStore;
  /** memory→subject identity (the SEAM); default = the requesting subject (single-owner store). */
  readonly subjectOf?: ((lesson: Lesson) => string) | undefined;
  readonly preferences?: readonly PortablePreference[] | undefined;
  readonly inferred?: readonly PortablePreference[] | undefined;
  readonly lenses?: readonly PortableLens[] | undefined;
  readonly connectors?: readonly PortableConnector[] | undefined;
  readonly corrections?: readonly PortableCorrection[] | undefined;
}

function asScope(scope: string): MemoryScope {
  return scope === "user" || scope === "global" ? scope : "project";
}

/**
 * Assemble a `DerivedState` FROM the real stores, CI-scoped to `subject` (each memory is tagged with its true
 * subject via `subjectOf`, so R8's `exportAll` filter removes another user's data). Retired lessons are excluded.
 */
export function assembleDerived(subject: string, sources: DerivedSources): DerivedState {
  const subjectOf = sources.subjectOf ?? ((): string => subject);
  const memories: PortableMemory[] = sources.memoryStore
    .all()
    .filter((l) => l.tier !== "retired")
    .map((l) => ({ id: l.id, content: l.content, tier: l.tier, scope: l.scope, subject: subjectOf(l) }));
  return {
    memories,
    preferences: sources.preferences ?? [],
    inferred: sources.inferred ?? [],
    lenses: sources.lenses ?? [],
    connectors: sources.connectors ?? [],
    corrections: sources.corrections ?? [],
  };
}

export interface RestoreSinks {
  readonly memoryStore: MemoryStore;
}

/**
 * Apply a verified `Restored` TO the real stores. Imported memories are borrowed/unverified, so they enter the
 * `MemoryStore` at PROBATION (origin `seeded` ⇒ probation tier) — never confirmed. (Preference/lens/connector
 * application is a thin pass-through sink handled by the envelope; memories are the substantive wiring here.)
 */
export async function applyRestored(restored: Restored, sinks: RestoreSinks): Promise<void> {
  for (const m of restored.memories) {
    await sinks.memoryStore.ingest(m.content, { origin: "seeded", scope: asScope(m.scope), citation: "imported via portability" });
  }
}

/**
 * Convenience: a full live round-trip through the real stores. `assemble → export → import → applyRestored`.
 * Returns the `ImportResult` (so callers can see a rejected/degraded bundle).
 */
export async function roundTrip(subject: string, sources: DerivedSources, sink: RestoreSinks): Promise<ImportResult> {
  const bundle: Portable = exportAll(subject, assembleDerived(subject, sources));
  const result = importAll(bundle);
  if (result.ok) await applyRestored(result.restored, sink);
  return result;
}
