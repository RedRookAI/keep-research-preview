/**
 * Event schema registry + read-time upcasting (Round 18).
 *
 * The spine is append-only and hash-chained, so historical events can NEVER be
 * mutated to a new schema (that would change their bytes and break the chain).
 * Instead, each event carries a schemaVersion, and upcasters project an event
 * from version N to N+1 *at read time, in memory*. Reading/replaying always
 * projects up to CURRENT_SCHEMA_VERSION before use.
 *
 * Safety property: upcasting changes only the in-memory projection, never the
 * stored bytes or their hash. Tamper-evidence and schema evolution coexist.
 */

import type { StagedEvent } from "./event.js";
import { CURRENT_SCHEMA_VERSION } from "./event.js";

/** An upcaster maps an event at version `from` to an equivalent at `from + 1`. */
export type Upcaster = (e: StagedEvent) => StagedEvent;

/** Registry of upcasters keyed by their source version. */
export class SchemaRegistry {
  private readonly upcasters = new Map<number, Upcaster>();

  /** Register the upcaster that takes events from `fromVersion` to `fromVersion + 1`. */
  register(fromVersion: number, up: Upcaster): void {
    if (this.upcasters.has(fromVersion)) {
      throw new Error(`upcaster already registered for version ${fromVersion}`);
    }
    this.upcasters.set(fromVersion, up);
  }

  /**
   * Project an event up to the current schema version. Pure: returns a new event,
   * never mutates the input (which represents immutable stored bytes).
   */
  upcast(e: StagedEvent, target: number = CURRENT_SCHEMA_VERSION): StagedEvent {
    let cur = e;
    while (cur.schemaVersion < target) {
      const up = this.upcasters.get(cur.schemaVersion);
      if (!up) {
        throw new Error(
          `no upcaster registered from schema version ${cur.schemaVersion} ` +
            `(needed to reach ${target})`,
        );
      }
      const next = up(cur);
      if (next.schemaVersion !== cur.schemaVersion + 1) {
        throw new Error(
          `upcaster from ${cur.schemaVersion} must produce version ` +
            `${cur.schemaVersion + 1}, produced ${next.schemaVersion}`,
        );
      }
      cur = next;
    }
    return cur;
  }
}
