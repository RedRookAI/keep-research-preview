/**
 * PollingSource (Increment W0) — the fallback for environments that cannot RECEIVE webhooks (back-of-house, no
 * public ingress, restricted networks). It PULLS new tracker items on a deterministic tick (no daemon; the host
 * or operator drives the cadence — an N=1 laptop can poll on demand), routing each item through the SAME
 * TriggerIngress dedup+dispatch path. So a poll of a ticket and a webhook redelivery of the same ticket are
 * idempotent through ONE mechanism — you never double-process because you happen to run both.
 *
 * Authentication for polling is the API token used by the fetcher (a pull the operator initiates), so there is
 * no payload signature to verify — the trust comes from the authenticated outbound fetch, not an inbound secret.
 * Zero deps.
 */

import type { TrackerSource, TriggerRouter } from "../ecosystem/integrations.js";
import type { TriggerIngress } from "./trigger_ingress.js";

/** Pull new native tracker payloads (the fetcher owns API auth + "since" bookkeeping). */
export type PollFetcher = () => Promise<ReadonlyArray<Readonly<Record<string, unknown>>>>;

export interface PollResult {
  readonly fetched: number;
  readonly accepted: number;
  readonly duplicates: number;
  readonly rejected: number;
}

export class PollingSource {
  constructor(
    private readonly source: TrackerSource,
    private readonly router: TriggerRouter,
    private readonly ingress: TriggerIngress,
    private readonly fetch: PollFetcher,
  ) {}

  /** One deterministic poll tick. Safe to call repeatedly — dedup makes re-fetching the same items harmless. */
  async poll(): Promise<PollResult> {
    const items = await this.fetch();
    let accepted = 0;
    let duplicates = 0;
    let rejected = 0;
    for (const native of items) {
      const trigger = this.router.route(this.source, native);
      if (!trigger) {
        rejected++;
        continue;
      }
      const r = await this.ingress.ingestPolled(trigger);
      if (r.status === "accepted") accepted++;
      else if (r.status === "duplicate") duplicates++;
      else rejected++;
    }
    return { fetched: items.length, accepted, duplicates, rejected };
  }
}
