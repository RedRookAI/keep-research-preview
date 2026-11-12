/**
 * Sequences caller-supplied progress events, sends them to subscribers and records them on the spine.
 * The caller supplies the headline, detail and any known progress fraction.
 */

import type { Spine } from "../spine/spine.js";

/** Lifecycle phase of a narrated step (AG-UI-shaped: start → update → done/blocked/failed). */
export type ProgressPhase = "start" | "update" | "done" | "blocked" | "failed";

export interface ProgressEvent {
  /** Monotonic sequence within a run (ordering for the interface). */
  readonly seq: number;
  /** The run this belongs to (a project loop, an auto-research pass, etc.). */
  readonly runId: string;
  /** The stage emitting it, e.g. "research", "plan", "vet", "implement". */
  readonly stage: string;
  readonly phase: ProgressPhase;
  /** The one-or-two-sentence, user-facing note. Concrete and truthful. */
  readonly headline: string;
  /** Optional extra detail (calm-by-default; interface reveals on demand). */
  readonly detail?: string;
  /** Optional 0..1 progress fraction, ONLY when the caller genuinely knows it. */
  readonly fraction?: number;
  readonly at: number;
}

/** A subscriber that renders or forwards progress events (the interface implements this). */
export interface NarrationSink {
  (event: ProgressEvent): void;
}

export interface NarrateInput {
  readonly stage: string;
  readonly phase: ProgressPhase;
  readonly headline: string;
  readonly detail?: string;
  readonly fraction?: number;
}

/**
 * A progress narrator scoped to one run. Callers emit real stage transitions; the
 * narrator sequences, timestamps, fans out to sinks, and logs to the spine.
 */
export class ProgressNarrator {
  private seq = 0;
  private readonly sinks: NarrationSink[] = [];

  constructor(
    private readonly runId: string,
    private readonly spine: Spine,
    private readonly now: () => number = () => Date.now(),
  ) {}

  /** Subscribe an interface/sink to this run's progress. Returns an unsubscribe fn. */
  subscribe(sink: NarrationSink): () => void {
    this.sinks.push(sink);
    return () => {
      const i = this.sinks.indexOf(sink);
      if (i >= 0) this.sinks.splice(i, 1);
    };
  }

  /** Sequence and record the progress reported by the caller. */
  narrate(input: NarrateInput): ProgressEvent {
    // Guard the fraction to [0,1] if provided; never fabricate one.
    const fraction = input.fraction === undefined ? undefined : Math.max(0, Math.min(1, input.fraction));
    const event: ProgressEvent = {
      seq: this.seq++,
      runId: this.runId,
      stage: input.stage,
      phase: input.phase,
      headline: input.headline.trim(),
      ...(input.detail !== undefined ? { detail: input.detail.trim() } : {}),
      ...(fraction !== undefined ? { fraction } : {}),
      at: this.now(),
    };

    // Record the same headline and detail sent to subscribers.
    this.spine.stage({
      type: "identity.action",
      actor: "narrator",
      payload: {
        event: "progress.narrated",
        runId: event.runId,
        seq: event.seq,
        stage: event.stage,
        phase: event.phase,
        headline: event.headline,
        ...(event.detail !== undefined ? { detail: event.detail } : {}),
      },
    });

    // Fan out to subscribers (best-effort; a bad sink never breaks the run).
    for (const sink of this.sinks) {
      try {
        sink(event);
      } catch {
        /* a rendering failure must not interrupt the work being narrated */
      }
    }
    return event;
  }

  /** Convenience: mark a stage started. */
  start(stage: string, headline: string, detail?: string): ProgressEvent {
    return this.narrate({ stage, phase: "start", headline, ...(detail !== undefined ? { detail } : {}) });
  }

  /** Convenience: an in-progress update within a stage. */
  update(stage: string, headline: string, fraction?: number): ProgressEvent {
    return this.narrate({ stage, phase: "update", headline, ...(fraction !== undefined ? { fraction } : {}) });
  }

  /** Convenience: mark a stage completed. */
  done(stage: string, headline: string, detail?: string): ProgressEvent {
    return this.narrate({ stage, phase: "done", headline, ...(detail !== undefined ? { detail } : {}) });
  }

  /** Mark a stage as waiting for input or authorization. */
  blocked(stage: string, headline: string, detail?: string): ProgressEvent {
    return this.narrate({ stage, phase: "blocked", headline, ...(detail !== undefined ? { detail } : {}) });
  }

  /** Mark a stage as failed. */
  failed(stage: string, headline: string, detail?: string): ProgressEvent {
    return this.narrate({ stage, phase: "failed", headline, ...(detail !== undefined ? { detail } : {}) });
  }
}

/** A sink that collects events in memory (for tests / a simple buffered interface). */
export function bufferSink(): { sink: NarrationSink; events: ProgressEvent[] } {
  const events: ProgressEvent[] = [];
  return { sink: (e) => events.push(e), events };
}
