/**
 * Autonomy Engine — ProgressNarrator (build item 1).
 *
 * The "don't stare at a blank screen" layer. Every loop and stage of the autonomy engine
 * emits progress through this so the operator always sees a sentence or two about what's
 * happening. Per 2026 agent-UX SOTA, the interface is "the accountability layer between
 * user intent and autonomous action" — so narration is STRUCTURED TYPED EVENTS, not raw
 * strings, and the interface renders them at its chosen density (calm headline by default,
 * detail on demand). The event shape mirrors AG-UI's start/content/finish lifecycle so a
 * wire adapter is a clean mapping later, not a rewrite.
 *
 * Honest-by-construction: an event only reports what the CALLING code says is actually
 * happening (a real stage transition, a real tool call). The narrator has no ability to
 * fabricate progress — it is a reporting channel, not a predictor. Every event is
 * spine-logged, so the narration doubles as the auditable trace of what the autonomous
 * engine did (the "safe, auditable autonomy" requirement). Zero deps.
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

  /** Emit a progress event. Honest-by-construction: reports only what the caller states. */
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

    // Spine-log for the auditable trace (accountability layer).
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
        // ROUND 40: the DETAIL was being dropped here. Every narrated event carries a headline
        // for the feed and a detail for the specifics, and only the headline reached the spine —
        // so the tamper-evident record held "A safety control is configured OFF" without saying
        // WHICH control, and an auditor reading the trace could not reconstruct what was said to
        // the operator. Same shape as the floor's reasons being discarded by composeGate (Z163):
        // the information existed and was lost in transit at a layer boundary.
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

  /** Convenience: the stage is waiting on the human (gated). Honest, not hidden. */
  blocked(stage: string, headline: string, detail?: string): ProgressEvent {
    return this.narrate({ stage, phase: "blocked", headline, ...(detail !== undefined ? { detail } : {}) });
  }

  /** Convenience: the stage failed. Honest framing — never pretend success. */
  failed(stage: string, headline: string, detail?: string): ProgressEvent {
    return this.narrate({ stage, phase: "failed", headline, ...(detail !== undefined ? { detail } : {}) });
  }
}

/** A sink that collects events in memory (for tests / a simple buffered interface). */
export function bufferSink(): { sink: NarrationSink; events: ProgressEvent[] } {
  const events: ProgressEvent[] = [];
  return { sink: (e) => events.push(e), events };
}
