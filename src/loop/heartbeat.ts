/**
 * Learning-loop heartbeat (Phase 0.5) — fixes coupling-bug #1.
 *
 * Original bug: `maybe_run_dream_cycle` lived on the provider-coupled worker and
 * idled when the provider key was absent — so swapping the provider silently
 * stopped the learning loop, an INVISIBLE moat-break. The build-records were
 * already provider-agnostic (keyed on outcome + origin); only the *heartbeat* was
 * coupled.
 *
 * Fix: the heartbeat runs on an always-on scheduler here, independent of any
 * provider/connector. It fires a provider-agnostic tick; the tick's work (dream,
 * consolidate) reads outcome-keyed records and routes any model calls through the
 * ModelGateway port — never a hardcoded provider.
 */

export type HeartbeatTick = () => Promise<void>;

export interface HeartbeatOptions {
  readonly intervalMs: number;
  /** Called if a tick throws, so a failing cycle can't kill the loop silently. */
  readonly onError?: (err: unknown) => void;
}

export class LearningHeartbeat {
  private timer: ReturnType<typeof setInterval> | undefined;
  private running = false;
  private tickCount = 0;

  constructor(
    private readonly tick: HeartbeatTick,
    private readonly opts: HeartbeatOptions,
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.runOnce(), this.opts.intervalMs);
    // Do not keep the process alive solely for the heartbeat.
    if (typeof this.timer === "object" && "unref" in this.timer) {
      (this.timer as { unref: () => void }).unref();
    }
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /** Run a single cycle now. Overlapping runs are skipped, not queued. */
  async runOnce(): Promise<boolean> {
    if (this.running) return false;
    this.running = true;
    try {
      await this.tick();
      this.tickCount++;
      return true;
    } catch (err) {
      // A failing cycle must never silently stop the loop.
      this.opts.onError?.(err);
      return false;
    } finally {
      this.running = false;
    }
  }

  get ticks(): number {
    return this.tickCount;
  }
}
