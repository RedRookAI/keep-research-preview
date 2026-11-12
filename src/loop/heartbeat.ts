/**
 * Provider-independent scheduler for learning-loop ticks.
 *
 * Ticks read outcome-keyed records and can run consolidation or dream-cycle work. Any model requests
 * use the ModelGateway port; an absent provider credential does not disable the scheduler itself.
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
