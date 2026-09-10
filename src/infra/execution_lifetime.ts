/** Cancellation owns a stop request and a bounded wait, never a proof of termination. */
export interface ExecutionContext {
  readonly signal?: AbortSignal;
  /** Absolute Unix milliseconds. Cleanup may extend beyond this deadline. */
  readonly deadline?: number;
  /** How long to observe completion after stop. This is not a containment guarantee. */
  readonly terminationGraceMs?: number;
}

export function executionStopReason(context?: ExecutionContext): string | undefined {
  if (context?.deadline !== undefined && !Number.isFinite(context.deadline)) return "invalid execution deadline";
  if (context?.terminationGraceMs !== undefined && (!Number.isFinite(context.terminationGraceMs) || context.terminationGraceMs < 0)) return "invalid termination observation interval";
  if (context?.signal?.aborted) return "execution cancelled";
  if (context?.deadline !== undefined && Date.now() >= context.deadline) return "execution deadline exhausted";
  return undefined;
}

/** Avoid Node's overflowing timeout becoming a one-millisecond timeout. */
export function atDeadline(deadline: number, callback: () => void): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let cancelled = false;
  const arm = () => {
    if (cancelled) return;
    const remaining = deadline - Date.now();
    if (remaining <= 0) { callback(); return; }
    timer = setTimeout(arm, Math.min(remaining, 2_147_483_647));
  };
  arm();
  return () => { cancelled = true; if (timer) clearTimeout(timer); };
}

export interface ExecutionLifetime<T> {
  readonly invoked: boolean;
  /** returned describes the callback promise, not child/descendant termination. */
  readonly completion: "not-started" | "returned" | "unconfirmed";
  readonly value?: T;
  readonly error?: string;
  readonly stopReason?: string;
}

/**
 * Invoke once with a linked signal. On stop, observe settlement for one finite grace
 * interval; a non-cooperating callback remains explicitly unconfirmed. Late values
 * and rejections are consumed but cannot change this attempt's terminal verdict.
 */
export async function withExecutionLifetime<T>(
  invoke: (context: ExecutionContext) => Promise<T>,
  context: ExecutionContext = {},
  timeoutMs?: number,
): Promise<ExecutionLifetime<T>> {
  if (timeoutMs !== undefined && (!Number.isFinite(timeoutMs) || timeoutMs < 0)) return { invoked: false, completion: "not-started", stopReason: "invalid execution timeout" };
  const deadline = Math.min(context.deadline ?? Infinity, timeoutMs === undefined ? Infinity : Date.now() + timeoutMs);
  const effective: ExecutionContext = { ...context, ...(deadline !== Infinity ? { deadline } : {}) };
  const early = executionStopReason(effective);
  if (early) return { invoked: false, completion: "not-started", stopReason: early };
  const controller = new AbortController();
  const grace = context.terminationGraceMs ?? 1000;
  let stopReason: string | undefined;
  let cancelGrace = () => {};
  let resolveStop!: () => void;
  const stopped = new Promise<void>(resolve => { resolveStop = resolve; });
  const stop = (reason: string) => {
    if (stopReason) return;
    stopReason = reason;
    // Arm before listeners: a synchronous cooperative completion does not reset grace.
    cancelGrace = atDeadline(Date.now() + grace, resolveStop);
    controller.abort();
  };
  const onAbort = () => stop("execution cancelled");
  context.signal?.addEventListener("abort", onAbort, { once: true });
  const cancelDeadline = deadline === Infinity ? () => {} : atDeadline(deadline, () => stop("execution deadline exhausted"));
  try {
    const latePrecheck = executionStopReason(effective);
    if (latePrecheck || stopReason) return { invoked: false, completion: "not-started", stopReason: latePrecheck ?? stopReason! };
    // Catch both synchronous throws and late asynchronous rejection, including after timeout.
    let operation: Promise<T>;
    try { operation = invoke({ ...effective, signal: controller.signal, terminationGraceMs: grace }); }
    catch (error) { operation = Promise.reject(error); }
    const settled = operation.then(
      value => ({ value }),
      error => ({ error: error instanceof Error ? error.message : String(error) }),
    );
    const outcome = await Promise.race([settled, stopped.then(() => undefined)]);
    // Timer callbacks may be delayed by a busy event loop. Check the absolute bound too.
    const finalStop = stopReason ?? executionStopReason(effective);
    if (outcome === undefined) return { invoked: true, completion: "unconfirmed", stopReason: finalStop ?? "execution stopped" };
    return { invoked: true, completion: "returned", ...outcome, ...(finalStop ? { stopReason: finalStop } : {}) };
  } finally {
    cancelDeadline(); cancelGrace(); context.signal?.removeEventListener("abort", onAbort);
  }
}
