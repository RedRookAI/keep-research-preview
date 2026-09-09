/**
 * R-EGRESS-STREAM — rolling-window rehydration for STREAMED (SSE) responses. The egress interceptor rehydrates a whole
 * response string on the non-streaming path; but SSE deltas are split on TOKEN boundaries, not semantic ones, so a
 * surrogate token `⟦email#1⟧` routinely arrives as `⟦email#` then `1⟧`. Rehydrate each chunk independently and the
 * surrogate is never seen whole — it leaks to the caller un-restored (RavenGate 2026). This wraps the interceptor's own
 * `rehydrate` closure (NO new redactor, NO second vault) with a stateful sliding-window buffer.
 *
 * SAFE: a surrogate never escapes un-rehydrated across a chunk boundary; a PARTIAL surrogate is never emitted.
 * FAITHFUL: the concatenation of all emitted output is BYTE-EXACT with rehydrating the full response at once.
 * BOUNDED: only the minimal tail that could still be a partial surrogate is held; a stray `⟦` that never closes within
 * the max surrogate length is emitted as-is, so a clean stream never stalls (pipelock 2026: bounded rolling tail).
 */

const OPEN = "\u27E6"; // ⟦
const CLOSE = "\u27E7"; // ⟧

export class StreamingRehydrator {
  private buf = "";

  /**
   * @param rehydrate the interceptor's per-call rehydrate closure (surrogate → real value from the ephemeral vault).
   * @param maxSurrogateLen the longest a real surrogate token can be; a dangling `⟦` longer than this is NOT a
   *   surrogate, so it is released rather than held (keeps the stream flowing; no unbounded buffer). Default 128.
   */
  constructor(private readonly rehydrate: (s: string) => string, private readonly maxSurrogateLen = 128) {}

  /** Feed one streamed chunk; returns the rehydrated text that is SAFE to emit now (a partial surrogate is held back). */
  push(chunk: string): string {
    this.buf += chunk;
    // Hold from the last OPEN that has no CLOSE after it — everything from there could be a partial surrogate.
    const lastOpen = this.buf.lastIndexOf(OPEN);
    let holdFrom = this.buf.length; // default: nothing held (no dangling open)
    if (lastOpen !== -1 && this.buf.indexOf(CLOSE, lastOpen) === -1) {
      // A dangling open. Hold it ONLY if the tail is still short enough to be a real surrogate (bounded window).
      if (this.buf.length - lastOpen <= this.maxSurrogateLen) holdFrom = lastOpen;
    }
    const emit = this.buf.slice(0, holdFrom);
    this.buf = this.buf.slice(holdFrom);
    // The emitted prefix contains only COMPLETE surrogates (holdFrom sits at a dangling open), so per-region rehydrate
    // equals whole-string rehydrate — byte-exact with the non-streamed path.
    return this.rehydrate(emit);
  }

  /** End of stream: rehydrate + emit whatever remains (a never-closed `⟦…` is literal text; rehydrate is a no-op on it). */
  flush(): string {
    const out = this.rehydrate(this.buf);
    this.buf = "";
    return out;
  }
}

/**
 * Convenience: rehydrate an async stream of chunks end-to-end, yielding safe-to-emit rehydrated text. Composes the
 * StreamingRehydrator; the final flush is yielded last so no buffered tail is dropped.
 */
export async function* rehydrateStream(
  chunks: AsyncIterable<string>,
  rehydrate: (s: string) => string,
  maxSurrogateLen = 128,
): AsyncGenerator<string> {
  const r = new StreamingRehydrator(rehydrate, maxSurrogateLen);
  for await (const c of chunks) {
    const out = r.push(c);
    if (out.length > 0) yield out;
  }
  const tail = r.flush();
  if (tail.length > 0) yield tail;
}
