/**
 * Incremental SSE text decoder for Keep's provider transports.
 *
 * Supported framing rules:
 *  - Events are terminated by a blank line (\n\n); a single event may have multiple `data:` lines
 *    which are joined with newlines.
 *  - A JSON payload can be split across network chunk boundaries, so a BUFFER must accumulate partial
 *    lines and only complete (\n\n-delimited) events are emitted.
 *  - `:` lines are comments/heartbeats and are ignored.
 *  - Normalized buffered text has a configured UTF8 byte cap, checked before each feed is emitted.
 * This is not an aggregate output/memory bound. finish() intentionally accepts an undelimited
 * final block for provider compatibility, unlike strict EventSource framing. The provider owns
 * error/terminal interpretation; this decoder alone cannot establish successful generation.
 *
 * Zero deps. This module is transport-agnostic: it decodes text; the provider maps decoded events to
 * dialect deltas.
 */

export interface SseEvent {
  /** The concatenated `data:` payload (multi-line joined with \n), trimmed of the field prefix. */
  readonly data: string;
  /** The `event:` type if present. */
  readonly event?: string;
  /** The `id:` if present. */
  readonly id?: string;
}

export interface SseDecoderOptions {
  /** Positive integer UTF8 byte cap on normalized decoded buffer, including framing, before
   * each feed is dispatched. Not raw wire bytes or an aggregate output cap. Default 8 MiB. */
  readonly maxBufferBytes?: number;
}

/**
 * A stateful, incremental SSE decoder. Feed it text chunks (already decoded from bytes); it returns
 * the complete events available so far, keeping any partial trailing event buffered. Throws if the
 * buffer exceeds the cap (a single unterminated event that never completes).
 */
export class SseDecoder {
  private buffer = "";
  private previousEndedWithCr = false;
  private readonly maxBufferBytes: number;

  constructor(opts: SseDecoderOptions = {}) {
    this.maxBufferBytes = opts.maxBufferBytes ?? 8 * 1024 * 1024;
    if (!Number.isSafeInteger(this.maxBufferBytes) || this.maxBufferBytes < 1) throw new Error("SSE buffer byte limit must be a positive safe integer");
  }

  /** Feed a text chunk; returns any newly-complete events. */
  feed(chunk: string): SseEvent[] {
    // A CR is already a newline; swallow only its following LF, even across feeds.
    if (chunk.length === 0) return [];
    const endedWithCr = chunk.endsWith("\r");
    if (this.previousEndedWithCr && chunk.startsWith("\n")) chunk = chunk.slice(1);
    this.previousEndedWithCr = endedWithCr;
    this.buffer += chunk.replace(/\r\n?/g, "\n");
    if (Buffer.byteLength(this.buffer, "utf8") > this.maxBufferBytes) {
      throw new Error(`SSE buffer overflow (> ${this.maxBufferBytes} bytes) — malformed or unterminated stream`);
    }
    const events: SseEvent[] = [];
    let idx: number;
    // A blank line (\n\n) terminates an event. Emit every complete one; keep the remainder buffered.
    while ((idx = this.buffer.indexOf("\n\n")) !== -1) {
      const raw = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 2);
      const ev = parseEventBlock(raw);
      if (ev) events.push(ev);
    }
    return events;
  }

  /**
   * Compatibility: parse the final buffered block even without a terminating blank line.
   * Its data may be incomplete; the caller still owns JSON and terminal validation.
   */
  finish(): SseEvent[] {
    const rest = this.buffer.trim();
    this.buffer = "";
    this.previousEndedWithCr = false;
    if (rest === "") return [];
    const ev = parseEventBlock(rest);
    return ev ? [ev] : [];
  }
}

/** Parse one event block (the text between blank lines) into an SseEvent, or null if it has no data. */
function parseEventBlock(block: string): SseEvent | null {
  const dataLines: string[] = [];
  let event: string | undefined;
  let id: string | undefined;
  for (const line of block.split("\n")) {
    if (line === "" || line.startsWith(":")) continue; // blank or comment/heartbeat
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    // Per spec, a single leading space after the colon is stripped.
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") dataLines.push(value);
    else if (field === "event") event = value;
    else if (field === "id") id = value;
  }
  if (dataLines.length === 0) return null;
  return {
    data: dataLines.join("\n"),
    ...(event !== undefined ? { event } : {}),
    ...(id !== undefined ? { id } : {}),
  };
}

/**
 * One-shot convenience: decode a complete SSE text body into events (for non-incremental callers/tests).
 */
export function parseSse(body: string, opts?: SseDecoderOptions): SseEvent[] {
  const d = new SseDecoder(opts);
  return [...d.feed(body), ...d.finish()];
}
