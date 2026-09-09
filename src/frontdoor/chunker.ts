/**
 * F3a — Chunker + prompt-injection sanitizer (the hostile-input front line).
 *
 * A dropped project/zip/large paste is a PRIME injection vector — GitInject (2026)
 * showed a malicious config file can turn low-trust input into "trusted project
 * guidance" and exfiltrate secrets. So before any chunk reaches a model we sanitize
 * the silent-confusion vectors (the enclawed defense) AND (elsewhere) run it through
 * the existing hostile ingestion gate.
 *
 * Chunking follows the 2026 baseline: recursive ~512-token chunks (ranked first across
 * strategies; a "context cliff" ~2,500 tokens means chunking helps even large-context
 * models). Overlap is a TUNABLE, not a mandatory default (a Jan-2026 analysis found it
 * added cost without benefit in some setups). Code is split structure-aware.
 *
 * What would change it: a long-context embedding model on the connected env enables
 * late/contextual chunking as an upgrade behind the same interface.
 */

export interface Chunk {
  readonly text: string;
  /** Where it came from (e.g. a file path or "pasted-goal"). */
  readonly source: string;
  /** 0-based index within its source. */
  readonly index: number;
  readonly approxTokens: number;
}

/** Zero-dep token estimate (~4 chars/token). */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Sanitize text that will flow into a model prompt from an untrusted source. Strips
 * control chars, Unicode bidirectional overrides, and zero-width characters so an
 * injected instruction surfaces as VISIBLE content, not a hidden control signal.
 * (Not a complete prompt-injection defense — that's an open problem — but it removes
 * the most common silent-confusion vectors, as the enclawed framework documents.)
 */
export function sanitizeForPrompt(text: string): string {
  let out = "";
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    // 1. C0 control chars (0x00-0x1F) except TAB(0x09)/LF(0x0A)/CR(0x0D) -> replacement char.
    if (cp <= 0x1f && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) {
      out += "\uFFFD";
      continue;
    }
    // 2. Bidi overrides U+202A-202E and U+2066-2069 -> dropped.
    if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) continue;
    // 3. Zero-width chars U+200B-200D, U+2060, U+FEFF -> dropped.
    if ((cp >= 0x200b && cp <= 0x200d) || cp === 0x2060 || cp === 0xfeff) continue;
    out += ch;
  }
  return out;
}

export interface ChunkOptions {
  /** Target chunk size in approx tokens (2026 baseline ~512; 512-1024 defensible). */
  readonly targetTokens?: number;
  /** Overlap in approx tokens between consecutive chunks (a tunable; default 0). */
  readonly overlapTokens?: number;
  readonly source?: string;
}

const DEFAULT_TARGET = 512;

/**
 * Recursive text chunking: split on paragraph, then sentence, then hard length, to
 * keep chunks near the target size without cutting mid-thought where avoidable.
 * Sanitizes each chunk. Overlap is applied only if requested.
 */
export function chunkText(raw: string, opts: ChunkOptions = {}): Chunk[] {
  const target = opts.targetTokens ?? DEFAULT_TARGET;
  const overlap = opts.overlapTokens ?? 0;
  const source = opts.source ?? "input";
  const targetChars = target * 4;
  const overlapChars = overlap * 4;

  const clean = sanitizeForPrompt(raw);
  // Split into paragraphs, then greedily pack into target-sized chunks.
  const paras = clean.split(/\n\s*\n/).map((p) => p.trim()).filter((p) => p.length > 0);
  const rawChunks: string[] = [];
  let buf = "";
  for (const para of paras) {
    if (para.length > targetChars) {
      // A huge paragraph: flush, then hard-split it by sentence/length.
      if (buf) { rawChunks.push(buf); buf = ""; }
      for (const piece of hardSplit(para, targetChars)) rawChunks.push(piece);
      continue;
    }
    if (buf.length + para.length + 2 > targetChars) {
      rawChunks.push(buf);
      buf = para;
    } else {
      buf = buf ? `${buf}\n\n${para}` : para;
    }
  }
  if (buf) rawChunks.push(buf);

  // Apply overlap (prepend the tail of the previous chunk) if requested.
  const withOverlap = overlapChars > 0
    ? rawChunks.map((c, i) => (i === 0 ? c : `${rawChunks[i - 1]!.slice(-overlapChars)}\n${c}`))
    : rawChunks;

  return withOverlap.map((text, index) => ({ text, source, index, approxTokens: estimateTokens(text) }));
}

/** Hard-split an overlong string by sentence boundaries, then by length. */
function hardSplit(s: string, maxChars: number): string[] {
  const sentences = s.split(/(?<=[.!?])\s+/);
  const out: string[] = [];
  let buf = "";
  for (const sent of sentences) {
    if (sent.length > maxChars) {
      if (buf) { out.push(buf); buf = ""; }
      for (let i = 0; i < sent.length; i += maxChars) out.push(sent.slice(i, i + maxChars));
      continue;
    }
    if (buf.length + sent.length + 1 > maxChars) { out.push(buf); buf = sent; }
    else buf = buf ? `${buf} ${sent}` : sent;
  }
  if (buf) out.push(buf);
  return out;
}

/**
 * Structure-aware code chunking: split on top-level block boundaries (blank lines
 * between functions/classes) while respecting the target size. Falls back to
 * chunkText's packing for the boundaries. Preserves whole logical blocks where they
 * fit, per the 2026 "split by function/logical block" guidance for code.
 */
export function chunkCode(raw: string, opts: ChunkOptions = {}): Chunk[] {
  const target = opts.targetTokens ?? DEFAULT_TARGET;
  const source = opts.source ?? "code";
  const targetChars = target * 4;
  const clean = sanitizeForPrompt(raw);

  // Split into logical blocks on blank lines (functions/classes are usually separated).
  const blocks = clean.split(/\n\s*\n/).filter((b) => b.trim().length > 0);
  const chunks: string[] = [];
  let buf = "";
  for (const block of blocks) {
    if (block.length > targetChars) {
      if (buf) { chunks.push(buf); buf = ""; }
      // A very large block: split by line while respecting size.
      let lineBuf = "";
      for (const line of block.split("\n")) {
        if (lineBuf.length + line.length + 1 > targetChars) { chunks.push(lineBuf); lineBuf = line; }
        else lineBuf = lineBuf ? `${lineBuf}\n${line}` : line;
      }
      if (lineBuf) chunks.push(lineBuf);
      continue;
    }
    if (buf.length + block.length + 2 > targetChars) { chunks.push(buf); buf = block; }
    else buf = buf ? `${buf}\n\n${block}` : block;
  }
  if (buf) chunks.push(buf);

  return chunks.map((text, index) => ({ text, source, index, approxTokens: estimateTokens(text) }));
}
