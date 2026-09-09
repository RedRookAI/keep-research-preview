/**
 * Theme 2 (Currency Layer), Part 2 — LandscapeCatalog.
 *
 * So Keep can say "this already exists — adopt it" instead of reinventing the wheel, it
 * carries a small, DATED catalog of known options by task-type, refreshable from search
 * on the connected env. Reuses F1.9's staleness pattern (asOf / isStale). Entries are
 * labeled by cost and license so the operator's locked principle is structural:
 * FREE/OPEN options are always surfaced first; paid options appear only when present and
 * are clearly labeled, never with any affiliate incentive.
 */

import { Bm25Index } from "./bm25.js";

export type CostClass = "free" | "freemium" | "paid";

export interface LandscapeEntry {
  readonly name: string;
  /** What it does, in plain language. */
  readonly summary: string;
  /** Task keywords this option is relevant to. */
  readonly tags: readonly string[];
  readonly cost: CostClass;
  /** License (for the build-vs-adopt licensing axis), if known. */
  readonly license?: string;
  /** Where to learn more (surfaced to the human, never auto-fetched). */
  readonly url?: string;
  /** ISO date this entry was last confirmed current. */
  readonly asOf: string;
}

const STALE_AFTER_DAYS = 120;

function todayISO(now: Date = new Date()): string {
  return now.toISOString().slice(0, 10);
}

/** A small, honestly-dated seed. Refreshed from search on the connected env. */
const SEED_AS_OF = "2026-08-01";
const SEED: readonly LandscapeEntry[] = [
  { name: "OpenClaw", summary: "Self-hostable AI agent gateway with channels and a soul.md-style persona.", tags: ["agent", "gateway", "self-host", "chat", "persona"], cost: "free", license: "open-source", url: "https://openclaw.ai", asOf: SEED_AS_OF },
  { name: "Hermes", summary: "Open agent runtime / assistant framework.", tags: ["agent", "runtime", "assistant", "framework"], cost: "free", license: "open-source", asOf: SEED_AS_OF },
  { name: "ElevenLabs", summary: "High-quality text-to-speech / voice synthesis (bring-your-own API key).", tags: ["voice", "tts", "audio", "audiobook", "narration"], cost: "paid", license: "commercial", url: "https://elevenlabs.io", asOf: SEED_AS_OF },
  { name: "Whisper-class local STT", summary: "Run speech-to-text locally, no cloud needed (open weights).", tags: ["voice", "stt", "transcription", "audio", "offline"], cost: "free", license: "open-weights", asOf: SEED_AS_OF },
  { name: "ffmpeg", summary: "Swiss-army tool for audio/video conversion and processing.", tags: ["audio", "video", "convert", "media", "encode"], cost: "free", license: "LGPL/GPL", asOf: SEED_AS_OF },
  { name: "Pandoc", summary: "Convert between document formats (Markdown, docx, PDF, EPUB).", tags: ["document", "convert", "markdown", "pdf", "epub", "book"], cost: "free", license: "GPL", asOf: SEED_AS_OF },
];

export class LandscapeCatalog {
  private readonly entries: LandscapeEntry[];
  private asOf: string;

  constructor(seed: readonly LandscapeEntry[] = SEED, asOf: string = SEED_AS_OF) {
    this.entries = [...seed];
    this.asOf = asOf;
  }

  /** Fold in newly-discovered options (from a connected-env search) and bump asOf. */
  refresh(entries: readonly LandscapeEntry[], asOf?: string): void {
    for (const e of entries) {
      const idx = this.entries.findIndex((x) => x.name.toLowerCase() === e.name.toLowerCase());
      if (idx >= 0) this.entries[idx] = e;
      else this.entries.push(e);
    }
    this.asOf = asOf ?? todayISO();
  }

  /**
   * Options relevant to a task, ranked by BM25 (rare/specific term matches outrank
   * common ones — so a "tts" query no longer treats a generic "audio" tag as an equal
   * match). Free/open options are preferred as a tiebreaker WITHIN the same relevance
   * band, preserving the locked free-first principle without letting a barely-relevant
   * free option outrank a strongly-relevant paid one.
   */
  matchesTask(keywords: readonly string[]): LandscapeEntry[] {
    const index = new Bm25Index();
    index.index(this.entries.map((e, i) => ({ id: String(i), text: `${e.name} ${e.summary} ${e.tags.join(" ")}` })));
    const hits = index.search(keywords.join(" "), this.entries.length);
    if (hits.length === 0) return [];

    // Group hits into relevance bands (round score) so free-first only reorders
    // options of comparable relevance, never a weak match above a strong one.
    const withEntries = hits.map((h) => ({ entry: this.entries[Number(h.id)]!, score: h.score }));
    withEntries.sort((a, b) => {
      const band = Math.round(b.score * 2) - Math.round(a.score * 2);
      if (band !== 0) return band;
      return costRank(a.entry.cost) - costRank(b.entry.cost); // free-first tiebreak
    });
    return withEntries.map((w) => w.entry);
  }

  isStale(now: Date = new Date()): boolean {
    const ageDays = (Date.parse(todayISO(now)) - Date.parse(this.asOf)) / 86_400_000;
    return ageDays > STALE_AFTER_DAYS;
  }

  stalenessNote(now: Date = new Date()): string {
    return this.isStale(now)
      ? `This list of existing options is from ${this.asOf} and may be out of date — there may be newer tools I don't know about. Worth a fresh check before deciding.`
      : `Options current as of ${this.asOf}.`;
  }
}

/** Free first, then freemium, then paid (the locked free-first principle). */
function costRank(c: CostClass): number {
  return c === "free" ? 0 : c === "freemium" ? 1 : 2;
}
