/**
 * INTAKE SAFE-PARSING REGISTRY — Hardening H3 (hardens Round 7's parser SEAM).
 *
 * Decompression bombs are a live 2026 surface: non-recursive zip bombs reach 281 TB from 10 MB (4.5 PB with
 * Zip64), and CVE-2025-6176 compresses 80 GiB into 64 KB via Brotli. A system that auto-parses untrusted uploads
 * must bound resources or be DoS'd (CWE-400 uncontrolled resource consumption, CWE-409 improper handling of highly
 * compressed data). The defenses are specific and FORMAT-TECHNIQUE-AGNOSTIC:
 *   - bound the DECOMPRESSED OUTPUT size in real time (NOT the input size — checking only the small compressed
 *     input is exactly what bomb defenses miss);
 *   - cap nesting/recursion depth;
 *   - reject on compression RATIO (a tiny input claiming a huge output).
 *
 * This registry registers a per-kind parser (the SEAM — the real codec) and dispatches by kind, wrapping every
 * parse in that resource-bound gate. It returns a TYPED result — never a throw, never an unbounded parse — so an
 * untrusted upload cannot exhaust the box. Extracted content stays tainted (untrusted).
 *
 * BUILT + proven in-env: the registry dispatch + the resource-bound gate. SEAM: the real per-format codecs (the
 * `RegisteredParser`s — voice→text, image→text, zip expansion).
 */

import type { IntakeItem, Parser } from "./intake.js";
import { tainted, type Labeled } from "../provenance/taint_tracer.js";

export interface ResourceBudget {
  /** cap on the DECOMPRESSED output size in bytes (bound the output, not the input). */
  readonly maxOutputBytes: number;
  /** cap on nesting/recursion depth (nested archives). */
  readonly maxDepth: number;
  /** reject if output/input byte ratio exceeds this (the classic bomb heuristic). */
  readonly maxRatio: number;
}

/** Conservative defaults: 10 MB output, depth 8, ratio 1000:1 (a null-byte DEFLATE payload exceeds ~1000:1). */
export const DEFAULT_BUDGET: ResourceBudget = { maxOutputBytes: 10_000_000, maxDepth: 8, maxRatio: 1000 };

/** What a registered parser returns. SEAM: the real codec produces `text` and reports the `depth` it encountered. */
export interface ParseOutput {
  readonly text: string;
  readonly depth?: number; // nesting depth encountered (default 1)
}
export type RegisteredParser = (item: IntakeItem) => ParseOutput | undefined;

export type RejectReason = "output-too-large" | "too-deep" | "ratio-exceeded";

export type ParseResult =
  | { readonly status: "parsed"; readonly text: Labeled<string> } // tainted (untrusted)
  | { readonly status: "rejected"; readonly reason: RejectReason }
  | { readonly status: "unsupported"; readonly kind: string };

function byteLen(s: string): number {
  return Buffer.byteLength(s, "utf8");
}

export class ParserRegistry {
  private readonly parsers = new Map<string, RegisteredParser>();

  constructor(private readonly budget: ResourceBudget = DEFAULT_BUDGET) {}

  /** Register a per-kind parser (the SEAM). */
  register(kind: string, parser: RegisteredParser): void {
    this.parsers.set(kind, parser);
  }

  /**
   * Dispatch by kind and parse, wrapping the parse in the resource-bound gate. Total + fail-safe — never throws,
   * never returns an unbounded result. A throwing codec degrades to `unsupported`.
   */
  parse(item: IntakeItem): ParseResult {
    const parser = this.parsers.get(item.kind);
    if (parser === undefined) return { status: "unsupported", kind: item.kind };

    let out: ParseOutput | undefined;
    try {
      out = parser(item);
    } catch {
      return { status: "unsupported", kind: item.kind }; // a throwing codec degrades gracefully
    }
    if (out === undefined) return { status: "unsupported", kind: item.kind };

    // resource-bound gate — bound the OUTPUT, the depth, and the ratio.
    const outputBytes = byteLen(out.text);
    if (outputBytes > this.budget.maxOutputBytes) return { status: "rejected", reason: "output-too-large" };

    const depth = out.depth ?? 1;
    if (depth > this.budget.maxDepth) return { status: "rejected", reason: "too-deep" };

    const inputBytes = Math.max(1, byteLen(item.content));
    if (outputBytes / inputBytes > this.budget.maxRatio) return { status: "rejected", reason: "ratio-exceeded" };

    return { status: "parsed", text: tainted(out.text, `parser:${item.kind}`) }; // extracted content is untrusted
  }

  /**
   * Adapt the registry into a `Parser` for `routeIntake`: returns the extracted text on success, or `undefined`
   * on reject/unsupported (so intake degrades gracefully — a bomb becomes an unsupported item, not a crash).
   */
  asParser(): Parser {
    return (item: IntakeItem): string | undefined => {
      const r = this.parse(item);
      return r.status === "parsed" ? r.text.value : undefined;
    };
  }
}
