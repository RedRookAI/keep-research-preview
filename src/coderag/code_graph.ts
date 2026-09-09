/**
 * On-device code-structure graph (Increment 14a).
 *
 * SOTA basis (2026-08-05): the winning open-source pattern is local-first graph retrieval (RANGER;
 * LARGER 2026 beats BM25 on four localization benchmarks by anchoring lexical queries into a repo
 * graph). The decisive practicality finding (Citation-Grounded 2026): import/reference edges can be
 * extracted by REGEX from source text alone — no compilation, no AST library, ~27ms — "a pragmatic
 * middle ground between no structural reasoning and expensive whole-program analysis." The
 * actionable-for-repair edge set (SGAgent 2026) is containment, invocation, symbol reference,
 * inheritance, import — NOT dataflow/control-flow (which need heavyweight analysis). So this graph
 * models file↔symbol containment, symbol→symbol reference, file→file import, class inheritance, via
 * regex. On-device, nothing leaves the machine (Keep's sovereignty thesis). Zero deps.
 *
 * What would change it: a language we can't cheaply regex-parse → fall back to BM25+embedding for it;
 * a real tree-sitter resolver behind the same builder port for function-level call precision.
 */

import { createHash } from "node:crypto";

export type EdgeKind = "imports" | "contains" | "references" | "inherits";

export interface SymbolNode {
  readonly name: string;
  readonly file: string;
  readonly kind: "function" | "class" | "const" | "unknown";
}

export interface GraphFile {
  readonly path: string;
  readonly content: string;
}

/** Per-language extraction rules (regex-only; extend by adding a LanguageRules entry). */
interface LanguageRules {
  readonly test: (path: string) => boolean;
  /** Extract imported module specifiers from source. */
  imports(content: string): string[];
  /** Extract defined symbols (name + kind). */
  defs(content: string): { name: string; kind: SymbolNode["kind"] }[];
  /** Extract class inheritance pairs [child, parent]. */
  inherits(content: string): [string, string][];
}

const tsjs: LanguageRules = {
  test: (p) => /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(p),
  imports(content) {
    const specs: string[] = [];
    // Matches: import X from 'y' | import {A} from 'y' | import 'y' (side-effect) | require('y') | import('y')
    const re = /(?:import\s+(?:[^'"]*?\s+from\s+)?|require\(\s*|import\(\s*)['"]([^'"]+)['"]/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) if (m[1]) specs.push(m[1]);
    return specs;
  },
  defs(content) {
    const out: { name: string; kind: SymbolNode["kind"] }[] = [];
    for (const m of content.matchAll(/(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/g)) if (m[1]) out.push({ name: m[1], kind: "function" });
    for (const m of content.matchAll(/(?:export\s+)?class\s+([A-Za-z_$][\w$]*)/g)) if (m[1]) out.push({ name: m[1], kind: "class" });
    for (const m of content.matchAll(/(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g)) if (m[1]) out.push({ name: m[1], kind: "const" });
    return out;
  },
  inherits(content) {
    const out: [string, string][] = [];
    for (const m of content.matchAll(/class\s+([A-Za-z_$][\w$]*)\s+extends\s+([A-Za-z_$][\w$.]*)/g)) if (m[1] && m[2]) out.push([m[1], m[2].split(".").pop()!]);
    return out;
  },
};

const python: LanguageRules = {
  test: (p) => /\.py$/.test(p),
  imports(content) {
    const specs: string[] = [];
    for (const m of content.matchAll(/^\s*import\s+([\w.]+)/gm)) if (m[1]) specs.push(m[1]);
    for (const m of content.matchAll(/^\s*from\s+([\w.]+)\s+import/gm)) if (m[1]) specs.push(m[1]);
    return specs;
  },
  defs(content) {
    const out: { name: string; kind: SymbolNode["kind"] }[] = [];
    for (const m of content.matchAll(/^\s*def\s+([A-Za-z_]\w*)/gm)) if (m[1]) out.push({ name: m[1], kind: "function" });
    for (const m of content.matchAll(/^\s*class\s+([A-Za-z_]\w*)/gm)) if (m[1]) out.push({ name: m[1], kind: "class" });
    return out;
  },
  inherits(content) {
    const out: [string, string][] = [];
    for (const m of content.matchAll(/^\s*class\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_][\w.]*)/gm)) if (m[1] && m[2]) out.push([m[1], m[2].split(".").pop()!]);
    return out;
  },
};

const LANGUAGES: readonly LanguageRules[] = [tsjs, python];

function rulesFor(path: string): LanguageRules | undefined {
  return LANGUAGES.find((l) => l.test(path));
}

/**
 * The single sha256 mechanism for the codebase's on-device content identity. Full-length hex over a
 * string or raw bytes. `contentHash` (the graph's dirty-file key) is a truncation of this; the tree
 * fingerprint (spine/tree_fingerprint.ts) COMPOSES over it so there is exactly one hashing primitive.
 */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function contentHash(s: string): string {
  return sha256Hex(s).slice(0, 16);
}

/** Resolve a relative import specifier to a repo file path, given the importing file. */
function resolveImport(fromFile: string, spec: string, allPaths: ReadonlySet<string>): string | undefined {
  if (!spec.startsWith(".")) {
    // bare/absolute (python module or package) — try matching by trailing path segment
    const asPath = spec.replace(/\./g, "/");
    for (const p of allPaths) if (p.includes(asPath)) return p;
    return undefined;
  }
  const dir = fromFile.split("/").slice(0, -1);
  const parts = spec.split("/");
  const stack = [...dir];
  for (const part of parts) {
    if (part === "." || part === "") continue;
    if (part === "..") stack.pop();
    else stack.push(part);
  }
  const base = stack.join("/");
  // Try common extensions + index files.
  for (const cand of [base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.py`, `${base}/index.ts`, `${base}/index.js`, `${base}/__init__.py`]) {
    if (allPaths.has(cand)) return cand;
  }
  return undefined;
}

export interface CodeGraphEdge {
  readonly from: string;
  readonly to: string;
  readonly kind: EdgeKind;
}

/** The on-device code-structure graph. */
export class CodeGraph {
  private readonly fileHash = new Map<string, string>();
  private readonly symbolsByFile = new Map<string, SymbolNode[]>();
  private readonly symbolToFiles = new Map<string, Set<string>>(); // symbol name → files defining it
  private edges: CodeGraphEdge[] = [];

  /** Build/rebuild the whole graph from a file set. */
  build(files: readonly GraphFile[]): void {
    this.fileHash.clear();
    this.symbolsByFile.clear();
    this.symbolToFiles.clear();
    this.edges = [];
    for (const f of files) this.indexFile(f);
    this.rebuildEdges(files);
  }

  /**
   * Incremental re-index: only re-process files whose content hash changed (Merkle-style dirty-file
   * re-index, like claude-context but on-device). Returns the set of files actually re-indexed.
   */
  update(files: readonly GraphFile[]): string[] {
    const dirty: string[] = [];
    const present = new Set(files.map((f) => f.path));
    // Drop files that disappeared.
    for (const known of [...this.fileHash.keys()]) if (!present.has(known)) { this.dropFile(known); dirty.push(known); }
    for (const f of files) {
      const h = contentHash(f.content);
      if (this.fileHash.get(f.path) === h) continue; // unchanged — skip
      this.dropFile(f.path);
      this.indexFile(f);
      dirty.push(f.path);
    }
    if (dirty.length > 0) this.rebuildEdges(files);
    return dirty;
  }

  private indexFile(f: GraphFile): void {
    this.fileHash.set(f.path, contentHash(f.content));
    const rules = rulesFor(f.path);
    const syms: SymbolNode[] = [];
    if (rules) {
      for (const d of rules.defs(f.content)) {
        syms.push({ name: d.name, file: f.path, kind: d.kind });
        if (!this.symbolToFiles.has(d.name)) this.symbolToFiles.set(d.name, new Set());
        this.symbolToFiles.get(d.name)!.add(f.path);
      }
    }
    this.symbolsByFile.set(f.path, syms);
  }

  private dropFile(path: string): void {
    this.fileHash.delete(path);
    const syms = this.symbolsByFile.get(path) ?? [];
    for (const s of syms) this.symbolToFiles.get(s.name)?.delete(path);
    this.symbolsByFile.delete(path);
  }

  /** Recompute edges (import/contains/references/inherits) from current file contents. */
  private rebuildEdges(files: readonly GraphFile[]): void {
    const paths = new Set(files.map((f) => f.path));
    const byPath = new Map(files.map((f) => [f.path, f]));
    const edges: CodeGraphEdge[] = [];

    for (const f of files) {
      const rules = rulesFor(f.path);
      if (!rules) continue;

      // contains: file → each symbol it defines
      for (const s of this.symbolsByFile.get(f.path) ?? []) edges.push({ from: f.path, to: `${f.path}#${s.name}`, kind: "contains" });

      // imports: file → resolved file
      for (const spec of rules.imports(f.content)) {
        const target = resolveImport(f.path, spec, paths);
        if (target && target !== f.path) edges.push({ from: f.path, to: target, kind: "imports" });
      }

      // inherits: class → parent's defining file (if resolvable)
      for (const [, parent] of rules.inherits(f.content)) {
        const parentFiles = this.symbolToFiles.get(parent);
        if (parentFiles) for (const pf of parentFiles) if (pf !== f.path) edges.push({ from: f.path, to: pf, kind: "inherits" });
      }

      // references: file → files defining a symbol this file mentions (cheap cross-file ref signal)
      const mentioned = new Set<string>();
      for (const [name, defFiles] of this.symbolToFiles) {
        if (defFiles.has(f.path)) continue; // defined here, not a cross-file ref
        // word-boundary mention check
        if (new RegExp(`\\b${escapeRe(name)}\\b`).test(byPath.get(f.path)!.content)) {
          for (const df of defFiles) mentioned.add(df);
        }
      }
      for (const df of mentioned) edges.push({ from: f.path, to: df, kind: "references" });
    }
    this.edges = edges;
  }

  /** Files directly connected to `file` within `hops` (bounded traversal — one-hop is usually enough). */
  neighbors(file: string, hops = 1): Set<string> {
    const seen = new Set<string>([file]);
    let frontier = new Set<string>([file]);
    for (let h = 0; h < hops; h++) {
      const next = new Set<string>();
      for (const node of frontier) {
        for (const e of this.edges) {
          const other = e.from === node ? e.to : e.to === node ? e.from : undefined;
          if (!other) continue;
          const otherFile = other.split("#")[0]!;
          if (!seen.has(otherFile)) { seen.add(otherFile); next.add(otherFile); }
        }
      }
      frontier = next;
      if (frontier.size === 0) break;
    }
    seen.delete(file);
    return seen;
  }

  /** Files that define a given symbol name. */
  filesDefining(symbol: string): string[] { return [...(this.symbolToFiles.get(symbol) ?? [])]; }

  /** Symbols defined in a file. */
  symbolsOf(file: string): readonly SymbolNode[] { return this.symbolsByFile.get(file) ?? []; }

  allEdges(): readonly CodeGraphEdge[] { return this.edges; }
  get fileCount(): number { return this.fileHash.size; }
  get edgeCount(): number { return this.edges.length; }
}

function escapeRe(s: string): string { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
