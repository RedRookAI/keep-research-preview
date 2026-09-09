/**
 * Structural edit differ (Phase 3.5, Feature 5 core).
 *
 * Turns a human edit (what Keep produced vs. what the human shipped) into a
 * GENERALIZED, reusable lesson — not a memorized before/after pair. It tokenizes
 * both sides, computes a token-level diff, and classifies the change into a
 * structural pattern; the lesson describes the pattern, and a signature lets the
 * shadow-mode corpus and retrieval match RECURRENCES OF THE PATTERN, not the text.
 *
 * Design choice: token-structural, not per-language AST. Keep is polyglot; a
 * language-agnostic structural classifier generalizes across languages where a
 * per-language parser would fragment. (What would change it: if a deployment is
 * single-language and wants deep semantic edits, a tree-sitter adapter can plug in
 * behind `analyzeEdit` — the signature/lesson contract stays the same.)
 */

export type TokenKind = "word" | "number" | "string" | "op" | "punct" | "space";

export interface Token {
  readonly kind: TokenKind;
  readonly text: string;
}

// Multi-char operators first so they tokenize as a unit.
const MULTI_OPS = [
  "===", "!==", "<<=", ">>=", "**=", "...", "&&=", "||=", "??=",
  "==", "!=", "<=", ">=", "=>", "->", "&&", "||", "??", "?.", "::",
  "++", "--", "+=", "-=", "*=", "/=", "%=", "**", "<<", ">>",
];

export function tokenize(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    // whitespace
    if (/\s/.test(ch)) {
      let j = i + 1;
      while (j < src.length && /\s/.test(src[j]!)) j++;
      tokens.push({ kind: "space", text: src.slice(i, j) });
      i = j;
      continue;
    }
    // words / identifiers / keywords
    if (/[A-Za-z_$]/.test(ch)) {
      let j = i + 1;
      while (j < src.length && /[A-Za-z0-9_$]/.test(src[j]!)) j++;
      tokens.push({ kind: "word", text: src.slice(i, j) });
      i = j;
      continue;
    }
    // numbers
    if (/[0-9]/.test(ch)) {
      let j = i + 1;
      while (j < src.length && /[0-9._]/.test(src[j]!)) j++;
      tokens.push({ kind: "number", text: src.slice(i, j) });
      i = j;
      continue;
    }
    // strings
    if (ch === '"' || ch === "'" || ch === "`") {
      let j = i + 1;
      while (j < src.length && src[j] !== ch) {
        if (src[j] === "\\") j++;
        j++;
      }
      tokens.push({ kind: "string", text: src.slice(i, Math.min(j + 1, src.length)) });
      i = j + 1;
      continue;
    }
    // multi-char operators
    let matched = false;
    for (const op of MULTI_OPS) {
      if (src.startsWith(op, i)) {
        tokens.push({ kind: "op", text: op });
        i += op.length;
        matched = true;
        break;
      }
    }
    if (matched) continue;
    // single-char op/punct
    const isOp = "+-*/%<>=&|!?~^".includes(ch);
    tokens.push({ kind: isOp ? "op" : "punct", text: ch });
    i++;
  }
  return tokens;
}

/** Non-space tokens only (structure ignores whitespace). */
function meaningful(tokens: Token[]): Token[] {
  return tokens.filter((t) => t.kind !== "space");
}

interface DiffOp {
  readonly kind: "equal" | "insert" | "delete";
  readonly token: Token;
}

/** Token-level diff via LCS. Returns an edit script over meaningful tokens. */
export function tokenDiff(a: Token[], b: Token[]): DiffOp[] {
  const A = meaningful(a);
  const B = meaningful(b);
  const n = A.length;
  const m = B.length;
  // LCS length table
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i]![j] = A[i]!.text === B[j]!.text ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
    }
  }
  const ops: DiffOp[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (A[i]!.text === B[j]!.text) {
      ops.push({ kind: "equal", token: A[i]! });
      i++;
      j++;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) {
      ops.push({ kind: "delete", token: A[i]! });
      i++;
    } else {
      ops.push({ kind: "insert", token: B[j]! });
      j++;
    }
  }
  while (i < n) ops.push({ kind: "delete", token: A[i++]! });
  while (j < m) ops.push({ kind: "insert", token: B[j++]! });
  return ops;
}

export type EditPatternKind =
  | "operator-substitution"
  | "boundary-condition"
  | "added-guard"
  | "added-error-handling"
  | "added-await"
  | "added-call"
  | "removed-call"
  | "identifier-rename"
  | "type-annotation-added"
  | "general-edit";

export interface EditPattern {
  readonly kind: EditPatternKind;
  /** Stable signature for matching recurrences of the PATTERN (not the text). */
  readonly signature: string;
  /** The generalized, reusable lesson. */
  readonly lesson: string;
  /** Default distillation confidence for this pattern kind (0..1). */
  readonly confidence: number;
}

const GUARD_WORDS = new Set(["null", "undefined", "None", "nil", "nullptr", "isset", "empty"]);
const ERROR_WORDS = new Set(["try", "catch", "except", "rescue", "finally", "throw", "raise"]);
const BOUNDARY_OPS = new Set(["<", "<=", ">", ">="]);

/** Classify an edit into its most specific structural pattern. */
export function classifyEdit(produced: string, shipped: string): EditPattern {
  const ops = tokenDiff(tokenize(produced), tokenize(shipped));
  const inserted = ops.filter((o) => o.kind === "insert").map((o) => o.token);
  const deleted = ops.filter((o) => o.kind === "delete").map((o) => o.token);
  const insWords = inserted.filter((t) => t.kind === "word").map((t) => t.text);
  const insOps = inserted.filter((t) => t.kind === "op").map((t) => t.text);
  const delOps = deleted.filter((t) => t.kind === "op").map((t) => t.text);

  // 1. boundary-condition: a comparison operator swapped for its inclusive/exclusive
  //    variant, or a numeric literal changed by ±1 (off-by-one).
  const delBoundary = delOps.find((o) => BOUNDARY_OPS.has(o));
  const insBoundary = insOps.find((o) => BOUNDARY_OPS.has(o));
  if (delBoundary && insBoundary && delBoundary !== insBoundary) {
    return {
      kind: "boundary-condition",
      signature: `boundary:${delBoundary}->${insBoundary}`,
      lesson:
        `Boundary condition changed (${delBoundary} -> ${insBoundary}): re-check inclusive/exclusive ` +
        `bounds and off-by-one on loop/range/index conditions.`,
      confidence: 0.5,
    };
  }
  const delNum = deleted.find((t) => t.kind === "number");
  const insNum = inserted.find((t) => t.kind === "number");
  if (delNum && insNum && Math.abs(Number(delNum.text) - Number(insNum.text)) === 1) {
    return {
      kind: "boundary-condition",
      signature: `boundary:num${delNum.text}->${insNum.text}`,
      lesson: `Off-by-one literal adjustment (${delNum.text} -> ${insNum.text}): verify range/index bounds.`,
      confidence: 0.45,
    };
  }

  // 2. operator-substitution: one binary operator replaced by another.
  if (delOps.length >= 1 && insOps.length >= 1 && delOps[0] !== insOps[0]) {
    const from = delOps[0]!;
    const to = insOps[0]!;
    return {
      kind: "operator-substitution",
      signature: `op-sub:${from}->${to}`,
      lesson:
        `Operator changed (${from} -> ${to}): verify operator direction/semantics against the ` +
        `intended behavior; this class of edit fixes silent logic errors.`,
      confidence: 0.5,
    };
  }

  // 3. added-error-handling.
  if (insWords.some((w) => ERROR_WORDS.has(w))) {
    return {
      kind: "added-error-handling",
      signature: "added-error-handling",
      lesson: `Error handling was added: wrap fallible operations and handle/propagate errors explicitly.`,
      confidence: 0.55,
    };
  }

  // 4. added-guard: a null/undefined/emptiness guard or optional chaining introduced.
  if (
    insOps.includes("?.") ||
    (insWords.includes("if") && inserted.some((t) => GUARD_WORDS.has(t.text))) ||
    insWords.some((w) => GUARD_WORDS.has(w))
  ) {
    return {
      kind: "added-guard",
      signature: "added-guard",
      lesson: `A null/undefined/emptiness guard was added: validate inputs/optionals before dereferencing or using them.`,
      confidence: 0.55,
    };
  }

  // 5. added-await (missing async wait).
  if (insWords.includes("await") || insWords.includes("async")) {
    return {
      kind: "added-await",
      signature: "added-await",
      lesson: `An await/async was added: ensure asynchronous calls are awaited so results/errors aren't dropped.`,
      confidence: 0.5,
    };
  }

  // 6. added-call / removed-call: an inserted or removed function-call name.
  const insCall = callName(inserted, ops, "insert");
  if (insCall) {
    return {
      kind: "added-call",
      signature: `added-call:${insCall}`,
      lesson: `A call to "${insCall}(...)" was added: this step was needed to satisfy the shipped behavior.`,
      confidence: 0.45,
    };
  }
  const delCall = callName(deleted, ops, "delete");
  if (delCall) {
    return {
      kind: "removed-call",
      signature: `removed-call:${delCall}`,
      lesson: `A call to "${delCall}(...)" was removed: it was unnecessary or incorrect for the shipped behavior.`,
      confidence: 0.4,
    };
  }

  // 7. type-annotation-added (`: Type`).
  if (insOps.includes(":") && insWords.length >= 1) {
    return {
      kind: "type-annotation-added",
      signature: "type-annotation-added",
      lesson: `A type annotation was added: annotate types where inference is ambiguous to catch mismatches early.`,
      confidence: 0.4,
    };
  }

  // 8. identifier-rename: equal structure with one word swapped for another.
  if (insWords.length === 1 && delOps.length === 0 && insOps.length === 0 && deleted.some((t) => t.kind === "word")) {
    return {
      kind: "identifier-rename",
      signature: "rename",
      lesson: `An identifier was renamed: align names with the codebase's naming conventions.`,
      confidence: 0.35,
    };
  }

  // Fallback: a real edit we can't classify more specifically.
  return {
    kind: "general-edit",
    signature: `general:+${inserted.length}-${deleted.length}`,
    lesson: `The human revised Keep's output (${inserted.length} tokens added, ${deleted.length} removed); ` +
      `treat the shipped form as the preferred pattern for similar changes here.`,
    confidence: 0.3,
  };
}

/** Detect a `name(` call among inserted/deleted tokens, using the op stream for the paren. */
function callName(tokens: Token[], ops: DiffOp[], side: "insert" | "delete"): string | undefined {
  const stream = ops.filter((o) => o.kind === (side === "insert" ? "insert" : "delete") || o.kind === "equal").map((o) => o.token);
  for (let i = 0; i < stream.length - 1; i++) {
    const t = stream[i]!;
    const next = stream[i + 1]!;
    if (t.kind === "word" && next.text === "(" && tokens.some((x) => x.text === t.text)) {
      // Exclude language keywords that look like calls.
      if (!["if", "for", "while", "switch", "catch", "return"].includes(t.text)) return t.text;
    }
  }
  return undefined;
}

export interface AnalyzedEdit {
  readonly pattern: EditPattern;
  /** True if there is any meaningful structural change at all. */
  readonly hasChange: boolean;
}

/** Analyze an edit end-to-end. `hasChange` is false for whitespace-only edits. */
export function analyzeEdit(produced: string, shipped: string): AnalyzedEdit {
  const same = meaningful(tokenize(produced)).map((t) => t.text).join("\u0001") ===
    meaningful(tokenize(shipped)).map((t) => t.text).join("\u0001");
  if (same) {
    return {
      pattern: { kind: "general-edit", signature: "none", lesson: "", confidence: 0 },
      hasChange: false,
    };
  }
  return { pattern: classifyEdit(produced, shipped), hasChange: true };
}
