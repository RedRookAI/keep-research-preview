/**
 * TYPED PREDICATE THEORY for guard atoms (Mechanical-Enforcement Increment 6, part A — the Total Decision Kernel's
 * atom semantics).
 *
 * Increment 2 (guard_dag.ts) treats a guard atom as an OPAQUE free boolean variable keyed by its predicate string: it
 * decides the PROPOSITIONAL structure (allOf/anyOf/not, shadowing, contradiction) but deliberately never interprets
 * what an atom MEANS. That interpretation is this module's job. A guard atom is a small PREDICATE over a typed request
 * CONTEXT — `net.port == 443`, `net.port in [80, 443]`, `path startsWith "/srv"`, `principal.labels has "prod"` — and
 * this module parses that predicate and evaluates it against the attributes the request carries.
 *
 * The evaluation is THREE-VALUED (Kleene): T (definitely holds), F (definitely fails), U (unknown — the attribute is
 * absent, ill-typed for the operator, or the atom is not in the interpreted grammar at all). U is the load-bearing
 * fail-closed value: the decision kernel never treats U as T, so an unresolvable predicate can never satisfy a permit,
 * and (deny-overrides) can only ever help a deny fire. A predicate string the grammar does not recognize is NOT an
 * error — it parses to `null` here and the kernel reads it as the constant U, the maximally conservative reading.
 *
 * HONEST BOUNDARY. This is the RUNTIME evaluation of an atom against a concrete, request-supplied context — that is
 * what actually gates an effect. Two things stay out of scope on purpose: (1) STATIC cross-atom theory reasoning
 * (proving `port==80 ∧ port==443` unsatisfiable at compile time — an interval/label SMT problem) is a possible later
 * refinement and is not attempted; the propositional layer's unsat results remain sound, theory only ever adds more.
 * (2) Binding an attribute to the ACTUAL resolved runtime object (a symlink resolved to its real path, a fd to its
 * real inode, TOCTOU-safe object identity) is Increment 11 (Resolver-Bound Guards); here the context is taken as
 * given, already-resolved typed data.
 *
 * Grounding: attribute-based access control (ABAC) predicates; Kleene/Belnap three-valued logic for partial
 * information; fail-closed evaluation (unknown ⇒ never-grant). Deterministic, offline, zero-dependency.
 */

/** A predicate scalar literal / attribute value: an integer (bigint — matching the EIR value model) or NFC text. */
export type Scalar = bigint | string;
/** A typed context attribute value: a scalar, or a list of scalars (for membership / `has`). */
export type ContextValue = Scalar | readonly Scalar[];
/** The typed request context: attribute name → typed value. An absent attribute reads as U (fail-closed). */
export type PredicateContext = ReadonlyMap<string, ContextValue>;

/** Three-valued truth. U = unknown (attribute absent / ill-typed / uninterpretable predicate). */
export type Tri = "T" | "F" | "U";

/** Parsed predicate AST (only these shapes are interpreted; anything else parses to null ⇒ constant U). */
export type Predicate =
  | { readonly op: "cmp"; readonly attr: string; readonly rel: "==" | "!=" | "<" | "<=" | ">" | ">="; readonly lit: Scalar }
  | { readonly op: "in"; readonly attr: string; readonly neg: boolean; readonly lits: readonly Scalar[] }
  | { readonly op: "has"; readonly attr: string; readonly lit: Scalar }
  | { readonly op: "affix"; readonly attr: string; readonly kind: "startsWith" | "endsWith"; readonly lit: string };

// ── Tokenizer ────────────────────────────────────────────────────────────────────────────────────────────────────
// A predicate is `attr OP literal`. attr is a dotted identifier; OP is one of the fixed operators; literal is an
// integer, a double-quoted string, or a bracketed list of those. The grammar is intentionally tiny and total: any
// deviation returns null (⇒ the kernel reads the atom as constant U — never an exception, never a silent T).

type Tok =
  | { readonly k: "ident"; readonly v: string }
  | { readonly k: "op"; readonly v: string }
  | { readonly k: "int"; readonly v: bigint }
  | { readonly k: "str"; readonly v: string }
  | { readonly k: "["; }
  | { readonly k: "]"; }
  | { readonly k: ","; };

const WORD_OPS = new Set(["in", "notin", "startsWith", "endsWith", "has"]);
const SYM_OPS = ["==", "!=", "<=", ">=", "<", ">"]; // longest-first so <= is not read as <

function tokenize(src: string): Tok[] | null {
  const toks: Tok[] = [];
  let i = 0;
  const n = src.length;
  const isIdentStart = (c: string): boolean => /[A-Za-z_]/.test(c);
  const isIdentPart = (c: string): boolean => /[A-Za-z0-9_.]/.test(c);
  while (i < n) {
    const c = src[i]!;
    if (c === " " || c === "\t") { i++; continue; }
    if (c === "[") { toks.push({ k: "[" }); i++; continue; }
    if (c === "]") { toks.push({ k: "]" }); i++; continue; }
    if (c === ",") { toks.push({ k: "," }); i++; continue; }
    if (c === '"') {
      // double-quoted string; escapes \" and \\ only (a predicate literal is deliberately simple).
      let out = ""; i++;
      let closed = false;
      while (i < n) {
        const ch = src[i]!;
        if (ch === '"') { i++; closed = true; break; }
        if (ch === "\\") {
          const e = src[i + 1];
          if (e === '"' || e === "\\") { out += e; i += 2; continue; }
          return null; // unknown escape ⇒ uninterpretable
        }
        if (ch.charCodeAt(0) < 0x20) return null; // raw control char
        out += ch; i++;
      }
      if (!closed) return null;
      if (out.normalize("NFC") !== out) return null; // literals must be NFC (identity discipline)
      toks.push({ k: "str", v: out });
      continue;
    }
    // integer (optional leading '-'), no leading zeros beyond a single 0, no fraction/exponent.
    if (c === "-" || (c >= "0" && c <= "9")) {
      const start = i;
      if (c === "-") i++;
      if (i >= n || !(src[i]! >= "0" && src[i]! <= "9")) return null;
      if (src[i] === "0") { i++; }
      else { while (i < n && src[i]! >= "0" && src[i]! <= "9") i++; }
      if (i < n && (src[i] === "." || src[i] === "e" || src[i] === "E")) return null; // integers only
      const lex = src.slice(start, i);
      if (lex === "-0") return null;
      toks.push({ k: "int", v: BigInt(lex) });
      continue;
    }
    // symbolic operator
    const sym = SYM_OPS.find((s) => src.startsWith(s, i));
    if (sym) { toks.push({ k: "op", v: sym }); i += sym.length; continue; }
    // identifier or word-operator
    if (isIdentStart(c)) {
      const start = i; i++;
      while (i < n && isIdentPart(src[i]!)) i++;
      const w = src.slice(start, i);
      if (WORD_OPS.has(w)) toks.push({ k: "op", v: w });
      else toks.push({ k: "ident", v: w });
      continue;
    }
    return null; // any other character ⇒ uninterpretable
  }
  return toks;
}

/**
 * Parse a guard atom's predicate string into a typed Predicate, or `null` if it is not in the interpreted grammar.
 * `null` is not an error — the kernel reads an unparseable atom as the constant U (fail-closed). Total: never throws.
 */
export function parsePredicate(atom: string): Predicate | null {
  if (typeof atom !== "string" || atom.length === 0) return null;
  const toks = tokenize(atom);
  if (toks === null || toks.length < 3) return null;
  const [a, o] = toks;
  if (a === undefined || a.k !== "ident") return null;
  if (o === undefined || o.k !== "op") return null;
  const attr = a.v;
  // attr must be well-formed dotted identifier segments (tokenizer already constrained the char class).
  if (attr.startsWith(".") || attr.endsWith(".") || attr.includes("..")) return null;
  const rest = toks.slice(2);
  const asScalar = (t: Tok | undefined): Scalar | null => (t === undefined ? null : t.k === "int" ? t.v : t.k === "str" ? t.v : null);

  switch (o.v) {
    case "==": case "!=": case "<": case "<=": case ">": case ">=": {
      if (rest.length !== 1) return null;
      const lit = asScalar(rest[0]);
      if (lit === null) return null;
      return { op: "cmp", attr, rel: o.v, lit };
    }
    case "in": case "notin": {
      // attr (in|notin) [ lit, lit, ... ]
      if (rest.length < 2 || rest[0]!.k !== "[" || rest[rest.length - 1]!.k !== "]") return null;
      const inner = rest.slice(1, -1);
      const lits: Scalar[] = [];
      for (let k = 0; k < inner.length; k++) {
        if (k % 2 === 0) { const s = asScalar(inner[k]); if (s === null) return null; lits.push(s); }
        else if (inner[k]!.k !== ",") return null;
      }
      if (inner.length > 0 && inner.length % 2 === 0) return null; // trailing comma / missing element
      if (lits.length === 0) return null;
      return { op: "in", attr, neg: o.v === "notin", lits };
    }
    case "has": {
      if (rest.length !== 1) return null;
      const lit = asScalar(rest[0]);
      if (lit === null) return null;
      return { op: "has", attr, lit };
    }
    case "startsWith": case "endsWith": {
      if (rest.length !== 1 || rest[0]!.k !== "str") return null;
      return { op: "affix", attr, kind: o.v, lit: rest[0]!.v };
    }
    default: return null;
  }
}

const isScalar = (v: ContextValue | undefined): v is Scalar => typeof v === "bigint" || typeof v === "string";
// Three-valued scalar equality. A TYPE MISMATCH is a type error ⇒ U (Indeterminate), NEVER a definite F: collapsing it
// to F would let `not(x == y)` manufacture a definite T out of a type error and grant a permit (cross-family review,
// GPT-5.6 SEV0). Same-type ⇒ definite T/F. This is the coherent basis for ==, !=, in/notin, and has.
const eq3 = (a: Scalar, b: Scalar): Tri => (typeof a !== typeof b ? "U" : a === b ? "T" : "F");
const not3 = (t: Tri): Tri => (t === "U" ? "U" : t === "T" ? "F" : "T");
const or3 = (ts: readonly Tri[]): Tri => { let u = false; for (const t of ts) { if (t === "T") return "T"; if (t === "U") u = true; } return u ? "U" : "F"; };

/** Evaluate a parsed predicate against the context. Total, three-valued: absent/ill-typed attribute ⇒ U. */
export function evalPredicate(p: Predicate, ctx: PredicateContext): Tri {
  const v = ctx.get(p.attr);
  if (v === undefined) return "U"; // attribute not supplied ⇒ unknown (fail-closed)
  switch (p.op) {
    case "cmp": {
      if (!isScalar(v)) return "U";
      if (p.rel === "==") return eq3(v, p.lit);
      if (p.rel === "!=") return not3(eq3(v, p.lit)); // type mismatch ⇒ U (can't determine inequality either)
      // ordering: integers only (a string vs int, or string ordering which is locale-fraught, ⇒ U — never a
      // silent byte compare and never a definite verdict from a type error).
      if (typeof v !== "bigint" || typeof p.lit !== "bigint") return "U";
      const c = v < p.lit ? -1 : v > p.lit ? 1 : 0;
      const holds = p.rel === "<" ? c < 0 : p.rel === "<=" ? c <= 0 : p.rel === ">" ? c > 0 : c >= 0;
      return holds ? "T" : "F";
    }
    case "in": {
      // Kleene membership: OR over three-valued element equality. If v is type-incompatible with EVERY literal the
      // result is U (a type error is undetermined, not "not a member"); a same-type non-match is a definite F.
      if (!isScalar(v)) return "U";
      const m = or3(p.lits.map((l) => eq3(v, l)));
      return p.neg ? not3(m) : m;
    }
    case "has": {
      if (!Array.isArray(v)) return "U"; // `has` requires a list-typed attribute
      return or3((v as readonly Scalar[]).map((e) => eq3(e, p.lit)));
    }
    case "affix": {
      if (typeof v !== "string") return "U";
      return (p.kind === "startsWith" ? v.startsWith(p.lit) : v.endsWith(p.lit)) ? "T" : "F";
    }
  }
}

/** Convenience: parse + evaluate an atom string in one step. Uninterpretable atom ⇒ U (never throws). */
export function evalAtom(atom: string, ctx: PredicateContext): Tri {
  const p = parsePredicate(atom);
  return p === null ? "U" : evalPredicate(p, ctx);
}
