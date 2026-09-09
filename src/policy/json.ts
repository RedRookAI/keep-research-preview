/**
 * Strict, dependency-free JSON frontend for the Total Policy Compiler (Mechanical-Enforcement Increment 2).
 *
 * WHY NOT `JSON.parse`: a total policy compiler must never SILENTLY drop or coerce input — that is a fail-open. The
 * platform parser silently (a) keeps only the LAST of duplicate object keys (so a policy carrying two `"decision"`
 * fields is accepted with one silently discarded), (b) admits floats/`1e3`/`-0` whose IEEE-754 value is ambiguous,
 * and (c) accepts a leading BOM. Each is a way a hostile or careless policy changes meaning without the compiler
 * noticing. This parser instead REJECTS every such ambiguity up front (fail-closed), so acceptance is total: an
 * accepted document has exactly one unambiguous reading.
 *
 * Scope: numbers are INTEGERS ONLY, decoded to `bigint` (the compiler's value model, matching canonical.ts which
 * rejects JS floats). Fractions/exponents/leading-zeros/`-0`/`+` are rejected. Strings must be well-formed Unicode
 * (no unpaired surrogates). Output is a plain, owned tree directly admissible as a canonical value.
 *
 * Grounding: RFC 8259 (JSON), RFC 7493 (I-JSON — unique member names, interoperable numbers), RFC 8949 canonical
 * value model (canonical.ts). Deterministic, offline, no dependencies.
 */

export type JsonValue = null | boolean | bigint | string | JsonValue[] | { [k: string]: JsonValue };

export class JsonError extends Error {
  readonly at: number;
  constructor(message: string, at: number) {
    super(`policy JSON: ${message} (at offset ${at})`);
    this.name = "JsonError";
    this.at = at;
  }
}

const MAX_DEPTH = 64; // matches the canonical encoder's structural bound

/** Is `s` well-formed Unicode (no unpaired surrogates)? Uses the native check when present, else a manual scan. */
function isWellFormed(s: string): boolean {
  const isWF = (String.prototype as unknown as { isWellFormed?: () => boolean }).isWellFormed;
  if (typeof isWF === "function") return isWF.call(s);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

/**
 * Parse a strict-JSON policy document. Accepts a `string` (validated well-formed) or UTF-8 `Uint8Array` (decoded
 * fatally). Throws `JsonError` on any ambiguity or malformed input. Returns an owned `JsonValue` tree.
 */
export function parsePolicyJson(input: string | Uint8Array): JsonValue {
  let src: string;
  if (input instanceof Uint8Array) {
    // Fatal decode rejects invalid UTF-8; ignoreBOM:false so a BOM would surface as U+FEFF and be rejected below.
    src = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(input);
  } else if (typeof input === "string") {
    if (!isWellFormed(input)) throw new JsonError("source string is not well-formed Unicode", 0);
    src = input;
  } else {
    throw new JsonError("input must be a string or Uint8Array", 0);
  }
  if (src.charCodeAt(0) === 0xfeff) throw new JsonError("leading byte-order mark is not admitted", 0);

  let i = 0;
  const n = src.length;

  const err = (m: string): never => {
    throw new JsonError(m, i);
  };

  // RFC 8259 insignificant whitespace: space, tab, LF, CR only. No other Unicode whitespace.
  const skipWs = (): void => {
    while (i < n) {
      const c = src.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const parseValue = (depth: number): JsonValue => {
    if (depth > MAX_DEPTH) err(`nesting deeper than ${MAX_DEPTH}`);
    skipWs();
    if (i >= n) err("unexpected end of input");
    const c = src[i]!;
    if (c === "{") return parseObject(depth);
    if (c === "[") return parseArray(depth);
    if (c === '"') return parseString();
    if (c === "t" || c === "f") return parseKeyword();
    if (c === "n") return parseNull();
    if (c === "-" || (c >= "0" && c <= "9")) return parseNumber();
    return err(`unexpected character ${JSON.stringify(c)}`);
  };

  const parseKeyword = (): boolean => {
    if (src.startsWith("true", i)) { i += 4; return true; }
    if (src.startsWith("false", i)) { i += 5; return false; }
    return err("invalid literal");
  };

  const parseNull = (): null => {
    if (src.startsWith("null", i)) { i += 4; return null; }
    return err("invalid literal");
  };

  const parseNumber = (): bigint => {
    const start = i;
    if (src[i] === "-") i++;
    if (i >= n) err("truncated number");
    // Integer part: single 0, or a nonzero digit followed by digits. No leading zeros (RFC 8259).
    if (src[i] === "0") {
      i++;
    } else if (src[i]! >= "1" && src[i]! <= "9") {
      while (i < n && src[i]! >= "0" && src[i]! <= "9") i++;
    } else {
      err("invalid number");
    }
    // Reject fraction / exponent (floats are ambiguous — integers only).
    if (i < n && (src[i] === "." || src[i] === "e" || src[i] === "E")) err("non-integer numbers (fraction/exponent) are not admitted — integers only");
    const lexeme = src.slice(start, i);
    if (lexeme === "-0") err("negative zero is not admitted");
    return BigInt(lexeme);
  };

  const parseString = (): string => {
    // assumes src[i] === '"'
    i++;
    let out = "";
    while (i < n) {
      const c = src.charCodeAt(i);
      if (c === 0x22) { i++; return out; } // closing quote
      if (c === 0x5c) { // backslash escape
        i++;
        if (i >= n) err("truncated escape");
        const e = src[i]!;
        if (e === '"') out += '"';
        else if (e === "\\") out += "\\";
        else if (e === "/") out += "/";
        else if (e === "b") out += "\b";
        else if (e === "f") out += "\f";
        else if (e === "n") out += "\n";
        else if (e === "r") out += "\r";
        else if (e === "t") out += "\t";
        else if (e === "u") {
          const cp = readHex4();
          if (cp >= 0xd800 && cp <= 0xdbff) {
            // high surrogate — MUST be followed by \u<low surrogate>
            if (src[i + 1] !== "\\" || src[i + 2] !== "u") err("unpaired high surrogate in \\u escape");
            i += 2;
            const low = readHex4();
            if (!(low >= 0xdc00 && low <= 0xdfff)) err("high surrogate not followed by a low surrogate");
            out += String.fromCharCode(cp, low);
          } else if (cp >= 0xdc00 && cp <= 0xdfff) {
            err("unpaired low surrogate in \\u escape");
          } else {
            out += String.fromCharCode(cp);
          }
        } else err(`invalid escape \\${e}`);
        i++;
      } else if (c < 0x20) {
        err("unescaped control character in string");
      } else {
        out += src[i];
        i++;
      }
    }
    return err("unterminated string");
  };

  // reads exactly 4 hex digits following a `\u` (i points at 'u'); returns the code unit; leaves i at last hex digit
  const readHex4 = (): number => {
    let v = 0;
    for (let k = 0; k < 4; k++) {
      const ch = src.charCodeAt(i + 1 + k);
      let d: number;
      if (ch >= 0x30 && ch <= 0x39) d = ch - 0x30;
      else if (ch >= 0x61 && ch <= 0x66) d = ch - 0x61 + 10;
      else if (ch >= 0x41 && ch <= 0x46) d = ch - 0x41 + 10;
      else return err("invalid \\u hex digits");
      v = v * 16 + d;
    }
    i += 4;
    return v;
  };

  const parseArray = (depth: number): JsonValue[] => {
    i++; // consume [
    const out: JsonValue[] = [];
    skipWs();
    if (src[i] === "]") { i++; return out; }
    for (;;) {
      out.push(parseValue(depth + 1));
      skipWs();
      const c = src[i];
      if (c === ",") { i++; continue; }
      if (c === "]") { i++; return out; }
      return err("expected ',' or ']' in array");
    }
  };

  const parseObject = (depth: number): { [k: string]: JsonValue } => {
    i++; // consume {
    const out: { [k: string]: JsonValue } = Object.create(null) as { [k: string]: JsonValue };
    const seen = new Set<string>();
    skipWs();
    if (src[i] === "}") { i++; return out; }
    for (;;) {
      skipWs();
      if (src[i] !== '"') return err("expected string key");
      const key = parseString();
      if (seen.has(key)) return err(`duplicate object key ${JSON.stringify(key)}`);
      seen.add(key);
      skipWs();
      if (src[i] !== ":") return err("expected ':' after key");
      i++;
      const val = parseValue(depth + 1);
      // Own data property; keys like "__proto__" become own data on a null-proto object (no pollution).
      Object.defineProperty(out, key, { value: val, enumerable: true, writable: true, configurable: true });
      skipWs();
      const c = src[i];
      if (c === ",") { i++; continue; }
      if (c === "}") { i++; return out; }
      return err("expected ',' or '}' in object");
    }
  };

  const value = parseValue(0);
  skipWs();
  if (i !== n) err("trailing data after top-level value");
  return value;
}
