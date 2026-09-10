/**
 * Static foreign-skill inspection: parse a documented subset, propose a Keep
 * specification, and optionally translate declarations into a catalog package.
 * Body text is untrusted reference data, never executed. The default envelope
 * screen is not the generic execution validator or comparative evaluator.
 * Legacy Ed25519 signatures cover only three intent fields under an embedded,
 * untrusted key. Neither a signature nor acknowledgment grants execution authority.
 */

import { verify as edVerify, createPublicKey, createHash } from "node:crypto";
import type { DistilledSkill, StructuredEnvelope, SkillAuthority } from "../loop/skill_distiller.js";
import { EnvelopeForbiddenSinkCheck } from "../loop/skill_validator_defaults.js";
import { parsePolicyJson } from "../policy/json.js";
import { snapshotSkill } from "../registry/skill_registry.js";

/** Trusted static-envelope gate. Null means this check did not refuse, not executed safety. */
export type SkillGate = (skill: DistilledSkill) => string | null;
const defaultGate: SkillGate = (skill) => new EnvelopeForbiddenSinkCheck().check(skill);

/** The declared surface a skill's frontmatter advertises (what it SAYS it needs — a declaration to check, not a grant). */
export interface DeclaredSurface {
  readonly env: readonly string[];
  readonly bins: readonly string[];
  readonly os: readonly string[];
  readonly permissions: readonly string[];
  readonly triggers: readonly string[];
  readonly tools: readonly string[];
}

/** INTENT parsed from the artifact — never executed. The body is kept only as an untrusted reference excerpt. */
export interface SkillIntent {
  readonly name: string;
  readonly description: string;
  readonly version: string;
  readonly surface: DeclaredSurface;
  readonly bodyExcerpt: string;
}

/** A Keep-authored proposal modeled after the intent — what Keep would build INSTEAD of running the foreign skill. */
export interface BespokeSkillSpec {
  readonly name: string;
  readonly description: string;
  readonly proposedPreconditions: readonly string[];
  readonly proposedEffects: readonly string[];
  readonly modeledAfter: string; // the source intent name — provenance
}

export type SignatureStatus = "verified-intent-fields" | "invalid" | "unsigned" | "not-checked";

export interface SignatureInfo {
  readonly scheme: "keep-legacy-intent-triplet-v1" | "none";
  readonly coveredFields: readonly string[];
  readonly uncoveredFields: readonly string[];
  /** Digest of the currently supplied source, NOT signed or authenticated. */
  readonly sourceSha256: string;
  readonly sourceDigestSigned: false;
  readonly sourceEncoding: "skill-md-utf8" | "legacy-json-stringify";
  readonly signerSpkiSha256?: string;
  readonly signerTrust: "untrusted-embedded-key" | "not-established";
}

export interface AdoptOptions {
  /** ONLY true translates the FOREIGN artifact → a gated DistilledSkill. Absent/false → bespoke rec + NO raw skill. */
  readonly acknowledgeRisk?: boolean;
  /** The safety gate (default: the real forbidden-sink check). An org can inject the full SkillValidator. */
  readonly gate?: SkillGate;
}

export interface OpenClawAdoptionResult {
  /** ALWAYS present, non-suppressible — names the real supply-chain risks for this specific artifact. */
  readonly warning: string;
  /** Parse/out-of-subset failure with a clear reason (when present, intent/bespokeSpec are absent). */
  readonly rejected?: string;
  readonly intent?: SkillIntent;
  /** DEFAULT output: the bespoke Keep spec to author instead of running the foreign skill. */
  readonly bespokeSpec?: BespokeSkillSpec;
  readonly recommendation?: string;
  /** Ed25519 provenance status — unsigned artifacts are reported, never silently trusted. */
  readonly signature: SignatureStatus;
  readonly signatureInfo?: SignatureInfo;
  /** OpenClaw fields we recognize but do not translate — reported so nothing is silently lost. */
  readonly unsupported: readonly string[];
  /** ONLY when acknowledgeRisk===true AND the gate passed: the foreign artifact as a gated DistilledSkill (informs). */
  readonly rawSkill?: DistilledSkill;
  /** When acknowledgeRisk===true but the gate REJECTED the foreign artifact (a poisoned import never passes). */
  readonly rawRejected?: string;
}

// ---- parsing (INTENT ONLY) --------------------------------------------------

interface ParsedFrontmatter {
  readonly scalars: Readonly<Record<string, string>>;
  readonly arrays: Readonly<Record<string, readonly string[]>>;
  readonly metadata?: Record<string, unknown>;
  readonly body: string;
}

/** Parse SKILL.md frontmatter: `---` fenced YAML (top-level scalars, `- ` arrays, inline-JSON `metadata:`) + body. */
function parseSkillMd(text: string): ParsedFrontmatter | { readonly error: string } {
  const m = /^---\s*\n([\s\S]*?)\n---\s*\n?([\s\S]*)$/.exec(text);
  if (!m) return { error: "not a SKILL.md: missing `---` YAML frontmatter fence" };
  const [, fm, body] = m as unknown as [string, string, string];
  const scalars: Record<string, string> = Object.create(null);
  const arrays: Record<string, string[]> = Object.create(null);
  const seen = new Set<string>();
  let metadata: Record<string, unknown> | undefined;
  const lines = fm.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim() === "" || /^\s*#/.test(line)) continue;
    const kv = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(line);
    if (!kv) return { error: "unsupported-input-language: expected a top-level scalar or block list; nested YAML is not supported" };
    const [, key, rawVal] = kv as unknown as [string, string, string];
    const val = rawVal.trim();
    if (seen.has(key)) return { error: `duplicate frontmatter field: ${key}` };
    seen.add(key);
    if (key === "metadata") {
      if (!val.startsWith("{")) return { error: "unsupported-input-language: metadata must be an inline JSON object; multi-line YAML metadata is unsupported" };
      try {
        const parsed = parsePolicyJson(val);
        if (!isRecord(parsed)) return { error: "metadata must be an object" };
        metadata = parsed;
      } catch (e) { return { error: `unsupported-input-language: metadata violates the strict JSON subset (exotic JSON5 unsupported): ${(e as Error).message}` }; }
      continue;
    }
    if (LIST_FIELDS.has(key) && val !== "") {
      try {
        // AgentSkills' scalar allowed-tools is only static metadata, not authority.
        if (key === "allowed-tools" && !/^[\[{&*!]/.test(val)) arrays[key] = [scalar(val)];
        else arrays[key] = stringList(parsePolicyJson(val), key);
      } catch (e) { return { error: `unsupported-input-language: ${key} requires a string block list or JSON string array: ${(e as Error).message}` }; }
      continue;
    }
    if (val === "") {
      // possible YAML array: consume following `  - item` lines
      const items: string[] = [];
      let j = i + 1;
      for (; j < lines.length; j++) {
        const item = /^\s*-\s+(.*)$/.exec(lines[j]!);
        if (!item) break;
        try { items.push(scalar(item[1]!.trim())); }
        catch (e) { return { error: `unsupported-input-language: ${key} list: ${(e as Error).message}` }; }
      }
      if (items.length > 0 || LIST_FIELDS.has(key)) { arrays[key] = items; i = j - 1; continue; }
      scalars[key] = "";
    } else {
      try { scalars[key] = scalar(val); }
      catch (e) { return { error: `unsupported-input-language: ${key}: ${(e as Error).message}` }; }
    }
  }
  for (const key of ["name", "description", "version", "signature", "publicKey"]) {
    if (key in arrays) return { error: `${key} must be a scalar string` };
  }
  const out: ParsedFrontmatter = { scalars, arrays, body: body.trim(), ...(metadata ? { metadata } : {}) };
  return out;
}

/** Legacy manifest.json shape: { name, version, description, triggers[], permissions[], config{} }. */
interface LegacyManifest { readonly name?: unknown; readonly version?: unknown; readonly description?: unknown; readonly triggers?: unknown; readonly permissions?: unknown; readonly config?: unknown; readonly [k: string]: unknown; }

const LIST_FIELDS = new Set(["permissions", "triggers", "required_tools", "allowed-tools"]);
function isRecord(v: unknown): v is Record<string, unknown> { return v !== null && typeof v === "object" && !Array.isArray(v); }
function stringList(v: unknown, field: string): string[] {
  if (!Array.isArray(v) || !v.every(x => typeof x === "string" && x.trim().length > 0)) throw Error(`${field} must be an array of nonempty strings`);
  return [...v];
}
function scalar(value: string): string {
  if (value.startsWith('"')) {
    const decoded = JSON.parse(value) as unknown;
    if (typeof decoded !== "string") throw Error("expected quoted string");
    return decoded;
  }
  if (value.startsWith("'")) {
    if (!/^'(?:[^']|'')*'$/.test(value)) throw Error("unsupported single-quoted scalar");
    return value.slice(1, -1).replace(/''/g, "'");
  }
  if (/^[\[\]{},&*!|>]/.test(value) || /:\s|\s#/.test(value)) throw Error("complex YAML scalar unsupported; quote the value");
  return value;
}

const KNOWN_FIELDS = new Set(["name", "description", "version", "metadata", "triggers", "required_tools", "allowed-tools", "permissions", "display_name", "user-invocable", "command-dispatch", "primaryEnv", "envVars", "emoji", "homepage", "signature", "publicKey"]);

// ---- intent + warning + bespoke --------------------------------------------

function surfaceFrom(meta: Record<string, unknown> | undefined, arrays: Readonly<Record<string, readonly string[]>>, unsupported: string[]): DeclaredSurface {
  const oc = meta?.["openclaw"] === undefined ? {} : meta["openclaw"];
  if (!isRecord(oc)) throw Error("metadata.openclaw must be an object");
  const requires = oc["requires"] === undefined ? {} : oc["requires"];
  if (!isRecord(requires)) throw Error("metadata.openclaw.requires must be an object");
  const permissions = oc["permissions"];
  let permList: string[] = [];
  if (permissions !== undefined) {
    if (Array.isArray(permissions)) permList = stringList(permissions, "metadata.openclaw.permissions");
    else if (isRecord(permissions) && Object.keys(permissions).every(k => k.trim().length > 0) && Object.values(permissions).every(v => typeof v === "boolean")) permList = Object.keys(permissions).filter(k => permissions[k]);
    else throw Error("metadata.openclaw.permissions must be a string list or boolean map");
  }
  for (const key of Object.keys(meta ?? {})) if (key !== "openclaw") unsupported.push(`metadata.${key}`);
  for (const key of Object.keys(oc)) if (!["requires", "permissions"].includes(key)) unsupported.push(`metadata.openclaw.${key}`);
  for (const key of Object.keys(requires)) if (!["env", "bins", "os"].includes(key)) unsupported.push(`metadata.openclaw.requires.${key}`);
  const required = (key: string) => requires[key] === undefined ? [] : stringList(requires[key], `metadata.openclaw.requires.${key}`);
  return {
    env: required("env"),
    bins: required("bins"),
    os: required("os"),
    permissions: [...permList, ...(arrays["permissions"] ?? [])],
    triggers: [...(arrays["triggers"] ?? [])],
    tools: [...(arrays["required_tools"] ?? []), ...(arrays["allowed-tools"] ?? [])],
  };
}

/** Build the ALWAYS-emitted, non-suppressible security warning, naming the real risks for THIS artifact. */
function buildWarning(intent: SkillIntent, signature: SignatureStatus): string {
  const risks: string[] = [
    "Third-party skills are untrusted input and may contain malicious instructions, including credential theft or infostealer installation.",
  ];
  const s = intent.surface;
  if (s.bins.length) risks.push(`declares external binaries (${s.bins.join(", ")}) — possible shell/command-execution sink.`);
  if (s.env.length) risks.push(`declares env/secrets access (${s.env.join(", ")}) — possible credential-exfiltration sink.`);
  if (s.permissions.length) risks.push(`declares permissions (${s.permissions.join(", ")}) — network/filesystem reach.`);
  risks.push("the declared surface may not match the ACTUAL behavior of the NL body (declared-vs-actual mismatch).");
  risks.push(`signature status is ${signature}; any valid legacy signature covers only name, description and version, not the body or permissions. The embedded key is untrusted; the author's identity is not established.`);
  return `SECURITY WARNING — do not run this OpenClaw skill as-is. ${risks.join(" ")} Keep's recommendation: author a bespoke Keep skill modeled after its intent (returned as bespokeSpec) and run that through Keep's own validation.`;
}

interface MappedDeclarations { readonly effects: readonly string[]; readonly authority: readonly SkillAuthority[]; readonly unsupported: readonly string[]; }
function mapDeclarations(intent: SkillIntent): MappedDeclarations {
  const effects = new Set<string>(), authority = new Set<SkillAuthority>(), unsupported: string[] = [];
  if (intent.surface.bins.length) { effects.add("local-command"); authority.add("sandbox:execute"); }
  for (const p of intent.surface.permissions) {
    effects.add(`declared-permission:${p}`);
    let recognized = false, unrepresentedAuthority = false;
    const add = (pattern: RegExp, effect: string, requirement?: SkillAuthority) => {
      if (!pattern.test(p)) return;
      recognized = true; effects.add(effect);
      if (requirement) authority.add(requirement); else unrepresentedAuthority = true;
    };
    add(/exfil|external|send|upload|share/i, "external-send");
    add(/leak|steal|export-cred|share-cred/i, "credential");
    add(/escalat|sudo|root|privilege/i, "escalate-privilege");
    add(/net|http|url/i, "network-read");
    add(/write/i, "file-write", "workspace:write");
    add(/(?:file|fs)[-_:]?read|read[-_:]?(?:file|fs)/i, "file-read", "workspace:read");
    add(/exec|shell|command/i, "local-command", "sandbox:execute");
    if (!recognized) unsupported.push(`permission:${p} (no normalized effect or authority mapping)`);
    else if (unrepresentedAuthority) unsupported.push(`permission:${p} (normalized effect only; no authority type represents this requirement)`);
  }
  if (intent.surface.env.length) unsupported.push("environment requirements are declarations; no credential authority is inferred");
  if (intent.surface.tools.length) unsupported.push("tool requirements are static metadata; no tool authority is inferred");
  return { effects: [...effects], authority: [...authority], unsupported };
}

function buildBespokeSpec(intent: SkillIntent, mapping: MappedDeclarations): BespokeSkillSpec {
  return {
    name: intent.name,
    description: `Keep-authored capability modeled after the intent of '${intent.name}': ${intent.description}`,
    proposedPreconditions: intent.surface.triggers.length ? intent.surface.triggers : [intent.name],
    proposedEffects: mapping.effects,
    modeledAfter: intent.name,
  };
}

/** Keep's legacy custom three-line payload, not an OpenClaw whole-artifact signature standard. */
function verifyProvenance(scalars: Readonly<Record<string, string>>, payload: string): { status: SignatureStatus; signerSpkiSha256?: string } {
  const sig = scalars["signature"];
  const pub = scalars["publicKey"];
  if (!sig) return { status: "unsigned" };
  if (!pub) return { status: "invalid" };
  try {
    const keyObj = createPublicKey(pub.includes("BEGIN") ? pub.replace(/\\n/g, "\n") : { key: Buffer.from(pub, "base64"), format: "der", type: "spki" });
    const signerSpkiSha256 = createHash("sha256").update(keyObj.export({ type: "spki", format: "der" })).digest("hex");
    const valid = keyObj.asymmetricKeyType === "ed25519" && edVerify(null, Buffer.from(payload), keyObj, Buffer.from(sig, "base64"));
    return { status: valid ? "verified-intent-fields" : "invalid", signerSpkiSha256 };
  } catch { return { status: "invalid" }; }
}

/** Translate the FOREIGN artifact into a DistilledSkill (ONLY used under acknowledgeRisk) — declared effects intact. */
function foreignToDistilled(intent: SkillIntent, mapping: MappedDeclarations, signature: SignatureStatus, info: SignatureInfo): DistilledSkill {
  const envelope: StructuredEnvelope = {
    preconditions: intent.surface.triggers.length ? [...intent.surface.triggers] : [intent.name],
    steps: [],
    postconditions: [],
    declaredEffects: mapping.effects,
  };
  return {
    format: "keep.skill/v1",
    id: `openclaw:${intent.name}`,
    name: intent.name,
    description: intent.description,
    relevanceKey: intent.surface.triggers[0] ?? intent.name,
    envelope,
    requiredAuthority: mapping.authority,
    provenance: ["openclaw-import", "acknowledged-risk", `source-sha256:${info.sourceSha256}`, "source-digest:unsigned-current-input",
      `signature-scope:${info.scheme}`, `signature-status:${signature}`, `signer-trust:${info.signerTrust}`,
      ...(info.signerSpkiSha256 ? [`signer-spki-sha256:${info.signerSpkiSha256}`] : [])],
    confidence: "low",
  };
}

// ---- the adopter ------------------------------------------------------------

/**
 * Adopt an OpenClaw skill (SKILL.md text or a legacy manifest object). ALWAYS warns; DEFAULT returns a bespoke Keep spec
 * and NO raw foreign skill; only opts.acknowledgeRisk===true translates the foreign artifact through the SAME gate.
 */
export function adoptOpenClawSkill(raw: string | Record<string, unknown>, opts: AdoptOptions = {}): OpenClawAdoptionResult {
  const gate = opts.gate ?? defaultGate;
  let intent: SkillIntent;
  let signature: SignatureStatus;
  let signatureInfo: SignatureInfo;
  const unsupportedKnown: string[] = [];
  const rejected = (reason: string): OpenClawAdoptionResult => ({ warning: "SECURITY WARNING — artifact could not be safely parsed; do not run it.", rejected: reason, signature: "not-checked", unsupported: [] });
  let sourceSha256: string;
  try {
    const serialized = typeof raw === "string" ? raw : JSON.stringify(raw);
    sourceSha256 = createHash("sha256").update(serialized).digest("hex");
    if (typeof raw !== "string") {
      // Use the same owned JSON representation for identity and translation.
      // A caller's getters/toJSON must not supply another value on a second read.
      const detached = JSON.parse(serialized) as unknown;
      if (!isRecord(detached)) return rejected("legacy manifest must serialize to an object");
      raw = detached;
    }
  }
  catch { return rejected("source is not a serializable skill document"); }
  const identity = { sourceSha256, sourceDigestSigned: false as const,
    sourceEncoding: typeof raw === "string" ? "skill-md-utf8" as const : "legacy-json-stringify" as const };

  if (typeof raw === "string") {
    const parsed = parseSkillMd(raw);
    if ("error" in parsed) return rejected(parsed.error);
    const name = parsed.scalars["name"] ?? "";
    if (!/^[a-z0-9-]{1,64}$/.test(name)) return rejected(`invalid or missing skill name (must be 1-64 lowercase letters/numbers/hyphens): '${name}'`);
    let surface: DeclaredSurface;
    try { surface = surfaceFrom(parsed.metadata, parsed.arrays, unsupportedKnown); }
    catch (e) { return rejected(`invalid declared surface: ${(e as Error).message}`); }
    intent = { name, description: parsed.scalars["description"] ?? name, version: parsed.scalars["version"] ?? "", surface, bodyExcerpt: parsed.body.slice(0, 500) };
    if (/[\r\n]/.test(intent.description + intent.version)) return rejected("unsupported-input-language: intent triplet fields must be single-line strings");
    const verification = verifyProvenance(parsed.scalars, `${name}\n${intent.description}\n${intent.version}`);
    signature = verification.status;
    signatureInfo = { ...identity, scheme: parsed.scalars["signature"] ? "keep-legacy-intent-triplet-v1" : "none",
      coveredFields: parsed.scalars["signature"] ? ["name", "description", "version"] : [],
      uncoveredFields: parsed.scalars["signature"] ? ["body", "metadata", "permissions", "triggers", "tools", "all other document fields", "sourceSha256"] : ["entire document", "sourceSha256"],
      ...(verification.signerSpkiSha256 ? { signerSpkiSha256: verification.signerSpkiSha256 } : {}),
      signerTrust: verification.signerSpkiSha256 ? "untrusted-embedded-key" : "not-established" };
    for (const k of [...Object.keys(parsed.scalars), ...Object.keys(parsed.arrays), ...(parsed.metadata ? ["metadata"] : [])]) if (!KNOWN_FIELDS.has(k)) unsupportedKnown.push(k);
    for (const k of Object.keys(parsed.scalars)) if (KNOWN_FIELDS.has(k) && !["name", "description", "version", "signature", "publicKey"].includes(k)) unsupportedKnown.push(`${k} (not translated)`);
    for (const k of Object.keys(parsed.arrays)) if (KNOWN_FIELDS.has(k) && !LIST_FIELDS.has(k)) unsupportedKnown.push(`${k} (not translated)`);
  } else {
    if (!isRecord(raw)) return rejected("legacy manifest must be an object");
    const man = raw as LegacyManifest;
    const name = typeof man.name === "string" ? man.name : "";
    if (!/^[a-z0-9-]{1,64}$/.test(name)) return rejected(`legacy manifest: invalid or missing name (1-64 lowercase/hyphen): '${name}'`);
    for (const k of ["description", "version"]) if (man[k] !== undefined && typeof man[k] !== "string") return rejected(`legacy ${k} must be a string`);
    let surface: DeclaredSurface;
    try { surface = { env: [], bins: [], os: [], permissions: man.permissions === undefined ? [] : stringList(man.permissions, "legacy permissions"),
      triggers: man.triggers === undefined ? [] : stringList(man.triggers, "legacy triggers"), tools: [] }; }
    catch (e) { return rejected((e as Error).message); }
    intent = { name, description: typeof man.description === "string" ? man.description : name, version: typeof man.version === "string" ? man.version : "", surface, bodyExcerpt: "" };
    signature = "unsigned"; // legacy manifests carry no Ed25519 provenance
    signatureInfo = { ...identity, scheme: "none", coveredFields: [], uncoveredFields: ["entire legacy manifest", "sourceSha256"], signerTrust: "not-established" };
    for (const k of Object.keys(man)) if (!new Set(["name", "version", "description", "triggers", "permissions", "config"]).has(k)) unsupportedKnown.push(k);
    if (man.config !== undefined) unsupportedKnown.push("config (not translated)");
  }

  const warning = buildWarning(intent, signature);
  const mapping = mapDeclarations(intent);
  unsupportedKnown.push(...mapping.unsupported);
  const bespokeSpec = buildBespokeSpec(intent, mapping);
  const recommendation = `Author the bespoke Keep skill '${bespokeSpec.name}' (modeled after the intent) and run it through Keep's distiller→validator→canary. Do NOT execute the OpenClaw skill.`;

  // Explicit acknowledgment permits only static declaration translation through the configured gate.
  if (opts.acknowledgeRisk === true) {
    const foreign = snapshotSkill(foreignToDistilled(intent, mapping, signature, signatureInfo));
    let bad: string | null;
    try { bad = gate(foreign); }
    catch { bad = "static gate failed; no candidate admitted"; }
    if (bad) return { warning, intent, bespokeSpec, recommendation, signature, signatureInfo, unsupported: unsupportedKnown, rawRejected: `safety gate rejected the foreign import: ${bad}` };
    return { warning, intent, bespokeSpec, recommendation, signature, signatureInfo, unsupported: unsupportedKnown, rawSkill: foreign };
  }

  // DEFAULT: bespoke recommendation only — NO raw foreign skill is returned.
  return { warning, intent, bespokeSpec, recommendation, signature, signatureInfo, unsupported: unsupportedKnown };
}
