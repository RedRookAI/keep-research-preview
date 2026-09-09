/**
 * M5 (REVET 2026-08) — OPENCLAW SKILL ADOPTION (warn-first, bespoke-by-default). OpenClaw/AgentSkills skills are a real,
 * cross-platform artifact: a SKILL.md folder with YAML frontmatter (name/description/version + a JSON5 `metadata.openclaw`
 * block declaring requires{env,bins,os}/permissions) and a natural-language body. They are also a documented SUPPLY-CHAIN
 * RISK: The Verge and Tom's Hardware reported malicious ClawHub skills installing infostealers, and audits find a
 * significant fraction of ClawHub's 10,700+ skills carry malicious payloads (KEEP_SOTA_AUDIT_2026-08 Topic 2). OpenClaw's
 * own docs say "treat third-party skills as untrusted code."
 *
 * Keep therefore ADOPTS INTENT, it does not import behavior:
 *   • It parses the artifact for INTENT ONLY (a foreign body is an untrusted SPEC, never executed).
 *   • It ALWAYS emits a non-suppressible security WARNING naming the real risks.
 *   • DEFAULT: it authors a BESPOKE Keep spec modeled after the intent, to run through the normal distiller→validator→
 *     canary path. Keep writes its own version; it never runs OpenClaw's.
 *   • OVERRIDE (opts.acknowledgeRisk === true): a human may translate the FOREIGN artifact into a DistilledSkill — but
 *     only through the SAME forbidden-sink gate every learned/registry skill passes. The override INFORMS; it never
 *     obstructs, and it is never a safety bypass. Absent the ack, no raw foreign skill is ever returned.
 *   • Ed25519 provenance (node:crypto) is verified when present; absent → reported as unsigned, never silently trusted.
 *
 * HONEST SCOPE: static adoption (artifact → intent → bespoke spec / gated foreign skill). Live OpenClaw RUNTIME interop
 * (running under its process/event-loop/tool wire) is a DEPLOYMENT SEAM — named, not faked.
 */

import { verify as edVerify, createPublicKey } from "node:crypto";
import type { DistilledSkill, StructuredEnvelope } from "../loop/skill_distiller.js";
import { EnvelopeForbiddenSinkCheck } from "../loop/skill_validator_defaults.js";

/** A skill-safety gate — the SAME contract installSkill uses. Returns a rejection reason, or null if safe. */
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

export type SignatureStatus = "verified" | "invalid" | "unsigned";

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
  readonly metadataError?: string;
  readonly body: string;
}

/** Parse SKILL.md frontmatter: `---` fenced YAML (top-level scalars, `- ` arrays, inline-JSON `metadata:`) + body. */
function parseSkillMd(text: string): ParsedFrontmatter | { readonly error: string } {
  const m = /^---\s*\n([\s\S]*?)\n---\s*\n?([\s\S]*)$/.exec(text);
  if (!m) return { error: "not a SKILL.md: missing `---` YAML frontmatter fence" };
  const [, fm, body] = m as unknown as [string, string, string];
  const scalars: Record<string, string> = {};
  const arrays: Record<string, string[]> = {};
  let metadata: Record<string, unknown> | undefined;
  let metadataError: string | undefined;
  const lines = fm.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.trim() === "" || /^\s*#/.test(line)) continue;
    const kv = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(line);
    if (!kv) continue;
    const [, key, rawVal] = kv as unknown as [string, string, string];
    const val = rawVal.trim();
    if (key === "metadata") {
      // metadata is JSON5-flattened; we accept the JSON-compatible inline form and REJECT exotic JSON5 with a reason.
      if (val.startsWith("{")) {
        try { metadata = JSON.parse(val) as Record<string, unknown>; }
        catch (e) { metadataError = `metadata is not JSON-parseable (exotic JSON5 unsupported): ${(e as Error).message}`; }
      } else if (val === "") {
        metadataError = "multi-line YAML `metadata` block unsupported by this adopter — re-express as inline JSON metadata";
      } else {
        metadataError = "metadata must be an inline JSON object";
      }
      continue;
    }
    if (val === "") {
      // possible YAML array: consume following `  - item` lines
      const items: string[] = [];
      let j = i + 1;
      for (; j < lines.length; j++) {
        const item = /^\s*-\s+(.*)$/.exec(lines[j]!);
        if (!item) break;
        items.push(item[1]!.trim().replace(/^["']|["']$/g, ""));
      }
      if (items.length > 0) { arrays[key] = items; i = j - 1; continue; }
      scalars[key] = "";
    } else {
      scalars[key] = val.replace(/^["']|["']$/g, "");
    }
  }
  const out: ParsedFrontmatter = { scalars, arrays, body: body.trim(), ...(metadata ? { metadata } : {}), ...(metadataError ? { metadataError } : {}) };
  return out;
}

/** Legacy manifest.json shape: { name, version, description, triggers[], permissions[], config{} }. */
interface LegacyManifest { readonly name?: unknown; readonly version?: unknown; readonly description?: unknown; readonly triggers?: unknown; readonly permissions?: unknown; readonly config?: unknown; readonly [k: string]: unknown; }

function strArr(v: unknown): string[] { return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []; }

const KNOWN_FIELDS = new Set(["name", "description", "version", "metadata", "triggers", "required_tools", "allowed-tools", "permissions", "display_name", "user-invocable", "command-dispatch", "primaryEnv", "envVars", "emoji", "homepage", "signature", "publicKey"]);

// ---- intent + warning + bespoke --------------------------------------------

function surfaceFrom(meta: Record<string, unknown> | undefined, arrays: Readonly<Record<string, readonly string[]>>): DeclaredSurface {
  const oc = (meta?.["openclaw"] ?? {}) as Record<string, unknown>;
  const requires = (oc["requires"] ?? {}) as Record<string, unknown>;
  const perms = (oc["permissions"] ?? {}) as Record<string, unknown>;
  const permList = Array.isArray(oc["permissions"]) ? strArr(oc["permissions"]) : Object.keys(perms).filter((k) => perms[k]);
  return {
    env: strArr(requires["env"]),
    bins: strArr(requires["bins"]),
    os: strArr(requires["os"]),
    permissions: [...permList, ...(arrays["permissions"] ?? [])],
    triggers: [...(arrays["triggers"] ?? [])],
    tools: [...(arrays["required_tools"] ?? []), ...(arrays["allowed-tools"] ?? [])],
  };
}

/** Build the ALWAYS-emitted, non-suppressible security warning, naming the real risks for THIS artifact. */
function buildWarning(intent: SkillIntent, signature: SignatureStatus): string {
  const risks: string[] = [
    "OpenClaw/ClawHub skills are third-party UNTRUSTED code: The Verge and Tom's Hardware documented malicious skills installing infostealers; audits find a significant fraction of ClawHub skills carry malicious payloads.",
  ];
  const s = intent.surface;
  if (s.bins.length) risks.push(`declares external binaries (${s.bins.join(", ")}) — possible shell/command-execution sink.`);
  if (s.env.length) risks.push(`declares env/secrets access (${s.env.join(", ")}) — possible credential-exfiltration sink.`);
  if (s.permissions.length) risks.push(`declares permissions (${s.permissions.join(", ")}) — network/filesystem reach.`);
  risks.push("the declared surface may not match the ACTUAL behavior of the NL body (declared-vs-actual mismatch).");
  if (signature !== "verified") risks.push(`provenance is ${signature.toUpperCase()} — the author is not cryptographically established.`);
  return `SECURITY WARNING — do not run this OpenClaw skill as-is. ${risks.join(" ")} Keep's recommendation: author a bespoke Keep skill modeled after its intent (returned as bespokeSpec) and run that through Keep's own validation.`;
}

function buildBespokeSpec(intent: SkillIntent): BespokeSkillSpec {
  const effects: string[] = [];
  if (intent.surface.bins.length) effects.push("local-command");
  if (intent.surface.permissions.some((p) => /net|http|url/i.test(p))) effects.push("network-read");
  if (intent.surface.permissions.some((p) => /write|fs|file/i.test(p))) effects.push("file-write");
  return {
    name: intent.name,
    description: `Keep-authored capability modeled after the intent of '${intent.name}': ${intent.description}`,
    proposedPreconditions: intent.surface.triggers.length ? intent.surface.triggers : [intent.name],
    proposedEffects: effects,
    modeledAfter: intent.name,
  };
}

/** Verify an Ed25519 signature over the artifact (node:crypto). Absent → "unsigned"; present+bad → "invalid". */
function verifyProvenance(scalars: Readonly<Record<string, string>>, payload: string): SignatureStatus {
  const sig = scalars["signature"];
  const pub = scalars["publicKey"];
  if (!sig || !pub) return "unsigned";
  try {
    const keyObj = createPublicKey(pub.includes("BEGIN") ? pub.replace(/\\n/g, "\n") : Buffer.from(pub, "base64"));
    return edVerify(null, Buffer.from(payload), keyObj, Buffer.from(sig, "base64")) ? "verified" : "invalid";
  } catch { return "invalid"; }
}

/** Translate the FOREIGN artifact into a DistilledSkill (ONLY used under acknowledgeRisk) — declared effects intact. */
function foreignToDistilled(intent: SkillIntent): DistilledSkill {
  const declaredEffects: string[] = [];
  if (intent.surface.bins.length) declaredEffects.push("local-command");
  for (const p of intent.surface.permissions) {
    // A forbidden SINK is an exfiltration/sharing/escalation permission — not merely holding a credential to call an API.
    if (/exfil|external|send|upload|share/i.test(p)) declaredEffects.push("external-send");
    if (/leak|steal|export-cred|share-cred/i.test(p)) declaredEffects.push("credential");
    if (/escalat|sudo|root|privilege/i.test(p)) declaredEffects.push("escalate-privilege");
    if (/net|http|url/i.test(p)) declaredEffects.push("network-read");
  }
  const envelope: StructuredEnvelope = {
    preconditions: intent.surface.triggers.length ? [...intent.surface.triggers] : [intent.name],
    steps: [],
    postconditions: [],
    declaredEffects,
  };
  return {
    format: "keep.skill/v1",
    id: `openclaw:${intent.name}`,
    name: intent.name,
    description: intent.description,
    relevanceKey: intent.surface.triggers[0] ?? intent.name,
    envelope,
    requiredAuthority: [],
    provenance: ["openclaw-import", "acknowledged-risk"],
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
  const unsupportedKnown: string[] = [];

  if (typeof raw === "string") {
    const parsed = parseSkillMd(raw);
    if ("error" in parsed) return { warning: "SECURITY WARNING — artifact could not be parsed as an OpenClaw skill; do not run it.", rejected: parsed.error, signature: "unsigned", unsupported: [] };
    if (parsed.metadataError) return { warning: "SECURITY WARNING — artifact could not be safely parsed; do not run it.", rejected: parsed.metadataError, signature: "unsigned", unsupported: [] };
    const name = parsed.scalars["name"] ?? "";
    if (!/^[a-z0-9-]{1,64}$/.test(name)) return { warning: "SECURITY WARNING — artifact could not be safely parsed; do not run it.", rejected: `invalid or missing skill name (must be 1-64 lowercase letters/numbers/hyphens): '${name}'`, signature: "unsigned", unsupported: [] };
    const surface = surfaceFrom(parsed.metadata, parsed.arrays);
    intent = { name, description: parsed.scalars["description"] ?? name, version: parsed.scalars["version"] ?? "", surface, bodyExcerpt: parsed.body.slice(0, 500) };
    // signature is over the frontmatter body minus the signature line — reconstruct a stable payload.
    signature = verifyProvenance(parsed.scalars, `${name}\n${intent.description}\n${intent.version}`);
    for (const k of [...Object.keys(parsed.scalars), ...Object.keys(parsed.arrays), ...(parsed.metadata ? ["metadata"] : [])]) if (!KNOWN_FIELDS.has(k)) unsupportedKnown.push(k);
  } else {
    const man = raw as LegacyManifest;
    const name = typeof man.name === "string" ? man.name : "";
    if (!/^[a-z0-9-]{1,64}$/.test(name)) return { warning: "SECURITY WARNING — artifact could not be safely parsed; do not run it.", rejected: `legacy manifest: invalid or missing name (1-64 lowercase/hyphen): '${name}'`, signature: "unsigned", unsupported: [] };
    const surface: DeclaredSurface = { env: [], bins: [], os: [], permissions: strArr(man.permissions), triggers: strArr(man.triggers), tools: [] };
    intent = { name, description: typeof man.description === "string" ? man.description : name, version: typeof man.version === "string" ? man.version : "", surface, bodyExcerpt: "" };
    signature = "unsigned"; // legacy manifests carry no Ed25519 provenance
    for (const k of Object.keys(man)) if (!new Set(["name", "version", "description", "triggers", "permissions", "config"]).has(k)) unsupportedKnown.push(k);
  }

  const warning = buildWarning(intent, signature);
  const bespokeSpec = buildBespokeSpec(intent);
  const recommendation = `Author the bespoke Keep skill '${bespokeSpec.name}' (modeled after the intent) and run it through Keep's distiller→validator→canary. Do NOT execute the OpenClaw skill.`;

  // OVERRIDE: only an explicit acknowledgeRisk translates the FOREIGN artifact — through the SAME gate. Informs, never obstructs.
  if (opts.acknowledgeRisk === true) {
    const foreign = foreignToDistilled(intent);
    const bad = gate(foreign);
    if (bad) return { warning, intent, bespokeSpec, recommendation, signature, unsupported: unsupportedKnown, rawRejected: `safety gate rejected the foreign import: ${bad}` };
    return { warning, intent, bespokeSpec, recommendation, signature, unsupported: unsupportedKnown, rawSkill: foreign };
  }

  // DEFAULT: bespoke recommendation only — NO raw foreign skill is returned.
  return { warning, intent, bespokeSpec, recommendation, signature, unsupported: unsupportedKnown };
}
