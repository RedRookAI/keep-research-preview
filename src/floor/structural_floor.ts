/**
 * Structural floor.
 *
 * A pure, total, MODEL-INDEPENDENT reference monitor over a typed op description. It
 * returns one of two verdicts — `reversible-execute` (the op is provably in the
 * narrow reversible class) or `gate` (everything else) — computed only from crisp
 * structural facts. There is NO model, NO learned classifier, NO threshold on a
 * probability. It cannot be argued with, which is the point.
 *
 * GROUNDING (research and historical references, 2026-08-08):
 *  - Anderson's reference monitor + Saltzer-Schroeder (1975): complete mediation,
 *    least privilege, economy of mechanism, and above all FAIL-SAFE DEFAULTS — base
 *    the decision on permission, not exclusion; the default is no access. Here: the
 *    default is `gate`; `reversible-execute` must be positively, structurally earned.
 *  - The deployed lesson from agent-security work: prefer a small DETERMINISTIC policy
 *    engine over a model-based judge; an LLM that authors the policy strains
 *    verifiability, and early-binarizing a classifier's score leaks uncertainty.
 *  - Cross-industry: the aviation Minimum Equipment List / go-no-go checklist — a
 *    coarse, pre-committed list consulted deterministically, not negotiated.
 *
 * CONSERVATISM: the predicates are NECESSARY conditions for reversibility, not
 * sufficient proof of safety. The floor reliably REJECTS (gates) anything not provably
 * reversible; it never certifies an op as "safe", only as "reversible-class, eligible
 * to run under the envelope". Irreversible / external / protected / unbounded / unknown
 * all fail closed to `gate`. This is the floor beneath the untrusted optimizer (which
 * may only RAISE caution) — it is never lowered by anything above it.
 */

// The floor is otherwise dependency-free. This one edge is deliberate: `withinScope` is a
// pure lexical predicate with no I/O, so the floor stays total and pure — and sharing it is
// what keeps the allowlist and the identity scope from becoming two mechanisms that disagree.
import { withinScope, unsupportedScopePatterns } from "../authz/path_scope.js";

export type FloorVerdict = {
  readonly verdict: "reversible-execute" | "gate";
  readonly reasons: readonly string[];
};

/** A typed description of an op's declared effect. Missing fields read as UNKNOWN → caution. */
export interface OpDescription {
  /** Effect kind, e.g. "file.edit", "sql", "shell", "git.push", "net.request". */
  readonly kind: string;
  /** Enumerated paths the op will write. undefined ⇒ unknown ⇒ treated as UNBOUNDED. */
  readonly writeSet?: readonly string[];
  /** External sinks the op reaches (hosts, external DBs, remotes). Non-empty ⇒ external. */
  readonly externalSinks?: readonly string[];
  /** Does the op carry a concrete, constructible inverse? undefined ⇒ unknown ⇒ false. */
  readonly hasInverse?: boolean;
  /** Raw command/SQL/patch text, screened for catastrophic + destructive sinks. */
  readonly raw?: string;
  /** Resources the op references (for protected-resource screening). */
  readonly targets?: readonly string[];
}

/** Pre-committed policy (config data, never model output). */
export interface FloorPolicy {
  /** Op-kinds eligible for the reversible class (everything else gates by construction). */
  readonly reversibleKinds: readonly string[];
  /** Jail root; every written path must resolve within it or the write-set is unbounded. */
  readonly workspaceRoot: string;
  /** Protected-resource matchers (config outside the write-set, secrets, spine, backups). */
  readonly protectedMatchers: readonly RegExp[];
  /** Operator-allowed write regions. Omission leaves the optional restriction absent;
   * an empty array permits no writes, while ["*"] permits every contained path. */
  readonly allowedPaths?: readonly string[];

  /** Acting-agent write scope. Declared writes must satisfy this scope and the
   * operator allowlist through the same withinScope predicate. Omission leaves
   * this optional restriction absent. In-process identity objects remain trusted. */
  readonly agentScope?: readonly string[];
}

/**
 * ROUND 40 — policy inputs that are configured into SILENCE.
 *
 * THE FAMILY, established by sweeping every policy input rather than patching the one case
 * already known. The fail-safe direction of a policy input depends on its SHAPE:
 *
 *   ALLOWLIST emptied  → admits nothing → refuses everything → LOUD, noticed immediately
 *   DENYLIST  emptied  → denies nothing → refuses nothing    → SILENT
 *   CEILING   raised   → never trips    → refuses nothing    → SILENT
 *
 * Keep has all three shapes, so half its policy surface fails safe when misconfigured and half
 * fails open. Measured: `protectedMatchers: []` stops refusing a `.env` write entirely, and
 * budget ceilings at `Infinity` stop tripping on any consumption. Neither says anything.
 *
 * WHY THIS CANNOT BE A REFUSAL. Every existing report — the floor's reasons, the gate's route
 * reasons, the pipeline's `held` status — is emitted ONLY when something is refused. A barrier
 * that has been configured into silence never refuses, so it is structurally unreportable by
 * the mechanisms that exist. This function is a separate, observe-only channel for that.
 *
 * WHAT IS DELIBERATELY *NOT* REPORTED: a plain `["*"]` allowlist, or an omitted one. Those are
 * the documented ways to say "unconstrained", and the policy-linting literature is explicit that
 * flagging syntactic permissiveness alone produces alerts that "tell you a policy is
 * syntactically permissive, but not whether those permissive actions are actually used" — the
 * muted-warning path. Only a SELF-CONTRADICTORY config is reported: one whose spelling implies a
 * constraint while its effect is none.
 */
/**
 * The SELF-CONTRADICTORY-scope predicate, factored out so the RUN-time report ({@link
 * inertFloorInputs}) and the CONFIG-TIME assessor ({@link assessDeclaredScope}) share ONE
 * definition rather than two that could drift apart. A scope that names specific regions yet also
 * contains a bare `"*"` reads as restrictive and constrains nothing. Returns the finding string, or
 * undefined when the scope is not self-contradictory.
 */
function selfContradictoryScope(allowed: readonly string[] | undefined): string | undefined {
  if (allowed !== undefined && allowed.length > 1 && allowed.includes("*")) {
    const others = allowed.filter((a) => a !== "*");
    return `allowedPaths names ${others.length} region(s) (${others.join(", ")}) but also contains a bare "*", which admits everything — the scope reads as restrictive and constrains nothing`;
  }
  return undefined;
}

export function inertFloorInputs(policy: FloorPolicy): string[] {
  const found: string[] = [];
  if (policy.protectedMatchers.length === 0) {
    found.push("protectedMatchers is empty — protected-resource screening is disabled, so secrets, .git and the spine are not defended");
  }
  const contradiction = selfContradictoryScope(policy.allowedPaths);
  if (contradiction !== undefined) found.push(contradiction);
  return found;
}

/** Classify declared scope for a one-time configuration audit. The assessment
 * records broad, contradictory and malformed scope without changing authority. */
export type DeclaredScopeDisposition =
  | "unconstrained" // omitted or a scope containing a bare "*" — admits everything
  | "self-contradictory" // names regions AND a bare "*" (a special case of unconstrained)
  | "malformed" // contains an unsupported pattern (slash + "*")
  | "constrained"; // a real, narrow scope — nothing to surface

export interface DeclaredScopeAssessment {
  /** The declared scope VERBATIM (undefined ⇒ omitted). Never narrowed, never rewritten. */
  readonly declared: readonly string[] | undefined;
  /** True when the scope admits every path inside the jail — an omitted scope or one with a bare "*". */
  readonly admitsEverything: boolean;
  /** Headline classification for the audit record. */
  readonly disposition: DeclaredScopeDisposition;
  /** Auditable, actionable findings (malformed patterns, self-contradiction). Empty for a clean scope. */
  readonly findings: readonly string[];
  /**
   * True when this assessment is worth an auditable set-time record: the operator DECLARED a scope
   * (not omitted) that is over-broad or malformed. A clean narrow scope and an omitted scope are both
   * false — no config-time noise, front-of-house unchanged.
   */
  readonly worthRecording: boolean;
}

export function assessDeclaredScope(allowedPaths: readonly string[] | undefined): DeclaredScopeAssessment {
  const findings: string[] = [];
  const unsupported = unsupportedScopePatterns(allowedPaths ?? []);
  for (const bad of unsupported) {
    findings.push(`unsupported-scope-pattern:${bad} (supported: a path, a directory, or a slashless glob like *.md)`);
  }
  const contradiction = selfContradictoryScope(allowedPaths);
  if (contradiction !== undefined) findings.push(contradiction);

  const admitsEverything = allowedPaths === undefined || allowedPaths.includes("*");
  const disposition: DeclaredScopeDisposition =
    unsupported.length > 0 ? "malformed" : contradiction !== undefined ? "self-contradictory" : admitsEverything ? "unconstrained" : "constrained";

  // Record only a DECLARED (not omitted) scope that is over-broad or malformed. Omitted ⇒ nothing
  // was declared ⇒ nothing to audit (byte-identical front-of-house). A clean narrow scope is silent.
  const worthRecording = allowedPaths !== undefined && (admitsEverything || findings.length > 0);

  return { declared: allowedPaths, admitsEverything, disposition, findings, worthRecording };
}

// ── Seeded, generalized sink patterns (from patch_verifier RISK_SINKS/CATASTROPHIC/DESTRUCTIVE) ──
const CATASTROPHIC: readonly RegExp[] = [
  /\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+["']?[~/]/i,
  /\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+["']?\$?\{?HOME/i,
  /\bmkfs\.[a-z0-9]+/i,
  /\bdd\s+[^\n]*\bof=\/dev\//i,
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
  />\s*\/dev\/(sd|nvme|disk|hd)/i,
  /\bshred\s+-/i,
];
const EXTERNAL_SINK_TEXT: readonly RegExp[] = [
  /\bgit\s+push\b/i,
  /\bcurl\b|\bwget\b|\bfetch\s*\(|\bhttps?:\/\//i,
  /\b(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA|COLLECTION|INDEX)\b/i,
  /\bDELETE\s+FROM\b(?![^;]*\bWHERE\b)/i,
];

function screens(raw: string | undefined, pats: readonly RegExp[]): boolean {
  if (!raw) return false;
  return pats.some((re) => re.test(raw));
}

// ── Decidable predicates (each TOTAL; unknown resolves to the cautious value) ──

function onReversibleWhitelist(op: OpDescription, policy: FloorPolicy): boolean {
  return policy.reversibleKinds.includes(op.kind);
}

function inverseConstructible(op: OpDescription): boolean {
  return op.hasInverse === true; // undefined/false ⇒ not reversible
}

function writeSetBounded(op: OpDescription, policy: FloorPolicy): boolean {
  if (op.writeSet === undefined) return false; // unknown ⇒ unbounded ⇒ caution
  if (op.writeSet.length === 0) return true; // no writes is trivially bounded
  const root = policy.workspaceRoot.replace(/\/+$/, "");
  return op.writeSet.every((p) => {
    // reject traversal / absolute escapes; require containment in the jail root
    if (p.includes("..")) return false;
    const norm = p.startsWith("/") ? p : `${root}/${p}`;
    return norm.startsWith(`${root}/`) || norm === root;
  });
}

/** Return the first undeclared or operator-disallowed write. Omitted policy is unconstrained. */
function firstPathOutsideAllowedScope(op: OpDescription, policy: FloorPolicy): string | undefined {
  if (policy.allowedPaths === undefined) return undefined; // unconstrained
  if (op.writeSet === undefined) return "<undeclared-write-set>";
  return op.writeSet.find((p) => !withinScope(policy.allowedPaths!, p));
}

/** Return the first undeclared or agent-disallowed write; both scopes must admit each path. */
function firstPathOutsideAgentScope(op: OpDescription, policy: FloorPolicy): string | undefined {
  if (policy.agentScope === undefined) return undefined; // no acting-agent constraint (byte-identical)
  if (op.writeSet === undefined) return "<undeclared-write-set>";
  return op.writeSet.find((p) => !withinScope(policy.agentScope!, p));
}

function reachesExternalSink(op: OpDescription): boolean {
  if ((op.externalSinks?.length ?? 0) > 0) return true;
  return screens(op.raw, EXTERNAL_SINK_TEXT);
}

function isCatastrophic(op: OpDescription): boolean {
  return screens(op.raw, CATASTROPHIC);
}

function touchesProtected(op: OpDescription, policy: FloorPolicy): boolean {
  const paths = [...(op.writeSet ?? []), ...(op.targets ?? [])];
  return paths.some((p) => policy.protectedMatchers.some((re) => re.test(p)));
}

/**
 * The floor. `reversible-execute` is earned ONLY if every necessary condition holds;
 * otherwise `gate`, with the specific reasons recorded. Total and pure: same input ⇒
 * same output, no I/O, no model.
 */
export function structuralFloor(op: OpDescription, policy: FloorPolicy): FloorVerdict {
  const reasons: string[] = [];

  if (isCatastrophic(op)) reasons.push("catastrophic-op");
  if (reachesExternalSink(op)) reasons.push("external-sink");
  if (touchesProtected(op, policy)) reasons.push("protected-resource");
  if (!onReversibleWhitelist(op, policy)) reasons.push(`kind-not-on-reversible-whitelist:${op.kind}`);
  if (!inverseConstructible(op)) reasons.push("no-constructible-inverse");
  if (!writeSetBounded(op, policy)) reasons.push("write-set-unbounded-or-escapes-jail");
  // ROUND 39: an unsupported scope pattern is the OPERATOR's bug, and it must say so. Left
  // silent, `src/**/*.ts` would match nothing, every plan would be refused, and the operator
  // would conclude the control is broken and remove it — the Z135 abandonment path, reached by
  // a spelling mistake nobody reported. Named first, because it explains the refusals below it.
  for (const bad of unsupportedScopePatterns(policy.allowedPaths ?? [])) {
    reasons.push(`unsupported-scope-pattern:${bad} (supported: a path, a directory, or a slashless glob like *.md)`);
  }
  // the SAME loud-error treatment for a malformed AGENT scope. Left silent,
  // `src/*.ts` in an identity scope would match nothing via `withinScope`, refuse every write for
  // that agent, and read as "the control is broken" (the Z135 abandonment path) — the exact footgun
  // round 39 fixed for `allowedPaths`. Parity, not a new mechanism.
  for (const bad of unsupportedScopePatterns(policy.agentScope ?? [])) {
    reasons.push(`unsupported-agent-scope-pattern:${bad} (supported: a path, a directory, or a slashless glob like *.md)`);
  }
  const outside = firstPathOutsideAllowedScope(op, policy);
  if (outside !== undefined) {
    // Name the minimal addition that would permit it. A refusal an operator can act on in one
    // step is a control they keep; a dead-end refusal is one they switch off.
    const hint = outside.includes("/") ? outside.slice(0, outside.indexOf("/")) : outside;
    reasons.push(`write-set-outside-allowed-scope:${outside} (add "${hint}" to allowedPaths to permit it)`);
  }
  // the per-agent conjunct. Effective authority is the INTERSECTION of
  // the operator allowlist and the acting agent's scope; a write within `allowedPaths` but outside
  // `agentScope` is refused, NAMING the path and the fact that the agent's own authority — not the
  // operator's — is what excluded it. Distinct reason from `allowed-scope` so the operator learns
  // WHICH boundary was crossed rather than widening the wrong one.
  const outsideAgent = firstPathOutsideAgentScope(op, policy);
  if (outsideAgent !== undefined) {
    reasons.push(`write-set-outside-agent-scope:${outsideAgent} (the acting agent's identity.scope does not permit it — effective authority is the INTERSECTION of the operator allowlist and the agent scope, the more restrictive of the two)`);
  }

  if (reasons.length === 0) {
    return { verdict: "reversible-execute", reasons: ["all-reversibility-preconditions-met"] };
  }
  return { verdict: "gate", reasons };
}

/** A conservative default policy (data only). Deployments narrow/extend it. */
/**
 * `allowedPaths` is threaded as an OPTIONAL second argument rather than added to the required
 * shape, so every existing caller of `defaultFloorPolicy(root)` keeps its exact behaviour and
 * the default stays unconstrained.
 */
export function defaultFloorPolicy(workspaceRoot: string, allowedPaths?: readonly string[]): FloorPolicy {
  return {
    reversibleKinds: ["file.edit"], // only in-workspace file edits are reversible-class by default
    workspaceRoot,
    protectedMatchers: [
      /(^|\/)\.git\//,
      /(^|\/)\.env(\.|$)/,
      /(^|\/)(secrets?|credentials?)(\/|\.|$)/i,
      /(^|\/)keep[-_]?config(\.|$)/i,
      /(^|\/)spine(\/|\.|$)/i,
      /(^|\/)(backups?|snapshots?)(\/|$)/i,
    ],
    // Spread rather than assigned, so an omitted allowlist leaves the KEY ABSENT rather than
    // present-and-undefined. The predicate keys off `=== undefined`, so both behave the same
    // today — but an absent key cannot be mistaken for a configured-then-cleared one by a
    // future reader or a structural diff.
    ...(allowedPaths !== undefined ? { allowedPaths } : {}),
  };
}
