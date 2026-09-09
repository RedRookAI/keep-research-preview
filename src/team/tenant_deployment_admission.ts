import { realpathSync } from "node:fs";
import { relative, sep } from "node:path";
import { canonicalize } from "../spine/event.js";
import { createHash } from "node:crypto";

export class TenantDeploymentAdmissionError extends Error {
  constructor(message: string) { super(message); this.name = "TenantDeploymentAdmissionError"; }
}

export interface TenantDeploymentRoots {
  readonly tenantId: string;
  readonly dataRoot: string;
  readonly repositoryRoot: string;
  readonly workspaceRoot: string;
  /** Explicit witness/export root when it lives outside dataRoot; an in-data witness is covered by dataRoot. */
  readonly witnessRoot?: string;
}

export interface TenantDeploymentAdmission {
  readonly tenantId: string;
  readonly rosterDigest: string;
  readonly roots: Readonly<TenantDeploymentRoots>;
  readonly peerCount: number;
}

const SAFE_TENANT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;

/**
 * Boot admission for a structurally isolated tenant process. It validates deployment facts only:
 * request routing and product state remain owned by the canonical gateway, registry, and Spine.
 */
export function admitTenantDeployment(
  own: TenantDeploymentRoots,
  peers: readonly TenantDeploymentRoots[],
): TenantDeploymentAdmission {
  if (peers.length < 1 || peers.length > 10_000) throw new TenantDeploymentAdmissionError("shared deployment requires a bounded non-empty peer roster");
  const roster = [normalize(own), ...peers.map(normalize)];
  const tenantIds = new Set<string>();
  for (const member of roster) {
    if (tenantIds.has(member.tenantId)) throw new TenantDeploymentAdmissionError(`duplicate tenant ${member.tenantId}`);
    tenantIds.add(member.tenantId);
  }
  assertAllRootsDisjoint(roster);
  const ordered = [...roster].sort((a, b) => a.tenantId.localeCompare(b.tenantId));
  const rosterDigest = createHash("sha256").update(canonicalize(ordered)).digest("hex");
  return Object.freeze({ tenantId: roster[0]!.tenantId, rosterDigest, roots: roster[0]!, peerCount: peers.length });
}

function normalize(input: TenantDeploymentRoots): Readonly<TenantDeploymentRoots> {
  if (!SAFE_TENANT.test(input.tenantId) || input.tenantId === "keep.n1.default") throw new TenantDeploymentAdmissionError("tenant id must be a 1-128 character safe non-reserved identifier");
  try {
    return Object.freeze({
      tenantId: input.tenantId,
      dataRoot: realpathSync(input.dataRoot),
      repositoryRoot: realpathSync(input.repositoryRoot),
      workspaceRoot: realpathSync(input.workspaceRoot),
      ...(input.witnessRoot === undefined ? {} : { witnessRoot: realpathSync(input.witnessRoot) }),
    });
  } catch {
    throw new TenantDeploymentAdmissionError(`tenant ${input.tenantId} roots must exist and resolve without ambiguity`);
  }
}

function roots(input: TenantDeploymentRoots): readonly (readonly [string, string])[] {
  return [["dataRoot", input.dataRoot], ["repositoryRoot", input.repositoryRoot], ["workspaceRoot", input.workspaceRoot], ...(input.witnessRoot === undefined ? [] : [["witnessRoot", input.witnessRoot] as const])];
}

function assertAllRootsDisjoint(roster: readonly Readonly<TenantDeploymentRoots>[]): void {
  const entries = roster.flatMap((member) => roots(member).map(([kind, path]) => ({ tenantId: member.tenantId, kind, path })))
    .sort((a, b) => Buffer.compare(Buffer.from(componentKey(a.path)), Buffer.from(componentKey(b.path))));
  // NUL cannot occur in a filesystem component and sorts below every component byte, so a parent and all descendants
  // form one contiguous prefix range. Any overlap is therefore adjacent even when a lexical sibling such as `a-2`
  // would otherwise sort between `a` and `a/child`.
  for (let index = 1; index < entries.length; index++) {
    const prior = entries[index - 1]!, current = entries[index]!;
    if (!overlaps(prior.path, current.path)) continue;
    if (prior.tenantId === current.tenantId) throw new TenantDeploymentAdmissionError(`tenant ${prior.tenantId} ${prior.kind} overlaps its ${current.kind}`);
    throw new TenantDeploymentAdmissionError(`tenant ${prior.tenantId} ${prior.kind} overlaps tenant ${current.tenantId} ${current.kind}`);
  }
}

function componentKey(path: string): string { return path.split(sep).join("\0"); }

function overlaps(a: string, b: string): boolean {
  const nested = (from: string, to: string): boolean => {
    const rel = relative(from, to);
    return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`));
  };
  return nested(a, b) || nested(b, a);
}
