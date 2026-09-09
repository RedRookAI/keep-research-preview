/** Closed-world admission for the effect owners used by Keep's installed solve path. */

export type InstalledEffectKind = "file" | "process" | "network" | "git" | "publication";

export const INSTALLED_EFFECT_OWNERS = Object.freeze({
  workspaceRead: { id: "workspace.read", kind: "file", control: "project jail + symlink refusal" },
  workspaceWrite: { id: "workspace.write", kind: "file", control: "write grant + project jail + symlink refusal" },
  repositoryMaterialize: { id: "repository.materialize", kind: "git", control: "exact immutable revision + new confined destination" },
  testProcess: { id: "solve.test-process", kind: "process", control: "resource-bounded process isolation" },
  modelNetwork: { id: "model.remote-egress", kind: "network", control: "one-shot broker permit + witnessed intent" },
  proposalPublication: { id: "proposal.publish", kind: "publication", control: "governed task branch + pinned remote + reversible push" },
  gitCommand: { id: "git.command", kind: "git", control: "closed environment + argv-only invocation" },
} as const satisfies Record<string, { readonly id: string; readonly kind: InstalledEffectKind; readonly control: string }>);

export type InstalledEffectOwnerId = (typeof INSTALLED_EFFECT_OWNERS)[keyof typeof INSTALLED_EFFECT_OWNERS]["id"];
const declarations = new Map<string, InstalledEffectAdmissionRecord>(
  Object.values(INSTALLED_EFFECT_OWNERS).map((owner) => [owner.id, owner]),
);

export interface InstalledEffectAdmissionRecord {
  readonly id: InstalledEffectOwnerId;
  readonly kind: InstalledEffectKind;
  readonly control: string;
}

export class UnknownEffectOwnerError extends Error {
  constructor(readonly owner: string) {
    super(`unknown installed effect owner '${owner}' — held before execution`);
    this.name = "UnknownEffectOwnerError";
  }
}

/** This boundary establishes ownership; it does not replace the owner's sandbox, permit, grant, pin, or gate. */
export class InstalledEffectAdmission {
  constructor(private readonly observe?: (record: InstalledEffectAdmissionRecord) => void) {}

  admit(owner: string): InstalledEffectAdmissionRecord {
    const declaration = declarations.get(owner);
    if (!declaration) throw new UnknownEffectOwnerError(owner);
    const record: InstalledEffectAdmissionRecord = declaration;
    this.observe?.(record);
    return record;
  }

  inventory(): readonly InstalledEffectAdmissionRecord[] { return [...declarations.values()]; }
}

/** Default boundary used by every owner, including callers outside composeKeep. */
export const installedEffectAdmission = new InstalledEffectAdmission();

