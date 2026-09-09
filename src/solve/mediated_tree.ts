/**
 * Mediation invariant (Build Step 1 — hardening the mediation root).
 *
 * THE PROPERTY: "no agent-originated effect reaches outside the system except
 * through a mediated chokepoint that records to the spine."
 *
 * For repo file-effects the chokepoint is `applyEditPlan`, which writes AND
 * registers a reversible action in the RollbackLedger — and `RollbackLedger.record`
 * stages an event to the spine. So write is *supposed* to be coupled to a
 * spine-recording ledger entry. Before this module that coupling was a CONVENTION
 * (applyEditPlan happened to do both); nothing PREVENTED a stray `tree.write(...)`
 * from mutating the working tree with no ledger/spine record — a silent, unmediated,
 * un-auditable, un-rollbackable effect.
 *
 * This module converts the convention into STRUCTURE: a `mediatedTree` refuses any
 * write that does not occur inside a mediation scope (`runMediated`), which the
 * recording chokepoint opens. A bare write throws `UnmediatedEffectError`.
 *
 * HONESTY (R3): this is an IN-ENV, best-effort guard for code running in this
 * process. It does not contain a compiled/out-of-process escape that writes to the
 * filesystem directly — that is the kernel belt (Landlock/seccomp), a SEAM. In-env
 * it makes the *typed-DSL* effect path structurally mediated; the SEAM makes it
 * complete on real infra.
 *
 * Scoping uses AsyncLocalStorage (node built-in, zero-dep): the mediation mark
 * propagates through awaits within the scope and is isolated per async context, so
 * concurrent commits don't leak permission to each other.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import type { FileTree } from "./patch.js";

export class UnmediatedEffectError extends Error {
  constructor(path: string) {
    super(
      `unmediated effect blocked: write to '${path}' occurred outside a mediated, ` +
        `spine-recording chokepoint (the mediation invariant)`,
    );
    this.name = "UnmediatedEffectError";
  }
}

const mediationScope = new AsyncLocalStorage<WriteGrant>();

/**
 * A per-commit write grant (Build Step 1, R24). Authority is an EXPLICIT object that
 * names exactly the writes the chokepoint declared — not an ambient "we are in a
 * mediated region" flag. A mediatedTree admits a write ONLY if (path, content) matches
 * a remaining entry in the active grant; any other write, even inside the same async
 * context, is refused. This closes the ambient-authority hole (HUNT3b): the countersign
 * travels with the specific voucher, not the room.
 *
 * Each declared write is one-shot: matching consumes it, so a duplicate/extra write to
 * the same path is not silently permitted either.
 */
export class WriteGrant {
  private readonly remaining: Array<{ path: string; content: string }>;
  constructor(writes: ReadonlyArray<{ path: string; content: string }>) {
    this.remaining = writes.map((w) => ({ path: w.path, content: w.content }));
  }
  /** Consume a matching (path, content) authorization; false if none matches. */
  consume(path: string, content: string): boolean {
    const i = this.remaining.findIndex((w) => w.path === path && w.content === content);
    if (i < 0) return false;
    this.remaining.splice(i, 1);
    return true;
  }
}

/**
 * Run `fn` under an explicit write grant — the ONLY context in which a mediatedTree
 * permits writes, and then ONLY the writes named in the grant. Replaces the former
 * ambient `runMediated(fn)` (which authorized ALL writes in the async context).
 */
export function runMediatedWith<T>(grant: WriteGrant, fn: () => Promise<T>): Promise<T> {
  return mediationScope.run(grant, fn);
}

/** The active write grant for the current async context, if any. */
function activeGrant(): WriteGrant | undefined {
  return mediationScope.getStore();
}

/**
 * Back-compat / test helper: run `fn` under a grant that authorizes the given writes
 * (default: none). With no writes it opens a scope in which the grant admits nothing —
 * useful only to observe isMediating(); real chokepoints use runMediatedWith with an
 * explicit write-set.
 */
export function runMediated<T>(
  fn: () => Promise<T>,
  writes: ReadonlyArray<{ path: string; content: string }> = [],
): Promise<T> {
  return mediationScope.run(new WriteGrant(writes), fn);
}

/** True iff the current async context is inside a mediated commit (any grant present). */
export function isMediating(): boolean {
  return activeGrant() !== undefined;
}

const MEDIATED = Symbol("keep.mediatedTree");

/**
 * Wrap a FileTree so writes are refused unless inside runMediated(...). Reads pass
 * through unchanged. This is the membrane: the returned object closes over `inner`
 * (no accessor exposes it) and carries a symbol tag so wrapping is idempotent. The
 * FileTree surface is exactly {read, write} (vet HUNT4), so no sub-reference leaks
 * through a returned value — the membrane is complete for this port.
 */
export function mediatedTree(inner: FileTree): FileTree {
  const m: FileTree = {
    read(path: string): Promise<string | undefined> {
      return inner.read(path);
    },
    async write(path: string, content: string): Promise<void> {
      const grant = activeGrant();
      if (!grant) throw new UnmediatedEffectError(path);
      // Per-write authority (R24): only writes named in the grant are admitted;
      // an unregistered write inside the same scope is refused (closes HUNT3b).
      if (!grant.consume(path, content)) throw new UnmediatedEffectError(path);
      return inner.write(path, content);
    },
    ...(inner.commitBatchIfUnchanged
      ? { async commitBatchIfUnchanged(expected: Readonly<Record<string, string>>, writes: readonly { readonly path: string; readonly content: string }[]): Promise<boolean> {
          const grant = activeGrant();
          if (!grant) throw new UnmediatedEffectError(writes[0]?.path ?? "<empty-batch>");
          for (const write of writes) if (!grant.consume(write.path, write.content)) throw new UnmediatedEffectError(write.path);
          return inner.commitBatchIfUnchanged!(expected, writes);
        } }
      : {}),
  };
  (m as unknown as Record<symbol, unknown>)[MEDIATED] = true;
  return m;
}

/** True iff `tree` is already a membrane (so ensureMediated is a no-op on it). */
export function isMediated(tree: FileTree): boolean {
  return (tree as unknown as Record<symbol, unknown>)[MEDIATED] === true;
}

/**
 * Idempotently return a mediated view of `tree`. Agent-path components call this at
 * construction and store ONLY the result, so they never hold a raw, unmediated-
 * writable reference (closes R23 — mediation is structural on the agent path, not
 * a boundary check at the call site). Wrapping an already-mediated tree is a no-op.
 */
export function ensureMediated(tree: FileTree): FileTree {
  return isMediated(tree) ? tree : mediatedTree(tree);
}
