/**
 * Reversible Execution Envelope (REE) — Build Step 2, layer 4.
 *
 * Turns a floor `reversible-execute` verdict into an ACTUALLY reversible execution.
 * The pipeline is a two-phase-commit / shadow-paging discipline:
 *
 *   confine → checkpoint → execute-on-a-fork → metamorphic acceptance → commit | rollback
 *
 * WHY IT IS ATOMIC (the load-bearing property):
 *   Execution happens on a FORK — a shadow copy of the tree. The real tree is NEVER
 *   written until the commit phase. So on reject there is no partial write to undo: we
 *   discard the fork and the real tree is byte-identical to the pre-state by
 *   construction. This is the copy-on-write / shadow-paging answer, not a careful
 *   sequence of compensations. (The commit-phase copy-back is the one place a crash
 *   could leave a partial state; that is covered by the spine checkpoint anchor + the
 *   RollbackLedger's compensating inverse — belt for the copy-back, not the guarantee.)
 *
 * GROUNDING (research, 2026-08-08):
 *   - Two-phase commit / WAL (Gray; Fowler; Wikipedia): a prepare phase does everything
 *     needed to commit EXCEPT committing; a NO vote aborts and each participant undoes
 *     via its undo log. Here the fork IS the prepare staging area and the metamorphic
 *     test IS the vote.
 *   - Saga / compensation: "an operation that semantically reverses an earlier one" — the
 *     RollbackLedger's real inverse, registered so undo is real, not hoped.
 *   - Metamorphic testing (Chen et al.): metamorphic relations are NECESSARY conditions;
 *     a violated relation is a RELIABLE REJECT, but all-relations-hold is a WEAK ACCEPT
 *     that does NOT prove correctness. The envelope's authority is therefore SCOPED TO
 *     REVERSIBILITY: it can reliably reject and guarantee restoration; it never certifies
 *     the op correct.
 *
 * HONESTY: a `committed` outcome means "no necessary reversibility relation was
 * violated and the effect is sealed", NOT "the op is correct". Kernel-enforced
 * confinement of the fork (so a compromised executor cannot reach the real tree out of
 * band) remains the R3 SEAM — in-env, the fork is a separate object, not an OS jail.
 */

import type { FileTree } from "../solve/patch.js";
import { InMemoryFileTree } from "../solve/patch.js";
import type { Spine } from "../spine/spine.js";
import type { FloorVerdict, OpDescription } from "../floor/structural_floor.js";
import { checkBudget, type ConsumptionRecord, type BudgetPolicy } from "../budget/budget_ledger.js";

/** A metamorphic relation: a NECESSARY property over (pre-state, post-state, op). */
export interface MetamorphicRelation {
  readonly name: string;
  /** true = relation holds; false = violated ⇒ reliable REJECT. */
  check(pre: Readonly<Record<string, string>>, post: Readonly<Record<string, string>>, op: OpDescription): boolean;
}

/** The acceptance test = a set of necessary relations. Reliable reject; weak accept. */
export interface AcceptanceTest {
  readonly relations: readonly MetamorphicRelation[];
}

/** An op the envelope can run: it mutates the (forked) tree it is handed. */
export interface EnvelopeOp {
  readonly description: OpDescription;
  /** Perform the effect against the given tree (a fork during the attempt). */
  execute(tree: FileTree): Promise<void>;
}

export type EnvelopeOutcome =
  | { outcome: "committed"; accept: "weak"; sealedSeq: number | undefined; relations: readonly string[] }
  | { outcome: "rolled-back"; reason: string; violated: readonly string[] }
  | { outcome: "refused"; reason: string };

export interface EnvelopeDeps {
  readonly spine: Spine;
  readonly actor: string;
  /** Operator identity + signer for the restoration attestation on rollback. */
  readonly operator: string;
  readonly sign: (payload: string) => string;
  /**
   * Optional structural budget. When present, the envelope measures the fork's ACTUAL
   * consumption (files, bytes, edits) — merged with any caller-declared counts (fan-out,
   * steps) — and an exceeded budget forces the cautious branch (rollback) BEFORE commit.
   * This CONSUMES the floor verdict (only reversible ops reach here); it can only ADD caution.
   */
  readonly budget?: { readonly declared?: ConsumptionRecord; readonly policy: BudgetPolicy };
  /**
   * Optional commit sink. When present, the accepted fork writes are handed to this function
   * INSTEAD of being written directly to realTree — the live integration supplies a commit
   * that writes through the mediated tree under a per-write grant, preserving R23/R24. When
   * absent, the envelope copies back to realTree directly (the standalone default).
   */
  readonly commit?: (writes: readonly { readonly path: string; readonly content: string }[]) => Promise<void>;
  /**
   * ROUND 36 — an optional LAST-MOMENT precondition, evaluated immediately before the commit
   * writes begin. Returning a string REFUSES and routes through the ORDINARY rollback, so the
   * atomicity guarantee is untouched: nothing has been written yet, and the real tree is
   * byte-identical to pre by construction, exactly as for a metamorphic reject.
   *
   * The hook may be asynchronous for a fresh repository traversal. Content-bound callers must
   * additionally use the commit sink's atomic compare-and-swap primitive; this hook provides
   * whole-repository/context refusal while CAS closes the target-byte check/use race.
   */
  readonly precommit?: () => string | undefined | Promise<string | undefined>;
}

/** Which files changed between pre and post (added / modified / removed). */
function changedPaths(pre: Record<string, string>, post: Record<string, string>): string[] {
  const keys = new Set([...Object.keys(pre), ...Object.keys(post)]);
  const changed: string[] = [];
  for (const k of keys) if (pre[k] !== post[k]) changed.push(k);
  return changed;
}

/**
 * The envelope. Only a floor `reversible-execute` verdict may enter; a `gate` verdict is
 * REFUSED here (it is already routed to human upstream — this is defence in depth).
 */
export async function runReversibly(
  op: EnvelopeOp,
  floorVerdict: FloorVerdict,
  realTree: InMemoryFileTree,
  acceptance: AcceptanceTest,
  deps: EnvelopeDeps,
): Promise<EnvelopeOutcome> {
  // 0) Consume the floor verdict. Gate ops never execute in the envelope.
  if (floorVerdict.verdict !== "reversible-execute") {
    return { outcome: "refused", reason: `floor-verdict-not-reversible:${floorVerdict.verdict}` };
  }

  // 1) Checkpoint: capture the pre-image and anchor the pre-state root in the spine.
  const pre = realTree.snapshot();
  const witnessBefore = deps.spine.witnessHead();
  await deps.spine.checkpoint(deps.actor);

  // 2) Confine: execute on a FORK. The real tree is untouched during the attempt.
  const fork = new InMemoryFileTree(pre);
  try {
    await op.execute(fork);
  } catch (e) {
    // Mid-execution failure → discard the fork. Real tree === pre by construction.
    return rollback(deps, witnessBefore, "execution-threw", []);
  }
  const post = fork.snapshot();

  // 3) Budget precondition (structural, model-independent). Measure the fork's ACTUAL
  //    consumption merged with caller-declared counts; an exceeded ceiling forces the
  //    cautious branch (rollback before commit). Consumes the floor verdict; adds caution only.
  if (deps.budget) {
    const changed = changedPaths(pre, post);
    const bytesWritten = changed.reduce((n, p) => n + Buffer.byteLength(post[p] ?? "", "utf8"), 0);
    const measured: ConsumptionRecord = {
      // observed from the fork:
      edits: changed.length,
      filesTouched: changed.length,
      bytesWritten,
      // the envelope's own action is a SINGLE attempt that spawns no sub-agents — these are
      // facts it knows, not unknowns. The caller declares higher when the op itself loops or
      // fans out internally (declared wins). The ledger stays strictly fail-safe for any
      // quantity that is genuinely missing.
      fanOut: 0,
      steps: 1,
      ...deps.budget.declared,
    };
    const budgetVerdict = checkBudget(measured, deps.budget.policy);
    if (budgetVerdict.verdict === "exceeded") {
      return rollback(deps, witnessBefore, `budget-exceeded:${budgetVerdict.ceilings.join(",")}`, []);
    }
  }

  // 4) Metamorphic acceptance: any violated NECESSARY relation ⇒ reliable REJECT.
  const violated = acceptance.relations.filter((r) => !r.check(pre, post, op.description)).map((r) => r.name);
  if (violated.length > 0) {
    return rollback(deps, witnessBefore, "metamorphic-reject", violated);
  }

  // 4.5) ROUND 36 — LAST-MOMENT PRECONDITION, immediately before any write.
  //
  // The authorization that admitted this op was computed once, upstream, before the twin ran.
  // Between that check and here sit TWO full applications of the op (the digital twin's preview
  // and the fork execution), a spine checkpoint, the gate, and the acceptance relations — i.e.
  // the bulk of the elapsed work. Re-asking the question here moves the exposure from "all of
  // that" down to "the write loop itself".
  //
  // Content-bound commit sinks follow this contextual check with atomic batch compare-and-swap.
  // Generic callers retain the historical narrowed-window behavior and do not gain a false CAS claim.
  const refusal = await deps.precommit?.();
  if (refusal !== undefined) {
    return rollback(deps, witnessBefore, refusal, []);
  }

  // 5) Weak ACCEPT → commit: hand the accepted writes to the commit sink (mediated, in the
  //    live path) or copy back to realTree directly (standalone default), then seal.
  const accepted = changedPaths(pre, post)
    .map((path) => ({ path, content: post[path] }))
    .filter((w): w is { path: string; content: string } => w.content !== undefined); // {read,write} has no delete
  if (deps.commit) {
    try { await deps.commit(accepted); }
    catch (error) { return rollback(deps, witnessBefore, `commit-refused:${error instanceof Error ? error.message : "non-Error failure"}`, []); }
  } else {
    for (const { path, content } of accepted) await realTree.write(path, content);
  }
  const sealed = await deps.spine.seal();
  return {
    outcome: "committed",
    accept: "weak", // NOT a correctness proof — only "no necessary relation violated"
    sealedSeq: sealed?.seq,
    relations: acceptance.relations.map((r) => r.name),
  };
}

/** Record an attested, authorized restoration. Real tree is already at pre-state. */
async function rollback(
  deps: EnvelopeDeps,
  witnessBefore: { seq: number; headHash: string } | undefined,
  reason: string,
  violated: readonly string[],
): Promise<EnvelopeOutcome> {
  const priorWitnessedHash = witnessBefore?.headHash ?? "0".repeat(64);
  deps.spine.attestRestoration({
    operator: deps.operator,
    restoredToSeq: witnessBefore?.seq ?? 0,
    priorWitnessedHash,
    signature: deps.sign(`restore:${priorWitnessedHash}:${reason}`),
  });
  await deps.spine.seal();
  return { outcome: "rolled-back", reason, violated };
}

// ── Default necessary relations (all conservative; a violation is a reliable reject) ──

/** Every changed file must be inside the op's declared write-set (no out-of-scope write). */
export const mrWriteSetRespected: MetamorphicRelation = {
  name: "write-set-respected",
  check(pre, post, op) {
    const declared = new Set(op.writeSet ?? []);
    return changedPaths(pre, post).every((p) => declared.has(p));
  },
};

/** No file outside the declared write-set may change (the dual, stated explicitly). */
export const mrNoCollateralChange: MetamorphicRelation = {
  name: "no-collateral-change",
  check(pre, post, op) {
    const declared = new Set(op.writeSet ?? []);
    for (const k of new Set([...Object.keys(pre), ...Object.keys(post)])) {
      if (!declared.has(k) && pre[k] !== post[k]) return false;
    }
    return true;
  },
};

/** The declared inverse, applied to post, must reproduce pre exactly (reversibility). */
export function mrInverseRestores(inverse: (post: Record<string, string>) => Record<string, string>): MetamorphicRelation {
  return {
    name: "inverse-restores-pre",
    check(pre, post) {
      const restored = inverse({ ...post });
      const keys = new Set([...Object.keys(pre), ...Object.keys(restored)]);
      for (const k of keys) if (pre[k] !== restored[k]) return false;
      return true;
    },
  };
}

export const defaultAcceptanceTest: AcceptanceTest = {
  relations: [mrWriteSetRespected, mrNoCollateralChange],
};
