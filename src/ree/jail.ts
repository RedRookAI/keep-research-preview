/**
 * R27 fork-jail — the INTERFACE SEAM between the in-env envelope and an OS-enforced jail.
 *
 * The REE runs an untrusted op `execute(fork)` and commits only accepted writes. In-env the "fork" is
 * a separate object, so a COMPROMISED executor could bypass it (R27). In a real deployment the fork is
 * an OS JAIL: a confined child process with no ambient authority (Linux user/mount/net/pid namespaces
 * + seccomp-bpf syscall allowlist + Landlock path-level FS allowlist over an OverlayFS shadow), whose
 * ONLY egress to the real tree is a single commit channel captured by a trusted supervisor. A jail
 * breach (seccomp/landlock denial, non-zero exit, timeout) → the whole process group is SIGKILLed and
 * the attempt rolls back. See KEEP_R27_FORK_JAIL_DESIGN.md for the full kernel spec.
 *
 * This module is the CONTRACT both sides implement. BUILT here: the typed `Jail` interface, the
 * envelope-side contract logic (`jailedAttempt`), and an in-memory `StubJail` for conformance tests.
 * SEAM (R27): the real OS jail (`OsJail` in a deployment) that provides the kernel enforcement — the
 * sandbox cannot exercise kernel isolation, so we do NOT fake it; we pin the envelope-side contract
 * (breach ⇒ deny + no commit; captured writes are the SOLE egress) and leave enforcement to the kernel.
 *
 * WHAT WOULD CHANGE IT: a microVM (Firecracker) or user-mode kernel (gVisor) jail is a drop-in `Jail`
 * with a stronger boundary; a formally-verified microkernel (seL4) shrinks the residual kernel trust.
 * None of these change the contract: a breach never commits, and only captured writes reach the sink.
 */

import type { EnvelopeOp } from "./reversible_envelope.js";
import { InMemoryFileTree } from "../solve/patch.js";

export interface Write {
  readonly path: string;
  readonly content: string;
}

export interface JailRequest {
  /** The untrusted effect to run under confinement. */
  readonly op: EnvelopeOp;
  /** The pre-state the jail forks as its shadow (OverlayFS lowerdir, read-only to the executor). */
  readonly preState: Readonly<Record<string, string>>;
}

/**
 * The result of a confined run. `clean` carries the writes the supervisor CAPTURED from the shadow's
 * upper layer — these are the ONLY writes that may reach the real tree. `breach` means the jail
 * detected an escape attempt / policy violation / abnormal exit and killed the process group.
 */
export type JailResult =
  | { readonly status: "clean"; readonly writes: readonly Write[] }
  | { readonly status: "breach"; readonly reason: string };

/** The contract a real OS jail (or the in-memory stub) implements. */
export interface Jail {
  run(req: JailRequest): Promise<JailResult>;
}

/**
 * The envelope-side contract. Given a jail result and an acceptance predicate over the captured
 * writes, decide commit | rollback and route accepted writes through the SOLE egress (the commit
 * sink). A breach fails safe to rollback with NO commit. This is what `runReversibly` delegates to
 * when it runs under a jail; the kernel enforces that `writes` is the only thing that escaped.
 */
export interface JailedAttemptDeps {
  /** The SOLE egress: accepted writes are handed here (the mediated grant/membrane commit). */
  readonly commit: (writes: readonly Write[]) => Promise<void>;
  /** Necessary-relations acceptance over the captured writes. Reliable reject; weak accept. */
  readonly accept: (writes: readonly Write[]) => boolean;
}

export type JailedOutcome =
  | { readonly outcome: "committed"; readonly writes: readonly Write[] }
  | { readonly outcome: "rolled-back"; readonly reason: string };

/**
 * Run one confined attempt and enforce the envelope-side contract. Total: any breach, or a failed
 * acceptance, or a commit failure, yields rollback (fail-safe) with NO partial commit.
 */
export async function jailedAttempt(jail: Jail, req: JailRequest, deps: JailedAttemptDeps): Promise<JailedOutcome> {
  let result: JailResult;
  try {
    result = await jail.run(req);
  } catch (e) {
    return { outcome: "rolled-back", reason: `jail-run-threw:${(e as Error).message}` };
  }

  if (result.status === "breach") {
    // A breach never commits — the process group was killed, the shadow is discarded.
    return { outcome: "rolled-back", reason: `jail-breach:${result.reason}` };
  }

  // clean: the captured writes are the ONLY candidate egress. Gate them through acceptance.
  if (!deps.accept(result.writes)) {
    return { outcome: "rolled-back", reason: "acceptance-rejected" };
  }

  try {
    await deps.commit(result.writes); // the sole egress — mediated grant/membrane
  } catch (e) {
    return { outcome: "rolled-back", reason: `commit-failed:${(e as Error).message}` };
  }
  return { outcome: "committed", writes: result.writes };
}

/**
 * In-memory stub jail for conformance testing ONLY — it does NOT provide isolation. It runs the op on
 * a forked InMemoryFileTree and returns the diff as the captured writes, or a breach when configured.
 * A real deployment replaces this with an OsJail; the sandbox cannot exercise kernel isolation.
 */
export class StubJail implements Jail {
  constructor(private readonly opts: { readonly forceBreach?: string; readonly throwOnRun?: boolean } = {}) {}

  async run(req: JailRequest): Promise<JailResult> {
    if (this.opts.throwOnRun) throw new Error("stub-jail-crash");
    if (this.opts.forceBreach) return { status: "breach", reason: this.opts.forceBreach };
    const pre = { ...req.preState };
    const fork = new InMemoryFileTree(pre);
    try {
      await req.op.execute(fork);
    } catch (e) {
      // an executor crash inside the jail is a breach (abnormal exit → killed).
      return { status: "breach", reason: `executor-exit:${(e as Error).message}` };
    }
    const post = fork.snapshot();
    const writes: Write[] = [];
    for (const [path, content] of Object.entries(post)) {
      if (pre[path] !== content) writes.push({ path, content });
    }
    return { status: "clean", writes };
  }
}
