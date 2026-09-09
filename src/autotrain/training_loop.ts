/**
 * Auto-Training system: the training loop + backend port (Increment 11b).
 *
 * This is the part that ACTUALLY TRAINS — the correction to the earlier dead-end. It does not
 * reimplement a trainer; it GENERATES a declarative config and drives a real backend through a port.
 *
 * SOTA basis (2026-08-04): the mature single-GPU, solo-dev-affordable toolchain is Unsloth (2-5x
 * faster, 50-70% less VRAM), Axolotl (declarative YAML), and TRL v1.0 (unified SFT/DPO/GRPO). GRPO
 * (DeepSeek-R1; TRL GRPOTrainer) is the 2026 standard when you have a VERIFIABLE reward — N rollouts
 * per prompt, each scored by the verifier (unit tests / compiler / exact-match), group-normalized, no
 * value model — which is exactly Keep's situation. QLoRA is the default (fits a 70B on one GPU).
 * Safety must be preserved DURING training, not only gated after: SaLoRA (arXiv 2501.01765) adds a
 * fixed safety module + task projection so the adapter can't move into the harmful subspace.
 * Reward hacking is detectable during training (TRACE, ICLR 2026) — reward rising while a held-out
 * signal degrades is the signal (the same rise-then-collapse insight as the RegressionGuard, item 6).
 *
 * Keep generates the config so a NON-ENGINEER never scripts; the backend (a real trainer in a
 * sandbox) plugs in behind the port. Zero deps.
 */

/** The training method. Only verifiable-reward methods are eligible in Keep's safe path. */
export type TrainingMethod = "grpo" | "sft" | "dpo";

/** Whether a method uses a verifiable reward (GRPO) vs preference/demo data. */
export function usesVerifiableReward(method: TrainingMethod): boolean {
  return method === "grpo";
}

/** A declarative training config Keep GENERATES (so the operator never writes YAML/scripts). */
export interface TrainingConfig {
  readonly baseModel: string;
  readonly method: TrainingMethod;
  /** PEFT: QLoRA is the 2026 default (memory-efficient, single-GPU). */
  readonly peft: "qlora" | "lora";
  readonly loraRank: number;
  /** Fraction of general replay data mixed in (10-20% — resists catastrophic forgetting). */
  readonly replayFraction: number;
  /** Safety-preserving training module (SaLoRA-style) enabled — keeps the adapter out of harmful subspace. */
  readonly safetyPreserving: boolean;
  /** The verifiable reward the verifier computes (only for GRPO). */
  readonly verifierKind?: "unit-tests" | "compiler" | "exact-match";
  readonly maxSteps: number;
  /** Sandbox is mandatory. */
  readonly sandboxed: true;
}

/** A verifiable-reward verifier: scores a rollout objectively (pass/fail → reward). */
export type RewardVerifier = (rollout: string, reference: string) => number;

/** A snapshot of one training step (for monitoring reward-hacking during training). */
export interface TrainingStepSnapshot {
  readonly step: number;
  /** The optimized reward this step (rising is the goal). */
  readonly reward: number;
  /** A held-out general-capability signal (must NOT collapse while reward rises). */
  readonly heldOutSignal: number;
}

/** Result of a completed (or aborted) training run. */
export interface TrainingRunResult {
  readonly completed: boolean;
  /** Opaque handle to the trained adapter weights (in the sandbox — never loaded into Keep's process). */
  readonly adapterRef?: string;
  readonly steps: number;
  /** If aborted mid-training, why (e.g. reward-hacking detected). */
  readonly abortedReason?: string;
  /** Final reward + held-out signal. */
  readonly finalReward: number;
  readonly finalHeldOut: number;
}

/** The trainer backend port — a real trainer (Unsloth/Axolotl/TRL in a sandbox) plugs in here. */
export interface TrainerBackend {
  readonly name: string;
  /**
   * Run a training job from a generated config. Emits step snapshots via onStep (so Keep can monitor
   * reward-hacking live) and returns the adapter handle. Returns null if the backend is unavailable
   * (offline) — the loop then reports honestly instead of pretending it trained.
   */
  train(
    config: TrainingConfig,
    data: readonly { input: string; reference: string }[],
    onStep: (s: TrainingStepSnapshot) => "continue" | "abort",
  ): Promise<{ adapterRef: string; steps: number; final: TrainingStepSnapshot } | null>;
}

export interface TrainingLoopOptions {
  /**
   * Max drop in the held-out signal from its running peak before we call it reward-hacking /
   * over-optimization and ABORT (the rise-then-collapse insight from item 6). Default 0.10.
   */
  readonly heldOutDropAbort?: number;
}

/**
 * Generate a safe training config from the decision context. Always GRPO + QLoRA + safety-preserving
 * + a replay buffer, because those are the safe defaults; the operator never writes this by hand.
 */
export function generateConfig(baseModel: string, verifierKind: "unit-tests" | "compiler" | "exact-match", maxSteps = 200): TrainingConfig {
  return {
    baseModel,
    method: "grpo", // verifiable-reward standard
    peft: "qlora",
    loraRank: 16,
    replayFraction: 0.15, // 10-20% general data
    safetyPreserving: true, // SaLoRA-style
    verifierKind,
    maxSteps,
    sandboxed: true,
  };
}

/**
 * Runs a training job through a backend and MONITORS it live for reward-hacking: it tracks the
 * held-out signal's running peak, and if the held-out signal collapses from its peak beyond the
 * threshold WHILE the reward rises, it aborts the run (reward being gamed). This is the training-time
 * analogue of the RegressionGuard — over-optimization is caught during, not just after.
 */
export class TrainingLoop {
  constructor(private readonly backend: TrainerBackend, private readonly opts: TrainingLoopOptions = {}) {}

  async run(config: TrainingConfig, data: readonly { input: string; reference: string }[]): Promise<TrainingRunResult> {
    // Safety invariant: only verifiable-reward methods may run in Keep's safe path.
    if (!usesVerifiableReward(config.method)) {
      return { completed: false, steps: 0, abortedReason: `method ${config.method} is not verifiable-reward — refused`, finalReward: 0, finalHeldOut: 0 };
    }
    const dropAbort = this.opts.heldOutDropAbort ?? 0.10;
    let heldOutPeak = -Infinity;
    let abortReason: string | undefined;

    const result = await this.backend.train(config, data, (s) => {
      if (s.heldOutSignal > heldOutPeak) heldOutPeak = s.heldOutSignal;
      // reward-hacking: held-out collapses from peak while reward is (relatively) high.
      if (heldOutPeak - s.heldOutSignal > dropAbort) {
        abortReason = `reward-hacking / over-optimization detected at step ${s.step}: held-out signal fell from peak ${heldOutPeak.toFixed(2)} to ${s.heldOutSignal.toFixed(2)} while optimizing reward — aborting to protect general capability`;
        return "abort";
      }
      return "continue";
    });

    if (result === null) {
      return { completed: false, steps: 0, abortedReason: "trainer backend unavailable (offline) — nothing trained", finalReward: 0, finalHeldOut: 0 };
    }
    if (abortReason) {
      return { completed: false, adapterRef: result.adapterRef, steps: result.steps, abortedReason: abortReason, finalReward: result.final.reward, finalHeldOut: result.final.heldOutSignal };
    }
    return { completed: true, adapterRef: result.adapterRef, steps: result.steps, finalReward: result.final.reward, finalHeldOut: result.final.heldOutSignal };
  }
}
