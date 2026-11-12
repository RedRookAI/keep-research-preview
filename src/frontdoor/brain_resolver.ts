/** Resolve a reachable local model or a supplied model credential and record the selection. */

import type { Spine } from "../spine/spine.js";
import type { CryptoShredKeyStore, Ciphertext } from "../keystore/keystore.js";
import { type BrainDescriptor, brainFromKey, localBrain, checkCredentialShape } from "./brain_port.js";

/** Probe: does a local model runtime answer? Injected so it's testable offline. */
export interface LocalProbe {
  /** Returns the local base URL + a model name if a runtime is reachable, else null. */
  (): Promise<{ baseURL: string; model: string } | null>;
}

export type ResolveState = "using-local" | "using-key" | "need-key";

export interface ResolveOutcome {
  readonly state: ResolveState;
  /** The resolved brain, when state is using-local / using-key. */
  readonly brain?: BrainDescriptor;
  /** A plain-language message for the human (what happened / what to do). */
  readonly message: string;
}

const SUBJECT = "brain-credential"; // keystore subject for the AI credential

export class BrainResolver {
  /** The encrypted credential (ciphertext only; the key lives in the keystore). */
  private ciphertext: Ciphertext | undefined;

  constructor(
    private readonly spine: Spine,
    private readonly keystore: CryptoShredKeyStore,
    private readonly probeLocal: LocalProbe,
  ) {}

  /**
   * Resolve the brain with no key given yet: try local, else ask for a key.
   */
  async resolveDefault(): Promise<ResolveOutcome> {
    const local = await this.probeLocal();
    if (local) {
      const brain = localBrain(local.baseURL, local.model);
      this.recordChoice(brain);
      return {
        state: "using-local",
        brain,
        message: "I found a private model on this machine. Tell me what you'd like to work on. You can connect another model with your own AI key later.",
      };
    }
    return {
      state: "need-key",
      message: "Connect a model to get started. Paste your AI key, or install a local model to work offline.",
    };
  }

  /**
   * Resolve with a pasted key. Stores it crypto-shredded and records the choice.
   * Returns a friendly nudge (not an error) if the key doesn't look complete yet.
   */
  async resolveWithKey(rawKey: string, opts: { baseURL?: string; model?: string } = {}): Promise<ResolveOutcome> {
    const check = checkCredentialShape(rawKey);
    if (!check.ok) {
      return { state: "need-key", message: check.message };
    }
    const brain = brainFromKey(rawKey, opts);
    // Store the secret crypto-shredded: a per-subject key encrypts it; destroying
    // that key (shred) makes the credential unrecoverable.
    this.keystore.ensureKey(SUBJECT);
    this.ciphertext = this.keystore.encrypt(SUBJECT, brain.apiKey);
    this.recordChoice(brain);
    return {
      state: "using-key",
      brain,
      message: `You're connected to ${brain.providerLabel}. What would you like to work on?`,
    };
  }

  /** Retrieve the stored credential (e.g. to build the live provider adapter). */
  storedKey(): string | undefined {
    if (!this.ciphertext) return undefined;
    return this.keystore.decrypt(SUBJECT, this.ciphertext);
  }

  /** Forget the credential (crypto-shred): the key becomes unrecoverable. */
  forgetKey(): void {
    this.keystore.shred(SUBJECT);
    this.ciphertext = undefined;
    this.spine.stage({ type: "identity.action", actor: "frontdoor", payload: { event: "brain.credential_forgotten" } });
  }

  private recordChoice(brain: BrainDescriptor): void {
    this.spine.stage({
      type: "identity.action",
      actor: "frontdoor",
      payload: {
        event: "brain.selected",
        kind: brain.kind,
        provider: brain.providerLabel,
        baseURL: brain.baseURL,
        // NEVER log the key. Record only that one exists.
        hasKey: brain.apiKey.length > 0 && brain.apiKey !== "local",
        ...(brain.model !== undefined ? { model: brain.model } : {}),
      },
    });
  }
}
