/**
 * F0 — Brain resolver. The onboarding flow you specified, exactly:
 *
 *   1. Default to LOCAL.
 *   2. PROBE for a real local runtime (Ollama/llama.cpp).
 *   3. If a local model is present -> use it (private, offline, works immediately).
 *   4. If NOT present -> do NOT dead-end. Return a friendly request for a key.
 *   5. If the human gives a key -> use it.
 *
 * The credential is stored crypto-shredded (Phase 0 keystore); the brain choice is
 * recorded to the spine with the key REDACTED. Messages are jargon-free.
 */

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
        message: "You're all set — I found a private model already running on this machine, so we can start right now with nothing to pay and nothing leaving your computer. You can add your own AI key any time to unlock more powerful models.",
      };
    }
    return {
      state: "need-key",
      message: "I couldn't find a private model on this machine yet, so let's hook up the AI of your choice. Paste your AI key (from Anthropic, OpenAI, OpenRouter, Google, Groq, NVIDIA, or others) and we'll get going. If you'd rather run fully offline, you can install a local model later and I'll pick it up automatically.",
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
      message: `You're connected to ${brain.providerLabel}. We're ready — tell me what you're working on and I'll take it from here.`,
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
