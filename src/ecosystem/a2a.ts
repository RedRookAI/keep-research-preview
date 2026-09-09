/**
 * A2A + signed Agent Cards (Phase 6, #47 bring-your-own-agent).
 *
 * Built to the A2A v1.0.x model (Linux Foundation): an Agent Card (a signed JSON
 * "business card" at /.well-known/agent-card.json) advertises an agent's skills;
 * transport is JSON-RPC/HTTP with an async task lifecycle. Keep is the STAR hub —
 * external agents delegate/receive THROUGH Keep, not peer-to-peer (avoids N^2).
 *
 * BYOA agents are HOSTILE/untrusted (port-security): scoped identity (Phase 0), NO
 * internal memory shared. The signed Agent Card is the hostile-intake gate — an
 * unsigned or invalid card cannot be promoted past untrusted.
 *
 * Trajectory caveat (Round 2): a BYOA agent runs OUTSIDE Keep's instrumentation, so
 * its internal steps are not in Keep's learning loop — only its task-level OUTCOMES
 * are captured (objective-anchored, like any external signal).
 */

import { createHmac } from "node:crypto";
import { boundedCapabilityOutput, type CapabilityAdapter, type CapabilityDescriptor, type CapabilityInvocation, type CapabilityResult, type CapabilityTrust } from "./capability_port.js";
import { canonicalize } from "../spine/event.js";

export const A2A_PROTOCOL_VERSION = "1.0.1";

export interface AgentCard {
  readonly name: string;
  readonly description: string;
  readonly protocolVersion: string;
  /** Skills the agent advertises (A2A capability discovery). */
  readonly skills: readonly string[];
  /** The well-known path the card is served from. */
  readonly url: string;
}

export interface SignedAgentCard {
  readonly card: AgentCard;
  readonly signature: string;
  /** Key id identifying which issuer key signed it. */
  readonly keyId: string;
}

/** Sign an Agent Card (issuer side). Keep verifies with the issuer's key. */
export function signAgentCard(card: AgentCard, keyId: string, key: Buffer): SignedAgentCard {
  const signature = createHmac("sha256", key).update(canonicalize(card), "utf8").digest("hex");
  return { card, signature, keyId };
}

/** Verify a signed Agent Card against a known issuer key. The hostile-intake gate. */
export function verifyAgentCard(signed: SignedAgentCard, key: Buffer): boolean {
  const expected = createHmac("sha256", key).update(canonicalize(signed.card), "utf8").digest("hex");
  if (expected.length !== signed.signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signed.signature.charCodeAt(i);
  return diff === 0;
}

/** The async task lifecycle states (A2A). Terminal states are final. */
export type A2ATaskState = "submitted" | "working" | "input-required" | "completed" | "failed" | "canceled";
export const TERMINAL_STATES: ReadonlySet<A2ATaskState> = new Set(["completed", "failed", "canceled"]);

/** An injected A2A transport (JSON-RPC/HTTP). A real A2A SDK plugs in behind this. */
export interface A2ATransport {
  sendTask(skill: string, args: Record<string, unknown>): Promise<{ state: A2ATaskState; output?: unknown; error?: string }>;
}

/** Keep-as-CLIENT of a BYOA agent: a hostile capability adapter identified by a signed card. */
export class A2AAgentAdapter implements CapabilityAdapter {
  readonly descriptor: CapabilityDescriptor;
  private readonly signed: SignedAgentCard;
  private intakeVerified = false;

  constructor(
    id: string,
    signed: SignedAgentCard,
    credentialId: string,
    private readonly transport: A2ATransport,
    /** Trust starts untrusted; promoted to verified only after card verification. */
    trust: CapabilityTrust = "untrusted",
    private readonly maxResultBytes = 1024 * 1024,
  ) {
    this.signed = Object.freeze({ ...signed, card: Object.freeze({ ...signed.card, skills: Object.freeze([...signed.card.skills]) }) });
    this.descriptor = { id, kind: "a2a-agent", name: signed.card.name, credentialId, trust };
  }

  /**
   * Verify the Agent Card + protocol version. Only a valid signature permits
   * promotion to "verified"; otherwise the agent stays untrusted (may still be used
   * for non-authority-bearing work, but never trusted).
   */
  verifyIntake(issuerKey: Buffer): { verified: boolean; reason: string } {
    if (this.signed.card.protocolVersion.split(".")[0] !== A2A_PROTOCOL_VERSION.split(".")[0]) {
      this.intakeVerified = false;
      return { verified: false, reason: `A2A major version mismatch: card ${this.signed.card.protocolVersion} vs Keep ${A2A_PROTOCOL_VERSION}` };
    }
    if (!verifyAgentCard(this.signed, issuerKey)) {
      this.intakeVerified = false;
      return { verified: false, reason: "Agent Card signature invalid — stays untrusted" };
    }
    this.intakeVerified = true;
    return { verified: true, reason: "Agent Card verified (signature + version)" };
  }

  get advertisedSkills(): readonly string[] {
    return this.signed.card.skills;
  }

  async invoke(inv: CapabilityInvocation): Promise<CapabilityResult> {
    if (!this.intakeVerified) return { ok: false, error: "A2A Agent Card has not passed signature and version verification" };
    if (!this.signed.card.skills.includes(inv.operation)) return { ok: false, error: `skill "${inv.operation}" is not pinned by the signed Agent Card` };
    // BYOA runs outside Keep's instrumentation: only the task-level outcome returns,
    // never internal trajectory. That is the trajectory caveat, enforced by shape.
    const res = await this.transport.sendTask(inv.operation, inv.args as Record<string, unknown>);
    if (TERMINAL_STATES.has(res.state) && res.state === "completed") {
      try { return { ok: true, output: boundedCapabilityOutput(res.output, this.maxResultBytes) }; }
      catch (error) { return { ok: false, error: (error as Error).message }; }
    }
    if (res.state === "failed") return { ok: false, error: res.error ?? "task failed" };
    // Non-terminal (working/input-required) — surfaced as not-yet-complete.
    return { ok: false, error: `task not complete (state=${res.state})` };
  }
}
