/**
 * Live integration (Build Step 2 close-out) — route the reversible-execution path through the
 * composed chain: floor → composed gate → REE envelope (checkpoint → fork → budget → metamorphic
 * accept → commit | rollback). This is the strangler-fig cutover seam: the new path and the old
 * direct-apply path coexist behind a feature flag, exactly one runs (no double-write), and the flag
 * is the kill switch back to direct-apply.
 *
 * MEDIATION PRESERVED (R23/R24): when the envelope commits, the accepted writes are handed to a
 * commit sink that mints a per-write `WriteGrant` naming EXACTLY those writes and applies them
 * through the MEDIATED tree under `runMediatedWith`. So the integrated path writes only through the
 * membrane, and only the declared writes — the ocap discipline is not bypassed by the new flow.
 *
 * CONTRACT THE NEW PATH HONORS (strangler-fig equivalence): for an ACCEPTED op, the final tree state
 * equals what direct-apply would produce; on rejection/over-budget the tree is unchanged (the envelope's
 * atomic rollback). The new path is therefore equivalent-or-safer than direct-apply, never laxer.
 *
 * GROUNDING (research, 2026-08-08): Fowler strangler-fig / branch-by-abstraction — coexist behind one
 * routing layer, feature-flag the cutover, keep instant fallback; the #1 failure is shared/double writes,
 * so exactly one path commits. Shadow-write-then-validate (the fork + acceptance) before authoritative
 * commit. Staged commissioning — prove the new path green before retiring the old (the fallback stays
 * until the envelope path is proven in the live path over time).
 */

import type { FileTree } from "../solve/patch.js";
import { InMemoryFileTree } from "../solve/patch.js";
import { WriteGrant, runMediatedWith } from "../solve/mediated_tree.js";
import { structuralFloor, type FloorPolicy, type OpDescription } from "../floor/structural_floor.js";
import { composeGate, type GatePolicy, type GateInputs } from "../gate/composed_gate.js";
import { checkBudget, type BudgetPolicy, type ConsumptionRecord } from "../budget/budget_ledger.js";
import {
  runReversibly,
  type AcceptanceTest,
  type EnvelopeOp,
  type EnvelopeOutcome,
  type EnvelopeDeps,
} from "../ree/reversible_envelope.js";
import type { ActionTier } from "../control/action_tier.js";
import { digitalTwin } from "../twin/digital_twin.js";
import { recordBom, verifyBom, sha256Hex, type AiBom } from "../bom/ai_bom.js";
import { type AgentIdentity, IdentityRegistry } from "../identity/agent_identity.js";
import { emitDecisionAudit, InMemoryAuditSink, type AuditSink, type OtlpExporter } from "../audit/decision_audit.js";

/** A process-local default audit sink (local-first) when the caller wires none. */
const sharedAuditSink = new InMemoryAuditSink();
import type { Spine } from "../spine/spine.js";

/** A reversible edit intent: the op's structural description + how to apply it to a tree. */
export interface ReversibleIntent {
  readonly description: OpDescription;
  /** Apply the intended change to the given tree (a fork during the attempt, the mediated tree on fallback). */
  apply(tree: FileTree): Promise<void>;
  /** The reversibility class the pipeline assigns (feeds the gate). */
  readonly actionTier: ActionTier;
  /** Declared context consumption (fan-out, steps) the fork cannot observe. */
  readonly declaredConsumption?: ConsumptionRecord;
}

export interface IntegrationDeps {
  readonly spine: Spine;
  readonly actor: string;
  readonly operator: string;
  readonly sign: (payload: string) => string;
  /** The MEDIATED tree (membrane preserved). Reads build the pre-state; commits go through a grant. */
  readonly tree: FileTree;
  readonly ownerPresent: boolean;
  /** Feature guard: route through the envelope (true) or fall back to direct mediated apply (false). */
  readonly envelopeEnabled: boolean;
  /**
   * Optional acting agent identity + its registry (Core Addition C). When present, a killed/unknown/
   * forged identity is a deny-capable gate input (→ human-hold). Absent ⇒ not assessed.
   */
  readonly identity?: AgentIdentity;
  readonly identityRegistry?: IdentityRegistry;
  /** Optional local-first audit sink + best-effort OTLP exporter (Core Addition D). Observe-only. */
  readonly auditSink?: AuditSink;
  readonly otlpExporter?: OtlpExporter;
  /** Optional TCB-integrity result (Core Addition A). false ⇒ deny-capable gate veto. */
  readonly tcbIntact?: boolean;
  /** Optional caller-owned content/CAS precondition rechecked at the commit boundary. */
  readonly precommit?: () => Promise<string | undefined> | string | undefined;
  /** Exact pre-image for a required atomic compare-and-swap commit. */
  readonly expectedContent?: Readonly<Record<string, string>>;
}

export interface IntegrationPolicies {
  readonly floor: FloorPolicy;
  readonly gate: GatePolicy;
  readonly budget: BudgetPolicy;
  readonly acceptance: AcceptanceTest;
}

export type IntegrationResult =
  | { path: "human-hold"; reasons: readonly string[] }
  | { path: "envelope"; outcome: EnvelopeOutcome }
  | { path: "direct-apply-fallback"; applied: boolean };

/**
 * Compose the chain for one reversible intent. Floor → gate; a human-hold route returns WITHOUT
 * executing (the existing human path owns it). An auto-proceed route runs through the envelope
 * (or the direct-apply fallback when the feature is disabled).
 */
export async function executeReversibly(
  intent: ReversibleIntent,
  policies: IntegrationPolicies,
  deps: IntegrationDeps,
): Promise<IntegrationResult> {
  // 1) Floor verdict (structural, model-independent).
  const floorVerdict = structuralFloor(intent.description, policies.floor);

  // 2) Estimate consumption for the gate's budget input (declared context + declared write-set size).
  const declaredWrites = intent.description.writeSet ?? [];
  const estimate: ConsumptionRecord = {
    edits: declaredWrites.length,
    filesTouched: new Set(declaredWrites).size,
    bytesWritten: 0, // pre-execution estimate; the envelope re-checks ACTUAL bytes before commit
    fanOut: intent.declaredConsumption?.fanOut ?? 0,
    steps: intent.declaredConsumption?.steps ?? 1,
  };
  const budgetVerdict = checkBudget(estimate, policies.budget);

  // Digital twin (layer 6): preview the op's ACTUAL effect on a throwaway shadow and compare it to
  // the DECLARED write-set/sinks. A mismatch (the op does more than it said) is a deny-capable gate
  // input — computed model-independently from the op's real behavior, before any real execution.
  const twinPre: Record<string, string> = {};
  for (const path of declaredWrites) {
    const cur = await deps.tree.read(path);
    if (cur !== undefined) twinPre[path] = cur;
  }
  const twinVerdict = await digitalTwin({ description: intent.description, preState: twinPre, execute: (t) => intent.apply(t) });

  // AI-BOM (Core Addition B): assemble a manifest of this decision's real inputs (barrier verdicts +
  // effect declaration), record its digest to the spine (tamper-evident), and self-verify. An
  // unverifiable BOM is a deny-capable gate input. Recording never loosens anything.
  const bom: AiBom = {
    subject: `reversible:${(intent.description.writeSet ?? []).join(",")}`,
    toolSet: [intent.description.kind],
    barriers: {
      floor: floorVerdict.verdict,
      budget: budgetVerdict.verdict,
      actionTier: intent.actionTier,
      ownerPresent: deps.ownerPresent,
      twin: twinVerdict.verdict,
    },
    codeHash: sha256Hex(intent.description.raw ?? ""),
    timestamp: Date.now(),
  };
  const recorded = recordBom(deps.spine, bom, deps.actor);
  const bomVerified = verifyBom(bom, recorded.digest).verified;

  // Per-agent identity (Core Addition C): if an acting identity + registry are supplied, a
  // killed/unknown/forged identity fails safe to a deny-capable gate input.
  const identityLive = deps.identityRegistry && deps.identity
    ? deps.identityRegistry.authorize(deps.identity).authorized
    : undefined;

  // 3) Compose the gate.
  const gateInputs: GateInputs = {
    floor: floorVerdict.verdict,
    budget: budgetVerdict.verdict,
    actionTier: intent.actionTier,
    ownerPresent: deps.ownerPresent,
    twin: twinVerdict.verdict,
    bomVerified,
    identityLive,
    tcbIntact: deps.tcbIntact,
  };
  const route = composeGate(gateInputs, policies.gate);

  // ROUND 38 — carry the FLOOR's rationale into the reported reasons.
  //
  // `composeGate` only receives the floor's VERDICT, so it can only ever say "floor-gate". The
  // floor knows far more — which path was out of scope, which protected matcher fired — and
  // that detail was being discarded at this boundary. An operator was told "held for human
  // review: floor-gate" and left to guess the file.
  //
  // Same shape as round 34's Z133, one layer deeper: the reason existed and was dropped in
  // transit. Each layer keeps its own rationale; they are joined HERE, where the report is
  // actually produced, rather than by widening the gate's input type to carry another layer's
  // explanations.
  const reportedReasons = floorVerdict.verdict === "reversible-execute"
    ? route.reasons
    : [...route.reasons, ...floorVerdict.reasons];

  // Local-audit + OTLP (Core Addition D): derive a faithful, structured audit record from THIS gate
  // decision (barriers + route + reasons), write it to a local-first sink, and best-effort export.
  // Observe-only — it never alters the route. The OTLP collector endpoint is a SEAM.
  // The audit record gets the SAME enriched reasons the caller is given — a record that says
  // less than the message the operator saw would be the worse of the two artifacts to trust.
  emitDecisionAudit(gateInputs, { ...route, reasons: reportedReasons }, deps.auditSink ?? sharedAuditSink, deps.otlpExporter);

  if (route.route === "human-hold") {
    return { path: "human-hold", reasons: reportedReasons }; // do NOT execute — the human path owns it
  }

  // 4) Auto-proceed. Feature-guarded fallback: direct mediated apply (the old path), unchanged.
  if (!deps.envelopeEnabled) {
    await applyThroughMediatedTree(intent, deps);
    return { path: "direct-apply-fallback", applied: true };
  }

  // 5) Route through the envelope. Pre-state = current content of the declared write-set (read
  //    through the membrane). The commit sink writes the accepted result through the grant.
  const preFiles: Record<string, string> = {};
  for (const path of declaredWrites) {
    const cur = await deps.tree.read(path);
    if (cur !== undefined) preFiles[path] = cur;
  }
  const preCarrier = new InMemoryFileTree(preFiles); // pre-state + fork source (has snapshot())

  const envelopeOp: EnvelopeOp = { description: intent.description, execute: (fork) => intent.apply(fork) };
  const envelopeDeps: EnvelopeDeps = {
    spine: deps.spine,
    actor: deps.actor,
    operator: deps.operator,
    sign: deps.sign,
    budget: { policy: policies.budget, ...(intent.declaredConsumption ? { declared: intent.declaredConsumption } : {}) },
    // ROUND 36: re-ask the identity question at the last moment before any write. Supplied ONLY
    // when an identity was supplied — a caller who passes nothing still gets no precommit hook at
    // all, so the "not assessed (no veto)" contract is byte-for-byte unchanged for them.
    ...((deps.identityRegistry && deps.identity) || deps.precommit
      ? {
          precommit: async (): Promise<string | undefined> => {
            if (deps.identityRegistry && deps.identity) {
              const live = deps.identityRegistry.authorize(deps.identity);
              if (!live.authorized) return `identity-revoked-before-commit:${live.reason}`;
            }
            return deps.precommit?.();
          },
        }
      : {}),
    commit: async (writes) => {
      // R23/R24: commit ONLY through the membrane, ONLY the declared writes, under a per-write grant.
      const grant = new WriteGrant(writes.map((w) => ({ path: w.path, content: w.content })));
      if (deps.expectedContent !== undefined) {
        if (!deps.tree.commitBatchIfUnchanged) throw new Error("content-bound commit requires atomic batch compare-and-swap support");
        const committed = await runMediatedWith(grant, () => deps.tree.commitBatchIfUnchanged!(deps.expectedContent!, writes));
        if (!committed) throw new Error("content-bound commit refused because repository bytes changed");
        return;
      }
      const attempted: string[] = [];
      try {
        await runMediatedWith(grant, async () => {
          for (const w of writes) { attempted.push(w.path); await deps.tree.write(w.path, w.content); }
        });
      } catch (writeError) {
        const restores = attempted.reverse().filter((path) => preFiles[path] !== undefined).map((path) => ({ path, content: preFiles[path]! }));
        try {
          const restoreGrant = new WriteGrant(restores);
          await runMediatedWith(restoreGrant, async () => {
            for (const restore of restores) await deps.tree.write(restore.path, restore.content);
          });
        } catch (restoreError) {
          throw new AggregateError([writeError, restoreError], "envelope commit failed and restoration also failed");
        }
        throw writeError;
      }
    },
  };
  const outcome = await runReversibly(envelopeOp, floorVerdict, preCarrier, policies.acceptance, envelopeDeps);
  return { path: "envelope", outcome };
}

/** The direct-apply fallback (old path): apply through the mediated tree under a grant. */
async function applyThroughMediatedTree(intent: ReversibleIntent, deps: IntegrationDeps): Promise<void> {
  // Read pre-state, apply to a scratch tree to learn the resulting writes, then commit through a grant.
  const declaredWrites = intent.description.writeSet ?? [];
  const preFiles: Record<string, string> = {};
  for (const path of declaredWrites) {
    const cur = await deps.tree.read(path);
    if (cur !== undefined) preFiles[path] = cur;
  }
  const scratch = new InMemoryFileTree(preFiles);
  await intent.apply(scratch);
  const post = scratch.snapshot();
  const writes = Object.keys(post)
    .filter((p) => preFiles[p] !== post[p])
    .map((p) => ({ path: p, content: post[p] }))
    .filter((w): w is { path: string; content: string } => w.content !== undefined);
  const grant = new WriteGrant(writes.map((w) => ({ path: w.path, content: w.content })));
  await runMediatedWith(grant, async () => {
    for (const w of writes) await deps.tree.write(w.path, w.content);
  });
}
