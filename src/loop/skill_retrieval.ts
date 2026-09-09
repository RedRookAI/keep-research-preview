/**
 * SkillRetrieval (Increment 18.7, Phase D) — given a task, select and compose the RIGHT skills from the
 * self-built library. This is what makes the validated+graduated skill library USABLE on new tasks.
 *
 * THE failure mode this defends against (SOTA, 2026-08-05): skill selection exhibits a PHASE TRANSITION —
 * "accuracy remains stable up to a critical library size, then drops SHARPLY" (When Single-Agent with Skills
 * arXiv 2601.04748), driven by SKILL SHADOWING (semantically similar skills competing for selection —
 * "More Skills, Worse Agents" 2605.24050), NOT raw count alone. The mitigations the literature converges on:
 *  - RETRIEVE-THEN-RERANK with a BOUNDED top-k — never expose the whole library (SkillFlow; SRA 2604.24594).
 *  - The skill BODY/envelope is the decisive routing signal, not just the name (SkillRouter 2603.22455:
 *    removing body text costs 31-44pp; Task-Decomposition Reranking 2607.06283).
 *  - The admission gate must EXCLUDE demoted/drifted skills (Dynamic Agent Skills 2607.10113: "a skill can be
 *    syntactically valid while operationally wrong — demote skills whose verifier has drifted").
 *
 * Keep's zero-dep realization (no embedding model — front/back-of-house identical): retrieve by relevance-key
 * + STRUCTURED precondition match (the envelope, deterministic), filter to LIVE-and-not-rolled-back (canary
 * state), rerank by (graduated > canary) then reuse-utility (consolidation), return a BOUNDED top-k that keeps
 * the offered set structurally BELOW the phase-transition threshold. Zero runtime deps; state behind ports.
 */

import type { DistilledSkill } from "./skill_distiller.js";

/** The canary state a skill is in (from 18.6). Only live states are retrievable. */
export type SkillLiveState = "canary" | "graduated" | "rolled-back" | "unknown";

/** Ports over the live subsystems — so retrieval reads real canary + consolidation state without coupling. */
export interface SkillStateProvider {
  /** The canary lifecycle state of a skill (graduated/canary/rolled-back). */
  liveState(skillId: string): SkillLiveState;
  /** The consolidation utility of a skill (recency+frequency+reuse-utility); higher = more useful. */
  utility(skillId: string): number;
}

export interface TaskQuery {
  readonly taskShape: string;
  /** Optional facts about the task that can satisfy/violate a skill's preconditions. */
  readonly facts?: readonly string[];
}

export interface RetrievedSkill {
  readonly skill: DistilledSkill;
  readonly state: SkillLiveState;
  readonly utility: number;
  readonly score: number; // rerank score (higher first)
}

export interface RetrievalConfig {
  /** Bounded top-k — the offered set size. Default 3; hard cap 5 (below the skill-shadowing phase transition). */
  readonly topK?: number;
  readonly state: SkillStateProvider;
}

/** Hard cap on the offered set — structurally below the phase-transition threshold regardless of config. */
export const RETRIEVAL_HARD_CAP = 5;

export class SkillRetrieval {
  private readonly skills = new Map<string, DistilledSkill>();
  private readonly topK: number;
  private readonly state: SkillStateProvider;

  constructor(config: RetrievalConfig) {
    this.topK = Math.min(Math.max(1, config.topK ?? 3), RETRIEVAL_HARD_CAP);
    this.state = config.state;
  }

  /** Add a skill to the library (idempotent by id). */
  add(skill: DistilledSkill): void {
    this.skills.set(skill.id, skill);
  }

  /**
   * Retrieve the right skills for a task: FILTER (relevant + preconditions satisfiable + LIVE, not rolled-back)
   * → RERANK (graduated > canary, then utility, then corroborated > low) → BOUNDED top-k. A rolled-back or
   * unknown-state skill is NEVER offered (admission gate). Deterministic, zero-dep.
   */
  retrieve(query: TaskQuery): readonly RetrievedSkill[] {
    const facts = new Set(query.facts ?? []);
    const candidates: RetrievedSkill[] = [];

    for (const skill of this.skills.values()) {
      // 1. Relevance: the skill's relevance key must match the task shape.
      if (skill.relevanceKey !== query.taskShape) continue;
      // 2. Admission gate: only LIVE skills (canary/graduated) — a rolled-back/unknown skill is excluded.
      const state = this.state.liveState(skill.id);
      if (state !== "canary" && state !== "graduated") continue;
      // 3. Precondition match: any "does not apply when: X" guard whose X is a task fact EXCLUDES the skill.
      if (this.violatesPreconditions(skill, facts)) continue;

      const utility = this.state.utility(skill.id);
      candidates.push({ skill, state, utility, score: this.score(skill, state, utility) });
    }

    // RERANK by score desc, then return the BOUNDED top-k (structural anti-shadowing).
    candidates.sort((a, b) => b.score - a.score);
    return candidates.slice(0, this.topK);
  }

  /**
   * Compose the retrieved skills into a single guidance bundle (the envelopes, ordered by score). Composition
   * is the union of steps with provenance — the caller applies them; Keep never auto-executes without the
   * normal pipeline gates. Empty if nothing was retrieved.
   */
  compose(query: TaskQuery): { readonly skills: readonly string[]; readonly steps: readonly string[] } {
    const retrieved = this.retrieve(query);
    const steps: string[] = [];
    for (const r of retrieved) {
      for (const s of r.skill.envelope.steps) steps.push(`${s.action} ${s.targetPattern}`);
    }
    return { skills: retrieved.map((r) => r.skill.id), steps };
  }

  /** A skill is excluded if any precondition guard "does not apply when: X" matches a task fact. */
  private violatesPreconditions(skill: DistilledSkill, facts: ReadonlySet<string>): boolean {
    for (const pre of skill.envelope.preconditions) {
      const m = pre.match(/^does not apply when:\s*(.+)$/);
      if (m && facts.has(m[1]!.trim())) return true;
    }
    return false;
  }

  /** Rerank score: graduated outranks canary; then utility; then corroborated outranks low-confidence. */
  private score(skill: DistilledSkill, state: SkillLiveState, utility: number): number {
    const stateWeight = state === "graduated" ? 100 : 10; // graduated strongly preferred
    const confidenceWeight = skill.confidence === "corroborated" ? 5 : 0;
    return stateWeight + utility + confidenceWeight;
  }

  get librarySize(): number { return this.skills.size; }
}
