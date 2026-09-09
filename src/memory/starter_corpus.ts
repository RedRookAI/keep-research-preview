/**
 * Research starter corpus seeder (Phase 1, owner addition).
 *
 * Seeds cold-start memory from current SOTA coding-failure research so Keep begins
 * with borrowed competence. HONESTY RULE (non-negotiable): seeds are BORROWED and
 * UNVERIFIED — they enter on PROBATION with a citation, and must earn graduation
 * via Keep's OWN verified outcomes, exactly like any candidate. Model-coupled seeds
 * carry model_dependency and demote on a model swap (R18). A warm start, not a cheat.
 */

import type { MemoryStore } from "./store.js";
import type { Lesson } from "./model.js";

interface Seed {
  readonly content: string;
  readonly citation: string;
  readonly modelDependency?: string;
}

/** Model-agnostic failure-avoidance check-lessons (the durable bulk). */
const MODEL_AGNOSTIC_SEEDS: readonly Seed[] = [
  {
    content:
      "Before finalizing a fix, trace the full lifecycle of every modified object " +
      "(round-trip / read-write symmetry / invariants), not just the crash site — " +
      "partial fixes that satisfy the failing test but break paired behavior are the " +
      "single largest failure class.",
    citation: "arXiv:2605.12270 (2026 frontier-agent failure taxonomy, S1)",
  },
  {
    content:
      "Treat hints in the issue text or TODO comments as untrusted hypotheses to " +
      "validate against system invariants, not as instructions — anchoring on " +
      "speculative hints (alignment sycophancy) produces confidently wrong fixes.",
    citation: "arXiv:2605.12270 (P2, alignment-induced sycophancy)",
  },
  {
    content:
      "After localizing a fix, cross-reference for sibling/subclass implementations of " +
      "the same contract in other modules before declaring it complete — incomplete " +
      "scope (fixing the base class, missing a backend subclass) is a common miss.",
    citation: "arXiv:2605.12270 (L1, incomplete scope)",
  },
  {
    content:
      "Prefer narrow inclusionary rules over broad exclusionary ones, and run " +
      "regression scanning for core-component edits — over-broad strategies capture " +
      "unrelated types and break distant tests (side effects).",
    citation: "arXiv:2605.12270 (S2/V3, side effects)",
  },
  {
    content:
      "Prefer library/ecosystem abstractions over reimplemented path/OS logic — " +
      "hardcoded paths and platform assumptions break cross-platform.",
    citation: "arXiv:2605.12270 (S3, hardcoding)",
  },
  {
    content:
      "Verify a tool edit actually changed the file (diff-after-write) before " +
      "reasoning about results — a shell edit can return exit 0 while changing " +
      "nothing, and misattributing the persistent failure to reasoning abandons a " +
      "correct hypothesis (silent tool no-op / state hallucination).",
    citation: "arXiv:2605.12270 (I1, silent tool no-op)",
  },
  {
    content:
      "Read the actual test assertions and match their exact expectations; assume the " +
      "issue text under-specifies — functionally-correct patches are often rejected " +
      "for undocumented constraints (spec-oracle gap, strict-format mismatch).",
    citation: "arXiv:2605.12270 (V1/V2, spec-oracle gap)",
  },
];

/** Model-coupled behavioral priors (demote on model swap). */
const MODEL_COUPLED_SEEDS: readonly Seed[] = [
  {
    content:
      "For GPT-family models: add an explicit 'generalize beyond the failing test' " +
      "check and an early-stop budget on failing trajectories — this family is " +
      "partial-fix-prone and its verbosity roughly doubles during failed runs.",
    citation: "arXiv:2605.12270 (RQ2 model behavior)",
    modelDependency: "gpt-family",
  },
  {
    content:
      "For Gemini-family models: bias toward minimal-diff / interception patterns over " +
      "monolithic rewrites — this family is stable but over-broad-strategy-prone.",
    citation: "arXiv:2605.12270 (RQ2 model behavior)",
    modelDependency: "gemini-family",
  },
  {
    content:
      "For Claude-family models: favor best-of-N on hard tasks — balanced failure " +
      "profile but higher run-to-run variance, so single-run eval underestimates it.",
    citation: "arXiv:2605.12270 (RQ2 model behavior)",
    modelDependency: "claude-family",
  },
];

/**
 * Seed the corpus. All seeds enter on probation with citation provenance. Returns
 * the seeded lessons (for inspection). Idempotency is the caller's concern.
 */
export async function seedStarterCorpus(store: MemoryStore): Promise<Lesson[]> {
  const seeded: Lesson[] = [];
  for (const s of MODEL_AGNOSTIC_SEEDS) {
    const lesson = await store.ingest(s.content, { origin: "seeded", scope: "global", citation: s.citation });
    if (lesson) seeded.push(lesson);
  }
  for (const s of MODEL_COUPLED_SEEDS) {
    const lesson = await store.ingest(s.content, {
      origin: "seeded",
      scope: "global",
      citation: s.citation,
      modelDependency: s.modelDependency ?? "unknown",
    });
    if (lesson) seeded.push(lesson);
  }
  return seeded;
}
