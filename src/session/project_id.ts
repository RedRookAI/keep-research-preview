/**
 * Project identity (Increment 3.5a) — the stable continuity key.
 *
 * SOTA basis (2026-08-04): "stable conversation/project IDs are the mechanism for
 * continuity, not model memory — skip them and you lose continuity even when memory
 * tools work perfectly" (OpenAI Agents SDK / editorialge 2026). So every project gets a
 * STABLE, OPAQUE id minted once at creation; everything the project owns (history,
 * memory namespace, corpus, secret scope, spine slice, checkpoint, budget) is keyed by it.
 *
 * The id is opaque (callers must not parse it) and collision-resistant. It doubles as the
 * CryptoShredKeyStore SubjectId for that project's per-project encryption key, so the
 * identity layer and the cryptographic-isolation layer share one key space by construction.
 *
 * Zero deps (node:crypto built-in).
 */

import { randomBytes } from "node:crypto";

/** A stable, opaque project identity. Do not parse; treat as a black-box handle. */
export type ProjectId = string & { readonly __brand: "ProjectId" };

/** Human-facing project name (mutable label); distinct from the immutable ProjectId. */
export interface ProjectName {
  readonly value: string;
}

const ID_PREFIX = "prj_";

/**
 * Mint a fresh, collision-resistant ProjectId. 16 random bytes = 128 bits of entropy,
 * hex-encoded, prefixed for readability in logs. Opaque by contract.
 */
export function mintProjectId(): ProjectId {
  return (ID_PREFIX + randomBytes(16).toString("hex")) as ProjectId;
}

/** Structural check that a string is a well-formed ProjectId (prefix + 32 hex chars). */
export function isProjectId(s: string): s is ProjectId {
  return typeof s === "string" && /^prj_[0-9a-f]{32}$/.test(s);
}

/**
 * Normalize/validate a caller-supplied id into a ProjectId, or throw. Used at trust
 * boundaries so a malformed or foreign id can never silently key into the wrong namespace.
 */
export function asProjectId(s: string): ProjectId {
  if (!isProjectId(s)) throw new Error(`not a valid ProjectId: ${JSON.stringify(s)}`);
  return s;
}
