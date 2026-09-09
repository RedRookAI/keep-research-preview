/**
 * Effect provenance-gating (Finding 2.6) — treat an effect DERIVED FROM UNTRUSTED CONTENT as a
 * deny-capable input to the gate. Untrusted-derived ⇒ cannot auto-proceed; it must gate.
 *
 * A pure, total, MODEL-INDEPENDENT taint predicate. Provenance (where a value came from and whether
 * any input crossed the trust boundary) is a DECIDABLE STRUCTURAL FACT, not a judgment about the
 * content. The key lesson from the IFC-for-agents literature: unsafe behaviour arises from INFLUENCE,
 * not content — a web page is safe to summarise but unsafe if an embedded instruction decides a tool
 * argument. So we gate on ORIGIN, deterministically.
 *
 * RULES (research, 2026-08-08):
 *  - Conservative propagation (Sabelfeld & Myers 2003; FIDES): the label of an operation's output is
 *    the LEAST-TRUSTED label of its inputs. One untrusted input taints the whole effect.
 *  - Fail-safe on unknown (FIDES, "lowest integrity label by design"): a missing/unknown input trust,
 *    or no declared inputs at all, is treated as UNTRUSTED — you cannot show clean provenance, so you
 *    are treated as dirty (customs "declare at the border"; clean-vs-dirty zones).
 *  - Declassification requires AUTHORITY (P4Control t⁻ capability; "declassification is explicit, rare,
 *    named, logged — like sudo"): taint clears ONLY via an authorized declassification by a trusted
 *    principal. The agent/model CANNOT self-declassify — an unauthorized declassification is ignored.
 *    This reuses the raise-only discipline: an untrusted party's claim of "trusted" is dropped.
 *
 * SCOPE — BUILT vs SEAM: BUILT is this in-env predicate + the gate veto it feeds. The real
 * cross-process TAINT TRACER — the machinery that automatically labels every tool output, fetched
 * page, and external issue as untrusted and propagates the label through every transformation — is a
 * SEAM (it needs to intercept all data flows, which in-env we cannot). Here, labels are supplied by
 * the caller; the predicate is the trusted decision over them.
 *
 * WHAT WOULD CHANGE IT: a coarser or finer origin taxonomy, or an information-capacity policy (FIDES:
 * a 1-bit extraction from untrusted context may be allowed where an unconstrained string is not) —
 * both extend the input labels; neither makes the predicate clear taint without authority.
 */

export type TrustLabel = "trusted" | "untrusted";
export type ProvenanceVerdict = "trusted" | "untrusted-derived";

/** One input to an effect, with its origin's trust. `trust` undefined ⇒ unknown ⇒ untrusted (fail-safe). */
export interface InputProvenance {
  readonly source: string; // e.g. "repo", "operator", "tool:web_fetch", "issue:external"
  readonly trust?: TrustLabel;
}

/** An explicit declassification. Only an AUTHORIZED one (by a trusted principal) clears taint. */
export interface Declassification {
  readonly by: string;
  readonly reason: string;
  /** The capability check: was this an authorized trusted step? The agent cannot set this to true. */
  readonly authorized: boolean;
}

export interface EffectProvenance {
  readonly inputs: readonly InputProvenance[];
  readonly declassification?: Declassification;
}

export interface ProvenanceResult {
  readonly verdict: ProvenanceVerdict;
  readonly reasons: readonly string[];
}

/** True iff an input is positively trusted (a known "trusted" label). Unknown ⇒ not trusted. */
function inputIsTrusted(i: InputProvenance): boolean {
  return i.trust === "trusted";
}

/**
 * The predicate. Total + pure. `trusted` only if there is at least one input and EVERY input is
 * positively trusted; otherwise `untrusted-derived`, unless an AUTHORIZED declassification clears it.
 */
export function effectProvenance(p: EffectProvenance): ProvenanceResult {
  const reasons: string[] = [];

  if (p.inputs.length === 0) {
    // No declared provenance ⇒ cannot show clean origin ⇒ untrusted (fail-safe).
    reasons.push("no-provenance-declared");
  } else {
    for (const i of p.inputs) {
      if (!inputIsTrusted(i)) reasons.push(`untrusted-input:${i.source}:${i.trust ?? "unknown"}`);
    }
  }

  const taintedByInputs = reasons.length > 0;
  if (!taintedByInputs) {
    return { verdict: "trusted", reasons: ["all-inputs-trusted"] };
  }

  // Tainted. Only an AUTHORIZED declassification clears it — the agent cannot self-declassify.
  const d = p.declassification;
  if (d && d.authorized === true) {
    return { verdict: "trusted", reasons: [`declassified-by:${d.by}:${d.reason}`] };
  }
  if (d && d.authorized !== true) {
    reasons.push(`unauthorized-declassification-ignored:${d.by}`); // self-declassify attempt dropped
  }
  return { verdict: "untrusted-derived", reasons };
}
