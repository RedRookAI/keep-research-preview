/**
 * NESTED ORG POLICY over the personalization surfaces — Teams/Enterprise arc, T3. PBAC / policy-as-code.
 *
 * PBAC is policy evaluated at runtime, external to the surface modules; it composes with RBAC/ReBAC (T1). This
 * layer applies Ostrom's principle of NESTED GOVERNANCE / SUBSIDIARITY: enduring institutions coordinate across
 * layers — user ⊆ team ⊆ org — where the innermost layer decides WITHIN the constraints of the outer layers.
 *
 * `resolvePolicy(request, layers)` evaluates a requested personalization choice (a lens preset, a connector, an
 * anticipation/retention threshold) against the nest. The decision is the INTERSECTION / tightening down the nest:
 *   - an OUTER layer can FORBID a choice;
 *   - an INNER choice is honored only if permitted by EVERY layer;
 *   - an INNER layer CANNOT re-permit what an OUTER layer forbids (subsidiarity — the outer forbid stands);
 *   - thresholds TIGHTEN to the minimum across the layers.
 *
 * STANDING PRINCIPLE — one mechanism, graceful degradation, never collapse to N=1:
 *   - N=1 FLOOR: with NO org/team layers, the user's own choice is fully honored — the solo operator is
 *     unconstrained except by themselves (policy is the identity function).
 *   - org CEILING: an org adds constraints that TIGHTEN (can forbid a connector, cap autonomy) but NEVER remove
 *     the floor — a choice permitted by every layer is honored.
 *
 * BUILT + proven in-env: nesting / tightening / graceful degradation. SEAM: the org-directory / policy-authoring
 * source (where the layers come from).
 */

export type PolicySurface = "lens" | "connector" | "anticipation" | "memory";

/** A constraint a layer places on a surface: an allowlist and/or denylist of values, and/or a threshold cap. */
export interface PolicyConstraint {
  readonly surface: PolicySurface;
  readonly allow?: readonly string[] | undefined; // if present, ONLY these values are permitted for this surface
  readonly deny?: readonly string[] | undefined; // these values are forbidden
  readonly maxThreshold?: number | undefined; // an upper bound (anticipation threshold / retention days)
}

/** One layer of the nest (e.g. "user", "team", "org"). */
export interface PolicyLayer {
  readonly name: string;
  readonly constraints: readonly PolicyConstraint[];
}

export interface PolicyRequest {
  readonly surface: PolicySurface;
  readonly value?: string | undefined; // the requested lens/connector value
  readonly threshold?: number | undefined; // the requested anticipation/retention value
}

export interface PolicyDecision {
  readonly allow: boolean;
  /** The effective (possibly tightened) result honored after the nest. */
  readonly effective: { value?: string | undefined; threshold?: number | undefined };
  readonly reason: string;
  /** Which layer forbade (when denied), for the evidence trail. */
  readonly decidedBy?: string | undefined;
}

function constraintFor(layer: PolicyLayer, surface: PolicySurface): PolicyConstraint | undefined {
  return layer.constraints.find((c) => c.surface === surface);
}

/** Does this single layer permit the requested value? (a layer with no constraint for the surface permits.) */
function layerPermitsValue(c: PolicyConstraint | undefined, value: string): boolean {
  if (c === undefined) return true;
  if (c.deny !== undefined && c.deny.includes(value)) return false;
  if (c.allow !== undefined && !c.allow.includes(value)) return false;
  return true;
}

/**
 * Resolve a personalization request against the nested policy layers. Intersection / tightening: every layer must
 * permit; the outer forbid stands; thresholds tighten to the minimum. With no layers, the request is honored (the
 * N=1 floor).
 */
export function resolvePolicy(request: PolicyRequest, layers: readonly PolicyLayer[]): PolicyDecision {
  // VALUE surfaces (lens/connector): every layer must permit; an outer forbid cannot be re-permitted by an inner.
  if (request.value !== undefined) {
    for (const layer of layers) {
      if (!layerPermitsValue(constraintFor(layer, request.surface), request.value)) {
        return {
          allow: false,
          effective: {},
          reason: `'${request.value}' forbidden by layer '${layer.name}' on ${request.surface}`,
          decidedBy: layer.name,
        };
      }
    }
    return { allow: true, effective: { value: request.value }, reason: `permitted by every layer` };
  }

  // THRESHOLD surfaces (anticipation/memory): tighten to the minimum across the request and every layer.
  if (request.threshold !== undefined) {
    let effective = request.threshold;
    let tightestLayer: string | undefined;
    for (const layer of layers) {
      const c = constraintFor(layer, request.surface);
      if (c?.maxThreshold !== undefined && c.maxThreshold < effective) {
        effective = c.maxThreshold;
        tightestLayer = layer.name;
      }
    }
    return {
      allow: true,
      effective: { threshold: effective },
      reason: tightestLayer !== undefined ? `tightened to ${effective} by layer '${tightestLayer}'` : `honored at ${effective}`,
      ...(tightestLayer !== undefined ? { decidedBy: tightestLayer } : {}),
    };
  }

  // Nothing requested ⇒ nothing to constrain.
  return { allow: true, effective: {}, reason: "no value or threshold requested" };
}
