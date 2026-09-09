/**
 * FeasibilityCheck — intake scope-of-competence classification.
 *
 * The gap a stress-test exposed: asked to "build a drone that carries 10x its weight,"
 * the system charged ahead as if it could — when Keep produces software, documents, and
 * analysis, not physical hardware. Per 2026 SOTA (arXiv 2605.28532 "Do Agents Know What
 * They Can't Do?"; Mirsky's L3 autonomy — "recognize when a situation exceeds competence
 * and proactively transfer control"), the fix is EARLY feasibility detection + honest
 * reframing, not "false continuation." Overpromising is the #1 trust-killer.
 *
 * This runs at the loop's `understand` stage so expectations are set before work begins.
 * It classifies WHAT Keep can actually deliver, reframes the project into the deliverable
 * part + the human-owned part, and flags sensitivity (dual-use / regulated / public).
 * Deterministic heuristics with an injected LLM seam for nuance; honest fallback.
 */

export type DeliverabilityClass =
  | "fully-deliverable" // software/docs/analysis Keep produces end-to-end
  | "assist-only" // physical/real-world action Keep can research+design+spec but not execute
  | "needs-account" // ongoing external-account operation; Keep drafts, but acting is gated
  | "out-of-scope"; // Keep can't meaningfully help

export type Sensitivity = "none" | "public-facing" | "regulated" | "dual-use";

export interface FeasibilityReport {
  readonly deliverability: DeliverabilityClass;
  readonly sensitivity: Sensitivity;
  /** What Keep can actually produce for this goal (honest, concrete). */
  readonly canDeliver: string;
  /** What stays with the human (physical action, approvals, real-world execution). */
  readonly humanOwns?: string;
  /** The honest, expectation-setting message shown at intake. */
  readonly framing: string;
  /** Whether the project should proceed into the loop as-is, or pause for a reframe first. */
  readonly proceed: boolean;
}

/** Optional injected LLM classifier for nuance (returns null if unavailable/uncertain). */
export interface FeasibilityClassifier {
  (goal: string): Promise<{ deliverability: DeliverabilityClass; sensitivity: Sensitivity } | null>;
}

// --- Deterministic signal lexicons (the honest floor; the LLM seam refines) ---

/** Physical/real-world construction or action Keep cannot execute (only assist). */
const PHYSICAL_RX =
  /\b(build|construct|assemble|fabricate|manufacture|3d[- ]?print|solder|wire up|fly|drive|grow|plant|cook|bake|install (a|the|my) (physical|hardware)|drone|robot|vehicle|circuit|hardware|machine|engine|motor|rocket|device)\b/i;

export function hasPhysicalFeasibilitySignal(goal: string): boolean {
  return PHYSICAL_RX.test(goal.toLowerCase());
}

/** Ongoing operation of an external account / public presence (gated to act). */
const ACCOUNT_OP_RX =
  /\b(run (my|the|our) (social|instagram|twitter|x|facebook|tiktok|linkedin|marketing)|post (to|on)|manage (my|the|our) (account|page|inbox|email|calendar)|reply to (customers|clients|dms|messages)|send (emails|messages|invoices)|schedule posts?)\b/i;

/** Software / document / analysis work Keep delivers end-to-end. */
const DELIVERABLE_RX =
  /\b(write|draft|code|program|script|fix|correct|implement|add|change|rename|replace|update|create|test|migrate|optimi[sz]e|patch|extend|build (a|an|the)? ?(app|api|website|site|tool|script|program|feature)|analy[sz]e|summari[sz]e|research|plan|design (a|the)? ?(doc|document|schema|architecture)|refactor|debug|document|report|essay|paper|novel|story|spreadsheet|dashboard)\b/i;

/** Sensitivity signals. */
const DUAL_USE_RX = /\b(weapon|payload|explosive|surveillance|jamming|autonomous (targeting|strike)|carry .*(weight|load|payload)|lift .*(kg|pounds|lbs)|10x|heavy[- ]?lift)\b/i;
const REGULATED_RX = /\b(medical|health|hipaa|financial advice|invest|legal advice|drug|prescription|faa|aviation|firearm|tax)\b/i;
const PUBLIC_RX = /\b(social media|publish|post publicly|brand|customers|public|audience|followers)\b/i;

/**
 * Classify a goal's feasibility. Deterministic first; if an LLM classifier is provided
 * and confident, its verdict refines the class (but never lowers honesty).
 */
export async function checkFeasibility(goal: string, classifier?: FeasibilityClassifier): Promise<FeasibilityReport> {
  const g = goal.toLowerCase();

  // Deterministic base signals.
  const physical = PHYSICAL_RX.test(g);
  const accountOp = ACCOUNT_OP_RX.test(g);
  const deliverable = DELIVERABLE_RX.test(g);

  let deliverability: DeliverabilityClass;
  if (accountOp) deliverability = "needs-account";
  else if (physical && !deliverableDominates(g)) deliverability = "assist-only";
  else if (deliverable) deliverability = "fully-deliverable";
  else deliverability = "assist-only"; // unknown-shape defaults to honest "I can help research/plan, not execute"

  // Sensitivity.
  let sensitivity: Sensitivity = "none";
  if (DUAL_USE_RX.test(g)) sensitivity = "dual-use";
  else if (REGULATED_RX.test(g)) sensitivity = "regulated";
  else if (PUBLIC_RX.test(g) || accountOp) sensitivity = "public-facing";

  // Optional LLM refinement (only tightens honesty; never flips assist-only -> fully).
  if (classifier) {
    try {
      const res = await classifier(goal);
      if (res) {
        // Accept a MORE conservative deliverability, or a higher sensitivity; ignore looser.
        if (rank(res.deliverability) > rank(deliverability)) deliverability = res.deliverability;
        if (sevRank(res.sensitivity) > sevRank(sensitivity)) sensitivity = res.sensitivity;
      }
    } catch {
      /* honest fallback: keep the deterministic verdict */
    }
  }

  return buildReport(goal, deliverability, sensitivity);
}

/** True if the goal is really about producing software/docs ABOUT a physical thing. */
function deliverableDominates(g: string): boolean {
  // e.g. "write the flight-controller software for a drone" — deliverable verb leads.
  return /\b(write|code|program|script|change|rename|replace|update|fix|patch|refactor|debug|design the software|firmware|simulation|model|cad|spec|plan|research|document)\b/i.test(g) && !/^\s*(build|construct|assemble|make|fabricate)\b/i.test(g);
}

function buildReport(goal: string, d: DeliverabilityClass, s: Sensitivity): FeasibilityReport {
  const sensNote = sensitivityNote(s);
  switch (d) {
    case "fully-deliverable":
      return {
        deliverability: d,
        sensitivity: s,
        canDeliver: "the full deliverable — I can research, plan, build, and vet this end to end.",
        framing: `This is squarely something I can do end to end.${sensNote}`,
        proceed: true,
      };
    case "assist-only":
      return {
        deliverability: d,
        sensitivity: s,
        canDeliver: "the research, design, component specs, simulations, build guide, and any software/firmware.",
        humanOwns: "the physical build, assembly, and real-world testing — I can't fabricate or operate hardware.",
        framing:
          `I want to be upfront: this is a physical project, and I build software, documents, and analysis — not hardware. ` +
          `What I *can* do is take you all the way through the research, the design and component selection, the math, any control software or simulations, and a detailed build guide. The physical building and testing stays with you.${sensNote} ` +
          `Want me to proceed on that basis?`,
        proceed: false, // pause for the reframe to be accepted
      };
    case "needs-account":
      return {
        deliverability: d,
        sensitivity: s,
        canDeliver: "the strategy, a content calendar, and fully drafted posts ready for your review.",
        humanOwns: "connecting the account and approving anything that posts publicly or spends money — those stay gated to you.",
        framing:
          `I can absolutely help run this — with one honest boundary: I'll do the strategy, the calendar, and draft every post for you, ` +
          `but actually posting publicly or spending on ads is your call each time (or via a scheduled approval you switch on), because those are public, irreversible actions under your brand.${sensNote} ` +
          `Want me to start on the strategy and first drafts?`,
        proceed: false,
      };
    case "out-of-scope":
      return {
        deliverability: d,
        sensitivity: s,
        canDeliver: "possibly some research or a summary, but this isn't really in my wheelhouse.",
        framing: `Honestly, this one is outside what I can meaningfully help with. I'd rather tell you that than waste your time.${sensNote}`,
        proceed: false,
      };
  }
}

function sensitivityNote(s: Sensitivity): string {
  switch (s) {
    case "dual-use":
      return " One note: this touches areas that can have dual-use implications, so I'll keep the work to legitimate, safe engineering and flag anything that veers toward misuse.";
    case "regulated":
      return " Heads-up: this is a regulated area, so I'll be careful to note where you'd need a licensed professional rather than relying on me.";
    case "public-facing":
      return " Since this is public-facing, I'll treat anything that goes out under your name as needing your sign-off.";
    case "none":
      return "";
  }
}

function rank(d: DeliverabilityClass): number {
  return d === "fully-deliverable" ? 0 : d === "needs-account" ? 1 : d === "assist-only" ? 2 : 3;
}
function sevRank(s: Sensitivity): number {
  return s === "none" ? 0 : s === "public-facing" ? 1 : s === "regulated" ? 2 : 3;
}
