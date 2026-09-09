/**
 * WiringLedger (Increment 18.W) — the standing inventory of module WIRING STATUS. The "no islands, wired end
 * to end" mandate was previously enforced only by manual audit; it drifted (18 built increments accumulated
 * islands). This ledger makes it an ENFORCED invariant: every module known to be off the live composeKeep
 * path is listed here WITH an explicit disposition and rationale, and a companion test fails if the list and
 * reality diverge. An orphan can no longer hide.
 *
 * Dispositions:
 *  - "live"        : now on the composeKeep runtime path (or reached transitively from it).
 *  - "entry-point" : intentionally reached from a distinct ENTRY POINT (CLI, CI, onboarding conversation),
 *                    not composeKeep — wiring it into compose would be wrong. Tracked as its own seam.
 *  - "adapter"     : an environment adapter supplied by the caller at use time (git, CI, tracker) — correct
 *                    that compose does not own it; the caller wires it.
 *  - "pending-wire": a genuine island with a KNOWN correct hub, scheduled to be wired (named), not yet done.
 *  - "retire"      : superseded; slated for removal.
 *
 * This is documentation-as-code: the DISPOSITIONS are the contract, the test is the enforcement.
 */

export type WiringDisposition = "live" | "entry-point" | "adapter" | "pending-wire" | "retire";

export interface WiringEntry {
  readonly module: string;
  readonly disposition: WiringDisposition;
  /** The hub/entry-point it is (or will be) reached from. */
  readonly hub: string;
  readonly rationale: string;
}

/**
 * The ledger. 18.W wired the solve→loop path (the highest-value connection); the front-door + solve-helper
 * islands are triaged with their correct hubs and scheduled as named pending-wires (each a small, verifiable
 * follow-on), NOT blind-wired into compose where they do not belong.
 */
export const WIRING_LEDGER: readonly WiringEntry[] = [
  // ── Wired live this increment (the core of 18.W) ──
  { module: "solve_outcome_wire", disposition: "live", hub: "composeKeep", rationale: "maps real SolveToPrResult → OutcomeSignal → bus; guards irreversible actions via the reference monitor" },
  { module: "self_improvement_bus", disposition: "live", hub: "composeKeep", rationale: "the Monitor wire (18.1)" },
  { module: "drift_monitor", disposition: "live", hub: "composeKeep", rationale: "registered on the bus; its inSafeMode gates improve (C4)" },
  { module: "reference_monitor", disposition: "live", hub: "composeKeep", rationale: "single trace-level enforcement point (C1)" },
  { module: "reference_clauses", disposition: "live", hub: "composeKeep", rationale: "default safety clauses registered into the reference monitor" },
  { module: "learners", disposition: "live", hub: "composeKeep", rationale: "18.2 improve-class learners (prompt/memory) + curriculum tracker registered on the bus when a proposer exists" },
  { module: "consolidation", disposition: "live", hub: "composeKeep", rationale: "18.3 sleep pass: registered on the bus as a protect-observer + driven by the heartbeat cadence tick" },
  { module: "skill_distiller", disposition: "live", hub: "composeKeep", rationale: "18.4 distills candidate skills; the skill learner (18.5) drives it, CEGIS validates before live" },
  { module: "skill_validator", disposition: "live", hub: "composeKeep", rationale: "18.5 CEGIS gate; present when an execution oracle is supplied — validates distilled skills before live" },
  { module: "skill_canary", disposition: "live", hub: "composeKeep", rationale: "18.6 instant-rollback canary lifecycle: validated skill → live → graduate/demote + tiered notify" },
  { module: "skill_retrieval", disposition: "live", hub: "composeKeep", rationale: "18.7 retrieve→rerank→bounded-top-k over canary+consolidation state; admission-gates rolled-back skills" },
  { module: "artifact_self_heal", disposition: "live", hub: "composeKeep", rationale: "C3 self-heal CEGIS loop for regressed skills/lessons; reuses validator+canary, escalates the rest" },
  { module: "adapter_proposal_bridge", disposition: "live", hub: "composeKeep", rationale: "18.8 opt-in rich-tier bridge: model-adapter proposals → LoRA entry gate + Colluding-LoRA composition eval + canary" },
  { module: "governed_anchor", disposition: "live", hub: "composeKeep", rationale: "18.9 governs anchor growth/rotation from verified outcomes; enforces bounded self-modification; MetaHarness consumes snapshot()" },
  { module: "front_door", disposition: "live", hub: "composeKeep", rationale: "19 non-engineer onboarding wired; deterministic always-works floor + optional LLM warming; captures directives to probation memory" },
  { module: "cli_core", disposition: "entry-point", hub: "keep CLI (main.ts → cli/keep.ts)", rationale: "S0 the runnable surface; onboard/solve/status/review/audit over the real app+spine; decisions recorded to the spine" },
  { module: "decision_packet", disposition: "live", hub: "cli/cli_core (review)", rationale: "S1 fuses DecisionBrief + ForecastVerdict + manifest into the Edilec-minimum packet; progressive disclosure; depth scaled to reversibility" },
  { module: "onboarding_conversation", disposition: "live", hub: "frontdoor/front_door", rationale: "19 wired via FrontDoor into composeKeep" },
  { module: "memory_consensus", disposition: "live", hub: "composeKeep", rationale: "C2 dual-memory consensus: gates lessons on independent-origin agreement; quarantines contradictions NOTE: the file is memory/consensus.ts (class MemoryConsensus); it is genuinely consumed by compose.ts, memory/store.ts, logicvet/logic_vet.ts and cascade/tier_adapters.ts — the ledger name differs from the file basename, which is why the no-islands check keys on the import graph (files), not ledger names." },

  // ── Entry-point reached (NOT composeKeep — wiring into compose would be wrong) ──
  { module: "ci_adapter", disposition: "entry-point", hub: "CI/CD entry (GitHub Actions step)", rationale: "Keep-as-a-CI-step is a distinct deployment entry point, not the in-process solve runtime" },

  // ── Caller-supplied adapters (compose correctly does not own these) ──
  { module: "tracker_adapters", disposition: "live", hub: "composeKeep (via triggerIngress’s TriggerRouter)", rationale: "W0: Linear/Jira/GitHub normalizers registered into the trigger router by registerAllTrackers; no longer standalone. WHICH tracker is deployment config, but the normalizers are wired by default." },
  { module: "trigger_ingress", disposition: "live", hub: "composeKeep", rationale: "W0: verifies HMAC over raw bytes → spine-backed idempotency dedup → normalize → Issue → solve seam; fail-closed + audited. The solve handler + real secrets + HTTP listener light up at deployment (VERIFIED-SEAM)." },
  { module: "webhook_verifier", disposition: "live", hub: "trigger_ingress", rationale: "W0: per-provider HMAC-SHA256 signature verification over raw bytes, constant-time, timestamp freshness. The security core of ingress." },
  { module: "polling_source", disposition: "adapter", hub: "caller (no-ingress environments) → triggerIngress.ingestPolled", rationale: "W0: deterministic pull fallback; shares the ingress dedup path. The fetcher (API token + since-cursor) is environment-specific, supplied at use time." },
  { module: "http_ingress", disposition: "entry-point", hub: "node:http listener (deployment)", rationale: "W0: zero-dep HTTP front door reading raw body bytes → triggerIngress.receive. A distinct deployment entry point; public TLS/DNS/allowlist is the VERIFIED-SEAM." },
  { module: "hostile_mcp_gateway", disposition: "live", hub: "composeKeep", rationale: "W1: the hostile-intake gauntlet every external MCP server sits behind — deny-by-default allowlist, tool-description pinning (rug-pull kill), untrusted-result tagging, destructive-call human-gate, reference-monitor egress guard, full audit. Live server transport + OAuth credential are deployment (SEAM)." },
  { module: "mcp", disposition: "live", hub: "hostile_mcp_gateway (client) + KeepMcpServer (server)", rationale: "W1: MCP client adapter + version negotiation + Keep-as-server, now consumed behind the hostile gateway (was an untracked island — now tracked)." },
  { module: "mcp_stdio_transport", disposition: "adapter", hub: "caller (MCP server connection)", rationale: "W1: a concrete stdio McpTransport; the specific transport + credentials are environment-specific, supplied at use time behind the gateway." },
  { module: "capability_port", disposition: "live", hub: "composeKeep (CapabilityHub) / hostile_mcp_gateway", rationale: "the capability port + hub (trust-tiered invoke) MCP/A2A/connector adapters plug into; consumed by the gateway." },
  { module: "notification_router", disposition: "live", hub: "composeKeep", rationale: "W2: routes oversight decisions to tiers (urgent/notify/digest/suppress) so only the dangerous few interrupt; batches the routine; suppresses F2-calibrated classes; dead-letters interrupt. Wired to recordPending + ingress onDeadLetter. Delivery channel is a deployment seam." },
  { module: "review_intake", disposition: "live", hub: "composeKeep (ingress handler) + cli solve", rationale: "W3 closed loop: shared review intake (review.pending + correlation id + W2 notify) used by the CLI solve path AND the trigger ingress. makeClosedLoopHandler wires ingress → solve → review when config.solve is present; human decision stays the gate. The provider+repo solve is the deployment seam." },
  { module: "non_engineer_view", disposition: "live", hub: "cli review --plain", rationale: "S3: plain-language render of the S1 DecisionPacket for non-engineers; preserves disposition + neutrality, counters rubber-stamping (specific-check cognitive forcing + intent-fit honest limit), frames routine work as optional to avoid overcorrection. Wired to `keep review --plain`; reused by the S2 web UI later." },
  { module: "review_core", disposition: "live", hub: "cli (review/status/audit) + review_web", rationale: "S2: single source of truth for reading pending reviews + the ONE decision path (applyReviewDecision records review.decided AND feeds F2 calibration together). Both the CLI and the web UI go through it, so they cannot drift." },
  { module: "review_web", disposition: "live", hub: "review_server + cli serve", rationale: "S2: pure request handler — routing + localhost security (Host/DNS-rebinding guard, token, SameSite cookie, Origin + CSRF) + HTML rendering from buildNonEngineerView. No socket dependency; fully unit-tested." },
  { module: "review_server", disposition: "live", hub: "cli serve", rationale: "S2: thin Node http seam; binds 127.0.0.1, per-run token, Host allowlist from the bound port, body cap. Delegates all logic to review_web. Exposing beyond localhost is an opt-in deployment choice (TLS + X1 SSO)." },
  { module: "rbac", disposition: "live", hub: "composeKeep (app.authorization) + review_core + review_web", rationale: "X0 open RBAC: roles->permissions behind an AuthorizationPort (swap for ABAC/ReBAC later). Enforced at applyReviewDecision + the web POST decide; N=1 defaults to owner (no login). The agent role structurally cannot approve (I9)." },
  { module: "session_store", disposition: "live", hub: "review_web multi-user mode (via composeKeep app.identity + serve)", rationale: "X1: opaque server-side sessions (idle + absolute timeout, revoke, per-session CSRF). Resolves the acting principal per request in multi-user mode; single-owner mode (N=1) does not use it." },
  { module: "identity_provider", disposition: "live", hub: "review_web /login (via app.identity)", rationale: "X1: IdentityProviderPort (OIDC adapter is the seam) + HmacAssertionProvider (verifiable now) + PrincipalRegistry (verified identity -> role, deny-by-default). Wired into the login flow; the real IdP federation is the deployment seam." },
  { module: "identity", disposition: "live", hub: "composeKeep (app.separationOfDuties) + security_gate", rationale: "SeparationOfDuties (N-of-M + N=1 step-up) is now COMPOSED and recording approvals to the spine; the security_gate enforces it (with RBAC) for security-critical actions. First live call site: calibration.reduce_escalation (keep calibration authorize --step-up). Other actions in the set route through the same gate as they gain call sites." },
  { module: "security_gate", disposition: "live", hub: "cli calibration authorize (+ future security-critical call sites)", rationale: "NIST AC-3(2) two-layer enforcement: RBAC then SoD dual-control (step-up in N=1, N-of-M in multi-op) for privileged actions; grants + denials audited. Wired to reducing Keep's own oversight." },
  { module: "best_of_n", disposition: "live", hub: "composeKeep (app.bestOfNSolver, when a candidate sampler is configured)", rationale: "R1 resolution: sample N candidates → score each with the deterministic verifyPatch (SOUND checks primary, anti reward-hacking) → pessimistic select (safer/smaller wins ties) → early-stop when verified-clean → audit. The candidate sampler (real provider at temperature) is the deploy seam; the winner still flows through the human gate." },
  { module: "selector", disposition: "live", hub: "composeKeep (config.candidateSelector → best_of_n)", rationale: "R2 hybrid selector: applied ONLY to the verified (sound-cleared) set, so it can never override verification (VeRA principle). Clusters verified candidates by approach, scores consensus with √(cluster size) diminishing returns, keeps consensus as the prior, refines ties by safety. Execution-based clustering + cross-model panels are seams behind the port." },
  { module: "novel_tests", disposition: "live", hub: "composeKeep (app.resolveWithTests, when candidateSolver + testGenerator + testExecutor configured)", rationale: "R3: generated tests strengthen selection — validate away no-pass tests, weight by discriminative power p(1-p), cluster verified candidates by pass-profile (upgrades R2), and flag a behavioral fork → escalate. Generated tests NEVER auto-approve; the SOUND floor (R1 verifyPatch) stays primary. The generator + executor are deploy seams." },
  { module: "budget_cascade", disposition: "live", hub: "composeKeep (app.resolveCascade, when resolutionTiers configured)", rationale: "R4: budget-aware resolution cascade — cheap tier first, escalate ONLY on a provable verification failure or an R3 behavioral fork (never on miscalibrated model confidence), honor a fixed budget a priori (never overspend — graceful degradation for free-tier/N=1), optional complexity pre-routing, human as the permanent final fallback. Every tier + escalation + budget-stop audited. The tiered samplers + budget ledger are deploy seams." },
  { module: "resolution_curve", disposition: "live", hub: "cli resolution (reads the R1–R4 spine trail)", rationale: "R5: honest resolution economics over the recorded resolve.* events — verified vs DEFERRED-to-human (containment != resolution), grounded cost per verified resolution (incl. deferred spend), escalation/tier-hit/fork rates. A trustworthy public-benchmark RATE needs contamination-controlled live runs (VERIFIED-SEAM); this computes the mechanism economics on the runs given." },
  { module: "solve_monitor", disposition: "live", hub: "cli monitor + web /monitor (reads the trigger/resolve/review spine trail)", rationale: "S4: read-only multi-solve monitor — folds the lifecycle trail into per-ticket state (phase, stuck, cost, escalations) stitched by the closed-loop correlation id; surfaces needs-attention tickets (awaiting-review, deferred, dead-lettered, stuck) first. Observes, never acts. OpenTelemetry export is a seam." },
  { module: "batch_digest", disposition: "pending-wire", hub: "S-track review UI / notification digest", rationale: "#20 batch review digest; the richer readiness/effort-ranked digest lights up once merge-readiness scoring is wired (S-track). W2 ships its own simple digest now." },
  { module: "merge_readiness", disposition: "pending-wire", hub: "S-track review scoring (#11/#19)", rationale: "reviewer-effort + merge-readiness scoring; belongs in the S-track review surface with real PR signals. It IS consumed by review/batch_digest.ts (an island cluster); both await a findings-producing review queue that carries DisplayedFindings + coverage — wiring from a bare PrManifest would fabricate readiness, so they stay honestly pending." },
  { module: "scanner_adapter", disposition: "adapter", hub: "caller (security scanner)", rationale: "environment-specific; supplied at use time" },

  // ── Genuine islands with a KNOWN hub, scheduled as named pending-wires (small verifiable follow-ons) ──
  { module: "brain_resolver", disposition: "pending-wire", hub: "frontdoor/conversation_driver", rationale: "F0 onboarding brain-probe step; belongs in the onboarding sequence, not the solve runtime" },
  { module: "config_applier", disposition: "pending-wire", hub: "frontdoor/conversation_driver", rationale: "F2 deterministic validate→gate→apply; onboarding step" },
  { module: "local_first_defaults", disposition: "pending-wire", hub: "frontdoor/conversation_driver", rationale: "no-account local defaults resolver; onboarding step" },
  { module: "rebuild_classifier", disposition: "pending-wire", hub: "frontdoor/conversation_driver", rationale: "F3b additive/destructive classifier; onboarding step" },
  { module: "grounded_estimator", disposition: "pending-wire", hub: "solve/plan pipeline (autonomy brief)", rationale: "autonomy feasibility estimate; belongs in the plan stage's decision brief" },
  { module: "prior_art", disposition: "pending-wire", hub: "solve/plan pipeline (planning step)", rationale: "anti-reinvention currency check; belongs in the plan stage" },
  { module: "soul_render", disposition: "pending-wire", hub: "model-call prompt construction", rationale: "personality→voice prompt prefix; belongs at model-call assembly (voice only, never policy)" },
  { module: "oversight_calibration", disposition: "live", hub: "compose (via calibration_wire)", rationale: "16.9b escalation calibration, WIRED in F2 via CalibrationWire: consumes post-approval revert/rework outcomes → governed reduce-escalation proposals; loosening is human-authorized + revocable, tightening is automatic (auto-revoke on rising reverts). Irreversible/high-risk never auto-widens." },
  { module: "calibration_wire", disposition: "live", hub: "composeKeep", rationale: "F2 wire: feeds review decisions + post-approval outcomes into OversightCalibration; emits governed proposals; the OversightRouter consumes activePolicyGates(). Real revert/rework signal SOURCE is a VERIFIED-SEAM (git revert / reopened ticket)." },
];

/** Modules considered accounted-for (not orphans). Anything genuinely off-path must appear here. */
export function ledgerModules(): ReadonlySet<string> {
  return new Set(WIRING_LEDGER.map((e) => e.module));
}

/** The still-to-wire work, in priority order (for the roadmap + the enforcement test's allowance). */
export function pendingWires(): readonly WiringEntry[] {
  return WIRING_LEDGER.filter((e) => e.disposition === "pending-wire");
}
