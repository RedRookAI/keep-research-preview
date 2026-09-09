/** Outcome-gated adaptation for soft behavior. Policy and authority are deliberately absent. */

import type { EffortKnob } from "../reference/reference_registry.js";
import type { PromptFormat, Verbosity } from "../personalize/personalize.js";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { ModelProvider, GenerateRequest, GenerateResult, Embedding } from "../gateway/gateway.js";

export interface AdaptiveBehavior {
  readonly prompt: { readonly version: string; readonly text: string };
  readonly routing: { readonly model: string; readonly effort: EffortKnob };
  readonly voice: { readonly promptFormat: PromptFormat; readonly verbosity: Verbosity };
}

export interface AdaptationPolicy {
  readonly minSamplesPerArm: number;
  readonly minQualityGain: number;
  readonly maxRegressionRate: number;
  readonly rollbackQualityDrop: number;
  /** Maximum delay between assignment and a product exposure or its outcome. Defaults to 30 days. */
  readonly assignmentTtlMs?: number;
}

export interface AdaptationOutcome {
  readonly quality: number;
  readonly regressed: boolean;
}

export interface AdaptationScope {
  readonly projectId: string;
  readonly tenant?: string;
}

export interface AdaptationAssignment {
  readonly experimentId: string;
  readonly assignmentId: string;
  readonly arm: "baseline" | "candidate";
  readonly behaviorVersion: string;
  readonly assignedAt: number;
}

export interface BoundAdaptationOutcome extends AdaptationOutcome {
  readonly assignmentId: string;
  readonly outcomeId: string;
  readonly observedAt: number;
  readonly evidence: "observed-product";
}

export interface BoundLiveOutcome extends AdaptationOutcome {
  readonly outcomeId: string;
  readonly observedAt: number;
  readonly evidence: "observed-product";
}

export interface OutcomeAdaptationPersistence {
  load(): { readonly snapshot?: unknown; readonly revision: number } | undefined;
  save(snapshot: unknown, expectedRevision: number): number;
}

export interface OutcomeAdaptationOptions {
  readonly scope?: AdaptationScope;
  readonly persistence?: OutcomeAdaptationPersistence;
  readonly clock?: () => number;
  readonly id?: () => string;
  readonly random?: () => number;
  /** Explicit compatibility mode for a fixed, caller-owned offline dataset. Never use on product traffic. */
  readonly allowUnboundOfflineEvidence?: boolean;
}

/** Deterministic presentation only: the original content remains an exact, separately inspectable payload. */
export interface AdaptivePresentation { readonly content: string; readonly rendered: string; }

export function presentAdaptiveText(content: string, voice: AdaptiveBehavior["voice"]): AdaptivePresentation {
  let rendered: string;
  if (voice.promptFormat === "json") rendered = JSON.stringify({ response: content, verbosity: voice.verbosity });
  else if (voice.promptFormat === "xml") rendered = `<response verbosity="${voice.verbosity}">${content.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")}</response>`;
  else if (voice.promptFormat === "terse") rendered = content;
  else rendered = voice.verbosity === "detailed" ? `### Response\n\n${content}` : content;
  return Object.freeze({ content, rendered });
}

export interface CurrentModelCapability {
  readonly effortKnob: EffortKnob;
  readonly timeoutClass: "standard" | "reasoning";
  readonly asOf: string;
  readonly freshness: "fresh" | "stale" | "expired";
}
export interface ModelCapabilityPort { current(model: string, now: number): CurrentModelCapability; }
export interface ResolvedOutcomeAdaptation { readonly adaptation: OutcomeAdaptation; readonly subjectId?: string; }
export type OutcomeAdaptationResolver = (request: GenerateRequest) => OutcomeAdaptation | ResolvedOutcomeAdaptation | undefined;

/** Solve-only provider decorator. Re-resolves perishable capability facts at call time; hints grant no authority. */
export class OutcomeAdaptiveProvider implements ModelProvider {
  private readonly resolveAdaptation: OutcomeAdaptationResolver;
  constructor(private readonly inner: ModelProvider, adaptation: OutcomeAdaptation | OutcomeAdaptationResolver, private readonly capabilities: ModelCapabilityPort, private readonly clock: () => number = Date.now) {
    this.resolveAdaptation = typeof adaptation === "function" ? adaptation : () => adaptation;
  }
  get name(): string { return this.inner.name; }
  get isLocal(): boolean { return this.inner.isLocal; }
  async generate(req: GenerateRequest): Promise<GenerateResult> {
    const resolved = this.resolveAdaptation(req);
    if (resolved === undefined) return this.inner.generate(req);
    const adaptation = resolved instanceof OutcomeAdaptation ? resolved : resolved.adaptation;
    const explicitAssignment = req.hints?.["adaptationAssignmentId"];
    const assignmentId = typeof explicitAssignment === "string" ? explicitAssignment : resolved instanceof OutcomeAdaptation || resolved.subjectId === undefined ? undefined : adaptation.assignOrGet(resolved.subjectId)?.assignmentId;
    const behavior = assignmentId === undefined ? adaptation.current() : adaptation.expose(assignmentId);
    const capability = this.capabilities.current(behavior.routing.model, this.clock());
    return this.inner.generate({
      ...req,
      prompt: `${behavior.prompt.text.trim()}\n\n${req.prompt}`,
      hints: Object.freeze({ ...req.hints, ...(assignmentId === undefined ? {} : { adaptationAssignmentId: assignmentId }), adaptationVersion: behavior.prompt.version, preferredModel: behavior.routing.model, preferredModelAdvisory: true, requestedEffort: behavior.routing.effort, effortKnob: capability.effortKnob, timeoutClass: capability.timeoutClass, referenceAsOf: capability.asOf, referenceFreshness: capability.freshness }),
    });
  }
  async generateStream(req: GenerateRequest, onDelta?: (text: string) => void): Promise<GenerateResult> {
    if (!this.inner.generateStream) return this.generate(req);
    const resolved = this.resolveAdaptation(req);
    if (resolved === undefined) return this.inner.generateStream(req, onDelta);
    const adaptation = resolved instanceof OutcomeAdaptation ? resolved : resolved.adaptation;
    const explicitAssignment = req.hints?.["adaptationAssignmentId"];
    const assignmentId = typeof explicitAssignment === "string" ? explicitAssignment : resolved instanceof OutcomeAdaptation || resolved.subjectId === undefined ? undefined : adaptation.assignOrGet(resolved.subjectId)?.assignmentId;
    const behavior = assignmentId === undefined ? adaptation.current() : adaptation.expose(assignmentId);
    const capability = this.capabilities.current(behavior.routing.model, this.clock());
    return this.inner.generateStream({ ...req, prompt: `${behavior.prompt.text.trim()}\n\n${req.prompt}`, hints: Object.freeze({ ...req.hints, ...(assignmentId === undefined ? {} : { adaptationAssignmentId: assignmentId }), adaptationVersion: behavior.prompt.version, preferredModel: behavior.routing.model, preferredModelAdvisory: true, requestedEffort: behavior.routing.effort, effortKnob: capability.effortKnob, timeoutClass: capability.timeoutClass, referenceAsOf: capability.asOf, referenceFreshness: capability.freshness }) }, onDelta);
  }
  embed(texts: readonly string[]): Promise<Embedding[]> { return this.inner.embed(texts); }
}

export type AdaptationDecision =
  | { readonly kind: "observing"; readonly reason: string }
  | { readonly kind: "promoted"; readonly version: string; readonly reason: string }
  | { readonly kind: "rejected"; readonly reason: string }
  | { readonly kind: "rolled-back"; readonly version: string; readonly reason: string };

interface Aggregate { count: number; quality: number; regressions: number; variance: number; }
interface NormalizedAdaptationPolicy extends Required<AdaptationPolicy> {}
interface ExperimentDisposition { readonly candidateDigest: string; readonly verdict: "rejected" | "abandoned"; readonly at: number; }
const empty = (): Aggregate => ({ count: 0, quality: 0, regressions: 0, variance: 0 });
const ownKeys = (value: unknown, expected: readonly string[], label: string): Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  const record = value as Record<string, unknown>;
  const unexpected = Object.keys(record).filter((key) => !expected.includes(key));
  const missing = expected.filter((key) => !Object.hasOwn(record, key));
  if (unexpected.length > 0 || missing.length > 0) throw new TypeError(`${label} has rejected or missing fields`);
  return record;
};

const sanitize = (behavior: AdaptiveBehavior): AdaptiveBehavior => {
  const root = ownKeys(behavior, ["prompt", "routing", "voice"], "adaptive behavior");
  const prompt = ownKeys(root["prompt"], ["version", "text"], "adaptive prompt");
  const routing = ownKeys(root["routing"], ["model", "effort"], "adaptive routing");
  const voice = ownKeys(root["voice"], ["promptFormat", "verbosity"], "adaptive voice");
  if (typeof prompt["version"] !== "string" || prompt["version"].length === 0 || typeof prompt["text"] !== "string") throw new TypeError("adaptive prompt fields are invalid");
  if (typeof routing["model"] !== "string" || routing["model"].length === 0 || !["graded", "binary", "none"].includes(String(routing["effort"]))) throw new TypeError("adaptive routing fields are invalid");
  if (!["xml", "markdown", "terse", "json"].includes(String(voice["promptFormat"])) || !["terse", "normal", "detailed"].includes(String(voice["verbosity"]))) throw new TypeError("adaptive voice fields are invalid");
  return Object.freeze({
    prompt: Object.freeze({ version: prompt["version"], text: prompt["text"] }),
    routing: Object.freeze({ model: routing["model"], effort: routing["effort"] as EffortKnob }),
    voice: Object.freeze({ promptFormat: voice["promptFormat"] as PromptFormat, verbosity: voice["verbosity"] as Verbosity }),
  });
};

/**
 * Runs a baseline/candidate cohort and changes only typed soft behavior. The caller-owned
 * policy is frozen on construction and is never accepted as candidate input, so observed
 * preferences cannot acquire authorization, reliability, budget, or autonomy authority.
 */
export class OutcomeAdaptation {
  private live: AdaptiveBehavior;
  private safe: AdaptiveBehavior;
  private candidate: AdaptiveBehavior | undefined;
  private baselineOutcomes = empty();
  private candidateOutcomes = empty();
  private liveOutcomes = empty();
  private promotedQuality: number | undefined;
  private readonly policy: Readonly<NormalizedAdaptationPolicy>;
  private readonly scope: Readonly<AdaptationScope> | undefined;
  private readonly persistence: OutcomeAdaptationPersistence | undefined;
  private readonly clock: () => number;
  private readonly id: () => string;
  private readonly random: () => number;
  private readonly allowUnboundOfflineEvidence: boolean;
  private readonly initialDigest: string;
  private revision = 0;
  private experimentId: string | undefined;
  private readonly assignments = new Map<string, {
    readonly experimentId: string;
    readonly subjectDigest: string;
    readonly arm: "baseline" | "candidate";
    readonly behaviorVersion: string;
    readonly assignedAt: number;
    exposedAt?: number;
    outcome?: { readonly outcomeId: string; readonly quality: number; readonly regressed: boolean; readonly observedAt: number };
  }>();
  private readonly outcomeIds = new Set<string>();
  private readonly liveEvidence = new Map<string, { readonly quality: number; readonly regressed: boolean; readonly observedAt: number }>();
  private experimentHistory: ExperimentDisposition[] = [];

  constructor(initial: AdaptiveBehavior, policy: AdaptationPolicy, options: OutcomeAdaptationOptions = {}) {
    this.live = sanitize(initial);
    this.safe = this.live;
    this.initialDigest = this.behaviorDigest(this.live);
    if (!Number.isInteger(policy.minSamplesPerArm) || policy.minSamplesPerArm < 4) throw new RangeError("minSamplesPerArm must be an integer of at least 4");
    for (const [name, value] of Object.entries(policy).filter(([name]) => !["minSamplesPerArm", "assignmentTtlMs"].includes(name))) if (!Number.isFinite(value) || value < 0 || value > 1) throw new RangeError(`${name} must be within [0,1]`);
    const assignmentTtlMs = policy.assignmentTtlMs ?? 30 * 24 * 60 * 60 * 1_000;
    if (!Number.isSafeInteger(assignmentTtlMs) || assignmentTtlMs < 1) throw new RangeError("assignmentTtlMs must be a positive safe integer");
    this.policy = Object.freeze({ ...policy, assignmentTtlMs });
    this.scope = options.scope === undefined ? undefined : this.sanitizeScope(options.scope);
    this.persistence = options.persistence;
    this.clock = options.clock ?? Date.now;
    this.id = options.id ?? randomUUID;
    this.random = options.random ?? (() => randomBytes(6).readUIntBE(0, 6) / 0x1000000000000);
    this.allowUnboundOfflineEvidence = options.allowUnboundOfflineEvidence === true;
    const restored = this.persistence?.load();
    if (restored !== undefined) {
      if (restored.snapshot === undefined) this.revision = restored.revision;
      else this.restore(restored.snapshot, restored.revision, initial);
    }
  }

  current(): AdaptiveBehavior { this.assertCurrent(); return this.live; }

  /** Selects and durably records the exact arm exposed to a product call. */
  expose(assignmentId: string): AdaptiveBehavior {
    return this.transition(() => {
      const id = this.boundedId(assignmentId, "assignment id");
      const assignment = this.assignments.get(id);
      if (assignment === undefined || assignment.experimentId !== this.experimentId || this.candidate === undefined) throw new Error("exposure has no assignment in the active experiment");
      const now = this.validTime(this.clock(), "exposure time");
      if (now < assignment.assignedAt || now - assignment.assignedAt > this.policy.assignmentTtlMs) throw new Error("adaptation assignment expired before exposure");
      if (assignment.exposedAt === undefined) assignment.exposedAt = now;
      return assignment.arm === "baseline" ? this.live : this.candidate;
    });
  }

  propose(candidate: AdaptiveBehavior): string {
    return this.transition(() => {
      if (this.candidate !== undefined) throw new Error("an adaptation experiment is already active");
      const proposed = sanitize(candidate);
      if (proposed.prompt.version === this.live.prompt.version) throw new Error("candidate version must differ from live version");
      if (proposed.prompt.text === this.live.prompt.text && JSON.stringify(proposed.voice) === JSON.stringify(this.live.voice)) throw new Error("a routing-only advisory candidate has no proven applied treatment");
      const digest = this.behaviorDigest(proposed);
      if (this.experimentHistory.some((row) => row.candidateDigest === digest)) throw new Error("a previously rejected or abandoned candidate cannot be retried unchanged");
      this.candidate = proposed;
      this.baselineOutcomes = empty();
      this.candidateOutcomes = empty();
      this.assignments.clear();
      this.outcomeIds.clear();
      this.experimentId = this.boundedId(this.id(), "experiment id");
      return this.experimentId;
    });
  }

  assign(subjectId: string): AdaptationAssignment {
    return this.transition(() => {
      if (this.candidate === undefined || this.experimentId === undefined) throw new Error("no candidate is under evaluation");
      this.sweepExpiredAssignments(this.validTime(this.clock(), "assignment time"));
      const subjectDigest = this.digestSubject(subjectId);
      if ([...this.assignments.values()].some((row) => row.subjectDigest === subjectDigest)) throw new Error("subject is already assigned in this experiment");
      const baseline = [...this.assignments.values()].filter((row) => row.arm === "baseline").length;
      const candidate = this.assignments.size - baseline;
      if (baseline >= this.policy.minSamplesPerArm && candidate >= this.policy.minSamplesPerArm) throw new Error("the fixed experiment horizon is fully assigned");
      const arm = baseline === candidate ? (this.validRandom() < 0.5 ? "baseline" : "candidate") : baseline < candidate ? "baseline" : "candidate";
      if ((arm === "baseline" ? baseline : candidate) >= this.policy.minSamplesPerArm) throw new Error("the selected experiment arm is full");
      const assignmentId = this.boundedId(this.id(), "assignment id");
      const assignedAt = this.validTime(this.clock(), "assignment time");
      const behaviorVersion = arm === "baseline" ? this.live.prompt.version : this.candidate.prompt.version;
      this.assignments.set(assignmentId, { experimentId: this.experimentId, subjectDigest, arm, behaviorVersion, assignedAt });
      return Object.freeze({ experimentId: this.experimentId, assignmentId, arm, behaviorVersion, assignedAt });
    });
  }

  /** Product-path idempotence: repeated model calls in one run reuse its prospectively frozen arm. */
  assignOrGet(subjectId: string): AdaptationAssignment | undefined {
    return this.transition(() => {
      if (this.candidate === undefined || this.experimentId === undefined) return undefined;
      const now = this.validTime(this.clock(), "assignment time");
      this.sweepExpiredAssignments(now);
      const subjectDigest = this.digestSubject(subjectId);
      const existing = [...this.assignments.entries()].find(([, row]) => row.subjectDigest === subjectDigest);
      if (existing !== undefined) {
        const [assignmentId, row] = existing;
        return Object.freeze({ experimentId: row.experimentId, assignmentId, arm: row.arm, behaviorVersion: row.behaviorVersion, assignedAt: row.assignedAt });
      }
      const baseline = [...this.assignments.values()].filter((row) => row.arm === "baseline").length;
      const candidate = this.assignments.size - baseline;
      if (baseline >= this.policy.minSamplesPerArm && candidate >= this.policy.minSamplesPerArm) return undefined;
      const arm = baseline === candidate ? (this.validRandom() < 0.5 ? "baseline" : "candidate") : baseline < candidate ? "baseline" : "candidate";
      if ((arm === "baseline" ? baseline : candidate) >= this.policy.minSamplesPerArm) return undefined;
      const assignmentId = this.boundedId(this.id(), "assignment id");
      const behaviorVersion = arm === "baseline" ? this.live.prompt.version : this.candidate.prompt.version;
      this.assignments.set(assignmentId, { experimentId: this.experimentId, subjectDigest, arm, behaviorVersion, assignedAt: now });
      return Object.freeze({ experimentId: this.experimentId, assignmentId, arm, behaviorVersion, assignedAt: now });
    });
  }

  observe(outcome: BoundAdaptationOutcome): AdaptationDecision {
    return this.transition(() => {
      if (outcome.evidence !== "observed-product") throw new Error("only observed product outcomes can enter a live experiment");
      const assignmentId = this.boundedId(outcome.assignmentId, "assignment id");
      const outcomeId = this.boundedId(outcome.outcomeId, "outcome id");
      const assignment = this.assignments.get(assignmentId);
      if (assignment === undefined || assignment.experimentId !== this.experimentId) throw new Error("outcome has no assignment in the active experiment");
      if (assignment.exposedAt === undefined) throw new Error("outcome refused before the assigned behavior was exposed");
      if (assignment.outcome !== undefined || this.outcomeIds.has(outcomeId)) throw new Error("duplicate experiment outcome refused");
      const observedAt = this.validTime(outcome.observedAt, "outcome time");
      if (observedAt < assignment.exposedAt) throw new Error("outcome predates its product exposure");
      if (observedAt - assignment.assignedAt > this.policy.assignmentTtlMs) throw new Error("adaptation outcome arrived after assignment expiry");
      this.validateOutcome(outcome);
      assignment.outcome = { outcomeId, quality: outcome.quality, regressed: outcome.regressed, observedAt };
      this.outcomeIds.add(outcomeId);
      this.add(assignment.arm === "baseline" ? this.baselineOutcomes : this.candidateOutcomes, outcome);
      return this.evaluateCandidate();
    });
  }

  /** Compatibility for an explicitly labelled, fixed offline dataset. Product composition leaves it disabled. */
  record(arm: "baseline" | "candidate", outcome: AdaptationOutcome): AdaptationDecision {
    return this.transition(() => {
      if (!this.allowUnboundOfflineEvidence) throw new Error("unbound adaptation outcome refused; assign before observing");
      if (!this.candidate) return { kind: "rejected", reason: "no candidate is under evaluation" };
      this.add(arm === "baseline" ? this.baselineOutcomes : this.candidateOutcomes, outcome);
      return this.evaluateCandidate();
    });
  }

  observeLive(outcome: BoundLiveOutcome): AdaptationDecision {
    return this.transition(() => {
      if (outcome.evidence !== "observed-product") throw new Error("only observed product outcomes can monitor live adaptation");
      if (this.promotedQuality === undefined) return { kind: "observing", reason: "no promoted adaptation is under live monitoring" };
      const outcomeId = this.boundedId(outcome.outcomeId, "outcome id");
      if (this.liveEvidence.has(outcomeId)) throw new Error("duplicate live outcome refused");
      const observedAt = this.validTime(outcome.observedAt, "outcome time");
      this.validateOutcome(outcome);
      this.liveEvidence.set(outcomeId, { quality: outcome.quality, regressed: outcome.regressed, observedAt });
      return this.recordLiveOutcome(outcome);
    });
  }

  recordLive(outcome: AdaptationOutcome): AdaptationDecision {
    return this.transition(() => {
      if (!this.allowUnboundOfflineEvidence) throw new Error("unbound live outcome refused");
      if (this.promotedQuality === undefined) return { kind: "observing", reason: "no promoted adaptation is under live monitoring" };
      return this.recordLiveOutcome(outcome);
    });
  }

  abandon(experimentId: string): AdaptationDecision {
    return this.transition(() => {
      if (this.candidate === undefined || this.experimentId !== this.boundedId(experimentId, "experiment id")) throw new Error("no matching adaptation experiment is active");
      this.rememberDisposition(this.candidate, "abandoned");
      this.clearExperiment();
      return { kind: "rejected", reason: "adaptation experiment was explicitly abandoned" };
    });
  }

  private evaluateCandidate(): AdaptationDecision {
    if (this.baselineOutcomes.count < this.policy.minSamplesPerArm || this.candidateOutcomes.count < this.policy.minSamplesPerArm) return { kind: "observing", reason: "waiting for both outcome cohorts" };
    if (this.baselineOutcomes.count !== this.policy.minSamplesPerArm || this.candidateOutcomes.count !== this.policy.minSamplesPerArm) {
      if (this.candidate !== undefined) this.rememberDisposition(this.candidate, "rejected");
      this.clearExperiment();
      return { kind: "rejected", reason: "fixed experiment horizon was exceeded" };
    }
    const regressionRate = this.candidateOutcomes.regressions / this.candidateOutcomes.count;
    const gain = this.candidateOutcomes.quality - this.baselineOutcomes.quality;
    const varianceFloor = (count: number) => 1 / (12 * count);
    const standardError = Math.sqrt(Math.max(this.baselineOutcomes.variance, varianceFloor(this.baselineOutcomes.count)) / this.baselineOutcomes.count + Math.max(this.candidateOutcomes.variance, varianceFloor(this.candidateOutcomes.count)) / this.candidateOutcomes.count);
    const lower95 = gain - this.oneSidedT95(Math.min(this.baselineOutcomes.count, this.candidateOutcomes.count) - 1) * standardError;
    if (regressionRate > this.policy.maxRegressionRate || gain < this.policy.minQualityGain || lower95 <= 0) {
      const reason = `candidate failed fixed-horizon outcome gate (gain=${gain.toFixed(3)}, lower95=${lower95.toFixed(3)}, regression=${regressionRate.toFixed(3)})`;
      if (this.candidate !== undefined) this.rememberDisposition(this.candidate, "rejected");
      this.clearExperiment();
      return { kind: "rejected", reason };
    }
    this.safe = this.live;
    this.live = this.candidate!;
    this.promotedQuality = this.candidateOutcomes.quality;
    this.clearExperiment();
    this.liveOutcomes = empty();
    this.liveEvidence.clear();
    return { kind: "promoted", version: this.live.prompt.version, reason: `candidate improved measured quality by ${gain.toFixed(3)}` };
  }

  private recordLiveOutcome(outcome: AdaptationOutcome): AdaptationDecision {
    this.add(this.liveOutcomes, outcome);
    if (this.promotedQuality === undefined || this.liveOutcomes.count < this.policy.minSamplesPerArm) {
      return { kind: "observing", reason: "waiting for live outcome window" };
    }
    const regressionRate = this.liveOutcomes.regressions / this.liveOutcomes.count;
    const qualityDrop = (this.promotedQuality ?? this.liveOutcomes.quality) - this.liveOutcomes.quality;
    if (regressionRate <= this.policy.maxRegressionRate && qualityDrop < this.policy.rollbackQualityDrop) {
      this.liveOutcomes = empty();
      this.liveEvidence.clear();
      return { kind: "observing", reason: "live adaptation window remains within regression bounds" };
    }
    if (this.candidate !== undefined) this.rememberDisposition(this.candidate, "abandoned");
    this.clearExperiment();
    this.live = this.safe;
    this.promotedQuality = undefined;
    this.liveOutcomes = empty();
    this.liveEvidence.clear();
    return { kind: "rolled-back", version: this.live.prompt.version, reason: "live outcomes regressed; restored last safe behavior" };
  }

  private add(aggregate: Aggregate, outcome: AdaptationOutcome): void {
    this.validateOutcome(outcome);
    const previousMean = aggregate.quality;
    const previousM2 = aggregate.variance * Math.max(0, aggregate.count - 1);
    aggregate.count++;
    aggregate.quality = previousMean + (outcome.quality - previousMean) / aggregate.count;
    const m2 = previousM2 + (outcome.quality - previousMean) * (outcome.quality - aggregate.quality);
    aggregate.variance = aggregate.count > 1 ? m2 / (aggregate.count - 1) : 0;
    if (outcome.regressed) aggregate.regressions++;
  }

  private validateOutcome(outcome: AdaptationOutcome): void {
    if (!Number.isFinite(outcome.quality) || outcome.quality < 0 || outcome.quality > 1) throw new RangeError("quality must be within [0,1]");
    if (typeof outcome.regressed !== "boolean") throw new TypeError("regressed must be boolean");
  }

  private sanitizeScope(scope: AdaptationScope): Readonly<AdaptationScope> {
    const projectId = this.boundedText(scope.projectId, "projectId", 128);
    const tenant = scope.tenant === undefined ? undefined : this.boundedText(scope.tenant, "tenant", 256);
    return Object.freeze({ projectId, ...(tenant === undefined ? {} : { tenant }) });
  }

  private boundedText(value: unknown, label: string, max: number): string {
    if (typeof value !== "string" || value.trim() !== value || value.length === 0 || Buffer.byteLength(value, "utf8") > max || /[\u0000-\u001f\u007f]/u.test(value)) throw new TypeError(`${label} is invalid`);
    return value;
  }
  private boundedId(value: unknown, label: string): string { return this.boundedText(value, label, 256); }
  private validTime(value: unknown, label: string): number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} is invalid`);
    return value;
  }
  private validRandom(): number {
    const value = this.random();
    if (!Number.isFinite(value) || value < 0 || value >= 1) throw new Error("adaptation random source returned an invalid value");
    return value;
  }
  private digestSubject(subjectId: string): string {
    return createHash("sha256").update("keep.outcome-adaptation-subject/v1\0").update(this.boundedText(subjectId, "subject id", 1024)).digest("hex");
  }

  private behaviorDigest(behavior: AdaptiveBehavior): string {
    return createHash("sha256").update("keep.outcome-adaptation-candidate/v1\0").update(JSON.stringify(behavior)).digest("hex");
  }

  private oneSidedT95(df: number): number {
    const critical = [Infinity, 6.314, 2.92, 2.353, 2.132, 2.015, 1.943, 1.895, 1.86, 1.833, 1.812, 1.796, 1.782, 1.771, 1.761, 1.753, 1.746, 1.74, 1.734, 1.729, 1.725, 1.721, 1.717, 1.714, 1.711, 1.708, 1.706, 1.703, 1.701, 1.699, 1.697];
    return df < critical.length ? critical[df]! : df < 60 ? 1.671 : df < 120 ? 1.658 : 1.645;
  }

  private rememberDisposition(candidate: AdaptiveBehavior, verdict: ExperimentDisposition["verdict"]): void {
    this.experimentHistory.push({ candidateDigest: this.behaviorDigest(candidate), verdict, at: this.validTime(this.clock(), "experiment disposition time") });
    if (this.experimentHistory.length > 256) this.experimentHistory = this.experimentHistory.slice(-256);
  }

  private sweepExpiredAssignments(now: number): void {
    for (const [assignmentId, assignment] of this.assignments) {
      if (assignment.outcome === undefined && now >= assignment.assignedAt && now - assignment.assignedAt > this.policy.assignmentTtlMs) this.assignments.delete(assignmentId);
    }
  }

  private clearExperiment(): void {
    this.candidate = undefined;
    this.experimentId = undefined;
    this.assignments.clear();
    this.outcomeIds.clear();
    this.baselineOutcomes = empty();
    this.candidateOutcomes = empty();
  }

  private snapshot(): unknown {
    if (this.assignments.size > this.policy.minSamplesPerArm * 2 || this.outcomeIds.size > this.policy.minSamplesPerArm * 2 || this.liveEvidence.size > this.policy.minSamplesPerArm || this.experimentHistory.length > 256) throw new Error("adaptation evidence exceeds durable bounds");
    return {
      schema: "keep.outcome-adaptation/v5", initialDigest: this.initialDigest, scope: this.scope ?? null, policy: this.policy,
      live: this.live, safe: this.safe, candidate: this.candidate ?? null, experimentId: this.experimentId ?? null,
      baselineOutcomes: { ...this.baselineOutcomes }, candidateOutcomes: { ...this.candidateOutcomes }, liveOutcomes: { ...this.liveOutcomes },
      promotedQuality: this.promotedQuality ?? null,
      assignments: [...this.assignments.entries()].map(([assignmentId, row]) => ({ assignmentId, ...row })),
      outcomeIds: [...this.outcomeIds].sort(), liveEvidence: [...this.liveEvidence.entries()].map(([outcomeId, value]) => ({ outcomeId, ...value })),
      experimentHistory: this.experimentHistory.map((row) => ({ ...row })),
    };
  }

  private transition<T>(mutate: () => T): T {
    this.assertCurrent();
    const before = this.snapshot();
    const revision = this.revision;
    try {
      const result = mutate();
      if (JSON.stringify(this.snapshot()) !== JSON.stringify(before)) this.persist();
      return result;
    } catch (error) {
      try { this.restore(before, revision, (before as { live: AdaptiveBehavior }).live); }
      catch { this.revision = revision; }
      throw error;
    }
  }

  private persist(): void {
    if (this.persistence === undefined) { this.revision++; return; }
    this.revision = this.persistence.save(this.snapshot(), this.revision);
  }

  private assertCurrent(): void {
    if (this.persistence === undefined) return;
    const stored = this.persistence.load();
    const observed = stored?.revision ?? 0;
    if (observed !== this.revision) throw new Error(`adaptation document conflict: expected ${this.revision}, found ${observed}`);
  }

  private restore(snapshot: unknown, revision: number, configuredInitial: AdaptiveBehavior): void {
    if (!Number.isSafeInteger(revision) || revision < 0 || typeof snapshot !== "object" || snapshot === null || Array.isArray(snapshot)) throw new Error("invalid persisted outcome adaptation");
    const row = snapshot as Record<string, unknown>;
    const schema = row["schema"];
    const exact = ["assignments", "baselineOutcomes", "candidate", "candidateOutcomes", "experimentId", ...(["keep.outcome-adaptation/v4", "keep.outcome-adaptation/v5"].includes(String(schema)) ? ["experimentHistory"] : []), ...(schema === "keep.outcome-adaptation/v5" ? ["initialDigest"] : []), "live", "liveEvidence", "liveOutcomes", "outcomeIds", "policy", "promotedQuality", "safe", "schema", "scope"].sort();
    if (Object.keys(row).sort().join(",") !== exact.join(",") || !["keep.outcome-adaptation/v3", "keep.outcome-adaptation/v4", "keep.outcome-adaptation/v5"].includes(String(schema))) throw new Error("invalid persisted outcome adaptation");
    if (schema === "keep.outcome-adaptation/v5" && row["initialDigest"] !== this.initialDigest) throw new Error("persisted adaptation initial behavior disagrees with configuration");
    if (JSON.stringify(row["scope"]) !== JSON.stringify(this.scope ?? null)) throw new Error("persisted outcome adaptation binding disagrees with configuration");
    const persistedPolicy = row["policy"] as Partial<NormalizedAdaptationPolicy>;
    const normalizedPersistedPolicy = { ...persistedPolicy, assignmentTtlMs: persistedPolicy.assignmentTtlMs ?? 30 * 24 * 60 * 60 * 1_000 };
    const policyChanged = JSON.stringify(normalizedPersistedPolicy) !== JSON.stringify(this.policy);
    const live = sanitize(row["live"] as AdaptiveBehavior), safe = sanitize(row["safe"] as AdaptiveBehavior);
    if (safe.prompt.version !== sanitize(configuredInitial).prompt.version && revision === 0) throw new Error("persisted adaptation initial behavior is invalid");
    const candidate = row["candidate"] === null ? undefined : sanitize(row["candidate"] as AdaptiveBehavior);
    const aggregate = (value: unknown): Aggregate => {
      if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("invalid persisted adaptation aggregate");
      const a = value as Record<string, unknown>;
      if (Object.keys(a).sort().join(",") !== "count,quality,regressions,variance" || !Number.isSafeInteger(a["count"]) || (a["count"] as number) < 0 || !Number.isSafeInteger(a["regressions"]) || (a["regressions"] as number) < 0 || (a["regressions"] as number) > (a["count"] as number) || !Number.isFinite(a["quality"]) || !Number.isFinite(a["variance"]) || (a["quality"] as number) < 0 || (a["quality"] as number) > 1 || (a["variance"] as number) < 0) throw new Error("invalid persisted adaptation aggregate");
      return { count: a["count"] as number, quality: a["quality"] as number, regressions: a["regressions"] as number, variance: a["variance"] as number };
    };
    const experimentId = row["experimentId"] === null ? undefined : this.boundedId(row["experimentId"], "experiment id");
    if ((candidate === undefined) !== (experimentId === undefined)) throw new Error("persisted adaptation experiment is incomplete");
    const restoredHorizon = Math.max(this.policy.minSamplesPerArm, Number(normalizedPersistedPolicy.minSamplesPerArm) || 0);
    if (!Array.isArray(row["assignments"]) || row["assignments"].length > restoredHorizon * 2 || !Array.isArray(row["outcomeIds"]) || row["outcomeIds"].length > restoredHorizon * 2 || !Array.isArray(row["liveEvidence"]) || row["liveEvidence"].length > restoredHorizon) throw new Error("invalid persisted adaptation evidence bounds");
    this.assignments.clear(); this.outcomeIds.clear(); this.liveEvidence.clear(); this.experimentHistory = [];
    this.live = live; this.safe = safe; this.candidate = candidate; this.experimentId = experimentId;
    this.baselineOutcomes = aggregate(row["baselineOutcomes"]); this.candidateOutcomes = aggregate(row["candidateOutcomes"]); this.liveOutcomes = aggregate(row["liveOutcomes"]);
    this.promotedQuality = row["promotedQuality"] === null ? undefined : Number(row["promotedQuality"]);
    if (this.promotedQuality !== undefined && (!Number.isFinite(this.promotedQuality) || this.promotedQuality < 0 || this.promotedQuality > 1)) throw new Error("invalid persisted promoted quality");
    const restoredOutcomeIds = new Set<string>();
    const restoredSubjects = new Set<string>();
    const restoredBaseline = empty(), restoredCandidate = empty();
    for (const value of row["assignments"]) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("invalid persisted assignment");
      const a = value as Record<string, unknown>; const assignmentId = this.boundedId(a["assignmentId"], "assignment id");
      const assignmentKeys = ["arm", "assignedAt", "assignmentId", "behaviorVersion", "experimentId", ...(a["exposedAt"] === undefined ? [] : ["exposedAt"]), ...(a["outcome"] === undefined ? [] : ["outcome"]), "subjectDigest"].sort().join(",");
      if (Object.keys(a).sort().join(",") !== assignmentKeys) throw new Error("invalid persisted assignment");
      const subjectDigest = String(a["subjectDigest"]), arm = a["arm"] as "baseline" | "candidate";
      const assignedAt = this.validTime(a["assignedAt"], "assignment time");
      const exposedAt = a["exposedAt"] === undefined ? undefined : this.validTime(a["exposedAt"], "exposure time");
      if (this.assignments.has(assignmentId) || a["experimentId"] !== experimentId || !/^[0-9a-f]{64}$/u.test(subjectDigest) || restoredSubjects.has(subjectDigest) || !["baseline", "candidate"].includes(String(a["arm"])) || typeof a["behaviorVersion"] !== "string" || a["behaviorVersion"] !== (arm === "baseline" ? live.prompt.version : candidate?.prompt.version) || (exposedAt !== undefined && (exposedAt < assignedAt || exposedAt - assignedAt > this.policy.assignmentTtlMs))) throw new Error("invalid persisted assignment");
      restoredSubjects.add(subjectDigest);
      const outcome = a["outcome"] === undefined ? undefined : a["outcome"] as Record<string, unknown>;
      let restoredOutcome: { readonly outcomeId: string; readonly quality: number; readonly regressed: boolean; readonly observedAt: number } | undefined;
      if (outcome !== undefined) {
        if (Object.keys(outcome).sort().join(",") !== "observedAt,outcomeId,quality,regressed" || typeof outcome["quality"] !== "number" || typeof outcome["regressed"] !== "boolean") throw new Error("invalid persisted assignment outcome");
        const outcomeId = this.boundedId(outcome["outcomeId"], "outcome id"), observedAt = this.validTime(outcome["observedAt"], "outcome time");
        if (restoredOutcomeIds.has(outcomeId) || exposedAt === undefined || observedAt < exposedAt || observedAt - assignedAt > this.policy.assignmentTtlMs) throw new Error("invalid persisted assignment outcome");
        this.validateOutcome({ quality: outcome["quality"], regressed: outcome["regressed"] });
        restoredOutcome = { outcomeId, quality: outcome["quality"], regressed: outcome["regressed"], observedAt };
        restoredOutcomeIds.add(outcomeId);
        this.add(arm === "baseline" ? restoredBaseline : restoredCandidate, restoredOutcome);
      }
      this.assignments.set(assignmentId, { experimentId: String(a["experimentId"]), subjectDigest, arm, behaviorVersion: String(a["behaviorVersion"]), assignedAt, ...(exposedAt === undefined ? {} : { exposedAt }), ...(restoredOutcome === undefined ? {} : { outcome: restoredOutcome }) });
    }
    const baselineAssignments = [...this.assignments.values()].filter((value) => value.arm === "baseline").length;
    const candidateAssignments = this.assignments.size - baselineAssignments;
    if (baselineAssignments > restoredHorizon || candidateAssignments > restoredHorizon) throw new Error("invalid persisted adaptation arm bounds");
    for (const value of row["outcomeIds"]) this.outcomeIds.add(this.boundedId(value, "outcome id"));
    if (["keep.outcome-adaptation/v4", "keep.outcome-adaptation/v5"].includes(String(schema))) {
      if (!Array.isArray(row["experimentHistory"]) || row["experimentHistory"].length > 256) throw new Error("invalid persisted adaptation experiment history");
      const digests = new Set<string>();
      for (const value of row["experimentHistory"]) {
        const history = ownKeys(value, ["candidateDigest", "verdict", "at"], "adaptation experiment history");
        if (!/^[0-9a-f]{64}$/u.test(String(history["candidateDigest"])) || digests.has(String(history["candidateDigest"])) || !["rejected", "abandoned"].includes(String(history["verdict"]))) throw new Error("invalid persisted adaptation experiment history");
        digests.add(String(history["candidateDigest"]));
        this.experimentHistory.push({ candidateDigest: String(history["candidateDigest"]), verdict: history["verdict"] as ExperimentDisposition["verdict"], at: this.validTime(history["at"], "experiment disposition time") });
      }
    }
    const restoredLive = empty();
    for (const value of row["liveEvidence"]) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("invalid persisted live adaptation evidence");
      const evidence = value as Record<string, unknown>;
      if (Object.keys(evidence).sort().join(",") !== "observedAt,outcomeId,quality,regressed" || typeof evidence["quality"] !== "number" || typeof evidence["regressed"] !== "boolean") throw new Error("invalid persisted live adaptation evidence");
      const outcomeId = this.boundedId(evidence["outcomeId"], "outcome id");
      if (this.liveEvidence.has(outcomeId)) throw new Error("invalid persisted live adaptation evidence");
      const observedAt = this.validTime(evidence["observedAt"], "outcome time");
      this.validateOutcome({ quality: evidence["quality"], regressed: evidence["regressed"] });
      this.liveEvidence.set(outcomeId, { quality: evidence["quality"], regressed: evidence["regressed"], observedAt });
      this.add(restoredLive, { quality: evidence["quality"], regressed: evidence["regressed"] });
    }
    const sameAggregate = (left: Aggregate, right: Aggregate) => left.count === right.count && left.regressions === right.regressions && Math.abs(left.quality - right.quality) < 1e-12 && Math.abs(left.variance - right.variance) < 1e-12;
    if (this.outcomeIds.size !== row["outcomeIds"].length || [...this.outcomeIds].some((id) => !restoredOutcomeIds.has(id)) || restoredOutcomeIds.size !== this.outcomeIds.size || !sameAggregate(this.baselineOutcomes, restoredBaseline) || !sameAggregate(this.candidateOutcomes, restoredCandidate) || !sameAggregate(this.liveOutcomes, restoredLive)) throw new Error("persisted adaptation evidence disagrees with assignments");
    this.revision = revision;
    if (policyChanged) {
      if (this.candidate !== undefined) this.rememberDisposition(this.candidate, "abandoned");
      this.clearExperiment();
      this.liveOutcomes = empty(); this.liveEvidence.clear();
      this.persist();
    }
    else if (schema !== "keep.outcome-adaptation/v5") this.persist();
  }
}
