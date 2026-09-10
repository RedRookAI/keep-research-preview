/**
 * Durable projected monetary accounting. Admission includes outstanding work.
 * Token prices and projected input usage are trusted configuration/estimator inputs;
 * these arithmetic checks are not a universal guarantee about a provider's bill.
 */
import { randomUUID } from "node:crypto";
import type { Spine } from "../spine/spine.js";
import { canonicalize, type StagedEvent } from "../spine/event.js";
import type { CostModel, TokenUsage } from "../observability/cost_model.js";

export type LoopClass = "auto-research" | "auto-rag" | "auto-learning" | "auto-training";
export type ModelTier = "local" | "small" | "frontier";
export interface AuthorizationEnvelope {
  readonly id: string;
  readonly projectId: string;
  readonly allowedClasses: readonly LoopClass[];
  readonly allowedTiers: readonly ModelTier[];
  readonly dailyCapUsd: number;
  readonly perRunCapUsd: number;
  readonly perCallTokenCeiling: number;
  readonly expiresAt: number;
  readonly grantedReason: string;
}
export interface RunSpend {
  readonly runId: string;
  readonly envelopeId: string;
  readonly spentUsd: number;
  readonly reservedUsd: number;
  readonly calls: number;
  readonly dayKey: string;
}
export type BreachKind = "expired" | "class-not-authorized" | "tier-not-authorized" | "per-run-cap" | "daily-cap" | "token-ceiling" | "price-unknown" | "invalid-usage" | "legacy-accounting" | "projection-exceeded";
export interface BreachCheck { readonly wouldBreach: boolean; readonly kind?: BreachKind; readonly reason?: string; }
interface Rates { readonly input: number; readonly cached: number; readonly output: number; }
export interface MonetaryReservation {
  readonly id: string; readonly runId: string; readonly envelopeId: string;
  readonly dayKey: string; readonly model: string; readonly amount: number;
  readonly rates: Rates; readonly projected: TokenUsage;
}
interface Held extends MonetaryReservation { state: "pending" | "settled" | "void"; actual?: number; actualUsage?: TokenUsage; }
interface Run { runId: string; envelopeId: string; dayKey: string; spentUsd: number; calls: number; }
interface Authority { envelope: AuthorizationEnvelope; revoked: boolean; legacyUnknown: boolean; }
export interface BudgetLedgerOptions {
  /** Configured startup intent; realized durably under the first mutation lock.
   * It never revives a revoked authority or resets an existing run. */
  readonly bootstrap?: { readonly envelope: AuthorizationEnvelope; readonly runId: string };
}
const number = (value: unknown, label: string): number => {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new Error("invalid nonnegative " + label);
  return value;
};
const id = (value: unknown): string => {
  if (typeof value !== "string" || !value.length || value.length > 512) throw new Error("invalid monetary identity");
  return value;
};
const day = (value: unknown): string => {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/u.test(value)) throw new Error("invalid monetary day");
  return value;
};
function exact(value: unknown, keys: readonly string[]): void {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).some(key => typeof key !== "string") ||
    Object.keys(value).sort().join(",") !== [...keys].sort().join(",") ||
    Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !("value" in d) || !d.enumerable)) throw new Error("invalid monetary record shape");
}
export function validateTokenUsage(usage: TokenUsage): TokenUsage {
  exact(usage, ["freshInputTokens", "cachedInputTokens", "outputTokens"]);
  for (const [name, value] of Object.entries(usage)) if (!["freshInputTokens", "cachedInputTokens", "outputTokens"].includes(name) || !Number.isSafeInteger(value) || value < 0) throw new Error("invalid token usage");
  for (const name of ["freshInputTokens", "cachedInputTokens", "outputTokens"] as const) {
    if (!Number.isSafeInteger(usage[name]) || usage[name] < 0) throw new Error("invalid token usage");
  }
  return Object.freeze({ ...usage });
}
function captureEnvelope(env: AuthorizationEnvelope): AuthorizationEnvelope {
  exact(env, ["id", "projectId", "allowedClasses", "allowedTiers", "dailyCapUsd", "perRunCapUsd", "perCallTokenCeiling", "expiresAt", "grantedReason"]);
  id(env.id); id(env.projectId);
  if (typeof env.grantedReason !== "string" || !env.grantedReason.trim() || env.grantedReason.length > 8192) throw new Error("invalid grant reason");
  number(env.dailyCapUsd, "daily cap"); number(env.perRunCapUsd, "run cap");
  if (!Number.isSafeInteger(env.perCallTokenCeiling) || env.perCallTokenCeiling < 0 || !Number.isSafeInteger(env.expiresAt) || env.expiresAt < 0) throw new Error("invalid envelope limit");
  if (!Array.isArray(env.allowedClasses) || env.allowedClasses.some(c => !["auto-research", "auto-rag", "auto-learning", "auto-training"].includes(c)) || !Array.isArray(env.allowedTiers) || env.allowedTiers.some(t => !["local", "small", "frontier"].includes(t))) throw new Error("invalid envelope scope");
  return Object.freeze({ ...env, allowedClasses: Object.freeze([...env.allowedClasses]), allowedTiers: Object.freeze([...env.allowedTiers]) });
}
const amount = (rates: Rates, usage: TokenUsage) => number(rates.input * usage.freshInputTokens + rates.cached * usage.cachedInputTokens + rates.output * usage.outputTokens, "computed cost");
const breach = (kind: BreachKind, reason: string): BreachCheck => ({ wouldBreach: true, kind, reason });

/** Mutations are awaited and serialized in the Spine's configured lock domain.
 * Reporting getters are local views; they never substitute for reserve(). */
export class BudgetLedger {
  private readonly authorities = new Map<string, Authority>();
  private readonly runs = new Map<string, Run>();
  private readonly reservations = new Map<string, Held>();
  private readonly daily = new Map<string, Map<string, number>>();
  private readonly legacy = new Set<string>();
  private readonly legacyRevoked = new Set<string>();
  private readable = true;
  private bootstrapApplied = false;
  private readonly bootstrap: BudgetLedgerOptions["bootstrap"];
  constructor(private readonly spine: Spine, private readonly costModel: CostModel,
    private readonly clock: () => number = Date.now, options: BudgetLedgerOptions = {}) {
    this.bootstrap = options.bootstrap === undefined ? undefined : Object.freeze({ envelope: captureEnvelope(options.bootstrap.envelope), runId: id(options.bootstrap.runId) });
  }
  async grant(envelope: AuthorizationEnvelope): Promise<void> {
    const env = captureEnvelope(envelope);
    await this.mutate(() => {
      this.grantLocked(env, false);
      if (this.bootstrap?.envelope.id === env.id) {
        this.beginLocked(this.bootstrap.runId, env.id);
        this.bootstrapApplied = true;
      }
    }, false);
  }
  async revoke(envelopeId: string, reason: string): Promise<void> {
    id(envelopeId); id(reason);
    await this.mutate(() => {
      const current = this.authorities.get(envelopeId);
      if (current && !current.revoked) this.append({ op: "revoke", envelopeId, reason });
    });
  }
  async beginRun(runId: string, envelopeId: string): Promise<RunSpend> {
    id(runId); id(envelopeId);
    return this.mutate(() => { this.beginLocked(runId, envelopeId); return this.runSpend(runId)!; });
  }
  /** Refresh a diagnostic view. This is not an admission reservation. */
  async refresh(): Promise<void> { await this.mutate(() => undefined); }
  getEnvelope(envelopeId: string): AuthorizationEnvelope | undefined {
    this.assertReadable(); const state = this.authorities.get(envelopeId);
    return state && !state.revoked ? state.envelope : undefined;
  }
  runSpend(runId: string): RunSpend | undefined {
    this.assertReadable(); const run = this.runs.get(runId);
    return run ? Object.freeze({ ...run, reservedUsd: this.pending(p => p.runId === runId) }) : undefined;
  }
  /** Consumed plus outstanding exposure for this day, not necessarily a paid bill. */
  dailySpend(envelopeId: string, now = this.clock()): number {
    this.assertReadable(); const key = this.dayKey(now);
    return (this.daily.get(envelopeId)?.get(key) ?? 0) + this.pending(p => p.envelopeId === envelopeId && p.dayKey === key);
  }
  willBreach(runId: string, cls: LoopClass, tier: ModelTier, model: string, projected: TokenUsage): BreachCheck {
    this.assertReadable();
    try { return this.check(runId, cls, tier, validateTokenUsage(projected), this.quote(model, projected)); }
    catch { return breach("price-unknown", "valid pricing and usage are required"); }
  }
  async reserve(runId: string, cls: LoopClass, tier: ModelTier, model: string, projected: TokenUsage): Promise<{ readonly breach: BreachCheck; readonly reservation?: MonetaryReservation }> {
    const usage = validateTokenUsage(projected); id(runId); id(model);
    return this.mutate(() => {
      // Check authority/token bounds before pricing, including deliberate zero ceilings.
      const preliminary = this.check(runId, cls, tier, usage, 0);
      if (preliminary.wouldBreach && preliminary.kind !== "legacy-accounting") return { breach: preliminary };
      let rates: Rates, cost: number;
      try { rates = this.rates(model); cost = amount(rates, usage); }
      catch { return { breach: breach("price-unknown", "known valid token rates are required") }; }
      const checked = this.check(runId, cls, tier, usage, cost);
      if (checked.wouldBreach) return { breach: checked };
      const run = this.runs.get(runId)!;
      const reservation: MonetaryReservation = Object.freeze({ id: randomUUID(), runId, envelopeId: run.envelopeId, dayKey: this.dayKey(this.clock()), model, amount: cost, rates, projected: usage });
      this.append({ op: "reserve", reservation });
      return { breach: checked, reservation };
    });
  }
  async settle(reservationId: string, usage: TokenUsage): Promise<number> {
    const captured = validateTokenUsage(usage); id(reservationId);
    return this.mutate(() => {
      const reservation = this.reservations.get(reservationId);
      if (!reservation) throw new Error("unknown monetary reservation");
      const cost = amount(reservation.rates, captured);
      if (reservation.state === "settled" && canonicalize(reservation.actualUsage) === canonicalize(captured)) return cost;
      if (reservation.state !== "pending") throw new Error("monetary reservation already resolved");
      this.checkAddition(reservation.runId, reservation.dayKey, cost);
      this.append({ op: "settle", reservationId, usage: captured, amount: cost, exceededReservation: cost > reservation.amount });
      return cost;
    });
  }
  /** Only the trusted dispatcher may attest known non-entry. Never call on an inner-provider error. */
  async voidBeforeDispatch(reservationId: string): Promise<void> {
    id(reservationId);
    await this.mutate(() => {
      const reservation = this.reservations.get(reservationId);
      if (reservation?.state === "void") return;
      if (reservation?.state !== "pending") throw new Error("reservation cannot be voided");
      this.append({ op: "void", reservationId });
    });
  }
  /** Compatibility for externally observed, non-reserved consumption; never refunds. */
  async recordSpend(runId: string, model: string, usage: TokenUsage): Promise<number> {
    const captured = validateTokenUsage(usage); id(runId); id(model);
    return this.mutate(() => {
      if (!this.runs.has(runId)) throw new Error("no run " + runId);
      const cost = this.quote(model, captured);
      const dayKey = this.dayKey(this.clock());
      this.checkAddition(runId, dayKey, cost);
      this.append({ op: "spend", runId, model, usage: captured, amount: cost, dayKey });
      return cost;
    });
  }
  private rates(model: string): Rates {
    // Invoking cost permits a configured dynamic lookup to register a real rate.
    const rates = Object.freeze({
      input: number(this.costModel.cost(model, { freshInputTokens: 1, cachedInputTokens: 0, outputTokens: 0 }).totalUsd, "input rate"),
      cached: number(this.costModel.cost(model, { freshInputTokens: 0, cachedInputTokens: 1, outputTokens: 0 }).totalUsd, "cached rate"),
      output: number(this.costModel.cost(model, { freshInputTokens: 0, cachedInputTokens: 0, outputTokens: 1 }).totalUsd, "output rate"),
    });
    if (!this.costModel.hasPricing(model)) throw new Error("unknown price is not zero");
    return rates;
  }
  private quote(model: string, usage: TokenUsage): number { return amount(this.rates(model), validateTokenUsage(usage)); }
  private check(runId: string, cls: LoopClass, tier: ModelTier, projected: TokenUsage, cost: number): BreachCheck {
    const run = this.runs.get(runId);
    if (!run) return breach("per-run-cap", "no run " + runId);
    const state = this.authorities.get(run.envelopeId);
    if (!state || state.revoked) return breach("expired", "envelope revoked/absent");
    const env = state.envelope;
    if (this.clock() > env.expiresAt) return breach("expired", "envelope expired");
    if (!env.allowedClasses.includes(cls)) return breach("class-not-authorized", "class not in envelope");
    if (env.allowedTiers.length && !env.allowedTiers.includes(tier)) return breach("tier-not-authorized", "tier not authorized");
    if (projected.outputTokens > env.perCallTokenCeiling) return breach("token-ceiling", "projected output exceeds ceiling");
    if (state.legacyUnknown && cost > 0) return breach("legacy-accounting", "historical consumption is unknown; explicit new allowance or reconciliation required");
    if (cost > 0 && [...this.reservations.values()].some(r => r.envelopeId === env.id && r.actual !== undefined && r.actual > r.amount)) return breach("projection-exceeded", "observed usage exceeded its reservation; corrected projection and explicit new allowance required");
    if (run.spentUsd + this.pending(p => p.runId === runId) + cost > env.perRunCapUsd) return breach("per-run-cap", "run consumption and reservations exceed cap");
    if (this.dailySpend(env.id) + cost > env.dailyCapUsd) return breach("daily-cap", "daily consumption and reservations exceed cap");
    return { wouldBreach: false };
  }
  private pending(select: (p: Held) => boolean): number {
    let total = 0; for (const p of this.reservations.values()) if (p.state === "pending" && select(p)) total = number(total + p.amount, "pending total");
    return total;
  }
  private dayKey(now: number): string {
    if (!Number.isSafeInteger(now) || now < 0) throw new Error("invalid accounting clock");
    return new Date(now).toISOString().slice(0, 10);
  }
  private grantLocked(env: AuthorizationEnvelope, bootstrap: boolean): void {
    const previous = this.authorities.get(env.id);
    if (bootstrap && !previous && this.legacyRevoked.has(env.id)) throw new Error("legacy authority was revoked; explicit grant required");
    if (previous && previous.envelope.projectId !== env.projectId) throw new Error("envelope identity belongs to a different project");
    if (previous && bootstrap) {
      if (previous.revoked) return;
      if (canonicalize(previous.envelope) !== canonicalize(env)) throw new Error("configured envelope differs from durable authority; explicit grant revision required");
      return;
    }
    if (previous && !previous.revoked && canonicalize(previous.envelope) === canonicalize(env)) return;
    this.append({ op: "grant", envelope: env, legacyUnknown: previous?.legacyUnknown ?? this.legacy.has(env.id) });
  }
  private beginLocked(runId: string, envelopeId: string): void {
    const previous = this.runs.get(runId);
    if (previous) { if (previous.envelopeId !== envelopeId) throw new Error("run belongs to another envelope"); return; }
    if (!this.authorities.has(envelopeId)) throw new Error("run requires a known envelope");
    this.append({ op: "run", runId, envelopeId, dayKey: this.dayKey(this.clock()) });
  }
  private async mutate<T>(fn: () => T, bootstrap = true): Promise<T> {
    return this.spine.withStableEventView(events => {
      this.readable = false;
      this.replay(events);
      this.spine.confirmEventDurability();
      this.readable = true;
      if (bootstrap && this.bootstrap && !this.bootstrapApplied) {
        this.grantLocked(this.bootstrap.envelope, true);
        this.beginLocked(this.bootstrap.runId, this.bootstrap.envelope.id);
        this.bootstrapApplied = true;
      }
      return fn();
    });
  }
  private append(fields: Record<string, unknown>): void {
    const payload = { schema: "keep.monetary/v1", ...fields };
    try {
      this.spine.stage({ type: "identity.action", actor: "monetary-ledger", payload });
      this.spine.confirmEventDurability();
      this.apply(payload);
    } catch (error) { this.readable = false; throw error; }
  }
  private replay(events: readonly StagedEvent[]): void {
    this.authorities.clear(); this.runs.clear(); this.reservations.clear(); this.daily.clear(); this.legacy.clear(); this.legacyRevoked.clear();
    const seen = new Map<string, string>();
    for (const event of events) {
      const encoded = canonicalize(event), prior = seen.get(event.id);
      if (prior !== undefined) { if (prior !== encoded) throw new Error("conflicting duplicate monetary event identity"); continue; }
      seen.set(event.id, encoded);
      if (event.actor === "scheduler" && ["envelope_granted", "envelope_revoked"].includes(String(event.payload["event"]))) {
        const envelopeId = id(event.payload["envelopeId"]);
        this.legacy.add(envelopeId);
        if (event.payload["event"] === "envelope_revoked") this.legacyRevoked.add(envelopeId);
        else this.legacyRevoked.delete(envelopeId);
        const current = this.authorities.get(envelopeId);
        if (current) { current.legacyUnknown = true; if (this.legacyRevoked.has(envelopeId)) current.revoked = true; }
      }
      if (event.actor === "monetary-ledger") {
        if (event.type !== "identity.action" || event.payload["schema"] !== "keep.monetary/v1") throw new Error("invalid monetary event schema");
        this.apply(event.payload);
      }
    }
  }
  private apply(p: Readonly<Record<string, unknown>>): void {
    const fields: Record<string, readonly string[]> = {
      grant: ["envelope", "legacyUnknown"], revoke: ["envelopeId", "reason"], run: ["runId", "envelopeId", "dayKey"],
      reserve: ["reservation"], settle: ["reservationId", "usage", "amount", "exceededReservation"], void: ["reservationId"],
      spend: ["runId", "model", "usage", "amount", "dayKey"],
    };
    if (typeof p["op"] !== "string" || !Object.hasOwn(fields, p["op"])) throw new Error("unknown monetary operation");
    exact(p, ["schema", "op", ...fields[p["op"]]!]);
    switch (p["op"]) {
      case "grant": {
        const env = captureEnvelope(p["envelope"] as AuthorizationEnvelope), old = this.authorities.get(env.id);
        if (typeof p["legacyUnknown"] !== "boolean" || (old && (old.envelope.projectId !== env.projectId || old.legacyUnknown !== p["legacyUnknown"]))) throw new Error("invalid grant transition");
        this.authorities.set(env.id, { envelope: env, revoked: false, legacyUnknown: p["legacyUnknown"] }); break;
      }
      case "revoke": {
        id(p["reason"]);
        const state = this.authorities.get(id(p["envelopeId"])); if (!state) throw new Error("revoke has no authority"); state.revoked = true; break;
      }
      case "run": {
        const runId = id(p["runId"]), envelopeId = id(p["envelopeId"]), dayKey = day(p["dayKey"]);
        if (this.runs.has(runId) || !this.authorities.has(envelopeId)) throw new Error("invalid monetary run");
        this.runs.set(runId, { runId, envelopeId, dayKey, spentUsd: 0, calls: 0 }); break;
      }
      case "reserve": {
        const r = p["reservation"] as MonetaryReservation;
        exact(r, ["id", "runId", "envelopeId", "dayKey", "model", "amount", "rates", "projected"]);
        exact(r.rates, ["input", "cached", "output"]);
        id(r.id); id(r.runId); id(r.envelopeId); id(r.model); day(r.dayKey); number(r.amount, "reservation");
        const rates = Object.freeze({ input: number(r.rates.input, "input rate"), cached: number(r.rates.cached, "cached rate"), output: number(r.rates.output, "output rate") });
        const projected = validateTokenUsage(r.projected);
        if (this.reservations.has(r.id) || this.runs.get(r.runId)?.envelopeId !== r.envelopeId || this.authorities.get(r.envelopeId)?.revoked !== false || amount(rates, projected) !== r.amount) throw new Error("invalid monetary reservation");
        this.reservations.set(r.id, { ...r, rates, projected, state: "pending" }); break;
      }
      case "settle": {
        const r = this.reservations.get(id(p["reservationId"]));
        const cost = number(p["amount"], "settlement");
        if (!r || r.state !== "pending" || amount(r.rates, validateTokenUsage(p["usage"] as TokenUsage)) !== cost || p["exceededReservation"] !== (cost > r.amount)) throw new Error("invalid monetary settlement");
        this.addSpend(r.runId, r.dayKey, cost); r.state = "settled"; r.actual = cost; r.actualUsage = validateTokenUsage(p["usage"] as TokenUsage); break;
      }
      case "void": {
        const r = this.reservations.get(id(p["reservationId"])); if (!r || r.state !== "pending") throw new Error("invalid monetary void"); r.state = "void"; break;
      }
      case "spend": {
        validateTokenUsage(p["usage"] as TokenUsage); id(p["model"]);
        this.addSpend(id(p["runId"]), day(p["dayKey"]), number(p["amount"], "spend")); break;
      }
      default: throw new Error("unknown monetary operation");
    }
  }
  private addSpend(runId: string, dayKey: string, cost: number): void {
    this.checkAddition(runId, dayKey, cost);
    const run = this.runs.get(runId); if (!run) throw new Error("spend has no run");
    run.spentUsd = number(run.spentUsd + cost, "run total"); run.calls++;
    const days = this.daily.get(run.envelopeId) ?? new Map<string, number>();
    days.set(dayKey, number((days.get(dayKey) ?? 0) + cost, "daily total")); this.daily.set(run.envelopeId, days);
  }
  private checkAddition(runId: string, dayKey: string, cost: number): void {
    const run = this.runs.get(runId); if (!run) throw new Error("spend has no run");
    number(run.spentUsd + cost, "run total");
    number((this.daily.get(run.envelopeId)?.get(dayKey) ?? 0) + cost, "daily total");
    if (!Number.isSafeInteger(run.calls + 1)) throw new Error("invalid call count");
  }
  private assertReadable(): void { if (!this.readable) throw new Error("monetary accounting requires durable reload"); }
}
