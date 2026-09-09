/**
 * Keep's load-bearing research-to-plan admission contract.
 *
 * This composes the existing per-source research predicates into a milestone artifact. A plan is
 * not research-ready merely because three links exist: the exact candidate, dated six-month
 * survey, historical failure lineage, cross-disciplinary transfer, claims, limitations, and
 * independent cross-family review must close over one canonical digest.
 *
 * This module decides structural eligibility only. Provider strings and model output are
 * caller-owned claims, so this API can never mint external-review authority. A deployment-selected
 * verifier adapter must validate the raw execution evidence before a separate promotion gate acts.
 */

import { createHash } from "node:crypto";
import { types } from "node:util";
import { canonicalize } from "../spine/event.js";

const SHA256 = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const MAX_SOURCES = 128;
const MAX_CLAIMS = 256;
const MAX_TEXT = 16_384;

export type ResearchLane = "current" | "historical" | "cross-disciplinary";

export interface TriResearchSource {
  readonly id: string;
  readonly lane: ResearchLane;
  readonly title: string;
  readonly locator: string;
  readonly publisher: string;
  readonly domain: string;
  readonly sourceDate: string;
  readonly retrievedAt: string;
  readonly bodyRef: string;
  readonly bodySha256: string;
  readonly primary: boolean;
  readonly supports: readonly string[];
  readonly limitation: string;
  readonly transferMechanism: string | null;
}

export interface TriResearchClaim {
  readonly id: string;
  readonly text: string;
  readonly sourceIds: readonly string[];
  readonly applicability: string;
  readonly limitation: string;
}

export interface TriResearchManifest {
  readonly schemaVersion: "keep.tri-research/v1";
  readonly milestoneId: string;
  readonly buildDomain: string;
  readonly candidateDigest: string;
  readonly planDigest: string;
  readonly researchAsOf: string;
  readonly currentWindowStart: string;
  readonly currentWindowEnd: string;
  readonly completedAt: string;
  readonly searchScopeRef: string;
  readonly searchScopeDigest: string;
  readonly searchLimitations: readonly string[];
  readonly sources: readonly TriResearchSource[];
  readonly claims: readonly TriResearchClaim[];
}

export interface CrossFamilyResearchReview {
  readonly schemaVersion: "keep.cross-family-research-review/v1";
  readonly manifestDigest: string;
  readonly candidateDigest: string;
  readonly authorFamily: string;
  readonly reviewerFamily: string;
  readonly provider: string;
  readonly model: string;
  readonly sessionId: string;
  readonly transport: "provider-first-party" | "operator-pinned-api";
  readonly outputTokens: number;
  readonly reviewedAt: string;
  readonly expiresAt: string;
  readonly verdict: "GO" | "REVISE" | "NO-GO";
  readonly findingsDigest: string;
  readonly rawEvidenceDigest: string;
}

export interface ResearchEligibilityContext {
  readonly candidateDigest: string;
  readonly planDigest: string;
  /** Observer-supplied time. A later authority gate must supply trusted time before promotion. */
  readonly observedNow: string;
}

export interface ResearchPlanningEligibility {
  /** Structural readiness only; never an admission or effect authority. */
  readonly readyForExternalVerification: boolean;
  readonly manifestDigest: string | null;
  readonly reasons: readonly string[];
}

export class TriResearchAdmissionError extends Error {
  constructor(message: string) { super(message); this.name = "TriResearchAdmissionError"; }
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function exactRecord(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || types.isProxy(value)) throw new TriResearchAdmissionError(`${label}: expected inert record`);
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new TriResearchAdmissionError(`${label}: prototype must be Object.prototype`);
  const own = Reflect.ownKeys(value);
  if (own.some((key) => typeof key !== "string")) throw new TriResearchAdmissionError(`${label}: symbol keys forbidden`);
  const descriptors = Object.getOwnPropertyDescriptors(value) as Record<string, PropertyDescriptor>;
  if (Object.values(descriptors).some((d) => d.get !== undefined || d.set !== undefined)) throw new TriResearchAdmissionError(`${label}: accessors forbidden`);
  const actual = (own as string[]).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new TriResearchAdmissionError(`${label}: keys are not exact`);
  const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) out[key] = descriptors[key]!.value;
  return out;
}

function denseArray(value: unknown, label: string, min: number, max: number): unknown[] {
  if (!Array.isArray(value) || types.isProxy(value)) throw new TriResearchAdmissionError(`${label}: expected inert array`);
  const descriptors = Object.getOwnPropertyDescriptors(value) as Record<string, PropertyDescriptor>;
  const own = Reflect.ownKeys(value);
  if (own.some((key) => typeof key !== "string")) throw new TriResearchAdmissionError(`${label}: symbol keys forbidden`);
  const lengthDescriptor = descriptors.length;
  if (!lengthDescriptor || lengthDescriptor.get !== undefined || lengthDescriptor.set !== undefined || !Number.isSafeInteger(lengthDescriptor.value)) throw new TriResearchAdmissionError(`${label}: invalid length`);
  const length = lengthDescriptor.value as number;
  if (length < min || length > max) throw new TriResearchAdmissionError(`${label}: invalid cardinality`);
  const expected = ["length", ...Array.from({ length }, (_, index) => String(index))].sort();
  const actual = (own as string[]).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new TriResearchAdmissionError(`${label}: sparse or extra properties`);
  const out: unknown[] = [];
  for (let index = 0; index < length; index++) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || descriptor.get !== undefined || descriptor.set !== undefined) throw new TriResearchAdmissionError(`${label}[${index}]: accessor forbidden`);
    out.push(descriptor.value);
  }
  return out;
}

function text(value: unknown, label: string, max = MAX_TEXT): string {
  if (typeof value !== "string" || value.length < 1 || value.length > max) throw new TriResearchAdmissionError(`${label}: invalid text`);
  return value;
}

function identifier(value: unknown, label: string): string {
  const out = text(value, label, 128);
  if (!ID.test(out)) throw new TriResearchAdmissionError(`${label}: invalid identifier`);
  return out;
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value) || /^0+$/.test(value)) throw new TriResearchAdmissionError(`${label}: invalid SHA-256`);
  return value;
}

function date(value: unknown, label: string): string {
  if (typeof value !== "string" || !ISO_DATE.test(value)) throw new TriResearchAdmissionError(`${label}: invalid ISO date`);
  const parsed = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== value) throw new TriResearchAdmissionError(`${label}: impossible date`);
  return value;
}

function instant(value: unknown, label: string): string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) throw new TriResearchAdmissionError(`${label}: invalid canonical instant`);
  return value;
}

function stringArray(value: unknown, label: string, max: number, allowEmpty = false): string[] {
  const rows = denseArray(value, label, allowEmpty ? 0 : 1, max);
  const out = rows.map((row, index) => text(row, `${label}[${index}]`));
  if (new Set(out).size !== out.length || out.some((row, index) => index > 0 && out[index - 1]! >= row)) throw new TriResearchAdmissionError(`${label}: must be sorted and unique`);
  return out;
}

function minusSixCalendarMonths(iso: string): string {
  const [year, month, day] = iso.split("-").map(Number) as [number, number, number];
  const targetMonthIndex = month - 1 - 6;
  const targetYear = year + Math.floor(targetMonthIndex / 12);
  const normalizedMonth = ((targetMonthIndex % 12) + 12) % 12;
  const lastDay = new Date(Date.UTC(targetYear, normalizedMonth + 1, 0)).getUTCDate();
  return new Date(Date.UTC(targetYear, normalizedMonth, Math.min(day, lastDay))).toISOString().slice(0, 10);
}

function captureSource(input: unknown, index: number): TriResearchSource {
  const row = exactRecord(input, ["id", "lane", "title", "locator", "publisher", "domain", "sourceDate", "retrievedAt", "bodyRef", "bodySha256", "primary", "supports", "limitation", "transferMechanism"], `sources[${index}]`);
  const lane = row.lane;
  if (lane !== "current" && lane !== "historical" && lane !== "cross-disciplinary") throw new TriResearchAdmissionError(`sources[${index}].lane: unknown lane`);
  if (typeof row.primary !== "boolean") throw new TriResearchAdmissionError(`sources[${index}].primary: expected boolean`);
  const transferMechanism = row.transferMechanism === null ? null : text(row.transferMechanism, `sources[${index}].transferMechanism`);
  return {
    id: identifier(row.id, `sources[${index}].id`), lane,
    title: text(row.title, `sources[${index}].title`), locator: text(row.locator, `sources[${index}].locator`, 4096),
    publisher: text(row.publisher, `sources[${index}].publisher`, 512), domain: identifier(row.domain, `sources[${index}].domain`),
    sourceDate: date(row.sourceDate, `sources[${index}].sourceDate`), retrievedAt: instant(row.retrievedAt, `sources[${index}].retrievedAt`), bodyRef: text(row.bodyRef, `sources[${index}].bodyRef`, 4096),
    bodySha256: digest(row.bodySha256, `sources[${index}].bodySha256`), primary: row.primary,
    supports: stringArray(row.supports, `sources[${index}].supports`, MAX_CLAIMS), limitation: text(row.limitation, `sources[${index}].limitation`),
    transferMechanism,
  };
}

function captureClaim(input: unknown, index: number): TriResearchClaim {
  const row = exactRecord(input, ["id", "text", "sourceIds", "applicability", "limitation"], `claims[${index}]`);
  return { id: identifier(row.id, `claims[${index}].id`), text: text(row.text, `claims[${index}].text`), sourceIds: stringArray(row.sourceIds, `claims[${index}].sourceIds`, MAX_SOURCES), applicability: text(row.applicability, `claims[${index}].applicability`), limitation: text(row.limitation, `claims[${index}].limitation`) };
}

export function captureTriResearchManifest(input: unknown): TriResearchManifest {
  const row = exactRecord(input, ["schemaVersion", "milestoneId", "buildDomain", "candidateDigest", "planDigest", "researchAsOf", "currentWindowStart", "currentWindowEnd", "completedAt", "searchScopeRef", "searchScopeDigest", "searchLimitations", "sources", "claims"], "manifest");
  if (row.schemaVersion !== "keep.tri-research/v1") throw new TriResearchAdmissionError("manifest: unsupported schemaVersion");
  const sources = denseArray(row.sources, "manifest.sources", 3, MAX_SOURCES).map(captureSource);
  const claims = denseArray(row.claims, "manifest.claims", 1, MAX_CLAIMS).map(captureClaim);
  if (new Set(sources.map((source) => source.id)).size !== sources.length) throw new TriResearchAdmissionError("manifest.sources: duplicate id");
  if (new Set(claims.map((claim) => claim.id)).size !== claims.length) throw new TriResearchAdmissionError("manifest.claims: duplicate id");
  if (sources.some((source, index) => index > 0 && sources[index - 1]!.id >= source.id)) throw new TriResearchAdmissionError("manifest.sources: must be id-sorted");
  if (claims.some((claim, index) => index > 0 && claims[index - 1]!.id >= claim.id)) throw new TriResearchAdmissionError("manifest.claims: must be id-sorted");
  return {
    schemaVersion: "keep.tri-research/v1", milestoneId: identifier(row.milestoneId, "manifest.milestoneId"), buildDomain: identifier(row.buildDomain, "manifest.buildDomain"),
    candidateDigest: digest(row.candidateDigest, "manifest.candidateDigest"), planDigest: digest(row.planDigest, "manifest.planDigest"),
    researchAsOf: date(row.researchAsOf, "manifest.researchAsOf"), currentWindowStart: date(row.currentWindowStart, "manifest.currentWindowStart"), currentWindowEnd: date(row.currentWindowEnd, "manifest.currentWindowEnd"), completedAt: instant(row.completedAt, "manifest.completedAt"),
    searchScopeRef: text(row.searchScopeRef, "manifest.searchScopeRef", 4096), searchScopeDigest: digest(row.searchScopeDigest, "manifest.searchScopeDigest"), searchLimitations: stringArray(row.searchLimitations, "manifest.searchLimitations", 64), sources, claims,
  };
}

export function triResearchManifestDigest(input: TriResearchManifest): string {
  return sha256(`keep.tri-research-manifest/v1\0${canonicalize(captureTriResearchManifest(input))}`);
}

function captureReview(input: unknown): CrossFamilyResearchReview {
  const row = exactRecord(input, ["schemaVersion", "manifestDigest", "candidateDigest", "authorFamily", "reviewerFamily", "provider", "model", "sessionId", "transport", "outputTokens", "reviewedAt", "expiresAt", "verdict", "findingsDigest", "rawEvidenceDigest"], "review");
  if (row.schemaVersion !== "keep.cross-family-research-review/v1") throw new TriResearchAdmissionError("review: unsupported schemaVersion");
  if (row.transport !== "provider-first-party" && row.transport !== "operator-pinned-api") throw new TriResearchAdmissionError("review.transport: unsupported evidence transport claim");
  if (row.verdict !== "GO" && row.verdict !== "REVISE" && row.verdict !== "NO-GO") throw new TriResearchAdmissionError("review.verdict: unknown");
  if (!Number.isSafeInteger(row.outputTokens) || (row.outputTokens as number) < 1) throw new TriResearchAdmissionError("review.outputTokens: must prove nonzero execution");
  return { schemaVersion: "keep.cross-family-research-review/v1", manifestDigest: digest(row.manifestDigest, "review.manifestDigest"), candidateDigest: digest(row.candidateDigest, "review.candidateDigest"), authorFamily: identifier(row.authorFamily, "review.authorFamily"), reviewerFamily: identifier(row.reviewerFamily, "review.reviewerFamily"), provider: identifier(row.provider, "review.provider"), model: identifier(row.model, "review.model"), sessionId: identifier(row.sessionId, "review.sessionId"), transport: row.transport, outputTokens: row.outputTokens as number, reviewedAt: instant(row.reviewedAt, "review.reviewedAt"), expiresAt: instant(row.expiresAt, "review.expiresAt"), verdict: row.verdict, findingsDigest: digest(row.findingsDigest, "review.findingsDigest"), rawEvidenceDigest: digest(row.rawEvidenceDigest, "review.rawEvidenceDigest") };
}

/**
 * Evaluate whether a research package is structurally ready to be sent to a deployment-approved
 * external verifier. Even a true result is not promotion: the review fields are still untrusted
 * claims until the selected provider adapter verifies their raw carrier and mints authority.
 */
export function evaluateResearchPlanningEligibility(manifestInput: unknown, reviewInput: unknown, contextInput: unknown): ResearchPlanningEligibility {
  const reasons: string[] = [];
  let manifest: TriResearchManifest;
  let review: CrossFamilyResearchReview;
  try { manifest = captureTriResearchManifest(manifestInput); } catch (error) { return { readyForExternalVerification: false, manifestDigest: null, reasons: [(error as Error).message] }; }
  const manifestDigest = triResearchManifestDigest(manifest);
  try { review = captureReview(reviewInput); } catch (error) { return { readyForExternalVerification: false, manifestDigest, reasons: [(error as Error).message] }; }
  let context: Record<string, unknown>;
  let observedNow: string;
  let contextCandidateDigest: string;
  let contextPlanDigest: string;
  try {
    context = exactRecord(contextInput, ["candidateDigest", "planDigest", "observedNow"], "context");
    observedNow = instant(context.observedNow, "context.observedNow");
    contextCandidateDigest = digest(context.candidateDigest, "context.candidateDigest");
    contextPlanDigest = digest(context.planDigest, "context.planDigest");
  } catch (error) { return { readyForExternalVerification: false, manifestDigest, reasons: [(error as Error).message] }; }
  const observedToday = observedNow.slice(0, 10);
  if (contextCandidateDigest !== manifest.candidateDigest) reasons.push("candidate digest is not the exact researched candidate");
  if (contextPlanDigest !== manifest.planDigest) reasons.push("plan digest is not the exact researched plan");
  if (manifest.researchAsOf !== observedToday || manifest.currentWindowEnd !== observedToday) reasons.push("current research is not anchored to observer time");
  if (manifest.currentWindowStart !== minusSixCalendarMonths(observedToday)) reasons.push("current window does not cover the exact preceding six calendar months");
  const sourceIds = new Set(manifest.sources.map((source) => source.id));
  const claimIds = new Set(manifest.claims.map((claim) => claim.id));
  const current = manifest.sources.filter((source) => source.lane === "current");
  const historical = manifest.sources.filter((source) => source.lane === "historical");
  const cross = manifest.sources.filter((source) => source.lane === "cross-disciplinary");
  if (current.length === 0 || !current.some((source) => source.primary)) reasons.push("current lane lacks a retrieved primary source");
  if (current.some((source) => source.sourceDate < manifest.currentWindowStart || source.sourceDate > observedToday || source.retrievedAt.slice(0, 10) !== observedToday)) reasons.push("current lane source is outside the six-month window or was not retrieved today");
  if (historical.length === 0 || historical.some((source) => source.sourceDate >= manifest.currentWindowStart)) reasons.push("historical lane lacks genuinely pre-window evidence");
  if (cross.length === 0 || cross.some((source) => source.domain.toLowerCase() === manifest.buildDomain.toLowerCase() || source.transferMechanism === null)) reasons.push("cross-disciplinary lane lacks a foreign-domain mechanism transfer");
  const completedMs = Date.parse(manifest.completedAt);
  const observedMs = Date.parse(observedNow);
  if (manifest.completedAt.slice(0, 10) !== manifest.researchAsOf || completedMs > observedMs) reasons.push("manifest completion is not on the research date or is future-dated");
  if (manifest.sources.some((source) => Date.parse(source.retrievedAt) > completedMs)) reasons.push("a source was retrieved after manifest completion");
  for (const source of manifest.sources) {
    if (source.supports.some((id) => !claimIds.has(id))) reasons.push(`source ${source.id} references an unknown claim`);
    if (source.lane !== "cross-disciplinary" && source.transferMechanism !== null) reasons.push(`source ${source.id} carries a transfer mechanism outside the cross-disciplinary lane`);
    const reverse = manifest.claims.filter((claim) => claim.sourceIds.includes(source.id)).map((claim) => claim.id).sort();
    if (source.supports.length !== reverse.length || source.supports.some((id, index) => id !== reverse[index])) reasons.push(`source ${source.id} support edges are not bidirectionally closed`);
  }
  for (const claim of manifest.claims) {
    if (claim.sourceIds.some((id) => !sourceIds.has(id))) reasons.push(`claim ${claim.id} references an unknown source`);
    if (!claim.sourceIds.some((id) => current.some((source) => source.id === id)) || !claim.sourceIds.some((id) => historical.some((source) => source.id === id)) || !claim.sourceIds.some((id) => cross.some((source) => source.id === id))) reasons.push(`claim ${claim.id} is not supported across all three lanes`);
  }
  if (review.manifestDigest !== manifestDigest || review.candidateDigest !== manifest.candidateDigest) reasons.push("cross-family review is not bound to this manifest and candidate");
  if (review.authorFamily.toLowerCase() === review.reviewerFamily.toLowerCase()) reasons.push("reviewer is not cross-family");
  if (review.verdict !== "GO") reasons.push(`cross-family verdict is ${review.verdict}`);
  const reviewedMs = Date.parse(review.reviewedAt); const expiresMs = Date.parse(review.expiresAt);
  const maxLifetimeMs = 30 * 24 * 60 * 60 * 1000;
  if (reviewedMs < completedMs || reviewedMs > observedMs || expiresMs < observedMs || expiresMs <= reviewedMs || expiresMs - reviewedMs > maxLifetimeMs) reasons.push("review predates research, is future-dated/expired, or exceeds the 30-day structural lifetime");
  return { readyForExternalVerification: reasons.length === 0, manifestDigest, reasons };
}

export { admitGoalResearch } from "./goal_research.js";
export type { CurrentResearchIdentities, GoalResearchAdmissionResult, ResearchDenial } from "./goal_research.js";
