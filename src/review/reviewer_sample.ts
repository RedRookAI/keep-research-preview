/** Trusted fixture registration, never decoded from HTTP input. This records
 * assembly provenance only; the gateway still enforces every public request. */
import type { KeepApp } from "../compose.js";
export const SAMPLE_GOAL = "In repository code, the sum function in calc.mjs should return the arithmetic sum of its two numeric operands. Preserve all other files.";
export const SAMPLE_ORIGINAL = "export const sum = (a,b) => a-b;\n";
export const SAMPLE_NOTICE = "Sample task · two scripted responses · real workspace edits and checks · no AI account or paid calls.";
export const SAMPLE_SUBMISSION_KEY = "keep.reviewer.sample.v1";
const fixtures = new WeakSet<KeepApp>();
/** Called only by the controlled sample composition factory, not a request handler. */
export function registerReviewerSample(app: KeepApp): void { fixtures.add(app); }
export function isReviewerSample(app: KeepApp): boolean { return fixtures.has(app); }
