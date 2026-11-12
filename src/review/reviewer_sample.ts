/** Trusted fixture registration, never decoded from HTTP input. This records
 * assembly provenance only; the gateway still enforces every public request. */
import type { KeepApp } from "../compose.js";
export const SAMPLE_FILE = "webhook.mjs";
export const SAMPLE_CHECK_FILE = "webhook.test.mjs";
export const SAMPLE_GOAL = "In repository code, delivery IDs should prevent the same webhook event from increasing the count twice. Record each ID before counting it. Preserve distinct deliveries and all other files.";
export const SAMPLE_ORIGINAL = `export function createState() { return { processed: new Set(), count: 0 }; }
export function recordDelivery(state, deliveryId) {
  if (state.processed.has(deliveryId)) return state.count;
  state.count += 1;
  return state.count;
}
`;
export const SAMPLE_FIXED = SAMPLE_ORIGINAL.replace("  state.count += 1;", "  state.processed.add(deliveryId);\n  state.count += 1;");
export const SAMPLE_CHECK_NAMES = ["first delivery counts once", "duplicate delivery ID is ignored", "distinct delivery IDs still count"] as const;
export const SAMPLE_CHECKER = `import test from 'node:test';
import assert from 'node:assert/strict';
import {createState,recordDelivery} from './${SAMPLE_FILE}';
test('${SAMPLE_CHECK_NAMES[0]}',()=>{const state=createState();assert.equal(recordDelivery(state,'delivery-a'),1);assert.equal(state.count,1);});
test('${SAMPLE_CHECK_NAMES[1]}',()=>{const state=createState();recordDelivery(state,'delivery-a');assert.equal(recordDelivery(state,'delivery-a'),1);assert.equal(state.count,1);});
test('${SAMPLE_CHECK_NAMES[2]}',()=>{const state=createState();recordDelivery(state,'delivery-a');assert.equal(recordDelivery(state,'delivery-b'),2);assert.equal(state.count,2);});
`;
export const SAMPLE_GOAL_TEST = "const {pathToFileURL}=await import('node:url');const {join}=await import('node:path');const {createState,recordDelivery}=await import(pathToFileURL(join(process.cwd(),'" + SAMPLE_FILE + "')));const state=createState();recordDelivery(state,'event-17');recordDelivery(state,'event-17');assert.equal(state.count,1);recordDelivery(state,'event-18');assert.equal(state.count,2);recordDelivery(state,'event-17');assert.equal(state.count,2);";
export const SAMPLE_NOTICE = "This demo uses two scripted responses. Keep edits the workspace and runs the checks.";
export const SAMPLE_SUBMISSION_KEY = "keep.reviewer.sample.v1";
const fixtures = new WeakMap<KeepApp, { readonly localWorkspaceOnly?: true }>();
/** Called only by the controlled sample composition factory, not a request handler. */
export function registerReviewerSample(app: KeepApp, options: { readonly localWorkspaceOnly?: true } = {}): void { fixtures.set(app, options); }
export function isReviewerSample(app: KeepApp): boolean { return fixtures.has(app); }
export function reviewerSampleNotice(app: KeepApp): string {
  return fixtures.get(app)?.localWorkspaceOnly
    ? SAMPLE_NOTICE + ' Approval retains the reviewed workspace. The source repository stays unchanged.'
    : SAMPLE_NOTICE;
}

export function reviewerSampleWorkspaceOnly(app: KeepApp): boolean { return fixtures.get(app)?.localWorkspaceOnly === true; }
export const SAMPLE_CONTRACT = {
  goal: SAMPLE_GOAL,
  sourceFiles: { [SAMPLE_FILE]: SAMPLE_ORIGINAL, [SAMPLE_CHECK_FILE]: SAMPLE_CHECKER },
  expectedFiles: { [SAMPLE_FILE]: SAMPLE_FIXED, [SAMPLE_CHECK_FILE]: SAMPLE_CHECKER },
  passedTests: [...SAMPLE_CHECK_NAMES, "goal: requested outcome"],
};
