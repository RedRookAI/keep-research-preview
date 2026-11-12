/** Actual Chromium consumer: submit → approval → real checks/diff → exact veto → download.
 * Run after TypeScript emit. Requires an existing Playwright driver and browser.
 * node acceptance/browser_project.mjs OUTPUT_DIR ABSOLUTE_PLAYWRIGHT_ENTRY [BROWSER_EXECUTABLE]
 * No dependency/browser installation, paid model, shared services or hosted exposure. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { startGatewayServer } from '../dist/src/gateway/http_gateway.js';
import { verifyProposalExport } from '../dist/src/audit/proposal_export.js';
import { SAMPLE_NOTICE } from '../dist/src/review/reviewer_sample.js';
import { createBrowserProjectFixture, SAMPLE_GOAL, SAMPLE_ORIGINAL } from './browser_project_fixture.mjs';

const [outputArg, driver, executablePath, mode] = process.argv.slice(2);
const sampleMode = mode === '--sample';
assert.ok(outputArg && driver, 'output directory and existing Playwright entry required');
const root = resolve(outputArg); mkdirSync(root, { recursive: true });
const { chromium } = await import(pathToFileURL(resolve(driver)).href);
const fixture = createBrowserProjectFixture(root), token = randomBytes(32).toString('hex');
const server = await startGatewayServer(fixture.app, { port: 0, token, ...(sampleMode ? { reviewerSample: true } : {}) });
let browser, page;
const stages = [];
try {
  browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}), args: ['--mute-audio'] });
  const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1365, height: 1000 } });
  page = await context.newPage();
  const sampleNotice = async () => { if (sampleMode) assert.equal(await page.getByText(SAMPLE_NOTICE, { exact: true }).count(), 1); };
  await page.goto(server.origin + '/console');
  await sampleNotice();
  await page.getByLabel('Instance credential').fill(token);
  await page.getByRole('button', { name: 'Open console' }).click();
  assert.equal(await page.locator('.project').count(), 0);
  await page.getByRole('link', { name: 'Submit a repository goal' }).click();
  await sampleNotice();
  const formUrl = page.url(), key = await page.locator('[name=idempotencyKey]').inputValue();
  await page.reload(); assert.equal(await page.locator('[name=idempotencyKey]').inputValue(), key);
  assert.equal(fixture.app.projectManager.list().length, 0); assert.equal(fixture.generations(), 0);
  if (sampleMode) assert.equal(await page.getByLabel('Repository goal').inputValue(), SAMPLE_GOAL);
  else await page.getByLabel('Repository goal').fill(SAMPLE_GOAL);
  await page.getByRole('button', { name: 'Submit goal', exact: true }).click();
  await page.waitForURL('**/console/project?projectId=*');
  const projectUrl = page.url(), projectId = new URL(projectUrl).searchParams.get('projectId');
  stages.push('browser-form-submitted');
  // Wait only for actual asynchronous state; bounded polling never submits a new goal.
  for (let attempt = 0; attempt < 100; attempt++) {
    await page.reload();
    if (await page.getByRole('button', { name: 'Approve this step', exact: true }).count()) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal(fixture.generations(), 0, 'approval gate precedes generation');
  await page.screenshot({ path: join(root, '01-approval.png'), fullPage: true });
  await page.getByRole('button', { name: 'Approve this step', exact: true }).click();
  await page.getByRole('link', { name: 'Open updated project' }).click();
  // Some retained policy steps may require separate approval. Each is an explicit browser action.
  for (let attempt = 0; attempt < 100; attempt++) {
    await page.reload();
    if (await page.getByRole('button', { name: 'Veto proposal', exact: true }).count()) break;
    if (await page.getByRole('button', { name: 'Approve this step', exact: true }).count()) {
      await page.getByRole('button', { name: 'Approve this step', exact: true }).click();
      await page.getByRole('link', { name: 'Open updated project' }).click();
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.match(await page.locator('.diff').innerText(), /\+export const sum = \(a,b\) => a\+b;/);
  assert.match(await page.locator('body').innerText(), /Tests passed/);
  const digest = await page.locator('[name=proposalDigest]').inputValue();
  const runId = await page.locator('form[action="/console/merge"] [name=runId]').inputValue();
  assert.equal(fixture.generations(), 2);
  const checkpoint = fixture.app.projectManager.session(projectId).inspect().checkpoint;
  const checks = checkpoint.artifacts.implement.solve.proposalEvidence.checks;
  assert.equal(checks.testsPassed, true); assert.equal(checks.vettingCleared, true);
  assert.deepEqual(checks.passedTests, ['arithmetic', 'goal: requested outcome']);
  await sampleNotice();
  stages.push('real-workspace-diff-and-two-unchanged-checks');
  await page.screenshot({ path: join(root, '02-checked-proposal.png'), fullPage: true });
  const retainedBefore = fixture.app.projectRuntime.retainedJobs(new Set([projectId])).map(job => job.id).sort();
  assert.ok(retainedBefore.includes(runId), 'original submission job is retained');
  // The same retained form recovers the accepted job, including after navigating away.
  await page.goto(sampleMode ? server.origin + '/console/new' : formUrl); if (sampleMode) assert.equal(await page.getByLabel('Repository goal').inputValue(), SAMPLE_GOAL);
  else await page.getByLabel('Repository goal').fill(SAMPLE_GOAL);
  await page.getByRole('button', { name: 'Submit goal', exact: true }).click();
  assert.equal(page.url(), projectUrl); assert.equal(fixture.app.projectManager.list().length, 1);
  assert.deepEqual(fixture.app.projectRuntime.retainedJobs(new Set([projectId])).map(job => job.id).sort(), retainedBefore, 'recovery creates no additional job; explicit step resume has its own job'); assert.equal(fixture.generations(), 2);
  stages.push('submission-recovery-no-new-job');
  await page.getByRole('button', { name: 'Veto proposal', exact: true }).click();
  await sampleNotice();
  assert.match(await page.locator('main').innerText(), /refused|veto/i);
  await page.getByRole('link', { name: 'Open updated project' }).click();
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Download proposal evidence' }).click();
  const download = await downloadEvent; await download.saveAs(join(root, 'proposal.json'));
  const exported = readFileSync(join(root, 'proposal.json'), 'utf8'), bundle = verifyProposalExport(exported);
  assert.equal(bundle.data.proposal.patchSha256, digest); assert.equal(bundle.data.runId, runId);
  assert.equal(bundle.data.proposal.baseRevision, fixture.baseRevision);
  assert.ok(bundle.data.decisions.some(decision => decision.decision === 'veto' && decision.proposalDigest === digest));
  assert.equal(readFileSync(join(fixture.source, 'calc.mjs'), 'utf8'), SAMPLE_ORIGINAL);
  assert.equal(readFileSync(join(fixture.workspaces, 'project/calc.mjs'), 'utf8'), 'export const sum = (a,b) => a+b;\n');
  assert.equal(fixture.generations(), 2); assert.ok(!exported.includes(token));
  const html = await page.content(); assert.ok(!html.includes(token));
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  await sampleNotice();
  stages.push('exact-proposal-veto-and-browser-export');
  await page.screenshot({ path: join(root, '03-vetoed-export.png'), fullPage: true });
  writeFileSync(join(root, 'result.json'), JSON.stringify({ status: 'PASS', scripted: true, enforcedSample: sampleMode, paidCalls: 0, browser: browser.version(), node: process.version,
    sourceRevision: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), stages, projectId, runId, proposalDigest: digest,
    fixtureBaseRevision: fixture.baseRevision, retainedJobCount: retainedBefore.length, originalSubmissionJobId: runId, generations: fixture.generations(), checks, sourceUnchanged: true, exported: true }, null, 2));
  process.stdout.write(JSON.stringify({ status: 'PASS', stages, generations: fixture.generations(), projectId, runId }) + '\n');
} catch (error) {
  if (page) { await page.screenshot({ path: join(root, 'failure.png'), fullPage: true }).catch(() => {}); writeFileSync(join(root, 'failure.html'), await page.content().catch(() => 'unavailable')); }
  writeFileSync(join(root, 'failure.json'), JSON.stringify({ stages, message: String(error), stack: error.stack }, null, 2));
  throw error;
} finally { await browser?.close(); await server.close(); }
