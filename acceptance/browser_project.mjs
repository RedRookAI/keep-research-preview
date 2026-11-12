/** Real Chromium consumer of the prepared fixture. Existing driver/browser required.
 * node acceptance/browser_project.mjs NEW_OUTPUT_DIR PLAYWRIGHT_ENTRY BROWSER_EXECUTABLE [--sample]
 * Scripted generation, deliberate owner decisions, real edits/checks, no paid calls. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { startGatewayServer } from '../dist/src/gateway/http_gateway.js';
import { verifyProposalExport } from '../dist/src/audit/proposal_export.js';
import { SAMPLE_NOTICE, SAMPLE_CONTRACT } from '../dist/src/review/reviewer_sample.js';
import { createBrowserProjectFixture } from './browser_project_fixture.mjs';

const [outputArg, driver, executablePath, mode] = process.argv.slice(2), sampleMode = mode === '--sample';
assert.ok(outputArg && driver, 'output directory and existing Playwright entry required');
const root = resolve(outputArg); mkdirSync(root, { recursive: true });
const { chromium } = await import(pathToFileURL(resolve(driver)).href);
const fixture = createBrowserProjectFixture(root), token = randomBytes(32).toString('hex');
const server = await startGatewayServer(fixture.app, { port: 0, token, ...(sampleMode ? { reviewerSample: true } : {}) });
let browser, page; const stages = [];
try {
  browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}), args: ['--mute-audio'] });
  const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1365, height: 1000 } });
  page = await context.newPage();
  const notice = async () => { if (sampleMode) assert.equal(await page.getByText(SAMPLE_NOTICE, { exact: true }).count(), 1); };
  await page.goto(server.origin + '/console'); await notice();
  await page.getByLabel(sampleMode ? 'Invitation credential' : 'Instance credential').fill(token);
  await page.getByRole('button', { name: sampleMode ? 'Open demo' : 'Open console', exact: true }).click();
  if (!sampleMode) await page.getByRole('link', { name: 'Submit a repository goal' }).click();
  await notice();
  const formUrl = page.url(), key = await page.locator('[name=idempotencyKey]').inputValue();
  await page.reload(); assert.equal(await page.locator('[name=idempotencyKey]').inputValue(), key);
  assert.equal(fixture.app.projectManager.list().length, 0); assert.equal(fixture.generations(), 0);
  if (sampleMode) {
    assert.match(await page.locator('main').innerText(), /Count each delivery once/);
    assert.equal(await page.locator('textarea').count(), 0);
    assert.equal(await page.locator('[name=goal]').inputValue(), SAMPLE_CONTRACT.goal);
    await page.screenshot({ path: join(root, '00-start.png'), fullPage: true });
  } else await page.getByLabel('Repository goal').fill(SAMPLE_CONTRACT.goal);
  await page.getByRole('button', { name: sampleMode ? 'Start demo' : 'Submit goal', exact: true }).click();
  await page.waitForURL('**/console/project?projectId=*');
  const projectUrl = page.url(), projectId = new URL(projectUrl).searchParams.get('projectId');
  stages.push('deliberate-start');
  const preparation = sampleMode ? 'Prepare the fix' : 'Approve this step';
  for (let attempt = 0; attempt < 100; attempt++) {
    await page.reload();
    if (await page.getByRole('button', { name: preparation, exact: true }).count()) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal(fixture.generations(), 0, 'actual approval gate precedes generation');
  if (sampleMode) assert.match(await page.locator('main').innerText(), /waiting for your approval/);
  await page.screenshot({ path: join(root, '01-approval.png'), fullPage: true });
  await page.getByRole('button', { name: preparation, exact: true }).click();
  if (!sampleMode) await page.getByRole('link', { name: 'Open updated project' }).click();
  else assert.equal(page.url(), projectUrl, 'preparation returns directly to the actual task');
  for (let attempt = 0; attempt < 100; attempt++) {
    await page.reload();
    if (await page.locator('form[action="/console/merge"]').count()) break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  if (sampleMode) await page.getByText('Inspect the code change', { exact: true }).click();
  assert.match(await page.locator('.diff').innerText(), /\+  state\.processed\.add\(deliveryId\);/);
  const digest = await page.locator('[name=proposalDigest]').inputValue();
  const runId = await page.locator('form[action="/console/merge"] [name=runId]').inputValue();
  const checkpoint = fixture.app.projectManager.session(projectId).inspect().checkpoint;
  const checks = checkpoint.artifacts.implement.solve.proposalEvidence.checks;
  assert.equal(checks.testsPassed, true); assert.equal(checks.vettingCleared, true);
  assert.deepEqual(checks.passedTests, SAMPLE_CONTRACT.passedTests); assert.equal(fixture.generations(), 2);
  if (sampleMode) {
    assert.match(await page.locator('main').innerText(), /Review the checked change/);
    assert.equal(await page.locator('.demo-checks strong').allTextContents().then(values => values.filter(value => value === 'Passed').length), 4);
  }
  await notice(); stages.push('real-webhook-fix-and-four-checks');
  await page.screenshot({ path: join(root, '02-checked-proposal.png'), fullPage: true });
  const retainedBefore = fixture.app.projectRuntime.retainedJobs(new Set([projectId])).map(job => job.id).sort();
  assert.ok(retainedBefore.includes(runId));
  await page.goto(sampleMode ? server.origin + '/console/new?submissionKey=fresh-guided-form-1234' : formUrl);
  if (sampleMode) {
    await page.getByText('Recover the existing submission', { exact: true }).click();
    await page.getByRole('button', { name: 'Recover demo', exact: true }).click();
  } else {
    await page.getByLabel('Repository goal').fill(SAMPLE_CONTRACT.goal);
    await page.getByRole('button', { name: 'Submit goal', exact: true }).click();
  }
  assert.equal(page.url(), projectUrl); assert.equal(fixture.app.projectManager.list().length, 1);
  assert.deepEqual(fixture.app.projectRuntime.retainedJobs(new Set([projectId])).map(job => job.id).sort(), retainedBefore);
  assert.equal(fixture.generations(), 2); stages.push('fresh-form-recovery-no-new-job');
  await page.getByRole('button', { name: sampleMode ? 'Veto this proposal' : 'Veto proposal', exact: true }).click();
  await notice();
  if (sampleMode) assert.match(await page.locator('h1').innerText(), /Proposal vetoed/);
  else await page.getByRole('link', { name: 'Open updated project' }).click();
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('link', { name: sampleMode ? 'Download evidence' : 'Download proposal evidence', exact: true }).click();
  const download = await downloadEvent; await download.saveAs(join(root, 'proposal.json'));
  const exported = readFileSync(join(root, 'proposal.json'), 'utf8'), bundle = verifyProposalExport(exported);
  assert.equal(bundle.data.proposal.patchSha256, digest); assert.equal(bundle.data.runId, runId);
  assert.equal(bundle.data.proposal.baseRevision, fixture.baseRevision);
  assert.ok(bundle.data.decisions.some(decision => decision.decision === 'veto' && decision.proposalDigest === digest));
  for (const [file, bytes] of Object.entries(SAMPLE_CONTRACT.sourceFiles)) assert.equal(readFileSync(join(fixture.source, file), 'utf8'), bytes);
  for (const [file, bytes] of Object.entries(SAMPLE_CONTRACT.expectedFiles)) assert.equal(readFileSync(join(fixture.workspaces, 'project', file), 'utf8'), bytes);
  assert.equal(fixture.generations(), 2); assert.ok(!exported.includes(token)); assert.ok(!(await page.content()).includes(token));
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  await notice(); stages.push('exact-veto-and-browser-evidence-download');
  await page.screenshot({ path: join(root, '03-vetoed-export.png'), fullPage: true });
  writeFileSync(join(root, 'result.json'), JSON.stringify({ status: 'PASS', scripted: true, enforcedSample: sampleMode, paidCalls: 0,
    browser: browser.version(), node: process.version, sourceRevision: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    stages, projectId, runId, proposalDigest: digest, fixtureBaseRevision: fixture.baseRevision, retainedJobCount: retainedBefore.length,
    originalSubmissionJobId: runId, generations: fixture.generations(), checks, sourceUnchanged: true, exported: true }, null, 2));
  process.stdout.write(JSON.stringify({ status: 'PASS', stages, generations: fixture.generations(), projectId, runId }) + '\n');
} catch (error) {
  if (page) { await page.screenshot({ path: join(root, 'failure.png'), fullPage: true }).catch(() => {}); writeFileSync(join(root, 'failure.html'), await page.content().catch(() => 'unavailable')); }
  writeFileSync(join(root, 'failure.json'), JSON.stringify({ stages, message: String(error), stack: error.stack }, null, 2)); throw error;
} finally { await browser?.close(); await server.close(); }
