/** Reusable account-free browser sample. Every generated response is scripted.
 * Private state and synthetic source are confined to a new caller-owned directory.
 * Uses the canonical composed runtime, real workspace edits and unchanged checker. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { composeKeep } from "../compose.js";
import { registerReviewerSample, SAMPLE_GOAL, SAMPLE_ORIGINAL } from "../review/reviewer_sample.js";
export { SAMPLE_GOAL, SAMPLE_ORIGINAL };

export interface BrowserProjectFixtureOptions {
  readonly localAppliance?: true;
  readonly resume?: boolean;
  readonly requiredJail?: { readonly executable: string; readonly nodeToolchain: string };
}

export function createBrowserProjectFixture(root: string, options: BrowserProjectFixtureOptions = {}) {
  const source = join(root, 'source'), workspaces = join(root, 'workspaces');
  if ((options.resume || options.requiredJail) && !options.localAppliance) throw new Error('Local appliance mode must be explicit');
  const marker = join(root, 'fixture.json');
  const checker = "import test from 'node:test';import assert from 'node:assert/strict';import {sum} from './calc.mjs';test('arithmetic',()=>assert.equal(sum(2,3),5));\n";
  if (!options.resume) {
    mkdirSync(source); mkdirSync(workspaces);
    writeFileSync(join(source, 'calc.mjs'), SAMPLE_ORIGINAL);
    writeFileSync(join(source, 'repo.test.mjs'), checker);
  }
  const git = (...args: string[]) => execFileSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgSign=false', ...args], {
    cwd: source, encoding: 'utf8', timeout: 5000, env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_AUTHOR_NAME: 'Browser Fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'Browser Fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
  }).trim();
  if (!options.resume) {
    git('init', '-q', '-b', 'main'); git('add', '-A'); git('commit', '-qm', 'scripted browser sample');
  }
  const baseRevision = git('rev-parse', 'HEAD');
  if (options.localAppliance) {
    if (!options.resume) writeFileSync(marker, JSON.stringify({ version: 1, baseRevision }) + '\n', { flag: 'wx', mode: 0o600 });
    const saved = JSON.parse(readFileSync(marker, 'utf8')) as { version: number; baseRevision: string };
    assert.equal(saved.version, 1); assert.match(saved.baseRevision, /^[0-9a-f]{40}$/u);
    assert.equal(baseRevision, saved.baseRevision, 'sample source revision changed; inspect retained state');
    assert.equal(git('status', '--porcelain'), '', 'sample source changed; inspect retained state');
    assert.equal(readFileSync(join(source, 'calc.mjs'), 'utf8'), SAMPLE_ORIGINAL);
    assert.equal(readFileSync(join(source, 'repo.test.mjs'), 'utf8'), checker);
  }
  // Retained jobs/checkpoints own recovery; no separate counter authorizes replay.
  let generations = 0;
  const app = composeKeep({ dataDir: join(root, 'state'), sourceLanding: true, projectPosture: 'approval-required',
    repositoryMaterialization: { sourceDir: source, workspaceBase: workspaces, repoRef: 'project', commit: baseRevision, baseBranch: 'main' },
    testCommand: { command: process.execPath, args: ['--test', 'repo.test.mjs'], timeoutMs: options.requiredJail ? 600_000 : 5000,
      ...(options.requiredJail ? { namespaceJail: 'required' as const, jailExecutable: options.requiredJail.executable,
        readOnlyPaths: [options.requiredJail.nodeToolchain], allowNet: false, envAllowlist: [], cpuLimitSec: 600, maxOutputBytes: 8 * 1024 * 1024 } : {}) },
    developmentProvider: { name: 'scripted-browser-sample', isLocal: true, embed: async () => [], generate: async request => {
      generations++; assert.ok(generations <= 2, 'sample allows exactly the two scripted responses; no hidden model retries');
      const value = request.hints?.taskRole === 'goal_test'
        ? { body: "const {pathToFileURL}=await import('node:url');const {join}=await import('node:path');const {sum}=await import(pathToFileURL(join(process.cwd(),'calc.mjs')));assert.equal(sum(2,3),5);" }
        : { action: 'plan', rationale: 'arithmetic correction', edits: [{ file: 'calc.mjs', search: 'a-b', replace: 'a+b', intent: 'add operands' }] };
      return { text: JSON.stringify(value), model: 'scripted-browser-sample', tokensIn: 1, tokensOut: 1 };
    } } });
  registerReviewerSample(app);
  return { app, source, workspaces, baseRevision, generations: () => generations };
}
