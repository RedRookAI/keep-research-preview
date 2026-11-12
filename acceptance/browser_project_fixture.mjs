/** Reusable account-free browser sample. Every generated response is scripted.
 * Private state and synthetic source are confined to a new caller-owned directory.
 * Uses the canonical composed runtime, real workspace edits and unchanged checker. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { composeKeep } from '../dist/src/compose.js';

export const SAMPLE_GOAL = 'In repository code, the sum function in calc.mjs should return the arithmetic sum of its two numeric operands. Preserve all other files.';
export const SAMPLE_ORIGINAL = 'export const sum = (a,b) => a-b;\n';
export function createBrowserProjectFixture(root) {
  const source = join(root, 'source'), workspaces = join(root, 'workspaces');
  mkdirSync(source); mkdirSync(workspaces);
  writeFileSync(join(source, 'calc.mjs'), SAMPLE_ORIGINAL);
  writeFileSync(join(source, 'repo.test.mjs'), "import test from 'node:test';import assert from 'node:assert/strict';import {sum} from './calc.mjs';test('arithmetic',()=>assert.equal(sum(2,3),5));\n");
  const git = (...args) => execFileSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgSign=false', ...args], {
    cwd: source, encoding: 'utf8', timeout: 5000, env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_AUTHOR_NAME: 'Browser Fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'Browser Fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
  }).trim();
  git('init', '-q', '-b', 'main'); git('add', '-A'); git('commit', '-qm', 'scripted browser sample');
  const baseRevision = git('rev-parse', 'HEAD'); let generations = 0;
  const app = composeKeep({ dataDir: join(root, 'state'), sourceLanding: true, projectPosture: 'approval-required',
    repositoryMaterialization: { sourceDir: source, workspaceBase: workspaces, repoRef: 'project', commit: baseRevision, baseBranch: 'main' },
    testCommand: { command: process.execPath, args: ['--test', 'repo.test.mjs'], timeoutMs: 5000 },
    developmentProvider: { name: 'scripted-browser-sample', isLocal: true, embed: async () => [], generate: async request => {
      generations++; assert.ok(generations <= 2, 'sample allows exactly the two scripted responses; no hidden model retries');
      const value = request.hints?.taskRole === 'goal_test'
        ? { body: "const {pathToFileURL}=await import('node:url');const {join}=await import('node:path');const {sum}=await import(pathToFileURL(join(process.cwd(),'calc.mjs')));assert.equal(sum(2,3),5);" }
        : { action: 'plan', rationale: 'arithmetic correction', edits: [{ file: 'calc.mjs', search: 'a-b', replace: 'a+b', intent: 'add operands' }] };
      return { text: JSON.stringify(value), model: 'scripted-browser-sample', tokensIn: 1, tokensOut: 1 };
    } } });
  return { app, source, workspaces, baseRevision, generations: () => generations };
}
