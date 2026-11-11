/** Scoped direct-archive consumer. Run as an unprivileged user in a fresh owned cwd. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { accessSync, constants, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

assert.notEqual(process.getuid(), 0, 'unprivileged consumer required');
const [archive, expectedSha] = process.argv.slice(2);
assert.ok(archive && /^[a-f0-9]{64}$/u.test(expectedSha ?? ''));
const sha = value => createHash('sha256').update(value).digest('hex');
assert.equal(sha(readFileSync(archive)), expectedSha, 'verify the exact archive before extraction');
const root = process.cwd(), installParent = join(root, 'fresh owner'), temp = join(root, 'temporary');
mkdirSync(installParent); mkdirSync(temp);
const env = { PATH: '/usr/bin:/bin', HOME: join(root, 'home'), TMPDIR: temp, KEEP_NODE_EXECUTABLE: process.execPath,
  GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', LANG: 'C.UTF-8' };
mkdirSync(env.HOME);
let commands = 0;
async function command(executable, args, cwd = root, expected = 0) {
  const child = spawn(executable, args, { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', b => { stdout += b; }); child.stderr.on('data', b => { stderr += b; });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  writeFileSync(join(root, `consumer-command-${commands++}.json`), JSON.stringify({ executable, args, code, stdout, stderr }), { mode: 0o600 });
  assert.equal(code, expected, stderr + stdout);
  return stdout;
}
await command('tar', ['-xzf', resolve(archive), '-C', installParent]);
const installed = join(installParent, 'keep-0.0.21-preview.1'), cli = join(installed, 'bin/keep');
accessSync(cli, constants.X_OK);
assert.equal((await command(cli, ['version'])).trim(), 'keep 0.0.21-preview.1');
assert.match(await command(cli, ['help']), /project export/u);
const packageInfo = JSON.parse(readFileSync(join(installed, 'package.json')));
assert.equal(packageInfo.version, '0.0.21-preview.1');
assert.equal(JSON.parse(readFileSync(join(installed, 'node_modules/typescript/package.json'))).version, '5.9.3');
await command(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify('file://' + join(installed, 'dist/src/index.js'))});`]);
const before = new Set(readdirSync(temp));
const demoOutput = await command(cli, ['demo', 'project']);
assert.match(demoOutput, /PASS.*Tests/u);
const demoDir = readdirSync(temp).find(name => !before.has(name) && name.startsWith('keep-project-demo-'));
assert.ok(demoDir);
const demo = JSON.parse(readFileSync(join(temp, demoDir, 'result.json')));
assert.equal(demo.status, 'PASS'); assert.equal(demo.controlledModelCalls, 2);
assert.equal(demo.proposalExport.status, 'PASS'); assert.equal(demo.proposalExport.addedModelCalls, 0);
assert.equal(demo.proposalExport.exactPatchBytes, true); assert.equal(demo.proposalExport.consoleFormLoginAttachment, true);
assert.match(await command(cli, ['demo', 'recovery']), /24 checks; 0 model calls/u);

// Reuse the demo's unchanged original repository for actual installed instance setup.
const source = join(temp, demoDir, 'source'), instance = join(root, 'owner instance');
await command(cli, ['instance', 'init', instance, '--repository=' + source, '--test-command=' + process.execPath,
  '--test-args=["--test","retry.test.mjs"]', '--test-prerequisites=[]']);
assert.match(await command(cli, ['instance', 'status', instance]), /no acknowledged worker/u);
assert.match(await command(cli, ['instance', 'prepare', instance]), /prerequisites are present/u);
const saved = JSON.parse(readFileSync(join(instance, 'instance.json')));
assert.equal(saved.schema, 'keep.instance/v1'); assert.equal(saved.environment.KEEP_PROJECT_MODEL, undefined);
let started = false;
try {
  const output = await command(cli, ['instance', 'start', instance, '--paused']); started = true;
  assert.match(output, /Dispatch: paused/u);
  const origin = /http:\/\/127\.0\.0\.1:\d+/u.exec(output)?.[0]; assert.ok(origin);
  const token = readFileSync(join(instance, 'data/gateway-token'), 'utf8').trim();
  const login = await fetch(origin + '/console/login', { method: 'POST', redirect: 'manual', headers: { origin,
    'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token }) });
  assert.equal(login.status, 303);
  const cookie = login.headers.get('set-cookie')?.split(';')[0]; assert.ok(cookie);
  const response = await fetch(origin + '/console', { headers: { cookie } });
  assert.equal(response.status, 200); const html = await response.text(); assert.ok(!html.includes(token));
  assert.match(await command(cli, ['instance', 'status', instance]), /Dispatch: paused/u);
  await command(cli, ['instance', 'stop', instance]); started = false;
  assert.match(await command(cli, ['instance', 'status', instance]), /stopped/u);
  assert.equal(readFileSync(join(source, 'src/retry.mjs'), 'utf8'), 'export const retryLimit = 0;\n');
} finally { if (started) await command(cli, ['instance', 'stop', instance]); }
const receipt = { schema: 'keep.installed-source-checkpoint/v1', status: 'PASS', uid: process.getuid(),
  version: packageInfo.version, archiveSha256: expectedSha, nodeVersion: process.version, nodeSha256: sha(readFileSync(process.execPath)),
  directArchive: true, installPathContainsSpaces: true, emptyInitialHome: true, packageImport: true,
  scriptedProjectDemo: { modelCalls: 2, paidCalls: 0, approvalBeforeDispatch: true, restartWithoutReplay: true,
    sourceUnchanged: true, exactProposalVeto: true, export: demo.proposalExport },
  recoveryDemo: { checks: 24, modelCalls: 0 }, instance: { savedSetup: true, preparedNoInstall: true, pausedStart: true,
    authenticatedConsole: true, status: true, ownedStop: true },
  limits: 'Unprivileged Linux fixture; scripted model responses and simulated decisions. Required-jail positive preparation, live account, native/full suite and broader platform remain separately qualified.' };
writeFileSync(join(root, 'qualification.json'), JSON.stringify(receipt, null, 2) + '\n', { mode: 0o600 });
console.log(JSON.stringify(receipt));
