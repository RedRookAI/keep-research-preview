#!/usr/bin/env node
/** Constructed preparation acceptance fixture; no claim about model-generated work.
 * Usage: node independent-preparation.mjs <extracted-keep> <node-root> <qualified-bwrap> <NEW-work-directory>
 * Run as an unprivileged owner on supported Linux x64. Node root must contain
 * bin/node and lib/node_modules/npm/bin/npm-cli.js. Keep/toolchain/helper must be
 * protected readonly inputs, disjoint from the fresh work directory. No checkout,
 * maintainer cache or fixtures required. Retains work/receipt.json and failures.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

// Match .21 CLI runtime defaults, rather than introduce a new validation budget.
const timeoutMs = 600_000, cpuLimitSec = 600, maxOutputBytes = 8 * 1024 * 1024;
const tarball = 'https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz';
const integrity = 'sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw==';
const sha256 = data => createHash('sha256').update(data).digest('hex');
const digestFile = path => sha256(readFileSync(path));
let stage = 'inputs', root, sequence = 0;
const observations = [];
function save(name, value) { writeFileSync(join(root, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 }); }
try {
  assert.equal(process.argv.length, 7, 'expected extracted Keep, Node root, qualified helper, NEW work directory');
  assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
  assert.ok(process.getuid() !== 0, 'run acceptance as an unprivileged owner');
  const installed = realpathSync(resolve(process.argv[2])), toolchain = realpathSync(resolve(process.argv[3]));
  const helper = realpathSync(resolve(process.argv[4]));
  const requested = resolve(process.argv[5]);
  assert.equal(existsSync(requested), false, 'work directory must be new; preserve prior observations');
  root = join(realpathSync(dirname(requested)), requested.slice(dirname(requested).length + 1));
  const within = (a, b) => { const rel = relative(a, b); return rel === '' || (rel !== '..' && !rel.startsWith('..' + sep) && !rel.startsWith(sep)); };
  for (const input of [installed, toolchain, helper]) assert.ok(!within(root, input) && !within(input, root), 'inputs and writable work must be disjoint');
  mkdirSync(root, { mode: 0o700 });
  const source = join(root, 'source'), instance = join(root, 'instance'), home = join(root, 'home'), temp = join(root, 'tmp');
  for (const directory of [source, home, temp]) mkdirSync(directory, { mode: 0o700 });
  const node = realpathSync(join(toolchain, 'bin/node'));
  const npmCli = realpathSync(join(toolchain, 'lib/node_modules/npm/bin/npm-cli.js'));
  assert.ok(within(toolchain, node) && within(toolchain, npmCli), 'Node/npm must remain inside selected root');
  const env = { PATH: `${join(toolchain, 'bin')}:/usr/bin:/bin`, HOME: home, TMPDIR: temp, LANG: 'C.UTF-8',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' };
  // SDK process execution sees the same credential-free environment as CLI calls.
  for (const key of Object.keys(process.env)) delete process.env[key];
  Object.assign(process.env, env);
  function command(executable, args, cwd = root, expected = 0) {
    const result = spawnSync(executable, args, { cwd, env, encoding: 'utf8', timeout: timeoutMs, maxBuffer: maxOutputBytes });
    const observation = { sequence: sequence++, status: result.status, signal: result.signal, error: result.error?.message,
      executable, args, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
    save(`command-${observation.sequence}.json`, observation);
    observations.push({ sequence: observation.sequence, stage, status: observation.status });
    assert.equal(result.error, undefined, `command failed to complete at ${stage}`);
    assert.equal(result.status, expected, `${stage}: ${(observation.stderr + observation.stdout).slice(-4096)}`);
    return observation.stdout;
  }
  const pkg = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
  assert.equal(pkg.version, '0.0.22-preview.1');
  const expectation=process.argv[6]; assert.ok(['success','preflight-refusal'].includes(expectation));
  assert.equal(pkg.exports['.'], './dist/src/index.js', 'use published root SDK export');
  const cli = join(installed, 'dist/src/main.js');
  const nodeVersion = command(node, ['--version']).trim();
  const version = /^v(\d+)\.(\d+)\.(\d+)$/u.exec(nodeVersion);
  assert.ok(version && Number(version[1]) === 22 && (Number(version[2]) > 23 || (Number(version[2]) === 23 && Number(version[3]) >= 3)), 'published Node >=22.23.3 <23 contract');
  const { SandboxedCommandRunner } = await import(pathToFileURL(join(installed, pkg.exports['.'])));
  const packageJson = { name: 'keep-offline-readiness-fixture', version: '1.0.0', private: true, dependencies: { typescript: '5.9.3' },
    scripts: { install: 'node -e "require(\'fs\').writeFileSync(\'lifecycle-ran\',\'unexpected\')"' } };
  const dependency = { version: '5.9.3', resolved: tarball, integrity, license: 'Apache-2.0', bin: { tsc: 'bin/tsc', tsserver: 'bin/tsserver' }, engines: { node: '>=14.17' } };
  const files = {
    'package.json': JSON.stringify(packageJson, null, 2) + '\n',
    'package-lock.json': JSON.stringify({ name: packageJson.name, version: packageJson.version, lockfileVersion: 3, requires: true,
      packages: { '': { name: packageJson.name, version: packageJson.version, dependencies: packageJson.dependencies }, 'node_modules/typescript': dependency } }, null, 2) + '\n',
    '.gitignore': 'node_modules/\n.keep-preparation-cache/\n',
    'check.cjs': `const test=require('node:test'),assert=require('node:assert/strict');
test('prepared TypeScript transpiles the configured input',()=>{
 const ts=require('typescript'); assert.equal(ts.version,'5.9.3');
 const result=ts.transpileModule('const value: number = 7;',{compilerOptions:{target:ts.ScriptTarget.ES2020}});
 assert.equal(result.outputText,'const value = 7;\\n'); assert.equal(result.diagnostics.length,0);
});\n`,
  };
  stage = 'source-fixture';
  for (const [name, text] of Object.entries(files)) writeFileSync(join(source, name), text, { flag: 'wx' });
  const git = args => command('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgSign=false', ...args], source).trim();
  git(['init', '-q', '-b', 'main']); git(['add', '.']);
  git(['-c', 'user.name=Keep Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'independent offline readiness fixture']);
  const revision = git(['rev-parse', 'HEAD']);
  const before = Object.fromEntries(Object.keys(files).map(name => [name, digestFile(join(source, name))]));
  stage = 'instance-init';
  command(node, [cli, 'instance', 'init', instance, `--repository=${source}`, `--test-command=${node}`,
    '--test-args=["--test","--test-reporter=tap","check.cjs"]', '--test-prerequisites=["node_modules/typescript/package.json"]',
    '--workspace-preparation=npm-offline', `--workspace-toolchain=${toolchain}`, '--test-namespace-jail=required', `--test-jail-executable=${helper}`]);
  const profile = JSON.parse(readFileSync(join(instance, 'instance.json'), 'utf8')).environment;
  assert.equal(profile.KEEP_WORKSPACE_PREPARATION, 'npm-offline'); assert.equal(profile.KEEP_WORKSPACE_TOOLCHAIN, toolchain);
  assert.equal(profile.KEEP_TEST_NAMESPACE_JAIL, 'required'); assert.equal(profile.KEEP_TEST_JAIL_EXECUTABLE, helper);
  assert.equal(profile.KEEP_TEST_COMMAND, node); assert.equal(profile.KEEP_REVISION, revision);
  assert.deepEqual(JSON.parse(profile.KEEP_TEST_ARGS_JSON), ['--test', '--test-reporter=tap', 'check.cjs']);
  stage = 'actual-empty-cache-prepare';
  const first = command(node, [cli, 'instance', 'prepare', instance], root, 1);
  assert.match(first, /Offline workspace preparation held/u);
  const workspace = join(instance, 'workspaces/project'), hold = join(workspace, '.git/keep-preparation-hold.json');
  const cache = join(workspace, '.keep-preparation-cache');
  assert.equal(existsSync(hold), true); assert.equal(existsSync(join(workspace, 'node_modules/typescript/package.json')), false);
  if (expectation === 'preflight-refusal') {
    assert.match(first, /required sandbox preflight failed/u);
    assert.match(first, /npm was not launched/u);
    assert.match(first, /AppArmor or container policy/u);
    assert.equal(existsSync(cache), false, 'npm was not launched or seeded');
    assert.equal(readdirSync(join(workspace, '.git')).some(name=>name.startsWith('keep-preparation-npmrc-')), false);
    assert.equal(git(['rev-parse', 'HEAD']), revision); assert.equal(git(['status', '--porcelain']), '');
    for (const [name, hash] of Object.entries(before)) assert.equal(digestFile(join(source, name)), hash);
    for (const name of ['current-worker.json','startup-pending.json']) assert.equal(existsSync(join(instance,name)), false);
    const receipt={status:'PASS_SOURCE_PREFLIGHT_REFUSAL',version:pkg.version,npmStarted:false,cacheSeeded:false,holdRetained:true,sourceUnchanged:true,hostPolicyChanged:false,modelCalls:0,cliDiagnostic:first,observations};
    save('receipt.json',receipt); process.stdout.write(JSON.stringify(receipt)+'\n');
  } else {
  const logDirectory = join(cache, '_logs');
  const logs = existsSync(logDirectory) ? readdirSync(logDirectory).filter(name => name.endsWith('.log')).map(name => readFileSync(join(logDirectory, name), 'utf8')) : [];
  if (!logs.some(text => /ENOTCACHED/u.test(text))) {
    save('unconfirmed-preparation-refusal.json', { classification: 'preparation-held-without-confirmed-npm-cache-miss',
      npmLogDirectoryPresent: existsSync(logDirectory), npmLogFiles: logs.length, holdRetained: existsSync(hold), cliOutput: first,
      prerequisitePreflightPassed: true, nextAction: 'Inspect retained CLI command and preflight outcomes; cache seeding not attempted.' });
    throw new Error('UNCONFIRMED_PREPARATION_REFUSAL: prepare held without npm ENOTCACHED evidence; this is an unresolved setup/runner/preparation failure, not a confirmed cache miss. Inspect unconfirmed-preparation-refusal.json and required-jail-preflight.json.');
  }
  save('empty-cache-refusal.json', { expected: true, actualNpmEnotcached: true, holdRetained: true });
  stage = 'public-registry-cache-seed';
  const seedConfig = join(root, 'seed-config'); mkdirSync(seedConfig, { mode: 0o700 });
  const userConfig = join(seedConfig, 'user.npmrc'), globalConfig = join(seedConfig, 'global.npmrc');
  for (const path of [userConfig, globalConfig]) writeFileSync(path, '', { flag: 'wx', mode: 0o600 });
  command(node, [npmCli, 'cache', 'add', tarball, `--cache=${cache}`, `--userconfig=${userConfig}`, `--globalconfig=${globalConfig}`,
    '--registry=https://registry.npmjs.org/', '--ignore-scripts', '--no-audit', '--no-fund']);
  assert.equal(existsSync(join(workspace, 'node_modules/typescript/package.json')), false, 'seed cache only; actual preparation installs');
  stage = 'explicit-seeded-offline-prepare';
  const prepared = command(node, [cli, 'instance', 'prepare', instance]);
  assert.match(prepared, /Declared check prerequisites are present/u); assert.equal(existsSync(hold), false);
  assert.equal(JSON.parse(readFileSync(join(workspace, 'node_modules/typescript/package.json'), 'utf8')).version, '5.9.3');
  assert.equal(existsSync(join(workspace, 'lifecycle-ran')), false);
  stage = 'public-sdk-required-checker';
  const checker = await new SandboxedCommandRunner({ command: profile.KEEP_TEST_COMMAND, args: JSON.parse(profile.KEEP_TEST_ARGS_JSON), projectDir: workspace,
    namespaceJail: 'required', jailExecutable: profile.KEEP_TEST_JAIL_EXECUTABLE, readOnlyPaths: [toolchain], allowNet: false,
    envAllowlist: [], timeoutMs, cpuLimitSec, maxOutputBytes }).run('.');
  save('checker.json', checker);
  assert.equal(checker.runnerError, undefined); assert.equal(checker.processIsolation?.namespacePolicy, 'required');
  assert.equal(checker.processIsolation.namespaceSetup, 'launcher-confirmed'); assert.equal(checker.processIsolation.basis, 'launcher-status');
  assert.deepEqual(checker.processIsolation.degraded, []); assert.equal(checker.results.length, 1); assert.equal(checker.results[0].passed, true);
  assert.equal(checker.processIsolation.rlimitSetup, 'launcher-confirmed');
  for (const namespace of ['mount-ns', 'pid-ns', 'ipc-ns', 'uts-ns', 'net-ns']) assert.ok(checker.processIsolation.requestedNamespaces.includes(namespace));
  stage = 'source-and-lifecycle-readback';
  assert.equal(git(['rev-parse', 'HEAD']), revision); assert.equal(git(['status', '--porcelain']), '');
  for (const [name, hash] of Object.entries(before)) assert.equal(digestFile(join(source, name)), hash);
  for (const name of ['node_modules', '.keep-preparation-cache', 'lifecycle-ran']) assert.equal(existsSync(join(source, name)), false);
  for (const name of ['current-worker.json', 'startup-pending.json', 'data/native-workers']) assert.equal(existsSync(join(instance, name)), false);
  const receipt = { status: 'PASS_SOURCE_OFFLINE_PREPARATION', scope: 'constructed preparation fixture; no model or whole-product quality claim',
    keepVersion: pkg.version, publicSdkRoot: pkg.exports['.'], uid: process.getuid(), platform: process.platform, arch: process.arch,
    nodeVersion, nodeSha256: digestFile(node), npmVersion: JSON.parse(readFileSync(join(toolchain, 'lib/node_modules/npm/package.json'))).version,
    npmCliSha256: digestFile(npmCli), helperSha256: digestFile(helper), sdkEntrySha256: digestFile(join(installed, pkg.exports['.'])),
    sourceRevision: revision, trackedSourceSha256: before, sourceUnchanged: true, emptyCacheRefused: true, explicitRetry: true,
    cacheSeed: { publicTarball: tarball, integrity, method: 'selected npm cache add, after actual empty-cache hold; no maintainer cache' },
    sourcePreflight: 'executed by the normal CLI before each npm attempt',
    installedDependency: 'typescript@5.9.3', lifecycleScriptsDisabled: true, usefulChecker: checker.results, processIsolation: checker.processIsolation,
    moduleOverlays: false, devCheckoutRequired: true, workerStarted: false, modelCalls: 0, observations };
  save('receipt.json', receipt); process.stdout.write(JSON.stringify(receipt) + '\n');

  }
} catch (error) {
  const failure = { status: 'FAIL_INDEPENDENT_PREPARATION', stage, error: error instanceof Error ? error.message : String(error), observations };
  if (root && existsSync(root)) try { save('failure.json', failure); } catch { /* preserve existing evidence */ }
  process.stderr.write(JSON.stringify(failure) + '\n'); process.exitCode = 1;
}
